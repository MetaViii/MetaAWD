import paramiko
from defence import ssh
from defence._bootstrap import get_runtime_dir
import random
import os
import socket
import threading
import time
import shlex
import re
import posixpath
from pathlib import Path
from termcolor import colored

from defence.state import state_manager

is_running = False
is_paused = False

def is_http_log_file(file_path):
    return str(file_path).lower().endswith('.http')


def quote_remote_arg(value):
    return shlex.quote(str(value))


def get_local_runtime_dir(hostname=None):
    """本地运行目录（可写）。打包后位于 exe 旁边，程序退出不丢失。"""
    safe_host = hostname or state_manager.hostname or "default"
    safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", safe_host)
    local_dir = get_runtime_dir(safe_host)
    local_dir.mkdir(parents=True, exist_ok=True)
    return local_dir


def get_local_source_dir(hostname=None):
    local_dir = get_local_runtime_dir(hostname) / "sources"
    local_dir.mkdir(parents=True, exist_ok=True)
    return local_dir

def _unescape_md5sum_name(name):
    """还原 GNU md5sum 对含 \\ / 换行 / 回车 的文件名所做的转义。

    不使用 --zero 时，这类文件名整行会以反斜杠开头，问题字符被转义成
    \\\\ / \\n / \\r。若不还原，删除时会拿转义串去 rm 真实文件而静默失败。
    """
    out = []
    i = 0
    while i < len(name):
        ch = name[i]
        if ch == "\\" and i + 1 < len(name):
            nxt = name[i + 1]
            if nxt == "n":
                out.append("\n"); i += 2; continue
            if nxt == "r":
                out.append("\r"); i += 2; continue
            if nxt == "\\":
                out.append("\\"); i += 2; continue
        out.append(ch); i += 1
    return "".join(out)


def batch_get_md5(ssh_client, directory_path, log_callback=print):
    """批量获取目录下所有文件的 MD5。

    可靠性要求：必须能区分「命令失败」与「目录确实为空」。
    原实现两者都返回 {}，导致采集失败时基线被写成空 dict，
    下一轮全部文件被判为"新增"，在自动删除模式下会清空整个站点。
    这里用 `find|wc -l` 计数与 md5sum 行数交叉校验，不一致即判定采集失败。
    """
    escaped_directory_path = quote_remote_arg(directory_path)
    marker = "__AWD_MD5_COUNT__"
    cmd = (
        f"n=$(find {escaped_directory_path} -type f 2>/dev/null | wc -l); "
        f"find {escaped_directory_path} -type f 2>/dev/null -exec md5sum {{}} + 2>/dev/null; "
        f"echo {marker}$n"
    )
    output, stderr = ssh.run_remote_capture_failure = ssh.run_ssh_command(ssh_client, cmd)
    output = output or ""

    expected = None
    body_lines = []
    for line in output.splitlines():
        if line.startswith(marker):
            try:
                expected = int(line[len(marker):].strip())
            except ValueError:
                expected = None
            continue
        body_lines.append(line)

    if expected is None:
        raise RuntimeError(
            f"MD5 采集未完成(命令未返回计数标记)，已中止本轮以免破坏基线: {stderr.strip()[:200]}"
        )

    md5_dict = {}
    for line in body_lines:
        if not line.strip():
            continue
        line = line.rstrip("\r")
        # GNU md5sum 对含 \ / 换行 / 回车的文件名会整行转义，需还原真实路径
        escaped = line.startswith("\\")
        if escaped:
            line = line[1:]
        digest, sep, rest = line.partition(" ")
        if not sep or not rest or len(digest) != 32:
            continue
        if rest[:1] in ("*", " "):
            name = rest[1:]
        else:
            name = rest
        md5_dict[_unescape_md5sum_name(name) if escaped else name] = digest

    # 交叉校验：拿到的条目数明显少于实际文件数，说明部分文件读取失败
    if len(md5_dict) < expected:
        raise RuntimeError(
            f"MD5 采集不完整: 实际文件 {expected} 个，仅取到 {len(md5_dict)} 个，"
            f"已中止本轮以免误判为新增文件"
        )

    if stderr and "Permission denied" not in stderr:
        log_callback(f"[警告] md5sum 获取异常: {stderr.strip()[:200]}")

    return md5_dict

def batch_delete_files(ssh_client, file_paths, log_callback=print):
    """使用一条命令批量删除文件，比 SFTP 循环删除快得多"""
    if not file_paths:
        return
        
    # 将文件路径用引号包裹，防止路径中有空格
    escaped_paths = [quote_remote_arg(path) for path in file_paths]
    
    # 如果文件太多，可能超出命令行长度限制，这里简单按 100 个文件分批
    batch_size = 100
    for i in range(0, len(escaped_paths), batch_size):
        batch = escaped_paths[i:i+batch_size]
        # 添加 2>/dev/null 抑制无权限等错误
        cmd = f"rm -f {' '.join(batch)} 2>/dev/null"
        output, stderr = ssh.run_ssh_command(ssh_client, cmd)
        if stderr and "Permission denied" not in stderr:
            log_callback(f"[警告] 批量删除异常: {stderr.strip()}")


def get_default_local_dir():
    """下载目录默认值：Windows 用用户目录，类 Unix 用 /home。

    原实现写死 /home，在 Windows 下会在当前盘根目录创建 \\home，位置异常。
    """
    if os.name == "nt":
        return str(Path.home())
    return "/home"


def tar(remote_path=None, local_dir=None, log_callback=print):
    if (state_manager.is_ssh == False):
        log_callback("请先测试ssh连接")
        return None
    if remote_path is None:
        remote_path = input("输入打包的路径 如/var/www/html/(默认)\n")
    if local_dir is None:
        local_dir = get_default_local_dir()
    if remote_path == "":
        remote_path = "/var/www/html/"
    if not local_dir:
        local_dir = get_default_local_dir()
    remote_path = remote_path.rstrip('/') or '/var/www/html'
    remote_tar_path = f"{remote_path}.tar.gz"
    remote_parent_dir = posixpath.dirname(remote_path) or "/"
    remote_base_name = posixpath.basename(remote_path)
    if not remote_base_name:
        remote_base_name = "."
    escaped_remote_tar_path = quote_remote_arg(remote_tar_path)
    escaped_remote_parent_dir = quote_remote_arg(remote_parent_dir)
    escaped_remote_base_name = quote_remote_arg(remote_base_name)
    ssh_client = None
    sftp_client = None
    try:
        # 连接创建必须放在 try 内：否则 SSH 掉线时异常会直接抛给调用方，
        # 使 GUI 的"打包并下载"按钮永久禁用。
        ssh_client, sftp_client = ssh.connect_sftp_client()
        tar_command = f"tar -czhvf {escaped_remote_tar_path} -C {escaped_remote_parent_dir} {escaped_remote_base_name}"
        stdin, stdout, stderr = ssh_client.exec_command(tar_command)
        for line in stdout:
            log_callback(line.strip())
        error_output = stderr.read().decode("utf-8", errors="replace").strip()
        if error_output and "Removing leading `/' from member names" not in error_output and "Removing leading '/' from member names" not in error_output and "从成员名中删除开头的“/”" not in error_output and "从硬连接目标中删除开头的“/”" not in error_output:
            log_callback(error_output)
            return None
        clean_path = remote_path.rstrip('/')
        dir_name = clean_path.split('/')[-1] if clean_path else "root"
        local_source_dir = Path(local_dir).expanduser()
        local_source_dir.mkdir(parents=True, exist_ok=True)
        local_path = local_source_dir / f"{dir_name}_{chr(random.randint(97, 122))}{random.randint(100, 999)}.tar.gz"
        sftp_client.get(remote_tar_path, str(local_path))
        log_callback("文件下载至{0}".format(local_path))
        rm_command = f"rm -f {escaped_remote_tar_path}"
        ssh_client.exec_command(rm_command)
        return str(local_path)
    except Exception as e:
        log_callback(f"打包错误！: {e}")
        return None
    finally:
        for cli in (sftp_client, ssh_client):
            if cli is not None:
                try:
                    cli.close()
                except Exception:
                    pass

def deploy_tar(local_tar_path, remote_path="/var/www/html/", log_callback=print):
    """把本地备份包部署到远端。

    关键安全约束（原实现三处缺陷均已修正）：
    1. 备份必须成功才允许清空目录 —— 原实现用 `;` 串联，备份失败照样 `find -delete`；
    2. 解压层级要与 tar() 的产物一致 —— tar() 打的包顶层是 basename，
       原实现解到目录自身会变成 <dir>/<base>/... 导致站点 404 却报成功；
       这里先探测包内首层，自适应选择解压目标；
    3. 用显式标记判断成败，不依赖 stderr 是否为空。
    """
    if state_manager.is_ssh == False:
        log_callback("请先测试ssh连接")
        return False
    if not local_tar_path or not os.path.exists(local_tar_path):
        log_callback("本地备份文件不存在")
        return False

    ssh_client = None
    sftp_client = None
    try:
        ssh_client, sftp_client = ssh.connect_sftp_client()
        ts = int(time.time())
        remote_tmp_tar = f"/tmp/.awd_restore_{ts}.tar.gz"
        remote_backup = f"/tmp/.awd_predeploy_{ts}.tar.gz"
        log_callback(f"[*] 上传备份包到远端: {remote_tmp_tar}")
        sftp_client.put(local_tar_path, remote_tmp_tar)

        remote_path_clean = remote_path.rstrip('/') or '/var/www/html'
        parent = posixpath.dirname(remote_path_clean) or '/'
        base = posixpath.basename(remote_path_clean)
        q = shlex.quote

        # 探测包内首层结构，决定解压到父目录还是目标目录
        list_out, _ = ssh.run_ssh_command(
            ssh_client, f"tar -tzf {q(remote_tmp_tar)} 2>/dev/null | head -5"
        )
        entries = [e.strip() for e in (list_out or "").splitlines() if e.strip()]
        if not entries:
            log_callback("[x] 备份包内容无法列出(包损坏或非 tar.gz)，已终止，远端未做任何改动")
            return False
        top_level = entries[0].split("/", 1)[0]
        if top_level == base:
            extract_dest = parent          # 包内已含顶层目录
        else:
            extract_dest = remote_path_clean
        log_callback(f"[*] 包内顶层 '{top_level}'，解压目标 {extract_dest}")

        command = (
            f"mkdir -p {q(remote_path_clean)} && "
            f"tar -czf {q(remote_backup)} -C {q(parent)} {q(base)} 2>/dev/null "
            f"&& test -s {q(remote_backup)} && echo AWD_BACKUP_OK && "
            f"find {q(remote_path_clean)} -mindepth 1 -delete && "
            f"if tar -xzf {q(remote_tmp_tar)} -C {q(extract_dest)} 2>/dev/null; then "
            f"  test -n \"$(ls -A {q(remote_path_clean)})\" && echo AWD_DEPLOY_OK; "
            f"else "
            f"  find {q(remote_path_clean)} -mindepth 1 -delete 2>/dev/null; "
            f"  tar -xzf {q(remote_backup)} -C {q(parent)} 2>/dev/null "
            f"    && echo AWD_DEPLOY_ROLLBACK; "
            f"fi; "
            f"rm -f {q(remote_tmp_tar)}"
        )
        stdout, stderr = ssh.run_ssh_command(ssh_client, command)
        out = (stdout or "").strip()

        if "AWD_BACKUP_OK" not in out:
            log_callback(f"[x] 远端备份失败，已终止部署(线上目录未改动): "
                         f"{(stderr or out or '未知原因').strip()[:200]}")
            return False
        if "AWD_DEPLOY_OK" in out:
            log_callback("[✓] 备份包部署完成")
            return True
        if "AWD_DEPLOY_ROLLBACK" in out:
            log_callback("[x] 解压失败，已自动回滚到部署前状态")
            return False
        log_callback(f"[x] 部署失败: {(stderr or out or '未知原因').strip()}")
        return False
    except Exception as exc:
        log_callback(f"[x] 部署异常: {exc}")
        return False
    finally:
        for cli in (sftp_client, ssh_client):
            if cli is not None:
                try:
                    cli.close()
                except Exception:
                    pass


def monitor_directory_changes(hostname, port, username, password, directory_path, is_delete, log_callback=print, is_gui=False):
    global is_running, is_paused
    is_running = True
    is_paused = False

    def stop_monitoring():
        log_callback(colored("正在停止文件监控...", 'red'))
        global is_running
        is_running = False

    def input_listener():
        while is_running:
            user_input = input()
            if user_input.strip().lower() == "end":
                stop_monitoring()

    if not is_gui:
        threading.Thread(target=input_listener, daemon=True).start()

    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, port, username=username, password=password)

        md5_dict = {}
        counter = 0
        consecutive_failures = 0
        # 连续失败上限：超过则重建连接。原实现从不重建，靶机 sshd 被打挂后
        # 会永久刷错误却仍显示"运行中"，防守方在无监控状态下裸奔。
        max_failures = 5

        while is_running:
            if is_paused:
                time.sleep(1)
                continue

            try:
                # 获取最新的所有文件的 MD5
                new_md5_dict = batch_get_md5(client, directory_path, log_callback)
                consecutive_failures = 0
                files_to_delete = []
                
                if counter == 0:
                    # 初次检测：建立基线。
                    # batch_get_md5 采集失败会抛异常(上面捕获)，因此走到这里
                    # 的空结果只可能是"目录确实为空"，不会被误当成失败基线。
                    md5_dict = dict(new_md5_dict)
                    log_callback(f"初检完成，共记录 {len(md5_dict)} 个文件")
                else:
                    # 对比检测
                    for file_path, new_md5 in new_md5_dict.items():
                        if file_path not in md5_dict:
                            if is_http_log_file(file_path):
                                log_callback(f"[+] 新增日志文件：{file_path}")
                                md5_dict[file_path] = new_md5
                                continue
                            log_callback(f"[😍] 新增文件：{file_path}: {new_md5}")
                            if is_delete:
                                files_to_delete.append(file_path)
                            else:
                                md5_dict[file_path] = new_md5
                        elif md5_dict[file_path] != new_md5:
                            if is_http_log_file(file_path):
                                md5_dict[file_path] = new_md5
                                continue
                            log_callback(f"[❗] {file_path} 被更改!")
                            log_callback(f"    旧的 MD5: {md5_dict[file_path]}")
                            log_callback(f"    新的 MD5: {new_md5}")
                            if is_delete:
                                files_to_delete.append(file_path)
                            else:
                                md5_dict[file_path] = new_md5

                    # 第二道防线：单轮变更比例异常高，说明基线可能失效
                    # (例如首轮采集不完整)。此时必须放弃自动删除，
                    # 否则会 rm -f 清空整个站点。
                    if is_delete and files_to_delete:
                        baseline_size = max(1, len(md5_dict))
                        ratio = len(files_to_delete) / baseline_size
                        if len(files_to_delete) > max(20, baseline_size * 0.5) or ratio > 0.5:
                            log_callback(
                                f"[⚠] 本轮变更异常(待删 {len(files_to_delete)} / 基线 "
                                f"{baseline_size})，疑似基线失效，已跳过自动删除以免清空站点"
                            )
                            for f in files_to_delete:
                                md5_dict.setdefault(f, new_md5_dict.get(f, ""))
                            files_to_delete = []
                                
                    # 批量删除
                    if is_delete and files_to_delete:
                        log_callback(f"[*] 准备批量删除 {len(files_to_delete)} 个异常文件...")
                        batch_delete_files(client, files_to_delete, log_callback)
                        for f in files_to_delete:
                            log_callback(f"[❌] 已提交删除：{f}")
                            # 同步基线：否则攻击者用相同内容重传同名文件时
                            # MD5 会与残留基线相同，被判为"未变化"而漏报
                            md5_dict.pop(f, None)
                            
                counter += 1
                time.sleep(2) # 增加小幅度延迟，防止死循环耗尽资源

            except (paramiko.AuthenticationException, paramiko.SSHException, socket.error) as e:
                consecutive_failures += 1
                log_callback(f"[❌] Error1 ({consecutive_failures}/{max_failures}): {e}")
                if consecutive_failures >= max_failures:
                    log_callback("[*] 连续失败过多，尝试重建 SSH 连接...")
                    try:
                        client.close()
                    except Exception:
                        pass
                    try:
                        client = paramiko.SSHClient()
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        client.connect(hostname, port, username=username, password=password, timeout=10)
                        consecutive_failures = 0
                        # 断线期间文件可能已变化，基线已不可信，重新建立
                        md5_dict = {}
                        counter = 0
                        log_callback("[✓] 连接已重建，重新建立基线")
                    except Exception as re_exc:
                        log_callback(f"[❌] 重建连接失败，5 秒后重试: {re_exc}")
                        time.sleep(5)
                time.sleep(1)
                continue
            except Exception as e:
                # 兜底：解码错误/类型错误等非网络异常不应让监控线程静默死掉
                # (曾导致 GUI 控件永久锁死且 is_running 不复位)
                log_callback(f"[❌] 监控轮次异常(已跳过本轮): {type(e).__name__}: {e}")
                time.sleep(1)
                continue

    except (paramiko.AuthenticationException, paramiko.SSHException, socket.error) as e:
        log_callback(f"[❌] Error2: {e}")
    except Exception as e:
        log_callback(f"[❌] 监控异常退出: {type(e).__name__}: {e}")
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        # 复位全局标志，避免线程结束后仍显示"运行中"
        is_running = False
        is_paused = False

    log_callback(colored("结束文件监控", 'red'))
