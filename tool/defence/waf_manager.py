import os
import posixpath
import re
import shlex
import tempfile
from pathlib import Path
from stat import S_ISREG
from uuid import uuid4

from defence import ssh
from defence._bootstrap import get_resource_dir, get_runtime_dir
from defence.request_logs import read_request_text
from defence.state import state_manager


def get_project_root():
    """只读资源根目录（phpwaf 模板所在）。打包后指向 _MEIPASS。"""
    return get_resource_dir()


def get_local_waf_loader_path(php_major):
    php_major = int(php_major)
    if php_major >= 8:
        return get_project_root() / "defence" / "phpwaf" / "waf_php8.php"
    if php_major >= 7:
        return get_project_root() / "defence" / "phpwaf" / "waf_php7.php"
    return get_project_root() / "defence" / "phpwaf" / "waf_php5.php"


def get_local_log_dir(hostname=None):
    """本地日志目录（可写）。打包后位于 exe 旁边，程序退出不丢失。"""
    safe_host = hostname or state_manager.hostname or "default"
    safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", safe_host)
    local_dir = get_runtime_dir(safe_host) / "waf_logs"
    local_dir.mkdir(parents=True, exist_ok=True)
    state_manager.local_waf_log_dir = str(local_dir)
    return local_dir


def get_remote_waf_dir(remote_dir=None):
    remote_dir = (remote_dir or state_manager.remote_waf_dir or "/var/www/html/.phpwaf").rstrip("/")
    return remote_dir or "/var/www/html/.phpwaf"


def get_remote_waf_path(remote_dir=None):
    remote_dir = get_remote_waf_dir(remote_dir)
    return f"{remote_dir}/waf.php"


def get_remote_waf_log_dir(remote_log_dir=None):
    remote_log_dir = (remote_log_dir or state_manager.remote_waf_log_dir or "/tmp/.phpwaf_logs").rstrip("/")
    return remote_log_dir or "/tmp/.phpwaf_logs"


def escape_php_single_quoted(value):
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


WAF_INCLUDE_START = "PHPWAF-INCLUDE-START"
WAF_INCLUDE_END = "PHPWAF-INCLUDE-END"

# 精确匹配带标记的注入块（标记位于 <?php ?> 内部，不会输出到页面）。
# 旧版本注入的块没有标记，由 strip_injected_block 的逐字兜底处理。
_MARKED_BLOCK_RE = re.compile(
    r"<\?php\s*/\*\s*" + WAF_INCLUDE_START + r"\s*\*/.*?/\*\s*"
    + WAF_INCLUDE_END + r"\s*\*/\s*\?>\s*",
    re.S,
)


def build_waf_include_snippet(remote_waf_path=None, remote_log_dir=None, waf_mode=1,
                              waf_strict_level=3, waf_redirect_path="", log_all=False):
    remote_waf_path = remote_waf_path or state_manager.remote_waf_path
    remote_log_dir = get_remote_waf_log_dir(remote_log_dir)
    waf_mode = int(waf_mode)
    waf_strict_level = int(waf_strict_level)
    waf_redirect_path = waf_redirect_path or ""
    log_all = 1 if log_all else 0
    escaped_remote_log_dir = escape_php_single_quoted(remote_log_dir)
    escaped_redirect_path = escape_php_single_quoted(waf_redirect_path)
    escaped_remote_waf_path = escape_php_single_quoted(remote_waf_path)
    # 标记写在 <?php ?> 内部作为注释，避免被当作页面内容输出
    return (
        f"<?php /* {WAF_INCLUDE_START} */ "
        f"if (!defined('PHPWAF_LOG_DIR')) {{ define('PHPWAF_LOG_DIR', '{escaped_remote_log_dir}'); }} "
        f"if (!defined('PHPWAF_MODE')) {{ define('PHPWAF_MODE', {waf_mode}); }} "
        f"if (!defined('PHPWAF_STRICT_LEVEL')) {{ define('PHPWAF_STRICT_LEVEL', {waf_strict_level}); }} "
        f"if (!defined('PHPWAF_REDIRECT_PATH')) {{ define('PHPWAF_REDIRECT_PATH', '{escaped_redirect_path}'); }} "
        f"if (!defined('PHPWAF_LOG_ALL')) {{ define('PHPWAF_LOG_ALL', {log_all}); }} "
        f"require_once '{escaped_remote_waf_path}'; "
        f"/* {WAF_INCLUDE_END} */ ?>"
    )


def strip_injected_block(content, legacy_snippet=None):
    """剥离注入块。

    策略：优先按 INCLUDE-START/END 标记精确剥离（绝不跨用户代码模糊匹配）；
    仅当找不到标记时，才退回"文件头逐字等于旧 snippet"这一种安全情形。
    """
    bom = "\ufeff" if content.startswith("\ufeff") else ""
    raw = content[1:] if bom else content

    cleaned, hits = _MARKED_BLOCK_RE.subn("", raw, count=1)
    if hits == 0 and legacy_snippet:
        for candidate in (legacy_snippet + "\n", legacy_snippet):
            if cleaned.startswith(candidate):
                cleaned = cleaned[len(candidate):]
                break
    return bom + cleaned


def prepend_waf_include(content, include_snippet):
    if content.startswith("\ufeff"):
        return "\ufeff" + include_snippet + "\n" + content[1:]
    return include_snippet + "\n" + content


def normalize_injected_content(content, include_snippet):
    """确保文件头部正好是本版本注入块（用于重复部署时的幂等修复）"""
    stripped = strip_injected_block(content, legacy_snippet=include_snippet)
    stripped = stripped.lstrip("\r\n")
    if stripped == content:
        return content
    bom = "\ufeff" if content.startswith("\ufeff") else ""
    return bom + include_snippet + "\n" + (stripped[1:] if stripped.startswith("\ufeff") else stripped)


def remove_waf_include_content(content, remote_waf_path):
    """移除注入块，其余内容原样保留（不做任何“补回 <?php”的猜测性修补）"""
    legacy_snippet = None
    try:
        legacy_snippet = build_waf_include_snippet(
            remote_waf_path,
            getattr(state_manager, "remote_waf_log_dir", None),
            getattr(state_manager, "waf_mode", 1),
            getattr(state_manager, "waf_strict_level", 3),
            getattr(state_manager, "waf_redirect_path", "") or "",
        )
    except Exception:
        legacy_snippet = None
    cleaned = strip_injected_block(content, legacy_snippet=legacy_snippet)
    return cleaned.lstrip("\r\n") if cleaned.strip() else cleaned


def detect_remote_php_major(log_callback=print):
    ssh_client = ssh.connect_ssh_client()
    try:
        stdout, stderr = ssh.run_ssh_command(ssh_client, "php -r 'echo PHP_VERSION;' 2>/dev/null")
        version_text = (stdout or stderr).strip()
        if not version_text:
            stdout, stderr = ssh.run_ssh_command(ssh_client, "php -v 2>/dev/null")
            version_text = (stdout or stderr).strip()
        match = re.search(r"(\d+)\.(\d+)", version_text)
        if not match:
            raise RuntimeError("无法识别远端 PHP 版本")
        php_major = int(match.group(1))
        log_callback(f"✓ 远端 PHP 版本: {version_text}")
        return php_major, version_text
    finally:
        ssh_client.close()


def list_remote_php_files(remote_root, log_callback=print):
    remote_root = remote_root.rstrip("/") or "/var/www/html"
    ssh_client = ssh.connect_ssh_client()
    try:
        command = f"find {shlex.quote(remote_root)} -type f -name '*.php' 2>/dev/null"
        stdout, stderr = ssh.run_ssh_command(ssh_client, command)
        if stderr.strip():
            log_callback(stderr.strip())
        return [line.strip() for line in stdout.splitlines() if line.strip()]
    finally:
        ssh_client.close()


def ensure_remote_waf_dir(remote_dir, log_callback=print, ensure_writable=False):
    ssh_client = ssh.connect_ssh_client()
    try:
        command = f"mkdir -p {shlex.quote(remote_dir)}"
        if ensure_writable:
            command += f" && chmod 0777 {shlex.quote(remote_dir)}"
        _, stderr = ssh.run_ssh_command(ssh_client, command)
        if stderr.strip():
            log_callback(stderr.strip())
        return stderr.strip() == ""
    finally:
        ssh_client.close()


def upload_waf(remote_dir=None, log_callback=print, *, update_only=False):
    remote_dir = get_remote_waf_dir(remote_dir)
    remote_waf_path = get_remote_waf_path(remote_dir)
    php_major, version_text = detect_remote_php_major(log_callback)
    local_waf_loader_path = get_local_waf_loader_path(php_major)
    temp_remote_waf_path = f"{remote_dir}/.waf-{uuid4().hex}.part"
    ssh_client, sftp_client = ssh.connect_sftp_client()
    try:
        try:
            sftp_client.stat(remote_dir)
        except OSError:
            raise FileNotFoundError(f"远端目录不存在: {remote_dir}")
        if update_only:
            if not S_ISREG(sftp_client.lstat(remote_waf_path).st_mode):
                raise RuntimeError(f"未找到可更新的 WAF 模板: {remote_waf_path}")
            directory = get_local_log_dir() / "templates"
            directory.mkdir(exist_ok=True)
            backup = directory / f"waf-{uuid4().hex}.php"
            sftp_client.get(remote_waf_path, str(backup))
            log_callback(f"已在本机备份 WAF 模板: {backup}")
        sftp_client.put(str(local_waf_loader_path), temp_remote_waf_path)
        try:
            sftp_client.posix_rename(temp_remote_waf_path, remote_waf_path)
        except OSError:
            # 不支持 SFTP 扩展时，在同一目录原子替换。失败时保留已部署的模板。
            _, stdout, stderr = ssh_client.exec_command(
                f"mv -fT -- {shlex.quote(temp_remote_waf_path)} {shlex.quote(remote_waf_path)}"
            )
            reason = stderr.read().decode("utf-8", errors="replace").strip()
            if stdout.channel.recv_exit_status():
                raise OSError(reason or "远端 WAF 模板替换失败")
        state_manager.remote_waf_dir = remote_dir
        state_manager.remote_waf_path = remote_waf_path
        # 注意：此处不置 waf_deployed=True —— 仅上传文件还不算防护生效，
        # 必须等 inject_waf_into_php_files 成功注入后再置位(见 deploy_waf)。
        log_callback(f"✓ 已上传 PHP{php_major} 版本 WAF: {remote_waf_path}")
        return remote_waf_path
    finally:
        try:
            sftp_client.remove(temp_remote_waf_path)
        except OSError:
            pass
        sftp_client.close()
        ssh_client.close()


def read_remote_text_file(sftp_client, remote_path):
    with sftp_client.open(remote_path, "rb") as remote_file:
        data = remote_file.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def write_remote_text_file(sftp_client, remote_path, content, backup=True):
    """远端文本写入。

    先备份原文件，再写临时文件后 rename 覆盖，避免中途失败留下被截断的源码
    （原实现直接以 "wb" 打开目标文件，打开即截断）。
    """
    if backup:
        try:
            backup_remote_file(sftp_client, remote_path)
        except Exception as exc:
            raise RuntimeError(f"备份失败，已中止改写 {remote_path}: {exc}")
    tmp_path = f"{remote_path}.phpwaf.tmp"
    with sftp_client.open(tmp_path, "wb") as tmp_file:
        tmp_file.write(content.encode("utf-8"))
    try:
        sftp_client.remove(remote_path)
    except OSError:
        pass
    sftp_client.rename(tmp_path, remote_path)


def backup_remote_file(sftp_client, remote_path):
    """把远端文件备份为 <path>.phpwaf.bak，返回备份路径"""
    backup_path = f"{remote_path}.phpwaf.bak"
    with sftp_client.open(remote_path, "rb") as src:
        data = src.read()
    with sftp_client.open(backup_path, "wb") as dst:
        dst.write(data)
    return backup_path


def should_skip_waf_managed_file(remote_file, remote_waf_path):
    """判断远端文件是否属于 WAF 自身（不做无意义注入）。

    路径先规范化，避免 `/var/www/html/../html/.phpwaf/waf.php` 这类
    含 `..` 或相对路径的写法绕过判断。
    """
    waf_path = posixpath.normpath(remote_waf_path)
    target = posixpath.normpath(remote_file)
    if target == waf_path:
        return True
    waf_dir = posixpath.dirname(waf_path).rstrip("/")
    return bool(waf_dir) and target.startswith(waf_dir + "/")


def inject_waf_into_php_files(
    remote_root, remote_waf_path=None, log_callback=print, remote_log_dir=None,
    waf_mode=1, waf_strict_level=3, waf_redirect_path="", log_all=False
):
    remote_waf_path = remote_waf_path or state_manager.remote_waf_path
    include_snippet = build_waf_include_snippet(remote_waf_path, remote_log_dir, waf_mode,
                                                waf_strict_level, waf_redirect_path, log_all)
    php_files = list_remote_php_files(remote_root, log_callback)
    injected = 0
    skipped = 0
    failed = []
    ssh_client, sftp_client = ssh.connect_sftp_client()
    try:
        for remote_file in php_files:
            try:
                if should_skip_waf_managed_file(remote_file, remote_waf_path):
                    skipped += 1
                    continue
                content = read_remote_text_file(sftp_client, remote_file)
                if remote_waf_path in content or "PHPWAF-INCLUDE-START" in content:
                    normalized_content = normalize_injected_content(content, include_snippet)
                    if normalized_content != content:
                        write_remote_text_file(sftp_client, remote_file, normalized_content)
                        injected += 1
                        log_callback(f"✓ 已修复注入: {remote_file}")
                    else:
                        skipped += 1
                    continue
                new_content = prepend_waf_include(content, include_snippet)
                write_remote_text_file(sftp_client, remote_file, new_content)
                injected += 1
                log_callback(f"✓ 已注入: {remote_file}")
            except Exception as exc:
                failed.append((remote_file, str(exc)))
                log_callback(f"✗ 注入失败 {remote_file}: {exc}")
    finally:
        sftp_client.close()
        ssh_client.close()
    return {
        "total": len(php_files),
        "injected": injected,
        "skipped": skipped,
        "failed": failed,
    }


def remove_waf_from_php_files(remote_root, remote_waf_path=None, log_callback=print):
    remote_waf_path = remote_waf_path or state_manager.remote_waf_path
    php_files = list_remote_php_files(remote_root, log_callback)
    removed = 0
    skipped = 0
    failed = []
    ssh_client, sftp_client = ssh.connect_sftp_client()
    try:
        for remote_file in php_files:
            try:
                if should_skip_waf_managed_file(remote_file, remote_waf_path):
                    skipped += 1
                    continue
                content = read_remote_text_file(sftp_client, remote_file)
                cleaned = remove_waf_include_content(content, remote_waf_path)
                if cleaned == content:
                    skipped += 1
                    continue
                write_remote_text_file(sftp_client, remote_file, cleaned)
                removed += 1
                log_callback(f"✓ 已移除注入: {remote_file}")
            except Exception as exc:
                failed.append((remote_file, str(exc)))
                log_callback(f"✗ 移除失败 {remote_file}: {exc}")
    finally:
        sftp_client.close()
        ssh_client.close()
    return {
        "total": len(php_files),
        "removed": removed,
        "skipped": skipped,
        "failed": failed,
    }


def deploy_waf(
    remote_root, remote_dir=None, log_callback=print, remote_log_dir=None,
    waf_mode=1, waf_strict_level=3, waf_redirect_path="", log_all=False
):
    waf_mode = int(waf_mode)
    waf_strict_level = int(waf_strict_level)
    if state_manager.waf_deployed:
        if waf_mode != int(state_manager.waf_mode) or waf_strict_level != int(state_manager.waf_strict_level):
            raise RuntimeError("WAF 已安装时不允许修改拦截方式和严格程度，请先一键下 WAF")
    remote_dir = get_remote_waf_dir(remote_dir)
    remote_log_dir = get_remote_waf_log_dir(remote_log_dir)
    ensure_remote_waf_dir(remote_dir, log_callback)
    ensure_remote_waf_dir(remote_log_dir, log_callback, ensure_writable=True)
    remote_waf_path = upload_waf(remote_dir, log_callback)
    result = inject_waf_into_php_files(
        remote_root, remote_waf_path, log_callback, remote_log_dir=remote_log_dir,
        waf_mode=waf_mode, waf_strict_level=waf_strict_level,
        waf_redirect_path=waf_redirect_path, log_all=log_all
    )
    # 注入才算部署成功：upload_waf 只负责传文件，不能据此认定已生效
    if result["failed"] or result["injected"] == 0:
        state_manager.waf_deployed = False
        raise RuntimeError(
            f"注入未完成：成功 {result['injected']}，失败 {len(result['failed'])}，"
            f"跳过 {result['skipped']}；远端文件已保留，请检查目录权限后重试"
        )
    state_manager.remote_waf_log_dir = remote_log_dir
    state_manager.waf_mode = waf_mode
    state_manager.waf_strict_level = waf_strict_level
    state_manager.waf_redirect_path = waf_redirect_path or ""
    state_manager.waf_deployed = True
    return {
        "remote_dir": remote_dir,
        "remote_log_dir": remote_log_dir,
        "remote_waf_path": remote_waf_path,
        "waf_mode": int(waf_mode),
        "waf_strict_level": int(waf_strict_level),
        "waf_redirect_path": waf_redirect_path or "",
        "inject_result": result,
    }


def undeploy_waf(remote_root, remote_dir=None, log_callback=print):
    """下线 WAF。

    关键约束：只要有任一文件未能剥离注入，就**必须保留** waf.php 并保持
    waf_deployed=True。否则残留的 require_once 会指向已删除的文件，
    导致全站 Fatal error（原实现忽略 remove_result["failed"] 直接删文件）。
    """
    remote_dir = get_remote_waf_dir(remote_dir)
    remote_waf_path = get_remote_waf_path(remote_dir)
    remove_result = remove_waf_from_php_files(remote_root, remote_waf_path, log_callback)

    if remove_result["failed"]:
        log_callback(f"✗ {len(remove_result['failed'])} 个文件未能清理，"
                     f"保留 {remote_waf_path} 以避免全站 Fatal error")
        for remote_file, err in remove_result["failed"][:10]:
            log_callback(f"    - {remote_file}: {err}")
        state_manager.waf_deployed = True
        return {
            "remote_dir": remote_dir,
            "remote_waf_path": remote_waf_path,
            "remove_result": remove_result,
            "ok": False,
        }

    ssh_client = None
    sftp_client = None
    try:
        ssh_client, sftp_client = ssh.connect_sftp_client()
        # 先降级为无害存根，再删除：万一下一步失败也不会造成 Fatal
        try:
            with sftp_client.open(remote_waf_path, "wb") as fp:
                fp.write(b"<?php /* phpwaf removed */\n")
        except OSError:
            pass
        try:
            sftp_client.remove(remote_waf_path)
            log_callback(f"✓ 已删除远端WAF: {remote_waf_path}")
        except OSError:
            log_callback(f"• 远端WAF文件不存在: {remote_waf_path}")
    except Exception as exc:
        log_callback(f"✗ 删除 WAF 文件失败: {exc}")
        state_manager.waf_deployed = True
        return {
            "remote_dir": remote_dir,
            "remote_waf_path": remote_waf_path,
            "remove_result": remove_result,
            "ok": False,
        }
    finally:
        for cli in (sftp_client, ssh_client):
            if cli is not None:
                try:
                    cli.close()
                except Exception:
                    pass

    if remove_result["removed"] == 0 and remove_result["skipped"] == remove_result["total"]:
        log_callback("⚠ 未发现任何注入痕迹，请确认业务目录与隐藏目录是否一致")
        return {
            "remote_dir": remote_dir,
            "remote_waf_path": remote_waf_path,
            "remove_result": remove_result,
            "ok": False,
        }

    state_manager.waf_deployed = False
    return {
        "remote_dir": remote_dir,
        "remote_waf_path": remote_waf_path,
        "remove_result": remove_result,
        "ok": True,
    }


def check_and_restore_waf(remote_dir=None, log_callback=print):
    remote_dir = get_remote_waf_dir(remote_dir)
    remote_waf_path = get_remote_waf_path(remote_dir)
    ssh_client, sftp_client = ssh.connect_sftp_client()
    try:
        try:
            sftp_client.stat(remote_waf_path)
            return False
        except OSError:
            pass
    finally:
        sftp_client.close()
        ssh_client.close()

    log_callback(f"⚠ 检测到 WAF 缺失，准备补传: {remote_waf_path}")
    ensure_remote_waf_dir(remote_dir, log_callback)
    upload_waf(remote_dir, log_callback)
    return True


def sync_remote_logs(remote_dir=None, log_callback=print, *, on_new_file=None,
                     raise_on_transport_error=False, io_timeout=None, stop_event=None):
    """把远端 WAF 记录的请求包拉到本地。

    逐条容错：单个文件下载/删除失败只跳过该文件，不中断整批同步。
    下载成功后才删除远端文件，避免下载失败却已丢失日志。
    on_new_file 在新日志保存到本机后调用，同名文件重复同步时不重复通知。
    """
    remote_dir = get_remote_waf_log_dir(remote_dir)
    local_dir = get_local_log_dir()
    downloaded = []
    failed = 0
    transport_errors = (ConnectionError, EOFError, TimeoutError)
    ssh_client = None
    sftp_client = None
    try:
        if stop_event is not None and stop_event.is_set():
            return downloaded
        options = {"io_timeout": io_timeout} if io_timeout is not None else {}
        ssh_client, sftp_client = ssh.connect_sftp_client(**options)
        if stop_event is not None and stop_event.is_set():
            return downloaded
        try:
            entries = sftp_client.listdir_attr(remote_dir)
        except OSError as exc:
            message = f"远端日志目录不存在或不可访问: {remote_dir}"
            if raise_on_transport_error:
                if isinstance(exc, transport_errors):
                    raise
                raise OSError(message) from exc
            log_callback(f"⚠ {message}")
            return downloaded
        for entry in entries:
            if stop_event is not None and stop_event.is_set():
                break
            if not S_ISREG(entry.st_mode) or not entry.filename.endswith(".http"):
                continue
            name = entry.filename
            if any(char in name for char in '/\\:*?"<>|\x00'):
                failed += 1
                log_callback("⚠ 跳过不能安全保存到本地的日志文件名")
                continue
            remote_path = f"{remote_dir}/{name}"
            local_path = local_dir / name
            staging = None
            try:
                new_file = on_new_file is not None and not local_path.exists()
                with tempfile.NamedTemporaryFile(dir=local_dir, suffix=".part", delete=False) as temp:
                    staging = Path(temp.name)
                sftp_client.get(remote_path, str(staging))
                remote_mtime = getattr(entry, "st_mtime", None)
                if remote_mtime is not None:
                    os.utime(staging, (remote_mtime, remote_mtime))
                os.replace(staging, local_path)
            except Exception as exc:
                if raise_on_transport_error and isinstance(exc, transport_errors):
                    raise
                failed += 1
                log_callback(f"⚠ 下载失败(已跳过) {name}: {exc}")
                continue
            finally:
                if staging is not None:
                    try:
                        staging.unlink(missing_ok=True)
                    except OSError as exc:
                        log_callback(f"⚠ 临时日志清理失败: {exc}")
            downloaded.append(str(local_path))
            if new_file:
                on_new_file(local_path)
            try:
                sftp_client.remove(remote_path)
            except Exception as exc:
                if raise_on_transport_error and isinstance(exc, transport_errors):
                    raise
                # 文件已落到本地，删除远端失败不影响使用，仅提示避免重复同步
                log_callback(f"• 远端清理失败(下次可能重复同步) {entry.filename}: {exc}")
            log_callback(f"↓ 已同步日志: {entry.filename}")
        if failed:
            log_callback(f"• 本次有 {failed} 个日志下载失败，已跳过")
    finally:
        for cli in (sftp_client, ssh_client):
            if cli is not None:
                try:
                    cli.close()
                except Exception:
                    pass
    return downloaded


def list_local_request_logs(hostname=None):
    local_dir = get_local_log_dir(hostname)
    files = []
    for path in local_dir.glob("*.http"):
        try:
            stat = path.lstat()
        except FileNotFoundError:
            continue
        if not S_ISREG(stat.st_mode):
            continue
        files.append({
            "name": path.name,
            "path": str(path),
            "size": stat.st_size,
            "mtime": stat.st_mtime,
            "revision": (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size),
        })
    return sorted(files, key=lambda item: item["mtime"], reverse=True)


def read_local_request_log(file_path):
    return read_request_text(file_path)


def clear_local_request_logs(hostname=None):
    local_dir = get_local_log_dir(hostname)
    removed = []
    for path in local_dir.glob("*.http"):
        path.unlink(missing_ok=True)
        removed.append(str(path))
    return removed
