import paramiko
import codecs
import select
import sys
import threading
from termcolor import colored
from defence.state import state_manager


def run_ssh_command(ssh_client, command):
    """执行远端命令并返回 (stdout, stderr)。

    用 errors="replace" 解码：AWD 靶机上常出现 GBK 文件名/中文输出，
    严格 decode 会抛 UnicodeDecodeError，该异常曾穿透 file_processing 的
    窄 except 并导致 GUI 控件永久锁死。解码永不抛错，由调用方按内容判断。
    """
    _, stdout, stderr = ssh_client.exec_command(command)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return out, err


def connect_ssh_client(hostname=None, port=None, username=None, password=None, timeout=10):
    """建立 SSH 连接。

    连接失败时必须显式 close：paramiko 的 connect() 失败路径不会关闭已启动的
    Transport，而 Transport 由后台线程持有强引用，不会因局部变量出栈被回收，
    每次失败都会泄漏一个线程+socket（密码错误在 AWD 中高频出现）。
    """
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh_client.connect(
            hostname=hostname or state_manager.hostname,
            port=port or state_manager.port,
            username=username or state_manager.username,
            password=password or state_manager.password,
            timeout=timeout
        )
    except Exception:
        try:
            ssh_client.close()
        except Exception:
            pass
        raise
    return ssh_client


def connect_sftp_client(hostname=None, port=None, username=None, password=None, timeout=10):
    ssh_client = connect_ssh_client(hostname, port, username, password, timeout)
    try:
        sftp_client = ssh_client.open_sftp()
    except Exception:
        try:
            ssh_client.close()
        except Exception:
            pass
        raise
    return ssh_client, sftp_client


def ssh_test(hostname=None, port=None, username=None, password=None, log_callback=print):
    has_conn = (state_manager.is_ssh and state_manager.hostname != '' and state_manager.port != 0
                and state_manager.username != '' and state_manager.password != '')
    if has_conn:
        log_callback("存在已经测试的ssh连接{0}@{1}".format(state_manager.username, state_manager.hostname))
        if hostname is None:
            # CLI 模式下复用已有连接；原实现这里是 pass，导致凭证被重新输入覆盖
            return True

    if hostname is None:
        hostname = input("请输入主机名：").strip()
        port = int(input("请输入端口号：").strip())
        username = input("请输入用户名：").strip()
        password = input("请输入密码：")

    log_callback(colored("测试中", 'red'))
    # 先暂存旧凭证：新连接失败时恢复，否则会丢失原本可用的目标
    old_state = (state_manager.hostname, state_manager.port,
                 state_manager.username, state_manager.password, state_manager.is_ssh)
    state_manager.hostname = hostname
    state_manager.port = port
    state_manager.username = username
    state_manager.password = password
    ssh_client = None
    try:
        ssh_client = connect_ssh_client()
        log_callback(colored("SSH 连接成功！", 'green'))
        state_manager.is_ssh = True
        return True
    except paramiko.AuthenticationException:
        log_callback("认证失败，请检查用户名和密码。")
    except paramiko.SSHException as ssh_ex:
        log_callback(f"SSH 连接异常: {ssh_ex}")
    except Exception as ex:
        log_callback(f"连接失败: {ex}")
    finally:
        if ssh_client is not None:
            try:
                ssh_client.close()
            except Exception:
                pass

    # 新目标不可用时恢复原有可用凭证
    (state_manager.hostname, state_manager.port,
     state_manager.username, state_manager.password, state_manager.is_ssh) = old_state
    if has_conn:
        log_callback("已回退到原有可用连接")
    return False


def shell():
    if not state_manager.is_ssh:
        print(colored("ssh连接未测试", 'red'))
        return

    ssh_client = None
    chan = None
    stop_event = threading.Event()
    try:
        ssh_client = connect_ssh_client()
        chan = ssh_client.invoke_shell()
        print("[*]正在使用shell 输入exit退出")

        def read_from_channel():
            # 用增量解码器，避免在 1024 边界切断多字节字符产生乱码
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            while not stop_event.is_set():
                try:
                    # select 阻塞等待，替代原来的 recv_ready() 忙等(单核 100% CPU)
                    readable, _, _ = select.select([chan], [], [], 0.2)
                except Exception:
                    break
                if not readable:
                    continue
                try:
                    data = chan.recv(4096)
                except Exception:
                    break
                if not data:
                    # 收到空数据表示对端已关闭 (比 chan.closed 更可靠，
                    # 网络半开时 closed 不会置位)
                    break
                text = decoder.decode(data).replace('\r', '')
                sys.stdout.write(text.replace('\u200b', ''))
                sys.stdout.flush()
            stop_event.set()
            print("\n[*] shell 已断开")

        def write_to_channel():
            while not stop_event.is_set():
                try:
                    command = input()
                except (EOFError, KeyboardInterrupt):
                    break
                if command.strip() == 'exit':
                    try:
                        chan.send('exit\n')
                    except Exception:
                        pass
                    break
                try:
                    chan.send(command + '\n')
                except Exception as exc:
                    print(f"[!] 发送失败，连接已失效: {exc}")
                    break
            stop_event.set()

        output_thread = threading.Thread(target=read_from_channel, daemon=True)
        input_thread = threading.Thread(target=write_to_channel, daemon=True)

        output_thread.start()
        input_thread.start()

        # 有超时的 join：原实现无超时，对端半开时主线程会永久阻塞
        input_thread.join()
        stop_event.set()
        output_thread.join(timeout=3)
    except Exception as exc:
        print(f"[!] shell 建立失败: {exc}")
    finally:
        for obj in (chan, ssh_client):
            if obj is not None:
                try:
                    obj.close()
                except Exception:
                    pass
