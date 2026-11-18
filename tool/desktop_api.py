"""Local bridge for the MetaAWD defensive workspace."""

import posixpath
import re
import threading
import time
from collections import deque
from contextlib import ExitStack, closing
from pathlib import Path

from defence import attacker_tools, file_processing, ssh, waf_manager, webshell_scanner
from defence._bootstrap import get_app_dir, get_runtime_dir
from defence.bugku_submit import BugkuBatch, preview_flags
from defence.request_logs import HIT_DECISIONS, read_request_preview, summarize_request
from defence.scan_removal import remove_malicious
from defence.ssh_terminal import SshTerminal
from defence.state import StateManager, state_manager

SITE_ROOT = "/var/www/html/"
SCAN_PAGE_SIZE = 100
PACKET_SYNC_INTERVAL = 5
PACKET_RETRY_INTERVAL = 15
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _text(data, key, label):
    value = data.get(key)
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError(f"请填写{label}。")
    return value.strip()


def _remote_directory(data, key, label):
    path = _text(data, key, label)
    if not path.startswith("/") or posixpath.normpath(path).strip("/") == "":
        raise ValueError(f"{label}须为服务器上的绝对目录，且不能是根目录。")
    return path


def _require_confirmation(data):
    if data.get("confirmed") is not True:
        raise ValueError("请在工作台中确认此操作。")


class DesktopService:
    def __init__(self):
        self._lock = threading.RLock()
        self._job = None
        self._job_version = 0
        self._monitor_stop = None
        self._monitor_ready = threading.Event()
        self._monitor_path = ""
        self._guard_stop = None
        self._connection = None
        self._host_key = None
        self._terminal = SshTerminal()
        self._bugku = BugkuBatch()
        self._events = deque(maxlen=160)
        self._event_id = 0
        self._attacker_store = get_runtime_dir("attacker") / attacker_tools.DEFAULT_SHELL_STORE
        self._attacker_output = get_runtime_dir("attacker") / "output.txt"
        self._attacker = attacker_tools.AttackerSession()
        self._load_attacker_session()
        self._report_id = 0
        self._scan = None
        self._results = []
        self._plan = None
        self._packet_count = 0
        self._packet_revision = 0
        self._packet_auto = None
        self._packet_last_checked = None
        self._packet_sync_error = None
        self._packet_hits = 0
        self._packet_hits_seen = 0
        self._closed = False
        self._waf_root = SITE_ROOT
        self._waf_log_all = False
        self._refresh_packet_count()

    def snapshot(self):
        with self._lock:
            return {
                "connection": self._connection,
                "terminal": self._terminal.snapshot(),
                "bugku": self._bugku.snapshot(),
                "attacker": {
                    "activeCount": len(self._attacker.active_urls),
                    "outputFile": str(self._attacker_output),
                    "shells": [
                        {
                            "number": shell.number,
                            "label": shell.label(),
                            "urlCount": len(shell.urls),
                            "payload": shell.payload,
                            "keyMethod": shell.key_method,
                            "key": shell.key,
                            "keyValue": shell.key_value,
                            "cmdMethod": shell.cmd_method,
                            "note": shell.note,
                        }
                        for shell in self._attacker.known_shells
                    ],
                },
                "job": self._job,
                "jobVersion": self._job_version,
                "monitor": {"state": self._monitor_status(), "path": self._monitor_path},
                "scan": self._scan,
                "scanDefaults": {
                    "threshold": webshell_scanner.DEFAULT_THRESHOLD,
                    "suspectRatio": webshell_scanner.SUSPECT_RATIO,
                    "types": list(webshell_scanner.TYPE_RULES),
                },
                "waf": {
                    "deployed": state_manager.waf_deployed,
                    "guard": self._guard_stop is not None and not self._guard_stop.is_set(),
                    "webRoot": self._waf_root,
                    "installDir": state_manager.remote_waf_dir,
                    "logDir": state_manager.remote_waf_log_dir,
                    "mode": state_manager.waf_mode,
                    "strict": state_manager.waf_strict_level,
                    "redirect": state_manager.waf_redirect_path or "/",
                    "logAll": self._waf_log_all,
                },
                "backupDir": file_processing.get_default_local_dir(),
                "packetCount": self._packet_count,
                "packetSync": {
                    "enabled": self._packet_auto is not None,
                    "directory": self._packet_auto[1] if self._packet_auto else None,
                    "interval": PACKET_SYNC_INTERVAL,
                    "retryInterval": PACKET_RETRY_INTERVAL,
                    "revision": self._packet_revision,
                    "lastCheckedAt": self._packet_last_checked,
                    "error": self._packet_sync_error,
                    "hitCursor": self._packet_hits,
                    "unreadHits": self._packet_hits - self._packet_hits_seen,
                },
                "plan": self._plan[1] if self._plan else None,
                "events": list(self._events),
            }

    def action(self, name, data):
        handlers = {
            "connect": self._connect,
            "terminal-open": self._open_terminal,
            "terminal-close": self._close_terminal,
            "terminal-send": self._send_terminal,
            "terminal-interrupt": self._interrupt_terminal,
            "bugku-submit": self._submit_bugku,
            "bugku-stop": self._stop_bugku,
            "attack-scan": self._attack_scan,
            "attack-read": self._attack_read,
            "attack-check": self._attack_check,
            "attack-exec": self._attack_exec,
            "attack-upload": self._attack_upload,
            "scan": self._start_scan,
            "report": self._save_report,
            "plan-quarantine": self._plan_quarantine,
            "quarantine": self._apply_quarantine,
            "start-monitor": self._start_monitor,
            "pause-monitor": self._pause_monitor,
            "stop-monitor": self._stop_monitor,
            "deploy-waf": self._deploy_waf,
            "update-waf-capture": self._update_waf_capture,
            "remove-waf": self._remove_waf,
            "start-guard": self._start_guard,
            "stop-guard": self._stop_guard,
            "sync-packets": self._sync_packets,
            "set-packet-auto-sync": self._set_packet_auto_sync,
            "ack-packet-hits": self._ack_packet_hits,
            "clear-packets": self._clear_packets,
            "backup": self._backup,
            "restore": self._restore,
        }
        if not isinstance(data, dict) or not isinstance(name, str) or name not in handlers:
            return {"ok": False, "message": "未知操作。"}
        try:
            with self._lock:
                handlers[name](data)
            return {"ok": True}
        except (ValueError, OSError) as exc:
            return {"ok": False, "message": str(exc)}

    def scan_results(self, offset):
        with self._lock:
            offset = max(0, offset) if type(offset) is int else 0
            items = self._results[offset : offset + SCAN_PAGE_SIZE]
            return {
                "total": len(self._results),
                "items": [
                    {**{key: item[key] for key in ("file", "type", "score", "verdict")},
                     "removed": item.get("removed", False)}
                    for item in items
                ],
            }

    def list_packets(self):
        with self._lock:
            host = self._log_host()
        packets = []
        for item in waf_manager.list_local_request_logs(host):
            try:
                summary = summarize_request(item["path"], item["revision"])
            except FileNotFoundError:
                continue
            packets.append({"name": item["name"], "mtime": item["mtime"], **summary})
        with self._lock:
            if self._log_host() == host:
                self._packet_count = len(packets)
        return sorted(packets, key=lambda packet: packet["capturedAt"] or packet["mtime"], reverse=True)

    def packet_path(self, name):
        if (not isinstance(name, str) or not name.endswith(".http")
                or any(char in name for char in "/\\:\x00")):
            raise ValueError("请选择列表中的请求日志。")
        with self._lock:
            directory = waf_manager.get_local_log_dir(self._log_host()).resolve()
        path = directory / name
        if path.is_symlink() or path.resolve().parent != directory or not path.is_file():
            raise ValueError("日志文件已移除或不在当前工作目录内。")
        return path

    def read_packet(self, name):
        return read_request_preview(self.packet_path(name))

    def terminal_output(self):
        return self._terminal.output()

    def bugku_results(self):
        return self._bugku.results()

    def bugku_preview(self, flags, options):
        return preview_flags(flags, options)
    def attack_urls(self, scope="active", number=None):
        """返回探活目标或某条后门记录中的站点，供界面分开展示。"""
        with self._lock:
            if scope == "shell":
                if type(number) is not int:
                    raise ValueError("请选择一个后门记录。")
                shell = self._attacker.get_shell(number)
                if shell is None:
                    raise ValueError("所选后门不存在，请刷新后重试。")
                items = list(shell.urls)
            elif scope == "active":
                items = list(self._attacker.active_urls)
            else:
                raise ValueError("未知的目标范围。")
        return {"total": len(items), "items": items}

    def _load_attacker_session(self):
        paths = [self._attacker_store, get_app_dir() / attacker_tools.DEFAULT_SHELL_STORE]
        for path in paths:
            if not path.is_file():
                continue
            try:
                self._attacker = attacker_tools.load_session(path)
                self._log("attack", f"已加载后门配置 · {path}")
            except Exception as exc:
                self._log("attack", f"加载后门配置失败 · {exc}", "error")
            return

    def _selected_attack_shell(self, data):
        number = data.get("shellNumber")
        if type(number) is not int:
            raise ValueError("请选择一个已检测的后门。")
        shell = self._attacker.get_shell(number)
        if shell is None:
            raise ValueError("所选后门不存在，请刷新后重试。")
        return shell

    @staticmethod
    def _attack_method(data, key, label, *, allow_none=False):
        value = data.get(key)
        allowed = {"GET", "POST"}
        if allow_none:
            allowed.add("0")
        if value not in allowed:
            raise ValueError(f"请选择{label}。")
        return value

    def _attack_scan(self, data):
        pattern = _text(data, "urlPattern", "URL 模板")
        if "?" not in pattern:
            raise ValueError("URL 模板必须包含 ? 作为编号占位符。")
        start, end = data.get("start"), data.get("end")
        if (type(start) is not int or type(end) is not int or start < 0 or end < start
                or end > 65535 or end - start > 4095):
            raise ValueError("编号须为 0–65535 的正序区间，单次最多探测 4096 个目标。")
        output_file = _text(data, "outputFile", "存活文件")

        def scan():
            urls = attacker_tools.scan_alive(
                pattern, output_file=output_file, start=start, end=end,
                log_callback=self._logger("attack"),
            )
            with self._lock:
                self._attacker.set_active_urls(urls)

        self._start_job("attack-scan", "attack", scan)

    def _attack_read(self, data):
        path = _text(data, "outputFile", "存活文件")

        def read():
            urls = attacker_tools.read_active_file(path, log_callback=self._logger("attack"))
            with self._lock:
                self._attacker.set_active_urls(urls)
            self._log("attack", f"当前存活目标 {len(urls)} 个", "success")

        self._start_job("attack-read", "attack", read)

    def _attack_check(self, data):
        path = _text(data, "path", "后门路径")
        key_method = self._attack_method(data, "keyMethod", "key 方式", allow_none=True)
        cmd_method = self._attack_method(data, "cmdMethod", "命令方式")
        key = data.get("key", "")
        key_value = data.get("keyValue", "")
        if not isinstance(key, str) or not isinstance(key_value, str):
            raise ValueError("key 参数格式无效。")
        payload = _text(data, "payload", "命令参数名")
        active_urls = list(self._attacker.active_urls)
        if not active_urls:
            raise ValueError("请先探活或从文件载入目标。")

        def check():
            shell = attacker_tools.check_known_backdoor(
                active_urls, path, key_method=key_method, key=key.strip(),
                key_value=key_value.strip(), cmd_method=cmd_method, payload=payload,
                log_callback=self._logger("attack"),
            )
            if shell:
                with self._lock:
                    self._attacker.add_shell(shell)
                self._log("attack", f"已添加后门编号 {shell.number}", "success")

        self._start_job("attack-check", "attack", check)

    def _attack_exec(self, data):
        shell = self._selected_attack_shell(data)
        command = _text(data, "command", "执行内容")
        self._start_job(
            "attack-exec", "attack",
            lambda: attacker_tools.execute_shell_command(
                shell, command, log_callback=self._logger("attack")
            ),
        )

    def _attack_upload(self, data):
        _require_confirmation(data)
        shell = self._selected_attack_shell(data)
        remote_dir = _remote_directory(data, "remoteDir", "写入目录")
        url_dir = _text(data, "urlDir", "Web 访问目录")
        if (not url_dir.startswith("/") or url_dir.startswith("//") or "\\" in url_dir
                or "\r" in url_dir or "\n" in url_dir):
            raise ValueError("Web 访问目录须为站点内以 / 开头的路径。")
        with_key = data.get("withKey")
        if type(with_key) is not bool:
            raise ValueError("请选择是否生成带 key 的后门。")

        def upload():
            new_shell = attacker_tools.upload_generated_backdoor(
                shell, remote_dir=remote_dir, url_dir=url_dir, with_key=with_key,
                log_callback=self._logger("attack"),
            )
            if not new_shell:
                raise RuntimeError("没有成功写入任何新后门。")
            with self._lock:
                self._attacker.add_shell(new_shell)
                saved = attacker_tools.save_session(self._attacker, self._attacker_store)
            self._log("attack", f"已添加新后门编号 {new_shell.number}", "success")
            self._log("attack", f"已保存后门配置 · {saved}", "success")

        self._start_job("attack-upload", "attack", upload)
    def shutdown(self):
        with self._lock:
            self._closed = True
            self._terminal.stop()
            self._bugku.stop()
            self._stop_packet_auto_sync()
            if self._monitor_stop:
                self._monitor_stop.set()
            if self._guard_stop:
                self._guard_stop.set()

    def _log(self, area, message, level="info"):
        message = ANSI.sub("", str(message)).strip()
        if not message:
            return
        with self._lock:
            self._event_id += 1
            self._events.append({
                "id": self._event_id,
                "time": time.time(),
                "area": area,
                "level": level,
                "message": message[:2400],
            })

    def _logger(self, area):
        return lambda message: self._log(area, message)

    def _require_ssh(self):
        if self._connection is None:
            raise ValueError("请先在 SSH 连接页验证服务器。")

    def _require_idle(self):
        if self._job:
            raise ValueError("有任务正在运行，请等它结束。")

    def _start_job(self, name, area, task, *, remote=False):
        self._require_idle()
        if remote:
            self._require_ssh()
        self._job = name

        def run():
            try:
                task()
            except Exception as exc:
                self._log(area, str(exc) or type(exc).__name__, "error")
            finally:
                with self._lock:
                    self._job = None
                    self._job_version += 1

        # 文件类任务在窗口关闭后仍需走完本轮写入和清理。
        threading.Thread(target=run, name=f"desktop-{name}", daemon=False).start()

    def _connect(self, data):
        if self._monitor_stop or self._guard_stop:
            raise ValueError("请先停止文件监控和 WAF 守护，再切换连接。")
        host = _text(data, "host", "主机地址")
        if host in {".", ".."} or any(char.isspace() or char in "/\\" for char in host):
            raise ValueError("请输入有效的主机名或 IP 地址。")
        user = _text(data, "user", "用户名")
        port = data.get("port")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("端口须为 1–65535 的整数。")
        password = data.get("password", "")
        if not isinstance(password, str):
            raise ValueError("密码格式无效。")

        def connect():
            keys = []
            verified = ssh.ssh_test(host, port, user, password, self._logger("ssh"), on_verified=keys.append)
            if not verified or not keys:
                raise RuntimeError("连接验证失败，请查看连接日志。")
            new_connection = {"host": host, "port": port, "user": user}
            with self._lock:
                changed = self._connection != new_connection
                if changed or self._host_key != keys[0]:
                    self._terminal.stop(discard=True)
                self._host_key = keys[0]
                if changed:
                    self._stop_packet_auto_sync()
                    self._packet_last_checked = None
                    self._packet_sync_error = None
                    self._packet_hits_seen = self._packet_hits
                    defaults = StateManager()
                    state_manager.waf_deployed = False
                    state_manager.remote_waf_dir = defaults.remote_waf_dir
                    state_manager.remote_waf_path = defaults.remote_waf_path
                    state_manager.remote_waf_log_dir = defaults.remote_waf_log_dir
                    state_manager.waf_mode = defaults.waf_mode
                    state_manager.waf_strict_level = defaults.waf_strict_level
                    state_manager.waf_redirect_path = defaults.waf_redirect_path
                    self._waf_root = SITE_ROOT
                    self._waf_log_all = False
                    self._plan = None
                self._connection = new_connection
                self._refresh_packet_count()
            self._log("ssh", f"已验证 {user}@{host}", "success")

        self._start_job("connect", "ssh", connect)

    def _open_terminal(self, _data):
        self._require_ssh()
        if self._closed or self._job == "connect" or self._host_key is None:
            raise ValueError("请完成 SSH 连接验证后再打开终端。")
        connection = self._connection
        self._terminal.start(
            connection["host"], connection["port"], connection["user"],
            state_manager.password, self._host_key,
        )

    def _close_terminal(self, _data):
        self._terminal.stop()

    def _send_terminal(self, data):
        self._terminal.send_line(data.get("line"))

    def _interrupt_terminal(self, _data):
        self._terminal.interrupt()

    def _submit_bugku(self, data):
        if self._closed:
            raise ValueError("工作台正在关闭。")
        self._bugku.start(data.get("token"), data.get("flags"), data.get("options"))

    def _stop_bugku(self, _data):
        self._bugku.stop()

    def _monitor_status(self):
        if self._monitor_stop is None:
            return "idle"
        if self._monitor_stop.is_set():
            return "stopping"
        if file_processing.is_paused:
            return "paused"
        return "running" if self._monitor_ready.is_set() else "starting"

    def _start_monitor(self, data):
        self._require_idle()
        self._require_ssh()
        if self._monitor_stop:
            raise ValueError("文件监控已启动。")
        path = _remote_directory(data, "path", "监控目录")
        stop = threading.Event()
        self._monitor_stop = stop
        self._monitor_ready.clear()
        self._monitor_path = path
        host = state_manager.hostname
        port = state_manager.port
        user = state_manager.username
        password = state_manager.password

        def monitor():
            try:
                self._log("monitor", f"正在建立文件基线 · {path}")
                file_processing.monitor_directory_changes(
                    host, port, user, password, path, is_delete=False,
                    log_callback=self._logger("monitor"), is_gui=True,
                    stop_event=stop, ready_callback=self._monitor_ready.set,
                )
            except Exception as exc:
                self._log("monitor", str(exc), "error")
            finally:
                with self._lock:
                    self._monitor_stop = None

        threading.Thread(target=monitor, name="desktop-monitor", daemon=True).start()

    def _pause_monitor(self, _data):
        if self._monitor_status() not in {"running", "paused"}:
            raise ValueError("当前没有可暂停或继续的监控。")
        file_processing.is_paused = not file_processing.is_paused
        self._log("monitor", "监控已暂停" if file_processing.is_paused else "监控已继续")

    def _stop_monitor(self, _data):
        if self._monitor_stop:
            self._monitor_stop.set()

    def _start_scan(self, data):
        mode = data.get("mode")
        if mode not in ("local", "remote"):
            raise ValueError("请选择扫描范围。")
        self._require_idle()
        if mode == "remote":
            self._require_ssh()
            target = _remote_directory(data, "target", "扫描目录")
        else:
            target = _text(data, "target", "扫描路径")
            if not (Path(target).is_file() or Path(target).is_dir()):
                raise ValueError("本地扫描目录或文件不存在。")
        threshold = data.get("threshold")
        if type(threshold) is not int or threshold <= 0:
            raise ValueError("扫描阈值须为正整数。")
        auto_delete = data.get("autoDelete") is True
        if auto_delete:
            _require_confirmation(data)
        self._report_id += 1
        self._scan = {
            "id": self._report_id, "mode": mode, "target": target, "threshold": threshold,
            "status": "running", "total": 0, "malicious": 0, "suspicious": 0,
            "removed": 0, "removalFailed": 0, "quarantineDir": None, "reportPath": None,
            "host": self._connection if mode == "remote" else None,
        }
        self._results = []
        self._plan = None

        def scan():
            try:
                engine = webshell_scanner.scan_remote if mode == "remote" else webshell_scanner.scan_local
                results, total = engine(target, threshold=threshold, log_callback=self._logger("scan"))
                malicious = sum(item["verdict"] == "malicious" for item in results)
                removed, failed, directory = set(), 0, None
                if auto_delete and malicious:
                    try:
                        with ExitStack() as stack:
                            sftp = self._scan_sftp(stack, self._scan)
                            removed, failed, directory = remove_malicious(
                                results, target, threshold, self._logger("scan"), sftp=sftp, host=self._scan["host"],
                            )
                    except Exception as exc:
                        self._log("scan", f"自动移除失败 · {exc}", "error")
                        failed = malicious - len(removed)
                    for item in results:
                        item["removed"] = item["file"] in removed
                with self._lock:
                    self._results = results
                    self._scan = {
                        **self._scan, "status": "done", "total": total,
                        "malicious": malicious, "suspicious": len(results) - malicious,
                        "removed": len(removed), "removalFailed": failed, "quarantineDir": directory,
                    }
                self._log("scan", f"已扫描 {total} 个文件，恶意 {malicious}，可疑 {len(results) - malicious}", "success")
            except Exception:
                with self._lock:
                    self._scan = {**self._scan, "status": "failed"}
                raise

        self._log("scan", f"开始扫描 {target}")
        self._start_job("scan", "scan", scan, remote=mode == "remote")

    def _finished_scan(self):
        if not self._scan or self._scan["status"] != "done":
            raise ValueError("当前没有已完成的扫描。")
        return self._scan

    def _save_report(self, _data):
        scan = self._finished_scan()

        def save():
            path = webshell_scanner.save_report(self._results, scan["total"], threshold=scan["threshold"])
            if not path:
                raise RuntimeError("保存报告失败，请检查本地目录权限。")
            with self._lock:
                self._scan = {**self._scan, "reportPath": path}
            self._log("scan", f"报告已保存 · {path}", "success")

        self._start_job("report", "scan", save)

    def _scan_site(self):
        scan = self._finished_scan()
        if scan["mode"] == "remote" and scan["host"] != self._connection:
            raise ValueError("当前连接与扫描目标不同，请在当前服务器上重新扫描。")
        return scan

    def _scan_sftp(self, stack, scan):
        if scan["mode"] == "local":
            return None
        client, sftp = ssh.connect_sftp_client()
        stack.enter_context(closing(client))
        return stack.enter_context(closing(sftp))

    def _plan_quarantine(self, _data):
        scan = self._scan_site()
        malicious = [item for item in self._results if item["level"] == 3 and not item.get("removed")]
        if not malicious:
            raise ValueError("扫描中没有待处置的恶意文件。")

        def prepare():
            with ExitStack() as stack:
                sftp = self._scan_sftp(stack, scan)
                plan = webshell_scanner.build_quarantine_plan(malicious, self._logger("scan"), sftp)
            files = [
                {"file": item["file"], "lines": sum(line["ok"] for line in item["lines"])}
                for item in plan
            ]
            info = {"scanId": scan["id"], "files": len(files), "items": files[:100]}
            with self._lock:
                self._plan = (plan, info)
            self._log("scan", f"注释预览已生成 · {len(files)} 个文件")

        self._start_job("plan-quarantine", "scan", prepare, remote=scan["mode"] == "remote")

    def _apply_quarantine(self, data):
        _require_confirmation(data)
        scan = self._scan_site()
        if not self._plan or not self._plan[0] or data.get("scanId") != scan["id"]:
            raise ValueError("请先生成当前扫描结果的注释预览。")
        plan = self._plan[0]

        def apply():
            with self._lock:
                self._plan = None
            with ExitStack() as stack:
                sftp = self._scan_sftp(stack, scan)
                stats = webshell_scanner.apply_quarantine(plan, self._logger("scan"), sftp_client=sftp)
            for path, reason in stats["failed"]:
                self._log("scan", f"未处理 {path} · {reason}", "error")
            self._log("scan", f"已注释 {stats['lines']} 行，保留 {len(stats['backups'])} 份备份")

        self._start_job("quarantine", "scan", apply, remote=scan["mode"] == "remote")

    def _deploy_waf(self, data):
        _require_confirmation(data)
        root = _remote_directory(data, "webRoot", "站点目录")
        directory = _remote_directory(data, "installDir", "安装目录")
        logs = _remote_directory(data, "logDir", "日志目录")
        mode, strict = data.get("mode"), data.get("strict")
        if mode not in (1, 2) or strict not in (1, 2, 3):
            raise ValueError("请选择 WAF 的拦截方式和严格程度。")
        redirect = _text(data, "redirect", "跳转路由") if mode == 2 else "/"
        if mode == 2 and (not redirect.startswith("/") or redirect.startswith("//")
                          or "\r" in redirect or "\n" in redirect or "\\" in redirect):
            raise ValueError("跳转路由须为站点内以 / 开头的路径。")
        log_all = data.get("logAll") is True

        def deploy():
            result = waf_manager.deploy_waf(
                root, directory, self._logger("waf"), remote_log_dir=logs, waf_mode=mode,
                waf_strict_level=strict, waf_redirect_path=redirect, log_all=log_all,
            )
            with self._lock:
                self._waf_root = root
                self._waf_log_all = log_all
            self._log("waf", f"已部署 WAF · {result['inject_result']['injected']} 个文件", "success")

        self._start_job("deploy-waf", "waf", deploy, remote=True)

    def _remove_waf(self, data):
        _require_confirmation(data)
        root = _remote_directory(data, "webRoot", "站点目录")
        directory = _remote_directory(data, "installDir", "安装目录")

        def remove():
            result = waf_manager.undeploy_waf(root, directory, self._logger("waf"))
            if not result.get("ok"):
                raise RuntimeError("WAF 卸载未完成，请检查操作日志。")
            self._log("waf", "WAF 已卸载", "success")

        self._require_idle()
        self._require_ssh()
        self._stop_guard({})
        self._start_job("remove-waf", "waf", remove, remote=True)

    def _update_waf_capture(self, data):
        _require_confirmation(data)
        directory = _remote_directory(data, "installDir", "安装目录")

        def update():
            waf_manager.upload_waf(directory, self._logger("waf"), update_only=True)
            self._log("waf", "已更新采集模板。之后记录的请求会包含来源和处理结果。", "success")

        self._start_job("update-waf-capture", "waf", update, remote=True)

    def _start_guard(self, _data):
        self._require_idle()
        self._require_ssh()
        if not state_manager.waf_deployed or self._guard_stop:
            raise ValueError("WAF 守护只对本次已部署的 WAF 开放。")
        stop = threading.Event()
        self._guard_stop = stop
        directory = state_manager.remote_waf_dir

        def guard():
            try:
                while not stop.wait(5):
                    with self._lock:
                        if self._job or stop.is_set():
                            continue
                        self._job = "check-waf"
                    try:
                        waf_manager.check_and_restore_waf(directory, self._logger("waf"))
                    except Exception as exc:
                        self._log("waf", f"WAF 守护检查失败 · {exc}", "error")
                    finally:
                        with self._lock:
                            self._job = None
            finally:
                with self._lock:
                    self._guard_stop = None

        self._log("waf", "WAF 守护已启动")
        threading.Thread(target=guard, name="desktop-waf-guard", daemon=True).start()

    def _stop_guard(self, _data):
        if self._guard_stop:
            self._guard_stop.set()
            self._log("waf", "WAF 守护已停止")

    def _log_host(self):
        return self._connection["host"] if self._connection else "default"

    def _refresh_packet_count(self):
        try:
            self._packet_count = len(waf_manager.list_local_request_logs(self._log_host()))
        except OSError as exc:
            self._packet_count = 0
            self._log("packets", f"读取本地日志失败 · {exc}", "error")

    def _sync_packets(self, data):
        directory = _remote_directory(data, "logDir", "日志目录")
        self._start_job(
            "sync-packets", "packets", lambda: self._collect_packets(directory), remote=True,
        )

    def _set_packet_auto_sync(self, data):
        enabled = data.get("enabled")
        if type(enabled) is not bool:
            raise ValueError("请选择自动同步的开关状态。")
        if not enabled:
            self._stop_packet_auto_sync()
            return
        self._require_ssh()
        if self._closed:
            raise ValueError("工作台正在关闭。")
        directory = _remote_directory(data, "logDir", "日志目录")
        if self._packet_auto and self._packet_auto[1] == directory:
            return

        self._stop_packet_auto_sync()
        stop = threading.Event()
        self._packet_auto = (stop, directory)
        self._packet_sync_error = None
        self._packet_last_checked = None
        threading.Thread(
            target=self._poll_packets, args=(stop, directory), name="desktop-packet-poll",
            daemon=True,
        ).start()

    def _stop_packet_auto_sync(self):
        if self._packet_auto:
            self._packet_auto[0].set()
            self._packet_auto = None

    def _poll_packets(self, stop, directory):
        delay = 0
        while not stop.wait(delay):
            with self._lock:
                if stop.is_set():
                    return
                if self._job:
                    delay = 1
                    continue
                finished = threading.Event()

                def collect():
                    try:
                        self._collect_packets(directory, stop_event=stop)
                    finally:
                        finished.set()

                self._start_job("auto-sync-packets", "packets", collect, remote=True)
            finished.wait()
            with self._lock:
                delay = PACKET_RETRY_INTERVAL if self._packet_sync_error else PACKET_SYNC_INTERVAL

    def _collect_packets(self, directory, *, stop_event=None):
        automatic = stop_event is not None
        new_files = []
        paths = []
        message = None
        try:
            paths = waf_manager.sync_remote_logs(
                directory, self._logger("packets"), on_new_file=new_files.append,
                raise_on_transport_error=True, io_timeout=10, stop_event=stop_event,
            )
        except Exception as exc:
            message = str(exc) or ("连接或读取超时" if isinstance(exc, TimeoutError) else type(exc).__name__)

        hits = 0
        for path in new_files:
            try:
                info = path.stat()
                revision = (info.st_mtime_ns, info.st_ctime_ns, info.st_size)
                if summarize_request(str(path), revision)["decision"] in HIT_DECISIONS:
                    hits += 1
            except OSError as exc:
                self._log("packets", f"读取请求判定失败 · {exc}", "error")
        needs_refresh = bool(new_files or paths or not automatic)
        if needs_refresh:
            self._refresh_packet_count()
        with self._lock:
            if message is None:
                self._packet_last_checked = time.time()
            changed = message != self._packet_sync_error
            self._packet_sync_error = message
            self._packet_hits += hits
            if needs_refresh:
                self._packet_revision += 1
        if message and (changed or not automatic):
            self._log("packets", f"请求同步失败 · {message}", "error")
        if new_files or (not automatic and not message):
            self._log("packets", f"已同步 {len(new_files)} 个新请求 · WAF 命中 {hits} 条", "success")

    def _ack_packet_hits(self, data):
        cursor = data.get("through")
        if type(cursor) is not int or not 0 <= cursor <= self._packet_hits:
            raise ValueError("请求提示已更新，请重试。")
        self._packet_hits_seen = max(self._packet_hits_seen, cursor)

    def _clear_packets(self, data):
        _require_confirmation(data)

        def clear():
            removed = waf_manager.clear_local_request_logs(self._log_host())
            self._refresh_packet_count()
            with self._lock:
                self._packet_revision += 1
                self._packet_hits_seen = self._packet_hits
            self._log("packets", f"已清理 {len(removed)} 个本地请求日志")

        self._start_job("clear-packets", "packets", clear)

    def _backup(self, data):
        root = _remote_directory(data, "webRoot", "站点目录")
        destination = _text(data, "destination", "下载目录")

        def backup():
            if not file_processing.tar(root, destination, self._logger("backup")):
                raise RuntimeError("备份未完成，请检查操作日志。")

        self._start_job("backup", "backup", backup, remote=True)

    def _restore(self, data):
        _require_confirmation(data)
        root = _remote_directory(data, "webRoot", "站点目录")
        archive = _text(data, "archive", "备份文件")
        if not Path(archive).is_file():
            raise ValueError("所选备份文件不存在。")

        def restore():
            if not file_processing.deploy_tar(archive, root, self._logger("backup")):
                raise RuntimeError("恢复未完成，请检查操作日志。")

        self._start_job("restore", "backup", restore, remote=True)
