"""A line-oriented, interactive SSH session for the desktop workspace."""

import codecs
import re
import socket
import threading
from contextlib import closing
from queue import Empty, Full, Queue

from paramiko import AuthenticationException, BadHostKeyException

from defence import ssh

OUTPUT_LIMIT = 64 * 1024
CONTROL_CODES = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))|[\x00-\x08\x0b-\x1f\x7f]"
)


class SshTerminal:
    def __init__(self):
        self._lock = threading.Lock()
        self._stop = None
        self._input = None
        self._phase = "idle"
        self._error = None
        self._text = ""
        self._revision = 0

    def snapshot(self):
        with self._lock:
            return {"phase": self._phase, "error": self._error, "revision": self._revision}

    def output(self):
        with self._lock:
            return self._text

    def start(self, host, port, user, password, host_key):
        with self._lock:
            if self._stop is not None:
                raise ValueError("终端会话正在运行或关闭。")
            self._phase = "connecting"
            self._error = None
            self._text = ""
            self._revision += 1
            self._stop = stop = threading.Event()
            self._input = pending = Queue(maxsize=16)
            threading.Thread(
                target=self._run, args=(host, port, user, password, host_key, stop, pending),
                name="desktop-ssh-terminal", daemon=True,
            ).start()

    def send_line(self, line):
        if (not isinstance(line, str) or len(line) > 4096
                or any(char != "\t" and (ord(char) < 32 or char == "\x7f") for char in line)):
            raise ValueError("请输入一行终端内容，最长 4096 个字符。")
        self._queue(line.encode("utf-8") + b"\n")

    def interrupt(self):
        self._queue(b"\x03")

    def stop(self, *, discard=False):
        with self._lock:
            if self._stop is not None:
                self._stop.set()
                self._phase = "closing"
            if discard:
                self._text = ""
                self._error = None
                self._revision += 1

    def _queue(self, data):
        with self._lock:
            if self._phase != "open":
                raise ValueError("请先打开 SSH 终端会话。")
            try:
                self._input.put_nowait(data)
            except Full as exc:
                raise ValueError("终端发送队列已满，请稍后再试。") from exc

    def _append(self, text, stop):
        text = CONTROL_CODES.sub("", text)
        if not text:
            return
        with self._lock:
            if not stop.is_set():
                self._text = (self._text + text)[-OUTPUT_LIMIT:]
                self._revision += 1

    def _run(self, host, port, user, password, host_key, stop, pending):
        error = None
        try:
            with closing(ssh.connect_ssh_client(
                host, port, user, password, timeout=8, host_key=host_key,
            )) as client:
                if stop.is_set():
                    return
                # Opening the channel and requesting its PTY can block independently of recv().
                deadline = threading.Timer(8, client.close)
                deadline.daemon = True
                deadline.start()
                try:
                    channel = client.invoke_shell(term="dumb", width=120, height=36)
                finally:
                    deadline.cancel()
                with closing(channel):
                    channel.settimeout(0.2)
                    with self._lock:
                        if stop.is_set():
                            return
                        self._phase = "open"
                    self._exchange(channel, stop, pending)
        except BadHostKeyException:
            error = "SSH 主机密钥与验证时不同，请核对服务器指纹。"
        except AuthenticationException:
            error = "SSH 认证失败，请重新验证连接。"
        except Exception:
            error = "SSH 终端连接超时或中断，请检查服务器和连接。"
        finally:
            with self._lock:
                self._stop = None
                self._input = None
                self._phase = "idle"
                self._error = None if stop.is_set() else error

    def _exchange(self, channel, stop, pending):
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        while not stop.is_set():
            try:
                data = pending.get_nowait()
            except Empty:
                pass
            else:
                channel.sendall(data)
            try:
                chunk = channel.recv(8192)
            except socket.timeout:
                if channel.exit_status_ready():
                    break
                continue
            if not chunk:
                break
            self._append(decoder.decode(chunk), stop)
        self._append(decoder.decode(b"", final=True), stop)
