"""Submit flags supplied by the operator to the Bugku scoreboard."""

import csv
import json
import os
import tempfile
import threading
from pathlib import Path

import requests

SUBMIT_URL = "https://ctf.bugku.com/pvp/submit.html"
MAX_FLAGS = 256
MAX_INPUT = 65536
MAX_RESPONSE = 4096
DEFAULT_OPTIONS = {"intervalMs": 250, "timeoutSeconds": 5, "maxFlags": MAX_FLAGS, "duplicates": "skip"}

VERDICTS = {
    "unauthorized": ("token错误", "token无效", "token不正确", "invalid token", "unauthorized"),
    "accepted": ("success", "提交成功", "flag提交成功", "flag正确", "correct flag"),
    "duplicate": ("已提交", "flag已提交", "flag已经提交", "already submitted"),
    "rejected": ("提交失败", "flag错误", "flag不正确", "flag无效", "flag已过期", "invalid flag", "incorrect flag"),
}
REPORTS = {
    "accepted": "平台确认提交成功。",
    "duplicate": "平台提示已提交过。",
    "rejected": "平台拒绝了这条 flag。",
    "unknown": "平台响应未能确认结果，请在比赛页面核对。",
}


def _validate_options(options):
    if options is None:
        return DEFAULT_OPTIONS
    if not isinstance(options, dict):
        raise ValueError("请检查提交参数。")
    values = {**DEFAULT_OPTIONS, **options}
    for key, low, high, label in (
        ("intervalMs", 250, 10000, "提交间隔（毫秒）"),
        ("timeoutSeconds", 1, 60, "请求超时（秒）"),
        ("maxFlags", 1, MAX_FLAGS, "单批上限"),
    ):
        value = values[key]
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"{label}须为 {low} 至 {high} 的整数。")
    if values["duplicates"] not in ("skip", "reject"):
        raise ValueError("请选择重复项处理方式。")
    return values


def _validate_token(token):
    if not isinstance(token, str) or not token.strip():
        raise ValueError("请输入 Bugku 队伍 Token。")
    token = token.strip()
    if len(token) > 256 or any(char.isspace() or ord(char) < 32 for char in token):
        raise ValueError("请检查 Token 格式。")
    return token


def _prepare(text, options):
    if not isinstance(text, str) or len(text) > MAX_INPUT:
        raise ValueError("flag 输入超过 65536 个字符。")
    rows = []
    seen = set()
    duplicates = []
    blanks = 0
    for line, value in enumerate(text.splitlines(), 1):
        flag = value.strip()
        if not flag:
            blanks += 1
            continue
        if len(flag) > 2048 or any(ord(char) < 32 or char == "\x7f" for char in flag):
            raise ValueError(f"第 {line} 行 flag 格式无效。")
        if flag in seen:
            duplicates.append(line)
            continue
        rows.append((line, flag))
        seen.add(flag)
    if not rows:
        raise ValueError("请输入至少一条 flag。")
    if len(rows) > options["maxFlags"]:
        raise ValueError(f"有效条目共 {len(rows)} 条，超过单批上限 {options['maxFlags']}。")
    if duplicates and options["duplicates"] == "reject":
        raise ValueError(f"第 {duplicates[0]} 行与前面的 flag 重复，请先去重。")
    return rows, duplicates, blanks


def preview_flags(text, options):
    rows, duplicates, blanks = _prepare(text, _validate_options(options))
    return {"count": len(rows), "duplicates": len(duplicates), "blanks": blanks}


def export_results(rows, destination):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8-sig", newline="", dir=Path(destination).parent,
            suffix=".part", delete=False,
        ) as output:
            temporary = Path(output.name)
            writer = csv.writer(output)
            writer.writerow(("输入行", "状态", "结果"))
            writer.writerows((row["line"], row["status"], row["message"]) for row in rows)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _verdict(body):
    text = body.decode("utf-8-sig", errors="replace").strip()
    try:
        payload = json.loads(text)
    except (ValueError, RecursionError):
        payload = text
    message = payload
    if isinstance(payload, dict):
        message = payload.get("msg") or payload.get("message")
    if isinstance(message, str):
        phrase = message.strip().rstrip("!！。 .").casefold()
        for verdict, labels in VERDICTS.items():
            if phrase in labels:
                return verdict
    if isinstance(payload, dict):
        if payload.get("success") is True:
            return "accepted"
        if payload.get("success") is False:
            return "rejected"
    return "unknown"


def _submit(session, token, flag, *, timeout=5):
    try:
        with session.get(
            SUBMIT_URL, params={"token": token, "flag": flag},
            timeout=(timeout, timeout), allow_redirects=False, stream=True,
        ) as response:
            if response.status_code in (401, 403):
                return "rejected", f"平台拒绝授权（HTTP {response.status_code}）。", True
            if response.status_code == 429:
                return "unknown", "平台限流（HTTP 429），已暂停本批。", True
            if not 200 <= response.status_code < 300:
                return "unknown", f"平台返回 HTTP {response.status_code}，请核对结果。", True
            body = bytearray()
            for chunk in response.iter_content(chunk_size=MAX_RESPONSE):
                body.extend(chunk)
                if len(body) > MAX_RESPONSE:
                    return "unknown", REPORTS["unknown"], False
            verdict = _verdict(body)
            if verdict == "unauthorized":
                return "rejected", "平台拒绝了 Token，已停止本批。", True
            return verdict, REPORTS[verdict], False
    except requests.RequestException:
        # Request exceptions can contain the full URL with both credentials and flag.
        return "unknown", "网络请求中断，提交结果未确认。", True


class BugkuBatch:
    def __init__(self):
        self._lock = threading.Lock()
        self._stop = None
        self._total = 0
        self._duplicates = 0
        self._revision = 0
        self._results = []

    def start(self, token, text, options=None):
        token = _validate_token(token)
        options = _validate_options(options)
        rows, duplicates, _ = _prepare(text, options)
        with self._lock:
            if self._stop is not None:
                raise ValueError("已有 Bugku 批次正在提交。")
            self._stop = stop = threading.Event()
            self._total = len(rows)
            self._duplicates = len(duplicates)
            self._results = []
            self._revision += 1
            threading.Thread(
                target=self._run, args=(token, rows, options, stop), name="desktop-bugku-submit",
                daemon=True,
            ).start()

    def stop(self):
        with self._lock:
            if self._stop is not None:
                self._stop.set()

    def snapshot(self):
        with self._lock:
            return {
                "running": self._stop is not None,
                "stopping": self._stop is not None and self._stop.is_set(),
                "total": self._total, "done": len(self._results),
                "duplicates": self._duplicates, "revision": self._revision,
            }

    def results(self):
        with self._lock:
            return list(self._results)

    def _run(self, token, rows, options, stop):
        try:
            with requests.Session() as session:
                for index, (line, flag) in enumerate(rows):
                    if stop.is_set():
                        break
                    verdict, message, halt = _submit(session, token, flag, timeout=options["timeoutSeconds"])
                    with self._lock:
                        self._results.append({"line": line, "status": verdict, "message": message})
                        self._revision += 1
                    if halt or (index + 1 < len(rows) and stop.wait(options["intervalMs"] / 1000)):
                        break
        finally:
            with self._lock:
                for line, _ in rows[len(self._results):]:
                    self._results.append({"line": line, "status": "skipped", "message": "未发送。"})
                self._stop = None
                self._revision += 1
