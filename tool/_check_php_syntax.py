# -*- coding: utf-8 -*-
"""PHP WAF 文件静态校验：剥离字符串/注释后检查括号配对 + 关键函数存在性"""
import glob
import io
import re
import sys


def strip_php(src):
    """去掉单引号串、双引号串、heredoc/nowdoc、// # 行注释、/* */ 块注释"""
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        # heredoc / nowdoc
        m = re.match(r"<<<[ \t]*['\"]?([A-Za-z_]\w*)['\"]?\r?\n", src[i:])
        if m:
            tag = m.group(1)
            body_start = i + m.end()
            end_m = re.search(r"^[ \t]*" + re.escape(tag) + r"\b", src[body_start:], re.M)
            if end_m:
                i = body_start + end_m.end()
            else:
                i = n
            continue
        if c == "/" and nxt == "/":
            j = src.find("\n", i); i = n if j < 0 else j; continue
        if c == "#":
            j = src.find("\n", i); i = n if j < 0 else j; continue
        if c == "/" and nxt == "*":
            j = src.find("*/", i + 2); i = n if j < 0 else j + 2; continue
        if c in ("'", '"'):
            quote = c
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2; continue
                if src[j] == quote:
                    break
                j += 1
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def check(path):
    src = io.open(path, encoding="utf-8").read()
    skel = strip_php(src)
    problems = []
    for o, c in [("{", "}"), ("(", ")"), ("[", "]")]:
        no, nc = skel.count(o), skel.count(c)
        if no != nc:
            problems.append(f"{o}{c}={no}/{nc}")

    required = ["function wafLogAll", "function saveRequest", "wafLogAll()"]
    missing = [r for r in required if r not in src]
    if missing:
        problems.append("缺少: " + ", ".join(missing))

    # 全量记录模式下不能误拦正常请求
    if "if ($suspicious && wafGetMode() === 2)" not in src:
        problems.append("exit 条件未加 $suspicious 保护")

    tags = len(re.findall(r"<\?php", src))
    if tags == 0:
        problems.append("缺少 <?php")

    name = path.split("\\")[-1]
    status = "OK" if not problems else "问题: " + "; ".join(problems)
    print(f"  {name:<14} {len(src):>6}B  骨架{len(skel):>6}B  {status}")
    return not problems


if __name__ == "__main__":
    files = sorted(glob.glob(r"defence\phpwaf\*.php"))
    if not files:
        print("未找到 phpwaf 文件")
        sys.exit(1)
    all_ok = all(check(p) for p in files)
    print()
    print("全部通过" if all_ok else "存在未通过项")
    sys.exit(0 if all_ok else 1)
