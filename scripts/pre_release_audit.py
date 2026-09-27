# -*- coding: utf-8 -*-
"""发布前最终审计：模拟「如果这个仓库公开会泄露什么」"""
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# 高危：真实凭据 / 比赛数据 / 靶机
CRITICAL = [
    (r"flag\{[0-9a-fA-F]{16,}\}", "真实 flag"),
    (r"pvp\d{3,}\.", "比赛环境域名"),
    (r"192-168-\d+-\d+", "比赛靶机命名"),
    # 排除版本号形式（2.1.8.1），只匹配真正的四段 IP
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b(?!\.\d)", "IP 地址"),
    (r"password\s*=\s*['\"][^'\"]{4,}['\"]", "硬编码密码"),
    (r"Authorization:\s*\S+", "认证头"),
    (r"Bearer\s+[A-Za-z0-9\-_\.]{20,}", "Bearer 凭据"),
]

# 中危：个人环境痕迹
MEDIUM = [
    (r"[A-Za-z]:\\Users\\[A-Za-z0-9_]+", "本机用户路径"),
    (r"[A-Za-z]:\\(CTF|Desktop|Documents)", "本机目录路径"),
]

ALLOW = [
    "example.com", "example-awd.com", "example-ctf.com",
    "127.0.0.1", "localhost", "0.0.0.0",
    "YOUR_TOKEN_HERE", "your-token",
    "ctf.bugku.com/pvp/submit",     # 平台公开提交接口，功能需要
    "bugku{",                       # flag 格式正则，功能需要
    # WAF 用于替换 flag 的占位常量（功能需要，非凭据）
    "383f0516865160a512df45a928969e12",
    "noreply@example.com",
    # 版本号
    "2.1.8.1",
]

SKIP_SUFFIX = {".exe", ".png", ".jpg", ".ico", ".zip", ".pyc", ".git"}
# dshield-reverse 为本地研究目录，不入库，因此不参与发布审计
SKIP_PARTS = {"__pycache__", ".git", "releases", "dshield-reverse"}
# 本脚本自身只含正则定义，扫描它会把自己的模式串当成命中
SELF = Path(__file__).resolve()


def allowed(line):
    low = line.lower()
    return any(a.lower() in low for a in ALLOW)


def scan(text, patterns):
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if allowed(line):
            continue
        stripped = line.strip()
        # 注释/文档里的示例说明也放过
        for pat, why in patterns:
            if re.search(pat, line, re.I):
                hits.append((lineno, why, stripped[:100]))
                break
    return hits


print("=" * 72)
print("  发布前最终审计")
print("=" * 72)

files = [p for p in REPO.rglob("*")
         if p.is_file()
         and p.resolve() != SELF
         and p.suffix.lower() not in SKIP_SUFFIX
         and not any(x in p.parts for x in SKIP_PARTS)]

critical_total = 0
medium_total = 0

for p in sorted(files):
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    rel = str(p.relative_to(REPO))
    c = scan(text, CRITICAL)
    m = scan(text, MEDIUM)
    if c:
        print(f"\n  [严重] {rel}")
        for ln, why, s in c:
            print(f"    L{ln} [{why}] {s}")
        critical_total += len(c)
    if m:
        print(f"\n  [中危] {rel}")
        for ln, why, s in m:
            print(f"    L{ln} [{why}] {s}")
        medium_total += len(m)

print()
print("-" * 72)
print(f"  严重 {critical_total} 处 / 中危 {medium_total} 处")

# git 历史检查
print()
print("  git 历史:")
try:
    r = subprocess.run(["git", "-C", str(REPO), "log", "--oneline", "--all"],
                       capture_output=True, text=True, timeout=30,
                       encoding="utf-8", errors="replace")
    for line in (r.stdout or "").strip().splitlines():
        print(f"    {line}")
    r2 = subprocess.run(["git", "-C", str(REPO), "ls-files"],
                        capture_output=True, text=True, timeout=30,
                        encoding="utf-8", errors="replace")
    n = len([x for x in (r2.stdout or "").splitlines() if x.strip()])
    print(f"    已跟踪 {n} 个文件")
except Exception as exc:
    print(f"    (检查失败: {exc})")

print()
if critical_total:
    print("  [FAIL] 存在严重泄露风险，需先处理")
    sys.exit(1)
print("  [PASS] 无严重泄露风险，可推送")
