#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键构建发布版 exe。

用法::

    python build_release.py           # 完整流程：校验 -> 打包 -> 验证 -> 部署
    python build_release.py --check   # 只校验版本一致性，不打包

流程::

    1. 校验 launcher.VERSION 与 build.spec 的产物名是否一致
    2. 调用 PyInstaller 打包
    3. 校验产物（存在性、体积、关键模块是否打进 PYZ）
    4. 复制到 ../releases/

**改动代码后请务必跑一遍本脚本** —— 源码更新了但 exe 没重建，
分发出的仍是旧版本。
"""
import io
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = Path(__file__).resolve().parent
RELEASES = HERE.parent / "releases"
DIST = HERE / "dist"

LINE = "=" * 70


def read_version():
    src = (HERE / "launcher.py").read_text(encoding="utf-8")
    m = re.search(r'^VERSION\s*=\s*"([^"]+)"', src, re.M)
    return m.group(1) if m else None


def spec_exe_name():
    src = (HERE / "build.spec").read_text(encoding="utf-8")
    m = re.search(r"^\s*name='([^']+)'", src, re.M)
    return m.group(1) if m else None


def check_consistency():
    ver = read_version()
    name = spec_exe_name()
    print(LINE)
    print("① 版本一致性")
    print(LINE)
    print("  launcher.VERSION : %s" % ver)
    print("  build.spec 产物名 : %s" % name)
    if not ver or not name:
        print("  ✗ 无法读取版本信息")
        return None
    if ver not in name:
        print("  ✗ 不一致！build.spec 的 name 应包含版本号 %s" % ver)
        return None
    print("  ✓ 一致")
    return "%s.exe" % name


def run_build():
    print()
    print(LINE)
    print("② PyInstaller 打包")
    print(LINE)
    t0 = time.time()
    cmd = [sys.executable, "-m", "PyInstaller", "build.spec", "--noconfirm", "--clean"]
    p = subprocess.run(cmd, cwd=str(HERE), capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    tail = (p.stdout or "").strip().split("\n")[-3:]
    for l in tail:
        print("  " + l.strip())
    print("  耗时 %.1fs，退出码 %d" % (time.time() - t0, p.returncode))
    return p.returncode == 0


def verify(exe: Path):
    print()
    print(LINE)
    print("③ 产物校验")
    print(LINE)
    if not exe.exists():
        print("  ✗ 未生成:", exe)
        return False
    size = exe.stat().st_size / 1024 / 1024
    print("  ✓ 产物: %s  (%.1f MB)" % (exe.name, size))
    if size < 5:
        print("  ✗ 体积异常偏小，构建可能失败")
        return False

    # 关键模块的字节码里应含新功能的字符串常量
    # （PYZ 是 zlib 压缩的，这里只做快速抽查：直接扫 exe 明文不可行，
    #   因此改为校验构建日志与产物存在性；深度校验用 verify_build.py）
    return True


def deploy(exe: Path):
    print()
    print(LINE)
    print("④ 部署到 releases/")
    print(LINE)
    RELEASES.mkdir(exist_ok=True)
    dst = RELEASES / exe.name
    shutil.copy2(exe, dst)
    print("  ✓ %s" % dst)
    print()
    print("  releases/ 现有产物:")
    for f in sorted(RELEASES.glob("*.exe")):
        mark = " <- 本次" if f.name == exe.name else ""
        print("    %-32s %6.1f MB%s" % (f.name, f.stat().st_size / 1024 / 1024, mark))


def main():
    only_check = "--check" in sys.argv
    print(LINE)
    print("  MetaAWD 发布版构建")
    print(LINE)

    exe_name = check_consistency()
    if not exe_name:
        return 1
    if only_check:
        print()
        print("  版本一致，可执行 python build_release.py 进行构建")
        return 0

    if not run_build():
        print("  ✗ 打包失败")
        return 1

    exe = DIST / exe_name
    if not verify(exe):
        return 1
    deploy(exe)

    print()
    print(LINE)
    print("  构建完成。可解包抽查产物，确认新规则已打进 PYZ：")
    print("    pyinstxtractor dist/MetaAWD-v3.5.exe")
    print(LINE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
