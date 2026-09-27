#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AWD Defence Tool v3.1 启动器

设计说明
--------
.bat 里的内容必须保持纯 ASCII：cmd 会按**启动时**的代码页解码整个 bat 文件，
chcp 只影响输出、无法补救已解码的内容。因此中文提示统一放在本文件里，
由 Python 处理编码（Python 会跟随控制台代码页，且在无法编码时降级而非崩溃）。

用法:
    python launcher.py          # 启动 GUI
    python launcher.py check    # 只做环境自检
"""
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MIN_PYTHON = (3, 9)

# (import 名, pip 包名)
CORE_DEPS = [
    ("paramiko", "paramiko>=3.4.0"),
    ("termcolor", "termcolor>=2.3.0"),
]
GUI_DEPS = [
    ("ttkbootstrap", "ttkbootstrap==1.7.2"),
]

MIRROR = "https://pypi.tuna.tsinghua.edu.cn/simple"
VERSION = "3.1"

LINE = "=" * 60


def setup_console():
    """尽最大努力避免中文提示因控制台编码而抛 UnicodeEncodeError"""
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except Exception:
                pass


def info(msg):
    print(msg)


def fail(msg, hint=""):
    print(f"[x] {msg}")
    if hint:
        print(f"    {hint}")


def check_python():
    if sys.version_info < MIN_PYTHON:
        fail(f"Python 版本过低：当前 {sys.version.split()[0]}，需要 "
             f"{MIN_PYTHON[0]}.{MIN_PYTHON[1]} 及以上")
        return False
    return True


def missing_deps(deps):
    """返回缺失的 (import 名, pip 包名) 列表"""
    missing = []
    for mod, pkg in deps:
        try:
            __import__(mod)
        except ImportError:
            missing.append((mod, pkg))
    return missing


def pip_install(packages):
    """尝试安装依赖，先走默认源，失败再走国内镜像"""
    for extra in ([], ["-i", MIRROR]):
        src = "默认源" if not extra else "清华镜像"
        info(f"[*] 正在从{src}安装: {' '.join(packages)}")
        try:
            rc = subprocess.call([sys.executable, "-m", "pip", "install", *packages, *extra])
        except Exception as exc:
            fail(f"调用 pip 失败: {exc}")
            continue
        if rc == 0:
            return True
    return False


def ensure_deps():
    need = list(CORE_DEPS) + list(GUI_DEPS)
    missing = missing_deps(need)
    if not missing:
        return True

    pkgs = [pkg for _mod, pkg in missing]
    info(f"[*] 检测到缺少依赖: {', '.join(m for m, _ in missing)}")
    info("")

    if not pip_install(pkgs):
        fail("依赖安装失败")
        info("")
        info("    请手动执行（二选一）：")
        info(f"      {sys.executable} -m pip install {' '.join(pkgs)}")
        info(f"      {sys.executable} -m pip install {' '.join(pkgs)} -i {MIRROR}")
        info("")
        return False

    still = missing_deps(need)
    if still:
        fail(f"安装后仍缺少: {', '.join(m for m, _ in still)}")
        return False

    info("[OK] 依赖安装完成")
    info("")
    return True


def launch_gui():
    info("[*] 正在启动界面 ...")
    info("")
    try:
        import runpy
        runpy.run_path(str(HERE / "gui_main.py"), run_name="__main__")
        return 0
    except ImportError as exc:
        fail(f"启动失败：{exc}")
        info("")
        info("    依赖可能不完整，可尝试：")
        info(f"      {sys.executable} -m pip install -r requirements.txt")
        return 1
    except Exception as exc:
        fail(f"程序异常退出：{type(exc).__name__}: {exc}")
        info("")
        info("    若为 Tk 相关错误，请确认当前环境有可用图形界面。")
        return 1


def main():
    setup_console()
    mode = (sys.argv[1].lower() if len(sys.argv) > 1 else "gui")

    info(LINE)
    info(f"   AWD Defence Tool v{VERSION}")
    info(f"   Python {sys.version.split()[0]} @ {sys.executable}")
    info(LINE)
    info("")

    if not check_python():
        sys.exit(1)

    if not ensure_deps():
        sys.exit(1)

    if mode == "check":
        info("[OK] 环境自检通过，可以正常启动")
        info("")
        info("     双击 start.bat 即可打开界面")
        sys.exit(0)

    # 让项目根目录可被 import（gui_main 依赖同目录的 defence 包）
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    os.chdir(HERE)

    sys.exit(launch_gui())


if __name__ == "__main__":
    main()
