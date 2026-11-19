# -*- mode: python ; coding: utf-8 -*-
"""Build the Windows defensive workbench as a single executable."""

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

tool_dir = Path(SPECPATH)
frontend = tool_dir / "desktop_ui" / "dist"
runner = tool_dir / "build" / "elf-runner" / "run-hardened"
if not (frontend / "index.html").is_file():
    raise SystemExit("Build the frontend first: npm --prefix tool/desktop_ui run build")
if not runner.is_file():
    raise SystemExit("Build the Linux runner first: tool/defence/elf_runner/build.ps1")

datas = [
    (str(frontend), "desktop_ui/dist"),
    (str(tool_dir / "desktop_ui" / "SHADCN-LICENSE.md"), "desktop_ui/dist"),
    (str(tool_dir / "defence" / "phpwaf" / "*.php"), "defence/phpwaf"),
    (str(runner), "build/elf-runner"),
    (str(tool_dir / "defence" / "elf_runner" / "profiles.json"), "defence/elf_runner"),
    (str(tool_dir / "defence" / "pwn_waf_source"), "defence/pwn_waf_source"),
]
# pywebview's Windows hook collects native libraries. The bridge scripts are data.
datas += collect_data_files("webview", subdir="js")

analysis = Analysis(
    [str(tool_dir / "desktop.py")],
    datas=datas,
    hiddenimports=["webview.platforms.winforms", "webview.platforms.edgechromium"],
    excludes=[
        "Attacker",
        "bugku_pvp_backdoor_submit",
        "gui_main",
        "tkinter",
        "PyQt5",
        "PyQt6",
        "PySide2",
        "PySide6",
        "qtpy",
        "gi",
        "cefpython3",
    ],
)

pyz = PYZ(analysis.pure)
exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    name="MetaAWD-Desktop",
    console=False,
    upx=False,
    icon=str(tool_dir / "desktop_ui" / "shield-check.ico"),
)
