# -*- mode: python ; coding: utf-8 -*-
"""AWD Defence Tool v3.1 打包配置

构建:
    python -m PyInstaller build.spec --noconfirm --clean

产物:
    dist/AWD-Defence-Tool-v3.1.exe   单文件绿色版，双击即用

要点说明
--------
1. defence/__init__.py 在源码环境下用 os.listdir 自动发现子模块，
   打包后代码位于 PYZ 归档中无法扫描，因此必须显式声明 hiddenimports
   （与 defence/__init__.py 里的冻结清单保持一致）。
2. defence/phpwaf/*.php 是运行时读取的模板文件，必须作为数据一并打包。
3. ttkbootstrap 自带主题资源，需要 collect_data_files 收集。
"""

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# ---- 数据文件 ----
datas = [
    ('defence/phpwaf/waf_php5.php', 'defence/phpwaf'),
    ('defence/phpwaf/waf_php7.php', 'defence/phpwaf'),
    ('defence/phpwaf/waf_php8.php', 'defence/phpwaf'),
    ('requirements.txt', '.'),
    ('README.md', '.'),
    ('FIXES.md', '.'),
]
datas += collect_data_files('ttkbootstrap')

# ---- 隐式导入（冻结环境下 os.listdir 无法发现）----
hiddenimports = [
    'defence._bootstrap',
    'defence.attacker_tools',
    'defence.file_processing',
    'defence.ssh',
    'defence.state',
    'defence.waf_manager',
    'defence.webshell_scanner',
]

# cryptography 的算法子模块是运行时按需导入的，静态分析抓不到。
# 实测缺少 asymmetric.ecdsa 会导致与 OpenSSH(默认优先 ECDSA/Ed25519)
# 的连接协商失败，因此必须显式收集整个 hazmat.primitives 子树。
hiddenimports += collect_submodules('cryptography.hazmat.primitives')
hiddenimports += collect_submodules('cryptography.hazmat.backends')
hiddenimports += [
    'cryptography.x509',
    'cryptography.fernet',
    'nacl',
    'bcrypt',
]

a = Analysis(
    ['gui_main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # 排除明显用不到的大件，减小体积
        'pytest', 'setuptools', 'pip', 'wheel',
        'numpy', 'pandas', 'matplotlib', 'scipy',
        'PyQt5', 'PySide2', 'PySide6',
        'IPython', 'jupyter', 'notebook',
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='AWD-Defence-Tool-v3.1',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # GUI 程序不弹黑框
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
