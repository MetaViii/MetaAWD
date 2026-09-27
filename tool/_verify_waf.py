# -*- coding: utf-8 -*-
"""验证 waf_manager 的注入/剥离是否会破坏用户代码"""
import sys
import io

sys.path.insert(0, ".")

from defence import waf_manager as wm
from defence.state import state_manager

state_manager.remote_waf_path = "/var/www/html/.phpwaf/waf.php"
state_manager.remote_waf_dir = "/var/www/html/.phpwaf"
state_manager.remote_waf_log_dir = "/tmp/.phpwaf_logs"

snippet = wm.build_waf_include_snippet(
    "/var/www/html/.phpwaf/waf.php", "/tmp/.phpwaf_logs", 1, 3, ""
)

CASES = {
    "A_标准PHP": "<?php\necho 'hi';\n",
    "B_BOM开头": "\ufeff<?php\necho 'hi';\n",
    "C_HTML模板(内有php片段)": "<html>\n<body>\n<?php echo $x; ?>\n</body>\n</html>\n",
    "D_纯HTML无php": "<html><body>static</body></html>\n",
    "E_用户代码在前_require在中": (
        "<?php\nsession_start();\n$db = new PDO('sqlite:x');\n"
        "require_once '/var/www/html/.phpwaf/waf.php';\n?>\n"
        "<html><body>ok</body></html>\n"
    ),
    "F_闭合后再开": "<?php echo 1; ?>text<?php echo 2;\n",
}

print("=" * 78)
print("验证 inject -> remove 是否幂等还原（round-trip）")
print("=" * 78)
for name, original in CASES.items():
    injected = wm.prepend_waf_include(original, snippet)
    removed = wm.remove_waf_include_content(injected, "/var/www/html/.phpwaf/waf.php")
    ok = (removed == original)
    print(f"\n[{name}] round-trip: {'✓ 还原' if ok else '✗ 不一致'}")
    if not ok:
        print(f"   原文 : {original!r}")
        print(f"   还原后: {removed!r}")

print()
print("=" * 78)
print("模拟 H1: 注入后剥离，看是否产生非法 PHP（<?php 后跟 <html>）")
print("=" * 78)
src = CASES["C_HTML模板(内有php片段)"]
inj = wm.prepend_waf_include(src, snippet)
rem = wm.remove_waf_include_content(inj, "/var/www/html/.phpwaf/waf.php")
bad = rem.lstrip().startswith("<?php <") or "<?php <html>" in rem
print(f"  剥离结果前 80 字符: {rem[:80]!r}")
print(f"  是否产生 '<?php <html>' 非法结构: {'是 ← 缺陷确认' if bad else '否'}")

print()
print("=" * 78)
print("模拟 H2: 文件中部存在同路径 require_once 且含 ?> 时是否吞掉用户代码")
print("=" * 78)
src = CASES["E_用户代码在前_require在中"]
rem2 = wm.remove_waf_include_content(src, "/var/www/html/.phpwaf/waf.php")
lost = ("session_start" not in rem2) or ("PDO" not in rem2)
print(f"  剥离结果: {rem2!r}")
print(f"  是否丢失 session_start/PDO: {'是 ← 缺陷确认' if lost else '否'}")
