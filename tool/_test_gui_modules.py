# -*- coding: utf-8 -*-
"""GUI 重构后的逐模块验收测试（离线可测部分）。

会把 messagebox 打桩，避免弹窗阻塞；不依赖真实 SSH 目标。
"""
import io
import os
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gui_main
from tkinter import messagebox

# ---- 打桩：把弹窗替换成记录，避免卡住 ----
POPUPS = []
for fn in ("showinfo", "showwarning", "showerror"):
    setattr(messagebox, fn,
            (lambda name: lambda *a, **k: POPUPS.append((name, a[:1])))(fn))
messagebox.askyesno = lambda *a, **k: (POPUPS.append(("askyesno", a[:1])), False)[1]
gui_main.messagebox = messagebox

ok, bad = [], []


def check(name, cond, detail=""):
    (ok if cond else bad).append(name)
    print(f"  {'✓' if cond else '✗'} {name}" + (f"  {detail}" if detail and not cond else ""))


app = gui_main.AWDDfenceGUI()
app.update_idletasks()
app.update()
print(f"窗口 {app.winfo_width()}x{app.winfo_height()}  主题 {__import__('tkinter.ttk', fromlist=['ttk']).Style().theme_use()}\n")

# ============================================================ 1. 页面与导航
print("【外壳】")
check("10 个页面已注册", len(app.pages) == 10, f"实际 {len(app.pages)}")
check("10 个导航按钮", len(app.nav_buttons) == 10, f"实际 {len(app.nav_buttons)}")
check("导航项齐备", len(app.NAV_ITEMS) == 10)
check("默认停在 SSH 页", app.current_page == "ssh")
for k in app.pages:
    app.show_page(k)
    app.update_idletasks()
check("页面逐一切换无异常", True)
check("切换后当前页正确", app.current_page == "shell")
app.show_page("ssh")

# ============================================================ 2. 各页控件与回调
print("\n【各页控件与按钮回调】")
EXPECT = {
    "ssh": ["ssh_host", "ssh_port", "ssh_user", "ssh_pass", "btn_ssh_test", "ssh_log"],
    "monitor": ["mon_path", "btn_start_mon", "btn_pause_mon", "btn_stop_mon", "mon_log"],
    "scanner": ["scan_path", "scan_threshold", "btn_scan_start", "btn_scan_save",
                "btn_scan_clear", "btn_scan_quarantine", "scan_summary", "scan_log"],
    "tar": ["tar_path", "tar_local_dir", "btn_tar", "btn_pick_tar_dir",
            "btn_pick_backup", "btn_deploy_backup", "tar_log"],
    "attacker": ["attack_url_pattern", "btn_attack_scan", "btn_attack_read",
                 "btn_attack_check", "btn_attack_exec", "btn_attack_upload", "attack_log"],
    "bugku": ["bugku_domain", "bugku_path", "bugku_token", "btn_bugku_start",
              "btn_bugku_stop", "bugku_log"],
    "waf": ["waf_web_root", "waf_remote_dir", "waf_mode", "waf_strict_level",
            "btn_deploy_waf", "btn_guard_waf", "btn_undeploy_waf", "waf_log"],
    "packet": ["btn_sync_packets", "btn_refresh_packets", "btn_clear_packets",
               "packet_tree", "packet_preview"],
    "system": ["system_summary", "btn_refresh_system", "system_log"],
    "shell": ["shell_log"],
}
missing = []
for page, attrs in EXPECT.items():
    for a in attrs:
        if not hasattr(app, a):
            missing.append(f"{page}.{a}")
check("各页关键控件齐备", not missing, "缺失: " + ", ".join(missing))

no_cmd = [n for n in dir(app) if n.startswith("btn_")
          and hasattr(getattr(app, n), "cget")
          and not getattr(app, n).cget("command")]
check("全部按钮已绑定回调", not no_cmd, "未绑定: " + ", ".join(no_cmd))

# ============================================================ 3. 顶栏连接指示
print("\n【顶栏】")
app.refresh_conn_status()
check("未连接时显示 ○ 未连接", "未连接" in app.conn_status.cget("text"))
gui_main.state_manager.is_ssh = True
app.refresh_conn_status()
check("已连接时显示 ● 已连接", "已连接" in app.conn_status.cget("text"))
gui_main.state_manager.is_ssh = False
app.refresh_conn_status()

# ============================================================ 4. 阈值联动
print("\n【木马查杀 · 阈值联动】")
app.scan_threshold.delete(0, "end")
app.scan_threshold.insert(0, "200")
app.update_threshold_hint()
t = app.threshold_hint.cget("text")
check("阈值 200 显示恶意/可疑两条线", "恶意" in t and "可疑" in t, t)
check("可疑线 = 阈值×40% = 80", "80" in t, t)
app.scan_threshold.delete(0, "end")
app.scan_threshold.insert(0, "abc")
app.update_threshold_hint()
check("非数字输入提示正整数", "正整数" in app.threshold_hint.cget("text"))

# ============================================================ 5. 本地查杀真实跑一遍
print("\n【木马查杀 · 本地扫描(走 GUI 的 log 通道)】")
d = tempfile.mkdtemp()
with io.open(os.path.join(d, "shell.php"), "w", encoding="utf-8") as f:
    f.write('<?php @eval($_POST["cmd"]); ?>')
with io.open(os.path.join(d, "clean.php"), "w", encoding="utf-8") as f:
    f.write('<?php echo "hello"; ?>')

app.scan_path.delete(0, "end")
app.scan_path.insert(0, d)
before = len(app.scan_log.get("1.0", "end"))
try:
    gui_main.webshell_scanner.scan_local(
        d, threshold=200, log_callback=app.log_scan)
    app.update()
    check("扫描日志写入 GUI", len(app.scan_log.get("1.0", "end")) > before)
except Exception as e:
    check("扫描日志写入 GUI", False, f"{type(e).__name__}: {e}")

res, total = gui_main.webshell_scanner.scan_local(
    d, threshold=200, log_callback=lambda *a, **k: None)
check("扫出 1 个恶意文件", len(res) == 1 and res[0]["level"] == 3,
      f"命中 {len(res)}")
plan = gui_main.webshell_scanner.build_quarantine_plan(
    res, log_callback=lambda *a, **k: None)
check("生成注释计划", len(plan) == 1 and any(e["ok"] for e in plan[0]["lines"]))

# ============================================================ 6. 数据包 / 系统日志页
print("\n【数据包审查 · 系统日志】")
try:
    app.refresh_packet_list()
    app.update()
    check("数据包列表刷新无异常", True)
except Exception as e:
    check("数据包列表刷新无异常", False, f"{type(e).__name__}: {e}")
try:
    app.refresh_system_status()
    app.update()
    check("系统状态刷新无异常", "SSH" in app.system_log.get("1.0", "end")
          or "监控" in app.system_log.get("1.0", "end"))
except Exception as e:
    check("系统状态刷新无异常", False, f"{type(e).__name__}: {e}")

# ============================================================ 7. 未连接时的保护
print("\n【未连接时的降级保护(不应崩溃)】")
from defence.state import state_manager
state_manager.is_ssh = False
for name, fn in [("启停监控", app.start_monitor), ("打包下载", app.run_tar),
                 ("一键部署", app.run_deploy_backup),
                 ("攻击辅助-探活", app.run_attack_scan),
                 ("WAF 部署", app.deploy_waf)]:
    try:
        fn()
        app.update()
        check(f"{name} 未连接时安全返回", True)
    except Exception as e:
        check(f"{name} 未连接时安全返回", False, f"{type(e).__name__}: {e}")

# ============================================================ 汇总
app.destroy()
print(f"\n{'='*60}")
print(f"  通过 {len(ok)} / 失败 {len(bad)}")
if bad:
    for b in bad:
        print(f"    ✗ {b}")
else:
    print("  全部通过")
print("=" * 60)
sys.exit(1 if bad else 0)
