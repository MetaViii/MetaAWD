import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from tkinter.constants import *
import ui_theme as ui
import threading
import re
import socket
import paramiko
import sys
import os
import subprocess
import time
from datetime import datetime

from defence import ssh, file_processing, waf_manager, attacker_tools, webshell_scanner
from defence.state import state_manager

# 使用更精确的正则表达式匹配所有的 ANSI 转义序列 (包括 CSI 颜色、清屏、OSC 序列等)
# 匹配: ESC [ ... 字母 (CSI) | ESC ] ... BEL (OSC) | 各种控制符
ansi_escape = re.compile(r'(?:\x1B[@-Z\\-_]|[\x80-\x9A\x9C-\x9F]|(?:\x1B\[|\x9B)[0-?]*[ -/]*[@-~]|\x1B\][^\x07\x1B]*?(?:\x07|\x1B\\)|\x1B[=>])')

def strip_ansi(text):
    """移除终端ANSI控制序列"""
    return ansi_escape.sub('', text)


# ==================================================================== 配色
# 全部语义色改由 ui_theme 的 ttk 样式提供（Danger/Success/Warning/Info/Muted.TLabel），
# 这样切换主题时会自动跟随。此前这里硬编码过一套色值，浅色主题下对比度不足。


class AWDDfenceGUI(tk.Tk):
    def __init__(self):
        ui.enable_dpi_awareness()         # 必须在创建 Tk 之前，否则窗口被位图拉伸
        super().__init__()
        ui.init_scale(self)
        ui.apply_theme(self)
        self.title("MetaAWD by metavi")
        ui.apply_dark_title_bar(self)
        self.configure_responsive_window()
        self.shell_input_buffer = ""
        self.shell_cursor_pos = 0
        self.shell_connecting = False
        self.shell_client = None
        self.shell_chan = None
        self.shell_bootstrapping = False
        self.shell_bootstrap_buffer = ""
        self.shell_bootstrap_deadline = 0
        self.waf_guard_thread = None
        self.waf_guard_stop = threading.Event()
        self.waf_sync_interval = 5
        self.packet_files = []
        self.sync_in_progress = False
        self.attacker_session = attacker_tools.AttackerSession()
        self.bugku_stop_event = threading.Event()
        self.scan_stop_event = threading.Event()
        self.scan_running = False
        self.scan_results = []
        self.scan_total = 0
        self.scan_used_mode = "local"      # 记录本次扫描模式，处置时决定走本地还是 SFTP
        self.shell_hidden_fragments = [
            "export TERM=xterm",
            "bind 'set enable-bracketed-paste off' 2>/dev/null",
            "printf '\\033[?2004l' >/dev/null 2>&1",
            "stty -echo -ixon 2>/dev/null"
        ]
        
        # ---------------- 外壳：顶栏 + 分组侧边栏 + 内容区 ----------------
        self.pages = {}          # key -> (页面 Frame, 内容容器)
        self.nav_buttons = {}    # key -> 侧边栏按钮
        self.current_page = None

        self._build_shell()

        self.create_ssh_tab()
        self.create_monitor_tab()
        self.create_scanner_tab()
        self.create_tar_tab()
        self.create_attacker_tab()
        self.load_default_attack_shells()
        self.create_bugku_tab()
        self.create_waf_tab()
        self.create_packet_tab()
        self.create_system_tab()
        self.create_shell_tab()

        # 各页创建 Text/Frame/Canvas 时未必显式配色，这里统一兜底
        ui.darken_native_widgets(self)
        self.show_page("ssh")

    def configure_responsive_window(self):
        # DPI 感知开启后 winfo_screen* 返回的是物理像素（本机 150% 时为 2560x1600），
        # 而这里的尺寸都是按 96 DPI 设计的，必须经 ui.px() 换算后再比较，
        # 否则 150% 下最小尺寸会缩水到设计值的 2/3。
        screen_width = max(self.winfo_screenwidth(), ui.px(1100))
        screen_height = max(self.winfo_screenheight(), ui.px(700))
        width = min(max(ui.px(1180), int(screen_width * 0.78)), screen_width - ui.px(40))
        height = min(max(ui.px(700), int(screen_height * 0.78)), screen_height - ui.px(80))
        min_width = min(ui.px(1060), screen_width - ui.px(80))
        min_height = min(ui.px(640), screen_height - ui.px(120))
        x = max((screen_width - width) // 2, 0)
        y = max((screen_height - height) // 2, 0)
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.minsize(min_width, min_height)
        self.resizable(True, True)

    # ================================================================ 外壳
    # 平铺导航，不再分组。页面数量不多，分组标题只会增加视觉噪音。
    # 顺序按实际操作流：先连上 -> 看住防线 -> 处置 -> 打包 -> 攻击面
    NAV_ITEMS = [
        ("ssh",      "SSH",     "Secure remote connection"),
        ("monitor",  "文件监控", "MD5 baseline change monitoring"),
        ("scanner",  "木马查杀", "WebShell detection & quarantine"),
        ("waf",      "WAF",     "Web application firewall"),
        ("system",   "系统日志", "Runtime status overview"),
        ("packet",   "数据包",   "Captured attack traffic"),
        ("tar",      "打包下载", "Source archive & one-click deploy"),
        ("attacker", "攻击辅助", "Recon, backdoor check & execution"),
        ("bugku",    "Bugku",   "Batch flag read & submit"),
        ("shell",    "交互终端", "Interactive SSH shell"),
    ]

    def _build_shell(self):
        """顶栏 + 左侧平铺导航 + 右侧内容区。

        品牌名只出现在窗口标题栏上，顶栏留给「当前页面 + 连接状态 + 主题切换」。
        导航项是纯文字按钮，选中项以强调色前景 + 底色块区分，不用分组标题。
        """
        # ---- 顶栏 ----
        topbar = ttk.Frame(self, padding=(ui.px(20), ui.px(12), ui.px(20), ui.px(12)))
        topbar.pack(fill=X)
        self.page_title_label = ttk.Label(topbar, text="", font=ui.FONT_UI_BOLD)
        self.page_title_label.pack(side=LEFT)

        self.theme_box = ttk.Combobox(
            topbar, state="readonly", width=10,
            values=[lb for _k, lb in ui.theme_names()])
        self.theme_box.set(ui.theme_label())
        self.theme_box.pack(side=RIGHT)
        self.theme_box.bind("<<ComboboxSelected>>", self.on_theme_change)

        self.conn_status = ttk.Label(topbar, text="○ 未连接",
                                     style="Muted.TLabel", font=ui.FONT_UI_SM)
        self.conn_status.pack(side=RIGHT, padx=(0, ui.px(16)))

        ttk.Separator(self, orient=HORIZONTAL).pack(fill=X)

        # ---- 主体：左导航 | 分隔线 | 右内容 ----
        body = ttk.Frame(self)
        body.pack(expand=True, fill=BOTH)

        sidebar = ttk.Frame(body, style="Sidebar.TFrame", width=ui.px(168))
        sidebar.pack(side=LEFT, fill=Y)
        sidebar.pack_propagate(False)

        ttk.Separator(body, orient=VERTICAL).pack(side=LEFT, fill=Y)

        self.pages_area = ttk.Frame(body)
        self.pages_area.pack(side=LEFT, expand=True, fill=BOTH)
        self.pages_area.rowconfigure(0, weight=1)
        self.pages_area.columnconfigure(0, weight=1)

        ttk.Frame(sidebar, height=ui.px(8)).pack(fill=X)
        for key, nav_label, _sub in self.NAV_ITEMS:
            btn = ttk.Button(sidebar, text=nav_label, style="Nav.TButton",
                             command=lambda k=key: self.show_page(k))
            btn.pack(fill=X, padx=ui.px(8), pady=ui.px(1))
            self.nav_buttons[key] = btn

    def on_theme_change(self, _event=None):
        """顶栏下拉切换主题：重建样式 -> 重新深色化 -> 重绘渐变。"""
        label = self.theme_box.get()
        key = next((k for k, lb in ui.theme_names() if lb == label), None)
        if not key or key == ui.current_theme():
            return
        ui.apply_theme(self, key)
        self.refresh_conn_status()
        self.refresh_page_title()

    def _add_page(self, key, padding=16):
        """建页面：标题 + 副标题 + 内容容器；返回内容容器供各页填控件。

        标题/副标题统一取自 NAV_ITEMS，避免两处维护。
        """
        title, subtitle = next(
            (n, s) for k, n, s in self.NAV_ITEMS if k == key)

        page = ttk.Frame(self.pages_area)
        page.grid(row=0, column=0, sticky="nsew")

        pad = ui.px(padding)
        header = ttk.Frame(page, padding=(pad, pad, pad, ui.px(4)))
        header.pack(fill=X)
        ttk.Label(header, text=title, font=ui.FONT_TITLE).pack(anchor=W)
        ttk.Label(header, text=subtitle,
                  style="Muted.TLabel").pack(anchor=W, pady=(ui.px(2), 0))

        content = ttk.Frame(page, padding=(pad, ui.px(4), pad, pad))
        content.pack(expand=True, fill=BOTH)

        self.pages[key] = (page, content)
        return content

    def show_page(self, key):
        """切换页面，并执行该页原本绑定在标签切换上的副作用"""
        prev = self.current_page
        for k, (page, _content) in self.pages.items():
            if k == key:
                page.tkraise()

        # 只改「离开的」和「进入的」这两个按钮。ttk 的 style 变更会触发全窗口
        # 重算，早前每页都 configure 一遍时切页会从 27ms 涨到 156ms。
        if prev and prev != key and prev in self.nav_buttons:
            self.nav_buttons[prev].configure(style="Nav.TButton")
        if key in self.nav_buttons:
            self.nav_buttons[key].configure(style="NavActive.TButton")

        self.current_page = key
        self.refresh_page_title()

        if key == "shell":
            # 切到终端且尚未连接时自动连
            if state_manager.is_ssh and not self.shell_connecting and (
                    not self.shell_chan or self.shell_chan.closed):
                self.start_shell()
        elif key == "packet":
            # 进该页先刷新本地列表；已连接则顺带从远端拉一次
            self.refresh_packet_list()
            if state_manager.is_ssh and not self.sync_in_progress:
                self.sync_waf_logs(ask_clear=False)
        elif key == "system":
            self.refresh_system_status()

    def refresh_page_title(self):
        """顶栏左侧显示当前页面名（页面标题统一取自 NAV_ITEMS）"""
        title = dict((k, n) for k, n, _s in self.NAV_ITEMS).get(self.current_page, "")
        try:
            self.page_title_label.configure(text=title)
        except Exception:
            pass

    def refresh_conn_status(self):
        """刷新顶栏的连接指示（用当前主题色，切换主题后会跟着变）"""
        P = ui.PALETTE
        if state_manager.is_ssh:
            self.conn_status.configure(text="● 已连接", foreground=P["success_hi"])
        else:
            self.conn_status.configure(text="○ 未连接", foreground=P["fg_dim"])

    def create_ssh_tab(self):
        frame = self._add_page("ssh", padding=20)

        # 输入区域使用 LabelFrame
        input_frame = ttk.LabelFrame(frame, text="连接信息", padding=15)
        input_frame.pack(fill=X, pady=(0, 15))

        ttk.Label(input_frame, text="主机 (IP):").grid(row=0, column=0, padx=10, pady=10, sticky=E)
        self.ssh_host = ttk.Entry(input_frame, width=30)
        self.ssh_host.grid(row=0, column=1, padx=10, pady=10, sticky=W)

        ttk.Label(input_frame, text="端口 (Port):").grid(row=0, column=2, padx=10, pady=10, sticky=E)
        self.ssh_port = ttk.Entry(input_frame, width=10)
        self.ssh_port.insert(0, "22")
        self.ssh_port.grid(row=0, column=3, padx=10, pady=10, sticky=W)

        ttk.Label(input_frame, text="用户名:").grid(row=1, column=0, padx=10, pady=10, sticky=E)
        self.ssh_user = ttk.Entry(input_frame, width=30)
        self.ssh_user.insert(0, "root")
        self.ssh_user.grid(row=1, column=1, padx=10, pady=10, sticky=W)

        ttk.Label(input_frame, text="密码:").grid(row=1, column=2, padx=10, pady=10, sticky=E)
        self.ssh_pass = ttk.Entry(input_frame, show="*", width=30)
        self.ssh_pass.grid(row=1, column=3, padx=10, pady=10, sticky=W)

        # 调整列权重，防止某一列被异常拉伸
        input_frame.columnconfigure(1, weight=1)
        input_frame.columnconfigure(3, weight=1)

        self.btn_ssh_test = ttk.Button(input_frame, text="测试连接", style="Accent.TButton", command=self.test_ssh)
        self.btn_ssh_test.grid(row=2, column=0, columnspan=4, pady=15)

        # 日志区域
        log_frame = ttk.LabelFrame(frame, text="连接日志", padding=10)
        log_frame.pack(expand=True, fill=BOTH)
        
        self.ssh_log = scrolledtext.ScrolledText(log_frame, height=15, font=ui.FONT_MONO)
        self.ssh_log.pack(expand=True, fill=BOTH)

    def log_ssh(self, msg):
        clean_msg = strip_ansi(str(msg)) + "\n"
        self.ssh_log.after(0, lambda: self._append_log(self.ssh_log, clean_msg))

    def _append_log(self, widget, msg):
        widget.insert(END, msg)
        widget.see(END)

    def test_ssh(self):
        host = self.ssh_host.get().strip()
        if not host:
            messagebox.showwarning("警告", "请填写主机地址")
            return
        try:
            # 端口非数字时原实现会从 Tk 回调抛出 ValueError，
            # pythonw 启动时无 stderr，表现为"点测试连接完全没反应"
            port = int(self.ssh_port.get().strip() or "22")
        except ValueError:
            messagebox.showwarning("警告", "端口必须是数字")
            return
        if not (1 <= port <= 65535):
            messagebox.showwarning("警告", "端口范围应为 1-65535")
            return
        user = self.ssh_user.get()
        password = self.ssh_pass.get()

        self.btn_ssh_test.config(state=DISABLED)
        self.ssh_log.delete(1.0, END)

        def run_test():
            try:
                ssh.ssh_test(hostname=host, port=port, username=user, password=password,
                             log_callback=self.log_ssh)
            except Exception as exc:
                self.log_ssh(f"[x] 连接测试异常: {type(exc).__name__}: {exc}")
            finally:
                self.btn_ssh_test.after(0, lambda: self.btn_ssh_test.config(state=NORMAL))
                # ssh_test 会写 state_manager.is_ssh，回到 UI 线程后刷新顶栏指示
                self.conn_status.after(0, self.refresh_conn_status)

        threading.Thread(target=run_test, daemon=True).start()

    def create_monitor_tab(self):
        frame = self._add_page("monitor", padding=20)

        control_frame = ttk.Frame(frame)
        control_frame.pack(fill=X, pady=(0, 15))

        ttk.Label(control_frame, text="监控目录:").grid(row=0, column=0, padx=(0, 10), pady=5, sticky=E)
        self.mon_path = ttk.Entry(control_frame, width=40)
        self.mon_path.insert(0, "/var/www/html/")
        self.mon_path.grid(row=0, column=1, padx=10, pady=5, sticky=EW)

        self.btn_start_mon = ttk.Button(control_frame, text="开始监控", style="Accent.TButton", command=self.start_monitor)
        self.btn_start_mon.grid(row=0, column=2, padx=(10, 6), pady=5)

        self.btn_pause_mon = ttk.Button(control_frame, text="暂停", command=self.toggle_pause_monitor, state=DISABLED)
        self.btn_pause_mon.grid(row=0, column=3, padx=6, pady=5)

        self.btn_stop_mon = ttk.Button(control_frame, text="停止监控", command=self.stop_monitor, state=DISABLED)
        self.btn_stop_mon.grid(row=0, column=4, padx=(6, 10), pady=5)

        # 复选框独占一行：此前它与 5 个控件挤在同一 row，而 column=1 的 Entry
        # 带 weight=1 会吃掉全部余量，复选框被压到最小宽度，几乎点不到。
        self.is_auto_delete = tk.IntVar(value=0)
        self.chk_auto_delete = ttk.Checkbutton(
            control_frame,
            text="自动删除被更改/新增的文件",
            variable=self.is_auto_delete,
        )
        self.chk_auto_delete.grid(row=1, column=1, padx=10, pady=(2, 6), sticky=W)

        control_frame.columnconfigure(1, weight=1)

        log_frame = ttk.LabelFrame(frame, text="监控日志", padding=10)
        log_frame.pack(expand=True, fill=BOTH)
        
        self.mon_log = scrolledtext.ScrolledText(log_frame, font=ui.FONT_MONO)
        self.mon_log.pack(expand=True, fill=BOTH)

    def log_mon(self, msg):
        clean_msg = strip_ansi(str(msg)) + "\n"
        self.mon_log.after(0, lambda: self._append_log(self.mon_log, clean_msg))

    def start_monitor(self):
        if not state_manager.is_ssh:
            messagebox.showwarning("警告", "请先在 SSH 选项卡测试并连接 SSH")
            return
            
        path = self.mon_path.get()
        auto_del = bool(self.is_auto_delete.get())
        
        self.btn_start_mon.config(state=DISABLED)
        self.chk_auto_delete.config(state=DISABLED)
        self.btn_pause_mon.config(state=NORMAL, text="暂停")
        self.btn_stop_mon.config(state=NORMAL)
        self.mon_log.delete(1.0, END)
        
        mode_text = "【自动删除模式】" if auto_del else "【仅监控模式】"
        self.log_mon(f"[*] 启动监控 {mode_text}...")

        def run_mon():
            try:
                file_processing.monitor_directory_changes(
                    state_manager.hostname, state_manager.port, state_manager.username, state_manager.password,
                    path, is_delete=auto_del, log_callback=self.log_mon, is_gui=True
                )
            except Exception as exc:
                # 缺少这层保护时，任何非网络异常(如解码错误)都会穿透，
                # 导致下面 4 个控件永久锁死且 is_running 不复位
                self.log_mon(f"[x] 监控线程异常退出: {type(exc).__name__}: {exc}")
            finally:
                file_processing.is_running = False
                file_processing.is_paused = False
                self.btn_start_mon.after(0, lambda: self.btn_start_mon.config(state=NORMAL))
                self.btn_start_mon.after(0, lambda: self.chk_auto_delete.config(state=NORMAL))
                self.btn_pause_mon.after(0, lambda: self.btn_pause_mon.config(state=DISABLED, text="暂停"))
                self.btn_stop_mon.after(0, lambda: self.btn_stop_mon.config(state=DISABLED))

        self.mon_thread = threading.Thread(target=run_mon, daemon=True)
        self.mon_thread.start()

    def toggle_pause_monitor(self):
        if not file_processing.is_running:
            return
            
        if file_processing.is_paused:
            file_processing.is_paused = False
            self.btn_pause_mon.config(text="暂停")
            self.log_mon("[*] 监控已继续...")
        else:
            file_processing.is_paused = True
            self.btn_pause_mon.config(text="继续")
            self.log_mon("[*] 监控已暂停...")

    def stop_monitor(self):
        file_processing.is_running = False
        self.log_mon("正在发送停止信号...")


    def create_scanner_tab(self):
        frame = self._add_page("scanner", padding=20)

        control_frame = ttk.LabelFrame(frame, text="WebShell 查杀", padding=12)
        control_frame.pack(fill=X, pady=(0, 12))

        # 扫描模式
        ttk.Label(control_frame, text="扫描模式:").grid(row=0, column=0, padx=(0, 8), pady=5, sticky=E)
        self.scan_mode = tk.StringVar(value="remote")
        mode_frame = ttk.Frame(control_frame)
        mode_frame.grid(row=0, column=1, padx=8, pady=5, sticky=W)
        ttk.Radiobutton(mode_frame, text="远端(SSH)", variable=self.scan_mode,
                         value="remote").pack(side=LEFT, padx=(0, 12))
        ttk.Radiobutton(mode_frame, text="本地", variable=self.scan_mode,
                         value="local").pack(side=LEFT)

        # 目标路径
        ttk.Label(control_frame, text="目标路径:").grid(row=1, column=0, padx=(0, 8), pady=5, sticky=E)
        self.scan_path = ttk.Entry(control_frame, width=46)
        self.scan_path.insert(0, "/var/www/html/")
        self.scan_path.grid(row=1, column=1, padx=8, pady=5, sticky=EW)

        self.btn_scan_pick = ttk.Button(control_frame, text="选择本地目录", command=self.pick_scan_dir)
        self.btn_scan_pick.grid(row=1, column=2, padx=8, pady=5)

        # 阈值
        ttk.Label(control_frame, text="判定阈值:").grid(row=2, column=0, padx=(0, 8), pady=5, sticky=E)
        thr_box = ttk.Frame(control_frame)
        thr_box.grid(row=2, column=1, padx=8, pady=5, sticky=W)
        self.scan_threshold = ttk.Entry(thr_box, width=8)
        self.scan_threshold.insert(0, str(webshell_scanner.DEFAULT_THRESHOLD))
        self.scan_threshold.pack(side=LEFT)
        self.scan_threshold.bind("<KeyRelease>", self.update_threshold_hint)
        self.btn_threshold_help = ttk.Button(
            thr_box, text="阈值说明", width=9,
            command=self.show_threshold_help)
        self.btn_threshold_help.pack(side=LEFT, padx=(6, 0))

        # 随输入实时显示两条判定线（可疑线 = 阈值的 40%，与阈值联动）
        # 独占一行：早前与 thr_box 挤在同一格、靠 padx=190 硬推开，
        # 而 thr_box 在 150% DPI 下比 190px 宽，两者直接叠在一起。
        self.threshold_hint = ttk.Label(control_frame, text="", style="CardMuted.TLabel")
        self.threshold_hint.grid(row=3, column=1, columnspan=2,
                                 padx=8, pady=(0, 4), sticky=W)

        # 自动删除
        self.scan_auto_delete = tk.IntVar(value=0)
        self.chk_scan_delete = ttk.Checkbutton(
            control_frame,
            text="自动删除恶意文件",
            variable=self.scan_auto_delete,
        )
        self.chk_scan_delete.grid(row=2, column=2, padx=8, pady=5, sticky=W)

        self.update_threshold_hint()

        # 按钮
        btn_frame = ttk.Frame(control_frame)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=(10, 0), sticky=W)
        self.btn_scan_start = ttk.Button(btn_frame, text="开始查杀", style="Accent.TButton", command=self.start_scan)
        self.btn_scan_start.pack(side=LEFT, padx=(0, 10))
        self.btn_scan_save = ttk.Button(btn_frame, text="保存报告", command=self.save_scan_report,
                                         state=DISABLED)
        self.btn_scan_save.pack(side=LEFT, padx=(0, 10))
        self.btn_scan_clear = ttk.Button(btn_frame, text="清空日志", command=self.clear_scan_log)
        self.btn_scan_clear.pack(side=LEFT)
        # 处置按钮：仅注释「命中那几行」，不动文件其余部分；
        # 且只对判定为「恶意」(level 3) 的文件开放，可疑项一律跳过
        self.btn_scan_quarantine = ttk.Button(btn_frame, text="注释危险代码", style="Danger.TButton",
                                               command=self.run_quarantine,
                                               state=DISABLED)
        self.btn_scan_quarantine.pack(side=LEFT, padx=(10, 0))

        control_frame.columnconfigure(1, weight=1)

        # 统计栏
        self.scan_summary = ttk.Label(frame, text="就绪", style="Info.TLabel")
        self.scan_summary.pack(fill=X, pady=(0, 8))

        # 结果区
        log_frame = ttk.LabelFrame(frame, text="查杀结果", padding=10)
        log_frame.pack(expand=True, fill=BOTH)
        self.scan_log = scrolledtext.ScrolledText(log_frame, font=ui.FONT_MONO)
        self.scan_log.pack(expand=True, fill=BOTH)

    def log_scan(self, msg):
        clean_msg = strip_ansi(str(msg)) + "\n"
        self.scan_log.after(0, lambda: self._append_log(self.scan_log, clean_msg))

    def clear_scan_log(self):
        self.scan_log.delete(1.0, END)

    def pick_scan_dir(self):
        path = filedialog.askdirectory(title="选择要扫描的目录")
        if path:
            self.scan_mode.set("local")
            self.scan_path.delete(0, END)
            self.scan_path.insert(0, path)

    # ------------------------------------------------------------ 阈值说明
    def update_threshold_hint(self, *_):
        """阈值输入变化时刷新两条判定线的位置与档位评价。

        可疑线 = 阈值 × SUSPECT_RATIO，与阈值联动 —— 所以调阈值会同时移动两条线。
        """
        try:
            t = int(self.scan_threshold.get().strip())
            if t <= 0:
                raise ValueError
        except (ValueError, AttributeError):
            self.threshold_hint.config(text="请输入正整数", style="CardDanger.TLabel")
            return
        sus = int(t * webshell_scanner.SUSPECT_RATIO)
        if t < 100:
            lvl, style = "极敏感·易误报", "CardDanger.TLabel"
        elif t < 180:
            lvl, style = "偏敏感", "CardWarning.TLabel"
        elif t <= 260:
            lvl, style = "平衡·推荐", "CardSuccess.TLabel"
        elif t <= 400:
            lvl, style = "偏保守", "CardWarning.TLabel"
        else:
            lvl, style = "很保守·易漏报", "CardDanger.TLabel"
        self.threshold_hint.config(
            text="恶意 ≥%d ｜ 可疑 ≥%d ｜ %s" % (t, sus, lvl), style=style)

    def show_threshold_help(self):
        """弹窗详解检测阈值：代表什么、分数怎么来、高低怎么取舍。"""
        try:
            t = int(self.scan_threshold.get().strip())
            if t <= 0:
                raise ValueError
        except ValueError:
            t = webshell_scanner.DEFAULT_THRESHOLD
        sus = int(t * webshell_scanner.SUSPECT_RATIO)
        dft = webshell_scanner.DEFAULT_THRESHOLD

        content = """检测阈值说明
================================================================

【一句话】
阈值是「判定为恶意」的分数分界线。分数由命中的特征累加而来。


【三条判定线】                         当前阈值 %(T)d
   分数 >= %(T)d       ->  【恶意】 建议立即处置（可开启自动删除）
   分数 >= %(S)d       ->  【可疑】 必须人工确认，本工具不会自动处置
   分数 <  %(S)d       ->   干净   不记录

   ※ 可疑线 = 阈值 × 40%%，与阈值联动
     调阈值会同时移动两条线，无法只改其中一条。


【阈值高低代表什么】
   阈值调低 = 更激进：检出率上升，误报同时上升
   阈值调高 = 更保守：误报下降，变种/免杀马可能藏在阈值之下被漏掉


【分数是怎么算出来的】
每个命中特征按危险程度带权重，累加成总分：

   常见载体函数（file_get_contents / fopen / chr / array_map 等）   20-35 分
     这类函数本身不危险，正常业务代码大量使用，所以权重低

   危险函数名（eval / system / 回调函数 / 文件写入）               40-70 分
     单独出现说明代码具备执行任意操作的能力，但未必是后门

   强特征（编码混淆链 / 工具签名 / 冰蝎·哥斯拉指纹 / 挖矿域名）    70-110 分
     这类特征几乎只出现在木马中

   组合规则（危险函数 + 外部输入同时出现）                        90-150 分
     例：eval + $_POST  ->  这是「一句话木马」的完整形态，
     单看每个特征都不致命，同现才构成证据

   同一特征重复出现会放大：2-3 次 ×1.5，3 次以上 ×2
   长特征（>=20 字节，多为样本级签名）走子串匹配，短特征走词边界匹配
   （避免 eval 命中 reeval）


【典型文件的分数参考】
   正常业务代码（含文件读写、数组处理、模板渲染）        0 - 80
   正常运维脚本（单独一个 system 调用）               60 - 90
   一句话木马  eval($_POST[1])                          245
   变量函数马  $k($_POST[...])                          210
   图片马 / 混淆大马                                  300 - 600
   冰蝎 Behinder                                      600 - 1100
   哥斯拉 Godzilla                                    600 - 900


【阈值怎么调】
   100 以下     不推荐 —— 大量正常业务代码会被判「可疑」
   100 - 180    偏敏感 —— 应急响应场景，宁可错杀
   %(D)d        默认值，平衡点，适合 AWD 常规防守
   260 - 400    偏保守 —— 只看铁证，可能漏掉变种马
   400 以上     很保守 —— 仅用于生产环境压制误报

调低的代价：需要人工排查的「可疑」文件变多
调高的代价：漏报变多，免杀马可能从阈值之下溜过


【阈值高低对判定的实际影响】（实测）

   样本                     分数   100   150  [200]  300   500  1000
   ------------------------------------------------------------------
   一句话木马 eval($_POST)   245   恶意  恶意  恶意  可疑  可疑  干净
   变量函数马 $k($_POST[])   210   恶意  恶意  恶意  可疑  可疑  干净
   冰蝎 Behinder            1015   恶意  恶意  恶意  恶意  恶意  恶意
   正常业务代码              20    干净  干净  干净  干净  干净  干净

   [200] = 默认阈值。阈值调到 300 以上时，典型一句话木马会从
   「恶意」降为「可疑」—— 不再触发自动处置，需要人工确认。

【实测参考】默认阈值 %(D)d 下的表现
   真实样本集（815 个脚本）      检出 92.0%%
   正常业务代码（500 个 PHP）     误报 0
   扫描速度                      约 1.4 ms/文件

================================================================
""" % {"T": t, "S": sus, "D": dft}

        win = tk.Toplevel(self)
        win.title("检测阈值说明")
        win.geometry("%dx%d" % (ui.px(820), ui.px(640)))
        win.transient(self)
        # Toplevel 是运行时新建的，不在启动时的兜底扫描范围内，单独配色
        txt = ui.style_text(scrolledtext.ScrolledText(win, wrap="word"))
        txt.pack(fill=BOTH, expand=True, padx=ui.px(12), pady=(ui.px(12), ui.px(8)))
        txt.insert("1.0", content)
        txt.config(state=DISABLED)
        ttk.Button(win, text="关闭", style="Accent.TButton",
                   command=win.destroy).pack(pady=(0, ui.px(12)))
        ui.apply_dark_title_bar(win)

    def start_scan(self):
        if self.scan_running:
            messagebox.showinfo("提示", "扫描正在进行中")
            return

        mode = self.scan_mode.get()
        target = self.scan_path.get().strip()
        if not target:
            messagebox.showwarning("警告", "请填写目标路径")
            return
        if mode == "remote" and not state_manager.is_ssh:
            messagebox.showwarning("警告", "请先在 SSH 选项卡测试并连接 SSH")
            return

        try:
            threshold = int(self.scan_threshold.get().strip() or webshell_scanner.DEFAULT_THRESHOLD)
        except ValueError:
            messagebox.showwarning("警告", "阈值必须是整数")
            return
        webshell_scanner.DEFAULT_THRESHOLD = threshold

        auto_delete = bool(self.scan_auto_delete.get())
        if auto_delete:
            if not messagebox.askyesno("危险操作", "确认自动删除判定为恶意的文件？"):
                return

        self.scan_running = True
        self.scan_stop_event.clear()
        self.scan_used_mode = mode
        self.btn_scan_start.config(state=DISABLED, text="查杀中...")
        self.btn_scan_save.config(state=DISABLED)
        self.btn_scan_quarantine.config(state=DISABLED)
        self.scan_log.delete(1.0, END)
        self.scan_summary.config(text="扫描中...", style="Warning.TLabel")

        def work():
            try:
                if mode == "remote":
                    results, total = webshell_scanner.scan_remote(
                        remote_dir=target,
                        threshold=threshold,
                        log_callback=self.log_scan,
                        auto_delete=auto_delete,
                    )
                else:
                    results, total = webshell_scanner.scan_local(
                        target,
                        threshold=threshold,
                        log_callback=self.log_scan,
                        auto_delete=auto_delete,
                    )
                self.scan_results = results
                self.scan_total = total
                report = webshell_scanner.format_report(results, total, threshold)
                self.log_scan(report)
                mal = sum(1 for r in results if r["verdict"] == "malicious")
                sus = len(results) - mal
                summary = f"扫描 {total} 个文件 | 恶意 {mal} | 可疑 {sus}"
                style = ("Danger.TLabel" if mal
                         else ("Warning.TLabel" if sus else "Success.TLabel"))
                self.scan_summary.after(0, lambda s=style: self.scan_summary.config(
                    text=summary, style=s))
                self.btn_scan_save.after(0, lambda: self.btn_scan_save.config(
                    state=NORMAL if results else DISABLED))
                # 只有存在「恶意」级结果时才允许处置
                n_mal = sum(1 for r in results if r.get("level") == 3)
                self.btn_scan_quarantine.after(0, lambda: self.btn_scan_quarantine.config(
                    state=NORMAL if n_mal else DISABLED))
            except Exception as exc:
                self.log_scan(f"[x] 扫描异常: {exc}")
                self.scan_summary.after(0, lambda: self.scan_summary.config(
                    text="扫描失败", style="Danger.TLabel"))
            finally:
                self.scan_running = False
                self.btn_scan_start.after(0, lambda: self.btn_scan_start.config(
                    state=NORMAL, text="开始查杀"))

        threading.Thread(target=work, daemon=True).start()

    def save_scan_report(self):
        if not self.scan_results:
            messagebox.showinfo("提示", "没有可保存的结果")
            return
        path = webshell_scanner.save_report(self.scan_results, self.scan_total)
        if path:
            self.log_scan(f"[+] 报告已保存: {path}")
            messagebox.showinfo("成功", f"报告已保存到:\n{path}")
        else:
            messagebox.showerror("失败", "报告保存失败")

    def run_quarantine(self):
        """一键注释判定为「恶意」的文件中的危险代码行。

        安全约束（缺一不可）：
          * 只处理 level==3(恶意)；level==2(可疑) 一律跳过 —— 可疑项有误报可能，
            自动改动会误伤正常业务代码
          * 只注释命中那几行，文件其余内容保持原样
          * 修改前自动备份为 <文件>.<时间戳>.bak，可随时回滚
          * 生成计划 -> 人工确认 -> 才执行，确认前不写任何文件
        """
        if self.scan_running:
            messagebox.showinfo("提示", "扫描正在进行中")
            return

        mal = [r for r in (self.scan_results or []) if r.get("level") == 3]
        if not mal:
            messagebox.showinfo(
                "提示",
                "没有判定为「恶意」的文件。\n\n"
                "「可疑」文件不会被自动处理 —— 它们有可能是正常业务代码，"
                "请人工确认后再处理。")
            return

        self.scan_running = True
        self.btn_scan_quarantine.config(state=DISABLED, text="处理中...")
        self.scan_summary.config(text="正在生成注释计划...", style="Warning.TLabel")

        def work():
            ssh_client = sftp_client = None
            try:
                if getattr(self, "scan_used_mode", "local") == "remote":
                    if not state_manager.is_ssh:
                        self.log_scan("[x] SSH 未连接，无法处置远端文件")
                        return
                    ssh_client = ssh.connect_ssh_client()
                    sftp_client = ssh_client.open_sftp()

                self.log_scan("[*] 生成待注释行计划（仅恶意文件，可疑项跳过）...")
                plan = webshell_scanner.build_quarantine_plan(
                    self.scan_results, log_callback=self.log_scan,
                    sftp_client=sftp_client)
                if not plan:
                    self.log_scan("[!] 没有可安全自动注释的行，未做任何修改")
                    self.scan_log.after(0, lambda: self.scan_summary.config(
                        text="无可安全注释的行", style="Warning.TLabel"))
                    return

                self.log_scan(webshell_scanner.format_quarantine_plan(plan))

                n_files = len(plan)
                n_lines = sum(1 for p in plan for e in p["lines"] if e["ok"])
                holder = {}
                done = threading.Event()

                def ask():
                    holder["ok"] = messagebox.askyesno(
                        "确认注释危险代码",
                        f"即将注释 {n_files} 个文件中的 {n_lines} 行危险代码。\n\n"
                        f"· 仅处理判定为「恶意」的文件，可疑项已跳过\n"
                        f"· 只注释命中那几行，文件其余内容不变\n"
                        f"· 修改前自动备份为 <文件名>.<时间戳>.bak\n\n"
                        f"详细清单已输出到下方日志，请先核对。\n\n确认执行？")
                    done.set()

                self.scan_log.after(0, ask)
                done.wait(timeout=600)
                if not holder.get("ok"):
                    self.log_scan("[*] 已取消，未修改任何文件")
                    self.scan_log.after(0, lambda: self.scan_summary.config(
                        text="已取消", style="Muted.TLabel"))
                    return

                stats = webshell_scanner.apply_quarantine(
                    plan, log_callback=self.log_scan, sftp_client=sftp_client)
                self.log_scan(f"[*] 处置完成: 修改 {stats['files']} 个文件 / "
                              f"注释 {stats['lines']} 行 / 备份 {len(stats['backups'])} 份")
                for p, why in stats["failed"]:
                    self.log_scan(f"[!] 未处理 {p}: {why}")
                self.log_scan("[*] 建议重新执行一次查杀，确认处置效果")
                self.scan_log.after(0, lambda: self.scan_summary.config(
                    text=f"已注释 {stats['lines']} 行危险代码（{stats['files']} 个文件）",
                    style="Success.TLabel"))
            except Exception as exc:
                self.log_scan(f"[x] 处置失败: {exc}")
                self.scan_log.after(0, lambda: self.scan_summary.config(
                    text="处置失败", style="Danger.TLabel"))
            finally:
                for c in (sftp_client, ssh_client):
                    try:
                        if c:
                            c.close()
                    except Exception:
                        pass
                self.scan_running = False
                self.btn_scan_quarantine.after(0, lambda: self.btn_scan_quarantine.config(
                    state=NORMAL, text="注释危险代码"))

        threading.Thread(target=work, daemon=True).start()


    def create_tar_tab(self):
        frame = self._add_page("tar", padding=20)

        control_frame = ttk.LabelFrame(frame, text="源码备份与恢复", padding=12)
        control_frame.pack(fill=X, pady=(0, 15))

        ttk.Label(control_frame, text="打包目录:").grid(row=0, column=0, padx=6, pady=6, sticky=E)
        self.tar_path = ttk.Entry(control_frame, width=32)
        self.tar_path.insert(0, "/var/www/html/")
        self.tar_path.grid(row=0, column=1, padx=6, pady=6, sticky=EW)

        ttk.Label(control_frame, text="下载到:").grid(row=0, column=2, padx=6, pady=6, sticky=E)
        self.tar_local_dir = ttk.Entry(control_frame, width=26)
        self.tar_local_dir.insert(0, file_processing.get_default_local_dir())
        self.tar_local_dir.grid(row=0, column=3, padx=6, pady=6, sticky=EW)

        self.btn_pick_tar_dir = ttk.Button(control_frame, text="选择目录", command=self.pick_tar_dir)
        self.btn_pick_tar_dir.grid(row=0, column=4, padx=6, pady=6)

        self.btn_tar = ttk.Button(control_frame, text="打包并下载", style="Accent.TButton", command=self.run_tar)
        self.btn_tar.grid(row=0, column=5, padx=6, pady=6)

        ttk.Label(control_frame, text="备份包:").grid(row=1, column=0, padx=6, pady=6, sticky=E)
        self.tar_backup_file = ttk.Entry(control_frame, width=42)
        self.tar_backup_file.grid(row=1, column=1, columnspan=3, padx=6, pady=6, sticky=EW)

        self.btn_pick_backup = ttk.Button(control_frame, text="选择备份", command=self.pick_backup_tar)
        self.btn_pick_backup.grid(row=1, column=4, padx=6, pady=6)

        self.btn_deploy_backup = ttk.Button(control_frame, text="一键部署", style="Success.TButton", command=self.run_deploy_backup)
        self.btn_deploy_backup.grid(row=1, column=5, padx=6, pady=6)
        control_frame.columnconfigure(1, weight=1)
        control_frame.columnconfigure(3, weight=1)

        log_frame = ttk.LabelFrame(frame, text="执行日志", padding=10)
        log_frame.pack(expand=True, fill=BOTH)
        
        self.tar_log = scrolledtext.ScrolledText(log_frame, font=ui.FONT_MONO)
        self.tar_log.pack(expand=True, fill=BOTH)

    def log_tar(self, msg):
        clean_msg = strip_ansi(str(msg)) + "\n"
        self.tar_log.after(0, lambda: self._append_log(self.tar_log, clean_msg))

    def run_tar(self):
        if not state_manager.is_ssh:
            messagebox.showwarning("警告", "请先在 SSH 选项卡测试并连接 SSH")
            return
            
        path = self.tar_path.get()
        local_dir = self.tar_local_dir.get().strip() or file_processing.get_default_local_dir()
        self.btn_tar.config(state=DISABLED)
        self.tar_log.delete(1.0, END)

        def execute_tar():
            try:
                local_tar_path = file_processing.tar(remote_path=path, local_dir=local_dir,
                                                     log_callback=self.log_tar)

                # 下载成功后打开文件所在目录
                if local_tar_path and os.path.exists(local_tar_path):
                    try:
                        if os.name == 'nt':
                            subprocess.run(['explorer', '/select,', os.path.normpath(local_tar_path)])
                        elif sys.platform == 'darwin':
                            subprocess.run(['open', '-R', local_tar_path])
                        else:
                            subprocess.run(['xdg-open', os.path.dirname(local_tar_path)])
                    except Exception as e:
                        self.log_tar(f"[*] 无法自动打开文件目录: {e}")
            except Exception as exc:
                # SSH 掉线时 paramiko 异常会直接抛到这里，缺这层保护会导致
                # "打包并下载"按钮永久禁用
                self.log_tar(f"[x] 打包失败: {type(exc).__name__}: {exc}")
            finally:
                self.btn_tar.after(0, lambda: self.btn_tar.config(state=NORMAL))

        threading.Thread(target=execute_tar, daemon=True).start()

    def pick_tar_dir(self):
        directory = filedialog.askdirectory(title="选择源码包下载目录")
        if directory:
            self.tar_local_dir.delete(0, END)
            self.tar_local_dir.insert(0, directory)

    def pick_backup_tar(self):
        file_path = filedialog.askopenfilename(
            title="选择备份包",
            filetypes=[("Tar GZ", "*.tar.gz"), ("Tar", "*.tar"), ("All Files", "*.*")]
        )
        if file_path:
            self.tar_backup_file.delete(0, END)
            self.tar_backup_file.insert(0, file_path)

    def run_deploy_backup(self):
        if not state_manager.is_ssh:
            messagebox.showwarning("警告", "请先在 SSH 选项卡测试并连接 SSH")
            return

        remote_path = self.tar_path.get().strip() or "/var/www/html/"
        backup_file = self.tar_backup_file.get().strip()
        if not backup_file:
            messagebox.showwarning("警告", "请先选择备份包")
            return
        if not messagebox.askyesno("确认部署", f"将清空远端目录并部署备份包：\n{remote_path}\n是否继续？"):
            return

        self.btn_deploy_backup.config(state=DISABLED)
        self.log_tar("• 开始一键部署备份...")

        def execute_deploy():
            try:
                ok = file_processing.deploy_tar(backup_file, remote_path=remote_path, log_callback=self.log_tar)
                if ok:
                    self.log_tar("✓ 一键部署完成")
            except Exception as exc:
                self.log_tar(f"[x] 部署失败: {type(exc).__name__}: {exc}")
            finally:
                self.btn_deploy_backup.after(0, lambda: self.btn_deploy_backup.config(state=NORMAL))

        threading.Thread(target=execute_deploy, daemon=True).start()

    def create_attacker_tab(self):
        frame = self._add_page("attacker", padding=15)

        top = ttk.Panedwindow(frame, orient=HORIZONTAL)
        top.pack(fill=X, pady=(0, 10))

        scan_frame = ttk.LabelFrame(top, text="探活与存活列表", padding=10)
        shell_frame = ttk.LabelFrame(top, text="后门检测与命令执行", padding=10)
        top.add(scan_frame, weight=1)
        top.add(shell_frame, weight=1)

        ttk.Label(scan_frame, text="URL模板:").grid(row=0, column=0, padx=5, pady=5, sticky=E)
        self.attack_url_pattern = ttk.Entry(scan_frame, width=48)
        self.attack_url_pattern.insert(0, "http://192-168-1-?.awd.example-ctf.com/")
        self.attack_url_pattern.grid(row=0, column=1, columnspan=3, padx=5, pady=5, sticky=EW)

        ttk.Label(scan_frame, text="编号:").grid(row=1, column=0, padx=5, pady=5, sticky=E)
        self.attack_start = ttk.Entry(scan_frame, width=8)
        self.attack_start.insert(0, "0")
        self.attack_start.grid(row=1, column=1, padx=5, pady=5, sticky=W)
        self.attack_end = ttk.Entry(scan_frame, width=8)
        self.attack_end.insert(0, "255")
        self.attack_end.grid(row=1, column=2, padx=5, pady=5, sticky=W)

        ttk.Label(scan_frame, text="存活文件:").grid(row=2, column=0, padx=5, pady=5, sticky=E)
        self.attack_output_file = ttk.Entry(scan_frame, width=35)
        self.attack_output_file.insert(0, "output.txt")
        self.attack_output_file.grid(row=2, column=1, columnspan=2, padx=5, pady=5, sticky=EW)

        self.btn_attack_scan = ttk.Button(scan_frame, text="快速探活并写入", command=self.run_attack_scan)
        self.btn_attack_scan.grid(row=3, column=0, padx=5, pady=8)
        self.btn_attack_read = ttk.Button(scan_frame, text="从文件读入", command=self.run_attack_read)
        self.btn_attack_read.grid(row=3, column=1, padx=5, pady=8)
        self.btn_attack_pick = ttk.Button(scan_frame, text="选择文件", command=self.pick_attack_file)
        self.btn_attack_pick.grid(row=3, column=2, padx=5, pady=8)

        self.attack_active_summary = ttk.Label(scan_frame, text="存活目标: 0")
        self.attack_active_summary.grid(row=4, column=0, columnspan=4, padx=5, pady=5, sticky=W)
        scan_frame.columnconfigure(1, weight=1)
        scan_frame.columnconfigure(2, weight=1)

        ttk.Label(shell_frame, text="后门路径:").grid(row=0, column=0, padx=5, pady=5, sticky=E)
        self.attack_backdoor_path = ttk.Entry(shell_frame, width=38)
        self.attack_backdoor_path.insert(0, "public/img/1.php")
        self.attack_backdoor_path.grid(row=0, column=1, columnspan=3, padx=5, pady=5, sticky=EW)

        ttk.Label(shell_frame, text="key方式:").grid(row=1, column=0, padx=5, pady=5, sticky=E)
        self.attack_key_method = ttk.Combobox(shell_frame, values=["0 无", "1 GET", "2 POST"], width=10, state="readonly")
        self.attack_key_method.set("0 无")
        self.attack_key_method.grid(row=1, column=1, padx=5, pady=5, sticky=W)
        self.attack_key = ttk.Entry(shell_frame, width=14)
        self.attack_key.grid(row=1, column=2, padx=5, pady=5, sticky=EW)
        self.attack_key_value = ttk.Entry(shell_frame, width=18)
        self.attack_key_value.grid(row=1, column=3, padx=5, pady=5, sticky=EW)

        ttk.Label(shell_frame, text="命令方式:").grid(row=2, column=0, padx=5, pady=5, sticky=E)
        self.attack_cmd_method = ttk.Combobox(shell_frame, values=["1 GET", "2 POST"], width=10, state="readonly")
        self.attack_cmd_method.set("2 POST")
        self.attack_cmd_method.grid(row=2, column=1, padx=5, pady=5, sticky=W)
        ttk.Label(shell_frame, text="参数名:").grid(row=2, column=2, padx=5, pady=5, sticky=E)
        self.attack_payload = ttk.Entry(shell_frame, width=18)
        self.attack_payload.insert(0, "cmd")
        self.attack_payload.grid(row=2, column=3, padx=5, pady=5, sticky=EW)

        self.btn_attack_check = ttk.Button(shell_frame, text="检测已知后门", command=self.run_attack_check)
        self.btn_attack_check.grid(row=3, column=0, padx=5, pady=8)
        self.attack_shell_select = ttk.Combobox(shell_frame, values=[], width=30, state="readonly")
        self.attack_shell_select.grid(row=3, column=1, columnspan=2, padx=5, pady=8, sticky=EW)
        self.btn_attack_refresh = ttk.Button(shell_frame, text="刷新", command=self.refresh_attack_shells)
        self.btn_attack_refresh.grid(row=3, column=3, padx=5, pady=8)

        ttk.Label(shell_frame, text="执行内容:").grid(row=4, column=0, padx=5, pady=5, sticky=E)
        self.attack_command = ttk.Entry(shell_frame, width=42)
        self.attack_command.insert(0, "system('id');")
        self.attack_command.grid(row=4, column=1, columnspan=3, padx=5, pady=5, sticky=EW)
        self.btn_attack_exec = ttk.Button(shell_frame, text="执行命令", command=self.run_attack_exec)
        self.btn_attack_exec.grid(row=5, column=0, padx=5, pady=8)

        ttk.Label(shell_frame, text="写入目录:").grid(row=5, column=1, padx=5, pady=5, sticky=E)
        self.attack_remote_dir = ttk.Entry(shell_frame, width=20)
        self.attack_remote_dir.insert(0, "/var/www/html/")
        self.attack_remote_dir.grid(row=5, column=2, padx=5, pady=5, sticky=EW)
        self.attack_url_dir = ttk.Entry(shell_frame, width=10)
        self.attack_url_dir.insert(0, "/")
        self.attack_url_dir.grid(row=5, column=3, padx=5, pady=5, sticky=EW)

        self.attack_with_key = tk.IntVar(value=1)
        self.chk_attack_key_shell = ttk.Checkbutton(
            shell_frame,
            text="生成带 key 后门",
            variable=self.attack_with_key,
        )
        self.chk_attack_key_shell.grid(row=6, column=1, padx=5, pady=8, sticky=W)
        self.btn_attack_upload = ttk.Button(shell_frame, text="生成新后门并上传", command=self.run_attack_upload)
        self.btn_attack_upload.grid(row=6, column=2, columnspan=2, padx=5, pady=8, sticky=EW)
        shell_frame.columnconfigure(1, weight=1)
        shell_frame.columnconfigure(2, weight=1)
        shell_frame.columnconfigure(3, weight=1)

        log_frame = ttk.LabelFrame(frame, text="攻击辅助日志", padding=10)
        log_frame.pack(expand=True, fill=BOTH)
        self.attack_log = scrolledtext.ScrolledText(log_frame, font=ui.FONT_MONO)
        self.attack_log.pack(expand=True, fill=BOTH)

    def log_attack(self, msg):
        clean_msg = strip_ansi(str(msg)) + "\n"
        self.attack_log.after(0, lambda: self._append_log(self.attack_log, clean_msg))

    def set_attack_buttons(self, state_value):
        buttons = [
            self.btn_attack_scan,
            self.btn_attack_read,
            self.btn_attack_check,
            self.btn_attack_exec,
            self.btn_attack_upload,
        ]
        for button in buttons:
            button.after(0, lambda b=button: b.config(state=state_value))

    def refresh_attack_shells(self):
        labels = [shell.label() for shell in self.attacker_session.known_shells]
        self.attack_shell_select.config(values=labels)
        if labels and not self.attack_shell_select.get():
            self.attack_shell_select.set(labels[0])
        self.attack_active_summary.config(text=f"存活目标: {len(self.attacker_session.active_urls)}")

    def load_default_attack_shells(self):
        try:
            self.attacker_session.load(attacker_tools.DEFAULT_SHELL_STORE)
            self.refresh_attack_shells()
            self.log_attack(f"[*] 已自动加载 {attacker_tools.DEFAULT_SHELL_STORE}")
        except FileNotFoundError:
            pass
        except Exception as exc:
            self.log_attack(f"[!] 自动加载后门配置失败: {exc}")

    def selected_attack_shell(self):
        value = self.attack_shell_select.get().strip()
        if not value:
            messagebox.showwarning("警告", "请先检测或选择一个后门")
            return None
        try:
            number = int(value.split(":", 1)[0])
        except ValueError:
            messagebox.showwarning("警告", "后门编号解析失败")
            return None
        shell = self.attacker_session.get_shell(number)
        if not shell:
            messagebox.showwarning("警告", "后门不存在，请刷新列表")
        return shell

    def pick_attack_file(self):
        file_path = filedialog.askopenfilename(title="选择存活目标文件", filetypes=[("Text", "*.txt"), ("All Files", "*.*")])
        if file_path:
            self.attack_output_file.delete(0, END)
            self.attack_output_file.insert(0, file_path)

    def run_attack_scan(self):
        self.attack_log.delete(1.0, END)
        self.set_attack_buttons(DISABLED)

        def work():
            try:
                urls = attacker_tools.scan_alive(
                    self.attack_url_pattern.get().strip(),
                    output_file=self.attack_output_file.get().strip() or "output.txt",
                    start=int(self.attack_start.get().strip() or "0"),
                    end=int(self.attack_end.get().strip() or "255"),
                    log_callback=self.log_attack,
                )
                self.attacker_session.set_active_urls(urls)
                self.attack_active_summary.after(0, lambda: self.attack_active_summary.config(text=f"存活目标: {len(urls)}"))
            except Exception as exc:
                self.log_attack(f"[x] 探活失败: {exc}")
            finally:
                self.set_attack_buttons(NORMAL)

        threading.Thread(target=work, daemon=True).start()

    def run_attack_read(self):
        self.set_attack_buttons(DISABLED)

        def work():
            try:
                urls = attacker_tools.read_active_file(self.attack_output_file.get().strip() or "output.txt", log_callback=self.log_attack)
                self.attacker_session.set_active_urls(urls)
                self.attack_active_summary.after(0, lambda: self.attack_active_summary.config(text=f"存活目标: {len(urls)}"))
                self.log_attack(f"[*] 当前存活目标 {len(urls)} 个")
            except Exception as exc:
                self.log_attack(f"[x] 读取失败: {exc}")
            finally:
                self.set_attack_buttons(NORMAL)

        threading.Thread(target=work, daemon=True).start()

    def run_attack_check(self):
        self.set_attack_buttons(DISABLED)

        def work():
            try:
                key_method = self.attack_key_method.get().split()[0]
                cmd_method = self.attack_cmd_method.get().split()[0]
                shell = attacker_tools.check_known_backdoor(
                    self.attacker_session.active_urls,
                    self.attack_backdoor_path.get().strip(),
                    key_method=key_method,
                    key=self.attack_key.get().strip(),
                    key_value=self.attack_key_value.get().strip(),
                    cmd_method=cmd_method,
                    payload=self.attack_payload.get().strip(),
                    log_callback=self.log_attack,
                )
                if shell:
                    self.attacker_session.add_shell(shell)
                    self.log_attack(f"[+] 已添加后门编号: {shell.number}")
                    self.attack_shell_select.after(0, self.refresh_attack_shells)
            except Exception as exc:
                self.log_attack(f"[x] 检测失败: {exc}")
            finally:
                self.set_attack_buttons(NORMAL)

        threading.Thread(target=work, daemon=True).start()

    def run_attack_exec(self):
        shell = self.selected_attack_shell()
        if not shell:
            return
        command = self.attack_command.get()
        self.set_attack_buttons(DISABLED)

        def work():
            try:
                attacker_tools.execute_shell_command(shell, command, log_callback=self.log_attack)
            except Exception as exc:
                self.log_attack(f"[x] 执行失败: {exc}")
            finally:
                self.set_attack_buttons(NORMAL)

        threading.Thread(target=work, daemon=True).start()

    def run_attack_upload(self):
        shell = self.selected_attack_shell()
        if not shell:
            return
        self.set_attack_buttons(DISABLED)

        def work():
            try:
                new_shell = attacker_tools.upload_generated_backdoor(
                    shell,
                    remote_dir=self.attack_remote_dir.get().strip() or "/var/www/html/",
                    url_dir=self.attack_url_dir.get().strip() or "/",
                    with_key=bool(self.attack_with_key.get()),
                    log_callback=self.log_attack,
                )
                if new_shell:
                    self.attacker_session.add_shell(new_shell)
                    self.log_attack(f"[+] 已添加新后门编号: {new_shell.number}")
                    self.attack_shell_select.after(0, self.refresh_attack_shells)
                    try:
                        saved_path = attacker_tools.save_session(self.attacker_session)
                        self.log_attack(f"[+] 已自动保存后门配置: {saved_path}")
                    except Exception as save_exc:
                        self.log_attack(f"[!] 自动保存失败: {save_exc}")
            except Exception as exc:
                self.log_attack(f"[x] 上传失败: {exc}")
            finally:
                self.set_attack_buttons(NORMAL)

        threading.Thread(target=work, daemon=True).start()

    def create_bugku_tab(self):
        frame = self._add_page("bugku", padding=15)

        form = ttk.LabelFrame(frame, text="Bugku PVP 批量提交", padding=12)
        form.pack(fill=X, pady=(0, 10))

        ttk.Label(form, text="域名后缀:").grid(row=0, column=0, padx=6, pady=6, sticky=E)
        self.bugku_domain = ttk.Entry(form, width=28)
        self.bugku_domain.insert(0, attacker_tools.BUGKU_DEFAULT_DOMAIN)
        self.bugku_domain.grid(row=0, column=1, padx=6, pady=6, sticky=EW)

        ttk.Label(form, text="后门路径:").grid(row=0, column=2, padx=6, pady=6, sticky=E)
        self.bugku_path = ttk.Entry(form, width=34)
        self.bugku_path.insert(0, attacker_tools.BUGKU_DEFAULT_PATH)
        self.bugku_path.grid(row=0, column=3, padx=6, pady=6, sticky=EW)

        ttk.Label(form, text="读取命令:").grid(row=1, column=0, padx=6, pady=6, sticky=E)
        self.bugku_cmd = ttk.Entry(form, width=28)
        self.bugku_cmd.insert(0, attacker_tools.BUGKU_DEFAULT_CMD)
        self.bugku_cmd.grid(row=1, column=1, padx=6, pady=6, sticky=EW)

        ttk.Label(form, text="提交Token:").grid(row=1, column=2, padx=6, pady=6, sticky=E)
        self.bugku_token = ttk.Entry(form, width=34)
        self.bugku_token.insert(0, attacker_tools.BUGKU_DEFAULT_TOKEN)
        self.bugku_token.grid(row=1, column=3, padx=6, pady=6, sticky=EW)

        ttk.Label(form, text="范围:").grid(row=2, column=0, padx=6, pady=6, sticky=E)
        self.bugku_range = ttk.Entry(form, width=16)
        self.bugku_range.insert(0, "1-255")
        self.bugku_range.grid(row=2, column=1, padx=6, pady=6, sticky=W)

        ttk.Label(form, text="排除:").grid(row=2, column=2, padx=6, pady=6, sticky=E)
        self.bugku_exclude = ttk.Entry(form, width=20)
        self.bugku_exclude.grid(row=2, column=3, padx=6, pady=6, sticky=W)

        ttk.Label(form, text="线程:").grid(row=3, column=0, padx=6, pady=6, sticky=E)
        self.bugku_threads = ttk.Entry(form, width=8)
        self.bugku_threads.insert(0, "32")
        self.bugku_threads.grid(row=3, column=1, padx=6, pady=6, sticky=W)

        ttk.Label(form, text="日志文件:").grid(row=3, column=2, padx=6, pady=6, sticky=E)
        self.bugku_out = ttk.Entry(form, width=34)
        self.bugku_out.insert(0, "bugku_pvp_results.jsonl")
        self.bugku_out.grid(row=3, column=3, padx=6, pady=6, sticky=EW)

        self.bugku_no_submit = tk.IntVar(value=0)
        self.chk_bugku_no_submit = ttk.Checkbutton(
            form,
            text="只探测不提交",
            variable=self.bugku_no_submit,
        )
        self.chk_bugku_no_submit.grid(row=4, column=1, padx=6, pady=8, sticky=W)

        self.btn_bugku_start = ttk.Button(form, text="开始批量提交", style="Accent.TButton", command=self.run_bugku_submit)
        self.btn_bugku_start.grid(row=4, column=2, padx=6, pady=8)
        self.btn_bugku_stop = ttk.Button(form, text="停止", command=self.stop_bugku_submit, state=DISABLED)
        self.btn_bugku_stop.grid(row=4, column=3, padx=6, pady=8, sticky=W)
        form.columnconfigure(1, weight=1)
        form.columnconfigure(3, weight=1)

        log_frame = ttk.LabelFrame(frame, text="提交日志", padding=10)
        log_frame.pack(expand=True, fill=BOTH)
        self.bugku_log = scrolledtext.ScrolledText(log_frame, font=ui.FONT_MONO)
        self.bugku_log.pack(expand=True, fill=BOTH)

    def log_bugku(self, msg):
        clean_msg = strip_ansi(str(msg)) + "\n"
        self.bugku_log.after(0, lambda: self._append_log(self.bugku_log, clean_msg))

    def set_bugku_running(self, running):
        self.btn_bugku_start.after(0, lambda: self.btn_bugku_start.config(state=DISABLED if running else NORMAL))
        self.btn_bugku_stop.after(0, lambda: self.btn_bugku_stop.config(state=NORMAL if running else DISABLED))

    def run_bugku_submit(self):
        self.bugku_log.delete(1.0, END)
        self.bugku_stop_event = threading.Event()
        self.set_bugku_running(True)

        def work():
            try:
                attacker_tools.bugku_batch_submit(
                    domain=self.bugku_domain.get().strip() or attacker_tools.BUGKU_DEFAULT_DOMAIN,
                    path=self.bugku_path.get().strip() or attacker_tools.BUGKU_DEFAULT_PATH,
                    cmd=self.bugku_cmd.get().strip() or attacker_tools.BUGKU_DEFAULT_CMD,
                    token=self.bugku_token.get().strip() or attacker_tools.BUGKU_DEFAULT_TOKEN,
                    target_range=self.bugku_range.get().strip() or "1-255",
                    exclude=self.bugku_exclude.get().strip(),
                    threads=int(self.bugku_threads.get().strip() or "32"),
                    no_submit=bool(self.bugku_no_submit.get()),
                    out=self.bugku_out.get().strip() or "bugku_pvp_results.jsonl",
                    stop_event=self.bugku_stop_event,
                    log_callback=self.log_bugku,
                )
            except Exception as exc:
                self.log_bugku(f"[x] Bugku 批量提交失败: {exc}")
            finally:
                self.set_bugku_running(False)

        threading.Thread(target=work, daemon=True).start()

    def stop_bugku_submit(self):
        self.bugku_stop_event.set()
        self.log_bugku("[*] 正在停止，已发出的请求会先返回")

    def create_waf_tab(self):
        frame = self._add_page("waf", padding=20)

        control_frame = ttk.LabelFrame(frame, text="WAF 部署", padding=15)
        control_frame.pack(fill=X, pady=(0, 15))

        ttk.Label(control_frame, text="业务目录:").grid(row=0, column=0, padx=10, pady=10, sticky=E)
        self.waf_web_root = ttk.Entry(control_frame, width=40)
        self.waf_web_root.insert(0, "/var/www/html")
        self.waf_web_root.grid(row=0, column=1, padx=10, pady=10, sticky=EW)

        ttk.Label(control_frame, text="隐藏目录:").grid(row=0, column=2, padx=10, pady=10, sticky=E)
        self.waf_remote_dir = ttk.Entry(control_frame, width=40)
        self.waf_remote_dir.insert(0, state_manager.remote_waf_dir)
        self.waf_remote_dir.grid(row=0, column=3, padx=10, pady=10, sticky=EW)

        ttk.Label(control_frame, text="日志目录:").grid(row=1, column=0, padx=10, pady=10, sticky=E)
        self.waf_remote_log_dir = ttk.Entry(control_frame, width=40)
        self.waf_remote_log_dir.insert(0, state_manager.remote_waf_log_dir)
        self.waf_remote_log_dir.grid(row=1, column=1, padx=10, pady=10, sticky=EW)

        ttk.Label(control_frame, text="拦截方式:").grid(row=1, column=2, padx=10, pady=10, sticky=E)
        self.waf_mode = ttk.Combobox(control_frame, values=["1 关键词替换", "2 跳转路由"], width=16, state="readonly")
        self.waf_mode.set("2 跳转路由" if state_manager.waf_mode == 2 else "1 关键词替换")
        self.waf_mode.grid(row=1, column=3, padx=10, pady=10, sticky=W)

        ttk.Label(control_frame, text="严格程度:").grid(row=2, column=0, padx=10, pady=10, sticky=E)
        self.waf_strict_level = ttk.Combobox(control_frame, values=["1 简单", "2 常见", "3 全量"], width=16, state="readonly")
        self.waf_strict_level.set(f"{state_manager.waf_strict_level} " + ("简单" if state_manager.waf_strict_level == 1 else "常见" if state_manager.waf_strict_level == 2 else "全量"))
        self.waf_strict_level.grid(row=2, column=1, padx=10, pady=10, sticky=W)

        ttk.Label(control_frame, text="跳转路由:").grid(row=2, column=2, padx=10, pady=10, sticky=E)
        self.waf_redirect_path = ttk.Entry(control_frame, width=40)
        self.waf_redirect_path.insert(0, state_manager.waf_redirect_path or "/")
        self.waf_redirect_path.grid(row=2, column=3, padx=10, pady=10, sticky=EW)

        self.btn_deploy_waf = ttk.Button(control_frame, text="一键上 WAF", style="Accent.TButton", command=self.deploy_waf)
        self.btn_deploy_waf.grid(row=3, column=0, padx=10, pady=10)

        # WAF 默认只在命中黑名单时记录请求包；开启此项可记录全部请求，
        # 便于在"数据包审查"页观察对手的完整流量（注意磁盘占用）
        self.waf_log_all = tk.IntVar(value=0)
        self.chk_waf_log_all = ttk.Checkbutton(
            control_frame,
            text="记录全部请求(数据包审查用)",
            variable=self.waf_log_all,
        )
        self.chk_waf_log_all.grid(row=4, column=0, columnspan=2, padx=10, pady=(0, 10), sticky=W)

        self.btn_guard_waf = ttk.Button(control_frame, text="启动自我防护", command=self.toggle_waf_guard)
        self.btn_guard_waf.grid(row=3, column=1, padx=10, pady=10)

        self.btn_undeploy_waf = ttk.Button(control_frame, text="一键下 WAF", style="Danger.TButton", command=self.undeploy_waf)
        self.btn_undeploy_waf.grid(row=3, column=2, padx=10, pady=10)

        self.waf_status = ttk.Label(control_frame, text="状态：未部署")
        self.waf_status.grid(row=3, column=3, padx=10, pady=10, sticky=W)

        self.waf_lock_hint = ttk.Label(
            control_frame,
            text="",
            style="Warning.TLabel"
        )
        self.waf_lock_hint.grid(row=4, column=0, columnspan=4, padx=10, pady=(0, 5), sticky=W)

        control_frame.columnconfigure(1, weight=1)
        control_frame.columnconfigure(3, weight=1)

        log_frame = ttk.LabelFrame(frame, text="WAF 日志", padding=10)
        log_frame.pack(expand=True, fill=BOTH)

        self.waf_log = scrolledtext.ScrolledText(log_frame, font=ui.FONT_MONO)
        self.waf_log.pack(expand=True, fill=BOTH)
        self.update_waf_param_controls()

    def log_waf(self, msg):
        clean_msg = strip_ansi(str(msg)) + "\n"
        self.waf_log.after(0, lambda: self._append_log(self.waf_log, clean_msg))

    def update_waf_status(self, text):
        self.waf_status.after(0, lambda: self.waf_status.config(text=text))

    def update_waf_param_controls(self):
        widget_state = DISABLED if state_manager.waf_deployed else "readonly"
        self.waf_mode.after(0, lambda: self.waf_mode.config(state=widget_state))
        self.waf_strict_level.after(0, lambda: self.waf_strict_level.config(state=widget_state))
        hint_text = "提示：WAF 已安装，拦截方式和严格程度已锁定。请先一键下 WAF 再调整。"
        if state_manager.waf_deployed:
            self.waf_lock_hint.after(0, lambda: self.waf_lock_hint.config(text=hint_text))
        else:
            self.waf_lock_hint.after(0, lambda: self.waf_lock_hint.config(text=""))

    def log_attack_packets(self, downloaded):
        if not downloaded:
            return
        for local_path in downloaded:
            self.log_waf(f"[+]疑似被被攻击，请求包保存在{local_path}")

    def refresh_packet_list_async(self):
        if hasattr(self, "packet_tree"):
            self.packet_tree.after(0, self.refresh_packet_list)

    def refresh_system_status_async(self):
        if hasattr(self, "system_log"):
            self.system_log.after(0, self.refresh_system_status)

    def confirm_clear_existing_packet_logs(self):
        existing_logs = waf_manager.list_local_request_logs()
        if not existing_logs:
            return True
        should_delete = messagebox.askyesno(
            "历史日志检测",
            f"检测到本地已有 {len(existing_logs)} 个历史请求包，是否先删除这些日志文件？"
        )
        if should_delete:
            removed = waf_manager.clear_local_request_logs()
            self.log_waf(f"• 已清理 {len(removed)} 个历史请求包")
            self.refresh_packet_list_async()
        return True

    def ensure_ssh_connection(self):
        if state_manager.is_ssh:
            return True
        messagebox.showwarning("警告", "请先在 SSH 选项卡测试并连接 SSH")
        return False

    def deploy_waf(self):
        if not self.ensure_ssh_connection():
            return
        if not self.confirm_clear_existing_packet_logs():
            return

        remote_root = self.waf_web_root.get().strip() or "/var/www/html"
        remote_dir = self.waf_remote_dir.get().strip() or "/var/www/html/.phpwaf"
        remote_log_dir = self.waf_remote_log_dir.get().strip() or "/tmp/.phpwaf_logs"
        waf_mode = int(str(self.waf_mode.get()).split()[0])
        waf_strict_level = int(str(self.waf_strict_level.get()).split()[0])
        waf_redirect_path = self.waf_redirect_path.get().strip() or "/"
        log_all = bool(self.waf_log_all.get())
        if log_all:
            if not messagebox.askyesno(
                "记录全部请求",
                "已开启「记录全部请求」：WAF 会把每个请求写入日志文件，\n"
                "便于在「数据包审查」查看对手完整流量，但会持续占用磁盘。\n\n"
                "（远端保留上限 2000 个包，超出后不再写入）\n\n确认继续？"
            ):
                return
        if not messagebox.askyesno("确认部署", f"将向业务目录注入 WAF：\n{remote_root}\n是否继续？"):
            return
        state_manager.remote_waf_log_dir = remote_log_dir
        self.btn_deploy_waf.config(state=DISABLED)
        self.waf_log.delete(1.0, END)
        self.log_waf("• 开始部署 WAF...")

        def run_deploy():
            try:
                result = waf_manager.deploy_waf(
                    remote_root, remote_dir, self.log_waf, remote_log_dir=remote_log_dir,
                    waf_mode=waf_mode, waf_strict_level=waf_strict_level,
                    waf_redirect_path=waf_redirect_path, log_all=log_all
                )
                inject_result = result["inject_result"]
                state_manager.remote_waf_dir = result["remote_dir"]
                state_manager.remote_waf_log_dir = result["remote_log_dir"]
                state_manager.remote_waf_path = result["remote_waf_path"]
                state_manager.waf_mode = result["waf_mode"]
                state_manager.waf_strict_level = result["waf_strict_level"]
                state_manager.waf_redirect_path = result["waf_redirect_path"]
                state_manager.waf_deployed = True
                self.update_waf_param_controls()
                self.update_waf_status(
                    f"状态：已部署，注入 {inject_result['injected']} 个，跳过 {inject_result['skipped']} 个"
                )
                self.log_waf("✓ WAF 部署完成")
                self.refresh_system_status_async()
                if not state_manager.waf_guard_enabled:
                    self.start_waf_guard(auto_started=True)
            except Exception as exc:
                # 部署失败可能只是本次网络异常，远端 WAF 未必真的不在；
                # 这里必须同步刷新控件，否则参数会永久锁死在 DISABLED
                self.update_waf_param_controls()
                self.update_waf_status(f"状态：部署失败 - {exc}")
                self.log_waf(f"⚠ WAF 部署失败: {exc}")
                self.refresh_system_status_async()
            finally:
                self.btn_deploy_waf.after(0, lambda: self.btn_deploy_waf.config(state=NORMAL))

        threading.Thread(target=run_deploy, daemon=True).start()

    def undeploy_waf(self):
        if not self.ensure_ssh_connection():
            return

        remote_root = self.waf_web_root.get().strip() or "/var/www/html"
        remote_dir = self.waf_remote_dir.get().strip() or "/var/www/html/.phpwaf"
        if not messagebox.askyesno("确认下线", f"将移除业务目录中的 WAF 注入并删除远端文件：\n{remote_dir}\n是否继续？"):
            return
        self.btn_undeploy_waf.config(state=DISABLED)
        self.log_waf("• 开始下线 WAF...")

        def run_undeploy():
            try:
                result = waf_manager.undeploy_waf(remote_root, remote_dir, self.log_waf)
                remove_result = result["remove_result"]
                ok = result.get("ok", True)
                # 只有确实全部剥离成功才算下线；否则保留状态与远端一致
                state_manager.waf_deployed = not ok
                self.update_waf_param_controls()
                if ok and state_manager.waf_guard_enabled:
                    self.waf_guard_stop.set()
                    state_manager.waf_guard_enabled = False
                    self.btn_guard_waf.after(0, lambda: self.btn_guard_waf.config(text="启动自我防护"))
                if ok:
                    self.update_waf_status(
                        f"状态：已下线，移除 {remove_result['removed']} 个，跳过 {remove_result['skipped']} 个"
                    )
                    self.log_waf("✓ WAF 下线完成")
                else:
                    self.update_waf_status(
                        f"状态：下线未完成 - 失败 {len(remove_result['failed'])} 个，WAF 文件已保留"
                    )
                    self.log_waf("⚠ 部分文件未能清理，已保留 WAF 文件以避免整站 Fatal error")
                self.refresh_system_status_async()
            except Exception as exc:
                self.log_waf(f"⚠ WAF 下线失败: {exc}")
                self.refresh_system_status_async()
            finally:
                self.btn_undeploy_waf.after(0, lambda: self.btn_undeploy_waf.config(state=NORMAL))

        threading.Thread(target=run_undeploy, daemon=True).start()

    def toggle_waf_guard(self):
        if not self.ensure_ssh_connection():
            return
        if self.waf_guard_thread and self.waf_guard_thread.is_alive():
            self.waf_guard_stop.set()
            state_manager.waf_guard_enabled = False
            self.btn_guard_waf.config(text="启动自我防护")
            self.log_waf("• 已停止 WAF 联动守护")
            self.refresh_system_status_async()
            return

        self.start_waf_guard(auto_started=False)

    def start_waf_guard(self, auto_started=False):
        self.waf_guard_stop = threading.Event()
        state_manager.waf_guard_enabled = True
        self.btn_guard_waf.after(0, lambda: self.btn_guard_waf.config(text="停止自我防护"))
        self.refresh_system_status_async()
        if auto_started:
            self.log_waf("✓ 已自动启动 WAF 联动守护")
        else:
            self.log_waf("✓ 已启动 WAF 联动守护")

        def guard_loop():
            while not self.waf_guard_stop.is_set():
                try:
                    restored = waf_manager.check_and_restore_waf(self.waf_remote_dir.get().strip(), self.log_waf)
                    if restored:
                        self.update_waf_status("状态：已自动补传 WAF")
                    downloaded = waf_manager.sync_remote_logs(self.waf_remote_log_dir.get().strip(), self.log_waf)
                    if downloaded:
                        self.log_attack_packets(downloaded)
                        self.refresh_packet_list_async()
                except Exception as exc:
                    self.log_waf(f"⚠ 守护异常: {exc}")
                self.waf_guard_stop.wait(self.waf_sync_interval)

        self.waf_guard_thread = threading.Thread(target=guard_loop, daemon=True)
        self.waf_guard_thread.start()

    def sync_waf_logs(self, ask_clear=True):
        """从远端拉取 WAF 记录的请求包。

        注意：这是请求包进入本地列表的**唯一途径**（列表页只读本地目录）。
        原实现没有把本方法绑定到任何按钮，切到"数据包审查"页看到的永远是
        空列表 —— 这是"数据包审查没有任何返回"的直接原因。
        """
        if not self.ensure_ssh_connection():
            return
        if ask_clear and not self.confirm_clear_existing_packet_logs():
            return

        self.sync_in_progress = True
        if hasattr(self, "btn_sync_packets"):
            self.btn_sync_packets.after(0, lambda: self.btn_sync_packets.config(
                state=DISABLED, text="同步中..."))
        self.log_waf("• 开始同步请求包日志...")

        def run_sync():
            try:
                downloaded = waf_manager.sync_remote_logs(self.waf_remote_log_dir.get().strip(), self.log_waf)
                if downloaded:
                    self.log_waf(f"↓ 本次同步 {len(downloaded)} 个请求包")
                    self.log_attack_packets(downloaded)
                else:
                    self.log_waf("• 没有新的请求包（可能是还没有流量被拦截）")
                self.refresh_packet_list_async()
            except Exception as exc:
                self.log_waf(f"⚠ 同步日志失败: {type(exc).__name__}: {exc}")
            finally:
                self.sync_in_progress = False
                if hasattr(self, "btn_sync_packets"):
                    self.btn_sync_packets.after(0, lambda: self.btn_sync_packets.config(
                        state=NORMAL, text="从远端同步"))

        threading.Thread(target=run_sync, daemon=True).start()

    def create_packet_tab(self):
        frame = self._add_page("packet", padding=20)

        toolbar = ttk.Frame(frame)
        toolbar.pack(fill=X, pady=(0, 10))

        # 关键入口：请求包只存在于远端 WAF 的日志目录，必须同步后才能查看
        self.btn_sync_packets = ttk.Button(toolbar, text="从远端同步",
                                            command=self.sync_waf_logs)
        self.btn_sync_packets.pack(side=LEFT, padx=(0, 10))

        self.btn_refresh_packets = ttk.Button(toolbar, text="刷新列表", command=self.refresh_packet_list)
        self.btn_refresh_packets.pack(side=LEFT, padx=(0, 10))

        self.btn_clear_packets = ttk.Button(toolbar, text="清空本地",
                                             command=self.clear_packet_logs)
        self.btn_clear_packets.pack(side=LEFT, padx=(0, 10))

        self.packet_summary = ttk.Label(toolbar, text="暂无请求包")
        self.packet_summary.pack(side=LEFT, padx=10)

        hint = ttk.Label(
            frame,
            text=("提示：请求包由远端 PHP WAF 拦截时记录到 "
                  "PHPWAF_LOG_DIR（默认 /tmp/.phpwaf_logs），"
                  "点「从远端同步」拉取。若列表始终为空，请确认："
                  "① WAF 已部署并生效 ② 业务已有流量被拦截 ③ 日志目录可写。"),
            style="Muted.TLabel", wraplength=980, justify=LEFT
        )
        hint.pack(fill=X, pady=(0, 8))

        content = ttk.Panedwindow(frame, orient=HORIZONTAL)
        content.pack(expand=True, fill=BOTH)

        left_frame = ttk.LabelFrame(content, text="请求包列表", padding=10)
        right_frame = ttk.LabelFrame(content, text="原始请求", padding=10)
        content.add(left_frame, weight=1)
        content.add(right_frame, weight=3)

        self.packet_tree = ttk.Treeview(left_frame, columns=("name",), show="headings")
        self.packet_tree.heading("name", text="文件名")
        self.packet_tree.column("name", anchor=W, width=320)
        self.packet_tree.pack(expand=True, fill=BOTH)
        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)

        self.packet_preview = scrolledtext.ScrolledText(right_frame, font=ui.FONT_MONO)
        self.packet_preview.pack(expand=True, fill=BOTH)

    def clear_packet_logs(self):
        removed = waf_manager.clear_local_request_logs()
        self.packet_files = []
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.packet_preview.delete(1.0, END)
        self.packet_summary.config(text=f"已清空 {len(removed)} 个本地请求包")

    def refresh_packet_list(self):
        self.packet_files = waf_manager.list_local_request_logs()
        if not hasattr(self, "packet_tree"):
            return
        self.packet_tree.delete(*self.packet_tree.get_children())
        for index, item in enumerate(self.packet_files):
            self.packet_tree.insert("", END, iid=str(index), values=(item["name"],))
        if self.packet_files:
            summary = f"共 {len(self.packet_files)} 个请求包"
        else:
            summary = "本地暂无请求包 —— 点左侧「从远端同步」拉取"
        if hasattr(self, "packet_summary"):
            self.packet_summary.config(text=summary)
        if self.packet_files:
            first = self.packet_tree.get_children()
            if first:
                self.packet_tree.selection_set(first[0])
                self.on_packet_select()
        else:
            if hasattr(self, "packet_preview"):
                self.packet_preview.delete(1.0, END)
                self.packet_preview.insert(
                    END,
                    "尚无请求包可显示。\n\n"
                    "请求包由远端 PHP WAF 在拦截到恶意请求时生成，流程：\n"
                    "  1. 在「WAF设置」页完成一键上 WAF（确认注入数量不为 0）\n"
                    "  2. 等待业务流量触发拦截（或自己打一条明显恶意的请求）\n"
                    "  3. 回到本页点「从远端同步」\n\n"
                    f"当前远端日志目录: {state_manager.remote_waf_log_dir or '/tmp/.phpwaf_logs'}\n"
                    f"WAF 部署状态: {'已部署' if state_manager.waf_deployed else '未部署'}\n"
                    f"SSH 连接: {'已连接 ' + str(state_manager.hostname) if state_manager.is_ssh else '未连接'}\n"
                )

    def on_packet_select(self, event=None):
        if not hasattr(self, "packet_tree"):
            return
        selection = self.packet_tree.selection()
        if not selection:
            return
        index = int(selection[0])
        packet = self.packet_files[index]
        content = waf_manager.read_local_request_log(packet["path"])
        self.packet_preview.delete(1.0, END)
        self.packet_preview.insert(END, content)

    def create_system_tab(self):
        frame = self._add_page("system", padding=20)

        top_bar = ttk.Frame(frame)
        top_bar.pack(fill=X, pady=(0, 10))

        self.btn_refresh_system = ttk.Button(top_bar, text="刷新状态", command=self.refresh_system_status)
        self.btn_refresh_system.pack(side=LEFT, padx=(0, 10))

        self.system_summary = ttk.Label(top_bar, text="等待状态刷新")
        self.system_summary.pack(side=LEFT, padx=10)

        self.system_log = scrolledtext.ScrolledText(frame, font=ui.FONT_MONO)
        self.system_log.pack(expand=True, fill=BOTH)
        self.refresh_system_status()

    def refresh_system_status(self):
        monitor_state = "运行中" if file_processing.is_running else "未启动"
        if file_processing.is_running and file_processing.is_paused:
            monitor_state = "已暂停"
        guard_state = "运行中" if state_manager.waf_guard_enabled else "未启动"
        ssh_state = "已连接" if state_manager.is_ssh else "未连接"
        waf_state = "已安装" if state_manager.waf_deployed else "未安装"
        mode_text = "关键词替换" if int(state_manager.waf_mode) == 1 else "跳转路由"
        strict_text = f"等级{state_manager.waf_strict_level}"
        packet_count = len(self.packet_files) if self.packet_files else 0
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            f"[{now}] 系统状态快照",
            f"SSH连接: {ssh_state}",
            f"文件监控: {monitor_state}",
            f"WAF安装: {waf_state}",
            f"WAF守护: {guard_state}",
            f"WAF拦截方式: {mode_text}",
            f"WAF严格程度: {strict_text}",
            f"WAF跳转路由: {state_manager.waf_redirect_path or '/'}",
            f"远端WAF目录: {state_manager.remote_waf_dir}",
            f"远端日志目录: {state_manager.remote_waf_log_dir}",
            f"本地请求包数量: {packet_count}",
            ""
        ]
        self.system_summary.config(text=f"SSH:{ssh_state} | 监控:{monitor_state} | WAF:{waf_state}")
        self.system_log.delete(1.0, END)
        self.system_log.insert(END, "\n".join(lines))

    def create_shell_tab(self):
        frame = self._add_page("shell", padding=10)

        # 终端配色统一走 ui_theme，避免这里再硬编码一套色值
        self.shell_log = ui.style_text(scrolledtext.ScrolledText(
            frame,
            insertwidth=2,
            insertontime=600,
            insertofftime=300,
            wrap=NONE,
        ), size=ui.FONT_MONO_LG[1])
        self.shell_log.pack(expand=True, fill=BOTH)
        self.shell_log.mark_set("input_start", "1.0")
        self.shell_log.mark_gravity("input_start", LEFT)
        
        # 绑定按键事件实现真实的终端输入
        self.shell_log.bind("<Key>", self.handle_shell_keypress)
        self.shell_log.bind("<FocusIn>", lambda e: self.set_shell_cursor())
        
    def set_shell_cursor(self):
        try:
            cursor_index = self.shell_log.index(f"input_start + {self.shell_cursor_pos}c")
            self.shell_log.mark_set(INSERT, cursor_index)
            self.shell_log.see(END)
        except:
            pass

    def render_shell_input(self):
        try:
            self.shell_log.delete("input_start", "end-1c")
            if self.shell_input_buffer:
                self.shell_log.insert("input_start", self.shell_input_buffer)
            self.set_shell_cursor()
        except:
            pass

    def reset_shell_input(self):
        self.shell_input_buffer = ""
        self.shell_cursor_pos = 0
        self.shell_log.mark_set("input_start", "end-1c")
        self.set_shell_cursor()

    def handle_shell_keypress(self, event):
        if not self.shell_chan or self.shell_chan.closed:
            # 如果是复制组合键，允许默认行为
            if event.state & 4 and event.keysym.lower() == 'c':
                return
            return "break" # 如果未连接，禁止输入
        self.set_shell_cursor()
            
        # 允许复制 (Ctrl+C, 如果选中了文本)
        if event.state & 4 and event.keysym.lower() == 'c':
            try:
                # 尝试获取选中的文本，如果有则执行复制
                if self.shell_log.tag_ranges(SEL):
                    return # 允许 Tkinter 的默认复制行为
            except:
                pass
            # 如果没有选中文本，发送中断信号
            self.shell_chan.send('\x03')
            self.reset_shell_input()
            self.shell_log.insert(END, "^C\n")
            self.shell_log.mark_set("input_start", "end-1c")
            self.set_shell_cursor()
            return "break"
            
        # 允许其他常用的功能键（如方向键、复制粘贴等）不被完全拦截，但不要直接发送给 SSH
        if event.keysym == 'Left':
            if self.shell_cursor_pos > 0:
                self.shell_cursor_pos -= 1
            self.set_shell_cursor()
            return "break"
        if event.keysym == 'Right':
            if self.shell_cursor_pos < len(self.shell_input_buffer):
                self.shell_cursor_pos += 1
            self.set_shell_cursor()
            return "break"
        if event.keysym == 'Home':
            self.shell_cursor_pos = 0
            self.set_shell_cursor()
            return "break"
        if event.keysym == 'End':
            self.shell_cursor_pos = len(self.shell_input_buffer)
            self.set_shell_cursor()
            return "break"
        if event.keysym in ('Up', 'Down', 'Prior', 'Next'):
            # TODO: 实现方向键对应的终端控制序列，暂时忽略
            return "break"
            
        if event.keysym == 'Return':
            command = self.shell_input_buffer
            self.shell_log.insert(END, "\n")
            if command.strip() == "clear":
                self.shell_log.delete(1.0, END)
                self.shell_log.mark_set("input_start", "1.0")
            self.shell_chan.send(command + "\n")
            self.reset_shell_input()
        elif event.keysym == 'BackSpace':
            if self.shell_cursor_pos > 0:
                self.shell_input_buffer = self.shell_input_buffer[:self.shell_cursor_pos - 1] + self.shell_input_buffer[self.shell_cursor_pos:]
                self.shell_cursor_pos -= 1
                self.render_shell_input()
        elif event.keysym == 'Delete':
            if self.shell_cursor_pos < len(self.shell_input_buffer):
                self.shell_input_buffer = self.shell_input_buffer[:self.shell_cursor_pos] + self.shell_input_buffer[self.shell_cursor_pos + 1:]
                self.render_shell_input()
        elif event.keysym == 'Tab':
            self.shell_input_buffer = self.shell_input_buffer[:self.shell_cursor_pos] + "    " + self.shell_input_buffer[self.shell_cursor_pos:]
            self.shell_cursor_pos += 4
            self.render_shell_input()
        elif event.char and event.char.isprintable():
            self.shell_input_buffer = self.shell_input_buffer[:self.shell_cursor_pos] + event.char + self.shell_input_buffer[self.shell_cursor_pos:]
            self.shell_cursor_pos += 1
            self.render_shell_input()
        self.set_shell_cursor()
            
        # 始终返回 "break" 以阻止 Tkinter 默认的插入行为
        # 我们完全依赖 SSH 服务器的 echo (回显) 来显示字符
        return "break"

    def log_shell(self, msg):
        # 优化退格符处理，避免正则死循环导致 UI 卡死
        def process_text():
            clean_msg = strip_ansi(msg)
            for fragment in self.shell_hidden_fragments:
                clean_msg = clean_msg.replace(fragment, "")
            if self.shell_bootstrapping:
                self.shell_bootstrap_buffer += clean_msg
                prompt_matches = list(re.finditer(r'(^|\n)[^\n]*[#$] ?$', self.shell_bootstrap_buffer, re.MULTILINE))
                if prompt_matches:
                    last_match = prompt_matches[-1]
                    clean_msg = self.shell_bootstrap_buffer[last_match.start():]
                    self.shell_bootstrap_buffer = ""
                    self.shell_bootstrapping = False
                elif ("Shell Error" in self.shell_bootstrap_buffer
                      or time.time() >= getattr(self, "shell_bootstrap_deadline", 0)):
                    # 没有识别到提示符(连接失败 / 非 #$ 提示符的 shell)时，
                    # 原实现会永久丢弃所有输出，终端整屏空白且无任何错误提示。
                    # 这里用错误关键字或超时强制放行既有缓冲内容。
                    clean_msg = self.shell_bootstrap_buffer
                    self.shell_bootstrap_buffer = ""
                    self.shell_bootstrapping = False
                else:
                    return
            
            # 改进 \r 的处理逻辑：如果遇到 \r，意味着光标回到行首，
            # 在一个简易的 Text 控件中，如果没有换行，我们可以直接删掉当前行的内容
            # 这里为了不破坏已有的显示，采用一种简单的处理方式：
            # 如果 \r 后面紧跟着 \n，那这就是一个正常的换行，我们把它变成 \n。
            clean_msg = clean_msg.replace('\r\n', '\n')
            
            for char in clean_msg:
                if char == '\b':
                    # 退格：删除最后一个字符
                    if self.shell_log.index("end-1c") != "1.0":
                        # 确保不跨行删除提示符
                        if self.shell_log.get("end-2c", "end-1c") != '\n':
                            self.shell_log.delete("end-2c", "end-1c")
                elif char == '\r':
                    continue
                elif char == '\x07': # BEL (响铃)，忽略
                    continue
                else:
                    self.shell_log.insert(END, char)
            self.shell_log.mark_set("input_start", "end-1c")
            if self.shell_input_buffer:
                self.render_shell_input()
            else:
                self.set_shell_cursor()

        self.shell_log.after(0, process_text)

    def start_shell(self):
        if not state_manager.is_ssh:
            # messagebox.showwarning("警告", "请先在 SSH 选项卡测试并连接 SSH")
            self.log_shell("\n[!] 请先在 SSH 选项卡中完成连接测试。\n")
            return
        if self.shell_connecting or (self.shell_chan and not self.shell_chan.closed):
            return
            
        self.shell_connecting = True
        self.shell_input_buffer = ""
        self.shell_cursor_pos = 0
        self.shell_bootstrapping = True
        self.shell_bootstrap_buffer = ""
        # bootstrap 超时保护：5 秒内没识别到提示符就放行缓冲内容，
        # 否则连接失败或非 #/$ 提示符的 shell 会让终端永久空白
        self.shell_bootstrap_deadline = time.time() + 5
        self.shell_log.delete(1.0, END)
        self.shell_log.mark_set("input_start", "1.0")
        self.shell_log.focus_set()
        self.set_shell_cursor()

        def connect():
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=state_manager.hostname, port=state_manager.port, 
                               username=state_manager.username, password=state_manager.password)
                self.shell_client = client
                
                # 请求伪终端以获得更好的交互体验
                self.shell_chan = client.invoke_shell(term='xterm', width=140, height=45)
                self.shell_chan.send("export TERM=xterm\n")
                self.shell_chan.send("bind 'set enable-bracketed-paste off' 2>/dev/null\n")
                self.shell_chan.send("printf '\\033[?2004l' >/dev/null 2>&1\n")
                self.shell_chan.send("stty -echo -ixon 2>/dev/null\n")
                
                chan = self.shell_chan
                chan.settimeout(1.0)
                # 用阻塞 recv 替代 sleep(0.01) 忙等：原实现每秒 100 次轮询常驻，
                # 且唯一出口是 exit_status_ready()，TCP 半开时永不重连也无法断开
                while True:
                    try:
                        data = chan.recv(8192)
                    except socket.timeout:
                        if chan.exit_status_ready():
                            self.log_shell("\n[*] Shell disconnected.\n")
                            break
                        continue
                    except Exception:
                        break
                    if not data:
                        self.log_shell("\n[*] Shell disconnected.\n")
                        break
                    self.log_shell(data.decode('utf-8', errors='replace'))
            except Exception as e:
                self.log_shell(f"\n[!] Shell Error: {e}\n")
            finally:
                self.shell_connecting = False
                try:
                    if self.shell_client:
                        self.shell_client.close()
                except:
                    pass
                self.shell_client = None
                self.shell_chan = None

        threading.Thread(target=connect, daemon=True).start()

if __name__ == "__main__":
    app = AWDDfenceGUI()
    app.mainloop()
