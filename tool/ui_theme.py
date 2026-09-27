"""MetaAWD 统一 UI 主题层。

三类历史问题的修复集中在这里
------------------------------
1. 发虚：进程未声明 DPI 感知时，Windows 会把整个窗口位图放大到物理分辨率
   （本机 150% → 放大 1.5 倍），文字边缘被插值成灰边。必须在创建 Tk 之前
   调用 enable_dpi_awareness()。
2. 发虚（其二）：界面硬编码 font=("Segoe UI", ...)，而 Segoe UI 不含中文字形，
   Windows 只能靠 font-linking 回退渲染中文，中英混排基线不齐、笔画发灰。
   这里统一改用含中文的 Microsoft YaHei UI。
3. 卡顿：sv-ttk 的样式在每次页面 map/unmap 时要重算大量图片元素，实测切页
   480ms/次，而同样控件树在 clam 上只要 24ms。改为基于 clam 自建的深色样式，
   同时保留深色观感。

附带收益：clam 是纯 Tk 绘制的主题，按钮可以单独着色；sv-ttk 的按钮由 PNG
精灵图绘制、无法逐个上色，此前只能把所有语义色退到文本上。现在恢复了
按语义给按钮上色的能力。
"""

import ctypes
import sys
import tkinter as tk
from tkinter import ttk

# ==================================================================== 调色板
# 冷调石墨深色：比纯灰更有层次，避免大面积同色平铺
PALETTE = {
    # 背景层次（由深到浅）
    "bg":         "#17191E",   # 窗口底色
    "surface":    "#1E2128",   # 输入框 / 文本区 / 卡片
    "surface_hi": "#272B34",   # 次级按钮 / 悬浮态
    "surface_lo": "#131519",   # 内嵌凹陷区
    "border":     "#333844",   # 边框 / 分隔线

    # 前景（由亮到暗）
    "fg":         "#E4E7EC",
    "fg_dim":     "#98A0AD",
    "fg_dis":     "#5B6472",

    # 强调色
    "accent":     "#3D7EFF",
    "accent_hi":  "#5B93FF",
    "accent_lo":  "#2A5BC4",

    # 语义色
    "danger":     "#E5534B",
    "danger_hi":  "#F0716A",
    "success":    "#3FB950",
    "success_hi": "#4CC38A",
    "warning":    "#D29922",
    "warning_hi": "#E0B341",
    "info":       "#57C8FF",
}

# ==================================================================== 字体
# Microsoft YaHei UI 含完整中文字形、走 ClearType 渲染，中英混排基线一致。
# 纯英文场景（品牌名）保留 Segoe UI，它在拉丁字符上更紧凑。
_FAMILY_UI = "Microsoft YaHei UI"
_FAMILY_LATIN = "Segoe UI"
_FAMILY_MONO = "Consolas"

FONT_UI = (_FAMILY_UI, 10)
FONT_UI_SM = (_FAMILY_UI, 9)
FONT_UI_BOLD = (_FAMILY_UI, 10, "bold")
FONT_TITLE = (_FAMILY_UI, 16, "bold")
FONT_SUBTITLE = (_FAMILY_UI, 10)
FONT_GROUP = (_FAMILY_UI, 9, "bold")       # 侧栏分组标题
FONT_BRAND = (_FAMILY_LATIN, 15, "bold")   # 顶栏 "MetaAWD"
FONT_MONO = (_FAMILY_MONO, 10)
FONT_MONO_LG = (_FAMILY_MONO, 11)

_SCALE = 1.0


def enable_dpi_awareness():
    """声明进程 DPI 感知。必须在创建 Tk 之前调用。

    优先用 shcore.SetProcessDpiAwareness(2)（PER_MONITOR_DPI_AWARE），
    旧系统回退到 user32.SetProcessDPIAware()。重复调用无副作用。
    """
    if sys.platform != "win32":
        return "n/a"
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return "per-monitor"
    except Exception:
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
        return "system"
    except Exception:
        return "failed"


def init_scale(root):
    """从 Tk 自身的 scaling 推导缩放系数，避免再走一遍 ctypes 查询。

    Tk 的 scaling 是「每点对应多少像素」，即 DPI/72。96 DPI 时为 1.3333。
    """
    global _SCALE
    try:
        scaling = float(root.tk.call("tk", "scaling"))
    except Exception:
        scaling = 1.3333
    _SCALE = max(scaling / (96.0 / 72.0), 1.0)
    return _SCALE


def scale():
    return _SCALE


def px(n):
    """把按 96 DPI 设计的像素值换算到当前 DPI。"""
    return int(round(n * _SCALE))


def apply_dark_title_bar(root):
    """把 Windows 标题栏切成深色，避免深色界面顶着一条亮白标题栏。"""
    if sys.platform != "win32":
        return False
    try:
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        if not hwnd:
            hwnd = root.winfo_id()
        value = ctypes.c_int(1)
        for attr in (20, 19):          # 20=Win10 20H1+ / 19=Win10 1809+
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attr, ctypes.byref(value), ctypes.sizeof(value)) == 0:
                return True
    except Exception:
        pass
    return False


# ==================================================================== 样式
def apply_theme(root):
    """应用自建深色主题。控件树构建前调用一次即可。"""
    st = ttk.Style(root)
    st.theme_use("clam")
    P = PALETTE

    # ---- 全局默认 ----
    st.configure(".", background=P["bg"], foreground=P["fg"],
                 fieldbackground=P["surface"], bordercolor=P["border"],
                 lightcolor=P["border"], darkcolor=P["border"],
                 troughcolor=P["surface_lo"], focuscolor=P["accent"],
                 selectbackground=P["accent"], selectforeground="#FFFFFF",
                 font=FONT_UI, borderwidth=0, relief="flat")

    st.configure("TFrame", background=P["bg"])
    st.configure("Card.TFrame", background=P["surface"])
    st.configure("TLabel", background=P["bg"], foreground=P["fg"])
    st.configure("Card.TLabel", background=P["surface"], foreground=P["fg"])

    # 语义文本（沿用 gui_main 里既有 COLOR_* 的用途）
    st.configure("Muted.TLabel", foreground=P["fg_dim"])
    st.configure("Danger.TLabel", foreground=P["danger_hi"])
    st.configure("Success.TLabel", foreground=P["success_hi"])
    st.configure("Warning.TLabel", foreground=P["warning_hi"])
    st.configure("Info.TLabel", foreground=P["info"])

    # ---- 分组框 ----
    st.configure("TLabelframe", background=P["bg"], bordercolor=P["border"],
                 relief="solid", borderwidth=1, padding=px(10))
    st.configure("TLabelframe.Label", background=P["bg"], foreground=P["fg_dim"],
                 font=FONT_GROUP)

    # ---- 按钮 ----
    st.configure("TButton", background=P["surface_hi"], foreground=P["fg"],
                 bordercolor=P["border"], padding=(px(14), px(7)),
                 relief="flat", borderwidth=0)
    st.map("TButton",
           background=[("disabled", P["surface"]), ("pressed", P["accent_lo"]),
                       ("active", P["border"])],
           foreground=[("disabled", P["fg_dis"])])

    st.configure("Accent.TButton", background=P["accent"], foreground="#FFFFFF")
    st.map("Accent.TButton",
           background=[("disabled", P["surface"]), ("pressed", P["accent_lo"]),
                       ("active", P["accent_hi"])],
           foreground=[("disabled", P["fg_dis"])])

    # 语义按钮：clam 主题下可单独着色（sv-ttk 做不到）
    for name, base, hover in (
            ("Danger", P["danger"], P["danger_hi"]),
            ("Success", P["success"], P["success_hi"]),
            ("Warning", P["warning"], P["warning_hi"])):
        st.configure("%s.TButton" % name, background=base, foreground="#FFFFFF")
        st.map("%s.TButton" % name,
               background=[("disabled", P["surface"]), ("pressed", base),
                           ("active", hover)],
               foreground=[("disabled", P["fg_dis"])])

    # ---- 侧栏导航 ----
    st.configure("Nav.TButton", background=P["bg"], foreground=P["fg_dim"],
                 anchor="w", padding=(px(16), px(9)), relief="flat",
                 borderwidth=0, font=FONT_UI)
    st.map("Nav.TButton",
           background=[("active", P["surface_hi"]), ("pressed", P["surface_hi"])],
           foreground=[("active", P["fg"])])
    st.configure("NavActive.TButton", background=P["surface_hi"],
                 foreground=P["accent_hi"], anchor="w",
                 padding=(px(16), px(9)), relief="flat", borderwidth=0,
                 font=FONT_UI_BOLD)

    # ---- 输入类 ----
    st.configure("TEntry", fieldbackground=P["surface"], foreground=P["fg"],
                 insertcolor=P["accent"], bordercolor=P["border"],
                 lightcolor=P["border"], darkcolor=P["border"],
                 padding=px(7), relief="flat")
    st.map("TEntry", bordercolor=[("focus", P["accent"])])

    st.configure("TCombobox", fieldbackground=P["surface"],
                 background=P["surface_hi"], foreground=P["fg"],
                 arrowcolor=P["fg_dim"], bordercolor=P["border"],
                 lightcolor=P["border"], darkcolor=P["border"], padding=px(5))
    st.map("TCombobox",
           fieldbackground=[("readonly", P["surface"])],
           foreground=[("readonly", P["fg"])],
           arrowcolor=[("active", P["accent_hi"])])
    # 下拉列表不在 ttk 样式体系内，必须走 option 数据库
    root.option_add("*TCombobox*Listbox.background", P["surface"])
    root.option_add("*TCombobox*Listbox.foreground", P["fg"])
    root.option_add("*TCombobox*Listbox.selectBackground", P["accent"])
    root.option_add("*TCombobox*Listbox.selectForeground", "#FFFFFF")

    st.configure("TSpinbox", fieldbackground=P["surface"], foreground=P["fg"],
                 arrowcolor=P["fg_dim"], bordercolor=P["border"], padding=px(5))

    st.configure("TCheckbutton", background=P["bg"], foreground=P["fg"],
                 indicatorcolor=P["surface"], focuscolor=P["bg"])
    st.map("TCheckbutton",
           background=[("active", P["bg"])],
           indicatorcolor=[("selected", P["accent"]), ("active", P["surface_hi"])],
           foreground=[("disabled", P["fg_dis"])])

    st.configure("TRadiobutton", background=P["bg"], foreground=P["fg"],
                 indicatorcolor=P["surface"], focuscolor=P["bg"])
    st.map("TRadiobutton",
           background=[("active", P["bg"])],
           indicatorcolor=[("selected", P["accent"]), ("active", P["surface_hi"])])

    # ---- 表格 ----
    st.configure("Treeview", background=P["surface"], fieldbackground=P["surface"],
                 foreground=P["fg"], bordercolor=P["border"],
                 lightcolor=P["border"], darkcolor=P["border"],
                 rowheight=px(28), relief="flat")
    st.map("Treeview",
           background=[("selected", P["accent"])],
           foreground=[("selected", "#FFFFFF")])
    st.configure("Treeview.Heading", background=P["surface_hi"],
                 foreground=P["fg_dim"], relief="flat", padding=px(7),
                 font=FONT_UI_BOLD, bordercolor=P["border"])
    st.map("Treeview.Heading", background=[("active", P["border"])])

    # ---- 分隔线 / 滚动条 / 分割窗 ----
    st.configure("TSeparator", background=P["border"], bordercolor=P["border"])
    st.configure("Vertical.TScrollbar", background=P["surface_hi"],
                 troughcolor=P["bg"], bordercolor=P["bg"],
                 arrowcolor=P["fg_dim"], relief="flat", borderwidth=0,
                 width=px(12))
    st.configure("Horizontal.TScrollbar", background=P["surface_hi"],
                 troughcolor=P["bg"], bordercolor=P["bg"],
                 arrowcolor=P["fg_dim"], relief="flat", borderwidth=0)
    for orient in ("Vertical", "Horizontal"):
        st.map("%s.TScrollbar" % orient,
               background=[("active", P["border"]), ("pressed", P["accent_lo"])],
               arrowcolor=[("active", P["accent_hi"])])

    st.configure("TPanedwindow", background=P["bg"])
    st.configure("Sash", sashthickness=px(6), gripcount=0)

    # ---- 非 ttk 控件的默认值 ----
    root.tk_setPalette(
        background=P["bg"], foreground=P["fg"],
        highlightColor=P["accent"], highlightBackground=P["border"],
        selectBackground=P["accent"], selectForeground="#FFFFFF",
        activeBackground=P["surface_hi"], activeForeground=P["fg"])

    return st


# ========================================================== 原生控件深色化
def style_text(widget, mono=True, size=None):
    """把 ScrolledText / Text / Listbox 变成深色终端外观。

    scrolledtext.ScrolledText 是 tk.Text 的子类，不参与 ttk 主题，必须显式配色；
    它内部的滚动条也是原生 tk.Scrollbar。
    """
    P = PALETTE
    try:
        widget.configure(
            background=P["surface"], foreground=P["fg"],
            insertbackground=P["accent"],
            selectbackground=P["accent"], selectforeground="#FFFFFF",
            inactiveselectbackground=P["surface_hi"],
            relief="flat", borderwidth=0,
            highlightthickness=1,
            highlightbackground=P["border"], highlightcolor=P["accent"],
            padx=px(10), pady=px(8),
            font=(FONT_MONO[0], size or FONT_MONO_LG[1]),
        )
    except tk.TclError:
        pass
    upgrade_scrolledtext_bars(widget)
    return widget


def style_scrollbar(widget):
    """给原生 tk.Scrollbar 配色。

    注意：Windows 上 Tk 的 Scrollbar 走系统原生绘制，这些颜色选项未必生效，
    深色界面里应优先走 upgrade_scrolledtext_bars() 换成 ttk.Scrollbar。
    这里保留是为了兜住独立创建的原生滚动条。
    """
    P = PALETTE
    try:
        widget.configure(background=P["surface_hi"], troughcolor=P["surface_lo"],
                         activebackground=P["accent_lo"],
                         highlightthickness=0, relief="flat", borderwidth=0,
                         width=px(12))
    except tk.TclError:
        pass
    return widget


def upgrade_scrolledtext_bars(widget):
    """把 ScrolledText 内部的 tk.Scrollbar 换成 ttk.Scrollbar。

    Windows 上 tk.Scrollbar 由系统原生绘制，background/troughcolor 会被忽略 ——
    实测配好色后 cget 能读到新值，画面上仍是一条亮白槽。ttk.Scrollbar 才会真正
    应用主题样式，因此这里做一次替换，并重新接好 yscrollcommand。
    """
    bar = getattr(widget, "vbar", None)
    if bar is None or bar.winfo_class() == "TScrollbar":
        return
    try:
        frame = bar.master
        new = ttk.Scrollbar(frame, orient="vertical",
                            command=widget.yview,
                            style="Vertical.TScrollbar")
        new.pack(side="right", fill="y")
        widget.configure(yscrollcommand=new.set)
        widget.vbar = new
        bar.destroy()
    except tk.TclError:
        pass


def style_listbox(widget):
    P = PALETTE
    try:
        widget.configure(background=P["surface"], foreground=P["fg"],
                         selectbackground=P["accent"], selectforeground="#FFFFFF",
                         relief="flat", borderwidth=0, highlightthickness=1,
                         highlightbackground=P["border"], font=FONT_UI)
    except tk.TclError:
        pass
    return widget


def darken_native_widgets(root):
    """遍历控件树，把遗漏的原生 tk 控件配色对齐主题。

    注意：不判断控件「是否已配色就跳过」—— tk_setPalette 会先把 Text 的
    background 填成主题底色，据此跳过反而会漏掉它内部那条亮白的滚动条。
    """
    P = PALETTE
    count = {"text": 0, "frame": 0, "canvas": 0, "listbox": 0, "scrollbar": 0}

    def walk(w):
        for child in w.winfo_children():
            cls = child.winfo_class()
            try:
                if cls == "Text":
                    style_text(child)
                    count["text"] += 1
                elif cls == "Frame":
                    child.configure(background=P["bg"], highlightthickness=0)
                    count["frame"] += 1
                elif cls == "Canvas":
                    child.configure(background=P["bg"], highlightthickness=0)
                    count["canvas"] += 1
                elif cls == "Listbox":
                    style_listbox(child)
                    count["listbox"] += 1
                elif cls == "Scrollbar":
                    style_scrollbar(child)
                    count["scrollbar"] += 1
            except tk.TclError:
                pass
            walk(child)

    walk(root)
    return count
