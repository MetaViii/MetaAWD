"""MetaAWD 统一 UI 主题层：DPI、深浅双主题、原生控件配色。

设计取向
--------
参考 Claude Desktop 与 Codex 的视觉语言，归纳出四条可落地的原则：

1. 不用渐变。整块纯色 + 背景层次（bg / surface / surface_hi 三档）表达结构，
   比渐变干净，也省掉自绘的开销。
2. 少用边框。层级靠背景色差和留白区分，只在必要处留极淡的分隔线。
3. 中性偏暖、低饱和。纯冷灰会显得"工程感"，暖中性更耐看。
4. 单一强调色。除强调色外只有语义色（红/绿/黄），不做多余着色。

已知硬约束：ttk 没有圆角，也没有真正的透明背景。现代感只能靠配色、间距、
层级来营造，不能照搬 Web 的卡片圆角风格。

DPI 与字体
----------
进程必须在创建 Tk 之前声明 DPI 感知，否则 Windows 会把窗口位图拉伸 1.5 倍，
文字边缘被插值成灰边。字体统一用含中文的 Microsoft YaHei UI —— Segoe UI
不含中文字形，中文靠 font-linking 回退渲染，会导致中英混排基线不齐。
"""

import ctypes
import sys
import tkinter as tk
from tkinter import ttk

# ==================================================================== 主题
# 只保留深浅两套。浅色不是深色的简单反相：深色下靠"更亮"表示抬升，
# 浅色下要靠"更白 + 淡阴影色"表示抬升，层次方向是相反的。
THEMES = {
    "dark": {
        "label": "深色 Dark",
        "dark": True,
        # 背景三档：窗口 / 卡片与输入框 / 悬浮与选中
        "bg":         "#1F1E1D",
        "surface":    "#262624",
        "surface_hi": "#31302D",
        "surface_lo": "#191817",
        "border":     "#3A3937",
        # 前景三档
        "fg":         "#F5F4EF",
        "fg_dim":     "#A8A49C",
        "fg_dis":     "#6B6760",
        # 强调与语义
        "accent":     "#D97757",
        "accent_hi":  "#E68A6B",
        "accent_lo":  "#B85F41",
        "danger":     "#E06C60",
        "danger_hi":  "#EE857A",
        "success":    "#7FB069",
        "success_hi": "#95C47F",
        "warning":    "#D9A441",
        "warning_hi": "#E8B85C",
        "info":       "#7BA7C9",
    },
    "light": {
        "label": "浅色 Light",
        "dark": False,
        "bg":         "#FAF9F5",
        "surface":    "#FFFFFF",
        "surface_hi": "#F0EEE8",
        "surface_lo": "#F3F1EC",
        "border":     "#E3E0D8",
        "fg":         "#2B2A28",
        "fg_dim":     "#6E6B64",
        "fg_dis":     "#A8A49C",
        "accent":     "#C96442",
        "accent_hi":  "#D97757",
        "accent_lo":  "#A64F31",
        "danger":     "#C0392B",
        "danger_hi":  "#D6503F",
        "success":    "#4F7A3C",
        "success_hi": "#5F924A",
        "warning":    "#9C7318",
        "warning_hi": "#B98A1E",
        "info":       "#3D6E8F",
    },
}

DEFAULT_THEME = "dark"
_current = DEFAULT_THEME

# 当前主题色。原地更新而非整体替换，保证外部已持有的引用始终有效。
PALETTE = {}
PALETTE.update(THEMES[DEFAULT_THEME])


def theme_names():
    """返回 [(key, label), ...]，供界面下拉使用。"""
    return [(k, v["label"]) for k, v in THEMES.items()]


def current_theme():
    return _current


def is_dark():
    return bool(PALETTE.get("dark", True))


def theme_label(name=None):
    return THEMES.get(name or _current, {}).get("label", name or _current)


# ==================================================================== 字体
_FAMILY_UI = "Microsoft YaHei UI"
_FAMILY_LATIN = "Segoe UI"
_FAMILY_MONO = "Consolas"

FONT_UI = (_FAMILY_UI, 10)
FONT_UI_SM = (_FAMILY_UI, 9)
FONT_UI_BOLD = (_FAMILY_UI, 10, "bold")
FONT_TITLE = (_FAMILY_UI, 15, "bold")
FONT_SUBTITLE = (_FAMILY_UI, 9)
FONT_BRAND = (_FAMILY_LATIN, 15, "bold")
FONT_MONO = (_FAMILY_MONO, 10)
FONT_MONO_LG = (_FAMILY_MONO, 10)

_SCALE = 1.0


def enable_dpi_awareness():
    """声明进程 DPI 感知。必须在创建 Tk 之前调用。"""
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
    """从 Tk 自身的 scaling 推导缩放系数（Tk 的 scaling = DPI/72）。"""
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


def apply_title_bar(root):
    """标题栏跟随主题：深色时用 immersive dark，浅色时显式关掉。

    只在应用启动时调用一次 —— 切换主题时重建原生标题栏会触发窗口闪烁。
    """
    if sys.platform != "win32":
        return False
    try:
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id()) or root.winfo_id()
        value = ctypes.c_int(1 if is_dark() else 0)
        for attr in (20, 19):
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attr, ctypes.byref(value), ctypes.sizeof(value)) == 0:
                return True
    except Exception:
        pass
    return False


# 兼容旧调用名
apply_dark_title_bar = apply_title_bar


# ==================================================================== 样式
def apply_theme(root, name=None):
    """应用（或切换）主题。控件树构建前后调用均可。"""
    global _current
    if name and name in THEMES:
        _current = name
    PALETTE.clear()
    PALETTE.update(THEMES[_current])

    st = ttk.Style(root)
    try:
        st.theme_use("clam")
    except tk.TclError:
        pass
    P = PALETTE
    dark = is_dark()

    # ---- 全局默认 ----
    st.configure(".", background=P["bg"], foreground=P["fg"],
                 fieldbackground=P["surface"], bordercolor=P["border"],
                 lightcolor=P["border"], darkcolor=P["border"],
                 troughcolor=P["surface_lo"], focuscolor=P["accent"],
                 selectbackground=P["accent"],
                 selectforeground="#FFFFFF" if dark else "#FFFFFF",
                 font=FONT_UI, borderwidth=0, relief="flat")

    st.configure("TFrame", background=P["bg"])
    st.configure("Surface.TFrame", background=P["surface"])
    # 侧栏比内容区略深/略暗一档，靠色差分界，不用描边
    st.configure("Sidebar.TFrame", background=P["surface_lo"])
    st.configure("TLabel", background=P["bg"], foreground=P["fg"])
    st.configure("Surface.TLabel", background=P["surface"], foreground=P["fg"])

    st.configure("Muted.TLabel", background=P["bg"], foreground=P["fg_dim"])
    st.configure("Danger.TLabel", background=P["bg"], foreground=P["danger_hi"])
    st.configure("Success.TLabel", background=P["bg"], foreground=P["success_hi"])
    st.configure("Warning.TLabel", background=P["bg"], foreground=P["warning_hi"])
    st.configure("Info.TLabel", background=P["bg"], foreground=P["info"])

    # LabelFrame 内部是 surface 底，标签得用配套底色，否则会浮出一块更亮的方框
    for suf, key in (("Muted", "fg_dim"), ("Danger", "danger_hi"),
                     ("Success", "success_hi"), ("Warning", "warning_hi"),
                     ("Info", "info")):
        st.configure("Card%s.TLabel" % suf, background=P["surface"],
                     foreground=P[key])
    st.configure("CardText.TLabel", background=P["surface"], foreground=P["fg"])

    # ---- 分组框：浅色下用白底卡片，深色下用一层更亮的底 ----
    st.configure("TLabelframe", background=P["surface"], bordercolor=P["border"],
                 relief="solid", borderwidth=1, padding=px(12))
    st.configure("TLabelframe.Label", background=P["surface"],
                 foreground=P["fg_dim"], font=FONT_UI_SM)

    # ---- 按钮 ----
    st.configure("TButton", background=P["surface_hi"], foreground=P["fg"],
                 bordercolor=P["surface_hi"], padding=(px(14), px(7)),
                 relief="flat", borderwidth=0)
    st.map("TButton",
           background=[("disabled", P["surface"]), ("pressed", P["border"]),
                       ("active", P["border"])],
           foreground=[("disabled", P["fg_dis"])])

    st.configure("Accent.TButton", background=P["accent"], foreground="#FFFFFF")
    st.map("Accent.TButton",
           background=[("disabled", P["surface_hi"]), ("pressed", P["accent_lo"]),
                       ("active", P["accent_hi"])],
           foreground=[("disabled", P["fg_dis"])])

    for sname, base, hover in (
            ("Danger", P["danger"], P["danger_hi"]),
            ("Success", P["success"], P["success_hi"]),
            ("Warning", P["warning"], P["warning_hi"])):
        st.configure("%s.TButton" % sname, background=base, foreground="#FFFFFF")
        st.map("%s.TButton" % sname,
               background=[("disabled", P["surface_hi"]), ("pressed", base),
                           ("active", hover)],
               foreground=[("disabled", P["fg_dis"])])

    # ---- 侧栏导航：纯文字项，不填充色块，靠前景色与底色块区分选中 ----
    st.configure("Nav.TButton", background=P["surface_lo"], foreground=P["fg_dim"],
                 anchor="w", padding=(px(14), px(8)), relief="flat",
                 borderwidth=0, font=FONT_UI)
    st.map("Nav.TButton",
           background=[("active", P["surface_hi"]), ("pressed", P["surface_hi"])],
           foreground=[("active", P["fg"])])
    st.configure("NavActive.TButton", background=P["surface_hi"],
                 foreground=P["accent"], anchor="w",
                 padding=(px(14), px(8)), relief="flat", borderwidth=0,
                 font=FONT_UI_BOLD)

    # ---- 输入类 ----
    st.configure("TEntry", fieldbackground=P["surface"], foreground=P["fg"],
                 insertcolor=P["accent"], bordercolor=P["border"],
                 lightcolor=P["border"], darkcolor=P["border"],
                 padding=px(7), relief="flat")
    st.map("TEntry", bordercolor=[("focus", P["accent"])],
           lightcolor=[("focus", P["accent"])],
           darkcolor=[("focus", P["accent"])])

    st.configure("TCombobox", fieldbackground=P["surface"],
                 background=P["surface_hi"], foreground=P["fg"],
                 arrowcolor=P["fg_dim"], bordercolor=P["border"],
                 lightcolor=P["border"], darkcolor=P["border"], padding=px(5))
    st.map("TCombobox",
           fieldbackground=[("readonly", P["surface"])],
           foreground=[("readonly", P["fg"])],
           arrowcolor=[("active", P["accent"])])
    root.option_add("*TCombobox*Listbox.background", P["surface"])
    root.option_add("*TCombobox*Listbox.foreground", P["fg"])
    root.option_add("*TCombobox*Listbox.selectBackground", P["accent"])
    root.option_add("*TCombobox*Listbox.selectForeground", "#FFFFFF")

    st.configure("TSpinbox", fieldbackground=P["surface"], foreground=P["fg"],
                 arrowcolor=P["fg_dim"], bordercolor=P["border"], padding=px(5))

    # 指示器用边框色：深色下够浅、浅色下够深，两种主题都能看清。
    # indicatorsize 实测有效，默认值在 150% DPI 下只有 12px 见方、整控件高 33px，
    # 太难点；这里放大指示器并加宽上下内边距，把点击区撑到约 44px 高。
    st.configure("TCheckbutton", background=P["bg"], foreground=P["fg"],
                 indicatorcolor=P["border"], focuscolor=P["bg"],
                 indicatorsize=px(17), indicatormargin=px(7),
                 padding=(px(3), px(7)), font=FONT_UI)
    st.map("TCheckbutton",
           background=[("active", P["bg"])],
           indicatorcolor=[("selected", P["accent"]), ("active", P["fg_dim"])],
           foreground=[("disabled", P["fg_dis"])])

    st.configure("TRadiobutton", background=P["bg"], foreground=P["fg"],
                 indicatorcolor=P["border"], focuscolor=P["bg"],
                 indicatorsize=px(15), indicatormargin=px(7),
                 padding=(px(3), px(6)), font=FONT_UI)
    st.map("TRadiobutton",
           background=[("active", P["bg"])],
           indicatorcolor=[("selected", P["accent"]), ("active", P["fg_dim"])],
           foreground=[("disabled", P["fg_dis"])])

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
                 font=FONT_UI_SM, bordercolor=P["border"])
    st.map("Treeview.Heading", background=[("active", P["border"])])

    # ---- 分隔线与滚动条 ----
    st.configure("TSeparator", background=P["border"], bordercolor=P["border"])
    st.configure("Vertical.TScrollbar", background=P["surface_hi"],
                 troughcolor=P["bg"], bordercolor=P["bg"],
                 arrowcolor=P["fg_dis"], relief="flat", borderwidth=0,
                 width=px(11))
    st.configure("Horizontal.TScrollbar", background=P["surface_hi"],
                 troughcolor=P["bg"], bordercolor=P["bg"],
                 arrowcolor=P["fg_dis"], relief="flat", borderwidth=0)
    for orient in ("Vertical", "Horizontal"):
        st.map("%s.TScrollbar" % orient,
               background=[("active", P["border"]), ("pressed", P["accent_lo"])],
               arrowcolor=[("active", P["accent"])])

    st.configure("TPanedwindow", background=P["bg"])
    st.configure("Sash", sashthickness=px(6), gripcount=0)

    # ---- 非 ttk 控件的默认值 ----
    root.tk_setPalette(
        background=P["bg"], foreground=P["fg"],
        highlightColor=P["accent"], highlightBackground=P["border"],
        selectBackground=P["accent"], selectForeground="#FFFFFF",
        activeBackground=P["surface_hi"], activeForeground=P["fg"])

    darken_native_widgets(root)
    return st


# ========================================================== 原生控件配色
def style_text(widget, size=None):
    """ScrolledText / Text 的配色。深浅主题下都取 surface 与 fg。"""
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
            font=(FONT_MONO[0], size or FONT_MONO[1]),
        )
    except tk.TclError:
        pass
    upgrade_scrolledtext_bars(widget)
    return widget


def style_scrollbar(widget):
    """给原生 tk.Scrollbar 配色（独立创建的滚动条兜底）。"""
    P = PALETTE
    try:
        widget.configure(background=P["surface_hi"], troughcolor=P["surface_lo"],
                         activebackground=P["accent_lo"],
                         highlightthickness=0, relief="flat", borderwidth=0,
                         width=px(11))
    except tk.TclError:
        pass
    return widget


def upgrade_scrolledtext_bars(widget):
    """把 ScrolledText 内部的 tk.Scrollbar 换成 ttk.Scrollbar。

    Windows 上 tk.Scrollbar 由系统原生绘制，background/troughcolor 会被忽略 ——
    实测配好色后 cget 能读到新值，画面上仍是一条亮白槽。
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
    """遍历控件树，把原生 tk 控件配色对齐当前主题。

    名字沿用历史的 darken_*，实际深浅主题通用。
    不判断「是否已配色就跳过」—— tk_setPalette 会先把 Text 的 background
    填成主题底色，据此跳过反而会漏掉它内部那条亮白的滚动条。
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
