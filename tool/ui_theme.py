"""MetaAWD 统一 UI 主题层：DPI、多主题配色、渐变、原生控件深色化。

三类历史问题的修复集中在这里
------------------------------
1. 发虚：进程未声明 DPI 感知时，Windows 会把整个窗口位图放大到物理分辨率
   （本机 150% → 放大 1.5 倍），文字边缘被插值成灰边。必须在创建 Tk 之前
   调用 enable_dpi_awareness()。
2. 发虚（其二）：界面曾硬编码 font=("Segoe UI", ...)，而 Segoe UI 不含中文字形，
   Windows 只能靠 font-linking 回退渲染中文，中英混排基线不齐、笔画发灰。
   这里统一改用含中文的 Microsoft YaHei UI。
3. 卡顿：sv-ttk 的样式在每次页面 map/unmap 时要重算大量图片元素，实测切页
   480ms/次，而同样控件树在 clam 上只要 24ms。改为基于 clam 自建的深色样式。

渐变说明
--------
ttk 样式的 -background 只接受纯色，渐变只能用 Canvas 自绘。三种实现实测
（侧栏 294x1350，本机 150% DPI）：

    Canvas 逐行矩形 64 行      首次 7.9ms   重绘 4.4ms
    Canvas 逐行矩形 256 行     首次 6.8ms   重绘 6.2ms
    2px PhotoImage + zoom      首次 9.9ms   重绘 8.4ms
    PhotoImage 逐像素 put      首次 147ms   重绘 133ms   <- 不可用

叠加渐变层后切页耗时 34.1ms vs 基线 34.6ms，无实质影响。因此这里采用
Canvas 逐行矩形（64 行），并对 <Configure> 做防抖 —— 拖动窗口会高频触发
重绘，单次 4.4ms 不痛，但不防抖累积起来就是几百毫秒。
"""

import ctypes
import sys
import tkinter as tk
from tkinter import ttk

# ==================================================================== 主题
# 统一结构：冷色低饱和底 + 单一高饱和强调色；渐变对比度刻意压低，
# 只做层次过渡，避免花哨。
THEMES = {
    "graphite": {
        "label": "石墨 Graphite",
        "bg":         "#17191E",
        "surface":    "#1E2128",
        "surface_hi": "#272B34",
        "surface_lo": "#131519",
        "border":     "#333844",
        "fg":         "#E4E7EC",
        "fg_dim":     "#98A0AD",
        "fg_dis":     "#5B6472",
        "accent":     "#3D7EFF",
        "accent_hi":  "#5B93FF",
        "accent_lo":  "#2A5BC4",
        "danger":     "#E5534B",
        "danger_hi":  "#F0716A",
        "success":    "#3FB950",
        "success_hi": "#4CC38A",
        "warning":    "#D29922",
        "warning_hi": "#E0B341",
        "info":       "#57C8FF",
        "grad_sidebar": ("#232C42", "#141619"),
        "grad_topbar":  ("#243049", "#17191E"),
    },
    "midnight": {
        "label": "午夜 Midnight",
        "bg":         "#0E1117",
        "surface":    "#151A24",
        "surface_hi": "#1E2534",
        "surface_lo": "#0A0D12",
        "border":     "#2A3345",
        "fg":         "#E6E9F0",
        "fg_dim":     "#8E97AB",
        "fg_dis":     "#525B70",
        "accent":     "#7C6BF0",
        "accent_hi":  "#9A8CFF",
        "accent_lo":  "#5B4BC4",
        "danger":     "#E5534B",
        "danger_hi":  "#F0716A",
        "success":    "#3FB950",
        "success_hi": "#4CC38A",
        "warning":    "#D29922",
        "warning_hi": "#E0B341",
        "info":       "#8B9DFF",
        "grad_sidebar": ("#1E2A52", "#0C0F16"),
        "grad_topbar":  ("#1C2450", "#0E1117"),
    },
    "ocean": {
        "label": "深海 Ocean",
        "bg":         "#0C1317",
        "surface":    "#121E24",
        "surface_hi": "#1A2A32",
        "surface_lo": "#080E11",
        "border":     "#243943",
        "fg":         "#E2EAEE",
        "fg_dim":     "#8A9AA3",
        "fg_dis":     "#4E5D66",
        "accent":     "#2BBCD4",
        "accent_hi":  "#4FD3E8",
        "accent_lo":  "#1C8CA0",
        "danger":     "#E5614B",
        "danger_hi":  "#F07D6A",
        "success":    "#3FB980",
        "success_hi": "#4CC394",
        "warning":    "#D2A022",
        "warning_hi": "#E0B841",
        "info":       "#5FD8E8",
        "grad_sidebar": ("#123A47", "#091014"),
        "grad_topbar":  ("#10333E", "#0C1317"),
    },
    "verdant": {
        "label": "苔原 Verdant",
        "bg":         "#0F1512",
        "surface":    "#151D18",
        "surface_hi": "#1E2820",
        "surface_lo": "#0A0F0D",
        "border":     "#28382D",
        "fg":         "#E3EAE5",
        "fg_dim":     "#8C9B91",
        "fg_dis":     "#515E55",
        "accent":     "#3FB950",
        "accent_hi":  "#5ED46F",
        "accent_lo":  "#2C8A3B",
        "danger":     "#E5614B",
        "danger_hi":  "#F07D6A",
        "success":    "#4CC38A",
        "success_hi": "#63D49E",
        "warning":    "#D2A022",
        "warning_hi": "#E0B841",
        "info":       "#6BD8A0",
        "grad_sidebar": ("#1A3A26", "#0C120E"),
        "grad_topbar":  ("#173524", "#0F1512"),
    },
    "ember": {
        "label": "余烬 Ember",
        "bg":         "#181412",
        "surface":    "#211B18",
        "surface_hi": "#2C2420",
        "surface_lo": "#110E0C",
        "border":     "#3B302A",
        "fg":         "#EDE6E1",
        "fg_dim":     "#A3958C",
        "fg_dis":     "#645A54",
        "accent":     "#F0883E",
        "accent_hi":  "#FFA35C",
        "accent_lo":  "#C46529",
        "danger":     "#E5534B",
        "danger_hi":  "#F0716A",
        "success":    "#4CC38A",
        "success_hi": "#63D49E",
        "warning":    "#D2A022",
        "warning_hi": "#E0B841",
        "info":       "#FFB067",
        "grad_sidebar": ("#42291A", "#14100E"),
        "grad_topbar":  ("#3A2418", "#181412"),
    },
}

DEFAULT_THEME = "graphite"
_current = DEFAULT_THEME

# 当前主题色。原地更新而非整体替换，保证外部已持有的引用始终有效。
PALETTE = {}
PALETTE.update(THEMES[DEFAULT_THEME])


def theme_names():
    """返回 [(key, label), ...]，供界面下拉使用。"""
    return [(k, v["label"]) for k, v in THEMES.items()]


def current_theme():
    return _current


def theme_label(name=None):
    return THEMES.get(name or _current, {}).get("label", name or _current)


# ==================================================================== 字体
_FAMILY_UI = "Microsoft YaHei UI"
_FAMILY_LATIN = "Segoe UI"
_FAMILY_MONO = "Consolas"

FONT_UI = (_FAMILY_UI, 10)
FONT_UI_SM = (_FAMILY_UI, 9)
FONT_UI_BOLD = (_FAMILY_UI, 10, "bold")
FONT_TITLE = (_FAMILY_UI, 16, "bold")
FONT_SUBTITLE = (_FAMILY_UI, 10)
FONT_GROUP = (_FAMILY_UI, 9, "bold")
FONT_BRAND = (_FAMILY_LATIN, 15, "bold")
FONT_MONO = (_FAMILY_MONO, 10)
FONT_MONO_LG = (_FAMILY_MONO, 11)

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


def apply_dark_title_bar(root):
    """把 Windows 标题栏切成深色。"""
    if sys.platform != "win32":
        return False
    try:
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id()) or root.winfo_id()
        value = ctypes.c_int(1)
        for attr in (20, 19):
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attr, ctypes.byref(value), ctypes.sizeof(value)) == 0:
                return True
    except Exception:
        pass
    return False


# ==================================================================== 渐变
_GRADIENTS = []


def _hex_rgb(c):
    c = c.lstrip("#")
    return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)


def _lerp(c1, c2, t):
    a, b = _hex_rgb(c1), _hex_rgb(c2)
    return "#%02x%02x%02x" % tuple(
        int(round(a[i] + (b[i] - a[i]) * t)) for i in range(3))


def _ramp(c1, c2, rows):
    return [_lerp(c1, c2, i / max(rows - 1, 1)) for i in range(rows)]


class GradientCanvas(tk.Canvas):
    """逐行矩形的垂直渐变背景，带 resize 防抖。

    用法：先 pack/place 它并压到下层，再把实际控件放上去。
    主题切换时 apply_theme() 会统一重绘。
    """

    ROWS = 64

    def __init__(self, master, kind="sidebar", **kw):
        kw.setdefault("highlightthickness", 0)
        kw.setdefault("bd", 0)
        super().__init__(master, **kw)
        self._kind = kind
        self._job = None
        self._last = (0, 0)
        _GRADIENTS.append(self)
        self.bind("<Configure>", self._on_configure)
        self.bind("<Destroy>", self._on_destroy)

    def _colors(self):
        key = "grad_%s" % self._kind
        pair = PALETTE.get(key) or THEMES[_current].get(key)
        if not pair:
            pair = (PALETTE["surface"], PALETTE["bg"])
        return pair

    def _on_destroy(self, _e=None):
        try:
            _GRADIENTS.remove(self)
        except ValueError:
            pass

    def _on_configure(self, event):
        # 拖动窗口会连续触发 <Configure>，防抖到停下来再画一次
        if self._job is not None:
            try:
                self.after_cancel(self._job)
            except Exception:
                pass
        self._job = self.after(120, self.redraw)

    def redraw(self):
        self._job = None
        try:
            w, h = self.winfo_width(), self.winfo_height()
        except tk.TclError:
            return
        if w <= 1 or h <= 1 or (w, h) == self._last:
            return
        self._last = (w, h)
        self.delete("all")
        c1, c2 = self._colors()
        cols = _ramp(c1, c2, self.ROWS)
        step = h / self.ROWS
        for i, col in enumerate(cols):
            y0 = i * step
            self.create_rectangle(0, y0, w, y0 + step + 1,
                                  fill=col, outline=col, width=0)
        self.tk.call("lower", self._w)


def attach_gradient(parent, kind="sidebar", **kw):
    """在 parent 里铺一层渐变背景并压到最下层，返回该 Canvas。"""
    cv = GradientCanvas(parent, kind=kind, **kw)
    cv.place(x=0, y=0, relwidth=1, relheight=1)
    return cv


def redraw_gradients():
    for cv in list(_GRADIENTS):
        try:
            if cv.winfo_exists():
                cv._last = (0, 0)
                cv.redraw()
        except tk.TclError:
            try:
                _GRADIENTS.remove(cv)
            except ValueError:
                pass
    apply_tints()


# --------------------------------------------------------- 跟随渐变的控件
# ttk 没有透明背景。若一组按钮共用一个底色，按钮区的渐变会被压成一条色带，
# 只有按钮之外的空白看得出渐变。这里按控件在容器里的实际纵向位置分档着色，
# 让控件底色与身后的渐变对齐，视觉上才是连续的一道。
_TINT_GROUPS = []
_TINT_STATE = {}


def register_tint(container, widgets, grad_key, prefix):
    """登记一组需要跟随渐变的控件。widgets 可以是 list 或 dict。"""
    _TINT_GROUPS.append((container, widgets, grad_key, prefix))


def apply_tints(force=False):
    """按当前主题与控件位置刷新底色。主题切换和 resize 后各调用一次。

    带状态缓存：主题和容器高度都没变时直接跳过。否则构造阶段会被
    <Configure> 反复触发，实测把启动耗时从 0.28s 抬到 0.89s。
    """
    st = ttk.Style()
    for container, widgets, grad_key, prefix in list(_TINT_GROUPS):
        try:
            if not container.winfo_exists():
                _TINT_GROUPS.remove((container, widgets, grad_key, prefix))
                continue
            h = max(container.winfo_height(), 1)
            if h <= 1:
                # 布局尚未完成（首轮 apply_theme 时控件还没排布），
                # 等 <Configure> 触发的下一次 redraw 再算
                continue
        except tk.TclError:
            continue

        sig = (id(container), _current, h)
        if not force and _TINT_STATE.get(id(container)) == sig:
            continue
        _TINT_STATE[id(container)] = sig

        seq = list(widgets.values()) if isinstance(widgets, dict) else list(widgets)
        c1, c2 = PALETTE.get(grad_key, (PALETTE["surface"], PALETTE["bg"]))
        p = PALETTE
        for i, w in enumerate(seq):
            try:
                if not w.winfo_exists():
                    continue
                # 用控件中心点取色；乘 0.85 是让底部余量不至于过暗
                t = (w.winfo_y() + w.winfo_height() / 2.0) / h
                col = _lerp(c1, c2, min(max(t, 0.0), 1.0) * 0.85)
                name = "%sTint%d.TButton" % (prefix, i)
                st.configure(name, background=col, foreground=p["fg_dim"],
                             anchor="w", padding=(px(16), px(9)),
                             relief="flat", borderwidth=0, font=FONT_UI)
                st.map(name,
                       background=[("active", p["surface_hi"]),
                                   ("pressed", p["surface_hi"])],
                       foreground=[("active", p["fg"])])
                # 选中态保持高亮，别被渐变底色盖掉
                w._tint_style = name
                if w.cget("style") != "NavActive.TButton":
                    w.configure(style=name)
            except tk.TclError:
                continue


def tint_style_of(widget):
    """取控件缓存的渐变底色样式名（切页恢复非选中态时用）。

    直接用缓存而不是重算：ttk 的 style configure 会触发全窗口样式重算，
    实测 5 个按钮要 130ms，必须避免在切页这种高频路径上调用。
    """
    return getattr(widget, "_tint_style", "Nav.TButton")


# ==================================================================== 样式
def apply_theme(root, name=None, restyle_native=True):
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

    # 语义按钮：clam 主题下可逐个着色（sv-ttk 的 PNG 精灵图做不到）
    for sname, base, hover in (
            ("Danger", P["danger"], P["danger_hi"]),
            ("Success", P["success"], P["success_hi"]),
            ("Warning", P["warning"], P["warning_hi"])):
        st.configure("%s.TButton" % sname, background=base, foreground="#FFFFFF")
        st.map("%s.TButton" % sname,
               background=[("disabled", P["surface"]), ("pressed", base),
                           ("active", hover)],
               foreground=[("disabled", P["fg_dis"])])

    # ---- 侧栏导航 / 顶栏 ----
    # 这两处底下铺了渐变。ttk 没有真正的透明背景，控件只能取渐变对应位置的
    # 颜色才能视觉融合，否则会在渐变上浮出一块块纯色矩形。
    nav_bg = _lerp(*P["grad_sidebar"], 0.30)
    top_bg = _lerp(*P["grad_topbar"], 0.40)

    st.configure("Nav.TButton", background=nav_bg, foreground=P["fg_dim"],
                 anchor="w", padding=(px(16), px(9)), relief="flat",
                 borderwidth=0, font=FONT_UI)
    st.map("Nav.TButton",
           background=[("active", P["surface_hi"]), ("pressed", P["surface_hi"])],
           foreground=[("active", P["fg"])])
    st.configure("NavActive.TButton", background=P["surface_hi"],
                 foreground=P["accent_hi"], anchor="w",
                 padding=(px(16), px(9)), relief="flat", borderwidth=0,
                 font=FONT_UI_BOLD)

    st.configure("NavGroup.TLabel", background=nav_bg, foreground=P["fg_dim"],
                 font=FONT_GROUP)
    st.configure("Top.TLabel", background=top_bg, foreground=P["fg"])
    st.configure("TopMuted.TLabel", background=top_bg, foreground=P["fg_dim"],
                 font=FONT_UI_SM)
    st.configure("TopSuccess.TLabel", background=top_bg,
                 foreground=P["success_hi"], font=FONT_UI_SM)
    st.configure("Top.TCombobox", fieldbackground=P["surface_hi"],
                 background=P["surface_hi"], foreground=P["fg"],
                 arrowcolor=P["fg_dim"], bordercolor=P["border"],
                 lightcolor=P["border"], darkcolor=P["border"], padding=px(4))

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

    if restyle_native:
        darken_native_widgets(root)

    redraw_gradients()
    return st


# ========================================================== 原生控件深色化
def style_text(widget, mono=True, size=None):
    """ScrolledText / Text / Listbox 的深色终端外观。"""
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
    """给原生 tk.Scrollbar 配色（独立创建的滚动条兜底）。"""
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
                    # 渐变层由 redraw_gradients 负责，这里别覆盖它的绘制
                    if not isinstance(child, GradientCanvas):
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
