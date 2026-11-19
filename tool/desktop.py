"""Start the locally bundled React workspace in pywebview."""

import sys
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
UI_INDEX = HERE / "desktop_ui" / "dist" / "index.html"


def _remove_windows_caption(window):
    """Hide the native caption while keeping Windows edge resizing."""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32")
    hwnd = window.native.Handle.ToInt64()
    style_index = -16  # GWL_STYLE
    caption = 0x00C00000  # WS_CAPTION
    resize_frame = 0x00040000  # WS_THICKFRAME
    # SWP_FRAMECHANGED with no move, size, Z-order, or activation change.
    frame_flags = 0x0020 | 0x0002 | 0x0001 | 0x0004 | 0x0010

    user32.GetWindowLongW.argtypes = (wintypes.HWND, ctypes.c_int)
    user32.GetWindowLongW.restype = wintypes.LONG
    user32.SetWindowLongW.argtypes = (wintypes.HWND, ctypes.c_int, wintypes.LONG)
    user32.SetWindowLongW.restype = wintypes.LONG
    user32.SetWindowPos.argtypes = (wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, ctypes.c_int, wintypes.UINT)
    user32.SetWindowPos.restype = wintypes.BOOL
    user32.IsZoomed.argtypes = (wintypes.HWND,)
    user32.IsZoomed.restype = wintypes.BOOL

    style = user32.GetWindowLongW(hwnd, style_index)
    if not style & resize_frame:
        return None
    if not user32.SetWindowLongW(hwnd, style_index, style & ~caption):
        return None
    if not user32.SetWindowPos(hwnd, None, 0, 0, 0, 0, frame_flags):
        user32.SetWindowLongW(hwnd, style_index, style)
        user32.SetWindowPos(hwnd, None, 0, 0, 0, 0, frame_flags)
        return None
    return lambda: bool(user32.IsZoomed(hwnd))


def create_workspace(webview, service, *, hidden=False):
    from defence.bugku_submit import export_results
    from defence.pwn_bundle import bundle_profiles, export_bundle, preview_bundle
    from defence.pwn_protection import DROP_IN, build_policy, inspect_elf, save_policy
    from defence.pwn_forward import build_forward_plan, export_forward_bundle
    from defence.request_logs import export_request

    webview.settings["ALLOW_FILE_URLS"] = False
    webview.settings["DRAG_REGION_DIRECT_TARGET_ONLY"] = True
    window = webview.create_window(
        "MetaAWD",
        str(UI_INDEX),
        width=1360,
        height=860,
        min_size=(860, 620),
        easy_drag=False,
        text_select=True,
        hidden=hidden,
    )

    is_maximized = None

    def configure_chrome():
        nonlocal is_maximized
        is_maximized = _remove_windows_caption(window)

    if sys.platform == "win32":
        window.events.before_show += configure_chrome

    def snapshot():
        view = service.snapshot()
        view["window"] = {
            "controls": is_maximized is not None,
            "maximized": is_maximized() if is_maximized is not None else False,
        }
        return view

    def window_control(command):
        if is_maximized is None:
            raise ValueError("请使用系统窗口按钮。")
        if command == "minimize":
            window.minimize()
        elif command == "toggle-maximize":
            (window.restore if is_maximized() else window.maximize)()
        elif command == "close":
            window.destroy()
        else:
            raise ValueError("未知窗口操作。")

    def pick_path(kind):
        if kind == "directory":
            selected = window.create_file_dialog(webview.FileDialog.FOLDER)
        else:
            filters = {
                "archive": ("Gzip 备份包 (*.tar.gz;*.tgz)",),
                "file": ("所有文件 (*.*)",),
            }
            if kind not in filters:
                raise ValueError("未知文件类型。")
            selected = window.create_file_dialog(
                webview.FileDialog.OPEN, allow_multiple=False, file_types=filters[kind]
            )
        return selected[0] if selected else None

    def export_packet(name):
        source = service.packet_path(name)
        selected = window.create_file_dialog(
            webview.FileDialog.SAVE, save_filename=source.name, file_types=("HTTP 请求 (*.http)",)
        )
        if not selected:
            return None
        destination = selected[0] if isinstance(selected, (list, tuple)) else selected
        export_request(source, destination)
        return str(destination)

    def export_bugku():
        rows = service.bugku_results()
        if not rows:
            raise ValueError("当前没有可导出的提交结果。")
        selected = window.create_file_dialog(
            webview.FileDialog.SAVE, save_filename="bugku-results.csv",
            file_types=("CSV 文件 (*.csv)",),
        )
        if not selected:
            return None
        destination = selected[0] if isinstance(selected, (list, tuple)) else selected
        export_results(rows, destination)
        return str(destination)

    def export_pwn_policy(options):
        build_policy(options)
        selected = window.create_file_dialog(
            webview.FileDialog.SAVE, save_filename=DROP_IN,
            file_types=("systemd 配置 (*.conf)",),
        )
        if not selected:
            return None
        destination = selected[0] if isinstance(selected, (list, tuple)) else selected
        return save_policy(options, destination)

    def export_pwn_bundle(path, groups):
        destination = pick_path("directory")
        if not destination:
            return None
        return export_bundle(path, groups, destination)

    def export_pwn_forward(options):
        destination = pick_path("directory")
        if not destination:
            return None
        return export_forward_bundle(options, destination)

    methods = {
        "snapshot": snapshot,
        "window_control": window_control,
        "action": service.action,
        "scan_results": service.scan_results,
        "attack_urls": service.attack_urls,
        "terminal_output": service.terminal_output,
        "bugku_results": service.bugku_results,
        "bugku_preview": service.bugku_preview,
        "export_bugku": export_bugku,
        "pwn_audit": inspect_elf,
        "pwn_plan": build_policy,
        "export_pwn_policy": export_pwn_policy,
        "pwn_bundle_profiles": bundle_profiles,
        "pwn_bundle_preview": preview_bundle,
        "export_pwn_bundle": export_pwn_bundle,
        "pwn_forward_plan": build_forward_plan,
        "export_pwn_forward": export_pwn_forward,
        "list_packets": service.list_packets,
        "read_packet": service.read_packet,
        "export_packet": export_packet,
        "pick_path": pick_path,
    }

    def invoke(method, args):
        current = urlsplit(str(window.get_current_url() or ""))
        expected = urlsplit(str(window.real_url or ""))
        if not current.netloc or current[:3] != expected[:3]:
            raise RuntimeError("请在本地防御工作台内操作。")
        if not isinstance(method, str) or method not in methods or not isinstance(args, list):
            raise ValueError("未知工作台操作。")
        return methods[method](*args)

    window.expose(invoke)
    window.events.closed += service.shutdown
    return window


def main(*, check_only=False):
    if not UI_INDEX.is_file():
        print(f"工作台前端尚未构建。请在 {HERE / 'desktop_ui'} 运行 npm ci 和 npm run build。")
        return 1
    try:
        import webview
        import elftools
        from desktop_api import DesktopService
    except ImportError as exc:
        print(f"工作台依赖未就绪：{exc}")
        print(f'请使用当前 Python 安装依赖。\n"{sys.executable}" -m pip install -r "{HERE / "desktop-requirements.txt"}"')
        return 1

    if check_only:
        print("[OK] 新版工作台的 Python 依赖和前端构建已就绪。")
        return 0

    create_workspace(webview, DesktopService())
    webview.start(gui="edgechromium" if sys.platform == "win32" else None)
    return 0


if __name__ == "__main__":
    sys.exit(main(check_only=sys.argv[1:] == ["--check"]))
