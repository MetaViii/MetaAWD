# MetaAWD 开发入口

开始改动前，先按任务查[维护交接](docs/README.md)。其中有页面和模块索引、增删改查步骤、请求数据流、离线测试及 EXE 构建方法。

- 新版用 `tool/start.bat` 启动，EXE 用 `tool/desktop.spec` 构建。无参数的 `tool/launcher.py` 和 `tool/build.spec` 对应旧版 Tkinter。共享防御模块在 `tool/defence/`。
- 改界面从 `tool/desktop_ui/src/pages/` 和同级的 `main.tsx` 开始。复用官方 shadcn/ui 组件、Zinc 主题令牌和 Lucide 图标，保持默认浅色。
- 改读取接口时核对 `tool/desktop.py` 的方法表和 `tool/desktop_ui/src/lib/desktop.ts` 的类型。业务动作、输入校验和长任务放在 `tool/desktop_api.py`，SSH 和文件逻辑复用 `tool/defence/`。
- 请求日志、备份和报告是运行数据。离线验证使用虚构请求和临时文件，改采集字段时保留已有 `.http` 日志的读取兼容。
- 改完按[验证表](docs/README.md#改完怎么验证)选择检查。前端入口用 `npm --prefix tool/desktop_ui run build`，启动自检用 `tool/start.bat --check`，发布步骤见[Windows EXE 构建](docs/README.md#构建新版-windows-exe)。
