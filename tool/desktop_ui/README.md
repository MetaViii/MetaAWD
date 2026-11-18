# MetaAWD 防御工作台

组件保留上游的结构和样式，使用项目内的导入路径。[shadcn/ui New York Registry](https://github.com/shadcn-ui/ui/tree/968d8cb9dc42ae5d52e8fd356cf84596ec832a26/apps/v4/registry/new-york-v4/ui) · [MIT 授权](SHADCN-LICENSE.md)

使用 shadcn/ui 官方 Zinc 主题，默认使用浅色。图标来自 Lucide，页面图标使用上游 Shield Check SVG。[Zinc 配色](https://github.com/shadcn-ui/ui/blob/968d8cb9dc42ae5d52e8fd356cf84596ec832a26/apps/v4/registry/themes.ts) · [Lucide](https://lucide.dev/icons/) · [图标授权](public/LUCIDE-LICENSE.txt)

Windows EXE 的图标由同一份 SVG 转为透明多尺寸 ICO，由打包配置嵌入。[SVG 原件](public/shield-check.svg) · [Windows 图标](shield-check.ico)

## 开发与运行

在本目录使用 `npm ci` 安装前端依赖，`npm run build` 先做 TypeScript 检查，再构建到 `dist/`。修改前端后重新构建并重开桌面窗口。完整的 Python 依赖安装和启动流程见[快速开始](../../README.md#快速开始)。

构建后在本目录运行 `..\start.bat --check` 检查前端入口与 Python 依赖，再运行 `..\start.bat` 打开新版桌面工作台。`npm run dev` 和 `npm run preview` 提供本地浏览器预览。需要 Python 桥接的操作在桌面窗口验证。

在 Windows 上，可以从页面顶部空白处拖动窗口，从右上角操作窗口。主题切换和 SSH 状态在侧栏底部。

页面、侧栏和桥接方法的修改入口见[维护交接](../../docs/README.md#日常增删改查)。

发布版 Windows EXE 使用独立的 PyInstaller 配置。[构建新版 Windows EXE](../../docs/README.md#构建新版-windows-exe)
