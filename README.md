# MetaAWD

面向 AWD / CTF 的图形化辅助工具。新版防御工作台使用 React、shadcn/ui 和 pywebview，复用 Python 防御模块。

**MetaAWD** · by metavi

**第一次使用请看：[新版工作台详细使用手册](docs/使用手册.md)** — 各模块参数、操作步骤、PWN 四模式部署与回滚、常见问题。

> 仅供授权的 CTF / AWD 比赛与安全研究使用。

---

## 防御工作台功能

- **SSH 和文件监控** — 验证 SSH 连接，使用 MD5 基线记录站点文件变化。
- **SSH 交互终端** — 复用已验证的服务器连接，按行输入、查看实时输出，支持 Ctrl+C 和断开会话。
- **WebShell 查杀** — 扫描本地或远端文件，可调整判定阈值并保存报告。恶意项可预览后注释，也可经确认启用扫描后自动备份并移除。
- **WAF 管理** — 部署 PHP 5/7/8 对应的模板，更新已部署的日志模板或下线 WAF。
- **PWN 沙箱防护** — 只读检查 ELF 加固状态，生成 Linux x86-64 ELF 加固副本或导出 systemd 服务策略。
- **PWN 流量转发** — 配置 CATCH、I0GAN、FORWARD、FORWARD_MULTI 四种模式，导出兼容 `pwn_waf` 的 Linux 构建、xinetd 部署与回滚文件。
- **请求审查** — 手动或自动同步 PHP WAF 采集的 HTTP 请求，查看原文、请求头和正文，提示新同步的 WAF 命中。
- **源码备份和恢复** — 将远端站点打包下载，恢复支持回滚。
- **Bugku 批量提交** — 粘贴已有 flag，由工作台去重后逐条送至计分端，按原输入行显示结果。

## 目录结构

| 路径 | 内容 |
|---|---|
| [`tool/`](tool/) | Python 桌面宿主、桥接层和防御模块 |
| [`tool/desktop_ui/`](tool/desktop_ui/) | React 前端、官方 shadcn/ui 组件与主题 |
| [使用手册](docs/使用手册.md) | 面向用户的各模块操作教程、参数说明与故障排查 |
| [维护交接](docs/README.md) | 模块增删改查、验证和发布流程 |
| [`AGENTS.md`](AGENTS.md) | 开发者与 agent 的快速入口 |
| [`releases/`](releases/) | Windows 可执行文件 |
| [`scripts/`](scripts/) | 发布前泄露审计脚本 |

## 快速开始

### 防御工作台（新版）

Windows x64 上可以直接双击当前发布包 `MetaAWD-Desktop-20261119-162436.exe`。EXE 已包含 Python 和前端资源，运行电脑需要 WebView2 Runtime。运行数据保存在 EXE 同级的 `tmp/`。[下载新版 EXE](releases/MetaAWD-Desktop-20261119-162436.exe) · [SHA-256](releases/MetaAWD-Desktop-20261119-162436.exe.sha256)

从源码启动时，在项目根目录用 PowerShell 执行以下命令。需要 Python 3.9+、Node.js 20.19+（20.x）或 22.12+，以及 Windows WebView2 Runtime。[WebView2 下载](https://developer.microsoft.com/microsoft-edge/webview2/)

```powershell
python -m venv tool/.venv
& '.\tool\.venv\Scripts\python.exe' -m pip install -r tool/desktop-requirements.txt
npm --prefix tool/desktop_ui ci
npm --prefix tool/desktop_ui run build
& '.\tool\start.bat' --check
& '.\tool\start.bat'
```

已经有 `tool/.venv` 时可直接使用其中的 Python 安装依赖。构建完成后可双击启动脚本。脚本优先使用 `tool/.venv`，其次查找 `python` 和 `py`。`--check` 只检查前端入口文件和 Python 依赖。[启动脚本](tool/start.bat) · [维护交接](docs/README.md)

### SSH 终端和 Bugku 提交

- **工作台与服务器管理** · 在「工作台 → SSH 连接」测试通过后，从「服务器管理」打开「SSH 交互终端」。按 Enter 或点「发送」输入一行。切换到另一台服务器时，原终端会断开。
- **平台工具** · 「Bugku 批量提交」支持粘贴已有的 flag 或导入 UTF-8 TXT，每行一条。可以调整提交间隔、超时、单批上限和重复项处理，先预览再填队伍 Token 提交。结果按输入行号显示，完成后可导出 CSV。

### 查看站点收到的请求

1. 验证 SSH，在「WAF 管理」部署 WAF。已经部署的站点可填写原来的安装目录，点击「更新日志模板」，为后续的新日志补充请求时间、对端 IP 和 WAF 判定。
2. 打开「请求审查」，点击「同步请求」或开启「自动同步」。工作台空闲时每 5 秒检查一次，收到新请求就刷新列表。新同步的 WAF 命中会在工作区内提示，点「查看命中」可直接筛选。
3. 选中一条记录即可查看请求原文、请求头和正文，也可保存完整采集字节。已有的 `.http` 日志可以直接查看。
4. 默认采集命中规则的请求。要同时留存未命中的 PHP 请求，在部署时开启「记录全部请求」。

请求原文按 PHP 接收到的内容保存。PHP 之前处理的静态请求或已经被拒绝的请求需要查看 Web 服务器日志。部分 multipart 上传的原始正文可能无法从 PHP 获取。[PHP 请求正文说明](https://www.php.net/manual/zh/wrappers.php.php)

### 检查 ELF 和配置 PWN 沙箱防护

1. 打开「站点防御 → PWN 沙箱防护」。在「ELF 体检」选择本地文件，查看架构、位数、SHA-256 和各加固项。
2. 在「systemd 策略」填写目标服务单元名，选择系统调用、文件系统、套接字等限制，点击「生成策略预览」。
3. 核对每项指令和兼容性提示后导出 `.conf`。在 Linux 测试环境放入预览给出的 drop-in 目录，检查合并后的服务单元，再重新加载配置并验证服务。策略在 systemd 加载并启动对应服务时生效。[systemd 指令](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html) · [配置验证](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html)

「ELF 加固副本」可以为 Linux x86-64 可执行 ELF 生成一套文件。选择系统调用组，预览拦截清单和 SHA-256，再导出到本地。把 `run-hardened`、`program.elf` 和 `policy.json` 一起放到 Linux 的受信目录，赋予前两个文件执行权限，从 `run-hardened` 启动。启动器校验副本并加载 seccomp，所选调用被拦截时收到 `EPERM`。[Linux seccomp 说明](https://docs.kernel.org/userspace-api/seccomp_filter.html)

沙箱预设提供三套起点，可以继续手动增减规则组。

- **Sandbox 1**适合先验证基础防护，限制挂载、内核管理和跨进程调试。
- **Sandbox 2**增加按文件句柄打开、删除和重命名限制。需要验证日志轮转和原子写入。
- **Sandbox 3**增加建连、监听和进程线程创建限制。需要自行监听或创建线程的服务可调整对应规则组。

预设参考 EvilPatcher 的分档方式，具体拦截清单以 MetaAWD 预览为准。当前启动器会先加载策略，再启动程序，所以保留启动和动态加载需要的调用。[EvilPatcher 原版规则](https://github.com/TTY-flag/evilPatcher/tree/main/sandboxs)

### 配置 PWN 流量转发

1. 打开「站点防御 → PWN 流量转发」，选择模式：`CATCH` 运行原程序并记录交互，`I0GAN` 额外终止后续危险系统调用，`FORWARD` 转发到单个 IPv4 目标，`FORWARD_MULTI` 按新连接轮询多目标列表。
2. 填写服务程序与备份路径、目标 x86 架构、日志目录、编译参数，以及 xinetd 的监听地址、端口、服务用户、并发和资源限制。单目标填写 IPv4 与端口，多目标每行填写一个 `IPv4:端口`。
3. 生成预览，核对 Makefile、xinetd 配置、文件清单和部署提示，再导出构建包。包内含四个构建目标、MIT 授权的 `pwn_waf` 兼容源码、`deploy.sh`、`rollback.sh`、`policy.json`，多目标模式另含规范化的 `hosts.txt`。
4. 在 glibc 版本不高于部署目标的 Linux x86/x86-64 构建环境运行预览中的 `make` 命令。在隔离环境执行部署脚本，从独立终端连接服务做完整交互测试，并确认日志和回滚脚本后再上线。32 位构建需要对应 multilib，静态链接需要对应静态库。[pwn_waf 上游](https://github.com/i0gan/pwn_waf)

### 旧版 Tkinter

`python tool/launcher.py` 启动旧版界面，追加 `check` 只做旧版环境自检。现有 `MetaAWD-v3.5.exe` 同样使用 Tkinter，`tmp/` 位于 EXE 同级目录。打包命令和旧版功能说明见旧版手册。[发布目录](releases/) · [旧版使用说明](tool/README.md)

## 旧版 Bugku 提交凭据

token 与域名不再硬编码，通过环境变量提供：

```bash
set AWD_BUGKU_TOKEN=你的token        # Windows
export AWD_BUGKU_TOKEN=你的token     # Linux/macOS
```

未设置时使用占位符，功能不可用但不会报错。

## 发布前检查

推送前可在干净的源码目录运行泄露审计，检查硬编码凭据、真实 IP、本机路径和比赛数据。

```bash
python scripts/pre_release_audit.py
```

存在严重风险时以非零码退出。

## 已知限制

- 现有 EXE 为 Windows 64 位产物。新版启动流程和窗口操作按 Windows + WebView2 说明。
- 远端功能需目标机提供 SSH 服务
- WAF 注入会改写业务 PHP 文件，操作前请先打包备份

维护入口和常见故障见交接 README。历史改动保留在旧版手册和修复记录中。[维护交接](docs/README.md) · [旧版使用说明](tool/README.md) · [历史修复记录](tool/FIXES.md)

## 免责声明

本项目仅用于授权的安全测试与 CTF/AWD 比赛。使用者需自行确保对目标系统
拥有合法授权。作者不对任何未授权使用承担责任。
