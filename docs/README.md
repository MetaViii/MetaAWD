# MetaAWD 维护交接

这份手册面向第一次接手 MetaAWD 防御工作台的开发者和 agent。它按实际改动给出入口，并说明哪些文件需要一起改、如何离线验证和如何生成新版 EXE。

如果你要了解各模块怎么使用，请先阅读 [新版工作台使用手册](使用手册.md)。本页主要用于开发维护与打包。

## 先找到你要改的地方

| 改动 | 从哪里开始 | 改完先验证什么 |
| --- | --- | --- |
| 调整布局、文案或按钮 | [前端页面](../tool/desktop_ui/src/pages/) 和 [main.tsx](../tool/desktop_ui/src/main.tsx) | 前端构建，桌面窗口看效果 |
| 增删页面或侧栏入口 | `main.tsx` 的 `groups`、`pages`，以及 `overview.tsx` 的 `Page` | 侧栏、概览捷径和页面内跳转 |
| 增删后端操作或返回字段 | [desktop_api.py](../tool/desktop_api.py)、[desktop.ts](../tool/desktop_ui/src/lib/desktop.ts)，读接口还看 [desktop.py](../tool/desktop.py) | 有效输入、无效输入、失败后状态恢复 |
| 改请求同步、筛选、命中提示 | [请求审查的数据流](#请求审查的数据流) | 新旧日志、刷新、去重、停止与重试 |
| 改 SSH 终端或 Bugku 提交 | [终端与平台提交](#终端与平台提交) | 连接归属、关闭清理、逐行结果和停止行为 |
| 改扫描规则、WAF 或备份逻辑 | [后台模块维护](#后台模块维护) | 对应模块的离线用例 |
| 改 Windows 窗口、图标、打包 | [desktop.py](../tool/desktop.py)、[desktop.spec](../tool/desktop.spec) | 源码启动或 EXE 的实际窗口加载 |

从项目根目录用 PowerShell 操作。首次克隆按项目首页创建 `tool/.venv`、安装 Python 依赖和运行 `npm ci`。当前源码入口要求 Python 3.9+，前端构建使用 Node.js 20.19+（20.x）或 22.12+，Windows 桌面窗口使用 WebView2 Runtime。[首次安装](../README.md#快速开始)

已有依赖时，开发期间用下面的命令重建界面和启动程序。

```powershell
npm --prefix tool/desktop_ui run build
if ($LASTEXITCODE -ne 0) { throw '前端构建失败' }
& '.\tool\start.bat' --check
if ($LASTEXITCODE -ne 0) { throw '启动自检失败' }
& '.\tool\start.bat'
```

只改 Python 时重开窗口即可。改桥接入参、返回类型或前端时，重建前端后重开窗口。`npm run dev` 和 `npm run preview` 在浏览器里预览布局。验证 Python 桥接、原生对话框或窗口按钮时使用桌面窗口。[前端开发说明](../tool/desktop_ui/README.md#开发与运行)

## 启动与架构

```text
源码  tool/start.bat → launcher.py desktop → desktop.py
EXE   releases/MetaAWD-Desktop-*.exe → desktop.py
                                        │
                    pywebview 加载本地 desktop_ui/dist/index.html
                                        │
React 页面 → callDesktop → invoke(method, args) → DesktopService → defence/ 模块
       ↑                                                   │
       └──────── useWorkspace 读取快照和页面查询结果 ─────────┘
```

`start.bat` 先切到 `tool/`，按 `tool/.venv`、`python`、`py` 的顺序选 Python。`launcher.py desktop` 和新版 EXE 进入同一份 `desktop.py`。直接运行 `python tool/launcher.py` 或启动 `MetaAWD-v3.5.exe` 会进入旧版 Tkinter。共享防御逻辑在 `tool/defence/`，改共享函数签名或文件格式时要查两套界面的调用。[启动脚本](../tool/start.bat) · [旧版打包说明](../tool/README.md#发布构建)

### 页面和模块索引

| 侧栏页面 | React 入口 | Python 或共享模块 |
| --- | --- | --- |
| 防御概览 `overview` | [overview.tsx](../tool/desktop_ui/src/pages/overview.tsx) 的 `Overview` | 读取 `snapshot()`，通过 `go(page)` 跳转 |
| SSH 连接 `ssh` | [connection.tsx](../tool/desktop_ui/src/pages/connection.tsx) 的 `ConnectionPage` | `connect` → `_connect()` → [ssh.py](../tool/defence/ssh.py) |
| SSH 交互终端 `terminal` | [terminal.tsx](../tool/desktop_ui/src/pages/terminal.tsx) 的 `TerminalPage` | `terminal-open`、`terminal-send`、`terminal-interrupt`、`terminal-close` → [ssh_terminal.py](../tool/defence/ssh_terminal.py) |
| 文件监控 `monitor` | 同文件的 `MonitorPage` | `start-monitor`、`pause-monitor`、`stop-monitor` → [file_processing.py](../tool/defence/file_processing.py) |
| WebShell 查杀 `scan` | [scanner.tsx](../tool/desktop_ui/src/pages/scanner.tsx) 的 `ScannerPage` | `scan`、`scan_results`、`report`、注释预览与应用 → [webshell_scanner.py](../tool/defence/webshell_scanner.py) |
| WAF 管理 `waf` | [operations.tsx](../tool/desktop_ui/src/pages/operations.tsx) 的 `WafPage` | 部署、模板更新、下线和守护 → [waf_manager.py](../tool/defence/waf_manager.py) 与 [PHP 模板](../tool/defence/phpwaf/) |
| PWN 沙箱防护 `pwn` | [pwn.tsx](../tool/desktop_ui/src/pages/pwn.tsx) 的 `PwnPage` | `pwn_audit`、`pwn_plan`、`export_pwn_policy` → [pwn_protection.py](../tool/defence/pwn_protection.py) |
| PWN 流量转发 `pwnForward` | [pwn-forward.tsx](../tool/desktop_ui/src/pages/pwn-forward.tsx) 的 `PwnForwardPage` | `pwn_forward_plan`、`export_pwn_forward` → [pwn_forward.py](../tool/defence/pwn_forward.py) 与 [pwn_waf 源码资源](../tool/defence/pwn_waf_source/) |
| ELF 加固副本 | [pwn-bundle.tsx](../tool/desktop_ui/src/pages/pwn-bundle.tsx) 的 `PwnBundleTab` | `pwn_bundle_profiles`、`pwn_bundle_preview`、`export_pwn_bundle` → [pwn_bundle.py](../tool/defence/pwn_bundle.py) |
| 请求审查 `packets` | [packets.tsx](../tool/desktop_ui/src/pages/packets.tsx) 的 `PacketsPage` | 请求查询、手动和自动同步 → `waf_manager.py` 与 [request_logs.py](../tool/defence/request_logs.py) |
| 源码备份 `backup` | `operations.tsx` 的 `BackupPage` | `backup`、`restore` → `file_processing.py` |
| 系统日志 `activity` | [main.tsx](../tool/desktop_ui/src/main.tsx) 中的 `LogPanel` | `DesktopService._log()` → `snapshot().events` |
| Bugku 批量提交 `bugku` | [bugku.tsx](../tool/desktop_ui/src/pages/bugku.tsx) 的 `BugkuPage` | `bugku-submit`、`bugku-stop`、`bugku_preview`、`export_bugku` → [bugku_submit.py](../tool/defence/bugku_submit.py) |
| 目标探活 `probe` | [attacker.tsx](../tool/desktop_ui/src/pages/attacker.tsx) 的 `TargetProbePage` | `attack-scan`、`attack-read` → [attacker_tools.py](../tool/defence/attacker_tools.py)；目标列表走 `attack_urls` |
| 攻击辅助 `attacker` | [attacker.tsx](../tool/desktop_ui/src/pages/attacker.tsx) 的 `AttackerPage` | `attack-check`、`attack-exec`、`attack-upload` → [attacker_tools.py](../tool/defence/attacker_tools.py)；后门配置存 `tmp/attacker/attacker_shells.json` |

`workspace.tsx` 提供 `useWorkspace()` 和页面通用布局。业务页面放在 `src/pages/`，复用 `PageHeading`、`Panel`、`Field`、`Empty`、`Confirm`，以及 `components/ui/` 里的官方 shadcn/ui 组件。`@/` 导入指向 `src/`。沿用官方 Zinc 主题、默认浅色、内置组件变体和 Lucide 图标。界面协调主要靠间距、对齐和组件尺寸。Windows 顶部的空白拖动区与窗口按钮由 `main.tsx` 渲染，原生窗口样式由 `desktop.py` 调整。[页面共用布局](../tool/desktop_ui/src/components/workspace.tsx) · [官方组件](../tool/desktop_ui/src/components/ui/) · [主题入口](../tool/desktop_ui/src/styles.css)

### 读写接口和状态约定

| 调用场景 | 前端怎么接 | Python 怎么接 |
| --- | --- | --- |
| 刷新全局小状态 | `useWorkspace()` 读取 `Snapshot` | `DesktopService.snapshot()` 生成业务状态，宿主补充 `window` |
| 查询列表、分页或详情 | `callDesktop("list_packets")`、`callDesktop("read_packet", name)`、`callDesktop("scan_results", offset)` | 在 `desktop.py` 的 `methods` 表里查对应函数 |
| 提交操作 | `workspace.run("动作名", data)` | `DesktopService.action()` 校验并分发到指定处理函数 |
| 打开系统对话框 | `workspace.pick()` 或 `callDesktop("export_packet", name)` | 在宿主用 pywebview 打开对话框，取消选取返回 `null` |

`desktop.ts` 的 `Calls` 约定每个桥接方法的参数元组和返回类型。`callDesktop()` 把它们交给 `window.pywebview.api.invoke`。`desktop.py` 比对当前页面与工作台页面的协议、服务器和路径，再查方法表。数据沿现有的对象或数组传递，时间戳统一按 Unix 秒处理。TypeScript 类型用于前端检查，参数是否可接受由 Python 决定。

`workspace.run()` 会显示提交时的 `pending`，并在受理后读一次快照。`{ ok: true }` 表示操作已受理。后台完成后看业务状态和日志，`job` 表示在运行的共享作业，`jobVersion` 在 `_start_job()` 的作业退出时增加。空闲时前端约每 1 秒读一次快照，运行任务或监控时约每 450 毫秒一次。请求详情和扫描结果走各自的查询接口，避免进入每次轮询。系统日志保留最近 160 条，可按 `Area` 分类。

### 后台任务的边界

- `DesktopService.action()` 使用 `RLock` 保护状态转换。耗时的 SSH/SFTP、磁盘处理和扫描沿用 `_start_job(name, area, task, remote=...)`，该函数先检查空闲状态，远程任务还检查连接。工作线程结束时在 `finally` 恢复 `job`。
- 文件监控、WAF 守护和请求自动同步有各自的停止事件。退出窗口会发出停止信号，已经启动的文件类作业使用非守护线程走完本轮写入和清理。切换 SSH 前，现有连接操作要求文件监控和 WAF 守护已停。
- 对站点或本地文件有写入或删除的操作，参考现有的 `Confirm` 和 `_require_confirmation()` 配合。远端路径用 `_remote_directory()` 校验为非根的绝对目录，SFTP 客户端和文件句柄沿用对应函数的关闭逻辑。
- SSH 密码供 `state_manager` 在本进程使用。前端连接对象只传 `host`、`port`、`user`，新增状态或日志字段时沿用现有数据范围。[共享状态](../tool/defence/state.py)

## 日常增删改查

### 查 · 从界面定位到方法

先搜界面文字，再搜动作名或接口名。下面的三个搜索分别定位按钮、提交入口和执行函数。

```powershell
rg -n '同步请求|自动同步' tool/desktop_ui/src
rg -n 'set-packet-auto-sync|sync-packets' tool/desktop_ui/src tool/desktop_api.py
rg -n 'def _collect_packets|def sync_remote_logs' tool/desktop_api.py tool/defence/waf_manager.py
```

找到 `run(...)` 时追 `DesktopService.action()`。找到 `callDesktop(...)` 时追 `desktop.py` 的 `methods` 和 `desktop.ts` 的 `Calls`。找到的是状态字段时比较 `snapshot()`、前端类型以及引用该字段的组件。运行中先读相应分类的操作日志，再看后台错误。

### 增 · 新增页面、查询或动作

1. **页面** · 在 `src/pages/` 新建页面或加入现有模块文件，以相邻页面的 `Workspace` 参数和布局为例。独立侧栏页面要改 `overview.tsx` 的 `Page` 类型以及 `main.tsx` 的导入、`groups` 和 `pages`。需要概览捷径时再添加 `go()` 调用。`main.tsx` 保留已访问页面的挂载状态，写轮询或异步查询时考虑隐藏页面和组件卸载时的清理。
2. **业务模块** · 纯业务函数放在 `tool/defence/`。从使用它的 Python 模块显式导入，`defence/__init__.py` 是包入口。原生窗口和文件对话框放在 `desktop.py`，业务校验、任务和状态放在 `desktop_api.py`。需要随 EXE 提供的模板等文件放入 `desktop.spec` 的 `datas`，并通过资源路径读取。
3. **查询** · 小型全局状态加入 `snapshot()` 和 TypeScript 的 `Snapshot`。列表、分页和详情走单独查询，在 `desktop.py` 注册方法，在 `desktop.ts` 的 `Calls` 编写匹配的参数和返回类型。读取特定本地文件时沿用现有文件定位函数。
4. **动作** · 在 `DesktopService.action()` 注册名字和处理函数，用 `workspace.run()` 提交；集中在 Python 校验参数，长任务沿用 `_start_job()`。已有通用 `action` 桥接，新业务动作共用它。增加日志分类时同步维护 `desktop.ts` 的 `Area` 和 `areaLabels`。

### 改 · 同时检查生产者、消费者和默认值

修改界面文案或样式从页面入手。涉及数据时，从产生数据的地方往下追。面板里的默认值可能在前端首次渲染、后端快照、共享配置或远端部署中出现。比如改 WAF 日志默认目录时要核对 `StateManager.remote_waf_log_dir`、`defaultWaf.logDir`、`get_remote_waf_log_dir()` 的回退值，以及已部署站点中的配置。

**示例 · 在请求列表显示已有的正文状态。** 在 `request_logs.py` 的 `summarize_request()` 找到 `body_state → bodyState`。它已经经由 `list_packets()` 到达 TypeScript 的 `Packet`。在 `PacketViewer` 的列表行中用现有 `Badge` 或文本展示，处理 `captured`、`empty`、`unavailable` 和旧日志的 `unknown`。搜索筛选、分页、详情和导出沿用现有行为。若以后新增的是 PHP 才能采集的字段，则按「PHP 5/7/8 模板 → Python 解析与默认值 → TypeScript 类型 → 展示」的顺序改，并用旧日志确认缺失字段的兼容性。

### 删 · 下线页面、操作或字段

1. 先搜索页面键、动作名、字段名和函数名。页面入口可能在 `groups`、`pages`、`Page`、概览捷径或其他页面跳转里。
2. 清理使用入口后再查桥接表、共享实现和仍在使用的状态字段。删除开关类入口时检查后台停止条件、连接切换和关闭窗口路径。
3. 共享函数和持久化字段要查 Tkinter 调用及历史文件读取。已有数据仍需使用时保留读取兼容，或者提供明确的数据迁移，之后再移除无调用的实现。
4. 清理文档里的页面说明和跳转链接，运行对应的前端构建或离线测试。处理下线功能时复查工作台是否还会产生原来的作业或提示。

## 请求审查的数据流

### 从 PHP 日志到页面和提示

1. **记录** · PHP 5/7/8 模板把到达 PHP 的 HTTP 请求内容写入 `.http`。默认记录 WAF 命中，部署时可启用「记录全部请求」。默认远端目录是 `/tmp/.phpwaf_logs`，模板先写临时文件再重命名。静态资源和 PHP 之前已被处理的请求查 Web 服务器日志。PHP 未提供某些 multipart 请求的原始正文时，WAF 将正文状态标为不可用。
2. **下载** · 手动 `sync-packets` 和自动同步共用 `_collect_packets()` → `waf_manager.sync_remote_logs()`。SFTP 先下载到本地 `.part`，完整落盘后才尝试清理远端文件。关掉自动同步时，已经开始的文件下载会安全收尾，后续文件留在远端。
3. **调度** · `set-packet-auto-sync` 需要已验证的 SSH 连接，开启后空闲时立即检查。后续正常间隔 5 秒，发生同步异常时 15 秒重试，有共享作业要等其完成。`PACKET_SYNC_INTERVAL` 和 `PACKET_RETRY_INTERVAL` 在 `desktop_api.py`，界面从 `packetSync` 获取。关闭开关、换到另一已验证连接、关闭窗口都会停止自动同步。WAF 守护有自己的开关。
4. **列表** · `list_packets()` 按当前主机读取本地 `.http`，用文件状态标识缓存请求摘要；按请求时间排序，无请求时间的文件回退到文件修改时间。`packetSync.revision` 变化会触发列表重读。「刷新本地」直接重读磁盘。`PacketsPage` 按连接对象标识重置内部选择和过滤状态。
5. **提示** · 仅把首次落盘且判定是 `matched`、`redirected` 或 `terminated` 的文件计入新命中，重试同步同名本地文件不会重复计数。`main.tsx` 用 `unreadHits` 显示提示，「查看命中」打开命中筛选。`ack-packet-hits` 用 `hitCursor` 确认当前已看到的一批，确认期间新增的命中仍会提示。
6. **详情** · `read_packet` 通过 `packet_path()` 把文件限定在当前主机日志目录。详情预览读取前 64 KiB，原文、请求头和正文由页面按 HTTP 分隔符显示。「保存 HTTP 原文」导出剥离元数据行后的完整采集字节。「清空本地」经确认后清理当前主机在本地的 `.http`，并更新列表和提示状态。

### 格式和数据路径

新版日志首行是 `# MetaAWD-HTTP/1 <JSON>`。下一行开始为 PHP 可见内容重建的 HTTP 请求。直接以 HTTP 请求行开头的旧版文件仍会显示原文，缺少 WAF 判定时显示「无判定信息」。

手测可把下列虚构样例用 UTF-8 无 BOM 保存为 `handoff.http`。在隔离的源码副本里放到 `tool/tmp/default/waf_logs/`，单独测试 EXE 时放到其旁边的 `tmp/default/waf_logs/`。离线打开「请求审查」，点击「刷新本地」即可核对列表、详情和导出。

```http
# MetaAWD-HTTP/1 {"captured_at":1762000700,"peer_ip":"2001:db8::1","decision":"observed","matched_areas":[],"body_state":"empty"}
GET /health HTTP/1.1
Host: local.test

```

| 文件 | 源码运行时的位置 |
| --- | --- |
| 同步的请求 | `tool/tmp/<主机>/waf_logs/*.http`，未连接时为 `tool/tmp/default/waf_logs/` |
| 更新 WAF 模板前保存的副本 | 对应主机的 `waf_logs/templates/` |
| 默认查杀报告 | `tool/tmp/<主机>/webshell_report_*.txt` |
| 站点备份 | 「源码备份」里选择的本地目录，Windows 初始目录是用户目录 |

磁盘上的主机目录用主机名生成，连接身份由 `host`、`port`、`user` 共同判断。切换连接会重置同步状态和命中提示。同一主机名的不同连接共用磁盘日志目录。若改存储分组，需要兼顾现有日志位置和旧读者。

`get_runtime_dir()` 定位可写数据。EXE 运行时把 `tmp/` 放在可执行文件旁。PyInstaller 解包目录用于读取构建资源和模板。新增运行数据沿用 `get_runtime_dir()`，新增测试用例使用临时目录和虚构文件。[路径模块](../tool/defence/_bootstrap.py) · [运行数据忽略规则](../.gitignore)

## 后台模块维护

| 要改的能力 | 实现与需要一起核对的行为 |
| --- | --- |
| SSH/SFTP | `ssh.py` 提供 `ssh_test()`、`connect_ssh_client()` 和 `connect_sftp_client()`。改连接参数时检查连接页、`_connect()` 和已验证连接的切换行为。远端调用需能归还客户端与文件句柄。 |
| 文件监控 | `file_processing.monitor_directory_changes()` 用 MD5 建立基线。桌面端传 `is_delete=False`，用于记录变化。保留开始、暂停、继续、停止和异常退出时的状态变化。 |
| 备份和恢复 | `file_processing.tar()`、`deploy_tar()` 共用远端路径处理。变更目录或归档处理时验证下载目标、恢复路径、失败回滚和临时产物清理。 |
| WebShell 查杀 | `webshell_scanner.py` 的 `TYPE_RULES` 组织文件类型规则，`COMBO_RULES` 是组合规则，`analyze_bytes()` 负责分析。看 `DEFAULT_THRESHOLD` 与 `SUSPECT_RATIO` 如何进入 `scanDefaults`，报告使用实际扫描阈值。新增规则和调整权重时用正常文件与本地防御测试样本确认分数和误报。 |
| 注释危险代码 | 先用 `build_quarantine_plan()` 生成预览，再经确认用 `apply_quarantine()` 处理。桌面端验证恶意等级、`scanId` 和远端扫描对应的连接。改这条链路时核对未确认、结果已过期、备份和失败路径。 |
| 自动删除恶意文件 | 扫描设置默认关闭此开关，开启后每次扫描都要确认。`scan_removal.py` 仅处理本次判定恶意的普通文件，核对扫描范围、复核内容并完整备份后才从原路径移除。原路径、服务器和备份文件名记录在 `tmp/scan-quarantine/` 下对应批次的 `restore.jsonl` 中。 |
| WAF 部署和采集 | `waf_manager.py` 按远端 PHP 主版本选择模板。部署时写入站点的加载配置，更新日志模板走 `upload_waf(update_only=True)`，先将现有模板备份在本地，再替换远端文件。改三个 PHP 模板的共同行为时检查 PHP 5/7/8。改变部署配置需核对站点当前的加载配置。更新模板影响后续产生的日志。 |

## 终端与平台提交

侧栏在 `main.tsx` 里按「工作台」「服务器管理」「站点防御」「站点攻击」「平台工具」分组。防御概览和 SSH 连接在「工作台」，系统日志在「站点防御」。交互终端、文件监控与源码备份在「服务器管理」，Bugku 批量提交在「平台工具」。目标探活和攻击辅助在「站点攻击」，两者共用 `snapshot().attacker` 的存活目标与后门记录。

- **SSH 终端** · SSH 验证时记录服务器公钥，`SshTerminal` 用该公钥校验后续的终端连接。会话保持一个 PTY，人工触发的发送和中断进入该会话的短队列。用 `snapshot().terminal` 跟踪阶段和输出版本，打开终端页时用 `terminal_output` 读取最近的文本输出。切换已验证连接或关闭应用时停止会话。终端输出与输入保存在当前进程中。
- **Bugku** · 列表支持粘贴或从本机选择 UTF-8 TXT。`bugku_preview` 和实际提交共用参数校验，预览返回有效条数、重复数和空行数，实际批次向固定的 Bugku HTTPS 计分地址顺序提交。提交间隔为 250–10000 毫秒，连接和读取超时各为 1–60 秒，单批上限为 1–256 条。重复项可以跳过或使校验失败。
- **Bugku 结果** · `bugku_results` 按原输入行号返回状态和说明。`export_bugku` 通过原生文件对话框保存这些字段为 CSV。超时、限流或无法判读的回复按待确认处理。停止后续提交时，已发出的请求仍可能完成。Token 和原始 flag 仅用于当前提交，导出和操作日志仅记录结果。
- **目标探活与攻击辅助** · `attack-scan` 按 URL 模板的 `?` 占位符并发探活，结果覆盖写入存活文件；`attack-read` 读入已有列表，忽略空行和 `#` 注释并去重。`attack-check` 在存活站点上按路径检测已知后门，`attack-exec` 通过所选记录批量提交命令，`attack-upload` 经确认后由所选后门写入新的随机 PHP 后门，可随机生成 key、key 值和命令参数。后门记录写在 `tmp/attacker/attacker_shells.json`，重新打开工作台会继续加载。站点列表用 `attack_urls` 单独查询，避免进入每次轮询的快照。
- **后台任务** · 终端会话与计分批次分别维护状态和停止事件。两者不占用 WAF、备份和请求同步使用的共享 `job`。改这两条链路时检查窗口关闭、连接切换和重复点击的行为。

## ELF 加固副本怎么维护

`pwn_bundle.py` 校验可执行 ELF 的架构、大小及哈希，导出 `run-hardened`、原字节副本 `program.elf` 和 `policy.json`。Go 启动器先比对哈希，再设置 `no_new_privs` 和 seccomp，最后启动同目录程序。运行环境为支持 seccomp BPF 且已挂载 `/proc` 的 Linux x86-64，动态链接程序继续使用部署主机上的加载器和依赖。将成套文件放在服务帐号不可写的目录，在目标 Linux 上进行服务回归。限制按界面列出的系统调用执行。[Linux seccomp 说明](https://docs.kernel.org/userspace-api/seccomp_filter.html)

防护组在 `profiles.json`，Python 展示同一份配置，Go 在构建时将它编入启动器。改动分组后重新运行 `tool/defence/elf_runner/build.ps1`，并用构建产物重新打包。Windows EXE 包含已构建的 Linux 启动器。[启动器源码](../tool/defence/elf_runner/main_linux_amd64.go) · [分组配置](../tool/defence/elf_runner/profiles.json)

兼容预设在 `pwn_bundle.py` 的 `PRESETS`，按组 ID 组合，界面从 `pwn_bundle_profiles` 读取。预设和手动选择共用同一套预览、导出及运行时规则。修改时保留启动及动态加载所需调用，用测试核对每档引用的规则组和具体系统调用。

## PWN 流量转发怎么维护

`pwn_forward.py` 集中校验前端参数并生成 Makefile、xinetd 配置、部署/回滚脚本和 `policy.json`。公开预览不返回内部规范化配置，导出时再使用同一份校验结果。模式保持 `CATCH`、`I0GAN`、`FORWARD`、`FORWARD_MULTI` 四种；多目标列表只接受 `IPv4:端口`，忽略空行、注释和重复项，最多 256 个。

兼容源码在 `defence/pwn_waf_source/`，保留上游 MIT 授权并随 Windows EXE 打包，运行架构限定为 Linux x86/x86-64。CATCH/I0GAN 从 root 管理的 `ORIGINAL_PATH`（界面的原程序备份路径）启动原程序，日志目录仅保存交互日志与轮询状态。部署脚本保存原程序 UID、GID 和权限，回滚时一并恢复；已有日志和备份目录不会被强制修改权限。同一方向的十六进制日志缓存最多 1 MiB，超出后写截断标记，原始字节继续写入日志。

在 Linux x86-64 的 `tool/` 下运行 `python3 -m unittest -v _test_pwn_forward_linux`，验证四模式零警告构建、启动参数、I0GAN 阻断、单目标半关闭、多目标轮询和日志缓存上限。以 root 运行可额外验证重复部署、备份只读和权限回滚；测试仅使用临时目录与回环服务，不修改 xinetd。实际部署仍需在目标 glibc、服务帐号和 xinetd 环境验证。

## 依赖和构建资源怎么维护

- **Python** · 共享依赖在 [requirements.txt](../tool/requirements.txt)，新版补充依赖在 [desktop-requirements.txt](../tool/desktop-requirements.txt)。ELF 体检使用 pyelftools。更改后用 `start.bat` 选到的解释器验证导入。涉及 pywebview 或 Windows 原生库时，还要检查 EXE 中的依赖和实际窗口加载。
- **前端** · React、Vite、Tailwind 和 Lucide 的依赖由 [package.json](../tool/desktop_ui/package.json) 与 [package-lock.json](../tool/desktop_ui/package-lock.json) 一起管理。新环境用 `npm ci`。同步上游组件时核对现有组件的来源版本、导入路径和授权。[组件来源](../tool/desktop_ui/README.md)
- **生成文件** · 前端 `dist/` 由 Vite 生成，`tool/build/` 和 `tool/dist/` 用于打包。改前端、模板和图标从源码文件入手。页面图标是官方 SVG，Windows 图标用同一 SVG 转制的 ICO，更新时同时检查两处资产。[SVG](../tool/desktop_ui/public/shield-check.svg) · [ICO](../tool/desktop_ui/shield-check.ico)

## 改完怎么验证

按实际改动选检查范围。前端构建执行 TypeScript 检查并生成 `tool/desktop_ui/dist/`。源码自检验证构建入口和 Python 模块导入，桌面窗口的 WebView2 渲染需要单独确认。

```powershell
npm --prefix tool/desktop_ui run build
& '.\tool\start.bat' --check

Push-Location tool
try {
    & '.\.venv\Scripts\python.exe' -m unittest -v _test_request_logs _test_packet_autosync _test_desktop_tools _test_scan_removal _test_pwn_protection _test_pwn_forward _test_desktop_attacker
} finally {
    Pop-Location
}
```

| 改动 | 建议验证 |
| --- | --- |
| 前端布局或路由 | 构建后重开桌面，验证侧栏展开折叠、页面跳转、空状态、错误提示与主题。 |
| 桥接或后台任务 | 在桌面验证有效参数和失败提示，检查 `job` 回到空闲。影响退出或连接切换时逐一验证停止行为。 |
| 请求解析和导出 | [`_test_request_logs.py`](../tool/_test_request_logs.py) 用临时文件验证旧日志、损坏的元数据、截断和二进制预览、完整字节导出。 |
| 请求轮询和 WAF 提示 | [`_test_packet_autosync.py`](../tool/_test_packet_autosync.py) 使用替身 SFTP 验证等待空闲、停止、命中去重、确认游标及连接失败重试。手测自动同步时用隔离站点或替身 SFTP 数据。 |
| SSH 终端与 Bugku | [`_test_desktop_tools.py`](../tool/_test_desktop_tools.py) 用替身 SSH 和 HTTP 验证终端收发、连接切换、批次去重、停止和错误提示。 |
| 查杀与文件处置 | [`_test_scan_removal.py`](../tool/_test_scan_removal.py) 用临时文件和替身 SFTP 验证确认、复核、备份、移除及报告状态，用桌面窗口检查阈值说明和处置按钮。 |
| PWN 沙箱防护 | [`_test_pwn_protection.py`](../tool/_test_pwn_protection.py) 验证合成 ELF 解析、路径校验、互斥设置以及导出与预览一致。部署前在目标版本的 systemd 中用 `systemd-analyze verify` 检查完整服务单元，并运行服务回归。 |
| PWN 流量转发 | [`_test_pwn_forward.py`](../tool/_test_pwn_forward.py) 验证参数、目标去重和导出；[`_test_pwn_forward_linux.py`](../tool/_test_pwn_forward_linux.py) 在 Linux x86-64 实测四模式、半关闭、轮询、日志上限和部署/回滚。 |
| 目标探活与攻击辅助 | [`_test_desktop_attacker.py`](../tool/_test_desktop_attacker.py) 用临时目标文件和替身后门检测、执行、上传函数验证读入、后门编号、key 传递、确认门槛、配置落盘及 `attack_urls` 查询。手测时用隔离站点确认写入路径与 Web 访问目录一致。 |
| PHP 注入或模板 | [`_verify_waf.py`](../tool/_verify_waf.py) 提供本地注入与剥离的往返样例。模板修改用对应 PHP 主版本的 `php -l` 检查。涉及真实写入行为时使用专门的测试站点。 |
| EXE 或原生窗口 | 见[新版 EXE 构建与验收](#构建新版-windows-exe)。 |

## 常见故障从哪里查

| 表现 | 排查入口 |
| --- | --- |
| 打开的是旧版窗口，或侧栏找不到终端和 Bugku | 使用 `tool/start.bat` 或项目首页链接的当前发布包。根目录下的源码启动命令为 `python tool/launcher.py desktop`。[当前发布包](../releases/MetaAWD-Desktop-20261119-162436.exe) |
| 提示前端未构建，或者修改后还是旧界面 | 重建前端、核对 `dist/index.html` 并重开窗口。用 EXE 时重新打包，EXE 自带构建时的前端。 |
| Python 依赖缺失 | 看启动日志打印的 Python 路径，用同一个解释器安装 `tool/desktop-requirements.txt`。 |
| 浏览器显示运行服务未连接 | 浏览器预览用于检查界面。桥接调试从 `tool/start.bat` 启动。自检成功而原生窗口打不开时，检查 Windows WebView2 Runtime 和源码入口的控制台输出。 |
| 自动同步开着但没有更新 | 查 SSH 连接、远端日志路径、站点采集设置和系统日志。已有长任务时等到空闲。显示重试提示时检查 SFTP 连接和目录访问。 |
| 本地有 `.http` 但列表没显示 | 核对当前主机的目录、扩展名、页面搜索和判定筛选，点击「刷新本地」。旧 EXE 和源码的 `tmp/` 随各自程序目录定位。 |
| 预览不全或正文为空 | 看截断和正文状态，点击「保存 HTTP 原文」检查完整采集内容。若 PHP 没有提供正文，从对应 Web 服务器日志或应用日志排查。 |

## 构建新版 Windows EXE

先完成源码依赖安装，使用 Windows x64 Python 构建单文件 EXE。ELF 加固功能随包提供 Linux 启动器，由 Go 交叉编译。项目根目录的命令如下。

```powershell
$desktopPython = '.\tool\.venv\Scripts\python.exe'
& $desktopPython -m pip install pyinstaller==6.22.3
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller 安装失败' }
& '.\tool\defence\elf_runner\build.ps1'
npm --prefix tool/desktop_ui run build
if ($LASTEXITCODE -ne 0) { throw '前端构建失败' }
& $desktopPython -m PyInstaller tool/desktop.spec --noconfirm --distpath tool/dist --workpath tool/build/desktop
if ($LASTEXITCODE -ne 0) { throw 'EXE 打包失败' }
```

1. 产物是 `tool/dist/MetaAWD-Desktop.exe`。可从 PowerShell 用 `Start-Process -FilePath '.\tool\dist\MetaAWD-Desktop.exe' -ArgumentList '--check' -WindowStyle Hidden -Wait -PassThru` 查看进程的 `ExitCode`，应为 0。
2. 双击验证实际窗口加载、侧栏导航和请求审查页面。在测试目录验证时，运行数据在测试 EXE 同级 `tmp/`。
3. 将验收后的 EXE 复制到 `releases/`。如果当前发行包正在运行，使用带日期的文件名保存新版。同步更新项目首页的发布链接，保留可回用的发行文件方便回退。
4. 交付或修改发布内容时，记录最终产物路径和实际通过的检查。发布前可在干净的源码副本运行 `python scripts/pre_release_audit.py`。

`desktop.spec` 以 `desktop.py` 为入口，收录前端构建、PHP 模板、PWN 流量转发源码和 pywebview 相关资源，并嵌入由官方 Shield Check SVG 转成的多尺寸 ICO。`tool/build.spec` 与 `tool/build_release.py` 用于旧版 Tkinter EXE。更新导航、按钮名或依赖时同步核对首页快速开始和本手册。修改打包资源路径时核对源码与 EXE 两种方式。[新版打包配置](../tool/desktop.spec) · [当前发布包](../releases/MetaAWD-Desktop-20261119-162436.exe) · [图标来源](../tool/desktop_ui/README.md)
