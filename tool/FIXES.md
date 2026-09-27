# AWD Defence Tool v3.x 修复与变更记录

本文档记录 v3.0 的 48 项缺陷修复，以及 v3.1 的架构变更（移除 CLI、支持打包 exe）。

---

# 第一部分：v3.1 变更

v3.1 在 v3.0（完整的缺陷修复版）基础上，移除命令行模式并支持打包为独立 exe。

## 一、移除命令行模式

删除以下文件（GUI 不依赖它们，删除后无残留引用）：

| 文件 | 说明 |
|---|---|
| `main.py` | CLI 入口 |
| `start_cli.bat` | CLI 启动器 |
| `defence/task.py` | CLI 命令分发 |
| `defence/menu.py` | CLI 菜单 |

`defence/__init__.py` 在源码模式下按目录自动发现模块，删除后不会再导入它们。

`Attacker.py` 与 `bugku_pvp_backdoor_submit.py` **保留** —— 它们是独立脚本，
不依赖 `defence` 包，可单独使用。

## 二、打包为独立 exe

新增 `build.spec`，构建：

```bash
python -m pip install pyinstaller
python -m PyInstaller build.spec --noconfirm --clean
# 产物: dist/AWD-Defence-Tool-v3.1.exe （单文件，约 20 MB）
```
目标机无需安装 Python 与任何依赖，双击即用。

### 打包遇到的两个问题及处理

**问题 1：`defence/__init__.py` 靠扫目录发现子模块，打包后失效**

源码模式下它用 `os.listdir` 自动加载同目录所有 `.py`；打包后代码在 PYZ 归档里，
没有真实目录可扫，会导致子模块全部加载不到（import 静默失败）。

处理：新增 `defence/_bootstrap.py`，其中 `is_frozen()` 判断运行环境；
`__init__.py` 在冻结环境下改用**固定清单**导入，并配合 spec 的 `hiddenimports`
（PyInstaller 只能静态分析到显式导入）。

**问题 2：`__file__` 指向临时目录，用户数据会丢**

打包后 `__file__` 位于 `_MEIPASS`（每次启动重建的临时目录），
若把 `tmp/`（源码包、WAF 日志、查杀报告）写在那里，程序退出即丢失。

处理：`_bootstrap.py` 区分两个概念并统一出口——
`get_resource_dir()`（只读资源，指向 `_MEIPASS`，用于取 phpwaf 模板）
与 `get_runtime_dir()`（可写数据，指向 **exe 同级目录**，用于 `tmp/`）。
`waf_manager`、`file_processing`、`webshell_scanner` 的路径函数已全部改用它们。

### 打包完整性验证

用 `--console` 单独构建了一个自检程序并在冻结环境下运行，**19 项全部通过**：

- 7 个子模块均能导入（hiddenimports 生效）
- `is_frozen()` 为 True，`app_dir` 正确指向 exe 目录，`resource_dir` 指向 `_MEIPASS`
- 运行目录可写且位于 exe 同级
- 3 个 phpwaf 模板均可读取（datas 生效，php5/7/8 分别 10984/12426/12426 字节）
- 查杀规则加载 683 条，判定功能正常（`eval($_POST)` 样本 level=3）
- tkinter / ttkbootstrap / gui_main 均可用

另外实测发布 exe 双击启动，**2 秒**内出现界面（窗口标题 `AWD Tool v3.1`）。

---

---

# 第二部分：v3.0 缺陷修复（48 项）

对 v3 代码做了全面检查（静态分析 + 三个独立审查视角 + 实测复现），
逐项修复并验证。以下按影响程度排列。

## 一、数据安全（会破坏线上站点的，最高优先级）

### 1. 空基线导致全量误删站点文件 ★最严重

`defence/file_processing.py` — `batch_get_md5` / `monitor_directory_changes`

**原行为**：`find|md5sum` 命令失败与"目录确实为空"返回同一个空 dict
（`2>/dev/null` 吞掉 stderr，告警判断永不触发）；首检无条件把空结果当成基线并推进计数。
下一轮每个现存文件都命中"不在基线里"→ 判为新增 → 自动删除模式下 `rm -f` 清空整站。

**触发**：目录被删、路径拼错、`find`/`md5sum` 缺失、权限不足、命令超时。

**修复**：
- 采集时用 `find|wc -l` 计数与 md5sum 结果数交叉校验，不一致即抛异常中止本轮
- 命令未返回计数标记（被中断）同样抛异常
- 新增**删除比例守卫**：单轮待删数超过 `max(20, 基线×50%)` 时放弃删除并告警
- 删除后同步 `md5_dict`（否则同名马重传因 MD5 相同被判"未变化"而漏报）

### 2. 部署备份失败仍清空源码

`defence/file_processing.py` — `deploy_tar`

**原行为**：备份命令以 `;` 结尾，失败被吞且不阻断，照样执行 `find -delete`；
主解压再失败时回滚包不存在，源码全丢，却只提示"部署失败"。

**修复**：`&&` 串联 + `test -s` 校验 + `AWD_BACKUP_OK` 标记；
未见到该标记直接终止，**线上目录不做任何改动**。

### 3. 部署解压层级错位（站点 404 却报成功）

`defence/file_processing.py` — `deploy_tar`

**原行为**：`tar()` 打的包顶层是 `basename`（`html/…`），
部署却解到目录自身 → 落成 `/var/www/html/html/…`，网站根目录只剩空壳，
tar 返回 0 于是打印"✓ 部署完成"。同函数的回滚却按"包内带顶层目录"处理，两套假设自相矛盾。

**修复**：先 `tar -tzf | head` 探测包内首层，与 `basename` 比对后自适应选择解压目标。

### 4. WAF 注入剥离会写坏 HTML 模板

`defence/waf_manager.py` — `normalize_injected_content` / `remove_waf_include_content`

**原行为**：剥离后若内容不以 `<?` 开头且含 `?>`，会补回 `<?php ` 前缀。
实测 `"<html>…<?php echo $x; ?>…"` 会变成 `<?php <html>…` —— 非法 PHP，页面 500。

**修复**：删除该猜测性分支，改为**标记即真相**：注入块写入
`/* PHPWAF-INCLUDE-START */ … /* PHPWAF-INCLUDE-END */`（标记在 `<?php ?>` 内部，
不会输出到页面），剥离时只精确匹配标记块；仅兼容"文件头逐字等于旧 snippet"一种情形。

### 5. 正则跨行剥离吞掉用户代码

同上文件。

**原行为**：`^<\?php.*?require_once 'waf路径'.*?\?>` 从文件头删到 require 后第一个 `?>`。
实测会删掉 `session_start()`、PDO 初始化等位于注入行之前的正常代码。

**修复**：同第 4 项的标记方案，绝不跨用户代码模糊匹配。

### 6. WAF 下线失败导致全站 Fatal error

`defence/waf_manager.py` — `undeploy_waf`

**原行为**：`remove_result["failed"]` 从未被消费，无论是否清理成功都删除 `waf.php`。
残留文件的 `require_once` 指向已删除文件 → 全站 `Fatal error`，
而状态显示"未安装"、防护线程已停。

**修复**：只要有任一文件未剥离成功，**保留** `waf.php` 并维持 `waf_deployed=True`；
返回 `ok` 标志供 GUI 判断；删除前先把文件降级为无害存根。

### 7. 远端改写无备份、无原子性

`defence/waf_manager.py` — `write_remote_text_file`

**原行为**：`sftp.open(path,"wb")` 打开即截断，中途断开就留下被截断的源码。

**修复**：先备份为 `.phpwaf.bak`（备份失败即中止改写），
再写 `.phpwaf.tmp` 后 `rename` 覆盖。

---

## 二、功能正确性

### 8. CLI 非法输入导致整个程序退出

`defence/task.py` / `defence/menu.py`

**原行为**：`threads = int(input(...))` 无保护，`bugku_menu` 无 try，
主循环只捕 `(KeyboardInterrupt, EOFError, SystemExit)`。
线程数填非数字、范围写 `1-abc` → ValueError 穿透三层 → **进程退出**。

**修复**：新增 `_ask_int` 健壮输入；`bugku_menu` 整体 try；
主循环加 `except Exception` 兜底并 `continue`；命令输入统一 `strip()`。

### 9. Bugku URL 用 `repr()` 生成 PHP 字面量

`defence/attacker_tools.py` — `make_bugku_backdoor_url`

**原行为**：`"system(%r);" % cmd`。命令含 `\` 或 `$` 时 repr 会选双引号包裹，
PHP 双引号里 `\\` 变 `\`、`$U` 被**变量插值**，实际执行的不是原命令。

**修复**：改用已有的 `make_php_system_command`（走 `php_quote` 单引号转义）。

### 10. 伪静态站点被误判为"存在后门"

`defence/attacker_tools.py` — `check_known_backdoor`

**原行为**：仅 `status == 200` 即登记为后门。SPA/伪静态把 404 返回 200 整页 HTML，
于是一堆无关页面被当成后门，后续命令全打到错误目标。

**修复**：限定 `status == 200` 且响应体不含 `<!doctype` / `<html`。

### 11. 探活漏报 3xx 站点

`defence/attacker_tools.py` — `scan_alive`

**原行为**：`status == 200` 才算存活，301/302/403 全部漏报。

**修复**：改用 `HttpResult.ok`（200-399）。

### 12. 停止按钮失效

`defence/attacker_tools.py` — `bugku_batch_submit`

**原行为**：`with ThreadPoolExecutor(...)` 退出时 `shutdown(wait=True)`，
必须等所有已排队任务跑完，`cancel()` 对运行中任务无效 → 点停止后仍卡数十秒。

**修复**：手动管理 executor，停止时 `shutdown(wait=False, cancel_futures=True)`。

### 13. worker 异常中断整批

`defence/attacker_tools.py`

**原行为**：`future.result()` 无 try；`http_request` 未捕 `ValueError`（含 `InvalidURL`）、
`except HTTPError` 内的 `exc.read()` 也无保护 → 单点异常逃出 `as_completed` 中断整批。

**修复**：`future.result()` 逐个 try；补捕 `ValueError`；保护错误响应体读取；
解码从 `"ignore"` 改为 `"replace"` 以便留痕。

### 14. 监控断线后永不重建

`defence/file_processing.py`

**原行为**：异常后 `continue` 但从不重建连接，靶机 sshd 被打挂后每秒刷错误、
界面仍显示"运行中"，防守方在无监控状态下裸奔。

**修复**：加连续失败计数，超过 5 次重建连接，成功后重新建立基线。

### 15. 含特殊字符的文件名无法删除

`defence/file_processing.py`

**原行为**：GNU md5sum 对含 `\`/换行/回车的文件名会整行转义，
解析出的路径是转义串 → `rm -f` 找不到真实文件（错误还被吞），日志谎报"已删除"。

**修复**：新增 `_unescape_md5sum_name` 还原真实路径；
日志改为"已提交删除"以免误导。

---

## 三、稳定性与资源

### 16. SSH 连接失败泄漏

`defence/ssh.py` — `connect_ssh_client` / `connect_sftp_client`

**原行为**：`connect()` 失败路径不调用 `close()`，而 Transport 已启动且由后台线程持有强引用，
不会被 GC 回收 → 每次密码错误泄漏一个线程+socket（AWD 中高频）。

**修复**：两处连接函数在异常时先 `close()` 再 `raise`。

### 17. 交互 shell 忙等 100% CPU

`defence/ssh.py` — `shell()`

**原行为**：`recv_ready()` 无数据立即返回 False，循环内无任何阻塞等待 → 单核 100% 自旋；
`chan.closed` 在网络半开时不置位 → 永久自旋；`join()` 无超时；
关闭不在 `finally`，Ctrl+C 逃出即泄漏连接。

**修复**：改用 `select.select` 阻塞等待；退出条件改为 `recv()` 返回空；
增量解码器避免切断多字节字符；线程 daemon；`join(timeout=3)`；关闭移入 `finally`。

### 18. 监控线程异常导致 4 个控件永久锁死

`gui_main.py` — `run_mon`

**原行为**：无 try/finally，控件恢复只在正常返回时执行。
而 `run_ssh_command` 原来的严格 `.decode()` 遇到 GBK 文件名会抛 `UnicodeDecodeError`，
穿透监控的两层窄 except → 按钮永久 DISABLED、`is_running` 不复位。

**修复**：根因侧把解码改为 `errors="replace"`；监控 `except` 加 `Exception` 兜底；
`run_mon` 加 try/except/finally 并在 finally 复位标志与控件。

### 19. 打包按钮永久禁用

`gui_main.py` — `execute_tar`

**原行为**：按钮恢复在调用之后，`file_processing.tar()` 的连接创建在自身 try 之外，
SSH 掉线时 paramiko 异常直接抛出 → 按钮永久 DISABLED。

**修复**：`tar()` 的连接创建移入 try；`execute_tar` 加 try/finally。

### 20. 终端连接失败整屏空白

`gui_main.py` — `log_shell`

**原行为**：bootstrap 期间只认 `#`/`$` 结尾的提示符，连接失败的错误文本被永久丢弃，
`bootstrapping` 也不复位 → 终端空白、无错误提示、无重试入口。

**修复**：加 `Shell Error` 关键字逃逸与 5 秒超时放行。

---

## 四、查杀引擎（v3 新增功能）

### 21. WAF 自身文件被误报为木马

`defence/webshell_scanner.py`

**原行为**：`waf.php` 内含完整黑名单（`system`/`eval`/`assert`…），
扫描业务目录时必然命中大量规则 → 部署 WAF 后每次查杀都报自己的 WAF 是马。

**修复**：新增 `is_excluded_path`，排除 `.phpwaf`、`node_modules`、`vendor`、
`.git` 等目录与 `waf.php`；远端 `find` 层与本地 walk 层双重过滤。

### 22. 图片马漏检 / 正常 htaccess 误报

- 图片扩展名未纳入扫描范围 → 已加入（只读头部 16KB）
- `RewriteEngine`/`RewriteRule` 属正常站点配置却计分 → 已移除，保留真正危险的
  `AddType`/`SetHandler`/`auto_prepend_file` 等

### 23. 文本重复解码导致计数翻倍

**原行为**：UTF-8 与 GBK 各解一次再拼接，ASCII 内容被算两遍，分数虚高。

**修复**：优先 UTF-8，仅在解码失败时才用 GBK 兜底。

---

## 已知未修（评估后认为改动成本高于收益）

| 项 | 说明 |
|---|---|
| 远端命令无超时 | 攻击者放超大文件可让 `md5sum` 长时间读不完。修需改 `run_ssh_command` 签名，影响 7 处调用方 |
| `tar -v` 全量回传 | 数万文件时逐行触发 UI 插入导致卡顿。属性能问题，不影响正确性 |
| 终端逐字符 insert | 实测比批量慢 35-96 倍，大输出迟滞。同上 |
| 全局 `is_running` 结构 | 当前两种用法（CLI 同步、GUI 按钮门控）下不构成并发干扰 |

---

## 五、数据包审查（专项修复）

现象：切到「数据包审查」页永远空白，没有任何返回。

**根因有两个，缺一不可**：

### 24. 同步入口缺失（主因）

`gui_main.py` — `sync_waf_logs` / `create_packet_tab`

请求包只存在于**远端** WAF 日志目录（默认 `/tmp/.phpwaf_logs`），
必须同步到本地才能查看。`sync_waf_logs()` 方法虽然存在，
**却没有绑定到任何按钮** —— 页面上只有"刷新列表"，而它只读本地目录。

唯一的同步触发点是 WAF 自我防护守护线程（每 5 秒一次），
而守护默认不启动 → 用户不点"启动自我防护"就永远拉不到日志。

**修复**：
- 数据包审查页新增「从远端同步」按钮（主入口）
- 新增「清空本地」按钮
- 切换到该页时，若已连接 SSH 则自动同步一次（不弹清空确认）
- 同步期间按钮置灰防重复触发

### 25. WAF 默认只记录被拦截的请求

`defence/phpwaf/waf_php*.php` — `saveRequest` 调用点

```php
if ($suspicious) {                    // 仅命中黑名单才写日志
    saveRequest($originalSnapshot['raw_request']);
```

即**正常请求不记录**。所以即使 WAF 工作正常，没被攻击时列表必然是空的
—— 这点界面上原本没有任何提示。

**修复**：
- 新增 `PHPWAF_LOG_ALL` 开关：置 1 后记录**全部请求**（默认 0，保持原行为）
- WAF 设置页新增「记录全部请求」复选框，带二次确认与磁盘占用提示
- 全量记录模式下加**远端上限**（2000 个包），超出即停止写入，防止刷爆磁盘
- **重要**：`exit`（跳转拦截）条件收紧为 `if ($suspicious && wafGetMode() === 2)`，
  确保全量记录模式下正常请求不会被误拦

### 26. 空列表无任何引导

**修复**：预览区在无数据时显示排查指引，含当前远端日志目录、
WAF 部署状态、SSH 连接状态三个实时字段，便于自查。

### 27. 同步逐条容错

`defence/waf_manager.py` — `sync_remote_logs`

**原行为**：单个文件下载抛错会中断整批同步；且先 `remove` 远端文件，
万一删除失败则下次重复同步。

**修复**：逐条 try，单个失败只跳过并计数；下载成功后才删远端；
远端清理失败仅提示（避免重复同步），不影响已下载内容。

---

## 六、一键启动器

新增 `start.bat`（GUI）/ `start_cli.bat`（CLI）/ `launcher.py`。

自动完成：定位 Python → 校验版本（3.9+）→ 检测缺失依赖并自动安装（默认源失败
自动回退清华镜像）→ 启动程序。出错时暂停留屏，不会一闪而过。

**踩到的坑（值得记录）**：`.bat` 必须保持**纯 ASCII**。

cmd 会按**启动时**的代码页解码整个 bat 文件，`chcp` 只能改变输出、无法补救
已解码的内容。把中文写进 bat，在默认代码页不是 936 的环境下会变成
`锟斤拷`（U+FFFD），甚至被当成命令执行而报一堆语法错误。

因此中文提示全部放在 `launcher.py`，由 Python 处理编码
（并设置了 `errors="replace"` 兜底，编码不匹配时降级显示而非崩溃）。

---

# 第三部分：验证方式

- 静态：`pyflakes` 全项目零告警（已滤除 star-import 噪音）
- 修复验收：`python _verify_final.py` → **48/48 通过**
- PHP 语法：`python _check_php_syntax.py` → 3 个 WAF 文件括号配对 + 关键函数校验通过
- WAF 幂等性：`python _verify_waf.py` → 6 类文件 inject→remove **全部正确还原**
- 端到端：CLI `help/scan/阈值/exit` 全链路、GUI 10 个 Tab 实例化
- 查杀回归：15 个样本（11 恶意 + 4 正常）→ 恶意全检出、正常零误报
- 数据包链路：模拟日志落盘 → 列表读取 → 详情渲染 → 清理，全流程通过
