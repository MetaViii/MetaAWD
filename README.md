# AWD Defence Tool

面向 AWD / CTF 攻防对抗场景的辅助工具集，包含两部分：

| 目录 | 内容 |
|---|---|
| [`tool/`](tool/) | **AWD Defence Tool v3.1** —— 图形化攻防辅助工具（含一键木马查杀引擎） |
| [`dshield-reverse/`](dshield-reverse/) | **D盾 2.1.8.1 木马检测引擎逆向分析** —— 规则库格式、检测算法与复现工具 |
| [`releases/`](releases/) | 打包好的独立可执行文件 |

> 仅供授权的 CTF / AWD 比赛与安全研究使用。

---

## tool/ — AWD Defence Tool v3.1

图形界面版（无命令行模式），功能：

- **文件监控** —— 基于 MD5 基线对比，检测新增/更改文件，支持自动删除
- **一键木马查杀** —— 检测引擎逆向自 D盾，683 条规则 + 26 条组合规则
  （PHP / ASP / ASPX / JSP，含 `.htaccess` 配置后门与图片马）
- **源码打包下载 / 一键部署** —— tar 打包拉回本地，支持带自动回滚的恢复
- **WAF 部署** —— 内置 PHP5/7/8 三套 WAF 模板，一键注入/下线
- **数据包审查** —— 拉取 WAF 记录的请求包，查看对手原始攻击流量
- **攻击辅助** —— 批量探活、已知后门检测、命令执行、生成上传后门
- **Bugku PVP** —— 批量读取并提交 flag
- SSH 交互终端、系统状态、WAF 日志同步

### 快速开始

**方式一：独立 exe**（推荐，目标机无需 Python）

下载 [`releases/AWD-Defence-Tool-v3.1.exe`](releases/)，双击运行。
数据目录 `tmp/` 会生成在 exe 同级目录。

> 未做数字签名，PyInstaller 产物易被杀软误报，建议先将目录加入白名单。

**方式二：源码运行**

```bash
python -m pip install -r tool/requirements.txt
cd tool
python launcher.py          # 自检依赖并启动界面
python launcher.py check    # 仅环境自检
```

或直接双击 `tool/start.bat`。

### 重新打包 exe

```bash
python -m pip install pyinstaller
cd tool
python -m PyInstaller build.spec --noconfirm --clean
# 产物: dist/AWD-Defence-Tool-v3.1.exe
```

### Bugku 提交凭据

token 与域名不再硬编码，通过环境变量提供：

```bash
set AWD_BUGKU_TOKEN=你的token        # Windows
export AWD_BUGKU_TOKEN=你的token     # Linux/macOS
```

未设置时使用占位符，功能不可用但不会报错。

### 已知限制

- 仅支持 64 位 Windows（exe）；源码方式跨平台
- 远端功能需目标机提供 SSH 服务
- WAF 注入会改写业务 PHP 文件，操作前请先打包备份

详见 [`tool/README.md`](tool/README.md) 与 [`tool/FIXES.md`](tool/FIXES.md)。

---

## dshield-reverse/ — D盾检测引擎逆向分析

对 D盾 2.1.8.1 木马查杀功能的完整逆向，产出：

- **`逆向分析报告.md`** —— 模块架构、`ws_lib.db` 容器格式、
  50 字节记录布局、114 项规则清单、检测算法反汇编还原
- **`rules/D盾规则名清单.txt`** —— 从 RTTI 提取的规则命名体系
- **`tools/`** —— 24 个分析脚本（PE 侦察、zlib 解包、Delphi VMT 解析、
  反汇编与交叉引用查询、规则提取等）

### 核心结论

检测引擎位于 `d_manage.dll`（非 `web_safe.dll`）。算法可归纳为：
按脚本类型分流 → 取每条规则 `|` 切分的候选特征串 → 做**带词边界的子串匹配**
→ 命中即 `level=3`，未命中走**手写词法扫描器**做关键字识别 → 输出 0/2/3 等级。

两个容易被误解的点：**正则不用于匹配**（正则串只作为被检测的样本特征出现）；
**不做熵计算**（用非 ANSI 字符比例代替）。

> 本目录**不包含** D盾 的原始二进制、解压后的规则库或其规则文本内容，
> 仅包含自行撰写的分析报告与分析工具。

---

## 环境要求

- Python 3.9+（源码运行）
- 依赖见 [`tool/requirements.txt`](tool/requirements.txt)：
  `paramiko`、`termcolor`、`ttkbootstrap`

## 免责声明

本项目仅用于授权的安全测试与 CTF/AWD 比赛。使用者需自行确保对目标系统
拥有合法授权。作者不对任何未授权使用承担责任。
