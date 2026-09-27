"""
WebShell 木马查杀模块
=====================================================================
检测引擎核心三要素：

  1. 按脚本类型分流 (PHP / ASP / ASPX / JSP)，各自独立规则集
  2. 特征串带「词边界」匹配：
     子串命中后检查前一字节字符类别，避免 eval 误命中 reeval
  3. 0/2/3 三级判定：
     score>=阈值 -> level 3 (恶意) / >=45% -> level 2 (可疑) / 否则 0 (干净)

采用加权累加再映射到等级的方式，便于按环境调阈值。

对外接口:
  scan_local(path, ...)                   本地目录/文件扫描
  scan_remote(remote_dir, ...)            SSH 远程扫描(自动拉回可疑文件)
"""

import os
import re
import shlex
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from defence import ssh
from defence._bootstrap import get_runtime_dir
from defence.state import state_manager

try:
    from termcolor import colored
except Exception:                                    # termcolor 缺失时降级
    def colored(text, *a, **k):
        return text


# ==================================================================== 规则表
# 每条规则: (特征串, 权重)。权重按危险程度分级，危险函数链类规则计高分。

PHP_EXEC = [
    ("system", 60), ("exec", 60), ("shell_exec", 70), ("passthru", 65),
    ("proc_open", 70), ("popen", 65), ("pcntl_exec", 70),
]

PHP_EVAL = [
    ("eval(", 80), ("assert(", 70), ("create_function(", 70),
    ("preg_replace(", 45), ("mb_ereg_replace(", 45),
    ("preg_replace_callback(", 40), ("mb_ereg_replace_callback(", 40),
    ("preg_filter(", 40), ("ob_start(", 30),
    ('"eval"', 55), ("'eval'", 55), ('"assert"', 50), ("'assert'", 50),
]

PHP_CALLBACK = [
    ("call_user_func(", 50), ("call_user_func_array(", 50),
    ("array_map(", 40), ("array_walk(", 40), ("array_walk_recursive(", 40),
    ("array_filter(", 35), ("array_reduce(", 35), ("array_udiff(", 35),
    ("array_diff_uassoc(", 35), ("array_diff_ukey(", 35),
    ("uasort(", 35), ("uksort(", 35), ("register_shutdown_function(", 45),
    ("register_tick_function(", 45), ("session_set_save_handler(", 45),
    ("filter_var(", 25), ("filter_var_array(", 25), ("yaml_parse(", 40),
    ("ReflectionFunction(", 55),
]

PHP_OBFUSC = [
    ("base64_decode(", 45), ("str_rot13(", 40), ("gzinflate(", 45),
    ("gzuncompress(", 45), ("gzdecode(", 45), ("strrev(", 25),
    ("chr(", 20), ("urldecode(", 25), ("strtr(", 25), ("pack(", 30),
    ("%7b", 30), ("${", 30), ("$$", 30),
]

PHP_FILE = [
    ("file_put_contents(", 45), ("fwrite(", 35), ("fputs(", 35),
    ("move_uploaded_file(", 40), ("file_get_contents(", 25),
    ("copy(", 20), ("rename(", 20), ("fopen(", 25), ("unlink(", 25),
    ("include(", 30), ("include_once(", 30), ("require(", 30), ("require_once(", 30),
]

PHP_NET = [
    ("fsockopen(", 45), ("socket_create(", 45), ("setsockopt(", 30),
    ("curl_exec(", 30), ("curl_setopt(", 20),
]

PHP_SUPER = [
    ("$_post[", 35), ("$_get[", 30), ("$_request[", 35), ("$_cookie[", 35),
    ("$_server[", 20), ("$_files[", 30), ("$http_post_vars[", 40),
    ("$http_get_vars[", 40), ("php://input", 55), ("php://filter", 45),
    ("phar://", 40), ("data://", 45),
]

PHP_MARKER = [
    ("phpinfo(", 55), ("zend_", 25), ("$i30:", 60), ("::", 45),
    ("getenv(", 25),
]

ASP_ENTRIES = [
    ("eval(", 80), ("execute(", 75), ("executeglobal(", 75),
    ("eval request(", 95), ("eval request", 90), ("eval(request(", 95),
    ("execute request(", 95), ("execute(request(", 95),
    ('createobject("wscript.shell")', 80), ('createobject("adodb.stream")', 75),
    ('server.createobject("scripting.filesystemobject")', 45),
    ('createobject("microsoft.xmlhttp")', 50),
    ("scripting.filesystemobject", 30), ("wscript.shell", 60),
    ("wscript.network", 45), ("shell.application", 55),
]

ASP_OBFUSC = [
    ("vbscript.encode", 80), ("baseaspdecode", 70), ("baseaspencmap", 70),
    ("chr(", 25), ("ascb(", 30), ("midb(", 25), ("strreverse(", 35),
    ("unescape(", 35), ("codepage", 25), ("@codepage", 30), ("charset=utf-7", 70),
]

ASP_EX = [
    ("request(", 25), ("request.form(", 30), ("request.querystring(", 30),
    ("server.mappath(", 30), ("createtextfile(", 40), ("savetofile(", 40),
    ("opentextfile(", 30), ("response.binarywrite", 40),
    (".loadfromfile(", 40), (".executestatement(", 40),
    ("global.asa", 45), ("application_onend", 45),
]

ASPX_ENTRIES = [
    ("eval(", 70), ("execute(", 60), ("assert(", 60), ("httpcontext", 25),
    ("system.diagnostics.process", 85), ("processstartinfo", 80),
    ("assembly.load", 85), ("binaryformatter", 80), ("deserialize", 70),
    ("frombase64string", 70), ("assembly.loadfrom", 85),
    ("compileassemblyfromsource", 80), ("mainmodule", 70),
    ("windowsidentity", 65), ("appdomain", 60), ("type.gettype", 65),
    ("activator.createinstance", 65),
]

JSP_ENTRIES = [
    ("runtime.getruntime().exec", 90), ("processbuilder", 85),
    ("filesystemobject", 60), ("fileoutputstream", 55),
    ("bufferedwriter", 45), ("defineclass", 80), ("classloader", 70),
    ("scriptengine", 70), ("urlclassloader", 75),
]

# .htaccess / httpd 配置后门 —— AWD 中常被用来把图片/文本当 PHP 执行
# 注: RewriteEngine / RewriteRule 是正常站点的常规配置，不计分(避免误报)
HTACCESS_RULES = [
    ("addtype", 90), ("addhandler", 90), ("sethandler", 90),
    ("auto_prepend_file", 100), ("auto_append_file", 100),
    ("php_value", 70), ("php_flag", 70), ("php_admin_value", 80),
    ("application/x-httpd-php", 100), ("options +exec", 60),
]

# 扩展名 -> (语言, 规则组)
TYPE_RULES = {
    "php":  ("PHP",  [PHP_EXEC, PHP_EVAL, PHP_CALLBACK, PHP_OBFUSC, PHP_FILE, PHP_NET, PHP_SUPER, PHP_MARKER]),
    "phtml": ("PHP", [PHP_EVAL, PHP_CALLBACK, PHP_OBFUSC, PHP_FILE, PHP_SUPER]),
    "php3": ("PHP",  [PHP_EVAL, PHP_CALLBACK, PHP_OBFUSC, PHP_FILE, PHP_SUPER]),
    "php4": ("PHP",  [PHP_EVAL, PHP_CALLBACK, PHP_OBFUSC, PHP_FILE, PHP_SUPER]),
    "php5": ("PHP",  [PHP_EVAL, PHP_CALLBACK, PHP_OBFUSC, PHP_FILE, PHP_SUPER]),
    "php7": ("PHP",  [PHP_EVAL, PHP_CALLBACK, PHP_OBFUSC, PHP_FILE, PHP_SUPER]),
    "inc":  ("PHP",  [PHP_EXEC, PHP_EVAL, PHP_CALLBACK, PHP_OBFUSC, PHP_FILE]),
    "asp":  ("ASP",  [ASP_ENTRIES, ASP_OBFUSC, ASP_EX]),
    "asa":  ("ASP",  [ASP_ENTRIES, ASP_OBFUSC]),
    "cer":  ("ASP",  [ASP_ENTRIES, ASP_OBFUSC]),
    "aspx": ("ASPX", [ASPX_ENTRIES]),
    "ashx": ("ASPX", [ASPX_ENTRIES]),
    "asmx": ("ASPX", [ASPX_ENTRIES]),
    "jsp":  ("JSP",  [JSP_ENTRIES]),
    "jspx": ("JSP",  [JSP_ENTRIES]),
    "jspf": ("JSP",  [JSP_ENTRIES]),
    "htaccess": ("HTACCESS", [HTACCESS_RULES]),
}

# .htaccess 的完整文件名(无扩展名，需单独匹配)
HTACCESS_NAMES = {".htaccess", ".user.ini", "php.ini", ".htpasswd", "web.config"}

# 组合规则：同时命中才计重分（危险函数链，权重高于单条规则）
COMBO_RULES = [
    (("base64_decode", "eval"), 120, "base64_decode + eval 一句话"),
    (("gzinflate", "eval"), 120, "gzinflate + eval 一句话"),
    (("str_rot13", "eval"), 110, "str_rot13 + eval 一句话"),
    (("$_post[", "eval"), 130, "POST 传入 + eval"),
    (("$_post[", "assert"), 130, "POST 传入 + assert"),
    (("system", "$_get["), 130, "system + GET 传参一句话"),
    (("system", "$_post["), 130, "system + POST 传参一句话"),
    (("system", "$_request["), 130, "system + REQUEST 传参一句话"),
    (("exec", "$_get["), 130, "exec + GET 传参一句话"),
    (("exec", "$_post["), 130, "exec + POST 传参一句话"),
    (("shell_exec", "$_"), 130, "shell_exec + 外部输入"),
    (("passthru", "$_"), 130, "passthru + 外部输入"),
    (("proc_open", "$_"), 130, "proc_open + 外部输入"),
    (("request(", "eval"), 120, "ASP: request + eval"),
    (("request(", "execute"), 120, "ASP: request + execute"),
    (("createobject(", "execute"), 120, "ASP: CreateObject + execute"),
    (("frombase64string", "assembly"), 130, "ASPX: Base64 反射加载"),
    (("call_user_func", "$_"), 110, "回调函数 + 外部输入"),
    (("array_map", "$_"), 100, "array_map 回调注入"),
    (("fsockopen", "$_"), 120, "fsockopen + 外部输入(可能反弹shell)"),
    (("create_function", "base64_decode"), 120, "create_function + base64 动态建马"),
    (("preg_replace", "/e"), 130, "preg_replace /e 修饰符执行"),
    (("assert", "$_"), 120, "assert + 外部输入"),
    (("system.diagnostics.process", "start("), 130, "ASPX: Process.Start 命令执行"),
    (("process", "cmd.exe"), 130, "ASPX: 调用 cmd.exe"),
    (("processstartinfo", "redirectstandardoutput"), 120, "ASPX: 命令回显"),
]

PIC_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico"}
# 图片只取头部即可判定"图片马"(图片头 + 脚本标签)，避免拉取大文件
PIC_HEAD_BYTES = 16 * 1024

# 扫描排除项：本工具自身部署的 WAF 文件内含大量黑名单关键词(如 system/eval)，
# 若参与扫描必然误报；另外排除常见缓存/依赖目录以减少噪声与耗时。
EXCLUDE_DIR_NAMES = {".phpwaf", "node_modules", "vendor", ".git", ".svn", "__pycache__"}
EXCLUDE_FILE_PATTERNS = ("waf.php", ".waf.php")

DEFAULT_THRESHOLD = 200
MAX_REMOTE_FILE_SIZE = 2 * 1024 * 1024
# 文件数不超过该值时全量拉取精确判定；超过才启用 grep 粗筛(保证不因粗筛漏报)
FULL_SCAN_LIMIT = 800
# 远端粗筛用的高频高危关键词，用于先把范围缩小
REMOTE_GREP_KEYWORDS = (
    "eval|assert|system|exec|passthru|shell_exec|proc_open|popen|"
    "base64_decode|gzinflate|gzuncompress|str_rot13|create_function|"
    "call_user_func|preg_replace|array_map|file_put_contents|fwrite|"
    "php:\\/\\/input|php:\\/\\/filter|fsockopen|move_uploaded_file"
)

# 词边界判定用字符集
_IDENT = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$")


# ==================================================================== 核心判定
def count_wordlike(text_bytes, kw_bytes):
    """统计 kw 以标识符边界出现的次数，避免命中更长标识符的一部分"""
    n = 0
    start = 0
    kw_len = len(kw_bytes)
    while True:
        i = text_bytes.find(kw_bytes, start)
        if i < 0:
            break
        start = i + 1
        if i > 0 and kw_bytes[:1] not in (b"$", b"_"):
            if text_bytes[i - 1] in _IDENT:
                continue
        j = i + kw_len
        if (j < len(text_bytes) and text_bytes[j] in _IDENT
                and not kw_bytes.endswith((b"(", b"[", b"."))):
            continue
        n += 1
    return n


def is_excluded_path(path):
    """判断路径是否属于扫描排除项(WAF 自身 / 依赖目录 / 缓存)"""
    parts = path.replace("\\", "/").split("/")
    for part in parts[:-1]:
        if part in EXCLUDE_DIR_NAMES:
            return True
    base = parts[-1].lower()
    return base in EXCLUDE_FILE_PATTERNS


def analyze_bytes(raw, filename, threshold=DEFAULT_THRESHOLD):
    """对文件内容做检测，返回结果字典；不支持的扩展名返回 None"""
    if is_excluded_path(filename):
        return None
    basename = os.path.basename(filename).lower()
    ext_with_dot = os.path.splitext(basename)[1].lower()
    is_pic = ext_with_dot in PIC_EXT

    if basename in HTACCESS_NAMES:
        lang, groups = TYPE_RULES["htaccess"]
    elif is_pic:
        # 图片只做"图片马"判定(图片头 + 脚本标签)
        lang, groups = "PIC", []
    else:
        ext = ext_with_dot.lstrip(".")
        info = TYPE_RULES.get(ext)
        if not info:
            return None
        lang, groups = info

    # 解码：优先 UTF-8，失败才用 GBK 兜底(避免同一内容被解两遍导致计数翻倍)
    try:
        text = raw.decode("utf-8").lower()
    except UnicodeDecodeError:
        text = raw.decode("gbk", errors="ignore").lower()
    except Exception:
        text = raw.decode("latin1", errors="ignore").lower()
    tb = text.encode("utf-8", errors="ignore")

    hits = []
    score = 0
    for group in groups:
        for kw, weight in group:
            if not kw or weight <= 0:
                continue
            cnt = count_wordlike(tb, kw.encode("utf-8"))
            if cnt:
                score += weight * (1 if cnt == 1 else (1.5 if cnt <= 3 else 2))
                hits.append(f"{kw}x{cnt}")

    for kws, weight, desc in COMBO_RULES:
        if all(k in text for k in kws):
            score += weight
            hits.append(f"[组合]{desc}")

    if lang == "PHP":
        head = raw[:4096]
        if head:
            nonascii = sum(1 for c in head if c >= 0x80)
            if nonascii / len(head) > 0.35:
                score += 25
                hits.append("[高比例非ASCII]")

    if os.path.splitext(filename)[1].lower() in PIC_EXT:
        low = raw[:2048]
        if b"<?" in low or b"<%" in low or b"<jsp" in low:
            score += 150
            hits.append("[图片马:图片头含脚本标签]")
        else:
            # 纯图片，无脚本标签则直接判净
            return {
                "file": filename, "type": "PIC", "size": len(raw),
                "score": 0.0, "level": 0, "verdict": "clean", "hits": [],
            }

    if lang == "PHP" and re.search(rb"\?>\s*\S", raw[:600]):
        score += 10

    if score >= threshold:
        verdict, level = "malicious", 3
    elif score >= threshold * 0.45:
        verdict, level = "suspicious", 2
    else:
        verdict, level = "clean", 0

    return {
        "file": filename,
        "type": lang,
        "size": len(raw),
        "score": round(score, 1),
        "level": level,
        "verdict": verdict,
        "hits": hits[:14],
    }


# ==================================================================== 本地扫描
def scan_local(target, threshold=DEFAULT_THRESHOLD, workers=8, log_callback=print,
               auto_delete=False, extensions=None):
    """扫描本地目录或单个文件"""
    exts = extensions or set(TYPE_RULES.keys())
    tasks = []

    def _is_script(path):
        base = os.path.basename(path).lower()
        if base in HTACCESS_NAMES:
            return True
        ext = os.path.splitext(base)[1].lower()
        if ext.lstrip(".") in exts:
            return True
        return ext in PIC_EXT          # 图片也纳入(检测图片马)

    if os.path.isfile(target):
        tasks = [target]
    else:
        for dirpath, dirnames, filenames in os.walk(target):
            # 原地裁剪遍历：跳过排除目录(依赖/缓存/WAF 自身)
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIR_NAMES]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                if is_excluded_path(full):
                    continue
                if _is_script(fn):
                    tasks.append(full)

    log_callback(f"[*] 待扫描文件(脚本+配置+图片): {len(tasks)} 个")
    results = []

    def work(p):
        try:
            is_pic = os.path.splitext(p)[1].lower() in PIC_EXT
            limit = PIC_HEAD_BYTES if is_pic else MAX_REMOTE_FILE_SIZE
            with open(p, "rb") as f:
                raw = f.read(limit)
            return analyze_bytes(raw, p, threshold)
        except Exception as exc:
            log_callback(f"[!] 读取失败 {p}: {exc}")
            return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for r in pool.map(work, tasks):
            if r and r["verdict"] != "clean":
                results.append(r)

    results.sort(key=lambda x: -x["score"])
    if auto_delete:
        for r in results:
            if r["verdict"] == "malicious":
                try:
                    os.remove(r["file"])
                    log_callback(colored(f"[x] 已删除: {r['file']}", "red"))
                except Exception as exc:
                    log_callback(f"[!] 删除失败 {r['file']}: {exc}")
    return results, len(tasks)


# ==================================================================== 远程扫描
def _build_find_clause():
    """构造 find 的 -name 条件：脚本扩展名 + .htaccess 类配置 + 图片(查图片马)"""
    parts = [f"-name '*.{e}'" for e in sorted(TYPE_RULES.keys()) if e != "htaccess"]
    parts += [f"-name '*.{e.lstrip('.')}'" for e in sorted(PIC_EXT)]
    parts += [f"-name '{n}'" for n in sorted(HTACCESS_NAMES)]
    return " -o ".join(parts)


def _remote_script_list(ssh_client, remote_dir, log_callback):
    """列出远端脚本文件与配置文件(已在 find 层排除依赖/缓存/WAF 自身目录)"""
    qdir = shlex.quote(remote_dir)
    clause = _build_find_clause()
    prune = " ".join(f"-not -path '*/{d}/*'" for d in sorted(EXCLUDE_DIR_NAMES))
    cmd = (f"find {qdir} {prune} -type f \\( {clause} \\) "
           f"-printf '%p|%s\\n' 2>/dev/null")
    out, err = ssh.run_ssh_command(ssh_client, cmd)
    files = []
    for line in (out or "").splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        path, _, size = line.rpartition("|")
        if is_excluded_path(path):      # 兜底：远端 find 版本差异时不漏排除
            continue
        try:
            sz = int(size)
        except ValueError:
            continue
        files.append((path, sz))
    return files


def _remote_grep_candidates(ssh_client, remote_dir, log_callback):
    """远端 grep 粗筛，返回候选文件集合(先缩小范围，减少拉取量)"""
    qdir = shlex.quote(remote_dir)
    include_args = " ".join(f"--include='*.{e}'" for e in sorted(TYPE_RULES.keys())
                            if e != "htaccess")
    cmd = (
        f"grep -rlE '{REMOTE_GREP_KEYWORDS}' {qdir} {include_args} 2>/dev/null; "
        f"grep -rlE 'AddType|AddHandler|SetHandler|auto_prepend_file|"
        f"application/x-httpd-php' {qdir} --include='.htaccess' "
        f"--include='.user.ini' --include='web.config' 2>/dev/null"
    )
    out, err = ssh.run_ssh_command(ssh_client, cmd)
    cands = set()
    for line in (out or "").splitlines():
        line = line.strip()
        if line:
            cands.add(line)
    return cands


def scan_remote(remote_dir="/var/www/html/", threshold=DEFAULT_THRESHOLD,
                log_callback=print, auto_delete=False, use_grep_prefilter=True):
    """SSH 远程扫描

    流程: find 列文件 -> grep 粗筛 -> SFTP 拉回候选 -> 本地精确判定 -> 可选删除
    """
    if not state_manager.is_ssh:
        log_callback("请先测试ssh连接")
        return [], 0

    started = time.time()
    ssh_client = None
    sftp_client = None
    try:
        ssh_client = ssh.connect_ssh_client()
        log_callback(f"[*] 扫描远端目录: {remote_dir}")
        files = _remote_script_list(ssh_client, remote_dir, log_callback)
        log_callback(f"[*] 发现脚本/配置文件 {len(files)} 个")

        # 配置文件与图片始终扫描，不参与粗筛(它们最容易藏马且总量可控)
        def _always_scan(p):
            base = os.path.basename(p).lower()
            return base in HTACCESS_NAMES or os.path.splitext(base)[1].lower() in PIC_EXT

        always = [f for f in files if _always_scan(f[0])]
        others = [f for f in files if not _always_scan(f[0])]

        if use_grep_prefilter and len(others) > FULL_SCAN_LIMIT:
            candidates = _remote_grep_candidates(ssh_client, remote_dir, log_callback)
            kept = [f for f in others if f[0] in candidates]
            log_callback(f"[*] 脚本文件较多({len(others)}>{FULL_SCAN_LIMIT})，启用粗筛: "
                         f"命中 {len(kept)} 个 + 配置/图片 {len(always)} 个(始终扫描)")
            files = _dedup_files(kept + always)
        else:
            log_callback(f"[*] 全量精确扫描 {len(files)} 个文件(未启用粗筛，避免漏报)")
            files = _dedup_files(files)

        sftp_client = ssh_client.open_sftp()
        results = []
        for path, size in files:
            is_pic = os.path.splitext(path)[1].lower() in PIC_EXT
            limit = PIC_HEAD_BYTES if is_pic else MAX_REMOTE_FILE_SIZE
            if not is_pic and size > MAX_REMOTE_FILE_SIZE:
                log_callback(f"[!] 跳过超大文件({size}B): {path}")
                continue
            try:
                with sftp_client.open(path, "rb") as fh:
                    raw = fh.read(limit)
            except Exception as exc:
                log_callback(f"[!] 读取失败 {path}: {exc}")
                continue
            r = analyze_bytes(raw, path, threshold)
            if r and r["verdict"] != "clean":
                results.append(r)

        results.sort(key=lambda x: -x["score"])

        if auto_delete and results:
            to_del = [r["file"] for r in results if r["verdict"] == "malicious"]
            if to_del:
                log_callback(colored(f"[*] 准备删除 {len(to_del)} 个恶意文件...", "red"))
                for i in range(0, len(to_del), 50):
                    batch = to_del[i:i + 50]
                    q = " ".join(shlex.quote(p) for p in batch)
                    ssh.run_ssh_command(ssh_client, f"rm -f {q} 2>/dev/null")
                for p in to_del:
                    log_callback(colored(f"[x] 已删除: {p}", "red"))

        log_callback(f"[*] 扫描完成，耗时 {time.time() - started:.2f}s，"
                     f"可疑 {len(results)} 个 (扫描 {len(files)} 个文件)")
        return results, len(files)
    except Exception as exc:
        log_callback(f"[x] 远程扫描失败: {exc}")
        return [], 0
    finally:
        try:
            if sftp_client:
                sftp_client.close()
        except Exception:
            pass
        try:
            if ssh_client:
                ssh_client.close()
        except Exception:
            pass


def _dedup_files(files):
    seen = set()
    out = []
    for p, s in files:
        if p in seen:
            continue
        seen.add(p)
        out.append((p, s))
    return out


# ==================================================================== 报告输出
def format_report(results, total, threshold=DEFAULT_THRESHOLD):
    """把扫描结果格式化成文本报告"""
    lines = []
    lines.append("=" * 78)
    lines.append(f"  WebShell 查杀报告   扫描 {total} 个文件，"
                 f"命中 {len(results)} 个，阈值 {threshold}")
    lines.append("=" * 78)
    if not results:
        lines.append("  未发现可疑文件")
        return "\n".join(lines)
    for r in results:
        mark = "【恶意】" if r["verdict"] == "malicious" else "【可疑】"
        lines.append(f"{mark} level={r['level']} score={r['score']:<8} "
                     f"{r['type']:<4} {r['file']}")
        if r["hits"]:
            lines.append(f"        命中: {' | '.join(r['hits'])}")
    mal = sum(1 for r in results if r["verdict"] == "malicious")
    sus = len(results) - mal
    lines.append("-" * 78)
    lines.append(f"  合计: 恶意 {mal} 个，可疑 {sus} 个")
    return "\n".join(lines)


def save_report(results, total, out_path=None, threshold=DEFAULT_THRESHOLD):
    """保存报告到运行目录(打包后为 exe 旁边的 tmp/<host>/)"""
    text = format_report(results, total, threshold)
    if out_path is None:
        safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", state_manager.hostname or "default")
        out_dir = get_runtime_dir(safe_host)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"webshell_report_{time.strftime('%Y%m%d_%H%M%S')}.txt"
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
        return str(out_path)
    except Exception:
        return None
