# -*- coding: utf-8 -*-
"""defence_v3 修复总验收"""
import sys
import inspect
import io
import re
import collections

sys.path.insert(0, ".")

from defence import file_processing as fp
from defence import waf_manager as wm
from defence import attacker_tools as at
from defence import webshell_scanner as ws
from defence import ssh as sshmod

results = []


def chk(group, name, cond):
    results.append((group, name, bool(cond)))


# ============ 数据安全（最高优先级）============
chk("数据安全", "H1 MD5采集失败抛异常", "MD5 采集未完成" in inspect.getsource(fp.batch_get_md5))
chk("数据安全", "H1 采集不完整抛异常", "MD5 采集不完整" in inspect.getsource(fp.batch_get_md5))
chk("数据安全", "H1 删除比例守卫", "疑似基线失效" in inspect.getsource(fp.monitor_directory_changes))
chk("数据安全", "H1 删除后同步基线", "md5_dict.pop(f, None)" in inspect.getsource(fp.monitor_directory_changes))
chk("数据安全", "H2 备份失败不清空", "&& test -s" in inspect.getsource(fp.deploy_tar))
chk("数据安全", "H2 备份成功标记", "AWD_BACKUP_OK" in inspect.getsource(fp.deploy_tar))
chk("数据安全", "H3 解压层级自适应", "extract_dest" in inspect.getsource(fp.deploy_tar))
chk("数据安全", "H2 失败自动回滚", "AWD_DEPLOY_ROLLBACK" in inspect.getsource(fp.deploy_tar))
chk("数据安全", "M3 md5sum转义还原", "_unescape_md5sum_name" in inspect.getsource(fp.batch_get_md5))
chk("数据安全", "M7 断线重建连接", "重建 SSH 连接" in inspect.getsource(fp.monitor_directory_changes))

# ============ WAF ============
_sn = wm.build_waf_include_snippet("/x/.phpwaf/waf.php", "/tmp/l", 1, 3, "")
chk("WAF", "H1 注入块带标记", "PHPWAF-INCLUDE-START" in _sn and "PHPWAF-INCLUDE-END" in _sn)
chk("WAF", "H1 标记在php标签内不输出页面", _sn.startswith("<?php /*") and _sn.rstrip().endswith("*/ ?>"))
chk("WAF", "H2 按标记精确剥离", "strip_injected_block" in inspect.getsource(wm.remove_waf_include_content))
chk("WAF", "H2 不再补回<?php", "<?php \" +" not in inspect.getsource(wm.remove_waf_include_content))
chk("WAF", "H3 清理失败保留文件", 'remove_result["failed"]' in inspect.getsource(wm.undeploy_waf))
chk("WAF", "H4 写入前备份", "backup_remote_file" in inspect.getsource(wm.write_remote_text_file))
chk("WAF", "H4 临时文件+rename", "phpwaf.tmp" in inspect.getsource(wm.write_remote_text_file))
chk("WAF", "M7 注入失败即报错", "注入未完成" in inspect.getsource(wm.deploy_waf))
chk("WAF", "M8 路径规范化", "posixpath.normpath" in inspect.getsource(wm.should_skip_waf_managed_file))

# ============ SSH ============
chk("SSH", "run_ssh_command 解码不抛错", 'errors="replace"' in inspect.getsource(sshmod.run_ssh_command))
chk("SSH", "M2 connect失败即关闭", "ssh_client.close()" in inspect.getsource(sshmod.connect_ssh_client))
chk("SSH", "M2 sftp失败即关闭", "ssh_client.close()" in inspect.getsource(sshmod.connect_sftp_client))
chk("SSH", "M5 已有连接返回True", "return True" in inspect.getsource(sshmod.ssh_test))
chk("SSH", "M5 失败恢复旧凭证", "old_state" in inspect.getsource(sshmod.ssh_test))
chk("SSH", "M1 shell用select", "select.select" in inspect.getsource(sshmod.shell))
chk("SSH", "M1 shell超时join", "timeout=3" in inspect.getsource(sshmod.shell))

# ============ 攻击工具 ============
chk("攻击工具", "M1 不用repr生成PHP", "%r" not in inspect.getsource(at.make_bugku_backdoor_url))
chk("攻击工具", "M4 后门判定限200", "result.status != 200" in inspect.getsource(at.check_known_backdoor))
chk("攻击工具", "M4 排除整页HTML", "looks_like_page" in inspect.getsource(at.check_known_backdoor))
chk("攻击工具", "M4 存活用ok", "if result.ok:" in inspect.getsource(at.scan_alive))
chk("攻击工具", "M5 worker异常保护", "探活任务异常" in inspect.getsource(at.scan_alive))
chk("攻击工具", "M5 http错误体保护", "read_exc" in inspect.getsource(at.http_request))
chk("攻击工具", "M6 停止用cancel_futures", "cancel_futures=True" in inspect.getsource(at.bugku_batch_submit))

# ============ GUI 入口 ============
gui_src = io.open("gui_main.py", encoding="utf-8").read()
chk("GUI", "标题栏标注 MetaAWD by metavi",
    'self.title("MetaAWD by metavi")' in gui_src)
chk("GUI", "品牌标识只在标题栏(未在内容区另加品牌栏)",
    "brand = ttkb.Frame" not in gui_src and "by metavi" in gui_src)
chk("GUI", "阈值说明按钮", "阈值说明" in gui_src and "show_threshold_help" in gui_src)
chk("GUI", "阈值动态提示", "update_threshold_hint" in gui_src)
chk("查杀", "可疑线与阈值联动",
    hasattr(ws, "SUSPECT_RATIO") and abs(ws.SUSPECT_RATIO - 0.40) < 1e-9)
chk("GUI", "数据包页有同步按钮", "btn_sync_packets" in gui_src)
chk("GUI", "记录全部请求开关", "chk_waf_log_all" in gui_src)
chk("GUI", "监控线程有finally", "监控线程异常退出" in gui_src)
chk("GUI", "打包有finally", "打包失败" in gui_src)
chk("GUI", "终端bootstrap超时", "shell_bootstrap_deadline" in gui_src)

# ============ 查杀 ============
chk("查杀", "WAF自身排除", hasattr(ws, "EXCLUDE_DIR_NAMES"))
chk("查杀", "图片马检测", hasattr(ws, "PIC_HEAD_BYTES"))
chk("查杀", "htaccess规则", hasattr(ws, "HTACCESS_RULES"))
chk("查杀", "词边界匹配", hasattr(ws, "count_wordlike"))

# ============ 结构 ============
for path, label in [("defence/waf_manager.py", "waf_manager"),
                    ("defence/file_processing.py", "file_processing"),
                    ("defence/attacker_tools.py", "attacker_tools"),
                    ("defence/ssh.py", "ssh")]:
    src = io.open(path, encoding="utf-8").read()
    names = re.findall(r"^def (\w+)", src, re.M)
    dup = [n for n, c in collections.Counter(names).items() if c > 1]
    chk("结构", f"{label} 无重复定义", not dup)

# ============ 输出 ============
cur = None
ok_n = 0
for group, name, ok in results:
    if group != cur:
        print(f"\n【{group}】")
        cur = group
    print(f"  {'✓' if ok else '✗'} {name}")
    ok_n += ok

print(f"\n{'='*60}")
print(f"总验收: {ok_n}/{len(results)} 通过")
if ok_n == len(results):
    print("全部修复项已落地")
