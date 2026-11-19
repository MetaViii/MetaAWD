"""Build exportable pwn_waf-compatible traffic handling bundles."""

import ipaddress
import json
import posixpath
import re
import shutil
import tempfile
from pathlib import Path

from defence._bootstrap import get_resource_dir

MODES = {
    "catch": {
        "label": "CATCH 捕获",
        "binary": "catch",
        "description": "运行原 PWN 程序并记录标准输入输出及危险系统调用。",
    },
    "i0gan": {
        "label": "I0GAN 防守",
        "binary": "i0gan",
        "description": "记录交互，并在程序启动后再次出现危险系统调用时终止本次处理。",
    },
    "forward": {
        "label": "FORWARD 单目标",
        "binary": "forward",
        "description": "把标准输入输出转发到一个 IPv4 目标，同时记录双向流量。",
    },
    "forward_multi": {
        "label": "FORWARD_MULTI 多目标",
        "binary": "forward_multi",
        "description": "按连接轮询 hosts.txt 中的 IPv4 目标，并记录双向流量。",
    },
}
SOURCE_FILES = ("waf.c", "waf.h", "logger.c", "logger.h", "LICENSE")
SAFE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
SAFE_PATH = re.compile(r"^/[A-Za-z0-9_./+-]+$")
COMPILERS = {"gcc", "musl-gcc"}
OPTIMIZATIONS = {"0", "1", "2", "3", "s"}
LOG_PERMISSIONS = {"0750", "0770", "0777"}
RESTART_METHODS = {"none", "systemctl", "service"}


def _source_root():
    return get_resource_dir() / "defence" / "pwn_waf_source"


def _write_text(path, text, encoding="utf-8"):
    Path(path).write_bytes(text.encode(encoding))


def _text(options, key, label, *, default=None):
    value = options.get(key, default)
    if not isinstance(value, str) or not value.strip() or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError(f"请填写{label}。")
    return value.strip()


def _choice(options, key, label, choices, *, default=None):
    value = options.get(key, default)
    if value not in choices:
        raise ValueError(f"请选择有效的{label}。")
    return value


def _boolean(options, key, label, *, default=None):
    value = options.get(key, default)
    if type(value) is not bool:
        raise ValueError(f"请选择是否{label}。")
    return value


def _integer(options, key, label, minimum, maximum, *, default=None):
    value = options.get(key, default)
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label}须为 {minimum}–{maximum} 的整数。")
    return value


def _name(options, key, label, *, default=None):
    value = _text(options, key, label, default=default)
    if not SAFE_NAME.fullmatch(value):
        raise ValueError(f"{label}仅可包含字母、数字、点、下划线和连字符，且须以字母或下划线开头。")
    return value


def _path(options, key, label, *, default=None):
    value = _text(options, key, label, default=default)
    normalized = posixpath.normpath(value)
    if (not SAFE_PATH.fullmatch(value) or "//" in value or normalized == "/"
            or normalized != value.rstrip("/")):
        raise ValueError(f"{label}须为不含空格、跳转段或控制字符的 Linux 绝对路径，且不能是根目录。")
    return normalized


def _ipv4(value, label):
    try:
        return str(ipaddress.IPv4Address(value))
    except (ipaddress.AddressValueError, ValueError):
        raise ValueError(f"{label}须为有效的 IPv4 地址。") from None


def _target_ipv4(value, label):
    host = _ipv4(value, label)
    address = ipaddress.IPv4Address(host)
    if address.is_unspecified or address.is_multicast or host == "255.255.255.255":
        raise ValueError(f"{label}须为可连接的单播 IPv4 地址。")
    return host


def _is_self_forward(bind_address, listen_port, target_host, target_port):
    if listen_port != target_port:
        return False
    bind = ipaddress.IPv4Address(bind_address)
    target = ipaddress.IPv4Address(target_host)
    if bind == target:
        return True
    if target.is_loopback and (bind.is_unspecified or bind.is_loopback):
        return True
    return False


def _targets(value):
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError("多目标列表格式无效。")
    targets = []
    seen = set()
    for number, raw in enumerate(value.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.count(":") != 1:
            raise ValueError(f"多目标第 {number} 行须使用 IPv4:端口 格式。")
        host, port_text = (part.strip() for part in line.split(":", 1))
        host = _target_ipv4(host, f"多目标第 {number} 行地址")
        if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
            raise ValueError(f"多目标第 {number} 行端口须为 1–65535 的整数。")
        target = f"{host}:{int(port_text)}"
        if target not in seen:
            seen.add(target)
            targets.append(target)
    if not targets:
        raise ValueError("FORWARD_MULTI 模式至少需要一个转发目标。")
    if len(targets) > 256:
        raise ValueError("FORWARD_MULTI 模式最多配置 256 个转发目标。")
    return targets


def _validated(options):
    if not isinstance(options, dict):
        raise ValueError("PWN 流量转发参数格式无效。")
    mode = _choice(options, "mode", "运行模式", MODES)
    architecture = _integer(options, "architecture", "程序位数", 32, 64, default=64)
    if architecture not in {32, 64}:
        raise ValueError("程序位数须为 32 或 64。")
    log_path = _path(options, "logPath", "日志目录", default="/tmp/.metaawd-pwn")
    service_path = _path(options, "servicePath", "服务程序路径", default="/pwn")
    backup_path = _path(options, "backupPath", "原程序备份路径", default="/opt/metaawd-backup/pwn.original")
    if service_path == backup_path or service_path.startswith(f"{log_path}/"):
        raise ValueError("服务程序和原程序备份须使用不同路径，服务程序不能位于服务帐号可写的日志目录内。")
    if backup_path == log_path or backup_path.startswith(f"{log_path}/"):
        raise ValueError("原程序备份不能位于服务帐号可写的日志目录内。")

    forward_host = _target_ipv4(
        _text(options, "forwardHost", "单目标地址", default="127.0.0.1"), "单目标地址"
    )
    forward_port = _integer(options, "forwardPort", "单目标端口", 1, 65535, default=20000)
    targets = _targets(options.get("targets", "")) if mode == "forward_multi" else []
    bind_address = _ipv4(_text(options, "listenAddress", "监听地址", default="0.0.0.0"), "监听地址")

    result = {
        "mode": mode,
        "architecture": architecture,
        "logEnabled": _boolean(options, "logEnabled", "记录流量日志", default=True),
        "logPath": log_path,
        "logPermissions": _choice(options, "logPermissions", "日志目录权限", LOG_PERMISSIONS, default="0770"),
        "compiler": _choice(options, "compiler", "编译器", COMPILERS, default="gcc"),
        "optimization": _choice(options, "optimization", "优化级别", OPTIMIZATIONS, default="2"),
        "staticLink": _boolean(options, "staticLink", "静态链接", default=True),
        "stripBinary": _boolean(options, "stripBinary", "移除符号", default=True),
        "extraWarnings": _boolean(options, "extraWarnings", "启用额外编译警告", default=True),
        "serviceName": _name(options, "serviceName", "xinetd 服务名", default="metaawd-pwn"),
        "servicePath": service_path,
        "backupPath": backup_path,
        "serviceUser": _name(options, "serviceUser", "服务用户", default="pwn"),
        "serviceGroup": _name(options, "serviceGroup", "服务用户组", default="pwn"),
        "listenAddress": bind_address,
        "listenPort": _integer(options, "listenPort", "监听端口", 1, 65535, default=10000),
        "perSource": _integer(options, "perSource", "单来源并发", 1, 1024, default=10),
        "instances": _integer(options, "instances", "总实例上限", 1, 4096, default=128),
        "cpuLimit": _integer(options, "cpuLimit", "CPU 秒数限制", 1, 3600, default=20),
        "memoryLimitMb": _integer(options, "memoryLimitMb", "内存限制", 16, 65536, default=256),
        "forwardHost": forward_host,
        "forwardPort": forward_port,
        "targets": targets,
        "installXinetd": _boolean(options, "installXinetd", "安装 xinetd 配置", default=True),
        "restartMethod": _choice(options, "restartMethod", "xinetd 重启方式", RESTART_METHODS, default="systemctl"),
    }
    if mode == "forward" and _is_self_forward(
            result["listenAddress"], result["listenPort"], result["forwardHost"], result["forwardPort"]):
        raise ValueError("单目标端口与本机监听端口形成转发环路；通配监听时请改用不同端口。")
    if mode == "forward_multi":
        for target in result["targets"]:
            host, port = target.rsplit(":", 1)
            if _is_self_forward(result["listenAddress"], result["listenPort"], host, int(port)):
                raise ValueError(f"多目标 {target} 与本机监听端口形成转发环路。")
    return result


def _makefile(config):
    flags = [f"-O{config['optimization']}"]
    if config["architecture"] == 32:
        flags.append("-m32")
    if config["extraWarnings"]:
        flags.extend(("-Wall", "-Wextra"))
    if config["staticLink"]:
        flags.append("-static")
    if config["stripBinary"]:
        flags.append("-s")
    values = {
        "compiler": config["compiler"],
        "flags": " ".join(flags),
        "log_method": "OPEN" if config["logEnabled"] else "CLOSE",
        "log_path": config["logPath"],
        "original_path": config["backupPath"],
        "arch": config["architecture"],
        "host": config["forwardHost"],
        "port": config["forwardPort"],
    }
    return """# Generated by MetaAWD. Source: https://github.com/i0gan/pwn_waf
CC := {compiler}
CFLAGS := {flags}
LOG_METHOD := {log_method}
LOG_PATH := {log_path}
ORIGINAL_PATH := {original_path}
ARCH := {arch}
FORWARD_IP := {host}
FORWARD_PORT := {port}
SRC := src/waf.c src/logger.c
COMMON_DEFINES := -DLOG_METHOD=$(LOG_METHOD) -DLOG_PATH=\\\"$(LOG_PATH)\\\" -DORIGINAL_PATH=\\\"$(ORIGINAL_PATH)\\\" -DARCH=$(ARCH)

.PHONY: all clean catch i0gan forward forward_multi
all: catch i0gan forward forward_multi

catch:
\t$(CC) $(CFLAGS) $(SRC) $(COMMON_DEFINES) -DRUN_MODE=CATCH -o $@

i0gan:
\t$(CC) $(CFLAGS) $(SRC) $(COMMON_DEFINES) -DRUN_MODE=I0GAN -o $@

forward:
\t$(CC) $(CFLAGS) $(SRC) $(COMMON_DEFINES) -DRUN_MODE=FORWARD -DFORWARD_IP=\\\"$(FORWARD_IP)\\\" -DFORWARD_PORT=$(FORWARD_PORT) -o $@

forward_multi:
\t$(CC) $(CFLAGS) $(SRC) $(COMMON_DEFINES) -DRUN_MODE=FORWARD_MULTI -o $@

clean:
\trm -f catch i0gan forward forward_multi
""".format(**values)


def _xinetd(config):
    return f"""service {config['serviceName']}
{{
    disable = no
    type = UNLISTED
    socket_type = stream
    protocol = tcp
    wait = no
    user = {config['serviceUser']}
    group = {config['serviceGroup']}
    bind = {config['listenAddress']}
    port = {config['listenPort']}
    server = {config['servicePath']}
    per_source = {config['perSource']}
    instances = {config['instances']}
    rlimit_cpu = {config['cpuLimit']}
    rlimit_as = {config['memoryLimitMb']}M
}}
"""


def _restart_lines(config):
    if config["restartMethod"] == "systemctl":
        return "systemctl restart xinetd"
    if config["restartMethod"] == "service":
        return "service xinetd restart"
    return "printf '%s\\n' 'xinetd 配置已变化，请按目标系统方式重新加载服务。'"


def _deploy_script(config):
    binary = MODES[config["mode"]]["binary"]
    hosts_copy = ""
    if config["mode"] == "forward_multi":
        hosts_copy = f'install -m 0640 -o "$SERVICE_USER" -g "$SERVICE_GROUP" hosts.txt "{config["logPath"]}/hosts.txt"\n'
    xinetd_install = ""
    if config["installXinetd"]:
        xinetd_install = f"""XINETD_PATH=/etc/xinetd.d/{config['serviceName']}
XINETD_BACKUP="$BACKUP_PATH.xinetd"
XINETD_ABSENT="$BACKUP_PATH.xinetd.absent"
if [ ! -f "$XINETD_BACKUP" ] && [ ! -f "$XINETD_ABSENT" ]; then
    if [ -f "$XINETD_PATH" ]; then
        cp -p "$XINETD_PATH" "$XINETD_BACKUP"
    else
        : > "$XINETD_ABSENT"
    fi
fi
install -m 0644 xinetd-{config['serviceName']} "$XINETD_PATH"
{_restart_lines(config)}
"""
    return f"""#!/bin/sh
set -eu

BINARY=./{binary}
SERVICE_PATH={config['servicePath']}
BACKUP_PATH={config['backupPath']}
BACKUP_META="$BACKUP_PATH.meta"
SERVICE_USER={config['serviceUser']}
SERVICE_GROUP={config['serviceGroup']}
LOG_PATH={config['logPath']}

[ "$(id -u)" -eq 0 ] || {{ echo '请使用 root 运行部署脚本。' >&2; exit 1; }}
id "$SERVICE_USER" >/dev/null 2>&1 || {{ echo "服务用户不存在: $SERVICE_USER" >&2; exit 1; }}
getent group "$SERVICE_GROUP" >/dev/null 2>&1 || {{ echo "服务用户组不存在: $SERVICE_GROUP" >&2; exit 1; }}
SERVICE_UID=$(id -u "$SERVICE_USER")
SERVICE_GID=$(getent group "$SERVICE_GROUP" | cut -d: -f3)
[ -f "$BINARY" ] && [ ! -L "$BINARY" ] || {{ echo "构建产物须为非符号链接普通文件: $BINARY" >&2; exit 1; }}
[ -f "$SERVICE_PATH" ] && [ ! -L "$SERVICE_PATH" ] || {{ echo "服务程序须为非符号链接普通文件: $SERVICE_PATH" >&2; exit 1; }}

if [ -e "$LOG_PATH" ]; then
    [ -d "$LOG_PATH" ] && [ ! -L "$LOG_PATH" ] || {{ echo "日志路径须为非符号链接目录: $LOG_PATH" >&2; exit 1; }}
    [ "$(stat -c %u "$LOG_PATH")" = "$SERVICE_UID" ] || {{ echo "已有日志目录须归服务用户所有: $LOG_PATH" >&2; exit 1; }}
    [ "$(stat -c %A "$LOG_PATH" | cut -c3)" = w ] || {{ echo "服务用户对日志目录没有写权限: $LOG_PATH" >&2; exit 1; }}
else
    install -d -m {config['logPermissions']} -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$LOG_PATH"
fi

BACKUP_DIR=$(dirname "$BACKUP_PATH")
if [ -e "$BACKUP_DIR" ]; then
    [ -d "$BACKUP_DIR" ] && [ ! -L "$BACKUP_DIR" ] || {{ echo "备份父路径须为非符号链接目录: $BACKUP_DIR" >&2; exit 1; }}
    [ "$(stat -c %u "$BACKUP_DIR")" = 0 ] || {{ echo "备份父目录须归 root 所有: $BACKUP_DIR" >&2; exit 1; }}
    ! find "$BACKUP_DIR" -maxdepth 0 -perm /022 -print -quit | grep -q . || {{ echo "备份父目录不能由组或其他用户写入: $BACKUP_DIR" >&2; exit 1; }}
    BACKUP_PERMS=$(stat -c %A "$BACKUP_DIR")
    BACKUP_GID=$(stat -c %g "$BACKUP_DIR")
    [ "$(printf '%s' "$BACKUP_PERMS" | cut -c10)" = x ] || {{ [ "$BACKUP_GID" = "$SERVICE_GID" ] && [ "$(printf '%s' "$BACKUP_PERMS" | cut -c7)" = x ]; }} || {{ echo "服务用户无法进入备份目录: $BACKUP_DIR" >&2; exit 1; }}
else
    install -d -m 0750 -o root -g "$SERVICE_GROUP" "$BACKUP_DIR"
fi

if [ -e "$BACKUP_PATH" ] || [ -e "$BACKUP_META" ]; then
    [ -f "$BACKUP_PATH" ] && [ ! -L "$BACKUP_PATH" ] || {{ echo "原程序备份须为非符号链接普通文件: $BACKUP_PATH" >&2; exit 1; }}
    [ -f "$BACKUP_META" ] && [ ! -L "$BACKUP_META" ] || {{ echo "原程序元数据缺失: $BACKUP_META" >&2; exit 1; }}
else
    BACKUP_TMP="$BACKUP_PATH.tmp.$$"
    META_TMP="$BACKUP_META.tmp.$$"
    cp -p "$SERVICE_PATH" "$BACKUP_TMP"
    chown root:"$SERVICE_GROUP" "$BACKUP_TMP"
    chmod 0550 "$BACKUP_TMP"
    stat -c '%u %g %a' "$SERVICE_PATH" > "$META_TMP"
    chown root:root "$META_TMP"
    chmod 0600 "$META_TMP"
    mv "$BACKUP_TMP" "$BACKUP_PATH"
    mv "$META_TMP" "$BACKUP_META"
fi
[ "$(stat -c %u "$BACKUP_PATH")" = 0 ] && [ "$(stat -c %g "$BACKUP_PATH")" = "$SERVICE_GID" ] || {{ echo "原程序备份属主无效: $BACKUP_PATH" >&2; exit 1; }}
[ "$(stat -c %u "$BACKUP_META")" = 0 ] && [ "$(stat -c %g "$BACKUP_META")" = 0 ] || {{ echo "原程序元数据须归 root:root 所有。" >&2; exit 1; }}
! find "$BACKUP_PATH" "$BACKUP_META" -maxdepth 0 -perm /022 -print -quit | grep -q . || {{ echo "原程序备份不能由组或其他用户写入。" >&2; exit 1; }}
BACKUP_FILE_PERMS=$(stat -c %A "$BACKUP_PATH")
[ "$(printf '%s' "$BACKUP_FILE_PERMS" | cut -c5)" = r ] && [ "$(printf '%s' "$BACKUP_FILE_PERMS" | cut -c7)" = x ] || {{ echo "服务用户对原程序备份没有读取或执行权限。" >&2; exit 1; }}

{hosts_copy}install -m 0755 -o root -g root "$BINARY" "$SERVICE_PATH"
{xinetd_install}printf '%s\\n' '部署完成。请从独立终端连接监听端口，验证服务、日志与回滚流程。'
"""


def _rollback_script(config):
    xinetd_rollback = ""
    if config["installXinetd"]:
        xinetd_rollback = f"""XINETD_PATH=/etc/xinetd.d/{config['serviceName']}
XINETD_BACKUP="$BACKUP_PATH.xinetd"
XINETD_ABSENT="$BACKUP_PATH.xinetd.absent"
if [ -f "$XINETD_BACKUP" ]; then
    cp -p "$XINETD_BACKUP" "$XINETD_PATH"
    rm -f "$XINETD_BACKUP"
elif [ -f "$XINETD_ABSENT" ]; then
    rm -f "$XINETD_PATH" "$XINETD_ABSENT"
else
    printf '%s\\n' '未找到 xinetd 原配置记录，保留当前配置。'
fi
{_restart_lines(config)}
"""
    return f"""#!/bin/sh
set -eu

SERVICE_PATH={config['servicePath']}
BACKUP_PATH={config['backupPath']}
BACKUP_META="$BACKUP_PATH.meta"
[ "$(id -u)" -eq 0 ] || {{ echo '请使用 root 运行回滚脚本。' >&2; exit 1; }}
[ -f "$BACKUP_PATH" ] && [ ! -L "$BACKUP_PATH" ] || {{ echo "原程序备份无效: $BACKUP_PATH" >&2; exit 1; }}
[ -f "$BACKUP_META" ] && [ ! -L "$BACKUP_META" ] || {{ echo "原程序元数据无效: $BACKUP_META" >&2; exit 1; }}
if [ -e "$SERVICE_PATH" ]; then
    [ -f "$SERVICE_PATH" ] && [ ! -L "$SERVICE_PATH" ] || {{ echo "服务程序路径不是普通文件: $SERVICE_PATH" >&2; exit 1; }}
fi
read ORIGINAL_UID ORIGINAL_GID ORIGINAL_MODE < "$BACKUP_META"
case "$ORIGINAL_UID" in ''|*[!0-9]*) echo '原程序 UID 记录无效。' >&2; exit 1;; esac
case "$ORIGINAL_GID" in ''|*[!0-9]*) echo '原程序 GID 记录无效。' >&2; exit 1;; esac
case "$ORIGINAL_MODE" in ''|*[!0-7]*) echo '原程序权限记录无效。' >&2; exit 1;; esac
cp -p "$BACKUP_PATH" "$SERVICE_PATH"
chown "$ORIGINAL_UID:$ORIGINAL_GID" "$SERVICE_PATH"
chmod "$ORIGINAL_MODE" "$SERVICE_PATH"
{xinetd_rollback}printf '%s\\n' '已恢复原服务程序及其属主、属组和权限。请重新执行连接测试。'
"""


def _readme(config):
    mode = MODES[config["mode"]]
    target_note = ""
    if config["mode"] == "forward":
        target_note = f"转发目标：{config['forwardHost']}:{config['forwardPort']}\n"
    elif config["mode"] == "forward_multi":
        target_note = f"轮询目标：{len(config['targets'])} 个，见 hosts.txt\n"
    return f"""MetaAWD PWN 流量转发构建包

模式：{mode['label']}
说明：{mode['description']}
架构：Linux {'x86-64' if config['architecture'] == 64 else 'x86'}
日志：{'开启，目录 ' + config['logPath'] if config['logEnabled'] else '关闭'}
原程序备份：{config['backupPath']}（root 管理，CATCH/I0GAN 直接从此路径启动）
{target_note}
1. 在不高于目标机 glibc 版本的 Linux 构建环境中运行：
   make {mode['binary']}
2. 核对 xinetd-{config['serviceName']}、deploy.sh 和 rollback.sh。
3. 在测试环境运行：sudo sh deploy.sh
4. 从独立终端连接 {config['listenAddress']}:{config['listenPort']} 做完整交互测试。
5. 需要恢复时运行：sudo sh rollback.sh

Makefile 同时提供 catch、i0gan、forward、forward_multi 四个构建目标。
CATCH 与 I0GAN 使用 ptrace，只支持与 ARCH 匹配的 Linux 程序；原程序从 root 管理的 ORIGINAL_PATH 启动。
FORWARD 与 FORWARD_MULTI 使用标准输入输出承接 xinetd/socat 的单连接进程。
上游源码及授权见 src/ 和 LICENSE，来源：https://github.com/i0gan/pwn_waf
"""


def _build_forward_plan(options):
    config = _validated(options)
    mode = MODES[config["mode"]]
    files = [
        "Makefile", "deploy.sh", "rollback.sh", "README.txt", "policy.json",
        f"xinetd-{config['serviceName']}", "src/waf.c", "src/waf.h", "src/logger.c",
        "src/logger.h", "LICENSE",
    ]
    if config["mode"] == "forward_multi":
        files.append("hosts.txt")
    notes = [
        "构建环境的 glibc 版本应不高于部署目标；静态链接还要求编译环境具备对应静态库。",
        "部署脚本会保留原程序及 UID、GID、权限元数据；原程序备份由 root 管理，服务帐号只有读取和执行权限。",
        "已有日志目录只做属主与写权限校验，不会被部署脚本修改权限。",
    ]
    if config["mode"] == "i0gan":
        notes.append("I0GAN 沿用上游规则：启动后再次出现 open、clone 或 execve 时结束本次处理，可能影响正常业务。")
    if config["mode"] == "forward_multi":
        notes.append("多目标按新连接轮询；不可达目标会使该次连接失败，hosts.txt 中已移除空行、注释和重复项。")
    summary = [
        {"label": "运行模式", "value": mode["label"]},
        {"label": "构建产物", "value": mode["binary"]},
        {"label": "目标架构", "value": f"Linux {'x86-64' if config['architecture'] == 64 else 'x86'}"},
        {"label": "流量日志", "value": config["logPath"] if config["logEnabled"] else "关闭"},
        {"label": "服务入口", "value": f"{config['listenAddress']}:{config['listenPort']}"},
        {"label": "服务身份", "value": f"{config['serviceUser']}:{config['serviceGroup']}"},
    ]
    if config["mode"] == "forward":
        summary.append({"label": "转发目标", "value": f"{config['forwardHost']}:{config['forwardPort']}"})
    if config["mode"] == "forward_multi":
        summary.append({"label": "轮询目标", "value": f"{len(config['targets'])} 个"})
    return {
        "mode": config["mode"],
        "modeLabel": mode["label"],
        "description": mode["description"],
        "binary": mode["binary"],
        "targetCount": len(config["targets"]) if config["mode"] == "forward_multi" else (1 if config["mode"] == "forward" else 0),
        "buildCommand": f"make {mode['binary']}",
        "deployCommand": "sudo sh deploy.sh",
        "xinetd": _xinetd(config),
        "makefile": _makefile(config),
        "summary": summary,
        "files": files,
        "notes": notes,
        "config": config,
    }


def build_forward_plan(options):
    plan = _build_forward_plan(options)
    return {key: value for key, value in plan.items() if key != "config"}


def export_forward_bundle(options, parent):
    plan = _build_forward_plan(options)
    config = plan["config"]
    parent = Path(parent).expanduser().resolve()
    if not parent.is_dir():
        raise ValueError("请选择已存在的导出目录。")
    source = _source_root()
    missing = [name for name in SOURCE_FILES if not (source / name).is_file()]
    if missing:
        raise RuntimeError(f"PWN 流量转发源码资源不完整：{', '.join(missing)}")

    output = Path(tempfile.mkdtemp(prefix=f"metaawd-pwn-{config['mode']}-", dir=parent))
    try:
        source_output = output / "src"
        source_output.mkdir()
        for name in SOURCE_FILES:
            destination = output / "LICENSE" if name == "LICENSE" else source_output / name
            shutil.copy2(source / name, destination)
        _write_text(output / "Makefile", plan["makefile"])
        _write_text(output / f"xinetd-{config['serviceName']}", plan["xinetd"])
        _write_text(output / "deploy.sh", _deploy_script(config))
        _write_text(output / "rollback.sh", _rollback_script(config))
        _write_text(output / "README.txt", _readme(config))
        if config["mode"] == "forward_multi":
            _write_text(output / "hosts.txt", "\n".join(config["targets"]) + "\n", "ascii")
        manifest = {key: value for key, value in plan.items() if key not in {"config", "makefile", "xinetd"}}
        manifest["options"] = config
        _write_text(
            output / "policy.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
        )
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise
    return {**{key: value for key, value in plan.items() if key != "config"}, "directory": str(output)}
