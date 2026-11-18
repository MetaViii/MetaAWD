"""Read ELF hardening metadata and render Linux service confinement policies."""

import hashlib
import os
import re
import tempfile
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

UNIT_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:@-]{0,245}\.service\Z")
LITERAL_PATH = re.compile(r"/[A-Za-z0-9_./-]+\Z")
MAX_ELF_SIZE = 128 * 1024 * 1024
DROP_IN = "90-metaawd-pwn.conf"

BOOL_POLICIES = (
    ("noNewPrivileges", "NoNewPrivileges=yes", "阻止服务通过后续执行获得新权限。"),
    ("privateTmp", "PrivateTmp=yes", "隔离服务的 /tmp 和 /var/tmp。依赖共享临时目录时需验证。"),
    ("nativeAbi", "SystemCallArchitectures=native", "仅允许宿主原生系统调用 ABI。兼容 ABI 程序需验证。"),
    ("denyWritableExecute", "MemoryDenyWriteExecute=yes", "限制产生新的可执行内存映射。JIT 等运行时需验证。"),
    ("noExecTemp", "NoExecPaths=-/tmp -/var/tmp -/dev/shm", "限制从常见临时目录执行文件。"),
)


def _as_choice(options, key, choices):
    value = options.get(key, "inherit")
    if not isinstance(value, str) or value not in choices:
        raise ValueError("请检查防护配置中的选项。")
    return value


def _paths(value):
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError("路径列表过长或格式无效。")
    paths = []
    for line in value.splitlines():
        path = line.strip()
        if not path:
            continue
        if not LITERAL_PATH.fullmatch(path) or any(part in ("", ".", "..") for part in path.split("/")[1:]):
            raise ValueError("请每行填写一个规范的 Linux 绝对路径。路径字符支持字母、数字、点、短横线和下划线。")
        paths.append(path)
    return list(dict.fromkeys(paths))


def build_policy(options):
    if not isinstance(options, dict):
        raise ValueError("请填写服务防护参数。")
    unit = options.get("unit")
    if not isinstance(unit, str) or not UNIT_NAME.fullmatch(unit.strip()):
        raise ValueError("请输入有效的 systemd 服务单元名，如 example.service。")
    unit = unit.strip()
    syscall = _as_choice(options, "syscalls", ("inherit", "baseline", "service"))
    filesystem = _as_choice(options, "filesystem", ("inherit", "full", "strict"))
    network = _as_choice(options, "network", ("inherit", "unix", "ip"))
    writable = _paths(options.get("writablePaths", ""))
    inaccessible = _paths(options.get("inaccessiblePaths", ""))
    if any(a == b or a.startswith(b + "/") or b.startswith(a + "/") for a in writable for b in inaccessible):
        raise ValueError("可写路径和隔离路径有重叠，请分开配置。")
    if writable and filesystem == "inherit":
        raise ValueError("设置可写例外时，请选择文件系统保护级别。")

    rules = []
    if syscall == "baseline":
        rules.append(("SystemCallFilter=~@mount @module @raw-io @reboot @swap @debug",
                      "限制挂载、内核模块、原始硬件访问、重启、交换空间及调试相关调用。"))
    elif syscall == "service":
        rules.append(("SystemCallFilter=@system-service", "采用 systemd 的常规服务调用白名单。"))
    if syscall != "inherit":
        rules.append(("SystemCallErrorNumber=EPERM", "拒绝的调用向程序返回权限错误。"))
    if filesystem != "inherit":
        explanation = "将系统目录设为只读。" if filesystem == "full" else "将文件系统视图设为只读，使用可写例外保留业务写入。"
        rules.append((f"ProtectSystem={filesystem}", explanation))
    if writable:
        rules.append(("ReadWritePaths=" + " ".join(writable), "允许服务写入列出的业务路径，仍受文件权限约束。"))
    if inaccessible:
        rules.append(("InaccessiblePaths=" + " ".join(inaccessible), "隐藏列出的路径。"))
    if network != "inherit":
        families = "AF_UNIX" if network == "unix" else "AF_UNIX AF_INET AF_INET6"
        rules.append((f"RestrictAddressFamilies={families}", "限制服务能够自行创建的套接字地址族。"))
    for key, directive, reason in BOOL_POLICIES:
        value = options.get(key, False)
        if type(value) is not bool:
            raise ValueError("请检查防护开关。")
        if value:
            rules.append((directive, reason))
    if not rules:
        raise ValueError("请至少选择一项防护措施。")

    warnings = ["应用前核对现有服务配置、目标 systemd 版本和内核支持，并在测试环境验证服务行为。"]
    if filesystem == "strict" and not writable:
        warnings.append("严格只读模式下，需要落盘的服务须配置相应的可写例外。")
    if syscall == "service":
        warnings.append("系统调用白名单使用目标主机的内置分组，验证启动、请求处理和关闭流程。")
    if network == "unix":
        warnings.append("仅 Unix 套接字适合本地域服务。TCP/UDP 服务应选择允许 IP。")
    if options.get("denyWritableExecute"):
        warnings.append("启用内存执行限制后，使用 JIT 或可执行栈的程序可能无法启动。")
    return {
        "unit": unit,
        "target": f"/etc/systemd/system/{unit}.d/{DROP_IN}",
        "text": "\n".join(("[Service]", *(directive for directive, _ in rules))) + "\n",
        "rules": [{"directive": directive, "effect": reason} for directive, reason in rules],
        "warnings": warnings,
    }


def save_policy(options, destination):
    destination = Path(destination)
    if destination.suffix.lower() != ".conf":
        raise ValueError("请使用 .conf 扩展名保存服务防护策略。")
    policy = build_policy(options)
    staged = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=destination.parent, suffix=".part", delete=False,
        ) as stream:
            staged = Path(stream.name)
            stream.write(policy["text"])
        os.replace(staged, destination)
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)
    return str(destination)


def _dynamic_entries(elf, stream, segment, size):
    if segment is None:
        return {}
    offset, length = segment["p_offset"], segment["p_filesz"]
    width = elf.structs.Elf_Dyn.sizeof()
    if offset + length > size or length // width > 4096 or length % width:
        raise ValueError("ELF 动态段损坏或超过体检范围。")
    stream.seek(offset)
    entries = {}
    for _ in range(length // width):
        entry = elf.structs.Elf_Dyn.parse(stream.read(width))
        if entry.d_tag == "DT_NULL":
            break
        entries[entry.d_tag] = entry.d_val
    return entries


def inspect_elf(path):
    if not isinstance(path, str) or not path.strip() or "\x00" in path:
        raise ValueError("请选择本地 ELF 文件。")
    file = Path(path).resolve()
    if not file.is_file():
        raise ValueError("请选择有效的本地文件。")
    with file.open("rb") as stream:
        initial = os.fstat(stream.fileno())
        size = initial.st_size
        if size > MAX_ELF_SIZE:
            raise ValueError("ELF 体检支持 128 MiB 以内的文件。")
        try:
            elf = ELFFile(stream)
            if elf.num_segments() > 4096 or elf.num_sections() > 65536:
                raise ValueError("ELF 文件的段表或节表超过体检范围。")
            segments = list(elf.iter_segments())
            types = {segment["p_type"] for segment in segments}
            stack = next((seg for seg in segments if seg["p_type"] == "PT_GNU_STACK"), None)
            dynamic = next((seg for seg in segments if seg["p_type"] == "PT_DYNAMIC"), None)
            tags = _dynamic_entries(elf, stream, dynamic, size)
            flags = tags.get("DT_FLAGS", 0)
            flags1 = tags.get("DT_FLAGS_1", 0)
            symbols = set()
            for name in (".dynsym", ".symtab"):
                section = elf.get_section_by_name(name)
                if section is not None and hasattr(section, "iter_symbols") and section.num_symbols() <= 200000:
                    symbols.update(symbol.name for symbol in section.iter_symbols() if symbol.name.endswith("_chk")
                                   or symbol.name in ("__stack_chk_fail", "__stack_chk_fail_local"))
        except (ELFError, OSError, IndexError, KeyError, TypeError) as exc:
            raise ValueError("无法解析 ELF 文件，请检查文件格式或是否完整。") from exc

        kind = elf.header["e_type"]
        nx = "unknown" if stack is None else "off" if stack["p_flags"] & 1 else "on"
        relro = "off"
        if "PT_GNU_RELRO" in types:
            if dynamic is None:
                relro = "present"
            else:
                relro = "full" if "DT_BIND_NOW" in tags or flags & 8 or flags1 & 1 else "partial"
        pie = "unknown"
        if kind == "ET_EXEC":
            pie = "off"
        elif kind == "ET_DYN" and ("PT_INTERP" in types or flags1 & 0x08000000):
            pie = "on"

        stream.seek(0)
        digest = hashlib.sha256()
        remaining = size
        while remaining:
            chunk = stream.read(min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError("体检期间 ELF 文件发生变化，请重试。")
            digest.update(chunk)
            remaining -= len(chunk)
        current = os.fstat(stream.fileno())
        if (current.st_size, current.st_mtime_ns) != (size, initial.st_mtime_ns):
            raise ValueError("体检期间 ELF 文件发生变化，请重试。")
        return {
            "path": str(file), "size": size, "sha256": digest.hexdigest(),
            "machine": elf.header["e_machine"], "kind": kind, "bits": elf.elfclass,
            "endian": "little" if elf.little_endian else "big", "dynamic": dynamic is not None,
            "loadable": "PT_LOAD" in types,
            "nx": nx, "relro": relro, "pie": pie,
            "canary": bool({"__stack_chk_fail", "__stack_chk_fail_local"} & symbols),
            "fortify": any(name.endswith("_chk") for name in symbols),
        }
