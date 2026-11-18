"""Export a visible, three-file Linux ELF protection bundle."""

import hashlib
import json
import shutil
import tempfile
from pathlib import Path

from defence._bootstrap import get_resource_dir
from defence.pwn_protection import MAX_ELF_SIZE, inspect_elf

RUNNER = "run-hardened"
PROGRAM = "program.elf"
POLICY = "policy.json"
PRESETS = (
    {"id": "sandbox1", "label": "Sandbox 1 · 基础防护", "groups": ["kernel", "debug"],
     "description": "限制挂载、内核管理和跨进程调试，适合先验证基本业务流程。"},
    {"id": "sandbox2", "label": "Sandbox 2 · 文件保护",
     "groups": ["kernel", "debug", "file-handle", "file-mutation"],
     "description": "增加文件句柄、删除和重命名限制。依赖原子写入或日志轮转的服务需验证。"},
    {"id": "sandbox3", "label": "Sandbox 3 · 网络与派生限制",
     "groups": ["kernel", "debug", "socket-setup", "new-tasks"],
     "description": "限制建立套接字、监听及创建进程和线程。服务自行监听端口或开启线程时需调整。"},
)


def _runner_path():
    return get_resource_dir() / "build" / "elf-runner" / RUNNER


def _profiles():
    path = get_resource_dir() / "defence" / "elf_runner" / "profiles.json"
    return json.loads(path.read_text(encoding="utf-8"))


def bundle_profiles():
    return {
        "runnerReady": _runner_path().is_file(),
        "groups": [{**profile, "syscalls": list(profile["syscalls"])} for profile in _profiles()],
        "presets": PRESETS,
    }


def preview_bundle(path, groups):
    if not isinstance(groups, list) or not groups or not all(isinstance(group, str) for group in groups):
        raise ValueError("请选择至少一组系统调用限制。")
    known = {profile["id"]: profile for profile in _profiles()}
    selected = list(dict.fromkeys(groups))
    if len(groups) > len(known) or any(group not in known for group in selected):
        raise ValueError("存在未知的系统调用限制组。")
    audit = inspect_elf(path)
    if not (
        audit["bits"] == 64 and audit["machine"] == "EM_X86_64" and audit["endian"] == "little"
        and audit["loadable"] and (audit["kind"] == "ET_EXEC" or audit["pie"] == "on")
    ):
        raise ValueError("加固副本支持 Linux x86-64 可执行 ELF，包括 PIE。")
    syscalls = sorted({name for group in selected for name in known[group]["syscalls"]})
    return {
        "source": audit["path"], "size": audit["size"], "sha256": audit["sha256"],
        "groups": selected, "syscalls": syscalls, "files": [RUNNER, PROGRAM, POLICY],
    }


def export_bundle(path, groups, parent):
    preview = preview_bundle(path, groups)
    runner = _runner_path()
    if not runner.is_file():
        raise ValueError("缺少 Linux 启动器，请使用已打包版本或按维护说明构建启动器。")
    directory = Path(tempfile.mkdtemp(prefix="metaawd-pwn-", dir=Path(parent)))
    try:
        program = directory / PROGRAM
        remaining = MAX_ELF_SIZE + 1
        checksum = hashlib.sha256()
        with Path(preview["source"]).open("rb") as original, program.open("xb") as output:
            while remaining:
                block = original.read(min(remaining, 1024 * 1024))
                if not block:
                    break
                remaining -= len(block)
                checksum.update(block)
                output.write(block)
        if not remaining or checksum.hexdigest() != preview["sha256"]:
            raise ValueError("导出期间输入文件发生变化，请重新选择。")
        (directory / POLICY).write_text(json.dumps({
            "version": 1, "programSha256": preview["sha256"], "groups": preview["groups"],
        }, indent=2) + "\n", encoding="utf-8")
        shutil.copyfile(runner, directory / RUNNER)
        for executable in (directory / RUNNER, program):
            executable.chmod(0o755)
    except (OSError, ValueError):
        for name in preview["files"]:
            (directory / name).unlink(missing_ok=True)
        directory.rmdir()
        raise
    return {**preview, "directory": str(directory)}
