"""Back up and remove files selected by a confirmed desktop scan."""

import json
import os
import posixpath
import stat
import tempfile
from pathlib import Path

from paramiko import SSHException

from defence._bootstrap import get_runtime_dir
from defence.webshell_scanner import MAX_REMOTE_FILE_SIZE, PIC_EXT, PIC_HEAD_BYTES, analyze_bytes


def _file_identity(path, scope, sftp):
    if sftp is None:
        resolved = Path(path).resolve()
        if not resolved.is_relative_to(scope):
            raise ValueError("路径超出扫描范围")
        info = Path(path).lstat()
        attributes = (info.st_dev, info.st_ino, info.st_ctime_ns, info.st_mtime_ns)
    else:
        resolved = sftp.normalize(path)
        if posixpath.commonpath((scope, resolved)) != scope:
            raise ValueError("路径超出扫描范围")
        info = sftp.lstat(path)
        attributes = (info.st_mtime,)
    if info.st_mode is None or info.st_size is None or not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REMOTE_FILE_SIZE:
        raise ValueError("仅自动处理可完整备份的普通文件")
    return resolved, info.st_size, *attributes


def _read(path, sftp):
    opener = open if sftp is None else sftp.open
    with opener(path, "rb") as stream:
        return stream.read(MAX_REMOTE_FILE_SIZE + 1)


def remove_malicious(results, target, threshold, log_callback, *, sftp=None, host=None):
    removed = set()
    failed = 0
    directory = None
    candidates = [result["file"] for result in results if result.get("level") == 3]
    if not candidates:
        return removed, failed, directory
    scope = Path(target).resolve() if sftp is None else sftp.normalize(target)
    for index, path in enumerate(dict.fromkeys(candidates), 1):
        try:
            identity = _file_identity(path, scope, sftp)
            raw = _read(path, sftp)
            limit = PIC_HEAD_BYTES if Path(path).suffix.lower() in PIC_EXT else MAX_REMOTE_FILE_SIZE
            current = analyze_bytes(raw[:limit], path, threshold)
            if len(raw) != identity[1] or not current or current.get("level") != 3:
                raise ValueError("文件已变化或复核未达到恶意阈值")
            if directory is None:
                root = get_runtime_dir("scan-quarantine")
                root.mkdir(parents=True, exist_ok=True)
                directory = Path(tempfile.mkdtemp(prefix="scan-", dir=root))
            backup = directory / f"{index:05d}.bak"
            backup.write_bytes(raw)
            record = {"path": str(identity[0]), "backup": backup.name, "host": host}
            with (directory / "restore.jsonl").open("a", encoding="utf-8") as manifest:
                manifest.write(json.dumps(record, ensure_ascii=False) + "\n")
            if _file_identity(path, scope, sftp) != identity or _read(path, sftp) != raw:
                raise ValueError("备份期间文件发生变化")
            if sftp is None:
                os.unlink(path)
            else:
                sftp.remove(path)
            removed.add(path)
            log_callback(f"已备份并移除 · {path}")
        except (OSError, ValueError, EOFError, SSHException) as exc:
            failed += 1
            log_callback(f"跳过或未确认移除 · {path} · {exc}")
    return removed, failed, str(directory) if directory is not None else None
