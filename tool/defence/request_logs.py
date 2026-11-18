"""Read WAF capture files and older logs that contain plain HTTP."""

import io
import ipaddress
import json
import os
import re
import shutil
import tempfile
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

CAPTURE_PREFIX = b"# MetaAWD-HTTP/1 "
PREVIEW_BYTES = 64 * 1024
PREFACE_LIMIT = 4096
REQUEST_LINE_LIMIT = 16 * 1024
REQUEST_LINE = re.compile(r"(\S+) (.+) HTTP/\d+(?:\.\d+)?")
HIT_DECISIONS = ("matched", "redirected", "terminated")
DECISIONS = ("observed", *HIT_DECISIONS)
BODY_STATES = ("captured", "empty", "unavailable")
MATCH_AREAS = ("get", "post", "headers", "raw_body", "files")


@contextmanager
def _open_request(path):
    with Path(path).open("rb") as stream:
        first_line = stream.readline(PREFACE_LIMIT + 1)
        metadata = {}
        if first_line.startswith(CAPTURE_PREFIX) and first_line.endswith(b"\n"):
            try:
                value = json.loads(first_line[len(CAPTURE_PREFIX):])
                if isinstance(value, dict):
                    metadata = value
            except (ValueError, RecursionError):
                pass
        else:
            stream.seek(0)
        yield stream, metadata


@lru_cache(maxsize=4096)
def summarize_request(path, _revision):
    """Read an entry's metadata and request line. The stat revision invalidates the cache."""
    with _open_request(path) as (stream, metadata):
        line = stream.readline(REQUEST_LINE_LIMIT).decode("utf-8", errors="replace").rstrip("\r\n")
    match = REQUEST_LINE.fullmatch(line)
    captured_at = metadata.get("captured_at")
    if type(captured_at) not in (int, float) or not 0 < captured_at < 253402300800:
        captured_at = None
    peer = metadata.get("peer_ip")
    if isinstance(peer, str) and len(peer) <= 64:
        try:
            peer = str(ipaddress.ip_address(peer))
        except ValueError:
            peer = None
    else:
        peer = None
    decision = metadata.get("decision")
    body_state = metadata.get("body_state")
    areas = metadata.get("matched_areas")
    target = match[2] if match else None
    if target and len(target) > 2048:
        target = target[:2048] + "…"
    return {
        "method": match[1][:32] if match else None,
        "target": target,
        "capturedAt": captured_at,
        "peer": peer,
        "decision": decision if decision in DECISIONS else "unknown",
        "bodyState": body_state if body_state in BODY_STATES else "unknown",
        "matchedAreas": [area for area in MATCH_AREAS if area in areas] if isinstance(areas, list) else [],
    }


def read_request_preview(path):
    with _open_request(path) as (stream, _metadata):
        sample = stream.read(PREVIEW_BYTES + 1)
    truncated = len(sample) > PREVIEW_BYTES
    data = sample[:PREVIEW_BYTES]
    try:
        text = data.decode("utf-8")
        has_binary = b"\x00" in data
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
        has_binary = True
    return {"text": text, "truncated": truncated, "hasBinary": has_binary}


def read_request_text(path):
    """Keep the existing text interface used by the Tkinter log viewer."""
    with _open_request(path) as (stream, _metadata):
        with io.TextIOWrapper(stream, encoding="utf-8", errors="replace") as text:
            return text.read()


def export_request(path, destination):
    destination = Path(destination)
    if Path(path).resolve() == destination.resolve():
        raise ValueError("请选择不同于采集日志的保存位置。")
    staging = None
    try:
        with _open_request(path) as (source, _metadata):
            with tempfile.NamedTemporaryFile(dir=destination.parent, suffix=".part", delete=False) as target:
                staging = Path(target.name)
                shutil.copyfileobj(source, target)
        os.replace(staging, destination)
    finally:
        if staging is not None:
            staging.unlink(missing_ok=True)
