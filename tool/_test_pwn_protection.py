import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from defence import pwn_bundle
from defence.pwn_protection import build_policy, inspect_elf, save_policy


class PwnProtectionTest(unittest.TestCase):
    def test_sandbox_presets_reference_supported_launch_rules(self):
        catalog = pwn_bundle.bundle_profiles()
        groups = {group["id"]: set(group["syscalls"]) for group in catalog["groups"]}
        presets = {preset["id"]: {call for group in preset["groups"] for call in groups[group]}
                   for preset in catalog["presets"]}
        self.assertEqual(set(presets), {"sandbox1", "sandbox2", "sandbox3"})
        self.assertLess(presets["sandbox1"], presets["sandbox2"])
        self.assertLess(presets["sandbox1"], presets["sandbox3"])
        self.assertTrue({"ptrace", "open_by_handle_at", "rename"} <= presets["sandbox2"])
        self.assertTrue({"socket", "listen", "clone"} <= presets["sandbox3"])
        for calls in presets.values():
            self.assertFalse({"execve", "open", "openat", "mmap"} & calls)

    def test_elf_bundle_exports_unchanged_program_and_selected_policy(self):
        header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)
        program_header = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 120, 120, 4096)
        raw = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8) + header + program_header
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "fixture.elf"
            source.write_bytes(raw)
            runner = Path(folder) / "fake-runner"
            runner.write_bytes(b"runner fixture")
            with patch.object(pwn_bundle, "_runner_path", return_value=runner):
                with self.assertRaises(ValueError):
                    pwn_bundle.preview_bundle(str(source), ["arbitrary"])
                output = pwn_bundle.export_bundle(str(source), ["debug", "connect"], folder)
            contents = Path(output["directory"])
            self.assertEqual((contents / "program.elf").read_bytes(), raw)
            self.assertEqual(source.read_bytes(), raw)
            self.assertEqual((contents / "run-hardened").read_bytes(), b"runner fixture")
            policy = json.loads((contents / "policy.json").read_text(encoding="utf-8"))
            self.assertEqual(policy["programSha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(policy["groups"], ["debug", "connect"])
            self.assertIn("ptrace", output["syscalls"])
            self.assertIn("connect", output["syscalls"])

    def test_policy_generates_explained_rules_and_matching_export(self):
        options = {
            "unit": "demo@one.service",
            "syscalls": "baseline",
            "filesystem": "strict",
            "network": "ip",
            "writablePaths": "/var/lib/demo\n/var/lib/demo",
            "inaccessiblePaths": "/srv/private",
            "nativeAbi": True,
            "noNewPrivileges": True,
        }
        plan = build_policy(options)
        self.assertEqual(plan["target"], "/etc/systemd/system/demo@one.service.d/90-metaawd-pwn.conf")
        self.assertEqual(plan["text"].splitlines(), ["[Service]", *(row["directive"] for row in plan["rules"])])
        self.assertIn("SystemCallFilter=~@mount", plan["text"])
        self.assertIn("ReadWritePaths=/var/lib/demo\n", plan["text"])
        self.assertIn("InaccessiblePaths=/srv/private\n", plan["text"])
        self.assertIn("SystemCallArchitectures=native\n", plan["text"])
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "policy.conf"
            self.assertEqual(save_policy(options, output), str(output))
            self.assertEqual(output.read_bytes(), plan["text"].encode())

    def test_rejects_directive_injection_and_conflicting_paths(self):
        for overrides in (
            {"unit": "../demo.service"},
            {"writablePaths": "/var/lib/demo\nExecStart=/other"},
            {"writablePaths": "/var/lib/demo/../other"},
            {"writablePaths": "/var/lib/demo", "inaccessiblePaths": "/var/lib/demo/private"},
            {"syscalls": "custom"},
            {"nativeAbi": "yes"},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                build_policy({"unit": "demo.service", "filesystem": "strict", **overrides})

    def test_audits_synthetic_elf_header_and_sha256_without_running_it(self):
        ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
        header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)
        stack = struct.pack("<IIQQQQQQ", 0x6474e551, 6, 0, 0, 0, 0, 0, 16)
        raw = ident + header + stack
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "fixture"
            file.write_bytes(raw)
            evidence = inspect_elf(str(file))
            self.assertEqual((evidence["bits"], evidence["machine"], evidence["kind"]), (64, "EM_X86_64", "ET_EXEC"))
            self.assertEqual((evidence["nx"], evidence["pie"], evidence["relro"]), ("on", "off", "off"))
            self.assertEqual(evidence["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertFalse(evidence["canary"])
            self.assertEqual(file.read_bytes(), raw)
            file.write_bytes(b"truncated")
            with self.assertRaisesRegex(ValueError, "无法解析 ELF"):
                inspect_elf(str(file))
