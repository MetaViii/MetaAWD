import json
import tempfile
import unittest
from pathlib import Path

from defence.pwn_forward import build_forward_plan, export_forward_bundle


class PwnForwardTest(unittest.TestCase):
    def options(self, mode="catch", **overrides):
        values = {
            "mode": mode,
            "architecture": 64,
            "logEnabled": True,
            "logPath": "/tmp/.metaawd-pwn",
            "logPermissions": "0770",
            "compiler": "gcc",
            "optimization": "2",
            "staticLink": True,
            "stripBinary": True,
            "extraWarnings": True,
            "serviceName": "metaawd-pwn",
            "servicePath": "/pwn",
            "backupPath": "/opt/metaawd-backup/pwn.original",
            "serviceUser": "pwn",
            "serviceGroup": "pwn",
            "listenAddress": "0.0.0.0",
            "listenPort": 10000,
            "perSource": 10,
            "instances": 128,
            "cpuLimit": 20,
            "memoryLimitMb": 256,
            "forwardHost": "192.0.2.10",
            "forwardPort": 20000,
            "targets": "192.0.2.10:20000\n192.0.2.11:20001",
            "installXinetd": True,
            "restartMethod": "systemctl",
        }
        values.update(overrides)
        return values

    def test_all_four_modes_have_matching_build_targets(self):
        expected = {
            "catch": "catch",
            "i0gan": "i0gan",
            "forward": "forward",
            "forward_multi": "forward_multi",
        }
        for mode, binary in expected.items():
            with self.subTest(mode=mode):
                plan = build_forward_plan(self.options(mode))
                self.assertEqual(plan["binary"], binary)
                self.assertEqual(plan["buildCommand"], f"make {binary}")
                for target in expected.values():
                    self.assertIn(f"{target}:", plan["makefile"])
                self.assertIn("server = /pwn", plan["xinetd"])
                self.assertNotIn("config", plan)

    def test_mode_specific_parameters_are_rendered(self):
        forward = build_forward_plan(self.options("forward", architecture=32, staticLink=False))
        self.assertIn("FORWARD_IP := 192.0.2.10", forward["makefile"])
        self.assertIn("FORWARD_PORT := 20000", forward["makefile"])
        self.assertIn("ORIGINAL_PATH := /opt/metaawd-backup/pwn.original", forward["makefile"])
        self.assertIn("-m32", forward["makefile"])
        self.assertNotIn("-static", forward["makefile"])
        self.assertEqual(forward["targetCount"], 1)

        multi = build_forward_plan(self.options(
            "forward_multi",
            targets="# pool\n192.0.2.10:20000\n\n192.0.2.10:20000\n192.0.2.11:20001",
        ))
        self.assertEqual(multi["targetCount"], 2)
        self.assertIn("hosts.txt", multi["files"])

    def test_export_contains_sources_deployment_and_normalized_hosts(self):
        options = self.options(
            "forward_multi",
            targets="192.0.2.10:020000\n192.0.2.10:20000\n192.0.2.11:20001",
        )
        with tempfile.TemporaryDirectory() as folder:
            result = export_forward_bundle(options, folder)
            output = Path(result["directory"])
            self.assertEqual(output.parent, Path(folder))
            for name in (
                "Makefile", "deploy.sh", "rollback.sh", "README.txt", "policy.json",
                "hosts.txt", "LICENSE", "src/waf.c", "src/waf.h", "src/logger.c", "src/logger.h",
            ):
                self.assertTrue((output / name).is_file(), name)
            self.assertEqual(
                (output / "hosts.txt").read_text(encoding="ascii"),
                "192.0.2.10:20000\n192.0.2.11:20001\n",
            )
            deploy = (output / "deploy.sh").read_text(encoding="utf-8")
            self.assertIn("install -m 0640 -o \"$SERVICE_USER\"", deploy)
            self.assertIn("systemctl restart xinetd", deploy)
            self.assertIn('XINETD_ABSENT="$BACKUP_PATH.xinetd.absent"', deploy)
            self.assertIn('[ ! -f "$XINETD_BACKUP" ] && [ ! -f "$XINETD_ABSENT" ]', deploy)
            rollback = (output / "rollback.sh").read_text(encoding="utf-8")
            self.assertIn("未找到 xinetd 原配置记录，保留当前配置。", rollback)
            policy = json.loads((output / "policy.json").read_text(encoding="utf-8"))
            self.assertEqual(policy["mode"], "forward_multi")
            self.assertEqual(policy["options"]["targets"], ["192.0.2.10:20000", "192.0.2.11:20001"])

    def test_catch_export_uses_root_managed_original(self):
        with tempfile.TemporaryDirectory() as folder:
            result = export_forward_bundle(self.options("catch"), folder)
            output = Path(result["directory"])
            deploy = (output / "deploy.sh").read_text(encoding="utf-8")
            self.assertIn('chown root:"$SERVICE_GROUP" "$BACKUP_TMP"', deploy)
            self.assertIn('chmod 0550 "$BACKUP_TMP"', deploy)
            self.assertNotIn('"/tmp/.metaawd-pwn/pwn"', deploy)
            rollback = (output / "rollback.sh").read_text(encoding="utf-8")
            self.assertIn('chown "$ORIGINAL_UID:$ORIGINAL_GID" "$SERVICE_PATH"', rollback)
            self.assertIn('chmod "$ORIGINAL_MODE" "$SERVICE_PATH"', rollback)

    def test_rejects_invalid_or_injected_parameters(self):
        invalid = (
            {"mode": "other"},
            {"architecture": 16},
            {"logPath": "/tmp/waf\nBAD=1"},
            {"servicePath": "relative/pwn"},
            {"serviceName": "bad name"},
            {"listenAddress": "localhost"},
            {"listenPort": None},
            {"logPath": "//tmp/waf"},
            {"backupPath": "/tmp/.metaawd-pwn"},
            {"backupPath": "/tmp/.metaawd-pwn/original"},
            {"mode": "forward", "forwardHost": "127.0.0.1", "listenAddress": "0.0.0.0", "forwardPort": 10000},
            {"mode": "forward", "forwardHost": "127.0.0.1", "listenAddress": "127.0.0.1", "forwardPort": 10000},
        )
        for overrides in invalid:
            options = self.options("catch")
            options.update(overrides)
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                build_forward_plan(options)

        for targets in ("", "hostname:20000", "192.0.2.1:0", "192.0.2.1:70000", "192.0.2.1"):
            with self.subTest(targets=targets), self.assertRaises(ValueError):
                build_forward_plan(self.options("forward_multi", targets=targets))
        with self.assertRaisesRegex(ValueError, "转发环路"):
            build_forward_plan(self.options(
                "forward_multi", listenPort=20000,
                targets="127.0.0.1:20000\n192.0.2.11:20001",
            ))


if __name__ == "__main__":
    unittest.main()
