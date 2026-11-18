import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from defence import attacker_tools
from desktop_api import DesktopService


class DesktopAttackerTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        root = Path(self.folder.name)
        with (
            patch("desktop_api.get_runtime_dir", side_effect=lambda sub=None: root / "tmp" / sub if sub else root / "tmp"),
            patch("desktop_api.get_app_dir", return_value=root),
            patch("desktop_api.waf_manager.list_local_request_logs", return_value=[]),
        ):
            self.service = DesktopService()
        self.addCleanup(self.service.shutdown)

    def wait_for_job(self):
        deadline = time.monotonic() + 3
        while self.service.snapshot()["job"] and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertIsNone(self.service.snapshot()["job"])

    def test_load_targets_and_detect_shell(self):
        target_file = Path(self.folder.name) / "targets.txt"
        target_file.write_text("example.test\n# ignored\nhttp://example.test/\n", encoding="utf-8")

        result = self.service.action("attack-read", {"outputFile": str(target_file)})
        self.assertTrue(result["ok"])
        self.wait_for_job()
        self.assertEqual(self.service.snapshot()["attacker"]["activeCount"], 1)

        found = attacker_tools.BackdoorShell(
            number=-1, urls=["http://example.test/shell.php"],
            cmd_method="POST", payload="cmd", note="known",
        )
        with patch.object(attacker_tools, "check_known_backdoor", return_value=found) as check:
            result = self.service.action("attack-check", {
                "path": "shell.php", "keyMethod": "0", "key": "", "keyValue": "",
                "cmdMethod": "POST", "payload": "cmd",
            })
            self.assertTrue(result["ok"])
            self.wait_for_job()
            check.assert_called_once()

        snapshot = self.service.snapshot()
        self.assertEqual(snapshot["attacker"]["shells"][0]["number"], 0)
        self.assertEqual(snapshot["attacker"]["shells"][0]["urlCount"], 1)
        self.assertTrue(any(event["area"] == "attack" for event in snapshot["events"]))

    def test_execute_and_upload_persist_session(self):
        source = self.service._attacker.add_shell(attacker_tools.BackdoorShell(
            number=-1, urls=["http://example.test/shell.php"],
            cmd_method="POST", payload="cmd", note="known",
        ))
        with patch.object(attacker_tools, "execute_shell_command", return_value=[]) as execute:
            result = self.service.action("attack-exec", {"shellNumber": source.number, "command": "system('id');"})
            self.assertTrue(result["ok"])
            self.wait_for_job()
            execute.assert_called_once()

        unconfirmed = self.service.action("attack-upload", {
            "shellNumber": source.number, "remoteDir": "/var/www/html/", "urlDir": "/",
            "withKey": True,
        })
        self.assertFalse(unconfirmed["ok"])
        self.assertIn("确认", unconfirmed["message"])

        generated = attacker_tools.BackdoorShell(
            number=-1, urls=["http://example.test/.new.php"], key_method="POST",
            key="pass", key_value="value", cmd_method="POST", payload="payload", note="generated-key",
        )
        with patch.object(attacker_tools, "upload_generated_backdoor", return_value=generated):
            result = self.service.action("attack-upload", {
                "shellNumber": source.number, "remoteDir": "/var/www/html/", "urlDir": "/",
                "withKey": True, "confirmed": True,
            })
            self.assertTrue(result["ok"])
            self.wait_for_job()

        snapshot = self.service.snapshot()
        self.assertEqual(len(snapshot["attacker"]["shells"]), 2)
        saved = attacker_tools.load_session(self.service._attacker_store)
        self.assertEqual(len(saved.known_shells), 2)
        self.assertEqual(saved.known_shells[1].payload, "payload")

    def test_attack_input_validation(self):
        invalid_scan = self.service.action("attack-scan", {
            "urlPattern": "http://example.test/", "start": 0, "end": 255,
            "outputFile": str(Path(self.folder.name) / "targets.txt"),
        })
        self.assertFalse(invalid_scan["ok"])
        self.assertIn("?", invalid_scan["message"])

        invalid_check = self.service.action("attack-check", {
            "path": "shell.php", "keyMethod": "BAD", "cmdMethod": "POST", "payload": "cmd",
        })
        self.assertFalse(invalid_check["ok"])
        self.assertIn("key 方式", invalid_check["message"])

        missing_shell = self.service.action("attack-exec", {"shellNumber": 99, "command": "id"})
        self.assertFalse(missing_shell["ok"])
        self.assertIn("不存在", missing_shell["message"])
    def test_attack_urls_query(self):
        target_file = Path(self.folder.name) / "targets.txt"
        target_file.write_text("http://a.test/\nhttp://b.test/\n", encoding="utf-8")

        result = self.service.action("attack-read", {"outputFile": str(target_file)})
        self.assertTrue(result["ok"])
        self.wait_for_job()

        active = self.service.attack_urls()
        self.assertEqual(active["total"], 2)
        self.assertEqual(active["items"], ["http://a.test/", "http://b.test/"])
        self.assertEqual(self.service.attack_urls("active", None)["total"], 2)

        shell = self.service._attacker.add_shell(attacker_tools.BackdoorShell(
            number=-1, urls=["http://a.test/shell.php"],
            cmd_method="POST", payload="cmd", note="known",
        ))
        found = self.service.attack_urls("shell", shell.number)
        self.assertEqual(found["total"], 1)
        self.assertEqual(found["items"], ["http://a.test/shell.php"])

        with self.assertRaises(ValueError):
            self.service.attack_urls("shell", 99)
        with self.assertRaises(ValueError):
            self.service.attack_urls("unknown")



if __name__ == "__main__":
    unittest.main()
