import io
import json
import stat
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from defence import scan_removal
from desktop_api import DesktopService


class ScanRemovalTest(unittest.TestCase):
    def setUp(self):
        runtime = tempfile.TemporaryDirectory()
        self.addCleanup(runtime.cleanup)
        self.root = Path(runtime.name)
        self.site = self.root / "site"
        self.site.mkdir()
        self.file = self.site / "example.php"
        self.file.write_bytes(b"sample")
        self.result = {"file": str(self.file), "level": 3, "verdict": "malicious", "score": 300, "type": "PHP"}
        self.backups = self.root / "quarantine"
        paths = patch.object(scan_removal, "get_runtime_dir", return_value=self.backups)
        paths.start()
        self.addCleanup(paths.stop)

    def test_scan_requires_confirmation_and_exposes_removal_and_report(self):
        with patch("desktop_api.waf_manager.list_local_request_logs", return_value=[]):
            service = DesktopService()
        self.addCleanup(service.shutdown)
        form = {"mode": "local", "target": str(self.site), "threshold": 250, "autoDelete": True}
        self.assertFalse(service.action("scan", form)["ok"])
        self.assertTrue(self.file.exists())
        suspected = {**self.result, "file": str(self.site / "other.php"), "level": 2, "verdict": "suspicious"}
        Path(suspected["file"]).touch()
        with patch("desktop_api.webshell_scanner.scan_local", return_value=([self.result, suspected], 2)), \
                patch.object(scan_removal, "analyze_bytes", return_value={"level": 3}) as review:
            self.assertTrue(service.action("scan", {**form, "confirmed": True})["ok"])
            self.wait_idle(service)
            review.assert_called_once_with(b"sample", str(self.file), 250)
        scan = service.snapshot()["scan"]
        self.assertEqual((scan["removed"], scan["removalFailed"]), (1, 0))
        self.assertFalse(self.file.exists())
        self.assertTrue(Path(suspected["file"]).exists())
        folder = Path(scan["quarantineDir"])
        record = json.loads((folder / "restore.jsonl").read_text(encoding="utf-8"))
        self.assertEqual((folder / record["backup"]).read_bytes(), b"sample")
        self.assertEqual(Path(record["path"]), self.file.resolve())
        self.assertTrue(service.scan_results(0)["items"][0]["removed"])
        self.assertFalse(service.action("plan-quarantine", {})["ok"])
        with patch("desktop_api.webshell_scanner.save_report", return_value=str(self.root / "report.txt")) as save:
            self.assertTrue(service.action("report", {})["ok"])
            self.wait_idle(service)
            self.assertEqual(save.call_args.kwargs["threshold"], 250)
        self.assertTrue(service.snapshot()["scan"]["reportPath"].endswith("report.txt"))

    def test_recheck_preserves_changed_and_out_of_scope_files(self):
        outside = self.root / "outside.php"
        outside.write_bytes(b"sample")

        def changed_review(*_args):
            self.file.write_bytes(b"changed")
            return {"level": 3}

        with patch.object(scan_removal, "analyze_bytes", side_effect=changed_review):
            removed, failed, _ = scan_removal.remove_malicious(
                [self.result, {**self.result, "file": str(outside)}], self.site, 250, Mock(),
            )
        self.assertEqual((removed, failed), (set(), 2))
        self.assertEqual(self.file.read_bytes(), b"changed")
        self.assertTrue(outside.exists())

    def test_remote_remove_happens_only_after_complete_backup(self):
        sftp = Mock()
        sftp.normalize.side_effect = lambda path: path
        sftp.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG, st_size=6, st_mtime=1)
        sftp.open.side_effect = lambda *_args: io.BytesIO(b"sample")
        path = "/test/site/example.php"
        host = {"host": "example.test", "port": 22, "user": "operator"}

        def confirmed_remove(file):
            self.assertEqual(file, path)
            backup, = self.backups.glob("scan-*/*.bak")
            self.assertEqual(backup.read_bytes(), b"sample")
            record = json.loads((backup.parent / "restore.jsonl").read_text(encoding="utf-8"))
            self.assertEqual(record["host"], host)

        sftp.remove.side_effect = confirmed_remove
        with patch.object(scan_removal, "analyze_bytes", return_value={"level": 3}):
            removed, failed, _ = scan_removal.remove_malicious(
                [{**self.result, "file": path}], "/test/site", 250, Mock(), sftp=sftp, host=host,
            )
        self.assertEqual((removed, failed), ({path}, 0))
        sftp.remove.assert_called_once_with(path)

    def wait_idle(self, service):
        deadline = time.monotonic() + 3
        while service.snapshot()["job"] is not None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertIsNone(service.snapshot()["job"])
