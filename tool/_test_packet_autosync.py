import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from stat import S_IFREG
from types import SimpleNamespace
from unittest.mock import Mock, patch

import desktop_api
from defence import request_logs, ssh, waf_manager


class PacketAutoSyncTest(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.local = Path(workspace.name)
        self.remote = {}
        self.transfers = Mock()
        self.transfers.listdir_attr.side_effect = lambda _directory: [
            SimpleNamespace(filename=name, st_mode=S_IFREG, st_mtime=1760000000)
            for name in self.remote
        ]
        self.transfers.get.side_effect = lambda path, dest: Path(dest).write_bytes(
            self.remote[path.rsplit("/", 1)[-1]]
        )
        for mock in (
            patch.object(waf_manager, "get_local_log_dir", return_value=self.local),
            patch.object(ssh, "connect_sftp_client", return_value=(Mock(), self.transfers)),
            patch.object(desktop_api, "PACKET_SYNC_INTERVAL", 0.05),
            patch.object(desktop_api, "PACKET_RETRY_INTERVAL", 0.15),
        ):
            mock.start()
            self.addCleanup(mock.stop)
        self.service = desktop_api.DesktopService()
        self.addCleanup(self.close_service)

    def close_service(self):
        self.service.shutdown()
        self.wait_for(lambda: self.service.snapshot()["job"] is None)

    def wait_for(self, ready):
        deadline = time.monotonic() + 3
        while not ready():
            if time.monotonic() >= deadline:
                self.fail("同步状态未按时更新")
            time.sleep(0.01)

    def connect_fixture(self):
        self.service._connection = {"host": "fixture.local", "port": 22, "user": "owner"}

    def state(self):
        return self.service.snapshot()["packetSync"]

    def add_request(self, name, decision):
        metadata = json.dumps({"decision": decision}).encode()
        self.remote[name] = (
            request_logs.CAPTURE_PREFIX + metadata + b"\r\n"
            + f"GET /{name} HTTP/1.1\r\n\r\n".encode()
        )

    def manual_sync(self):
        self.assertTrue(self.service.action("sync-packets", {"logDir": "/logs"})["ok"])
        self.wait_for(lambda: self.service.snapshot()["job"] is None)

    def toggle(self, enabled):
        return self.service.action("set-packet-auto-sync", {"enabled": enabled, "logDir": "/logs"})

    def test_automatic_sync_waits_for_an_existing_job_and_can_stop(self):
        self.assertFalse(self.toggle(True)["ok"])
        self.connect_fixture()
        release = threading.Event()
        self.addCleanup(release.set)
        self.service._start_job("fixture", "packets", lambda: release.wait(2))
        self.assertTrue(self.toggle(True)["ok"])
        self.assertTrue(self.state()["enabled"])
        time.sleep(0.06)
        self.transfers.listdir_attr.assert_not_called()
        release.set()
        self.wait_for(lambda: self.state()["lastCheckedAt"] is not None)
        self.assertEqual(self.state()["revision"], 0)

        self.assertTrue(self.toggle(False)["ok"])
        self.wait_for(lambda: self.service.snapshot()["job"] is None)
        checked = self.transfers.listdir_attr.call_count
        time.sleep(0.11)
        self.assertEqual(self.transfers.listdir_attr.call_count, checked)

    def test_only_new_rule_hits_raise_the_alert_and_ack_keeps_newer_hits_unread(self):
        self.connect_fixture()
        self.add_request("hit.http", "matched")
        self.add_request("normal.http", "observed")
        self.remote["legacy.http"] = b"GET /legacy HTTP/1.1\r\n\r\n"
        self.manual_sync()
        stamp = self.state()["hitCursor"]
        self.assertEqual(self.state()["unreadHits"], 1)

        self.add_request("later.http", "redirected")
        self.manual_sync()
        self.assertEqual(self.state()["unreadHits"], 2)
        self.assertTrue(self.service.action("ack-packet-hits", {"through": stamp})["ok"])
        self.manual_sync()
        self.assertEqual(self.state()["unreadHits"], 1)

    def test_stop_finishes_only_the_file_already_downloading(self):
        self.connect_fixture()
        self.add_request("first.http", "matched")
        self.add_request("second.http", "matched")
        started = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)

        def receive(path, destination):
            started.set()
            release.wait(2)
            Path(destination).write_bytes(self.remote[path.rsplit("/", 1)[-1]])

        self.transfers.get.side_effect = receive
        self.assertTrue(self.toggle(True)["ok"])
        self.assertTrue(started.wait(2))
        self.assertTrue(self.toggle(False)["ok"])
        release.set()
        self.wait_for(lambda: self.service.snapshot()["job"] is None)
        self.assertEqual(sorted(path.name for path in self.local.glob("*.http")), ["first.http"])
        self.transfers.remove.assert_called_once_with("/logs/first.http")

    def test_connection_failure_keeps_the_saved_request_and_retries(self):
        self.connect_fixture()
        self.add_request("saved.http", "terminated")

        def remove(_path):
            if self.transfers.remove.call_count == 1:
                raise TimeoutError()

        self.transfers.remove.side_effect = remove
        self.assertTrue(self.toggle(True)["ok"])
        self.wait_for(lambda: self.state()["error"] is not None)
        self.assertTrue((self.local / "saved.http").is_file())
        self.assertEqual(self.state()["revision"], 1)
        self.assertEqual(self.state()["unreadHits"], 1)
        self.wait_for(lambda: self.state()["lastCheckedAt"] is not None)
        self.assertIsNone(self.state()["error"])
        self.assertEqual(self.state()["unreadHits"], 1)


if __name__ == "__main__":
    unittest.main()
