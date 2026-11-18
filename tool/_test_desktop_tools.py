import json
import socket
import tempfile
import threading
import time
import unittest
from queue import Empty, Queue
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from defence import bugku_submit, ssh
from defence.ssh_terminal import SshTerminal
from desktop_api import DesktopService


class DesktopToolsTest(unittest.TestCase):
    def wait_for(self, condition):
        deadline = time.monotonic() + 3
        while not condition() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(condition())

    def test_bugku_deduplicates_and_preserves_input_line_numbers(self):
        batch = bugku_submit.BugkuBatch()
        self.addCleanup(batch.stop)
        with patch.object(bugku_submit, "_submit", return_value=("accepted", "confirmed", False)) as submit:
            batch.start("sample-token", " flag{example} \n\nflag{example}\nflag{second}")
            self.wait_for(lambda: not batch.snapshot()["running"])
            self.assertEqual([call.args[2] for call in submit.call_args_list], ["flag{example}", "flag{second}"])
        self.assertEqual(batch.snapshot()["duplicates"], 1)
        self.assertEqual([row["line"] for row in batch.results()], [1, 4])
        self.assertNotIn("sample-token", str(batch.results()))

    def test_bugku_confirms_only_recognized_responses_and_keeps_secrets_out_of_errors(self):
        payload = json.dumps({"msg": "提交成功"}).encode("utf-8")
        self.assertEqual(bugku_submit._verdict(payload), "accepted")
        self.assertEqual(bugku_submit._verdict(b"<html>success</html>"), "unknown")
        self.assertEqual(bugku_submit._verdict(b'{"success": false}'), "rejected")
        session = Mock()
        session.get.side_effect = requests.Timeout("secret-token and flag{example}")
        status, message, halt = bugku_submit._submit(session, "secret-token", "flag{example}")
        self.assertEqual(status, "unknown")
        self.assertTrue(halt)
        self.assertNotIn("secret-token", message)
        self.assertNotIn("flag{example}", message)
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])

    def test_bugku_stops_before_sending_additional_items(self):
        batch = bugku_submit.BugkuBatch()
        started = threading.Event()
        release = threading.Event()
        self.addCleanup(batch.stop)

        def held_submit(_session, _token, _flag, *, timeout):
            started.set()
            release.wait(2)
            return "accepted", "confirmed", False

        with patch.object(bugku_submit, "_submit", side_effect=held_submit) as submit:
            batch.start("test-token", "flag{first}\nflag{second}")
            try:
                self.assertTrue(started.wait(2))
                batch.stop()
                self.assertTrue(batch.snapshot()["stopping"])
            finally:
                release.set()
            self.wait_for(lambda: not batch.snapshot()["running"])
            submit.assert_called_once()
        self.assertEqual([row["status"] for row in batch.results()], ["accepted", "skipped"])

    def test_bugku_options_match_preview_and_submission_validation(self):
        flags = "flag{first}\n\nflag{first}\nflag{second}"
        self.assertEqual(bugku_submit.preview_flags(flags, {}), {"count": 2, "duplicates": 1, "blanks": 1})
        with self.assertRaisesRegex(ValueError, "第 3 行"):
            bugku_submit.preview_flags(flags, {"duplicates": "reject"})
        with self.assertRaisesRegex(ValueError, "超过单批上限"):
            bugku_submit.BugkuBatch().start("example", flags, {"maxFlags": 1})
        with self.assertRaisesRegex(ValueError, "提交间隔"):
            bugku_submit.preview_flags(flags, {"intervalMs": 0})
        batch = bugku_submit.BugkuBatch()
        self.addCleanup(batch.stop)
        with patch.object(bugku_submit, "_submit", return_value=("accepted", "confirmed", False)) as submit:
            batch.start("example", "flag{first}", {"timeoutSeconds": 9, "intervalMs": 10000})
            self.wait_for(lambda: not batch.snapshot()["running"])
            self.assertEqual(submit.call_args.kwargs["timeout"], 9)

    def test_bugku_export_includes_row_outcomes_without_raw_input(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.csv"
            bugku_submit.export_results([
                {"line": 2, "status": "unknown", "message": "待确认", "flag": "private", "token": "private"},
            ], path)
            self.assertEqual(path.read_text(encoding="utf-8-sig"), "输入行,状态,结果\n2,unknown,待确认\n")

    def test_ssh_terminal_sends_only_manual_lines_and_preserves_split_utf8(self):
        terminal = SshTerminal()
        self.addCleanup(terminal.stop)
        received = Queue()
        sent = []
        client = Mock()
        channel = client.invoke_shell.return_value
        channel.sendall.side_effect = sent.append
        channel.exit_status_ready.return_value = False

        def receive(_size):
            try:
                return received.get(timeout=0.03)
            except Empty as exc:
                raise socket.timeout() from exc

        channel.recv.side_effect = receive
        host_key = object()
        with patch.object(ssh, "connect_ssh_client", return_value=client) as connect:
            terminal.start("server.test", 2222, "operator", "", host_key)
            self.wait_for(lambda: terminal.snapshot()["phase"] == "open")
            encoded = "终端输出\r\n".encode("utf-8")
            received.put(encoded[:2])
            received.put(encoded[2:])
            terminal.send_line("pwd")
            terminal.interrupt()
            self.wait_for(lambda: terminal.output() == "终端输出\n" and len(sent) == 2)
            self.assertEqual(sent, [b"pwd\n", b"\x03"])
            self.assertEqual(connect.call_args.kwargs["host_key"], host_key)
            terminal.stop(discard=True)
            self.wait_for(lambda: terminal.snapshot()["phase"] == "idle")
            self.assertEqual(terminal.output(), "")
        channel.close.assert_called_once()
        client.close.assert_called_once()

    def test_ssh_terminal_connection_uses_the_verified_key(self):
        key = Mock()
        key.get_name.return_value = "ssh-ed25519"
        with patch.object(ssh.paramiko, "SSHClient") as build_client:
            client = ssh.connect_ssh_client("server.test", 2222, "operator", "", host_key=key)
            client.get_host_keys().add.assert_called_once_with("[server.test]:2222", "ssh-ed25519", key)
            client.set_missing_host_key_policy.assert_not_called()
            self.assertEqual(client.connect.call_args.kwargs["password"], "")
        build_client.assert_called_once()

    def test_switching_verified_ssh_connection_disposes_the_old_terminal(self):
        with patch("desktop_api.waf_manager.list_local_request_logs", return_value=[]):
            service = DesktopService()
            self.addCleanup(service.shutdown)
            self.assertFalse(service.action("terminal-open", {})["ok"])
            service._connection = {"host": "old.test", "port": 22, "user": "operator"}
            service._host_key = object()
            key = object()

            def verify(*_args, on_verified):
                on_verified(key)
                return True

            with patch.object(ssh, "ssh_test", side_effect=verify), patch.object(service._terminal, "stop") as stop:
                result = service.action("connect", {"host": "new.test", "port": 22, "user": "operator"})
                self.assertTrue(result["ok"])
                self.wait_for(lambda: service.snapshot()["job"] is None)
                stop.assert_called_once_with(discard=True)
            self.assertEqual(service.snapshot()["connection"]["host"], "new.test")
            self.assertIs(service._host_key, key)


if __name__ == "__main__":
    unittest.main()
