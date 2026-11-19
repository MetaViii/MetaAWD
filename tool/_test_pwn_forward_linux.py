"""Linux x86-64 integration checks; all traffic uses loopback and temporary files.

Run: python3 -m unittest -v _test_pwn_forward_linux
Root additionally enables deployment/rollback ownership checks; no xinetd is changed.
"""
import os
import platform
if platform.system() == "Linux":
    import pwd
    import grp
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from defence.pwn_forward import export_forward_bundle

TARGET = r'''
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    char buffer[512000];
    size_t total = 0;
    if (argc > 1) { write(1, argv[1], strlen(argv[1])); return 0; }
    while (total < sizeof(buffer)) {
        ssize_t size = read(0, buffer + total, sizeof(buffer) - total);
        if (size <= 0) break;
        total += (size_t)size;
    }
    if (total >= 4 && !memcmp(buffer, "EXEC", 4)) {
        execl("/bin/echo", "echo", "exec-allowed", (char *)0);
        return 2;
    }
    write(1, buffer, total);
    return 0;
}
'''


class ReplyServer:
    def __init__(self, prefix):
        self.prefix = prefix
        self.error = None
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        self.socket.listen(1)
        self.socket.settimeout(10)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        try:
            with self.socket:
                connection, _ = self.socket.accept()
                with connection:
                    connection.settimeout(10)
                    data = bytearray()
                    while True:
                        chunk = connection.recv(8192)
                        if not chunk:
                            break
                        data.extend(chunk)
                    connection.sendall(self.prefix + data)
        except Exception as exc:
            self.error = exc

    def finish(self):
        self.thread.join(12)
        if self.thread.is_alive():
            raise AssertionError("loopback server did not finish")
        if self.error:
            raise self.error


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "requires Linux x86-64")
class PwnForwardLinuxTest(unittest.TestCase):
    def setUp(self):
        for command in ("gcc", "make", "sh"):
            if not shutil.which(command):
                self.skipTest(f"requires {command}")
        self.temp = tempfile.TemporaryDirectory(prefix="metaawd-pwn-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o755)
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.original = self.root / "backup" / "original"
        self.original.parent.mkdir()
        self.service = self.root / "service"
        self.source = self.root / "fixture.c"
        self.source.write_text(TARGET)
        self.run_command(["gcc", "-O2", "-Wall", "-Wextra", str(self.source), "-o", str(self.service)])
        self.options = {
            "mode": "forward_multi", "logPath": str(self.logs),
            "backupPath": str(self.original), "servicePath": str(self.service),
            "staticLink": False, "stripBinary": False, "installXinetd": False,
            "restartMethod": "none", "targets": "127.0.0.1:20000",
        }

    def run_command(self, command, **kwargs):
        return subprocess.run(command, check=True, capture_output=True, timeout=20, **kwargs)

    def bundle(self):
        result = export_forward_bundle(self.options, self.root)
        bundle = Path(result["directory"])
        build = self.run_command(["make", "all"], cwd=bundle)
        self.assertEqual(build.stderr, b"", build.stderr.decode(errors="replace"))
        for name in ("deploy.sh", "rollback.sh"):
            self.run_command(["sh", "-n", str(bundle / name)])
        return bundle

    def test_four_modes_arguments_half_close_and_bounded_logs(self):
        single = ReplyServer(b"single:")
        first = ReplyServer(b"first:")
        second = ReplyServer(b"second:")
        self.options.update(forwardPort=single.port,
                            targets=f"127.0.0.1:{first.port}\n127.0.0.1:{second.port}")
        bundle = self.bundle()
        shutil.copy2(self.service, self.original)
        shutil.copy2(bundle / "hosts.txt", self.logs / "hosts.txt")
        self.assertEqual(self.run_command([str(bundle / "catch")], input=b"fixture").stdout, b"fixture")
        self.assertEqual(self.run_command([str(bundle / "catch"), "argument"], input=b"").stdout, b"argument")
        self.assertIn(b"exec-allowed", self.run_command([str(bundle / "catch")], input=b"EXEC").stdout)
        before = set(self.logs.glob("*.log"))
        self.assertNotIn(b"exec-allowed", self.run_command([str(bundle / "i0gan")], input=b"EXEC").stdout)
        self.assertTrue(any(b"AVOID" in path.read_bytes() for path in set(self.logs.glob("*.log")) - before))
        before = set(self.logs.glob("*.log"))
        data = b"A" * 400000
        self.assertEqual(self.run_command([str(bundle / "catch")], input=data).stdout, data)
        large_logs = set(self.logs.glob("*.log")) - before
        self.assertTrue(any(b"hex log truncated at 1 MiB" in path.read_bytes() for path in large_logs))
        self.assertTrue(all(path.stat().st_size < 3500000 for path in large_logs))
        self.assertEqual(self.run_command([str(bundle / "forward")], input=b"half-close").stdout, b"single:half-close")
        self.assertEqual(self.run_command([str(bundle / "forward_multi")], input=b"one").stdout, b"first:one")
        self.assertEqual(self.run_command([str(bundle / "forward_multi")], input=b"two").stdout, b"second:two")
        for server in (single, first, second):
            server.finish()

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "ownership checks require root")
    def test_deploy_twice_preserves_directories_and_rollback_metadata(self):
        if not shutil.which("runuser"):
            self.skipTest("requires runuser")
        account = pwd.getpwnam("nobody")
        group = grp.getgrgid(account.pw_gid).gr_name
        self.options.update(serviceUser=account.pw_name, serviceGroup=group)
        os.chown(self.logs, account.pw_uid, account.pw_gid)
        self.logs.chmod(0o730)
        os.chown(self.original.parent, 0, account.pw_gid)
        self.original.parent.chmod(0o750)
        os.chown(self.service, account.pw_uid, account.pw_gid)
        self.service.chmod(0o751)
        original = self.service.read_bytes()
        def metadata(path):
            stat = path.stat()
            return stat.st_uid, stat.st_gid, stat.st_mode & 0o7777
        original_metadata = metadata(self.service)
        log_metadata = metadata(self.logs)
        directory_metadata = metadata(self.original.parent)
        bundle = self.bundle()
        bundle.chmod(0o755)
        for _ in range(2):
            self.run_command(["sh", "deploy.sh"], cwd=bundle)
        self.assertEqual(self.original.read_bytes(), original)
        self.assertEqual(metadata(self.original), (0, account.pw_gid, 0o550))
        self.assertEqual(metadata(self.logs), log_metadata)
        self.assertEqual(metadata(self.original.parent), directory_metadata)
        self.run_command(["runuser", "-u", account.pw_name, "--", "test", "-x", str(self.original)])
        writable = subprocess.run(["runuser", "-u", account.pw_name, "--", "test", "-w", str(self.original)], timeout=10)
        self.assertNotEqual(writable.returncode, 0)
        response = self.run_command(["runuser", "-u", account.pw_name, "--", str(bundle / "catch")], input=b"unprivileged")
        self.assertEqual(response.stdout, b"unprivileged")
        self.run_command(["sh", "rollback.sh"], cwd=bundle)
        self.assertEqual(self.service.read_bytes(), original)
        self.assertEqual(metadata(self.service), original_metadata)


if __name__ == "__main__":
    unittest.main()
