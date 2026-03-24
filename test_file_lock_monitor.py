#!/usr/bin/env python3
"""Unit tests for file_lock_monitor module."""

import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import mock_open, patch

from file_lock_monitor import (
    LockInfo,
    find_locks_for_path,
    format_json,
    format_table,
    get_process_name,
    get_process_user,
    parse_lsof_output,
    run_command,
    scan_proc_locks,
    uid_to_username,
)


class TestLockInfo(unittest.TestCase):
    """Tests for LockInfo dataclass."""

    def test_lock_info_creation(self):
        lock = LockInfo(
            pid=1234,
            process_name="test",
            file_path="/tmp/test.txt",
            lock_type="read/write",
            mode="exclusive",
            user="root",
            fd="3u"
        )
        self.assertEqual(lock.pid, 1234)
        self.assertEqual(lock.process_name, "test")
        self.assertEqual(lock.file_path, "/tmp/test.txt")


class TestRunCommand(unittest.TestCase):
    """Tests for run_command function."""

    def test_successful_command(self):
        stdout, stderr, returncode = run_command(["echo", "hello"])
        self.assertEqual(returncode, 0)
        self.assertIn("hello", stdout)

    def test_command_not_found(self):
        stdout, stderr, returncode = run_command(["nonexistent_command_xyz"])
        self.assertEqual(returncode, -1)

    def test_command_with_timeout(self):
        stdout, stderr, returncode = run_command(["sleep", "10"], timeout=1)
        self.assertEqual(returncode, -1)
        self.assertIn("timed out", stderr)


class TestGetProcessName(unittest.TestCase):
    """Tests for get_process_name function."""

    @patch("builtins.open", new_callable=mock_open, read_data="test_process\n")
    def test_get_process_name_success(self, mock_file):
        name = get_process_name(1234)
        self.assertEqual(name, "test_process")
        mock_file.assert_called_once_with("/proc/1234/comm", "r")

    @patch("builtins.open", side_effect=FileNotFoundError)
    def test_get_process_name_not_found(self, mock_file):
        name = get_process_name(99999)
        self.assertEqual(name, "unknown")

    @patch("builtins.open", side_effect=PermissionError)
    def test_get_process_name_permission_denied(self, mock_file):
        name = get_process_name(1234)
        self.assertEqual(name, "unknown")


class TestGetProcessUser(unittest.TestCase):
    """Tests for get_process_user function."""

    @patch("builtins.open", new_callable=mock_open, read_data="Name:   test\nUid:    1000    1000    1000    1000\n")
    def test_get_process_user_success(self, mock_file):
        uid = get_process_user(1234)
        self.assertEqual(uid, "1000")
        mock_file.assert_called_with("/proc/1234/status", "r")

    @patch("builtins.open", side_effect=FileNotFoundError)
    def test_get_process_user_not_found(self, mock_file):
        uid = get_process_user(99999)
        self.assertEqual(uid, "unknown")


class TestUidToUsername(unittest.TestCase):
    """Tests for uid_to_username function."""

    @patch("builtins.open", new_callable=mock_open, read_data="root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n")
    def test_uid_to_username_from_passwd(self, mock_file):
        username = uid_to_username("0")
        self.assertEqual(username, "root")

    @patch("builtins.open", side_effect=FileNotFoundError)
    @patch("pwd.getpwuid")
    def test_uid_to_username_from_pwd(self, mock_pwd, mock_file):
        mock_pwd.return_value.pw_name = "testuser"
        username = uid_to_username("1000")
        self.assertEqual(username, "testuser")

    def test_uid_to_username_invalid(self):
        username = uid_to_username("99999999")
        self.assertEqual(username, "99999999")


class TestParseLsofOutput(unittest.TestCase):
    """Tests for parse_lsof_output function."""

    def test_parse_basic_lock(self):
        lsof_output = "bash    1234    root    3u    R    REG    8,1    1234    0    /etc/passwd"
        locks = parse_lsof_output(lsof_output)
        self.assertEqual(len(locks), 1)
        self.assertEqual(locks[0].pid, 1234)
        self.assertEqual(locks[0].process_name, "bash")
        self.assertEqual(locks[0].file_path, "/etc/passwd")
        self.assertEqual(locks[0].lock_type, "read")
        self.assertEqual(locks[0].mode, "exclusive")

    def test_parse_read_lock(self):
        lsof_output = "vim    5678    user    4r    r    REG    8,1    5678    0    /home/user/file.txt"
        locks = parse_lsof_output(lsof_output)
        self.assertEqual(len(locks), 1)
        self.assertEqual(locks[0].lock_type, "read")
        self.assertEqual(locks[0].mode, "shared")

    def test_parse_write_lock(self):
        lsof_output = "python    9012    user    5w    W    REG    8,1    9012    0    /var/log/app.log"
        locks = parse_lsof_output(lsof_output)
        self.assertEqual(len(locks), 1)
        self.assertEqual(locks[0].lock_type, "write")
        self.assertEqual(locks[0].mode, "exclusive")

    def test_parse_readwrite_lock(self):
        lsof_output = "bash    1234    root    3u    U    REG    8,1    1234    0    /etc/passwd"
        locks = parse_lsof_output(lsof_output)
        self.assertEqual(len(locks), 1)
        self.assertEqual(locks[0].lock_type, "read/write")
        self.assertEqual(locks[0].mode, "exclusive")

    def test_parse_multiple_locks(self):
        lsof_output = """bash    1234    root    3u    U    REG    8,1    1234    0    /etc/passwd
vim    5678    user    4r    R    REG    8,1    5678    0    /home/user/file.txt
python    9012    user    5w    W    REG    8,1    9012    0    /var/log/app.log"""
        locks = parse_lsof_output(lsof_output)
        self.assertEqual(len(locks), 3)

    def test_parse_empty_output(self):
        locks = parse_lsof_output("")
        self.assertEqual(len(locks), 0)

    def test_parse_invalid_pid(self):
        lsof_output = "bash    abc root    3u   REG    8,1    1234 /etc/passwd"
        locks = parse_lsof_output(lsof_output)
        self.assertEqual(len(locks), 0)

    def test_parse_malformed_line(self):
        lsof_output = "incomplete line"
        locks = parse_lsof_output(lsof_output)
        self.assertEqual(len(locks), 0)


class TestScanProcLocks(unittest.TestCase):
    """Tests for scan_proc_locks function."""

    @patch("file_lock_monitor.os.listdir", return_value=["1234", "5678"])
    @patch("file_lock_monitor.os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open, read_data="0: POSIX  ADVISORY  WRITE 0000000000000000 00:0f:12345 0 0\n")
    @patch("file_lock_monitor.get_process_name", return_value="test_proc")
    @patch("file_lock_monitor.uid_to_username", return_value="testuser")
    def test_scan_proc_locks_success(self, mock_uid, mock_name, mock_file, mock_exists, mock_listdir):
        locks = scan_proc_locks()
        self.assertEqual(len(locks), 2)
        self.assertEqual(locks[0].pid, 1234)
        self.assertEqual(locks[0].process_name, "test_proc")

    @patch("file_lock_monitor.os.listdir", return_value=["1234"])
    @patch("file_lock_monitor.os.path.exists", return_value=False)
    def test_scan_proc_locks_no_locks_file(self, mock_exists, mock_listdir):
        locks = scan_proc_locks()
        self.assertEqual(len(locks), 0)

    @patch("file_lock_monitor.os.listdir", return_value=["1234"])
    @patch("file_lock_monitor.os.path.exists", return_value=True)
    @patch("builtins.open", side_effect=PermissionError)
    def test_scan_proc_locks_permission_denied(self, mock_file, mock_exists, mock_listdir):
        locks = scan_proc_locks()
        self.assertEqual(len(locks), 0)


class TestFindLocksForPath(unittest.TestCase):
    """Tests for find_locks_for_path function."""

    def setUp(self):
        self.locks = [
            LockInfo(
                pid=1234,
                process_name="bash",
                file_path="/home/user/test.txt",
                lock_type="read/write",
                mode="exclusive",
                user="user",
                fd="3u"
            ),
            LockInfo(
                pid=5678,
                process_name="vim",
                file_path="/var/log/syslog",
                lock_type="read",
                mode="shared",
                user="root",
                fd="4r"
            ),
        ]

    def test_find_exact_match(self):
        matches = find_locks_for_path("/home/user/test.txt", self.locks)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].pid, 1234)

    def test_find_partial_match(self):
        matches = find_locks_for_path("/home/user", self.locks)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].pid, 1234)

    def test_find_no_match(self):
        matches = find_locks_for_path("/nonexistent/path", self.locks)
        self.assertEqual(len(matches), 0)

    def test_find_multiple_matches(self):
        locks = [
            LockInfo(
                pid=1111,
                process_name="proc1",
                file_path="/data/file1.txt",
                lock_type="read",
                mode="shared",
                user="user",
                fd="1"
            ),
            LockInfo(
                pid=2222,
                process_name="proc2",
                file_path="/data/file2.txt",
                lock_type="write",
                mode="exclusive",
                user="user",
                fd="2"
            ),
        ]
        matches = find_locks_for_path("/data", locks)
        self.assertEqual(len(matches), 2)


class TestFormatTable(unittest.TestCase):
    """Tests for format_table function."""

    def test_format_empty_locks(self):
        output = format_table([])
        self.assertEqual(output, "No file locks found.")

    def test_format_single_lock(self):
        locks = [
            LockInfo(
                pid=1234,
                process_name="bash",
                file_path="/etc/passwd",
                lock_type="read/write",
                mode="exclusive",
                user="root",
                fd="3u"
            )
        ]
        output = format_table(locks)
        self.assertIn("PID", output)
        self.assertIn("1234", output)
        self.assertIn("bash", output)
        self.assertIn("/etc/passwd", output)

    def test_format_multiple_locks(self):
        locks = [
            LockInfo(
                pid=1234,
                process_name="bash",
                file_path="/etc/passwd",
                lock_type="read/write",
                mode="exclusive",
                user="root",
                fd="3u"
            ),
            LockInfo(
                pid=5678,
                process_name="vim",
                file_path="/home/user/file.txt",
                lock_type="read",
                mode="shared",
                user="user",
                fd="4r"
            ),
        ]
        output = format_table(locks)
        lines = output.split("\n")
        self.assertGreaterEqual(len(lines), 4)
        self.assertIn("PID", lines[0])


class TestFormatJson(unittest.TestCase):
    """Tests for format_json function."""

    @patch("file_lock_monitor.datetime")
    def test_format_json_structure(self, mock_datetime):
        mock_datetime.now.return_value.isoformat.return_value = "2024-01-01T00:00:00"
        locks = [
            LockInfo(
                pid=1234,
                process_name="bash",
                file_path="/etc/passwd",
                lock_type="read/write",
                mode="exclusive",
                user="root",
                fd="3u"
            )
        ]
        output = format_json(locks)
        data = json.loads(output)
        self.assertIn("timestamp", data)
        self.assertIn("total_locks", data)
        self.assertIn("locks", data)
        self.assertEqual(data["total_locks"], 1)
        self.assertEqual(data["locks"][0]["pid"], 1234)

    def test_format_json_empty(self):
        output = format_json([])
        data = json.loads(output)
        self.assertEqual(data["total_locks"], 0)
        self.assertEqual(data["locks"], [])


class TestIntegration(unittest.TestCase):
    """Integration tests for the module."""

    def test_full_workflow(self):
        lsof_output = """bash    1234    root    3u    U    REG    8,1    1234    0    /etc/passwd
vim    5678    user    4r    R    REG    8,1    5678    0    /home/user/file.txt"""
        locks = parse_lsof_output(lsof_output)
        self.assertEqual(len(locks), 2)

        filtered = find_locks_for_path("/etc", locks)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].process_name, "bash")

        table_output = format_table(filtered)
        self.assertIn("bash", table_output)

        json_output = format_json(filtered)
        parsed = json.loads(json_output)
        self.assertEqual(parsed["total_locks"], 1)


if __name__ == "__main__":
    unittest.main()
