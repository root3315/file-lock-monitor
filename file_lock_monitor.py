#!/usr/bin/env python3
"""
File Lock Monitor - Detect processes holding file locks on Linux systems.
Uses lsof and /proc filesystem to gather lock information.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Dict, Optional


@dataclass
class LockInfo:
    """Represents information about a file lock."""
    pid: int
    process_name: str
    file_path: str
    lock_type: str
    mode: str
    user: str
    fd: str


def run_command(cmd: List[str], timeout: int = 10) -> tuple:
    """Execute a shell command and return stdout, stderr, returncode."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", -1


def get_process_name(pid: int) -> str:
    """Get process name from /proc filesystem."""
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError, IOError):
        return "unknown"


def get_process_user(pid: int) -> str:
    """Get the username owning a process."""
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("Uid:"):
                    uid = line.split()[1]
                    return uid
    except (FileNotFoundError, PermissionError, IOError):
        pass
    return "unknown"


def uid_to_username(uid: str) -> str:
    """Convert UID to username using /etc/passwd."""
    try:
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3 and parts[2] == uid:
                    return parts[0]
    except (FileNotFoundError, IOError):
        pass
    try:
        import pwd
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError):
        pass
    return uid


def parse_lsof_output(output: str) -> List[LockInfo]:
    """Parse lsof output to extract file lock information."""
    locks = []
    lines = output.strip().split("\n")
    
    for line in lines:
        if not line.strip():
            continue
        
        parts = line.split(None, 9)
        if len(parts) < 9:
            continue
        
        command = parts[0]
        pid_str = parts[1]
        user = parts[2]
        fd = parts[3]
        lock_char = parts[4] if len(parts) > 4 else "-"
        file_path = parts[-1] if parts else ""
        
        if not pid_str.isdigit():
            continue
        
        pid = int(pid_str)
        
        lock_type = "none"
        if lock_char == "U":
            lock_type = "read/write"
        elif lock_char == "R":
            lock_type = "read"
        elif lock_char == "W":
            lock_type = "write"
        elif lock_char in ("r", "w"):
            lock_type = "read" if lock_char == "r" else "write"
        
        mode = "shared" if lock_char.islower() else "exclusive"
        
        locks.append(LockInfo(
            pid=pid,
            process_name=command,
            file_path=file_path,
            lock_type=lock_type,
            mode=mode,
            user=uid_to_username(user) if user.isdigit() else user,
            fd=fd
        ))
    
    return locks


def scan_proc_locks() -> List[LockInfo]:
    """Scan /proc/*/locks for additional lock information."""
    locks = []
    proc_dirs = [d for d in os.listdir("/proc") if d.isdigit()]
    
    for pid_str in proc_dirs:
        pid = int(pid_str)
        try:
            locks_path = f"/proc/{pid}/locks"
            if not os.path.exists(locks_path):
                continue
            
            with open(locks_path, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 6 and parts[0] == "0:":
                        lock_info = " ".join(parts[1:])
                        locks.append(LockInfo(
                            pid=pid,
                            process_name=get_process_name(pid),
                            file_path=lock_info,
                            lock_type=parts[1] if len(parts) > 1 else "unknown",
                            mode="unknown",
                            user=uid_to_username(str(pid)),
                            fd="locks"
                        ))
        except (PermissionError, FileNotFoundError, IOError):
            continue
    
    return locks


def find_locks_for_path(target_path: str, locks: List[LockInfo]) -> List[LockInfo]:
    """Filter locks to only those affecting a specific path."""
    matching = []
    for lock in locks:
        if target_path in lock.file_path or lock.file_path in target_path:
            matching.append(lock)
        try:
            real_target = os.path.realpath(target_path)
            real_lock = os.path.realpath(lock.file_path)
            if real_target == real_lock:
                if lock not in matching:
                    matching.append(lock)
        except (OSError, ValueError):
            pass
    return matching


def get_all_file_locks() -> List[LockInfo]:
    """Get all file locks on the system using lsof."""
    stdout, stderr, returncode = run_command([
        "lsof", "-n", "-P", "-F", "flock"
    ])
    
    if returncode != 0 and "not found" in stderr.lower():
        stdout, stderr, returncode = run_command([
            "lsof", "+f", "-n", "-P"
        ])
    
    if returncode != 0:
        return []
    
    return parse_lsof_output(stdout)


def format_table(locks: List[LockInfo]) -> str:
    """Format lock information as a table."""
    if not locks:
        return "No file locks found."
    
    headers = ["PID", "PROCESS", "USER", "LOCK TYPE", "MODE", "FILE"]
    col_widths = [len(h) for h in headers]
    
    for lock in locks:
        col_widths[0] = max(col_widths[0], len(str(lock.pid)))
        col_widths[1] = max(col_widths[1], len(lock.process_name))
        col_widths[2] = max(col_widths[2], len(lock.user))
        col_widths[3] = max(col_widths[3], len(lock.lock_type))
        col_widths[4] = max(col_widths[4], len(lock.mode))
        col_widths[5] = max(col_widths[5], len(lock.file_path))
    
    lines = []
    header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    lines.append(header_line)
    lines.append("-+-".join("-" * w for w in col_widths))
    
    for lock in locks:
        row = [
            str(lock.pid),
            lock.process_name,
            lock.user,
            lock.lock_type,
            lock.mode,
            lock.file_path
        ]
        lines.append(" | ".join(cell.ljust(col_widths[i]) for i, cell in enumerate(row)))
    
    return "\n".join(lines)


def format_json(locks: List[LockInfo]) -> str:
    """Format lock information as JSON."""
    data = {
        "timestamp": datetime.now().isoformat(),
        "total_locks": len(locks),
        "locks": [asdict(lock) for lock in locks]
    }
    return json.dumps(data, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Monitor file locks and detect processes holding them"
    )
    parser.add_argument(
        "-p", "--path",
        help="Filter locks for a specific file path"
    )
    parser.add_argument(
        "-j", "--json",
        action="store_true",
        help="Output in JSON format"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show additional details"
    )
    parser.add_argument(
        "--proc-scan",
        action="store_true",
        help="Also scan /proc/*/locks for additional info"
    )
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("Warning: Running without root privileges. Some locks may not be visible.",
              file=sys.stderr)
    
    locks = get_all_file_locks()
    
    if args.proc_scan:
        proc_locks = scan_proc_locks()
        existing_pids = {l.pid for l in locks}
        for lock in proc_locks:
            if lock.pid not in existing_pids:
                locks.append(lock)
    
    if args.path:
        target = os.path.abspath(args.path)
        locks = find_locks_for_path(target, locks)
        if args.verbose:
            print(f"Searching for locks on: {target}", file=sys.stderr)
    
    if args.json:
        print(format_json(locks))
    else:
        print(format_table(locks))
    
    if args.verbose:
        print(f"\nTotal locks found: {len(locks)}", file=sys.stderr)
    
    return 0 if not locks else 1


if __name__ == "__main__":
    sys.exit(main())
