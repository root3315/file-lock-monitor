# file-lock-monitor

Quick tool to see what's locking files on your Linux box. You know when you can't delete or modify a file because something's got it open? This tells you exactly what's holding it.

## Why I wrote this

Ever tried to unmount a drive and got "target is busy"? Or couldn't delete a log file because some process won't let go? Yeah, me too. This script finds those stubborn processes.

## Requirements

- Python 3.7+
- `lsof` command (usually pre-installed, or `apt install lsof` / `yum install lsof`)
- Linux (uses /proc filesystem)
- Root/sudo recommended for seeing all locks

## Installation

```bash
git clone <repo>
cd file-lock-monitor
pip install -r requirements.txt
```

That's it. No fancy setup.

## Usage

### Show all file locks

```bash
python file_lock_monitor.py
```

### Check a specific file

```bash
python file_lock_monitor.py -p /var/log/syslog
python file_lock_monitor.py --path /home/user/data.db
```

### JSON output (for scripting)

```bash
python file_lock_monitor.py -j
```

### Verbose mode

```bash
python file_lock_monitor.py -v
python file_lock_monitor.py -p /some/file -v
```

### Scan /proc for extra lock info

```bash
python file_lock_monitor.py --proc-scan
```

## Output

Normal mode gives you a table:

```
PID | PROCESS    | USER | LOCK TYPE   | MODE      | FILE
----+------------+------+-------------+-----------+------------------
1234| postgres   | postgres | read/write | exclusive | /var/lib/postgresql/data/base
5678| vim        | john | read        | shared    | /home/john/notes.txt
```

JSON mode gives you structured data you can pipe to `jq` or whatever.

## Exit codes

- `0` - No locks found (or no locks matching your path filter)
- `1` - Found some locks

Useful for scripting:

```bash
if python file_lock_monitor.py -p /mnt/usb; then
    echo "Safe to unmount"
else
    echo "Something's still using it!"
fi
```

## Notes

- Without root, you'll only see locks from your own processes
- Network file locks might not show up reliably
- The `--proc-scan` flag digs deeper but is slower

## License

MIT. Do whatever.
