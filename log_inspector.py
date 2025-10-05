#!/usr/bin/env python3
import argparse, re
from collections import defaultdict
from datetime import datetime

# Syslog "Oct  5 12:34:56" -> naive datetime with current year
def parse_syslog_ts(mon, day, hhmmss):
    year = datetime.now().year
    return datetime.strptime(f"{year} {mon} {int(day)} {hhmmss}", "%Y %b %d %H:%M:%S")

SSH_FAIL_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*sshd\[.*\]:\s+"
    r"(Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+))"
)

def scan(path, since=None, min_count=1):
    since_dt = datetime.fromisoformat(since) if since else None
    stats = defaultdict(lambda: {"count":0, "users":set(), "first":None, "last":None})
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = SSH_FAIL_RE.match(line)
            if not m:
                continue
            ts = parse_syslog_ts(m["mon"], m["day"], m["time"])
            if since_dt and ts < since_dt:
                continue
            ip = m["ip"]
            user = m["user"]
            s = stats[ip]
            s["count"] += 1
            s["users"].add(user)
            s["first"] = ts if not s["first"] or ts < s["first"] else s["first"]
            s["last"]  = ts if not s["last"]  or ts > s["last"]  else s["last"]

    rows = [
        (ip, d["count"], sorted(d["users"]), d["first"], d["last"])
        for ip, d in stats.items() if d["count"] >= min_count
    ]
    rows.sort(key=lambda r: r[1], reverse=True)
    return rows

def main():
    ap = argparse.ArgumentParser(description="Detect SSH brute-force patterns in auth logs.")
    ap.add_argument("logfile", help="Path to auth.log / secure log")
    ap.add_argument("--since", help="ISO timestamp filter, e.g. 2025-10-01T00:00:00")
    ap.add_argument("--min-count", type=int, default=5, help="Only show IPs with >= this many fails")
    args = ap.parse_args()

    rows = scan(args.logfile, since=args.since, min_count=args.min_count)
    if not rows:
        print("No failed-password patterns meeting the threshold.")
        return 0

    print(f"{'IP':<16} {'Fails':>5}  Users  First_seen -> Last_seen")
    print("-"*72)
    for ip, count, users, first_ts, last_ts in rows:
        users_str = ",".join(users)[:40]
        first_s = first_ts.strftime("%b %d %H:%M:%S") if first_ts else "-"
        last_s  = last_ts.strftime("%b %d %H:%M:%S") if last_ts else "-"
        print(f"{ip:<16} {count:>5}  {users_str:<40}  {first_s} -> {last_s}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
