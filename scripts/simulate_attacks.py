import os
import sys
import json
import time
import random
import argparse
from datetime import datetime

import redis

REDIS_URL          = os.getenv("REDIS_URL", "redis://localhost:6379")
REDIS_EVENTS_QUEUE = "siem:events:queue"
REDIS_EVENTS_CHAN  = "siem:events"

ATTACKER_IPS = [
    "45.33.32.156",
    "198.51.100.42",
    "203.0.113.5",
    "192.0.2.100",
]


def ts():
    return datetime.utcnow().isoformat()


def push(r: redis.Redis, event: dict):
    payload = json.dumps(event)
    r.lpush(REDIS_EVENTS_QUEUE, payload)
    r.publish(REDIS_EVENTS_CHAN, payload)
    sev_colors = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    icon = sev_colors.get(event.get("severity", "low"), "⚪")
    print(f"  {icon} [{event['severity'].upper():8}] {event['event_type']:30} from {event.get('source_ip','—')}")


# ── Scenarios ─────────────────────────────────────────────────────────────────

def ssh_brute_force(r, ip=None):

    ip = ip or random.choice(ATTACKER_IPS)
    usernames = ["root", "admin", "ubuntu", "deploy", "test", "user", "guest", "pi"]
    print(f"\n🔨 SSH Brute Force from {ip}")
    for i in range(10):
        push(r, {
            "timestamp":  ts(),
            "event_type": "ssh_failed_login",
            "category":   "authentication",
            "severity":   "medium",
            "source_ip":  ip,
            "username":   random.choice(usernames),
            "message":    f"Failed password for {random.choice(usernames)} from {ip} port 22 ssh2",
            "raw_log":    f"Jun 12 10:00:0{i} host sshd[1234]: Failed password",
            "log_source": "auth.log",
            "extra":      {},
        })
        time.sleep(0.3)


def ssh_root_login(r, ip=None):

    ip = ip or random.choice(ATTACKER_IPS)
    print(f"\n💀 Root SSH Login from {ip}")
    push(r, {
        "timestamp":  ts(),
        "event_type": "ssh_accepted_login",
        "category":   "authentication",
        "severity":   "high",
        "source_ip":  ip,
        "username":   "root",
        "message":    f"Accepted password for root from {ip} port 22 ssh2",
        "raw_log":    f"Jun 12 10:01:00 host sshd[9999]: Accepted password for root",
        "log_source": "auth.log",
        "extra":      {},
    })


def port_scan(r, ip=None):

    ip = ip or random.choice(ATTACKER_IPS)
    ports = [22, 23, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017, 4444, 1337, 31337]
    print(f"\n🔍 Port Scan from {ip}")
    for port in ports:
        push(r, {
            "timestamp":  ts(),
            "event_type": "port_scan",
            "category":   "network",
            "severity":   "medium",
            "source_ip":  ip,
            "dest_ip":    "10.0.0.1",
            "dest_port":  port,
            "message":    f"[UFW BLOCK] SRC={ip} DST=10.0.0.1 DPT={port}",
            "raw_log":    f"kernel: [UFW BLOCK] IN=eth0 SRC={ip} DST=10.0.0.1 DPT={port}",
            "log_source": "kern.log",
            "extra":      {"blocked": True},
        })
        time.sleep(0.15)


def privilege_escalation(r):

    print(f"\n⬆️  Privilege Escalation (sudo bash)")
    push(r, {
        "timestamp":  ts(),
        "event_type": "sudo_usage",
        "category":   "privilege_escalation",
        "severity":   "high",
        "source_ip":  None,
        "username":   "www-data",
        "message":    "www-data : TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash",
        "raw_log":    "sudo: www-data : TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash",
        "log_source": "auth.log",
        "extra":      {"command": "/bin/bash"},
    })


def new_user_created(r):

    print(f"\n👤 New User Created (potential backdoor)")
    push(r, {
        "timestamp":  ts(),
        "event_type": "user_created",
        "category":   "account_management",
        "severity":   "medium",
        "source_ip":  None,
        "username":   "backdoor",
        "message":    "new user: name=backdoor, UID=0, GID=0",
        "raw_log":    "useradd[9999]: new user: name=backdoor, UID=0, GID=0",
        "log_source": "auth.log",
        "extra":      {"uid": "0", "gid": "0"},
    })


def user_enumeration(r, ip=None):

    ip = ip or random.choice(ATTACKER_IPS)
    fake_users = ["jenkins", "gitlab", "postgres", "mysql", "oracle", "hadoop"]
    print(f"\n🕵️  User Enumeration from {ip}")
    for user in fake_users:
        push(r, {
            "timestamp":  ts(),
            "event_type": "ssh_invalid_user",
            "category":   "authentication",
            "severity":   "medium",
            "source_ip":  ip,
            "username":   user,
            "message":    f"Invalid user {user} from {ip} port 22",
            "raw_log":    f"sshd[1]: Invalid user {user} from {ip} port 22",
            "log_source": "auth.log",
            "extra":      {},
        })
        time.sleep(0.5)


def mixed_attack(r):

    ip = random.choice(ATTACKER_IPS)
    print(f"\n💥 Mixed Attack Simulation from {ip}")
    print("   Phase 1: Reconnaissance")
    port_scan(r, ip)
    time.sleep(1)
    print("   Phase 2: Credential Access")
    ssh_brute_force(r, ip)
    time.sleep(1)
    print("   Phase 3: Initial Access")
    ssh_root_login(r, ip)
    time.sleep(1)
    print("   Phase 4: Privilege Escalation")
    privilege_escalation(r)
    time.sleep(1)
    print("   Phase 5: Persistence")
    new_user_created(r)
    print("\n   ✅ Full attack chain injected!")


SCENARIOS = {
    "ssh_brute_force":      ssh_brute_force,
    "ssh_root_login":       ssh_root_login,
    "port_scan":            port_scan,
    "privilege_escalation": privilege_escalation,
    "new_user_created":     new_user_created,
    "user_enumeration":     user_enumeration,
    "mixed_attack":         mixed_attack,
}


def main():
    parser = argparse.ArgumentParser(description="SIEM Lite Attack Simulator")
    parser.add_argument("--scenario", choices=list(SCENARIOS), default=None,
                        help="Run a specific scenario")
    parser.add_argument("--loop",     action="store_true",
                        help="Loop forever with random delays")
    parser.add_argument("--list",     action="store_true",
                        help="List available scenarios")
    args = parser.parse_args()

    if args.list:
        print("Available scenarios:")
        for name in SCENARIOS:
            print(f"  {name}")
        return

    r = redis.from_url(REDIS_URL)
    try:
        r.ping()
        print(f"✅ Connected to Redis at {REDIS_URL}")
    except Exception as e:
        print(f"❌ Cannot connect to Redis: {e}")
        sys.exit(1)

    if args.loop:
        print("🔁 Looping attack simulation (Ctrl+C to stop)\n")
        while True:
            scenario_name = args.scenario or random.choice(list(SCENARIOS))
            fn = SCENARIOS[scenario_name]
            if fn.__code__.co_varcount > 1:
                fn(r)
            else:
                fn(r)
            delay = random.uniform(5, 15)
            print(f"\n   ⏳ Next attack in {delay:.0f}s…")
            time.sleep(delay)
    else:
        scenario_name = args.scenario or "mixed_attack"
        fn = SCENARIOS[scenario_name]
        fn(r)
        print("\n✅ Done. Check your SIEM Lite dashboard!")


if __name__ == "__main__":
    main()
