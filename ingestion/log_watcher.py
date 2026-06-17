
import os
import json
import time
import socket
import logging
import threading
from pathlib import Path
from typing import List

import redis
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from ingestion.parser import parse_log_line
from ingestion.enrichment import enrich_event
from database.connection import create_tables_sync
from database.models import Event
from sqlalchemy.orm import Session
from sqlalchemy import create_engine

ENRICH_ENABLED = os.getenv("ENRICH_EVENTS", "true").lower() == "true"

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://siem:siempass@localhost:5432/siemdb")

WATCHED_FILES = {
    "/host_logs/auth.log": "auth.log",
    "/host_logs/syslog": "syslog",
    "/host_logs/kern.log": "kern.log",
    "/host_logs/nginx/access.log": "nginx",
    "/var/log/auth.log": "auth.log",
    "/var/log/syslog": "syslog",
}

SYSLOG_UDP_PORT = 514
REDIS_EVENTS_CHANNEL = "siem:events"
REDIS_EVENTS_QUEUE = "siem:events:queue"


class LogFileHandler(FileSystemEventHandler):

    def __init__(self, filepath: str, source: str, redis_client: redis.Redis):
        self.filepath = filepath
        self.source = source
        self.redis = redis_client
        self._file_pos = self._get_file_size()

    def _get_file_size(self) -> int:
        try:
            return os.path.getsize(self.filepath)
        except OSError:
            return 0

    def on_modified(self, event):
        if event.src_path != self.filepath:
            return
        self._read_new_lines()

    def _read_new_lines(self):
        try:
            with open(self.filepath, "r", errors="replace") as f:
                f.seek(self._file_pos)
                new_lines = f.readlines()
                self._file_pos = f.tell()

            for line in new_lines:
                event = parse_log_line(line, self.source)
                if event:
                    self._publish(event)
        except (OSError, IOError) as e:
            logger.warning(f"Error reading {self.filepath}: {e}")

    def _publish(self, event: dict):
        if ENRICH_ENABLED:
            event = enrich_event(event)
        payload = json.dumps(event)
        self.redis.lpush(REDIS_EVENTS_QUEUE, payload)
        self.redis.publish(REDIS_EVENTS_CHANNEL, payload)
        score = event.get("threat_score", 0)
        logger.debug(f"[{self.source}] Published: {event['event_type']} from {event.get('source_ip')} [score={score:.0f}]")


def start_file_watchers(redis_client: redis.Redis) -> Observer:
    observer = Observer()
    watched_dirs = set()

    for filepath, source in WATCHED_FILES.items():
        if not os.path.exists(filepath):
            logger.info(f"Skipping {filepath} (not found)")
            continue

        handler = LogFileHandler(filepath, source, redis_client)
        dir_path = str(Path(filepath).parent)

        if dir_path not in watched_dirs:
            observer.schedule(handler, dir_path, recursive=False)
            watched_dirs.add(dir_path)
            logger.info(f"Watching: {filepath} [{source}]")

    observer.start()
    return observer


def start_syslog_udp(redis_client: redis.Redis):
    def _listen():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("0.0.0.0", SYSLOG_UDP_PORT))
            logger.info(f"Syslog UDP listener on port {SYSLOG_UDP_PORT}")
        except PermissionError:
            sock.bind(("0.0.0.0", 5140))
            logger.info("Syslog UDP listener on port 5140 (dev mode)")

        while True:
            try:
                data, addr = sock.recvfrom(65535)
                line = data.decode("utf-8", errors="replace")
                event = parse_log_line(line, f"syslog_udp:{addr[0]}")
                if event:
                    if not event.get("source_ip"):
                        event["source_ip"] = addr[0]
                    payload = json.dumps(event)
                    redis_client.lpush(REDIS_EVENTS_QUEUE, payload)
            except Exception as e:
                logger.warning(f"Syslog UDP error: {e}")

    t = threading.Thread(target=_listen, daemon=True)
    t.start()
    return t


def generate_demo_events(redis_client: redis.Redis):
    import random
    demo_logs = [
        "Jun 12 10:00:01 myhost sshd[1234]: Failed password for root from 45.33.32.156 port 22 ssh2",
        "Jun 12 10:00:02 myhost sshd[1234]: Failed password for admin from 45.33.32.156 port 22 ssh2",
        "Jun 12 10:00:03 myhost sshd[1234]: Failed password for ubuntu from 45.33.32.156 port 22 ssh2",
        "Jun 12 10:01:00 myhost sshd[2345]: Accepted password for deploy from 192.168.1.10 port 5555 ssh2",
        "Jun 12 10:02:00 myhost sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
        "Jun 12 10:03:00 myhost useradd[3456]: new user: name=hacker, UID=1001, GID=1001",
        "Jun 12 10:05:00 myhost sshd[9999]: Invalid user testuser from 198.51.100.42",
        "Jun 12 10:06:00 myhost kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.1 DPT=4444",
        "Jun 12 10:10:00 myhost sshd[1234]: Failed password for root from 45.33.32.156 port 22 ssh2",
        "Jun 12 10:10:01 myhost sshd[1234]: Failed password for root from 45.33.32.156 port 22 ssh2",
        "Jun 12 10:10:02 myhost sshd[1234]: Failed password for root from 45.33.32.156 port 22 ssh2",
    ]

    def _send():
        while True:
            line = random.choice(demo_logs)
            event = parse_log_line(line, "demo")
            if event:
                redis_client.lpush(REDIS_EVENTS_QUEUE, json.dumps(event))
            time.sleep(random.uniform(2, 8))

    t = threading.Thread(target=_send, daemon=True)
    t.start()
    logger.info("Demo event generator started")


if __name__ == "__main__":
    create_tables_sync()
    r = redis.from_url(REDIS_URL)

    observer = start_file_watchers(r)
    syslog_thread = start_syslog_udp(r)

    real_files = [f for f in WATCHED_FILES if os.path.exists(f)]
    if not real_files:
        logger.info("No real log files found — starting demo event generator")
        generate_demo_events(r)

    logger.info("Log watcher running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
