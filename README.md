# SIEM Lite

A lightweight Security Information and Event Management system built with Python, FastAPI, React, and Redis. Designed as a portfolio-quality project demonstrating full-stack cybersecurity automation.

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react&logoColor=black)
![Redis](https://img.shields.io/badge/Redis-7-DC382D?style=flat&logo=redis&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-4169E1?style=flat&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Installation — Linux (Arch / Ubuntu)](#-installation--linux)
- [Installation — Windows](#-installation--windows)
- [Configuration](#-configuration)
- [Detection Rules](#-detection-rules)
- [Playbooks](#-playbooks)
- [Using the Dashboard](#-using-the-dashboard)
- [API Reference](#-api-reference)
- [Testing](#-testing)
- [Attack Simulator](#-attack-simulator)
- [Project Structure](#-project-structure)
- [MITRE ATT&CK Coverage](#-mitre-attck-coverage)
- [Portfolio Notes](#-portfolio-notes)
- [License](#-license)

---

## Features

| Feature | Details |
|---|---|
| **Log Collection** | Watches `/var/log/auth.log`, syslog, nginx + UDP syslog receiver on port 514 |
| **Log Parsing** | 12 pattern types: SSH brute force, sudo abuse, user management, port scans, web errors, JSON logs |
| **IP Enrichment** | GeoIP via ip-api.com + threat scores via AbuseIPDB (free tier) |
| **Detection Engine** | Sigma-inspired YAML rules — threshold and pattern matching with sliding windows |
| **Alert Management** | Deduplication, MITRE ATT&CK tagging, triage workflow (acknowledge / resolve / false-positive) |
| **Automation** | Playbook runner: auto-block IPs via iptables, Slack/email notifications, Jira/GitHub ticket creation |
| **Live Dashboard** | React SPA with real-time SSE event feed, charts, alert triage, rule editor, blocked IP management |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          SIEM Lite                              │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  Log Sources │    │  Enrichment  │    │   Detection      │  │
│  │              │    │              │    │   Engine         │  │
│  │ auth.log     │───▶│ ip-api.com   │───▶│                  │  │
│  │ syslog       │    │ AbuseIPDB    │    │ rules.yaml       │  │
│  │ kern.log     │    │              │    │ threshold rules  │  │
│  │ UDP :514     │    └──────────────┘    │ pattern rules    │  │
│  └──────────────┘            │           └──────────┬───────┘  │
│                              ▼                      │          │
│                      ┌──────────────┐               ▼          │
│                      │    Redis     │      ┌──────────────────┐ │
│                      │              │      │  Playbook Runner │ │
│                      │ event queue  │      │                  │ │
│                      │ alert pub/sub│      │ block_ip         │ │
│                      │ SSE stream   │      │ notify_slack     │ │
│                      └──────┬───────┘      │ create_ticket    │ │
│                             │              └──────────────────┘ │
│                             ▼                                   │
│                      ┌──────────────┐    ┌──────────────────┐  │
│                      │  PostgreSQL  │    │   FastAPI        │  │
│                      │              │    │                  │  │
│                      │ events       │◀───│ /api/events      │  │
│                      │ alerts       │    │ /api/alerts      │  │
│                      │ rules        │    │ /api/stats       │  │
│                      │ blocked_ips  │    │ /api/rules       │  │
│                      │ incidents    │    │ /api/blocked-ips │  │
│                      └──────────────┘    └──────────┬───────┘  │
│                                                     │          │
│                                                     ▼          │
│                                          ┌──────────────────┐  │
│                                          │  React Dashboard │  │
│                                          │                  │  │
│                                          │ Dashboard KPIs   │  │
│                                          │ Live Event Feed  │  │
│                                          │ Alert Triage     │  │
│                                          │ Rules Manager    │  │
│                                          │ Blocked IPs      │  │
│                                          └──────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Installation — Linux

> Tested on **Arch Linux** and **Ubuntu 22.04+**. Steps shown for both.

### Prerequisites

| Tool | Arch | Ubuntu/Debian |
|---|---|---|
| Docker + Compose | `sudo pacman -S docker docker-compose` | `sudo apt install docker.io docker-compose-v2` |
| Git | `sudo pacman -S git` | `sudo apt install git` |
| Python 3.10+ | `sudo pacman -S python python-pip` | `sudo apt install python3 python3-pip` |

**Start Docker and add your user to the docker group:**

```bash
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
newgrp docker          # apply group without logging out
```

**Verify:**

```bash
docker --version        # Docker 24+
docker compose version  # v2+
```

---

### Step 1 — Get the Project

```bash
# Option A — clone from GitHub
git clone https://github.com/yourname/siem-lite.git
cd siem-lite

# Option B — from downloaded ZIP
unzip ~/Downloads/siem-lite-COMPLETE.zip
cd siem-lite
```

---

### Step 2 — Configure Environment

```bash
cp .env.example .env
nano .env             # edit optional settings (Slack, AbuseIPDB, email)
```

Key settings (all optional — defaults work out of the box):

```env
IPTABLES_DRY_RUN=true        # change to false in production
ABUSEIPDB_API_KEY=            # free at https://www.abuseipdb.com
SLACK_WEBHOOK_URL=            # incoming webhook from Slack
```

---

### Step 3 — Fix the docker-compose.yml Version Warning

```bash
sed -i '/^version:/d' docker-compose.yml
```

---

### Step 4 — Build and Start

```bash
docker compose up --build
```

Wait for:

```
api | INFO:     Application startup complete.
```

> To run in background: `docker compose up --build -d`

---

### Step 5 — Load Rules and Test

```bash
# New terminal tab — load detection rules
curl -X POST http://localhost:8000/api/rules/sync

# Install simulator dependency
pip install redis --break-system-packages

# Run attack simulation
python scripts/simulate_attacks.py --scenario mixed_attack
```

Open **http://localhost:3000** and refresh — events and alerts will appear.

---

### Linux Troubleshooting

| Problem | Fix |
|---|---|
| `permission denied` on docker | Run `newgrp docker` or log out and back in |
| `siemdb does not exist` on first boot | `docker compose down -v && docker compose up --build` |
| Port already in use | `sudo ss -tlnp \| grep 3000` then `sudo kill <PID>` |
| Pip install fails on Arch | Add `--break-system-packages` flag |

---

## Installation — Windows

> **Tested on:** Windows 10 (21H2+) and Windows 11
> **Time:** ~20–30 minutes

### Prerequisites Overview

| Tool | Purpose | Required |
|---|---|---|
| WSL 2 | Linux environment inside Windows | Yes |
| Docker Desktop | Run all containers | Yes |
| Git | Clone / unzip project | Yes |
| Python 3.10+ | Run attack simulator | Yes |
| Windows Terminal | Better terminal experience | Recommended |

---

### Step 1 — Enable WSL 2

Open **PowerShell as Administrator** (right-click Start → "Windows PowerShell (Admin)"):

```powershell
wsl --install
```

Restart when prompted. After restart Ubuntu opens — set a username and password.

**Verify WSL 2 is active:**

```powershell
wsl --list --verbose
```

Expected:

```
  NAME      STATE    VERSION
* Ubuntu    Running  2
```

> If VERSION shows `1`: `wsl --set-version Ubuntu 2`

---

### Step 2 — Install Docker Desktop

Download: [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)

Run the installer — keep all defaults, ensure these are checked:
- Use WSL 2 instead of Hyper-V
- Add shortcut to desktop

**Verify in PowerShell:**

```powershell
docker --version
docker compose version
```

> If "WSL 2 installation incomplete": Docker Desktop → Settings → Resources → WSL Integration → enable Ubuntu.

---

### Step 3 — Install Git

[https://git-scm.com/download/win](https://git-scm.com/download/win)

During install, set **Line ending conversions** to `Checkout as-is, commit as-is`.

```powershell
git --version   # verify
```

---

### Step 4 — Install Python

[https://www.python.org/downloads/windows](https://www.python.org/downloads/windows)

> **Check "Add Python to PATH"** at the bottom of the installer before clicking Install.

```powershell
python --version   # Python 3.11.x
pip --version
```

> If `python` is not found: Settings → Apps → "App execution aliases" → disable Python store aliases.

---

### Step 5 — Install Windows Terminal (Recommended)

```powershell
winget install Microsoft.WindowsTerminal
```

---

### Step 6 — Get the Project

```powershell
# Option A — from downloaded ZIP
# Right-click siem-lite-COMPLETE.zip → Extract All → C:\Projects\
cd C:\Projects\siem-lite

# Option B — from GitHub
cd C:\Projects
git clone https://github.com/yourname/siem-lite.git
cd siem-lite
```

---

### Step 7 — Fix Line Endings

Windows `\r\n` line endings break Linux containers. Fix before building:

```powershell
wsl find . -name "*.py" -exec dos2unix {} \;
wsl dos2unix Dockerfile.api docker-compose.yml
```

Or add a `.gitattributes` to enforce this permanently:

```powershell
echo "* text=auto eol=lf" > .gitattributes
```

---

### Step 8 — Configure Environment

```powershell
copy .env.example .env
notepad .env
```

Defaults work. Optionally add:

```env
IPTABLES_DRY_RUN=true
ABUSEIPDB_API_KEY=
SLACK_WEBHOOK_URL=
```

---

### Step 9 — Remove Obsolete Version Field

```powershell
(Get-Content docker-compose.yml) | Where-Object { $_ -notmatch '^version:' } | Set-Content docker-compose.yml
```

---

### Step 10 — Build and Start

Make sure Docker Desktop is running (check system tray), then:

```powershell
docker compose up --build
```

Takes 5–10 minutes first time. Wait for:

```
api  | INFO:     Application startup complete.
```

> Background mode: `docker compose up --build -d`

---

### Step 11 — Load Rules and Test

```powershell
# New terminal tab — load detection rules
curl -X POST http://localhost:8000/api/rules/sync

# Install simulator dependency
pip install redis

# Run attack simulation
python scripts\simulate_attacks.py --scenario mixed_attack
```

Open **http://localhost:3000** and refresh — events and alerts will appear.

---

### Windows Troubleshooting

| Problem | Fix |
|---|---|
| Docker Desktop won't start | Enable virtualization in BIOS (Intel VT-x / AMD-V): Task Manager → Performance → CPU → Virtualization: Enabled |
| `permission denied` on docker | Ensure Docker Desktop is running; restart it; or run PowerShell as Administrator |
| `siemdb does not exist` | `docker compose down -v` then `docker compose up --build` |
| Port 3000 or 8000 in use | `netstat -ano \| findstr :3000` → `taskkill /PID <pid> /F` |
| Simulator can't reach Redis | `docker compose exec redis redis-cli ping` — should return `PONG` |
| WSL 2 using too much memory | Create `C:\Users\YourName\.wslconfig` with `[wsl2]` `memory=4GB` then `wsl --shutdown` |

---

## 🔧 Configuration

All config lives in `.env`. Full reference:

| Variable | Default | Description |
|---|---|---|
| `IPTABLES_DRY_RUN` | `true` | Set `false` in prod to enable real IP blocking |
| `AUTO_UNBLOCK_MINUTES` | `60` | Auto-unblock timer (0 = never) |
| `ENRICH_EVENTS` | `true` | Enable IP geolocation + threat scoring |
| `ABUSEIPDB_API_KEY` | — | Free key at [abuseipdb.com](https://www.abuseipdb.com/) |
| `SLACK_WEBHOOK_URL` | — | Incoming webhook from Slack app settings |
| `ALERT_EMAIL` | — | Destination email for alerts |
| `SMTP_USER` / `SMTP_PASS` | — | Gmail: use an [App Password](https://support.google.com/accounts/answer/185833) |
| `SMTP_HOST` / `SMTP_PORT` | `smtp.gmail.com` / `587` | SMTP server settings |
| `JIRA_URL` / `JIRA_API_TOKEN` | — | Jira Cloud integration |
| `JIRA_PROJECT_KEY` | `SEC` | Jira project key for tickets |
| `GITHUB_TOKEN` / `GITHUB_REPO` | — | GitHub Issues integration (`org/repo`) |

---

## Detection Rules

Rules live in `detection/rules.yaml` using a Sigma-inspired format:

```yaml
- id: SSH-001
  name: SSH Brute Force Attack
  description: More than 5 failed SSH logins from one IP within 60s
  enabled: true
  severity: high
  category: authentication
  mitre_tactic: "TA0006 - Credential Access"
  mitre_technique: "T1110 - Brute Force"
  condition_type: threshold
  condition:
    event_type: ssh_failed_login
    count: 5
    window_seconds: 60
    group_by: source_ip
  playbook: block_ip_and_notify
  tags: [brute-force, ssh]
```

**Condition types:**

| Type | Description | Example use |
|---|---|---|
| `threshold` | Fires when event count exceeds N within a time window | Brute force, port scan |
| `pattern` | Fires on field value match or substring | Root login, specific commands |

**Reload rules without restarting:**

```bash
curl -X POST http://localhost:8000/api/rules/sync
```

**Built-in rules:**

| ID | Name | Severity | Trigger |
|---|---|---|---|
| SSH-001 | SSH Brute Force | High | 5+ failed logins / 60s |
| SSH-002 | SSH Root Login | Critical | Root login accepted |
| SSH-003 | User Enumeration | Medium | 3+ invalid users / 120s |
| PRIV-001 | Sudo Auth Failure | High | Failed sudo |
| PRIV-002 | Sensitive Sudo Command | High | sudo to bash/python/nc |
| ACCT-001 | New User Created | Medium | useradd detected |
| ACCT-002 | User Account Deleted | High | userdel detected |
| NET-001 | Port Scan | Medium | 10+ blocked ports / 30s |
| NET-002 | IP Banned by Fail2ban | Medium | fail2ban ban event |

---

## Playbooks

| Playbook | Triggers | Actions |
|---|---|---|
| `block_ip_and_notify` | SSH brute force, port scan | iptables DROP + Slack/email |
| `notify_only` | Root login, sudo abuse, user creation | Slack/email only |
| `create_ticket` | Any alert | Local DB incident + optional Jira/GitHub |

**Add a custom playbook:**

1. Create `automation/playbooks/my_playbook.py` with:
```python
def execute(alert_payload: dict) -> dict:
    # your logic here
    return {"status": "success"}
```
2. Register it in `automation/playbook_runner.py`:
```python
PLAYBOOK_REGISTRY = {
    ...
    "my_playbook": "automation.playbooks.my_playbook",
}
```
3. Reference it in a rule's `playbook:` field in `rules.yaml`

---

## Using the Dashboard

| Page | URL | What to do |
|---|---|---|
| **Dashboard** | `/` | KPI cards, event timeline, top IPs, alert status breakdown |
| **Live Events** | `/events` | Real-time SSE stream — filter, pause, search, clear |
| **Alerts** | `/alerts` | Triage alerts — expand row for details, add analyst notes |
| **Rules** | `/rules` | Toggle rules on/off, click severity badge to edit, sync YAML |
| **Blocked IPs** | `/blocked-ips` | View auto-blocks, manually block/unblock IPs |

**Alert triage actions:**

| Action | Meaning |
|---|---|
| Acknowledge | Seen it, currently investigating |
| Resolve | Confirmed and closed |
| False Positive | Noise — helps track rule quality |

---

## API Reference

Interactive docs at **http://localhost:8000/docs**

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/events` | List events (paginated, filterable by severity, category, IP, search) |
| `GET` | `/api/events/{id}` | Single event detail |
| `GET` | `/api/events/stream/live` | SSE real-time event stream |
| `GET` | `/api/alerts` | List alerts (paginated, filterable) |
| `PATCH` | `/api/alerts/{id}` | Update status / analyst notes |
| `POST` | `/api/alerts/{id}/acknowledge` | Acknowledge alert |
| `POST` | `/api/alerts/{id}/resolve` | Resolve alert |
| `POST` | `/api/alerts/{id}/false-positive` | Mark false positive |
| `GET` | `/api/alerts/stream/live` | SSE real-time alert stream |
| `GET` | `/api/stats/dashboard` | All KPIs in one call |
| `GET` | `/api/stats/top-ips` | Top source IPs |
| `GET` | `/api/stats/top-event-types` | Top event types |
| `GET` | `/api/stats/mitre` | MITRE ATT&CK coverage heatmap data |
| `GET` | `/api/rules` | List detection rules |
| `PATCH` | `/api/rules/{id}` | Enable/disable, change severity |
| `POST` | `/api/rules/sync` | Reload rules.yaml → DB |
| `GET` | `/api/blocked-ips` | List blocked IPs |
| `POST` | `/api/blocked-ips` | Manually block an IP |
| `DELETE` | `/api/blocked-ips/{ip}` | Unblock an IP |

---

## Testing

```bash
# Run all tests
pytest

# Run by milestone
pytest tests/test_ingestion.py -v    # M1: log parsing (20 tests)
pytest tests/test_detection.py -v    # M2: rule engine (22 tests)
pytest tests/test_automation.py -v   # M3: playbooks
pytest tests/test_api.py -v          # M4: API routes (25 tests)
pytest tests/test_enrichment.py -v   # M6: enrichment (15 tests)
```

---

## Attack Simulator

```bash
# Run all scenarios in sequence (full kill-chain demo)
python scripts/simulate_attacks.py --scenario mixed_attack

# Run individual scenarios
python scripts/simulate_attacks.py --scenario ssh_brute_force
python scripts/simulate_attacks.py --scenario ssh_root_login
python scripts/simulate_attacks.py --scenario port_scan
python scripts/simulate_attacks.py --scenario privilege_escalation
python scripts/simulate_attacks.py --scenario new_user_created
python scripts/simulate_attacks.py --scenario user_enumeration

# Loop forever (great for live demos)
python scripts/simulate_attacks.py --loop

# List all available scenarios
python scripts/simulate_attacks.py --list
```

---

## Common Commands

```bash
# View all service logs
docker compose logs -f

# View one service
docker compose logs -f detection
docker compose logs -f api

# Stop everything
docker compose down

# Wipe database and start fresh
docker compose down -v && docker compose up --build

# Restart one service after code changes
docker compose restart api

# Check container health
docker compose ps
docker stats
```

---

## Project Structure

```
siem-lite/
├── ingestion/
│   ├── parser.py           # Log parsing — 12 pattern types
│   ├── log_watcher.py      # File watcher + UDP syslog on :514
│   └── enrichment.py       # IP geo + AbuseIPDB threat scoring
├── detection/
│   ├── rules.yaml          # Detection rules (Sigma-inspired)
│   └── rule_engine.py      # Threshold + pattern evaluator
├── automation/
│   ├── playbook_runner.py  # Dispatches playbooks on alerts
│   └── playbooks/
│       ├── block_ip.py         # iptables blocking
│       ├── notify_slack.py     # Slack + SMTP email
│       └── create_ticket.py    # Local DB + Jira + GitHub
├── api/
│   ├── main.py             # FastAPI app entry point
│   ├── schemas.py          # Pydantic request/response models
│   └── routes/
│       ├── events.py       # GET /api/events + SSE stream
│       ├── alerts.py       # GET/PATCH /api/alerts + triage
│       ├── stats.py        # Dashboard KPIs + time-series
│       ├── rules.py        # Rule CRUD + YAML sync
│       └── blocked_ips.py  # Block/unblock IP management
├── database/
│   ├── models.py           # SQLAlchemy ORM models
│   └── connection.py       # Async engine + session factory
├── dashboard/              # React + Vite SPA
│   ├── src/
│   │   ├── pages/          # Dashboard, Events, Alerts, Rules, BlockedIPs
│   │   ├── components/     # Sidebar, Badges, shared UI
│   │   ├── hooks/          # useFetch, usePolling, useSSE
│   │   └── lib/            # API client, Toast notifications
│   ├── Dockerfile.dashboard
│   └── nginx.conf
├── scripts/
│   └── simulate_attacks.py # 7 attack scenarios + kill-chain demo
├── tests/                  # 80+ pytest tests
├── docker-compose.yml
├── Dockerfile.api
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Rules |
|---|---|---|
| Initial Access | T1078 — Valid Accounts | SSH-002 |
| Credential Access | T1110 — Brute Force | SSH-001, SSH-003 |
| Discovery | T1046 — Network Service Discovery | NET-001 |
| Privilege Escalation | T1548 — Abuse Elevation Control | PRIV-001, PRIV-002 |
| Persistence | T1136 — Create Account | ACCT-001, ACCT-002 |

---

## Portfolio Notes

This project demonstrates:

- **Full-stack Python** — async FastAPI, SQLAlchemy ORM, Redis pub/sub
- **Security engineering** — SIEM architecture, detection logic, MITRE ATT&CK mapping
- **Automation** — event-driven playbooks, auto-remediation, multi-channel alerting
- **Modern React** — SSE real-time streams, custom hooks, Recharts data visualization
- **DevOps** — Docker Compose, multi-service orchestration, nginx reverse proxy, health checks
- **Testing** — 80+ unit + integration tests across all modules with pytest

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*SIEM Lite — Built for learning, portfolio-ready, production-aware.*
