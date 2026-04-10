# FMTool

**Firewall Migration Tool** — Migrate pfSense configurations to Sophos XGS via API.

FMTool is a local web application that parses pfSense XML backups and pushes the
configuration to a Sophos XGS firewall using its REST API. It runs on your own
machine inside the Sophos management network — no cloud, no login, no telemetry.

---

## Features

- Import pfSense XML backups and browse every section in a clean UI
- Migrate **aliases**, **firewall rules**, **NAT rules**, **services**, **DNS
  host overrides**, **static routes**, and more
- **Dry-run** previews for every category — see exactly what will be pushed
- **Rule merging**: combine multiple pfSense rules into a single Sophos rule
- **Rollback**: delete migrated Sophos objects per item or in bulk
- **Activity log** with full audit trail and SSE live progress
- **Reports**: export migration results as CSV or PDF (branded with your logo)
- Works entirely offline against a reachable Sophos XGS

---

## One-line install (Windows PowerShell)

Open **PowerShell** and run:

```powershell
irm https://raw.githubusercontent.com/404-developer-AI/FMTool/master/install.ps1 | iex
```

The installer will:

1. Check that `git` and Python 3.10+ are installed
2. Clone FMTool into a folder you choose (default: `%USERPROFILE%\FMTool`)
3. Create a Python virtual environment
4. Install all dependencies
5. Seed `config.local.py` from the example
6. Optionally start FMTool immediately

> **First-time PowerShell users:** if `irm | iex` is blocked, run
> `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` once,
> then retry. You do **not** need to run PowerShell as administrator.

---

## Manual install (Windows)

If you prefer to install step by step:

### 1. Prerequisites

- **Python 3.10 or newer** — <https://www.python.org/downloads/windows/>
  (tick **Add Python to PATH** during setup)
- **Git for Windows** — <https://git-scm.com/download/win>
- A **Sophos XGS** firewall with the API enabled and reachable on port **4444**

Verify in PowerShell:

```powershell
python --version
git --version
```

### 2. Clone and set up

```powershell
# Pick any folder you like
cd $HOME
git clone https://github.com/404-developer-AI/FMTool.git
cd FMTool

# Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Sophos credentials

```powershell
Copy-Item config.local.example.py config.local.py
notepad config.local.py
```

Fill in:

```python
SOPHOS_HOST     = "192.0.2.1"        # your Sophos XGS mgmt IP
SOPHOS_USERNAME = "admin"
SOPHOS_PASSWORD = "your-password"
SOPHOS_PORT     = 4444
```

`config.local.py` is gitignored — it will never be committed.

### 4. Run

```powershell
python run.py
```

Open <http://127.0.0.1:5000> in your browser.

To stop the server, press **Ctrl+C** in the PowerShell window.

---

## Daily use

After the first install, starting FMTool is just:

```powershell
cd $HOME\FMTool
.\venv\Scripts\Activate.ps1
python run.py
```

Or, if you prefer a one-liner without activating the venv:

```powershell
cd $HOME\FMTool; .\venv\Scripts\python.exe run.py
```

---

## Enabling the Sophos XGS API

In the Sophos XGS web admin:

1. **Backup & firmware → API**
2. Enable **API Configuration**
3. Add the IP address of the machine running FMTool to **Allowed IP Address**
4. Save

Test the connection from FMTool's **Settings** page after launch.

---

## Updating FMTool

```powershell
cd $HOME\FMTool
git pull
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Or just re-run the one-line installer — it detects an existing checkout and
offers to pull the latest changes.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `python` not recognised | Reinstall Python and tick **Add Python to PATH**, then open a new PowerShell window |
| `Activate.ps1 cannot be loaded` | Run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` once |
| `SSL: CERTIFICATE_VERIFY_FAILED` when talking to Sophos | Expected on self-signed certs — FMTool disables verification internally |
| `Connection refused` to Sophos | Check that the API is enabled and your IP is in the allowed list |
| Port 5000 already in use | Edit `run.py` and change the `port=` value |

---

## Project structure

```
FMTool/
├── app/                    # Application package
│   ├── __init__.py         # Flask app factory
│   ├── routes/             # Route blueprints
│   ├── models/             # Database models
│   ├── services/           # Parser, Sophos client, migrators
│   └── templates/          # Jinja2 HTML templates
├── static/                 # CSS, JS, images
├── instance/               # Local DB + uploads (gitignored)
├── example/                # Example pfSense backup (fake data)
├── config.py               # App defaults
├── config.local.py         # Your Sophos credentials (gitignored)
├── install.ps1             # Windows one-line installer
├── run.py                  # Entry point
├── requirements.txt        # Python dependencies
└── README.MD               # This file
```

---

## Security notes

- FMTool runs on **127.0.0.1 only** — not exposed to the network
- No login is required because the app is not reachable from outside your host
- Credentials live in `config.local.py`, which is gitignored
- The repository never contains real IPs, hostnames, or backups

---

## License

MIT
