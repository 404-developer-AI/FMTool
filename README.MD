# FMTool

**Firewall Migration Tool** — Migrate pfSense configurations to Sophos XGS via API.

FMTool is a local web application that parses pfSense XML backups and pushes the configuration to a Sophos XGS firewall using its REST API.

## Features

- Import pfSense XML backup files
- Overview dashboard with migration status per category
- Migrate aliases, firewall rules, NAT rules, VPN, and more
- Rule merging: combine multiple pfSense rules into a single Sophos rule
- Dry-run mode: preview changes before pushing to Sophos
- Rollback support for migrated objects

## Quick Start

### Requirements

- Python 3.10+
- A Sophos XGS firewall with API access enabled
- Network access to the Sophos XGS management interface (port 4444)

### Installation

```bash
# Clone the repository
git clone https://github.com/404-developer-AI/FMTool.git
cd FMTool

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Run

```bash
python run.py
```

Open your browser and go to [http://127.0.0.1:5000](http://127.0.0.1:5000).

## Project Structure

```
FMTool/
├── app/                    # Application package
│   ├── __init__.py         # Flask app factory
│   ├── routes/             # Route blueprints
│   ├── models/             # Database models
│   ├── services/           # Business logic (parser, API client)
│   └── templates/          # Jinja2 HTML templates
├── static/                 # CSS, JS, images
├── instance/               # Local data (database, uploads) — not committed
├── example/                # Example files for development
├── config.py               # Application configuration
├── run.py                  # Entry point
├── requirements.txt        # Python dependencies
└── README.MD               # This file
```

## License

MIT
