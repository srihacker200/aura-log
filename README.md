# AURA LOG

A simple, responsive attendance log for recording students and reviewing daily attendance. It runs locally with SQLite and includes a Render Blueprint for a one-step web deployment with persistent storage.

> **Starter project:** This version does not include user accounts or access controls. Do not store real student or other sensitive information on a public deployment until authentication and appropriate privacy protections have been added.

## Run locally

Requires Python 3.10+.

```bash
git clone https://github.com/srihacker200/aura-log.git
cd aura-log
python -m venv .venv
# macOS/Linux:
source .venv/bin/activate
# Windows PowerShell:
# .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>.

## Deploy to Render

1. Push this branch to GitHub and create a Render account.
2. In Render, choose **New → Blueprint**, connect this repository, and select `copilot/aura-log-premium-foundation`.
3. Accept the settings from `render.yaml`. Render will create the web service and mount a persistent disk for the SQLite database.

The database is stored at `/var/data/aura_log.db` on Render. For other hosts, set `DATABASE_PATH` to a persistent location; many free hosting filesystems are temporary and can lose SQLite data on restart.

## Features

- Add an attendance entry with student name, class/group, date, and status.
- View recent records and attendance totals.
- SQLite database initialized automatically on first run.
- Responsive interface for mobile and desktop.

## Configuration

- `PORT` (default `5000`): HTTP port.
- `DATABASE_PATH` (default `instance/aura_log.db`): SQLite database file path.
- `FLASK_DEBUG` (default off): set to `1` for local development only.
