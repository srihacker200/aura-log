# AURA LOG

AURA LOG is a Flask attendance-management app backed by MongoDB Atlas. It includes admin, teacher and student accounts; class rosters; daily attendance; reporting; CSV export; and an admin audit log.

## Security note
Do not commit database credentials or share them in chats. If a database password has been exposed, rotate it in MongoDB Atlas before deployment. Configure secrets only in your host's environment settings. This project is a practical app foundation, not a security certification; obtain your organization's privacy/security review before putting real student data in it. Teachers currently share the organization-wide roster; class-level teacher restrictions, email/SMS alerts, bulk import and password-reset mail are not included.

## Deploy on Render with MongoDB Atlas

1. In Atlas, create or use the `AuraCluster` cluster in project `AURA_LOG`, create a database user, and allow the Render service to connect in **Network Access**. Prefer a narrowly scoped database user; avoid opening access to all IPs unless necessary for your hosting setup. Atlas free-tier eligibility/limits can change.
2. In Render, choose **New → Blueprint**, connect this repository and select branch `copilot/aura-log-premium-foundation`. Review and deploy `render.yaml`.
3. In the Render service environment settings, add `MONGODB_URI` with the Atlas driver URI, replacing `<password>` with the database user's password (URL-encode special characters). Keep it secret. Set `MONGODB_DATABASE` to `aura_log` if not already populated. Add a strong random `BOOTSTRAP_TOKEN`; Render generates `SECRET_KEY` from the Blueprint.
4. Wait for `/health` to report `ok`. Visit the service's `/setup` page, enter the bootstrap token, and create the first administrator with a unique strong password (12+ characters).
5. Remove `BOOTSTRAP_TOKEN` from Render environment settings after administrator setup, then redeploy. Sign in, create classes and students, then create user accounts. For student logins, account email must match the roster student's email.

**Important:** Do not paste the URI/password into GitHub files. The URI belongs only in Render's secret environment variable. Existing SQLite records are not automatically copied to MongoDB; export/backup them before switching if they contain data you need.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export MONGODB_URI='mongodb+srv://<db_user>:<password>@<cluster-host>/?retryWrites=true&w=majority'
export MONGODB_DATABASE=aura_log
export BOOTSTRAP_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python app.py
```

Open <http://127.0.0.1:5000/setup> and create the initial administrator. Never commit your `.env` file or secrets.

## Features

- Role-protected admin, teacher and student sign-in; secure password hashing, CSRF, secure cookies and login throttling.
- Class and student roster management; attendance add/update/delete with notes and duplicate-per-student/date prevention.
- Student portal showing only the signed-in student's matching roster email attendance.
- Date-range summaries, spreadsheet-safe CSV export, and admin audit history.
- MongoDB collections and indexes are provisioned automatically when the app connects.

## Configuration

`MONGODB_URI` (required; secret), `MONGODB_DATABASE` (default `aura_log`), `SECRET_KEY` (required in production; Render Blueprint generates it), `BOOTSTRAP_TOKEN` (temporary initial-admin secret), `COOKIE_SECURE` (true on HTTPS), `PORT` (host-provided), and `FLASK_DEBUG` (local only).
