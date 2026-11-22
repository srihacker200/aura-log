# AURA LOG

AURA LOG is a responsive attendance-management app with admin, teacher and student accounts; class rosters; daily attendance; reporting; CSV export; and an audit log. It uses Flask, SQLite, password hashing, CSRF protection, secure cookie defaults and login throttling.

## Important before using real student data
This is a deployable application foundation, not a certification or guarantee of production readiness. Have your organization review applicable privacy/security requirements, establish backups and retention procedures, and arrange an independent security review. SQLite is suitable for a small single-instance deployment; use a managed database for multiple instances or significant concurrency. Teachers currently share the organization-wide roster and attendance scope. Email/SMS alerts, bulk import, password reset and fine-grained class-level teacher permissions are not included.

## Start locally
Requires Python 3.10+.

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export BOOTSTRAP_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python app.py
```

On Windows PowerShell, set the two variables with `$env:SECRET_KEY='...'` and `$env:BOOTSTRAP_TOKEN='...'`. Visit <http://127.0.0.1:5000/setup>, enter the bootstrap token and create the first administrator (use a unique password with 12+ characters). Keep both secrets private. Setup closes after that initial account is created.

## Deploy on Render
1. In Render choose **New → Blueprint**, connect this repository and select branch `copilot/aura-log-premium-foundation`.
2. Review and apply `render.yaml`. The service needs a persistent disk; hosting may incur charges.
3. In the Render service's environment settings, add `BOOTSTRAP_TOKEN` with a long random value. Deploy and visit `/setup` to create the administrator. Remove `BOOTSTRAP_TOKEN` after setup.
4. Use HTTPS, strong unique passwords, regular backups, and tested restore procedures.

The Blueprint stores SQLite at `/var/data/aura_log.db`. Other hosts need a persistent filesystem; ephemeral filesystems can erase the database on restart.

## Roles and features
- **Admin:** accounts and roles, classes, students, attendance, reports/CSV, audit history.
- **Teacher:** classes, students, attendance and reports.
- **Student:** views only attendance for a roster entry whose email matches their login.
- Edit/delete attendance, add notes, and enforce one record per student/date.
- Existing starter attendance records are migrated to roster/class records on app startup.

Create student user accounts from **Users**; the email must match the roster student's email. Share credentials securely. No email delivery/password-reset flow is included.

## Settings
`SECRET_KEY` (random session/CSRF secret), `BOOTSTRAP_TOKEN` (temporary initial-admin secret), `DATABASE_PATH` (default `instance/aura_log.db`), `PORT` (default `5000`), `COOKIE_SECURE` (default secure-only), and `FLASK_DEBUG` (local development only).
