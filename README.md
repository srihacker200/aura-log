# AURA LOG

Flask attendance management backed by MongoDB Atlas: admin/teacher/student roles, attendance, class and student rosters, reports/CSV, audit history, password-reset email, bulk CSV import, optional absence email notifications, teacher class scoping, readiness/health checks and operational backup/restore scripts.

## Deploy (Render + MongoDB Atlas)
1. Create/use an Atlas project/cluster and database user. Configure Atlas Network Access for the Render service. Rotate any credentials previously shared in chat.
2. Deploy this branch from the Render Blueprint. Configure `MONGODB_URI`, `BOOTSTRAP_TOKEN`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `MAIL_FROM`, and optionally `EMAIL_ABSENCE_NOTIFICATIONS=1` in Render environment settings. Do not commit credentials. Set `MONGODB_DATABASE=aura_log`; Render generates `SECRET_KEY`.
3. Wait for `/ready`, visit `/setup`, create the first admin with a unique strong password, remove `BOOTSTRAP_TOKEN`, then redeploy. Configure and test SMTP before relying on password reset.
4. Create classes, add students or use the CSV template/import, create teacher accounts and select their assigned classes. Student login email must match roster email.

## Features and operational notes
- Password reset uses single-use random tokens stored hashed, expiring after 30 minutes. Responses do not disclose whether an email exists. SMTP is optional but must be configured for delivery.
- Absence email notices are off by default; enable `EMAIL_ABSENCE_NOTIFICATIONS=1` only after SMTP and school contact/data policies are verified. It emails the student's roster email, not a guardian address.
- CSV import requires `full_name,email,class_name`; use the in-app downloadable template. Up to 1,000 rows, 1 MB. Teachers can import only into assigned classes. Unknown classes/invalid rows/duplicates are skipped.
- Teachers can only see and modify assigned classes; administrators assign classes on account creation. Class assignments are stored as class ObjectIds.
- `/health` and `/ready` are database-backed health endpoints. `/monitoring` (admin-only) shows basic record counts, not full infrastructure monitoring or alerting.
- `scripts/mongo_backup.py` and `scripts/mongo_restore.py` require MongoDB Database Tools. Schedule backups from a trusted host/CI job with secrets, encrypt archives, store them outside the app/repository, set retention, and regularly test restores. Restore uses `--drop`; explicit `CONFIRM_RESTORE=YES` is required.
- Security headers, CSRF, password hashing, login throttling, secure-cookie defaults, server-side role checks, upload size/row limits, and spreadsheet-safe CSV output are included. This is not a security certification; conduct a privacy and security review before real student data.
- Existing SQLite data is not automatically migrated; export and plan a separate controlled migration if necessary.

## Local run
Python 3.10+ and MongoDB Database Tools only for backups.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export MONGODB_URI='mongodb+srv://<db_user>:<URL_ENCODED_PASSWORD>@<cluster-host>/?retryWrites=true&w=majority'
export MONGODB_DATABASE=aura_log
export BOOTSTRAP_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python app.py
```

Never commit `.env`, MongoDB URIs, SMTP credentials, backup archives, or real student data.
