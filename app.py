import os
import sqlite3
from datetime import date
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, url_for

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "local-development-only-change-me")
DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", "instance/aura_log.db"))


def get_db():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_name TEXT NOT NULL,
                group_name TEXT NOT NULL DEFAULT '',
                attendance_date TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('Present', 'Absent', 'Late')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)


@app.get("/")
def index():
    selected_date = request.args.get("date", date.today().isoformat())
    with get_db() as db:
        totals = {row["status"]: row["total"] for row in db.execute(
            "SELECT status, COUNT(*) AS total FROM attendance WHERE attendance_date = ? GROUP BY status",
            (selected_date,),
        )}
        records = db.execute(
            "SELECT id, student_name, group_name, attendance_date, status "
            "FROM attendance WHERE attendance_date = ? ORDER BY id DESC",
            (selected_date,),
        ).fetchall()
    return render_template(
        "index.html",
        selected_date=selected_date,
        records=records,
        totals={status: totals.get(status, 0) for status in ("Present", "Absent", "Late")},
    )


@app.post("/attendance")
def add_attendance():
    student_name = request.form.get("student_name", "").strip()
    group_name = request.form.get("group_name", "").strip()
    attendance_date = request.form.get("attendance_date", "").strip()
    status = request.form.get("status", "").strip()

    if not student_name or len(student_name) > 100:
        flash("Enter a student name (up to 100 characters).", "error")
    elif len(group_name) > 100:
        flash("Class or group must be 100 characters or fewer.", "error")
    elif not attendance_date:
        flash("Choose an attendance date.", "error")
    elif status not in {"Present", "Absent", "Late"}:
        flash("Choose a valid attendance status.", "error")
    else:
        with get_db() as db:
            db.execute(
                "INSERT INTO attendance (student_name, group_name, attendance_date, status) "
                "VALUES (?, ?, ?, ?)",
                (student_name, group_name, attendance_date, status),
            )
        flash("Attendance entry saved.", "success")
    return redirect(url_for("index", date=attendance_date or date.today().isoformat()))


initialize_db()

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=debug)
