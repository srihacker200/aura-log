import csv
import io
import os
import re
import secrets
import sqlite3
from datetime import date, datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, make_response, redirect, render_template, request, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        DATABASE_PATH=os.environ.get("DATABASE_PATH", "instance/aura_log.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=1024 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    CSRFProtect(app)
    login_manager = LoginManager(app)
    login_manager.login_view = "login"
    login_manager.login_message = "Please sign in to continue."
    login_manager.login_message_category = "error"

    def connect_db():
        path = app.config["DATABASE_PATH"]
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def db():
        if "db" not in g:
            g.db = connect_db()
        return g.db

    @app.teardown_appcontext
    def close_db(_error=None):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    def initialize_db():
        connection = connect_db()
        try:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    full_name TEXT NOT NULL, password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin','teacher','student')),
                    active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS classes (
                    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS students (
                    id INTEGER PRIMARY KEY, full_name TEXT NOT NULL,
                    email TEXT UNIQUE COLLATE NOCASE, class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL,
                    active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            """)
            old = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='attendance'").fetchone()
            if old:
                columns = {row["name"] for row in connection.execute("PRAGMA table_info(attendance)")}
                if "student_id" not in columns:
                    connection.execute("ALTER TABLE attendance RENAME TO attendance_legacy")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS attendance (
                    id INTEGER PRIMARY KEY,
                    student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE RESTRICT,
                    class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL,
                    attendance_date TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('Present','Absent','Late')),
                    notes TEXT NOT NULL DEFAULT '',
                    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(student_id, attendance_date)
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY, actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    action TEXT NOT NULL, details TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY, email TEXT NOT NULL, attempted_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance(attendance_date);
                CREATE INDEX IF NOT EXISTS idx_attendance_student ON attendance(student_id);
                CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
            """)
            legacy_exists = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='attendance_legacy'").fetchone()
            if legacy_exists:
                for row in connection.execute("SELECT * FROM attendance_legacy ORDER BY id").fetchall():
                    group = (row["group_name"] or "Unassigned").strip() or "Unassigned"
                    name = (row["student_name"] or "Unknown student").strip() or "Unknown student"
                    connection.execute("INSERT OR IGNORE INTO classes(name) VALUES (?)", (group,))
                    class_id = connection.execute("SELECT id FROM classes WHERE name=? COLLATE NOCASE", (group,)).fetchone()[0]
                    connection.execute("INSERT INTO students(full_name,class_id) VALUES (?,?)", (name, class_id))
                    student_id = connection.execute("SELECT last_insert_rowid()").fetchone()[0]
                    connection.execute("INSERT OR IGNORE INTO attendance(student_id,class_id,attendance_date,status) VALUES (?,?,?,?)",
                                       (student_id, class_id, row["attendance_date"], row["status"]))
                connection.execute("DROP TABLE attendance_legacy")
            connection.commit()
        finally:
            connection.close()

    class User(UserMixin):
        def __init__(self, row):
            self.id = str(row["id"])
            self.email = row["email"]
            self.full_name = row["full_name"]
            self.role = row["role"]

    @login_manager.user_loader
    def load_user(user_id):
        row = db().execute("SELECT * FROM users WHERE id=? AND active=1", (user_id,)).fetchone()
        return User(row) if row else None

    def roles_required(*roles):
        def decorate(view):
            @wraps(view)
            @login_required
            def wrapped(*args, **kwargs):
                if current_user.role not in roles:
                    abort(403)
                return view(*args, **kwargs)
            return wrapped
        return decorate

    def audit(action, details=""):
        db().execute("INSERT INTO audit_log(actor_id,action,details) VALUES (?,?,?)",
                     (int(current_user.get_id()) if current_user.is_authenticated else None, action, details[:300]))
        db().commit()

    def valid_date(value):
        try:
            return date.fromisoformat(value)
        except (TypeError, ValueError):
            return None

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()[:254]
            now = int(datetime.utcnow().timestamp())
            connection = db()
            connection.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (now - 900,))
            attempts = connection.execute("SELECT COUNT(*) FROM login_attempts WHERE email=? AND attempted_at>?", (email, now - 900)).fetchone()[0]
            user = connection.execute("SELECT * FROM users WHERE email=? COLLATE NOCASE AND active=1", (email,)).fetchone()
            if attempts < 8 and user and check_password_hash(user["password_hash"], request.form.get("password", "")):
                connection.execute("DELETE FROM login_attempts WHERE email=?", (email,))
                connection.commit()
                login_user(User(user), fresh=True)
                return redirect(url_for("dashboard"))
            connection.execute("INSERT INTO login_attempts(email,attempted_at) VALUES (?,?)", (email or "unknown", now))
            connection.commit()
            flash("Email or password is incorrect, or sign-in is temporarily locked. Try again later.", "error")
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if db().execute("SELECT 1 FROM users LIMIT 1").fetchone():
            abort(404)
        token_expected = os.environ.get("BOOTSTRAP_TOKEN", "")
        if not token_expected:
            return render_template("setup.html", token_configured=False)
        if request.method == "POST":
            token = request.form.get("setup_token", "")
            email = request.form.get("email", "").strip().lower()
            name = request.form.get("full_name", "").strip()
            password = request.form.get("password", "")
            if not secrets.compare_digest(token, token_expected):
                flash("Invalid setup token.", "error")
            elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or not 2 <= len(name) <= 100:
                flash("Enter a valid email and a name between 2 and 100 characters.", "error")
            elif not 12 <= len(password) <= 200:
                flash("Use a password between 12 and 200 characters.", "error")
            else:
                db().execute("INSERT INTO users(email,full_name,password_hash,role) VALUES (?,?,?,'admin')",
                             (email, name, generate_password_hash(password)))
                db().commit()
                flash("Administrator created. Sign in to continue.", "success")
                return redirect(url_for("login"))
        return render_template("setup.html", token_configured=True)

    @app.get("/")
    @login_required
    def dashboard():
        selected_date = request.args.get("date", date.today().isoformat())
        if not valid_date(selected_date):
            selected_date = date.today().isoformat()
        if current_user.role == "student":
            records = db().execute("""SELECT a.*,s.full_name AS student_name,c.name AS class_name
                FROM attendance a JOIN students s ON s.id=a.student_id LEFT JOIN classes c ON c.id=a.class_id
                WHERE s.email=? AND a.attendance_date=? ORDER BY s.full_name""", (current_user.email, selected_date)).fetchall()
        else:
            records = db().execute("""SELECT a.*,s.full_name AS student_name,c.name AS class_name
                FROM attendance a JOIN students s ON s.id=a.student_id LEFT JOIN classes c ON c.id=a.class_id
                WHERE a.attendance_date=? ORDER BY s.full_name""", (selected_date,)).fetchall()
        totals = {status: sum(row["status"] == status for row in records) for status in ("Present", "Absent", "Late")}
        students = db().execute("SELECT id,full_name FROM students WHERE active=1 ORDER BY full_name").fetchall() if current_user.role != "student" else []
        classes = db().execute("SELECT id,name FROM classes ORDER BY name").fetchall() if current_user.role != "student" else []
        return render_template("dashboard.html", records=records, totals=totals, selected_date=selected_date,
                               students=students, classes=classes, can_manage=current_user.role in ("admin", "teacher"))

    @app.post("/attendance")
    @roles_required("admin", "teacher")
    def add_attendance():
        student_id = request.form.get("student_id", type=int)
        attendance_date = request.form.get("attendance_date", "")
        status = request.form.get("status", "")
        notes = request.form.get("notes", "").strip()[:500]
        student = db().execute("SELECT id,class_id FROM students WHERE id=? AND active=1", (student_id,)).fetchone()
        if not student or not valid_date(attendance_date) or status not in ("Present", "Absent", "Late"):
            flash("Check the student, date, and attendance status.", "error")
        else:
            try:
                db().execute("INSERT INTO attendance(student_id,class_id,attendance_date,status,notes,created_by) VALUES (?,?,?,?,?,?)",
                             (student["id"], student["class_id"], attendance_date, status, notes, int(current_user.get_id())))
                db().commit()
                audit("attendance.created", f"student_id={student_id}; date={attendance_date}")
                flash("Attendance saved.", "success")
            except sqlite3.IntegrityError:
                db().rollback()
                flash("Attendance for this student and date already exists. Edit the existing entry instead.", "error")
        return redirect(url_for("dashboard", date=attendance_date if valid_date(attendance_date) else date.today().isoformat()))

    @app.post("/attendance/<int:record_id>/update")
    @roles_required("admin", "teacher")
    def update_attendance(record_id):
        status = request.form.get("status", "")
        notes = request.form.get("notes", "").strip()[:500]
        if status not in ("Present", "Absent", "Late"):
            abort(400)
        cursor = db().execute("UPDATE attendance SET status=?,notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (status, notes, record_id))
        db().commit()
        if not cursor.rowcount:
            abort(404)
        audit("attendance.updated", f"record_id={record_id}")
        flash("Attendance updated.", "success")
        return redirect(url_for("dashboard", date=request.form.get("return_date", date.today().isoformat())))

    @app.post("/attendance/<int:record_id>/delete")
    @roles_required("admin", "teacher")
    def delete_attendance(record_id):
        cursor = db().execute("DELETE FROM attendance WHERE id=?", (record_id,))
        db().commit()
        if not cursor.rowcount:
            abort(404)
        audit("attendance.deleted", f"record_id={record_id}")
        flash("Attendance entry deleted.", "success")
        return redirect(url_for("dashboard", date=request.form.get("return_date", date.today().isoformat())))

    @app.route("/classes", methods=["GET", "POST"])
    @roles_required("admin", "teacher")
    def classes_page():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            if not name or len(name) > 100:
                flash("Class name must be 1–100 characters.", "error")
            else:
                try:
                    db().execute("INSERT INTO classes(name) VALUES (?)", (name,))
                    db().commit()
                    audit("class.created", name)
                    flash("Class added.", "success")
                except sqlite3.IntegrityError:
                    db().rollback()
                    flash("A class with that name already exists.", "error")
            return redirect(url_for("classes_page"))
        rows = db().execute("SELECT * FROM classes ORDER BY name").fetchall()
        return render_template("classes.html", classes=rows)

    @app.post("/classes/<int:class_id>/delete")
    @roles_required("admin")
    def delete_class(class_id):
        cursor = db().execute("DELETE FROM classes WHERE id=?", (class_id,))
        db().commit()
        if not cursor.rowcount:
            abort(404)
        audit("class.deleted", f"class_id={class_id}")
        flash("Class removed; student records are retained as unassigned.", "success")
        return redirect(url_for("classes_page"))

    @app.route("/students", methods=["GET", "POST"])
    @roles_required("admin", "teacher")
    def students_page():
        classes = db().execute("SELECT id,name FROM classes ORDER BY name").fetchall()
        if request.method == "POST":
            name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower() or None
            class_id = request.form.get("class_id", type=int) or None
            if not name or len(name) > 100 or (email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)):
                flash("Enter a valid name and optional email address.", "error")
            else:
                try:
                    db().execute("INSERT INTO students(full_name,email,class_id) VALUES (?,?,?)", (name,email,class_id))
                    db().commit()
                    audit("student.created", name)
                    flash("Student added.", "success")
                except sqlite3.IntegrityError:
                    db().rollback()
                    flash("That email is already assigned, or the class is invalid.", "error")
            return redirect(url_for("students_page"))
        students = db().execute("SELECT s.*,c.name AS class_name FROM students s LEFT JOIN classes c ON c.id=s.class_id ORDER BY s.full_name").fetchall()
        return render_template("students.html", students=students, classes=classes)

    @app.post("/students/<int:student_id>/update")
    @roles_required("admin", "teacher")
    def update_student(student_id):
        name = request.form.get("full_name", "").strip()[:100]
        email = request.form.get("email", "").strip().lower() or None
        class_id = request.form.get("class_id", type=int) or None
        active = int(request.form.get("active") == "1")
        if not name or (email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)):
            abort(400)
        try:
            cursor = db().execute("UPDATE students SET full_name=?,email=?,class_id=?,active=? WHERE id=?", (name,email,class_id,active,student_id))
            db().commit()
        except sqlite3.IntegrityError:
            db().rollback()
            flash("Email or class is already in use or invalid.", "error")
            return redirect(url_for("students_page"))
        if not cursor.rowcount:
            abort(404)
        audit("student.updated", f"student_id={student_id}")
        flash("Student updated.", "success")
        return redirect(url_for("students_page"))

    @app.route("/users", methods=["GET", "POST"])
    @roles_required("admin")
    def users_page():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            name = request.form.get("full_name", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "")
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or not name or len(name) > 100 or not 12 <= len(password) <= 200 or role not in ("admin", "teacher", "student"):
                flash("Provide a valid email, name, role, and password of at least 12 characters.", "error")
            else:
                try:
                    db().execute("INSERT INTO users(email,full_name,password_hash,role) VALUES (?,?,?,?)", (email,name,generate_password_hash(password),role))
                    db().commit()
                    audit("user.created", f"{email}; role={role}")
                    flash("Account created. Share credentials securely.", "success")
                except sqlite3.IntegrityError:
                    db().rollback()
                    flash("That email is already registered.", "error")
            return redirect(url_for("users_page"))
        users = db().execute("SELECT id,email,full_name,role,active FROM users ORDER BY full_name").fetchall()
        return render_template("users.html", users=users)

    @app.post("/users/<int:user_id>/toggle")
    @roles_required("admin")
    def toggle_user(user_id):
        if user_id == int(current_user.get_id()):
            flash("You cannot deactivate your own account.", "error")
            return redirect(url_for("users_page"))
        row = db().execute("SELECT active FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            abort(404)
        db().execute("UPDATE users SET active=? WHERE id=?", (0 if row["active"] else 1, user_id))
        db().commit()
        audit("user.status_changed", f"user_id={user_id}")
        return redirect(url_for("users_page"))

    @app.get("/reports")
    @roles_required("admin", "teacher")
    def reports():
        start = request.args.get("start", (date.today() - timedelta(days=30)).isoformat())
        end = request.args.get("end", date.today().isoformat())
        if not valid_date(start) or not valid_date(end) or start > end or (valid_date(end) - valid_date(start)).days > 366:
            flash("Choose a valid date range no longer than one year.", "error")
            start, end = (date.today() - timedelta(days=30)).isoformat(), date.today().isoformat()
        rows = db().execute("""SELECT a.attendance_date,c.name AS class_name,
            SUM(CASE WHEN a.status='Present' THEN 1 ELSE 0 END) AS present,
            SUM(CASE WHEN a.status='Absent' THEN 1 ELSE 0 END) AS absent,
            SUM(CASE WHEN a.status='Late' THEN 1 ELSE 0 END) AS late
            FROM attendance a LEFT JOIN classes c ON c.id=a.class_id
            WHERE a.attendance_date BETWEEN ? AND ? GROUP BY a.attendance_date,c.name
            ORDER BY a.attendance_date DESC,c.name""", (start,end)).fetchall()
        return render_template("reports.html", rows=rows, start=start, end=end)

    @app.get("/reports.csv")
    @roles_required("admin", "teacher")
    def export_csv():
        start, end = request.args.get("start", ""), request.args.get("end", "")
        if not valid_date(start) or not valid_date(end) or start > end or (valid_date(end) - valid_date(start)).days > 366:
            abort(400)
        rows = db().execute("""SELECT a.attendance_date,s.full_name,s.email,c.name AS class_name,a.status,a.notes
            FROM attendance a JOIN students s ON s.id=a.student_id LEFT JOIN classes c ON c.id=a.class_id
            WHERE a.attendance_date BETWEEN ? AND ? ORDER BY a.attendance_date,s.full_name""", (start,end)).fetchall()
        def safe_cell(value):
            text = "" if value is None else str(value)
            return "'" + text if text.startswith(("=", "+", "-", "@", "\t", "\r")) else text
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(("Date", "Student", "Student email", "Class", "Status", "Notes"))
        writer.writerows(tuple(safe_cell(value) for value in row) for row in rows)
        response = make_response("\ufeff" + output.getvalue())
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        response.headers["Content-Disposition"] = f'attachment; filename="aura-log-{start}-to-{end}.csv"'
        return response

    @app.get("/audit")
    @roles_required("admin")
    def audit_page():
        events = db().execute("SELECT a.*,u.email FROM audit_log a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 200").fetchall()
        return render_template("audit.html", events=events)

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="You do not have permission to access this page."), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="That page could not be found."), 404

    initialize_db()
    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=os.environ.get("FLASK_DEBUG") == "1")
