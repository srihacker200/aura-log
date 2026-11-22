import csv
import io
import os
import re
import secrets
import threading
from datetime import date, datetime, timedelta, timezone
from functools import wraps

from bson import ObjectId
from flask import Flask, abort, flash, g, make_response, redirect, render_template, request, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_wtf.csrf import CSRFProtect
from pymongo import MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError
from werkzeug.security import check_password_hash, generate_password_hash


def utcnow():
    return datetime.now(timezone.utc)


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        MONGODB_URI=os.environ.get("MONGODB_URI", ""),
        MONGODB_DATABASE=os.environ.get("MONGODB_DATABASE", "aura_log"),
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
    index_lock = threading.Lock()
    indexes_ready = False
    client = None
    if app.config["MONGODB_URI"]:
        client = MongoClient(app.config["MONGODB_URI"], serverSelectionTimeoutMS=8000,
                             connectTimeoutMS=8000, appname="AURA-LOG")
        app.extensions["mongo_client"] = client

    def get_db():
        nonlocal indexes_ready
        if client is None:
            raise RuntimeError("MongoDB is not configured. Set MONGODB_URI in the host environment.")
        if not indexes_ready:
            with index_lock:
                if not indexes_ready:
                    database = client[app.config["MONGODB_DATABASE"]]
                    database.users.create_index("email", unique=True, collation={"locale": "en", "strength": 2})
                    database.classes.create_index("name", unique=True, collation={"locale": "en", "strength": 2})
                    database.students.create_index("email", unique=True, sparse=True, collation={"locale": "en", "strength": 2})
                    database.attendance.create_index([("student_id", 1), ("attendance_date", 1)], unique=True)
                    database.attendance.create_index([("attendance_date", -1), ("class_id", 1)])
                    database.login_attempts.create_index("created_at", expireAfterSeconds=900)
                    database.audit_log.create_index("created_at", -1)
                    indexes_ready = True
        return client[app.config["MONGODB_DATABASE"]]

    @app.teardown_appcontext
    def teardown(_error=None):
        g.pop("mongo_db", None)

    def db():
        if "mongo_db" not in g:
            g.mongo_db = get_db()
        return g.mongo_db

    class User(UserMixin):
        def __init__(self, row):
            self.id = str(row["_id"])
            self.email = row["email"]
            self.full_name = row["full_name"]
            self.role = row["role"]

    @login_manager.user_loader
    def load_user(user_id):
        if not ObjectId.is_valid(user_id):
            return None
        row = db().users.find_one({"_id": ObjectId(user_id), "active": True})
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
        db().audit_log.insert_one({"actor_id": ObjectId(current_user.get_id()) if current_user.is_authenticated else None,
                                   "actor_email": current_user.email if current_user.is_authenticated else "system",
                                   "action": action, "details": details[:300], "created_at": utcnow()})

    def parse_date(value):
        try:
            return date.fromisoformat(value)
        except (TypeError, ValueError):
            return None

    def oid(value):
        return ObjectId(value) if ObjectId.is_valid(str(value)) else None

    @app.get("/health")
    def health():
        if client is None:
            return {"status": "not_configured"}, 503
        try:
            client.admin.command("ping")
            return {"status": "ok"}, 200
        except PyMongoError:
            return {"status": "database_unavailable"}, 503

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if db().users.find_one({}, {"_id": 1}):
            abort(404)
        expected = os.environ.get("BOOTSTRAP_TOKEN", "")
        if request.method == "POST":
            token = request.form.get("setup_token", "")
            email = request.form.get("email", "").strip().lower()
            name = request.form.get("full_name", "").strip()
            password = request.form.get("password", "")
            if not expected or not secrets.compare_digest(token, expected):
                flash("Invalid setup token. Check the deployment environment configuration.", "error")
            elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or not 2 <= len(name) <= 100:
                flash("Enter a valid email and a name between 2 and 100 characters.", "error")
            elif not 12 <= len(password) <= 200:
                flash("Use a password between 12 and 200 characters.", "error")
            else:
                try:
                    db().users.insert_one({"email": email, "full_name": name,
                        "password_hash": generate_password_hash(password), "role": "admin",
                        "active": True, "created_at": utcnow()})
                    flash("Administrator created. Sign in to continue.", "success")
                    return redirect(url_for("login"))
                except DuplicateKeyError:
                    flash("An account already exists; sign in instead.", "error")
        return render_template("setup.html", token_configured=bool(expected))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()[:254]
            now = utcnow()
            recent = db().login_attempts.count_documents({"email": email, "created_at": {"$gte": now - timedelta(minutes=15)}})
            user = db().users.find_one({"email": email, "active": True}, collation={"locale": "en", "strength": 2})
            if recent < 8 and user and check_password_hash(user["password_hash"], request.form.get("password", "")):
                db().login_attempts.delete_many({"email": email})
                login_user(User(user), fresh=True)
                return redirect(url_for("dashboard"))
            db().login_attempts.insert_one({"email": email or "unknown", "created_at": now})
            flash("Email or password is incorrect, or sign-in is temporarily locked. Try again later.", "error")
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def dashboard():
        selected = request.args.get("date", date.today().isoformat())
        if not parse_date(selected):
            selected = date.today().isoformat()
        query = {"attendance_date": selected}
        if current_user.role == "student":
            student = db().students.find_one({"email": current_user.email}, collation={"locale": "en", "strength": 2})
            query["student_id"] = student["_id"] if student else None
        entries = list(db().attendance.find(query).sort("student_name", 1))
        for entry in entries:
            entry["id"] = str(entry["_id"])
            entry["class_name"] = entry.get("class_name") or "—"
        totals = {status: sum(1 for entry in entries if entry["status"] == status) for status in ("Present", "Absent", "Late")}
        students = list(db().students.find({"active": True}).sort("full_name", 1)) if current_user.role != "student" else []
        classes = list(db().classes.find().sort("name", 1)) if current_user.role != "student" else []
        return render_template("dashboard.html", records=entries, totals=totals, selected_date=selected,
            students=students, classes=classes, can_manage=current_user.role in ("admin", "teacher"))

    @app.post("/attendance")
    @roles_required("admin", "teacher")
    def add_attendance():
        student_id = oid(request.form.get("student_id", ""))
        when = request.form.get("attendance_date", "")
        status = request.form.get("status", "")
        notes = request.form.get("notes", "").strip()[:500]
        student = db().students.find_one({"_id": student_id, "active": True}) if student_id else None
        if not student or not parse_date(when) or status not in ("Present", "Absent", "Late"):
            flash("Check the student, date, and attendance status.", "error")
        else:
            class_doc = db().classes.find_one({"_id": student.get("class_id")}) if student.get("class_id") else None
            record = {"student_id": student["_id"], "student_name": student["full_name"],
                "student_email": student.get("email", ""), "class_id": student.get("class_id"),
                "class_name": class_doc["name"] if class_doc else "", "attendance_date": when,
                "status": status, "notes": notes, "created_by": ObjectId(current_user.get_id()),
                "created_at": utcnow(), "updated_at": utcnow()}
            try:
                db().attendance.insert_one(record)
                audit("attendance.created", f"student_id={student_id}; date={when}")
                flash("Attendance saved.", "success")
            except DuplicateKeyError:
                flash("Attendance for this student and date already exists.", "error")
        return redirect(url_for("dashboard", date=when if parse_date(when) else date.today().isoformat()))

    @app.post("/attendance/<record_id>/update")
    @roles_required("admin", "teacher")
    def update_attendance(record_id):
        record_oid = oid(record_id)
        status = request.form.get("status", "")
        if not record_oid or status not in ("Present", "Absent", "Late"):
            abort(400)
        result = db().attendance.update_one({"_id": record_oid}, {"$set": {"status": status,
            "notes": request.form.get("notes", "").strip()[:500], "updated_at": utcnow()}})
        if not result.matched_count:
            abort(404)
        audit("attendance.updated", f"record_id={record_id}")
        flash("Attendance updated.", "success")
        return redirect(url_for("dashboard", date=request.form.get("return_date", date.today().isoformat())))

    @app.post("/attendance/<record_id>/delete")
    @roles_required("admin", "teacher")
    def delete_attendance(record_id):
        record_oid = oid(record_id)
        if not record_oid or not db().attendance.delete_one({"_id": record_oid}).deleted_count:
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
                    db().classes.insert_one({"name": name, "created_at": utcnow()})
                    audit("class.created", name)
                    flash("Class added.", "success")
                except DuplicateKeyError:
                    flash("A class with that name already exists.", "error")
            return redirect(url_for("classes_page"))
        return render_template("classes.html", classes=list(db().classes.find().sort("name", 1)))

    @app.post("/classes/<class_id>/delete")
    @roles_required("admin")
    def delete_class(class_id):
        class_oid = oid(class_id)
        if not class_oid or not db().classes.delete_one({"_id": class_oid}).deleted_count:
            abort(404)
        db().students.update_many({"class_id": class_oid}, {"$unset": {"class_id": ""}})
        db().attendance.update_many({"class_id": class_oid}, {"$set": {"class_name": ""}, "$unset": {"class_id": ""}})
        audit("class.deleted", f"class_id={class_id}")
        flash("Class removed; student and attendance history are retained.", "success")
        return redirect(url_for("classes_page"))

    @app.route("/students", methods=["GET", "POST"])
    @roles_required("admin", "teacher")
    def students_page():
        classes = list(db().classes.find().sort("name", 1))
        if request.method == "POST":
            name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower() or None
            class_id = oid(request.form.get("class_id", "")) if request.form.get("class_id") else None
            if not name or len(name) > 100 or (email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)) or (request.form.get("class_id") and not class_id):
                flash("Enter a valid name, email, and class.", "error")
            else:
                class_doc = db().classes.find_one({"_id": class_id}) if class_id else None
                try:
                    db().students.insert_one({"full_name": name, "email": email, "class_id": class_id,
                        "class_name": class_doc["name"] if class_doc else "", "active": True, "created_at": utcnow()})
                    audit("student.created", name)
                    flash("Student added.", "success")
                except DuplicateKeyError:
                    flash("That email is already assigned.", "error")
            return redirect(url_for("students_page"))
        students = list(db().students.find().sort("full_name", 1))
        for student in students:
            student["id"] = str(student["_id"])
        return render_template("students.html", students=students, classes=classes)

    @app.post("/students/<student_id>/update")
    @roles_required("admin", "teacher")
    def update_student(student_id):
        student_oid = oid(student_id)
        name = request.form.get("full_name", "").strip()[:100]
        email = request.form.get("email", "").strip().lower() or None
        class_id = oid(request.form.get("class_id", "")) if request.form.get("class_id") else None
        if not student_oid or not name or (email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)):
            abort(400)
        class_doc = db().classes.find_one({"_id": class_id}) if class_id else None
        try:
            result = db().students.update_one({"_id": student_oid}, {"$set": {"full_name": name, "email": email,
                "class_id": class_id, "class_name": class_doc["name"] if class_doc else "",
                "active": request.form.get("active") == "1"}})
        except DuplicateKeyError:
            flash("That email is already assigned.", "error")
            return redirect(url_for("students_page"))
        if not result.matched_count:
            abort(404)
        db().attendance.update_many({"student_id": student_oid}, {"$set": {"student_name": name, "student_email": email or "",
            "class_id": class_id, "class_name": class_doc["name"] if class_doc else ""}})
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
                    db().users.insert_one({"email": email, "full_name": name, "password_hash": generate_password_hash(password),
                        "role": role, "active": True, "created_at": utcnow()})
                    audit("user.created", f"{email}; role={role}")
                    flash("Account created. Share credentials securely.", "success")
                except DuplicateKeyError:
                    flash("That email is already registered.", "error")
            return redirect(url_for("users_page"))
        users = list(db().users.find({}, {"password_hash": 0}).sort("full_name", 1))
        for user in users:
            user["id"] = str(user["_id"])
        return render_template("users.html", users=users)

    @app.post("/users/<user_id>/toggle")
    @roles_required("admin")
    def toggle_user(user_id):
        user_oid = oid(user_id)
        if not user_oid:
            abort(404)
        if user_id == current_user.get_id():
            flash("You cannot deactivate your own account.", "error")
            return redirect(url_for("users_page"))
        user = db().users.find_one({"_id": user_oid})
        if not user:
            abort(404)
        db().users.update_one({"_id": user_oid}, {"$set": {"active": not user.get("active", True)}})
        audit("user.status_changed", f"user_id={user_id}")
        return redirect(url_for("users_page"))

    @app.get("/reports")
    @roles_required("admin", "teacher")
    def reports():
        start = request.args.get("start", (date.today() - timedelta(days=30)).isoformat())
        end = request.args.get("end", date.today().isoformat())
        if not parse_date(start) or not parse_date(end) or start > end or (parse_date(end) - parse_date(start)).days > 366:
            flash("Choose a valid date range no longer than one year.", "error")
            start, end = (date.today() - timedelta(days=30)).isoformat(), date.today().isoformat()
        pipeline = [{"$match": {"attendance_date": {"$gte": start, "$lte": end}}},
            {"$group": {"_id": {"date": "$attendance_date", "class": {"$ifNull": ["$class_name", "Unassigned"]}},
                "present": {"$sum": {"$cond": [{"$eq": ["$status", "Present"]}, 1, 0]}},
                "absent": {"$sum": {"$cond": [{"$eq": ["$status", "Absent"]}, 1, 0]}},
                "late": {"$sum": {"$cond": [{"$eq": ["$status", "Late"]}, 1, 0]}}}},
            {"$sort": {"_id.date": -1, "_id.class": 1}}]
        rows = [{"attendance_date": item["_id"]["date"], "class_name": item["_id"]["class"],
                 "present": item["present"], "absent": item["absent"], "late": item["late"]}
                for item in db().attendance.aggregate(pipeline)]
        return render_template("reports.html", rows=rows, start=start, end=end)

    @app.get("/reports.csv")
    @roles_required("admin", "teacher")
    def export_csv():
        start, end = request.args.get("start", ""), request.args.get("end", "")
        if not parse_date(start) or not parse_date(end) or start > end or (parse_date(end) - parse_date(start)).days > 366:
            abort(400)
        rows = db().attendance.find({"attendance_date": {"$gte": start, "$lte": end}}).sort([("attendance_date", 1), ("student_name", 1)])
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(("Date", "Student", "Student email", "Class", "Status", "Notes"))
        for row in rows:
            values = [row.get("attendance_date", ""), row.get("student_name", ""), row.get("student_email", ""),
                      row.get("class_name", ""), row.get("status", ""), row.get("notes", "")]
            writer.writerow([("'" + str(value)) if str(value).startswith(("=", "+", "-", "@", "\t", "\r")) else value for value in values])
        response = make_response("\ufeff" + output.getvalue())
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        response.headers["Content-Disposition"] = f'attachment; filename="aura-log-{start}-to-{end}.csv"'
        return response

    @app.get("/audit")
    @roles_required("admin")
    def audit_page():
        events = list(db().audit_log.find().sort("created_at", -1).limit(200))
        for event in events:
            event["created_at"] = event["created_at"].strftime("%Y-%m-%d %H:%M UTC")
        return render_template("audit.html", events=events)

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="You do not have permission to access this page."), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="That page could not be found."), 404

    @app.errorhandler(RuntimeError)
    def configuration_error(error):
        app.logger.error("Application configuration error: %s", error)
        return render_template("error.html", code=503, message="The application database is not configured. Check deployment environment settings."), 503

    @app.errorhandler(PyMongoError)
    def database_error(error):
        app.logger.error("MongoDB operation failed: %s", error.__class__.__name__)
        return render_template("error.html", code=503, message="The database is temporarily unavailable. Check MongoDB Atlas network access and credentials."), 503

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=os.environ.get("FLASK_DEBUG") == "1")
