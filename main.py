import os
import sys
import sqlite3
import subprocess
from flask import Flask, render_template, request, redirect, session
from flask_cors import CORS
import user_management as db
from urllib.parse import urlparse, urljoin
from flask_wtf.csrf import CSRFProtect
from functools import wraps

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DB_PATH      = os.path.join(BASE_DIR, "database_files", "database.db")
SETUP_SCRIPT = os.path.join(BASE_DIR, "database_files", "setup_db.py")

def is_safe_redirect(target):
    host_url = request.host_url
    test_url = urljoin(host_url, target)

    parsed_host = urlparse(host_url)
    parsed_test = urlparse(test_url)

    return (
        parsed_test.scheme in ("http", "https") and
        parsed_host.netloc == parsed_test.netloc
    )

def safe_redirect(target, fallback="/"):
    if target and is_safe_redirect(target):
        return redirect(target)
    return redirect(fallback)

def _tables_exist():
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        tables = {r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        con.close()
        return {"users", "posts", "messages"}.issubset(tables)
    except Exception:
        return False

def init_db():
    os.makedirs(os.path.join(BASE_DIR, "database_files"), exist_ok=True)
    if not os.path.exists(DB_PATH) or not _tables_exist():
        print("[SocialPWA] Setting up database...")
        result = subprocess.run(
            [sys.executable, SETUP_SCRIPT],
            capture_output=True, text=True
        )
        print(result.stdout)
        if result.returncode != 0:
            print("[SocialPWA] WARNING: setup_db failed:", result.stderr)
    else:
        print("[SocialPWA] Database already exists — skipping setup.")

init_db()


app = Flask(__name__)
CORS(app)
csrf = CSRFProtect(app)

app.secret_key = "supersecretkey123"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect("/")
        return view(*args, **kwargs)
    return wrapped


@app.route("/", methods=["POST", "GET"])
@app.route("/index.html", methods=["POST", "GET"])
def home():
    if request.method == "GET" and request.args.get("url"):
        return safe_redirect(request.args.get("url"))

    if request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("index.html", msg=msg)

    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        isLoggedIn = db.retrieveUsers(username, password)

        if isLoggedIn:
            session["username"] = username
            session["logged_in"] = True

            posts = db.getPosts()
            return render_template("feed.html", username=username, state=isLoggedIn, posts=posts)
        else:
            return render_template("index.html", msg="Invalid credentials. Please try again.")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        return safe_redirect(request.args.get("url"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        DoB      = request.form["dob"]
        bio      = request.form.get("bio", "")

        db.insertUser(username, password, DoB, bio)
        return render_template("index.html", msg="Account created! Please log in.")
    else:
        return render_template("signup.html")


@app.route("/feed.html", methods=["POST", "GET"])
@login_required
def feed():
    if request.method == "GET" and request.args.get("url"):
        return safe_redirect(request.args.get("url"))

    if request.method == "POST":
        post_content = request.form["content"]

        username = session["username"]
        db.insertPost(username, post_content)

        posts = db.getPosts()
        return render_template("feed.html", username=username, state=True, posts=posts)
    else:
        posts = db.getPosts()
        return render_template("feed.html", username=session["username"], state=True, posts=posts)


@app.route("/profile")
@login_required
def profile():
    if request.args.get("url"):
        return safe_redirect(request.args.get("url"))

    username = session["username"]
    profile_data = db.getUserProfile(username)

    return render_template("profile.html", profile=profile_data, username=username)


# 🔐 FIXED: IDOR removed here
@app.route("/messages", methods=["POST", "GET"])
@login_required
def messages():
    if request.method == "POST":
        sender    = session["username"]
        recipient = request.form.get("recipient", "")
        body      = request.form.get("body", "")

        db.sendMessage(sender, recipient, body)

        # FIX: prevent user-controlled data exposure
        msgs = db.getMessages(sender)

        return render_template("messages.html", messages=msgs, username=sender, recipient=sender)

    else:
        username = session["username"]

        # FIX: never trust request input for data access
        msgs = db.getMessages(username)

        return render_template("messages.html", messages=msgs, username=username, recipient=username)


@app.route("/success.html")
def success():
    msg = request.args.get("msg", "Your action was completed successfully.")
    return render_template("success.html", msg=msg)


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)