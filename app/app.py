"""
TP1 DevSecOps - "Notes App" : petite application Flask de prise de notes.

/!\\ VERSION INITIALE (baseline) : ce code contient VOLONTAIREMENT des
vulnerabilites. Il sert de point de depart aux analyses SAST (Bandit) et
SCA (OWASP Dependency-Check / pip-audit). Ne pas deployer.
"""
import base64
import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, g, redirect, render_template, request, session, url_for
from markupsafe import Markup

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "notes.db")

app = Flask(__name__)
app.secret_key = "s3cr3t-k3y-tp1-devsecops"

ADMIN_PASSWORD = "admin123"


# --------------------------------------------------------------------------
# Base de donnees
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL
        );
        """
    )
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", hash_password(ADMIN_PASSWORD)),
        )
        db.execute(
            "INSERT INTO notes (owner_id, title, content) VALUES (1, ?, ?)",
            ("Bienvenue", "Premiere note de l'administrateur."),
        )
    db.commit()
    db.close()


# --------------------------------------------------------------------------
# Authentification
# --------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        db = get_db()
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (request.form["username"], hash_password(request.form["password"])),
        )
        db.commit()
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        query = "SELECT id, username FROM users WHERE username = '%s' AND password = '%s'" % (
            username,
            hash_password(password),
        )
        user = get_db().execute(query).fetchone()
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("index"))
        error = "Identifiants invalides"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Notes
# --------------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    notes = get_db().execute(
        "SELECT id, title, content FROM notes WHERE owner_id = ?", (session["user_id"],)
    ).fetchall()
    return render_template("index.html", notes=notes)


@app.route("/notes", methods=["POST"])
def add_note():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    db.execute(
        "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)",
        (session["user_id"], request.form["title"], request.form["content"]),
    )
    db.commit()
    return redirect(url_for("index"))


@app.route("/search")
def search():
    if "user_id" not in session:
        return redirect(url_for("login"))
    q = request.args.get("q", "")
    sql = "SELECT id, title, content FROM notes WHERE owner_id = %d AND title LIKE '%%%s%%'" % (
        session["user_id"],
        q,
    )
    notes = get_db().execute(sql).fetchall()
    message = Markup("Resultats pour : <b>%s</b>" % q)
    return render_template("index.html", notes=notes, message=message)


@app.route("/import", methods=["POST"])
def import_notes():
    """Importe des notes depuis un fichier YAML (liste de {title, content})."""
    if "user_id" not in session:
        return redirect(url_for("login"))
    data = yaml.load(request.files["file"].read())
    db = get_db()
    for note in data:
        db.execute(
            "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)",
            (session["user_id"], note["title"], note["content"]),
        )
    db.commit()
    return redirect(url_for("index"))


# --------------------------------------------------------------------------
# Preferences (stockees dans un cookie)
# --------------------------------------------------------------------------
@app.route("/preferences", methods=["GET", "POST"])
def preferences():
    if request.method == "POST":
        prefs = {"theme": request.form.get("theme", "light")}
        resp = redirect(url_for("preferences"))
        resp.set_cookie("prefs", base64.b64encode(pickle.dumps(prefs)).decode())
        return resp
    prefs = {"theme": "light"}
    if request.cookies.get("prefs"):
        prefs = pickle.loads(base64.b64decode(request.cookies["prefs"]))
    return render_template("preferences.html", prefs=prefs)


# --------------------------------------------------------------------------
# Outils reseau
# --------------------------------------------------------------------------
@app.route("/tools/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output("ping -c 1 " + host, shell=True, stderr=subprocess.STDOUT)
    return render_template("tool.html", title="Ping", output=output.decode(errors="replace"))


@app.route("/tools/fetch")
def fetch():
    url = request.args.get("url", "https://example.com")
    resp = requests.get(url, verify=False)
    return render_template("tool.html", title="Fetch", output=resp.text[:2000])


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
