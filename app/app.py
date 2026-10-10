"""
TP1 DevSecOps - "Notes App" : petite application Flask de prise de notes.

Version corrigee apres l'analyse SAST (Bandit). Chaque correction est reperee
par un commentaire "[SAST Bxxx]" qui renvoie a la regle Bandit et au rapport
(RAPPORT.md).
"""
import functools
import ipaddress
import os
import secrets
import socket
import sqlite3
import subprocess
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "notes.db"))

app = Flask(__name__)
# [SAST B105] Le secret de signature des sessions vient de l'environnement.
# A defaut, une cle aleatoire est generee au demarrage (jamais dans le code).
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
    MAX_CONTENT_LENGTH=1024 * 1024,  # 1 Mo max pour les imports
)

# [SAST B105] Plus de mot de passe administrateur en dur : il est fourni
# (optionnellement) par une variable d'environnement.
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

ALLOWED_THEMES = {"light", "dark"}


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
    if ADMIN_PASSWORD and db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        # [SAST B324] Hachage lent (scrypt de Werkzeug, avec sel aleatoire) au lieu de MD5.
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", generate_password_hash(ADMIN_PASSWORD)),
        )
    db.commit()
    db.close()


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    return resp


# --------------------------------------------------------------------------
# Authentification
# --------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (request.form["username"], generate_password_hash(request.form["password"])),
            )
            db.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            error = "Nom d'utilisateur indisponible"
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        # [SAST B608] Requete parametree : la saisie n'est jamais concatenee au SQL.
        user = get_db().execute(
            "SELECT id, username, password FROM users WHERE username = ?",
            (request.form["username"],),
        ).fetchone()
        if user and check_password_hash(user["password"], request.form["password"]):
            session.clear()
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
@login_required
def index():
    notes = get_db().execute(
        "SELECT id, title, content FROM notes WHERE owner_id = ?", (session["user_id"],)
    ).fetchall()
    return render_template("index.html", notes=notes)


@app.route("/notes", methods=["POST"])
@login_required
def add_note():
    db = get_db()
    db.execute(
        "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)",
        (session["user_id"], request.form["title"], request.form["content"]),
    )
    db.commit()
    return redirect(url_for("index"))


@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "")
    # [SAST B608] Requete parametree (le motif LIKE est passe comme parametre).
    notes = get_db().execute(
        "SELECT id, title, content FROM notes WHERE owner_id = ? AND title LIKE ?",
        (session["user_id"], "%" + q + "%"),
    ).fetchall()
    # [SAST B704] Plus de Markup() sur une donnee utilisateur : la recherche est
    # passee telle quelle au template et echappee par l'auto-escaping de Jinja2.
    return render_template("index.html", notes=notes, query=q)


@app.route("/import", methods=["POST"])
@login_required
def import_notes():
    """Importe des notes depuis un fichier YAML (liste de {title, content})."""
    # [SAST B506] safe_load ne construit que des types simples (dict, list, str...).
    try:
        data = yaml.safe_load(request.files["file"].read())
    except yaml.YAMLError:
        abort(400, "Fichier YAML invalide")
    if not isinstance(data, list):
        abort(400, "Le fichier doit contenir une liste de notes")
    db = get_db()
    for note in data:
        if not (
            isinstance(note, dict)
            and isinstance(note.get("title"), str)
            and isinstance(note.get("content"), str)
        ):
            abort(400, "Chaque note doit avoir un titre et un contenu texte")
        db.execute(
            "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)",
            (session["user_id"], note["title"], note["content"]),
        )
    db.commit()
    return redirect(url_for("index"))


# --------------------------------------------------------------------------
# Preferences
# --------------------------------------------------------------------------
@app.route("/preferences", methods=["GET", "POST"])
@login_required
def preferences():
    # [SAST B301/B403] Plus de pickle : la preference est stockee dans la session
    # Flask (cookie signe HMAC, serialise en JSON) et validee par liste blanche.
    if request.method == "POST":
        theme = request.form.get("theme", "light")
        session["theme"] = theme if theme in ALLOWED_THEMES else "light"
        return redirect(url_for("preferences"))
    return render_template("preferences.html", prefs={"theme": session.get("theme", "light")})


# --------------------------------------------------------------------------
# Outils reseau
# --------------------------------------------------------------------------
@app.route("/tools/ping")
@login_required
def ping():
    # [SAST B602] Validation stricte de l'entree (adresse IP uniquement) et
    # appel sans shell, avec une liste d'arguments et un chemin absolu.
    try:
        ip = ipaddress.ip_address(request.args.get("host", "127.0.0.1"))
    except ValueError:
        abort(400, "Adresse IP invalide")
    result = subprocess.run(
        ["/bin/ping", "-c", "1", str(ip)], capture_output=True, timeout=5, check=False
    )
    output = (result.stdout + result.stderr).decode(errors="replace")
    return render_template("tool.html", title="Ping", output=output)


def is_public_http_url(url):
    """N'autorise que http(s) vers des adresses publiques (anti-SSRF)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or 443)
    except (socket.gaierror, ValueError):
        return False
    return all(ipaddress.ip_address(info[4][0]).is_global for info in infos)


@app.route("/tools/fetch")
@login_required
def fetch():
    url = request.args.get("url", "https://example.com")
    if not is_public_http_url(url):
        abort(400, "URL non autorisee")
    # [SAST B501] Verification TLS active (verify=True par defaut).
    # [SAST B113] Timeout obligatoire ; pas de redirection automatique (anti-SSRF).
    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)
    except requests.RequestException:
        abort(502, "Impossible de joindre l'URL")
    return render_template("tool.html", title="Fetch", output=resp.text[:2000])


init_db()

if __name__ == "__main__":
    # [SAST B201/B104] Serveur de developpement uniquement : debug desactive et
    # ecoute sur localhost par defaut. En production (Docker), c'est gunicorn
    # qui sert l'application.
    app.run(
        host=os.environ.get("FLASK_RUN_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLASK_RUN_PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
