from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import bleach
from flask import Flask, flash, g, redirect, render_template, request, url_for
from flask_wtf import FlaskForm
from werkzeug.middleware.proxy_fix import ProxyFix
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired, Length


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("GUESTBOOK_DB", BASE_DIR / "guestbook.sqlite3"))

# We store plain text only (no HTML). Jinja2 auto-escaping then safely renders it.
ALLOWED_TAGS: list[str] = []
ALLOWED_ATTRS: dict[str, list[str]] = {}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-change-me"),
        WTF_CSRF_TIME_LIMIT=None,
        MAX_CONTENT_LENGTH=64 * 1024,  # helps avoid huge payloads
        DATABASE=str(DB_PATH),
    )

    # If the app is deployed behind a reverse proxy, this makes URL generation
    # and scheme detection safer/correct when configured properly upstream.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    @app.after_request
    def add_security_headers(resp):
        # Strong baseline headers. CSP is the key XSS mitigation layer.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "form-action 'self'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return resp

    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            conn = sqlite3.connect(app.config["DATABASE"])
            conn.row_factory = sqlite3.Row
            g.db = conn
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    def init_db() -> None:
        db = get_db()
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS entries (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              message TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        db.execute("CREATE INDEX IF NOT EXISTS idx_entries_created_at ON entries(created_at)")
        db.commit()

    @app.before_request
    def ensure_db():
        init_db()

    class EntryForm(FlaskForm):
        name = StringField(
            "Имя",
            validators=[DataRequired(message="Введите имя."), Length(min=1, max=60)],
            render_kw={"maxlength": 60, "autocomplete": "name"},
        )
        message = TextAreaField(
            "Сообщение",
            validators=[DataRequired(message="Введите сообщение."), Length(min=1, max=800)],
            render_kw={"maxlength": 800, "rows": 4},
        )

    def sanitize_text(value: str) -> str:
        # Remove any HTML tags/attributes; keep only text.
        cleaned = bleach.clean(
            value,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRS,
            strip=True,
            strip_comments=True,
        )
        # Normalize whitespace a bit (keeps user formatting but avoids weird leading/trailing).
        return cleaned.strip()

    @app.get("/")
    def index():
        form = EntryForm()
        db = get_db()
        entries = db.execute(
            "SELECT id, name, message, created_at FROM entries ORDER BY created_at DESC, id DESC LIMIT 200"
        ).fetchall()
        return render_template("index.html", form=form, entries=entries)

    @app.post("/sign")
    def sign():
        form = EntryForm()
        if not form.validate_on_submit():
            # Re-render index with errors and existing entries.
            db = get_db()
            entries = db.execute(
                "SELECT id, name, message, created_at FROM entries ORDER BY created_at DESC, id DESC LIMIT 200"
            ).fetchall()
            return render_template("index.html", form=form, entries=entries), 400

        name = sanitize_text(form.name.data)
        message = sanitize_text(form.message.data)

        # Extra guard: if sanitation nuked everything, reject.
        if not name or not message:
            flash("Сообщение содержит только недопустимые символы/теги.", "error")
            return redirect(url_for("index"))

        db = get_db()
        db.execute(
            "INSERT INTO entries (name, message, created_at) VALUES (?, ?, ?)",
            (name, message, _utc_now_iso()),
        )
        db.commit()
        flash("Запись добавлена.", "success")
        return redirect(url_for("index"))

    @app.post("/clear")
    def clear():
        # Optional helper route for local demos.
        if os.environ.get("ALLOW_CLEAR_DB") != "1":
            return ("Not found", 404)
        db = get_db()
        db.execute("DELETE FROM entries")
        db.commit()
        flash("Гостевая книга очищена.", "success")
        return redirect(url_for("index"))

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
