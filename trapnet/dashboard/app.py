from __future__ import annotations
import asyncio
import functools
import os

from flask import (
    Flask, jsonify, redirect, render_template,
    request, send_file, session, url_for,
)


def create_app(logger, config) -> Flask:
    app = Flask(__name__)

    # Secret key is generated once at startup and lives only in memory.
    # Sessions are invalidated whenever the process restarts.
    app.secret_key = os.urandom(24)

    # ---------------------------------------------------------------------------
    # Threading model:
    # Flask runs in a daemon thread started by __main__.py. The asyncio engine
    # runs in the main thread's event loop. The logger methods are pure async
    # coroutines, so each Flask route that needs data bridges into async by
    # calling asyncio.run(), which creates a temporary event loop for that call.
    # This is safe because each asyncio.run() call is independent and the logger
    # only uses aiosqlite, which opens and closes its own connection per call.
    # ---------------------------------------------------------------------------

    def _run_async(coro):
        try:
            return asyncio.run(coro)
        except Exception as exc:
            print(f"dashboard async error: {exc}")
            return None

    def require_auth(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            if not session.get("authenticated"):
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return wrapper

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            if request.form.get("password") == config.dashboard.password:
                session["authenticated"] = True
                return redirect(url_for("index"))
            error = "Incorrect password."
        return render_template("login.html", error=error)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @require_auth
    def index():
        return render_template("index.html")

    @app.route("/api/stats")
    @require_auth
    def api_stats():
        stats = _run_async(logger.get_stats())
        if stats is None:
            stats = {
                "total_connections": 0,
                "top_services": [],
                "top_ips": [],
                "connections_last_24h": [],
                "scanner_breakdown": [],
            }
        return jsonify(stats)

    @app.route("/api/recent")
    @require_auth
    def api_recent():
        rows = _run_async(logger.get_recent(limit=100))
        return jsonify(rows or [])

    @app.route("/api/export/json")
    @require_auth
    def api_export_json():
        path = os.path.join("logs", "export.json")
        _run_async(logger.export_json(path))
        return send_file(
            os.path.abspath(path),
            mimetype="application/json",
            as_attachment=True,
            download_name="trapnet_export.json",
        )

    @app.route("/api/export/csv")
    @require_auth
    def api_export_csv():
        path = os.path.join("logs", "export.csv")
        _run_async(logger.export_csv(path))
        return send_file(
            os.path.abspath(path),
            mimetype="text/csv",
            as_attachment=True,
            download_name="trapnet_export.csv",
        )

    return app
