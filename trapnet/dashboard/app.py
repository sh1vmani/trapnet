from __future__ import annotations
from flask import Flask


def create_app(logger, config) -> Flask:
    app = Flask(__name__)

    # Password protection is required here before
    # the full dashboard routes are implemented.
    # See config.dashboard.password.

    @app.route("/")
    def index():
        return "<h1>trapnet</h1><p>Dashboard initializing.</p>", 200

    @app.route("/api/stats")
    def api_stats():
        return {"status": "ok"}, 200

    return app
