import hmac
import os
import threading
import time
from datetime import UTC, datetime, timedelta

from flask import Flask, abort, jsonify, render_template, request, send_file, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from .scanner import MAX_FILE_BYTES, ScanError, scan_log
from .storage import ScanStore

RETENTION_SECONDS = 48 * 60 * 60
CLEANUP_INTERVAL_SECONDS = 60 * 60


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_BYTES + (1024 * 1024)
    app.config["SCAN_STORE"] = os.environ.get("SCAN_STORE", "/data/scans")
    app.config["LOGSCAN_API_KEY"] = os.environ.get("LOGSCAN_API_KEY", "")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    store = ScanStore(app.config["SCAN_STORE"])

    def cleanup_loop():
        while True:
            try:
                removed = store.delete_expired(RETENTION_SECONDS)
                if removed:
                    app.logger.info("Deleted %d expired scan(s).", removed)
            except Exception:
                app.logger.exception("Unable to clean up expired scans.")
            time.sleep(CLEANUP_INTERVAL_SECONDS)

    # Gunicorn is intentionally configured with one worker, so one daemon is
    # sufficient. The immediate sweep also removes expired data after downtime.
    store.delete_expired(RETENTION_SECONDS)
    if not app.config.get("TESTING"):
        threading.Thread(target=cleanup_loop, name="logscan-cleanup", daemon=True).start()

    @app.get("/")
    def index():
        return render_template("index.html", initial_scan=None)

    @app.get("/scan/<scan_id>")
    def result_page(scan_id):
        record = store.get(scan_id)
        if record is None:
            abort(404)
        public = {key: value for key, value in record.items() if key != "delete_token_hash"}
        return render_template("index.html", initial_scan=public)

    @app.post("/api/scan")
    @app.post("/api/bot/scan")
    def scan():
        configured_key = app.config["LOGSCAN_API_KEY"]
        if configured_key:
            supplied = request.headers.get("Authorization", "").removeprefix("Bearer ")
            is_bot = hmac.compare_digest(supplied, configured_key)
        else:
            is_bot = False
        if request.path == "/api/bot/scan" and (not configured_key or not is_bot):
            return jsonify(error="Invalid API key."), 401
        upload = request.files.get("log")
        if upload is None or not upload.filename:
            return jsonify(error="Choose a log file to scan."), 400
        try:
            content = upload.read()
            result = scan_log(upload.filename, content)
        except ScanError as exc:
            return jsonify(error=str(exc)), 400
        scan_id, delete_token = store.create(upload.filename, content, result)
        result_url = url_for("result_page", scan_id=scan_id, _external=True)
        expires_at = int((datetime.now(UTC) + timedelta(seconds=RETENTION_SECONDS)).timestamp())
        return jsonify(
            id=scan_id,
            filename=result.filename,
            recommendations=result.recommendations,
            metadata=result.metadata,
            overview=result.overview,
            categories=result.categories,
            result_url=result_url,
            delete_token=delete_token,
            expires_at=expires_at,
            uploaded_by_bot=is_bot,
        )

    @app.get("/api/scans/<scan_id>/log")
    def stored_log(scan_id):
        path = store.log_path(scan_id)
        if path is None:
            abort(404)
        return send_file(path, mimetype="text/plain; charset=utf-8", conditional=True)

    @app.delete("/api/scans/<scan_id>")
    def delete_scan(scan_id):
        token = request.headers.get("X-Delete-Token", "")
        if not token or not store.delete(scan_id, token):
            return jsonify(error="The scan was not found or the delete token is invalid."), 403
        return "", 204

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify(error="The selected file is larger than the 100 MB limit."), 413

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
