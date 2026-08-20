import hmac
import hashlib
import json
import os
import threading
import time
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from flask import Flask, abort, jsonify, render_template, request, send_file, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from .scanner import MAX_FILE_BYTES, ScanError, extract_missing_people, prepare_scan_input, scan_archive_logs, scan_log
from .storage import PeopleStore, ScanStore

RETENTION_SECONDS = 48 * 60 * 60
CLEANUP_INTERVAL_SECONDS = 60 * 60


def load_local_env() -> None:
    """Load a local development .env without overriding real process settings."""
    env_file = os.path.join(os.getcwd(), ".env")
    try:
        with open(env_file, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                if key and key.replace("_", "").isalnum():
                    os.environ.setdefault(key, value.strip().strip("'\""))
    except FileNotFoundError:
        pass


def create_app() -> Flask:
    load_local_env()
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_BYTES + (1024 * 1024)
    app.config["SCAN_STORE"] = os.environ.get("SCAN_STORE", "/data/scans")
    app.config["LOGSCAN_API_KEY"] = os.environ.get("LOGSCAN_API_KEY", "")
    app.config["TMDB_API_KEY"] = os.environ.get("TMDB_API_KEY", "")
    app.config["DISCORD_PEOPLE_WEBHOOK_URL"] = os.environ.get("DISCORD_PEOPLE_WEBHOOK_URL", "")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    store = ScanStore(app.config["SCAN_STORE"])
    people_store = PeopleStore(app.config["SCAN_STORE"])

    def tmdb_get(path: str, params: dict | None = None) -> dict | None:
        api_key = app.config["TMDB_API_KEY"]
        if not api_key:
            return None
        query = urlencode({"api_key": api_key, **(params or {})})
        request_url = f"https://api.themoviedb.org/3{path}?{query}"
        try:
            with urlopen(Request(request_url, headers={"Accept": "application/json"}), timeout=10) as response:
                import json
                return json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, ValueError):
            app.logger.warning("TMDb lookup failed for %s", path)
            return None

    def save_missing_people(candidates: list[dict], *, filename: str, log_url: str, source_url: str | None) -> list[dict]:
        saved = []
        for candidate in candidates:
            name = candidate["name"]
            match_data = tmdb_get("/search/person", {"query": name})
            matches = (match_data or {}).get("results", [])
            exact = next((item for item in matches if item.get("name", "").casefold() == name.casefold()), None)
            match = exact or (matches[0] if matches else None)
            tmdb_id = match.get("id") if match else None
            image_data = tmdb_get(f"/person/{tmdb_id}/images") if tmdb_id else None
            tmdb_image_found = bool((image_data or {}).get("profiles", []))
            key_seed = str(tmdb_id) if tmdb_id else name.casefold()
            key = f"tmdb-{tmdb_id}" if tmdb_id else f"name-{hashlib.sha256(key_seed.encode()).hexdigest()[:16]}"
            person, is_new = people_store.upsert_with_status({
                "key": key,
                "name": match.get("name", name) if match else name,
                "tmdb_id": tmdb_id,
                "tmdb_image_found": tmdb_image_found,
                "log_tmdb_image_found": bool(candidate["tmdb_image_found"]),
                "log_name": filename,
                "log_url": log_url,
                "source_url": source_url,
            })
            person["people_url"] = url_for("person_page", person_key=person["key"], _external=True)
            person["is_new"] = is_new
            saved.append(person)
        return saved

    def notify_people_webhook(people: list[dict]) -> None:
        """Notify Discord when the website creates a new people-backlog entry."""
        webhook_url = app.config["DISCORD_PEOPLE_WEBHOOK_URL"]
        if not webhook_url:
            app.logger.info("Missing-person webhook is not configured; no website notification sent.")
            return
        new_people = [person for person in people if person.get("is_new")]
        for person in people:
            if not person.get("is_new"):
                app.logger.info("Missing-person webhook skipped for existing person: %s", person["name"])
        if not new_people:
            return
        first = new_people[0]
        names = "\n".join(
            f"- [{person['name']}]({person['people_url']}) — **TMDb Image Found:** "
            f"{'Yes' if person.get('tmdb_image_found') else 'No'}"
            for person in new_people
        )
        message = (
            f"**Log Name:** `{first['log_name']}`\n"
            f"**Log URL:** [Click Here]({first['log_url']})\n"
            "**Log Source:** Not available\n"
            f"**People Found:**\n{names}"
        )
        try:
            payload = json.dumps({"content": message[:2000], "flags": 4}).encode("utf-8")
            webhook_request = Request(
                webhook_url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Kometa-Logscan/1.0",
                },
                method="POST",
            )
            with urlopen(webhook_request, timeout=10):
                pass
            app.logger.info("Missing-person webhook sent for %d new people.", len(new_people))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            app.logger.warning(
                "Unable to send missing-person Discord webhook: HTTP %s %s",
                exc.code,
                detail,
            )
        except (URLError, TimeoutError) as exc:
            app.logger.warning("Unable to send missing-person Discord webhook: %s", exc)

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

    @app.get("/people")
    def people_page():
        return render_template("people.html")

    @app.get("/people/<person_key>")
    def person_page(person_key):
        if people_store.get(person_key) is None:
            abort(404)
        return render_template("person.html", person_key=person_key)

    @app.get("/scan/<scan_id>")
    def result_page(scan_id):
        record = store.get(scan_id)
        if record is None:
            abort(404)
        public = {key: value for key, value in record.items() if key != "delete_token_hash"}
        public["expires_at"] = int(datetime.fromisoformat(record["created_at"]).timestamp() + RETENTION_SECONDS)
        return render_template("index.html", initial_scan=public)

    @app.get("/batch/<batch_id>")
    def batch_page(batch_id):
        batch = store.get_batch(batch_id)
        if batch is None:
            abort(404)
        return render_template("batch.html", scans=batch["scans"], admin=False)

    @app.get("/batch/<batch_id>/admin/<token>")
    def batch_admin_page(batch_id, token):
        batch = store.get_batch(batch_id, token)
        if batch is None:
            abort(404)
        return render_template("batch.html", scans=batch["scans"], admin=True)

    def bot_request_is_authorized() -> bool:
        configured_key = app.config["LOGSCAN_API_KEY"]
        supplied = request.headers.get("Authorization", "").removeprefix("Bearer ")
        return bool(configured_key) and hmac.compare_digest(supplied, configured_key)

    @app.post("/api/bot/validate")
    def validate_bot_upload():
        """Check an attachment without persisting a scan or notifying anyone."""
        if not bot_request_is_authorized():
            return jsonify(error="Invalid API key."), 401
        upload = request.files.get("log")
        if upload is None or not upload.filename:
            return jsonify(error="Choose a log file to scan."), 400
        try:
            scans = scan_archive_logs(upload.filename, upload.read())
        except ScanError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(files=[{"filename": filename, "content_size": len(content)} for filename, content, _result in scans])

    @app.post("/api/scan")
    @app.post("/api/bot/scan")
    def scan():
        is_bot = bot_request_is_authorized()
        if request.path == "/api/bot/scan" and not is_bot:
            return jsonify(error="Invalid API key."), 401
        upload = request.files.get("log")
        if upload is None or not upload.filename:
            return jsonify(error="Choose a log file to scan."), 400
        try:
            content = upload.read()
            scans = scan_archive_logs(upload.filename, content) if request.path == "/api/bot/scan" else []
            if not scans:
                filename, content = prepare_scan_input(upload.filename, content)
                scans = [(filename, content, scan_log(filename, content))]
        except ScanError as exc:
            return jsonify(error=str(exc)), 400
        source_url = request.form.get("source_url") if is_bot else None
        expires_at = int((datetime.now(UTC) + timedelta(seconds=RETENTION_SECONDS)).timestamp())
        payloads = []
        for filename, content, result in scans:
            scan_id, delete_token = store.create(filename, content, result)
            result_url = url_for("result_page", scan_id=scan_id, _external=True)
            missing_people = save_missing_people(extract_missing_people(content.decode("utf-8", errors="replace")), filename=result.filename, log_url=result_url, source_url=source_url)
            payloads.append({"id": scan_id, "filename": result.filename, "recommendations": result.recommendations, "metadata": result.metadata, "overview": result.overview, "categories": result.categories, "result_url": result_url, "delete_token": delete_token, "expires_at": expires_at, "uploaded_by_bot": is_bot, "missing_people": missing_people})
        if not is_bot:
            notify_people_webhook([person for payload in payloads for person in payload["missing_people"]])
        if request.path == "/api/bot/scan":
            batch_id, admin_token = store.create_batch(payloads)
            return jsonify(scans=payloads, batch_result_url=url_for("batch_page", batch_id=batch_id, _external=True), batch_admin_url=url_for("batch_admin_page", batch_id=batch_id, token=admin_token, _external=True))
        return jsonify(payloads[0])

    @app.get("/api/people")
    def people():
        people = people_store.list()
        for person in people:
            person["people_url"] = url_for("person_page", person_key=person["key"], _external=True)
        return jsonify(people=people)

    @app.get("/api/people/<person_key>/images")
    def person_images(person_key):
        person = people_store.get(person_key)
        if person is None:
            abort(404)
        images = []
        if not person.get("tmdb_id"):
            match_data = tmdb_get("/search/person", {"query": person["name"]})
            matches = (match_data or {}).get("results", [])
            exact = next(
                (item for item in matches if item.get("name", "").casefold() == person["name"].casefold()),
                None,
            )
            match = exact or (matches[0] if matches else None)
            if match:
                person = people_store.upsert({
                    **person,
                    "tmdb_id": match["id"],
                    "name": match.get("name", person["name"]),
                })
        if person.get("tmdb_id"):
            data = tmdb_get(f"/person/{person['tmdb_id']}/images", {"include_image_language": "en,null"})
            for image in (data or {}).get("profiles", []):
                path = image.get("file_path")
                if path:
                    images.append({
                        "preview_url": f"https://image.tmdb.org/t/p/w342{path}",
                        "download_url": f"https://image.tmdb.org/t/p/original{path}",
                        "width": image.get("width"),
                        "height": image.get("height"),
                    })
            if person.get("tmdb_image_found") != bool(images):
                person = people_store.upsert({**person, "tmdb_image_found": bool(images)})
        limit = request.args.get("limit", type=int)
        if limit is not None:
            images = images[:max(0, min(limit, 100))]
        return jsonify(person=person, images=images)

    @app.delete("/api/people/<person_key>")
    def complete_person(person_key):
        if not people_store.delete(person_key):
            abort(404)
        return "", 204

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
