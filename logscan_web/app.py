from flask import Flask, jsonify, render_template, request

from .scanner import MAX_FILE_BYTES, ScanError, scan_log


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_BYTES

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.post("/api/scan")
    def scan():
        upload = request.files.get("log")
        if upload is None or not upload.filename:
            return jsonify(error="Choose a log file to scan."), 400
        try:
            result = scan_log(upload.filename, upload.read())
        except ScanError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(
            filename=result.filename,
            recommendations=result.recommendations,
            metadata=result.metadata,
        )

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify(error="The selected file is larger than the 100 MB limit."), 413

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
