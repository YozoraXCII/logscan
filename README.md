# Kometa Log Scanner

A standalone website that scans Kometa log files and presents recommendations,
clickable line references, and a built-in log viewer. It does not require Red
Bot, Discord, a database, or persistent file storage.

Uploaded files are processed in memory. The browser keeps its local copy for
the log viewer; the server does not save uploads.

## Requirements

- Python 3.13
- Approximately 1 GB RAM is recommended for 100 MB logs
- Windows, Linux, or macOS

## Windows installation

Open PowerShell in the extracted `kometa-logscan-web` directory:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m logscan_web.app
```

Open <http://127.0.0.1:5000>.

If PowerShell blocks virtual-environment activation, run this once in the
current PowerShell window:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

## Linux or macOS installation

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m logscan_web.app
```

Open <http://127.0.0.1:5000>.

## Production

Do not use Flask's development server for a public deployment.

Linux production command:

```bash
gunicorn --workers 1 --threads 1 --timeout 300 --bind 0.0.0.0:8000 logscan_web.app:app
```

Windows production command:

```powershell
waitress-serve --listen=0.0.0.0:8000 --threads=1 logscan_web.app:app
```

One worker/thread is intentional because the inherited recommendation engine
has process-global divider state. It also avoids allowing simultaneous 100 MB
scans to exhaust memory. Put a reverse proxy and rate limiting in front of a
public instance.

## Docker

```bash
docker build -t kometa-logscan-web .
docker run --rm -p 8000:8000 kometa-logscan-web
```

Open <http://127.0.0.1:8000>.

## Reverse proxy notes

The application accepts uploads up to 100 MiB. Your reverse proxy must accept a
slightly larger HTTP request because multipart uploads add overhead.

For Nginx, include this in the applicable `server` or `location` block:

```nginx
client_max_body_size 110M;
proxy_read_timeout 300s;
proxy_send_timeout 300s;
proxy_pass http://127.0.0.1:8000;
```

If Cloudflare proxies the hostname, its plan-specific request-body limit also
applies. A nominal 100 MB Cloudflare limit may reject a 100 MiB file plus form
overhead. Use a smaller application limit, a higher-limit plan, or DNS-only
routing if full-size uploads must work.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Included files

- `logscan_web/app.py` — Flask routes and upload handling
- `logscan_web/scanner.py` — input validation and result normalization
- `logscan_web/engine.py` — standalone recommendation engine
- `logscan_web/templates/` — HTML interface
- `logscan_web/static/` — styles and browser behavior
- `tests/` — scanner and API regression tests
- `requirements.txt` — complete Python dependencies
- `Dockerfile` — container deployment
