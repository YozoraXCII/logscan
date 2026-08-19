"""Small filesystem-backed store for uploaded logs and scan results."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import threading
from datetime import UTC, datetime
from pathlib import Path


class ScanStore:
    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def create(self, filename: str, content: bytes, result) -> tuple[str, str]:
        scan_id = secrets.token_urlsafe(18)
        delete_token = secrets.token_urlsafe(32)
        directory = self.root / scan_id
        directory.mkdir()
        (directory / "log").write_bytes(content)
        record = {
            "id": scan_id,
            "filename": result.filename,
            "created_at": datetime.now(UTC).isoformat(),
            "recommendations": result.recommendations,
            "metadata": result.metadata,
            "overview": result.overview,
            "categories": result.categories,
            "delete_token_hash": hashlib.sha256(delete_token.encode()).hexdigest(),
        }
        temporary = directory / "result.json.tmp"
        temporary.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        temporary.replace(directory / "result.json")
        return scan_id, delete_token

    def get(self, scan_id: str) -> dict | None:
        if not self._valid_id(scan_id):
            return None
        try:
            return json.loads((self.root / scan_id / "result.json").read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def log_path(self, scan_id: str) -> Path | None:
        if self.get(scan_id) is None:
            return None
        path = self.root / scan_id / "log"
        return path if path.is_file() else None

    def delete(self, scan_id: str, token: str) -> bool:
        record = self.get(scan_id)
        if record is None:
            return False
        supplied = hashlib.sha256(token.encode()).hexdigest()
        if not hmac.compare_digest(supplied, record["delete_token_hash"]):
            return False
        directory = self.root / scan_id
        for name in ("log", "result.json", "result.json.tmp"):
            try:
                (directory / name).unlink()
            except FileNotFoundError:
                pass
        directory.rmdir()
        return True

    def delete_expired(self, max_age_seconds: int) -> int:
        """Delete scans whose recorded creation time is older than max_age_seconds."""
        cutoff = datetime.now(UTC).timestamp() - max_age_seconds
        deleted = 0
        for directory in self.root.iterdir():
            if not directory.is_dir() or not self._valid_id(directory.name):
                continue
            record = self.get(directory.name)
            if record is None:
                continue
            try:
                created = datetime.fromisoformat(record["created_at"]).timestamp()
            except (KeyError, TypeError, ValueError):
                created = 0
            if created >= cutoff:
                continue
            shutil.rmtree(directory)
            deleted += 1
        return deleted

    @staticmethod
    def _valid_id(scan_id: str) -> bool:
        return bool(scan_id) and scan_id.replace("-", "").replace("_", "").isalnum()


class PeopleStore:
    """A small durable backlog for People Posters work, independent of scan expiry."""

    def __init__(self, root: str | os.PathLike[str]):
        self.path = Path(root) / "people.json"
        self.lock = threading.Lock()

    def list(self) -> list[dict]:
        with self.lock:
            return self._read()

    def get(self, key: str) -> dict | None:
        return next((person for person in self.list() if person["key"] == key), None)

    def upsert(self, person: dict) -> dict:
        with self.lock:
            people = self._read()
            existing = next((item for item in people if item["key"] == person["key"]), None)
            if existing:
                existing.update({key: value for key, value in person.items() if value is not None})
                existing["last_seen_at"] = datetime.now(UTC).isoformat()
                result = existing
            else:
                result = {**person, "created_at": datetime.now(UTC).isoformat(), "last_seen_at": datetime.now(UTC).isoformat()}
                people.append(result)
            self._write(people)
            return result.copy()

    def delete(self, key: str) -> bool:
        with self.lock:
            people = self._read()
            remaining = [person for person in people if person["key"] != key]
            if len(remaining) == len(people):
                return False
            self._write(remaining)
            return True

    def _read(self) -> list[dict]:
        try:
            result = json.loads(self.path.read_text(encoding="utf-8"))
            return result if isinstance(result, list) else []
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _write(self, people: list[dict]) -> None:
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(people, ensure_ascii=False), encoding="utf-8")
        temporary.replace(self.path)
