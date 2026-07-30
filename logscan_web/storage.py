"""Small filesystem-backed store for uploaded logs and scan results."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
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
