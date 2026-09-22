"""Append-only, hash-chained JSONL audit log.

Every attack run is recorded with its exact prompt, the target's exact
response, the verdict, and a SHA-256 hash chaining it to the previous
record. ``verify`` recomputes the chain; any edit, deletion, or reorder is
detected.
"""
import hashlib
import json
from datetime import datetime, timezone


def _canonical(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()


def _hash(record):
    return hashlib.sha256(_canonical(record)).hexdigest()


class AuditLog:
    def __init__(self, path):
        self.path = path
        self._seq = 0
        self._prev = "GENESIS"
        # Resume the chain if the file already exists.
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    self._seq = rec["seq"] + 1
                    self._prev = rec["hash"]
        except FileNotFoundError:
            pass

    def append(self, entry):
        record = {
            "seq": self._seq,
            "ts": datetime.now(timezone.utc).isoformat(),
            "prev_hash": self._prev,
        }
        record.update(entry)
        record["hash"] = _hash({k: v for k, v in record.items()
                                if k != "hash"})
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=True) + "\n")
        self._seq += 1
        self._prev = record["hash"]
        return record

    def verify(self):
        """Return (ok, message). Recomputes the full chain."""
        prev = "GENESIS"
        seq = 0
        try:
            with open(self.path, encoding="utf-8") as f:
                lines = [ln for ln in f if ln.strip()]
        except FileNotFoundError:
            return True, "no log file yet"
        for line in lines:
            rec = json.loads(line)
            if rec["seq"] != seq or rec["prev_hash"] != prev:
                return False, f"chain broken at seq {rec.get('seq')}"
            h = rec.pop("hash")
            if _hash(rec) != h:
                return False, f"tamper detected at seq {seq}"
            prev, seq = h, seq + 1
        return True, f"chain intact ({seq} records)"
