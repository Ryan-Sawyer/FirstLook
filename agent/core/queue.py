import json
import time
from pathlib import Path
from typing import Any


# =============================================================
# Offline Result Queue
# =============================================================
# If the control server is unreachable when the agent tries to
# push scan results, results are written to a local JSON file.
# On the next successful connection the queue is flushed.
#
# Simple append-only file format — each line is one queued
# payload serialised as JSON (newline-delimited JSON / NDJSON).
# =============================================================


class LocalQueue:

    def __init__(self, queue_file: Path):
        self.queue_file = queue_file
        self.queue_file.parent.mkdir(parents=True, exist_ok=True)

    def enqueue(self, payload: dict[str, Any]) -> None:
        """
        Append a result payload to the local queue file.

        Args:
            payload: The scan results dict to persist.
        """
        entry = {
            "queued_at": time.time(),
            "payload":   payload,
        }
        with open(self.queue_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
        print(f"[QUEUE] Result queued locally. Queue file: {self.queue_file}")

    def drain(self) -> list[dict[str, Any]]:
        """
        Read all queued payloads and clear the queue file.
        Returns the list of payloads in queued order.

        Returns:
            List of payload dicts. Empty list if queue is empty.
        """
        if not self.queue_file.exists():
            return []

        entries = []
        with open(self.queue_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    entries.append(entry["payload"])
                except (json.JSONDecodeError, KeyError):
                    # Corrupted line — skip it
                    continue

        if entries:
            # Clear the queue file after reading
            self.queue_file.unlink()
            print(f"[QUEUE] Drained {len(entries)} queued result(s).")

        return entries

    def is_empty(self) -> bool:
        """
        Returns True if there are no queued results.
        """
        return not self.queue_file.exists() or self.queue_file.stat().st_size == 0

    def size(self) -> int:
        """
        Returns the number of queued entries.
        """
        if not self.queue_file.exists():
            return 0
        with open(self.queue_file, "r") as f:
            return sum(1 for line in f if line.strip())
