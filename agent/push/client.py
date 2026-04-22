from typing import Any

import httpx

from core.config import AgentConfig
from core.queue import LocalQueue


# =============================================================
# Push Client
# =============================================================
# Handles all outbound communication from the agent to the
# control server — polling for jobs, pushing results, and
# updating job status.
#
# If a push fails the result is queued locally and retried
# on the next successful connection.
# =============================================================

TIMEOUT = 30.0  # seconds — scan results can be large


class PushClient:

    def __init__(self, config: AgentConfig):
        self.config = config
        self.queue  = LocalQueue(config.queue_file)
        self.headers = {
            "Authorization": f"Bearer {config.api_token}",
            "Content-Type":  "application/json",
        }

    # ─────────────────────────────────────────
    # Job polling
    # ─────────────────────────────────────────

    def get_pending_jobs(self) -> list[dict[str, Any]]:
        """
        Poll the control server for queued scan jobs.

        Returns:
            List of scan job dicts. Empty list if none or unreachable.
        """
        try:
            response = httpx.get(
                f"{self.config.server_url}/api/scans/pending/{self.config.agent_uuid}",
                headers=self.headers,
                timeout=TIMEOUT,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            print(f"[PUSH] Failed to fetch jobs: {e.response.status_code}")
            return []
        except httpx.RequestError:
            print("[PUSH] Control server unreachable — will retry")
            return []

    # ─────────────────────────────────────────
    # Job status updates
    # ─────────────────────────────────────────

    def mark_job_running(self, job_uuid: str) -> bool:
        """Mark a scan job as running on the control server."""
        from datetime import datetime, timezone
        return self._update_job_status(job_uuid, {
            "status":     "running",
            "started_at": datetime.now(timezone.utc).isoformat(),
        })

    def mark_job_failed(self, job_uuid: str) -> bool:
        """Mark a scan job as failed on the control server."""
        return self._update_job_status(job_uuid, {"status": "failed"})

    def _update_job_status(self, job_uuid: str, payload: dict) -> bool:
        try:
            response = httpx.patch(
                f"{self.config.server_url}/api/scans/job/{job_uuid}",
                headers=self.headers,
                json=payload,
                timeout=TIMEOUT,
            )
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"[PUSH] Failed to update job status: {e}")
            return False

    # ─────────────────────────────────────────
    # Results submission
    # ─────────────────────────────────────────

    def push_results(self, job_uuid: str, assets: list[dict]) -> bool:
        """
        Push scan results to the control server.
        If the push fails, results are queued locally for later retry.

        Args:
            job_uuid:   The scan job UUID.
            assets:     List of discovered asset dicts.

        Returns:
            True if results were accepted, False if queued locally.
        """
        payload = {
            "job_uuid": job_uuid,
            "assets":   assets,
        }

        # First try to flush any previously queued results
        self._flush_queue()

        success = self._post_results(payload)

        if not success:
            print(f"[PUSH] Push failed — queuing {len(assets)} assets locally")
            self.queue.enqueue(payload)
            return False

        print(f"[PUSH] Results accepted by control server. {len(assets)} assets.")
        return True

    def _post_results(self, payload: dict) -> bool:
        """
        Attempt a single POST of scan results.

        Returns:
            True on success, False on any failure.
        """
        try:
            response = httpx.post(
                f"{self.config.server_url}/api/scans/submit",
                headers=self.headers,
                json=payload,
                timeout=TIMEOUT,
            )
            response.raise_for_status()
            return True
        except httpx.HTTPStatusError as e:
            print(f"[PUSH] Server rejected results: {e.response.status_code} {e.response.text}")
            return False
        except httpx.RequestError:
            print("[PUSH] Control server unreachable")
            return False

    def _flush_queue(self) -> None:
        """
        Attempt to push any locally queued results to the control server.
        Quietly skips if queue is empty or server is still unreachable.
        """
        if self.queue.is_empty():
            return

        print(f"[PUSH] Flushing {self.queue.size()} queued result(s)...")
        queued = self.queue.drain()

        for payload in queued:
            success = self._post_results(payload)
            if not success:
                # Server still unreachable — re-queue and stop trying
                self.queue.enqueue(payload)
                print("[PUSH] Server still unreachable — re-queued")
                break
            print(f"[PUSH] Flushed queued result for job {payload.get('job_uuid')}")
