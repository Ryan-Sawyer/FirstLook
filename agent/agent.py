import time

from core.config import load_config
from core.registration import register, send_heartbeat
from push.client import PushClient
from scanners import dns, lldp, nmap, snmp


# =============================================================
# FirstLook Field Agent
# =============================================================
# Main entrypoint. Lifecycle:
#
#   1. Load config (CLI args / env vars)
#   2. Register with the control server
#   3. Enter the main loop:
#       a. Send heartbeat
#       b. Poll for queued scan jobs
#       c. For each job:
#           - Mark running
#           - Run scanners (nmap → SNMP → DNS → LLDP)
#           - Push results
#       d. Flush any locally queued results
#       e. Sleep until next poll
# =============================================================

BANNER = """
  ___  _         _    _              _
 | __||_| _ _  _| |_ | |  ___  ___ | |__
 | _| | || '_|_/  _| | | / _ \/ _ \| / /
 |_|  |_||_|   \__| |_|  \___/\___/|_\_\\

 Open source network discovery for MSPs.
 Control server: {server}
 Agent UUID:     {uuid}
"""


def run_scan_job(job: dict, config, push_client: PushClient) -> None:
    """
    Execute a single scan job end-to-end.

    Args:
        job:        Scan job dict from the control server.
        config:     Loaded AgentConfig.
        push_client: Initialised PushClient.
    """
    job_uuid    = job["job_uuid"]
    scan_type   = job.get("scan_type", "basic")
    subnets     = job.get("target_subnets", [])

    print(f"\n[JOB] Starting {scan_type} scan — job {job_uuid}")
    print(f"[JOB] Target subnets: {', '.join(subnets)}")

    # Mark running
    push_client.mark_job_running(job_uuid)

    try:
        # ─────────────────────────────────────────
        # Step 1 — LLDP discovery (passive, fast)
        # ─────────────────────────────────────────
        print("\n[JOB] Step 1/4 — LLDP discovery")
        lldp_assets = lldp.run_lldp_discovery()

        # ─────────────────────────────────────────
        # Step 2 — Nmap scan
        # ─────────────────────────────────────────
        print(f"\n[JOB] Step 2/4 — Nmap {scan_type} scan")
        if scan_type == "deep":
            nmap_assets = nmap.run_deep_scan(subnets, throttle=config.scan_throttle)
        else:
            nmap_assets = nmap.run_basic_scan(subnets, throttle=config.scan_throttle)

        # ─────────────────────────────────────────
        # Step 3 — SNMP enrichment
        # ─────────────────────────────────────────
        print(f"\n[JOB] Step 3/4 — SNMP enrichment ({len(nmap_assets)} hosts)")
        snmp.enrich_assets(nmap_assets)

        # ─────────────────────────────────────────
        # Step 4 — Reverse DNS
        # ─────────────────────────────────────────
        print(f"\n[JOB] Step 4/4 — Reverse DNS resolution")
        dns.enrich_assets_dns(nmap_assets)

        # ─────────────────────────────────────────
        # Combine and deduplicate before pushing
        # ─────────────────────────────────────────
        # LLDP assets go first — they're typically network devices
        # that SNMP/nmap may also have found. The server-side
        # deduplication handles MAC-based merging.
        all_assets = lldp_assets + nmap_assets

        print(f"\n[JOB] Scan complete — {len(all_assets)} total assets")
        print(f"[JOB]   LLDP:  {len(lldp_assets)}")
        print(f"[JOB]   Nmap:  {len(nmap_assets)}")

        # ─────────────────────────────────────────
        # Push results
        # ─────────────────────────────────────────
        push_client.push_results(job_uuid, all_assets)

    except Exception as e:
        print(f"[JOB] Scan failed with exception: {e}")
        push_client.mark_job_failed(job_uuid)
        raise


def main() -> None:
    # Load config
    config = load_config()

    print(BANNER.format(server=config.server_url, uuid=config.agent_uuid))

    # Register with control server
    print("[AGENT] Registering with control server...")
    registered = register(config)
    if not registered:
        print("[AGENT] Registration failed. Retrying in 30 seconds...")
        # Keep retrying registration — don't exit. The server may be
        # temporarily unavailable.

    # Initialise push client
    push_client = PushClient(config)

    # Counters for heartbeat timing
    last_heartbeat = 0.0

    print(f"[AGENT] Entering main loop. Poll interval: {config.poll_interval}s")

    while True:
        now = time.time()

        # ── Heartbeat ──────────────────────────────
        if now - last_heartbeat >= config.heartbeat_interval:
            send_heartbeat(config)
            last_heartbeat = now

        # ── Poll for jobs ──────────────────────────
        jobs = push_client.get_pending_jobs()

        if jobs:
            print(f"[AGENT] {len(jobs)} job(s) queued")
            for job in jobs:
                try:
                    run_scan_job(job, config, push_client)
                except Exception as e:
                    print(f"[AGENT] Job {job.get('job_uuid')} failed: {e}")
        else:
            print(f"[AGENT] No pending jobs. Sleeping {config.poll_interval}s...")

        time.sleep(config.poll_interval)


if __name__ == "__main__":
    main()
