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
 _____ _          _   _                _
|  ___(_)_ __ ___| |_| |    ___   ___ | | __
| |_  | | '__/ __| __| |   / _ \ / _ \| |/ /
|  _| | | |  \__ \ |_| |__| (_) | (_) |   <
|_|   |_|_|  |___/\__|_____\___/ \___/|_|\_\
 Open source network discovery for MSPs.
 Control server: {server}
 Agent UUID:     {uuid}
"""



def run_scan_job(job: dict, config, push_client: PushClient) -> None:
    job_uuid    = job["job_uuid"]
    scan_type   = job.get("scan_type", "basic")
    subnets     = job.get("target_subnets", [])
    dns_server  = job.get("dns_server")

    print(f"\n[JOB] Starting {scan_type} scan — job {job_uuid}")
    print(f"[JOB] Target subnets: {', '.join(subnets)}")
    if dns_server:
        print(f"[JOB] DNS server override: {dns_server}")

    push_client.mark_job_running(job_uuid)

    try:
        if scan_type == "basic":
            print("\n[JOB] Running Layer 0 discovery")
            assets = run_layer0(subnets=subnets, dns_server=dns_server)

        elif scan_type == "deep":
            print("\n[JOB] Running Layer 0 discovery")
            assets = run_layer0(subnets=subnets, dns_server=dns_server)
            # TODO: Layer 1 — SNMP enrichment
            # TODO: Layer 2 — Port scan + service detection

        else:
            print(f"[JOB] Unknown scan type: {scan_type} — defaulting to Layer 0")
            assets = run_layer0(subnets=subnets, dns_server=dns_server)

        print(f"\n[JOB] Scan complete — {len(assets)} total assets")
        push_client.push_results(job_uuid, assets)

    except Exception as e:
        print(f"[JOB] Scan failed with exception: {e}")
        push_client.mark_job_failed(job_uuid)
        raise


def main() -> None:
    config = load_config()

    print(BANNER.format(server=config.server_url, uuid=config.agent_uuid))

    print("[AGENT] Registering with control server...")
    registered = register(config)
    if not registered:
        print("[AGENT] Registration failed — will retry on next heartbeat cycle")

    push_client = PushClient(config)
    last_heartbeat = 0.0

    print(f"[AGENT] Entering main loop. Poll interval: {config.poll_interval}s")

    while True:
        now = time.time()

        if now - last_heartbeat >= config.heartbeat_interval:
            send_heartbeat(config)
            last_heartbeat = now

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
