import argparse
import os
from dataclasses import dataclass, field
from pathlib import Path


# =============================================================
# Agent Configuration
# =============================================================
# Settings are loaded in priority order:
#   1. Command-line arguments (highest)
#   2. Environment variables
#   3. Defaults (lowest)
#
# This allows the install command to pass --server, --agent-id,
# and --token as args while still being overridable via env
# for more complex deployments.
# =============================================================

# Path to persist the agent config after first registration
CONFIG_FILE = Path("/etc/firstlook-agent/agent.conf")
QUEUE_FILE  = Path("/var/lib/firstlook-agent/queue.json")


@dataclass
class AgentConfig:
    # Control server
    server_url:     str     = ""

    # Agent identity
    agent_uuid:     str     = ""
    api_token:      str     = ""

    # Behaviour
    poll_interval:  int     = 30        # seconds between job polls
    heartbeat_interval: int = 60        # seconds between heartbeats
    scan_throttle:  float   = 0.5       # seconds between nmap host probes
    max_retries:    int     = 5         # push retries before queuing locally

    # Paths
    queue_file:     Path    = field(default_factory=lambda: QUEUE_FILE)


def load_config() -> AgentConfig:
    """
    Load agent configuration from CLI args and environment variables.
    CLI args take precedence over env vars.

    Returns:
        Populated AgentConfig instance.

    Raises:
        SystemExit: If required fields (server, agent-id, token) are missing.
    """
    parser = argparse.ArgumentParser(description="FirstLook Field Agent")

    parser.add_argument("--server",     help="Control server base URL",  default=None)
    parser.add_argument("--agent-id",   help="Agent UUID",               default=None)
    parser.add_argument("--token",      help="API token",                 default=None)
    parser.add_argument("--poll",       help="Poll interval (seconds)",   type=int, default=None)
    parser.add_argument("--heartbeat",  help="Heartbeat interval (secs)", type=int, default=None)
    parser.add_argument("--throttle",   help="Scan throttle (seconds)",   type=float, default=None)

    args = parser.parse_args()

    config = AgentConfig(
        server_url  = args.server       or os.getenv("FL_SERVER_URL",  ""),
        agent_uuid  = args.agent_id     or os.getenv("FL_AGENT_UUID",  ""),
        api_token   = args.token        or os.getenv("FL_API_TOKEN",   ""),
        poll_interval       = args.poll         or int(os.getenv("FL_POLL_INTERVAL",      "30")),
        heartbeat_interval  = args.heartbeat    or int(os.getenv("FL_HEARTBEAT_INTERVAL", "60")),
        scan_throttle       = args.throttle     or float(os.getenv("FL_SCAN_THROTTLE",    "0.5")),
    )

    # Validate required fields
    errors = []
    if not config.server_url:
        errors.append("--server / FL_SERVER_URL is required")
    if not config.agent_uuid:
        errors.append("--agent-id / FL_AGENT_UUID is required")
    if not config.api_token:
        errors.append("--token / FL_API_TOKEN is required")

    if errors:
        for e in errors:
            print(f"[ERROR] {e}")
        raise SystemExit(1)

    # Normalise server URL — strip trailing slash
    config.server_url = config.server_url.rstrip("/")

    # Ensure queue directory exists
    config.queue_file.parent.mkdir(parents=True, exist_ok=True)

    return config
