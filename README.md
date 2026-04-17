# FirstLook

> Lightweight, credential-free network discovery for MSPs. See the environment before the engagement.

FirstLook is an open source network discovery platform built for Managed Service Providers. Deploy a lightweight agent into a client's network segment, and let FirstLook map hosts, interfaces, and assets — no credentials required. Results are pushed back to the FirstLook Control Server, enriched, and ready to sync into your PSA.

---

## Why FirstLook?

Pre-sales and onboarding assessments are time-consuming. Most discovery tools require credentials, complex setup, or assume you already have access to the environment. FirstLook is designed for the moment before all of that — when you're scoping a prospect, doing an initial walkthrough, or onboarding a new client and need to know what you're dealing with.

- **No credentials needed** for basic discovery
- **Agent-based** — drop one per VLAN segment, no complex routing required
- **Non-invasive** — configurable scan throttling to avoid triggering IDS/IPS
- **ITflow integration** — push discovered assets directly into your PSA
- **Self-hosted** — your data stays on your infrastructure

---

## How It Works

```
Create Lead → Deploy Agent → Agent Scans → Results Push → Review → Go Deeper
```

1. Create a **Lead** in the FirstLook web UI for the prospect or client
2. The UI generates a **pre-configured agent package** with a unique API token
3. Drop the agent on any Linux box inside the target network segment
4. The agent runs discovery (NMAP, SNMP, LLDP, reverse DNS) and pushes results back over HTTPS
5. Review discovered hosts, interfaces, and assets in the UI
6. Optionally trigger **deeper scans** with more aggressive profiles or additional credentials

---

## Architecture

```
┌─────────────────────────────────────┐
│       FirstLook Control Server       │
│  ┌──────────┐  ┌──────────────────┐ │
│  │  Web UI  │  │    REST API      │ │
│  │  (HTMX)  │  │  (FastAPI)       │ │
│  └──────────┘  └──────────────────┘ │
│  ┌───────────────────────────────┐  │
│  │          PostgreSQL           │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
          ▲              ▲
          │              │
   ┌──────┴───┐   ┌──────┴───┐
   │  Agent   │   │  Agent   │
   │  VLAN 10 │   │  VLAN 20 │
   └──────────┘   └──────────┘
```

The **Control Server** hosts the web UI, REST API, and database. It manages agent registration, job dispatch, deduplication, and ITflow sync.

**Field Agents** are lightweight Python processes deployed per network segment. They register with the control server on first run, receive scan jobs, execute discovery locally, and push results back over HTTPS. Agents queue results locally if the control server is unreachable and flush on reconnection.

---

## Discovery Capabilities

| Method | What It Finds |
|---|---|
| NMAP ping sweep | Live hosts, open ports, OS fingerprinting |
| SNMP (public OIDs) | Device type, interfaces, ARP tables, system description |
| LLDP | Network topology, connected interfaces, switch/AP identification |
| Reverse DNS | Hostnames from local DNS infrastructure |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| API | FastAPI |
| Web UI | HTMX + Jinja2 + Tailwind CSS |
| Database | PostgreSQL + SQLAlchemy + Alembic |
| Discovery | Nmap, pysnmp, Scapy |
| Task Scheduling | APScheduler |
| Deployment | Docker Compose |

---

## Project Structure

```
firstlook/
├── control-server/         # FastAPI app, web UI, database, API
│   ├── api/                # Route handlers
│   ├── core/               # Config, security, scheduling
│   ├── db/                 # Models, schemas, migrations
│   ├── services/           # Deduplication, enrichment, ITflow client
│   └── web/                # HTMX templates, static assets
├── agent/                  # Lightweight field agent
│   ├── scanners/           # Nmap, SNMP, LLDP, DNS wrappers
│   ├── core/               # Config, registration, offline queue
│   └── push/               # HTTPS result push client
├── docs/                   # Architecture, deployment, integration guides
└── docker/                 # Docker Compose, Dockerfiles
```

---

## Getting Started

### Prerequisites

- Docker and Docker Compose
- A Linux box accessible via SSH or VPN for the control server
- A Linux box per network segment for each field agent

### Control Server

```bash
git clone https://github.com/firstlook-msp/firstlook.git
cd firstlook/docker
cp .env.example .env
# Edit .env with your settings
docker compose up -d
```

The web UI will be available at `http://your-server:8000`.

### Field Agent

From the FirstLook web UI:

1. Create a Lead for the client
2. Navigate to **Agents → Prepare Agent**
3. Copy the one-liner install command (includes your unique agent token)
4. Run it on the target Linux box inside the client's network segment

```bash
curl -sSL https://your-server:8000/agent/install.sh | bash -s -- --token YOUR_AGENT_TOKEN
```

The agent will register itself, await a scan job, and begin discovery.

---

## ITflow Integration

FirstLook can push discovered assets directly into an [ITflow](https://itflow.org) instance. Configure your ITflow URL and API key in the control server `.env` file:

```env
ITFLOW_URL=https://your-itflow-instance.com
ITFLOW_API_KEY=your_api_key
```

Asset sync can be triggered manually per lead or configured to run automatically after each scan completes.

---

## Roadmap

- [x] Project structure and architecture
- [ ] Control server — API and database
- [ ] Web UI — Lead management, agent prep, scan results
- [ ] Field agent — registration, job loop, offline queue
- [ ] NMAP scanner module
- [ ] SNMP scanner module
- [ ] LLDP scanner module
- [ ] Reverse DNS module
- [ ] Deduplication and enrichment engine
- [ ] ITflow sync adapter
- [ ] Docker Compose deployment
- [ ] Deeper scan profiles (credentialed, aggressive)
- [ ] Multi-agent coordination
- [ ] Netbox integration

---

## Contributing

FirstLook is in active early development. Contributions, feedback, and ideas are welcome.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

Please open an issue before starting significant work so we can discuss approach and avoid duplication.

---

## License

FirstLook is licensed under the [GNU Affero General Public License v3.0](LICENSE).

This means you are free to use, modify, and self-host FirstLook. If you distribute or host FirstLook as a service for others, you must make your modifications available under the same license.
