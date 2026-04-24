-- =============================================================
-- FirstLook Database Schema
-- =============================================================
-- This script runs automatically on first boot of the PostgreSQL
-- container via /docker-entrypoint-initdb.d/
-- Future schema changes are handled by Alembic migrations.
-- =============================================================

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================
-- ENUMS
-- =============================================================

CREATE TYPE client_status AS ENUM (
    'prospect',
    'active',
    'archived'
);

CREATE TYPE agent_status AS ENUM (
    'pending',
    'active',
    'inactive'
);

CREATE TYPE job_status AS ENUM (
    'queued',
    'running',
    'complete',
    'failed'
);

CREATE TYPE scan_type AS ENUM (
    'basic',
    'deep'
);

CREATE TYPE asset_type AS ENUM (
    'server',
    'workstation',
    'switch',
    'router',
    'ap',
    'printer',
    'unknown'
);

CREATE TYPE discovery_method AS ENUM (
    'nmap',
    'snmp',
    'lldp',
    'arp'
);

-- =============================================================
-- TABLES
-- =============================================================

-- -------------------------------------------------------------
-- clients
-- A prospect becomes a client — same record, status changes.
-- -------------------------------------------------------------
CREATE TABLE clients (
    client_uuid         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(255) NOT NULL,
    status              client_status NOT NULL DEFAULT 'prospect',
    contact_name        VARCHAR(255),
    contact_email       VARCHAR(255),
    contact_phone       VARCHAR(50),
    itflow_client_id    VARCHAR(100),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -------------------------------------------------------------
-- agents
-- Client-scoped. One per VLAN segment. Decommission when done.
-- -------------------------------------------------------------
CREATE TABLE agents (
    agent_uuid          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_uuid         UUID NOT NULL REFERENCES clients(client_uuid) ON DELETE CASCADE,
    name                VARCHAR(255) NOT NULL,
    status              agent_status NOT NULL DEFAULT 'pending',
    api_token_hash      VARCHAR(255) NOT NULL,
    ip_address          INET,
    last_seen_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -------------------------------------------------------------
-- scan_jobs
-- A discrete discovery run. A client can have many over time.
-- -------------------------------------------------------------
CREATE TABLE scan_jobs (
    job_uuid            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_uuid         UUID NOT NULL REFERENCES clients(client_uuid) ON DELETE CASCADE,
    agent_uuid          UUID NOT NULL REFERENCES agents(agent_uuid) ON DELETE RESTRICT,
    status              job_status NOT NULL DEFAULT 'queued',
    scan_type           scan_type NOT NULL DEFAULT 'basic',
    target_subnets      JSONB NOT NULL DEFAULT '[]',
    dns_server          VARCHAR(45),
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -------------------------------------------------------------
-- assets
-- A discovered host or device.
-- -------------------------------------------------------------
CREATE TABLE assets (
    asset_uuid          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_uuid         UUID NOT NULL REFERENCES clients(client_uuid) ON DELETE CASCADE,
    job_uuid            UUID NOT NULL REFERENCES scan_jobs(job_uuid) ON DELETE RESTRICT,
    hostname            VARCHAR(255),
    asset_type          asset_type NOT NULL DEFAULT 'unknown',
    os_fingerprint      VARCHAR(255),
    snmp_description    TEXT,
    itflow_asset_id     VARCHAR(100),
    itflow_synced_at    TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -------------------------------------------------------------
-- interfaces
-- Network interfaces belonging to an asset.
-- MAC address is the deduplication anchor.
-- -------------------------------------------------------------
CREATE TABLE interfaces (
    interface_uuid      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_uuid          UUID NOT NULL REFERENCES assets(asset_uuid) ON DELETE CASCADE,
    client_uuid         UUID NOT NULL REFERENCES clients(client_uuid) ON DELETE CASCADE,
    mac_address         MACADDR NOT NULL,
    ipv4_address        INET,
    ipv6_address        INET,
    vlan_id             INTEGER,
    interface_name      VARCHAR(100),
    discovered_via      discovery_method NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================
-- INDEXES
-- =============================================================

-- clients
CREATE INDEX idx_clients_status ON clients(status);

-- agents
CREATE INDEX idx_agents_client_uuid ON agents(client_uuid);
CREATE INDEX idx_agents_status ON agents(status);

-- scan_jobs
CREATE INDEX idx_scan_jobs_client_uuid ON scan_jobs(client_uuid);
CREATE INDEX idx_scan_jobs_agent_uuid ON scan_jobs(agent_uuid);
CREATE INDEX idx_scan_jobs_status ON scan_jobs(status);

-- assets
CREATE INDEX idx_assets_client_uuid ON assets(client_uuid);
CREATE INDEX idx_assets_job_uuid ON assets(job_uuid);
CREATE INDEX idx_assets_itflow_synced ON assets(itflow_synced_at) WHERE itflow_synced_at IS NULL;

-- interfaces
CREATE INDEX idx_interfaces_asset_uuid ON interfaces(asset_uuid);
CREATE INDEX idx_interfaces_client_uuid ON interfaces(client_uuid);
CREATE INDEX idx_interfaces_mac_address ON interfaces(mac_address);
CREATE INDEX idx_interfaces_ipv4_address ON interfaces(ipv4_address);

-- =============================================================
-- AUTO-UPDATE updated_at TRIGGER
-- =============================================================

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_clients_updated_at
    BEFORE UPDATE ON clients
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_agents_updated_at
    BEFORE UPDATE ON agents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_scan_jobs_updated_at
    BEFORE UPDATE ON scan_jobs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_assets_updated_at
    BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_interfaces_updated_at
    BEFORE UPDATE ON interfaces
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
