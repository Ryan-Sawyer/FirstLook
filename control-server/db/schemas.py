import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field

from .models import (
    AgentStatus,
    AssetType,
    ClientStatus,
    DiscoveryMethod,
    JobStatus,
    ScanType,
)


# =============================================================
# Base Config
# =============================================================

class BaseSchema(BaseModel):
    model_config = {"from_attributes": True}


# =============================================================
# Client Schemas
# =============================================================

class ClientCreate(BaseSchema):
    """Payload to create a new prospect/client."""
    name:           str             = Field(..., min_length=1, max_length=255)
    contact_name:   Optional[str]   = Field(None, max_length=255)
    contact_email:  Optional[EmailStr] = None
    contact_phone:  Optional[str]   = Field(None, max_length=50)


class ClientUpdate(BaseSchema):
    """Payload to update an existing client. All fields optional."""
    name:               Optional[str]       = Field(None, min_length=1, max_length=255)
    status:             Optional[ClientStatus] = None
    contact_name:       Optional[str]       = Field(None, max_length=255)
    contact_email:      Optional[EmailStr]  = None
    contact_phone:      Optional[str]       = Field(None, max_length=50)
    itflow_client_id:   Optional[str]       = Field(None, max_length=100)


class ClientResponse(BaseSchema):
    """Full client record returned from the API."""
    client_uuid:        uuid.UUID
    name:               str
    status:             ClientStatus
    contact_name:       Optional[str]
    contact_email:      Optional[str]
    contact_phone:      Optional[str]
    itflow_client_id:   Optional[str]
    created_at:         datetime
    updated_at:         datetime


class ClientSummary(BaseSchema):
    """Lightweight client record for list views."""
    client_uuid:    uuid.UUID
    name:           str
    status:         ClientStatus
    created_at:     datetime


# =============================================================
# Agent Schemas
# =============================================================

class AgentCreate(BaseSchema):
    """Payload to create (prep) a new agent for a client."""
    name: str = Field(..., min_length=1, max_length=255,
                      description="Friendly name e.g. 'VLAN10-Agent'")


class AgentUpdate(BaseSchema):
    """Payload to update an agent. All fields optional."""
    name:   Optional[str]           = Field(None, min_length=1, max_length=255)
    status: Optional[AgentStatus]   = None


class AgentRegistration(BaseSchema):
    """
    Payload sent by the agent on first-run registration.
    Includes the plain-text token issued at prep time.
    """
    agent_uuid: uuid.UUID
    api_token:  str     = Field(..., description="Plain-text token issued at prep — stored hashed server-side")
    ip_address: Optional[str] = None


class AgentHeartbeat(BaseSchema):
    """Payload sent by the agent on each heartbeat ping."""
    ip_address: Optional[str] = None


class AgentResponse(BaseSchema):
    """Full agent record returned from the API."""
    agent_uuid:     uuid.UUID
    client_uuid:    uuid.UUID
    name:           str
    status:         AgentStatus
    ip_address:     Optional[str]
    last_seen_at:   Optional[datetime]
    created_at:     datetime
    updated_at:     datetime


class AgentPrepResponse(BaseSchema):
    """
    Returned when an agent is first prepped.
    Includes the plain-text token — only shown once, never stored plain.
    """
    agent_uuid:     uuid.UUID
    name:           str
    api_token:      str     = Field(..., description="Show once and never again")
    install_command: str    = Field(..., description="One-liner install command for the agent")


# =============================================================
# Scan Job Schemas
# =============================================================

class ScanJobCreate(BaseSchema):
    """Payload to create and dispatch a new scan job."""
    agent_uuid:     uuid.UUID
    scan_type:      ScanType                = ScanType.basic
    target_subnets: List[str]               = Field(..., min_length=1,
                                                    description="List of CIDR ranges e.g. ['192.168.1.0/24']")


class ScanJobUpdate(BaseSchema):
    """Payload sent by the agent to update job status."""
    status:         Optional[JobStatus]     = None
    started_at:     Optional[datetime]      = None
    completed_at:   Optional[datetime]      = None


class ScanJobResponse(BaseSchema):
    """Full scan job record returned from the API."""
    job_uuid:       uuid.UUID
    client_uuid:    uuid.UUID
    agent_uuid:     uuid.UUID
    status:         JobStatus
    scan_type:      ScanType
    target_subnets: List[str]
    started_at:     Optional[datetime]
    completed_at:   Optional[datetime]
    created_at:     datetime
    updated_at:     datetime


class ScanJobSummary(BaseSchema):
    """Lightweight scan job record for list views."""
    job_uuid:       uuid.UUID
    status:         JobStatus
    scan_type:      ScanType
    started_at:     Optional[datetime]
    completed_at:   Optional[datetime]
    created_at:     datetime


# =============================================================
# Interface Schemas
# =============================================================

class InterfaceCreate(BaseSchema):
    """A single discovered interface — submitted as part of a scan result."""
    mac_address:    str             = Field(..., description="MAC address e.g. 'aa:bb:cc:dd:ee:ff'")
    ipv4_address:   Optional[str]   = None
    ipv6_address:   Optional[str]   = None
    vlan_id:        Optional[int]   = None
    interface_name: Optional[str]   = Field(None, max_length=100)
    discovered_via: DiscoveryMethod


class InterfaceResponse(BaseSchema):
    """Full interface record returned from the API."""
    interface_uuid: uuid.UUID
    asset_uuid:     uuid.UUID
    client_uuid:    uuid.UUID
    mac_address:    str
    ipv4_address:   Optional[str]
    ipv6_address:   Optional[str]
    vlan_id:        Optional[int]
    interface_name: Optional[str]
    discovered_via: DiscoveryMethod
    created_at:     datetime
    updated_at:     datetime


# =============================================================
# Asset Schemas
# =============================================================

class AssetCreate(BaseSchema):
    """
    A single discovered asset with its interfaces.
    Submitted by the agent as part of scan results.
    """
    hostname:           Optional[str]           = Field(None, max_length=255)
    asset_type:         AssetType               = AssetType.unknown
    os_fingerprint:     Optional[str]           = Field(None, max_length=255)
    snmp_description:   Optional[str]           = None
    interfaces:         List[InterfaceCreate]   = Field(default_factory=list)


class AssetUpdate(BaseSchema):
    """Payload to manually update an asset record."""
    hostname:           Optional[str]       = Field(None, max_length=255)
    asset_type:         Optional[AssetType] = None
    os_fingerprint:     Optional[str]       = Field(None, max_length=255)
    snmp_description:   Optional[str]       = None


class AssetResponse(BaseSchema):
    """Full asset record returned from the API, including interfaces."""
    asset_uuid:         uuid.UUID
    client_uuid:        uuid.UUID
    job_uuid:           uuid.UUID
    hostname:           Optional[str]
    asset_type:         AssetType
    os_fingerprint:     Optional[str]
    snmp_description:   Optional[str]
    itflow_asset_id:    Optional[str]
    itflow_synced_at:   Optional[datetime]
    interfaces:         List[InterfaceResponse] = []
    created_at:         datetime
    updated_at:         datetime


class AssetSummary(BaseSchema):
    """Lightweight asset record for list and results views."""
    asset_uuid:     uuid.UUID
    hostname:       Optional[str]
    asset_type:     AssetType
    itflow_synced_at: Optional[datetime]
    created_at:     datetime


# =============================================================
# Scan Results Schemas
# =============================================================

class ScanResultsSubmit(BaseSchema):
    """
    Full payload pushed by the agent when a scan job completes.
    Contains all discovered assets and their interfaces.
    """
    job_uuid:   uuid.UUID
    assets:     List[AssetCreate] = Field(default_factory=list)


class ScanResultsResponse(BaseSchema):
    """Summary returned after scan results are accepted."""
    job_uuid:           uuid.UUID
    assets_received:    int
    assets_created:     int
    assets_deduplicated: int


# =============================================================
# ITflow Sync Schemas
# =============================================================

class ITflowSyncResponse(BaseSchema):
    """Summary returned after an ITflow sync is triggered."""
    client_uuid:    uuid.UUID
    assets_synced:  int
    assets_failed:  int
    synced_at:      datetime
