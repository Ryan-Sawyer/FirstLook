import enum
import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, MACADDR, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


# =============================================================
# Base
# =============================================================

class Base(DeclarativeBase):
    pass


# =============================================================
# Enums
# =============================================================

class ClientStatus(str, enum.Enum):
    prospect = "prospect"
    active   = "active"
    archived = "archived"

class AgentStatus(str, enum.Enum):
    pending  = "pending"
    active   = "active"
    inactive = "inactive"

class JobStatus(str, enum.Enum):
    queued   = "queued"
    running  = "running"
    complete = "complete"
    failed   = "failed"

class ScanType(str, enum.Enum):
    basic = "basic"
    deep  = "deep"

class AssetType(str, enum.Enum):
    server      = "server"
    workstation = "workstation"
    switch      = "switch"
    router      = "router"
    ap          = "ap"
    printer     = "printer"
    unknown     = "unknown"

class DiscoveryMethod(str, enum.Enum):
    nmap = "nmap"
    snmp = "snmp"
    lldp = "lldp"
    arp  = "arp"


# =============================================================
# Models
# =============================================================

class Client(Base):
    """
    A prospect or active client. Status changes as the
    relationship progresses — the UUID never changes.
    """
    __tablename__ = "clients"

    client_uuid:        Mapped[uuid.UUID]           = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name:               Mapped[str]                 = mapped_column(String(255), nullable=False)
    status:             Mapped[ClientStatus]        = mapped_column(Enum(ClientStatus, name="client_status"), nullable=False, default=ClientStatus.prospect)
    contact_name:       Mapped[Optional[str]]       = mapped_column(String(255))
    contact_email:      Mapped[Optional[str]]       = mapped_column(String(255))
    contact_phone:      Mapped[Optional[str]]       = mapped_column(String(50))
    itflow_client_id:   Mapped[Optional[str]]       = mapped_column(String(100))
    created_at:         Mapped[datetime]            = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at:         Mapped[datetime]            = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    agents:     Mapped[List["Agent"]]       = relationship("Agent",     back_populates="client", cascade="all, delete-orphan")
    scan_jobs:  Mapped[List["ScanJob"]]     = relationship("ScanJob",   back_populates="client", cascade="all, delete-orphan")
    assets:     Mapped[List["Asset"]]       = relationship("Asset",     back_populates="client", cascade="all, delete-orphan")
    interfaces: Mapped[List["Interface"]]   = relationship("Interface", back_populates="client", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_clients_status", "status"),
    )

    def __repr__(self) -> str:
        return f"<Client {self.name} ({self.status})>"


class Agent(Base):
    """
    A field agent deployed per VLAN segment.
    Client-scoped — decommission when the engagement is done.
    """
    __tablename__ = "agents"

    agent_uuid:     Mapped[uuid.UUID]           = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_uuid:    Mapped[uuid.UUID]           = mapped_column(UUID(as_uuid=True), ForeignKey("clients.client_uuid", ondelete="CASCADE"), nullable=False)
    name:           Mapped[str]                 = mapped_column(String(255), nullable=False)
    status:         Mapped[AgentStatus]         = mapped_column(Enum(AgentStatus, name="agent_status"), nullable=False, default=AgentStatus.pending)
    api_token_hash: Mapped[str]                 = mapped_column(String(255), nullable=False)
    ip_address:     Mapped[Optional[str]]       = mapped_column(INET)
    last_seen_at:   Mapped[Optional[datetime]]  = mapped_column(DateTime(timezone=True))
    created_at:     Mapped[datetime]            = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at:     Mapped[datetime]            = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    client:    Mapped["Client"]         = relationship("Client",  back_populates="agents")
    scan_jobs: Mapped[List["ScanJob"]]  = relationship("ScanJob", back_populates="agent")

    __table_args__ = (
        Index("idx_agents_client_uuid", "client_uuid"),
        Index("idx_agents_status",      "status"),
    )

    def __repr__(self) -> str:
        return f"<Agent {self.name} ({self.status})>"


class ScanJob(Base):
    """
    A discrete discovery run dispatched to an agent.
    A client can have many scan jobs over time.
    """
    __tablename__ = "scan_jobs"

    job_uuid:       Mapped[uuid.UUID]           = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_uuid:    Mapped[uuid.UUID]           = mapped_column(UUID(as_uuid=True), ForeignKey("clients.client_uuid", ondelete="CASCADE"), nullable=False)
    agent_uuid:     Mapped[uuid.UUID]           = mapped_column(UUID(as_uuid=True), ForeignKey("agents.agent_uuid", ondelete="RESTRICT"), nullable=False)
    status:         Mapped[JobStatus]           = mapped_column(Enum(JobStatus, name="job_status"), nullable=False, default=JobStatus.queued)
    scan_type:      Mapped[ScanType]            = mapped_column(Enum(ScanType, name="scan_type"), nullable=False, default=ScanType.basic)
    target_subnets: Mapped[dict]                = mapped_column(JSONB, nullable=False, default=list)
    started_at:     Mapped[Optional[datetime]]  = mapped_column(DateTime(timezone=True))
    completed_at:   Mapped[Optional[datetime]]  = mapped_column(DateTime(timezone=True))
    created_at:     Mapped[datetime]            = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at:     Mapped[datetime]            = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    dns_server:     Mapped[Optional[str]]       = mapped_column(String(45))

    # Relationships
    client: Mapped["Client"]        = relationship("Client",  back_populates="scan_jobs")
    agent:  Mapped["Agent"]         = relationship("Agent",   back_populates="scan_jobs")
    assets: Mapped[List["Asset"]]   = relationship("Asset",   back_populates="scan_job")

    __table_args__ = (
        Index("idx_scan_jobs_client_uuid", "client_uuid"),
        Index("idx_scan_jobs_agent_uuid",  "agent_uuid"),
        Index("idx_scan_jobs_status",      "status"),
    )

    def __repr__(self) -> str:
        return f"<ScanJob {self.job_uuid} ({self.status})>"


class Asset(Base):
    """
    A discovered host or device.
    job_uuid records which scan first found it.
    """
    __tablename__ = "assets"

    asset_uuid:         Mapped[uuid.UUID]           = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_uuid:        Mapped[uuid.UUID]           = mapped_column(UUID(as_uuid=True), ForeignKey("clients.client_uuid", ondelete="CASCADE"), nullable=False)
    job_uuid:           Mapped[uuid.UUID]           = mapped_column(UUID(as_uuid=True), ForeignKey("scan_jobs.job_uuid", ondelete="RESTRICT"), nullable=False)
    hostname:           Mapped[Optional[str]]       = mapped_column(String(255))
    asset_type:         Mapped[AssetType]           = mapped_column(Enum(AssetType, name="asset_type"), nullable=False, default=AssetType.unknown)
    os_fingerprint:     Mapped[Optional[str]]       = mapped_column(String(255))
    snmp_description:   Mapped[Optional[str]]       = mapped_column(Text)
    itflow_asset_id:    Mapped[Optional[str]]       = mapped_column(String(100))
    itflow_synced_at:   Mapped[Optional[datetime]]  = mapped_column(DateTime(timezone=True))
    created_at:         Mapped[datetime]            = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at:         Mapped[datetime]            = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    client:     Mapped["Client"]            = relationship("Client",    back_populates="assets")
    scan_job:   Mapped["ScanJob"]           = relationship("ScanJob",   back_populates="assets")
    interfaces: Mapped[List["Interface"]]   = relationship("Interface", back_populates="asset", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_assets_client_uuid", "client_uuid"),
        Index("idx_assets_job_uuid",    "job_uuid"),
        # Partial index — only unsynced assets, keeps ITflow sync queries fast
        Index("idx_assets_itflow_synced", "itflow_synced_at",
              postgresql_where=Column("itflow_synced_at").is_(None)),
    )

    def __repr__(self) -> str:
        return f"<Asset {self.hostname or 'unknown'} ({self.asset_type})>"


class Interface(Base):
    """
    A network interface belonging to an asset.
    MAC address is the deduplication anchor across scan runs.
    """
    __tablename__ = "interfaces"

    interface_uuid: Mapped[uuid.UUID]           = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_uuid:     Mapped[uuid.UUID]           = mapped_column(UUID(as_uuid=True), ForeignKey("assets.asset_uuid", ondelete="CASCADE"), nullable=False)
    client_uuid:    Mapped[uuid.UUID]           = mapped_column(UUID(as_uuid=True), ForeignKey("clients.client_uuid", ondelete="CASCADE"), nullable=False)
    mac_address:    Mapped[str]                 = mapped_column(MACADDR, nullable=False)
    ipv4_address:   Mapped[Optional[str]]       = mapped_column(INET)
    ipv6_address:   Mapped[Optional[str]]       = mapped_column(INET)
    vlan_id:        Mapped[Optional[int]]       = mapped_column(Integer)
    interface_name: Mapped[Optional[str]]       = mapped_column(String(100))
    discovered_via: Mapped[DiscoveryMethod]     = mapped_column(Enum(DiscoveryMethod, name="discovery_method"), nullable=False)
    created_at:     Mapped[datetime]            = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at:     Mapped[datetime]            = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    asset:  Mapped["Asset"]     = relationship("Asset",  back_populates="interfaces")
    client: Mapped["Client"]    = relationship("Client", back_populates="interfaces")

    __table_args__ = (
        Index("idx_interfaces_asset_uuid",   "asset_uuid"),
        Index("idx_interfaces_client_uuid",  "client_uuid"),
        Index("idx_interfaces_mac_address",  "mac_address"),
        Index("idx_interfaces_ipv4_address", "ipv4_address"),
    )

    def __repr__(self) -> str:
        return f"<Interface {self.mac_address} {self.ipv4_address}>"
