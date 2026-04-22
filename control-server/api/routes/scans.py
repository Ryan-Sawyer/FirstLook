import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from core.database import get_db
from db.models import Agent, Asset, Interface, ScanJob, JobStatus
from db.schemas import (
    ScanJobCreate,
    ScanJobResponse,
    ScanJobSummary,
    ScanJobUpdate,
    ScanResultsSubmit,
    ScanResultsResponse,
)
from services.deduplication import deduplicate_assets

router = APIRouter()


# =============================================================
# GET /api/scans
# =============================================================

@router.get(
    "/",
    response_model=List[ScanJobSummary],
    summary="List scan jobs",
)
def list_scan_jobs(
    client_uuid: uuid.UUID | None = None,
    agent_uuid: uuid.UUID | None = None,
    status: JobStatus | None = None,
    db: Session = Depends(get_db),
):
    """
    Returns all scan jobs. Optionally filter by client, agent, or status.
    """
    query = db.query(ScanJob)

    if client_uuid:
        query = query.filter(ScanJob.client_uuid == client_uuid)
    if agent_uuid:
        query = query.filter(ScanJob.agent_uuid == agent_uuid)
    if status:
        query = query.filter(ScanJob.status == status)

    return query.order_by(ScanJob.created_at.desc()).all()

# =============================================================
# POST /api/scans/results
# =============================================================

@router.post(
    "/submit",
    response_model=ScanResultsResponse,
    summary="Submit scan results — called by the agent on job completion",
)
def submit_scan_results(
    payload: ScanResultsSubmit,
    db: Session = Depends(get_db),
):
    """
    The agent POSTs all discovered assets and interfaces here
    when a scan job completes.

    The deduplication service compares incoming MAC addresses
    against existing interface records for the client and avoids
    creating duplicate asset records across scan runs.
    """
    job = _get_job_or_404(db, payload.job_uuid)

    assets_created = 0
    assets_deduplicated = 0

    for asset_data in payload.assets:
        # Check each interface MAC against existing records for this client
        existing_uuid = deduplicate_assets(
            db=db,
            client_uuid=job.client_uuid,
            interfaces=asset_data.interfaces,
        )

    if existing_uuid:
        # Enrich existing asset with data from deeper scan
        existing = db.query(Asset).filter(
            Asset.asset_uuid == existing_uuid
        ).first()

        if existing:
            if asset_data.os_fingerprint:
                existing.os_fingerprint = asset_data.os_fingerprint
            if asset_data.snmp_description:
                existing.snmp_description = asset_data.snmp_description
            if asset_data.hostname and not existing.hostname:
                existing.hostname = asset_data.hostname
            if asset_data.asset_type.value != "unknown":
                existing.asset_type = asset_data.asset_type

        assets_deduplicated += 1
        continue
        # Create the asset
        asset = Asset(
            client_uuid=job.client_uuid,
            job_uuid=job.job_uuid,
            hostname=asset_data.hostname,
            asset_type=asset_data.asset_type,
            os_fingerprint=asset_data.os_fingerprint,
            snmp_description=asset_data.snmp_description,
        )
        db.add(asset)
        db.flush()  # Flush to get asset_uuid before creating interfaces

        # Create interfaces
        for iface_data in asset_data.interfaces:
            interface = Interface(
                asset_uuid=asset.asset_uuid,
                client_uuid=job.client_uuid,
                mac_address=iface_data.mac_address,
                ipv4_address=iface_data.ipv4_address,
                ipv6_address=iface_data.ipv6_address,
                vlan_id=iface_data.vlan_id,
                interface_name=iface_data.interface_name,
                discovered_via=iface_data.discovered_via,
            )
            db.add(interface)

        assets_created += 1

    # Mark the job complete
    from datetime import datetime, timezone
    job.status = JobStatus.complete
    job.completed_at = datetime.now(timezone.utc)

    db.commit()

    return ScanResultsResponse(
        job_uuid=job.job_uuid,
        assets_received=len(payload.assets),
        assets_created=assets_created,
        assets_deduplicated=assets_deduplicated,
    )

# =============================================================
# GET /api/scans/pending/{agent_uuid}
# =============================================================

@router.get(
    "/pending/{agent_uuid}",
    response_model=List[ScanJobResponse],
    summary="Get queued scan jobs for an agent — polled by the agent",
)
def get_pending_jobs(
    agent_uuid: uuid.UUID,
    db: Session = Depends(get_db),
):
    """
    The agent polls this endpoint to check for queued work.
    Returns all jobs in 'queued' status assigned to this agent.
    """
    return db.query(ScanJob).filter(
        ScanJob.agent_uuid == agent_uuid,
        ScanJob.status == JobStatus.queued,
    ).all()

# =============================================================
# POST /api/scans/{client_uuid}
# =============================================================

@router.post(
    "/{client_uuid}",
    response_model=ScanJobResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Dispatch a new scan job to an agent",
)
def create_scan_job(
    client_uuid: uuid.UUID,
    payload: ScanJobCreate,
    db: Session = Depends(get_db),
):
    """
    Creates a new scan job in 'queued' status.
    The agent polls for queued jobs and picks this up on its next cycle.
    """
    # Verify the agent exists and belongs to this client
    agent = db.query(Agent).filter(
        Agent.agent_uuid == payload.agent_uuid,
        Agent.client_uuid == client_uuid,
    ).first()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found for this client",
        )

    job = ScanJob(
        client_uuid=client_uuid,
        agent_uuid=payload.agent_uuid,
        scan_type=payload.scan_type,
        target_subnets=payload.target_subnets,
        status=JobStatus.queued,
    )
    db.add(job)
    db.commit()
    return job


# =============================================================
# GET /api/scans/job/{job_uuid}
# =============================================================

@router.get(
    "/job/{job_uuid}",
    response_model=ScanJobResponse,
    summary="Get a single scan job",
)
def get_scan_job(
    job_uuid: uuid.UUID,
    db: Session = Depends(get_db),
):
    return _get_job_or_404(db, job_uuid)


# =============================================================
# PATCH /api/scans/job/{job_uuid}
# =============================================================

@router.patch(
    "/job/{job_uuid}",
    response_model=ScanJobResponse,
    summary="Update scan job status — called by the agent",
)
def update_scan_job(
    job_uuid: uuid.UUID,
    payload: ScanJobUpdate,
    db: Session = Depends(get_db),
):
    """
    Used by the agent to move a job through its lifecycle:
    queued → running → complete | failed
    """
    job = _get_job_or_404(db, job_uuid)

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(job, field, value)

    db.commit()
    return job

# =============================================================
# Helpers
# =============================================================

def _get_job_or_404(db: Session, job_uuid: uuid.UUID) -> ScanJob:
    job = db.query(ScanJob).filter(ScanJob.job_uuid == job_uuid).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job {job_uuid} not found",
        )
    return job
