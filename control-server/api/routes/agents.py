import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from core.config import get_settings
from core.database import get_db
from core.security import generate_agent_token, generate_install_command, hash_token, verify_token
from db.models import Agent, AgentStatus
from db.schemas import (
    AgentCreate,
    AgentHeartbeat,
    AgentPrepResponse,
    AgentRegistration,
    AgentResponse,
    AgentUpdate,
)

router = APIRouter()
settings = get_settings()


# =============================================================
# GET /api/agents
# =============================================================

@router.get(
    "/",
    response_model=List[AgentResponse],
    summary="List all agents",
)
def list_agents(
    client_uuid: uuid.UUID | None = None,
    status: AgentStatus | None = None,
    db: Session = Depends(get_db),
):
    """
    Returns all agents. Optionally filter by client or status.
    """
    query = db.query(Agent)

    if client_uuid:
        query = query.filter(Agent.client_uuid == client_uuid)
    if status:
        query = query.filter(Agent.status == status)

    return query.order_by(Agent.created_at.desc()).all()


# =============================================================
# POST /api/agents/prep/{client_uuid}
# =============================================================

@router.post(
    "/prep/{client_uuid}",
    response_model=AgentPrepResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Prep a new agent for a client",
)
def prep_agent(
    client_uuid: uuid.UUID,
    payload: AgentCreate,
    db: Session = Depends(get_db),
):
    """
    Creates a new agent record, generates a one-time API token,
    and returns the install command to paste on the target Linux box.

    The plain-text token is returned ONCE here and never stored.
    Only the hash is persisted in the database.
    """
    plain_token = generate_agent_token()

    agent = Agent(
        client_uuid=client_uuid,
        name=payload.name,
        status=AgentStatus.pending,
        api_token_hash=hash_token(plain_token),
    )
    db.add(agent)
    db.commit()

    return AgentPrepResponse(
        agent_uuid=agent.agent_uuid,
        name=agent.name,
        api_token=plain_token,
        install_command=generate_install_command(
            base_url=settings.firstlook_base_url,
            agent_uuid=str(agent.agent_uuid),
            plain_token=plain_token,
        ),
    )


# =============================================================
# POST /api/agents/register
# =============================================================

@router.post(
    "/register",
    response_model=AgentResponse,
    summary="Agent self-registration on first run",
)
def register_agent(
    payload: AgentRegistration,
    db: Session = Depends(get_db),
):
    """
    Called by the agent on first boot. Validates the token,
    records the agent's IP address, and sets status to active.
    """
    agent = db.query(Agent).filter(Agent.agent_uuid == payload.agent_uuid).first()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    if not verify_token(payload.api_token, agent.api_token_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    agent.status = AgentStatus.active
    agent.ip_address = payload.ip_address
    db.commit()

    return agent


# =============================================================
# POST /api/agents/{agent_uuid}/heartbeat
# =============================================================

@router.post(
    "/{agent_uuid}/heartbeat",
    response_model=AgentResponse,
    summary="Agent heartbeat — updates last seen timestamp",
)
def agent_heartbeat(
    agent_uuid: uuid.UUID,
    payload: AgentHeartbeat,
    db: Session = Depends(get_db),
):
    """
    Called periodically by the agent to signal it is alive.
    Updates last_seen_at and optionally refreshes the IP address.
    """
    from datetime import datetime, timezone, timedelta
    from db.models import ScanJob, JobStatus

    agent = _get_or_404(db, agent_uuid)

    agent.last_seen_at = datetime.now(timezone.utc)
    if payload.ip_address:
        agent.ip_address = payload.ip_address

    # Reset any jobs stuck in running state for this agent.
    # A job is considered stuck if it has been running for
    # more than 2 hours — covers even the longest deep scans.
    stuck_threshold = datetime.now(timezone.utc) - timedelta(hours=2)
    stuck_jobs = db.query(ScanJob).filter(
        ScanJob.agent_uuid == agent_uuid,
        ScanJob.status == JobStatus.running,
        ScanJob.started_at < stuck_threshold,
    ).all()

    if stuck_jobs:
        for job in stuck_jobs:
            print(f"[RECOVERY] Resetting stuck job {job.job_uuid} for agent {agent_uuid}")
            job.status = JobStatus.queued
            job.started_at = None


    db.commit()
    return agent


# =============================================================
# GET /api/agents/{agent_uuid}
# =============================================================

@router.get(
    "/{agent_uuid}",
    response_model=AgentResponse,
    summary="Get a single agent",
)
def get_agent(
    agent_uuid: uuid.UUID,
    db: Session = Depends(get_db),
):
    return _get_or_404(db, agent_uuid)


# =============================================================
# PATCH /api/agents/{agent_uuid}
# =============================================================

@router.patch(
    "/{agent_uuid}",
    response_model=AgentResponse,
    summary="Update an agent — rename or deactivate",
)
def update_agent(
    agent_uuid: uuid.UUID,
    payload: AgentUpdate,
    db: Session = Depends(get_db),
):
    agent = _get_or_404(db, agent_uuid)

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(agent, field, value)

    db.commit()
    return agent


# =============================================================
# DELETE /api/agents/{agent_uuid}
# =============================================================

@router.delete(
    "/{agent_uuid}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Decommission and delete an agent",
)
def delete_agent(
    agent_uuid: uuid.UUID,
    db: Session = Depends(get_db),
):
    """
    Removes the agent record. Scan jobs that reference this agent
    are protected by ON DELETE RESTRICT — decommission only agents
    with no associated scan history, or archive the client instead.
    """
    agent = _get_or_404(db, agent_uuid)

    try:
        db.delete(agent)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Agent has associated scan jobs and cannot be deleted. "
                   "Set status to inactive instead.",
        )


# =============================================================
# Helpers
# =============================================================

def _get_or_404(db: Session, agent_uuid: uuid.UUID) -> Agent:
    agent = db.query(Agent).filter(Agent.agent_uuid == agent_uuid).first()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_uuid} not found",
        )
    return agent
