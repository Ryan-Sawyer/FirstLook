import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from core.database import get_db
from core.security import generate_agent_token, generate_install_command, hash_token
from core.config import get_settings
from db.models import Agent, AgentStatus, Asset, Client, ClientStatus, ScanJob, JobStatus, ScanType
from db.schemas import ScanJobCreate

settings = get_settings()
router = APIRouter()
templates = Jinja2Templates(directory="web/templates")


# =============================================================
# Dashboard — redirect to leads list
# =============================================================

@router.get("/", response_class=RedirectResponse)
def root():
    return RedirectResponse(url="/leads")


# =============================================================
# Leads
# =============================================================

@router.get("/leads", response_class=HTMLResponse)
def leads_index(request: Request, db: Session = Depends(get_db)):
    clients = db.query(Client).order_by(Client.created_at.desc()).all()
    return templates.TemplateResponse("leads/index.html", {
        "request": request,
        "clients": clients,
    })


@router.get("/leads/create", response_class=HTMLResponse)
def leads_create_form(request: Request):
    return templates.TemplateResponse("leads/create.html", {
        "request": request,
    })


@router.post("/leads/create", response_class=RedirectResponse)
def leads_create_submit(
    request: Request,
    name: str = Form(...),
    contact_name: str = Form(""),
    contact_email: str = Form(""),
    contact_phone: str = Form(""),
    db: Session = Depends(get_db),
):
    client = Client(
        name=name,
        contact_name=contact_name or None,
        contact_email=contact_email or None,
        contact_phone=contact_phone or None,
        status=ClientStatus.prospect,
    )
    db.add(client)
    db.commit()
    return RedirectResponse(url=f"/leads/{client.client_uuid}", status_code=303)


@router.get("/leads/{client_uuid}", response_class=HTMLResponse)
def leads_detail(request: Request, client_uuid: uuid.UUID, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.client_uuid == client_uuid).first()
    agents = db.query(Agent).filter(Agent.client_uuid == client_uuid).order_by(Agent.created_at.desc()).all()
    scan_jobs = db.query(ScanJob).filter(ScanJob.client_uuid == client_uuid).order_by(ScanJob.created_at.desc()).all()
    return templates.TemplateResponse("leads/detail.html", {
        "request": request,
        "client": client,
        "agents": agents,
        "scan_jobs": scan_jobs,
        "client_statuses": ClientStatus,
    })


@router.post("/leads/{client_uuid}/status", response_class=RedirectResponse)
def leads_update_status(
    client_uuid: uuid.UUID,
    status: str = Form(...),
    db: Session = Depends(get_db),
):
    client = db.query(Client).filter(Client.client_uuid == client_uuid).first()
    client.status = ClientStatus(status)
    db.commit()
    return RedirectResponse(url=f"/leads/{client_uuid}", status_code=303)


# =============================================================
# Agents
# =============================================================

@router.get("/agents", response_class=HTMLResponse)
def agents_index(request: Request, db: Session = Depends(get_db)):
    agents = db.query(Agent).order_by(Agent.created_at.desc()).all()
    return templates.TemplateResponse("agents/index.html", {
        "request": request,
        "agents": agents,
    })


@router.get("/agents/prep/{client_uuid}", response_class=HTMLResponse)
def agents_prep_form(request: Request, client_uuid: uuid.UUID, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.client_uuid == client_uuid).first()
    return templates.TemplateResponse("agents/prep.html", {
        "request": request,
        "client": client,
    })


@router.post("/agents/prep/{client_uuid}", response_class=HTMLResponse)
def agents_prep_submit(
    request: Request,
    client_uuid: uuid.UUID,
    name: str = Form(...),
    db: Session = Depends(get_db),
):
    plain_token = generate_agent_token()
    client = db.query(Client).filter(Client.client_uuid == client_uuid).first()

    agent = Agent(
        client_uuid=client_uuid,
        name=name,
        status=AgentStatus.pending,
        api_token_hash=hash_token(plain_token),
    )
    db.add(agent)
    db.commit()

    install_command = generate_install_command(
        base_url=settings.firstlook_base_url,
        agent_uuid=str(agent.agent_uuid),
        plain_token=plain_token,
    )

    return templates.TemplateResponse("agents/prep.html", {
        "request": request,
        "client": client,
        "agent": agent,
        "plain_token": plain_token,
        "install_command": install_command,
        "show_token": True,
    })


@router.post("/agents/{agent_uuid}/decommission", response_class=RedirectResponse)
def agents_decommission(
    agent_uuid: uuid.UUID,
    db: Session = Depends(get_db),
):
    agent = db.query(Agent).filter(Agent.agent_uuid == agent_uuid).first()
    client_uuid = agent.client_uuid
    agent.status = AgentStatus.inactive
    db.commit()
    return RedirectResponse(url=f"/leads/{client_uuid}", status_code=303)


# =============================================================
# Scans
# =============================================================

@router.get("/scans/{client_uuid}/new", response_class=HTMLResponse)
def scans_new_form(request: Request, client_uuid: uuid.UUID, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.client_uuid == client_uuid).first()
    agents = db.query(Agent).filter(
        Agent.client_uuid == client_uuid,
        Agent.status == AgentStatus.active,
    ).all()
    return templates.TemplateResponse("scans/new.html", {
        "request": request,
        "client": client,
        "agents": agents,
        "scan_types": ScanType,
    })


@router.post("/scans/{client_uuid}/new", response_class=RedirectResponse)
def scans_new_submit(
    client_uuid: uuid.UUID,
    agent_uuid: str = Form(...),
    scan_type: str = Form(...),
    target_subnets: str = Form(...),
    db: Session = Depends(get_db),
):
    # Parse subnets — one per line
    subnets = [s.strip() for s in target_subnets.splitlines() if s.strip()]

    job = ScanJob(
        client_uuid=client_uuid,
        agent_uuid=uuid.UUID(agent_uuid),
        scan_type=ScanType(scan_type),
        target_subnets=subnets,
        status=JobStatus.queued,
    )
    db.add(job)
    db.commit()
    return RedirectResponse(url=f"/scans/{job.job_uuid}/results", status_code=303)


@router.get("/scans/{job_uuid}/results", response_class=HTMLResponse)
def scans_results(request: Request, job_uuid: uuid.UUID, db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.job_uuid == job_uuid).first()
    assets = db.query(Asset).filter(Asset.job_uuid == job_uuid).all()
    client = db.query(Client).filter(Client.client_uuid == job.client_uuid).first()
    return templates.TemplateResponse("scans/results.html", {
        "request": request,
        "job": job,
        "assets": assets,
        "client": client,
    })


@router.get("/scans/{job_uuid}/deeper", response_class=HTMLResponse)
def scans_deeper(request: Request, job_uuid: uuid.UUID, db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.job_uuid == job_uuid).first()
    assets = db.query(Asset).filter(Asset.job_uuid == job_uuid).all()
    client = db.query(Client).filter(Client.client_uuid == job.client_uuid).first()
    active_agents = db.query(Agent).filter(
        Agent.client_uuid == job.client_uuid,
        Agent.status == AgentStatus.active,
    ).all()
    return templates.TemplateResponse("scans/deeper.html", {
        "request": request,
        "job": job,
        "assets": assets,
        "client": client,
        "active_agents": active_agents,
    })
