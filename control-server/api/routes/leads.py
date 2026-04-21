import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from core.database import get_db
from db.models import Client, ClientStatus
from db.schemas import (
    ClientCreate,
    ClientResponse,
    ClientSummary,
    ClientUpdate,
)

router = APIRouter()


# =============================================================
# GET /api/clients
# =============================================================

@router.get(
    "/",
    response_model=List[ClientSummary],
    summary="List all clients and prospects",
)
def list_clients(
    status: ClientStatus | None = None,
    db: Session = Depends(get_db),
):
    """
    Returns all clients. Optionally filter by status:
    - prospect
    - active
    - archived
    """
    query = db.query(Client)

    if status:
        query = query.filter(Client.status == status)

    return query.order_by(Client.created_at.desc()).all()


# =============================================================
# POST /api/clients
# =============================================================

@router.post(
    "/",
    response_model=ClientResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new prospect",
)
def create_client(
    payload: ClientCreate,
    db: Session = Depends(get_db),
):
    """
    Creates a new prospect. Status defaults to 'prospect'.
    The client UUID never changes — status is updated as
    the relationship progresses.
    """
    client = Client(**payload.model_dump())
    db.add(client)
    db.commit()
    return client


# =============================================================
# GET /api/clients/{client_uuid}
# =============================================================

@router.get(
    "/{client_uuid}",
    response_model=ClientResponse,
    summary="Get a single client",
)
def get_client(
    client_uuid: uuid.UUID,
    db: Session = Depends(get_db),
):
    client = _get_or_404(db, client_uuid)
    return client


# =============================================================
# PATCH /api/clients/{client_uuid}
# =============================================================

@router.patch(
    "/{client_uuid}",
    response_model=ClientResponse,
    summary="Update a client — including promoting prospect to active",
)
def update_client(
    client_uuid: uuid.UUID,
    payload: ClientUpdate,
    db: Session = Depends(get_db),
):
    """
    Partial update. Only supplied fields are changed.
    Use this to update status from prospect → active → archived.
    """
    client = _get_or_404(db, client_uuid)

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(client, field, value)

    db.commit()
    return client


# =============================================================
# DELETE /api/clients/{client_uuid}
# =============================================================

@router.delete(
    "/{client_uuid}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a client and all associated data",
)
def delete_client(
    client_uuid: uuid.UUID,
    db: Session = Depends(get_db),
):
    """
    Deletes the client and cascades to all associated agents,
    scan jobs, assets, and interfaces.
    This action is irreversible — consider archiving instead.
    """
    client = _get_or_404(db, client_uuid)
    db.delete(client)
    db.commit()


# =============================================================
# Helpers
# =============================================================

def _get_or_404(db: Session, client_uuid: uuid.UUID) -> Client:
    client = db.query(Client).filter(Client.client_uuid == client_uuid).first()
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client {client_uuid} not found",
        )
    return client
