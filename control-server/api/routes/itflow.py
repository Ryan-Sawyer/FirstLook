import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from core.database import get_db
from db.models import Asset, Client
from db.schemas import ITflowSyncResponse
from services.itflow_client import ITflowClient, ITflowNotConfiguredError

router = APIRouter()


# =============================================================
# POST /api/itflow/sync/{client_uuid}
# =============================================================

@router.post(
    "/sync/{client_uuid}",
    response_model=ITflowSyncResponse,
    summary="Push unsynced assets to ITflow for a client",
)
def sync_client_to_itflow(
    client_uuid: uuid.UUID,
    db: Session = Depends(get_db),
):
    """
    Finds all assets for the client that have not yet been
    pushed to ITflow (itflow_synced_at IS NULL) and syncs them.

    Requires ITFLOW_URL and ITFLOW_API_KEY to be configured.
    """
    # Verify client exists
    client = db.query(Client).filter(Client.client_uuid == client_uuid).first()
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client {client_uuid} not found",
        )

    # Initialise the ITflow client — raises if not configured
    try:
        itflow = ITflowClient()
    except ITflowNotConfiguredError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ITflow integration is not configured. "
                   "Set ITFLOW_URL and ITFLOW_API_KEY in your .env file.",
        )

    # Fetch unsynced assets for this client
    unsynced_assets = db.query(Asset).filter(
        Asset.client_uuid == client_uuid,
        Asset.itflow_synced_at.is_(None),
    ).all()

    if not unsynced_assets:
        return ITflowSyncResponse(
            client_uuid=client_uuid,
            assets_synced=0,
            assets_failed=0,
            synced_at=datetime.now(timezone.utc),
        )

    # Ensure the client exists in ITflow — create if not
    if not client.itflow_client_id:
        itflow_client_id = itflow.get_or_create_client(client)
        client.itflow_client_id = itflow_client_id
        db.flush()

    # Sync each asset
    assets_synced = 0
    assets_failed = 0

    for asset in unsynced_assets:
        try:
            itflow_asset_id = itflow.push_asset(
                itflow_client_id=client.itflow_client_id,
                asset=asset,
            )
            asset.itflow_asset_id = itflow_asset_id
            asset.itflow_synced_at = datetime.now(timezone.utc)
            assets_synced += 1
        except Exception:
            # Log and continue — don't let one failed asset abort the batch
            assets_failed += 1
            continue

    db.commit()

    return ITflowSyncResponse(
        client_uuid=client_uuid,
        assets_synced=assets_synced,
        assets_failed=assets_failed,
        synced_at=datetime.now(timezone.utc),
    )


# =============================================================
# GET /api/itflow/status/{client_uuid}
# =============================================================

@router.get(
    "/status/{client_uuid}",
    summary="Get ITflow sync status for a client",
)
def get_sync_status(
    client_uuid: uuid.UUID,
    db: Session = Depends(get_db),
):
    """
    Returns a summary of synced vs unsynced assets for the client.
    Useful for the web UI sync status indicator.
    """
    total = db.query(Asset).filter(Asset.client_uuid == client_uuid).count()
    synced = db.query(Asset).filter(
        Asset.client_uuid == client_uuid,
        Asset.itflow_synced_at.isnot(None),
    ).count()

    return {
        "client_uuid":  client_uuid,
        "total_assets": total,
        "synced":       synced,
        "unsynced":     total - synced,
    }
