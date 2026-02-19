from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.database import get_db
from app.detection import run_detection
from app.gateway_sniffer import generate_mixed_traffic_batch

router = APIRouter()


@router.post("/logs", summary="Ingest network logs (or auto-generate a batch)")
async def ingest_logs(
    logs: Optional[List[dict]] = None,
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """
    POST /logs
    Accepts a JSON array of network log objects.
    If no body provided, auto-generates a simulated batch from the gateway sniffer.
    Runs detection engine and stores both logs and alerts.
    """
    if not logs:
        logs = generate_mixed_traffic_batch()

    if not logs:
        raise HTTPException(status_code=400, detail="No logs provided")

    # Store logs
    result = await db.network_logs.insert_many(logs)
    inserted_count = len(result.inserted_ids)

    # Run detection engine
    alerts = run_detection(logs)
    alert_count = 0
    if alerts:
        await db.alerts.insert_many(alerts)
        alert_count = len(alerts)

    return {
        "message": "Logs ingested and analyzed",
        "logs_stored": inserted_count,
        "alerts_generated": alert_count,
        "alerts": alerts,
    }


@router.get("/logs", summary="Get recent network logs")
async def get_logs(
    limit: int = 100,
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    cursor = db.network_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
    logs = await cursor.to_list(length=limit)
    return {"logs": logs, "count": len(logs)}
