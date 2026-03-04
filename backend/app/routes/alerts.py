from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.database import get_db
from datetime import datetime, timezone, timedelta

router = APIRouter()


@router.get("/alerts", summary="Get all alerts")
async def get_alerts(
    limit: int = 200,
    severity: str = None,
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """GET /alerts — Returns stored security alerts, optionally filtered by severity."""
    query = {}
    if severity:
        query["severity"] = severity.upper()

    cursor = db.alerts.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit)
    alerts = await cursor.to_list(length=limit)
    return {"alerts": alerts, "count": len(alerts)}


@router.get("/stats", summary="Get dashboard statistics")
async def get_stats(db: AsyncIOMotorDatabase = Depends(get_db)):
    """GET /stats — Returns aggregate statistics for the dashboard."""
    total_logs = await db.network_logs.count_documents({})
    total_alerts = await db.alerts.count_documents({})

    high_alerts = await db.alerts.count_documents({"severity": "HIGH"})
    medium_alerts = await db.alerts.count_documents({"severity": "MEDIUM"})
    low_alerts = await db.alerts.count_documents({"severity": "LOW"})
    critical_alerts = await db.alerts.count_documents({"severity": "CRITICAL"})

    # Threat type breakdown
    pipeline = [
        {"$group": {"_id": "$threat_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    threat_cursor = db.alerts.aggregate(pipeline)
    threat_breakdown = {}
    async for doc in threat_cursor:
        threat_breakdown[doc["_id"]] = doc["count"]

    # Recent alerts (last 24h)
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    recent_alerts = await db.alerts.count_documents({"timestamp": {"$gte": since}})

    # Timeline: alerts per hour for last 12 hours
    timeline = []
    now = datetime.now(timezone.utc)
    for i in range(11, -1, -1):
        hour_start = (now - timedelta(hours=i + 1)).isoformat()
        hour_end = (now - timedelta(hours=i)).isoformat()
        count = await db.alerts.count_documents({
            "timestamp": {"$gte": hour_start, "$lt": hour_end}
        })
        label = (now - timedelta(hours=i)).strftime("%H:00")
        timeline.append({"hour": label, "alerts": count})

    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "active_threats": critical_alerts + high_alerts + medium_alerts,
        "severity_breakdown": {
            "CRITICAL": critical_alerts,
            "HIGH": high_alerts,
            "MEDIUM": medium_alerts,
            "LOW": low_alerts,
        },
        "threat_breakdown": threat_breakdown,
        "recent_alerts_24h": recent_alerts,
        "timeline": timeline,
    }


@router.get("/risk-score", summary="Get current system risk score")
async def get_risk_score(db: AsyncIOMotorDatabase = Depends(get_db)):
    """GET /risk-score — Computes an aggregate risk score (0-100) for the system."""
    # Weighted average of recent alert risk scores
    since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    pipeline = [
        {"$match": {"timestamp": {"$gte": since}}},
        {"$group": {
            "_id": None,
            "avg_risk": {"$avg": "$risk_score"},
            "max_risk": {"$max": "$risk_score"},
            "count": {"$sum": 1},
        }},
    ]
    result = None
    async for doc in db.alerts.aggregate(pipeline):
        result = doc

    if not result:
        # Check all-time
        pipeline2 = [
            {"$group": {
                "_id": None,
                "avg_risk": {"$avg": "$risk_score"},
                "max_risk": {"$max": "$risk_score"},
                "count": {"$sum": 1},
            }},
        ]
        async for doc in db.alerts.aggregate(pipeline2):
            result = doc

    if not result:
        return {"risk_score": 0, "level": "SAFE", "alert_count": 0}

    avg = result.get("avg_risk", 0) or 0
    max_r = result.get("max_risk", 0) or 0
    count = result.get("count", 0)

    # Composite score: weighted blend of avg and max
    composite = int(avg * 0.6 + max_r * 0.4)
    composite = min(100, composite)

    if composite >= 75:
        level = "CRITICAL"
    elif composite >= 50:
        level = "HIGH"
    elif composite >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk_score": composite,
        "level": level,
        "alert_count": count,
        "avg_risk": round(avg, 1),
        "max_risk": max_r,
    }


@router.post("/alerts/{alert_id}/block", summary="Block a threat alert")
async def block_alert(
    alert_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """POST /alerts/{alert_id}/block — Marks a specific alert as blocked/contained."""
    from datetime import datetime, timezone
    blocked_at = datetime.now(timezone.utc).isoformat()

    result = await db.alerts.find_one_and_update(
        {"alert_id": alert_id},
        {"$set": {"status": "blocked", "blocked_at": blocked_at}},
        return_document=True,
    )
    if result is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    # Strip MongoDB _id before returning
    result.pop("_id", None)
    return {"message": "Threat blocked successfully", "alert": result}
