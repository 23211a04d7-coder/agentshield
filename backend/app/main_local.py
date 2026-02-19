"""
Local dev entry point - uses in-memory MongoDB mock.
Run with: python3 -m uvicorn app.main_local:app --reload --port 8000
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.database_local import connect_db, close_db, get_db
from app.gateway_sniffer import (
    generate_mixed_traffic_batch,
    generate_c2_beacon,
    generate_dns_tunneling,
    generate_lateral_movement,
    generate_ransomware_spread,
    generate_port_scan,
    generate_brute_force,
    generate_data_exfiltration,
    ENDPOINT_IPS,
)
from app.detection import run_detection

# Monkey-patch database module so routes use the mock
import app.database as _db_module
import app.database_local as _local_db
_db_module.connect_db = _local_db.connect_db
_db_module.close_db = _local_db.close_db
_db_module.get_db = _local_db.get_db

from app.routes import logs, alerts


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    db = get_db()
    print("Seeding initial simulated traffic...")

    # --- Seed random mixed batches (background noise) ---
    for _ in range(3):
        batch = generate_mixed_traffic_batch(normal_count=8)
        await db.network_logs.insert_many(batch)
        detected = run_detection(batch)
        if detected:
            await db.alerts.insert_many(detected)

    # --- Guarantee one example of every threat type for PoC demo ---
    import random
    ips = ENDPOINT_IPS

    # C2 Beacon — Cobalt Strike callback simulation
    c2_logs = generate_c2_beacon(infected_ip="192.168.1.10", count=8)
    await db.network_logs.insert_many(c2_logs)
    await db.alerts.insert_many(run_detection(c2_logs))

    # DNS Tunneling — data exfil over DNS
    dns_logs = generate_dns_tunneling(infected_ip="192.168.1.11", count=25)
    await db.network_logs.insert_many(dns_logs)
    await db.alerts.insert_many(run_detection(dns_logs))

    # Lateral Movement — internal pivoting
    lat_logs = generate_lateral_movement(attacker_ip="192.168.1.20", count=7)
    await db.network_logs.insert_many(lat_logs)
    await db.alerts.insert_many(run_detection(lat_logs))

    # Ransomware Spread — WannaCry-style SMB propagation
    ransom_logs = generate_ransomware_spread(infected_ip="10.0.0.5")
    await db.network_logs.insert_many(ransom_logs)
    await db.alerts.insert_many(run_detection(ransom_logs))

    # Port Scan
    ps_logs = generate_port_scan(attacker_ip="192.168.1.12", count=15)
    await db.network_logs.insert_many(ps_logs)
    await db.alerts.insert_many(run_detection(ps_logs))

    # Brute Force — SSH attack
    bf_logs = generate_brute_force(attacker_ip="192.168.1.21", count=8)
    await db.network_logs.insert_many(bf_logs)
    await db.alerts.insert_many(run_detection(bf_logs))

    # Data Exfiltration
    exfil_logs = generate_data_exfiltration(source_ip="10.0.0.6", count=2)
    await db.network_logs.insert_many(exfil_logs)
    await db.alerts.insert_many(run_detection(exfil_logs))

    count = await db.alerts.count_documents({})
    print(f"Seeded {count} alerts into in-memory DB (all 7 threat types represented)")
    yield
    await close_db()


app = FastAPI(
    title="AgentShield - Local Dev",
    description="Agentless Endpoint Security Framework (local mode with in-memory DB)",
    version="1.0.0-local",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(logs.router, tags=["Telemetry"])
app.include_router(alerts.router, tags=["Detection"])


@app.get("/")
async def root():
    return {
        "system": "AgentShield - Agentless Endpoint Security Framework",
        "mode": "local-dev (in-memory MongoDB)",
        "agents_on_endpoints": False,
        "status": "operational",
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}
