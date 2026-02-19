"""
Agentless Endpoint Security Framework - FastAPI Backend
========================================================
Gateway-based monitoring: all telemetry captured at network level.
No agents installed on endpoints.
"""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.database import connect_db, close_db, get_db
from app.routes import logs, alerts

# In production set ALLOWED_ORIGINS to your Vercel URL, e.g.:
#   ALLOWED_ORIGINS=https://agentshield.vercel.app
_raw_origins = os.getenv("ALLOWED_ORIGINS", "*")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",")] if _raw_origins != "*" else ["*"]


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()


app = FastAPI(
    title="Agentless Endpoint Security Framework",
    description=(
        "Gateway-based security monitoring system. "
        "Detects threats without installing agents on endpoints."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(logs.router, tags=["Telemetry"])
app.include_router(alerts.router, tags=["Detection"])


@app.get("/", tags=["Health"])
async def root():
    return {
        "system": "Agentless Endpoint Security Framework",
        "version": "1.0.0",
        "architecture": "Gateway-Based Monitoring",
        "agents_on_endpoints": False,
        "status": "operational",
    }


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy"}
