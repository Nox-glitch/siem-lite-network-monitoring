"""
SIEM Lite - FastAPI Application Entry Point (Milestone 4)
Registers all routers, handles startup/shutdown, configures CORS.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from database.connection import create_tables
from api.routes import events, alerts, stats, rules, blocked_ips, network

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run DB migrations on startup."""
    logger.info("SIEM Lite API starting up...")
    await create_tables()
    logger.info("Database tables ready.")
    # Seed demo network devices on first boot
    try:
        from network.seeder import seed_devices
        import asyncio
        await asyncio.get_event_loop().run_in_executor(None, seed_devices)
    except Exception as e:
        logger.warning(f"Device seeder: {e}")
    yield
    logger.info("SIEM Lite API shutting down.")


app = FastAPI(
    title="SIEM Lite API",
    description="Security Information & Event Management — lightweight edition",
    version="1.0.0",
    lifespan=lifespan,
)

# Allow React dashboard (dev + prod) to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(events.router,      prefix="/api/events",      tags=["Events"])
app.include_router(alerts.router,      prefix="/api/alerts",      tags=["Alerts"])
app.include_router(stats.router,       prefix="/api/stats",       tags=["Stats"])
app.include_router(rules.router,       prefix="/api/rules",       tags=["Rules"])
app.include_router(blocked_ips.router, prefix="/api/blocked-ips", tags=["Blocked IPs"])
app.include_router(network.router,      prefix="/api/network",      tags=["Network"])


@app.get("/", tags=["Health"])
async def root():
    return {"status": "ok", "service": "SIEM Lite API", "version": "1.0.0"}


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy"}


@app.exception_handler(404)
async def not_found(request, exc):
    return JSONResponse(status_code=404, content={"detail": "Resource not found"})


@app.exception_handler(500)
async def server_error(request, exc):
    logger.exception("Unhandled server error")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
