from fastapi import FastAPI, Query, BackgroundTasks, HTTPException, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import uuid
import os
import json
import httpx
from app.aggressive_scanner.scanner import perform_scan, ScanResult
from loguru import logger
import sys
from sqlalchemy.orm import Session
import redis

from . import database

# Load environment variables
load_dotenv()

# Enhanced Configure logging
logger.remove()
logger.add(
    sys.stderr,
    level="DEBUG",
    format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
)
# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)
logger.add(
    "logs/cyberscythe.log",
    rotation="100 MB",
    retention="7 days",
    level="DEBUG",
    encoding="utf-8"
)

# Initialize Database
database.init_db()

app = FastAPI(
    title="CyberScythe",
    description="Aggressive Smart Vulnerability Scanner",
    version="5.0.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Redis Cache Connection ---
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
CACHE_EXPIRATION_SECONDS = 3600  # 1 hour

try:
    redis_cache = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
    redis_cache.ping() # Check connection
    logger.info("Successfully connected to Redis cache.")
except redis.exceptions.ConnectionError as e:
    logger.error("Failed to connect to Redis: %s. Caching will be disabled.", e)
    redis_cache = None

# Mount static directory
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def root():
    """Serve the main CyberScythe interface directly (SAST-style approach)"""
    logger.info("🌐 Root endpoint accessed - serving index.html directly")
    try:
        return FileResponse("static/index.html")
    except Exception as e:
        logger.error(f"Error serving index.html: {e}")
        return RedirectResponse("/static/index.html")

@app.get("/health")
def health_check():
    try:
        db_ok = database.engine and database.engine.connect() is not None
    except:
        db_ok = False

    try:
        redis_ok = redis_cache.ping() if redis_cache else False
    except:
        redis_ok = False

    return {"status": "ok", "database": "ok" if db_ok else "disabled", "cache": "ok" if redis_ok else "disabled"}

class ScanRequest(BaseModel):
    url: str

@app.post("/scan")
async def scan(request: ScanRequest, db: Session = Depends(database.get_db)):
    scan_id = str(uuid.uuid4())
    url = request.url

    if not url or not url.strip() or not url.startswith(('http://', 'https://')):
        raise HTTPException(400, "A valid URL is required.")

    # 1. Check Cache
    if redis_cache:
        cached_result = redis_cache.get(url)
        if cached_result:
            logger.info("Returning cached result for target: %s", url)
            return json.loads(cached_result)

    try:
        # 2. Run Scan
        logger.info("Starting new scan for target: %s", url)
        findings: ScanResult = await perform_scan(url)

        # 3. Store in Database (if available)
        if db and database.engine:
            try:
                new_scan = database.Scan(scan_id=scan_id, target=url)
                db.add(new_scan)
                db.commit()
                db.refresh(new_scan)

                for vuln_data in findings.vulnerabilities:
                    vuln = database.Vulnerability(
                        **vuln_data,
                        scan_id=new_scan.id
                    )
                    db.add(vuln)
                db.commit()
                logger.info("Successfully stored %d vulnerabilities in the database.", len(findings.vulnerabilities))
            except Exception as e:
                logger.warning("Failed to store results in database: %s", e)
        else:
            logger.info("Database not available, skipping result storage.")

        response_data = findings.to_dict()

        # 4. Update Cache
        if redis_cache:
            redis_cache.set(url, json.dumps(response_data), ex=CACHE_EXPIRATION_SECONDS)
            logger.info("Result for target '%s' cached.", url)

        return response_data

    except Exception as e:
        logger.error("Scan failed for target %s: %s", url, e, exc_info=True)
        raise HTTPException(500, f"Internal server error: {e}")