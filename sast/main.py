import os
import shutil
import uuid
import logging
import subprocess
import json
from zipfile import ZipFile
from tarfile import open as TarOpen
from pathlib import Path

from fastapi import FastAPI, UploadFile, Form, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import redis

import scan_engine
import database

# --- Basic Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("app.main")

# Initialize Database
database.init_db()

app = FastAPI(title="VulnPrism SAST API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)
templates = Jinja2Templates(directory="templates")

# --- Redis Cache Connection ---
# Reads connection details from environment variables
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

# --- API Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
async def health_check():
    # Add DB and Redis health checks
    try:
        db_ok = database.engine and database.engine.connect() is not None
    except:
        db_ok = False

    redis_ok = redis_cache.ping() if redis_cache else False

    return {"status": "ok", "database": "ok" if db_ok else "disabled", "cache": "ok" if redis_ok else "disabled"}

@app.post("/scan")
async def scan_code(
    repo_url: str = Form(None),
    code_text: str = Form(None),
    file: UploadFile = None,
    db: Session = Depends(database.get_db)
):
    temp_id = str(uuid.uuid4())
    base_dir = os.path.join("/home/jenkins", temp_id)
    code_dir = os.path.join(base_dir, "source")

    # Determine the primary target for caching and logging
    target = repo_url or (file.filename if file else "pasted_code")
    if not target:
        raise HTTPException(400, "No input provided.")

    # Caching is more complex with PDF responses, so we disable it for now.

    try:
        os.makedirs(code_dir, exist_ok=True)

        # --- Input Handling ---
        if repo_url:
            logger.info("Cloning repo: %s", repo_url)
            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, code_dir],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode != 0:
                raise HTTPException(400, f"Git clone failed: {result.stderr}")
        elif code_text:
            with open(os.path.join(code_dir, "snippet.txt"), "w") as f:
                f.write(code_text)
        elif file:
            safe_filename = Path(file.filename).name
            upload_path = os.path.join(base_dir, safe_filename)
            with open(upload_path, "wb") as f:
                shutil.copyfileobj(file.file, f)
            # Handle archives
            if safe_filename.endswith(".zip"): ZipFile(upload_path, "r").extractall(code_dir)
            elif safe_filename.endswith(('.tar.gz', '.tgz', '.tar')): TarOpen(upload_path, "r:*").extractall(code_dir)
            else: shutil.move(upload_path, os.path.join(code_dir, safe_filename))

        # 2. Run Scan
        logger.info("Starting new scan for target: %s", target)
        summary, issues = scan_engine.run_full_scan(code_dir, temp_id)

        # 3. Store Results in Database (if available)
        if db and database.engine:
            try:
                new_scan = database.Scan(scan_id=temp_id, target=target)
                db.add(new_scan)
                db.commit()
                db.refresh(new_scan)

                for issue_data in issues:
                    vuln = database.Vulnerability(
                        **issue_data, # Unpack the dictionary
                        scan_id=new_scan.id
                    )
                    db.add(vuln)
                db.commit()
                logger.info("Successfully stored %d vulnerabilities in the database.", len(issues))
            except Exception as e:
                logger.warning("Failed to store results in database: %s", e)
        else:
            logger.info("Database not available, skipping result storage.")

        # 4. Generate PDF Report
        pdf_buffer = scan_engine.generate_pdf_report(target, summary, issues)
        
        return Response(content=pdf_buffer.getvalue(), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=VulnPrism_SAST_Report_{temp_id[:8]}.pdf"})

    except Exception as e:
        logger.error("Scan failed for target %s: %s", target, e, exc_info=True)
        raise HTTPException(500, f"Internal server error: {e}")
    finally:
        # Clean up temporary directory
        if os.path.exists(base_dir):
            shutil.rmtree(base_dir)