import os
import shutil
import uuid
import logging
import subprocess
import json
import time
import traceback
from zipfile import ZipFile
from tarfile import open as TarOpen
from pathlib import Path

from fastapi import FastAPI, UploadFile, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

import scan_engine

# --- Basic Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("app.main")

app = FastAPI(title="VulnPrism SAST API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)
templates = Jinja2Templates(directory="templates")

# Stateless operation - no database or cache dependencies
logger.info("🚀 SAST service running in stateless mode - no database or cache dependencies")

# --- API Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
async def health_check():
    """Stateless health check - only checks service availability"""
    return {"status": "ok", "mode": "stateless", "service": "sast"}

@app.post("/scan")
async def scan_code(
    repo_url: str = Form(None),
    code_text: str = Form(None),
    file: UploadFile = None
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
        scan_start_time = time.time()
        logger.info(f"🚀 Starting comprehensive SAST scan for target: {target} at {time.strftime('%Y-%m-%d %H:%M:%S')}")

        try:
            summary, issues = scan_engine.run_full_scan(code_dir, temp_id)
            scan_duration = time.time() - scan_start_time
            logger.info(f"✅ SAST scan completed in {scan_duration:.2f} seconds - Found {len(issues)} issues")
        except Exception as scan_error:
            scan_duration = time.time() - scan_start_time
            logger.error(f"❌ SAST scan failed after {scan_duration:.2f} seconds: {str(scan_error)}")
            logger.error(f"📍 SAST scan error traceback: {traceback.format_exc()}")
            # Create a minimal report even if scan fails
            summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            issues = [{"rule": "scan-error", "desc": f"Scan failed: {str(scan_error)}", "impact": "N/A", "fix": "Check logs for details", "severity": "High"}]

        # Stateless operation - no database storage needed
        logger.info("📊 Scan completed - proceeding to PDF generation")

        # 4. Generate PDF Report
        pdf_start_time = time.time()
        logger.info(f"📄 Starting PDF report generation for {len(issues)} issues")

        try:
            pdf_buffer = scan_engine.generate_pdf_report(target, summary, issues)
            pdf_duration = time.time() - pdf_start_time
            logger.info(f"✅ PDF report generated successfully in {pdf_duration:.2f} seconds")
            return Response(content=pdf_buffer.getvalue(), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=VulnPrism_SAST_Report_{temp_id[:8]}.pdf"})
        except Exception as pdf_error:
            pdf_duration = time.time() - pdf_start_time
            logger.error(f"❌ PDF generation failed after {pdf_duration:.2f} seconds: {str(pdf_error)}")
            logger.error(f"📍 PDF error traceback: {traceback.format_exc()}")
            # Return JSON response as fallback
            logger.info("📋 Returning JSON fallback response")
            return {"target": target, "summary": summary, "issues": issues, "error": "PDF generation failed, returning JSON", "scan_duration": f"{time.time() - scan_start_time:.2f}s"}

    except Exception as e:
        logger.error("Scan failed for target %s: %s", target, e, exc_info=True)
        raise HTTPException(500, f"Internal server error: {e}")
    finally:
        # Clean up temporary directory
        if os.path.exists(base_dir):
            shutil.rmtree(base_dir)