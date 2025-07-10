import os
import logging
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
from core.database import init_db, SessionLocal, Scan, Vulnerability
from config import APP_TITLE, REPORTS_DIR, LOG_LEVEL
from celery_app import celery_app, run_scan_task

# --- Configuration ---
logging.basicConfig(level=getattr(logging, LOG_LEVEL.upper()), format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title=APP_TITLE)
templates = Jinja2Templates(directory="templates")

# --- Database Initialization ---
@app.on_event("startup")
def on_startup():
    """Initializes the database when the application starts."""
    logger.info("Initializing database...")
    init_db()
    os.makedirs(REPORTS_DIR, exist_ok=True)
    logger.info("Database and report directory initialized.")

# --- Routes ---
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serves the main HTML page."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan", status_code=202)
async def start_scan_endpoint(url: str = Form(...)):
    """
    Initiates a scan on the given URL.
    This endpoint returns immediately with a scan ID.
    """
    if not url.startswith("http"):
        raise HTTPException(status_code=400, detail="Invalid URL. Must start with http:// or https://")

    db = SessionLocal()
    try:
        # Create a new scan record in the database
        new_scan = Scan(target_url=url, status="pending")
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)
        
        scan_id = new_scan.id
        logger.info(f"[{scan_id}] Scan queued for URL: {url}")

        # Send the scan task to Celery
        run_scan_task.delay(scan_id, url)
        
        return {"message": "Scan initiated successfully.", "scan_id": scan_id}
    
    except Exception as e:
        logger.error(f"Failed to initiate scan for {url}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to initiate scan.")
    finally:
        db.close()

@app.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: int):
    """Checks the status of a scan."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")
        
        response = {"scan_id": scan.id, "status": scan.status, "target": scan.target_url}
        if scan.status == "completed":
            response["report_url"] = f"/reports/{scan.id}"
        return JSONResponse(content=response)
    finally:
        db.close()

@app.get("/reports/{scan_id}")
async def get_report(scan_id: int):
    """Downloads the PDF report for a completed scan."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")
        if scan.status != "completed":
            raise HTTPException(status_code=400, detail=f"Scan is not complete. Current status: {scan.status}")
        
        report_path = scan.report_path
        if not os.path.exists(report_path):
            logger.error(f"Report file not found for scan {scan_id} at {report_path}")
            raise HTTPException(status_code=404, detail="Report file not found.")

        return FileResponse(
            report_path,
            filename=os.path.basename(report_path),
            media_type="application/pdf"
        )
    finally:
        db.close()

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}