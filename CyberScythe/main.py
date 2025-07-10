import os
import logging
from pythonjsonlogger import jsonlogger # Import jsonlogger
from fastapi import FastAPI, Request, Form, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from core.database import init_db, SessionLocal, Scan, Vulnerability
from config import APP_TITLE, REPORTS_DIR, LOG_LEVEL, AUTH_CREDENTIALS
from celery_app import celery_app, run_scan_task
from datetime import datetime
import secrets

# --- Configuration ---
# Custom JSON formatter
formatter = jsonlogger.JsonFormatter(
    '%(asctime)s %(levelname)s %(name)s %(message)s'
)

# Get root logger and set level
root_logger = logging.getLogger()
root_logger.setLevel(getattr(logging, LOG_LEVEL.upper()))

# Remove existing handlers to avoid duplicate logs
if root_logger.handlers:
    for handler in root_logger.handlers:
        root_logger.removeHandler(handler)

# Add a console handler with the custom formatter
handler = logging.StreamHandler()
handler.setFormatter(formatter)
root_logger.addHandler(handler)

logger = logging.getLogger(__name__)

app = FastAPI(title=APP_TITLE)
templates = Jinja2Templates(directory="templates")

security = HTTPBasic()

def get_current_username(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials.username in AUTH_CREDENTIALS:
        correct_password = secrets.compare_digest(
            credentials.password, 
            AUTH_CREDENTIALS[credentials.username]
        )
        if not correct_password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Basic"},
            )
        return credentials.username
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Basic"},
    )

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
async def start_scan_endpoint(url: str = Form(...), username: str = Depends(get_current_username)):
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

@app.post("/schedule_scan", status_code=202)
async def schedule_scan_endpoint(url: str = Form(...), schedule_time: str = Form(...), username: str = Depends(get_current_username)):
    """
    Schedules a scan on the given URL at a specified time.
    """
    if not url.startswith("http"):
        raise HTTPException(status_code=400, detail="Invalid URL. Must start with http:// or https://")
    
    try:
        # Parse the schedule_time string into a datetime object
        # Assuming schedule_time is in ISO format, e.g., "2025-07-10T10:30:00"
        scheduled_datetime = datetime.fromisoformat(schedule_time)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid schedule_time format. Use ISO format (e.g., YYYY-MM-DDTHH:MM:SS).")

    db = SessionLocal()
    try:
        new_scan = Scan(target_url=url, status="scheduled", created_at=scheduled_datetime) # Use created_at for scheduled time
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)

        scan_id = new_scan.id
        logger.info(f"[{scan_id}] Scan scheduled for URL: {url} at {scheduled_datetime}")

        # Send the scan task to Celery with eta (estimated time of arrival)
        run_scan_task.apply_async(args=[scan_id, url], eta=scheduled_datetime)

        return {"message": "Scan scheduled successfully.", "scan_id": scan_id, "scheduled_for": scheduled_datetime.isoformat()}

    except Exception as e:
        logger.error(f"Failed to schedule scan for {url}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to schedule scan.")
    finally:
        db.close()

@app.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: int, username: str = Depends(get_current_username)):
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
async def get_report(scan_id: int, username: str = Depends(get_current_username)):
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