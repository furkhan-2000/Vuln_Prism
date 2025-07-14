from fastapi import FastAPI, Query, BackgroundTasks, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import uuid
import os
import json
import httpx
from app.aggressive_scanner.scanner import perform_scan, ScanResult
from app.report import create_pdf_report
from loguru import logger
import sys

# Load environment variables
load_dotenv(".env")
load_dotenv()  # Also check local .env if exists

# Configure logging
logger.remove()
logger.add(
    sys.stderr,
    level="INFO",
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

REPORTS_DIR = "static/reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# Mount static directory
app.mount("/static", StaticFiles(directory="static"), name="static")

def update_scan_status(scan_id: str, status: str, message: str = None, report_path: str = None):
    status_file = os.path.join(REPORTS_DIR, f"status_{scan_id}.json")
    with open(status_file, "w") as f:
        status_data = {"status": status}
        if message:
            status_data["message"] = message
        if report_path:
            status_data["report_path"] = report_path
        json.dump(status_data, f)

async def run_scan_and_generate_report(scan_id: str, url: str):
    """
    The core function that runs in the background.
    """
    pdf_report_path = os.path.join(REPORTS_DIR, f"report_{scan_id}.pdf")
    
    try:
        logger.info(f"Starting scan for {url} with scan_id {scan_id}")
        update_scan_status(scan_id, "scanning", message=f"Starting scan for {url}")

        findings: ScanResult = await perform_scan(url)
        
        setattr(findings, "url", url)
        
        logger.info(f"Scan logic complete for {url}. Generating report...")
        update_scan_status(scan_id, "generating_report", message="Scan complete, generating PDF report.")

        create_pdf_report(scan_id, url, findings.to_dict(), pdf_report_path)
        
        logger.info(f"Scan and report complete for {url} with scan_id {scan_id}")
        update_scan_status(scan_id, "complete", report_path=f"/{pdf_report_path}")

    except Exception as e:
        logger.exception(f"A critical error occurred during the scan for {url} (scan_id: {scan_id})")
        update_scan_status(scan_id, "error", message=str(e))

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/static/index.html")

@app.get("/health")
def health_check():
    return {"status": "healthy"}



class ScanRequest(BaseModel):
    url: str

@app.post("/scan")
async def scan(background_tasks: BackgroundTasks, request: ScanRequest):
    scan_id = str(uuid.uuid4())
    
    # Immediately create a status file to indicate the process has started
    update_scan_status(scan_id, "queued", message="Scan has been queued.")
    
    # Add the long-running task to the background
    background_tasks.add_task(run_scan_and_generate_report, scan_id, request.url)
    
    # Return immediately with the scan_id
    return {"message": "Scan initiated.", "scan_id": scan_id}

@app.get("/status/{scan_id}")
def get_status(scan_id: str):
    status_file = os.path.join(REPORTS_DIR, f"status_{scan_id}.json")
    if not os.path.exists(status_file):
        return JSONResponse(status_code=404, content={"error": "Scan ID not found."})
    
    with open(status_file, "r") as f:
        status_data = json.load(f)
    return status_data

@app.get("/report/{scan_id}")
def download_report(scan_id: str):
    filepath = os.path.join(REPORTS_DIR, f"report_{scan_id}.pdf")
    if not os.path.exists(filepath):
        return JSONResponse(status_code=404, content={"error": "Report not found or not yet generated."})
    return FileResponse(filepath, media_type='application/pdf', filename=f"CyberScythe_Report_{scan_id}.pdf")

