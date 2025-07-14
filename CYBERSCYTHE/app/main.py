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
logger.add(
    "/tmp/cyberscythe_debug.log",
    level="DEBUG",
    format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} - {message}",
    encoding="utf-8"
)

logger.info("🚀 CyberScythe Service Starting Up...")
logger.info("📁 Working Directory: {}", os.getcwd())
logger.info("🐍 Python Version: {}", sys.version)
logger.info("📦 Checking Dependencies...")

# Check if playwright is available
try:
    import playwright
    logger.info("✅ Playwright is available")
except ImportError as e:
    logger.error("❌ Playwright not available: {}", e)

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

    logger.info("🎯 BACKGROUND SCAN STARTED")
    logger.info("  - Scan ID: {}", scan_id)
    logger.info("  - Target URL: {}", url)
    logger.info("  - Report Path: {}", pdf_report_path)

    try:
        logger.info("🔄 Updating status to 'scanning'...")
        update_scan_status(scan_id, "scanning", message=f"Starting scan for {url}")
        logger.info("✅ Status updated")

        logger.info("🔍 Calling perform_scan function...")
        findings: ScanResult = await perform_scan(url)
        logger.info("✅ Scan completed successfully")
        logger.info("  - Findings type: {}", type(findings))
        logger.info("  - Findings data: {}", findings.to_dict() if hasattr(findings, 'to_dict') else str(findings))

        setattr(findings, "url", url)
        logger.info("✅ URL attribute set on findings")

        logger.info("📊 Updating status to 'generating_report'...")
        update_scan_status(scan_id, "generating_report", message="Scan complete, generating PDF report.")
        logger.info("✅ Status updated")

        logger.info("📄 Creating PDF report...")
        create_pdf_report(scan_id, url, findings.to_dict(), pdf_report_path)

        # Verify report was created
        if os.path.exists(pdf_report_path):
            report_size = os.path.getsize(pdf_report_path)
            logger.info("✅ PDF report created successfully")
            logger.info("  - File size: {} bytes", report_size)
        else:
            logger.error("❌ PDF report file not found after creation")
            raise Exception("PDF report creation failed - file not found")

        logger.info("🎉 Updating status to 'complete'...")
        update_scan_status(scan_id, "complete", report_path=f"/report/{scan_id}")
        logger.info("✅ Scan and report complete for {} with scan_id {}", url, scan_id)

    except Exception as e:
        logger.error("💥 Critical error during scan for {} (scan_id: {})", url, scan_id)
        logger.error("  - Error type: {}", type(e).__name__)
        logger.error("  - Error message: {}", str(e))
        logger.exception("  - Full traceback:")
        update_scan_status(scan_id, "error", message=str(e))

@app.get("/", include_in_schema=False)
def root():
    logger.info("🌐 Root endpoint accessed - redirecting to static/index.html")
    return RedirectResponse("/static/index.html")

@app.get("/health")
def health_check():
    logger.debug("💓 Health check requested")
    return {"status": "healthy"}



class ScanRequest(BaseModel):
    url: str

@app.post("/scan")
async def scan(background_tasks: BackgroundTasks, request: ScanRequest):
    scan_id = str(uuid.uuid4())

    logger.info("🔍 SCAN REQUEST RECEIVED")
    logger.info("  - Scan ID: {}", scan_id)
    logger.info("  - Target URL: {}", request.url)
    logger.info("  - Request Type: {}", type(request))

    try:
        # Validate URL
        if not request.url or not request.url.strip():
            logger.error("❌ Empty URL provided")
            raise HTTPException(400, "URL is required")

        # Basic URL validation
        if not request.url.startswith(('http://', 'https://')):
            logger.error("❌ Invalid URL format: {}", request.url)
            raise HTTPException(400, "URL must start with http:// or https://")

        logger.info("✅ URL validation passed")

        # Immediately create a status file to indicate the process has started
        logger.info("📝 Creating status file...")
        update_scan_status(scan_id, "queued", message="Scan has been queued.")
        logger.info("✅ Status file created")

        # Add the long-running task to the background
        logger.info("🚀 Adding background task...")
        background_tasks.add_task(run_scan_and_generate_report, scan_id, request.url)
        logger.info("✅ Background task added")

        # Return immediately with the scan_id
        response = {"message": "Scan initiated.", "scan_id": scan_id}
        logger.info("📤 Returning response: {}", response)
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error("💥 Unexpected error in scan endpoint: {}", e, exc_info=True)
        raise HTTPException(500, f"Internal server error: {str(e)}")

@app.get("/status/{scan_id}")
def get_status(scan_id: str):
    logger.debug("📊 Status check requested for scan ID: {}", scan_id)
    status_file = os.path.join(REPORTS_DIR, f"status_{scan_id}.json")
    logger.debug("  - Status file path: {}", status_file)

    if not os.path.exists(status_file):
        logger.warning("❌ Status file not found: {}", status_file)
        return JSONResponse(status_code=404, content={"error": "Scan ID not found."})

    try:
        with open(status_file, "r") as f:
            status_data = json.load(f)
        logger.debug("✅ Status data loaded: {}", status_data)
        return status_data
    except Exception as e:
        logger.error("❌ Error reading status file: {}", e)
        return JSONResponse(status_code=500, content={"error": "Error reading status"})

@app.get("/report/{scan_id}")
def download_report(scan_id: str):
    filepath = os.path.join(REPORTS_DIR, f"report_{scan_id}.pdf")
    if not os.path.exists(filepath):
        return JSONResponse(status_code=404, content={"error": "Report not found or not yet generated."})
    return FileResponse(filepath, media_type='application/pdf', filename=f"CyberScythe_Report_{scan_id}.pdf")

