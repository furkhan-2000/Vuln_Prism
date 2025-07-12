from fastapi import FastAPI, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.concurrency import run_in_threadpool
import uuid
import os
from app.scanner import perform_scan
from app.report import create_pdf_report
from loguru import logger
import sys

# Configure logging
logger.remove()
logger.add(
    sys.stderr,
    level="INFO",
    format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
)
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
    version="4.0.0",
)

# Mount static directory
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/static/index.html")

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.get("/scan")
async def scan(url: str = Query(..., description="Target URL to scan")):
    scan_id = str(uuid.uuid4())
    report_path = f"static/reports/report_{scan_id}.pdf"

    try:
        os.makedirs(os.path.dirname(report_path), exist_ok=True)

        # Offload the blocking perform_scan into a thread
        findings = await run_in_threadpool(perform_scan, url)

        # Offload the blocking create_pdf_report into a thread
        await run_in_threadpool(create_pdf_report, scan_id, url, findings, report_path)

        logger.info(f"Scan complete for {url} with scan_id {scan_id}")
        return {"msg": "Scan complete", "report": f"/{report_path}"}

    except Exception as e:
        logger.exception(f"Failed to scan {url}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/report/{scan_id}")
def download_report(scan_id: str):
    filepath = f"static/reports/report_{scan_id}.pdf"
    if not os.path.exists(filepath):
        return JSONResponse(status_code=404, content={"error": "Report not found"})
    return FileResponse(filepath, media_type='application/pdf', filename=f"CyberScythe_Report_{scan_id}.pdf")

