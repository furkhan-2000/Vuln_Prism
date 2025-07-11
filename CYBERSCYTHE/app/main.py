from fastapi import FastAPI, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
import uuid
import os
from app.scanner import perform_scan  # Updated async scanner
from app.report import create_pdf_report
import logging
import asyncio  # Add this import

# Setup logging
logging.basicConfig(
    filename="logs/server.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

app = FastAPI(
    title="CyberScythe",
    description="Aggressive Smart Vulnerability Scanner",
    version="3.0.0",
)

# Mount static directory
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/static/index.html")

# Health check endpoint
@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.get("/scan")
async def scan(url: str = Query(..., description="Target URL to scan")):
    scan_id = str(uuid.uuid4())
    report_path = f"static/reports/report_{scan_id}.pdf"

    try:
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        findings = await perform_scan(url)  # Use await with async function
        create_pdf_report(scan_id, url, findings, report_path)
        logging.info(f"Scan complete for {url} with scan_id {scan_id}")
        return {"msg": "Scan complete", "report": f"/{report_path}"}
    except Exception as e:
        logging.exception(f"Failed to scan {url}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/report/{scan_id}")
def download_report(scan_id: str):
    filepath = f"static/reports/report_{scan_id}.pdf"
    if not os.path.exists(filepath):
        return JSONResponse(status_code=404, content={"error": "Report not found"})
    return FileResponse(filepath, media_type='application/pdf', filename=f"CyberScythe_Report_{scan_id}.pdf")
