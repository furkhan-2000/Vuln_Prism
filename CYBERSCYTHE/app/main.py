from fastapi import FastAPI, Query, BackgroundTasks, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse, FileResponse, Response
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
import time
import traceback
from io import BytesIO
from fpdf import FPDF

# Load environment variables
load_dotenv()

# Enhanced Configure logging with 1-2 day retention
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
    rotation="50 MB",
    retention="2 days",  # Changed from 7 days to 2 days
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

# Stateless operation - no caching needed
logger.info("🚀 CyberScythe running in stateless mode - no database or cache dependencies")

def generate_cyberscythe_pdf_report(target_url: str, scan_result: ScanResult) -> BytesIO:
    """Generate PDF report for CyberScythe scan results using FPDF2"""
    buffer = BytesIO()

    # Create PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 16)

    # Title
    pdf.cell(0, 10, 'VulnPrism CyberScythe DAST Report', 0, 1, 'C')
    pdf.ln(10)

    # Target URL
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 10, f'Target URL: {target_url}', 0, 1)
    pdf.ln(5)

    # Scan Summary
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 8, f'URLs Scanned: {scan_result.scanned_urls}', 0, 1)
    pdf.cell(0, 8, f'Vulnerabilities Found: {scan_result.vuln_count}', 0, 1)
    pdf.cell(0, 8, f'Errors Encountered: {scan_result.error_count}', 0, 1)
    pdf.ln(10)

    # Severity Summary
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for vuln in scan_result.vulnerabilities:
        severity = vuln.get('severity', 'Info')
        if severity in severity_counts:
            severity_counts[severity] += 1

    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 10, 'Severity Summary:', 0, 1)
    pdf.set_font('Helvetica', '', 10)

    for severity, count in severity_counts.items():
        if count > 0:
            pdf.cell(0, 8, f'{severity}: {count}', 0, 1)
    pdf.ln(10)

    # Vulnerabilities Details
    if scan_result.vulnerabilities:
        pdf.set_font('Helvetica', 'B', 12)
        pdf.cell(0, 10, 'Vulnerability Details:', 0, 1)
        pdf.set_font('Helvetica', '', 9)

        # Sort by severity (Critical first)
        severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        sorted_vulns = sorted(scan_result.vulnerabilities,
                            key=lambda x: severity_order.get(x.get('severity', 'Info'), 0),
                            reverse=True)

        for i, vuln in enumerate(sorted_vulns, 1):
            if pdf.get_y() > 250:  # Add new page if needed
                pdf.add_page()
                pdf.set_font('Helvetica', '', 9)

            pdf.set_font('Helvetica', 'B', 10)
            pdf.cell(0, 8, f'{i}. {vuln.get("type", "Unknown")} ({vuln.get("severity", "Info")})', 0, 1)
            pdf.set_font('Helvetica', '', 9)

            # URL (truncate if too long)
            url = vuln.get('url', 'N/A')
            if len(url) > 80:
                url = url[:77] + "..."
            pdf.cell(0, 6, f'   URL: {url}', 0, 1)

            # Parameter
            param = vuln.get('param', 'N/A')
            pdf.cell(0, 6, f'   Parameter: {param}', 0, 1)

            # Payload (truncate if too long)
            payload = vuln.get('payload', 'N/A')
            if len(payload) > 100:
                payload = payload[:97] + "..."
            pdf.cell(0, 6, f'   Payload: {payload}', 0, 1)
            pdf.ln(3)
    else:
        pdf.set_font('Helvetica', 'B', 12)
        pdf.cell(0, 10, 'No vulnerabilities found during the scan.', 0, 1)

    # Save to buffer
    pdf_output = pdf.output()
    # Handle both bytes and bytearray
    if isinstance(pdf_output, (bytes, bytearray)):
        buffer.write(bytes(pdf_output))
    else:
        buffer.write(pdf_output.encode('latin-1'))
    buffer.seek(0)
    return buffer

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
    """Stateless health check - only checks service availability"""
    return {"status": "ok", "mode": "stateless", "service": "cyberscythe"}

class ScanRequest(BaseModel):
    url: str

@app.post("/scan")
async def scan(request: ScanRequest):
    scan_id = str(uuid.uuid4())
    url = request.url

    if not url or not url.strip() or not url.startswith(('http://', 'https://')):
        raise HTTPException(400, "A valid URL is required.")

    try:
        # Start scan timing
        scan_start_time = time.time()
        logger.info(f"🚀 Starting CyberScythe DAST scan for target: {url} at {time.strftime('%Y-%m-%d %H:%M:%S')}")

        # Run Scan
        findings: ScanResult = await perform_scan(url)
        scan_duration = time.time() - scan_start_time
        logger.info(f"✅ CyberScythe scan completed in {scan_duration:.2f} seconds - Found {findings.vuln_count} vulnerabilities")

        # Generate PDF Report
        pdf_start_time = time.time()
        logger.info(f"📄 Starting PDF report generation for {findings.vuln_count} vulnerabilities")

        try:
            pdf_buffer = generate_cyberscythe_pdf_report(url, findings)
            pdf_duration = time.time() - pdf_start_time
            logger.info(f"✅ PDF report generated successfully in {pdf_duration:.2f} seconds")

            return Response(
                content=pdf_buffer.getvalue(),
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=VulnPrism_CyberScythe_Report_{scan_id[:8]}.pdf"}
            )
        except Exception as pdf_error:
            pdf_duration = time.time() - pdf_start_time
            logger.error(f"❌ PDF generation failed after {pdf_duration:.2f} seconds: {str(pdf_error)}")
            logger.error(f"📍 PDF error traceback: {traceback.format_exc()}")

            # Return JSON response as fallback
            logger.info("📋 Returning JSON fallback response")
            response_data = findings.to_dict()
            response_data.update({
                "error": "PDF generation failed, returning JSON",
                "scan_duration": f"{scan_duration:.2f}s"
            })
            return response_data

    except Exception as e:
        logger.error("Scan failed for target %s: %s", url, e, exc_info=True)
        raise HTTPException(500, f"Internal server error: {e}")