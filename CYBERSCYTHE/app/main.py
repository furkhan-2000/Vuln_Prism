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
from io import BytesIO
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.pagesizes import letter

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
    """Generate PDF report for CyberScythe scan results using same layout as SAST"""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("VulnPrism CyberScythe DAST Report", styles['Title']))
    story.append(Spacer(1, 0.2*inch))

    # Target URL
    story.append(Paragraph(f"<b>Target URL:</b> {target_url}", styles['Normal']))
    story.append(Spacer(1, 0.2*inch))

    # Scan Summary
    story.append(Paragraph(f"<b>URLs Scanned:</b> {scan_result.scanned_urls}", styles['Normal']))
    story.append(Paragraph(f"<b>Vulnerabilities Found:</b> {scan_result.vuln_count}", styles['Normal']))
    story.append(Paragraph(f"<b>Errors Encountered:</b> {scan_result.error_count}", styles['Normal']))
    story.append(Spacer(1, 0.3*inch))

    # Severity Summary
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for vuln in scan_result.vulnerabilities:
        severity = vuln.get('severity', 'Info')
        if severity in severity_counts:
            severity_counts[severity] += 1

    summary_data = [["Severity", "Count"]]
    for sev, count in severity_counts.items():
        summary_data.append([sev, str(count)])

    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), colors.beige),
        ('GRID', (0,0), (-1,-1), 1, colors.black)
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3*inch))

    # Vulnerabilities Table
    if scan_result.vulnerabilities:
        vuln_data = [["Severity", "Type", "URL", "Parameter", "Payload"]]

        # Sort by severity (Critical first)
        severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        sorted_vulns = sorted(scan_result.vulnerabilities,
                            key=lambda x: severity_order.get(x.get('severity', 'Info'), 0),
                            reverse=True)

        for vuln in sorted_vulns:
            vuln_data.append([
                vuln.get('severity', 'N/A'),
                Paragraph(vuln.get('type', 'N/A'), styles['Normal']),
                Paragraph(vuln.get('url', 'N/A'), styles['Normal']),
                vuln.get('param', 'N/A'),
                Paragraph(vuln.get('payload', 'N/A')[:100] + "..." if len(vuln.get('payload', '')) > 100 else vuln.get('payload', 'N/A'), styles['Normal'])
            ])

        vuln_table = Table(vuln_data, colWidths=[0.8*inch, 1.2*inch, 2.5*inch, 1*inch, 2*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkred),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('TOPPADDING', (0,0), (-1,0), 10),
            ('BACKGROUND', (0,1), (-1,-1), colors.lightgrey),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('WORDWRAP', (0,0), (-1,-1), 'CJK')
        ]))
        story.append(vuln_table)
    else:
        story.append(Paragraph("✅ No vulnerabilities found during the scan.", styles['Normal']))

    doc.build(story)
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
            logger.error(f"📍 PDF error traceback: {str(pdf_error)}")

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