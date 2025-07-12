from fpdf import FPDF
import os
from pathlib import Path

def create_pdf_report(scan_id, url, findings, output_path):
    safe_path = Path(output_path).resolve()
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    pdf = FPDF()
    pdf.add_page()

    # Helper function to safely encode text
    def write(text):
        return str(text).encode('latin-1', 'replace').decode('latin-1')

    # --- Header ---
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, write("CyberScythe Scan Report"), 0, 1, 'C')
    pdf.set_font("Arial", '', 10)
    pdf.cell(0, 8, write(f"Scan ID: {scan_id}"), 0, 1, 'C')
    pdf.ln(10)

    # --- Scan Details ---
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, write("Scan Details"), 0, 1, 'L')
    pdf.set_font("Arial", '', 10)
    pdf.cell(0, 8, write(f"URL Scanned: {findings.get('url', 'N/A')}"), 0, 1, 'L')
    pdf.cell(0, 8, write(f"Page Title: {findings.get('title', 'N/A')}"), 0, 1, 'L')
    pdf.cell(0, 8, write(f"Vulnerabilities Found: {len(findings.get('vulnerabilities', []))}"), 0, 1, 'L')
    pdf.ln(10)

    # --- Vulnerabilities Section ---
    vulnerabilities = findings.get('vulnerabilities', [])
    if vulnerabilities:
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, write("Vulnerability Details"), 0, 1, 'L')

        for vuln in vulnerabilities:
            pdf.set_font("Arial", 'B', 10)
            pdf.cell(0, 8, write(f"[{vuln.get('type', 'N/A').upper()}] Severity: {vuln.get('severity', 'N/A')}"), 0, 1)
            pdf.set_font("Arial", '', 10)
            # Use multi_cell for descriptions that might wrap
            pdf.multi_cell(0, 6, write(f"Description: {vuln.get('description', 'No description provided.')}"))
            pdf.ln(5)

    # --- Footer ---
    pdf.set_y(-30)
    pdf.set_font("Arial", 'I', 8)
    pdf.cell(0, 10, write("Designed and developed by Khan Mohammed"), 0, 1, 'C')
    pdf.cell(0, 10, write("(c) All rights reserved 2025 | www.linkedin.com/in/khan-mohammed-790b18214"), 0, 1, 'C')

    pdf.output(safe_path)  # Use safe_path for output
