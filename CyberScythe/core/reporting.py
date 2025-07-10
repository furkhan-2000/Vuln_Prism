
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER
from reportlab.lib import colors
from html import escape # Import escape for HTML sanitization

def generate_pdf_report(target_url: str, vulnerabilities: list, output_path: str):
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Justify', alignment=TA_JUSTIFY))
    styles.add(ParagraphStyle(name='Center', alignment=TA_CENTER))
    
    story = []

    # --- Title Page ---
    story.append(Paragraph("<b>CyberScythe Security Report</b>", styles['Title']))
    story.append(Spacer(1, 24))
    story.append(Paragraph(f"<b>Target URL:</b> {target_url}", styles['h2']))
    story.append(Paragraph(f"<b>Generated On:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles['h2']))
    story.append(Spacer(1, 48))
    story.append(Paragraph("<i>This report details potential security vulnerabilities identified by CyberScythe.</i>", styles['Italic']))
    story.append(PageBreak())

    # --- Executive Summary ---
    story.append(Paragraph("<b>Executive Summary</b>", styles['h1']))
    story.append(Spacer(1, 12))
    
    critical_count = sum(1 for v in vulnerabilities if v.get('severity') == 'Critical')
    high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'High')
    medium_count = sum(1 for v in vulnerabilities if v.get('severity') == 'Medium')
    low_count = sum(1 for v in vulnerabilities if v.get('severity') == 'Low')

    story.append(Paragraph(f"Total Vulnerabilities Found: <b>{len(vulnerabilities)}</b>", styles['Normal']))
    story.append(Paragraph(f"- Critical: <font color='red'>{critical_count}</font>", styles['Normal']))
    story.append(Paragraph(f"- High: <font color='orange'>{high_count}</font>", styles['Normal']))
    story.append(Paragraph(f"- Medium: <font color='blue'>{medium_count}</font>", styles['Normal']))
    story.append(Paragraph(f"- Low: <font color='green'>{low_count}</font>", styles['Normal']))
    story.append(Spacer(1, 24))
    story.append(Paragraph("This section provides a high-level overview of the security posture of the target application.", styles['Justify']))
    story.append(PageBreak())

    # --- Detailed Vulnerability Findings ---
    story.append(Paragraph("<b>Detailed Vulnerability Findings</b>", styles['h1']))
    story.append(Spacer(1, 12))

    if not vulnerabilities:
        story.append(Paragraph("No specific vulnerabilities were identified during this scan.", styles['Normal']))
    else:
        for i, vuln in enumerate(vulnerabilities):
            story.append(Paragraph(f"<b>{i+1}. {escape(vuln.get('title', 'N/A'))}</b>", styles['h2']))
            story.append(Paragraph(f"<b>Severity:</b> <font color='{_get_severity_color(vuln.get('severity'))}'>{escape(vuln.get('severity'))}</font>", styles['Normal']))
            story.append(Paragraph(f"<b>URL:</b> {escape(vuln.get('url', 'N/A'))}", styles['Normal']))
            story.append(Paragraph(f"<b>Description:</b> {escape(vuln.get('description', 'N/A'))}", styles['Justify']))
            if vuln.get('payload'):
                story.append(Paragraph(f"<b>Payload:</b> <code>{escape(vuln.get('payload'))}</code>", styles['Normal']))
            if vuln.get('screenshot'):
                try:
                    story.append(Spacer(1, 6))
                    story.append(Paragraph("<b>Screenshot:</b>", styles['Normal']))
                    story.append(Image(vuln['screenshot'], width=400, height=300)) # Adjust width/height as needed
                    story.append(Spacer(1, 6))
                except Exception as img_e:
                    story.append(Paragraph(f"<i>Could not load screenshot: {img_e}</i>", styles['Normal']))
            
            # Add recommendation
            recommendations = {
                "SQL Injection": "Use parameterized queries or prepared statements. Validate and sanitize all user input. Implement a Web Application Firewall (WAF).",
                "Cross-Site Scripting (XSS)": "Sanitize all user-supplied input. Encode output based on context (HTML, URL, JavaScript). Implement a Content Security Policy (CSP).",
                "Path Traversal": "Validate and sanitize all user-supplied input used in file paths. Use whitelisting for allowed characters and file names. Avoid directly concatenating user input into file paths.",
                "Command Injection": "Avoid executing OS commands directly with user-supplied input. If necessary, use whitelisting for commands and arguments. Sanitize and validate all input. Use built-in API functions instead of external commands.",
                "Directory/File Disclosure": "Ensure sensitive directories and files are not publicly accessible. Configure web server to prevent directory listing. Remove unnecessary files and backups from production servers.",
                "Open Port": "Close unnecessary ports. Implement strict firewall rules. Ensure services running on open ports are properly secured and patched."
            }
            vuln_type = vuln.get('type', 'N/A')
            recommendation_text = recommendations.get(vuln_type, "No specific recommendation available for this vulnerability type. Consult security best practices for general web application security.")
            story.append(Paragraph(f"<b>Recommendation:</b> {recommendation_text}", styles['Justify']))
            story.append(Spacer(1, 18))

    doc.build(story, onFirstPage=_footer_callback, onLaterPages=_footer_callback)

def _footer_callback(canvas_obj, doc):
    canvas_obj.saveState()
    canvas_obj.setFont('Helvetica', 9)
    
    footer_text_1 = "© Khan Mohammed — All rights reserved"
    footer_text_2 = "Designed & developed by Khan Mohammed | linkedin.com/in/khan-mohammed-790b18214"
    
    # Position the footer text at the bottom center of the page
    canvas_obj.drawCentredString(doc.width / 2.0 + doc.leftMargin, 20, footer_text_1)
    canvas_obj.drawCentredString(doc.width / 2.0 + doc.leftMargin, 10, footer_text_2)
    
    canvas_obj.restoreState()

def _get_severity_color(severity):
    if severity == 'Critical':
        return 'red'
    elif severity == 'High':
        return 'orange'
    elif severity == 'Medium':
        return 'blue'
    elif severity == 'Low':
        return 'green'
    else:
        return 'black'
