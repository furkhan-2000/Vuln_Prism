import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib import colors

def build_pdf_with_enhancements(summary, collected, report_file_path):
    doc = SimpleDocTemplate(report_file_path, pagesize=letter)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Justify', alignment=TA_JUSTIFY))
    story = []

    story.append(Paragraph("<b>VulnPrism SAST & SCA Report</b>", styles['Title']))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Generated at:</b> {datetime.utcnow().isoformat()} UTC", styles['Normal']))
    story.append(Spacer(1, 12))

    story.append(Paragraph("<b>Summary:</b>", styles['Heading2']))
    for key, value in summary.items():
        story.append(Paragraph(f"<b>{key}:</b> {value}", styles['Normal']))

    story.append(Spacer(1, 12))
    story.append(Paragraph("<b>Detailed Issues:</b>", styles['Heading2']))
    for issue in collected:
        risk_color = _get_risk_color(issue.get('severity', 'Info'))
        story.append(Paragraph(f"<b>Rule:</b> {issue.get('rule')}", styles['Justify']))
        story.append(Paragraph(f"<b>Description:</b> {issue.get('desc')}", styles['Justify']))
        story.append(Paragraph(f"<b>Impact:</b> {issue.get('impact')}", styles['Justify']))
        story.append(Paragraph(f"<b>Recommendation:</b> {issue.get('fix')}", styles['Justify']))
        story.append(Paragraph(f"<b>File:</b> {issue.get('file')}:{issue.get('line')}", styles['Justify']))
        story.append(Paragraph(
            f"<b>Risk Score:</b> <font color='{risk_color.hexval()}'>{issue.get('risk_score')} ({issue.get('severity')})</font>",
            styles['Justify']
        ))
        story.append(Spacer(1, 12))

    doc.build(story)

def _get_risk_color(severity):
    if severity == 'Critical':
        return colors.red
    elif severity == 'High':
        return colors.orangered
    elif severity == 'Medium':
        return colors.orange
    elif severity == 'Low':
        return colors.green
    else:
        return colors.grey
