from typing import List, Dict
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

class ReportGenerator:
    def __init__(self):
        self.style = getSampleStyleSheet()
    
    def generate_pdf_report(self, filename: str, target: str, vulnerabilities: List[Dict]):
        doc = SimpleDocTemplate(filename, pagesize=letter)
        elements = []
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.style['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#e94560'),
            spaceAfter=30,
        )
        title = Paragraph(f"MoD Security Report - {datetime.now().strftime('%Y-%m-%d')}", title_style)
        elements.append(title)
        elements.append(Spacer(1, 0.3*inch))
        info_data = [
            ['Target', target],
            ['Scan Date', datetime.now().isoformat()],
            ['Total Vulnerabilities', str(len(vulnerabilities))],
        ]
        info_table = Table(info_data)
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e94560')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(info_table)
        elements.append(Spacer(1, 0.3*inch))
        vuln_data = [['Type', 'Severity', 'Description', 'Evidence']]
        severity_colors = {
            'Critical': colors.HexColor('#ff0000'),
            'High': colors.HexColor('#ff6600'),
            'Medium': colors.HexColor('#ffff00'),
            'Low': colors.HexColor('#00ff00'),
        }
        for vuln in vulnerabilities:
            vuln_data.append([
                vuln.get('type', ''),
                vuln.get('severity', ''),
                vuln.get('description', '')[:50],
                vuln.get('evidence', '')[:50]
            ])
        vuln_table = Table(vuln_data)
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(vuln_table)
        doc.build(elements)
    
    def generate_html_report(self, filename: str, target: str, vulnerabilities: List[Dict]) -> str:
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>MoD Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; background: #f5f5f5; }}
                .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 20px; }}
                h1 {{ color: #e94560; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th {{ background: #1a1a2e; color: white; padding: 10px; text-align: left; }}
                td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
                .critical {{ color: #ff0000; font-weight: bold; }}
                .high {{ color: #ff6600; font-weight: bold; }}
                .medium {{ color: #ffff00; font-weight: bold; }}
                .low {{ color: #00ff00; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>MoD Security Report</h1>
                <p>Target: {target}</p>
                <p>Scan Date: {datetime.now().isoformat()}</p>
                <p>Total Vulnerabilities: {len(vulnerabilities)}</p>
                <table>
                    <tr>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Description</th>
                        <th>Evidence</th>
                    </tr>
        """
        for vuln in vulnerabilities:
            severity_class = vuln.get('severity', 'Low').lower()
            html += f"""
                    <tr>
                        <td>{vuln.get('type', '')}</td>
                        <td class="{severity_class}">{vuln.get('severity', '')}</td>
                        <td>{vuln.get('description', '')}</td>
                        <td>{vuln.get('evidence', '')}</td>
                    </tr>
            """
        html += """
                </table>
            </div>
        </body>
        </html>
        """
        with open(filename, 'w') as f:
            f.write(html)
        return filename