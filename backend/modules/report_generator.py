"""
Report Generator (report_generator.py) - Executive-Grade PDF & HTML Assessment Reports.

Delivers an executive-grade document structured into four clear sections:
- Header: "CyberSentry Enterprise Assessment Report", Target/CIDR, timestamp, and RT-MSSU evaluator metadata.
- Section 1: Executive Summary & Network Health Index (with high-level CVSS risk count table).
- Section 2: Asset Inventory Matrix (discovered IP addresses, hostnames, open ports, and operating systems).
- Section 3: Prioritized Vulnerability Register (with CISA KEV badges and CVSS metrics).
- Section 4: Actionable Remediation Guide (system-by-system hardening recommendations).
"""

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    HRFlowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from jinja2 import Environment
import glob
import json
import logging
import os
import time
from datetime import datetime
from xml.sax.saxutils import escape as xml_escape

logger = logging.getLogger(__name__)

# Retention policy for generated reports
REPORT_RETENTION_DAYS = 7


def _escape_pdf_text(value):
    """Render untrusted values as literal text in ReportLab paragraphs."""
    return xml_escape(str(value if value is not None else ""))


def _wrap_table_text(text, style, max_len=60):
    """Wrap long unbroken strings (like URLs) inside a Paragraph to prevent table margin overflow."""
    escaped = _escape_pdf_text(text)
    return Paragraph(escaped, style)


class ReportGenerator:
    """Generate executive security assessment reports in PDF and HTML formats."""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Setup custom executive typography and layout styles."""
        self.title_style = ParagraphStyle(
            'CyberSentryTitle',
            parent=self.styles['Heading1'],
            fontSize=22,
            leading=26,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#0d233a'),
            fontName='Helvetica-Bold',
            spaceAfter=6,
        )

        self.subtitle_style = ParagraphStyle(
            'CyberSentrySubtitle',
            parent=self.styles['Normal'],
            fontSize=11,
            leading=15,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#4b6584'),
            fontName='Helvetica',
            spaceAfter=15,
        )

        self.section_heading = ParagraphStyle(
            'SectionHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#1b3a4b'),
            fontName='Helvetica-Bold',
            spaceBefore=14,
            spaceAfter=8,
        )

        self.subheading_style = ParagraphStyle(
            'SubHeading',
            parent=self.styles['Heading3'],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#2c3e50'),
            fontName='Helvetica-Bold',
            spaceBefore=8,
            spaceAfter=4,
        )

        self.body_style = ParagraphStyle(
            'ExecutiveBody',
            parent=self.styles['Normal'],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor('#2d3436'),
            fontName='Helvetica',
            spaceAfter=6,
        )

        self.table_cell = ParagraphStyle(
            'TableCell',
            parent=self.styles['Normal'],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor('#2d3436'),
            fontName='Helvetica',
        )

        self.table_cell_bold = ParagraphStyle(
            'TableCellBold',
            parent=self.styles['Normal'],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor('#0d233a'),
            fontName='Helvetica-Bold',
        )

        self.table_header = ParagraphStyle(
            'TableHeader',
            parent=self.styles['Normal'],
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor('#ffffff'),
            fontName='Helvetica-Bold',
            alignment=TA_LEFT,
        )

        self.table_header_center = ParagraphStyle(
            'TableHeaderCenter',
            parent=self.styles['Normal'],
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor('#ffffff'),
            fontName='Helvetica-Bold',
            alignment=TA_CENTER,
        )

        self.table_cell_center_bold = ParagraphStyle(
            'TableCellCenterBold',
            parent=self.styles['Normal'],
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor('#0d233a'),
            fontName='Helvetica-Bold',
            alignment=TA_CENTER,
        )

        self.code_style = ParagraphStyle(
            'CodeSnippet',
            parent=self.styles['Normal'],
            fontSize=7.5,
            leading=10,
            fontName='Courier',
            textColor=colors.HexColor('#1e272e'),
        )

    def generate_report(self, scan_data, report_format='html'):
        """Generate a comprehensive security assessment report."""
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')

            # Resolve reports directory:
            reports_dir = os.environ.get(
                'REPORTS_DIR',
                os.path.join(os.getcwd(), 'reports')
            )
            os.makedirs(reports_dir, exist_ok=True)

            if report_format.lower() == 'pdf':
                filename = f"security_report_{timestamp}.pdf"
                filepath = os.path.join(reports_dir, filename)
                self._generate_pdf_report(scan_data, filepath)
            elif report_format.lower() == 'html':
                filename = f"security_report_{timestamp}.html"
                filepath = os.path.join(reports_dir, filename)
                self._generate_html_report(scan_data, filepath)
            else:
                raise ValueError(f"Unsupported report format: {report_format}")

            logger.info("Report generated: %s", filepath)
            self._purge_stale_reports(reports_dir)
            return filepath

        except Exception as e:
            logger.error("Report generation failed: %s", e)
            raise e

    def _purge_stale_reports(self, reports_dir, max_age_days=REPORT_RETENTION_DAYS):
        """Delete generated reports older than the retention window."""
        cutoff = time.time() - max_age_days * 86400
        for pattern in ("security_report_*.html", "security_report_*.pdf"):
            for filepath in glob.glob(os.path.join(reports_dir, pattern)):
                try:
                    if os.path.getmtime(filepath) < cutoff:
                        os.remove(filepath)
                except OSError:
                    continue

    def _generate_pdf_report(self, scan_data, filepath):
        """Generate executive-grade 4-section PDF assessment report."""
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            leftMargin=0.5 * inch,
            rightMargin=0.5 * inch,
            topMargin=0.6 * inch,
            bottomMargin=0.6 * inch,
        )
        story = []

        # Header: Document Title & Subtitle with RT-MSSU Evaluator Metadata
        story.append(Paragraph("CyberSentry Enterprise Assessment Report", self.title_style))
        story.append(Paragraph(
            "Executive Vulnerability Assessment & Asset Intelligence Engine | RT-MSSU Capstone 2026-27 | Academic Research Lab",
            self.subtitle_style
        ))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0d233a'), spaceAfter=12))

        # Metadata Box (Target / CIDR, Evaluator, Timestamp)
        target = scan_data.get('target') or scan_data.get('domain') or 'Target Network'
        scan_type = scan_data.get('scan_type', 'Comprehensive Subnet & Service Audit')
        timestamp_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

        meta_data = [
            [
                Paragraph("<b>Target Network / CIDR:</b>", self.table_cell_bold),
                Paragraph(_escape_pdf_text(target), self.table_cell),
                Paragraph("<b>Assessment Date:</b>", self.table_cell_bold),
                Paragraph(_escape_pdf_text(timestamp_str), self.table_cell),
            ],
            [
                Paragraph("<b>Scan Scope / Type:</b>", self.table_cell_bold),
                Paragraph(_escape_pdf_text(scan_type.upper()), self.table_cell),
                Paragraph("<b>Evaluation Body:</b>", self.table_cell_bold),
                Paragraph("RT-MSSU Security Evaluation Lab", self.table_cell),
            ]
        ]
        meta_table = Table(meta_data, colWidths=[1.8 * inch, 2.0 * inch, 1.6 * inch, 1.8 * inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f5f9')),
            ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 14))

        # Parse findings (vulnerabilities + misconfigurations)
        raw_vulns = scan_data.get('vulnerabilities', [])
        vuln_list = raw_vulns if isinstance(raw_vulns, list) else raw_vulns.get('vulnerabilities', [])
        misc_list = scan_data.get('misconfigurations', [])
        if not isinstance(misc_list, list):
            misc_list = []
        all_findings = vuln_list + misc_list

        # Compute severity statistics
        critical_count = sum(1 for v in all_findings if str(v.get('severity', '')).lower() == 'critical')
        high_count = sum(1 for v in all_findings if str(v.get('severity', '')).lower() == 'high')
        medium_count = sum(1 for v in all_findings if str(v.get('severity', '')).lower() == 'medium')
        low_count = sum(1 for v in all_findings if str(v.get('severity', '')).lower() == 'low')
        total_findings = len(all_findings)

        # Health index computation (0-100 score where 100 is pristine)
        threat_score = min(100, (critical_count * 25) + (high_count * 15) + (medium_count * 5) + (low_count * 1))
        health_index = max(0, 100 - threat_score)

        # -------------------------------------------------------------
        # SECTION 1: Executive Summary & Network Health Index
        # -------------------------------------------------------------
        story.append(Paragraph("Section 1: Executive Summary & Network Health Index", self.section_heading))
        summary_p = f"""
        This security assessment document provides executive-grade threat intelligence and technical remediation guidance 
        for <b>{_escape_pdf_text(target)}</b>. The automated audit identified a total of <b>{total_findings} security findings</b>, 
        including <b>{critical_count} Critical</b>, <b>{high_count} High</b>, and <b>{medium_count} Medium</b> severity issues. 
        The overall Enterprise Network Health Index is rated at <b>{health_index}/100</b>.
        """
        story.append(Paragraph(summary_p, self.body_style))
        story.append(Spacer(1, 6))

        # Health & CVSS Risk Count Table
        health_color = '#d32f2f' if health_index < 40 else ('#f57c00' if health_index < 70 else '#388e3c')
        risk_summary_data = [
            [
                Paragraph("<b>Network Health Index</b>", self.table_header_center),
                Paragraph("<b>Critical Findings (CVSS 9.0+)</b>", self.table_header_center),
                Paragraph("<b>High Risk (CVSS 7.0-8.9)</b>", self.table_header_center),
                Paragraph("<b>Medium Risk (CVSS 4.0-6.9)</b>", self.table_header_center),
                Paragraph("<b>Low Risk (CVSS <4.0)</b>", self.table_header_center),
            ],
            [
                Paragraph(f"<font color='{health_color}' size='12'><b>{health_index}/100</b></font>", self.table_cell_center_bold),
                Paragraph(f"<font color='#d32f2f' size='11'><b>{critical_count}</b></font>", self.table_cell_center_bold),
                Paragraph(f"<font color='#f57c00' size='11'><b>{high_count}</b></font>", self.table_cell_center_bold),
                Paragraph(f"<font color='#fbc02d' size='11'><b>{medium_count}</b></font>", self.table_cell_center_bold),
                Paragraph(f"<font color='#388e3c' size='11'><b>{low_count}</b></font>", self.table_cell_center_bold),
            ]
        ]
        risk_table = Table(risk_summary_data, colWidths=[1.6 * inch, 1.6 * inch, 1.4 * inch, 1.4 * inch, 1.2 * inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1b3a4b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#ffffff')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#ffffff')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#1b3a4b')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 14))

        # -------------------------------------------------------------
        # SECTION 2: Asset Inventory Matrix
        # -------------------------------------------------------------
        story.append(Paragraph("Section 2: Asset Inventory Matrix", self.section_heading))
        
        # Extract host information from scan_results or ports
        raw_hosts = scan_data.get('scan_results', [])
        if not raw_hosts and 'ports' in scan_data:
            port_data = scan_data.get('ports')
            if isinstance(port_data, dict):
                raw_hosts = port_data.get('scan_results', [])

        asset_rows = [
            [
                Paragraph("<b>Discovered IP Address</b>", self.table_header),
                Paragraph("<b>Canonical Hostname</b>", self.table_header),
                Paragraph("<b>Inferred OS</b>", self.table_header),
                Paragraph("<b>Discovered Open Ports & Services</b>", self.table_header),
            ]
        ]

        if raw_hosts:
            for host in raw_hosts:
                ip = host.get('ip_address') or host.get('host') or target
                hostname = host.get('hostname') or ip
                os_name = host.get('inferred_os') or 'Linux / Unix (Inferred)'
                open_ports = host.get('open_ports', [])
                if open_ports:
                    ports_desc = ", ".join([f"{p.get('port')}/{p.get('service', 'tcp')}" for p in open_ports[:8]])
                    if len(open_ports) > 8:
                        ports_desc += f" (+{len(open_ports)-8} more)"
                else:
                    ports_desc = "None Identified"

                asset_rows.append([
                    Paragraph(_escape_pdf_text(ip), self.table_cell),
                    Paragraph(_escape_pdf_text(hostname), self.table_cell),
                    Paragraph(_escape_pdf_text(os_name), self.table_cell),
                    Paragraph(_escape_pdf_text(ports_desc), self.table_cell),
                ])
        else:
            # Fallback single target row
            asset_rows.append([
                Paragraph(_escape_pdf_text(target), self.table_cell),
                Paragraph(_escape_pdf_text(target), self.table_cell),
                Paragraph("Linux / Web Host", self.table_cell),
                Paragraph("Ports 80/HTTP, 443/HTTPS", self.table_cell),
            ])

        asset_table = Table(asset_rows, colWidths=[1.8 * inch, 1.8 * inch, 1.6 * inch, 2.0 * inch])
        asset_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1b3a4b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#ffffff')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#ffffff'), colors.HexColor('#f8fafc')]),
            ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(asset_table)
        story.append(Spacer(1, 14))

        # -------------------------------------------------------------
        # SECTION 3: Prioritized Vulnerability Register
        # -------------------------------------------------------------
        story.append(Paragraph("Section 3: Prioritized Vulnerability Register", self.section_heading))
        
        if all_findings:
            # Sort findings by CVSS descending
            sorted_findings = sorted(
                all_findings,
                key=lambda x: float(x.get('cvss_score') or x.get('cvss') or (9.0 if str(x.get('severity')).lower() == 'critical' else 5.0)),
                reverse=True
            )

            vuln_rows = [
                [
                    Paragraph("<b>CVE / Finding ID</b>", self.table_header),
                    Paragraph("<b>Severity / CVSS</b>", self.table_header),
                    Paragraph("<b>Vulnerability Title & Affected Target</b>", self.table_header),
                    Paragraph("<b>CISA KEV / EPSS Status</b>", self.table_header),
                ]
            ]

            for finding in sorted_findings[:18]:  # Top 18 prioritized findings in PDF
                cve_id = finding.get('cve_id') or finding.get('id') or 'MISCONFIG'
                severity = (finding.get('severity') or 'Medium').upper()
                cvss = finding.get('cvss_score') or finding.get('cvss') or 'N/A'
                title = finding.get('title') or finding.get('description') or 'Unknown Issue'
                port = finding.get('port') or 'N/A'
                is_kev = finding.get('cisa_kev_listed', False)
                epss = finding.get('epss_percentile') or 'N/A'

                kev_tag = "<font color='#d32f2f'><b>Active KEV Listed</b></font>" if is_kev else "Standard Threat"
                sev_color = '#d32f2f' if severity == 'CRITICAL' else ('#f57c00' if severity == 'HIGH' else '#fbc02d')

                finding_desc = f"<b>{_escape_pdf_text(title)}</b><br/><font color='#636e72'>Port: {port} | Target: {_escape_pdf_text(target)}</font>"

                vuln_rows.append([
                    Paragraph(f"<b>{_escape_pdf_text(cve_id)}</b>", self.table_cell),
                    Paragraph(f"<font color='{sev_color}'><b>{severity}</b></font><br/>CVSS {cvss}", self.table_cell),
                    Paragraph(finding_desc, self.table_cell),
                    Paragraph(f"{kev_tag}<br/>EPSS: {epss}", self.table_cell),
                ])

            vuln_table = Table(vuln_rows, colWidths=[1.4 * inch, 1.4 * inch, 2.8 * inch, 1.6 * inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1b3a4b')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#ffffff')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#ffffff'), colors.HexColor('#f8fafc')]),
                ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LEFTPADDING', (0, 0), (-1, -1), 5),
                ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(vuln_table)
        else:
            story.append(Paragraph("No critical or high vulnerabilities identified during the assessment period.", self.body_style))

        story.append(Spacer(1, 14))

        # -------------------------------------------------------------
        # SECTION 4: Actionable Remediation Guide
        # -------------------------------------------------------------
        story.append(KeepTogether([
            Paragraph("Section 4: Actionable Remediation Guide", self.section_heading),
            Paragraph("System-by-system hardening recommendations and administrator execution playbooks:", self.body_style)
        ]))

        # Display top remediation playbooks
        if all_findings:
            for i, finding in enumerate(all_findings[:5], 1):
                title = finding.get('title', 'Security Finding')
                remediation_steps = finding.get('remediation_steps') or [finding.get('remediation') or finding.get('recommendation') or 'Apply vendor security patch.']
                snippet = finding.get('fix_snippet', '')
                impact = finding.get('impact', '')

                playbook_story = []
                playbook_story.append(Paragraph(f"<b>{i}. {_escape_pdf_text(title)}</b>", self.subheading_style))
                if impact:
                    playbook_story.append(Paragraph(f"<b>Impact:</b> {_escape_pdf_text(impact)}", self.body_style))
                
                steps_text = "<br/>".join([f"• {_escape_pdf_text(step)}" for step in remediation_steps])
                playbook_story.append(Paragraph(f"<b>Action Plan:</b><br/>{steps_text}", self.body_style))

                if snippet:
                    clean_snippet = _escape_pdf_text(snippet.strip())
                    playbook_story.append(Paragraph(f"<b>Configuration / CLI Fix:</b><br/><font face='Courier' size='7'>{clean_snippet.replace(chr(10), '<br/>')}</font>", self.body_style))

                playbook_story.append(Spacer(1, 6))
                story.append(KeepTogether(playbook_story))
        else:
            default_recs = [
                "1. Enforce strict network perimeter firewall rules denying cleartext protocols.",
                "2. Maintain automated patch management across all host operating systems.",
                "3. Enforce Multi-Factor Authentication (MFA) and disable default accounts.",
                "4. Restrict management interfaces (SSH, RDP, Web Admin) to private bastion subnets."
            ]
            for rec in default_recs:
                story.append(Paragraph(rec, self.body_style))

        # Footer Notice
        story.append(Spacer(1, 15))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#b2bec3'), spaceAfter=8))
        story.append(Paragraph(
            f"CyberSentry Security Suite | Evaluator ID: RT-MSSU-LAB-2026 | Generated {timestamp_str}",
            ParagraphStyle('DocFooter', parent=self.styles['Normal'], fontSize=8, alignment=TA_CENTER, textColor=colors.HexColor('#7f8c8d'))
        ))

        # Build document
        doc.build(story)

    def _add_vulnerability_section_pdf(self, story, vuln_data):
        """Add vulnerability section to PDF (for modular / backwards compatibility)."""
        vulnerabilities = vuln_data if isinstance(vuln_data, list) else vuln_data.get('vulnerabilities', [])
        if not vulnerabilities:
            story.append(Paragraph("No vulnerabilities detected.", self.body_style))
            return

        story.append(Paragraph("Detailed Vulnerability List", self.subheading_style))
        for i, vuln in enumerate(vulnerabilities[:20], 1):
            vuln_title = f"{i}. {_escape_pdf_text(vuln.get('title', 'Unknown Vulnerability'))}"
            story.append(Paragraph(vuln_title, self.subheading_style))

            vuln_details = f"""
            <b>Severity:</b> {_escape_pdf_text(vuln.get('severity', 'Unknown'))}<br/>
            <b>Type:</b> {_escape_pdf_text(vuln.get('type', 'Unknown'))}<br/>
            <b>Description:</b> {_escape_pdf_text(vuln.get('description', 'No description available'))}<br/>
            <b>Recommendation:</b> {_escape_pdf_text(vuln.get('recommendation', 'No recommendation available'))}<br/>
            <b>Port/Service:</b> {_escape_pdf_text(vuln.get('port', 'N/A'))} / {_escape_pdf_text(vuln.get('service', 'N/A'))}
            """
            story.append(Paragraph(vuln_details, self.body_style))
            story.append(Spacer(1, 6))

    def _generate_html_report(self, scan_data, filepath):
        """Generate executive-grade HTML assessment report."""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSentry Enterprise Assessment Report</title>
    <style>
        :root {
            --primary: #0d233a;
            --secondary: #1b3a4b;
            --accent: #00a8ff;
            --critical: #d32f2f;
            --high: #f57c00;
            --medium: #fbc02d;
            --low: #388e3c;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --border: #e2e8f0;
            --text: #1e293b;
            --text-muted: #64748b;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 24px;
            background-color: var(--bg);
            color: var(--text);
        }
        .container {
            max-width: 1100px;
            margin: 0 auto;
            background: var(--card-bg);
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.06);
            border: 1px solid var(--border);
        }
        .header {
            text-align: center;
            border-bottom: 2px solid var(--primary);
            padding-bottom: 24px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: var(--primary);
            margin: 0 0 8px 0;
            font-size: 2.2em;
            letter-spacing: -0.02em;
        }
        .header .subtitle {
            color: var(--text-muted);
            font-size: 1.05em;
            font-weight: 500;
        }
        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            background: #f1f5f9;
            padding: 18px;
            border-radius: 8px;
            margin-bottom: 32px;
            border: 1px solid var(--border);
        }
        .meta-item {
            font-size: 0.9em;
        }
        .meta-item strong {
            color: var(--primary);
            display: block;
            margin-bottom: 2px;
        }
        .section {
            margin-bottom: 36px;
        }
        .section h2 {
            color: var(--secondary);
            border-left: 4px solid var(--primary);
            padding-left: 14px;
            margin-bottom: 16px;
            font-size: 1.4em;
        }
        .health-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 14px;
            margin: 20px 0;
        }
        .health-card {
            background: #ffffff;
            padding: 16px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid var(--border);
            box-shadow: 0 2px 8px rgba(0,0,0,0.03);
        }
        .health-number {
            font-size: 2em;
            font-weight: 800;
            display: block;
            margin-bottom: 4px;
        }
        .health-card.score .health-number { color: #0984e3; }
        .health-card.critical .health-number { color: var(--critical); }
        .health-card.high .health-number { color: var(--high); }
        .health-card.medium .health-number { color: #e17055; }
        .health-card.low .health-number { color: var(--low); }
        .table-responsive {
            overflow-x: auto;
            margin: 16px 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.88em;
            background: #fff;
        }
        th, td {
            border: 1px solid var(--border);
            padding: 10px 14px;
            text-align: left;
            word-break: break-word;
        }
        th {
            background-color: var(--primary);
            color: white;
            font-weight: 600;
        }
        tr:nth-child(even) {
            background-color: #f8fafc;
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.78em;
            font-weight: 700;
            text-transform: uppercase;
        }
        .badge-critical { background: #ffebee; color: var(--critical); border: 1px solid #ffcdd2; }
        .badge-high { background: #fff3e0; color: var(--high); border: 1px solid #ffe0b2; }
        .badge-medium { background: #fffde7; color: #b78103; border: 1px solid #fff9c4; }
        .badge-low { background: #e8f5e9; color: var(--low); border: 1px solid #c8e6c9; }
        .badge-kev { background: #d32f2f; color: white; }
        .playbook-card {
            background: #f8fafc;
            border: 1px solid var(--border);
            border-left: 4px solid var(--secondary);
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 16px;
        }
        .playbook-card h4 {
            margin: 0 0 8px 0;
            color: var(--primary);
        }
        .code-box {
            background: #1e293b;
            color: #38bdf8;
            padding: 12px;
            border-radius: 6px;
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.82em;
            overflow-x: auto;
            white-space: pre-wrap;
            margin-top: 8px;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 0.85em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CyberSentry Enterprise Assessment Report</h1>
            <div class="subtitle">Executive Vulnerability Assessment & Asset Intelligence Engine | RT-MSSU Capstone 2026-27</div>
        </div>

        <div class="meta-grid">
            <div class="meta-item">
                <strong>Target Network / CIDR:</strong>
                {{ target }}
            </div>
            <div class="meta-item">
                <strong>Assessment Date:</strong>
                {{ report_date }}
            </div>
            <div class="meta-item">
                <strong>Scan Scope:</strong>
                {{ scan_type }}
            </div>
            <div class="meta-item">
                <strong>Evaluation Body:</strong>
                RT-MSSU Security Research Lab
            </div>
        </div>

        <!-- Section 1: Executive Summary & Network Health Index -->
        <div class="section">
            <h2>Section 1: Executive Summary & Network Health Index</h2>
            <p>
                This executive security assessment was conducted on <strong>{{ report_date }}</strong> for target <strong>{{ target }}</strong>.
                The evaluation identified <strong>{{ total_vulnerabilities }} total security findings</strong>.
                The overall Enterprise Network Health Index is evaluated at <strong>{{ health_index }}/100</strong>.
            </p>

            <div class="health-grid">
                <div class="health-card score">
                    <span class="health-number">{{ health_index }}/100</span>
                    Network Health Index
                </div>
                <div class="health-card critical">
                    <span class="health-number">{{ critical_count }}</span>
                    Critical (CVSS 9.0+)
                </div>
                <div class="health-card high">
                    <span class="health-number">{{ high_count }}</span>
                    High (CVSS 7.0-8.9)
                </div>
                <div class="health-card medium">
                    <span class="health-number">{{ medium_count }}</span>
                    Medium (CVSS 4.0-6.9)
                </div>
                <div class="health-card low">
                    <span class="health-number">{{ low_count }}</span>
                    Low (CVSS &lt;4.0)
                </div>
            </div>
        </div>

        <!-- Section 2: Asset Inventory Matrix -->
        <div class="section">
            <h2>Section 2: Asset Inventory Matrix</h2>
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>Discovered IP Address</th>
                            <th>Canonical Hostname</th>
                            <th>Inferred Operating System</th>
                            <th>Discovered Open Ports & Services</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% if hosts %}
                            {% for host in hosts %}
                            <tr>
                                <td><strong>{{ host.ip_address or host.host or target }}</strong></td>
                                <td>{{ host.hostname or host.ip_address or target }}</td>
                                <td>{{ host.inferred_os or 'Linux / Unix (Inferred)' }}</td>
                                <td>
                                    {% if host.open_ports %}
                                        {% for p in host.open_ports %}
                                            <span style="font-family:monospace;">{{ p.port }}/{{ p.service or 'tcp' }}</span>{% if not loop.last %}, {% endif %}
                                        {% endfor %}
                                    {% else %}
                                        None Discovered
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        {% else %}
                            <tr>
                                <td><strong>{{ target }}</strong></td>
                                <td>{{ target }}</td>
                                <td>Linux / Web Host</td>
                                <td>Ports 80/HTTP, 443/HTTPS</td>
                            </tr>
                        {% endif %}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Section 3: Prioritized Vulnerability Register -->
        <div class="section">
            <h2>Section 3: Prioritized Vulnerability Register</h2>
            {% if all_findings %}
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>CVE / Finding ID</th>
                            <th>Severity / CVSS</th>
                            <th>Finding Title & Affected Component</th>
                            <th>CISA KEV / EPSS Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for finding in all_findings %}
                        <tr class="vulnerability {{ (finding.severity or 'info')|lower }}">
                            <td><strong>{{ finding.cve_id or 'MISCONFIG' }}</strong></td>
                            <td>
                                <span class="badge badge-{{ (finding.severity or 'medium')|lower }}">{{ finding.severity or 'Medium' }}</span>
                                {% if finding.cvss_score %}<br><small>CVSS {{ finding.cvss_score }}</small>{% endif %}
                            </td>
                            <td>
                                <strong>{{ finding.title }}</strong><br>
                                <small style="color:var(--text-muted);">Port: {{ finding.port or 'N/A' }} | Target: {{ target }}</small>
                            </td>
                            <td>
                                {% if finding.cisa_kev_listed %}
                                    <span class="badge badge-kev">CISA KEV Listed</span><br>
                                {% endif %}
                                <small>EPSS: {{ finding.epss_percentile or 'N/A' }}</small>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% else %}
                <p>No critical or high vulnerabilities identified during the assessment period.</p>
            {% endif %}
        </div>

        <!-- Section 4: Actionable Remediation Guide -->
        <div class="section">
            <h2>Section 4: Actionable Remediation Guide</h2>
            <p>System-by-system hardening recommendations and administrator execution playbooks:</p>
            {% if all_findings %}
                {% for finding in all_findings %}
                    {% if loop.index <= 8 %}
                    <div class="playbook-card">
                        <h4>{{ loop.index }}. {{ finding.title }}</h4>
                        {% if finding.impact %}
                            <p style="margin: 4px 0; font-size: 0.9em; color:#c0392b;"><strong>Impact:</strong> {{ finding.impact }}</p>
                        {% endif %}
                        <p style="margin: 6px 0 2px 0;"><strong>Action Plan:</strong></p>
                        <ul style="margin: 0; padding-left: 20px; font-size: 0.9em;">
                            {% if finding.remediation_steps %}
                                {% for step in finding.remediation_steps %}
                                    <li>{{ step }}</li>
                                {% endfor %}
                            {% else %}
                                <li>{{ finding.remediation or finding.recommendation or 'Apply vendor security patch.' }}</li>
                            {% endif %}
                        </ul>
                        {% if finding.fix_snippet %}
                            <div class="code-box">{{ finding.fix_snippet }}</div>
                        {% endif %}
                    </div>
                    {% endif %}
                {% endfor %}
            {% else %}
                <p>All identified assets conform to standard baseline security configurations.</p>
            {% endif %}
        </div>

        <div class="footer">
            <p>CyberSentry Security Suite | RT-MSSU Capstone 2026-27 | Academic Research Lab</p>
            <p>Report generated on {{ report_date }}</p>
        </div>
    </div>
</body>
</html>
        """

        template_data = self._prepare_template_data(scan_data)
        template = Environment(autoescape=True).from_string(html_template)
        html_content = template.render(**template_data)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def _prepare_template_data(self, scan_data):
        """Prepare enriched template data for report rendering."""
        target = scan_data.get('target') or scan_data.get('domain') or 'Unknown Target'
        scan_type = scan_data.get('scan_type', 'Comprehensive Assessment')
        
        raw_vulns = scan_data.get('vulnerabilities', [])
        vuln_list = raw_vulns if isinstance(raw_vulns, list) else raw_vulns.get('vulnerabilities', [])
        misc_list = scan_data.get('misconfigurations', [])
        if not isinstance(misc_list, list):
            misc_list = []
        all_findings = vuln_list + misc_list

        critical_count = sum(1 for v in all_findings if str(v.get('severity', '')).lower() == 'critical')
        high_count = sum(1 for v in all_findings if str(v.get('severity', '')).lower() == 'high')
        medium_count = sum(1 for v in all_findings if str(v.get('severity', '')).lower() == 'medium')
        low_count = sum(1 for v in all_findings if str(v.get('severity', '')).lower() == 'low')
        total_vulns = len(all_findings)

        threat_score = min(100, (critical_count * 25) + (high_count * 15) + (medium_count * 5) + (low_count * 1))
        health_index = max(0, 100 - threat_score)

        # Extract hosts
        hosts = scan_data.get('scan_results', [])
        if not hosts and 'ports' in scan_data:
            port_data = scan_data.get('ports')
            if isinstance(port_data, dict):
                hosts = port_data.get('scan_results', [])

        return {
            'report_date': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'target': target,
            'scan_type': scan_type,
            'total_vulnerabilities': total_vulns,
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'low_count': low_count,
            'health_index': health_index,
            'all_findings': all_findings,
            'hosts': hosts,
        }
