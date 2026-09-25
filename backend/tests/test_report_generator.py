import unittest
import os
import shutil
import tempfile
from backend.modules.report_generator import ReportGenerator


class TestReportGenerator(unittest.TestCase):
    """Test suite for ReportGenerator (PDF/HTML generation and 4-section structure)."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        os.environ['REPORTS_DIR'] = self.test_dir
        self.report_gen = ReportGenerator()
        self.sample_scan_data = {
            'target': '10.0.0.0/24',
            'scan_type': 'comprehensive',
            'vulnerabilities': [
                {
                    'title': 'Apache Log4j RCE (Log4Shell)',
                    'cve_id': 'CVE-2021-44228',
                    'severity': 'Critical',
                    'cvss_score': 10.0,
                    'cisa_kev_listed': True,
                    'epss_percentile': '97th percentile',
                    'port': 8080,
                    'impact': 'Unauthenticated remote arbitrary code execution via JNDI expressions.',
                    'remediation_steps': ['Upgrade log4j to >= 2.17.1', 'Add -Dlog4j2.formatMsgNoLookups=true'],
                    'fix_snippet': 'export JAVA_OPTS="$JAVA_OPTS -Dlog4j2.formatMsgNoLookups=true"'
                }
            ],
            'misconfigurations': [
                {
                    'title': 'Exposed Environment Configuration File (/.env)',
                    'severity': 'Critical',
                    'cvss_score': 8.6,
                    'port': 80,
                    'impact': 'Exposes database passwords and API tokens.',
                    'remediation_steps': ['Deny web access to dotfiles', 'Rotate secrets'],
                    'fix_snippet': 'location ~ /\\.(env|git) { deny all; }'
                }
            ],
            'scan_results': [
                {
                    'ip_address': '10.0.0.15',
                    'hostname': 'app-server.corp.local',
                    'inferred_os': 'Ubuntu Linux 22.04 LTS',
                    'open_ports': [{'port': 80, 'service': 'http'}, {'port': 8080, 'service': 'http-alt'}]
                }
            ]
        }

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
        if 'REPORTS_DIR' in os.environ:
            del os.environ['REPORTS_DIR']

    def test_generate_pdf_report(self):
        """Verify executive PDF generation produces non-empty file with 4 sections."""
        pdf_path = self.report_gen.generate_report(self.sample_scan_data, 'pdf')
        self.assertTrue(os.path.exists(pdf_path))
        self.assertGreater(os.path.getsize(pdf_path), 2000)

    def test_generate_html_report(self):
        """Verify HTML report includes title, 4 sections, and RT-MSSU evaluator metadata."""
        html_path = self.report_gen.generate_report(self.sample_scan_data, 'html')
        self.assertTrue(os.path.exists(html_path))
        
        with open(html_path, 'r', encoding='utf-8') as f:
            content = f.read()

        self.assertIn("CyberSentry Enterprise Assessment Report", content)
        self.assertIn("Section 1: Executive Summary & Network Health Index", content)
        self.assertIn("Section 2: Asset Inventory Matrix", content)
        self.assertIn("Section 3: Prioritized Vulnerability Register", content)
        self.assertIn("Section 4: Actionable Remediation Guide", content)
        self.assertIn("RT-MSSU", content)
        self.assertIn("10.0.0.0/24", content)
        self.assertIn("CVE-2021-44228", content)


if __name__ == '__main__':
    unittest.main()
