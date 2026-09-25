import unittest
from unittest.mock import MagicMock, patch
import app as application
from modules.scanner import VulnScanner
from modules.vuln_engine import enrich_vulnerability, enrich_vulnerabilities


class TestUnifiedScanPipeline(unittest.TestCase):
    def setUp(self):
        self.client = application.app.test_client()

    def test_unified_scan_endpoint_returns_complete_dataset(self):
        """Verify /api/scan executes all modules and outputs unified dataset."""
        with patch.object(application.recon_module, 'find_subdomains', return_value={
            'domain': 'mssu.ac.in',
            'subdomains': ['portal.mssu.ac.in', 'mail.mssu.ac.in'],
            'total_found': 2
        }), patch.object(application.recon_module, 'port_scan', return_value={
            'target': 'mssu.ac.in',
            'total_open_ports': 2,
            'scan_results': [{
                'host': 'mssu.ac.in',
                'ip_address': '10.0.0.1',
                'hostname': 'mssu.ac.in',
                'alive': True,
                'open_ports': [
                    {'port': 80, 'service': 'http', 'product': 'nginx/1.24.0', 'state': 'open'},
                    {'port': 443, 'service': 'https', 'product': 'nginx/1.24.0', 'state': 'open'}
                ]
            }]
        }), patch.object(application.vuln_scanner, 'scan_target', return_value={
            'target': 'mssu.ac.in',
            'scan_type': 'comprehensive',
            'vulnerabilities': [
                {
                    'title': 'Missing Content-Security-Policy (CSP)',
                    'severity': 'Medium',
                    'cwe_id': 'CWE-693',
                    'cvss_score': 6.5,
                    'port': '443'
                }
            ],
            'misconfigurations': [],
            'total_vulnerabilities': 1,
            'severity_breakdown': {'Critical': 0, 'High': 0, 'Medium': 1, 'Low': 0}
        }), patch.object(application.ai_assistant, 'analyze_comprehensive_scan', return_value={
            'summary': 'Unified security assessment complete',
            'overall_risk': 'Medium'
        }):
            response = self.client.post('/api/scan', json={'target': 'mssu.ac.in'})
            self.assertEqual(response.status_code, 200)
            data = response.get_json()

            self.assertEqual(data['target'], 'mssu.ac.in')
            self.assertEqual(data['scan_type'], 'unified')
            self.assertEqual(len(data['subdomains']), 2)
            self.assertEqual(data['total_open_ports'], 2)
            self.assertEqual(data['total_vulnerabilities'], 1)
            self.assertEqual(data['vulnerabilities'][0]['title'], 'Missing Content-Security-Policy (CSP)')
            self.assertIn('ai_analysis', data)

    def test_web_security_headers_produce_concrete_findings(self):
        """Verify web header audit extracts missing CSP, HSTS, X-Frame-Options as findings."""
        scanner = VulnScanner()
        mock_response = MagicMock()
        mock_response.headers = {'Server': 'nginx/1.24.0'}  # Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options

        findings = scanner._check_security_headers('http://example.com', mock_response)
        enriched = enrich_vulnerabilities(findings)

        titles = [f['title'] for f in enriched]
        self.assertTrue(any('Content-Security-Policy' in t for t in titles))
        self.assertTrue(any('Strict-Transport-Security' in t or 'HSTS' in t for t in titles))
        self.assertTrue(any('X-Frame-Options' in t or 'Clickjacking' in t for t in titles))
        self.assertTrue(all(f.get('cvss_score') is not None for f in enriched))
        self.assertTrue(all(len(f.get('remediation_steps', [])) > 0 for f in enriched))

    def test_sensitive_endpoint_probing(self):
        """Verify sensitive endpoint probe recognizes robots.txt and exposed .env."""
        scanner = VulnScanner()
        
        with patch('modules.scanner.requests.get') as mock_get:
            def side_effect(url, **kwargs):
                resp = MagicMock()
                if 'robots.txt' in url:
                    resp.status_code = 200
                    resp.text = 'User-agent: *\nDisallow: /admin/'
                    return resp
                elif '.env' in url:
                    resp.status_code = 200
                    resp.text = 'DB_PASSWORD=supersecret\nAPP_KEY=123'
                    return resp
                else:
                    resp.status_code = 404
                    resp.text = 'Not found'
                    return resp

            mock_get.side_effect = side_effect
            findings = scanner._check_common_files('http://example.com')
            enriched = enrich_vulnerabilities(findings)

            self.assertTrue(any('robots.txt' in f['title'].lower() for f in enriched))
            self.assertTrue(any('.env' in f['title'].lower() for f in enriched))
            env_finding = next(f for f in enriched if '.env' in f['title'].lower())
            self.assertEqual(env_finding['severity'], 'Critical')


if __name__ == '__main__':
    unittest.main()
