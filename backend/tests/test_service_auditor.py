import unittest
from unittest.mock import patch, MagicMock
import ftplib
import requests

from backend.modules.service_auditor import ServiceAuditor, SAFE_DEFAULT_CREDS, ADMIN_ENDPOINTS


class TestServiceAuditor(unittest.TestCase):
    """Test suite for Insecure Service & Default Credential Auditor."""

    def setUp(self):
        self.auditor = ServiceAuditor(timeout=1)

    def test_cleartext_service_detection(self):
        """Verify Telnet 23, FTP 21, and HTTP 80 trigger cleartext findings."""
        open_ports = [{'port': 23, 'service': 'telnet'}, {'port': 21, 'service': 'ftp'}, {'port': 80, 'service': 'http'}]
        findings = self.auditor._check_cleartext_services("127.0.0.1", {23, 21, 80})
        
        ports = [f['port'] for f in findings]
        self.assertIn(23, ports)
        self.assertIn(21, ports)
        self.assertIn(80, ports)
        self.assertTrue(any("Telnet" in f['title'] for f in findings))
        self.assertTrue(any("FTP" in f['title'] for f in findings))
        self.assertTrue(any("HTTP" in f['title'] for f in findings))

    @patch('ftplib.FTP')
    def test_anonymous_ftp_detected(self, mock_ftp_cls):
        """Verify Anonymous FTP login succeeds and creates a finding."""
        mock_ftp = MagicMock()
        mock_ftp_cls.return_value = mock_ftp
        mock_ftp.connect.return_value = "Connected"
        mock_ftp.login.return_value = "230 Anonymous user logged in"

        finding = self.auditor._check_anonymous_ftp("192.168.1.50")
        self.assertIsNotNone(finding)
        self.assertEqual(finding['title'], "Anonymous FTP Login Allowed (Port 21)")
        self.assertEqual(finding['port'], 21)
        self.assertEqual(finding['severity'], "High")

    @patch('ftplib.FTP')
    def test_anonymous_ftp_rejected(self, mock_ftp_cls):
        """Verify rejected FTP login returns None."""
        mock_ftp = MagicMock()
        mock_ftp_cls.return_value = mock_ftp
        mock_ftp.login.side_effect = ftplib.error_perm("530 Login incorrect")

        finding = self.auditor._check_anonymous_ftp("192.168.1.50")
        self.assertIsNone(finding)

    @patch('requests.get')
    def test_exposed_admin_interfaces_detected(self, mock_get):
        """Verify detection of exposed /.env, /admin, /phpmyadmin, /actuator/health."""
        def side_effect(url, **kwargs):
            mock_res = MagicMock()
            if "/.env" in url:
                mock_res.status_code = 200
                mock_res.text = "DB_PASSWORD=secret"
            elif "/actuator/health" in url:
                mock_res.status_code = 200
                mock_res.text = '{"status":"UP"}'
            else:
                mock_res.status_code = 404
                mock_res.text = ""
            return mock_res

        mock_get.side_effect = side_effect
        findings = self.auditor._check_exposed_admin_interfaces("http://127.0.0.1", "127.0.0.1", {80})
        
        titles = [f['title'] for f in findings]
        self.assertTrue(any("/.env" in t for t in titles))
        self.assertTrue(any("/actuator/health" in t for t in titles))

    @patch('requests.get')
    def test_default_credential_probe_safety_cap(self, mock_get):
        """Verify default credential probe is capped at 3 attempts maximum."""
        call_count = 0

        def side_effect(url, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_res = MagicMock()
            if "auth" not in kwargs:
                # Challenge with HTTP 401 Basic
                mock_res.status_code = 401
                mock_res.headers = {"WWW-Authenticate": "Basic realm=\"Access\""}
            else:
                auth = kwargs["auth"]
                if auth == ("admin", "admin"):
                    mock_res.status_code = 200
                    mock_res.text = "Welcome admin"
                else:
                    mock_res.status_code = 401
                    mock_res.text = "Unauthorized"
            return mock_res

        mock_get.side_effect = side_effect
        findings = self.auditor._check_default_basic_auth("http://127.0.0.1", "127.0.0.1", {80})
        
        self.assertEqual(len(findings), 1)
        self.assertIn("admin:admin", findings[0]['title'])
        # Safety cap check: Initial challenge + at most 3 auth attempts = max 4 requests
        self.assertLessEqual(call_count, 4)


if __name__ == '__main__':
    unittest.main()
