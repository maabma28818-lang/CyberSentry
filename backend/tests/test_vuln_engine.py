import unittest
from backend.modules.vuln_engine import enrich_vulnerability, enrich_vulnerabilities, CISA_KEV_CATALOG


class TestVulnEnginePlaybooks(unittest.TestCase):
    """Test suite for Vulnerability Engine Remediation Playbooks and Threat Intelligence."""

    def test_cve_remediation_mapping(self):
        """Verify known CVEs map to specific impact, step-by-step instructions, and fix snippets."""
        vuln = {"title": "Apache Log4j RCE", "cve_id": "CVE-2021-44228"}
        enriched = enrich_vulnerability(vuln)

        self.assertEqual(enriched["cvss_score"], 10.0)
        self.assertTrue(enriched["cisa_kev_listed"])
        self.assertEqual(enriched["severity"], "Critical")
        self.assertIn("JNDI", enriched["impact"])
        self.assertTrue(len(enriched["remediation_steps"]) >= 3)
        self.assertIn("-Dlog4j2.formatMsgNoLookups=true", enriched["fix_snippet"])

    def test_ssh_regresshion_remediation_mapping(self):
        """Verify OpenSSH / regreSSHion mapping."""
        vuln = {"title": "OpenSSH Signal Handler Race Condition", "service": "ssh", "port": 22}
        enriched = enrich_vulnerability(vuln)

        self.assertEqual(enriched["cve_id"], "CVE-2024-6387")
        self.assertIn("root privileges", enriched["impact"])
        self.assertTrue(any("LoginGraceTime 0" in step for step in enriched["remediation_steps"]))
        self.assertIn("openssh-server", enriched["fix_snippet"])

    def test_anonymous_ftp_remediation(self):
        """Verify Anonymous FTP mapping produces vsftpd disable commands."""
        vuln = {"title": "Anonymous FTP Access", "service": "ftp", "port": 21}
        enriched = enrich_vulnerability(vuln)

        self.assertIn("without credentials", enriched["impact"])
        self.assertTrue(any("anonymous_enable=NO" in step for step in enriched["remediation_steps"]))
        self.assertIn("anonymous_enable=NO", enriched["fix_snippet"])

    def test_missing_headers_remediation(self):
        """Verify missing security headers mapping produces Nginx/HSTS configuration."""
        vuln = {"title": "Missing Security Headers", "service": "http", "port": 80}
        enriched = enrich_vulnerability(vuln)

        self.assertIn("Clickjacking", enriched["impact"])
        self.assertTrue(any("Strict-Transport-Security" in step for step in enriched["remediation_steps"]))
        self.assertIn("Strict-Transport-Security", enriched["fix_snippet"])

    def test_fallback_playbook_generation(self):
        """Verify unrecognized vulnerabilities receive a structured fallback playbook."""
        vuln = {"title": "Custom Application Buffer Anomaly", "port": 9000, "service": "custom-rpc"}
        enriched = enrich_vulnerability(vuln)

        self.assertIsNotNone(enriched["impact"])
        self.assertTrue(len(enriched["remediation_steps"]) >= 3)
        self.assertIn("9000", enriched["fix_snippet"])


if __name__ == "__main__":
    unittest.main()
