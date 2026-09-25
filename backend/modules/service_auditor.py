"""
Insecure Service & Default Credential Auditor (service_auditor.py)

Performs passive and non-destructive security auditing for:
1. Cleartext services (Telnet 23, HTTP 80, FTP 21)
2. Anonymous authentication (FTP Anonymous login)
3. Exposed administrative & diagnostic interfaces (/.env, /admin, /phpmyadmin, /actuator/health)
4. Safe default credential probes for HTTP basic authentication with a strict safety cap (max 3 attempts).
"""

import logging
import socket
import ftplib
import requests
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Standard administrative endpoints to audit for exposure
ADMIN_ENDPOINTS = [
    {
        "path": "/.env",
        "title": "Exposed Environment Configuration File (/.env)",
        "severity": "Critical",
        "category": "Information Disclosure",
        "desc": "Application environment file containing secrets, API keys, or credentials is publicly accessible.",
        "remediation": "Block web server access to all hidden files (.env, .git) in web server configurations.",
        "impact": "Exposes database passwords, secret keys, and API credentials directly to unauthenticated external actors.",
        "remediation_steps": [
            "Configure web server rules to deny access to files starting with a dot (e.g., .env, .git).",
            "Move environment configuration files outside the public document root.",
            "Immediately rotate all database passwords, secret keys, and API tokens exposed in the .env file."
        ],
        "fix_snippet": "# Nginx configuration:\nlocation ~ /\\.(env|git) {\n    deny all;\n    return 404;\n}"
    },
    {
        "path": "/admin",
        "title": "Publicly Exposed Administrative Portal (/admin)",
        "severity": "High",
        "category": "Access Control",
        "desc": "Administrative interface is exposed to external untrusted networks.",
        "remediation": "Restrict administrative access to VPN, bastion hosts, or IP whitelist.",
        "impact": "Exposes administrative login portals to automated brute force attacks and privilege escalation exploits.",
        "remediation_steps": [
            "Configure IP access restrictions allowing only internal/VPN subnets to reach `/admin`.",
            "Enforce Multi-Factor Authentication (MFA) on all administrative accounts.",
            "Implement rate-limiting and WAF protection on administrative entry points."
        ],
        "fix_snippet": "# Nginx restrict admin endpoint:\nlocation /admin {\n    allow 10.0.0.0/8;\n    deny all;\n}"
    },
    {
        "path": "/phpmyadmin",
        "title": "Exposed Database Management Console (/phpmyadmin)",
        "severity": "High",
        "category": "Database Security",
        "desc": "phpMyAdmin web database interface is exposed to external traffic.",
        "remediation": "Disable external phpMyAdmin routing or require multi-factor authentication / VPN.",
        "impact": "Provides direct web database login access, making the system vulnerable to credential attacks and SQL injection.",
        "remediation_steps": [
            "Disable public web routing to phpMyAdmin.",
            "Change the default `/phpmyadmin` alias to a private or obscure path.",
            "Enforce IP whitelisting or tunnel phpMyAdmin via SSH port forwarding."
        ],
        "fix_snippet": "# Apache / Nginx disable phpmyadmin alias:\nsudo a2disconf phpmyadmin\nsudo systemctl reload apache2"
    },
    {
        "path": "/actuator/health",
        "title": "Exposed Spring Boot Actuator Endpoint (/actuator/health)",
        "severity": "Medium",
        "category": "Information Disclosure",
        "desc": "Internal application diagnostic and health actuator endpoints are accessible without authentication.",
        "remediation": "Configure management.endpoints.web.exposure.include to exclude unneeded actuator endpoints or require authentication.",
        "impact": "Reveals internal application architecture, runtime dependencies, and system health status.",
        "remediation_steps": [
            "Restrict Spring Boot actuator endpoint exposure in `application.properties`.",
            "Enforce Spring Security authentication on all `/actuator/**` routes."
        ],
        "fix_snippet": "# In application.properties:\nmanagement.endpoints.web.exposure.include=none\n# Or require authentication via Spring Security"
    },
    {
        "path": "/.git/config",
        "title": "Exposed Git Metadata Repository (/.git/config)",
        "severity": "Critical",
        "category": "Information Disclosure",
        "desc": "Git repository configuration is publicly exposed, allowing reconstruction of entire source code.",
        "remediation": "Deny all web requests matching ^/\\.git in web server directives.",
        "impact": "Attackers can download the entire git repository, extracting complete application source code, commit history, and hardcoded credentials.",
        "remediation_steps": [
            "Add a web server directive to block all requests targeting `/.git`.",
            "Remove `.git` directories from production web server deployment folders.",
            "Audit git logs and rotate any secrets that have ever been committed."
        ],
        "fix_snippet": "# Nginx:\nlocation ~ /\\.git {\n    deny all;\n    return 404;\n}"
    },
]

# Standard default test credentials (strictly capped at 3 attempts max to prevent lockouts)
SAFE_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("guest", "guest"),
    ("test", "test"),
]


class ServiceAuditor:
    """Audits network services for dangerous misconfigurations and default credentials."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def audit_target(self, target: str, open_ports: list = None) -> list:
        """Run all passive and non-destructive misconfiguration audits on target."""
        misconfigurations = []
        clean_host = target.replace("http://", "").replace("https://", "").partition("/")[0].partition(":")[0]

        # Extract port numbers from open_ports list if supplied
        open_port_nums = set()
        open_ports_provided = open_ports is not None
        if open_ports:
            for p in open_ports:
                if isinstance(p, dict) and 'port' in p:
                    try:
                        open_port_nums.add(int(p['port']))
                    except (ValueError, TypeError):
                        pass
                elif isinstance(p, (int, str)):
                    try:
                        open_port_nums.add(int(p))
                    except (ValueError, TypeError):
                        pass

        # 1. Cleartext service checks
        misconfigurations.extend(self._check_cleartext_services(clean_host, open_port_nums, open_ports_provided))

        # 2. Anonymous FTP check
        if (open_ports_provided and 21 in open_port_nums) or (not open_ports_provided and self._probe_port_open(clean_host, 21)):
            ftp_result = self._check_anonymous_ftp(clean_host)
            if ftp_result:
                misconfigurations.append(ftp_result)

        # 3. Exposed administrative & diagnostic interfaces
        has_web = any(p in open_port_nums for p in [80, 443, 8080, 8443]) or target.lower().startswith(("http://", "https://"))
        if has_web or (not open_ports_provided and (self._probe_port_open(clean_host, 80) or self._probe_port_open(clean_host, 443))):
            misconfigurations.extend(self._check_exposed_admin_interfaces(target, clean_host, open_port_nums))

        # 4. Safe HTTP Basic Auth default credential probe (max 3 attempts)
        if has_web or (not open_ports_provided and (self._probe_port_open(clean_host, 80) or self._probe_port_open(clean_host, 443))):
            misconfigurations.extend(self._check_default_basic_auth(target, clean_host, open_port_nums))

        return misconfigurations

    def _check_cleartext_services(self, host: str, open_port_nums: set, open_ports_provided: bool = False) -> list:
        """Check for cleartext services transmitting unencrypted data."""
        findings = []

        # Telnet (Port 23)
        if 23 in open_port_nums or (not open_ports_provided and self._probe_port_open(host, 23)):
            findings.append({
                "title": "Unencrypted Telnet Service (Port 23)",
                "category": "Cleartext Protocol",
                "severity": "Critical",
                "port": 23,
                "protocol": "telnet",
                "cisa_kev_listed": False,
                "cvss_score": 7.5,
                "description": "Telnet service transmits all authentication credentials and session data in plain text.",
                "remediation": "Disable Telnet and migrate exclusively to SSH (Port 22) with strong cryptographic keys.",
                "impact": "Network eavesdroppers can capture administrative passwords and execute arbitrary commands.",
                "remediation_steps": [
                    "Immediately stop and disable the Telnet systemd service.",
                    "Migrate all administrative access to OpenSSH (Port 22).",
                    "Block incoming port 23 traffic on host and perimeter firewalls."
                ],
                "fix_snippet": "sudo systemctl stop telnet.socket telnet.service\nsudo systemctl disable --now telnet.socket telnet.service\nsudo ufw deny 23/tcp"
            })

        # FTP (Port 21) Cleartext
        if 21 in open_port_nums or (not open_ports_provided and self._probe_port_open(host, 21)):
            findings.append({
                "title": "Unencrypted FTP Transmission (Port 21)",
                "category": "Cleartext Protocol",
                "severity": "Medium",
                "port": 21,
                "protocol": "ftp",
                "cisa_kev_listed": False,
                "cvss_score": 5.3,
                "description": "Standard FTP communicates in cleartext, exposing session credentials to network sniffing.",
                "remediation": "Enforce FTPS (FTP over TLS) or SFTP (SSH File Transfer Protocol).",
                "impact": "FTP username and password credentials are sent in cleartext across the network.",
                "remediation_steps": [
                    "Configure FTP daemon with TLS encryption (`ssl_enable=YES`).",
                    "Require explicit FTPS or transition to SSH File Transfer Protocol (SFTP).",
                    "Restart FTP daemon."
                ],
                "fix_snippet": "# In /etc/vsftpd.conf:\nssl_enable=YES\nallow_anon_ssl=NO\nforce_local_data_ssl=YES\nforce_local_logins_ssl=YES\nsudo systemctl restart vsftpd"
            })

        # HTTP (Port 80) without SSL
        if 80 in open_port_nums or (not open_ports_provided and self._probe_port_open(host, 80)):
            findings.append({
                "title": "Unencrypted HTTP Service (Port 80)",
                "category": "Cleartext Protocol",
                "severity": "Medium",
                "port": 80,
                "protocol": "http",
                "cisa_kev_listed": False,
                "cvss_score": 5.3,
                "description": "Web server serves plaintext HTTP traffic without mandatory HTTPS redirection.",
                "remediation": "Enforce HTTP to HTTPS redirection (Port 443) and implement HTTP Strict Transport Security (HSTS).",
                "impact": "Exposes website visitors to credential sniffing, cookie hijacking, and traffic tampering.",
                "remediation_steps": [
                    "Obtain a valid SSL/TLS certificate via Let's Encrypt / Certbot.",
                    "Configure web server to issue a 301 Permanent Redirect to HTTPS.",
                    "Add Strict-Transport-Security (HSTS) header to enforce HTTPS in client browsers."
                ],
                "fix_snippet": "# Nginx redirect HTTP to HTTPS:\nserver {\n    listen 80;\n    server_name _;\n    return 301 https://$host$request_uri;\n}"
            })

        return findings

    def _check_anonymous_ftp(self, host: str) -> dict:
        """Verify if FTP service allows unauthenticated Anonymous login."""
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, 21, timeout=self.timeout)
            ftp.login("anonymous", "anonymous@")
            ftp.quit()

            return {
                "title": "Anonymous FTP Login Allowed (Port 21)",
                "category": "Insecure Authentication",
                "severity": "High",
                "port": 21,
                "protocol": "ftp",
                "cisa_kev_listed": False,
                "cvss_score": 7.5,
                "description": "FTP server allows anonymous users to authenticate without valid credentials.",
                "remediation": "Disable anonymous FTP authentication in vsftpd / proftpd / IIS FTP server configuration.",
                "impact": "Allows anyone on the network to download confidential files or upload unauthorized payloads without logging in.",
                "remediation_steps": [
                    "Open `/etc/vsftpd.conf`.",
                    "Set `anonymous_enable=NO`.",
                    "Restart vsftpd service: `sudo systemctl restart vsftpd`."
                ],
                "fix_snippet": "sudo sed -i 's/anonymous_enable=YES/anonymous_enable=NO/g' /etc/vsftpd.conf\nsudo systemctl restart vsftpd"
            }
        except Exception:
            return None

    def _check_exposed_admin_interfaces(self, original_target: str, host: str, open_port_nums: set) -> list:
        """Probe for standard exposed administrative portals and sensitive files."""
        findings = []
        schemes_to_test = ["http", "https"] if original_target.startswith("http") else ["http", "https"]

        test_bases = []
        for scheme in schemes_to_test:
            test_bases.append(f"{scheme}://{host}")
            if 8080 in open_port_nums:
                test_bases.append(f"{scheme}://{host}:8080")
            if 8443 in open_port_nums:
                test_bases.append(f"{scheme}://{host}:8443")

        # Eliminate duplicate base URLs
        test_bases = list(dict.fromkeys(test_bases))

        for base_url in test_bases:
            for endpoint in ADMIN_ENDPOINTS:
                target_url = f"{base_url.rstrip('/')}{endpoint['path']}"
                try:
                    res = requests.get(
                        target_url,
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=False,
                        headers={"User-Agent": "CyberSentry-Security-Audit/1.0"}
                    )
                    # Check for successful exposure (200 OK or 206 Partial)
                    if res.status_code == 200 and len(res.text) > 0:
                        findings.append({
                            "title": endpoint["title"],
                            "category": endpoint["category"],
                            "severity": endpoint["severity"],
                            "port": 443 if base_url.startswith("https") else 80,
                            "protocol": "http",
                            "cisa_kev_listed": endpoint["severity"] == "Critical",
                            "cvss_score": 8.6 if endpoint["severity"] == "Critical" else 7.0,
                            "description": f"{endpoint['desc']} Located at: {target_url}",
                            "remediation": endpoint["remediation"],
                            "url": target_url,
                        })
                except requests.exceptions.RequestException:
                    continue

        return findings

    def _check_default_basic_auth(self, original_target: str, host: str, open_port_nums: set) -> list:
        """
        Non-destructive verification against standard test credentials (admin:admin, guest:guest)
        with a strict safety cap of 3 attempts maximum to avoid locking accounts.
        """
        findings = []
        target_url = original_target if original_target.startswith("http") else f"http://{host}"

        try:
            # First check if the endpoint actually challenges with HTTP 401 Basic Auth
            initial_res = requests.get(
                target_url,
                timeout=self.timeout,
                verify=False,
                headers={"User-Agent": "CyberSentry-Security-Audit/1.0"}
            )
            
            if initial_res.status_code == 401 and "basic" in initial_res.headers.get("WWW-Authenticate", "").lower():
                # Safe probe: strictly limit to SAFE_DEFAULT_CREDS (max 3 attempts)
                for username, password in SAFE_DEFAULT_CREDS[:3]:
                    try:
                        auth_res = requests.get(
                            target_url,
                            auth=(username, password),
                            timeout=self.timeout,
                            verify=False,
                            headers={"User-Agent": "CyberSentry-Security-Audit/1.0"}
                        )
                        if auth_res.status_code == 200:
                            findings.append({
                                "title": f"Default Credentials Accepted ({username}:{password})",
                                "category": "Default Credentials",
                                "severity": "Critical",
                                "port": 443 if target_url.startswith("https") else 80,
                                "protocol": "http-basic-auth",
                                "cisa_kev_listed": True,
                                "cvss_score": 9.8,
                                "description": f"HTTP Basic Authentication accepted standard default credentials '{username}:{password}' without account restrictions.",
                                "remediation": "Immediately replace default administrative passwords with strong, randomly generated credentials and enable MFA.",
                                "impact": "Allows unauthenticated remote attackers to gain full administrative privileges using standard credentials.",
                                "remediation_steps": [
                                    "Log into the target service and change the default administrative password immediately.",
                                    "Enforce high-entropy passwords (minimum 16 characters).",
                                    "Enable Multi-Factor Authentication (MFA) on all management portals.",
                                    "Disable or remove unused test/guest user accounts."
                                ],
                                "fix_snippet": "# Generate a secure random 24-character credential:\nopenssl rand -base64 24",
                                "url": target_url,
                            })
                            break  # Stop immediately on first verified match
                    except requests.exceptions.RequestException:
                        break
        except requests.exceptions.RequestException:
            pass

        return findings

    def _probe_port_open(self, host: str, port: int) -> bool:
        """Quick socket connection test to verify port state."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.35)
                return s.connect_ex((host, port)) == 0
        except OSError:
            return False
