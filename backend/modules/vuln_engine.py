"""
Vulnerability Engine (vuln_engine.py) - Exploit-Aware Scoring & Threat Intelligence.

Enriches vulnerability findings with:
- Common Vulnerability Scoring System (CVSS v3.1 base score: 0.0 to 10.0 & Vector String)
- Common Weakness Enumeration (CWE) classification
- CISA Known Exploited Vulnerabilities (KEV) Catalog matching
- Exploit Prediction Scoring System (EPSS) probability percentile
- Unified risk severity calculation:
    * CRITICAL: CVSS >= 9.0 or CISA KEV Active Exploit in the Wild
    * HIGH:     CVSS 7.0 - 8.9
    * MEDIUM:   CVSS 4.0 - 6.9
    * LOW:      CVSS < 4.0
"""

import re
import logging

logger = logging.getLogger(__name__)

# Curated offline database of CISA Known Exploited Vulnerabilities (KEV) & high-impact CVEs
CISA_KEV_CATALOG = {
    "CVE-2021-44228": {
        "title": "Apache Log4j Remote Code Execution (Log4Shell)",
        "cwe": "CWE-502",
        "cvss": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "epss": 0.97,
        "kev": True,
        "service": "log4j",
        "impact": "Unauthenticated remote attackers can execute arbitrary code on the target server via JNDI lookup expressions.",
        "remediation_steps": [
            "Upgrade log4j-core library to version 2.17.1 or newer across all application modules.",
            "As an interim mitigation, add -Dlog4j2.formatMsgNoLookups=true to JVM launch parameters.",
            "Remove the JndiLookup class from the classpath: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class",
            "Restart affected Java services and verify logs."
        ],
        "fix_snippet": "# Upgrade Maven dependency in pom.xml to >= 2.17.1\n# Or apply JVM runtime mitigation:\nexport JAVA_OPTS=\"$JAVA_OPTS -Dlog4j2.formatMsgNoLookups=true\""
    },
    "CVE-2022-22965": {
        "title": "Spring Framework RCE (Spring4Shell)",
        "cwe": "CWE-94",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": 0.94,
        "kev": True,
        "service": "spring",
        "impact": "Remote code execution through DataBinder parameter binding on Tomcat WAR deployments.",
        "remediation_steps": [
            "Upgrade Spring Framework to version >= 5.3.18 or >= 5.2.20.",
            "Upgrade Spring Boot dependencies to >= 2.6.6 or >= 2.5.12.",
            "Rebuild and redeploy application artifacts."
        ],
        "fix_snippet": "# Upgrade Spring Boot in build.gradle / pom.xml:\n# <version>2.6.6</version> or higher"
    },
    "CVE-2017-0144": {
        "title": "Microsoft SMBv1 Remote Code Execution (EternalBlue)",
        "cwe": "CWE-119",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": 0.97,
        "kev": True,
        "service": "smb",
        "impact": "Allows remote unauthenticated attackers to execute arbitrary code and spread lateral malware across the subnet.",
        "remediation_steps": [
            "Disable legacy SMBv1 protocol on all Windows workstations and servers.",
            "Apply Microsoft security bulletin MS17-010.",
            "Block inbound Port 445 on the network perimeter and boundary firewalls."
        ],
        "fix_snippet": "# PowerShell command to disable SMBv1\nDisable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol\nSet-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
    },
    "CVE-2019-0708": {
        "title": "Microsoft RDP Remote Code Execution (BlueKeep)",
        "cwe": "CWE-416",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": 0.92,
        "kev": True,
        "service": "rdp",
        "impact": "Unauthenticated pre-auth remote code execution in Remote Desktop Services, allowing self-propagating worm attacks.",
        "remediation_steps": [
            "Install Microsoft security update KB4499175 / KB4499160.",
            "Enforce Network Level Authentication (NLA) on all RDP-enabled hosts.",
            "Restrict Port 3389 access behind a secure VPN gateway."
        ],
        "fix_snippet": "# Enforce Network Level Authentication (NLA) via PowerShell\n(Get-WmiObject -class \"Win32_TSGeneralSetting\" -Namespace \"root\\cimv2\\terminalservices\").SetUserAuthenticationRequired(1)"
    },
    "CVE-2021-26855": {
        "title": "Microsoft Exchange Server SSRF (ProxyLogon)",
        "cwe": "CWE-918",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": 0.96,
        "kev": True,
        "service": "exchange",
        "impact": "Enables remote unauthenticated attackers to bypass authentication and execute code as SYSTEM on Exchange servers.",
        "remediation_steps": [
            "Install the latest Microsoft Exchange Server Cumulative Update (CU) and Security Update (SU).",
            "Run Microsoft Exchange On-Premises Mitigation Tool (EOMT) to detect active indicators of compromise.",
            "Restrict external HTTPS access to Exchange admin and OWA endpoints."
        ],
        "fix_snippet": "# Check Exchange Security Update version via PowerShell\nGet-ExchangeServer | Format-List Name,Edition,AdminDisplayVersion"
    },
    "CVE-2021-34473": {
        "title": "Microsoft Exchange Remote Code Execution (ProxyShell)",
        "cwe": "CWE-94",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": 0.95,
        "kev": True,
        "service": "exchange",
        "impact": "Remote code execution chain permitting full takeover of Microsoft Exchange mail environments.",
        "remediation_steps": [
            "Apply Microsoft security patch KB5003435 immediately.",
            "Block incoming external traffic to PowerShell virtual directory `/autodiscover/autodiscover.json`."
        ],
        "fix_snippet": "# Block external unauthenticated PowerShell remoting in IIS"
    },
    "CVE-2021-41773": {
        "title": "Apache HTTP Server Path Traversal & File Disclosure",
        "cwe": "CWE-22",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "epss": 0.96,
        "kev": True,
        "service": "http",
        "impact": "Path traversal flaw permitting unauthenticated attackers to read sensitive files outside web document root.",
        "remediation_steps": [
            "Upgrade Apache HTTP Server to version >= 2.4.51.",
            "Configure `<Directory />` directive with `Require all denied` in `httpd.conf`.",
            "Restart Apache service: `sudo systemctl restart apache2`."
        ],
        "fix_snippet": "# In Apache httpd.conf / apache2.conf:\n<Directory />\n    AllowOverride none\n    Require all denied\n</Directory>\nsudo systemctl restart apache2"
    },
    "CVE-2022-26134": {
        "title": "Atlassian Confluence OGNL Injection RCE",
        "cwe": "CWE-917",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": 0.97,
        "kev": True,
        "service": "confluence",
        "impact": "Unauthenticated remote code execution in Confluence Server and Data Center instances.",
        "remediation_steps": [
            "Upgrade Confluence to version >= 7.18.1, 7.17.4, 7.16.5, or 7.15.3.",
            "Apply Atlassian security workaround files to xwork-1.0.3.6.jar."
        ],
        "fix_snippet": "# Confluence upgrade command\nsudo systemctl stop confluence\n# Install latest LTS release from Atlassian repository"
    },
    "CVE-2023-3519": {
        "title": "Citrix ADC / NetScaler Unauthenticated Remote Code Execution",
        "cwe": "CWE-119",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": 0.96,
        "kev": True,
        "service": "citrix",
        "impact": "Unauthenticated remote arbitrary code execution on Citrix ADC appliance.",
        "remediation_steps": [
            "Apply Citrix firmware updates: NetScaler ADC and Gateway 13.1-49.13+ or 14.1-8.50+.",
            "Review access logs for unauthorized bash shell invocations."
        ],
        "fix_snippet": "# Update NetScaler firmware via CLI:\ninstallns"
    },
    "CVE-2022-40684": {
        "title": "Fortinet FortiOS Authentication Bypass",
        "cwe": "CWE-287",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": 0.95,
        "kev": True,
        "service": "fortios",
        "impact": "Enables remote attackers to execute administration operations on FortiOS / FortiProxy via crafted requests.",
        "remediation_steps": [
            "Upgrade FortiOS to 7.0.7+ or 7.2.2+.",
            "Disable HTTP/HTTPS administrative interface on public internet-facing ports."
        ],
        "fix_snippet": "# Disable WAN admin access in FortiOS CLI:\nconfig system interface\nedit \"wan1\"\nset allowaccess ping ssh\nend"
    },
    "CVE-2014-0160": {
        "title": "OpenSSL TLS Heartbeat Information Disclosure (Heartbleed)",
        "cwe": "CWE-125",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "epss": 0.89,
        "kev": True,
        "service": "ssl",
        "impact": "Allows remote attackers to read memory chunks containing private keys, passwords, and session tokens.",
        "remediation_steps": [
            "Upgrade OpenSSL package to version >= 1.0.1g or latest OS security release.",
            "Revoke and re-issue all SSL/TLS private keys and certificates that were exposed.",
            "Restart web servers and background daemons using OpenSSL."
        ],
        "fix_snippet": "sudo apt update && sudo apt install --only-upgrade openssl libssl-dev -y\nsudo systemctl restart nginx apache2"
    },
    "CVE-2023-24488": {
        "title": "Citrix Gateway Cross-Site Scripting / Parameter Injection",
        "cwe": "CWE-79",
        "cvss": 7.2,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "epss": 0.84,
        "kev": True,
        "service": "web",
        "impact": "Allows attackers to execute scripts in client browsers and steal active session cookies.",
        "remediation_steps": [
            "Update Citrix ADC / Gateway to patched firmware versions.",
            "Enforce Content-Security-Policy headers."
        ],
        "fix_snippet": "# Enforce CSP header in reverse proxy config:\nadd_header Content-Security-Policy \"default-src 'self';\" always;"
    },
    "CVE-2024-6387": {
        "title": "OpenSSH Signal Handler Race Condition (regreSSHion)",
        "cwe": "CWE-362",
        "cvss": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": 0.72,
        "kev": False,
        "service": "ssh",
        "impact": "Signal handler race condition in OpenSSH server on Linux glibc systems allowing unauthenticated remote code execution as root.",
        "remediation_steps": [
            "Upgrade OpenSSH to version >= 9.8p1 via distribution package manager.",
            "As an interim mitigation, set `LoginGraceTime 0` in `/etc/ssh/sshd_config` (prevents race condition, but may expose to DoS).",
            "Restrict SSH port 22 access to trusted management IP subnets.",
            "Restart sshd service: `sudo systemctl restart ssh`."
        ],
        "fix_snippet": "sudo apt update && sudo apt install --only-upgrade openssh-server -y\nsudo systemctl restart ssh"
    },
}

# Heuristic vulnerability signatures mapping to CVSS, KEV, EPSS, CWE, impact, and remediation playbooks
VULN_SIGNATURE_RULES = [
    {
        "pattern": r"(log4j|log4shell)",
        "cve": "CVE-2021-44228",
        "cwe": "CWE-502",
        "base_cvss": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "epss": 0.97,
        "kev": True,
        "desc": "Apache Log4j Remote Code Execution.",
        "impact": "Allows unauthenticated remote attackers to execute arbitrary code via JNDI lookup strings.",
        "remediation_steps": [
            "Upgrade Log4j to version >= 2.17.1 across all application modules.",
            "Set -Dlog4j2.formatMsgNoLookups=true in JVM launch parameters.",
            "Restart application services and review execution logs."
        ],
        "fix_snippet": "export JAVA_OPTS=\"$JAVA_OPTS -Dlog4j2.formatMsgNoLookups=true\""
    },
    {
        "pattern": r"(spring4shell|spring framework rce)",
        "cve": "CVE-2022-22965",
        "cwe": "CWE-94",
        "base_cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": 0.94,
        "kev": True,
        "desc": "Spring Framework Remote Code Execution.",
        "impact": "Permits unauthenticated remote code execution via DataBinder parameter binding.",
        "remediation_steps": [
            "Upgrade Spring Framework to version >= 5.3.18 or >= 5.2.20.",
            "Upgrade Spring Boot to >= 2.6.6 or >= 2.5.12.",
            "Rebuild and redeploy application artifacts."
        ],
        "fix_snippet": "# Maven dependency update:\n<version>5.3.18</version>"
    },
    {
        "pattern": r"(heartbleed|tls heartbeat)",
        "cve": "CVE-2014-0160",
        "cwe": "CWE-125",
        "base_cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "epss": 0.89,
        "kev": True,
        "desc": "OpenSSL Heartbleed TLS information disclosure.",
        "impact": "Allows remote attackers to read memory chunks containing private keys, passwords, and session tokens.",
        "remediation_steps": [
            "Upgrade OpenSSL to the latest OS security patch.",
            "Revoke and regenerate SSL/TLS certificates and private keys.",
            "Restart all services using OpenSSL."
        ],
        "fix_snippet": "sudo apt update && sudo apt install --only-upgrade openssl libssl-dev -y"
    },
    {
        "pattern": r"(openssh|regresshion|ssh vulnerability|ssh.*weak)",
        "cve": "CVE-2024-6387",
        "cwe": "CWE-362",
        "base_cvss": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": 0.72,
        "kev": False,
        "desc": "OpenSSH Server signal handler race condition (regreSSHion) or weak algorithm configuration.",
        "impact": "Unauthenticated remote attackers can trigger race conditions to execute arbitrary code with root privileges or compromise session cryptography.",
        "remediation_steps": [
            "Upgrade OpenSSH server to version >= 9.8p1 via distribution package manager.",
            "As an interim mitigation, set `LoginGraceTime 0` in `/etc/ssh/sshd_config`.",
            "Disable root login over SSH (`PermitRootLogin no`) and enforce SSH key authentication.",
            "Restart sshd service: `sudo systemctl restart ssh`."
        ],
        "fix_snippet": "sudo apt update && sudo apt install --only-upgrade openssh-server -y\nsudo systemctl restart ssh"
    },
    {
        "pattern": r"(proxylogon|proxyshell)",
        "cve": "CVE-2021-26855",
        "cwe": "CWE-918",
        "base_cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": 0.96,
        "kev": True,
        "desc": "Microsoft Exchange Server Pre-Auth RCE / SSRF.",
        "impact": "Allows remote unauthenticated attackers to execute commands as SYSTEM on Exchange servers.",
        "remediation_steps": [
            "Install latest Microsoft Exchange Security Updates (KB5003435).",
            "Block external access to PowerShell and OWA backend routes."
        ],
        "fix_snippet": "# Apply latest Microsoft Exchange Cumulative Update"
    },
    {
        "pattern": r"(\.env|\.git/config|\.git/head|config\.php|backup/|sensitive files|admin/)",
        "cve": "CVE-2021-41773",
        "cwe": "CWE-538",
        "base_cvss": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "epss": 0.88,
        "kev": True,
        "desc": "Sensitive administrative/configuration files publicly accessible.",
        "impact": "Exposes database passwords, API credentials, secret keys, or administrative panels to unauthorized public users.",
        "remediation_steps": [
            "Deny public HTTP access to all hidden files (`^/\\.`) and configuration directories in web server configs.",
            "Restrict `/admin` and management endpoints to private IP ranges or VPN bastions.",
            "Immediately rotate all database passwords and API tokens found in exposed `.env` files.",
            "Reload web server daemon."
        ],
        "fix_snippet": "# Nginx: Block hidden files and admin exposure\nlocation ~ /\\.(env|git) {\n    deny all;\n    return 404;\n}\nlocation /admin {\n    allow 10.0.0.0/8;\n    deny all;\n}"
    },
    {
        "pattern": r"(sql injection|sqli)",
        "cve": "CVE-2022-22965",
        "cwe": "CWE-89",
        "base_cvss": 9.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": 0.91,
        "kev": True,
        "desc": "SQL Injection vulnerability permitting unauthorized data access or RCE.",
        "impact": "Attackers can bypass authentication, read or modify database contents, and potentially achieve operating system code execution.",
        "remediation_steps": [
            "Convert all dynamic SQL queries into Parameterized Queries or Prepared Statements.",
            "Use an Object Relational Mapper (ORM) with automated input escaping.",
            "Apply principle of least privilege to database user accounts.",
            "Deploy a Web Application Firewall (WAF) to filter malicious SQL syntax."
        ],
        "fix_snippet": "# Python Parameterized Query Example:\ncursor.execute(\"SELECT * FROM users WHERE username = %s\", (username,))"
    },
    {
        "pattern": r"(cross-site scripting|reflected xss|xss)",
        "cve": "CVE-2023-24488",
        "cwe": "CWE-79",
        "base_cvss": 7.2,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "epss": 0.84,
        "kev": True,
        "desc": "Cross-Site Scripting vulnerability enabling script execution in client session.",
        "impact": "Allows attackers to execute malicious JavaScript in user sessions, hijacking session cookies and performing unauthorized actions.",
        "remediation_steps": [
            "Implement contextual HTML and JavaScript output encoding before rendering user input.",
            "Enforce Content Security Policy (CSP) with `script-src 'self'`.",
            "Set `HttpOnly` and `Secure` flags on all session cookies."
        ],
        "fix_snippet": "# Nginx: Set Content Security Policy Header\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self';\" always;\nadd_header Set-Cookie \"Path=/; Secure; HttpOnly; SameSite=Strict\";"
    },
    {
        "pattern": r"(bluekeep|3389.*rdp|rdp.*brute|remote desktop.*exposed)",
        "cve": "CVE-2019-0708",
        "cwe": "CWE-287",
        "base_cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": 0.92,
        "kev": True,
        "desc": "Remote Desktop Protocol service exposed with potential RCE or brute-force exposure.",
        "impact": "Exposes Windows hosts to brute-force credential stuffing and unauthenticated pre-auth code execution.",
        "remediation_steps": [
            "Enforce Network Level Authentication (NLA) on the host.",
            "Place Remote Desktop Services behind a secure VPN gateway or RD Gateway.",
            "Apply Microsoft security patch KB4499175.",
            "Implement Account Lockout policies for repeated failed RDP login attempts."
        ],
        "fix_snippet": "# PowerShell command to enforce NLA:\n(Get-WmiObject -class \"Win32_TSGeneralSetting\" -Namespace \"root\\cimv2\\terminalservices\").SetUserAuthenticationRequired(1)"
    },
    {
        "pattern": r"(anonymous ftp|ftp.*anonymous)",
        "cve": None,
        "cwe": "CWE-287",
        "base_cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "epss": 0.45,
        "kev": False,
        "desc": "Anonymous FTP login enabled allowing unauthenticated read/write access.",
        "impact": "Allows unauthenticated remote attackers to read sensitive company files or upload unauthorized payloads without credentials.",
        "remediation_steps": [
            "Edit FTP daemon configuration file (`/etc/vsftpd.conf` or `/etc/proftpd/proftpd.conf`).",
            "Set `anonymous_enable=NO` to disable unauthenticated anonymous access.",
            "Enforce TLS encryption (`ssl_enable=YES`) for all authenticated sessions.",
            "Restart FTP service: `sudo systemctl restart vsftpd`."
        ],
        "fix_snippet": "sudo sed -i 's/anonymous_enable=YES/anonymous_enable=NO/g' /etc/vsftpd.conf\nsudo systemctl restart vsftpd"
    },
    {
        "pattern": r"(unencrypted services|telnet.*unencrypted|ftp.*unencrypted|cleartext protocol|cleartext)",
        "cve": None,
        "cwe": "CWE-319",
        "base_cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "epss": 0.38,
        "kev": False,
        "desc": "Cleartext transmission of credentials and session traffic.",
        "impact": "Transmits passwords, commands, and confidential session data in plaintext, exposing traffic to eavesdropping and MITM attacks.",
        "remediation_steps": [
            "Disable legacy cleartext services (Telnet Port 23, plaintext FTP Port 21).",
            "Migrate exclusively to SSH (Port 22), SFTP, or FTPS over TLS.",
            "Block incoming connections on unencrypted service ports at the firewall."
        ],
        "fix_snippet": "sudo systemctl stop telnet.socket telnet.service\nsudo systemctl disable --now telnet.socket telnet.service\nsudo ufw deny 23/tcp"
    },
    {
        "pattern": r"(default credentials|default.*basic.*auth|accepted.*admin:admin)",
        "cve": None,
        "cwe": "CWE-798",
        "base_cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss": 0.90,
        "kev": True,
        "desc": "Default administrative credentials accepted without restriction.",
        "impact": "Provides unauthenticated remote attackers with direct administrative access, allowing total system compromise.",
        "remediation_steps": [
            "Immediately log into the administrative interface and change default passwords.",
            "Enforce strong password complexity rules (16+ characters, high entropy).",
            "Enable Multi-Factor Authentication (MFA / 2FA) on all management accounts.",
            "Disable or delete default test and guest accounts."
        ],
        "fix_snippet": "# Generate a secure 32-character random credential:\nopenssl rand -base64 24"
    },
    {
        "pattern": r"(weak ssl cipher|rc4|des|md5|sha1)",
        "cve": "CVE-2014-0160",
        "cwe": "CWE-326",
        "base_cvss": 7.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "epss": 0.42,
        "kev": True,
        "desc": "Obsolete cryptographic cipher suites vulnerable to decryption attacks.",
        "impact": "Exposes encrypted HTTPS/TLS communications to passive decryption and man-in-the-middle downgrade attacks.",
        "remediation_steps": [
            "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 in web server configuration.",
            "Configure modern TLS 1.2 and TLS 1.3 AEAD cipher suites (AES-GCM, CHACHA20-POLY1305).",
            "Reload web server configuration and test using SSL Labs."
        ],
        "fix_snippet": "# Nginx Modern SSL Configuration\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';\nssl_prefer_server_ciphers off;"
    },
    {
        "pattern": r"(ssl certificate expiring|certificate verification failed)",
        "cve": None,
        "cwe": "CWE-295",
        "base_cvss": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "epss": 0.15,
        "kev": False,
        "desc": "TLS/SSL certificate trust chain failure or impending expiration.",
        "impact": "Users will receive browser security warnings, potentially breaking client trust and encrypted connectivity.",
        "remediation_steps": [
            "Renew the SSL/TLS certificate with a trusted Certificate Authority before expiry.",
            "Automate certificate renewal using Let's Encrypt Certbot or ACME client.",
            "Verify the full intermediate certificate chain is installed."
        ],
        "fix_snippet": "sudo certbot renew --dry-run\nsudo systemctl reload nginx"
    },
    {
        "pattern": r"(content-security-policy|missing.*csp)",
        "cve": None,
        "cwe": "CWE-693",
        "base_cvss": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "epss": 0.20,
        "kev": False,
        "desc": "Missing Content-Security-Policy (CSP) Defense Header.",
        "impact": "Leaves application vulnerable to Cross-Site Scripting (XSS), data injection, and unauthorized frame embedding.",
        "remediation_steps": [
            "Define and enforce a strict Content-Security-Policy header.",
            "Restrict script execution to authorized origins: `script-src 'self'`.",
            "Enforce CSP in Nginx or Apache configuration."
        ],
        "fix_snippet": "# Nginx:\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;\" always;\n\n# Apache:\nHeader always set Content-Security-Policy \"default-src 'self';\""
    },
    {
        "pattern": r"(strict-transport-security|missing.*hsts|hsts)",
        "cve": None,
        "cwe": "CWE-319",
        "base_cvss": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "epss": 0.14,
        "kev": False,
        "desc": "Missing HTTP Strict Transport Security (HSTS) Header.",
        "impact": "Allows attackers in a Man-in-the-Middle position to strip TLS and downgrade HTTPS traffic to cleartext HTTP.",
        "remediation_steps": [
            "Add `Strict-Transport-Security` header with `max-age=31536000; includeSubDomains`.",
            "Consider submitting the domain to the Chrome HSTS Preload List."
        ],
        "fix_snippet": "# Nginx:\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n\n# Apache:\nHeader always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\""
    },
    {
        "pattern": r"(x-frame-options|clickjacking)",
        "cve": None,
        "cwe": "CWE-1021",
        "base_cvss": 5.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "epss": 0.12,
        "kev": False,
        "desc": "Missing X-Frame-Options (Clickjacking Protection).",
        "impact": "Allows malicious websites to embed this site in an iframe to trick users into unintended clicks (Clickjacking).",
        "remediation_steps": [
            "Set `X-Frame-Options: SAMEORIGIN` or `DENY` on all HTTP responses.",
            "Alternatively, configure `frame-ancestors 'self'` in Content-Security-Policy."
        ],
        "fix_snippet": "# Nginx:\nadd_header X-Frame-Options \"SAMEORIGIN\" always;\n\n# Apache:\nHeader always set X-Frame-Options \"SAMEORIGIN\""
    },
    {
        "pattern": r"(x-content-type-options|mime sniffing)",
        "cve": None,
        "cwe": "CWE-16",
        "base_cvss": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "epss": 0.08,
        "kev": False,
        "desc": "Missing X-Content-Type-Options Header.",
        "impact": "Browsers may perform MIME sniffing on untrusted user uploads, interpreting them as executable scripts.",
        "remediation_steps": [
            "Add `X-Content-Type-Options: nosniff` header to all web responses."
        ],
        "fix_snippet": "# Nginx:\nadd_header X-Content-Type-Options \"nosniff\" always;\n\n# Apache:\nHeader always set X-Content-Type-Options \"nosniff\""
    },
    {
        "pattern": r"(permissions-policy|feature-policy)",
        "cve": None,
        "cwe": "CWE-16",
        "base_cvss": 3.7,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "epss": 0.05,
        "kev": False,
        "desc": "Missing Permissions-Policy Defense Header.",
        "impact": "Fails to restrict client browser APIs such as camera, microphone, geolocation, and payment delegation.",
        "remediation_steps": [
            "Implement modern `Permissions-Policy` header in web server configuration."
        ],
        "fix_snippet": "# Nginx:\nadd_header Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\" always;"
    },
    {
        "pattern": r"(cookie.*httponly|missing httponly)",
        "cve": None,
        "cwe": "CWE-1004",
        "base_cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "epss": 0.15,
        "kev": False,
        "desc": "Session Cookie Missing HttpOnly Flag.",
        "impact": "Allows client-side JavaScript to access session tokens, facilitating cookie theft via XSS vulnerabilities.",
        "remediation_steps": [
            "Configure application session manager to append the `HttpOnly` flag to all session cookies."
        ],
        "fix_snippet": "# Python / Flask:\nSESSION_COOKIE_HTTPONLY = True\n# PHP in php.ini:\nsession.cookie_httponly = 1"
    },
    {
        "pattern": r"(cookie.*secure|missing secure flag)",
        "cve": None,
        "cwe": "CWE-614",
        "base_cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "epss": 0.12,
        "kev": False,
        "desc": "Session Cookie Missing Secure Flag.",
        "impact": "Allows sensitive cookies to be transmitted over unencrypted HTTP connections, exposing them to network sniffers.",
        "remediation_steps": [
            "Configure session manager to mandate the `Secure` flag on all cookies."
        ],
        "fix_snippet": "# Python / Flask:\nSESSION_COOKIE_SECURE = True\n# PHP in php.ini:\nsession.cookie_secure = 1"
    },
    {
        "pattern": r"(robots\.txt|sensitive directory disclosure in robots)",
        "cve": None,
        "cwe": "CWE-200",
        "base_cvss": 3.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "epss": 0.08,
        "kev": False,
        "desc": "Robots.txt Discloses Administrative & Sensitive Paths.",
        "impact": "Exposes hidden backend directory routes, administrative panels, and staging environments to automated scrapers.",
        "remediation_steps": [
            "Audit `robots.txt` and remove sensitive, confidential, or private administration URLs.",
            "Protect private endpoints with authentication rather than relying on robots.txt disallow rules."
        ],
        "fix_snippet": "# In public robots.txt:\nUser-agent: *\nDisallow: /private-api/\n# Enforce HTTP authentication on private routes"
    },
    {
        "pattern": r"(swagger|openapi|api documentation exposed)",
        "cve": None,
        "cwe": "CWE-200",
        "base_cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "epss": 0.18,
        "kev": False,
        "desc": "Publicly Exposed Swagger / OpenAPI Specification.",
        "impact": "Provides unauthorized actors with full documentation of all backend API endpoints, parameters, and authentication schemas.",
        "remediation_steps": [
            "Disable Swagger UI and OpenAPI JSON endpoints in production environments.",
            "Restrict `/swagger.json` and `/docs` to internal VPN or authenticated developers."
        ],
        "fix_snippet": "# Nginx:\nlocation ~* /(swagger|api-docs|openapi) {\n    allow 10.0.0.0/8;\n    deny all;\n}"
    },
    {
        "pattern": r"(missing security headers|csp|x-frame-options|hsts|strict-transport-security)",
        "cve": None,
        "cwe": "CWE-693",
        "base_cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "epss": 0.12,
        "kev": False,
        "desc": "Missing HTTP response defense-in-depth headers.",
        "impact": "Increases vulnerability to Clickjacking, XSS exploitation, MIME-type sniffing, and plaintext HTTP downgrade.",
        "remediation_steps": [
            "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` header.",
            "Add `X-Frame-Options: DENY` or `SAMEORIGIN` to prevent framing.",
            "Add `X-Content-Type-Options: nosniff` to prevent MIME sniffing.",
            "Add `Content-Security-Policy` to restrict executable script origins."
        ],
        "fix_snippet": "# Nginx: Add Security Headers to server block\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\nadd_header X-Frame-Options \"DENY\" always;\nadd_header X-Content-Type-Options \"nosniff\" always;\nadd_header Content-Security-Policy \"default-src 'self';\" always;"
    },
    {
        "pattern": r"(server information disclosure|technology stack disclosure|server header)",
        "cve": None,
        "cwe": "CWE-200",
        "base_cvss": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "epss": 0.08,
        "kev": False,
        "desc": "Server header banner leaks exact software product versions.",
        "impact": "Provides attackers with exact software version numbers to tailor targeted exploit payloads.",
        "remediation_steps": [
            "Disable server signature tokens in Nginx (`server_tokens off;`) or Apache (`ServerTokens Prod`).",
            "Strip `X-Powered-By` header in application middleware.",
            "Restart web server."
        ],
        "fix_snippet": "# Nginx:\nserver_tokens off;\n\n# Apache (in httpd.conf / security.conf):\nServerTokens Prod\nServerSignature Off"
    },
    {
        "pattern": r"(excessive open ports|attack surface)",
        "cve": None,
        "cwe": "CWE-16",
        "base_cvss": 5.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "epss": 0.18,
        "kev": False,
        "desc": "Broad attack surface with excessive exposed network services.",
        "impact": "Unnecessary open ports increase the likelihood of unpatched services being compromised.",
        "remediation_steps": [
            "Audit all listening network ports with `netstat -tulpn` or `ss -tulpn`.",
            "Disable unused system services and daemons.",
            "Configure host firewall (UFW / iptables) with default DROP policy on external interfaces."
        ],
        "fix_snippet": "sudo ufw default deny incoming\nsudo ufw default allow outgoing\nsudo ufw allow ssh\nsudo ufw allow http\nsudo ufw allow https\nsudo ufw enable"
    },
    {
        "pattern": r"(database service.*(1433|3306|5432)|database listener|mysql listener|postgres listener)",
        "cve": None,
        "cwe": "CWE-284",
        "base_cvss": 7.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "epss": 0.40,
        "kev": False,
        "desc": "Database listener exposed to external network traffic.",
        "impact": "Exposes database listeners to brute-force credential attacks and unauthorized external queries.",
        "remediation_steps": [
            "Bind database daemon exclusively to localhost (`127.0.0.1`) or private VPC subnet.",
            "Block incoming external database traffic at the host firewall.",
            "Enforce TLS encryption and strong database user authentication."
        ],
        "fix_snippet": "# In /etc/mysql/mysql.conf.d/mysqld.cnf:\nbind-address = 127.0.0.1\n\nsudo systemctl restart mysql"
    },
]

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def calculate_unified_severity(cvss_score: float, is_kev_active: bool) -> str:
    """
    Calculate unified severity rating:
    - CRITICAL: CVSS >= 9.0 or KEV active in the wild
    - HIGH:     CVSS 7.0 - 8.9
    - MEDIUM:   CVSS 4.0 - 6.9
    - LOW:      CVSS < 4.0
    """
    if is_kev_active or cvss_score >= 9.0:
        return "Critical"
    if cvss_score >= 7.0:
        return "High"
    if cvss_score >= 4.0:
        return "Medium"
    return "Low"


def generate_fallback_playbook(title: str, severity: str, port=None, service=None) -> tuple:
    """Generate default impact, remediation steps, and fix snippet when no signature matches."""
    port_str = f"Port {port}" if port else "the affected service"
    service_str = service.upper() if service else "Service"

    impact = f"Security vulnerability in {service_str} on {port_str} may allow unauthorized reconnaissance or lateral exploitation."
    steps = [
        f"1. Audit the configuration of {service_str} running on {port_str}.",
        "2. Apply the latest vendor security patches and distribution package updates.",
        "3. Restrict network access to authorized management subnets using host and network firewalls.",
        "4. Verify service security hardening and restart the daemon."
    ]
    snippet = f"# Audit listening port status\nsudo ss -tulpn | grep {port if port else ''}\n# Update packages\nsudo apt update && sudo apt upgrade -y"

    return impact, steps, snippet


def enrich_vulnerability(vuln: dict) -> dict:
    """
    Enrich a single vulnerability dictionary with CVSS score, CVSS vector, CWE ID,
    CISA KEV status, EPSS exploit risk metrics, impact assessment, remediation
    playbook steps, and copyable fix snippets.
    """
    if not isinstance(vuln, dict):
        return vuln

    enriched = dict(vuln)
    title = enriched.get('title', '')
    desc = enriched.get('description', '')
    vuln_type = enriched.get('type', '')
    service = enriched.get('service', '')
    port = enriched.get('port', '')

    combined_text = f"{title} {desc} {vuln_type} {service} {enriched.get('category', '')}".lower()

    # 1. Check for explicit CVE identifier
    cve_match = CVE_REGEX.search(combined_text)
    cve_id = cve_match.group(0).upper() if cve_match else enriched.get("cve_id")

    base_cvss = enriched.get("cvss_score") or enriched.get("cvss")
    cvss_vector = enriched.get("cvss_vector")
    cwe_id = enriched.get("cwe_id") or enriched.get("cwe")
    cisa_kev = enriched.get("cisa_kev_listed", False)
    epss_score = enriched.get("epss_score")
    impact = enriched.get("impact")
    remediation_steps = enriched.get("remediation_steps")
    fix_snippet = enriched.get("fix_snippet")

    # 2. Check CISA KEV Catalog lookup
    if cve_id and cve_id in CISA_KEV_CATALOG:
        catalog_entry = CISA_KEV_CATALOG[cve_id]
        cisa_kev = catalog_entry["kev"]
        base_cvss = catalog_entry["cvss"]
        cvss_vector = cvss_vector or catalog_entry.get("cvss_vector")
        cwe_id = cwe_id or catalog_entry.get("cwe")
        epss_score = catalog_entry["epss"]
        if not impact:
            impact = catalog_entry.get("impact")
        if not remediation_steps:
            remediation_steps = catalog_entry.get("remediation_steps")
        if not fix_snippet:
            fix_snippet = catalog_entry.get("fix_snippet")
    else:
        # Match against heuristic signatures
        matched_rule = None
        for rule in VULN_SIGNATURE_RULES:
            if re.search(rule["pattern"], combined_text):
                matched_rule = rule
                break

        if matched_rule:
            if not cve_id and matched_rule.get("cve"):
                cve_id = matched_rule["cve"]
            if base_cvss is None:
                base_cvss = matched_rule["base_cvss"]
            if not cvss_vector and matched_rule.get("cvss_vector"):
                cvss_vector = matched_rule["cvss_vector"]
            if not cwe_id and matched_rule.get("cwe"):
                cwe_id = matched_rule["cwe"]
            if cisa_kev is False and matched_rule.get("kev"):
                cisa_kev = True
            if epss_score is None:
                epss_score = matched_rule["epss"]
            if not impact:
                impact = matched_rule.get("impact")
            if not remediation_steps:
                remediation_steps = matched_rule.get("remediation_steps")
            if not fix_snippet:
                fix_snippet = matched_rule.get("fix_snippet")

    # 3. Fallbacks if still unset
    if base_cvss is None:
        raw_sev = str(enriched.get("severity", "Low")).lower()
        if raw_sev == "critical":
            base_cvss = 9.5
        elif raw_sev == "high":
            base_cvss = 7.8
        elif raw_sev == "medium":
            base_cvss = 5.2
        else:
            base_cvss = 2.5

    if not cvss_vector:
        if base_cvss >= 9.0:
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        elif base_cvss >= 7.0:
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        elif base_cvss >= 4.0:
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
        else:
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

    if not cwe_id:
        cwe_id = "CWE-693" if "header" in combined_text else ("CWE-200" if "disclosure" in combined_text else "CWE-16")

    if epss_score is None:
        if base_cvss >= 9.0:
            epss_score = 0.88
        elif base_cvss >= 7.0:
            epss_score = 0.65
        elif base_cvss >= 4.0:
            epss_score = 0.25
        else:
            epss_score = 0.05

    base_cvss = round(float(base_cvss), 1)
    epss_score = round(float(epss_score), 2)
    epss_percentile = f"{int(epss_score * 100)}th percentile"
    epss_high_risk = epss_score >= 0.50

    # 4. Compute Unified Severity
    unified_severity = calculate_unified_severity(base_cvss, cisa_kev)

    # 5. Playbook fallbacks if still missing
    if not impact or not remediation_steps or not fix_snippet:
        f_impact, f_steps, f_snippet = generate_fallback_playbook(title, unified_severity, port, service)
        impact = impact or f_impact
        remediation_steps = remediation_steps or (
            [enriched["recommendation"]] if enriched.get("recommendation") else f_steps
        )
        fix_snippet = fix_snippet or f_snippet

    # 6. Populate enriched fields
    enriched["cve_id"] = cve_id or cwe_id
    enriched["cwe_id"] = cwe_id
    enriched["cvss_score"] = base_cvss
    enriched["cvss_vector"] = cvss_vector
    enriched["cisa_kev_listed"] = bool(cisa_kev)
    enriched["active_exploit_in_wild"] = bool(cisa_kev)
    enriched["epss_score"] = epss_score
    enriched["epss_percentile"] = epss_percentile
    enriched["epss_high_risk"] = epss_high_risk
    enriched["severity"] = unified_severity
    enriched["impact"] = impact
    enriched["remediation_steps"] = remediation_steps
    enriched["fix_snippet"] = fix_snippet

    return enriched


def enrich_vulnerabilities(vulnerabilities: list) -> list:
    """Enrich a list of vulnerability findings with exploit-aware metrics and remediation playbooks."""
    if not isinstance(vulnerabilities, list):
        return []
    return [enrich_vulnerability(v) for v in vulnerabilities]
