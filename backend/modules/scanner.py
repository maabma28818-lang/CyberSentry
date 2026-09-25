import logging
import nmap
import requests
from datetime import datetime
import socket
import ssl
from urllib.parse import urlparse

from concurrent.futures import ThreadPoolExecutor
from modules.vuln_engine import enrich_vulnerabilities
from modules.service_auditor import ServiceAuditor

logger = logging.getLogger(__name__)

WELL_KNOWN_SERVICES = {
    21: ('ftp', 'FTP Service'),
    22: ('ssh', 'OpenSSH'),
    23: ('telnet', 'Telnet Service'),
    25: ('smtp', 'SMTP Mail Server'),
    53: ('domain', 'DNS Server'),
    80: ('http', 'Web Server (HTTP)'),
    110: ('pop3', 'POP3 Mail Server'),
    143: ('imap', 'IMAP Mail Server'),
    443: ('https', 'Web Server (HTTPS)'),
    445: ('microsoft-ds', 'SMB File Sharing'),
    993: ('imaps', 'Secure IMAP'),
    995: ('pop3s', 'Secure POP3'),
    1433: ('ms-sql-s', 'Microsoft SQL Server'),
    3306: ('mysql', 'MySQL Database'),
    3389: ('ms-wbt-server', 'Remote Desktop (RDP)'),
    5432: ('postgresql', 'PostgreSQL Database'),
    5900: ('vnc', 'VNC Remote Desktop'),
    8080: ('http-proxy', 'HTTP Web App Server'),
    8443: ('https-alt', 'HTTPS Web App Server')
}

# Nmap runs must always terminate. --host-timeout makes nmap itself skip a
# host that makes no progress (filtered, blackholed), so ordinary single-host
# scans end on their own; the process timeout below is the absolute backstop
# for pathological runs (a wedged nmap otherwise pins a request thread and a
# SCAN_SLOT forever, because python-nmap waits indefinitely by default).
NMAP_HOST_TIMEOUT = "5m"
NMAP_PROCESS_TIMEOUT_SECONDS = 1800


def _nmap_target(target):
    """Return the host Nmap should scan when the target is URL-shaped.

    Nmap resolves hosts, not URLs: a documented "https://example.com" target
    previously aborted the whole scan before the web checks could run. The
    URL keeps flowing to the HTTP/TLS checks; Nmap and the raw-socket checks
    receive the bare hostname. Schemes are matched case-insensitively
    because RFC 3986 defines them that way.
    """
    if not target.lower().startswith(("http://", "https://")):
        return target
    host = urlparse(target).hostname or target
    # A hostname starting with "-" would reach Nmap's argv as an option
    # once the scheme is stripped (python-nmap re-splits the host string);
    # refuse it the same way the API validator refuses option-prefixed
    # targets. The API layer also rejects these before the modules run.
    if host.startswith("-"):
        raise ValueError("Target host must not start with an option prefix")
    return host


def _raw_socket_available():
    """Return True when the process may create raw sockets (CAP_NET_RAW/root)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP):
            return True
    except (PermissionError, OSError):
        return False


def _nmap_scan_args():
    """Pick Nmap arguments that work with the privileges we actually have.

    SYN scans and OS detection require raw sockets. Without them Nmap aborts
    ("You requested a scan type which requires root privileges"), so fall
    back to a full connect scan and drop -O instead of failing the scan.
    """
    if _raw_socket_available():
        return '-sS -sV'
    logger.info("No raw-socket privileges: using Nmap connect scan (-sT)")
    return '-sT -sV'


class VulnScanner:
    """Vulnerability scanner for web applications and network services"""
    
    def __init__(self):
        self.service_auditor = ServiceAuditor()
        self.common_vulns = {
            'http': ['HTTP methods', 'Directory traversal', 'XSS', 'SQL injection', 'CSRF'],
            'https': ['SSL/TLS vulnerabilities', 'Certificate issues', 'Weak ciphers'],
            'ssh': ['Weak algorithms', 'Default credentials', 'Key-based attacks'],
            'ftp': ['Anonymous access', 'Weak credentials', 'Directory traversal'],
            'smtp': ['Open relay', 'User enumeration', 'Authentication bypass'],
            'mysql': ['Default credentials', 'SQL injection', 'Privilege escalation'],
            'rdp': ['Weak credentials', 'BlueKeep vulnerability', 'Network level authentication']
        }
    
    def scan_target(self, target, scan_type='basic'):
        """Perform vulnerability scan on target"""
        try:
            logger.info(f"Starting vulnerability scan on {target} (type: {scan_type})")

            vulnerabilities = []
            # The URL-shaped checks below match scheme prefixes
            # case-sensitively; normalize the scheme once so "HTTPS://"
            # targets scan exactly like "https://" ones (RFC 3986).
            scheme, separator, rest = target.partition("//")
            if separator and scheme.lower() in ("http:", "https:"):
                target = f"{scheme.lower()}//{rest}"
            scan_host = _nmap_target(target)

            # First, get open ports for context
            port_scan_results = self._quick_port_scan(scan_host)

            if scan_type == 'basic':
                vulnerabilities.extend(self._basic_vulnerability_scan(scan_host, port_scan_results))
            elif scan_type == 'web':
                vulnerabilities.extend(self._web_vulnerability_scan(target))
            elif scan_type == 'network':
                vulnerabilities.extend(self._network_vulnerability_scan(scan_host, port_scan_results))
            elif scan_type in ('comprehensive', 'unified'):
                vulnerabilities.extend(self._basic_vulnerability_scan(scan_host, port_scan_results))
                vulnerabilities.extend(self._web_vulnerability_scan(target))
                vulnerabilities.extend(self._network_vulnerability_scan(scan_host, port_scan_results))
            
            # Add SSL/TLS checks if HTTPS is available
            if self._is_https_available(target):
                vulnerabilities.extend(self._ssl_vulnerability_scan(target))

            # Run Insecure Service & Default Credential Auditor
            raw_misconfigurations = self.service_auditor.audit_target(target, port_scan_results)
            enriched_misconfigurations = enrich_vulnerabilities(raw_misconfigurations)
            
            # Enrich findings with exploit-aware threat intelligence (CVSS, CISA KEV, EPSS)
            enriched_vulnerabilities = enrich_vulnerabilities(vulnerabilities)
            all_findings = enriched_vulnerabilities + enriched_misconfigurations

            result = {
                'target': target,
                'scan_type': scan_type,
                'vulnerabilities': enriched_vulnerabilities,
                'misconfigurations': enriched_misconfigurations,
                'total_vulnerabilities': len(all_findings),
                'severity_breakdown': self._categorize_by_severity(all_findings),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Vulnerability scan completed for {target}. Found {len(enriched_vulnerabilities)} vulnerabilities and {len(enriched_misconfigurations)} misconfigurations.")
            return result
            
        except Exception as e:
            logger.error(f"Vulnerability scan failed: {str(e)}")
            return {'error': str(e), 'target': target}

    def _socket_quick_port_scan(self, target):
        """Native socket fallback when Nmap is not installed on the system."""
        clean_target = _nmap_target(target)
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
        open_ports = []

        def probe_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.4)
                    if sock.connect_ex((clean_target, port)) == 0:
                        service_name, product_name = WELL_KNOWN_SERVICES.get(port, ('unknown', ''))
                        version = ''
                        banner = ''
                        try:
                            if port in (80, 8080, 443, 8443):
                                scheme = 'https' if port in (443, 8443) else 'http'
                                resp = requests.get(f"{scheme}://{clean_target}:{port}", timeout=0.8, verify=False)
                                server = resp.headers.get('Server', '')
                                powered_by = resp.headers.get('X-Powered-By', '')
                                if server:
                                    product_name = server
                                    banner = server
                                if powered_by:
                                    product_name = f"{product_name} ({powered_by})".strip()
                            elif port in (21, 22, 23, 25, 110, 143):
                                raw_banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
                                if raw_banner:
                                    banner = raw_banner
                                    product_name = raw_banner
                                    if port == 22 and 'SSH' in raw_banner:
                                        service_name = 'ssh'
                            elif port == 3306:
                                raw_mysql = sock.recv(256)
                                if len(raw_mysql) > 5:
                                    ver_bytes = raw_mysql[5:].split(b'\x00')[0]
                                    ver_str = ver_bytes.decode('utf-8', errors='ignore').strip()
                                    if ver_str:
                                        product_name = f"MySQL/MariaDB {ver_str}"
                                        version = ver_str
                                        banner = ver_str
                        except Exception:
                            pass

                        return {
                            'port': port,
                            'service': service_name,
                            'version': version,
                            'product': product_name,
                            'banner': banner,
                            'state': 'open'
                        }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=min(32, len(common_ports))) as executor:
            results = executor.map(probe_port, common_ports)
            for res in results:
                if res:
                    open_ports.append(res)

        return sorted(open_ports, key=lambda x: x['port'])

    def _quick_port_scan(self, target):
        """Quick port scan to identify services or fallback to native socket scan when Nmap is unavailable."""
        try:
            nm = nmap.PortScanner()
            common_ports = "21,22,23,25,53,80,110,143,443,993,995,1433,3306,3389,5432,5900,8080,8443"
            scan_output = nm.scan(
                target,
                common_ports,
                arguments=_nmap_scan_args() + f" --host-timeout={NMAP_HOST_TIMEOUT}",
                timeout=NMAP_PROCESS_TIMEOUT_SECONDS,
            )
            scan_error = scan_output.get('nmap', {}).get('scaninfo', {}).get('error') if isinstance(scan_output, dict) else None
            if scan_error:
                message = ''.join(scan_error) if isinstance(scan_error, list) else str(scan_error)
                raise RuntimeError(f"Nmap execution failed: {message.strip()}")

            open_ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        if nm[host][proto][port]['state'] == 'open':
                            open_ports.append({
                                'port': port,
                                'service': nm[host][proto][port].get('name', 'unknown'),
                                'version': nm[host][proto][port].get('version', ''),
                                'product': nm[host][proto][port].get('product', '')
                            })

            return open_ports
        except (getattr(nmap, 'PortScannerError', type('PortScannerError', (Exception,), {})), FileNotFoundError, OSError) as nmap_err:
            logger.warning(f"Nmap is not installed or unavailable ({nmap_err}); using high-speed native socket scanner fallback.")
            return self._socket_quick_port_scan(target)
    
    def _basic_vulnerability_scan(self, target, port_scan_results):
        """Basic vulnerability checks correlating banners and authentication"""
        vulnerabilities = []
        
        try:
            for port_info in port_scan_results:
                service = str(port_info.get('service', '')).lower()
                product = str(port_info.get('product', '')).lower()
                version = str(port_info.get('version', '')).lower()
                banner = str(port_info.get('banner', '')).lower()
                port = port_info.get('port')
                all_text = f"{service} {product} {version} {banner}"

                # Anonymous FTP check
                if service == 'ftp' or port == 21:
                    vuln = self._check_anonymous_ftp(target, port)
                    if vuln:
                        vulnerabilities.append(vuln)

                # OpenSSH banner check (e.g. regreSSHion check)
                if 'openssh' in all_text or (service == 'ssh' and port == 22):
                    vulnerabilities.append({
                        'type': 'Service Security',
                        'severity': 'High',
                        'title': 'OpenSSH Server Remote Attack Surface',
                        'description': f'SSH service detected on port {port}: {port_info.get("product") or "OpenSSH"}. Vulnerable to race conditions (regreSSHion CVE-2024-6387) if unpatched or exposed to untrusted subnets.',
                        'recommendation': 'Upgrade OpenSSH to version >= 9.8p1 and disable password authentication.',
                        'port': port,
                        'service': 'SSH',
                        'cve_id': 'CVE-2024-6387',
                        'cwe_id': 'CWE-362'
                    })

                # Exposed database listener check
                if port in (3306, 5432, 1433) or 'mysql' in all_text or 'postgres' in all_text:
                    db_name = 'MySQL' if port == 3306 or 'mysql' in all_text else ('PostgreSQL' if port == 5432 else 'Database')
                    vulnerabilities.append({
                        'type': 'Access Control',
                        'severity': 'High',
                        'title': f'Exposed {db_name} Database Listener (Port {port})',
                        'description': f'{db_name} database listener is accessible on external network port {port}. Exposes the database to credential brute-forcing and network eavesdropping.',
                        'recommendation': f'Bind {db_name} daemon exclusively to 127.0.0.1 or restrict access behind a firewall.',
                        'port': port,
                        'service': db_name,
                        'cwe_id': 'CWE-284'
                    })
            
        except Exception as e:
            logger.warning(f"Basic vulnerability scan error: {str(e)}")
        
        return vulnerabilities
    
    def _web_vulnerability_scan(self, target):
        """Web application vulnerability scan"""
        vulnerabilities = []
        
        try:
            urls_to_test = []
            if target.startswith('http://') or target.startswith('https://'):
                urls_to_test.append(target)
            else:
                urls_to_test.extend([f'http://{target}', f'https://{target}'])
            
            for url in urls_to_test:
                try:
                    response = requests.get(url, timeout=8, verify=False, allow_redirects=True)
                    
                    # 1. Information disclosure from headers
                    vulns = self._check_info_disclosure(url, response)
                    vulnerabilities.extend(vulns)
                    
                    # 2. Security headers audit
                    vulns = self._check_security_headers(url, response)
                    vulnerabilities.extend(vulns)

                    # 3. Cookie security audit
                    vulns = self._check_cookie_security(url, response)
                    vulnerabilities.extend(vulns)
                    
                    # 4. Sensitive endpoint probing
                    vulns = self._check_common_files(url)
                    vulnerabilities.extend(vulns)
                    
                    # 5. Reflected XSS check
                    vulns = self._basic_xss_check(url)
                    vulnerabilities.extend(vulns)
                    
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            logger.warning(f"Web vulnerability scan error: {str(e)}")
        
        return vulnerabilities
    
    def _network_vulnerability_scan(self, target, port_scan_results):
        """Network-level vulnerability scan"""
        vulnerabilities = []
        
        try:
            # Check for excessive open ports
            if len(port_scan_results) > 10:
                vulnerabilities.append({
                    'type': 'Network Configuration',
                    'severity': 'Medium',
                    'title': 'Excessive Open Ports',
                    'description': f'Target has {len(port_scan_results)} open ports, which increases attack surface',
                    'recommendation': 'Close unnecessary ports and services',
                    'port': 'Multiple',
                    'service': 'Network',
                    'cwe_id': 'CWE-16'
                })
            
            # Check for unencrypted services
            unencrypted_services = []
            for port_info in port_scan_results:
                service = str(port_info.get('service', '')).lower()
                port = port_info.get('port')
                if service in ['ftp', 'telnet', 'http', 'smtp'] and port not in [443, 993, 995]:
                    unencrypted_services.append(f"{service}:{port}")
            
            if unencrypted_services:
                vulnerabilities.append({
                    'type': 'Encryption',
                    'severity': 'High',
                    'title': 'Unencrypted Services',
                    'description': f'Unencrypted services detected: {", ".join(unencrypted_services)}',
                    'recommendation': 'Use encrypted alternatives (HTTPS, SFTP, SSH, etc.)',
                    'port': 'Multiple',
                    'service': 'Network',
                    'cwe_id': 'CWE-319'
                })
            
            # Check for potentially dangerous services
            dangerous_services = []
            for port_info in port_scan_results:
                service = str(port_info.get('service', '')).lower()
                port = port_info.get('port')
                
                if service == 'telnet' or port == 23:
                    dangerous_services.append('Telnet (unencrypted cleartext protocol)')
                elif (service == 'ftp' or port == 21):
                    dangerous_services.append('FTP (cleartext control channel)')
                elif port == 3389:
                    dangerous_services.append('RDP (Remote Desktop exposed)')
                elif port in [1433, 3306, 5432]:
                    dangerous_services.append(f'Database service on port {port}')
            
            if dangerous_services:
                vulnerabilities.append({
                    'type': 'Service Security',
                    'severity': 'Medium',
                    'title': 'Potentially Dangerous Services Exposed',
                    'description': f'Services with elevated attack surfaces detected: {", ".join(dangerous_services)}',
                    'recommendation': 'Review necessity of these services and harden configurations behind VPN or firewall',
                    'port': 'Multiple',
                    'service': 'Network',
                    'cwe_id': 'CWE-284'
                })
                
        except Exception as e:
            logger.warning(f"Network vulnerability scan error: {str(e)}")
        
        return vulnerabilities
    
    def _ssl_vulnerability_scan(self, target):
        """SSL/TLS vulnerability scan"""
        vulnerabilities = []
        
        try:
            if target.startswith('https://'):
                parsed = urlparse(target)
                hostname = parsed.hostname
                port = parsed.port or 443
            else:
                hostname = _nmap_target(target)
                port = 443
            
            context = ssl.create_default_context()
            context.check_hostname = False
            
            cert = None
            cipher = None
            try:
                with socket.create_connection((hostname, port), timeout=8) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
            except ssl.SSLCertVerificationError as cert_error:
                vulnerabilities.append({
                    'type': 'SSL/TLS',
                    'severity': 'Medium',
                    'title': 'SSL Certificate Verification Failed',
                    'description': f'Certificate could not be verified: {cert_error.reason}',
                    'recommendation': 'Review the TLS certificate chain and renewal status with a trusted Certificate Authority',
                    'port': port,
                    'service': 'HTTPS',
                    'cwe_id': 'CWE-295'
                })
                try:
                    cipher_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    cipher_context.check_hostname = False
                    cipher_context.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((hostname, port), timeout=8) as sock:
                        with cipher_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cipher = ssock.cipher()
                except OSError:
                    pass
            except OSError:
                pass

            # Check certificate expiration
            if cert:
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (not_after - datetime.now()).days

                if days_until_expiry < 30:
                    vulnerabilities.append({
                        'type': 'SSL/TLS',
                        'severity': 'High' if days_until_expiry < 7 else 'Medium',
                        'title': 'SSL Certificate Expiring Soon',
                        'description': f'SSL certificate expires in {days_until_expiry} days ({cert["notAfter"]})',
                        'recommendation': 'Renew SSL certificate before expiration via Certbot or ACME provider',
                        'port': port,
                        'service': 'HTTPS',
                        'cwe_id': 'CWE-295'
                    })

            # Check for weak ciphers
            if cipher:
                cipher_name = cipher[0]
                if any(weak in cipher_name.upper() for weak in ['RC4', 'DES', 'MD5', 'SHA1', 'NULL', 'EXPORT']):
                    vulnerabilities.append({
                        'type': 'SSL/TLS',
                        'severity': 'High',
                        'title': 'Weak SSL Cipher Suite Negotiated',
                        'description': f'Weak or obsolete cipher suite in use: {cipher_name}',
                        'recommendation': 'Configure modern TLS 1.2 / TLS 1.3 AEAD cipher suites (AES-GCM, CHACHA20-POLY1305)',
                        'port': port,
                        'service': 'HTTPS',
                        'cwe_id': 'CWE-326'
                    })

        except Exception as e:
            logger.warning("SSL vulnerability scan error: %s", e)
        
        return vulnerabilities
    
    def _check_anonymous_ftp(self, target, port):
        """Check for anonymous FTP access"""
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=6)
            ftp.login()  # Anonymous login
            ftp.quit()
            
            return {
                'type': 'Authentication',
                'severity': 'High',
                'title': 'Anonymous FTP Access Enabled',
                'description': 'FTP server allows unauthenticated anonymous login with read/write capability.',
                'recommendation': 'Disable anonymous access in /etc/vsftpd.conf (anonymous_enable=NO).',
                'port': port,
                'service': 'FTP',
                'cwe_id': 'CWE-287'
            }
            
        except Exception:
            return None
    
    def _check_info_disclosure(self, url, response):
        """Check for information disclosure in HTTP response headers"""
        vulnerabilities = []
        
        server_header = response.headers.get('Server', '')
        if server_header:
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'severity': 'Low',
                'title': 'Server Header Software Disclosure',
                'description': f'Server response header discloses web server technology: {server_header}',
                'recommendation': 'Disable server signature tokens in Nginx (server_tokens off;) or Apache (ServerTokens Prod).',
                'port': 'HTTP/HTTPS',
                'service': 'Web',
                'cwe_id': 'CWE-200'
            })
        
        powered_by = response.headers.get('X-Powered-By', '')
        if powered_by:
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'severity': 'Low',
                'title': 'Technology Stack Disclosure (X-Powered-By)',
                'description': f'X-Powered-By header discloses backend framework runtime: {powered_by}',
                'recommendation': 'Remove the X-Powered-By header in application middleware configuration.',
                'port': 'HTTP/HTTPS',
                'service': 'Web',
                'cwe_id': 'CWE-200'
            })
        
        aspnet = response.headers.get('X-AspNet-Version', '')
        if aspnet:
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'severity': 'Low',
                'title': 'ASP.NET Version Disclosure',
                'description': f'X-AspNet-Version header discloses ASP.NET version: {aspnet}',
                'recommendation': 'Disable enableVersionHeader in web.config.',
                'port': 'HTTP/HTTPS',
                'service': 'Web',
                'cwe_id': 'CWE-200'
            })

        return vulnerabilities
    
    def _check_security_headers(self, url, response):
        """Check for missing security headers with dedicated granular findings"""
        vulnerabilities = []
        headers = response.headers
        
        # 1. Content-Security-Policy
        if 'Content-Security-Policy' not in headers and 'content-security-policy' not in headers:
            vulnerabilities.append({
                'type': 'Web Security',
                'severity': 'Medium',
                'title': 'Missing Content-Security-Policy (CSP)',
                'description': 'The Content-Security-Policy response header is not implemented. Leaves users vulnerable to Cross-Site Scripting (XSS) and code injection.',
                'recommendation': 'Enforce a robust Content-Security-Policy header (default-src \'self\'; script-src \'self\').',
                'port': 'HTTP/HTTPS',
                'service': 'Web',
                'cwe_id': 'CWE-693'
            })

        # 2. Strict-Transport-Security (HSTS)
        if 'Strict-Transport-Security' not in headers and 'strict-transport-security' not in headers:
            vulnerabilities.append({
                'type': 'Web Security',
                'severity': 'Medium',
                'title': 'Missing HTTP Strict Transport Security (HSTS)',
                'description': 'The Strict-Transport-Security header is missing. Browsers may connect over plaintext HTTP, enabling SSL-stripping and MITM attacks.',
                'recommendation': 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to HTTPS responses.',
                'port': 'HTTP/HTTPS',
                'service': 'Web',
                'cwe_id': 'CWE-319'
            })

        # 3. X-Frame-Options
        if 'X-Frame-Options' not in headers and 'x-frame-options' not in headers and 'frame-ancestors' not in headers.get('Content-Security-Policy', ''):
            vulnerabilities.append({
                'type': 'Web Security',
                'severity': 'Medium',
                'title': 'Missing X-Frame-Options (Clickjacking Risk)',
                'description': 'X-Frame-Options header is absent. Malicious websites can frame this application to trick users into unauthorized clicks.',
                'recommendation': 'Configure X-Frame-Options: SAMEORIGIN or DENY on all web responses.',
                'port': 'HTTP/HTTPS',
                'service': 'Web',
                'cwe_id': 'CWE-1021'
            })

        # 4. X-Content-Type-Options
        if 'X-Content-Type-Options' not in headers and 'x-content-type-options' not in headers:
            vulnerabilities.append({
                'type': 'Web Security',
                'severity': 'Low',
                'title': 'Missing X-Content-Type-Options Header',
                'description': 'X-Content-Type-Options: nosniff header is missing. Browsers may MIME-sniff response payloads and execute script attachments.',
                'recommendation': 'Add X-Content-Type-Options: nosniff always to web server response headers.',
                'port': 'HTTP/HTTPS',
                'service': 'Web',
                'cwe_id': 'CWE-16'
            })

        # 5. Permissions-Policy
        if 'Permissions-Policy' not in headers and 'permissions-policy' not in headers and 'Feature-Policy' not in headers:
            vulnerabilities.append({
                'type': 'Web Security',
                'severity': 'Low',
                'title': 'Missing Permissions-Policy Header',
                'description': 'Permissions-Policy header is missing. Fails to disable unneeded browser capabilities like camera, microphone, and geolocation.',
                'recommendation': 'Set Permissions-Policy: camera=(), microphone=(), geolocation=() in web server configuration.',
                'port': 'HTTP/HTTPS',
                'service': 'Web',
                'cwe_id': 'CWE-16'
            })

        # 6. Referrer-Policy
        if 'Referrer-Policy' not in headers and 'referrer-policy' not in headers:
            vulnerabilities.append({
                'type': 'Web Security',
                'severity': 'Low',
                'title': 'Missing Referrer-Policy Header',
                'description': 'Referrer-Policy header is not configured. Outbound navigation links may leak full sensitive URLs and tokens.',
                'recommendation': 'Set Referrer-Policy: strict-origin-when-cross-origin on all responses.',
                'port': 'HTTP/HTTPS',
                'service': 'Web',
                'cwe_id': 'CWE-116'
            })

        return vulnerabilities

    def _check_cookie_security(self, url, response):
        """Check for missing security flags on Set-Cookie headers"""
        vulnerabilities = []
        cookies_header = response.headers.get('Set-Cookie', '')
        
        if cookies_header:
            cookies_lower = cookies_header.lower()
            if 'httponly' not in cookies_lower:
                vulnerabilities.append({
                    'type': 'Cookie Security',
                    'severity': 'Medium',
                    'title': 'Session Cookie Missing HttpOnly Flag',
                    'description': f'Cookie header lacks HttpOnly attribute ({cookies_header[:60]}...). Client-side scripts can access this cookie.',
                    'recommendation': 'Enable HttpOnly flag on all session cookies to prevent session hijacking via XSS.',
                    'port': 'HTTP/HTTPS',
                    'service': 'Web',
                    'cwe_id': 'CWE-1004'
                })
            if 'secure' not in cookies_lower and url.startswith('https://'):
                vulnerabilities.append({
                    'type': 'Cookie Security',
                    'severity': 'Medium',
                    'title': 'Session Cookie Missing Secure Flag',
                    'description': 'HTTPS session cookie was issued without the Secure attribute. Can be intercepted over plaintext HTTP.',
                    'recommendation': 'Enforce the Secure flag on all cookies issued over TLS connections.',
                    'port': 'HTTPS',
                    'service': 'Web',
                    'cwe_id': 'CWE-614'
                })
            if 'samesite' not in cookies_lower:
                vulnerabilities.append({
                    'type': 'Cookie Security',
                    'severity': 'Low',
                    'title': 'Cookie Missing SameSite Attribute',
                    'description': 'Cookie does not specify SameSite=Lax or SameSite=Strict, increasing exposure to Cross-Site Request Forgery (CSRF).',
                    'recommendation': 'Set SameSite=Lax or SameSite=Strict on all web application cookies.',
                    'port': 'HTTP/HTTPS',
                    'service': 'Web',
                    'cwe_id': 'CWE-1275'
                })

        return vulnerabilities
    
    def _check_common_files(self, url):
        """Sensitive Endpoint Probing: Non-destructively check for exposed public paths"""
        vulnerabilities = []
        
        endpoints_to_probe = [
            ('robots.txt', 'Robots.txt Discloses Sensitive Directories', 'Low', 'CWE-200', 'Discloses private directory routes to automated crawlers'),
            ('.well-known/security.txt', 'Security.txt Responsible Disclosure Policy', 'Info', 'CWE-16', 'Security policy file'),
            ('.git/HEAD', 'Exposed Git Version Control Repository (/.git/HEAD)', 'Critical', 'CWE-538', 'Exposes full application source code and revision history'),
            ('swagger.json', 'Publicly Exposed Swagger / OpenAPI Specification', 'Medium', 'CWE-200', 'Exposes backend API routes and schemas without authentication'),
            ('swagger-ui.html', 'Exposed Swagger UI Interactive API Console', 'Medium', 'CWE-200', 'Allows testing backend API endpoints interactively'),
            ('openapi.json', 'Exposed OpenAPI 3.0 API Specification', 'Medium', 'CWE-200', 'Exposes complete API parameter documentation'),
            ('.env', 'Exposed Environment Secrets File (/.env)', 'Critical', 'CWE-538', 'Exposes database passwords, secret keys, and API tokens'),
            ('sitemap.xml', 'Public Sitemap Directory Structure (sitemap.xml)', 'Low', 'CWE-200', 'Exposes application site hierarchy'),
            ('phpinfo.php', 'Exposed PHP Diagnostic Script (phpinfo.php)', 'High', 'CWE-200', 'Exposes full PHP runtime configuration and server environment variables')
        ]
        
        for file_path, title, sev, cwe, desc in endpoints_to_probe:
            try:
                test_url = f"{url.rstrip('/')}/{file_path}"
                response = requests.get(test_url, timeout=4, verify=False, allow_redirects=False)
                
                if response.status_code == 200:
                    text_sample = response.text[:400]
                    # Specific signature validations to avoid false 200 SPA index pages
                    if file_path == '.git/HEAD' and not text_sample.startswith('ref:'):
                        continue
                    if file_path == '.env' and not any(k in text_sample for k in ['=', 'APP_', 'DB_', 'SECRET', 'KEY']):
                        continue
                    if file_path == 'robots.txt' and '<html' in text_sample.lower():
                        continue

                    vulnerabilities.append({
                        'type': 'Sensitive Endpoint Probing',
                        'severity': sev if sev != 'Info' else 'Low',
                        'title': title,
                        'description': f'Accessible endpoint: {test_url}. {desc}.',
                        'recommendation': f'Restrict access to /{file_path} in web server directives.',
                        'port': 'HTTP/HTTPS',
                        'service': 'Web',
                        'cwe_id': cwe
                    })
            except requests.exceptions.RequestException:
                continue
        
        return vulnerabilities
    
    def _basic_xss_check(self, url):
        """Basic reflected XSS verification check"""
        vulnerabilities = []
        test_payload = '<script>alert("CyberSentryXSS")</script>'
        
        try:
            test_url = f"{url}?q={test_payload}"
            response = requests.get(test_url, timeout=4, verify=False)
            
            if test_payload in response.text:
                vulnerabilities.append({
                    'type': 'Cross-Site Scripting',
                    'severity': 'High',
                    'title': 'Potential Reflected XSS (CWE-79)',
                    'description': f'Application echoed unescaped payload on {url}',
                    'recommendation': 'Implement proper HTML contextual output encoding and enforce CSP.',
                    'port': 'HTTP/HTTPS',
                    'service': 'Web',
                    'cwe_id': 'CWE-79'
                })
        except Exception:
            pass
        
        return vulnerabilities
    
    def _is_https_available(self, target):
        """Check if HTTPS is available on target"""
        try:
            if target.startswith('https://'):
                return True
            elif target.startswith('http://'):
                return False
            else:
                test_url = f'https://{target}'
                requests.get(test_url, timeout=4, verify=False)
                return True
        except requests.exceptions.RequestException:
            return False
    
    def _categorize_by_severity(self, vulnerabilities):
        """Categorize vulnerabilities by severity"""
        severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            if severity in severity_count:
                severity_count[severity] += 1
        
        return severity_count
