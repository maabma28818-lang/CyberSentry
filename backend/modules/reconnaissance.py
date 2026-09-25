import logging
import nmap
import dns.resolver
import whois
import requests
import threading
import ipaddress
from datetime import datetime
import socket
from concurrent.futures import ThreadPoolExecutor

from modules.scanner import (
    _nmap_scan_args,
    _nmap_target,
    NMAP_HOST_TIMEOUT,
    NMAP_PROCESS_TIMEOUT_SECONDS,
    WELL_KNOWN_SERVICES,
)

logger = logging.getLogger(__name__)

# The whois package exposes no per-call timeout and runs the system binary
# without one either, so the wait is bounded here instead.
WHOIS_TIMEOUT_SECONDS = 20

class ReconModule:
    """Reconnaissance module for subdomain enumeration, port scanning, DNS enumeration, and WHOIS lookups"""
    
    def __init__(self):
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'm', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns4', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile',
            'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo',
            'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img',
            'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn',
            'stats', 'dns1', 'ns5', 'upload', 'client', 'forum', 'bb', 'subdomain',
            'stage', 'app', 'cdn1', 'cdn2', 'ns6', 'ns7', 'ns8', 'ns9', 'ns10'
        ]
    
    def find_subdomains(self, domain):
        """Find subdomains using multiple techniques"""
        try:
            subdomains = set()
            
            # Method 1: Common subdomain brute force
            logger.info(f"Starting subdomain enumeration for {domain}")
            subdomains.update(self._brute_force_subdomains(domain))
            
            # Method 2: Certificate transparency logs
            subdomains.update(self._cert_transparency_search(domain))
            
            # Method 3: DNS zone transfer attempt
            subdomains.update(self._dns_zone_transfer(domain))
            
            # Remove the main domain from results if present
            subdomains.discard(domain)
            
            # Verify subdomains are actually resolvable
            verified_subdomains = self._verify_subdomains(list(subdomains))
            
            result = {
                'domain': domain,
                'total_found': len(verified_subdomains),
                'subdomains': verified_subdomains,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Found {len(verified_subdomains)} subdomains for {domain}")
            return result
            
        except Exception as e:
            logger.error(f"Subdomain enumeration failed: {str(e)}")
            return {'error': str(e), 'domain': domain}
    
    def _brute_force_subdomains(self, domain):
        """Brute force common subdomains"""
        found_subdomains = []
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                found_subdomains.append(full_domain)
                logger.info(f"Subdomain found: {full_domain}")
            except socket.gaierror:
                pass
        
        # Use ThreadPoolExecutor for concurrent subdomain checking; consuming
        # the map iterator surfaces worker exceptions instead of burying them
        # in futures that are never inspected.
        with ThreadPoolExecutor(max_workers=50) as executor:
            list(executor.map(check_subdomain, self.common_subdomains))
        
        return found_subdomains
    
    def _cert_transparency_search(self, domain):
        """Search certificate transparency logs for subdomains"""
        try:
            # crt.sh matches lowercase names; an uppercase domain from the
            # client would silently return zero matches.
            domain = domain.strip().lower()
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(
                url,
                timeout=10,
                headers={'User-Agent': 'Network-Scanner/1.0 (security auditing tool)'},
            )

            if response.status_code == 200:
                cert_data = response.json()
                subdomains = set()

                for cert in cert_data:
                    name_value = cert.get('name_value', '')
                    if name_value:
                        # Handle multi-line certificate names
                        names = name_value.split('\n')
                        for domain_name in names:
                            domain_name = domain_name.strip().lower()
                            # Skip wildcard cert entries (e.g. *.example.com) —
                            # the wildcard itself is not a real subdomain.
                            if domain_name.startswith('*.'):
                                continue
                            if domain_name.endswith(f'.{domain}') or domain_name == domain:
                                subdomains.add(domain_name)
                
                logger.info(f"Certificate transparency found {len(subdomains)} entries")
                return list(subdomains)
            
        except Exception as e:
            logger.warning(f"Certificate transparency search failed: {str(e)}")
        
        return []
    
    def _dns_zone_transfer(self, domain):
        """Attempt DNS zone transfer"""
        subdomains = []
        try:
            # Get nameservers for the domain
            ns_records = dns.resolver.resolve(domain, 'NS')
            
            for ns in ns_records:
                try:
                    # Attempt zone transfer. Without an explicit lifetime a
                    # silent nameserver would leave the request thread hanging
                    # forever (dnspython does not apply a default cap here).
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain, timeout=5, lifetime=15))
                    for name in zone.nodes.keys():
                        subdomain = f"{name}.{domain}"
                        if subdomain != domain:
                            subdomains.append(subdomain)
                    
                    logger.info(f"Zone transfer successful from {ns}")
                    break
                    
                except Exception:
                    continue
                    
        except Exception as e:
            logger.info(f"Zone transfer not available: {str(e)}")
        
        return subdomains
    
    def _verify_subdomains(self, subdomains):
        """Verify that subdomains are actually resolvable"""
        verified = []
        
        def verify_subdomain(subdomain):
            try:
                socket.gethostbyname(subdomain)
                verified.append(subdomain)
            except socket.gaierror:
                pass
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            # Consume the map so worker exceptions propagate to the caller
            # instead of dying with the uniterated futures.
            list(executor.map(verify_subdomain, subdomains))
        
        return sorted(verified)
    
    def _probe_host_live(self, ip_str, probe_ports=(80, 443, 22, 445, 8080, 139, 3389, 21, 53), timeout=0.35):
        """Check if a host is alive via socket probes and resolve its canonical hostname."""
        is_alive = False
        open_probe_ports = []
        
        # 1. Quick TCP connect probes on common discovery ports
        for port in probe_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    res = sock.connect_ex((ip_str, port))
                    if res == 0:
                        is_alive = True
                        open_probe_ports.append(port)
            except OSError:
                continue

        # 2. Canonical hostname resolution via reverse DNS
        hostname = ip_str
        try:
            resolved_name = socket.getnameinfo((ip_str, 0), socket.NI_NAMEREQD)[0]
            if resolved_name and resolved_name != ip_str:
                hostname = resolved_name
        except (socket.herror, socket.gaierror, OSError):
            try:
                host_tuple = socket.gethostbyaddr(ip_str)
                if host_tuple and host_tuple[0]:
                    hostname = host_tuple[0]
            except (socket.herror, socket.gaierror, OSError):
                hostname = ip_str

        return {
            'ip_address': ip_str,
            'hostname': hostname,
            'alive': is_alive,
            'discovered_ports': open_probe_ports
        }

    @staticmethod
    def _infer_os(os_matches, open_ports, banners=""):
        """Infer Operating System from Nmap osmatch, open ports, and service banners."""
        if os_matches and len(os_matches) > 0 and os_matches[0]:
            return os_matches[0]

        port_nums = {p.get('port') for p in open_ports if isinstance(p, dict)}
        services = {str(p.get('service', '')).lower() for p in open_ports if isinstance(p, dict)}
        products = " ".join([str(p.get('product', '')) for p in open_ports if isinstance(p, dict)]).lower()
        all_text = f"{products} {banners}".lower()

        if 3389 in port_nums or 445 in port_nums or 'microsoft' in all_text or 'windows' in all_text or 'ms-wbt-server' in services:
            return 'Windows'
        if 'ubuntu' in all_text:
            return 'Linux (Ubuntu)'
        if 'debian' in all_text:
            return 'Linux (Debian)'
        if 'centos' in all_text or 'redhat' in all_text or 'rhel' in all_text:
            return 'Linux (RHEL/CentOS)'
        if 22 in port_nums or 'ssh' in services or 'linux' in all_text:
            return 'Linux / Unix'
        if 80 in port_nums or 443 in port_nums:
            if 'iis' in all_text:
                return 'Windows Server (IIS)'
            if 'apache' in all_text or 'nginx' in all_text:
                return 'Linux / Unix (Web Server)'
        if 'cisco' in all_text or 'router' in all_text or 161 in port_nums:
            return 'Network Appliance / Embedded'
        return 'Generic / Unknown OS'

    def _parse_port_range(self, port_range_str):
        """Parse port range string (e.g. '1-100', '80,443', '22-25,80') into a list of ints."""
        ports = []
        try:
            for part in str(port_range_str).split(','):
                part = part.strip()
                if '-' in part:
                    s, e = part.split('-', 1)
                    ports.extend(range(int(s), int(e) + 1))
                elif part.isdigit():
                    ports.append(int(part))
        except Exception:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]
        return ports if ports else [80, 443, 22, 21, 3389]

    def _socket_port_scan(self, targets_to_scan, port_range):
        """High-speed native socket port scanner fallback when Nmap is unavailable."""
        ports_to_check = self._parse_port_range(port_range)
        if len(ports_to_check) > 1024:
            ports_to_check = ports_to_check[:1024]

        results = []
        for host in targets_to_scan:
            open_ports = []
            hostname = host
            try:
                host_tuple = socket.gethostbyaddr(host)
                if host_tuple and host_tuple[0]:
                    hostname = host_tuple[0]
            except Exception:
                hostname = host

            def probe_host_port(port):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.4)
                        if s.connect_ex((host, port)) == 0:
                            service_info = WELL_KNOWN_SERVICES.get(port, ('unknown', ''))
                            service_name = service_info[0] if isinstance(service_info, tuple) else service_info
                            product_name = service_info[1] if isinstance(service_info, tuple) else ''
                            version = ''
                            banner = ''
                            try:
                                if port in (80, 8080, 443, 8443):
                                    scheme = 'https' if port in (443, 8443) else 'http'
                                    resp = requests.get(f"{scheme}://{host}:{port}", timeout=0.8, verify=False)
                                    server = resp.headers.get('Server', '')
                                    powered_by = resp.headers.get('X-Powered-By', '')
                                    if server:
                                        product_name = server
                                        banner = server
                                    if powered_by:
                                        product_name = f"{product_name} ({powered_by})".strip()
                                elif port in (21, 22, 23, 25, 110, 143):
                                    raw_banner = s.recv(256).decode('utf-8', errors='ignore').strip()
                                    if raw_banner:
                                        banner = raw_banner
                                        product_name = raw_banner
                                        if port == 22 and 'SSH' in raw_banner:
                                            service_name = 'ssh'
                                elif port == 3306:
                                    raw_mysql = s.recv(256)
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
                                'protocol': 'tcp',
                                'service': service_name,
                                'version': version,
                                'product': product_name,
                                'banner': banner,
                                'state': 'open'
                            }
                except Exception:
                    pass
                return None

            with ThreadPoolExecutor(max_workers=min(40, max(1, len(ports_to_check)))) as executor:
                port_results = executor.map(probe_host_port, ports_to_check)
                for pr in port_results:
                    if pr:
                        open_ports.append(pr)

            open_ports = sorted(open_ports, key=lambda x: x['port'])
            is_up = len(open_ports) > 0 or host in ('127.0.0.1', 'localhost')
            
            results.append({
                'host': host,
                'ip_address': host,
                'hostname': hostname,
                'alive': is_up,
                'state': 'up' if is_up else 'down',
                'open_ports': open_ports,
                'os_match': [],
                'inferred_os': self._infer_os([], open_ports)
            })

        return results

    def port_scan(self, target, port_range='1-1000'):
        """Perform port scan on a single target IP/domain or a CIDR subnet block."""
        try:
            logger.info(f"Starting port scan on {target} (ports {port_range})")

            # Check if target is a CIDR network
            is_cidr = False
            cidr_network = None
            try:
                if '/' in target and not target.lower().startswith(('http://', 'https://')):
                    cidr_network = ipaddress.ip_network(target, strict=False)
                    if cidr_network.num_addresses > 1:
                        is_cidr = True
            except ValueError:
                pass

            live_discovered_hosts = []
            targets_to_scan = []

            if is_cidr and cidr_network:
                # Extract all host IPs in the CIDR subnet (safety limit max 1024)
                host_ips = [str(ip) for ip in cidr_network.hosts()]
                if not host_ips:
                    host_ips = [str(cidr_network.network_address)]
                
                logger.info(f"Sweeping CIDR subnet {target} ({len(host_ips)} hosts) using ThreadPoolExecutor...")
                
                # Concurrent host-discovery sweep
                workers = min(64, max(10, len(host_ips)))
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    sweep_results = list(executor.map(self._probe_host_live, host_ips))
                
                live_discovered_hosts = [h for h in sweep_results if h['alive']]
                logger.info(f"CIDR sweep complete: {len(live_discovered_hosts)} live hosts found out of {len(host_ips)}")

                if live_discovered_hosts:
                    targets_to_scan = [h['ip_address'] for h in live_discovered_hosts]
                else:
                    targets_to_scan = host_ips[:32]
            else:
                # Single host or domain
                clean_target = _nmap_target(target)
                targets_to_scan = [clean_target]

            try:
                # A shared PortScanner instance is not thread-safe under the
                # threaded WSGI server: python-nmap stores per-scan state on the
                # object, so concurrent scans would read each other's results.
                nm = nmap.PortScanner()
                scan_args = _nmap_scan_args() + f" --host-timeout={NMAP_HOST_TIMEOUT}"
                if '-sS' in scan_args:
                    scan_args += ' -O'

                nmap_target_str = " ".join(targets_to_scan)
                scan_output = nm.scan(
                    nmap_target_str,
                    port_range,
                    arguments=scan_args,
                    timeout=NMAP_PROCESS_TIMEOUT_SECONDS,
                )
                scan_error = scan_output.get('nmap', {}).get('scaninfo', {}).get('error')
                if scan_error:
                    message = ''.join(scan_error) if isinstance(scan_error, list) else str(scan_error)
                    raise RuntimeError(f"Nmap execution failed: {message.strip()}")

                results = []
                for host in nm.all_hosts():
                    host_state = nm[host].state()
                    os_matches = [o.get('name') for o in nm[host].get('osmatch', [])]
                    
                    # Resolve canonical hostname
                    nmap_hostname = nm[host].hostname() or host
                    if nmap_hostname == host:
                        try:
                            host_tuple = socket.gethostbyaddr(host)
                            if host_tuple and host_tuple[0]:
                                nmap_hostname = host_tuple[0]
                        except Exception:
                            nmap_hostname = host

                    host_info = {
                        'host': host,
                        'ip_address': host,
                        'hostname': nmap_hostname,
                        'alive': host_state == 'up',
                        'state': host_state,
                        'open_ports': [],
                        'os_match': os_matches,
                        'inferred_os': self._infer_os(os_matches, [])
                    }
                    
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in ports:
                            port_info = nm[host][proto][port]
                            if port_info['state'] == 'open':
                                host_info['open_ports'].append({
                                    'port': port,
                                    'protocol': proto,
                                    'service': port_info.get('name', 'unknown'),
                                    'version': port_info.get('version', ''),
                                    'product': port_info.get('product', ''),
                                    'state': port_info['state']
                                })
                    
                    host_info['inferred_os'] = self._infer_os(os_matches, host_info['open_ports'])
                    results.append(host_info)
            except (getattr(nmap, 'PortScannerError', type('PortScannerError', (Exception,), {})), FileNotFoundError, OSError) as nmap_err:
                logger.warning(f"Nmap unavailable ({nmap_err}); performing high-speed native socket port scan.")
                results = self._socket_port_scan(targets_to_scan, port_range)

            # Ensure any live hosts discovered during CIDR sweep without open ports in the scanned range are still included
            if is_cidr:
                reported_ips = {h['ip_address'] for h in results}
                for live_host in live_discovered_hosts:
                    if live_host['ip_address'] not in reported_ips:
                        discovered_ports = [
                            {
                                'port': p,
                                'protocol': 'tcp',
                                'service': 'active-probe',
                                'version': '',
                                'product': '',
                                'state': 'open'
                            } for p in live_host.get('discovered_ports', [])
                        ]
                        results.append({
                            'host': live_host['ip_address'],
                            'ip_address': live_host['ip_address'],
                            'hostname': live_host['hostname'],
                            'alive': True,
                            'state': 'up',
                            'open_ports': discovered_ports,
                            'os_match': [],
                            'inferred_os': self._infer_os([], discovered_ports)
                        })

            result = {
                'target': target,
                'port_range': port_range,
                'is_cidr': is_cidr,
                'total_hosts': len(results),
                'scan_results': results,
                'total_open_ports': sum(len(host['open_ports']) for host in results),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Port scan completed for {target}: {len(results)} hosts analyzed")
            return result
            
        except Exception as e:
            logger.error(f"Port scan failed: {str(e)}")
            return {'error': str(e), 'target': target}
    
    def whois_lookup(self, domain):
        """Perform WHOIS lookup"""
        try:
            logger.info(f"Performing WHOIS lookup for {domain}")

            # The pinned whois==0.9.27 release exposes query(), while older
            # builds of the same package expose whois(). Support both entry
            # points so the lookup does not depend on which variant was
            # resolved at install time.
            lookup = getattr(whois, 'whois', None) or getattr(whois, 'query', None)
            if lookup is None:
                raise RuntimeError("whois library exposes neither whois() nor query()")
            # The whois package exposes no per-call timeout; bound the wait
            # with a daemon worker so a hung WHOIS server cannot pin request
            # threads. A daemon thread never keeps the process alive at
            # shutdown, unlike an executor worker whose shutdown(wait=False)
            # still leaks a joinable thread per timed-out lookup.
            result_box = {}

            def run_lookup():
                try:
                    result_box['record'] = lookup(domain)
                except Exception as exc:
                    result_box['error'] = exc

            worker = threading.Thread(target=run_lookup, daemon=True)
            worker.start()
            worker.join(timeout=WHOIS_TIMEOUT_SECONDS)
            if worker.is_alive():
                return {'error': f'WHOIS lookup timed out for {domain}', 'domain': domain}
            if 'error' in result_box:
                raise result_box['error']
            w = result_box.get('record')
            if w is None:
                return {'error': f'No WHOIS data available for {domain}', 'domain': domain}

            result = {
                'domain': domain,
                'registrar': getattr(w, 'registrar', None),
                'creation_date': str(w.creation_date) if getattr(w, 'creation_date', None) else None,
                'expiration_date': str(w.expiration_date) if getattr(w, 'expiration_date', None) else None,
                'name_servers': list(w.name_servers) if getattr(w, 'name_servers', None) else [],
                'status': w.status if getattr(w, 'status', None) else [],
                'emails': w.emails if getattr(w, 'emails', None) else [],
                'org': getattr(w, 'org', None),
                'country': getattr(w, 'country', None),
                'timestamp': datetime.utcnow().isoformat()
            }

            logger.info(f"WHOIS lookup completed for {domain}")
            return result

        except Exception as e:
            logger.error("WHOIS lookup failed for %s: %s", domain, e)
            return {'error': str(e), 'domain': domain}
    
    def dns_enumeration(self, domain):
        """Perform comprehensive DNS enumeration"""
        try:
            logger.info(f"Starting DNS enumeration for {domain}")
            
            dns_records = {}
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_records[record_type] = []
                    
                    for answer in answers:
                        dns_records[record_type].append(str(answer))
                        
                except dns.resolver.NXDOMAIN:
                    dns_records[record_type] = ['NXDOMAIN']
                except dns.resolver.NoAnswer:
                    dns_records[record_type] = ['No Answer']
                except Exception as e:
                    dns_records[record_type] = [f'Error: {str(e)}']
            
            result = {
                'domain': domain,
                'dns_records': dns_records,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            logger.info(f"DNS enumeration completed for {domain}")
            return result
            
        except Exception as e:
            logger.error(f"DNS enumeration failed: {str(e)}")
            return {'error': str(e), 'domain': domain}
