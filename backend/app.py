from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv
from functools import wraps
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shlex
import threading
import time
import base64
from datetime import datetime
from urllib.parse import urlparse


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

PRODUCTION_SECRET_PLACEHOLDERS = {
    "",
    "dev-key-change-in-production",
    "your-secret-key-change-this",
    "replace-with-a-random-secret-key-at-least-32-characters",
    "change-this",
    "secret",
}
PRODUCTION_API_TOKEN_PLACEHOLDERS = {
    "",
    "replace-with-a-separate-random-api-access-token",
    "change-this",
    "secret",
}
VALID_VULNERABILITY_SCAN_TYPES = {"basic", "web", "network", "comprehensive"}
VALID_AUTOMATED_SCAN_TYPES = {"subdomain", "port", "vuln", "dns"}
PORT_RANGE_PATTERN = re.compile(r"^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$")
# Downloads are restricted to the files this service generates: the reports
# directory also holds operator notes (readme) that must not be served. The
# pattern matches the security_report_YYYYMMDD_HHMMSS names the generator
# emits (see ReportGenerator.generate_report).
REPORT_FILENAME_PATTERN = re.compile(r"^security_report_\d{8}_\d{6}\.(?:html|pdf)$")

# WebSocket events are not covered by flask-limiter, so cap how many
# automated scans may run at the same time on the scanner host.
SCAN_SLOTS = threading.BoundedSemaphore(int(os.environ.get("SCAN_CONCURRENCY") or "2"))


# Initialize Flask app
app = Flask(__name__)
is_production = os.environ.get("FLASK_ENV") == "production"
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-key-change-in-production")
if is_production and (
    app.config["SECRET_KEY"] in PRODUCTION_SECRET_PLACEHOLDERS
    or len(app.config["SECRET_KEY"]) < 32
):
    raise RuntimeError("SECRET_KEY must be a unique value of at least 32 characters in production")

api_access_token = os.environ.get("API_ACCESS_TOKEN", "")
if is_production and api_access_token in PRODUCTION_API_TOKEN_PLACEHOLDERS:
    raise RuntimeError("API_ACCESS_TOKEN must be a unique value in production")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
default_db_path = os.path.join(BASE_DIR, "network_scanner.db").replace("\\", "/")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", f"sqlite:///{default_db_path}")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# Reject oversized bodies early (scan payloads and report data are small).
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

if os.environ.get("TRUST_PROXY") == "1":
    # Deployment behind the reverse proxy: honor X-Forwarded-* so the real
    # client address drives per-client rate limiting. Off by default to keep
    # header spoofing ineffective in direct deployments.
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# CORS configuration: default to permissive in local/dev environments if CORS_ORIGINS is not set
cors_origins = [origin.strip() for origin in os.environ.get("CORS_ORIGINS", "").split(",") if origin.strip()]
if cors_origins:
    CORS(app, origins=cors_origins)
    socketio_options = {"cors_allowed_origins": cors_origins}
else:
    CORS(app, origins="*")
    socketio_options = {"cors_allowed_origins": "*"}

socketio = SocketIO(
    app,
    async_mode=os.environ.get("SOCKETIO_ASYNC_MODE", "threading"),
    **socketio_options,
)
def rate_limit_key():
    """Use the authenticated token when present; otherwise limit by source IP."""
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    if (
        api_access_token
        and scheme.lower() == "bearer"
        and token
        and hmac.compare_digest(token.encode(), api_access_token.encode())
    ):
        # Hash the token: limiter keys end up in the configured storage and
        # must not leak the credential itself.
        digest = hashlib.sha256(api_access_token.encode()).hexdigest()[:32]
        return f"token:{digest}"
    return get_remote_address()


limiter = Limiter(
    key_func=rate_limit_key,
    app=app,
    default_limits=[os.environ.get("RATE_LIMIT_DEFAULT") or "60 per minute"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI") or "memory://",
)
from extensions import db
db.init_app(app)


# Import modules
from modules.reconnaissance import ReconModule
from modules.ai_assistant import AIAssistant
from modules.scanner import VulnScanner
from modules.report_generator import ReportGenerator
from models.scan_results import ScanResult, User, Project

# Initialize modules
recon_module = ReconModule()
ai_assistant = AIAssistant()
vuln_scanner = VulnScanner()
report_generator = ReportGenerator()


def init_database(app_instance):
    """Ensure database schema exists and default demo credentials are initialized."""
    with app_instance.app_context():
        try:
            db.create_all()
            admin_user = User.query.filter(
                (User.username == 'admin') | (User.email == 'admin@cybersentry.local')
            ).first()
            if not admin_user:
                demo_admin = User(
                    username='admin',
                    email='admin@cybersentry.local',
                    password_hash=generate_password_hash('Admin@123'),
                    role='admin',
                    is_active=True,
                    learning_mode=True
                )
                db.session.add(demo_admin)
                db.session.commit()
                app_instance.logger.info("Database initialized with default admin user.")
        except Exception as e:
            db.session.rollback()
            app_instance.logger.exception("Database schema initialization notice: %s", e)

init_database(app)


@app.before_request
def ensure_db_schema():
    """Ensure DB tables exist on every incoming request in case of runtime reset."""
    if request.path.startswith("/api/auth"):
        try:
            db.create_all()
        except Exception:
            pass


def get_json_payload():
    """Return a JSON object body or None when the request body is invalid."""
    payload = request.get_json(silent=True)
    return payload if isinstance(payload, dict) else None


def get_scan_error(result):
    """Return an explicit module failure message, preserving legitimate empty results."""
    if isinstance(result, dict) and result.get("error"):
        return str(result["error"])
    return None


def scan_failure_response(result, target, scan_name):
    """Convert an explicit scanner-module failure into a consistent API error."""
    error = get_scan_error(result)
    if not error:
        return None
    app.logger.error("%s failed for %s: %s", scan_name, target, error)
    return jsonify({
        "error": f"{scan_name} failed",
        "details": error,
        "target": target,
    }), 502


def require_api_token(view):
    """Require the operator-provided bearer token when one is configured."""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not api_access_token:
            return view(*args, **kwargs)

        # Compare bytes: hmac.compare_digest(str, str) is ASCII-only and
        # raises TypeError on hostile non-ASCII header values, turning an
        # authentication failure into a server error before the request
        # even reaches the limiter.
        authorization = request.headers.get("Authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token or not hmac.compare_digest(
            token.encode(), api_access_token.encode()
        ):
            return jsonify({"error": "Valid bearer token required"}), 401
        return view(*args, **kwargs)

    return wrapped_view


def validate_target(value):
    """Return a normalized target or a human-readable validation error."""
    if not isinstance(value, str):
        return None, "Target must be a string"
    target = value.strip()
    if not target:
        return None, "Target is required"
    if len(target) > 253 or any(character.isspace() for character in target):
        return None, "Target contains invalid characters"
    try:
        parsed_target = shlex.split(target)
    except ValueError:
        return None, "Target contains invalid characters"
    if len(parsed_target) != 1 or parsed_target[0] != target or parsed_target[0].startswith("-"):
        return None, "Target must not start with an option prefix"
    if target.lower().startswith(("http://", "https://")):
        try:
            url_host = urlparse(target).hostname or ""
        except ValueError:
            # urlparse raises on malformed IPv6 URLs (e.g. "http://[");
            # reject them as invalid input instead of erroring later.
            return None, "Target contains invalid characters"
        if url_host.startswith("-"):
            # Stripping the scheme would hand Nmap an argv option (python-nmap
            # re-splits the host string), so refuse these targets up front.
            return None, "Target host must not start with an option prefix"
    elif "/" in target:
        # Validate CIDR notation safely using Python's ipaddress module
        try:
            net = ipaddress.ip_network(target, strict=False)
            if net.num_addresses > 1024:
                return None, "CIDR block is too large (maximum 1024 hosts / /22 supported)"
            return str(net), None
        except ValueError:
            return None, "Target contains invalid CIDR notation"
    return target, None


def validate_port_range(value):
    """Accept only Nmap-compatible numeric single ports, ranges, and lists."""
    if not isinstance(value, str):
        return None, "Port range must be a string"
    port_range = value.strip()
    if len(port_range) > 200:
        return None, "Port range is too long"
    if not PORT_RANGE_PATTERN.fullmatch(port_range):
        return None, "Port range must contain only ports, ranges, and commas"

    for part in port_range.split(","):
        start_text, separator, end_text = part.partition("-")
        start = int(start_text)
        end = int(end_text) if separator else start
        if not 1 <= start <= end <= 65535:
            return None, "Ports must be between 1 and 65535"
    return port_range, None

def generate_user_token(user_id):
    """Generate a tamper-proof URL-safe auth token with HMAC signature."""
    timestamp = int(time.time())
    payload = f"{user_id}:{timestamp}"
    signature = hmac.new(
        app.config["SECRET_KEY"].encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    raw = f"{payload}:{signature}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("utf-8")


def verify_user_token(token_str, max_age_seconds=86400 * 14):
    """Verify an auth token string and return the User instance, or None if invalid/expired."""
    if not token_str or not isinstance(token_str, str):
        return None
    try:
        raw = base64.urlsafe_b64decode(token_str.encode("utf-8")).decode("utf-8")
        parts = raw.split(":")
        if len(parts) != 3:
            return None
        user_id_str, timestamp_str, sig = parts
        user_id = int(user_id_str)
        timestamp = int(timestamp_str)
        if (time.time() - timestamp) > max_age_seconds:
            return None
        payload = f"{user_id}:{timestamp}"
        expected_sig = hmac.new(
            app.config["SECRET_KEY"].encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        return db.session.get(User, user_id)
    except Exception:
        return None


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})


@app.route('/api/auth/signup', methods=['POST'])
@limiter.limit("20 per minute")
def auth_signup():
    """Register a new user account."""
    try:
        db.create_all()
        payload = get_json_payload()
        if not payload:
            return jsonify({"error": "Request body must be a JSON object"}), 400

        username = (payload.get("username") or "").strip()
        email = (payload.get("email") or "").strip().lower()
        password = payload.get("password") or ""
        role = (payload.get("role") or "analyst").strip().lower()

        if not username or len(username) < 3 or len(username) > 40:
            return jsonify({"error": "Username must be between 3 and 40 characters"}), 400
        if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
            return jsonify({"error": "Username may only contain letters, numbers, dots, and underscores"}), 400

        if not email or "@" not in email or "." not in email.split("@")[-1] or len(email) > 120:
            return jsonify({"error": "Please provide a valid email address"}), 400

        if not password or len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters long"}), 400

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            if existing_user.email == email:
                return jsonify({"error": "An account with this email address already exists"}), 409
            return jsonify({"error": "Username is already taken"}), 409

        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role=role if role in ["admin", "analyst", "user", "viewer"] else "analyst",
            is_active=True,
            learning_mode=True
        )
        db.session.add(new_user)
        db.session.commit()

        token = generate_user_token(new_user.id)
        return jsonify({
            "message": "Account created successfully",
            "token": token,
            "user": new_user.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        app.logger.exception("Failed to register user: %s", e)
        return jsonify({"error": f"Failed to create account: {str(e)}"}), 500


@app.route('/api/auth/signin', methods=['POST'])
@limiter.limit("30 per minute")
def auth_signin():
    """Authenticate an existing user with username/email and password."""
    try:
        db.create_all()
        payload = get_json_payload()
        if not payload:
            return jsonify({"error": "Request body must be a JSON object"}), 400

        account = (payload.get("account") or payload.get("email") or payload.get("username") or "").strip()
        password = payload.get("password") or ""

        if not account or not password:
            return jsonify({"error": "Account username/email and password are required"}), 400

        user = User.query.filter(
            (User.email == account.lower()) | (User.username == account)
        ).first()

        if not user or not user.password_hash or not check_password_hash(user.password_hash, password):
            return jsonify({"error": "Invalid username/email or password"}), 401

        if not user.is_active:
            return jsonify({"error": "This account has been deactivated. Please contact an administrator."}), 403

        token = generate_user_token(user.id)
        return jsonify({
            "message": "Authentication successful",
            "token": token,
            "user": user.to_dict()
        }), 200
    except Exception as e:
        app.logger.exception("Signin error: %s", e)
        return jsonify({"error": f"Authentication server error: {str(e)}"}), 500


@app.route('/api/auth/me', methods=['GET'])
def auth_me():
    """Verify session token and retrieve current authenticated user details."""
    try:
        authorization = request.headers.get("Authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return jsonify({"error": "Authentication token required"}), 401

        user = verify_user_token(token)
        if not user or not user.is_active:
            return jsonify({"error": "Invalid or expired session token"}), 401

        return jsonify({
            "user": user.to_dict()
        }), 200
    except Exception as e:
        app.logger.exception("Auth me error: %s", e)
        return jsonify({"error": "Session validation failed"}), 500


@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    """Acknowledge logout."""
    return jsonify({"message": "Logged out successfully"}), 200


@app.route('/api/scan', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_SCAN") or "10 per minute")
@require_api_token
def unified_scan():
    """Unified end-to-end security assessment pipeline endpoint.
    
    Sequentially executes:
    1. Subdomain Discovery (crt.sh & DNS resolver)
    2. High-Speed Port & Banner Scanner (Python native socket/asyncio banner grabbing)
    3. Web Security Posture & Header Audit (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, cookies)
    4. Sensitive Endpoint Probing (/robots.txt, /.well-known/security.txt, /.git/HEAD, /swagger.json, /.env, etc.)
    5. Insecure Service & Default Credential Audit
    6. Exploit-Aware CVE & Risk Scoring Engine (CVSS vectors, CISA KEV tags, EPSS percentiles, remediation playbooks)
    7. DNS & WHOIS reconnaissance (if domain)
    8. AI Assistant security analysis & executive summary
    """
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        
        target_raw = payload.get("target") or payload.get("domain")
        target, target_error = validate_target(target_raw)
        if target_error:
            return jsonify({"error": target_error}), 400
        
        port_range = payload.get("port_range", "21,22,23,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,5900,8080,8443")
        port_range, port_range_error = validate_port_range(port_range)
        if port_range_error:
            port_range = "1-1000"

        # Determine clean domain / host for subdomains and DNS
        clean_host = target.replace("http://", "").replace("https://", "").partition("/")[0].partition(":")[0]
        is_ip_or_cidr = False
        try:
            if "/" in clean_host:
                ipaddress.ip_network(clean_host, strict=False)
                is_ip_or_cidr = True
            else:
                ipaddress.ip_address(clean_host)
                is_ip_or_cidr = True
        except ValueError:
            is_ip_or_cidr = False

        # 1. Subdomain Discovery (for domains)
        subdomains = []
        subdomain_data = {}
        if not is_ip_or_cidr:
            try:
                sub_res = recon_module.find_subdomains(clean_host)
                if isinstance(sub_res, dict) and not sub_res.get("error"):
                    subdomain_data = sub_res
                    subdomains = sub_res.get("subdomains", [])
            except Exception as e:
                app.logger.warning("Subdomain discovery non-fatal error for %s: %s", clean_host, e)

        # 2. High-Speed Port & Banner Scanner
        port_res = recon_module.port_scan(clean_host, port_range)
        scan_results = []
        flat_open_ports = []
        total_open_ports = 0
        if isinstance(port_res, dict) and not port_res.get("error"):
            scan_results = port_res.get("scan_results", [])
            total_open_ports = port_res.get("total_open_ports", 0)
            for h in scan_results:
                for p in h.get("open_ports", []):
                    flat_open_ports.append(p)

        # 3, 4, 5, 6. Web Security, Endpoint Probing, Insecure Services & Exploit-Aware Vulnerability Engine
        vuln_res = vuln_scanner.scan_target(target, scan_type='comprehensive')
        vulnerabilities = []
        misconfigurations = []
        severity_breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        
        if isinstance(vuln_res, dict) and not vuln_res.get("error"):
            vulnerabilities = vuln_res.get("vulnerabilities", [])
            misconfigurations = vuln_res.get("misconfigurations", [])
            severity_breakdown = vuln_res.get("severity_breakdown", severity_breakdown)

        # 7. DNS Enumeration & WHOIS (if domain)
        dns_records = {}
        whois_data = {}
        if not is_ip_or_cidr:
            try:
                dns_res = recon_module.dns_enumeration(clean_host)
                if isinstance(dns_res, dict) and not dns_res.get("error"):
                    dns_records = dns_res.get("dns_records", {})
            except Exception:
                pass
            try:
                w_res = recon_module.whois_lookup(clean_host)
                if isinstance(w_res, dict) and not w_res.get("error"):
                    whois_data = w_res
            except Exception:
                pass

        # 8. AI Analysis
        aggregate_findings = {
            "target": target,
            "subdomains": subdomain_data,
            "ports": port_res if isinstance(port_res, dict) else {},
            "vulnerabilities": vuln_res if isinstance(vuln_res, dict) else {},
            "dns": dns_records,
        }
        ai_analysis = ai_assistant.analyze_comprehensive_scan(aggregate_findings)

        total_vulnerabilities = len(vulnerabilities) + len(misconfigurations)

        # Construct final unified dataset
        unified_output = {
            "target": target,
            "domain": clean_host,
            "scan_type": "unified",
            "subdomains": subdomains,
            "total_subdomains": len(subdomains),
            "subdomain_data": subdomain_data,
            "scan_results": scan_results,
            "open_ports": flat_open_ports,
            "total_open_ports": total_open_ports,
            "port_data": port_res if isinstance(port_res, dict) else {},
            "vulnerabilities": vulnerabilities,
            "misconfigurations": misconfigurations,
            "total_vulnerabilities": total_vulnerabilities,
            "severity_breakdown": severity_breakdown,
            "dns_records": dns_records,
            "whois_data": whois_data,
            "ai_analysis": ai_analysis,
            "timestamp": datetime.utcnow().isoformat()
        }

        return jsonify(unified_output)

    except HTTPException:
        raise
    except Exception:
        app.logger.exception("Unhandled error in unified scan: %s", request.path)
        return jsonify({"error": "Internal server error during unified scan"}), 500

@app.route('/api/scan/subdomain', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_SCAN") or "10 per minute")
@require_api_token
def scan_subdomains():
    """Subdomain enumeration endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        domain, error = validate_target(payload.get("domain"))
        if error:
            return jsonify({"error": error}), 400

        # Perform subdomain scan
        results = recon_module.find_subdomains(domain)
        failure_response = scan_failure_response(results, domain, "Subdomain enumeration")
        if failure_response:
            return failure_response

        # Get AI analysis
        ai_analysis = ai_assistant.analyze_subdomains(results)
        
        subdomain_data = results if isinstance(results, dict) else {}
        return jsonify({
            "domain": domain,
            "subdomains": subdomain_data.get("subdomains", results if isinstance(results, list) else []),
            "total_found": subdomain_data.get("total_found", 0),
            "subdomain_data": subdomain_data,
            "ai_analysis": ai_analysis,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except HTTPException:
        raise
    except Exception:
        app.logger.exception("Unhandled error in %s", request.path)
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/scan/ports', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_SCAN") or "10 per minute")
@require_api_token
def scan_ports():
    """Port scanning endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        target, target_error = validate_target(payload.get("target"))
        if target_error:
            return jsonify({"error": target_error}), 400
        port_range, port_range_error = validate_port_range(payload.get("port_range", "1-1000"))
        if port_range_error:
            return jsonify({"error": port_range_error}), 400

        # Perform port scan
        results = recon_module.port_scan(target, port_range)
        failure_response = scan_failure_response(results, target, "Port scan")
        if failure_response:
            return failure_response

        # Get AI analysis
        ai_analysis = ai_assistant.analyze_ports(results)
        
        port_data = results if isinstance(results, dict) else {}
        return jsonify({
            "target": target,
            "port_range": port_range,
            "open_ports": results,
            "scan_results": port_data.get("scan_results", []),
            "total_open_ports": port_data.get("total_open_ports", 0),
            "port_data": port_data,
            "ai_analysis": ai_analysis,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except HTTPException:
        raise
    except Exception:
        app.logger.exception("Unhandled error in %s", request.path)
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/scan/whois', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_SCAN") or "10 per minute")
@require_api_token
def whois_lookup():
    """WHOIS lookup endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        domain, error = validate_target(payload.get("domain"))
        if error:
            return jsonify({"error": error}), 400

        # Perform WHOIS lookup
        results = recon_module.whois_lookup(domain)
        failure_response = scan_failure_response(results, domain, "WHOIS lookup")
        if failure_response:
            return failure_response

        return jsonify({
            "domain": domain,
            "whois_data": results,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except HTTPException:
        raise
    except Exception:
        app.logger.exception("Unhandled error in %s", request.path)
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/scan/dns', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_SCAN") or "10 per minute")
@require_api_token
def dns_enumeration():
    """DNS enumeration endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        domain, error = validate_target(payload.get("domain"))
        if error:
            return jsonify({"error": error}), 400

        # Perform DNS enumeration
        results = recon_module.dns_enumeration(domain)
        failure_response = scan_failure_response(results, domain, "DNS enumeration")
        if failure_response:
            return failure_response

        # Get AI analysis
        ai_analysis = ai_assistant.analyze_dns(results)
        
        return jsonify({
            "domain": domain,
            "dns_records": results,
            "ai_analysis": ai_analysis,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except HTTPException:
        raise
    except Exception:
        app.logger.exception("Unhandled error in %s", request.path)
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/vulnerability/scan', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_SCAN") or "10 per minute")
@require_api_token
def vulnerability_scan():
    """Vulnerability scanning endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        target, target_error = validate_target(payload.get("target"))
        if target_error:
            return jsonify({"error": target_error}), 400
        scan_type = payload.get("scan_type", "basic")
        if scan_type not in VALID_VULNERABILITY_SCAN_TYPES:
            return jsonify({"error": "scan_type must be one of: basic, web, network, comprehensive"}), 400

        # Perform vulnerability scan
        results = vuln_scanner.scan_target(target, scan_type)
        failure_response = scan_failure_response(results, target, "Vulnerability scan")
        if failure_response:
            return failure_response

        # Get AI analysis and recommendations
        ai_analysis = ai_assistant.analyze_vulnerabilities(results)
        
        vulnerability_data = results if isinstance(results, dict) else {}
        return jsonify({
            "target": target,
            "scan_type": scan_type,
            "vulnerabilities": vulnerability_data.get("vulnerabilities", results if isinstance(results, list) else []),
            "total_vulnerabilities": vulnerability_data.get("total_vulnerabilities", 0),
            "severity_breakdown": vulnerability_data.get("severity_breakdown", {}),
            "vulnerability_data": vulnerability_data,
            "ai_analysis": ai_analysis,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except HTTPException:
        raise
    except Exception:
        app.logger.exception("Unhandled error in %s", request.path)
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/report/generate', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_REPORT") or "20 per minute")
@require_api_token
def generate_report():
    """Generate scan report endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        scan_data = payload.get('scan_data')
        report_format = payload.get('format', 'html')
        
        if not isinstance(scan_data, dict) or not scan_data:
            return jsonify({"error": "Scan data must be a non-empty JSON object"}), 400
        if not isinstance(report_format, str) or report_format.lower() not in {"html", "pdf"}:
            return jsonify({"error": "Format must be either html or pdf"}), 400
        
        # Generate report
        report_path = report_generator.generate_report(scan_data, report_format.lower())

        return jsonify({
            "report_path": os.path.basename(report_path),
            "format": report_format.lower(),
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except HTTPException:
        raise
    except Exception:
        app.logger.exception("Unhandled error in %s", request.path)
        return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(413)
def request_entity_too_large(error):
    """Map oversized bodies to a 413 instead of a generic 500."""
    return jsonify({"error": "Request body too large"}), 413

@app.route('/api/report/download/<path:filename>', methods=['GET'])
@limiter.limit(os.environ.get("RATE_LIMIT_REPORT") or "20 per minute")
@require_api_token
def download_report(filename):
    """Download a generated report from the configured reports directory."""
    reports_dir = os.environ.get('REPORTS_DIR', os.path.join(os.getcwd(), 'reports'))
    safe_filename = os.path.basename(filename)
    if safe_filename != filename or not REPORT_FILENAME_PATTERN.fullmatch(safe_filename):
        return jsonify({"error": "Invalid report filename"}), 400
    return send_from_directory(reports_dir, safe_filename, as_attachment=True)

@app.route('/api/ai/chat', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_AI") or "20 per minute")
@require_api_token
def ai_chat():
    """AI assistant chat endpoint"""
    try:
        payload = get_json_payload()
        if payload is None:
            return jsonify({"error": "Request body must be a JSON object"}), 400
        message = payload.get('message')
        context = payload.get('context', {})

        if not isinstance(message, str) or not (1 <= len(message) <= 4000):
            return jsonify({"error": "Message must be a string of 1 to 4000 characters"}), 400
        if not isinstance(context, dict):
            return jsonify({"error": "Context must be a JSON object"}), 400

        # Bound the scan data that travels into the prompt: full scan
        # payloads can be large and every byte is billed as input tokens.
        serialized_context = json.dumps(context, default=str)
        if len(serialized_context) > 20000:
            context = {"scan_results": "<omitted: context payload too large>", "note": "truncated"}
        
        # Get AI response
        response = ai_assistant.chat_response(message, context)
        
        return jsonify({
            "message": message,
            "response": response,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    except HTTPException:
        raise
    except Exception:
        app.logger.exception("Unhandled error in %s", request.path)
        return jsonify({"error": "Internal server error"}), 500

@socketio.on("connect")
def authenticate_socket(auth):
    """Reject WebSocket clients that do not present the configured API token."""
    if not api_access_token:
        return True
    token = auth.get("token") if isinstance(auth, dict) else None
    # The payload is arbitrary JSON: reject non-string tokens outright and
    # compare bytes so hostile non-ASCII values cannot raise mid-handshake.
    return bool(
        isinstance(token, str)
        and token
        and hmac.compare_digest(token.encode(), api_access_token.encode())
    )


@socketio.on("start_automated_scan")
def handle_automated_scan(data):
    """Run the selected, validated scan types for an authenticated socket client."""
    try:
        if not isinstance(data, dict):
            emit("scan_error", {"error": "Scan request must be an object"})
            return

        target, target_error = validate_target(data.get("target"))
        if target_error:
            emit("scan_error", {"error": target_error})
            return

        scan_types = data.get("scan_types", ["subdomain", "port", "vuln"])
        if not isinstance(scan_types, list) or not scan_types:
            emit("scan_error", {"error": "scan_types must be a non-empty list"})
            return
        if any(scan_type not in VALID_AUTOMATED_SCAN_TYPES for scan_type in scan_types):
            emit("scan_error", {"error": "scan_types contains an unsupported scan type"})
            return

        # Preserve selection order while avoiding duplicate work.
        selected_scan_types = list(dict.fromkeys(scan_types))

        if not SCAN_SLOTS.acquire(blocking=False):
            emit("scan_error", {"error": "An automated scan is already in progress, try again shortly"})
            return
        try:
            emit("scan_status", {"status": "starting", "message": f"Starting automated scan for {target}"})
            results = {}

            for scan_type in selected_scan_types:
                emit("scan_status", {"status": "running", "message": f"Running {scan_type} scan..."})
                if scan_type == "subdomain":
                    scan_result = recon_module.find_subdomains(target)
                    result_key = "subdomains"
                elif scan_type == "port":
                    scan_result = recon_module.port_scan(target)
                    result_key = "ports"
                elif scan_type == "vuln":
                    scan_result = vuln_scanner.scan_target(target)
                    result_key = "vulnerabilities"
                elif scan_type == "dns":
                    scan_result = recon_module.dns_enumeration(target)
                    result_key = "dns"

                scan_error = get_scan_error(scan_result)
                if scan_error:
                    app.logger.error("Automated %s scan failed for %s: %s", scan_type, target, scan_error)
                    emit("scan_error", {
                        "error": f"{scan_type} scan failed",
                        "details": scan_error,
                        "scan_type": scan_type,
                    })
                    return
                results[result_key] = scan_result

            results["ai_analysis"] = ai_assistant.analyze_comprehensive_scan(results)
            emit("scan_complete", {"results": results, "target": target})
        finally:
            SCAN_SLOTS.release()

    except Exception:
        app.logger.exception("Automated scan failed")
        emit("scan_error", {"error": "Automated scan failed"})

if __name__ == '__main__':
    # Create database tables and seed default admin if empty
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            demo_admin = User(
                username='admin',
                email='admin@cybersentry.local',
                password_hash=generate_password_hash('Admin@123'),
                role='admin',
                is_active=True,
                learning_mode=True
            )
            db.session.add(demo_admin)
            db.session.commit()

    # SECURITY: debug=False prevents RCE via the Werkzeug debugger PIN.
    # debug_mode is enabled only when FLASK_ENV=development (explicit opt-in).
    # SECURITY: bind to 127.0.0.1 by default to prevent public exposure.
    # Operators who need remote access (including Docker deployments) MUST set
    # the HOST env var (e.g. HOST=0.0.0.0) and place a reverse proxy with TLS
    # and authentication in front. docker-compose.yml sets HOST=0.0.0.0 for the
    # backend service so the container remains reachable on the Docker network.
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    host = os.environ.get('HOST', '127.0.0.1')
    # flask-socketio refuses to serve through Werkzeug outside debug mode
    # unless the operator acknowledges it; direct `python app.py` runs are
    # local-only (127.0.0.1) and never run the Werkzeug debugger because
    # debug stays off. Production deployments serve through gunicorn.
    socketio.run(
        app,
        host=host,
        port=5000,
        debug=debug_mode,
        allow_unsafe_werkzeug=True,
    )
