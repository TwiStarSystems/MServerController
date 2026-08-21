#!/usr/bin/env python3
"""
MServer - A web-based Minecraft server controller and manager
Python/Flask implementation with multi-server support and RBAC
"""

import os
import io
import re
import gzip
import json
import shutil
import signal
import atexit
import zipfile
import subprocess
import threading
import uuid
import time
import struct
import requests
import hashlib
import hmac
import secrets
import socket
import select
import pyotp
import qrcode
import argparse
import sys
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from enum import Enum
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from functools import wraps
from concurrent.futures import ThreadPoolExecutor
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from dotenv import load_dotenv

# Load environment variables from .env *before* importing local modules, so any
# module-level env reads in them (e.g. db.py's DB_PATH) see the configured values.
load_dotenv()

from flask import Flask, request, jsonify, send_from_directory, send_file, session, redirect, make_response
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf, CSRFError
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

from db import get_db, init_db, rollback_stray_transaction


# ── Typed environment-variable helpers ────────────────────────────────────────
# Keep every os.environ read consistent and validated. Empty/unset always falls
# back to the code default, so an existing install with no extra .env keys is
# unchanged. (_env_path is defined below, after BASE_DIR, since it needs it.)
def _env_str(key, default):
    """Return a stripped string env var, or `default` if unset/blank."""
    val = os.environ.get(key)
    val = val.strip() if val is not None else ''
    return val if val else default

def _env_int(key, default):
    """Return an int env var; warn and fall back to `default` on a bad value."""
    raw = os.environ.get(key)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        import warnings
        warnings.warn(f"{key}={raw!r} is not a valid integer; using default {default}.", stacklevel=2)
        return default

def _env_bool(key, default=False):
    """Return a bool env var. True set: 1/true/yes/on (case-insensitive)."""
    raw = os.environ.get(key)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ('1', 'true', 'yes', 'on')


# Load environment variables from .env file (loaded above, before local imports)

# Initialize Flask app
app = Flask(__name__, static_folder='public', static_url_path='')

# --- SECRET_KEY validation ---
_raw_secret = os.environ.get('SECRET_KEY', '')
if not _raw_secret:
    if os.environ.get('FLASK_ENV', 'production') != 'development':
        raise SystemExit(
            "SECRET_KEY not set in environment — refusing to start in production. "
            "Set SECRET_KEY in .env (re-run install.sh update, or generate one with "
            "`python3 -c \"import secrets; print(secrets.token_hex(32))\"`)."
        )
    import warnings
    warnings.warn(
        "SECRET_KEY not set in environment — a random key has been generated. "
        "Sessions will be invalidated on every restart. Set SECRET_KEY in .env to persist sessions.",
        stacklevel=2
    )
    _raw_secret = secrets.token_hex(32)
elif len(_raw_secret) < 32:
    import warnings
    warnings.warn(
        f"SECRET_KEY is short ({len(_raw_secret)} characters). "
        "Minimum 32 characters is recommended for production security. "
        "Consider regenerating your SECRET_KEY in .env.",
        stacklevel=2
    )
app.config['SECRET_KEY'] = _raw_secret

# Bounds for PERMANENT_SESSION_LIFETIME (seconds): floor avoids sessions that
# expire before a user can do anything useful; ceiling avoids an absurdly
# large value effectively creating non-expiring sessions.
PERMANENT_SESSION_LIFETIME_MIN_SECONDS = 300       # 5 minutes
PERMANENT_SESSION_LIFETIME_MAX_SECONDS = 2592000   # 30 days

def _clamp_session_lifetime(seconds):
    """Clamp a session-lifetime value (seconds) into the sane bounds above,
    warning if the caller's value was out of range."""
    clamped = max(PERMANENT_SESSION_LIFETIME_MIN_SECONDS,
                  min(PERMANENT_SESSION_LIFETIME_MAX_SECONDS, seconds))
    if clamped != seconds:
        import warnings
        warnings.warn(
            f"PERMANENT_SESSION_LIFETIME={seconds} is out of range "
            f"[{PERMANENT_SESSION_LIFETIME_MIN_SECONDS}, {PERMANENT_SESSION_LIFETIME_MAX_SECONDS}]; "
            f"clamped to {clamped}.", stacklevel=2
        )
    return clamped

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(
    seconds=_clamp_session_lifetime(_env_int('PERMANENT_SESSION_LIFETIME', 604800))
)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Set to True when serving over HTTPS (SESSION_COOKIE_SECURE=true in .env)
app.config['SESSION_COOKIE_SECURE'] = _env_bool('SESSION_COOKIE_SECURE', False)
# Optional: scope session cookie to a domain (e.g. .twistar.org for subdomain sharing)
_cookie_domain = _env_str('SESSION_COOKIE_DOMAIN', '')
if _cookie_domain:
    app.config['SESSION_COOKIE_DOMAIN'] = _cookie_domain
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0  # Disable caching for development
app.config['WTF_CSRF_TIME_LIMIT'] = None     # Token valid for full session lifetime
# Max upload size (large world ZIPs). Override with MAX_UPLOAD_SIZE_GB in .env.
app.config['MAX_CONTENT_LENGTH'] = _env_int('MAX_UPLOAD_SIZE_GB', 25) * 1024 * 1024 * 1024

# Configure ProxyFix for reverse proxy (e.g., Nginx) headers
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# Pre-authentication routes (login, register, MFA verify, logout, csrf-token) are
# exempted via @csrf.exempt decorators. They rely on rate limiting for protection.
# CSRF tokens are session-bound and cannot be reliably issued before a session exists
# (e.g. first visit via raw IP without prior cookie).

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Return JSON instead of HTML for CSRF failures so the frontend can parse the error"""
    return api_error('CSRF token missing or invalid. Please refresh the page and try again.', 403)

# Initialize SocketIO with threading async mode and tuned ping settings.
# Threading mode works natively with the existing subprocess/thread-based
# architecture. The simple-websocket package provides real WebSocket support
# (not just long-polling) without requiring gevent monkey-patching.
#
# CORS: set CORS_ORIGINS in .env to a comma-separated list of allowed origins,
# e.g. CORS_ORIGINS=https://panel.example.com,https://example.com
# Leave unset (or set to *) only for local/dev use.
_cors_env = _env_str('CORS_ORIGINS', '')
_socketio_cors: object = [o.strip() for o in _cors_env.split(',') if o.strip()] if _cors_env and _cors_env != '*' else '*'

socketio = SocketIO(
    app,
    manage_session=False,
    async_mode='threading',
    ping_interval=_env_int('SOCKETIO_PING_INTERVAL', 25),
    ping_timeout=_env_int('SOCKETIO_PING_TIMEOUT', 60),
    cors_allowed_origins=_socketio_cors
)

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[_env_str('RATE_LIMIT_DEFAULT', '100 per 15 minutes')],
    storage_uri="memory://"
)

# Flask-Limiter only wraps HTTP routes — it has no hook into SocketIO event
# handlers, so 'command'/'subscribe' spam could bypass the HTTP-only limits.
# This is a minimal, independent per-connection sliding-window counter keyed by
# the socket session id, applied to the socketio.on() handlers below.
SOCKET_COMMAND_RATE_LIMIT = _env_int('SOCKET_COMMAND_RATE_LIMIT', 20)            # commands
SOCKET_COMMAND_RATE_WINDOW = _env_int('SOCKET_COMMAND_RATE_WINDOW_SECONDS', 10)  # per N seconds
SOCKET_SUBSCRIBE_RATE_LIMIT = _env_int('SOCKET_SUBSCRIBE_RATE_LIMIT', 30)
SOCKET_SUBSCRIBE_RATE_WINDOW = _env_int('SOCKET_SUBSCRIBE_RATE_WINDOW_SECONDS', 10)

_socket_rate_lock = threading.Lock()
_socket_rate_hits = defaultdict(deque)  # (sid, event) -> deque[monotonic timestamps]

# Tracks each connected user's active websocket session ids, so a live
# permission change (group edit, server unsharing, group reassignment) can
# drop an already-connected socket's room membership immediately instead of
# waiting for it to reconnect. See _resync_user_rooms().
_user_sockets_lock = threading.Lock()
_user_sockets = defaultdict(set)  # user_id -> set of sids


def _socket_rate_limited(event, limit, window_seconds):
    """True if this socket connection has exceeded `limit` hits of `event`
    within the trailing `window_seconds`; otherwise records this hit and
    returns False."""
    key = (request.sid, event)
    now = time.monotonic()
    with _socket_rate_lock:
        hits = _socket_rate_hits[key]
        while hits and now - hits[0] > window_seconds:
            hits.popleft()
        if len(hits) >= limit:
            return True
        hits.append(now)
        return False

# Configuration
PORT = _env_int('PORT', 3000)
BASE_DIR = Path(__file__).parent.absolute()

def _env_path(key, default):
    """Return a resolved absolute Path from an env var, or `default` (a Path).
    Relative values are resolved against BASE_DIR; `~` is expanded."""
    raw = os.environ.get(key)
    if raw is None or not raw.strip():
        return Path(default).resolve()
    p = Path(raw.strip()).expanduser()
    if not p.is_absolute():
        p = BASE_DIR / p
    return p.resolve()

# Core directories. SERVERS_DIR / BACKUPS_DIR / DB_PATH are operator-overridable
# via .env (e.g. to put servers/backups/db on a separate volume). SERVERS_DIR is
# also the trusted containment base for per-server file routes — see
# is_server_path_allowed(); _env_path always returns a resolved absolute path so
# that containment re-pins cleanly to the configured location.
SERVERS_DIR = _env_path('SERVERS_DIR', BASE_DIR / 'servers')
BACKUPS_DIR = _env_path('BACKUPS_DIR', BASE_DIR / 'backups')
UPLOADS_DIR = BASE_DIR / 'uploads'
JOBS_TMP_DIR = UPLOADS_DIR / 'jobs'   # prepared zip-download artifacts produced by JobManager
RESOURCEPACKS_DIR = BASE_DIR / 'public' / 'resourcepacks'
SETTINGS_PATH = BASE_DIR / 'settings.json'
DB_PATH = _env_path('DB_PATH', BASE_DIR / 'msc.db')
JAR_URLS_PATH = BASE_DIR / 'configs' / 'jarurls.conf'
TOOLS_DIR = BASE_DIR / 'tools'
VERSION_FILE = BASE_DIR / 'version'

# Per-server panel-side cache of Bedrock gamertag -> XUID, learned from the
# "Player connected: <name>, xuid: <id>" console lines. Bedrock's permissions.json
# is keyed by XUID only and there is no public gamertag->XUID lookup, so this is
# the only way to manage operators for a player who is not currently online.
BEDROCK_XUID_CACHE = '.mserver_xuids.json'

# Per-server panel-side ban list for Bedrock, which has no ban list of its own
# (issue #82). The panel owns the server process and sees every join on the
# console, so it enforces these by kicking on connect. Note the consequence:
# this is a panel policy, not a server one — it only holds while the server runs
# under the panel.
BEDROCK_BANS_FILE = '.mserver_bans.json'

# ── Tunable configuration (env-overridable) ───────────────────────────────────
DEFAULT_JAVA_ARGS = _env_str('DEFAULT_JAVA_ARGS', '-Xmx4G -Xms1G')  # default JVM args for new servers
JAVA_BINARY = _env_str('JAVA_BINARY', 'java')                        # java executable (name on PATH or absolute path)
MFA_TIMEOUT_SECONDS = _env_int('MFA_TIMEOUT_SECONDS', 300)           # pending-MFA login window
MAX_RESOURCEPACK_SIZE_MB = _env_int('MAX_RESOURCEPACK_SIZE_MB', 100) # per-server resource pack upload cap

# Ensure directories exist
for directory in [SERVERS_DIR, BACKUPS_DIR, UPLOADS_DIR, JOBS_TMP_DIR, TOOLS_DIR, RESOURCEPACKS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)


# ==================== Version Helper Functions ====================

def read_version_file():
    """
    Read version from version file.
    Returns version string or None if file doesn't exist or is invalid.
    Supports both 'version=X.X.X' and 'X.X.X' formats.
    """
    try:
        if not VERSION_FILE.exists():
            return None

        content = VERSION_FILE.read_text().strip()

        # Try 'version=X.X.X' format first
        if '=' in content:
            parts = content.split('=', 1)
            if len(parts) == 2:
                version = parts[1].strip()
                # Validate format
                if version and all(c.isdigit() or c == '.' for c in version):
                    return version

        # Try plain 'X.X.X' format
        if all(c.isdigit() or c == '.' for c in content):
            return content

        return None
    except Exception as e:
        print(f"[Version] Error reading version file: {e}")
        return None


# --- Minecraft version era helpers ---
# 26.1 renumbered Java Edition (1.21.x -> 26.x) and restructured the world folder:
# dimensions moved under world/dimensions/<namespace>/<dim>/ and per-player files
# under world/players/{data,stats,advancements}/.  Upgrading a world is one-way.
# MC_LEGACY_MAX: highest version in the old world format.  Legacy servers may
#   upgrade/downgrade within this tier but cannot cross to the modern era.
# MC_MODERN_MIN: first version with the new world storage format.
MC_LEGACY_MAX = '1.21.11'
MC_MODERN_MIN = '26.1'


def _parse_mc_version_tuple(v):
    """Convert a MC version string to a sortable integer tuple (a, b, c).
    Strips modloader suffixes (e.g. '1.21.3-53.0.26' -> '1.21.3').
    Handles '1.21.4', '1.26', '26.1', etc.
    """
    base = str(v).split('-')[0]
    parts = re.findall(r'\d+', base)
    nums = [int(p) for p in parts[:3]]
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums)


def mc_version_is_modern(v):
    """Return True if version is in the 26.1+ (new world format) era."""
    m = re.match(r'(\d+)(?:\.(\d+))?', str(v).strip())
    if not m:
        return False
    major, minor = int(m.group(1)), int(m.group(2) or 0)
    # New scheme '26.1', '26.2', '27.x' — a bare major ('26') and snapshots
    # ('26w14a') land here too. '1.26'-style names never shipped but are still
    # accepted, since older configs were written against that guess.
    return major >= 26 or (major == 1 and minor >= 26)


def compare_mc_versions(v1, v2):
    """Compare two MC version strings. Returns -1, 0, or 1."""
    t1 = _parse_mc_version_tuple(v1)
    t2 = _parse_mc_version_tuple(v2)
    if t1 < t2:
        return -1
    if t1 > t2:
        return 1
    return 0


def get_current_version():
    """
    Get current version with fallback to git if version file doesn't exist.
    Returns tuple: (version_string, source)
    source can be: 'file', 'git', or 'unknown'
    """
    # Try reading from version file first
    file_version = read_version_file()
    if file_version:
        return (file_version, 'file')

    # Fallback to git
    try:
        result = subprocess.run(
            ['git', 'describe', '--tags', '--always', '--abbrev=7'],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            return (version, 'git')
    except Exception as e:
        print(f"[Version] Error getting version from git: {e}")

    return ('unknown', 'unknown')


# ==================== Settings Manager ====================

class SettingsManager:
    """Manages application settings including branding"""
    
    DEFAULT_SETTINGS = {
        'branding': {
            'siteTitle': 'MServer',
            'siteIcon': '',
            'footerAddition': '',
            'baseUrl': '',
            'gameHostname': '',
        },
        'app': {
            'enableRegistration': True,
            'globalMaxBackups': 10,
            'autoDeleteExpiredBackups': False,
            'policies': {
                'registration':       'require_approval',
                'serverCreate':       'allow',
                'serverDelete':       'allow',
                'serverEdit':         'allow',
                'serverLifecycle':    'allow',
                'backupCreate':       'allow',
                'backupDelete':       'allow',
                'fileUpload':         'allow',
                'modManagement':      'allow',
                'playerManagement':   'allow',
            }
        },
        'mfa': {
            'requireMfaForAdmins': False,
            'requireMfaForAllUsers': False
        },
        'smtp': {
            'enabled': False,
            'host': '',
            'port': 587,
            'secure': True,
            'username': '',
            'password': '',
            'fromEmail': '',
            'fromName': 'MServer'
        },
        'externalBackup': {
            'enabled': False,
            'type': 'ftp',  # 'ftp' or 's3'
            's3': {
                'bucket': '',
                'region': 'us-east-1',
                'accessKey': '',
                'secretKey': '',
                'prefix': 'backups/'
            },
            'ftp': {
                'host': '',
                'port': 21,
                'username': '',
                'password': '',
                'remotePath': '/backups/',
                'passive': True
            }
        },
        'webhook': {
            'enabled': False,
            'url': '',
            'secret': ''
        },
        'emailTemplates': {}
    }
    
    def __init__(self):
        self.settings = self._load_settings()
    
    def _load_settings(self):
        """Load settings from file"""
        if SETTINGS_PATH.exists():
            try:
                with open(SETTINGS_PATH, 'r') as f:
                    settings = json.load(f)
                    # Merge with defaults to ensure all keys exist
                    for key, value in self.DEFAULT_SETTINGS.items():
                        if key not in settings:
                            settings[key] = value
                        elif isinstance(value, dict):
                            for k, v in value.items():
                                if k not in settings[key]:
                                    settings[key][k] = v
                    return settings
            except Exception:
                pass
        return self.DEFAULT_SETTINGS.copy()
    
    def _save_settings(self):
        """Save settings to file"""
        with open(SETTINGS_PATH, 'w') as f:
            json.dump(self.settings, f, indent=2)
    
    def get_settings(self):
        """Get all settings"""
        return self.settings
    
    def get_branding(self):
        """Get branding settings"""
        return self.settings.get('branding', self.DEFAULT_SETTINGS['branding'])
    
    def update_branding(self, branding_data):
        """Update branding settings"""
        if 'branding' not in self.settings:
            self.settings['branding'] = {}
        
        for key in ['siteTitle', 'siteIcon', 'footerAddition', 'baseUrl', 'gameHostname']:
            if key in branding_data:
                self.settings['branding'][key] = branding_data[key]
        
        self._save_settings()
        return self.settings['branding']
    
    def get_app_settings(self):
        """Get app settings"""
        return self.settings.get('app', self.DEFAULT_SETTINGS['app'])
    
    def update_app_settings(self, app_data):
        """Update app settings"""
        if 'app' not in self.settings:
            self.settings['app'] = {}

        for key in ['enableRegistration', 'globalMaxBackups', 'autoDeleteExpiredBackups']:
            if key in app_data:
                self.settings['app'][key] = app_data[key]

        if 'policies' in app_data and isinstance(app_data['policies'], dict):
            self.update_policies(app_data['policies'])

        self._save_settings()
        return self.settings['app']

    VALID_POLICIES = {'allow', 'notify', 'require_approval'}
    POLICY_KEYS = {
        'registration', 'serverCreate', 'serverDelete', 'serverEdit',
        'serverLifecycle', 'backupCreate', 'backupDelete', 'fileUpload',
        'modManagement', 'playerManagement',
    }

    def get_policies(self):
        """Get all action policies"""
        defaults = self.DEFAULT_SETTINGS['app']['policies']
        return {**defaults, **self.settings.get('app', {}).get('policies', {})}

    def get_policy(self, action_type):
        """Get the policy for a specific action type"""
        return self.get_policies().get(action_type, 'allow')

    def update_policies(self, policies_data):
        """Update action policies (only known keys and valid values accepted)"""
        if 'app' not in self.settings:
            self.settings['app'] = {}
        if 'policies' not in self.settings['app']:
            self.settings['app']['policies'] = {}
        for key, value in policies_data.items():
            if key in self.POLICY_KEYS and value in self.VALID_POLICIES:
                self.settings['app']['policies'][key] = value
        self._save_settings()
        return self.get_policies()
    
    def update_mfa_settings(self, mfa_data):
        """Update MFA settings"""
        if 'mfa' not in self.settings:
            self.settings['mfa'] = {}
        
        for key in ['requireMfaForAdmins', 'requireMfaForAllUsers']:
            if key in mfa_data:
                self.settings['mfa'][key] = mfa_data[key]
        
        self._save_settings()
        return self.settings['mfa']
    
    def get_smtp_settings(self):
        """Get SMTP settings (without password for security)"""
        smtp = self.settings.get('smtp', self.DEFAULT_SETTINGS['smtp']).copy()
        # Don't expose the password
        if 'password' in smtp:
            smtp['password'] = '********' if smtp['password'] else ''
        return smtp
    
    def get_smtp_settings_full(self):
        """Get full SMTP settings including password (for internal use)"""
        return self.settings.get('smtp', self.DEFAULT_SETTINGS['smtp'])
    
    def update_smtp_settings(self, smtp_data):
        """Update SMTP settings"""
        if 'smtp' not in self.settings:
            self.settings['smtp'] = self.DEFAULT_SETTINGS['smtp'].copy()
        
        for key in ['enabled', 'host', 'port', 'secure', 'username', 'fromEmail', 'fromName']:
            if key in smtp_data:
                self.settings['smtp'][key] = smtp_data[key]
        
        # Only update password if it's not the placeholder
        if 'password' in smtp_data and smtp_data['password'] != '********':
            self.settings['smtp']['password'] = smtp_data['password']
        
        self._save_settings()
        return self.get_smtp_settings()
    
    def is_smtp_configured(self):
        """Check if SMTP is properly configured"""
        smtp = self.settings.get('smtp', {})
        return (
            smtp.get('enabled', False) and
            smtp.get('host') and
            smtp.get('fromEmail')
        )

    def get_external_backup_settings(self):
        """Get external backup settings (passwords masked)"""
        ext = self.settings.get('externalBackup',
                                self.DEFAULT_SETTINGS['externalBackup']).copy()
        # Deep copy and mask secrets
        ext = json.loads(json.dumps(ext))
        if ext.get('s3', {}).get('secretKey'):
            ext['s3']['secretKey'] = '********'
        if ext.get('ftp', {}).get('password'):
            ext['ftp']['password'] = '********'
        return ext

    def get_external_backup_settings_full(self):
        """Get full external backup settings including secrets (internal use)"""
        return self.settings.get('externalBackup',
                                 self.DEFAULT_SETTINGS['externalBackup'])

    def update_external_backup_settings(self, data):
        """Update external backup settings"""
        if 'externalBackup' not in self.settings:
            self.settings['externalBackup'] = json.loads(
                json.dumps(self.DEFAULT_SETTINGS['externalBackup'])
            )
        ext = self.settings['externalBackup']

        for key in ['enabled', 'type']:
            if key in data:
                ext[key] = data[key]

        if 's3' in data:
            if 's3' not in ext:
                ext['s3'] = {}
            for key in ['bucket', 'region', 'accessKey', 'prefix']:
                if key in data['s3']:
                    ext['s3'][key] = data['s3'][key]
            if 'secretKey' in data['s3'] and data['s3']['secretKey'] != '********':
                ext['s3']['secretKey'] = data['s3']['secretKey']

        if 'ftp' in data:
            if 'ftp' not in ext:
                ext['ftp'] = {}
            for key in ['host', 'port', 'username', 'remotePath', 'passive']:
                if key in data['ftp']:
                    ext['ftp'][key] = data['ftp'][key]
            if 'password' in data['ftp'] and data['ftp']['password'] != '********':
                ext['ftp']['password'] = data['ftp']['password']

        self._save_settings()
        return self.get_external_backup_settings()

    def get_webhook_settings(self):
        """Get webhook settings (secret masked)"""
        s = self.settings.get('webhook', self.DEFAULT_SETTINGS['webhook']).copy()
        s['secret'] = '********' if s.get('secret') else ''
        return s

    def get_webhook_settings_full(self):
        """Get webhook settings including secret (internal use)"""
        return self.settings.get('webhook', self.DEFAULT_SETTINGS['webhook'])

    def update_webhook_settings(self, data):
        """Update webhook settings"""
        if 'webhook' not in self.settings:
            self.settings['webhook'] = self.DEFAULT_SETTINGS['webhook'].copy()
        for key in ['enabled', 'url']:
            if key in data:
                self.settings['webhook'][key] = data[key]
        if 'secret' in data and data['secret'] != '********':
            self.settings['webhook']['secret'] = data['secret']
        self._save_settings()
        return self.get_webhook_settings()

    def get_email_templates(self):
        """Return effective email templates (stored overrides merged with defaults)"""
        result = {}
        stored = self.settings.get('emailTemplates', {})
        for name, default in EmailService.DEFAULT_TEMPLATES.items():
            result[name] = stored.get(name, default).copy()
        return result

    def update_email_template(self, name, template_data):
        """Override a single email template"""
        if name not in EmailService.DEFAULT_TEMPLATES:
            return False, "Unknown template name"
        if 'emailTemplates' not in self.settings:
            self.settings['emailTemplates'] = {}
        self.settings['emailTemplates'][name] = {
            'subject': template_data.get('subject', EmailService.DEFAULT_TEMPLATES[name]['subject']),
            'html': template_data.get('html', EmailService.DEFAULT_TEMPLATES[name]['html']),
            'text': template_data.get('text', EmailService.DEFAULT_TEMPLATES[name].get('text', ''))
        }
        self._save_settings()
        return True, "Template updated"

    def reset_email_template(self, name):
        """Reset a template to its built-in default"""
        stored = self.settings.get('emailTemplates', {})
        if name in stored:
            del stored[name]
            self._save_settings()
        return True


# ==================== Email Service ====================

class EmailService:
    """Handles email sending via SMTP"""

    DEFAULT_TEMPLATES = {
        'backup_complete': {
            'subject': '[{{ siteTitle }}] Backup Complete: {{ serverName }}',
            'html': (
                '<html><body style="font-family:Arial,sans-serif;background-color:#1a1a2e;color:#e0e0e0;padding:20px;">'
                '<div style="max-width:600px;margin:0 auto;background-color:#16213e;border-radius:8px;padding:30px;">'
                '<h2 style="color:#10b981;margin-top:0;">✅ Backup Completed Successfully</h2>'
                '<p style="margin:10px 0;"><strong>Server:</strong> {{ serverName }}</p>'
                '<p style="margin:10px 0;"><strong>Backup Name:</strong> {{ backupName }}</p>'
                '<p style="margin:10px 0;"><strong>Time:</strong> {{ timestamp }}</p>'
                '<hr style="border:1px solid #333;margin:20px 0;">'
                '<p style="color:#888;font-size:12px;">This is an automated notification from {{ siteTitle }}.</p>'
                '</div></body></html>'
            ),
            'text': 'Backup Completed Successfully\nServer: {{ serverName }}\nBackup: {{ backupName }}\nTime: {{ timestamp }}'
        },
        'backup_failure': {
            'subject': '[{{ siteTitle }}] Backup Failed: {{ serverName }}',
            'html': (
                '<html><body style="font-family:Arial,sans-serif;background-color:#1a1a2e;color:#e0e0e0;padding:20px;">'
                '<div style="max-width:600px;margin:0 auto;background-color:#16213e;border-radius:8px;padding:30px;">'
                '<h2 style="color:#ef4444;margin-top:0;">❌ Backup Failed</h2>'
                '<p style="margin:10px 0;"><strong>Server:</strong> {{ serverName }}</p>'
                '<p style="margin:10px 0;"><strong>Error:</strong> {{ error }}</p>'
                '<p style="margin:10px 0;"><strong>Time:</strong> {{ timestamp }}</p>'
                '<hr style="border:1px solid #333;margin:20px 0;">'
                '<p style="color:#888;font-size:12px;">This is an automated notification from {{ siteTitle }}.</p>'
                '</div></body></html>'
            ),
            'text': 'Backup Failed\nServer: {{ serverName }}\nError: {{ error }}\nTime: {{ timestamp }}'
        },
        'server_start': {
            'subject': '[{{ siteTitle }}] Server Started: {{ serverName }}',
            'html': (
                '<html><body style="font-family:Arial,sans-serif;background-color:#1a1a2e;color:#e0e0e0;padding:20px;">'
                '<div style="max-width:600px;margin:0 auto;background-color:#16213e;border-radius:8px;padding:30px;">'
                '<h2 style="color:#10b981;margin-top:0;">🟢 Server Started</h2>'
                '<p style="margin:10px 0;"><strong>Server:</strong> {{ serverName }}</p>'
                '<p style="margin:10px 0;"><strong>Time:</strong> {{ timestamp }}</p>'
                '<hr style="border:1px solid #333;margin:20px 0;">'
                '<p style="color:#888;font-size:12px;">This is an automated notification from {{ siteTitle }}.</p>'
                '</div></body></html>'
            ),
            'text': 'Server Started\nServer: {{ serverName }}\nTime: {{ timestamp }}'
        },
        'server_stop': {
            'subject': '[{{ siteTitle }}] Server Stopped: {{ serverName }}',
            'html': (
                '<html><body style="font-family:Arial,sans-serif;background-color:#1a1a2e;color:#e0e0e0;padding:20px;">'
                '<div style="max-width:600px;margin:0 auto;background-color:#16213e;border-radius:8px;padding:30px;">'
                '<h2 style="color:#e0a800;margin-top:0;">🔴 Server Stopped</h2>'
                '<p style="margin:10px 0;"><strong>Server:</strong> {{ serverName }}</p>'
                '<p style="margin:10px 0;"><strong>Time:</strong> {{ timestamp }}</p>'
                '<hr style="border:1px solid #333;margin:20px 0;">'
                '<p style="color:#888;font-size:12px;">This is an automated notification from {{ siteTitle }}.</p>'
                '</div></body></html>'
            ),
            'text': 'Server Stopped\nServer: {{ serverName }}\nTime: {{ timestamp }}'
        },
        'player_join': {
            'subject': '[{{ siteTitle }}] Player Joined: {{ player }} on {{ serverName }}',
            'html': (
                '<html><body style="font-family:Arial,sans-serif;background-color:#1a1a2e;color:#e0e0e0;padding:20px;">'
                '<div style="max-width:600px;margin:0 auto;background-color:#16213e;border-radius:8px;padding:30px;">'
                '<h2 style="color:#667eea;margin-top:0;">👤 Player Joined</h2>'
                '<p style="margin:10px 0;"><strong>Player:</strong> {{ player }}</p>'
                '<p style="margin:10px 0;"><strong>Server:</strong> {{ serverName }}</p>'
                '<p style="margin:10px 0;"><strong>Time:</strong> {{ timestamp }}</p>'
                '<hr style="border:1px solid #333;margin:20px 0;">'
                '<p style="color:#888;font-size:12px;">This is an automated notification from {{ siteTitle }}.</p>'
                '</div></body></html>'
            ),
            'text': 'Player Joined\nPlayer: {{ player }}\nServer: {{ serverName }}\nTime: {{ timestamp }}'
        },
        'player_leave': {
            'subject': '[{{ siteTitle }}] Player Left: {{ player }} on {{ serverName }}',
            'html': (
                '<html><body style="font-family:Arial,sans-serif;background-color:#1a1a2e;color:#e0e0e0;padding:20px;">'
                '<div style="max-width:600px;margin:0 auto;background-color:#16213e;border-radius:8px;padding:30px;">'
                '<h2 style="color:#9ca3af;margin-top:0;">👋 Player Left</h2>'
                '<p style="margin:10px 0;"><strong>Player:</strong> {{ player }}</p>'
                '<p style="margin:10px 0;"><strong>Server:</strong> {{ serverName }}</p>'
                '<p style="margin:10px 0;"><strong>Time:</strong> {{ timestamp }}</p>'
                '<hr style="border:1px solid #333;margin:20px 0;">'
                '<p style="color:#888;font-size:12px;">This is an automated notification from {{ siteTitle }}.</p>'
                '</div></body></html>'
            ),
            'text': 'Player Left\nPlayer: {{ player }}\nServer: {{ serverName }}\nTime: {{ timestamp }}'
        },
        'critical_alert': {
            'subject': '[{{ siteTitle }}] ⚠️ Critical Alert: {{ alertType }}',
            'html': (
                '<html><body style="font-family:Arial,sans-serif;background-color:#1a1a2e;color:#e0e0e0;padding:20px;">'
                '<div style="max-width:600px;margin:0 auto;background-color:#16213e;border-radius:8px;padding:30px;">'
                '<h2 style="color:#ef4444;margin-top:0;">⚠️ Critical Alert</h2>'
                '<p style="margin:10px 0;"><strong>Alert Type:</strong> {{ alertType }}</p>'
                '<p style="margin:10px 0;"><strong>Details:</strong> {{ details }}</p>'
                '<p style="margin:10px 0;"><strong>Time:</strong> {{ timestamp }}</p>'
                '<hr style="border:1px solid #333;margin:20px 0;">'
                '<p style="color:#888;font-size:12px;">This is an automated notification from {{ siteTitle }}.</p>'
                '</div></body></html>'
            ),
            'text': 'Critical Alert\nType: {{ alertType }}\nDetails: {{ details }}\nTime: {{ timestamp }}'
        },
    }

    def __init__(self, settings_manager):
        self.settings_manager = settings_manager

    # ---- Jinja2 helpers ----

    def _render(self, template_str, context, html=True):
        """Render a Jinja2 template string with the given context."""
        from jinja2 import Environment
        env = Environment(autoescape=html)
        return env.from_string(template_str).render(**context)

    def _get_template(self, event_type):
        """Return the active template for an event type (stored override or default)."""
        stored = self.settings_manager.settings.get('emailTemplates', {}).get(event_type)
        return stored if stored else self.DEFAULT_TEMPLATES.get(event_type)

    # ---- Core send method ----

    def send_email(self, to_email, subject, html_content, text_content=None):
        """Send an email using configured SMTP settings"""
        if not self.settings_manager.is_smtp_configured():
            app.logger.warning('[Email] Attempted to send email but SMTP is not configured')
            return False, "SMTP is not configured"
        
        smtp_settings = self.settings_manager.get_smtp_settings_full()
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{smtp_settings['fromName']} <{smtp_settings['fromEmail']}>"
            msg['To'] = to_email
            
            # Add text part
            if text_content:
                msg.attach(MIMEText(text_content, 'plain'))
            
            # Add HTML part
            msg.attach(MIMEText(html_content, 'html'))
            
            # Connect to SMTP server
            if smtp_settings.get('secure', True):
                server = smtplib.SMTP(smtp_settings['host'], smtp_settings['port'])
                server.starttls()
            else:
                server = smtplib.SMTP(smtp_settings['host'], smtp_settings['port'])
            
            # Login if credentials provided
            if smtp_settings.get('username') and smtp_settings.get('password'):
                server.login(smtp_settings['username'], smtp_settings['password'])
            
            # Send email
            server.sendmail(smtp_settings['fromEmail'], to_email, msg.as_string())
            server.quit()
            
            return True, "Email sent successfully"
        except smtplib.SMTPAuthenticationError:
            app.logger.error(f'[Email] SMTP authentication failed sending to {to_email}')
            return False, "SMTP authentication failed"
        except smtplib.SMTPException as e:
            app.logger.error(f'[Email] SMTP error sending to {to_email}: {e}')
            return False, f"SMTP error: {str(e)}"
        except Exception as e:
            app.logger.error(f'[Email] Failed to send email to {to_email}: {e}')
            return False, f"Failed to send email: {str(e)}"

    # ---- Template-based event notifications ----

    def send_event_notification(self, event_type, context, recipients):
        """Render a template for event_type and send to the list of recipient emails."""
        template = self._get_template(event_type)
        if not template:
            app.logger.warning(f'[Email] No template found for event type: {event_type}')
            return []
        site_title = self.settings_manager.get_branding().get('siteTitle', 'MServer')
        ctx = {'siteTitle': site_title, 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), **context}
        subject = self._render(template.get('subject', '[{{ siteTitle }}] Notification'), ctx, html=False)
        html_content = self._render(template.get('html', '<p>Notification</p>'), ctx, html=True)
        text_tpl = template.get('text', '')
        text_content = self._render(text_tpl, ctx, html=False) if text_tpl else None
        results = []
        for email in recipients:
            ok, msg = self.send_email(email, subject, html_content, text_content)
            if not ok:
                app.logger.warning(f'[Email] Failed to send {event_type} notification to {email}: {msg}')
            results.append((email, ok, msg))
        return results

    # ---- Legacy direct-send methods (kept for backwards compatibility) ----

    def send_test_email(self, to_email):
        """Send a test email to verify SMTP configuration"""
        site_title = self.settings_manager.get_branding().get('siteTitle', 'MServer')
        subject = f"[{site_title}] Test Email"
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #1a1a2e; color: #e0e0e0; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #16213e; border-radius: 8px; padding: 30px;">
                <h2 style="color: #667eea; margin-top: 0;">🎮 {site_title} - Test Email</h2>
                <p>This is a test email to verify your SMTP configuration is working correctly.</p>
                <p style="margin: 10px 0;"><strong>Sent at:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <hr style="border: 1px solid #333; margin: 20px 0;">
                <p style="color: #10b981;">✅ If you're reading this, your email settings are configured correctly!</p>
            </div>
        </body>
        </html>
        """
        text_content = f"{site_title} - Test Email\n\nThis is a test email to verify your SMTP configuration is working correctly.\n\nSent at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\nIf you're reading this, your email settings are configured correctly!"
        
        return self.send_email(to_email, subject, html_content, text_content)


# ==================== Webhook Service ====================

class WebhookService:
    """Delivers event notifications to a configured HTTP webhook endpoint."""

    def __init__(self, settings_manager):
        self.settings_manager = settings_manager

    def dispatch(self, event_type, payload):
        """POST JSON payload to the configured webhook URL.

        Returns (success: bool, message: str).
        If webhook is not enabled/configured, returns silently as (False, reason).
        """
        settings = self.settings_manager.get_webhook_settings_full()
        if not settings.get('enabled'):
            return False, "Webhook not enabled"
        url = settings.get('url', '').strip()
        if not url:
            return False, "Webhook URL not configured"
        # Basic URL validation — must be http(s)
        if not url.startswith(('http://', 'https://')):
            return False, "Invalid webhook URL scheme"

        body = json.dumps(payload).encode('utf-8')
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'MServer/1.0',
            'X-MSC-Event': event_type,
        }
        secret = settings.get('secret', '').strip()
        if secret:
            sig = hmac.new(secret.encode('utf-8'), body, hashlib.sha256).hexdigest()
            headers['X-MSC-Signature'] = f'sha256={sig}'

        try:
            resp = requests.post(url, data=body, headers=headers, timeout=10)
            if resp.status_code < 400:
                return True, f"Delivered (HTTP {resp.status_code})"
            return False, f"Webhook endpoint returned HTTP {resp.status_code}"
        except requests.RequestException as e:
            app.logger.error(f'[Webhook] Delivery failed for event {event_type}: {e}')
            return False, str(e)


# ==================== System Stats Manager ====================

class StatsManager:
    """Manages system statistics collection and storage — backed by SQLite."""

    RETENTION_DAYS = _env_int('STATS_RETENTION_DAYS', 7)

    def __init__(self):
        self._stop_event = threading.Event()
        self._start_collection()

    def stop(self):
        """Signal the background collection thread to stop."""
        self._stop_event.set()

    def _cleanup_old_stats(self):
        """Delete stats older than the retention period from the DB."""
        cutoff = (datetime.now() - timedelta(days=self.RETENTION_DAYS)).isoformat()
        conn = get_db()
        conn.execute('DELETE FROM stats_history WHERE timestamp < ?', (cutoff,))
        conn.commit()
    
    def _get_system_stats(self, blocking_cpu_sample=True):
        """Get current system statistics.

        blocking_cpu_sample=False uses psutil's non-blocking cpu_percent
        (comparison against the last call) instead of sleeping 1s inline —
        used by the background collection loop so it stays responsive to stop().
        """
        stats = {
            'timestamp': datetime.now().isoformat(),
            'cpu': 0,
            'memory': {'used': 0, 'total': 0, 'percent': 0},
            'disk': {'used': 0, 'total': 0, 'percent': 0}
        }

        try:
            # Try to use psutil if available
            import psutil
            stats['cpu'] = psutil.cpu_percent(interval=1 if blocking_cpu_sample else None)

            mem = psutil.virtual_memory()
            stats['memory'] = {
                'used': mem.used,
                'total': mem.total,
                'percent': mem.percent
            }
            
            disk = psutil.disk_usage('/')
            stats['disk'] = {
                'used': disk.used,
                'total': disk.total,
                'percent': disk.percent
            }
        except ImportError:
            # Fallback to reading from /proc on Linux
            try:
                # CPU usage from /proc/stat
                with open('/proc/stat', 'r') as f:
                    cpu_line = f.readline()
                    cpu_times = list(map(int, cpu_line.split()[1:8]))
                    idle = cpu_times[3]
                    total = sum(cpu_times)
                    # Store for next calculation
                    if hasattr(self, '_last_cpu'):
                        idle_delta = idle - self._last_cpu[0]
                        total_delta = total - self._last_cpu[1]
                        if total_delta > 0:
                            stats['cpu'] = round(100 * (1 - idle_delta / total_delta), 1)
                    self._last_cpu = (idle, total)
                
                # Memory from /proc/meminfo
                with open('/proc/meminfo', 'r') as f:
                    meminfo = {}
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2:
                            key = parts[0].rstrip(':')
                            value = int(parts[1]) * 1024  # Convert KB to bytes
                            meminfo[key] = value
                    
                    total = meminfo.get('MemTotal', 0)
                    available = meminfo.get('MemAvailable', meminfo.get('MemFree', 0))
                    used = total - available
                    stats['memory'] = {
                        'used': used,
                        'total': total,
                        'percent': round(100 * used / total, 1) if total > 0 else 0
                    }
                
                # Disk usage
                statvfs = os.statvfs('/')
                total = statvfs.f_blocks * statvfs.f_frsize
                free = statvfs.f_bavail * statvfs.f_frsize
                used = total - free
                stats['disk'] = {
                    'used': used,
                    'total': total,
                    'percent': round(100 * used / total, 1) if total > 0 else 0
                }
            except Exception as e:
                print(f"Failed to get system stats: {e}")
        
        return stats
    
    def _collect_stats(self):
        """Background thread: collect stats every 10 seconds and persist to SQLite."""
        try:
            import psutil
            psutil.cpu_percent(interval=None)  # prime; first call's value is meaningless
        except ImportError:
            pass

        while not self._stop_event.is_set():
            try:
                stats = self._get_system_stats(blocking_cpu_sample=False)
                conn = get_db()
                conn.execute(
                    '''INSERT INTO stats_history
                       (timestamp, cpu, memory_used, memory_total, memory_percent,
                        disk_used, disk_total, disk_percent)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                    (stats['timestamp'],
                     stats['cpu'],
                     stats['memory']['used'],
                     stats['memory']['total'],
                     stats['memory']['percent'],
                     stats['disk']['used'],
                     stats['disk']['total'],
                     stats['disk']['percent'])
                )
                conn.commit()
                self._cleanup_old_stats()

                socketio.emit('stats_update', stats, to='stats_viewers', namespace='/')
            except Exception as e:
                print(f"Stats collection error: {e}")

            self._stop_event.wait(10)

    def _start_collection(self):
        """Start the stats collection thread."""
        thread = threading.Thread(target=self._collect_stats, daemon=True)
        thread.start()

    def get_current_stats(self):
        """Get the most recent stats (live reading, not from DB)."""
        return self._get_system_stats()

    def get_history(self, hours=24):
        """Get stats history for the specified number of hours from SQLite."""
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        rows = get_db().execute(
            'SELECT * FROM stats_history WHERE timestamp > ? ORDER BY timestamp',
            (cutoff,)
        ).fetchall()
        return [
            {
                'timestamp': r['timestamp'],
                'cpu':       r['cpu'],
                'memory': {
                    'used':    r['memory_used'],
                    'total':   r['memory_total'],
                    'percent': r['memory_percent'],
                },
                'disk': {
                    'used':    r['disk_used'],
                    'total':   r['disk_total'],
                    'percent': r['disk_percent'],
                },
            }
            for r in rows
        ]


# ==================== Backup Helpers ====================

def verify_backup_file(backup_path):
    """Verify a ZIP backup's integrity and compute its SHA-256 checksum.

    Returns (ok: bool, checksum: str|None, error: str|None).
    Also writes a .sha256 sidecar file next to the backup.
    """
    backup_path = Path(backup_path)
    try:
        with zipfile.ZipFile(backup_path, 'r') as zf:
            bad = zf.testzip()
            if bad is not None:
                return False, None, f"Corrupt entry in ZIP: {bad}"

        sha256 = hashlib.sha256()
        with open(backup_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
        checksum = sha256.hexdigest()

        sidecar = backup_path.with_suffix('.sha256')
        sidecar.write_text(f"{checksum}  {backup_path.name}\n")

        return True, checksum, None
    except zipfile.BadZipFile as e:
        return False, None, f"Bad ZIP file: {e}"
    except Exception as e:
        return False, None, str(e)


def upload_backup_to_external(backup_path, server_id, backup_name):
    """Upload a backup file to configured external storage (S3 or FTP).

    Returns (ok: bool, message: str).
    """
    ext = settings_manager.get_external_backup_settings_full()
    if not ext.get('enabled', False):
        return True, 'External backup not enabled'

    storage_type = ext.get('type', 'ftp')
    backup_path = Path(backup_path)

    if storage_type == 's3':
        try:
            import boto3
            s3_cfg = ext.get('s3', {})
            bucket = s3_cfg.get('bucket', '')
            region = s3_cfg.get('region', 'us-east-1')
            access_key = s3_cfg.get('accessKey', '')
            secret_key = s3_cfg.get('secretKey', '')
            prefix = s3_cfg.get('prefix', 'backups/').rstrip('/') + '/'

            if not bucket:
                return False, 'S3 bucket not configured'

            s3 = boto3.client(
                's3',
                region_name=region,
                aws_access_key_id=access_key or None,
                aws_secret_access_key=secret_key or None,
            )
            key = f"{prefix}{server_id}/{backup_name}"
            s3.upload_file(str(backup_path), bucket, key)
            return True, f"Uploaded to s3://{bucket}/{key}"
        except ImportError:
            return False, 'boto3 is not installed. Run: pip install boto3'
        except Exception as e:
            return False, f"S3 upload failed: {e}"

    elif storage_type == 'ftp':
        import ftplib
        ftp_cfg = ext.get('ftp', {})
        host = ftp_cfg.get('host', '')
        port = int(ftp_cfg.get('port', 21))
        username = ftp_cfg.get('username', '')
        password = ftp_cfg.get('password', '')
        remote_path = ftp_cfg.get('remotePath', '/backups/').rstrip('/') + '/'
        passive = ftp_cfg.get('passive', True)

        if not host:
            return False, 'FTP host not configured'

        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=30)
            ftp.login(username, password)
            ftp.set_pasv(passive)

            # Ensure remote directory exists
            remote_dir = f"{remote_path}{server_id}"
            try:
                ftp.mkd(remote_dir)
            except ftplib.error_perm:
                pass  # Directory already exists

            with open(backup_path, 'rb') as f:
                ftp.storbinary(f"STOR {remote_dir}/{backup_name}", f)
            ftp.quit()
            return True, f"Uploaded to ftp://{host}{remote_dir}/{backup_name}"
        except Exception as e:
            return False, f"FTP upload failed: {e}"

    return False, f"Unknown external storage type: {storage_type}"


# ==================== Backup Scheduler ====================

class BackupScheduler:
    """Manages scheduled automated backups for servers — backed by SQLite."""

    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.scheduler.start()
        self._restore_schedules()

    # ── Row helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_schedule_dict(row):
        """Convert a backup_schedules DB row to the camelCase dict the app expects."""
        if row is None:
            return None
        return {
            'enabled':          bool(row['enabled']),
            'type':             row['schedule_type'],
            'hour':             row['hour'],
            'minute':           row['minute'],
            'dayOfWeek':        row['day_of_week'],
            'cron':             row['cron'],
            'compressionLevel': row['compression_level'],
            'stopServer':       bool(row['stop_server']),
            'restartAfter':     bool(row['restart_after']),
        }

    # ── Startup restore ───────────────────────────────────────────────────────

    def _restore_schedules(self):
        """Re-register APScheduler jobs from the database on startup."""
        rows = get_db().execute(
            'SELECT * FROM backup_schedules WHERE enabled=1'
        ).fetchall()
        for row in rows:
            self._add_job(row['server_id'], self._row_to_schedule_dict(row))

    # ── APScheduler job management ────────────────────────────────────────────

    def _add_job(self, server_id, schedule):
        """Add (or replace) the APScheduler cron job for a server's backup schedule."""
        job_id = f"backup_{server_id}"
        try:
            self.scheduler.remove_job(job_id)
        except Exception:
            pass

        schedule_type = schedule.get('type', 'daily')
        hour   = schedule.get('hour', 3)
        minute = schedule.get('minute', 0)

        if schedule_type == 'hourly':
            trigger = CronTrigger(minute=minute)
        elif schedule_type == 'daily':
            trigger = CronTrigger(hour=hour, minute=minute)
        elif schedule_type == 'weekly':
            trigger = CronTrigger(day_of_week=schedule.get('dayOfWeek', 0),
                                  hour=hour, minute=minute)
        elif schedule_type == 'custom':
            parts = schedule.get('cron', '0 3 * * *').split()
            if len(parts) == 5:
                trigger = CronTrigger(minute=parts[0], hour=parts[1],
                                      day=parts[2], month=parts[3],
                                      day_of_week=parts[4])
            else:
                trigger = CronTrigger(hour=3, minute=0)
        else:
            trigger = CronTrigger(hour=hour, minute=minute)

        self.scheduler.add_job(
            self._execute_backup, trigger,
            args=[server_id], id=job_id,
            replace_existing=True, max_instances=1
        )

    # ── Backup execution ──────────────────────────────────────────────────────

    def _execute_backup(self, server_id):
        """Execute a scheduled backup for a server."""
        print(f"[Scheduler] Starting scheduled backup for server: {server_id}")
        try:
            server_config = server_manager.get_server_config(server_id)
            if not server_config:
                print(f"[Scheduler] Server {server_id} not found")
                return

            try:
                message_scheduler.fire_event(server_id, 'backup_start')
            except Exception:
                pass

            server_path = Path(server_config.get('serverPath', SERVERS_DIR))
            if not server_path.exists():
                print(f"[Scheduler] Server path not found for {server_id}")
                return

            schedule = self.get_schedule(server_id) or {}
            was_running = False
            instance = server_manager.servers.get(server_id)

            if instance and instance.is_running():
                if schedule.get('stopServer', True):
                    print(f"[Scheduler] Stopping server {server_id} for backup")
                    was_running = True
                    server_manager.send_command(server_id, "say [Backup] Server will restart in 30 seconds for scheduled backup!")
                    time.sleep(10)
                    server_manager.send_command(server_id, "say [Backup] Server restarting in 20 seconds...")
                    time.sleep(10)
                    server_manager.send_command(server_id, "say [Backup] Server restarting in 10 seconds...")
                    time.sleep(10)
                    server_manager.stop_server(server_id)
                    for _ in range(60):
                        if server_id not in server_manager.servers or not server_manager.servers[server_id].is_running():
                            break
                        time.sleep(1)
                    if server_id in server_manager.servers and server_manager.servers[server_id].is_running():
                        server_manager.kill_server(server_id)
                        time.sleep(2)
                else:
                    print(f"[Scheduler] Server {server_id} is running, backup may be inconsistent (stopServer=False)")

            backup_dir = BACKUPS_DIR / server_id
            backup_dir.mkdir(parents=True, exist_ok=True)

            timestamp         = datetime.now().strftime('%Y-%m-%dT%H-%M-%S')
            compression_level = max(0, min(9, int(schedule.get('compressionLevel', 6))))
            backup_name       = f'scheduled-backup-{timestamp}.zip'
            backup_path       = backup_dir / backup_name

            print(f"[Scheduler] Creating full backup: {backup_name}")
            included_files = []
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED,
                                 compresslevel=compression_level) as zipf:
                for root, dirs, files in os.walk(server_path):
                    for file in files:
                        file_path = Path(root) / file
                        arcname   = file_path.relative_to(server_path)
                        zipf.write(file_path, arcname)
                        included_files.append(str(arcname))
                manifest = {
                    'type': 'full',
                    'created': timestamp,
                    'file_count': len(included_files)
                }
                zipf.writestr('backup_manifest.json', json.dumps(manifest, indent=2))

            size = backup_path.stat().st_size
            print(f"[Scheduler] Backup created: {backup_name} ({size} bytes)")

            ok, checksum, verify_err = verify_backup_file(backup_path)
            if not ok:
                print(f"[Scheduler] Backup verification warning: {verify_err}")

            ext_ok, ext_msg = upload_backup_to_external(backup_path, server_id, backup_name)
            if not ext_ok:
                print(f"[Scheduler] External upload warning: {ext_msg}")

            self._log_backup_event(server_id, {
                'type': 'scheduled',
                'backupName': backup_name,
                'size': size,
                'success': True,
                'checksum': checksum,
            })

            if settings_manager.get_app_settings().get('autoDeleteExpiredBackups', False):
                self._cleanup_old_backups(server_id)

            if was_running and schedule.get('restartAfter', True):
                print(f"[Scheduler] Restarting server {server_id}")
                server_manager.start_server(server_id)

            socketio.emit('backup_completed', {
                'serverId': server_id,
                'backup':   backup_name,
                'size':     size,
                'scheduled': True,
                'verified':  ok,
                'checksum':  checksum,
            }, to=f'server_{server_id}', namespace='/')

            _backup_ctx = {
                'serverId':   server_id,
                'serverName': server_config.get('name', server_id),
                'backupName': backup_name,
                'size':        size,
            }
            threading.Thread(
                target=dispatch_notification,
                args=('backup_complete', _backup_ctx), daemon=True
            ).start()

            print(f"[Scheduler] Scheduled backup completed for server: {server_id}")

        except Exception as e:
            print(f"[Scheduler] Backup failed for server {server_id}: {e}")
            self._log_backup_event(server_id, {
                'type':        'scheduled',
                'backupName': None,
                'success':     False,
                'error':       str(e),
            })
            socketio.emit('backup_failed', {'serverId': server_id, 'error': str(e), 'scheduled': True},
                          to=f'server_{server_id}', namespace='/')
            try:
                _fail_cfg  = server_manager.get_server_config(server_id)
                _fail_name = _fail_cfg.get('name', server_id) if _fail_cfg else server_id
            except Exception:
                _fail_name = server_id
            threading.Thread(
                target=dispatch_notification,
                args=('backup_failure', {'serverName': _fail_name, 'error': str(e)}),
                daemon=True
            ).start()

    # ── Backup event log ──────────────────────────────────────────────────────

    def _log_backup_event(self, server_id, event):
        """Insert a backup event row into backup_events."""
        conn = get_db()
        try:
            conn.execute(
                '''INSERT INTO backup_events
                   (server_id, timestamp, type, backup_name, size, success, error, checksum)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (server_id,
                 event.get('timestamp', datetime.now().isoformat()),
                 event.get('type', 'manual'),
                 event.get('backupName'),
                 event.get('size'),
                 1 if event.get('success', True) else 0,
                 event.get('error'),
                 event.get('checksum'))
            )
            conn.commit()
            # Trim to 500 events per server
            conn.execute(
                '''DELETE FROM backup_events WHERE id IN (
                       SELECT id FROM backup_events WHERE server_id=?
                       ORDER BY timestamp DESC LIMIT -1 OFFSET 500
                   )''',
                (server_id,)
            )
            conn.commit()
        except Exception as e:
            print(f"[Backup] Failed to log backup event: {e}")

    def get_backup_history(self, server_id):
        """Return backup event history for a server (newest first, max 500)."""
        rows = get_db().execute(
            '''SELECT * FROM backup_events WHERE server_id=?
               ORDER BY timestamp DESC LIMIT 500''',
            (server_id,)
        ).fetchall()
        return [
            {
                'id':         r['id'],
                'timestamp':  r['timestamp'],
                'type':       r['type'],
                'backupName': r['backup_name'],
                'size':       r['size'],
                'success':    bool(r['success']),
                'error':      r['error'],
                'checksum':   r['checksum'],
            }
            for r in rows
        ]

    # ── Backup retention ──────────────────────────────────────────────────────

    def _cleanup_old_backups(self, server_id, max_backups=None):
        """Remove backups exceeding the global retention limit. Returns deleted count."""
        if max_backups is None:
            max_backups = settings_manager.get_app_settings().get('globalMaxBackups', 0)
        if max_backups <= 0:
            return 0

        backup_dir = BACKUPS_DIR / server_id
        if not backup_dir.exists():
            return 0

        backups = [
            (item, item.stat().st_mtime)
            for item in backup_dir.iterdir()
            if item.suffix == '.zip' and not item.name.startswith('_')
        ]
        backups.sort(key=lambda x: x[1], reverse=True)

        deleted = 0
        for backup_file, _ in backups[max_backups:]:
            try:
                backup_file.unlink()
                sidecar = backup_file.with_suffix('.sha256')
                if sidecar.exists():
                    sidecar.unlink()
                print(f"[Backup] Removed expired backup: {backup_file.name}")
                deleted += 1
            except Exception as e:
                print(f"[Backup] Failed to remove expired backup {backup_file.name}: {e}")
        return deleted

    # ── Schedule CRUD ─────────────────────────────────────────────────────────

    def set_schedule(self, server_id, schedule_config):
        """Upsert a backup schedule for a server."""
        conn = get_db()
        conn.execute(
            '''INSERT OR REPLACE INTO backup_schedules
               (server_id, enabled, schedule_type, hour, minute, day_of_week, cron,
                compression_level, stop_server, restart_after)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (server_id,
             1 if schedule_config.get('enabled', True) else 0,
             schedule_config.get('type', 'daily'),
             int(schedule_config.get('hour', 3)),
             int(schedule_config.get('minute', 0)),
             int(schedule_config.get('dayOfWeek', 0)),
             schedule_config.get('cron', ''),
             int(schedule_config.get('compressionLevel', 6)),
             1 if schedule_config.get('stopServer', True) else 0,
             1 if schedule_config.get('restartAfter', True) else 0)
        )
        conn.commit()

        if schedule_config.get('enabled', True):
            self._add_job(server_id, self.get_schedule(server_id))
        else:
            try:
                self.scheduler.remove_job(f"backup_{server_id}")
            except Exception:
                pass

        return self.get_schedule(server_id)

    def get_schedule(self, server_id):
        """Get the backup schedule dict for a server, enriched with next-run time."""
        row = get_db().execute(
            'SELECT * FROM backup_schedules WHERE server_id=?', (server_id,)
        ).fetchone()
        if row is None:
            return None
        schedule = self._row_to_schedule_dict(row)
        try:
            job = self.scheduler.get_job(f"backup_{server_id}")
            if job and job.next_run_time:
                schedule['nextRun'] = job.next_run_time.isoformat()
        except Exception:
            pass
        return schedule

    def delete_schedule(self, server_id):
        """Delete a backup schedule for a server."""
        conn = get_db()
        result = conn.execute(
            'DELETE FROM backup_schedules WHERE server_id=?', (server_id,)
        )
        conn.commit()
        try:
            self.scheduler.remove_job(f"backup_{server_id}")
        except Exception:
            pass
        return result.rowcount > 0


# ==================== Task Scheduler ====================

class TaskScheduler:
    """Manages scheduled tasks for servers (start/stop/reboot/commands) — backed by SQLite."""

    def __init__(self, server_manager, socketio):
        self.server_manager = server_manager
        self.socketio       = socketio
        self.scheduler      = BackgroundScheduler()
        self.scheduler.start()
        self._restore_tasks()

    # ── Row helper ────────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_task_dict(row):
        """Convert a tasks DB row to the camelCase dict the app expects."""
        if row is None:
            return None
        return {
            'id':                   row['id'],
            'name':                 row['name'],
            'action':               row['action'],
            'interval':             row['interval'],
            'enabled':              bool(row['enabled']),
            'command':              row['command'],
            'runs':                 row['runs'],
            'runCount':             row['run_count'],
            'lastRun':              row['last_run'],
            'deleteAfterExecution': bool(row['delete_after_execution']),
            'deleteAfterRunsCount': bool(row['delete_after_runs_count']),
            'createdAt':            row['created'],
        }

    # ── Startup restore ───────────────────────────────────────────────────────

    def _restore_tasks(self):
        """Re-register APScheduler jobs for all enabled tasks on startup."""
        rows = get_db().execute('SELECT * FROM tasks WHERE enabled=1').fetchall()
        for row in rows:
            self._add_job(row['server_id'], row['id'], self._row_to_task_dict(row))

    # ── APScheduler job management ────────────────────────────────────────────

    def _add_job(self, server_id, task_id, task):
        """Add (or replace) the APScheduler cron job for a task."""
        job_id   = f"task_{server_id}_{task_id}"
        cron_expr = task.get('interval', '0 3 * * *')
        try:
            self.scheduler.remove_job(job_id)
        except Exception:
            pass
        try:
            parts = cron_expr.split()
            if len(parts) == 5:
                trigger = CronTrigger(
                    minute=parts[0], hour=parts[1],
                    day=parts[2], month=parts[3], day_of_week=parts[4]
                )
                self.scheduler.add_job(
                    self._execute_task, trigger=trigger,
                    id=job_id, args=[server_id, task_id]
                )
                print(f"[TaskScheduler] Added job {job_id}: {cron_expr}")
        except Exception as e:
            print(f"[TaskScheduler] Failed to add job {job_id}: {e}")

    # ── Task execution ────────────────────────────────────────────────────────

    def _execute_task(self, server_id, task_id):
        """Execute a scheduled task."""
        print(f"[TaskScheduler] Executing task {task_id} for server {server_id}")
        try:
            conn = get_db()
            row  = conn.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
            if not row:
                print(f"[TaskScheduler] Task {task_id} not found")
                return
            task = self._row_to_task_dict(row)
            if not task['enabled']:
                print(f"[TaskScheduler] Task {task_id} is disabled")
                return

            action = task.get('action', '')
            if action == 'START':
                self._execute_start(server_id, task)
            elif action == 'STOP':
                self._execute_stop(server_id, task)
            elif action == 'REBOOT':
                self._execute_reboot(server_id, task)
            elif action == 'COMMAND':
                self._execute_command(server_id, task)

            # Increment run counter
            conn.execute(
                'UPDATE tasks SET run_count=run_count+1, last_run=? WHERE id=?',
                (datetime.now().isoformat(), task_id)
            )
            conn.commit()
            row       = conn.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
            task      = self._row_to_task_dict(row)
            run_count = task['runCount']

            if task['deleteAfterExecution']:
                self.delete_task(server_id, task_id)
                print(f"[TaskScheduler] Deleted task {task_id} after execution")
            elif task['runs'] > 0 and run_count >= task['runs']:
                if task['deleteAfterRunsCount']:
                    self.delete_task(server_id, task_id)
                    print(f"[TaskScheduler] Deleted task {task_id} after {run_count} runs")
                else:
                    conn.execute('UPDATE tasks SET enabled=0 WHERE id=?', (task_id,))
                    conn.commit()
                    try:
                        self.scheduler.remove_job(f"task_{server_id}_{task_id}")
                    except Exception:
                        pass
                    print(f"[TaskScheduler] Disabled task {task_id} after {run_count} runs")

            print(f"[TaskScheduler] Task {task_id} executed successfully")
        except Exception as e:
            print(f"[TaskScheduler] Task execution failed for {task_id}: {e}")

    def _is_server_running(self, server_id):
        instance = self.server_manager.servers.get(server_id)
        return instance is not None and instance.is_running()

    def _execute_start(self, server_id, task):
        try:
            if not self._is_server_running(server_id):
                self.server_manager.start_server(server_id)
                print(f"[TaskScheduler] Started server {server_id}")
            else:
                print(f"[TaskScheduler] Server {server_id} is already running")
        except Exception as e:
            print(f"[TaskScheduler] Failed to start server {server_id}: {e}")

    def _execute_stop(self, server_id, task):
        try:
            if self._is_server_running(server_id):
                self.server_manager.stop_server(server_id)
                print(f"[TaskScheduler] Stopped server {server_id}")
            else:
                print(f"[TaskScheduler] Server {server_id} is not running")
        except Exception as e:
            print(f"[TaskScheduler] Failed to stop server {server_id}: {e}")

    def _execute_reboot(self, server_id, task):
        try:
            if self._is_server_running(server_id):
                print(f"[TaskScheduler] Rebooting server {server_id}...")
                self.server_manager.stop_server(server_id)
                waited = 0
                while self._is_server_running(server_id) and waited < 60:
                    time.sleep(1)
                    waited += 1
                time.sleep(3)
            self.server_manager.start_server(server_id)
            print(f"[TaskScheduler] Server {server_id} rebooted successfully")
        except Exception as e:
            print(f"[TaskScheduler] Failed to reboot server {server_id}: {e}")

    def _execute_command(self, server_id, task):
        try:
            command = task.get('command', '')
            if command and self._is_server_running(server_id):
                self.server_manager.send_command(server_id, command)
                print(f"[TaskScheduler] Executed command '{command}' on server {server_id}")
            elif not command:
                print("[TaskScheduler] No command specified for task")
            else:
                print(f"[TaskScheduler] Server {server_id} is not running, cannot execute command")
        except Exception as e:
            print(f"[TaskScheduler] Failed to execute command on server {server_id}: {e}")

    # ── Task CRUD ─────────────────────────────────────────────────────────────

    def create_task(self, server_id, task_config):
        """Create a new scheduled task for a server."""
        task_id = str(int(datetime.now().timestamp() * 1000))
        conn = get_db()
        conn.execute(
            '''INSERT INTO tasks
               (id, server_id, name, action, interval, enabled, command, runs,
                run_count, last_run, delete_after_execution, delete_after_runs_count, created)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?)''',
            (task_id, server_id,
             task_config.get('name', 'Unnamed Task'),
             task_config.get('action', 'START'),
             task_config.get('interval', '0 3 * * *'),
             1 if task_config.get('enabled', True) else 0,
             task_config.get('command', ''),
             int(task_config.get('runs', 0)),
             1 if task_config.get('deleteAfterExecution', False) else 0,
             1 if task_config.get('deleteAfterRunsCount', False) else 0,
             datetime.now().isoformat())
        )
        conn.commit()

        task = self._row_to_task_dict(
            conn.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
        )
        if task['enabled']:
            self._add_job(server_id, task_id, task)
        return task

    def update_task(self, server_id, task_id, task_config):
        """Update an existing task."""
        conn = get_db()
        row = conn.execute('SELECT * FROM tasks WHERE id=? AND server_id=?',
                           (task_id, server_id)).fetchone()
        if row is None:
            return None

        task = self._row_to_task_dict(row)
        conn.execute(
            '''UPDATE tasks SET name=?, action=?, interval=?, command=?, runs=?,
               enabled=?, delete_after_execution=?, delete_after_runs_count=?
               WHERE id=?''',
            (task_config.get('name',                 task['name']),
             task_config.get('action',               task['action']),
             task_config.get('interval',             task['interval']),
             task_config.get('command',              task.get('command', '')),
             int(task_config.get('runs',             task['runs'])),
             1 if task_config.get('enabled',         task['enabled']) else 0,
             1 if task_config.get('deleteAfterExecution',  task['deleteAfterExecution']) else 0,
             1 if task_config.get('deleteAfterRunsCount',  task['deleteAfterRunsCount']) else 0,
             task_id)
        )
        conn.commit()

        updated = self._row_to_task_dict(
            conn.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
        )
        if updated['enabled']:
            self._add_job(server_id, task_id, updated)
        else:
            try:
                self.scheduler.remove_job(f"task_{server_id}_{task_id}")
            except Exception:
                pass
        return updated

    def delete_task(self, server_id, task_id):
        """Delete a task."""
        conn = get_db()
        result = conn.execute('DELETE FROM tasks WHERE id=? AND server_id=?',
                              (task_id, server_id))
        conn.commit()
        try:
            self.scheduler.remove_job(f"task_{server_id}_{task_id}")
        except Exception:
            pass
        return result.rowcount > 0

    def get_tasks(self, server_id):
        """Get all tasks for a server, enriched with next-run times."""
        rows = get_db().execute(
            'SELECT * FROM tasks WHERE server_id=? ORDER BY created', (server_id,)
        ).fetchall()
        result = []
        for row in rows:
            t = self._row_to_task_dict(row)
            try:
                job = self.scheduler.get_job(f"task_{server_id}_{row['id']}")
                if job and job.next_run_time:
                    t['nextRun'] = job.next_run_time.isoformat()
            except Exception:
                pass
            result.append(t)
        return result

    def get_task(self, server_id, task_id):
        """Get a specific task, enriched with next-run time."""
        row = get_db().execute(
            'SELECT * FROM tasks WHERE id=? AND server_id=?', (task_id, server_id)
        ).fetchone()
        if row is None:
            return None
        t = self._row_to_task_dict(row)
        try:
            job = self.scheduler.get_job(f"task_{server_id}_{task_id}")
            if job and job.next_run_time:
                t['nextRun'] = job.next_run_time.isoformat()
        except Exception:
            pass
        return t


# ==================== Server Message Scheduler ====================

class MessageScheduler:
    """Manages scheduled and event-triggered server messages — backed by SQLite."""

    EVENT_TRIGGERS = ['backup_start', 'backup_complete', 'server_start', 'server_stop', 'server_crash']

    def __init__(self, server_manager):
        self.server_manager = server_manager
        self.scheduler = BackgroundScheduler()
        self.scheduler.start()
        self._restore_jobs()

    @staticmethod
    def _row_to_dict(row):
        if row is None:
            return None
        return {
            'id':            row['id'],
            'serverId':      row['server_id'],
            'name':          row['name'],
            'trigger':       row['trigger'],
            'cronExpr':      row['cron_expr'],
            'msgType':       row['msg_type'],
            'target':        row['target'],
            'message':       row['message'],
            'color':         row['color'],
            'bold':          bool(row['bold']),
            'italic':        bool(row['italic']),
            'underlined':    bool(row['underlined']),
            'strikethrough': bool(row['strikethrough']),
            'obfuscated':    bool(row['obfuscated']),
            'enabled':       bool(row['enabled']),
            'runCount':      row['run_count'],
            'lastRun':       row['last_run'],
            'createdAt':     row['created'],
        }

    def _restore_jobs(self):
        rows = get_db().execute(
            "SELECT * FROM scheduled_messages WHERE enabled=1 AND trigger='cron'"
        ).fetchall()
        for row in rows:
            self._add_cron_job(row['server_id'], row['id'], row['cron_expr'])

    def _add_cron_job(self, server_id, msg_id, cron_expr):
        job_id = f"msg_{server_id}_{msg_id}"
        try:
            self.scheduler.remove_job(job_id)
        except Exception:
            pass
        if not cron_expr:
            return
        try:
            parts = cron_expr.split()
            if len(parts) == 5:
                trigger = CronTrigger(
                    minute=parts[0], hour=parts[1],
                    day=parts[2], month=parts[3], day_of_week=parts[4]
                )
                self.scheduler.add_job(
                    self._execute_message, trigger=trigger,
                    id=job_id, args=[server_id, msg_id]
                )
        except Exception as e:
            print(f"[MessageScheduler] Failed to add cron job {job_id}: {e}")

    def _build_command(self, msg, is_bedrock):
        msg_type = msg['msgType']
        # Sanitize at send time so rows created before this hardening (or via
        # the raw API) can't smuggle a second console command past stdin.
        message = _safe_console_text(msg['message'])
        target = _safe_message_target(msg['target'])
        color = msg['color'] if msg['color'] in VALID_MESSAGE_COLORS else 'white'
        if not target:
            return None
        safe = message.replace('\\', '\\\\').replace('"', '\\"')

        if msg_type == 'say':
            return f'say {message}'
        elif msg_type == 'msg':
            return f'msg {target} {message}'
        elif msg_type == 'chat':
            if is_bedrock:
                return f'tellraw {target} {{"rawtext":[{{"text":"{safe}"}}]}}'
            parts = [f'"text":"{safe}"', f'"color":"{color}"']
            if msg['bold']:
                parts.append('"bold":true')
            if msg['italic']:
                parts.append('"italic":true')
            if msg['underlined']:
                parts.append('"underlined":true')
            if msg['strikethrough']:
                parts.append('"strikethrough":true')
            if msg['obfuscated']:
                parts.append('"obfuscated":true')
            return f'tellraw {target} {{{",".join(parts)}}}'
        elif msg_type in ('title', 'subtitle', 'actionbar'):
            if is_bedrock:
                return f'titleraw {target} {msg_type} {{"rawtext":[{{"text":"{safe}"}}]}}'
            parts = [f'"text":"{safe}"', f'"color":"{color}"']
            if msg['bold']:
                parts.append('"bold":true')
            if msg['italic']:
                parts.append('"italic":true')
            return f'title {target} {msg_type} {{{",".join(parts)}}}'
        return None

    def _execute_message(self, server_id, msg_id):
        try:
            conn = get_db()
            row = conn.execute('SELECT * FROM scheduled_messages WHERE id=?', (msg_id,)).fetchone()
            if not row or not row['enabled']:
                return
            msg = self._row_to_dict(row)
            instance = self.server_manager.servers.get(server_id)
            if not instance or not instance.is_running():
                print(f"[MessageScheduler] Server {server_id} not running, skipping message {msg_id}")
                return

            server_config = self.server_manager.get_server_config(server_id)
            is_bedrock = server_config and server_config.get('category') == 'bedrock'
            command = self._build_command(msg, is_bedrock)
            if command:
                instance.send_command(command)
                conn.execute(
                    'UPDATE scheduled_messages SET run_count=run_count+1, last_run=? WHERE id=?',
                    (datetime.now().isoformat(), msg_id)
                )
                conn.commit()
                print(f"[MessageScheduler] Sent message {msg_id} to server {server_id}: {command}")
        except Exception as e:
            print(f"[MessageScheduler] Failed to execute message {msg_id}: {e}")

    def fire_event(self, server_id, event_type):
        """Called by event hooks (backup, start, stop, crash) to fire matching messages."""
        try:
            rows = get_db().execute(
                'SELECT * FROM scheduled_messages WHERE server_id=? AND trigger=? AND enabled=1',
                (server_id, event_type)
            ).fetchall()
            for row in rows:
                self._execute_message(server_id, row['id'])
        except Exception as e:
            print(f"[MessageScheduler] Error firing event {event_type} for {server_id}: {e}")

    def create_message(self, server_id, config):
        msg_id = str(int(datetime.now().timestamp() * 1000))
        trigger = config.get('trigger', 'cron')
        cron_expr = config.get('cronExpr', '') if trigger == 'cron' else None
        conn = get_db()
        conn.execute(
            '''INSERT INTO scheduled_messages
               (id, server_id, name, trigger, cron_expr, msg_type, target, message,
                color, bold, italic, underlined, strikethrough, obfuscated,
                enabled, run_count, last_run, created)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?)''',
            (msg_id, server_id,
             config.get('name', 'Unnamed Message'),
             trigger,
             cron_expr,
             config.get('msgType', 'say'),
             config.get('target', '@a'),
             config.get('message', ''),
             config.get('color', 'white'),
             1 if config.get('bold') else 0,
             1 if config.get('italic') else 0,
             1 if config.get('underlined') else 0,
             1 if config.get('strikethrough') else 0,
             1 if config.get('obfuscated') else 0,
             1 if config.get('enabled', True) else 0,
             datetime.now().isoformat())
        )
        conn.commit()
        msg = self._row_to_dict(
            conn.execute('SELECT * FROM scheduled_messages WHERE id=?', (msg_id,)).fetchone()
        )
        if msg['enabled'] and trigger == 'cron' and cron_expr:
            self._add_cron_job(server_id, msg_id, cron_expr)
        return msg

    def update_message(self, server_id, msg_id, config):
        conn = get_db()
        row = conn.execute(
            'SELECT * FROM scheduled_messages WHERE id=? AND server_id=?',
            (msg_id, server_id)
        ).fetchone()
        if row is None:
            return None
        old = self._row_to_dict(row)
        trigger = config.get('trigger', old['trigger'])
        cron_expr = config.get('cronExpr', old['cronExpr']) if trigger == 'cron' else None
        conn.execute(
            '''UPDATE scheduled_messages SET name=?, trigger=?, cron_expr=?, msg_type=?,
               target=?, message=?, color=?, bold=?, italic=?, underlined=?,
               strikethrough=?, obfuscated=?, enabled=?
               WHERE id=?''',
            (config.get('name', old['name']),
             trigger,
             cron_expr,
             config.get('msgType', old['msgType']),
             config.get('target', old['target']),
             config.get('message', old['message']),
             config.get('color', old['color']),
             1 if config.get('bold', old['bold']) else 0,
             1 if config.get('italic', old['italic']) else 0,
             1 if config.get('underlined', old['underlined']) else 0,
             1 if config.get('strikethrough', old['strikethrough']) else 0,
             1 if config.get('obfuscated', old['obfuscated']) else 0,
             1 if config.get('enabled', old['enabled']) else 0,
             msg_id)
        )
        conn.commit()
        updated = self._row_to_dict(
            conn.execute('SELECT * FROM scheduled_messages WHERE id=?', (msg_id,)).fetchone()
        )
        job_id = f"msg_{server_id}_{msg_id}"
        try:
            self.scheduler.remove_job(job_id)
        except Exception:
            pass
        if updated['enabled'] and trigger == 'cron' and cron_expr:
            self._add_cron_job(server_id, msg_id, cron_expr)
        return updated

    def delete_message(self, server_id, msg_id):
        conn = get_db()
        result = conn.execute(
            'DELETE FROM scheduled_messages WHERE id=? AND server_id=?',
            (msg_id, server_id)
        )
        conn.commit()
        try:
            self.scheduler.remove_job(f"msg_{server_id}_{msg_id}")
        except Exception:
            pass
        return result.rowcount > 0

    def get_messages(self, server_id):
        rows = get_db().execute(
            'SELECT * FROM scheduled_messages WHERE server_id=? ORDER BY created',
            (server_id,)
        ).fetchall()
        result = []
        for row in rows:
            m = self._row_to_dict(row)
            if m['trigger'] == 'cron':
                try:
                    job = self.scheduler.get_job(f"msg_{server_id}_{row['id']}")
                    if job and job.next_run_time:
                        m['nextRun'] = job.next_run_time.isoformat()
                except Exception:
                    pass
            result.append(m)
        return result

    def get_message(self, server_id, msg_id):
        row = get_db().execute(
            'SELECT * FROM scheduled_messages WHERE id=? AND server_id=?',
            (msg_id, server_id)
        ).fetchone()
        if row is None:
            return None
        m = self._row_to_dict(row)
        if m['trigger'] == 'cron':
            try:
                job = self.scheduler.get_job(f"msg_{server_id}_{msg_id}")
                if job and job.next_run_time:
                    m['nextRun'] = job.next_run_time.isoformat()
            except Exception:
                pass
        return m

    def test_message(self, server_id, config):
        """Send a message immediately without saving it."""
        instance = self.server_manager.servers.get(server_id)
        if not instance or not instance.is_running():
            return False, "Server is not running"
        server_config = self.server_manager.get_server_config(server_id)
        is_bedrock = server_config and server_config.get('category') == 'bedrock'
        command = self._build_command(config, is_bedrock)
        if not command:
            return False, "Invalid message type or target"
        instance.send_command(command)
        return True, command


# ==================== Permission Groups ====================

class GroupManager:
    """Manages permission groups backed by SQLite with in-memory cache."""

    # The catalog is the source of truth for the group editor's checkboxes, so it
    # must only list permissions that are actually enforced somewhere in code
    # (issues #71/#79) — a checkbox for an unchecked permission is a lie about
    # what the panel restricts. Anything added here needs a matching guard.
    ALL_PERMISSIONS = [
        # Panel
        'panel.users.view', 'panel.users.manage',
        'panel.groups.view', 'panel.groups.manage',
        'panel.approvals.manage',
        'panel.settings.view', 'panel.settings.manage',
        'panel.jars.manage', 'panel.tools.manage',
        'panel.stats.view', 'panel.panel.backup',
        # Server
        'servers.create', 'servers.access.all',
    ]

    PERMISSION_CATEGORIES = {
        'Panel': [
            'panel.users.view', 'panel.users.manage',
            'panel.groups.view', 'panel.groups.manage',
            'panel.approvals.manage',
            'panel.settings.view', 'panel.settings.manage',
            'panel.jars.manage', 'panel.tools.manage',
            'panel.stats.view', 'panel.panel.backup',
        ],
        'Server': [
            'servers.create', 'servers.access.all',
        ],
    }

    PERMISSION_LABELS = {
        'panel.users.view': 'View Users',
        'panel.users.manage': 'Manage Users',
        'panel.groups.view': 'View Groups',
        'panel.groups.manage': 'Manage Groups',
        'panel.approvals.manage': 'Manage Approvals',
        'panel.settings.view': 'View Settings',
        'panel.settings.manage': 'Manage Settings',
        'panel.jars.manage': 'Manage Server JARs',
        'panel.tools.manage': 'Manage Tools',
        'panel.stats.view': 'View System Stats',
        'panel.panel.backup': 'Panel Backup/Restore',
        'servers.create': 'Create Servers',
        'servers.access.all': 'Access All Servers',
    }

    def __init__(self):
        self._cache = None
        self._lock = threading.Lock()

    def _ensure_cache(self):
        if self._cache is None:
            self._load_cache()

    def _load_cache(self):
        try:
            conn = get_db()
            rows = conn.execute('SELECT * FROM groups').fetchall()
            self._cache = {r['id']: self._row_to_dict(r) for r in rows}
        except Exception:
            self._cache = {}

    def _invalidate(self):
        with self._lock:
            self._load_cache()

    def prune_stale_permissions(self):
        """Drop stored permission strings that are no longer in the catalog.

        Groups seeded or saved before #71/#79 still carry the removed granular
        `servers.*` strings. Nothing enforces them, and update_group() already
        filters them out on the next save — this just stops them from lingering
        in the DB and in the /api/auth/me payload. Wildcards are kept, matching
        create_group()/update_group() validation. Called once after init_db(),
        which seeds the built-in groups."""
        try:
            conn = get_db()
            rows = conn.execute('SELECT id, permissions FROM groups').fetchall()
        except Exception:
            return
        changed = False
        for r in rows:
            try:
                perms = json.loads(r['permissions'] or '[]')
            except Exception:
                continue
            kept = [p for p in perms
                    if p in self.ALL_PERMISSIONS or p.endswith('.*') or p == '*']
            if len(kept) != len(perms):
                conn.execute('UPDATE groups SET permissions=? WHERE id=?',
                             (json.dumps(kept), r['id']))
                changed = True
        if changed:
            conn.commit()
            self._invalidate()

    @staticmethod
    def _row_to_dict(row):
        if row is None:
            return None
        perms = []
        try:
            perms = json.loads(row['permissions'] or '[]')
        except Exception:
            pass
        return {
            'id': row['id'],
            'name': row['name'],
            'permissions': perms,
            'isDefault': bool(row['is_default']),
            'isBuiltin': bool(row['is_builtin']),
            'priority': row['priority'],
            'created': row['created'],
        }

    # ── Permission checking ──────────────────────────────────────────────────

    def has_permission(self, group_id, permission):
        self._ensure_cache()
        if not group_id:
            return False
        group = self._cache.get(group_id)
        if not group:
            return False
        perms = group.get('permissions', [])
        if '*' in perms:
            return True
        if permission in perms:
            return True
        parts = permission.split('.')
        for i in range(1, len(parts)):
            wildcard = '.'.join(parts[:i]) + '.*'
            if wildcard in perms:
                return True
        return False

    def is_admin_group(self, group_id):
        self._ensure_cache()
        if not group_id:
            return False
        group = self._cache.get(group_id)
        return group is not None and '*' in group.get('permissions', [])

    def get_permissions_for_group(self, group_id):
        self._ensure_cache()
        group = self._cache.get(group_id)
        if not group:
            return []
        perms = group.get('permissions', [])
        if '*' in perms:
            return list(self.ALL_PERMISSIONS)
        resolved = []
        for p in self.ALL_PERMISSIONS:
            if p in perms:
                resolved.append(p)
                continue
            parts = p.split('.')
            for i in range(1, len(parts)):
                wildcard = '.'.join(parts[:i]) + '.*'
                if wildcard in perms:
                    resolved.append(p)
                    break
        return resolved

    # ── CRUD ─────────────────────────────────────────────────────────────────

    def get_group(self, group_id):
        self._ensure_cache()
        return self._cache.get(group_id)

    def get_all_groups(self):
        self._ensure_cache()
        return sorted(self._cache.values(), key=lambda g: -g['priority'])

    def create_group(self, name, permissions, is_default=False):
        conn = get_db()
        group_id = str(uuid.uuid4())[:8]
        valid_perms = [p for p in permissions if p in self.ALL_PERMISSIONS or p.endswith('.*') or p == '*']
        conn.execute(
            '''INSERT INTO groups (id, name, permissions, is_default, is_builtin, priority, created)
               VALUES (?, ?, ?, ?, 0, 0, ?)''',
            (group_id, name, json.dumps(valid_perms), 1 if is_default else 0,
             datetime.now().isoformat())
        )
        if is_default:
            conn.execute('UPDATE groups SET is_default=0 WHERE id != ?', (group_id,))
        conn.commit()
        self._invalidate()
        return group_id

    def update_group(self, group_id, name=None, permissions=None, is_default=None, priority=None):
        group = self.get_group(group_id)
        if not group:
            return False, 'Group not found'
        conn = get_db()
        if name is not None:
            if group['isBuiltin']:
                return False, 'Cannot rename built-in groups'
            existing = conn.execute(
                'SELECT id FROM groups WHERE name=? COLLATE NOCASE AND id != ?',
                (name, group_id)).fetchone()
            if existing:
                return False, 'A group with that name already exists'
            conn.execute('UPDATE groups SET name=? WHERE id=?', (name, group_id))
        if permissions is not None:
            if group_id == 'builtin-admin':
                permissions = list(set(permissions) | {'*'})
            valid_perms = [p for p in permissions if p in self.ALL_PERMISSIONS or p.endswith('.*') or p == '*']
            conn.execute('UPDATE groups SET permissions=? WHERE id=?',
                         (json.dumps(valid_perms), group_id))
        if is_default is not None and is_default:
            conn.execute('UPDATE groups SET is_default=0')
            conn.execute('UPDATE groups SET is_default=1 WHERE id=?', (group_id,))
        if priority is not None:
            conn.execute('UPDATE groups SET priority=? WHERE id=?', (priority, group_id))
        conn.commit()
        self._invalidate()
        return True, 'Group updated'

    def delete_group(self, group_id):
        group = self.get_group(group_id)
        if not group:
            return False, 'Group not found'
        if group['isBuiltin']:
            return False, 'Cannot delete built-in groups'
        conn = get_db()
        default_id = self.get_default_group_id()
        if default_id == group_id:
            return False, 'Cannot delete the default group'
        conn.execute('UPDATE users SET group_id=? WHERE group_id=?',
                     (default_id, group_id))
        conn.execute('DELETE FROM groups WHERE id=?', (group_id,))
        conn.commit()
        self._invalidate()
        return True, 'Group deleted'

    def get_default_group_id(self):
        self._ensure_cache()
        for gid, g in self._cache.items():
            if g.get('isDefault'):
                return gid
        return 'builtin-user'

    def get_admin_group_id(self):
        return 'builtin-admin'

    def set_default_group(self, group_id):
        self._ensure_cache()
        if group_id not in self._cache:
            return False
        conn = get_db()
        conn.execute('UPDATE groups SET is_default=0')
        conn.execute('UPDATE groups SET is_default=1 WHERE id=?', (group_id,))
        conn.commit()
        self._invalidate()
        return True

    def get_user_count(self, group_id):
        conn = get_db()
        row = conn.execute('SELECT COUNT(*) AS cnt FROM users WHERE group_id=?',
                           (group_id,)).fetchone()
        return row['cnt'] if row else 0

    # ── Server group access (sharing) ────────────────────────────────────────

    def get_server_groups(self, server_id):
        self._ensure_cache()
        conn = get_db()
        rows = conn.execute(
            'SELECT group_id FROM server_group_access WHERE server_id=?',
            (server_id,)).fetchall()
        return [self._cache[r['group_id']] for r in rows
                if r['group_id'] in self._cache]

    def get_server_group_ids(self, server_id):
        conn = get_db()
        rows = conn.execute(
            'SELECT group_id FROM server_group_access WHERE server_id=?',
            (server_id,)).fetchall()
        return [r['group_id'] for r in rows]

    def set_server_groups(self, server_id, group_ids):
        self._ensure_cache()
        conn = get_db()
        conn.execute('DELETE FROM server_group_access WHERE server_id=?',
                     (server_id,))
        for gid in group_ids:
            if gid in self._cache:
                conn.execute(
                    'INSERT OR IGNORE INTO server_group_access (server_id, group_id) VALUES (?, ?)',
                    (server_id, gid))
        conn.commit()


group_manager = GroupManager()


# ==================== User Management & RBAC ====================

class UserManager:
    """Manages users, authentication, and role-based access control — backed by SQLite."""

    # The permanent hidden anti-lockout admin. Exactly one row carries
    # is_anti_lockout=1. It normally stays disabled and hidden from the user list;
    # it is activated (enabled + a fresh password logged to the server log) only
    # when no real admin can log in. Its identifying fields are fixed and cannot
    # be edited or deleted through the UI/API.
    ANTI_LOCKOUT_USERNAME = 'admin'
    ANTI_LOCKOUT_NAME = 'Admin'
    ANTI_LOCKOUT_EMAIL = 'Admin@local'

    # An account auto-disabled by failed logins unlocks itself this many seconds
    # after disabled_at; a disabled account with no disabled_at stays locked.
    LOCKOUT_DURATION_SECONDS = 1800

    _DEFAULT_NOTIF_PREFS = {
        'backupComplete': False,
        'backupFailure': False,
        'serverStart': False,
        'serverStop': False,
        'playerJoin': False,
        'playerLeave': False,
        'criticalAlerts': False,
    }

    def __init__(self):
        self._ensure_anti_lockout_admin_exists()

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _row_to_dict(row):
        """Convert a sqlite3.Row to the camelCase user dict expected by the rest of the app."""
        if row is None:
            return None
        prefs = {}
        try:
            prefs = json.loads(row['notification_prefs'] or '{}')
        except Exception:
            pass
        gid = row['group_id']
        group = group_manager.get_group(gid) if gid else None
        return {
            'username':             row['username'],
            'password':             row['password'],
            'groupId':              gid,
            'groupName':            group['name'] if group else None,
            'name':                 row['name'],
            'email':                row['email'],
            'mfaEnabled':           bool(row['mfa_enabled']),
            'mfaSecret':            row['mfa_secret'],
            'mfaRecoveryCode':      row['mfa_recovery_code'],
            'approved':             bool(row['approved']),
            'created':              row['created'],
            'lastLogin':            row['last_login'],
            'failedLoginAttempts':  row['failed_login_attempts'],
            'accountDisabled':      bool(row['account_disabled']),
            'disabledAt':           row['disabled_at'],
            'isAntiLockout':        bool(row['is_anti_lockout']),
            'notificationPrefs':    prefs,
        }

    @classmethod
    def _is_locked(cls, row):
        """True if the account is currently unable to log in.

        A failed-login lockout carries a disabled_at timestamp and expires on its
        own after LOCKOUT_DURATION_SECONDS, so a stale account_disabled flag past
        that window is not reported as locked."""
        if not row['account_disabled']:
            return False
        disabled_at = row['disabled_at']
        if not disabled_at:
            return True
        try:
            elapsed = (datetime.now() - datetime.fromisoformat(disabled_at)).total_seconds()
        except (TypeError, ValueError):
            return True
        return elapsed < cls.LOCKOUT_DURATION_SECONDS

    def _ensure_anti_lockout_admin_exists(self):
        """Ensure the permanent hidden anti-lockout 'admin' account exists.

        Created once (disabled, hidden) with a random placeholder password that is
        never revealed. A real, logged password is only set when the account is
        activated by _activate_anti_lockout_admin(). This replaces the old
        auto-created default admin: a clean install has no usable admin and is
        steered to the first-run setup flow instead.
        """
        conn = get_db()
        row = conn.execute('SELECT id FROM users WHERE is_anti_lockout=1').fetchone()
        if row:
            return
        # Don't collide with a pre-existing real account named 'admin' (legacy DBs).
        existing = conn.execute(
            'SELECT id FROM users WHERE username=? COLLATE NOCASE',
            (self.ANTI_LOCKOUT_USERNAME,)
        ).fetchone()
        if existing:
            return
        user_id = str(uuid.uuid4())[:8]
        placeholder = secrets.token_urlsafe(24)  # never logged; account starts disabled
        conn.execute(
            '''INSERT INTO users
               (id, username, password, group_id, name, email, mfa_enabled, approved, created,
                failed_login_attempts, account_disabled, disabled_at, is_anti_lockout, notification_prefs)
               VALUES (?, ?, ?, ?, ?, ?, 0, 1, ?, 0, 1, NULL, 1, '{}')''',
            (user_id, self.ANTI_LOCKOUT_USERNAME, generate_password_hash(placeholder),
             group_manager.get_admin_group_id(),
             self.ANTI_LOCKOUT_NAME, self.ANTI_LOCKOUT_EMAIL, datetime.now().isoformat())
        )
        conn.commit()

    def needs_setup(self):
        """True on a clean install: no real (non-anti-lockout) admin has ever been
        created. Used to gate the first-run setup flow. Note this is False during a
        lockout (real admins exist but are disabled) — that case uses the hidden
        admin for recovery, NOT the unauthenticated setup endpoint."""
        return self._count_real_admins() == 0

    def _count_real_admins(self):
        """Count admin-group accounts that are not the hidden anti-lockout account, in any
        state (enabled or disabled, approved or not)."""
        row = get_db().execute(
            "SELECT COUNT(*) FROM users WHERE group_id=? AND is_anti_lockout=0",
            (group_manager.get_admin_group_id(),)
        ).fetchone()
        return row[0]

    def _get_anti_lockout_id(self):
        row = get_db().execute('SELECT id FROM users WHERE is_anti_lockout=1').fetchone()
        return row['id'] if row else None

    def _is_anti_lockout(self, user_id):
        """True if the given user id is the permanent hidden anti-lockout account."""
        row = get_db().execute(
            'SELECT is_anti_lockout FROM users WHERE id=?', (user_id,)
        ).fetchone()
        return bool(row and row['is_anti_lockout'])

    # ── Authentication ────────────────────────────────────────────────────────

    def authenticate(self, username, password):
        """Authenticate a user and return (user_id, user_dict) or (None, error_str)."""
        conn = get_db()
        row = conn.execute(
            'SELECT * FROM users WHERE username=? COLLATE NOCASE', (username,)
        ).fetchone()

        if row is None:
            return None, "Invalid username or password"

        user_id = row['id']

        if row['account_disabled']:
            # Auto-expire lockout after 30 minutes
            disabled_at = row['disabled_at']
            if disabled_at:
                locked_dt = datetime.fromisoformat(disabled_at)
                elapsed = (datetime.now() - locked_dt).total_seconds()
                if elapsed >= self.LOCKOUT_DURATION_SECONDS:
                    conn.execute(
                        'UPDATE users SET account_disabled=0, failed_login_attempts=0, disabled_at=NULL WHERE id=?',
                        (user_id,)
                    )
                    conn.commit()
                    # Fall through to password check below
                else:
                    return None, "Account temporarily locked due to too many failed attempts. Try again later."
            else:
                return None, "Account has been disabled. Please contact an administrator."

        if check_password_hash(row['password'], password):
            if not row['approved'] and not group_manager.is_admin_group(row['group_id']):
                return None, "Account pending approval"

            conn.execute(
                'UPDATE users SET failed_login_attempts=0, last_login=? WHERE id=?',
                (datetime.now().isoformat(), user_id)
            )
            conn.commit()
            return user_id, self._row_to_dict(row)
        else:
            new_attempts = row['failed_login_attempts'] + 1
            if new_attempts >= 5:
                conn.execute(
                    'UPDATE users SET failed_login_attempts=?, account_disabled=1, disabled_at=? WHERE id=?',
                    (new_attempts, datetime.now().isoformat(), user_id)
                )
                conn.commit()
                self._check_anti_lockout()
                return None, "Account temporarily locked due to too many failed attempts. Try again later."

            conn.execute(
                'UPDATE users SET failed_login_attempts=? WHERE id=?',
                (new_attempts, user_id)
            )
            conn.commit()
            return None, "Invalid username or password"

    # ── Registration / Creation ───────────────────────────────────────────────

    def register(self, username, password):
        """Register a new user (pending approval)."""
        if len(username) < 3 or len(username) > 32:
            return None, "Username must be 3-32 characters"
        if not username.replace('_', '').replace('-', '').isalnum():
            return None, "Username can only contain letters, numbers, underscores, and hyphens"
        if username.lower() == self.ANTI_LOCKOUT_USERNAME:
            return None, "That username is reserved"
        if len(password) < 12:
            return None, "Password must be at least 12 characters"
        if not any(c.isupper() for c in password):
            return None, "Password must contain at least one uppercase letter"
        if not any(c.islower() for c in password):
            return None, "Password must contain at least one lowercase letter"
        if not any(c.isdigit() for c in password):
            return None, "Password must contain at least one number"

        reg_policy = settings_manager.get_policy('registration')
        require_approval = reg_policy == 'require_approval'
        user_id = str(uuid.uuid4())[:8]
        default_prefs = json.dumps({k: False for k in self._DEFAULT_NOTIF_PREFS})

        conn = get_db()
        try:
            conn.execute(
                '''INSERT INTO users
                   (id, username, password, group_id, name, email, approved, created,
                    failed_login_attempts, account_disabled, is_anti_lockout, notification_prefs)
                   VALUES (?, ?, ?, ?, '', '', ?, ?, 0, 0, 0, ?)''',
                (user_id, username, generate_password_hash(password),
                 group_manager.get_default_group_id(),
                 0 if require_approval else 1,
                 datetime.now().isoformat(), default_prefs)
            )
            conn.commit()
        except Exception as e:
            if 'UNIQUE' in str(e).upper():
                return None, "Username already exists"
            raise

        if reg_policy == 'notify':
            notification_manager.notify_admins(
                'action_notify', 'New user registered',
                f'{username} has registered an account.',
                ref_type='user', ref_id=user_id)
        elif require_approval:
            notification_manager.notify_admins(
                'approval_request', 'User registration — approval needed',
                f'{username} has registered and is awaiting approval.',
                link='/settings#approvals',
                ref_type='user', ref_id=user_id)

        if require_approval:
            return user_id, "Registration successful. Please wait for admin approval."
        return user_id, "Registration successful. You can now log in."

    def create_user(self, username, password, group_id=None, email=''):
        """Create a user directly (admin function, auto-approved)."""
        if len(username) < 3 or len(username) > 32:
            return None, "Username must be 3-32 characters"
        if not username.replace('_', '').replace('-', '').isalnum():
            return None, "Username can only contain letters, numbers, underscores, and hyphens"
        if username.lower() == self.ANTI_LOCKOUT_USERNAME:
            return None, "That username is reserved"
        if len(password) < 6:
            return None, "Password must be at least 6 characters"
        if group_id is None:
            group_id = group_manager.get_default_group_id()
        if not group_manager.get_group(group_id):
            return None, "Invalid group"

        user_id = str(uuid.uuid4())[:8]
        default_prefs = json.dumps({k: False for k in self._DEFAULT_NOTIF_PREFS})

        conn = get_db()
        try:
            conn.execute(
                '''INSERT INTO users
                   (id, username, password, group_id, name, email, approved, created,
                    failed_login_attempts, account_disabled, is_anti_lockout, notification_prefs)
                   VALUES (?, ?, ?, ?, '', ?, 1, ?, 0, 0, 0, ?)''',
                (user_id, username, generate_password_hash(password), group_id, email,
                 datetime.now().isoformat(), default_prefs)
            )
            conn.commit()
        except Exception as e:
            if 'UNIQUE' in str(e).upper():
                return None, "Username already exists"
            raise

        if group_manager.is_admin_group(group_id):
            self._deactivate_anti_lockout_admin()

        return user_id, "User created successfully"

    def create_first_admin(self, username, password, name='', email=''):
        """Create the first real admin during first-run setup. Only allowed on a
        clean install (no real admin yet); enforced here as defence in depth in
        addition to the route guard."""
        if not self.needs_setup():
            return None, "Setup has already been completed"
        username = (username or '').strip()
        if username.lower() == self.ANTI_LOCKOUT_USERNAME:
            return None, "That username is reserved"
        if len(username) < 3 or len(username) > 32:
            return None, "Username must be 3-32 characters"
        if not username.replace('_', '').replace('-', '').isalnum():
            return None, "Username can only contain letters, numbers, underscores, and hyphens"
        if len(password) < 12:
            return None, "Password must be at least 12 characters"
        if not any(c.isupper() for c in password):
            return None, "Password must contain at least one uppercase letter"
        if not any(c.islower() for c in password):
            return None, "Password must contain at least one lowercase letter"
        if not any(c.isdigit() for c in password):
            return None, "Password must contain at least one number"

        user_id = str(uuid.uuid4())[:8]
        default_prefs = json.dumps({k: False for k in self._DEFAULT_NOTIF_PREFS})
        conn = get_db()
        try:
            conn.execute(
                '''INSERT INTO users
                   (id, username, password, group_id, name, email, approved, created,
                    failed_login_attempts, account_disabled, is_anti_lockout, notification_prefs)
                   VALUES (?, ?, ?, ?, ?, ?, 1, ?, 0, 0, 0, ?)''',
                (user_id, username, generate_password_hash(password),
                 group_manager.get_admin_group_id(),
                 (name or '').strip(), (email or '').strip(),
                 datetime.now().isoformat(), default_prefs)
            )
            conn.commit()
        except Exception as e:
            if 'UNIQUE' in str(e).upper():
                return None, "Username already exists"
            raise

        # A real admin now exists; make sure the hidden admin is disabled/hidden.
        self._deactivate_anti_lockout_admin()
        return user_id, "Admin account created"

    # ── Lookups ───────────────────────────────────────────────────────────────

    def get_user(self, user_id):
        """Get full user dict by ID (includes password hash — internal use)."""
        row = get_db().execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
        return self._row_to_dict(row)

    def get_user_by_id(self, user_id):
        """Get safe user dict by ID (for admin panel — no password)."""
        row = get_db().execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
        if row is None:
            return None
        gid = row['group_id']
        group = group_manager.get_group(gid) if gid else None
        return {
            'id':        row['id'],
            'username':  row['username'],
            'name':      row['name'],
            'email':     row['email'],
            'groupId':   gid,
            'groupName': group['name'] if group else None,
            'mfaEnabled': bool(row['mfa_enabled']),
            'approved':  bool(row['approved']),
            'created':   row['created'],
            'lastLogin': row['last_login'],
            'accountDisabled': bool(row['account_disabled']),
            'disabledAt': row['disabled_at'],
            'locked':    self._is_locked(row),
        }

    def get_all_users(self, include_anti_lockout=False):
        """Get all users as safe dicts (for admin panel).

        The permanent hidden anti-lockout account is excluded unless
        include_anti_lockout is True (only when the requester IS that account)."""
        if include_anti_lockout:
            rows = get_db().execute('SELECT * FROM users ORDER BY created').fetchall()
        else:
            rows = get_db().execute(
                'SELECT * FROM users WHERE is_anti_lockout=0 ORDER BY created'
            ).fetchall()
        result = []
        for r in rows:
            gid = r['group_id']
            group = group_manager.get_group(gid) if gid else None
            result.append({
                'id':        r['id'],
                'username':  r['username'],
                'name':      r['name'],
                'email':     r['email'],
                'groupId':   gid,
                'groupName': group['name'] if group else None,
                'mfaEnabled': bool(r['mfa_enabled']),
                'approved':  bool(r['approved']),
                'created':   r['created'],
                'lastLogin': r['last_login'],
                'accountDisabled': bool(r['account_disabled']),
                'disabledAt': r['disabled_at'],
                'locked':    self._is_locked(r),
                'isAntiLockout': bool(r['is_anti_lockout']),
            })
        return result

    # ── Approval & role ───────────────────────────────────────────────────────

    def approve_user(self, user_id):
        """Approve a pending user."""
        conn = get_db()
        result = conn.execute(
            'UPDATE users SET approved=1 WHERE id=?', (user_id,)
        )
        conn.commit()
        if result.rowcount == 0:
            return False
        row = conn.execute('SELECT group_id FROM users WHERE id=?', (user_id,)).fetchone()
        if row and group_manager.is_admin_group(row['group_id']) and self._has_active_admin():
            self._deactivate_anti_lockout_admin()
        return True

    def _has_active_admin(self):
        """Return True if at least one non-disabled, approved, non-anti-lockout admin exists."""
        row = get_db().execute(
            '''SELECT COUNT(*) FROM users
               WHERE group_id=? AND account_disabled=0 AND approved=1 AND is_anti_lockout=0''',
            (group_manager.get_admin_group_id(),)
        ).fetchone()
        return row[0] > 0

    def _check_anti_lockout(self):
        """If no real admin can currently log in, activate the hidden admin.

        Skipped when a real admin is active, and skipped on a clean install (no
        real admin ever created — the setup flow handles that and we must not
        expose the hidden admin to an unconfigured panel)."""
        if self._has_active_admin():
            return
        if self.needs_setup():
            return
        self._activate_anti_lockout_admin()

    def _activate_anti_lockout_admin(self):
        """Enable the hidden admin with a fresh 16-character password and log it to
        the server log. Resets the account to its fixed identity and disables MFA.
        Returns the plaintext password (also printed), or None if unavailable."""
        conn = get_db()
        user_id = self._get_anti_lockout_id()
        if not user_id:
            self._ensure_anti_lockout_admin_exists()
            user_id = self._get_anti_lockout_id()
            if not user_id:
                return None

        import string
        alphabet = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(alphabet) for _ in range(16))

        conn.execute(
            '''UPDATE users
               SET password=?, group_id=?, name=?, email=?, approved=1,
                   mfa_enabled=0, mfa_secret=NULL, mfa_recovery_code=NULL,
                   account_disabled=0, failed_login_attempts=0, disabled_at=NULL
               WHERE id=?''',
            (generate_password_hash(password), group_manager.get_admin_group_id(),
             self.ANTI_LOCKOUT_NAME, self.ANTI_LOCKOUT_EMAIL, user_id)
        )
        conn.commit()

        print(f"""
{'='*80}
⚠️  ANTI-LOCKOUT ADMIN ACTIVATED ⚠️
{'='*80}
No active administrator account could be found, so the built-in emergency
admin account has been ENABLED:

  USERNAME: {self.ANTI_LOCKOUT_USERNAME}
  PASSWORD: {password}

⚠️  IMPORTANT:
  1. Log in with these credentials immediately.
  2. Re-enable or create a permanent admin account.
  3. This account is hidden and will be disabled again automatically once a
     normal admin is active. MFA is never required for it.
  4. This password is shown ONLY in this log line.
{'='*80}
""", flush=True)
        return password

    def _deactivate_anti_lockout_admin(self):
        """Re-hide (disable) the permanent hidden admin once a real admin is active.
        Never deletes it. Only acts when a real active admin exists, so it can never
        lock the operator out."""
        if not self._has_active_admin():
            return
        conn = get_db()
        conn.execute(
            'UPDATE users SET account_disabled=1, disabled_at=NULL WHERE is_anti_lockout=1'
        )
        conn.commit()

    def enable_account(self, user_id):
        """Enable a disabled user account and reset failed attempts."""
        if self._is_anti_lockout(user_id):
            return False, "This account is managed by the system"
        conn = get_db()
        result = conn.execute(
            'UPDATE users SET account_disabled=0, failed_login_attempts=0, disabled_at=NULL WHERE id=?',
            (user_id,)
        )
        conn.commit()
        if result.rowcount == 0:
            return False, "User not found"
        if self._has_active_admin():
            self._deactivate_anti_lockout_admin()
        return True, "Account enabled successfully"

    def update_user_group(self, user_id, group_id):
        """Update user's group."""
        if self._is_anti_lockout(user_id):
            return False
        if not group_manager.get_group(group_id):
            return False
        conn = get_db()
        result = conn.execute('UPDATE users SET group_id=? WHERE id=?', (group_id, user_id))
        conn.commit()
        if result.rowcount == 0:
            return False
        if group_manager.is_admin_group(group_id):
            self._deactivate_anti_lockout_admin()
        else:
            self._check_anti_lockout()
        return True

    def delete_user(self, user_id):
        """Delete a user."""
        if self._is_anti_lockout(user_id):
            return False
        conn = get_db()
        result = conn.execute('DELETE FROM users WHERE id=?', (user_id,))
        conn.commit()
        if result.rowcount == 0:
            return False
        # Deleting the last active admin should fail over to the hidden admin.
        self._check_anti_lockout()
        return True

    # ── Password management ───────────────────────────────────────────────────

    def change_password(self, user_id, old_password, new_password):
        """Change user password (requires current password)."""
        if self._is_anti_lockout(user_id):
            return False, "This account is managed by the system"
        row = get_db().execute('SELECT password FROM users WHERE id=?', (user_id,)).fetchone()
        if row is None:
            return False, "User not found"
        if not check_password_hash(row['password'], old_password):
            return False, "Current password is incorrect"
        if len(new_password) < 12:
            return False, "New password must be at least 12 characters"
        if not any(c.isupper() for c in new_password):
            return False, "Password must contain at least one uppercase letter"
        if not any(c.islower() for c in new_password):
            return False, "Password must contain at least one lowercase letter"
        if not any(c.isdigit() for c in new_password):
            return False, "Password must contain at least one number"
        conn = get_db()
        conn.execute('UPDATE users SET password=? WHERE id=?',
                     (generate_password_hash(new_password), user_id))
        conn.commit()
        return True, "Password changed successfully"

    def reset_password(self, user_id, new_password):
        """Admin reset user password (no old password required)."""
        if self._is_anti_lockout(user_id): return False
        if len(new_password) < 12: return False
        if not any(c.isupper() for c in new_password): return False
        if not any(c.islower() for c in new_password): return False
        if not any(c.isdigit() for c in new_password): return False
        conn = get_db()
        result = conn.execute('UPDATE users SET password=? WHERE id=?',
                              (generate_password_hash(new_password), user_id))
        conn.commit()
        return result.rowcount > 0

    # ── Profile updates ───────────────────────────────────────────────────────

    def update_username(self, user_id, new_username):
        """Update user's username."""
        if self._is_anti_lockout(user_id):
            return False, "This account is managed by the system"
        if new_username.lower() == self.ANTI_LOCKOUT_USERNAME:
            return False, "That username is reserved"
        if len(new_username) < 3 or len(new_username) > 32:
            return False, "Username must be 3-32 characters"
        if not new_username.replace('_', '').replace('-', '').isalnum():
            return False, "Username can only contain letters, numbers, underscores, and hyphens"
        conn = get_db()
        try:
            result = conn.execute('UPDATE users SET username=? WHERE id=?', (new_username, user_id))
            conn.commit()
        except Exception as e:
            if 'UNIQUE' in str(e).upper():
                return False, "Username already exists"
            raise
        if result.rowcount == 0:
            return False, "User not found"
        return True, "Username updated successfully"

    def update_name(self, user_id, name):
        """Update user's display name."""
        if self._is_anti_lockout(user_id):
            return False, "This account is managed by the system"
        if len(name) > 100:
            return False, "Name must be 100 characters or less"
        conn = get_db()
        result = conn.execute('UPDATE users SET name=? WHERE id=?', (name, user_id))
        conn.commit()
        return (True, "Name updated successfully") if result.rowcount else (False, "User not found")

    def update_email(self, user_id, email):
        """Update user's email address."""
        if self._is_anti_lockout(user_id):
            return False, "This account is managed by the system"
        if email and len(email) > 254:
            return False, "Email must be 254 characters or less"
        if email and '@' not in email:
            return False, "Invalid email format"
        conn = get_db()
        result = conn.execute('UPDATE users SET email=? WHERE id=?', (email, user_id))
        conn.commit()
        return (True, "Email updated successfully") if result.rowcount else (False, "User not found")

    # ── Notification preferences ──────────────────────────────────────────────

    def get_notification_prefs(self, user_id):
        """Return the notification preference dict for a user (merged with defaults)."""
        row = get_db().execute(
            'SELECT notification_prefs FROM users WHERE id=?', (user_id,)
        ).fetchone()
        if row is None:
            return None
        try:
            stored = json.loads(row['notification_prefs'] or '{}')
        except Exception:
            stored = {}
        return {**self._DEFAULT_NOTIF_PREFS, **stored}

    def update_notification_prefs(self, user_id, prefs):
        """Update notification preferences (only known keys accepted)."""
        current = self.get_notification_prefs(user_id)
        if current is None:
            return False
        for key in self._DEFAULT_NOTIF_PREFS:
            if key in prefs:
                current[key] = bool(prefs[key])
        conn = get_db()
        result = conn.execute(
            'UPDATE users SET notification_prefs=? WHERE id=?',
            (json.dumps(current), user_id)
        )
        conn.commit()
        return result.rowcount > 0

    def get_notification_recipients(self, pref_key):
        """Return email addresses of users who have pref_key enabled."""
        rows = get_db().execute(
            'SELECT email, notification_prefs FROM users WHERE email != \'\''
        ).fetchall()
        recipients = []
        for row in rows:
            try:
                prefs = json.loads(row['notification_prefs'] or '{}')
            except Exception:
                prefs = {}
            if prefs.get(pref_key, False):
                recipients.append(row['email'])
        return recipients

    # ── MFA ───────────────────────────────────────────────────────────────────

    def generate_mfa_secret(self, user_id):
        """Generate a new TOTP secret for user."""
        row = get_db().execute('SELECT id FROM users WHERE id=?', (user_id,)).fetchone()
        if row is None:
            return None, "User not found"
        return pyotp.random_base32(), "Secret generated successfully"

    def generate_recovery_code(self):
        """Generate a recovery code in format XXXXXXXX-XXXXXXXX-XXXXXXXX."""
        parts = [''.join(secrets.choice('ABCDEF0123456789') for _ in range(8)) for _ in range(3)]
        return '-'.join(parts)

    def verify_totp(self, secret, code):
        """Verify a TOTP code."""
        return pyotp.TOTP(secret).verify(code, valid_window=1)

    def enable_mfa(self, user_id, secret, recovery_code):
        """Enable MFA for user with hashed recovery code."""
        if self._is_anti_lockout(user_id):
            return False, "MFA cannot be enabled for this account"
        row = get_db().execute('SELECT id FROM users WHERE id=?', (user_id,)).fetchone()
        if row is None:
            return False, "User not found"
        conn = get_db()
        conn.execute(
            'UPDATE users SET mfa_enabled=1, mfa_secret=?, mfa_recovery_code=? WHERE id=?',
            (secret, generate_password_hash(recovery_code), user_id)
        )
        conn.commit()
        return True, "MFA enabled successfully"

    def disable_mfa(self, user_id):
        """Disable MFA for user."""
        row = get_db().execute('SELECT id FROM users WHERE id=?', (user_id,)).fetchone()
        if row is None:
            return False, "User not found"
        conn = get_db()
        conn.execute(
            'UPDATE users SET mfa_enabled=0, mfa_secret=NULL, mfa_recovery_code=NULL WHERE id=?',
            (user_id,)
        )
        conn.commit()
        return True, "MFA disabled successfully"

    def verify_recovery_code(self, user_id, recovery_code):
        """Verify and consume recovery code (one-time use)."""
        row = get_db().execute(
            'SELECT mfa_recovery_code FROM users WHERE id=?', (user_id,)
        ).fetchone()
        if row is None or not row['mfa_recovery_code']:
            return False
        if check_password_hash(row['mfa_recovery_code'], recovery_code):
            self.disable_mfa(user_id)
            return True
        return False

    def user_has_permission(self, user, permission):
        """Check if a user dict has a specific permission via their group."""
        gid = user.get('groupId') if isinstance(user, dict) else None
        return group_manager.has_permission(gid, permission)

    def get_user_permissions(self, user):
        """Return the full resolved permission list for a user."""
        gid = user.get('groupId') if isinstance(user, dict) else None
        if not gid:
            return []
        return group_manager.get_permissions_for_group(gid)


# Initialize database (creates tables if not present — safe on every boot)
init_db()
group_manager.prune_stale_permissions()

# Initialize managers (settings_manager must be first as UserManager uses it)
settings_manager = SettingsManager()
user_manager = UserManager()
stats_manager = StatsManager()
email_service = EmailService(settings_manager)
webhook_service = WebhookService(settings_manager)


def dispatch_notification(event_type, context):
    """Fan out a notification event: send email to subscribed users and fire webhook.

    This function is safe to call from background threads.  All network I/O is
    caught internally so a delivery failure never propagates to the caller.
    """
    # Map camelCase pref key → event_type string
    _PREF_MAP = {
        'backup_complete': 'backupComplete',
        'backup_failure': 'backupFailure',
        'server_start':   'serverStart',
        'server_stop':    'serverStop',
        'player_join':    'playerJoin',
        'player_leave':   'playerLeave',
        'critical_alert': 'criticalAlerts',
    }
    pref_key = _PREF_MAP.get(event_type)
    if pref_key:
        recipients = user_manager.get_notification_recipients(pref_key)
        if recipients:
            try:
                email_service.send_event_notification(event_type, context, recipients)
            except Exception as e:
                app.logger.error(f'[Notify] Email dispatch error for {event_type}: {e}')
    # Always attempt webhook (service checks its own enabled flag)
    try:
        webhook_service.dispatch(event_type, {
            'event': event_type,
            'timestamp': datetime.now().isoformat(),
            **context
        })
    except Exception as e:
        app.logger.error(f'[Notify] Webhook dispatch error for {event_type}: {e}')

    # Fire event-triggered server messages
    server_id = context.get('serverId')
    if server_id and event_type in MessageScheduler.EVENT_TRIGGERS:
        try:
            message_scheduler.fire_event(server_id, event_type)
        except Exception as e:
            app.logger.error(f'[Notify] Message event dispatch error for {event_type}: {e}')


# ==================== Notification Manager ====================

class NotificationManager:
    """In-app notification system for admin alerts and user feedback."""

    def create(self, user_id, ntype, title, message='', link=None,
               ref_type=None, ref_id=None):
        nid = str(uuid.uuid4())
        conn = get_db()
        conn.execute(
            '''INSERT INTO notifications
               (id, user_id, type, title, message, link, ref_type, ref_id, created)
               VALUES (?,?,?,?,?,?,?,?,?)''',
            (nid, user_id, ntype, title, message, link, ref_type, ref_id,
             datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
        note = self._row_to_dict(conn.execute(
            'SELECT * FROM notifications WHERE id=?', (nid,)).fetchone())
        try:
            socketio.emit('notification:new', {'notification': note},
                          to=f'user_{user_id}')
        except Exception:
            pass
        return note

    def notify_admins(self, ntype, title, message='', link=None,
                      ref_type=None, ref_id=None):
        conn = get_db()
        admin_gids = [g['id'] for g in group_manager.get_all_groups()
                      if '*' in g.get('permissions', [])
                      or 'panel.approvals.manage' in g.get('permissions', [])]
        if not admin_gids:
            return []
        placeholders = ','.join(['?'] * len(admin_gids))
        admins = conn.execute(
            f"SELECT id FROM users WHERE group_id IN ({placeholders})",
            admin_gids).fetchall()
        notes = []
        for row in admins:
            notes.append(self.create(row['id'], ntype, title, message,
                                     link, ref_type, ref_id))
        return notes

    def get_for_user(self, user_id, include_dismissed=False, limit=50):
        conn = get_db()
        if include_dismissed:
            rows = conn.execute(
                '''SELECT * FROM notifications WHERE user_id=?
                   ORDER BY created DESC LIMIT ?''',
                (user_id, limit)).fetchall()
        else:
            rows = conn.execute(
                '''SELECT * FROM notifications WHERE user_id=? AND dismissed=0
                   ORDER BY created DESC LIMIT ?''',
                (user_id, limit)).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def unread_count(self, user_id):
        conn = get_db()
        row = conn.execute(
            '''SELECT COUNT(*) AS cnt FROM notifications
               WHERE user_id=? AND read=0 AND dismissed=0''',
            (user_id,)).fetchone()
        return row['cnt'] if row else 0

    def mark_read(self, notification_id, user_id):
        conn = get_db()
        conn.execute(
            'UPDATE notifications SET read=1 WHERE id=? AND user_id=?',
            (notification_id, user_id))
        conn.commit()

    def dismiss(self, notification_id, user_id):
        conn = get_db()
        conn.execute(
            'UPDATE notifications SET dismissed=1, read=1 WHERE id=? AND user_id=?',
            (notification_id, user_id))
        conn.commit()

    def mark_all_read(self, user_id):
        conn = get_db()
        conn.execute(
            'UPDATE notifications SET read=1 WHERE user_id=? AND read=0',
            (user_id,))
        conn.commit()

    def dismiss_all(self, user_id):
        conn = get_db()
        conn.execute(
            'UPDATE notifications SET dismissed=1, read=1 WHERE user_id=? AND dismissed=0',
            (user_id,))
        conn.commit()

    def dismiss_by_ref(self, ref_type, ref_id):
        conn = get_db()
        conn.execute(
            'UPDATE notifications SET dismissed=1, read=1 WHERE ref_type=? AND ref_id=?',
            (ref_type, ref_id))
        conn.commit()

    @staticmethod
    def _row_to_dict(row):
        if not row:
            return None
        return {
            'id': row['id'], 'userId': row['user_id'], 'type': row['type'],
            'title': row['title'], 'message': row['message'],
            'link': row['link'], 'refType': row['ref_type'],
            'refId': row['ref_id'], 'read': bool(row['read']),
            'dismissed': bool(row['dismissed']), 'created': row['created'],
        }

notification_manager = NotificationManager()


# ==================== Pending Action Manager ====================

POLICY_ACTION_LABELS = {
    'registration':       'User Registration',
    'serverCreate':       'Server Creation',
    'serverDelete':       'Server Deletion',
    'serverEdit':         'Server Edit',
    'serverLifecycle':    'Server Start/Stop/Restart',
    'backupCreate':       'Backup Creation',
    'backupDelete':       'Backup Deletion',
    'fileUpload':         'File Upload',
    'modManagement':      'Mod Management',
    'playerManagement':   'Player Management',
}

class PendingActionManager:
    """Manages actions that require admin approval before execution."""

    def create(self, action_type, user_id, payload, target_id=None):
        action_id = str(uuid.uuid4())
        conn = get_db()
        conn.execute(
            '''INSERT INTO pending_actions
               (id, action_type, target_id, user_id, payload, created)
               VALUES (?,?,?,?,?,?)''',
            (action_id, action_type, target_id, user_id,
             json.dumps(payload), datetime.now(timezone.utc).isoformat())
        )
        conn.commit()

        user = user_manager.get_user_by_id(user_id)
        username = user.get('username', 'Unknown') if user else 'Unknown'
        label = POLICY_ACTION_LABELS.get(action_type, action_type)
        notification_manager.notify_admins(
            'approval_request',
            f'{label} — approval needed',
            f'{username} has requested: {label}',
            link='/settings#approvals',
            ref_type='pending_action', ref_id=action_id
        )
        return action_id

    def get_pending(self):
        conn = get_db()
        rows = conn.execute(
            '''SELECT * FROM pending_actions WHERE status='pending'
               ORDER BY created DESC''').fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_all(self, limit=100):
        conn = get_db()
        rows = conn.execute(
            'SELECT * FROM pending_actions ORDER BY created DESC LIMIT ?',
            (limit,)).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_by_id(self, action_id):
        conn = get_db()
        row = conn.execute(
            'SELECT * FROM pending_actions WHERE id=?', (action_id,)).fetchone()
        return self._row_to_dict(row)

    def get_pending_for_user(self, user_id):
        conn = get_db()
        rows = conn.execute(
            '''SELECT * FROM pending_actions
               WHERE user_id=? AND status='pending' ORDER BY created DESC''',
            (user_id,)).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def approve(self, action_id, admin_id, note=None):
        conn = get_db()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            '''UPDATE pending_actions
               SET status='approved', reviewed_by=?, review_note=?, reviewed=?
               WHERE id=? AND status='pending' ''',
            (admin_id, note, now, action_id))
        conn.commit()

        action = self.get_by_id(action_id)
        if not action:
            return None

        label = POLICY_ACTION_LABELS.get(action['actionType'], action['actionType'])
        notification_manager.create(
            action['userId'], 'action_approved',
            f'{label} approved',
            f'Your request for {label} has been approved.',
            ref_type='pending_action', ref_id=action_id)
        notification_manager.dismiss_by_ref('pending_action', action_id)
        return action

    def reject(self, action_id, admin_id, note=None):
        conn = get_db()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            '''UPDATE pending_actions
               SET status='rejected', reviewed_by=?, review_note=?, reviewed=?
               WHERE id=? AND status='pending' ''',
            (admin_id, note, now, action_id))
        conn.commit()

        action = self.get_by_id(action_id)
        if not action:
            return None

        label = POLICY_ACTION_LABELS.get(action['actionType'], action['actionType'])
        msg = f'Your request for {label} has been rejected.'
        if note:
            msg += f' Reason: {note}'
        notification_manager.create(
            action['userId'], 'action_rejected',
            f'{label} rejected', msg,
            ref_type='pending_action', ref_id=action_id)
        notification_manager.dismiss_by_ref('pending_action', action_id)
        return action

    @staticmethod
    def _row_to_dict(row):
        if not row:
            return None
        return {
            'id': row['id'], 'actionType': row['action_type'],
            'targetId': row['target_id'], 'userId': row['user_id'],
            'payload': json.loads(row['payload'] or '{}'),
            'status': row['status'], 'reviewedBy': row['reviewed_by'],
            'reviewNote': row['review_note'], 'created': row['created'],
            'reviewed': row['reviewed'],
        }

pending_action_manager = PendingActionManager()


# ==================== Policy Check Helper ====================

def check_action_policy(action_type, user, payload, target_id=None,
                        execute_fn=None, description=None):
    """
    Enforce the action policy for non-admin users.
    Returns (result_dict, http_status_code).
    - 'allow': execute_fn() runs immediately.
    - 'notify': execute_fn() runs, admins are notified.
    - 'require_approval': action is queued; admins are notified.
    """
    is_admin = group_manager.is_admin_group(user.get('groupId'))
    policy = settings_manager.get_policy(action_type)

    if is_admin or policy == 'allow':
        if execute_fn:
            return execute_fn()
        return {'allowed': True}, 200

    user_id = user.get('id') or session.get('user_id')
    label = POLICY_ACTION_LABELS.get(action_type, action_type)
    username = user.get('username', 'Unknown')

    if policy == 'notify':
        notification_manager.notify_admins(
            'action_notify',
            f'{label} — {username}',
            description or f'{username} performed: {label}',
            ref_type='server' if target_id else None,
            ref_id=target_id)
        if execute_fn:
            return execute_fn()
        return {'allowed': True}, 200

    # require_approval
    pending_id = pending_action_manager.create(
        action_type, user_id, payload, target_id=target_id)
    return {
        'pending': True,
        'pendingId': pending_id,
        'message': f'Your request for {label} has been submitted and is awaiting admin approval.'
    }, 202


# ==================== Authentication Decorators ====================

def get_current_user():
    """Get the currently logged in user from session"""
    user_id = session.get('user_id')
    if user_id:
        user = user_manager.get_user(user_id)
        if user and user.get('approved', False):
            return user_id, user
    return None, None

def login_required(f):
    """Decorator to require login for a route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id, user = get_current_user()
        if not user:
            return api_error('Authentication required', 401, code='AUTH_REQUIRED')
        return f(*args, **kwargs)
    return decorated_function

def permission_required(*permissions):
    """Decorator requiring the current user to have ALL listed permissions."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id, user = get_current_user()
            if not user:
                return api_error('Authentication required', 401, code='AUTH_REQUIRED')
            for perm in permissions:
                if not user_manager.user_has_permission(user, perm):
                    return api_error('Insufficient permissions', 403, code='FORBIDDEN')
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    """Decorator: user must be in a group with the wildcard permission."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id, user = get_current_user()
        if not user:
            return api_error('Authentication required', 401, code='AUTH_REQUIRED')
        if not group_manager.is_admin_group(user.get('groupId')):
            return api_error('Insufficient permissions', 403, code='FORBIDDEN')
        return f(*args, **kwargs)
    return decorated_function

def can_access_server(server_id):
    """Check if current user can access a specific server"""
    user_id, user = get_current_user()
    if not user:
        return False
    if user_manager.user_has_permission(user, 'servers.access.all'):
        return True
    server_config = server_manager.get_server_config(server_id)
    if server_config and server_config.get('owner') == user_id:
        return True
    user_group_id = user.get('groupId')
    if user_group_id:
        shared_ids = group_manager.get_server_group_ids(server_id)
        if user_group_id in shared_ids:
            return True
    return False

def server_access_required(f):
    """Decorator to require access to a specific server"""
    @wraps(f)
    def decorated_function(server_id, *args, **kwargs):
        user_id, user = get_current_user()
        if not user:
            return api_error('Authentication required', 401, code='AUTH_REQUIRED')
        if not can_access_server(server_id):
            return api_error('Access denied to this server', 403, code='FORBIDDEN')
        return f(server_id, *args, **kwargs)
    return decorated_function


# ==================== JAR/Version Manager ====================

class JarVersionManager:
    """Manager for Minecraft server JAR files and versions"""
    
    # Server executables directory
    EXECUTABLES_DIR = BASE_DIR / 'serverexecutables'
    
    def __init__(self):
        self.jar_urls = self._load_jar_urls()
    
    def _load_jar_urls(self):
        """Load JAR URLs from config file"""
        urls = {}
        if JAR_URLS_PATH.exists():
            with open(JAR_URLS_PATH, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '=' in line:
                        key, url = line.split('=', 1)
                        if ':' in key:
                            server_type, version = key.split(':', 1)
                            if server_type not in urls:
                                urls[server_type] = {}
                            urls[server_type][version] = url
        return urls
    
    def _scan_local_jars(self):
        """
        Scan serverexecutables directory for available JAR files.
        Returns dict: {server_type: [{version, filename, path, size}]}
        """
        local_jars = {}
        
        if not self.EXECUTABLES_DIR.exists():
            return local_jars
        
        for type_dir in self.EXECUTABLES_DIR.iterdir():
            if not type_dir.is_dir():
                continue
            
            server_type = type_dir.name.lower()
            local_jars[server_type] = []
            
            for jar_file in type_dir.iterdir():
                if not jar_file.is_file():
                    continue
                if jar_file.suffix not in ['.jar', '.zip']:
                    continue
                if jar_file.name.startswith('.'):
                    continue
                
                # Parse version from filename
                version = self._extract_version(jar_file.name, server_type)
                if version:
                    local_jars[server_type].append({
                        'version': version,
                        'filename': jar_file.name,
                        'path': str(jar_file),
                        'size': jar_file.stat().st_size
                    })
        
        return local_jars
    
    def _extract_version(self, filename, server_type):
        """
        Extract version from JAR filename.
        Handles patterns like:
          - vanilla-1.21.4.jar -> 1.21.4
          - paper-1.21.4-232.jar -> 1.21.4 (build 232)
          - forge-1.21.3-53.0.26-installer.jar -> 1.21.3-53.0.26
          - neoforge-21.4.156-installer.jar -> 21.4.156
        """
        import re
        
        # Remove extension
        name = filename.replace('.jar', '').replace('.zip', '')
        
        # Remove -installer suffix
        name = name.replace('-installer', '')
        
        # Pattern for different server types
        patterns = {
            'vanilla': r'vanilla-([\d.]+)',
            'paper': r'paper-([\d.]+)(?:-\d+)?',
            'folia': r'folia-([\d.]+)(?:-\d+)?',
            'purpur': r'purpur-([\d.]+)(?:-\d+)?',
            'forge': r'forge-([\d.]+-[\d.]+)',
            'neoforge': r'neoforge-([\d.]+(?:-beta)?)',
        }
        
        # Try specific pattern first
        if server_type in patterns:
            match = re.search(patterns[server_type], name, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Generic fallback: type-VERSION or just VERSION
        generic = re.search(rf'{server_type}-([\d.-]+)', name, re.IGNORECASE)
        if generic:
            return generic.group(1)
        
        # Very generic: just find version-like string
        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?(?:-[\d.]+)?)', name)
        if version_match:
            return version_match.group(1)
        
        return None
    
    def get_local_jar_info(self, server_type, version):
        """
        Get info about a specific local JAR file.
        Returns: {filename, path, size} or None if not found
        """
        local_jars = self._scan_local_jars()
        
        if server_type not in local_jars:
            return None
        
        for jar in local_jars[server_type]:
            if jar['version'] == version:
                return jar
        
        return None
    
    def copy_jar_to_server(self, server_type, version, dest_path):
        """
        Copy a local JAR file to the server directory.
        Returns: (success: bool, message: str)
        """
        jar_info = self.get_local_jar_info(server_type, version)
        
        if not jar_info:
            return False, f'JAR file not found for {server_type} version {version}'
        
        source_path = Path(jar_info['path'])
        dest_path = Path(dest_path)
        
        if not source_path.exists():
            return False, f'Source JAR file not found: {source_path}'
        
        try:
            # Ensure destination directory exists
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Copy the JAR file
            shutil.copy2(source_path, dest_path)
            
            return True, str(dest_path)
        except Exception as e:
            return False, f'Failed to copy JAR: {str(e)}'


# Initialize JAR manager
jar_manager = JarVersionManager()


# ==================== NBT Parser/Editor ====================

class NBTEditor:
    """
    Pure Python NBT (Named Binary Tag) parser and editor for Minecraft .dat files.
    Supports both compressed (gzip) and uncompressed NBT files.
    """
    
    # Tag type constants
    TAG_END = 0
    TAG_BYTE = 1
    TAG_SHORT = 2
    TAG_INT = 3
    TAG_LONG = 4
    TAG_FLOAT = 5
    TAG_DOUBLE = 6
    TAG_BYTE_ARRAY = 7
    TAG_STRING = 8
    TAG_LIST = 9
    TAG_COMPOUND = 10
    TAG_INT_ARRAY = 11
    TAG_LONG_ARRAY = 12
    
    TAG_NAMES = {
        0: 'End', 1: 'Byte', 2: 'Short', 3: 'Int', 4: 'Long',
        5: 'Float', 6: 'Double', 7: 'ByteArray', 8: 'String',
        9: 'List', 10: 'Compound', 11: 'IntArray', 12: 'LongArray'
    }
    
    def __init__(self):
        self.compression = None  # 'gzip' or None
    
    def read_file(self, filepath):
        """Read and parse an NBT file, returns tree structure"""
        filepath = Path(filepath)
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # Try gzip first
        try:
            decompressed = gzip.decompress(data)
            self.compression = 'gzip'
            data = decompressed
        except:
            self.compression = None
        
        reader = io.BytesIO(data)
        return self._read_named_tag(reader)
    
    def write_file(self, filepath, nbt_data):
        """Write NBT data back to file"""
        filepath = Path(filepath)
        
        writer = io.BytesIO()
        self._write_named_tag(writer, nbt_data)
        
        data = writer.getvalue()
        
        if self.compression == 'gzip':
            data = gzip.compress(data)
        
        with open(filepath, 'wb') as f:
            f.write(data)
    
    def _read_named_tag(self, reader):
        """Read a named tag from the stream"""
        tag_type = struct.unpack('>B', reader.read(1))[0]
        
        if tag_type == self.TAG_END:
            return None
        
        name_length = struct.unpack('>H', reader.read(2))[0]
        name = reader.read(name_length).decode('utf-8')
        
        value = self._read_tag_payload(reader, tag_type)
        
        return {
            'type': tag_type,
            'typeName': self.TAG_NAMES.get(tag_type, 'Unknown'),
            'name': name,
            'value': value
        }
    
    def _read_tag_payload(self, reader, tag_type):
        """Read tag payload based on type"""
        if tag_type == self.TAG_BYTE:
            return struct.unpack('>b', reader.read(1))[0]
        
        elif tag_type == self.TAG_SHORT:
            return struct.unpack('>h', reader.read(2))[0]
        
        elif tag_type == self.TAG_INT:
            return struct.unpack('>i', reader.read(4))[0]
        
        elif tag_type == self.TAG_LONG:
            return struct.unpack('>q', reader.read(8))[0]
        
        elif tag_type == self.TAG_FLOAT:
            return struct.unpack('>f', reader.read(4))[0]
        
        elif tag_type == self.TAG_DOUBLE:
            return struct.unpack('>d', reader.read(8))[0]
        
        elif tag_type == self.TAG_BYTE_ARRAY:
            length = struct.unpack('>i', reader.read(4))[0]
            return list(struct.unpack(f'>{length}b', reader.read(length)))
        
        elif tag_type == self.TAG_STRING:
            length = struct.unpack('>H', reader.read(2))[0]
            return reader.read(length).decode('utf-8')
        
        elif tag_type == self.TAG_LIST:
            list_type = struct.unpack('>B', reader.read(1))[0]
            length = struct.unpack('>i', reader.read(4))[0]
            items = []
            for _ in range(length):
                items.append({
                    'type': list_type,
                    'typeName': self.TAG_NAMES.get(list_type, 'Unknown'),
                    'value': self._read_tag_payload(reader, list_type)
                })
            return {'listType': list_type, 'items': items}
        
        elif tag_type == self.TAG_COMPOUND:
            children = []
            while True:
                child = self._read_named_tag(reader)
                if child is None:
                    break
                children.append(child)
            return children
        
        elif tag_type == self.TAG_INT_ARRAY:
            length = struct.unpack('>i', reader.read(4))[0]
            return list(struct.unpack(f'>{length}i', reader.read(length * 4)))
        
        elif tag_type == self.TAG_LONG_ARRAY:
            length = struct.unpack('>i', reader.read(4))[0]
            return list(struct.unpack(f'>{length}q', reader.read(length * 8)))
        
        return None
    
    def _write_named_tag(self, writer, tag):
        """Write a named tag to the stream"""
        tag_type = tag['type']
        name = tag['name']
        
        writer.write(struct.pack('>B', tag_type))
        name_bytes = name.encode('utf-8')
        writer.write(struct.pack('>H', len(name_bytes)))
        writer.write(name_bytes)
        
        self._write_tag_payload(writer, tag_type, tag['value'])
    
    def _write_tag_payload(self, writer, tag_type, value):
        """Write tag payload based on type"""
        if tag_type == self.TAG_BYTE:
            writer.write(struct.pack('>b', int(value)))
        
        elif tag_type == self.TAG_SHORT:
            writer.write(struct.pack('>h', int(value)))
        
        elif tag_type == self.TAG_INT:
            writer.write(struct.pack('>i', int(value)))
        
        elif tag_type == self.TAG_LONG:
            writer.write(struct.pack('>q', int(value)))
        
        elif tag_type == self.TAG_FLOAT:
            writer.write(struct.pack('>f', float(value)))
        
        elif tag_type == self.TAG_DOUBLE:
            writer.write(struct.pack('>d', float(value)))
        
        elif tag_type == self.TAG_BYTE_ARRAY:
            writer.write(struct.pack('>i', len(value)))
            writer.write(struct.pack(f'>{len(value)}b', *value))
        
        elif tag_type == self.TAG_STRING:
            value_bytes = value.encode('utf-8')
            writer.write(struct.pack('>H', len(value_bytes)))
            writer.write(value_bytes)
        
        elif tag_type == self.TAG_LIST:
            list_type = value['listType']
            items = value['items']
            writer.write(struct.pack('>B', list_type))
            writer.write(struct.pack('>i', len(items)))
            for item in items:
                self._write_tag_payload(writer, list_type, item['value'])
        
        elif tag_type == self.TAG_COMPOUND:
            for child in value:
                self._write_named_tag(writer, child)
            writer.write(struct.pack('>B', self.TAG_END))
        
        elif tag_type == self.TAG_INT_ARRAY:
            writer.write(struct.pack('>i', len(value)))
            writer.write(struct.pack(f'>{len(value)}i', *value))
        
        elif tag_type == self.TAG_LONG_ARRAY:
            writer.write(struct.pack('>i', len(value)))
            writer.write(struct.pack(f'>{len(value)}q', *value))
    
    def to_dict(self, nbt_data):
        """Convert NBT tree structure to a simple Python dict"""
        def convert(tag):
            tag_type = tag['type']
            value = tag['value']
            if tag_type == self.TAG_COMPOUND:
                result = {}
                for child in value:
                    result[child['name']] = convert(child)
                return result
            elif tag_type == self.TAG_LIST:
                return [convert(item) for item in value['items']]
            else:
                return value
        return convert(nbt_data)
    
    def update_value(self, nbt_data, path, new_value):
        """
        Update a value at a specific path in the NBT tree.
        Path is a list of keys/indices like ['Data', 'Player', 'Pos', 0]
        """
        if not path:
            return nbt_data
        
        current = nbt_data
        for i, key in enumerate(path[:-1]):
            if current['type'] == self.TAG_COMPOUND:
                for child in current['value']:
                    if child['name'] == key:
                        current = child
                        break
            elif current['type'] == self.TAG_LIST:
                current = current['value']['items'][int(key)]
        
        # Set the final value
        final_key = path[-1]
        if current['type'] == self.TAG_COMPOUND:
            for child in current['value']:
                if child['name'] == final_key:
                    child['value'] = new_value
                    break
        elif current['type'] == self.TAG_LIST:
            current['value']['items'][int(final_key)]['value'] = new_value
        else:
            current['value'] = new_value
        
        return nbt_data
    
    def add_tag(self, nbt_data, parent_path, new_tag):
        """Add a new tag to a compound or list"""
        current = nbt_data
        for key in parent_path:
            if current['type'] == self.TAG_COMPOUND:
                for child in current['value']:
                    if child['name'] == key:
                        current = child
                        break
            elif current['type'] == self.TAG_LIST:
                current = current['value']['items'][int(key)]
        
        if current['type'] == self.TAG_COMPOUND:
            current['value'].append(new_tag)
        elif current['type'] == self.TAG_LIST:
            current['value']['items'].append(new_tag)
        
        return nbt_data
    
    def delete_tag(self, nbt_data, path):
        """Delete a tag at the specified path"""
        if not path:
            return nbt_data
        
        current = nbt_data
        for key in path[:-1]:
            if current['type'] == self.TAG_COMPOUND:
                for child in current['value']:
                    if child['name'] == key:
                        current = child
                        break
            elif current['type'] == self.TAG_LIST:
                current = current['value']['items'][int(key)]
        
        final_key = path[-1]
        if current['type'] == self.TAG_COMPOUND:
            current['value'] = [c for c in current['value'] if c['name'] != final_key]
        elif current['type'] == self.TAG_LIST:
            del current['value']['items'][int(final_key)]
        
        return nbt_data


# Initialize NBT editor
nbt_editor = NBTEditor()


# ==================== Server Status Enum ====================

class ServerStatus(Enum):
    """Server status states"""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    UNRESPONSIVE = "unresponsive"


# ==================== Server Manager ====================

# Console commands that grant/revoke in-game operator status. Blocked at the
# console (HTTP, SocketIO, and public API all funnel through
# ServerManager.send_command) because they let any caller with console access
# bypass the panel's own permission model entirely — e.g. a public API key
# scoped to CONSOLE only (not WRITE/ADMIN) has no dedicated op-management
# endpoint, but could otherwise 'op' a player and gain full in-game control.
# The Operators tab (add_operator route) is the supported way to do this,
# gated at the same @server_access_required level with proper auditing.
BLOCKED_CONSOLE_COMMANDS = re.compile(r'^\s*/?\s*(op|deop)\b', re.IGNORECASE)


class ServerManager:
    """Manages multiple Minecraft server instances — backed by SQLite."""

    def __init__(self):
        self.servers = {}  # server_id -> ServerInstance (in-memory runtime state only)
        self.lock = threading.Lock()
        # Serializes port-conflict-check + commit so two concurrent requests can't
        # both pass the "port is free" check and write the same port to two servers.
        self.port_lock = threading.Lock()

    # ── Internal row → dict helper ────────────────────────────────────────────

    @staticmethod
    def _row_to_config(row):
        """Convert a sqlite3.Row from the servers table to a config dict."""
        if row is None:
            return None
        return {
            'name':       row['name'],
            'serverPath': row['server_path'],
            'executable': row['executable'],
            'javaArgs':   row['java_args'],
            'serverType': row['server_type'],
            'version':    row['version'],
            'owner':      row['owner'],
            'autoStart':  bool(row['auto_start']),
            'approved':   bool(row['approved']),
            'category':   row['category'],
            'created':    row['created'],
        }

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def get_server_config(self, server_id):
        """Get configuration dict for a specific server."""
        row = get_db().execute('SELECT * FROM servers WHERE id=?', (server_id,)).fetchone()
        return self._row_to_config(row)

    def get_all_server_ids(self):
        """Return a list of all server IDs (approved and pending)."""
        rows = get_db().execute('SELECT id FROM servers').fetchall()
        return [r['id'] for r in rows]

    def get_servers_list(self, include_pending=False):
        """Get list of all configured servers with their runtime status."""
        if include_pending:
            rows = get_db().execute('SELECT * FROM servers ORDER BY created').fetchall()
        else:
            rows = get_db().execute(
                'SELECT * FROM servers WHERE approved=1 ORDER BY created'
            ).fetchall()

        servers = []
        for row in rows:
            server_id = row['id']
            server_config = self._row_to_config(row)

            instance = self.servers.get(server_id)
            is_running = instance is not None and instance.is_running()
            status = instance.get_status().value if instance else ServerStatus.STOPPED.value

            port = self.get_server_port(server_id)

            server_dir = Path(server_config.get('serverPath', ''))
            managed = self._read_managed_conf(server_dir) if server_dir.exists() else {}

            engine_from_conf = managed.get('Engine') or server_config.get('serverType')
            version_from_conf = managed.get('Version') or server_config.get('version')
            if engine_from_conf and engine_from_conf.lower() == 'imported':
                engine_from_conf = managed.get('Engine') or None

            servers.append({
                'id':         server_id,
                'name':       server_config.get('name', 'Unnamed Server'),
                'serverPath': server_config.get('serverPath', ''),
                'executable': server_config.get('executable', 'server.jar'),
                'javaArgs':   server_config.get('javaArgs', DEFAULT_JAVA_ARGS),
                'autoStart':  server_config.get('autoStart', False),
                'serverType': engine_from_conf,
                'version':    version_from_conf,
                'owner':      server_config.get('owner'),
                'created':    server_config.get('created'),
                'approved':   server_config.get('approved', True),
                'running':    is_running,
                'status':     status,
                'port':       port,
                'category':   server_config.get('category', 'unmodded'),
            })
        return servers

    def get_pending_servers(self):
        """Get list of servers pending approval."""
        rows = get_db().execute(
            'SELECT * FROM servers WHERE approved=0 ORDER BY created'
        ).fetchall()
        return [
            {
                'id':      r['id'],
                'name':    r['name'],
                'type':    r['server_type'],
                'owner':   r['owner'],
                'created': r['created'],
            }
            for r in rows
        ]

    def approve_server(self, server_id):
        """Approve a pending server."""
        conn = get_db()
        result = conn.execute('UPDATE servers SET approved=1 WHERE id=?', (server_id,))
        conn.commit()
        return result.rowcount > 0

    def reject_server(self, server_id):
        """Reject (delete) a pending server."""
        return self.delete_server(server_id)

    def create_server(self, name, server_path='', executable='server.jar',
                      java_args=DEFAULT_JAVA_ARGS, server_type=None, version=None,
                      owner=None, approved=True, category='unmodded', port=None):
        """Create a new server configuration."""
        server_id = str(uuid.uuid4())[:8]

        server_dir = Path(server_path) if server_path else SERVERS_DIR / server_id
        server_dir.mkdir(parents=True, exist_ok=True)

        is_bedrock = category == 'bedrock'
        is_modded = category == 'modded'
        engine_name = 'Vanilla'
        if is_bedrock:
            engine_name = 'Bedrock'
        elif is_modded and server_type:
            engine_name = server_type.title()

        self._create_managed_conf(server_dir, server_id, name, engine=engine_name,
                                  owner=owner, version=version, port=port)
        self._ensure_canned_commands_conf(server_dir)

        conn = get_db()
        conn.execute(
            '''INSERT INTO servers
               (id, name, server_path, executable, java_args, server_type, version,
                owner, auto_start, approved, category, created)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)''',
            (server_id, name, str(server_dir), executable, java_args,
             server_type, version, owner, 1 if approved else 0,
             category, datetime.now().isoformat())
        )
        conn.commit()
        return server_id

    def update_server(self, server_id, **kwargs):
        """Update server configuration fields."""
        row = get_db().execute('SELECT * FROM servers WHERE id=?', (server_id,)).fetchone()
        if row is None:
            return False

        category = kwargs.get('category', row['category'])
        kwargs['executable'] = 'server.sh' if category == 'bedrock' else 'server.jar'

        # Build dynamic SET clause for provided kwargs
        col_map = {
            'name': 'name', 'serverPath': 'server_path', 'executable': 'executable',
            'javaArgs': 'java_args', 'serverType': 'server_type', 'version': 'version',
            'owner': 'owner', 'autoStart': 'auto_start', 'approved': 'approved',
            'category': 'category',
        }
        sets, values = [], []
        for k, v in kwargs.items():
            col = col_map.get(k)
            if col:
                sets.append(f'{col}=?')
                values.append(1 if v is True else (0 if v is False else v))
        if not sets:
            return True
        values.append(server_id)
        conn = get_db()
        conn.execute(f'UPDATE servers SET {", ".join(sets)} WHERE id=?', values)
        conn.commit()

        server_config = self.get_server_config(server_id)
        server_dir = Path(server_config.get('serverPath', ''))
        managed_conf_path = server_dir / 'managed.conf'
        if managed_conf_path.exists():
            managed_config = self._read_managed_conf(server_dir)
            if 'category' in kwargs:
                managed_config.pop('Modded', None)
            if 'autoStart' in kwargs:
                managed_config['AutoStart'] = 'true' if kwargs['autoStart'] else 'false'
            self._write_managed_conf(server_dir, managed_config)
        return True

    def delete_server(self, server_id, delete_files=False):
        """Delete a server configuration (and optionally its files)."""
        if server_id in self.servers:
            self.stop_server(server_id)

        row = get_db().execute(
            'SELECT server_path FROM servers WHERE id=?', (server_id,)
        ).fetchone()
        if row is None:
            return False

        server_path = Path(row['server_path'])
        if delete_files:
            if server_path.exists():
                try:
                    shutil.rmtree(server_path)
                except Exception as e:
                    print(f"Error deleting server files: {e}")
        else:
            managed_conf = server_path / 'managed.conf'
            if managed_conf.exists():
                try:
                    managed_conf.unlink()
                except Exception as e:
                    print(f"Error removing managed.conf: {e}")

        conn = get_db()
        conn.execute('DELETE FROM servers WHERE id=?', (server_id,))
        conn.commit()
        return True
    
    # Required fields for managed.conf
    MANAGED_CONF_REQUIRED_FIELDS = [
        'ManagedBy',
        'ServerId',
        'ServerName',
        'Engine',
        'Version',
        'Port',
        'Owner',
        'AutoStart',
        'CreatedAt',
        'EULAAccepted',
    ]
    
    def _create_managed_conf(self, server_dir, server_id, name, engine=None, owner=None, version=None, port=None, auto_start=False):
        """Create or update the managed.conf file for a server"""
        managed_conf_path = Path(server_dir) / 'managed.conf'
        
        # Determine engine based on category
        if engine is None:
            engine = 'Vanilla'
        
        # Version is now required - default to 'Unknown' if not provided
        if not version:
            version = 'Unknown'
        
        # Port defaults to 25565 if not provided
        if not port:
            port = '25565'
        
        config = {
            'ManagedBy': 'MServer',
            'ServerId': server_id,
            'ServerName': name,
            'Engine': engine,
            'Version': version,
            'Port': str(port),
            'Owner': owner or 'admin',
            'AutoStart': 'true' if auto_start else 'false',
            'CreatedAt': datetime.now().isoformat(),
            'EULAAccepted': 'false',
            'LastStarted': '',
            'PublicVisible': 'true'
        }
        
        # If file exists, preserve existing settings
        if managed_conf_path.exists():
            existing = self._read_managed_conf(server_dir)
            config.update(existing)
            config['ServerId'] = server_id  # Always update these
            config['ServerName'] = name
            if engine:
                config['Engine'] = engine
            if owner:
                config['Owner'] = owner
            # Remove deprecated Modded field if present
            config.pop('Modded', None)
        
        self._write_managed_conf(server_dir, config)
    
    def _read_managed_conf(self, server_dir):
        """Read the managed.conf file"""
        managed_conf_path = Path(server_dir) / 'managed.conf'
        config = {}
        if managed_conf_path.exists():
            try:
                with open(managed_conf_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if '=' in line and not line.startswith('#'):
                            key, value = line.split('=', 1)
                            config[key.strip()] = value.strip()
            except Exception:
                pass
        return config
    
    def _write_managed_conf(self, server_dir, config):
        """Write the managed.conf file"""
        managed_conf_path = Path(server_dir) / 'managed.conf'
        try:
            with open(managed_conf_path, 'w') as f:
                f.write("# MServer Managed Server Configuration\n")
                f.write("# Do not edit this file manually unless you know what you're doing\n\n")
                for key, value in config.items():
                    f.write(f"{key}={value}\n")
        except Exception as e:
            print(f"Error writing managed.conf: {e}")
    
    def validate_managed_conf(self, server_id):
        """
        Validate that managed.conf has all required fields.
        Returns (is_valid, missing_fields) tuple.
        """
        server_config = self.get_server_config(server_id)
        if not server_config:
            return False, ['Server not found']
        
        server_dir = Path(server_config.get('serverPath', ''))
        managed_conf_path = server_dir / 'managed.conf'
        
        if not managed_conf_path.exists():
            return False, ['managed.conf file not found']
        
        config = self._read_managed_conf(server_dir)
        
        missing_fields = []
        for field in self.MANAGED_CONF_REQUIRED_FIELDS:
            if field not in config or not config[field]:
                missing_fields.append(field)
        
        return len(missing_fields) == 0, missing_fields
    
    def is_managed(self, server_id):
        """Check if a server has a managed.conf file"""
        server_config = self.get_server_config(server_id)
        if not server_config:
            return False
        
        server_dir = Path(server_config.get('serverPath', ''))
        managed_conf_path = server_dir / 'managed.conf'
        return managed_conf_path.exists()
    
    def enable_management(self, server_id):
        """Create managed.conf for an existing server that doesn't have one"""
        server_config = self.get_server_config(server_id)
        if not server_config:
            return False, "Server not found"
        
        server_dir = Path(server_config.get('serverPath', ''))
        if not server_dir.exists():
            return False, "Server directory not found"
        
        # Check if already managed
        managed_conf_path = server_dir / 'managed.conf'
        if managed_conf_path.exists():
            return True, "Server is already managed"
        
        # Create managed.conf
        name = server_config.get('name', 'Unknown Server')
        category = server_config.get('category', 'unmodded')
        is_modded = category == 'modded'
        is_bedrock = category == 'bedrock'
        server_type = server_config.get('serverType', '')
        owner = server_config.get('owner', 'admin')
        version = server_config.get('version', 'Unknown')  # Default to 'Unknown' if not set
        
        # Determine engine name
        engine_name = 'Vanilla'
        if is_bedrock:
            engine_name = 'Bedrock'
        elif is_modded and server_type:
            engine_name = server_type.title()
        
        # Get port from server.properties if available
        port = self.get_server_port(server_id)
        
        self._create_managed_conf(server_dir, server_id, name, engine=engine_name, owner=owner, version=version, port=port)
        
        return True, "Management enabled"
    
    @staticmethod
    def _eula_txt_accepted(server_dir):
        """True if the server's own eula.txt carries eula=true.

        This is what the JVM actually enforces, so it is the authority for a
        server the panel did not create — an imported one, or one whose operator
        edited eula.txt by hand — where managed.conf has no EULAAccepted at all."""
        eula_path = Path(server_dir) / 'eula.txt'
        try:
            for line in eula_path.read_text(errors='ignore').splitlines():
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, _, value = line.partition('=')
                if key.strip().lower() == 'eula':
                    return value.strip().lower() == 'true'
        except OSError:
            return False
        return False

    def check_eula_accepted(self, server_id):
        """Check if EULA has been accepted for a server"""
        server_config = self.get_server_config(server_id)
        if not server_config:
            return False

        server_dir = Path(server_config.get('serverPath', ''))
        managed_conf = self._read_managed_conf(server_dir)
        if managed_conf.get('EULAAccepted', 'false').lower() == 'true':
            return True
        return self._eula_txt_accepted(server_dir)

    def accept_eula(self, server_id):
        """Accept the EULA for a server"""
        server_config = self.get_server_config(server_id)
        if not server_config:
            return False, "Server not found"
        
        server_dir = Path(server_config.get('serverPath', ''))
        
        # Update managed.conf
        managed_conf = self._read_managed_conf(server_dir)
        managed_conf['EULAAccepted'] = 'true'
        managed_conf['EULAAcceptedAt'] = datetime.now().isoformat()
        self._write_managed_conf(server_dir, managed_conf)
        
        # Create/update eula.txt
        eula_path = server_dir / 'eula.txt'
        try:
            with open(eula_path, 'w') as f:
                f.write("# By setting this to TRUE, you agree to the Minecraft EULA\n")
                f.write("# https://aka.ms/MinecraftEULA\n")
                f.write("eula=true\n")
            return True, "EULA accepted"
        except Exception as e:
            return False, f"Failed to write eula.txt: {e}"
    
    def import_server_from_zip(self, name, zip_path, java_args=DEFAULT_JAVA_ARGS,
                               executable_name=None, owner=None, approved=True,
                               category='unmodded', port=None, engine=None):
        """Import a server from a ZIP file."""
        server_id = str(uuid.uuid4())[:8]
        server_dir = SERVERS_DIR / server_id

        try:
            server_dir.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(zip_path, 'r') as zipf:
                # Rejects path-traversal/absolute/symlink members and verifies
                # every member resolves inside server_dir before extracting.
                safe_extractall(zipf, server_dir)

            subdirs = [d for d in server_dir.iterdir() if d.is_dir()]
            if len(subdirs) == 1 and not any(server_dir.glob('*.jar')):
                subdir = subdirs[0]
                for item in subdir.iterdir():
                    shutil.move(str(item), str(server_dir / item.name))
                subdir.rmdir()

            found_jar = None
            if executable_name:
                target = server_dir / executable_name
                if target.exists() and target.suffix == '.jar':
                    found_jar = target

            if not found_jar:
                priority_names = ['server.jar', 'paper.jar', 'purpur.jar', 'folia.jar',
                                  'forge.jar', 'neoforge.jar']
                fallback = None
                for item in server_dir.iterdir():
                    if item.suffix == '.jar' and item.is_file():
                        if item.name in priority_names:
                            found_jar = item
                            break
                        elif ('server' in item.name.lower() or 'paper' in item.name.lower()) and not fallback:
                            fallback = item
                if not found_jar:
                    found_jar = fallback

            if found_jar and found_jar.name != 'server.jar':
                standard_jar = server_dir / 'server.jar'
                if standard_jar.exists():
                    standard_jar.unlink()
                found_jar.rename(standard_jar)

            executable = 'server.jar'

            managed_conf_path = server_dir / 'managed.conf'
            if managed_conf_path.exists():
                existing_conf = self._read_managed_conf(server_dir)
                existing_conf['ServerId'] = server_id
                if owner:
                    existing_conf['Owner'] = owner
                existing_conf.pop('Modded', None)
                existing_conf.setdefault('Port', port or '25565')
                existing_conf.setdefault('AutoStart', 'false')
                existing_conf.setdefault('LastStarted', '')
                self._write_managed_conf(server_dir, existing_conf)
                imported_name    = existing_conf.get('ServerName', name)
                imported_version = existing_conf.get('Version', 'Unknown')
            else:
                if not engine:
                    engine = 'Bedrock' if category == 'bedrock' else (
                             'Unknown' if category == 'modded' else 'Vanilla')
                self._create_managed_conf(server_dir, server_id, name,
                                          engine=engine, owner=owner, port=port)
                imported_name    = name
                imported_version = 'Unknown'

            conn = get_db()
            conn.execute(
                '''INSERT INTO servers
                   (id, name, server_path, executable, java_args, server_type, version,
                    owner, auto_start, approved, category, created)
                   VALUES (?, ?, ?, ?, ?, 'imported', ?, ?, 0, ?, ?, ?)''',
                (server_id, imported_name, str(server_dir), executable, java_args,
                 imported_version, owner, 1 if approved else 0,
                 category, datetime.now().isoformat())
            )
            conn.commit()
            return True, server_id
        except Exception as e:
            if server_dir.exists():
                shutil.rmtree(server_dir)
            return False, str(e)
    
    def start_server(self, server_id):
        """Start a Minecraft server"""
        with self.lock:
            if server_id in self.servers and self.servers[server_id].is_running():
                return False, "Server is already running"
            
            server_config = self.get_server_config(server_id)
            if not server_config:
                return False, "Server configuration not found"
            
            server_path = Path(server_config.get('serverPath', ''))
            executable = server_config.get('executable', 'server.jar')
            java_args = server_config.get('javaArgs', DEFAULT_JAVA_ARGS)
            is_bedrock = server_config.get('category') == 'bedrock'
            
            if not server_path.exists():
                return False, "Server path does not exist"
            
            executable_path = server_path / executable
            if not executable_path.exists():
                return False, f"Server executable '{executable}' not found"

            # Without an accepted EULA the JVM prints the notice and exits at once,
            # which looks like a crash in the console (issue #55). Bedrock has no
            # eula.txt, matching the /eula route's exemption.
            if not is_bedrock and not self.check_eula_accepted(server_id):
                return False, "Minecraft EULA has not been accepted for this server. Accept it before starting."

            # Ensure canned_commands.conf exists (create if missing for older servers)
            self._ensure_canned_commands_conf(server_path)

            try:
                instance = ServerInstance(server_id, server_path, executable, java_args, is_bedrock=is_bedrock)
                instance.start()
                self.servers[server_id] = instance
                
                # Update LastStarted in managed.conf
                managed_conf_path = server_path / 'managed.conf'
                if managed_conf_path.exists():
                    managed_config = self._read_managed_conf(server_path)
                    managed_config['LastStarted'] = datetime.now().isoformat()
                    # Also sync Port from server.properties if available
                    port = self.get_server_port(server_id)
                    if port:
                        managed_config['Port'] = port
                    self._write_managed_conf(server_path, managed_config)
                
                return True, "Server started"
            except Exception as e:
                return False, str(e)
    
    def stop_server(self, server_id):
        """Stop a Minecraft server gracefully"""
        with self.lock:
            if server_id not in self.servers:
                return False, "Server is not running"
            
            instance = self.servers[server_id]
            if not instance.is_running():
                del self.servers[server_id]
                return False, "Server is not running"
            
            instance.stop()
            return True, "Server stopping..."

    def restart_server(self, server_id):
        """Restart a server: stop it (if running), wait for the process to exit,
        pause 5s so the stopped state is visible, then start it again. Runs in a
        background thread so the request returns immediately. Returns (True, message)."""
        def _worker():
            cur = self.servers.get(server_id)
            if cur and cur.is_running():
                self.stop_server(server_id)
                # stop_server force-kills after 30s; wait up to ~35s for exit.
                for _ in range(70):
                    inst = self.servers.get(server_id)
                    if not inst or not inst.is_running():
                        break
                    time.sleep(0.5)
            time.sleep(5)
            self.start_server(server_id)
        threading.Thread(target=_worker, daemon=True).start()
        return True, "Server restarting"

    def kill_server(self, server_id):
        """Forcefully kill a Minecraft server process"""
        with self.lock:
            if server_id not in self.servers:
                return False, "Server is not running"
            
            instance = self.servers[server_id]
            if not instance.is_running():
                del self.servers[server_id]
                return False, "Server is not running"
            
            instance.kill()
            del self.servers[server_id]
            return True, "Server killed"
    
    def send_command(self, server_id, command):
        """Send a command to a running server"""
        if BLOCKED_CONSOLE_COMMANDS.match(command or ''):
            return False, "The 'op'/'deop' commands are blocked from the console — use the Operators tab (or its API) instead."

        if server_id not in self.servers:
            return False, "Server is not running"

        instance = self.servers[server_id]
        if not instance.is_running():
            return False, "Server is not running"
        
        instance.send_command(command)
        return True, "Command sent"
    
    def get_server_port(self, server_id):
        """Get the port number from server.properties"""
        try:
            server_path = self.get_server_path(server_id)
            properties_path = server_path / 'server.properties'
            
            if properties_path.exists():
                with open(properties_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            if key.strip() == 'server-port':
                                return value.strip()
            return None
        except Exception:
            return None
    
    def get_all_server_ports(self, exclude_server_id=None):
        """Get all server ports currently in use (excluding a specific server if specified)"""
        ports = {}
        for server_id in self.get_all_server_ids():
            if exclude_server_id and server_id == exclude_server_id:
                continue
            port = self.get_server_port(server_id)
            if port:
                ports[server_id] = port
        return ports
    
    def _ensure_canned_commands_conf(self, server_dir):
        """Create canned_commands.conf in server_dir if it does not already exist."""
        conf_path = Path(server_dir) / 'canned_commands.conf'
        if not conf_path.exists():
            default = {'autoExecute': False, 'commands': []}
            conf_path.write_text(json.dumps(default, indent=2), encoding='utf-8')

    def get_server_path(self, server_id):
        """Get the path for a specific server"""
        server_config = self.get_server_config(server_id)
        if server_config:
            return Path(server_config.get('serverPath', SERVERS_DIR))
        return SERVERS_DIR


class ServerInstance:
    """Represents a running Minecraft server instance"""
    
    def __init__(self, server_id, server_path, executable, java_args, is_bedrock=False):
        self.server_id = server_id
        self.server_path = Path(server_path)
        self.executable = executable
        self.java_args = java_args
        self.is_bedrock = is_bedrock
        self.process = None
        self.output_buffer = []
        self.max_buffer_size = 1000
        self.status = ServerStatus.STOPPED
        self.start_time = None
        self.server_port = None
        self._status_monitor_thread = None
        self._stop_status_monitor = False
        self.online_players = {}  # name -> join_time (epoch float)
        self._start_notified = False  # ensure server-start notification fires once per start
    
    def start(self):
        """Start the server process"""
        # Clear the output buffer on start for fresh logs
        self.output_buffer = []
        self.online_players = {}
        self._start_notified = False
        self.status = ServerStatus.STARTING
        self.start_time = time.time()
        self.server_port = None  # Will be read from properties
        
        # Set environment
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        
        if self.is_bedrock:
            # Bedrock server: run the server.sh wrapper script
            executable_path = self.server_path / self.executable
            args = ['bash', str(executable_path)]
        else:
            # Java server: run java -jar
            args = [JAVA_BINARY] + self.java_args.split() + ['-jar', self.executable, 'nogui']
        
        self.process = subprocess.Popen(
            args,
            cwd=str(self.server_path),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stderr into stdout for unified output
            text=False,  # Use binary mode for better control
            bufsize=0,  # Unbuffered
            env=env
        )
        
        # Start threads
        threading.Thread(target=self._read_output_unbuffered, daemon=True).start()
        threading.Thread(target=self._monitor_process, daemon=True).start()
        
        # Start status monitoring
        self._stop_status_monitor = False
        self._status_monitor_thread = threading.Thread(target=self._monitor_status, daemon=True)
        self._status_monitor_thread.start()
        
        # Broadcast initial status
        self._broadcast({'type': 'status', 'serverId': self.server_id, 'status': self.status.value, 'running': True})
    
    def _read_output_unbuffered(self):
        """Read output from the process in real-time and broadcast to clients"""
        try:
            buffer = b''
            fd = self.process.stdout.fileno()
            last_partial_send = 0
            
            while self.process.poll() is None:
                # Use select to check if data is available (timeout 0.01s for faster response)
                ready, _, _ = select.select([fd], [], [], 0.01)
                
                if ready:
                    # Data is available, read it
                    chunk = os.read(fd, 4096)
                    if chunk:
                        buffer += chunk
                        
                        # Process all complete lines in the buffer
                        while b'\n' in buffer:
                            line_bytes, buffer = buffer.split(b'\n', 1)
                            line_bytes += b'\n'
                            try:
                                line = line_bytes.decode('utf-8', errors='replace')
                            except:
                                line = line_bytes.decode('latin-1', errors='replace')
                            self._broadcast({'type': 'output', 'data': line, 'serverId': self.server_id})
                            self._add_to_buffer(line)
                            self._parse_player_events(line)
                            last_partial_send = 0  # Reset partial send timer
                        
                        # Send partial line only if:
                        # 1. Buffer has content AND
                        # 2. Either buffer is large (>100 bytes) OR 0.1s has passed since last partial send
                        # This prevents sending every single character while still showing progress
                        current_time = time.time()
                        if buffer and (len(buffer) > 100 or (last_partial_send and current_time - last_partial_send > 0.1)):
                            try:
                                line = buffer.decode('utf-8', errors='replace')
                            except:
                                line = buffer.decode('latin-1', errors='replace')
                            self._broadcast({'type': 'output', 'data': line, 'serverId': self.server_id})
                            self._add_to_buffer(line)
                            buffer = b''
                            last_partial_send = current_time
            
            # Read any remaining output after process exits
            remaining = self.process.stdout.read()
            if remaining:
                try:
                    line = remaining.decode('utf-8', errors='replace')
                except:
                    line = remaining.decode('latin-1', errors='replace')
                if line:
                    self._broadcast({'type': 'output', 'data': line, 'serverId': self.server_id})
                    self._add_to_buffer(line)
        except Exception as e:
            self._broadcast({'type': 'error', 'data': f'Stream error: {str(e)}\n', 'serverId': self.server_id})
    
    def _monitor_process(self):
        """Monitor the process and notify when it exits"""
        if self.process:
            self.process.wait()
            code = self.process.returncode
            self._stop_status_monitor = True
            self.status = ServerStatus.STOPPED
            self.online_players = {}
            self._start_notified = False
            self._broadcast({'type': 'info', 'data': f'Server stopped with code {code}\n', 'serverId': self.server_id})
            self._broadcast({'type': 'status', 'serverId': self.server_id, 'status': self.status.value, 'running': False})
            # Notify subscribers that the server stopped
            try:
                cfg = server_manager.get_server_config(self.server_id)
                sname = cfg.get('name', self.server_id) if cfg else self.server_id
                threading.Thread(
                    target=dispatch_notification,
                    args=('server_stop', {'serverName': sname, 'serverId': self.server_id}),
                    daemon=True
                ).start()
            except Exception:
                pass

    def _parse_player_events(self, line):
        """Parse console output for player join/leave events and update online_players"""
        # Java Minecraft: "[HH:MM:SS] [Server thread/INFO]: PlayerName joined the game"
        # Also handles Paper/Spigot/Folia variants
        join_match = re.search(r':\s+(\S+) joined the game', line)
        if join_match:
            name = join_match.group(1)
            self.online_players[name] = time.time()
            self._broadcast({'type': 'player_join', 'serverId': self.server_id, 'player': name})
            self._dispatch_player_event('player_join', name)
            return

        leave_match = re.search(r':\s+(\S+) left the game', line)
        if leave_match:
            name = leave_match.group(1)
            self.online_players.pop(name, None)
            self._broadcast({'type': 'player_leave', 'serverId': self.server_id, 'player': name})
            self._dispatch_player_event('player_leave', name)
            return

        # Bedrock: "Player connected: PlayerName, xuid: 2535412345678901"
        bedrock_join = re.search(r'Player connected:\s+([^,]+)', line)
        if bedrock_join:
            name = bedrock_join.group(1).strip()
            self._remember_bedrock_xuid(name, line)
            self.online_players[name] = time.time()
            self._broadcast({'type': 'player_join', 'serverId': self.server_id, 'player': name})
            self._dispatch_player_event('player_join', name)
            self._enforce_bedrock_ban(name, line)
            return

        bedrock_leave = re.search(r'Player disconnected:\s+([^,]+)', line)
        if bedrock_leave:
            name = bedrock_leave.group(1).strip()
            self._remember_bedrock_xuid(name, line)
            self.online_players.pop(name, None)
            self._broadcast({'type': 'player_leave', 'serverId': self.server_id, 'player': name})
            self._dispatch_player_event('player_leave', name)

    def _enforce_bedrock_ban(self, name, line):
        """Kick a banned player the moment they connect (issue #82).

        Bedrock has no ban list of its own, so the panel keeps one and enforces
        it here — the panel owns the process and sees every join. Best-effort by
        design and fully guarded: this runs in the console reader thread, where
        an exception would take down console streaming for this server."""
        try:
            if not self.is_bedrock:
                return
            match = re.search(r'xuid:\s*(\d+)', line)
            ban = _bedrock_ban_for(self.server_path, name=name,
                                   xuid=match.group(1) if match else None)
            if not ban:
                return
            target = _safe_bedrock_name(name)
            if not target:
                return
            reason = _safe_console_text(ban.get('reason')) or 'Banned by an operator'
            self.send_command(f'kick "{target}" {reason}')
            notice = f'[MServer] Kicked banned player {name}: {reason}\n'
            self._broadcast({'type': 'output', 'data': notice, 'serverId': self.server_id})
            self._add_to_buffer(notice)
        except Exception:
            pass

    def _remember_bedrock_xuid(self, name, line):
        """Cache the gamertag -> XUID pair carried by a Bedrock connect/disconnect line.

        permissions.json is keyed by XUID and Bedrock exposes no gamertag lookup,
        so this cache is what lets the Operators tab work for a player who isn't
        online. Persisted beside the server so it survives a panel restart."""
        match = re.search(r'xuid:\s*(\d+)', line)
        if not name or not match:
            return
        xuid = match.group(1)
        try:
            cache_file = self.server_path / BEDROCK_XUID_CACHE
            cache = {}
            if cache_file.exists():
                with open(cache_file, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    cache = loaded
            if cache.get(name) == xuid:
                return
            cache[name] = xuid
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache, f, indent=2)
        except Exception:
            pass

    def _dispatch_start_notification(self):
        """Fire the server-start notification once per start, in a background thread."""
        if self._start_notified:
            return
        self._start_notified = True
        try:
            cfg = server_manager.get_server_config(self.server_id)
            sname = cfg.get('name', self.server_id) if cfg else self.server_id
            threading.Thread(
                target=dispatch_notification,
                args=('server_start', {'serverName': sname, 'serverId': self.server_id}),
                daemon=True
            ).start()
        except Exception:
            pass

    def _dispatch_player_event(self, event_type, player_name):
        """Fire player join/leave notification in a background thread."""
        try:
            cfg = server_manager.get_server_config(self.server_id)
            sname = cfg.get('name', self.server_id) if cfg else self.server_id
            threading.Thread(
                target=dispatch_notification,
                args=(event_type, {'serverName': sname, 'serverId': self.server_id, 'player': player_name}),
                daemon=True
            ).start()
        except Exception:
            pass

    def _broadcast(self, data):
        """Push a message to clients subscribed to THIS server's room.

        Emitting globally would leak one server's live console/player events and
        status to every authenticated client (the frontend only filters by
        serverId client-side). Clients join 'server_<id>' on connect/subscribe
        only after the same access check used by the HTTP routes, so scoping the
        emit to that room enforces per-server access on the realtime stream too."""
        socketio.emit('message', data, to=f'server_{self.server_id}', namespace='/')
    
    def _add_to_buffer(self, line):
        """Add line to output buffer"""
        self.output_buffer.append(line)
        if len(self.output_buffer) > self.max_buffer_size:
            self.output_buffer.pop(0)
    
    def _check_tcp_port(self, port, timeout=1):
        """Check if server is responding on TCP port"""
        if not port:
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _get_server_port(self):
        """Extract server port from server.properties"""
        if self.server_port:
            return self.server_port
        
        props_file = self.server_path / 'server.properties'
        if props_file.exists():
            try:
                with open(props_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('server-port='):
                            self.server_port = int(line.split('=')[1])
                            return self.server_port
            except Exception:
                pass
        return 25565  # Default Minecraft port
    
    def _monitor_status(self):
        """Background thread to monitor server status"""
        while not self._stop_status_monitor:
            if self.process is None or self.process.poll() is not None:
                # Process not running
                if self.status != ServerStatus.STOPPED:
                    self.status = ServerStatus.STOPPED
                    self._broadcast({'type': 'status', 'serverId': self.server_id, 'status': self.status.value})
                time.sleep(2)
                continue
            
            # Process is running, check state
            elapsed = time.time() - self.start_time if self.start_time else 0
            
            # Bedrock servers: simplified status detection (process-based only)
            # Bedrock uses UDP for queries which is more complex, so we just check if process is running
            if self.is_bedrock:
                if elapsed < 10:
                    # Short startup grace period for Bedrock
                    if self.status != ServerStatus.STARTING:
                        self.status = ServerStatus.STARTING
                        self._broadcast({
                            'type': 'status',
                            'serverId': self.server_id,
                            'status': self.status.value,
                            'running': True
                        })
                else:
                    # Process is running, assume server is ready
                    if self.status != ServerStatus.RUNNING:
                        self.status = ServerStatus.RUNNING
                        self._broadcast({
                            'type': 'status',
                            'serverId': self.server_id,
                            'status': self.status.value,
                            'running': True
                        })
                        self._dispatch_start_notification()
            else:
                # Java servers: TCP port-based detection
                port = self._get_server_port()
                tcp_responsive = self._check_tcp_port(port)
                
                new_status = None
                
                if tcp_responsive:
                    # Server is responding on TCP port
                    if self.status != ServerStatus.RUNNING:
                        new_status = ServerStatus.RUNNING
                elif elapsed < 30:
                    # Within startup grace period
                    if self.status != ServerStatus.STARTING:
                        new_status = ServerStatus.STARTING
                else:
                    # Process running but not responding after 30s
                    if self.status != ServerStatus.UNRESPONSIVE:
                        new_status = ServerStatus.UNRESPONSIVE
                
                if new_status and new_status != self.status:
                    self.status = new_status
                    self._broadcast({
                        'type': 'status',
                        'serverId': self.server_id,
                        'status': self.status.value,
                        'running': self.status in [ServerStatus.STARTING, ServerStatus.RUNNING, ServerStatus.UNRESPONSIVE]
                    })
                    # Dispatch server-start notification once per lifecycle
                    if new_status == ServerStatus.RUNNING:
                        self._dispatch_start_notification()
            
            time.sleep(2)  # Check every 2 seconds
    
    def get_status(self):
        """Get current server status"""
        return self.status
    
    def is_running(self):
        """Check if the server is running"""
        return self.process is not None and self.process.poll() is None
    
    def send_command(self, command):
        """Send a command to the server"""
        if self.is_running():
            # Write as bytes since we're using binary mode
            self.process.stdin.write((command + '\n').encode('utf-8'))
            self.process.stdin.flush()
    
    def stop(self):
        """Stop the server gracefully by sending 'stop' command"""
        if self.is_running():
            self.status = ServerStatus.STOPPING
            self._broadcast({'type': 'status', 'serverId': self.server_id, 'status': self.status.value, 'running': True})
            self.send_command('stop')
            
            def force_kill():
                time.sleep(30)
                if self.is_running():
                    self.process.kill()
            
            threading.Thread(target=force_kill, daemon=True).start()
    
    def kill(self):
        """Forcefully kill the server process immediately"""
        if self.is_running():
            self.status = ServerStatus.STOPPING
            self._broadcast({'type': 'status', 'serverId': self.server_id, 'status': self.status.value})
            self.process.kill()
            self.process.wait()
            self._stop_status_monitor = True
            self.status = ServerStatus.STOPPED
    
    def get_recent_output(self, lines=100):
        """Get recent output from the buffer"""
        return self.output_buffer[-lines:]


# Initialize server manager
server_manager = ServerManager()

# ---- Auto-start servers after a short delay ----
def _auto_start_servers():
    """Start all servers marked autoStart=True, 15 seconds after the controller launches.

    The delay gives the web server, database, and networking time to fully
    initialise before Minecraft JVMs start competing for CPU.  Servers are
    started sequentially (30-second gap between each) to reduce the CPU spike
    that occurs during JVM initialisation.
    """
    time.sleep(15)
    all_servers = server_manager.get_servers_list(include_pending=False)
    auto_start_ids = [
        s['id'] for s in all_servers
        if s.get('autoStart', False) and s.get('approved', True)
    ]
    if not auto_start_ids:
        return
    print(f"[AutoStart] {len(auto_start_ids)} server(s) queued for auto-start")
    for idx, server_id in enumerate(auto_start_ids):
        name = server_manager.get_server_config(server_id).get('name', server_id)
        success, msg = server_manager.start_server(server_id)
        if success:
            print(f"[AutoStart] Started: {name}")
        else:
            print(f"[AutoStart] Failed to start '{name}': {msg}")
        if idx < len(auto_start_ids) - 1:
            time.sleep(30)

threading.Thread(target=_auto_start_servers, daemon=True).start()
# ------------------------------------------------

# Initialize backup scheduler
backup_scheduler = BackupScheduler()

# Initialize task scheduler
task_scheduler = TaskScheduler(server_manager, socketio)

# Initialize message scheduler
message_scheduler = MessageScheduler(server_manager)


# ==================== Background Job Queue ====================

class JobCancelled(Exception):
    """Raised by a job handler (or its progress callback) when a job is cancelled."""
    pass


class JobManager:
    """Unified background task queue for long-running operations.

    Heavy operations (backups, restores, server deletion, zip downloads)
    submit a job here instead of blocking the HTTP request thread.
    Jobs are persisted in the `jobs` table (so the task list and
    history survive a restart), run in a bounded thread pool, and report live
    progress over Socket.IO (push) plus the GET /api/jobs/<id> poll endpoint.

    Concurrency model: a global ThreadPoolExecutor runs several jobs at once
    across DIFFERENT servers, but a per-server lock serializes jobs that touch
    the SAME server (so e.g. a backup and a delete can never overlap).
    """

    # Statuses considered "still active" (used for recovery + UI filtering)
    ACTIVE_STATUSES = ('queued', 'running')

    def __init__(self, socketio, server_manager, max_workers=4):
        self.socketio = socketio
        self.server_manager = server_manager
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='job')
        self.handlers = {}                 # type -> handler(job_id, params, progress_cb, cancel_evt)
        self._guard = threading.Lock()      # protects the dicts below
        self._server_locks = {}             # server_id -> threading.Lock
        self._cancel_flags = {}             # job_id -> threading.Event
        self._futures = {}                  # job_id -> Future
        self._last_pct = {}                 # job_id -> last emitted progress int (throttle)
        # init_db() already flips interrupted rows to 'failed' on boot.

    # ---- registration ----
    def register(self, job_type, handler):
        """Register a handler for a job type. handler(job_id, params, progress_cb, cancel_evt)."""
        self.handlers[job_type] = handler

    # ---- helpers ----
    def _server_lock(self, server_id):
        with self._guard:
            lock = self._server_locks.get(server_id)
            if lock is None:
                lock = threading.Lock()
                self._server_locks[server_id] = lock
            return lock

    @staticmethod
    def _row_to_dict(row):
        if row is None:
            return None
        d = dict(row)
        # camelCase + JSON-decode for the frontend
        for key in ('params', 'result'):
            if d.get(key):
                try:
                    d[key] = json.loads(d[key])
                except (ValueError, TypeError):
                    d[key] = None
        return {
            'id': d['id'],
            'type': d['type'],
            'serverId': d.get('server_id'),
            'title': d['title'],
            'status': d['status'],
            'progress': d.get('progress', 0),
            'message': d.get('message'),
            'params': d.get('params'),
            'result': d.get('result'),
            'error': d.get('error'),
            'createdBy': d.get('created_by'),
            'created': d.get('created'),
            'started': d.get('started'),
            'finished': d.get('finished'),
        }

    def _emit(self, event, job):
        """Emit a job event to the owner's user room and the admins room."""
        try:
            owner = job.get('createdBy')
            if owner:
                self.socketio.emit(event, {'job': job}, to=f'user_{owner}')
            self.socketio.emit(event, {'job': job}, to='admins')
        except Exception as e:
            print(f"[JobManager] emit failed for {event}: {e}")

    # ---- public read API ----
    def get_job(self, job_id):
        row = get_db().execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
        return self._row_to_dict(row)

    def list_jobs(self, *, is_admin, user_id, owned_server_ids=None, limit=100):
        """List jobs visible to a user. Admins see all; users see their own jobs
        plus jobs for servers they own."""
        if is_admin:
            rows = get_db().execute(
                'SELECT * FROM jobs ORDER BY created DESC LIMIT ?', (limit,)
            ).fetchall()
        else:
            owned = list(owned_server_ids or [])
            placeholders = ','.join('?' * len(owned)) if owned else ''
            clause = 'created_by=?'
            params = [user_id]
            if owned:
                clause += f' OR server_id IN ({placeholders})'
                params.extend(owned)
            rows = get_db().execute(
                f'SELECT * FROM jobs WHERE {clause} ORDER BY created DESC LIMIT ?',
                (*params, limit)
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ---- submission ----
    def submit(self, job_type, title, params=None, created_by=None, server_id=None):
        if job_type not in self.handlers:
            raise ValueError(f'Unknown job type: {job_type}')
        job_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        conn = get_db()
        conn.execute(
            '''INSERT INTO jobs
               (id, type, server_id, title, status, progress, message, params,
                result, error, created_by, created, started, finished)
               VALUES (?, ?, ?, ?, 'queued', 0, ?, ?, NULL, NULL, ?, ?, NULL, NULL)''',
            (job_id, job_type, server_id, title, 'Queued',
             json.dumps(params or {}), created_by, now)
        )
        conn.commit()
        with self._guard:
            self._cancel_flags[job_id] = threading.Event()
            self._last_pct[job_id] = 0
        self._emit('job_queued', self.get_job(job_id))
        future = self.executor.submit(self._run, job_id)
        with self._guard:
            self._futures[job_id] = future
        return job_id

    def cancel(self, job_id):
        """Request cancellation. Returns True if the job was active."""
        job = self.get_job(job_id)
        if not job or job['status'] not in self.ACTIVE_STATUSES:
            return False
        with self._guard:
            evt = self._cancel_flags.get(job_id)
            future = self._futures.get(job_id)
        if evt:
            evt.set()
        # If still queued (not yet started), try to cancel the future outright.
        if future and future.cancel():
            self._finish(job_id, 'cancelled', error='Cancelled before starting')
        return True

    # ---- internal lifecycle ----
    def _set_running(self, job_id):
        conn = get_db()
        conn.execute(
            "UPDATE jobs SET status='running', started=?, message=? WHERE id=?",
            (datetime.now().isoformat(), 'Starting…', job_id)
        )
        conn.commit()
        self._emit('job_started', self.get_job(job_id))

    def progress(self, job_id, pct, message=None):
        """Progress callback handed to handlers. Throttled to whole-percent steps.
        Raises JobCancelled if cancellation was requested."""
        with self._guard:
            evt = self._cancel_flags.get(job_id)
        if evt and evt.is_set():
            raise JobCancelled()
        pct = max(0, min(100, int(pct)))
        with self._guard:
            last = self._last_pct.get(job_id, -1)
            changed = (pct != last)
            self._last_pct[job_id] = pct
        # Skip redundant writes when neither percent nor message advanced.
        if not changed and message is None:
            return
        conn = get_db()
        if message is not None:
            conn.execute('UPDATE jobs SET progress=?, message=? WHERE id=?', (pct, message, job_id))
        else:
            conn.execute('UPDATE jobs SET progress=? WHERE id=?', (pct, job_id))
        conn.commit()
        self._emit('job_progress', self.get_job(job_id))

    def _finish(self, job_id, status, *, result=None, error=None):
        conn = get_db()
        if status == 'completed':
            final_pct = 100
        else:
            current = self.get_job(job_id)
            final_pct = current.get('progress', 0) if current else 0
        conn.execute(
            'UPDATE jobs SET status=?, progress=?, result=?, error=?, finished=? WHERE id=?',
            (status,
             final_pct,
             json.dumps(result) if result is not None else None,
             error,
             datetime.now().isoformat(),
             job_id)
        )
        conn.commit()
        event = {'completed': 'job_completed', 'failed': 'job_failed',
                 'cancelled': 'job_cancelled'}.get(status, 'job_completed')
        self._emit(event, self.get_job(job_id))
        # Drop in-memory tracking for this job.
        with self._guard:
            self._cancel_flags.pop(job_id, None)
            self._futures.pop(job_id, None)
            self._last_pct.pop(job_id, None)

    def _run(self, job_id):
        job = self.get_job(job_id)
        if not job:
            return
        with self._guard:
            evt = self._cancel_flags.get(job_id)
        # Cancelled while still queued.
        if evt and evt.is_set():
            self._finish(job_id, 'cancelled', error='Cancelled before starting')
            return
        handler = self.handlers.get(job['type'])
        if handler is None:
            self._finish(job_id, 'failed', error=f"No handler for job type '{job['type']}'")
            return
        server_id = job.get('serverId')
        lock = self._server_lock(server_id) if server_id else None
        if lock:
            lock.acquire()
        try:
            # Re-check cancellation after possibly waiting on the server lock.
            if evt and evt.is_set():
                self._finish(job_id, 'cancelled', error='Cancelled before starting')
                return
            self._set_running(job_id)
            params = job.get('params') or {}
            progress_cb = lambda pct, message=None: self.progress(job_id, pct, message)
            result = handler(job_id, params, progress_cb, evt)
            self.progress(job_id, 100)
            self._finish(job_id, 'completed', result=result if isinstance(result, dict) else None)
        except JobCancelled:
            self._finish(job_id, 'cancelled', error='Cancelled')
        except Exception as e:
            import traceback
            traceback.print_exc()
            self._finish(job_id, 'failed', error=str(e))
        finally:
            if lock:
                lock.release()


# Initialize job manager (handlers are registered below, after their functions
# are defined). Singletons it depends on (socketio, server_manager) already exist.
job_manager = JobManager(socketio, server_manager)


# ---- Job handlers --------------------------------------------------------------
# Each handler runs in a background worker thread with signature
#   handler(job_id, params, progress, cancel) -> dict | None
# `progress(pct, message=None)` reports progress and raises JobCancelled if the
# job was cancelled; `cancel` is the threading.Event for cooperative checks inside
# tight loops. Input validation lives in the routes (so the user gets an immediate
# error); these handlers assume params are already validated. Globals they use
# (verify_backup_file, safe_extractall, jar_manager, etc.) are resolved at call
# time, so registering before those are defined is fine.

def _job_backup(job_id, params, progress, cancel):
    server_id = params['serverId']
    compression_level = max(0, min(9, int(params.get('compressionLevel', 6))))
    backup_type = str(params.get('backupType', 'manual'))
    server_path = server_manager.get_server_path(server_id)
    if not server_path.exists():
        raise Exception('Server path not found')

    timestamp = datetime.now().strftime('%Y-%m-%dT%H-%M-%S')
    backup_dir = BACKUPS_DIR / server_id
    backup_dir.mkdir(parents=True, exist_ok=True)

    instance = server_manager.servers.get(server_id)
    was_running = instance is not None and instance.is_running()
    if was_running:
        progress(2, 'Stopping server…')
        server_manager.send_command(server_id, "say [Backup] Server is being stopped for a backup...")
        time.sleep(2)
        server_manager.stop_server(server_id)
        for _ in range(60):
            time.sleep(1)
            inst = server_manager.servers.get(server_id)
            if inst is None or not inst.is_running():
                break

    custom_name = params.get('customName', '')
    backup_name = custom_name if custom_name else f'backup-{timestamp}.zip'
    backup_path = backup_dir / backup_name
    try:
        all_files = [Path(root) / f for root, _, files in os.walk(server_path) for f in files]
        total = len(all_files) or 1
        progress(5, 'Archiving files…')
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED,
                             compresslevel=compression_level) as zipf:
            for i, fp in enumerate(all_files):
                if cancel and cancel.is_set():
                    raise JobCancelled()
                zipf.write(fp, fp.relative_to(server_path))
                if i % 50 == 0:
                    progress(5 + int((i / total) * 80))  # 5–85%
            zipf.writestr('backup_manifest.json',
                          json.dumps({'type': 'full', 'created': timestamp,
                                      'file_count': len(all_files)}, indent=2))

        progress(88, 'Verifying…')
        size = backup_path.stat().st_size
        ok, checksum, _verify_err = verify_backup_file(backup_path)

        ext_ok, ext_msg = upload_backup_to_external(backup_path, server_id, backup_name)
        if not ext_ok:
            print(f"[Backup] External upload warning: {ext_msg}")

        backup_scheduler._log_backup_event(server_id, {
            'type': backup_type, 'backupName': backup_name, 'size': size,
            'compressionLevel': compression_level, 'verified': ok,
            'checksum': checksum, 'uploaded_to_external': ext_ok, 'success': True
        })

        if settings_manager.get_app_settings().get('autoDeleteExpiredBackups', False):
            backup_scheduler._cleanup_old_backups(server_id)

        if was_running:
            progress(95, 'Restarting server…')
            server_manager.start_server(server_id)

        return {'backup': backup_name, 'size': size, 'verified': ok, 'checksum': checksum}

    except JobCancelled:
        try:
            if backup_path.exists():
                backup_path.unlink()
        except Exception:
            pass
        if was_running:
            try:
                server_manager.start_server(server_id)
            except Exception:
                pass
        raise
    except Exception as e:
        backup_scheduler._log_backup_event(server_id, {
            'type': backup_type, 'backupName': backup_name, 'success': False, 'error': str(e)
        })
        if was_running:
            try:
                server_manager.start_server(server_id)
            except Exception:
                pass
        raise


def _job_restore(job_id, params, progress, cancel):
    server_id = params['serverId']
    backup_name = params['backupName']  # already sanitized in the route
    backup_path = BACKUPS_DIR / server_id / backup_name
    server_path = server_manager.get_server_path(server_id)

    instance = server_manager.servers.get(server_id)
    was_running = instance is not None and instance.is_running()
    if was_running:
        progress(5, 'Stopping server…')
        server_manager.send_command(server_id, "say [Restore] Server is being stopped to restore a backup...")
        time.sleep(2)
        server_manager.stop_server(server_id)
        for _ in range(60):
            time.sleep(1)
            inst = server_manager.servers.get(server_id)
            if inst is None or not inst.is_running():
                break

    try:
        progress(20, 'Clearing server directory…')
        for item in server_path.iterdir():
            if cancel and cancel.is_set():
                raise JobCancelled()
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

        progress(45, 'Extracting backup…')
        with zipfile.ZipFile(backup_path, 'r') as zipf:
            safe_extractall(zipf, server_path)

        if was_running:
            progress(90, 'Restarting server…')
            server_manager.start_server(server_id)

        return {'backup': backup_name}
    except Exception:
        if was_running:
            try:
                server_manager.start_server(server_id)
            except Exception:
                pass
        raise


def _job_delete_server(job_id, params, progress, cancel):
    server_id = params['serverId']
    delete_files = bool(params.get('deleteFiles', False))
    progress(10, 'Stopping server…')
    # delete_server() stops the server, removes files (if requested), and the DB row.
    # rmtree is not interruptible mid-call, so this job is best-effort cancellable.
    progress(40, 'Removing files…' if delete_files else 'Removing configuration…')
    ok = server_manager.delete_server(server_id, delete_files=delete_files)
    if not ok:
        raise Exception('Server not found')
    return {'deleted': True}


def _job_zip_download(job_id, params, progress, cancel):
    server_id = params['serverId']
    requested_path = params.get('requestedPath', '')
    server_path = server_manager.get_server_path(server_id)
    full_path = server_path / requested_path
    if not full_path.exists() or not full_path.is_dir():
        raise Exception('Path not found or not a directory')

    folder_name = full_path.name or 'server'
    download_name = f'{folder_name}.zip'
    out_path = JOBS_TMP_DIR / f'{job_id}.zip'

    all_files = [p for p in full_path.rglob('*') if p.is_file()]
    total = len(all_files) or 1
    progress(2, 'Archiving files…')
    try:
        with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for i, fp in enumerate(all_files):
                if cancel and cancel.is_set():
                    raise JobCancelled()
                zf.write(str(fp), str(fp.relative_to(full_path)))
                if i % 25 == 0:
                    progress(2 + int((i / total) * 96))  # 2–98%
    except JobCancelled:
        try:
            if out_path.exists():
                out_path.unlink()
        except Exception:
            pass
        raise

    size = out_path.stat().st_size
    return {'download': True, 'filename': download_name, 'size': size}


def _job_jar_download(job_id, params, progress, cancel):
    """Download one server JAR into the shared bucket (serverexecutables/).

    Not tied to a server, so several run concurrently across the job pool.
    `progress`/`cancel` come from the JobManager; download_jar raises
    JobCancelled on cancel so the task ends as 'cancelled'."""
    server_type = params['type']
    version = params['version']
    result = jar_bucket.download_jar(server_type, version,
                                     progress_cb=progress, cancel=cancel)
    if not result.get('success'):
        raise Exception(result.get('error', 'Download failed'))
    return result


job_manager.register('backup', _job_backup)
job_manager.register('restore', _job_restore)
job_manager.register('delete_server', _job_delete_server)
job_manager.register('zip_download', _job_zip_download)
job_manager.register('jar_download', _job_jar_download)


def _cleanup_job_artifacts(max_age_hours=24):
    """Remove prepared zip-download artifacts that are stale or orphaned.

    A completed artifact is kept until it ages out (so the user has time to
    download it); artifacts whose job no longer exists or failed/was cancelled
    are removed immediately. In-progress (queued/running) artifacts are left
    alone since they may be mid-write.
    """
    try:
        now = time.time()
        for f in JOBS_TMP_DIR.glob('*.zip'):
            try:
                job = job_manager.get_job(f.stem)
                stale = (now - f.stat().st_mtime) > max_age_hours * 3600
                if job is None:
                    remove = True
                elif job['status'] in ('failed', 'cancelled'):
                    remove = True
                elif job['status'] == 'completed':
                    remove = stale
                else:
                    remove = False  # queued/running — leave it
                if remove:
                    f.unlink()
            except Exception:
                pass
    except Exception as e:
        print(f"[JobManager] artifact cleanup error: {e}")


# Sweep prepared zip artifacts periodically, reusing the backup scheduler's
# APScheduler instance. The first run fires shortly after boot to clear anything
# left behind by a previous process.
backup_scheduler.scheduler.add_job(
    _cleanup_job_artifacts, 'interval', hours=6,
    id='job_artifact_cleanup', replace_existing=True,
    next_run_time=datetime.now() + timedelta(seconds=30)
)

# Initialize API Manager. Pass the dependencies its routes need explicitly —
# api_manager.py must not `from server import X` itself: this app is launched
# as `python server.py`, so it's registered as sys.modules['__main__'], not
# sys.modules['server']. A `from server import` from within a module that's
# only ever imported BY this already-running script would re-execute this
# entire file as a second, independent module (re-running the module-level
# signal.signal() call below off the main thread, which raises on every call).
from api_manager import init_api_manager, api_v1
init_api_manager(app, server_manager, get_current_user, group_manager, read_version_file)

# Exempt API v1 from CSRF protection (uses API key authentication)
csrf.exempt(api_v1)


def is_safe_path(base_path, requested_path):
    """Check if the requested path is within the base path (prevent directory traversal)"""
    try:
        base = Path(base_path).resolve()
        full = (base / requested_path).resolve()
        # Proper containment check (avoids the str.startswith prefix bug where
        # e.g. base "/srv/foo" would wrongly accept "/srv/foobar").
        return full == base or base in full.parents
    except Exception:
        return False


def is_server_path_allowed(server_path):
    """Ensure a server's base directory stays within SERVERS_DIR.

    The per-server file routes trust the stored serverPath as the base for
    is_safe_path(). If a user could set serverPath to an arbitrary location
    (e.g. "/"), every file read/write/delete route would operate against the
    whole filesystem. Constrain all server directories to live under SERVERS_DIR.
    """
    try:
        base = SERVERS_DIR.resolve()
        full = Path(server_path).resolve()
        return full == base or base in full.parents
    except Exception:
        return False


def validate_zip_members(zipf, dest_dir):
    """Raise ValueError if any member of zipf is unsafe to extract into dest_dir:
    an absolute or '..'-containing name, a symlink, or a name whose *resolved*
    target falls outside dest_dir (a plain '..' substring check isn't enough —
    see issue #14). Callers doing custom member-by-member extraction (e.g.
    import_world) should call this before writing anything.
    """
    dest = Path(dest_dir).resolve()
    for info in zipf.infolist():
        name = info.filename
        if name.startswith('/') or '..' in Path(name).parts:
            raise ValueError(f'Unsafe path in archive: {name}')
        # Reject symlink members (S_IFLNK == 0o120000 in the high 16 bits).
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            raise ValueError(f'Archive contains a symbolic link: {name}')
        target = (dest / name).resolve()
        if target != dest and dest not in target.parents:
            raise ValueError(f'Path escapes destination: {name}')


def safe_extractall(zipf, dest_dir, skip=None):
    """Extract a zip archive, rejecting path-traversal and symlink members.

    zipfile.extractall() sanitizes ".."/absolute names but still happily writes
    symlink members, which a crafted archive can use to escape dest_dir on a
    follow-up write. Validate every member before extracting.

    `skip`, if given, is called with each member's name and returning True leaves
    that member on disk untouched — for archives that must not clobber existing
    files (the Bedrock update keeps the operator's world and configs this way).
    Validation still covers every member, skipped ones included, so a hostile
    archive can't hide behind the skip-list.
    """
    validate_zip_members(zipf, dest_dir)
    members = None
    if skip is not None:
        members = [info for info in zipf.infolist() if not skip(info.filename)]
    zipf.extractall(dest_dir, members)


def reject_if_not_zip(saved_path):
    """After saving an upload that must be a ZIP/JAR (JARs are ZIP archives),
    verify the actual content — not just the filename extension — really is a
    zip. Deletes the file and returns an error response tuple on mismatch, so
    a polyglot file can't ride an extension check onto disk unexamined.
    Returns None when the file is a valid zip."""
    if not zipfile.is_zipfile(saved_path):
        Path(saved_path).unlink(missing_ok=True)
        return api_error('Uploaded file is not a valid ZIP/JAR archive', 400)
    return None


# Magic-number signatures for the image types accepted for the branding favicon.
_IMAGE_MAGIC_BYTES = {
    'png': (b'\x89PNG\r\n\x1a\n',),
    'jpg': (b'\xff\xd8\xff',),
    'jpeg': (b'\xff\xd8\xff',),
    'gif': (b'GIF87a', b'GIF89a'),
    'ico': (b'\x00\x00\x01\x00',),
}


def reject_if_not_image(file_storage, file_ext):
    """Verify an uploaded favicon's leading bytes match its claimed extension,
    rejecting content/extension mismatches (e.g. an HTML/SVG polyglot saved
    with a .png name and later served as a static asset). Resets the stream
    position so the caller can still .save() it. Returns an error response
    tuple on mismatch, None if the content matches."""
    signatures = _IMAGE_MAGIC_BYTES.get(file_ext, ())
    file_storage.seek(0)
    header = file_storage.read(16)
    file_storage.seek(0)
    if not any(header.startswith(sig) for sig in signatures):
        return api_error(f'File content does not match a valid {file_ext.upper()} image', 400)
    return None


# ==================== API Response Helpers ====================
# See issue #28: response shapes across routes historically mixed
# {'success': True, ...}, {'error': ...}-only, and raw un-enveloped data.
# New/touched routes should use these so every JSON response carries a
# top-level `success` boolean, even the raw-shape GET/list endpoints that
# previously omitted it — existing fields are never renamed or nested, only
# `success` is added, so this is safe to adopt incrementally route by route.

def api_success(data=None, status=200, **extra):
    """Standard success JSON response: always includes `success: true`.
    `data`, if given, is merged flat at the top level (matches the existing
    {'success': True, ...fields} convention already used across server.py)."""
    body = {'success': True}
    if data:
        body.update(data)
    body.update(extra)
    return jsonify(body), status


def api_error(message, status=400, **extra):
    """Standard error JSON response: always includes `success: false`
    alongside the existing `error` key every route already returns."""
    body = {'success': False, 'error': message}
    body.update(extra)
    return jsonify(body), status


# ==================== CSRF Token Endpoint ====================

@app.route('/api/csrf-token', methods=['GET'])
@csrf.exempt
def get_csrf_token():
    """Get CSRF token for authenticated sessions"""
    token = generate_csrf()
    return jsonify({'csrfToken': token})


# ==================== Static Files & Page Routes ====================

@app.route('/')
def index():
    """Serve main page - redirects to first-run setup or login as needed."""
    if user_manager.needs_setup():
        return redirect('/setup')
    user_id, user = get_current_user()
    if not user:
        return redirect('/login.html')
    return send_from_directory('public', 'index.html')

@app.route('/login.html')
def login_page():
    """Serve login page"""
    if user_manager.needs_setup():
        return redirect('/setup')
    return send_from_directory('public', 'login.html')

@app.route('/setup')
@app.route('/setup.html')
def setup_page():
    """Serve the first-run setup page (create the initial admin account).

    Only reachable on a clean install. Once an admin exists it redirects away so
    the create-admin form can never be reached on a configured panel."""
    if not user_manager.needs_setup():
        return redirect('/')
    return send_from_directory('public', 'setup.html')

@app.route('/public.html')
def public_page():
    """Serve public status page (no auth required)"""
    return send_from_directory('public', 'public.html')


# ==================== First-Run Setup API ====================

@app.route('/api/setup/status', methods=['GET'])
@csrf.exempt
def api_setup_status():
    """Whether the panel still needs its first admin account created."""
    return api_success(needsSetup=user_manager.needs_setup())

@app.route('/api/setup/admin', methods=['POST'])
@csrf.exempt
@limiter.limit("10 per hour")
def api_setup_create_admin():
    """Create the first admin account on a clean install. Hard-gated by
    needs_setup() so it is inert once any real admin exists (and during a lockout,
    where the hidden admin is the recovery path instead)."""
    if not user_manager.needs_setup():
        return api_error('Setup has already been completed', 403)
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')
    name = data.get('name', '')
    email = data.get('email', '')
    if not username or not password:
        return api_error('Username and password required', 400)
    user_id, message = user_manager.create_first_admin(username, password, name, email)
    if not user_id:
        return api_error(message, 400)
    return api_success(message=message)

@app.route('/settings.html')
@login_required
def settings_page():
    """Serve settings page — requires at least one panel permission."""
    user_id, user = get_current_user()
    if not any(user_manager.user_has_permission(user, p)
               for p in group_manager.ALL_PERMISSIONS if p.startswith('panel.')):
        return redirect('/')
    return send_from_directory('public', 'settings.html')

@app.route('/<path:path>')
def static_files(path):
    """Serve static files"""
    # Allow certain files without auth (CSS, JS, and public pages)
    public_files = ['styles.css', 'app.js', 'login.js', 'public.js', 'settings.js', 'utils.js', 'setup.js']
    if path in public_files or path.startswith('assets/'):
        response = send_from_directory('public', path)
        # Add cache-control headers to prevent caching of JS/CSS files
        # This ensures users get the latest version after updates
        if path.endswith('.js') or path.endswith('.css'):
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        return response
    
    # Check auth for other files
    user_id, user = get_current_user()
    if not user:
        return redirect('/login.html')
    
    response = send_from_directory('public', path)
    # Add cache-control headers for authenticated files too
    if path.endswith('.js') or path.endswith('.css'):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response


# ==================== Authentication API ====================

@app.route('/api/auth/login', methods=['POST'])
@csrf.exempt
@limiter.limit("10 per minute")
def api_login():
    """Authenticate user"""
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return api_error('Username and password required', 400)

    user_id, result = user_manager.authenticate(username, password)

    if user_id is None:
        return api_error(result, 401)

    # Check if MFA is enabled for this user
    if result.get('mfaEnabled', False):
        # Regenerate session before storing any auth state (prevents session fixation)
        session.clear()
        session['temp_user_id'] = user_id
        session['mfa_required'] = True
        session['mfa_timestamp'] = time.time()

        return api_success(mfaRequired=True, message='MFA verification required')
    
    # Check MFA policies. The hidden anti-lockout admin is never subject to MFA
    # enforcement — it is the recovery path and must always be usable.
    mfa_settings = settings_manager.get_settings().get('mfa', {})
    require_all = mfa_settings.get('requireMfaForAllUsers', False)
    require_admin = mfa_settings.get('requireMfaForAdmins', False)

    if not result.get('isAntiLockout', False) and (require_all or (require_admin and group_manager.is_admin_group(result.get('groupId')))):
        if not result.get('mfaEnabled', False):
            # MFA is mandatory but this user hasn't enrolled yet. Instead of locking
            # them out, grant a limited "enrollment" session that can ONLY complete
            # MFA setup (see api_mfa_enroll_setup/verify). It carries no user_id, so
            # it grants no access to the panel; it is promoted to a full session only
            # once MFA is successfully verified.
            session.clear()
            session['mfa_enroll_user_id'] = user_id
            session['mfa_enroll_timestamp'] = time.time()
            return api_success(mfaSetupRequired=True,
                                message='MFA is required for your account. Set it up now to continue.')

    # Regenerate session before setting auth data (prevents session fixation)
    session.clear()
    session.permanent = True
    session['user_id'] = user_id
    session['username'] = result['username']
    session['group_id'] = result.get('groupId')

    return api_success(user={
        'id': user_id,
        'username': result['username'],
        'groupId': result.get('groupId'),
        'groupName': result.get('groupName'),
    })

@app.route('/api/auth/logout', methods=['POST'])
@csrf.exempt
def api_logout():
    """Log out user"""
    session.clear()
    return api_success()

@app.route('/api/auth/register', methods=['POST'])
@csrf.exempt
@limiter.limit("5 per hour")
def api_register():
    """Register new user"""
    # Check if registration is enabled
    if not settings_manager.get_app_settings().get('enableRegistration', True):
        return api_error('Registration is currently disabled', 403)

    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return api_error('Username and password required', 400)

    user_id, message = user_manager.register(username, password)

    if user_id is None:
        return api_error(message, 400)

    return api_success(message=message)

@app.route('/api/auth/me', methods=['GET'])
def api_current_user():
    """Get current logged in user"""
    user_id, user = get_current_user()

    if not user:
        return api_error('Not authenticated', 401)

    return api_success({
        'id': user_id,
        'username': user['username'],
        'name': user.get('name', ''),
        'displayName': user.get('name', ''),
        'email': user.get('email', ''),
        'groupId': user.get('groupId'),
        'groupName': user.get('groupName'),
        'permissions': user_manager.get_user_permissions(user),
        'mfaEnabled': user.get('mfaEnabled', False)
    })

@app.route('/api/auth/password', methods=['POST'])
@login_required
def api_change_password():
    """Change current user's password"""
    user_id = session.get('user_id')
    data = request.get_json()

    old_password = data.get('oldPassword', '')
    new_password = data.get('newPassword', '')

    success, message = user_manager.change_password(user_id, old_password, new_password)

    if not success:
        return api_error(message, 400)

    return api_success(message=message)

@app.route('/api/auth/profile/username', methods=['PUT'])
@login_required
def api_update_username():
    """Update current user's username"""
    user_id = session.get('user_id')
    data = request.get_json()

    new_username = data.get('username', '').strip()

    if not new_username:
        return api_error('Username is required', 400)

    success, message = user_manager.update_username(user_id, new_username)

    if not success:
        return api_error(message, 400)

    # Update session with new username
    session['username'] = new_username

    return api_success(message=message)

@app.route('/api/auth/profile/name', methods=['PUT'])
@login_required
def api_update_name():
    """Update current user's display name"""
    user_id = session.get('user_id')
    data = request.get_json()

    name = data.get('name', '').strip()

    success, message = user_manager.update_name(user_id, name)

    if not success:
        return api_error(message, 400)

    return api_success(message=message)

@app.route('/api/auth/profile/email', methods=['PUT'])
@login_required
def api_update_email():
    """Update current user's email address"""
    user_id = session.get('user_id')
    data = request.get_json()

    email = data.get('email', '').strip()

    success, message = user_manager.update_email(user_id, email)

    if not success:
        return api_error(message, 400)

    return api_success(message=message)

# ==================== MFA API ====================

@app.route('/api/auth/mfa/setup', methods=['POST'])
@login_required
def api_mfa_setup():
    """Generate MFA secret and QR code for setup"""
    user_id = session.get('user_id')
    user = user_manager.get_user(user_id)

    if not user:
        return api_error('User not found', 404)

    # Generate secret
    secret, _ = user_manager.generate_mfa_secret(user_id)

    # Generate QR code
    username = user['username']
    app_name = settings_manager.get_branding().get('siteTitle', 'MServer')

    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name=app_name
    )

    # Generate QR code as base64 image
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to base64
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    import base64
    img_base64 = 'data:image/png;base64,' + base64.b64encode(img_buffer.getvalue()).decode()

    return api_success(secret=secret, qrCode=img_base64, manualEntry=secret)

@app.route('/api/auth/mfa/verify', methods=['POST'])
@login_required
def api_mfa_verify():
    """Verify TOTP code and enable MFA"""
    user_id = session.get('user_id')
    data = request.get_json()

    secret = data.get('secret', '')
    code = data.get('code', '')

    if not secret or not code:
        return api_error('Secret and code are required', 400)

    # Verify the code
    if not user_manager.verify_totp(secret, code):
        return api_error('Invalid verification code', 400)

    # Generate recovery code
    recovery_code = user_manager.generate_recovery_code()

    # Enable MFA
    success, message = user_manager.enable_mfa(user_id, secret, recovery_code)

    if not success:
        return api_error(message, 400)

    return api_success(message='MFA enabled successfully', recoveryCode=recovery_code)

@app.route('/api/auth/mfa/disable', methods=['POST'])
@login_required
def api_mfa_disable():
    """Disable MFA for current user"""
    user_id = session.get('user_id')
    data = request.get_json()

    password = data.get('password', '')

    if not password:
        return api_error('Password required to disable MFA', 400)

    # Verify password
    user = user_manager.get_user(user_id)
    if not check_password_hash(user['password'], password):
        return api_error('Invalid password', 401)

    success, message = user_manager.disable_mfa(user_id)

    if not success:
        return api_error(message, 400)

    return api_success(message=message)

@app.route('/api/auth/mfa/verify-login', methods=['POST'])
@csrf.exempt
@limiter.limit("10 per minute")
def api_mfa_verify_login():
    """Verify MFA code during login"""
    temp_user_id = session.get('temp_user_id')
    mfa_timestamp = session.get('mfa_timestamp')

    if not temp_user_id:
        return api_error('No pending MFA verification', 400)

    # Check for MFA timeout (default 5 minutes; MFA_TIMEOUT_SECONDS in .env)
    if mfa_timestamp:
        mfa_age = time.time() - mfa_timestamp
        if mfa_age > MFA_TIMEOUT_SECONDS:
            session.pop('temp_user_id', None)
            session.pop('mfa_required', None)
            session.pop('mfa_timestamp', None)
            return api_error('MFA verification timeout. Please login again.', 400)

    data = request.get_json()
    code = data.get('code', '')
    use_recovery = data.get('useRecovery', False)

    if not code:
        return api_error('Code is required', 400)

    user = user_manager.get_user(temp_user_id)
    if not user:
        return api_error('User not found', 404)

    verified = False

    if use_recovery:
        # Verify recovery code
        verified = user_manager.verify_recovery_code(temp_user_id, code)
        if verified:
            # Recovery code disables MFA
            message = 'MFA has been disabled using recovery code'
        else:
            return api_error('Invalid recovery code', 401)
    else:
        # Verify TOTP code
        if not user.get('mfaSecret'):
            return api_error('MFA not enabled for this user', 400)

        verified = user_manager.verify_totp(user.get('mfaSecret'), code)
        if not verified:
            return api_error('Invalid verification code', 401)
        message = 'Login successful'

    if verified:
        # Complete login - clear temp session and regenerate to prevent session fixation
        session.clear()
        session.permanent = True
        session['user_id'] = temp_user_id
        session['username'] = user['username']
        session['group_id'] = user.get('groupId')

        return api_success(message=message, user={
            'id': temp_user_id,
            'username': user['username'],
            'groupId': user.get('groupId'),
            'groupName': user.get('groupName'),
        })

    return api_error('Verification failed', 401)


# Forced MFA enrollment at login. When a policy (requireMfaForAll/Admins) mandates
# MFA but the user has none, api_login hands out a limited enrollment session
# (session['mfa_enroll_user_id']) instead of rejecting them. These two endpoints
# are the only thing that session can do, and a successful verify promotes it to a
# full authenticated session.
MFA_ENROLL_TIMEOUT = 600  # 10 minutes

def _get_mfa_enroll_user():
    """Resolve the user behind a pending forced-enrollment session, or (None, error_response)."""
    user_id = session.get('mfa_enroll_user_id')
    ts = session.get('mfa_enroll_timestamp')
    if not user_id:
        return None, api_error('No pending MFA enrollment', 400)
    if ts and time.time() - ts > MFA_ENROLL_TIMEOUT:
        session.pop('mfa_enroll_user_id', None)
        session.pop('mfa_enroll_timestamp', None)
        return None, api_error('Enrollment timed out. Please log in again.', 400)
    user = user_manager.get_user(user_id)
    if not user:
        return None, api_error('User not found', 404)
    return (user_id, user), None

@app.route('/api/auth/mfa/enroll/setup', methods=['POST'])
@csrf.exempt
@limiter.limit("10 per minute")
def api_mfa_enroll_setup():
    """Generate a TOTP secret + QR for a user completing forced MFA enrollment at login."""
    resolved, err = _get_mfa_enroll_user()
    if err:
        return err
    user_id, user = resolved

    secret, _ = user_manager.generate_mfa_secret(user_id)
    app_name = settings_manager.get_branding().get('siteTitle', 'MServer')
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user['username'], issuer_name=app_name)

    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    import base64
    img_base64 = 'data:image/png;base64,' + base64.b64encode(img_buffer.getvalue()).decode()

    return api_success(secret=secret, qrCode=img_base64, manualEntry=secret)

@app.route('/api/auth/mfa/enroll/verify', methods=['POST'])
@csrf.exempt
@limiter.limit("10 per minute")
def api_mfa_enroll_verify():
    """Verify the TOTP code during forced enrollment, enable MFA, and promote to a full session."""
    resolved, err = _get_mfa_enroll_user()
    if err:
        return err
    user_id, user = resolved

    data = request.get_json() or {}
    secret = data.get('secret', '')
    code = data.get('code', '')
    if not secret or not code:
        return api_error('Secret and code are required', 400)
    if not user_manager.verify_totp(secret, code):
        return api_error('Invalid verification code', 400)

    recovery_code = user_manager.generate_recovery_code()
    success, message = user_manager.enable_mfa(user_id, secret, recovery_code)
    if not success:
        return api_error(message, 400)

    # Promote the limited enrollment session into a full authenticated session.
    session.clear()
    session.permanent = True
    session['user_id'] = user_id
    session['username'] = user['username']
    session['group_id'] = user.get('groupId')

    return api_success(message='MFA enabled successfully', recoveryCode=recovery_code)


# ==================== Admin API ====================

@app.route('/api/admin/users', methods=['GET'])
@permission_required('panel.users.view')
def api_get_users():
    """Get all users (admin only). The hidden anti-lockout admin is only included
    when the requester IS that account."""
    _uid, _user = get_current_user()
    include_hidden = bool(_user and _user.get('isAntiLockout'))
    return api_success(users=user_manager.get_all_users(include_anti_lockout=include_hidden))

@app.route('/api/admin/users', methods=['POST'])
@permission_required('panel.users.manage')
def api_create_user():
    """Create a new user (admin only)"""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    group_id = data.get('groupId', group_manager.get_default_group_id())
    email = data.get('email', '').strip()

    if not username or not password:
        return api_error('Username and password required', 400)

    if not group_manager.get_group(group_id):
        return api_error('Invalid group', 400)

    user_id, message = user_manager.create_user(username, password, group_id, email)

    if not user_id:
        return api_error(message, 400)

    return api_success(userId=user_id, message=message)

@app.route('/api/admin/users/<user_id>/approve', methods=['POST'])
@permission_required('panel.users.manage')
def api_approve_user(user_id):
    """Approve a pending user"""
    if user_manager.approve_user(user_id):
        return api_success()
    return api_error('User not found', 404)

def _actor_is_admin():
    """True if the current session user belongs to an admin (wildcard) group."""
    _, actor = get_current_user()
    return bool(actor and group_manager.is_admin_group(actor.get('groupId')))

@app.route('/api/admin/users/<user_id>/group', methods=['PUT'])
@permission_required('panel.users.manage')
def api_update_user_group(user_id):
    """Update user group"""
    data = request.get_json()
    group_id = data.get('groupId')

    if not group_id:
        return api_error('Group ID required', 400)

    if user_id == session.get('user_id'):
        return api_error('Cannot change your own group', 400)

    # Only an admin may grant an admin (wildcard) group, so a delegated
    # user-manager can't mint new admins through another account.
    if group_manager.is_admin_group(group_id) and not _actor_is_admin():
        return api_error('Only an administrator can assign an admin group', 403)

    if user_manager.update_user_group(user_id, group_id):
        # Drop the target's live socket from any room the new group no longer covers.
        _resync_user_rooms(user_id)
        return api_success()
    return api_error('Invalid group or user not found', 400)

@app.route('/api/admin/users/<user_id>/password', methods=['POST'])
@permission_required('panel.users.manage')
def api_reset_user_password(user_id):
    """Reset user password (admin only)"""
    data = request.get_json()
    new_password = data.get('password', '')

    if len(new_password) < 12:
        return api_error('Password must be at least 12 characters', 400)
    if not any(c.isupper() for c in new_password):
        return api_error('Password must contain at least one uppercase letter', 400)
    if not any(c.islower() for c in new_password):
        return api_error('Password must contain at least one lowercase letter', 400)
    if not any(c.isdigit() for c in new_password):
        return api_error('Password must contain at least one number', 400)

    if user_manager.reset_password(user_id, new_password):
        return api_success()
    return api_error('User not found', 404)

@app.route('/api/admin/users/<user_id>/mfa', methods=['DELETE'])
@permission_required('panel.users.manage')
def api_clear_user_mfa(user_id):
    """Clear user MFA (admin only)"""
    # Prevent clearing own MFA
    if user_id == session.get('user_id'):
        return api_error('Cannot clear your own MFA. Use the profile settings instead.', 400)

    success, message = user_manager.disable_mfa(user_id)
    if success:
        return api_success(message=message)
    return api_error(message, 404)

@app.route('/api/admin/users/<user_id>/enable', methods=['POST'])
@permission_required('panel.users.manage')
def api_enable_user_account(user_id):
    """Enable a disabled user account (admin only)"""
    success, message = user_manager.enable_account(user_id)
    if success:
        return api_success(message=message)
    return api_error(message, 404)

@app.route('/api/admin/users/<user_id>', methods=['GET'])
@permission_required('panel.users.view')
def api_get_user(user_id):
    """Get a specific user's details (admin only)"""
    user = user_manager.get_user_by_id(user_id)
    if user:
        return api_success(user=user)
    return api_error('User not found', 404)

@app.route('/api/admin/users/<user_id>/username', methods=['PUT'])
@permission_required('panel.users.manage')
def api_admin_update_username(user_id):
    """Update a user's username (admin only)"""
    data = request.get_json()
    new_username = data.get('username', '').strip()

    if not new_username:
        return api_error('Username required', 400)

    success, message = user_manager.update_username(user_id, new_username)
    if success:
        return api_success(message=message)
    return api_error(message, 400)

@app.route('/api/admin/users/<user_id>/name', methods=['PUT'])
@permission_required('panel.users.manage')
def api_admin_update_name(user_id):
    """Update a user's display name (admin only)"""
    data = request.get_json()
    name = data.get('name', '').strip()

    success, message = user_manager.update_name(user_id, name)
    if success:
        return api_success(message=message)
    return api_error(message, 400)

@app.route('/api/admin/users/<user_id>/email', methods=['PUT'])
@permission_required('panel.users.manage')
def api_admin_update_email(user_id):
    """Update a user's email address (admin only)"""
    data = request.get_json()
    email = data.get('email', '').strip()

    success, message = user_manager.update_email(user_id, email)
    if success:
        return api_success(message=message)
    return api_error(message, 400)

@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@permission_required('panel.users.manage')
def api_delete_user(user_id):
    """Delete a user"""
    # Prevent deleting self
    if user_id == session.get('user_id'):
        return api_error('Cannot delete your own account', 400)

    if user_manager.delete_user(user_id):
        # Drop any live socket the deleted user still holds open from every room.
        _resync_user_rooms(user_id)
        return api_success()
    return api_error('User not found', 404)


# ==================== Admin Server Approval API ====================

@app.route('/api/admin/servers/pending', methods=['GET'])
@permission_required('panel.approvals.manage')
def api_get_pending_servers():
    """Get list of servers pending approval"""
    pending = server_manager.get_pending_servers()
    # Enrich with owner usernames
    for server in pending:
        owner_id = server.get('owner')
        if owner_id:
            user = user_manager.get_user_by_id(owner_id)
            server['owner'] = user.get('username', 'Unknown') if user else 'Unknown'
    return api_success(servers=pending)

@app.route('/api/admin/servers/<server_id>/approve', methods=['POST'])
@permission_required('panel.approvals.manage')
def api_approve_server(server_id):
    """Approve a pending server"""
    if server_manager.approve_server(server_id):
        return api_success()
    return api_error('Server not found', 404)

@app.route('/api/admin/servers/<server_id>/reject', methods=['DELETE'])
@permission_required('panel.approvals.manage')
def api_reject_server(server_id):
    """Reject (delete) a pending server"""
    if server_manager.reject_server(server_id):
        return api_success()
    return api_error('Server not found', 404)


# ==================== Group Management API ====================

@app.route('/api/admin/groups', methods=['GET'])
@permission_required('panel.groups.view')
def api_get_groups():
    """List all permission groups."""
    groups = group_manager.get_all_groups()
    for g in groups:
        g['userCount'] = group_manager.get_user_count(g['id'])
    return api_success(groups=groups)

@app.route('/api/admin/groups/permissions', methods=['GET'])
@permission_required('panel.groups.view')
def api_get_permissions_catalog():
    """Return the full permission catalog for UI rendering."""
    return api_success({
        'permissions': group_manager.ALL_PERMISSIONS,
        'categories': group_manager.PERMISSION_CATEGORIES,
        'labels': group_manager.PERMISSION_LABELS,
    })

@app.route('/api/admin/groups', methods=['POST'])
@permission_required('panel.groups.manage')
def api_create_group():
    """Create a new permission group."""
    data = request.get_json()
    name = (data.get('name') or '').strip()
    if not name:
        return api_error('Group name is required', 400)
    permissions = data.get('permissions', [])
    is_default = bool(data.get('isDefault', False))
    # Only an admin may author an admin (wildcard) group.
    if '*' in (permissions or []) and not _actor_is_admin():
        return api_error('Only an administrator can create an admin group', 403)
    try:
        group_id = group_manager.create_group(name, permissions, is_default)
    except Exception as e:
        if 'UNIQUE' in str(e).upper():
            return api_error('A group with that name already exists', 400)
        raise
    return api_success(groupId=group_id)

@app.route('/api/admin/groups/<group_id>', methods=['GET'])
@permission_required('panel.groups.view')
def api_get_group(group_id):
    """Get a single group's details."""
    group = group_manager.get_group(group_id)
    if not group:
        return api_error('Group not found', 404)
    group = dict(group)
    group['userCount'] = group_manager.get_user_count(group_id)
    return api_success(group=group)

@app.route('/api/admin/groups/<group_id>', methods=['PUT'])
@permission_required('panel.groups.manage')
def api_update_group(group_id):
    """Update a permission group."""
    data = request.get_json()
    permissions = data.get('permissions')
    # Only an admin may grant a group admin (wildcard) permissions.
    if permissions is not None and '*' in permissions and not _actor_is_admin():
        return api_error('Only an administrator can grant admin permissions', 403)
    ok, msg = group_manager.update_group(
        group_id,
        name=data.get('name'),
        permissions=permissions,
        is_default=data.get('isDefault'),
        priority=data.get('priority'),
    )
    if not ok:
        return api_error(msg, 400)
    if permissions is not None:
        # Permission changes can affect every connected member of this group at once.
        _resync_all_connected_rooms()
    return api_success(message=msg)

@app.route('/api/admin/groups/<group_id>', methods=['DELETE'])
@permission_required('panel.groups.manage')
def api_delete_group(group_id):
    """Delete a custom permission group."""
    ok, msg = group_manager.delete_group(group_id)
    if not ok:
        return api_error(msg, 400)
    # Deleting a group reassigns its members elsewhere — resync everyone connected.
    _resync_all_connected_rooms()
    return api_success(message=msg)

@app.route('/api/admin/groups/<group_id>/default', methods=['POST'])
@permission_required('panel.groups.manage')
def api_set_default_group(group_id):
    """Set a group as the default for new registrations."""
    if group_manager.set_default_group(group_id):
        return api_success()
    return api_error('Group not found', 404)


# ==================== Server Sharing API ====================

@app.route('/api/servers/<server_id>/access', methods=['GET'])
@server_access_required
def api_get_server_access(server_id):
    """Get server access info: owner and shared groups."""
    server_config = server_manager.get_server_config(server_id)
    owner_id = server_config.get('owner') if server_config else None
    owner = user_manager.get_user_by_id(owner_id) if owner_id else None
    shared_groups = group_manager.get_server_groups(server_id)
    return api_success({
        'owner': {'id': owner_id, 'username': owner['username'], 'name': owner.get('name', '')} if owner else None,
        'sharedGroups': shared_groups,
    })

@app.route('/api/servers/<server_id>/access', methods=['PUT'])
@server_access_required
def api_update_server_access(server_id):
    """Update server sharing — set which groups have access."""
    user_id, user = get_current_user()
    server_config = server_manager.get_server_config(server_id)
    if not user_manager.user_has_permission(user, 'servers.access.all'):
        if not server_config or server_config.get('owner') != user_id:
            return api_error('Only the server owner can change sharing', 403)
    data = request.get_json()
    group_ids = data.get('groupIds', [])
    group_manager.set_server_groups(server_id, group_ids)
    # Unsharing can revoke access for every connected member of an affected group.
    _resync_all_connected_rooms()
    return api_success()


# ==================== Notification API ====================

@app.route('/api/notifications', methods=['GET'])
@login_required
def api_get_notifications():
    user_id, _ = get_current_user()
    include_dismissed = request.args.get('includeDismissed', 'false').lower() == 'true'
    limit = min(int(request.args.get('limit', 50)), 200)
    return api_success({
        'notifications': notification_manager.get_for_user(user_id, include_dismissed, limit),
        'unreadCount': notification_manager.unread_count(user_id)
    })

@app.route('/api/notifications/unread-count', methods=['GET'])
@login_required
def api_notification_unread_count():
    user_id, _ = get_current_user()
    return api_success(unreadCount=notification_manager.unread_count(user_id))

@app.route('/api/notifications/<notification_id>/read', methods=['POST'])
@login_required
def api_notification_read(notification_id):
    user_id, _ = get_current_user()
    notification_manager.mark_read(notification_id, user_id)
    return api_success()

@app.route('/api/notifications/<notification_id>/dismiss', methods=['POST'])
@login_required
def api_notification_dismiss(notification_id):
    user_id, _ = get_current_user()
    notification_manager.dismiss(notification_id, user_id)
    return api_success()

@app.route('/api/notifications/read-all', methods=['POST'])
@login_required
def api_notifications_read_all():
    user_id, _ = get_current_user()
    notification_manager.mark_all_read(user_id)
    return api_success()

@app.route('/api/notifications/dismiss-all', methods=['POST'])
@login_required
def api_notifications_dismiss_all():
    user_id, _ = get_current_user()
    notification_manager.dismiss_all(user_id)
    return api_success()


# ==================== Pending Action Approval API ====================

@app.route('/api/admin/pending-actions', methods=['GET'])
@permission_required('panel.approvals.manage')
def api_get_pending_actions():
    pending = pending_action_manager.get_pending()
    for action in pending:
        user = user_manager.get_user_by_id(action.get('userId'))
        action['username'] = user.get('username', 'Unknown') if user else 'Unknown'
        action['actionLabel'] = POLICY_ACTION_LABELS.get(action['actionType'], action['actionType'])
    return api_success(actions=pending)

@app.route('/api/admin/pending-actions/<action_id>/approve', methods=['POST'])
@permission_required('panel.approvals.manage')
def api_approve_pending_action(action_id):
    admin_id, _ = get_current_user()
    data = request.get_json(silent=True) or {}
    note = data.get('note', '')

    action = pending_action_manager.approve(action_id, admin_id, note)
    if not action:
        return api_error('Pending action not found', 404)

    result = _execute_approved_action(action)
    return api_success(executionResult=result)

@app.route('/api/admin/pending-actions/<action_id>/reject', methods=['POST'])
@permission_required('panel.approvals.manage')
def api_reject_pending_action(action_id):
    admin_id, _ = get_current_user()
    data = request.get_json(silent=True) or {}
    note = data.get('note', '')

    action = pending_action_manager.reject(action_id, admin_id, note)
    if not action:
        return api_error('Pending action not found', 404)
    return api_success()


def _execute_approved_action(action):
    """Execute the deferred action after admin approval."""
    action_type = action['actionType']
    payload = action['payload']
    user_id = action['userId']
    target_id = action.get('targetId')

    try:
        if action_type == 'serverDelete':
            sid = payload.get('serverId', target_id)
            job_id = job_manager.submit(
                'delete_server', f'Delete: {payload.get("serverName", sid)}',
                params={'serverId': sid, 'deleteFiles': payload.get('deleteFiles', False)},
                created_by=user_id, server_id=sid)
            return {'jobId': job_id}

        if action_type == 'serverEdit':
            safe = {k: v for k, v in payload.items()
                    if k not in ('id', 'created', 'owner', 'serverPath')}
            server_manager.update_server(target_id, **safe)
            return {'updated': True}

        if action_type == 'serverLifecycle':
            act = payload.get('action', 'start')
            sid = payload.get('serverId', target_id)
            if act == 'start':
                ok, msg = server_manager.start_server(sid)
            elif act == 'stop':
                ok, msg = server_manager.stop_server(sid)
            elif act == 'restart':
                ok, msg = server_manager.restart_server(sid)
            elif act == 'kill':
                ok, msg = server_manager.kill_server(sid)
            else:
                return {'error': f'Unknown lifecycle action: {act}'}
            return {'success': ok, 'message': msg}

        if action_type == 'backupCreate':
            sid = payload.get('serverId', target_id)
            job_params = {k: v for k, v in payload.items() if k != 'serverName'}
            cfg = server_manager.get_server_config(sid) or {}
            job_id = job_manager.submit(
                'backup', f'Backup: {cfg.get("name", sid)}',
                params=job_params, created_by=user_id, server_id=sid)
            return {'jobId': job_id}

        if action_type == 'backupDelete':
            sid = payload.get('serverId', target_id)
            backup_name = payload.get('backupName', '')
            backup_path = (BACKUPS_DIR / sid / backup_name).resolve()
            if str(backup_path).startswith(str(BACKUPS_DIR.resolve())) and backup_path.exists():
                backup_path.unlink()
                return {'deleted': True}
            return {'error': 'Backup not found or invalid path'}

        if action_type == 'fileUpload':
            return {'note': 'File uploads must be re-submitted after approval.'}

        if action_type == 'modManagement':
            sid = payload.get('serverId', target_id)
            act = payload.get('action')
            mod_type = payload.get('modType', 'plugins')
            fname = payload.get('filename', '')
            server_path = server_manager.get_server_path(sid)
            mod_dir = server_path / mod_type

            if act == 'enable':
                disabled_path = mod_dir / fname
                enabled_name = fname.rsplit('.disabled', 1)[0]
                if disabled_path.exists():
                    disabled_path.rename(mod_dir / enabled_name)
                    return {'enabled': enabled_name}
            elif act == 'disable':
                mod_path = mod_dir / fname
                if mod_path.exists():
                    mod_path.rename(mod_dir / (fname + '.disabled'))
                    return {'disabled': fname + '.disabled'}
            elif act == 'delete':
                mod_path = mod_dir / fname
                if mod_path.exists():
                    mod_path.unlink()
                    return {'deleted': True}
            elif act == 'upload':
                return {'note': 'Mod uploads must be re-submitted after approval.'}
            return {'error': f'Mod action {act} could not be completed'}

        if action_type == 'playerManagement':
            return {'note': 'Player management actions must be re-submitted after approval.'}

        return {'note': f'Action type {action_type} executed.'}

    except Exception as e:
        app.logger.error(f'Error executing approved action {action["id"]}: {e}')
        return {'error': str(e)}


# ==================== Policy Settings API ====================

@app.route('/api/settings/policies', methods=['GET'])
@permission_required('panel.settings.manage')
def api_get_policies():
    return api_success({'policies': settings_manager.get_policies()})

@app.route('/api/settings/policies', methods=['PUT'])
@permission_required('panel.settings.manage')
def api_update_policies():
    data = request.get_json()
    if not data or not isinstance(data, dict):
        return api_error('Invalid data', 400)
    updated = settings_manager.update_policies(data)
    return api_success({'policies': updated})


# ==================== Public API (No Auth Required) ====================

@app.route('/api/public/servers', methods=['GET'])
def api_public_servers():
    """Get server status for public view — name, status, address, owner."""
    servers = server_manager.get_servers_list()
    game_hostname = settings_manager.get_branding().get('gameHostname', '')
    public_servers = []
    for s in servers:
        sid = s.get('id', '')
        server_dir = SERVERS_DIR / sid if sid else None
        managed = {}
        if server_dir and server_dir.exists():
            managed = server_manager._read_managed_conf(server_dir)
        if managed.get('PublicVisible', 'true').lower() == 'false':
            continue
        port = managed.get('Port', '25565')
        address = f'{game_hostname}:{port}' if game_hostname else ''
        owner_name = ''
        owner_id = s.get('owner')
        if owner_id:
            owner_user = user_manager.get_user_by_id(owner_id)
            if owner_user:
                owner_name = owner_user.get('name') or owner_user.get('username', '')
        public_servers.append({
            'name': s['name'],
            'running': s['running'],
            'address': address,
            'ownerName': owner_name,
            'serverType': s.get('serverType'),
            'version': s.get('version'),
        })
    return api_success(servers=public_servers)


# ==================== JAR/Version API ====================

@app.route('/api/default-server-path', methods=['GET'])
@login_required
def get_default_server_path():
    """Get the default server installation path"""
    return api_success(path=str(SERVERS_DIR))


# ==================== Server Management API ====================

@app.route('/api/servers', methods=['GET'])
@login_required
def get_servers():
    """Get list of servers accessible to the current user"""
    user_id, user = get_current_user()
    all_servers = server_manager.get_servers_list()

    if user_manager.user_has_permission(user, 'servers.access.all'):
        return api_success({'servers': all_servers})

    user_group_id = user.get('groupId')
    user_servers = []
    for s in all_servers:
        if s.get('owner') == user_id:
            user_servers.append(s)
        elif user_group_id and user_group_id in group_manager.get_server_group_ids(s.get('id', '')):
            user_servers.append(s)
    return api_success({'servers': user_servers})


def _generate_server_properties(custom_properties, server_name='A Minecraft Server'):
    """Generate a server.properties file with custom properties merged with defaults"""
    # Default server.properties template with common settings
    default_properties = {
        'server-port': '25565',
        'max-players': '20',
        'gamemode': 'survival',
        'difficulty': 'easy',
        'motd': f'{server_name}, Powered by MServer',
        'level-name': 'world',
        'online-mode': 'true',
        'white-list': 'false',
        'enable-command-block': 'false',
        'spawn-protection': '16',
        'view-distance': '10',
        'simulation-distance': '10',
        'pvp': 'true',
        'allow-flight': 'false',
        'allow-nether': 'true',
        'spawn-npcs': 'true',
        'spawn-animals': 'true',
        'spawn-monsters': 'true',
        'generate-structures': 'true',
        'max-world-size': '29999984',
        'enable-rcon': 'false',
        'enable-query': 'false',
        'enable-status': 'true',
        'enforce-whitelist': 'false',
        'network-compression-threshold': '256',
        'sync-chunk-writes': 'true',
    }
    
    # Merge custom properties (convert all values to strings). Booleans are
    # rendered lowercase so the file reads like a hand-written server.properties
    # rather than Python's 'True'/'False'.
    for key, value in custom_properties.items():
        if isinstance(value, bool):
            default_properties[key] = 'true' if value else 'false'
        else:
            default_properties[key] = str(value)
    
    # Truncate motd if needed (59 char limit)
    if 'motd' in default_properties and len(default_properties['motd']) > 59:
        default_properties['motd'] = default_properties['motd'][:59]
    
    # Build the properties file content
    lines = [
        '# Minecraft server properties',
        f'# Generated by MServer',
        ''
    ]
    
    for key, value in sorted(default_properties.items()):
        lines.append(f'{key}={value}')

    return '\n'.join(lines) + '\n'


def _bedrock_int_property(properties, key, default, minimum, maximum):
    """Read a numeric Bedrock property from a request body, clamped to its allowed range"""
    try:
        value = int(str(properties.get(key, default)).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


def _bedrock_level_name(raw, default='Bedrock level'):
    """Sanitize level-name — it becomes a directory under worlds/ and a properties value"""
    name = re.sub(r'[\x00-\x1f\x7f]', ' ', str(raw or ''))
    name = name.replace('/', '').replace('\\', '').strip()
    if not name or name.strip('.') == '':
        return default
    return name[:64]


@app.route('/api/servers', methods=['POST'])
@permission_required('servers.create')
def create_server():
    """Create a new server"""
    user_id, user = get_current_user()
    
    data = request.get_json()
    name = data.get('name', 'New Server')
    server_path = data.get('serverPath', '')
    # Reject server paths outside SERVERS_DIR — a user-controlled base directory
    # would let the per-server file routes read/write anywhere on disk (RCE).
    if server_path and not is_server_path_allowed(server_path):
        return api_error('Invalid server path: must be within the servers directory', 400)
    java_args = data.get('javaArgs', DEFAULT_JAVA_ARGS)
    category = data.get('category', 'unmodded')
    executable = 'server.sh' if category == 'bedrock' else 'server.jar'
    server_engine = data.get('serverEngine')  # New: engine (paper, folia, etc.)
    server_type = data.get('serverType') or server_engine  # Backward compat
    version = data.get('version')
    download_jar = data.get('downloadJar', False)
    server_properties = data.get('serverProperties', {})  # Server properties from form
    
    # Check action policy for server creation
    is_admin = group_manager.is_admin_group(user.get('groupId'))
    policy = settings_manager.get_policy('serverCreate')
    approved = is_admin or policy != 'require_approval'

    # Check for duplicate port and create the server + server.properties under a
    # single lock so two concurrent requests can't both pass the "port is free"
    # check and then each write the same port to a different server (issue #11).
    with server_manager.port_lock:
        if 'server-port' in server_properties:
            new_port = str(server_properties['server-port'])
            existing_ports = server_manager.get_all_server_ports()

            for other_server_id, port in existing_ports.items():
                if port == new_port:
                    other_server_config = server_manager.get_server_config(other_server_id)
                    other_server_name = other_server_config.get('name', 'Unknown Server') if other_server_config else 'Unknown Server'
                    return api_error(f'Port {new_port} is already in use by server: {other_server_name}', 400)

        # Create server locally. This is fast (DB row + a local JAR copy + a couple of
        # config files) and is invoked from several frontend wizards that expect a
        # synchronous {serverId}, so it stays inline rather than going on the job queue.
        server_id = server_manager.create_server(
            name=name,
            server_path=server_path,
            executable=executable,
            java_args=java_args,
            server_type=server_type,
            version=version,
            owner=user_id,
            approved=approved,
            category=category,
            port=server_properties.get('server-port')
        )

        # Get server directory for creating files
        server_config = server_manager.get_server_config(server_id)
        server_dir = Path(server_config['serverPath'])

        # Handle Bedrock server setup
        if category == 'bedrock':
            # server.properties is written by setup-bedrock after ZIP extraction
            response = {'success': True, 'serverId': server_id}
            if not approved:
                response['pendingApproval'] = True
                response['message'] = 'Server created and pending admin approval'
            if not is_admin and policy == 'notify':
                notification_manager.notify_admins(
                    'action_notify', f'Server created — {user.get("username", "Unknown")}',
                    f'{user.get("username", "Unknown")} created Bedrock server "{name}".',
                    ref_type='server', ref_id=server_id)
            return jsonify(response)

        # Copy JAR from serverexecutables if requested (Java servers only)
        if download_jar and server_type and version:
            jar_path = server_dir / executable

            # Copy the local JAR file to the server directory
            success, result = jar_manager.copy_jar_to_server(server_type, version, jar_path)
            if not success:
                return jsonify({
                    'success': True,
                    'serverId': server_id,
                    'warning': f'Server created but JAR copy failed: {result}'
                })

        # Create eula.txt for convenience
        eula_path = server_dir / 'eula.txt'
        eula_path.write_text('# By setting this to TRUE, you agree to the Minecraft EULA\neula=false\n')

        # Create server.properties with the provided settings
        if server_properties:
            properties_path = server_dir / 'server.properties'
            properties_content = _generate_server_properties(server_properties, name)
            properties_path.write_text(properties_content, encoding='utf-8')

    response = {'success': True, 'serverId': server_id}
    if not approved:
        response['pendingApproval'] = True
        response['message'] = 'Server created and pending admin approval'
    if not is_admin and policy == 'notify':
        notification_manager.notify_admins(
            'action_notify', f'Server created — {user.get("username", "Unknown")}',
            f'{user.get("username", "Unknown")} created server "{name}".',
            ref_type='server', ref_id=server_id)

    return jsonify(response)


@app.route('/api/servers/<server_id>/setup-bedrock', methods=['POST'])
@server_access_required
def setup_bedrock_server(server_id):
    """Download and set up a Bedrock server: download zip, extract, write server.properties, set permissions"""
    server_config = server_manager.get_server_config(server_id)
    if not server_config:
        return api_error('Server not found', 404)

    if server_config.get('category') != 'bedrock':
        return api_error('Server is not a Bedrock server', 400)

    server_dir = Path(server_config['serverPath'])
    progress_id = str(uuid.uuid4())
    
    # Accept server properties and name from request body
    data = request.get_json(silent=True) or {}
    server_properties = data.get('serverProperties', {})
    server_name = data.get('serverName', server_config.get('name', 'Bedrock Server'))
    
    # Initialize progress
    jar_bucket.set_progress(progress_id, {
        'status': 'initializing',
        'message': 'Starting Bedrock server download...',
        'kind': 'bedrock',
        'serverId': server_id,
        'progress': 0,
        'step': 1
    })

    def do_bedrock_setup():
        zip_path = server_dir / 'bedrock_server.zip'
        try:
            # Step 2: Fetch download URL
            jar_bucket.update_progress(
                progress_id,
                status='downloading',
                message='Fetching Bedrock server download URL...',
                progress=5,
                step=2,
            )

            download_url, _ = jar_bucket._fetch_bedrock_download_url()
            if not download_url:
                jar_bucket.update_progress(
                    progress_id,
                    status='error',
                    error='Could not get Bedrock server download URL',
                )
                return

            # Download the zip
            jar_bucket.update_progress(
                progress_id,
                status='downloading',
                message='Downloading latest Bedrock server...',
                progress=10,
                step=2,
            )
            
            # (connect, read) timeout — read applies per chunk, so a stalled
            # connection fails in seconds instead of holding the worker for
            # the full download budget (issue #13).
            response = requests.get(download_url, stream=True, timeout=(10, 30), headers={
                'User-Agent': 'Mozilla/5.0 (Linux; x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
            })
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0

            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size:
                            pct = 10 + int((downloaded / total_size) * 70)  # 10-80%
                            jar_bucket.update_progress(
                                progress_id,
                                status='downloading',
                                message=f'Downloading... ({downloaded // 1024 // 1024} MB / {total_size // 1024 // 1024} MB)',
                                progress=pct,
                                total=total_size,
                                downloaded=downloaded,
                                step=2,
                            )

            # Step 3: Extract the zip
            jar_bucket.update_progress(
                progress_id,
                status='downloading',
                message='Extracting Bedrock server files...',
                progress=85,
                step=3,
            )
            
            # Preserve existing user files
            preserve_files = {'server.properties', 'permissions.json', 'allowlist.json', 'worlds',
                              BEDROCK_XUID_CACHE, BEDROCK_BANS_FILE}
            
            def is_preserved(name):
                return (any(name.startswith(pf) for pf in preserve_files)
                        and (server_dir / name).exists())

            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                safe_extractall(zip_ref, server_dir, skip=is_preserved)
            
            # Set executable permissions on Linux
            if os.name != 'nt':
                bedrock_exe = server_dir / 'bedrock_server'
                if bedrock_exe.exists():
                    os.chmod(str(bedrock_exe), 0o744)
            
            # Create server.sh launcher wrapper
            server_sh = server_dir / 'server.sh'
            with open(str(server_sh), 'w') as f:
                f.write('#!/bin/bash\n')
                f.write('cd "$(dirname "$0")"\n')
                f.write('LD_LIBRARY_PATH=. ./bedrock_server\n')
            if os.name != 'nt':
                os.chmod(str(server_sh), 0o755)
            
            # Delete the zip
            zip_path.unlink()
            
            # Step 4: Write server.properties with user-selected settings
            jar_bucket.update_progress(
                progress_id,
                status='downloading',
                message='Writing server.properties...',
                progress=92,
                step=4,
            )
            
            properties_path = server_dir / 'server.properties'
            bedrock_props = {
                'server-name': server_name,
                'server-port': server_properties.get('server-port', 19132),
                'server-portv6': server_properties.get('server-portv6', 19133),
                'max-players': server_properties.get('max-players', 10),
                'gamemode': server_properties.get('gamemode', 'survival'),
                'force-gamemode': 'true' if server_properties.get('force-gamemode') else 'false',
                'difficulty': server_properties.get('difficulty', 'easy'),
                'level-seed': server_properties.get('level-seed', ''),
                'allow-cheats': 'false',
                'online-mode': 'true',
                # Bedrock's documented key is 'allow-list'; 'white-list' is accepted
                # here so older API clients keep working (issue #51)
                'allow-list': 'true' if server_properties.get(
                    'allow-list', server_properties.get('white-list')) else 'false',
                # Allowed ranges come from the Bedrock server.properties documentation
                'view-distance': _bedrock_int_property(server_properties, 'view-distance', 32, 4, 255),
                'tick-distance': _bedrock_int_property(server_properties, 'tick-distance', 4, 4, 12),
                'player-idle-timeout': _bedrock_int_property(server_properties, 'player-idle-timeout', 30, 0, 10080),
                'level-name': _bedrock_level_name(server_properties.get('level-name')),
                'default-player-permission-level': 'member',
            }
            lines = [
                '# Bedrock server properties',
                '# Generated by MServer',
                '',
            ]
            for key, value in bedrock_props.items():
                # Strip control chars so a value can't inject extra properties lines
                lines.append(f'{key}=' + re.sub(r'[\x00-\x1f\x7f]', '', str(value)))
            properties_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
            
            # Update server config with the correct executable
            server_manager.update_server(server_id, executable='server.sh', version='latest')
            
            jar_bucket.update_progress(
                progress_id,
                status='complete',
                message='Bedrock server setup complete!',
                progress=100,
                step=5,
                success=True,
            )

        except Exception as e:
            if zip_path.exists():
                zip_path.unlink()

            jar_bucket.update_progress(
                progress_id,
                status='error',
                error=f'Bedrock setup failed: {str(e)}',
            )
    
    thread = threading.Thread(target=do_bedrock_setup, daemon=True)
    thread.start()

    return api_success(progressId=progress_id, message='Starting Bedrock server setup...')


@app.route('/api/servers/import', methods=['POST'])
@permission_required('servers.create')
@limiter.limit("5 per 15 minutes")
def import_server():
    """Import a server from a ZIP file"""
    user_id, user = get_current_user()
    
    if 'file' not in request.files:
        return api_error('No file uploaded', 400)

    file = request.files['file']
    if not file.filename.endswith('.zip'):
        return api_error('File must be a ZIP archive', 400)

    name = request.form.get('name', 'Imported Server')
    executable_name = request.form.get('executableName', '').strip()
    java_args = request.form.get('javaArgs', DEFAULT_JAVA_ARGS)
    category = request.form.get('category', 'unmodded')
    port = request.form.get('port', '25565').strip()
    engine = request.form.get('engine', '').strip() or None
    
    # Check action policy for server creation
    is_admin = group_manager.is_admin_group(user.get('groupId'))
    policy = settings_manager.get_policy('serverCreate')
    approved = is_admin or policy != 'require_approval'

    # Save uploaded file temporarily
    filename = secure_filename(file.filename)
    temp_path = UPLOADS_DIR / filename
    
    try:
        file.save(str(temp_path))
        
        success, result = server_manager.import_server_from_zip(
            name, temp_path, java_args,
            executable_name=executable_name or None,
            owner=user_id,
            approved=approved,
            category=category,
            port=port,
            engine=engine
        )
        
        if success:
            response = {'success': True, 'serverId': result}
            if not approved:
                response['pendingApproval'] = True
                response['message'] = 'Server imported and pending admin approval'
            if not is_admin and policy == 'notify':
                notification_manager.notify_admins(
                    'action_notify', f'Server imported — {user.get("username", "Unknown")}',
                    f'{user.get("username", "Unknown")} imported server "{name}".',
                    ref_type='server', ref_id=result)
            return jsonify(response)
        else:
            return api_error(result, 400)
    except Exception as e:
        return api_error(f'Import failed: {str(e)}', 500)
    finally:
        # Clean up temp file
        if temp_path.exists():
            temp_path.unlink()

@app.route('/api/servers/<server_id>/import-world', methods=['POST'])
@server_access_required
@limiter.limit("5 per 15 minutes")
def import_world(server_id):
    """Import a world ZIP into an existing server, placing it as the world/ folder"""
    if 'file' not in request.files:
        return api_error('No file uploaded', 400)

    file = request.files['file']
    if not file.filename.endswith('.zip'):
        return api_error('File must be a ZIP archive', 400)

    server_config = server_manager.get_server_config(server_id)
    if not server_config:
        return api_error('Server not found', 404)

    server_path = Path(server_config['serverPath']).resolve()
    filename = secure_filename(file.filename)
    temp_path = UPLOADS_DIR / filename

    try:
        file.save(str(temp_path))

        with zipfile.ZipFile(temp_path, 'r') as zipf:
            _infos = zipf.infolist()
            names = [i.filename for i in _infos]

            # Determine the structure of the world ZIP
            top_level_items = set()
            for n in names:
                part = n.split('/')[0]
                if part:
                    top_level_items.add(part)

            if 'level.dat' in names:
                # World files are at ZIP root → extract into world/ subfolder
                world_dir = server_path / 'world'
                if world_dir.exists():
                    shutil.rmtree(world_dir)
                world_dir.mkdir()
                # Reject traversal/symlink members and members whose resolved
                # target would land outside world_dir (issue #14) before writing
                # anything — a substring '..' check alone isn't sufficient.
                try:
                    validate_zip_members(zipf, world_dir)
                except ValueError as e:
                    shutil.rmtree(world_dir, ignore_errors=True)
                    return api_error(f'Invalid ZIP: {e}', 400)
                for member in names:
                    if member.endswith('/'):
                        continue
                    target = world_dir / member
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zipf.open(member) as src, open(target, 'wb') as dst:
                        shutil.copyfileobj(src, dst)
            else:
                # Extract to a temp directory, then locate the world folder
                tmp_dir = server_path / '_world_import_tmp'
                if tmp_dir.exists():
                    shutil.rmtree(tmp_dir)
                tmp_dir.mkdir()
                try:
                    validate_zip_members(zipf, tmp_dir)
                except ValueError as e:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                    return api_error(f'Invalid ZIP: {e}', 400)
                for _info in _infos:
                    if not _info.filename.endswith('/'):
                        zipf.extract(_info, tmp_dir)

                # Find a directory that contains level.dat
                world_found = None
                for candidate in tmp_dir.iterdir():
                    if candidate.is_dir() and (candidate / 'level.dat').exists():
                        world_found = candidate
                        break

                if world_found:
                    target_world = server_path / 'world'
                    if target_world.exists():
                        shutil.rmtree(target_world)
                    shutil.move(str(world_found), str(target_world))
                elif len(top_level_items) == 1:
                    # Single top-level directory — use it as the world
                    single = tmp_dir / list(top_level_items)[0]
                    target_world = server_path / 'world'
                    if target_world.exists():
                        shutil.rmtree(target_world)
                    shutil.move(str(single), str(target_world))
                else:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                    return api_error('Could not locate a valid world in the ZIP (level.dat not found)', 400)

                shutil.rmtree(tmp_dir, ignore_errors=True)

        return api_success()
    except zipfile.BadZipFile:
        return api_error('Invalid or corrupted ZIP file', 400)
    except Exception as e:
        return api_error(str(e), 500)
    finally:
        if temp_path.exists():
            temp_path.unlink()

@app.route('/api/servers/<server_id>/upload-jar', methods=['POST'])
@server_access_required
@limiter.limit("10 per 15 minutes")
def upload_custom_jar(server_id):
    """Upload a custom JAR file for a server"""
    if 'file' not in request.files:
        return api_error('No file uploaded', 400)

    file = request.files['file']
    if not file.filename.endswith('.jar'):
        return api_error('File must be a JAR file', 400)

    server_config = server_manager.get_server_config(server_id)
    if not server_config:
        return api_error('Server not found', 404)

    server_path = Path(server_config['serverPath'])
    filename = secure_filename(file.filename)
    jar_path = server_path / filename

    try:
        file.save(str(jar_path))

        rejected = reject_if_not_zip(jar_path)
        if rejected:
            return rejected

        # Update server config to use this JAR
        server_manager.update_server(server_id, executable=filename, serverType='custom')

        return api_success(executable=filename)
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>', methods=['GET'])
@server_access_required
def get_server(server_id):
    """Get a specific server's configuration"""
    config = server_manager.get_server_config(server_id)
    if not config:
        return api_error('Server not found', 404)

    instance = server_manager.servers.get(server_id)
    is_running = instance is not None and instance.is_running()
    status = instance.get_status().value if instance else ServerStatus.STOPPED.value

    # Enrich with managed.conf Engine/Version (authoritative source)
    server_dir = Path(config.get('serverPath', ''))
    managed = server_manager._read_managed_conf(server_dir) if server_dir.exists() else {}
    engine = managed.get('Engine') or config.get('serverType')
    version = managed.get('Version') or config.get('version')
    if engine and engine.lower() == 'imported':
        engine = None

    return api_success({
        'id': server_id,
        'running': is_running,
        'status': status,
        **config,
        'serverType': engine,
        'version': version
    })

@app.route('/api/servers/<server_id>', methods=['PUT'])
@server_access_required
def update_server(server_id):
    """Update a server's configuration"""
    user_id, user = get_current_user()
    data = request.get_json()

    # Don't allow updating certain fields
    data.pop('id', None)
    data.pop('created', None)
    data.pop('owner', None)
    data.pop('serverPath', None)

    def do_update():
        if server_manager.update_server(server_id, **data):
            return jsonify({'success': True}), 200
        return api_error('Server not found', 404)

    cfg = server_manager.get_server_config(server_id)
    server_name = cfg.get('name', server_id) if cfg else server_id
    result, status = check_action_policy(
        'serverEdit', user, data, target_id=server_id,
        execute_fn=do_update,
        description=f'{user.get("username","Unknown")} edited server "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status

@app.route('/api/servers/<server_id>', methods=['DELETE'])
@server_access_required
def delete_server(server_id):
    """Queue server deletion on the unified job queue (rmtree can be slow)."""
    user_id, user = get_current_user()
    delete_files = request.args.get('deleteFiles', 'false').lower() == 'true'

    cfg = server_manager.get_server_config(server_id)
    if not cfg:
        return api_error('Server not found', 404)
    server_name = cfg.get('name', server_id)

    def do_delete():
        job_id = job_manager.submit(
            'delete_server', f'Delete: {server_name}',
            params={'serverId': server_id, 'deleteFiles': delete_files},
            created_by=user_id, server_id=server_id)
        return jsonify({'started': True, 'jobId': job_id}), 202

    result, status = check_action_policy(
        'serverDelete', user,
        {'serverId': server_id, 'deleteFiles': delete_files, 'serverName': server_name},
        target_id=server_id, execute_fn=do_delete,
        description=f'{user.get("username","Unknown")} deleted server "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status

@app.route('/api/servers/<server_id>/managed', methods=['GET'])
@server_access_required
def check_managed(server_id):
    """Check if a server has managed.conf and validate its fields"""
    is_managed = server_manager.is_managed(server_id)

    if not is_managed:
        return api_success({'managed': False, 'valid': False, 'missingFields': ['managed.conf file not found']})

    # Validate managed.conf
    is_valid, missing_fields = server_manager.validate_managed_conf(server_id)

    # Get current managed.conf data
    server_config = server_manager.get_server_config(server_id)
    server_dir = Path(server_config.get('serverPath', ''))
    managed_data = server_manager._read_managed_conf(server_dir)

    return api_success({
        'managed': True,
        'valid': is_valid,
        'missingFields': missing_fields,
        'data': managed_data
    })

@app.route('/api/servers/<server_id>/managed/enable', methods=['POST'])
@server_access_required
def enable_management(server_id):
    """Create managed.conf for a server"""
    success, message = server_manager.enable_management(server_id)
    if success:
        return api_success({'message': message})
    return api_error(message, 400)

@app.route('/api/servers/<server_id>/managed/update', methods=['POST'])
@server_access_required
def update_managed_conf(server_id):
    """Update fields in managed.conf"""
    data = request.get_json()

    if not data:
        return api_error('No data provided', 400)

    server_config = server_manager.get_server_config(server_id)
    if not server_config:
        return api_error('Server not found', 404)

    server_dir = Path(server_config.get('serverPath', ''))
    managed_conf = server_manager._read_managed_conf(server_dir)

    # Update provided fields
    for field, value in data.items():
        if field in server_manager.MANAGED_CONF_REQUIRED_FIELDS or field == 'EULAAcceptedAt':
            managed_conf[field] = value

    server_manager._write_managed_conf(server_dir, managed_conf)

    return api_success({'message': 'Configuration updated'})


# ==================== Canned Commands API ====================

@app.route('/api/servers/<server_id>/canned-commands', methods=['GET'])
@server_access_required
def get_canned_commands(server_id):
    """Return the canned_commands.conf for a server, creating it if missing."""
    server_path = server_manager.get_server_path(server_id)
    conf_path = server_path / 'canned_commands.conf'
    server_manager._ensure_canned_commands_conf(server_path)
    try:
        data = json.loads(conf_path.read_text(encoding='utf-8'))
        # Migrate pre-rename (snake_case) files written before issue #29's camelCase pass
        data = {
            'autoExecute': data.get('autoExecute', data.get('auto_execute', False)),
            'commands': [
                {'cmdName': c.get('cmdName', c.get('cmd_name', '')), 'cmd': c.get('cmd', '')}
                for c in data.get('commands', [])
            ],
        }
        return api_success(data)
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/canned-commands', methods=['PUT'])
@server_access_required
def save_canned_commands(server_id):
    """Save (overwrite) the canned_commands.conf for a server."""
    server_path = server_manager.get_server_path(server_id)
    body = request.get_json()
    if body is None:
        return api_error('Invalid JSON', 400)

    auto_execute = bool(body.get('autoExecute', False))
    raw_commands = body.get('commands', [])

    # Sanitise each command entry
    commands = []
    for item in raw_commands:
        cmd_name = str(item.get('cmdName', '')).strip()[:25]
        cmd = str(item.get('cmd', '')).strip()
        if cmd_name and cmd:
            commands.append({'cmdName': cmd_name, 'cmd': cmd})

    conf_data = {'autoExecute': auto_execute, 'commands': commands}
    conf_path = server_path / 'canned_commands.conf'
    try:
        conf_path.write_text(json.dumps(conf_data, indent=2), encoding='utf-8')
        return api_success()
    except Exception as e:
        return api_error(str(e), 500)


@app.route('/api/servers/<server_id>/change-version', methods=['POST'])
@server_access_required
def change_server_version(server_id):
    """Change the server version.

    Era rules
    ---------
    Modern (26.1+): may only upgrade, never downgrade.  Cross-era moves blocked.
    Legacy (<=1.21.11): may upgrade/downgrade within the legacy tier only.
      Downgrades are allowed but include a warning in the response.
      Upgrades are capped at MC_LEGACY_MAX (1.21.11).
      Cannot cross to the modern era — create a new server instead.
    """
    data = request.get_json()

    if not data:
        return api_error('No data provided', 400)

    new_version = data.get('version')

    if not new_version:
        return api_error('Version is required', 400)

    server_config = server_manager.get_server_config(server_id)
    if not server_config:
        return api_error('Server not found', 404)

    server_dir = Path(server_config.get('serverPath', ''))
    managed_conf = server_manager._read_managed_conf(server_dir)
    current_version = managed_conf.get('Version', server_config.get('version', ''))

    current_modern = mc_version_is_modern(current_version)
    new_modern = mc_version_is_modern(new_version)

    # --- Modern -> Legacy: blocked (the new world storage format is one-way) ---
    if current_modern and not new_modern:
        return api_error(
            f'Cannot downgrade a modern (26.1+) server to legacy version {new_version}. '
            f'The new world storage format is not backwards-compatible. '
            f'Create a new server if you need a legacy version.', 400)

    # --- Legacy -> Legacy: cap upgrades at the legacy tier max ---
    # (Crossing to a modern version is allowed below and is NOT subject to this cap.)
    if not current_modern and not new_modern and compare_mc_versions(new_version, MC_LEGACY_MAX) > 0:
        return api_error(
            f'Legacy servers cannot be upgraded beyond {MC_LEGACY_MAX} within the legacy tier. '
            f'Select a modern (26.1+) version to migrate to the new world format.', 400)

    # --- Determine warnings (informational only; these do NOT block the change) ---
    # world_conversion_warning: ONLY a Legacy -> Modern crossing triggers the one-way
    #   world-storage conversion. Same-generation changes never show it.
    # downgrade_warning: a same-generation downgrade (legacy->legacy or modern->modern)
    #   warns about feature differences / possible world corruption.
    world_conversion_warning = None
    downgrade_warning = None
    if not current_modern and new_modern:
        world_conversion_warning = (
            f'Minecraft {new_version} uses a new world storage format. Upgrading from '
            f'{current_version} will automatically convert your world the next time the '
            f'server starts, but this conversion is one-way and cannot be undone. '
            f'A backup has been created automatically.'
        )
    elif compare_mc_versions(new_version, current_version) < 0:
        downgrade_warning = (
            f'Downgrading from {current_version} to {new_version}: newer world data and '
            f'features may be incompatible with the older version and can cause feature '
            f'loss or world corruption. A backup has been created automatically.'
        )

    # Check if server is running
    instance = server_manager.servers.get(server_id)
    if instance and instance.is_running():
        return api_error('Server must be stopped before changing version', 400)
    
    # Always create a safety backup before changing versions. World conversions
    # (Legacy -> Modern) are one-way and downgrades can corrupt data, so a backup
    # is mandatory — if it fails, abort the version change.
    try:
        # Create backup directory for this server
        backup_dir = BACKUPS_DIR / server_id
        backup_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y-%m-%dT%H-%M-%S')
        backup_name = f'pre-version-change-{timestamp}.zip'
        backup_path = backup_dir / backup_name

        # Create the backup
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED,
                             compresslevel=6) as zipf:
            file_count = 0
            for root, dirs, files in os.walk(server_dir):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(server_dir)
                    zipf.write(file_path, arcname)
                    file_count += 1
            zipf.writestr('backup_manifest.json', json.dumps({
                'type': 'full', 'created': timestamp, 'file_count': file_count
            }))

        bk_size = backup_path.stat().st_size
        ok, checksum, _ = verify_backup_file(backup_path)
        backup_scheduler._log_backup_event(server_id, {
            'type': 'pre-version-change',
            'backupName': backup_name,
            'size': bk_size,
            'is_incremental': False,
            'compressionLevel': 6,
            'verified': ok,
            'checksum': checksum,
            'success': True
        })
    except Exception as e:
        return api_error(f'Failed to create mandatory pre-change backup: {str(e)}', 500)

    # Copy the new version JAR into the server directory (download first if needed)
    engine = managed_conf.get('Engine', server_config.get('serverType', 'vanilla'))
    server_type = engine.lower() if engine else 'vanilla'
    is_bedrock = server_config.get('category') == 'bedrock'
    executable = server_config.get('executable', 'server.sh' if is_bedrock else 'server.jar')
    jar_dest = server_dir / executable

    if not is_bedrock:
        # Try local copy first; if the JAR isn't cached, download it from upstream
        jar_ok, jar_msg = jar_manager.copy_jar_to_server(server_type, new_version, jar_dest)
        if not jar_ok:
            dl_result = jar_bucket.download_jar(server_type, new_version)
            if not dl_result.get('success'):
                return api_error(
                    f'Failed to download {server_type} {new_version} JAR: {dl_result.get("error", "Unknown error")}', 500)
            # Now copy the freshly-downloaded JAR
            jar_ok, jar_msg = jar_manager.copy_jar_to_server(server_type, new_version, jar_dest)
            if not jar_ok:
                return api_error(f'Downloaded JAR but failed to copy to server: {jar_msg}', 500)

    # Update version in DB and managed.conf
    server_manager.update_server(server_id, version=new_version)

    # Update version in managed.conf
    managed_conf['Version'] = new_version
    server_manager._write_managed_conf(server_dir, managed_conf)
    
    response = {
        'success': True,
        'message': f'Version updated from {current_version} to {new_version}',
        'oldVersion': current_version,
        'newVersion': new_version,
        'backupCreated': True,
    }
    # Surface at most one warning: the one-way conversion notice takes precedence.
    if world_conversion_warning:
        response['warning'] = world_conversion_warning
    elif downgrade_warning:
        response['warning'] = downgrade_warning
    return jsonify(response)

@app.route('/api/servers/<server_id>/eula', methods=['GET'])
@server_access_required
def check_eula(server_id):
    """Check if EULA has been accepted for a server"""
    # Bedrock servers don't require EULA acceptance
    server_config = server_manager.get_server_config(server_id)
    if server_config and server_config.get('category') == 'bedrock':
        return api_success({'accepted': True})
    accepted = server_manager.check_eula_accepted(server_id)
    return api_success({'accepted': accepted})

@app.route('/api/servers/<server_id>/eula/accept', methods=['POST'])
@server_access_required
def accept_eula(server_id):
    """Accept the EULA for a server"""
    success, message = server_manager.accept_eula(server_id)
    if success:
        return api_success({'message': message})
    return api_error(message, 400)

@app.route('/api/servers/<server_id>/start', methods=['POST'])
@server_access_required
def start_server(server_id):
    """Start a server"""
    user_id, user = get_current_user()
    cfg = server_manager.get_server_config(server_id)
    server_name = cfg.get('name', server_id) if cfg else server_id

    def do_start():
        success, message = server_manager.start_server(server_id)
        if success:
            return jsonify({'success': True, 'message': message}), 200
        return api_error(message, 400)

    result, status = check_action_policy(
        'serverLifecycle', user, {'serverId': server_id, 'action': 'start', 'serverName': server_name},
        target_id=server_id, execute_fn=do_start,
        description=f'{user.get("username","Unknown")} started server "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status

@app.route('/api/servers/<server_id>/stop', methods=['POST'])
@server_access_required
def stop_server(server_id):
    """Stop a server gracefully"""
    user_id, user = get_current_user()
    cfg = server_manager.get_server_config(server_id)
    server_name = cfg.get('name', server_id) if cfg else server_id

    def do_stop():
        success, message = server_manager.stop_server(server_id)
        if success:
            return jsonify({'success': True, 'message': message}), 200
        return api_error(message, 400)

    result, status = check_action_policy(
        'serverLifecycle', user, {'serverId': server_id, 'action': 'stop', 'serverName': server_name},
        target_id=server_id, execute_fn=do_stop,
        description=f'{user.get("username","Unknown")} stopped server "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status

@app.route('/api/servers/<server_id>/restart', methods=['POST'])
@server_access_required
def restart_server(server_id):
    """Restart a server: stop it, then start it again after a short delay"""
    user_id, user = get_current_user()
    cfg = server_manager.get_server_config(server_id)
    server_name = cfg.get('name', server_id) if cfg else server_id

    def do_restart():
        success, message = server_manager.restart_server(server_id)
        if success:
            return jsonify({'success': True, 'message': message}), 200
        return api_error(message, 400)

    result, status = check_action_policy(
        'serverLifecycle', user, {'serverId': server_id, 'action': 'restart', 'serverName': server_name},
        target_id=server_id, execute_fn=do_restart,
        description=f'{user.get("username","Unknown")} restarted server "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status

@app.route('/api/servers/<server_id>/kill', methods=['POST'])
@server_access_required
def kill_server(server_id):
    """Forcefully kill a server process"""
    user_id, user = get_current_user()
    cfg = server_manager.get_server_config(server_id)
    server_name = cfg.get('name', server_id) if cfg else server_id

    def do_kill():
        success, message = server_manager.kill_server(server_id)
        if success:
            return jsonify({'success': True, 'message': message}), 200
        return api_error(message, 400)

    result, status = check_action_policy(
        'serverLifecycle', user, {'serverId': server_id, 'action': 'kill', 'serverName': server_name},
        target_id=server_id, execute_fn=do_kill,
        description=f'{user.get("username","Unknown")} killed server "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status

@app.route('/api/servers/<server_id>/command', methods=['POST'])
@server_access_required
def send_command(server_id):
    """Send a command to a server"""
    data = request.get_json()
    command = data.get('command', '')
    
    success, message = server_manager.send_command(server_id, command)
    if success:
        return api_success()
    return api_error(message, 400)

@app.route('/api/servers/<server_id>/output', methods=['GET'])
@server_access_required
def get_server_output(server_id):
    """Get recent output from a server"""
    instance = server_manager.servers.get(server_id)
    if not instance:
        return api_success(output=[])

    lines = request.args.get('lines', 100, type=int)
    return api_success(output=instance.get_recent_output(lines))


# ==================== File Explorer API ====================

@app.route('/api/servers/<server_id>/files', methods=['GET'])
@server_access_required
def list_files(server_id):
    """List files in a server's directory"""
    requested_path = request.args.get('path', '')
    server_path = server_manager.get_server_path(server_id)
    
    if not is_safe_path(server_path, requested_path):
        return api_error('Access denied', 403)

    full_path = server_path / requested_path

    if not full_path.exists():
        return api_error('Path not found', 404)

    if full_path.is_file():
        return api_success({'isFile': True, 'path': requested_path})

    files = []
    try:
        for item in full_path.iterdir():
            stat = item.stat()
            files.append({
                'name': item.name,
                'isDirectory': item.is_dir(),
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
    except PermissionError:
        return api_error('Permission denied', 403)

    return api_success({'files': files, 'currentPath': requested_path})

@app.route('/api/servers/<server_id>/files/read', methods=['GET'])
@server_access_required
def read_server_file(server_id):
    """Read file content"""
    requested_path = request.args.get('path', '')
    server_path = server_manager.get_server_path(server_id)
    
    if not is_safe_path(server_path, requested_path):
        return api_error('Access denied', 403)

    full_path = server_path / requested_path

    if not full_path.exists():
        return api_error('File not found', 404)

    try:
        content = full_path.read_text(encoding='utf-8')
        return api_success({'content': content})
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/files/write', methods=['POST'])
@server_access_required
def write_server_file(server_id):
    """Write file content"""
    data = request.get_json()
    file_path = data.get('path', '')
    content = data.get('content', '')
    server_path = server_manager.get_server_path(server_id)
    
    if not is_safe_path(server_path, file_path):
        return api_error('Access denied', 403)

    full_path = server_path / file_path

    try:
        full_path.write_text(content, encoding='utf-8')
        return jsonify({'success': True})
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/logs', methods=['GET'])
@server_access_required
def read_server_logs(server_id):
    """Read latest.log from the logs folder"""
    server_config = server_manager.get_server_config(server_id)
    if not server_config:
        return jsonify({'content': 'Server not found.', 'success': False})
    
    # Bedrock servers don't have log files - they only output to console
    if server_config.get('category') == 'bedrock':
        return jsonify({
            'content': 'Bedrock servers do not store log files.\n\nConsole output is available in the Console tab while the server is running.',
            'success': False
        })
    
    server_path = server_manager.get_server_path(server_id)
    logs_path = server_path / 'logs' / 'latest.log'
    
    if not logs_path.exists():
        return jsonify({'content': 'No logs available. The server may not have been started yet.', 'success': False})
    
    try:
        content = logs_path.read_text(encoding='utf-8', errors='replace')
        return jsonify({'content': content, 'success': True})
    except Exception as e:
        return jsonify({'content': f'Error reading logs: {str(e)}', 'success': False})

# ==================== NBT File Endpoints ====================

@app.route('/api/servers/<server_id>/nbt/read', methods=['GET'])
@server_access_required
def read_nbt_file(server_id):
    """Read and parse an NBT file (.dat)"""
    requested_path = request.args.get('path', '')
    server_path = server_manager.get_server_path(server_id)
    
    if not is_safe_path(server_path, requested_path):
        return api_error('Access denied', 403)

    full_path = server_path / requested_path

    if not full_path.exists():
        return api_error('File not found', 404)

    try:
        nbt_data = nbt_editor.read_file(full_path)
        return jsonify({
            'success': True,
            'data': nbt_data,
            'compression': nbt_editor.compression
        })
    except Exception as e:
        return api_error(f'Failed to parse NBT file: {str(e)}', 500)

@app.route('/api/servers/<server_id>/nbt/write', methods=['POST'])
@server_access_required
def write_nbt_file(server_id):
    """Write modified NBT data back to file"""
    data = request.get_json()
    file_path = data.get('path', '')
    nbt_data = data.get('data')
    compression = data.get('compression', 'gzip')
    server_path = server_manager.get_server_path(server_id)
    
    if not is_safe_path(server_path, file_path):
        return api_error('Access denied', 403)

    full_path = server_path / file_path

    try:
        nbt_editor.compression = compression
        nbt_editor.write_file(full_path, nbt_data)
        return jsonify({'success': True, 'message': 'NBT file saved'})
    except Exception as e:
        return api_error(f'Failed to write NBT file: {str(e)}', 500)

@app.route('/api/servers/<server_id>/nbt/update', methods=['POST'])
@server_access_required
def update_nbt_value(server_id):
    """Update a single value in an NBT file"""
    data = request.get_json()
    file_path = data.get('path', '')
    tag_path = data.get('tagPath', [])
    new_value = data.get('value')
    server_path = server_manager.get_server_path(server_id)
    
    if not is_safe_path(server_path, file_path):
        return api_error('Access denied', 403)

    full_path = server_path / file_path

    try:
        nbt_data = nbt_editor.read_file(full_path)
        nbt_data = nbt_editor.update_value(nbt_data, tag_path, new_value)
        nbt_editor.write_file(full_path, nbt_data)
        return jsonify({'success': True, 'message': 'Value updated'})
    except Exception as e:
        return api_error(f'Failed to update NBT value: {str(e)}', 500)

@app.route('/api/servers/<server_id>/nbt/add', methods=['POST'])
@server_access_required
def add_nbt_tag(server_id):
    """Add a new tag to an NBT file"""
    data = request.get_json()
    file_path = data.get('path', '')
    parent_path = data.get('parentPath', [])
    new_tag = data.get('tag')
    server_path = server_manager.get_server_path(server_id)
    
    if not is_safe_path(server_path, file_path):
        return api_error('Access denied', 403)

    full_path = server_path / file_path

    try:
        nbt_data = nbt_editor.read_file(full_path)
        nbt_data = nbt_editor.add_tag(nbt_data, parent_path, new_tag)
        nbt_editor.write_file(full_path, nbt_data)
        return jsonify({'success': True, 'message': 'Tag added'})
    except Exception as e:
        return api_error(f'Failed to add NBT tag: {str(e)}', 500)

@app.route('/api/servers/<server_id>/nbt/delete', methods=['POST'])
@server_access_required
def delete_nbt_tag(server_id):
    """Delete a tag from an NBT file"""
    data = request.get_json()
    file_path = data.get('path', '')
    tag_path = data.get('tagPath', [])
    server_path = server_manager.get_server_path(server_id)
    
    if not is_safe_path(server_path, file_path):
        return api_error('Access denied', 403)

    full_path = server_path / file_path

    try:
        nbt_data = nbt_editor.read_file(full_path)
        nbt_data = nbt_editor.delete_tag(nbt_data, tag_path)
        nbt_editor.write_file(full_path, nbt_data)
        return jsonify({'success': True, 'message': 'Tag deleted'})
    except Exception as e:
        return api_error(f'Failed to delete NBT tag: {str(e)}', 500)


# ==================== Player Management Endpoints ====================

def get_player_uuid(player_name):
    """Lookup player UUID from Mojang API"""
    try:
        response = requests.get(f'https://api.mojang.com/users/profiles/minecraft/{player_name}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            # Format UUID with dashes
            uuid_raw = data.get('id', '')
            if len(uuid_raw) == 32:
                uuid_formatted = f"{uuid_raw[:8]}-{uuid_raw[8:12]}-{uuid_raw[12:16]}-{uuid_raw[16:20]}-{uuid_raw[20:]}"
                return uuid_formatted, data.get('name', player_name)
        return None, None
    except:
        return None, None


def _running_instance(server_id):
    """Return the live ServerInstance if the server is running, else None.

    Player-management actions (op/ban/whitelist/...) must be applied through the
    server console while it is running: this makes them take effect immediately
    AND lets the server persist its own ops.json/whitelist.json/banned-*.json.
    Editing those files directly behind a running server's back doesn't apply
    live and gets overwritten from the server's in-memory state on its next
    change. Direct file editing is therefore only correct while the server is
    stopped."""
    inst = server_manager.servers.get(server_id)
    return inst if (inst and inst.is_running()) else None


def _safe_player_token(name):
    """Sanitize a player name for use in a single console command line.

    Returns the trimmed name, or None if it isn't a single safe token. Java
    usernames are [A-Za-z0-9_]{1,16}; rejecting anything else stops a name with
    whitespace/newlines from smuggling a second console command."""
    if not name:
        return None
    name = name.strip()
    if not re.match(r'^[A-Za-z0-9_]{1,16}$', name):
        return None
    return name


def _safe_console_text(text):
    """Collapse newlines so free text (e.g. a ban reason) stays on one console line."""
    return re.sub(r'[\r\n]+', ' ', str(text or '')).strip()


VALID_MESSAGE_COLORS = {
    'black', 'dark_blue', 'dark_green', 'dark_aqua', 'dark_red',
    'dark_purple', 'gold', 'gray', 'dark_gray', 'blue', 'green',
    'aqua', 'red', 'light_purple', 'yellow', 'white'
}


def _safe_message_target(target):
    """Validate a message target for use in a single console command line.

    Accepts a selector (@a/@p/@r/@s/@e, optionally with one [...] argument
    block) or a player name (letters/digits/underscore; interior spaces
    allowed for Bedrock gamertags). Returns the trimmed target, or None —
    anything else (newlines especially) could smuggle a second command."""
    target = (target or '').strip()
    if re.match(r'^@[aprse](\[[^\[\]\r\n]*\])?$', target):
        return target
    if re.match(r'^[A-Za-z0-9_][A-Za-z0-9_ ]{0,31}$', target):
        return target
    return None


def _name_from_json_by_uuid(server_path, filename, uuid):
    """Resolve a player's name from a Minecraft list file (ops/whitelist/banned) by uuid."""
    f = server_path / filename
    if f.exists():
        try:
            with open(f, 'r') as fh:
                for entry in json.load(fh):
                    if entry.get('uuid') == uuid:
                        return entry.get('name')
        except Exception:
            pass
    return None


# ==================== Bedrock player management ====================
#
# Bedrock Dedicated Server stores none of the Java files. Operators live in
# permissions.json keyed by XUID, the allow list lives in allowlist.json
# (name + optional xuid + ignoresPlayerLimit), player data is inside the world's
# LevelDB, and there is no ban list at all. Both JSON files are re-read on demand
# by the 'permission reload' / 'allowlist reload' console commands, so the panel
# writes the file and then asks a running server to reload it — unlike Java,
# where the file must be driven through op/whitelist/ban console commands.

BEDROCK_PERMISSIONS = ('visitor', 'member', 'operator')

BEDROCK_NO_BANS_MESSAGE = (
    'Bedrock Dedicated Server does not expose client IPs on the console, so the '
    'panel cannot enforce IP bans. Ban the player instead, or use the allow list.'
)


def _is_bedrock_server(server_id):
    """True if this server is a Bedrock server."""
    cfg = server_manager.get_server_config(server_id)
    return bool(cfg and cfg.get('category') == 'bedrock')


def _safe_bedrock_name(name):
    """Sanitize a Bedrock gamertag for use in a single console command line.

    Gamertags are 3-16 characters and may contain spaces, so unlike Java names
    they get quoted when sent; anything with a quote, backslash or newline is
    rejected so it cannot close the quoting and smuggle a second command."""
    name = (name or '').strip()
    if not re.match(r'^[A-Za-z0-9_][A-Za-z0-9_ .\-]{0,31}$', name):
        return None
    return name


def _safe_xuid(xuid):
    """Return the XUID if it is a plain decimal id, else None."""
    xuid = str(xuid or '').strip()
    return xuid if re.match(r'^\d{1,20}$', xuid) else None


def _read_json_list(path):
    """Read a JSON array from path, returning [] when missing or unreadable."""
    if not path.exists():
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _write_json_list(path, data):
    """Write a JSON array, matching the formatting Bedrock itself uses."""
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


def _bedrock_known_players(server_path):
    """Return the known gamertag <-> XUID pairs for a Bedrock server.

    Sources, merged in increasing order of trust: the panel's console-learned
    cache, then allowlist.json (Bedrock fills in the xuid there itself on first
    join). Returns (by_name_lower, by_xuid)."""
    by_name, by_xuid = {}, {}

    def record(name, xuid):
        if not xuid:
            return
        if name:
            by_name[name.lower()] = xuid
            by_xuid[xuid] = name

    try:
        cache_file = server_path / BEDROCK_XUID_CACHE
        if cache_file.exists():
            with open(cache_file, 'r', encoding='utf-8') as f:
                cache = json.load(f)
            if isinstance(cache, dict):
                for name, xuid in cache.items():
                    record(name, _safe_xuid(xuid))
    except Exception:
        pass

    for entry in _read_json_list(server_path / 'allowlist.json'):
        if isinstance(entry, dict):
            record(entry.get('name'), _safe_xuid(entry.get('xuid')))

    return by_name, by_xuid


def _bedrock_resolve_xuid(server_path, name=None, xuid=None):
    """Resolve a Bedrock player's XUID from an explicit value or a known gamertag."""
    explicit = _safe_xuid(xuid)
    if explicit:
        return explicit
    if not name:
        return None
    by_name, _ = _bedrock_known_players(server_path)
    return by_name.get(name.strip().lower())


def _bedrock_reload(server_id, subsystem):
    """Ask a running Bedrock server to re-read permissions.json / allowlist.json.

    Returns True if the reload was sent (i.e. the change is live), False if the
    server is stopped and will simply pick the file up at next start."""
    inst = _running_instance(server_id)
    if not inst:
        return False
    inst.send_command(f'{subsystem} reload')
    return True


def _bedrock_applied_suffix(live):
    """Say plainly whether a running server was asked to reload the file."""
    return ' (reloaded on the running server)' if live else ' (applies on next start)'


def _bedrock_apply_permission(server_id, server_path, xuid, permission, label):
    """Upsert a permissions.json entry and reload it on a running server."""
    try:
        perms_file = server_path / 'permissions.json'
        entries = _read_json_list(perms_file)
        for entry in entries:
            if isinstance(entry, dict) and _safe_xuid(entry.get('xuid')) == xuid:
                entry['permission'] = permission
                break
        else:
            # Only the two documented keys — BDS validates this file on load.
            entries.append({'permission': permission, 'xuid': xuid})
        _write_json_list(perms_file, entries)
        live = _bedrock_reload(server_id, 'permission')
        return jsonify({
            'success': True,
            'message': f'{label} set to {permission}{_bedrock_applied_suffix(live)}'
        }), 200
    except Exception as e:
        return api_error(str(e), 500)


def _bedrock_remove_permission(server_id, server_path, xuid, label):
    """Drop a permissions.json entry (back to the server-wide default permission)."""
    try:
        perms_file = server_path / 'permissions.json'
        entries = _read_json_list(perms_file)
        remaining = [e for e in entries
                     if not (isinstance(e, dict) and _safe_xuid(e.get('xuid')) == xuid)]
        if len(remaining) == len(entries):
            return api_error('No permission entry for that XUID', 404)
        _write_json_list(perms_file, remaining)
        live = _bedrock_reload(server_id, 'permission')
        return jsonify({
            'success': True,
            'message': f'{label} removed from permissions.json{_bedrock_applied_suffix(live)}'
        }), 200
    except Exception as e:
        return api_error(str(e), 500)


def _bedrock_permission_label(server_path, xuid, name=None):
    """Best display name for a Bedrock player: given name, known gamertag, else XUID."""
    if name:
        return name
    _, by_xuid = _bedrock_known_players(server_path)
    return by_xuid.get(xuid) or xuid


# ── Panel-side ban list (issue #82) ───────────────────────────────────────────
#
# BDS has no ban list, so the panel keeps its own and enforces it by kicking on
# connect — see ServerInstance._enforce_bedrock_ban. Two consequences the UI has
# to be honest about: the ban only holds while the server runs under the panel,
# and the player is kicked just after connecting rather than blocked at the door.

def _bedrock_ban_expiry(expires):
    """Parse a ban's expiry into an aware datetime, or None for a permanent ban.

    Raises ValueError on a value that is neither 'forever' nor a parseable
    timestamp, so a typo can't quietly become a permanent ban."""
    expires = str(expires or 'forever').strip()
    if not expires or expires.lower() == 'forever':
        return None
    when = datetime.fromisoformat(expires.replace('Z', '+00:00'))
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def _bedrock_ban_expired(entry, now=None):
    """True if this ban entry's expiry has passed."""
    try:
        when = _bedrock_ban_expiry(entry.get('expires'))
    except ValueError:
        return False  # unparseable: keep enforcing rather than silently lifting it
    return when is not None and (now or datetime.now(timezone.utc)) >= when


def _bedrock_active_bans(server_path):
    """The panel's Bedrock ban entries that are still in force."""
    return [e for e in _read_json_list(server_path / BEDROCK_BANS_FILE)
            if isinstance(e, dict) and not _bedrock_ban_expired(e)]


def _bedrock_ban_for(server_path, name=None, xuid=None):
    """Return the in-force ban entry matching this player, if any.

    The XUID is authoritative; the gamertag is the fallback for a ban placed
    before the player was ever seen, since Bedrock only reveals an XUID on
    connect. Read straight from disk on every call: the file is tiny, joins are
    infrequent, and it keeps the enforcement path free of cache invalidation."""
    xuid = _safe_xuid(xuid)
    lname = (name or '').strip().lower()
    for entry in _bedrock_active_bans(server_path):
        if xuid and _safe_xuid(entry.get('xuid')) == xuid:
            return entry
        if lname and str(entry.get('name', '')).strip().lower() == lname:
            return entry
    return None


def _bedrock_kick_if_online(server_id, name, reason):
    """Kick a just-banned player who is already connected. True if a kick was sent."""
    inst = _running_instance(server_id)
    if not inst:
        return False
    online = next((p for p in inst.online_players if p.lower() == name.lower()), None)
    target = _safe_bedrock_name(online) if online else None
    if not target:
        return False
    inst.send_command(f'kick "{target}" {_safe_console_text(reason)}'.strip())
    return True


@app.route('/api/servers/<server_id>/players/online', methods=['GET'])
@server_access_required
def get_online_players(server_id):
    """Get currently online players tracked from console output"""
    instance = server_manager.servers.get(server_id)
    if not instance or not instance.is_running():
        return api_success({'online': [], 'count': 0})
    players = [
        {'name': name, 'since': since}
        for name, since in instance.online_players.items()
    ]
    return api_success({'online': players, 'count': len(players)})

@app.route('/api/servers/<server_id>/players/<uuid>/stats', methods=['GET'])
@server_access_required
def get_player_stats(server_id, uuid):
    """Read player statistics from world/stats/<uuid>.json"""
    server_path = server_manager.get_server_path(server_id)
    stats_file = None

    for item in server_path.iterdir():
        if not item.is_dir():
            continue
        # 26.1+ path: world/players/stats/<uuid>.json  (see get_playerdata)
        new_path = item / 'players' / 'stats' / f'{uuid}.json'
        if new_path.exists():
            stats_file = new_path
            break
        # Legacy (<= 1.21.x) path: world/stats/<uuid>.json
        old_path = item / 'stats' / f'{uuid}.json'
        if old_path.exists():
            stats_file = old_path
            break

    if not stats_file:
        return api_error('Stats file not found for this player', 404)

    try:
        with open(stats_file, 'r', encoding='utf-8') as f:
            raw = json.load(f)

        # Flatten nested stat categories
        stats = raw.get('stats', raw)
        flat = {}
        for category, entries in stats.items():
            if isinstance(entries, dict):
                for stat_key, value in entries.items():
                    display_cat = category.replace('minecraft:', '')
                    display_key = stat_key.replace('minecraft:', '')
                    flat[f'{display_cat}.{display_key}'] = value

        highlights = {
            'playtimeTicks': flat.get('custom.play_time', flat.get('custom.play_one_minute', 0)),
            'deaths': flat.get('custom.deaths', 0),
            'playerKills': flat.get('custom.player_kills', 0),
            'mobKills': flat.get('custom.mob_kills', 0),
            'damageDealt': flat.get('custom.damage_dealt', 0),
            'damageTaken': flat.get('custom.damage_taken', 0),
            'jumps': flat.get('custom.jump', 0),
            'distanceWalkedCm': flat.get('custom.walk_one_cm', 0),
        }
        return api_success({'stats': flat, 'highlights': highlights})
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/players/<uuid>/inventory', methods=['GET'])
@server_access_required
def get_player_inventory(server_id, uuid):
    """Extract inventory, armor and ender chest from player NBT data"""
    server_path = server_manager.get_server_path(server_id)
    player_dat = None

    for item in server_path.iterdir():
        if not item.is_dir():
            continue
        # 26.1+ path: world/players/data/<uuid>.dat  (see get_playerdata)
        new_path = item / 'players' / 'data' / f'{uuid}.dat'
        if new_path.exists():
            player_dat = new_path
            break
        # Legacy (<= 1.21.x) path: world/playerdata/<uuid>.dat
        old_path = item / 'playerdata' / f'{uuid}.dat'
        if old_path.exists():
            player_dat = old_path
            break

    if not player_dat:
        return api_error('Player data file not found', 404)

    try:
        nbt_data = nbt_editor.read_file(player_dat)
        nbt_json = nbt_editor.to_dict(nbt_data)

        return api_success({
            'inventory': nbt_json.get('Inventory', []),
            'armor': nbt_json.get('ArmorItems', []),
            'enderChest': nbt_json.get('EnderItems', []),
            'offhand': nbt_json.get('OffhandItem', []),
            'health': nbt_json.get('Health'),
            'food': nbt_json.get('foodLevel'),
            'xpLevel': nbt_json.get('XpLevel'),
            'gameType': nbt_json.get('playerGameType'),
        })
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/players/banned-ips', methods=['GET'])
@server_access_required
def get_banned_ips(server_id):
    """Get banned IPs list (Bedrock exposes no client IPs)"""
    if _is_bedrock_server(server_id):
        return api_success({'bannedIps': [], 'supported': False, 'message': BEDROCK_NO_BANS_MESSAGE})

    server_path = server_manager.get_server_path(server_id)
    banned_ips_file = server_path / 'banned-ips.json'
    try:
        if banned_ips_file.exists():
            with open(banned_ips_file, 'r') as f:
                banned_ips = json.load(f)
            return api_success({'bannedIps': banned_ips})
        return api_success({'bannedIps': []})
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/players/banned-ips', methods=['POST'])
@server_access_required
def ban_ip(server_id):
    """Ban an IP address (Bedrock exposes no client IPs)"""
    if _is_bedrock_server(server_id):
        return api_error(BEDROCK_NO_BANS_MESSAGE, 400, supported=False)

    data = request.get_json()
    ip_address = data.get('ip', '').strip()
    reason = data.get('reason', 'Banned By Admin')
    expires = data.get('expires', 'forever')

    if not ip_address:
        return api_error('IP address is required', 400)

    # Validate IP address format (IPv4/IPv6/wildcards Minecraft allows)
    if not re.match(r'^[\d\.\:a-fA-F\*]+$', ip_address):
        return api_error('Invalid IP address format', 400)

    server_path = server_manager.get_server_path(server_id)
    banned_ips_file = server_path / 'banned-ips.json'

    # Running server: ban-ip live via console (kicks matching players and lets the
    # server persist banned-ips.json itself; a file edit wouldn't apply until restart).
    inst = _running_instance(server_id)
    if inst:
        cmd = f'ban-ip {ip_address} {_safe_console_text(reason)}'.strip()
        inst.send_command(cmd)
        return jsonify({'success': True, 'message': f'{ip_address} has been banned (applied live)'})

    try:
        banned_ips = []
        if banned_ips_file.exists():
            with open(banned_ips_file, 'r') as f:
                banned_ips = json.load(f)

        for entry in banned_ips:
            if entry.get('ip') == ip_address:
                return api_error(f'{ip_address} is already banned', 400)

        banned_ips.append({
            'ip': ip_address,
            'created': datetime.now().strftime('%Y-%m-%d %H:%M:%S +0000'),
            'source': 'MServer',
            'expires': expires,
            'reason': reason
        })

        with open(banned_ips_file, 'w') as f:
            json.dump(banned_ips, f, indent=2)

        return jsonify({'success': True, 'message': f'{ip_address} has been banned'})
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/players/banned-ips/<path:ip_address>', methods=['DELETE'])
@server_access_required
def unban_ip(server_id, ip_address):
    """Unban an IP address (Bedrock exposes no client IPs)"""
    if _is_bedrock_server(server_id):
        return api_error(BEDROCK_NO_BANS_MESSAGE, 400, supported=False)

    server_path = server_manager.get_server_path(server_id)
    banned_ips_file = server_path / 'banned-ips.json'

    # Running server: pardon-ip live via console (server persists banned-ips.json itself).
    inst = _running_instance(server_id)
    if inst and re.match(r'^[\d\.\:a-fA-F\*]+$', ip_address or ''):
        inst.send_command(f'pardon-ip {ip_address}')
        return jsonify({'success': True, 'message': f'{ip_address} has been unbanned (applied live)'})

    try:
        if not banned_ips_file.exists():
            return api_error('Banned IPs file not found', 404)

        with open(banned_ips_file, 'r') as f:
            banned_ips = json.load(f)

        original_len = len(banned_ips)
        banned_ips = [e for e in banned_ips if e.get('ip') != ip_address]

        if len(banned_ips) == original_len:
            return api_error('IP not found in ban list', 404)

        with open(banned_ips_file, 'w') as f:
            json.dump(banned_ips, f, indent=2)

        return jsonify({'success': True, 'message': f'{ip_address} has been unbanned'})
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/players/message', methods=['POST'])
@server_access_required
def message_players(server_id):
    """Send a message to players via console commands (say/msg/tellraw/title/actionbar)"""
    data = request.get_json()
    msg_type = data.get('type', 'chat')
    target = _safe_message_target(data.get('target', '@a'))
    message = _safe_console_text(data.get('message', ''))
    color = data.get('color', 'white')
    bold = data.get('bold', False)
    italic = data.get('italic', False)
    underlined = data.get('underlined', False)
    strikethrough = data.get('strikethrough', False)
    obfuscated = data.get('obfuscated', False)

    if not message:
        return api_error('Message is required', 400)
    if not target:
        return api_error('Invalid target: use @a/@p/@r/@s/@e or a player name', 400)

    server_config = server_manager.get_server_config(server_id)
    is_bedrock = server_config and server_config.get('category') == 'bedrock'

    safe = message.replace('\\', '\\\\').replace('"', '\\"')

    if color not in VALID_MESSAGE_COLORS:
        color = 'white'

    if msg_type == 'say':
        command = f'say {message}'
    elif msg_type == 'msg':
        if not target or target.startswith('@a'):
            return api_error('/msg requires a specific player target, not @a', 400)
        command = f'msg {target} {message}'
    elif msg_type == 'chat':
        if is_bedrock:
            command = f'tellraw {target} {{"rawtext":[{{"text":"{safe}"}}]}}'
        else:
            parts = [f'"text":"{safe}"', f'"color":"{color}"']
            if bold:
                parts.append('"bold":true')
            if italic:
                parts.append('"italic":true')
            if underlined:
                parts.append('"underlined":true')
            if strikethrough:
                parts.append('"strikethrough":true')
            if obfuscated:
                parts.append('"obfuscated":true')
            command = f'tellraw {target} {{{",".join(parts)}}}'
    elif msg_type == 'title':
        if is_bedrock:
            command = f'titleraw {target} title {{"rawtext":[{{"text":"{safe}"}}]}}'
        else:
            parts = [f'"text":"{safe}"', '"bold":true', f'"color":"{color}"']
            if italic:
                parts.append('"italic":true')
            command = f'title {target} title {{{",".join(parts)}}}'
    elif msg_type == 'subtitle':
        if is_bedrock:
            command = f'titleraw {target} subtitle {{"rawtext":[{{"text":"{safe}"}}]}}'
        else:
            parts = [f'"text":"{safe}"', f'"color":"{color}"']
            if bold:
                parts.append('"bold":true')
            if italic:
                parts.append('"italic":true')
            command = f'title {target} subtitle {{{",".join(parts)}}}'
    elif msg_type == 'actionbar':
        if is_bedrock:
            command = f'titleraw {target} actionbar {{"rawtext":[{{"text":"{safe}"}}]}}'
        else:
            parts = [f'"text":"{safe}"', f'"color":"{color}"']
            if bold:
                parts.append('"bold":true')
            command = f'title {target} actionbar {{{",".join(parts)}}}'
    else:
        return api_error(f'Unknown message type: {msg_type}', 400)

    success, msg = server_manager.send_command(server_id, command)
    if not success:
        return api_error(msg, 400)

    type_labels = {
        'say': '/say broadcast',
        'msg': f'/msg to {target}',
        'chat': 'tellraw',
        'title': 'title',
        'subtitle': 'subtitle',
        'actionbar': 'action bar'
    }
    return jsonify({'success': True, 'message': f'{type_labels.get(msg_type, msg_type)} sent to {target}', 'command': command})


# ==================== Scheduled / Event Messages API ====================

@app.route('/api/servers/<server_id>/messages', methods=['GET'])
@server_access_required
def get_scheduled_messages(server_id):
    """Get all scheduled/event messages for a server."""
    return api_success({'messages': message_scheduler.get_messages(server_id)})

@app.route('/api/servers/<server_id>/messages', methods=['POST'])
@server_access_required
def create_scheduled_message(server_id):
    """Create a new scheduled/event message."""
    data = request.get_json()
    if not data.get('message', '').strip():
        return api_error('Message text is required', 400)
    trigger = data.get('trigger', 'cron')
    if trigger == 'cron' and not data.get('cronExpr', '').strip():
        return api_error('Cron expression is required for scheduled messages', 400)
    if trigger != 'cron' and trigger not in MessageScheduler.EVENT_TRIGGERS:
        return api_error(f'Unknown event trigger: {trigger}', 400)
    msg = message_scheduler.create_message(server_id, data)
    return api_success({'message': msg}, 201)

@app.route('/api/servers/<server_id>/messages/<msg_id>', methods=['PUT'])
@server_access_required
def update_scheduled_message(server_id, msg_id):
    """Update an existing scheduled/event message."""
    data = request.get_json()
    msg = message_scheduler.update_message(server_id, msg_id, data)
    if msg is None:
        return api_error('Message not found', 404)
    return api_success({'message': msg})

@app.route('/api/servers/<server_id>/messages/<msg_id>', methods=['DELETE'])
@server_access_required
def delete_scheduled_message(server_id, msg_id):
    """Delete a scheduled/event message."""
    if message_scheduler.delete_message(server_id, msg_id):
        return api_success()
    return api_error('Message not found', 404)

@app.route('/api/servers/<server_id>/messages/test', methods=['POST'])
@server_access_required
def test_scheduled_message(server_id):
    """Test-fire a message immediately without saving."""
    data = request.get_json()
    if not data.get('message', '').strip():
        return api_error('Message text is required', 400)
    success, result = message_scheduler.test_message(server_id, data)
    if not success:
        return api_error(result, 400)
    return api_success({'command': result})


@app.route('/api/servers/<server_id>/players/ops', methods=['GET'])
@server_access_required
def get_operators(server_id):
    """Get list of operators — ops.json on Java, permissions.json on Bedrock"""
    server_path = server_manager.get_server_path(server_id)

    if _is_bedrock_server(server_id):
        _, by_xuid = _bedrock_known_players(server_path)
        operators = []
        for entry in _read_json_list(server_path / 'permissions.json'):
            if not isinstance(entry, dict):
                continue
            xuid = _safe_xuid(entry.get('xuid'))
            if not xuid:
                continue
            operators.append({
                'xuid': xuid,
                'name': by_xuid.get(xuid, ''),
                'permission': str(entry.get('permission', 'member')).lower(),
            })
        return api_success({'operators': operators, 'bedrock': True})

    ops_file = server_path / 'ops.json'

    try:
        if ops_file.exists():
            with open(ops_file, 'r') as f:
                ops = json.load(f)
            return api_success({'operators': ops})
        return api_success({'operators': []})
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/players/ops', methods=['POST'])
@server_access_required
def add_operator(server_id):
    """Add a player as operator"""
    user_id, user = get_current_user()
    data = request.get_json()
    player_name = data.get('name', '').strip()
    player_uuid = data.get('uuid', '').strip()
    level = data.get('level', 4)
    bypass_limit = data.get('bypassesPlayerLimit', False)

    server_path = server_manager.get_server_path(server_id)
    ops_file = server_path / 'ops.json'
    cfg = server_manager.get_server_config(server_id) or {}
    server_name = cfg.get('name', server_id)

    # Bedrock: permissions.json keyed by XUID, applied with 'permission reload'.
    if _is_bedrock_server(server_id):
        permission = str(data.get('permission') or 'operator').strip().lower()
        if permission not in BEDROCK_PERMISSIONS:
            return api_error(f'Permission must be one of: {", ".join(BEDROCK_PERMISSIONS)}', 400)

        display = _safe_bedrock_name(player_name) if player_name else None
        if player_name and not display:
            return api_error('Invalid gamertag', 400)

        xuid = _bedrock_resolve_xuid(server_path, name=display,
                                     xuid=data.get('xuid') or player_uuid)
        if not xuid:
            return api_error(
                f'No XUID is known for "{player_name or "that player"}". Bedrock keys operators '
                'by XUID — have the player join once (the panel records their XUID from the '
                'console) or enter their XUID directly.', 404)

        label = _bedrock_permission_label(server_path, xuid, display)

        def do_bedrock_permission():
            return _bedrock_apply_permission(server_id, server_path, xuid, permission, label)

        result, status = check_action_policy(
            'playerManagement', user,
            {'serverId': server_id, 'action': 'add_op', 'player': label,
             'permission': permission, 'serverName': server_name},
            target_id=server_id, execute_fn=do_bedrock_permission,
            description=f'{user.get("username","Unknown")} set "{label}" to {permission} on "{server_name}".')
        return jsonify(result) if isinstance(result, dict) else result, status

    # Running server: apply live via console so it takes effect immediately and
    # the server persists ops.json itself. Uses only the name, so this also works
    # on offline-mode servers where Mojang UUID lookup would fail.
    inst = _running_instance(server_id)
    if inst:
        live_name = _safe_player_token(player_name)
        if not live_name:
            return api_error('A valid player name is required to op a player on a running server', 400)

        def do_add_op_live():
            inst.send_command(f'op {live_name}')
            return jsonify({'success': True, 'message': f'{live_name} granted operator (applied live)'}), 200

        result, status = check_action_policy(
            'playerManagement', user,
            {'serverId': server_id, 'action': 'add_op', 'player': live_name, 'serverName': server_name},
            target_id=server_id, execute_fn=do_add_op_live,
            description=f'{user.get("username","Unknown")} added operator "{live_name}" on "{server_name}".')
        return jsonify(result) if isinstance(result, dict) else result, status

    resolved_uuid = None
    actual_name = None

    if player_uuid:
        usercache_file = server_path / 'usercache.json'
        if usercache_file.exists():
            try:
                with open(usercache_file, 'r') as f:
                    cache = json.load(f)
                for entry in cache:
                    if entry.get('uuid') == player_uuid:
                        actual_name = entry.get('name', player_uuid)
                        resolved_uuid = player_uuid
                        break
            except Exception:
                pass
        if not resolved_uuid:
            resolved_uuid = player_uuid
            actual_name = player_name or player_uuid
    elif player_name:
        resolved_uuid, actual_name = get_player_uuid(player_name)
        if not resolved_uuid:
            return api_error(f'Could not find player "{player_name}". Make sure the name is correct.', 404)
    else:
        return api_error('Player name or UUID is required', 400)

    def do_add_op():
        try:
            ops = []
            if ops_file.exists():
                with open(ops_file, 'r') as f:
                    ops = json.load(f)
            for op in ops:
                if op.get('uuid') == resolved_uuid:
                    return api_error(f'{actual_name} is already an operator', 400)
            ops.append({
                'uuid': resolved_uuid, 'name': actual_name,
                'level': int(level), 'bypassesPlayerLimit': bool(bypass_limit)
            })
            with open(ops_file, 'w') as f:
                json.dump(ops, f, indent=2)
            return jsonify({'success': True, 'message': f'{actual_name} added as operator'}), 200
        except Exception as e:
            return api_error(str(e), 500)

    result, status = check_action_policy(
        'playerManagement', user,
        {'serverId': server_id, 'action': 'add_op', 'player': actual_name, 'serverName': server_name},
        target_id=server_id, execute_fn=do_add_op,
        description=f'{user.get("username","Unknown")} added operator "{actual_name}" on "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status

@app.route('/api/servers/<server_id>/players/ops/<uuid>', methods=['PUT'])
@server_access_required
def update_operator(server_id, uuid):
    """Update an operator's settings (Bedrock: <uuid> is the player's XUID)"""
    data = request.get_json()
    level = data.get('level', 4)
    bypass_limit = data.get('bypassesPlayerLimit', False)

    server_path = server_manager.get_server_path(server_id)

    if _is_bedrock_server(server_id):
        xuid = _safe_xuid(uuid)
        if not xuid:
            return api_error('Invalid XUID', 400)
        permission = str(data.get('permission') or '').strip().lower()
        if permission not in BEDROCK_PERMISSIONS:
            return api_error(f'Permission must be one of: {", ".join(BEDROCK_PERMISSIONS)}', 400)
        label = _bedrock_permission_label(server_path, xuid)
        return _bedrock_apply_permission(server_id, server_path, xuid, permission, label)

    ops_file = server_path / 'ops.json'

    try:
        if not ops_file.exists():
            return api_error('Ops file not found', 404)

        with open(ops_file, 'r') as f:
            ops = json.load(f)

        found = False
        for op in ops:
            if op.get('uuid') == uuid:
                op['level'] = int(level)
                op['bypassesPlayerLimit'] = bool(bypass_limit)
                found = True
                break

        if not found:
            return api_error('Operator not found', 404)

        with open(ops_file, 'w') as f:
            json.dump(ops, f, indent=2)

        return jsonify({'success': True, 'message': 'Operator updated'})
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/players/ops/<uuid>', methods=['DELETE'])
@server_access_required
def remove_operator(server_id, uuid):
    """Remove an operator (Bedrock: <uuid> is the player's XUID)"""
    user_id, user = get_current_user()
    server_path = server_manager.get_server_path(server_id)
    ops_file = server_path / 'ops.json'
    cfg = server_manager.get_server_config(server_id) or {}
    server_name = cfg.get('name', server_id)

    # Bedrock: drop the permissions.json entry and reload it on a running server.
    if _is_bedrock_server(server_id):
        xuid = _safe_xuid(uuid)
        if not xuid:
            return api_error('Invalid XUID', 400)
        label = _bedrock_permission_label(server_path, xuid)

        def do_bedrock_remove():
            return _bedrock_remove_permission(server_id, server_path, xuid, label)

        result, status = check_action_policy(
            'playerManagement', user,
            {'serverId': server_id, 'action': 'remove_op', 'xuid': xuid, 'serverName': server_name},
            target_id=server_id, execute_fn=do_bedrock_remove,
            description=f'{user.get("username","Unknown")} removed the permission entry for "{label}" on "{server_name}".')
        return jsonify(result) if isinstance(result, dict) else result, status

    # Running server: deop live via console (server persists ops.json itself).
    inst = _running_instance(server_id)
    live_name = _safe_player_token(_name_from_json_by_uuid(server_path, 'ops.json', uuid)) if inst else None
    if inst and live_name:
        def do_remove_live():
            inst.send_command(f'deop {live_name}')
            return jsonify({'success': True, 'message': f'{live_name} removed from operators (applied live)'}), 200

        result, status = check_action_policy(
            'playerManagement', user,
            {'serverId': server_id, 'action': 'remove_op', 'uuid': uuid, 'serverName': server_name},
            target_id=server_id, execute_fn=do_remove_live,
            description=f'{user.get("username","Unknown")} removed operator "{live_name}" on "{server_name}".')
        return jsonify(result) if isinstance(result, dict) else result, status

    def do_remove():
        try:
            if not ops_file.exists():
                return api_error('Ops file not found', 404)
            with open(ops_file, 'r') as f:
                ops = json.load(f)
            original_len = len(ops)
            ops = [op for op in ops if op.get('uuid') != uuid]
            if len(ops) == original_len:
                return api_error('Operator not found', 404)
            with open(ops_file, 'w') as f:
                json.dump(ops, f, indent=2)
            return jsonify({'success': True, 'message': 'Operator removed'}), 200
        except Exception as e:
            return api_error(str(e), 500)

    result, status = check_action_policy(
        'playerManagement', user,
        {'serverId': server_id, 'action': 'remove_op', 'uuid': uuid, 'serverName': server_name},
        target_id=server_id, execute_fn=do_remove,
        description=f'{user.get("username","Unknown")} removed operator on "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status

@app.route('/api/servers/<server_id>/players/whitelist', methods=['GET'])
@server_access_required
def get_whitelist(server_id):
    """Get the whitelist — whitelist.json on Java, allowlist.json on Bedrock"""
    server_path = server_manager.get_server_path(server_id)

    if _is_bedrock_server(server_id):
        entries = []
        for entry in _read_json_list(server_path / 'allowlist.json'):
            if not isinstance(entry, dict):
                continue
            entries.append({
                'name': entry.get('name', ''),
                'xuid': _safe_xuid(entry.get('xuid')) or '',
                'ignoresPlayerLimit': bool(entry.get('ignoresPlayerLimit', False)),
            })
        return api_success({'whitelist': entries, 'bedrock': True})

    whitelist_file = server_path / 'whitelist.json'

    try:
        if whitelist_file.exists():
            with open(whitelist_file, 'r') as f:
                whitelist = json.load(f)
            return api_success({'whitelist': whitelist})
        return api_success({'whitelist': []})
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/players/whitelist', methods=['POST'])
@server_access_required
def add_to_whitelist(server_id):
    """Add a player to whitelist"""
    user_id, user = get_current_user()
    data = request.get_json()
    player_name = data.get('name', '').strip()
    player_uuid = data.get('uuid', '').strip()

    server_path = server_manager.get_server_path(server_id)
    whitelist_file = server_path / 'whitelist.json'
    cfg = server_manager.get_server_config(server_id) or {}
    server_name = cfg.get('name', server_id)

    # Bedrock: allowlist.json entries are name-keyed (Bedrock fills in the xuid
    # itself on first join), applied with 'allowlist reload'.
    if _is_bedrock_server(server_id):
        name = _safe_bedrock_name(player_name)
        if not name:
            return api_error('A valid gamertag is required', 400)
        ignores_limit = bool(data.get('ignoresPlayerLimit', False))
        xuid = _safe_xuid(data.get('xuid')) or _bedrock_resolve_xuid(server_path, name=name)

        def do_bedrock_allow():
            try:
                allow_file = server_path / 'allowlist.json'
                entries = _read_json_list(allow_file)
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    if (str(entry.get('name', '')).strip().lower() == name.lower()
                            or (xuid and _safe_xuid(entry.get('xuid')) == xuid)):
                        return api_error(f'{name} is already on the allow list', 400)
                new_entry = {'ignoresPlayerLimit': ignores_limit, 'name': name}
                if xuid:
                    new_entry['xuid'] = xuid
                entries.append(new_entry)
                _write_json_list(allow_file, entries)
                live = _bedrock_reload(server_id, 'allowlist')
                return jsonify({
                    'success': True,
                    'message': f'{name} added to the allow list{_bedrock_applied_suffix(live)}'
                }), 200
            except Exception as e:
                return api_error(str(e), 500)

        result, status = check_action_policy(
            'playerManagement', user,
            {'serverId': server_id, 'action': 'whitelist_add', 'player': name, 'serverName': server_name},
            target_id=server_id, execute_fn=do_bedrock_allow,
            description=f'{user.get("username","Unknown")} added "{name}" to the allow list on "{server_name}".')
        return jsonify(result) if isinstance(result, dict) else result, status

    # Running server: apply live via console (server persists whitelist.json
    # itself and reloads enforcement). Name-only, so offline-mode works too.
    inst = _running_instance(server_id)
    if inst:
        live_name = _safe_player_token(player_name)
        if not live_name:
            return api_error('A valid player name is required to whitelist a player on a running server', 400)

        def do_add_live():
            inst.send_command(f'whitelist add {live_name}')
            return jsonify({'success': True, 'message': f'{live_name} added to whitelist (applied live)'}), 200

        result, status = check_action_policy(
            'playerManagement', user,
            {'serverId': server_id, 'action': 'whitelist_add', 'player': live_name, 'serverName': server_name},
            target_id=server_id, execute_fn=do_add_live,
            description=f'{user.get("username","Unknown")} whitelisted "{live_name}" on "{server_name}".')
        return jsonify(result) if isinstance(result, dict) else result, status

    resolved_uuid = actual_name = None

    if player_uuid:
        usercache_file = server_path / 'usercache.json'
        if usercache_file.exists():
            try:
                with open(usercache_file, 'r') as f:
                    cache = json.load(f)
                for entry in cache:
                    if entry.get('uuid') == player_uuid:
                        actual_name = entry.get('name', player_uuid)
                        resolved_uuid = player_uuid
                        break
            except Exception:
                pass
        if not resolved_uuid:
            resolved_uuid = player_uuid
            actual_name = player_name or player_uuid
    elif player_name:
        resolved_uuid, actual_name = get_player_uuid(player_name)
        if not resolved_uuid:
            return api_error(f'Could not find player "{player_name}"', 404)
    else:
        return api_error('Player name or UUID is required', 400)

    def do_add():
        try:
            whitelist = []
            if whitelist_file.exists():
                with open(whitelist_file, 'r') as f:
                    whitelist = json.load(f)
            for player in whitelist:
                if player.get('uuid') == resolved_uuid:
                    return api_error(f'{actual_name} is already whitelisted', 400)
            whitelist.append({'uuid': resolved_uuid, 'name': actual_name})
            with open(whitelist_file, 'w') as f:
                json.dump(whitelist, f, indent=2)
            return jsonify({'success': True, 'message': f'{actual_name} added to whitelist'}), 200
        except Exception as e:
            return api_error(str(e), 500)

    result, status = check_action_policy(
        'playerManagement', user,
        {'serverId': server_id, 'action': 'whitelist_add', 'player': actual_name, 'serverName': server_name},
        target_id=server_id, execute_fn=do_add,
        description=f'{user.get("username","Unknown")} whitelisted "{actual_name}" on "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status

@app.route('/api/servers/<server_id>/players/whitelist/<uuid>', methods=['DELETE'])
@server_access_required
def remove_from_whitelist(server_id, uuid):
    """Remove a player from the whitelist (Bedrock: <uuid> is an XUID or gamertag)"""
    user_id, user = get_current_user()
    server_path = server_manager.get_server_path(server_id)
    whitelist_file = server_path / 'whitelist.json'
    cfg = server_manager.get_server_config(server_id) or {}
    server_name = cfg.get('name', server_id)

    # Bedrock: allowlist.json entries have no UUID, so the path segment carries
    # the XUID when Bedrock has filled one in and the gamertag otherwise.
    if _is_bedrock_server(server_id):
        target_xuid = _safe_xuid(uuid)
        target_name = None if target_xuid else _safe_bedrock_name(uuid)
        if not target_xuid and not target_name:
            return api_error('Invalid allow-list entry', 400)
        label = target_name or _bedrock_permission_label(server_path, target_xuid)

        def matches(entry):
            if not isinstance(entry, dict):
                return False
            if target_xuid:
                return _safe_xuid(entry.get('xuid')) == target_xuid
            return str(entry.get('name', '')).strip().lower() == target_name.lower()

        def do_bedrock_remove_allow():
            try:
                allow_file = server_path / 'allowlist.json'
                entries = _read_json_list(allow_file)
                remaining = [e for e in entries if not matches(e)]
                if len(remaining) == len(entries):
                    return api_error('Player not found on the allow list', 404)
                _write_json_list(allow_file, remaining)
                live = _bedrock_reload(server_id, 'allowlist')
                return jsonify({
                    'success': True,
                    'message': f'{label} removed from the allow list{_bedrock_applied_suffix(live)}'
                }), 200
            except Exception as e:
                return api_error(str(e), 500)

        result, status = check_action_policy(
            'playerManagement', user,
            {'serverId': server_id, 'action': 'whitelist_remove', 'player': label, 'serverName': server_name},
            target_id=server_id, execute_fn=do_bedrock_remove_allow,
            description=f'{user.get("username","Unknown")} removed "{label}" from the allow list on "{server_name}".')
        return jsonify(result) if isinstance(result, dict) else result, status

    # Running server: remove live via console (server persists whitelist.json itself).
    inst = _running_instance(server_id)
    live_name = _safe_player_token(_name_from_json_by_uuid(server_path, 'whitelist.json', uuid)) if inst else None
    if inst and live_name:
        def do_remove_live():
            inst.send_command(f'whitelist remove {live_name}')
            return jsonify({'success': True, 'message': f'{live_name} removed from whitelist (applied live)'}), 200

        result, status = check_action_policy(
            'playerManagement', user,
            {'serverId': server_id, 'action': 'whitelist_remove', 'uuid': uuid, 'serverName': server_name},
            target_id=server_id, execute_fn=do_remove_live,
            description=f'{user.get("username","Unknown")} removed "{live_name}" from whitelist on "{server_name}".')
        return jsonify(result) if isinstance(result, dict) else result, status

    def do_remove():
        try:
            if not whitelist_file.exists():
                return api_error('Whitelist file not found', 404)
            with open(whitelist_file, 'r') as f:
                whitelist = json.load(f)
            original_len = len(whitelist)
            whitelist = [p for p in whitelist if p.get('uuid') != uuid]
            if len(whitelist) == original_len:
                return api_error('Player not found in whitelist', 404)
            with open(whitelist_file, 'w') as f:
                json.dump(whitelist, f, indent=2)
            return jsonify({'success': True, 'message': 'Player removed from whitelist'}), 200
        except Exception as e:
            return api_error(str(e), 500)

    result, status = check_action_policy(
        'playerManagement', user,
        {'serverId': server_id, 'action': 'whitelist_remove', 'uuid': uuid, 'serverName': server_name},
        target_id=server_id, execute_fn=do_remove,
        description=f'{user.get("username","Unknown")} removed player from whitelist on "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status

@app.route('/api/servers/<server_id>/players/banned', methods=['GET'])
@server_access_required
def get_banned_players(server_id):
    """Get banned players — banned-players.json on Java, the panel's list on Bedrock"""
    if _is_bedrock_server(server_id):
        server_path = server_manager.get_server_path(server_id)
        return api_success({'banned': _bedrock_active_bans(server_path), 'bedrock': True})

    server_path = server_manager.get_server_path(server_id)
    banned_file = server_path / 'banned-players.json'

    try:
        if banned_file.exists():
            with open(banned_file, 'r') as f:
                banned = json.load(f)
            return api_success({'banned': banned})
        return api_success({'banned': []})
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/players/banned', methods=['POST'])
@server_access_required
def ban_player(server_id):
    """Ban a player"""
    user_id, user = get_current_user()
    data = request.get_json()
    player_name = data.get('name', '').strip()
    player_uuid = data.get('uuid', '').strip()
    reason = data.get('reason', 'Banned By Admin')
    expires = data.get('expires', 'forever')

    server_path = server_manager.get_server_path(server_id)
    banned_file = server_path / 'banned-players.json'
    cfg = server_manager.get_server_config(server_id) or {}
    server_name = cfg.get('name', server_id)

    # Bedrock has no ban list and no ban command, so the panel keeps its own and
    # enforces it by kicking on connect (issue #82).
    if _is_bedrock_server(server_id):
        name = _safe_bedrock_name(player_name)
        if not name:
            return api_error('A valid gamertag is required', 400)
        try:
            _bedrock_ban_expiry(expires)
        except ValueError:
            return api_error('Expiry must be "forever" or an ISO-8601 timestamp', 400)
        ban_reason = _safe_console_text(reason)[:200] or 'Banned By Admin'
        xuid = _safe_xuid(data.get('xuid')) or _bedrock_resolve_xuid(server_path, name=name)
        bans_file = server_path / BEDROCK_BANS_FILE

        def do_bedrock_ban():
            try:
                # Drop lapsed entries while we're rewriting the file anyway
                entries = [e for e in _read_json_list(bans_file)
                           if isinstance(e, dict) and not _bedrock_ban_expired(e)]
                for entry in entries:
                    if ((xuid and _safe_xuid(entry.get('xuid')) == xuid)
                            or str(entry.get('name', '')).strip().lower() == name.lower()):
                        return api_error(f'{name} is already banned', 400)
                entries.append({
                    'name': name, 'xuid': xuid or '',
                    'created': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S +0000'),
                    'source': 'MServer', 'expires': expires, 'reason': ban_reason,
                })
                _write_json_list(bans_file, entries)
                kicked = _bedrock_kick_if_online(server_id, name, ban_reason)
                return jsonify({
                    'success': True,
                    'message': f'{name} has been banned' + (' and kicked' if kicked else '')
                }), 200
            except Exception as e:
                return api_error(str(e), 500)

        result, status = check_action_policy(
            'playerManagement', user,
            {'serverId': server_id, 'action': 'ban', 'player': name,
             'reason': ban_reason, 'serverName': server_name},
            target_id=server_id, execute_fn=do_bedrock_ban,
            description=f'{user.get("username","Unknown")} banned "{name}" on "{server_name}".')
        return jsonify(result) if isinstance(result, dict) else result, status

    # Running server: ban live via console. This kicks the player immediately,
    # blocks reconnection, and lets the server persist banned-players.json itself
    # (a direct file edit would not take effect until restart). Name-only, so
    # offline-mode servers work too.
    inst = _running_instance(server_id)
    if inst:
        live_name = _safe_player_token(player_name)
        if not live_name:
            return api_error('A valid player name is required to ban a player on a running server', 400)
        live_reason = _safe_console_text(reason)
        cmd = f'ban {live_name} {live_reason}'.strip()

        def do_ban_live():
            inst.send_command(cmd)
            return jsonify({'success': True, 'message': f'{live_name} has been banned (applied live)'}), 200

        result, status = check_action_policy(
            'playerManagement', user,
            {'serverId': server_id, 'action': 'ban', 'player': live_name, 'reason': reason, 'serverName': server_name},
            target_id=server_id, execute_fn=do_ban_live,
            description=f'{user.get("username","Unknown")} banned "{live_name}" on "{server_name}".')
        return jsonify(result) if isinstance(result, dict) else result, status

    resolved_uuid = actual_name = None

    if player_uuid:
        usercache_file = server_path / 'usercache.json'
        if usercache_file.exists():
            try:
                with open(usercache_file, 'r') as f:
                    cache = json.load(f)
                for entry in cache:
                    if entry.get('uuid') == player_uuid:
                        actual_name = entry.get('name', player_uuid)
                        resolved_uuid = player_uuid
                        break
            except Exception:
                pass
        if not resolved_uuid:
            resolved_uuid = player_uuid
            actual_name = player_name or player_uuid
    elif player_name:
        resolved_uuid, actual_name = get_player_uuid(player_name)
        if not resolved_uuid:
            return api_error(f'Could not find player "{player_name}"', 404)
    else:
        return api_error('Player name or UUID is required', 400)

    def do_ban():
        try:
            banned = []
            if banned_file.exists():
                with open(banned_file, 'r') as f:
                    banned = json.load(f)
            for player in banned:
                if player.get('uuid') == resolved_uuid:
                    return api_error(f'{actual_name} is already banned', 400)
            banned.append({
                'uuid': resolved_uuid, 'name': actual_name,
                'created': datetime.now().strftime('%Y-%m-%d %H:%M:%S +0000'),
                'source': 'MServer', 'expires': expires, 'reason': reason
            })
            with open(banned_file, 'w') as f:
                json.dump(banned, f, indent=2)
            return jsonify({'success': True, 'message': f'{actual_name} has been banned'}), 200
        except Exception as e:
            return api_error(str(e), 500)

    result, status = check_action_policy(
        'playerManagement', user,
        {'serverId': server_id, 'action': 'ban', 'player': actual_name, 'reason': reason, 'serverName': server_name},
        target_id=server_id, execute_fn=do_ban,
        description=f'{user.get("username","Unknown")} banned "{actual_name}" on "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status

@app.route('/api/servers/<server_id>/players/banned/<uuid>', methods=['DELETE'])
@server_access_required
def unban_player(server_id, uuid):
    """Unban a player (Bedrock: <uuid> is the XUID or gamertag of a panel ban)"""
    user_id, user = get_current_user()
    server_path = server_manager.get_server_path(server_id)
    banned_file = server_path / 'banned-players.json'
    cfg = server_manager.get_server_config(server_id) or {}
    server_name = cfg.get('name', server_id)

    # Bedrock: drop the entry from the panel's own ban list (issue #82)
    if _is_bedrock_server(server_id):
        target_xuid = _safe_xuid(uuid)
        target_name = None if target_xuid else _safe_bedrock_name(uuid)
        if not target_xuid and not target_name:
            return api_error('Invalid ban entry', 400)
        bans_file = server_path / BEDROCK_BANS_FILE

        def matches(entry):
            if not isinstance(entry, dict):
                return False
            if target_xuid:
                return _safe_xuid(entry.get('xuid')) == target_xuid
            return str(entry.get('name', '')).strip().lower() == target_name.lower()

        def do_bedrock_unban():
            try:
                entries = _read_json_list(bans_file)
                remaining = [e for e in entries if not matches(e)]
                if len(remaining) == len(entries):
                    return api_error('Player not found in the ban list', 404)
                _write_json_list(bans_file, remaining)
                return jsonify({
                    'success': True,
                    'message': f'{target_name or target_xuid} unbanned'
                }), 200
            except Exception as e:
                return api_error(str(e), 500)

        result, status = check_action_policy(
            'playerManagement', user,
            {'serverId': server_id, 'action': 'unban',
             'player': target_name or target_xuid, 'serverName': server_name},
            target_id=server_id, execute_fn=do_bedrock_unban,
            description=f'{user.get("username","Unknown")} unbanned "{target_name or target_xuid}" on "{server_name}".')
        return jsonify(result) if isinstance(result, dict) else result, status

    # Running server: pardon live via console (server persists banned-players.json itself).
    inst = _running_instance(server_id)
    live_name = _safe_player_token(_name_from_json_by_uuid(server_path, 'banned-players.json', uuid)) if inst else None
    if inst and live_name:
        def do_unban_live():
            inst.send_command(f'pardon {live_name}')
            return jsonify({'success': True, 'message': f'{live_name} unbanned (applied live)'}), 200

        result, status = check_action_policy(
            'playerManagement', user,
            {'serverId': server_id, 'action': 'unban', 'uuid': uuid, 'serverName': server_name},
            target_id=server_id, execute_fn=do_unban_live,
            description=f'{user.get("username","Unknown")} unbanned "{live_name}" on "{server_name}".')
        return jsonify(result) if isinstance(result, dict) else result, status

    def do_unban():
        try:
            if not banned_file.exists():
                return api_error('Banned players file not found', 404)
            with open(banned_file, 'r') as f:
                banned = json.load(f)
            original_len = len(banned)
            banned = [p for p in banned if p.get('uuid') != uuid]
            if len(banned) == original_len:
                return api_error('Player not found in ban list', 404)
            with open(banned_file, 'w') as f:
                json.dump(banned, f, indent=2)
            return jsonify({'success': True, 'message': 'Player unbanned'}), 200
        except Exception as e:
            return api_error(str(e), 500)

    result, status = check_action_policy(
        'playerManagement', user,
        {'serverId': server_id, 'action': 'unban', 'uuid': uuid, 'serverName': server_name},
        target_id=server_id, execute_fn=do_unban,
        description=f'{user.get("username","Unknown")} unbanned a player on "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status

@app.route('/api/servers/<server_id>/players/kick', methods=['POST'])
@server_access_required
def kick_player(server_id):
    """Kick an online player.

    Bedrock's only moderation command — it has no ban — and it works the same on
    Java, so both editions share this route."""
    user_id, user = get_current_user()
    data = request.get_json() or {}
    player_name = (data.get('name') or '').strip()
    reason = _safe_console_text(data.get('reason', ''))

    cfg = server_manager.get_server_config(server_id) or {}
    server_name = cfg.get('name', server_id)

    inst = _running_instance(server_id)
    if not inst:
        return api_error('The server must be running to kick a player', 400)

    if cfg.get('category') == 'bedrock':
        # Gamertags may contain spaces, so quote the target.
        name = _safe_bedrock_name(player_name)
        if not name:
            return api_error('A valid gamertag is required', 400)
        command = f'kick "{name}" {reason}'.strip()
    else:
        name = _safe_player_token(player_name)
        if not name:
            return api_error('A valid player name is required', 400)
        command = f'kick {name} {reason}'.strip()

    def do_kick():
        inst.send_command(command)
        return jsonify({'success': True, 'message': f'{name} has been kicked'}), 200

    result, status = check_action_policy(
        'playerManagement', user,
        {'serverId': server_id, 'action': 'kick', 'player': name,
         'reason': reason, 'serverName': server_name},
        target_id=server_id, execute_fn=do_kick,
        description=f'{user.get("username","Unknown")} kicked "{name}" on "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status


def _whitelist_property(server_id):
    """Return (property_key, console_command, legacy_key) for the whitelist toggle.

    Bedrock documents 'allow-list' in server.properties and its only console command
    is 'allowlist' — 'whitelist' does not exist there. BDS does still honour a
    'white-list' line as a legacy alias (verified against BDS 1.26.32.2, where
    'allow-list' takes precedence when both are present), and older panel versions
    wrote exactly that, so reads fall back to it and the toggle rewrites it."""
    server_config = server_manager.get_server_config(server_id)
    if server_config and server_config.get('category') == 'bedrock':
        return 'allow-list', 'allowlist', 'white-list'
    return 'white-list', 'whitelist', None


@app.route('/api/servers/<server_id>/players/whitelist-status', methods=['GET'])
@server_access_required
def get_whitelist_status(server_id):
    """Return whether whitelist is enabled in server.properties"""
    key, _command, legacy = _whitelist_property(server_id)
    server_path = server_manager.get_server_path(server_id)
    properties_path = server_path / 'server.properties'
    if not properties_path.exists():
        return api_success({'enabled': False, 'available': False})
    try:
        legacy_value = None
        with open(properties_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith(f'{key}='):
                    value = line.split('=', 1)[1].strip().lower()
                    return api_success({'enabled': value == 'true', 'available': True, 'property': key})
                if legacy and line.startswith(f'{legacy}='):
                    legacy_value = line.split('=', 1)[1].strip().lower()
        if legacy_value is not None:
            return api_success({'enabled': legacy_value == 'true', 'available': True, 'property': legacy})
        return api_success({'enabled': False, 'available': True, 'property': key})
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/players/whitelist-toggle', methods=['PATCH'])
@server_access_required
def toggle_whitelist_setting(server_id):
    """Toggle the whitelist (Java) / allow-list (Bedrock) property in server.properties"""
    key, command, legacy = _whitelist_property(server_id)
    server_path = server_manager.get_server_path(server_id)
    properties_path = server_path / 'server.properties'
    if not properties_path.exists():
        return api_error('server.properties not found', 404)
    try:
        with open(properties_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        current = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(f'{key}='):
                current = stripped.split('=', 1)[1].strip().lower() == 'true'
                break
            if legacy and stripped.startswith(f'{legacy}='):
                current = stripped.split('=', 1)[1].strip().lower() == 'true'

        new_enabled = not current
        new_line = f'{key}={"true" if new_enabled else "false"}\n'
        updated = []
        written = False
        for line in lines:
            stripped = line.strip()
            # A legacy Bedrock 'white-list' line is rewritten under the current key so
            # the two can never disagree, and an absent key is appended rather than
            # silently dropped.
            if stripped.startswith(f'{key}=') or (legacy and stripped.startswith(f'{legacy}=')):
                if not written:
                    updated.append(new_line)
                    written = True
                continue
            updated.append(line)
        if not written:
            if updated and not updated[-1].endswith('\n'):
                updated[-1] += '\n'
            updated.append(new_line)

        with open(properties_path, 'w', encoding='utf-8') as f:
            f.writelines(updated)
        # server.properties isn't re-read by a running server, so also toggle
        # enforcement live. (The file edit above keeps it persistent across restarts.)
        inst = _running_instance(server_id)
        if inst:
            inst.send_command(f'{command} on' if new_enabled else f'{command} off')
        return api_success({'enabled': new_enabled, 'property': key})
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/players/playerdata', methods=['GET'])
@server_access_required
def get_playerdata(server_id):
    """Get list of player data files"""
    # Check if this is a Bedrock server
    server_config = server_manager.get_server_config(server_id)
    if server_config and server_config.get('category') == 'bedrock':
        return api_success({
            'players': [],
            'message': 'Bedrock servers store player data in LevelDB format (worlds/db/). Individual player data files are not accessible. Use permissions.json and allowlist.json to manage players.'
        })
    
    server_path = server_manager.get_server_path(server_id)

    # Player data lives only in the main world folder (nether/end never had it).
    # Legacy (<= 1.21.x): world/playerdata/<uuid>.dat
    # 26.1+:              world/players/data/<uuid>.dat, next to players/stats/
    #                     and players/advancements/
    # Both layouts are live in the wild: 26.1 restructured the world folder and
    # migrates the old one on first launch, so a panel install can hold servers of
    # either era — probe for both. The 26.1+ form is identified by the data/
    # subdirectory, which also keeps it distinct from pre-1.7.6 worlds, where
    # world/players/ holds <username>.dat files directly (never supported here).
    # Search all subdirectories for either layout.
    playerdata_path = None

    for item in server_path.iterdir():
        if not item.is_dir():
            continue
        # 26.1+ layout first
        new_path = item / 'players' / 'data'
        if new_path.exists():
            playerdata_path = new_path
            break
        # Legacy layout
        old_path = item / 'playerdata'
        if old_path.exists():
            playerdata_path = old_path
            break
    
    if not playerdata_path or not playerdata_path.exists():
        return api_success({'players': [], 'message': 'No playerdata folder found'})

    try:
        players = []
        for item in playerdata_path.iterdir():
            if item.suffix == '.dat':
                stat = item.stat()
                players.append({
                    'uuid': item.stem,
                    'filename': item.name,
                    'path': str(item.relative_to(server_path)),
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                })

        return api_success({'players': players})
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/files/create', methods=['POST'])
@server_access_required
def create_server_file(server_id):
    """Create file or directory"""
    data = request.get_json()
    file_path = data.get('path', '')
    file_type = data.get('type', 'file')
    server_path = server_manager.get_server_path(server_id)
    
    if not is_safe_path(server_path, file_path):
        return api_error('Access denied', 403)

    full_path = server_path / file_path

    try:
        if file_type == 'directory':
            full_path.mkdir(parents=True, exist_ok=True)
        else:
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.touch()
        return jsonify({'success': True})
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/files/delete', methods=['DELETE'])
@server_access_required
def delete_server_file(server_id):
    """Delete file or directory"""
    data = request.get_json()
    file_path = data.get('path', '')
    server_path = server_manager.get_server_path(server_id)
    
    if not is_safe_path(server_path, file_path):
        return api_error('Access denied', 403)

    full_path = server_path / file_path

    if not full_path.exists():
        return api_error('File not found', 404)

    try:
        if full_path.is_dir():
            shutil.rmtree(full_path)
        else:
            full_path.unlink()
        return jsonify({'success': True})
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/files/download', methods=['GET'])
@server_access_required
def download_server_file(server_id):
    """Download a file"""
    requested_path = request.args.get('path', '')
    server_path = server_manager.get_server_path(server_id)
    
    if not is_safe_path(server_path, requested_path):
        return api_error('Access denied', 403)

    full_path = server_path / requested_path

    if not full_path.exists():
        return api_error('File not found', 404)

    return send_file(full_path, as_attachment=True)


@app.route('/api/servers/<server_id>/files/zip', methods=['POST'])
@server_access_required
def zip_server_folder(server_id):
    """Queue a folder-archive job. The zip is built in the background; when the
    job completes, download it from GET /api/jobs/<job_id>/download."""
    data = request.get_json(silent=True) or {}
    requested_path = data.get('path', request.args.get('path', ''))
    server_path = server_manager.get_server_path(server_id)

    if not is_safe_path(server_path, requested_path):
        return api_error('Access denied', 403)

    full_path = server_path / requested_path

    if not full_path.exists():
        return api_error('Path not found', 404)

    if not full_path.is_dir():
        return api_error('Path is not a directory', 400)

    folder_name = full_path.name or 'server'
    cfg = server_manager.get_server_config(server_id) or {}
    server_name = cfg.get('name', server_id)
    job_id = job_manager.submit(
        'zip_download', f'Zip {folder_name}: {server_name}',
        params={'serverId': server_id, 'requestedPath': requested_path},
        created_by=get_current_user()[0],
        server_id=server_id
    )
    return jsonify({'started': True, 'jobId': job_id}), 202

@app.route('/api/servers/<server_id>/files/upload', methods=['POST'])
@limiter.limit("10 per 15 minutes")
@server_access_required
def upload_server_file(server_id):
    """Upload a file"""
    user_id, user = get_current_user()
    if 'file' not in request.files:
        return api_error('No file uploaded', 400)

    file = request.files['file']
    target_path = request.form.get('path', '')
    server_path = server_manager.get_server_path(server_id)

    if not is_safe_path(server_path, target_path):
        return api_error('Access denied', 403)

    filename = secure_filename(file.filename)
    cfg = server_manager.get_server_config(server_id) or {}
    server_name = cfg.get('name', server_id)

    def do_upload():
        dest_dir = server_path / target_path
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / filename
        try:
            file.save(str(dest_path))
            return jsonify({'success': True}), 200
        except Exception as e:
            return api_error(str(e), 500)

    result, status = check_action_policy(
        'fileUpload', user,
        {'serverId': server_id, 'filename': filename, 'path': target_path, 'serverName': server_name},
        target_id=server_id, execute_fn=do_upload,
        description=f'{user.get("username","Unknown")} uploaded "{filename}" to "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status


# ==================== Mods/Plugins API ====================

@app.route('/api/servers/<server_id>/mods', methods=['GET'])
@server_access_required
def list_mods(server_id):
    """List mods and plugins for a server"""
    server_path = server_manager.get_server_path(server_id)
    
    result = {
        'plugins': [],
        'mods': []
    }
    
    # List plugins folder
    plugins_dir = server_path / 'plugins'
    if plugins_dir.exists():
        for item in plugins_dir.iterdir():
            if item.is_file() and (item.suffix == '.jar' or item.name.endswith('.jar.disabled')):
                stat = item.stat()
                result['plugins'].append({
                    'name': item.name,
                    'size': stat.st_size,
                    'modified': stat.st_mtime * 1000
                })
    
    # List mods folder
    mods_dir = server_path / 'mods'
    if mods_dir.exists():
        for item in mods_dir.iterdir():
            if item.is_file() and (item.suffix == '.jar' or item.name.endswith('.jar.disabled')):
                stat = item.stat()
                result['mods'].append({
                    'name': item.name,
                    'size': stat.st_size,
                    'modified': stat.st_mtime * 1000
                })
    
    # Sort by name
    result['plugins'].sort(key=lambda x: x['name'].lower())
    result['mods'].sort(key=lambda x: x['name'].lower())

    return api_success(result)

@app.route('/api/servers/<server_id>/mods/upload', methods=['POST'])
@limiter.limit("20 per 15 minutes")
@server_access_required
def upload_mod(server_id):
    """Upload a mod or plugin"""
    user_id, user = get_current_user()
    if 'file' not in request.files:
        return api_error('No file uploaded', 400)

    file = request.files['file']
    mod_type = request.form.get('type', 'plugins')

    if mod_type not in ['plugins', 'mods']:
        return api_error('Invalid mod type', 400)

    if not file.filename.endswith('.jar'):
        return api_error('File must be a JAR file', 400)

    server_path = server_manager.get_server_path(server_id)
    filename = secure_filename(file.filename)
    cfg = server_manager.get_server_config(server_id) or {}
    server_name = cfg.get('name', server_id)

    def do_upload():
        target_dir = server_path / mod_type
        target_dir.mkdir(parents=True, exist_ok=True)
        dest_path = target_dir / filename
        try:
            file.save(str(dest_path))
            rejected = reject_if_not_zip(dest_path)
            if rejected:
                return rejected
            return jsonify({'success': True, 'filename': filename}), 200
        except Exception as e:
            return api_error(str(e), 500)

    result, status = check_action_policy(
        'modManagement', user,
        {'serverId': server_id, 'filename': filename, 'modType': mod_type, 'action': 'upload', 'serverName': server_name},
        target_id=server_id, execute_fn=do_upload,
        description=f'{user.get("username","Unknown")} uploaded {mod_type[:-1]} "{filename}" to "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status

@app.route('/api/servers/<server_id>/mods/<mod_type>/<filename>/enable', methods=['POST'])
@server_access_required
def enable_mod(server_id, mod_type, filename):
    """Enable a disabled mod"""
    user_id, user = get_current_user()
    if mod_type not in ['plugins', 'mods']:
        return api_error('Invalid mod type', 400)

    server_path = server_manager.get_server_path(server_id)
    mod_dir = server_path / mod_type

    safe_fn = secure_filename(filename)
    if safe_fn != filename or '..' in filename or '/' in filename:
        return api_error('Invalid filename', 400)

    disabled_path = mod_dir / filename
    if not disabled_path.exists() or not filename.endswith('.disabled'):
        return api_error('Disabled mod not found', 404)

    enabled_name = filename.rsplit('.disabled', 1)[0]
    cfg = server_manager.get_server_config(server_id) or {}
    server_name = cfg.get('name', server_id)

    def do_enable():
        enabled_path = mod_dir / enabled_name
        try:
            disabled_path.rename(enabled_path)
            return jsonify({'success': True, 'filename': enabled_name}), 200
        except Exception as e:
            return api_error(str(e), 500)

    result, status = check_action_policy(
        'modManagement', user,
        {'serverId': server_id, 'filename': filename, 'modType': mod_type, 'action': 'enable', 'serverName': server_name},
        target_id=server_id, execute_fn=do_enable,
        description=f'{user.get("username","Unknown")} enabled {mod_type[:-1]} "{enabled_name}" on "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status

@app.route('/api/servers/<server_id>/mods/<mod_type>/<filename>/disable', methods=['POST'])
@server_access_required
def disable_mod(server_id, mod_type, filename):
    """Disable a mod by renaming it"""
    user_id, user = get_current_user()
    if mod_type not in ['plugins', 'mods']:
        return api_error('Invalid mod type', 400)

    server_path = server_manager.get_server_path(server_id)
    mod_dir = server_path / mod_type

    safe_fn = secure_filename(filename)
    if safe_fn != filename or '..' in filename or '/' in filename:
        return api_error('Invalid filename', 400)

    mod_path = mod_dir / filename
    if not mod_path.exists():
        return api_error('Mod not found', 404)

    cfg = server_manager.get_server_config(server_id) or {}
    server_name = cfg.get('name', server_id)

    def do_disable():
        disabled_path = mod_dir / (filename + '.disabled')
        try:
            mod_path.rename(disabled_path)
            return jsonify({'success': True, 'filename': filename + '.disabled'}), 200
        except Exception as e:
            return api_error(str(e), 500)

    result, status = check_action_policy(
        'modManagement', user,
        {'serverId': server_id, 'filename': filename, 'modType': mod_type, 'action': 'disable', 'serverName': server_name},
        target_id=server_id, execute_fn=do_disable,
        description=f'{user.get("username","Unknown")} disabled {mod_type[:-1]} "{filename}" on "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status

@app.route('/api/servers/<server_id>/mods/<mod_type>/<filename>', methods=['DELETE'])
@server_access_required
def delete_mod(server_id, mod_type, filename):
    """Delete a mod or plugin"""
    user_id, user = get_current_user()
    if mod_type not in ['plugins', 'mods']:
        return api_error('Invalid mod type', 400)

    server_path = server_manager.get_server_path(server_id)
    mod_dir = server_path / mod_type

    safe_fn = secure_filename(filename)
    if safe_fn != filename or '..' in filename or '/' in filename:
        return api_error('Invalid filename', 400)

    mod_path = mod_dir / filename
    if not mod_path.exists():
        return api_error('Mod not found', 404)

    cfg = server_manager.get_server_config(server_id) or {}
    server_name = cfg.get('name', server_id)

    def do_delete():
        try:
            mod_path.unlink()
            return jsonify({'success': True}), 200
        except Exception as e:
            return api_error(str(e), 500)

    result, status = check_action_policy(
        'modManagement', user,
        {'serverId': server_id, 'filename': filename, 'modType': mod_type, 'action': 'delete', 'serverName': server_name},
        target_id=server_id, execute_fn=do_delete,
        description=f'{user.get("username","Unknown")} deleted {mod_type[:-1]} "{filename}" from "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status


# ==================== Modrinth Integration ====================

MODRINTH_API = 'https://api.modrinth.com/v2'
MODRINTH_UA  = 'TwiStarSystems/MServer/1.0 (github.com/TwiStarSystems)'

def _modrinth_get(path, params=None, timeout=15):
    """Make a GET request to the Modrinth API with proper headers."""
    headers = {'User-Agent': MODRINTH_UA}
    resp = requests.get(f'{MODRINTH_API}{path}', headers=headers, params=params, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


@app.route('/api/servers/<server_id>/mods/search', methods=['GET'])
@server_access_required
def modrinth_search(server_id):
    """Proxy a Modrinth project search to keep credentials/UA server-side."""
    query        = request.args.get('query', '').strip()
    project_type = request.args.get('projectType', 'mod')   # mod | plugin | modpack
    loader       = request.args.get('loader', '')             # fabric, forge, spigot, paper …
    mc_version   = request.args.get('mcVersion', '')
    limit        = min(int(request.args.get('limit', 20)), 50)
    offset       = max(int(request.args.get('offset', 0)), 0)

    # Build facets: always filter to server-side-relevant and requested project_type
    facets = []
    if project_type == 'plugin':
        # Plugins live under project_type:mod on Modrinth but with loader 'spigot'/'paper' etc.
        facets.append(['project_type:mod'])
        if loader:
            facets.append([f'categories:{loader}'])
        else:
            facets.append(['categories:paper', 'categories:spigot', 'categories:bukkit', 'categories:folia', 'categories:purpur'])
    else:
        facets.append([f'project_type:{project_type}'])
        if loader:
            facets.append([f'categories:{loader}'])

    if mc_version:
        facets.append([f'versions:{mc_version}'])

    # Always prefer server-side content
    facets.append(['server_side:required', 'server_side:optional'])

    params = {
        'query': query,
        'limit': limit,
        'offset': offset,
        'facets': json.dumps(facets),
        'index': 'relevance',
    }

    try:
        data = _modrinth_get('/search', params=params)
        # Slim down the response to only what the frontend needs
        hits = []
        for h in data.get('hits', []):
            hits.append({
                'projectId':    h.get('project_id'),
                'slug':         h.get('slug'),
                'title':        h.get('title'),
                'description':  h.get('description'),
                'iconUrl':      h.get('icon_url'),
                'downloads':    h.get('downloads', 0),
                'categories':   h.get('categories', []),
                'versions':     h.get('versions', []),
                'gameVersions': h.get('display_categories', h.get('versions', [])),
                'latestVersion': h.get('latest_version'),
                'projectType':  h.get('project_type'),
                'author':       h.get('author'),
            })
        return api_success({
            'hits':     hits,
            'totalHits': data.get('total_hits', 0),
            'offset':   data.get('offset', 0),
            'limit':    data.get('limit', limit),
        })
    except requests.exceptions.Timeout:
        return api_error('Modrinth API timed out', 504)
    except requests.exceptions.RequestException as e:
        return api_error(f'Modrinth API error: {str(e)}', 502)


@app.route('/api/servers/<server_id>/mods/modrinth/versions/<project_id>', methods=['GET'])
@server_access_required
def modrinth_project_versions(server_id, project_id):
    """Return available versions for a Modrinth project, filtered by loader/mc_version."""
    # Validate project_id is safe (base62 or slug)
    if not re.match(r'^[a-zA-Z0-9_\-]{1,64}$', project_id):
        return api_error('Invalid project ID', 400)

    loader     = request.args.get('loader', '')
    mc_version = request.args.get('mcVersion', '')

    params = {'include_changelog': 'false'}
    if loader:
        params['loaders'] = json.dumps([loader])
    if mc_version:
        params['game_versions'] = json.dumps([mc_version])

    try:
        versions = _modrinth_get(f'/project/{project_id}/version', params=params)
        slim = []
        for v in versions:
            # Pick the primary file (.jar only)
            jar_file = next((f for f in v.get('files', []) if f.get('primary') and f['filename'].endswith('.jar')), None)
            if jar_file is None:
                jar_file = next((f for f in v.get('files', []) if f['filename'].endswith('.jar')), None)
            if jar_file is None:
                continue
            slim.append({
                'versionId':    v.get('id'),
                'versionNumber': v.get('version_number'),
                'name':         v.get('name'),
                'loaders':      v.get('loaders', []),
                'gameVersions': v.get('game_versions', []),
                'datePublished': v.get('date_published'),
                'filename':     jar_file['filename'],
                'url':          jar_file['url'],
                'size':         jar_file.get('size', 0),
                'sha512':       jar_file.get('hashes', {}).get('sha512'),
                'sha1':         jar_file.get('hashes', {}).get('sha1'),
            })
        return api_success({'versions': slim})
    except requests.exceptions.Timeout:
        return api_error('Modrinth API timed out', 504)
    except requests.exceptions.RequestException as e:
        return api_error(f'Modrinth API error: {str(e)}', 502)


@app.route('/api/servers/<server_id>/mods/modrinth/install', methods=['POST'])
@limiter.limit("30 per 10 minutes")
@server_access_required
def modrinth_install(server_id):
    """Download a mod/plugin version from Modrinth and save it to the server."""
    data       = request.get_json()
    url        = data.get('url', '').strip()
    filename   = data.get('filename', '').strip()
    mod_type   = data.get('modType', 'mods')   # 'mods' or 'plugins'
    sha512_expected = data.get('sha512', '')

    # Validate inputs
    if not url or not filename:
        return api_error('url and filename are required', 400)
    if mod_type not in ('mods', 'plugins'):
        return api_error('modType must be mods or plugins', 400)
    if not filename.endswith('.jar'):
        return api_error('filename must be a .jar file', 400)

    # Only allow downloads from Modrinth CDN
    if not url.startswith('https://cdn.modrinth.com/'):
        return api_error('Only Modrinth CDN URLs are permitted', 400)

    safe_filename = secure_filename(filename)
    if not safe_filename:
        return api_error('Invalid filename', 400)

    server_path = server_manager.get_server_path(server_id)
    target_dir  = server_path / mod_type
    target_dir.mkdir(parents=True, exist_ok=True)
    dest_path   = target_dir / safe_filename

    try:
        resp = requests.get(url, headers={'User-Agent': MODRINTH_UA}, timeout=120, stream=True)
        resp.raise_for_status()

        sha512_actual = hashlib.sha512()
        with open(str(dest_path), 'wb') as f:
            for chunk in resp.iter_content(65536):
                f.write(chunk)
                sha512_actual.update(chunk)

        # Verify integrity if hash provided
        if sha512_expected and sha512_actual.hexdigest() != sha512_expected:
            dest_path.unlink(missing_ok=True)
            return api_error('SHA-512 integrity check failed — file deleted', 409)

        return jsonify({'success': True, 'filename': safe_filename})
    except requests.exceptions.Timeout:
        dest_path.unlink(missing_ok=True)
        return api_error('Download timed out', 504)
    except requests.exceptions.RequestException as e:
        dest_path.unlink(missing_ok=True)
        return api_error(f'Download failed: {str(e)}', 502)
    except Exception as e:
        dest_path.unlink(missing_ok=True)
        return api_error(str(e), 500)


@app.route('/api/servers/<server_id>/mods/updates', methods=['GET'])
@server_access_required
def check_mod_updates(server_id):
    """Check installed mods/plugins for available updates via Modrinth's hash lookup."""
    server_path  = server_manager.get_server_path(server_id)
    loader       = request.args.get('loader', '')
    mc_version   = request.args.get('mcVersion', '')

    jar_files = []
    for folder in ('mods', 'plugins'):
        folder_path = server_path / folder
        if folder_path.exists():
            for item in folder_path.iterdir():
                if item.is_file() and item.suffix == '.jar':
                    jar_files.append({'path': item, 'folder': folder})

    if not jar_files:
        return api_success({'updates': [], 'notOnModrinth': []})

    # Compute SHA-512 hashes for all jars
    hashes = {}
    for entry in jar_files:
        sha = hashlib.sha512()
        try:
            with open(str(entry['path']), 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha.update(chunk)
            hashes[sha.hexdigest()] = entry
        except OSError:
            pass

    if not hashes:
        return api_success({'updates': [], 'notOnModrinth': []})

    # Ask Modrinth for the latest version matching these hashes
    try:
        body = {
            'hashes': list(hashes.keys()),
            'algorithm': 'sha512',
        }
        if loader:
            body['loaders'] = [loader]
        if mc_version:
            body['game_versions'] = [mc_version]

        headers = {'User-Agent': MODRINTH_UA, 'Content-Type': 'application/json'}
        resp = requests.post(
            f'{MODRINTH_API}/version_files/update',
            json=body,
            headers=headers,
            timeout=20
        )
        resp.raise_for_status()
        latest_map = resp.json()   # {current_hash: {version object with latest available}}
    except requests.exceptions.Timeout:
        return api_error('Modrinth API timed out', 504)
    except requests.exceptions.RequestException as e:
        return api_error(f'Modrinth API error: {str(e)}', 502)

    updates = []
    not_on_modrinth = []

    for current_hash, entry in hashes.items():
        if current_hash in latest_map:
            latest = latest_map[current_hash]
            jar_file = next((f for f in latest.get('files', []) if f.get('primary') and f['filename'].endswith('.jar')), None)
            if jar_file is None:
                jar_file = next((f for f in latest.get('files', []) if f['filename'].endswith('.jar')), None)

            latest_hash = (jar_file.get('hashes', {}).get('sha512') if jar_file else None)

            if latest_hash and latest_hash != current_hash:
                updates.append({
                    'currentFilename': entry['path'].name,
                    'folder':          entry['folder'],
                    'projectId':       latest.get('project_id'),
                    'versionId':       latest.get('id'),
                    'versionNumber':   latest.get('version_number'),
                    'filename':        jar_file['filename'] if jar_file else '',
                    'url':             jar_file['url'] if jar_file else '',
                    'sha512':          latest_hash,
                    'size':            jar_file.get('size', 0) if jar_file else 0,
                })
        else:
            not_on_modrinth.append(entry['path'].name)

    return api_success({
        'updates':        updates,
        'notOnModrinth':  not_on_modrinth,
    })


# ==================== Properties API ====================

@app.route('/api/servers/<server_id>/properties/exists', methods=['GET'])
@server_access_required
def check_properties_exists(server_id):
    """Check if server.properties file exists"""
    server_path = server_manager.get_server_path(server_id)
    properties_path = server_path / 'server.properties'

    return api_success({'exists': properties_path.exists()})

@app.route('/api/servers/<server_id>/properties', methods=['GET'])
@server_access_required
def get_properties(server_id):
    """Get server properties"""
    server_path = server_manager.get_server_path(server_id)
    properties_path = server_path / 'server.properties'
    
    if not properties_path.exists():
        return api_error('server.properties not found. Start the server at least once to generate it.', 404)

    try:
        properties = {}
        with open(properties_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        properties[key.strip()] = value.strip()

        return api_success({'properties': properties})
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/properties', methods=['POST'])
@server_access_required
def save_properties(server_id):
    """Save server properties"""
    server_path = server_manager.get_server_path(server_id)
    properties_path = server_path / 'server.properties'
    
    if not properties_path.exists():
        return api_error('server.properties not found', 404)

    data = request.json
    if not data or 'properties' not in data:
        return api_error('Missing properties', 400)
    
    new_properties = data['properties']

    # Check for duplicate port and write the file under a single lock so two
    # concurrent requests can't both pass the "port is free" check and then each
    # commit the same port to a different server (issue #11).
    with server_manager.port_lock:
        if 'server-port' in new_properties:
            new_port = new_properties['server-port']
            existing_ports = server_manager.get_all_server_ports(exclude_server_id=server_id)

            # Check if this port is already in use by another server
            for other_server_id, port in existing_ports.items():
                if port == new_port:
                    other_server_config = server_manager.get_server_config(other_server_id)
                    other_server_name = other_server_config.get('name', 'Unknown Server') if other_server_config else 'Unknown Server'
                    return api_error(f'Port {new_port} is already in use by server: {other_server_name}', 400)

        try:
            # Read existing file to preserve comments and order
            lines = []
            with open(properties_path, 'r', encoding='utf-8') as f:
                for line in f:
                    stripped = line.strip()
                    # Preserve comments and empty lines
                    if not stripped or stripped.startswith('#'):
                        lines.append(line)
                    elif '=' in stripped:
                        key, _ = stripped.split('=', 1)
                        key = key.strip()
                        # Update with new value if exists, otherwise keep original
                        if key in new_properties:
                            lines.append(f'{key}={new_properties[key]}\n')
                            # Mark as processed
                            new_properties.pop(key)
                        else:
                            lines.append(line)
                    else:
                        lines.append(line)

            # Append any new properties that weren't in the original file
            if new_properties:
                lines.append('\n# Added by MServer\n')
                for key, value in new_properties.items():
                    lines.append(f'{key}={value}\n')

            # Write back to file
            with open(properties_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)

            return jsonify({'success': True})
        except Exception as e:
            return api_error(str(e), 500)


# ==================== Resource Pack API ====================

@app.route('/api/servers/<server_id>/resourcepack', methods=['GET'])
@server_access_required
def get_resourcepack_info(server_id):
    """Get resource pack information for a server"""
    server_config = server_manager.get_server_config(server_id)
    if server_config and server_config.get('category') == 'bedrock':
        return api_error('Resource packs are not supported for Bedrock servers', 400)

    server_path = server_manager.get_server_path(server_id)
    resourcepack_path = RESOURCEPACKS_DIR / f"{server_id}.zip"

    if not resourcepack_path.exists():
        return api_success({'exists': False})

    try:
        stat = resourcepack_path.stat()

        # Calculate SHA1 hash
        sha1_hash = hashlib.sha1()
        with open(resourcepack_path, 'rb') as f:
            while chunk := f.read(8192):
                sha1_hash.update(chunk)

        # Get base URL from settings
        base_url = settings_manager.get_branding().get('baseUrl', '')
        pack_url = f"{base_url}/resourcepacks/{server_id}.zip" if base_url else ''

        return api_success({
            'exists': True,
            'filename': resourcepack_path.name,
            'size': stat.st_size,
            'uploaded': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'sha1': sha1_hash.hexdigest(),
            'url': pack_url
        })
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/resourcepack/upload', methods=['POST'])
@server_access_required
def upload_resourcepack(server_id):
    """Upload a resource pack for a server"""
    server_config = server_manager.get_server_config(server_id)
    if server_config and server_config.get('category') == 'bedrock':
        return api_error('Resource packs are not supported for Bedrock servers', 400)

    if 'file' not in request.files:
        return api_error('No file provided', 400)

    file = request.files['file']

    if file.filename == '':
        return api_error('No file selected', 400)

    # Check file extension
    if not file.filename.lower().endswith('.zip'):
        return api_error('File must be a .zip file', 400)

    # Check file size (default 100MB; MAX_RESOURCEPACK_SIZE_MB in .env)
    MAX_SIZE = MAX_RESOURCEPACK_SIZE_MB * 1024 * 1024
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)

    if file_size > MAX_SIZE:
        return api_error(f'File size exceeds {MAX_RESOURCEPACK_SIZE_MB}MB limit (size: {file_size / (1024*1024):.2f}MB)', 400)
    
    try:
        # Save the file
        resourcepack_path = RESOURCEPACKS_DIR / f"{server_id}.zip"
        file.save(str(resourcepack_path))

        rejected = reject_if_not_zip(resourcepack_path)
        if rejected:
            return rejected

        # Calculate SHA1 hash
        sha1_hash = hashlib.sha1()
        with open(resourcepack_path, 'rb') as f:
            while chunk := f.read(8192):
                sha1_hash.update(chunk)
        
        sha1_hex = sha1_hash.hexdigest()
        
        # Get base URL from settings
        base_url = settings_manager.get_branding().get('baseUrl', '')
        if not base_url:
            return api_error('Base URL is not configured. Please set it in Settings > Branding.', 400)
        
        pack_url = f"{base_url}/resourcepacks/{server_id}.zip"
        
        # Update server.properties if it exists
        properties_path = server_manager.get_server_path(server_id) / 'server.properties'
        if properties_path.exists():
            # Read existing properties
            lines = []
            resource_pack_found = False
            resource_pack_sha1_found = False
            
            with open(properties_path, 'r', encoding='utf-8') as f:
                for line in f:
                    stripped = line.strip()
                    if stripped.startswith('resource-pack='):
                        lines.append(f'resource-pack={pack_url}\n')
                        resource_pack_found = True
                    elif stripped.startswith('resource-pack-sha1='):
                        lines.append(f'resource-pack-sha1={sha1_hex}\n')
                        resource_pack_sha1_found = True
                    else:
                        lines.append(line)
            
            # Add properties if they don't exist
            if not resource_pack_found or not resource_pack_sha1_found:
                lines.append('\n# Resource Pack Configuration (added by MServer)\n')
                if not resource_pack_found:
                    lines.append(f'resource-pack={pack_url}\n')
                if not resource_pack_sha1_found:
                    lines.append(f'resource-pack-sha1={sha1_hex}\n')
            
            # Write back
            with open(properties_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
        
        stat = resourcepack_path.stat()
        
        return jsonify({
            'success': True,
            'filename': resourcepack_path.name,
            'size': stat.st_size,
            'sha1': sha1_hex,
            'url': pack_url,
            'propertiesUpdated': properties_path.exists()
        })
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/resourcepack', methods=['DELETE'])
@server_access_required
def delete_resourcepack(server_id):
    """Delete resource pack for a server"""
    server_config = server_manager.get_server_config(server_id)
    if server_config and server_config.get('category') == 'bedrock':
        return api_error('Resource packs are not supported for Bedrock servers', 400)

    resourcepack_path = RESOURCEPACKS_DIR / f"{server_id}.zip"

    if not resourcepack_path.exists():
        return api_error('No resource pack found', 404)

    try:
        resourcepack_path.unlink()

        # Remove from server.properties if it exists
        properties_path = server_manager.get_server_path(server_id) / 'server.properties'
        if properties_path.exists():
            lines = []
            with open(properties_path, 'r', encoding='utf-8') as f:
                for line in f:
                    stripped = line.strip()
                    # Remove resource pack lines
                    if not stripped.startswith('resource-pack=') and not stripped.startswith('resource-pack-sha1='):
                        lines.append(line)

            with open(properties_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)

        return jsonify({'success': True})
    except Exception as e:
        return api_error(str(e), 500)


# ==================== Backup API ====================

@app.route('/api/servers/<server_id>/backups', methods=['GET'])
@server_access_required
def list_backups(server_id):
    """List backups for a server"""
    backup_dir = BACKUPS_DIR / server_id

    if not backup_dir.exists():
        return api_success({'backups': []})

    # Auto-detect every backup by scanning the folder for .zip files. All backups
    # (manual, scheduled, pre-version-change, pre-jar-update, imported, or files
    # copied in by hand) are .zip, so a case-insensitive suffix match surfaces them
    # all without relying on any index or naming convention.
    backups = []
    for item in backup_dir.iterdir():
        if item.is_file() and item.suffix.lower() == '.zip':
            stat = item.stat()
            entry = {
                'name': item.name,
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'isScheduled': item.name.startswith('scheduled-backup-'),
                'hasChecksum': item.with_suffix('.sha256').exists()
            }
            backups.append(entry)

    backups.sort(key=lambda x: x['created'], reverse=True)

    # Mark expired backups beyond the global retention limit
    max_backups = settings_manager.get_app_settings().get('globalMaxBackups', 0)
    for i, b in enumerate(backups):
        b['expired'] = bool(max_backups > 0 and i >= max_backups)

    return api_success({'backups': backups})

@app.route('/api/servers/<server_id>/backups/create', methods=['POST'])
@limiter.limit("5 per 15 minutes")
@server_access_required
def create_backup(server_id):
    """Queue a manual backup on the unified job queue."""
    user_id, user = get_current_user()
    server_path = server_manager.get_server_path(server_id)

    if not server_path.exists():
        return api_error('Server path not found', 400)

    data = request.get_json(silent=True) or {}
    compression_level = max(0, min(9, int(data.get('compressionLevel', 6))))
    backup_type = str(data.get('backupType', 'manual'))

    custom_name = data.get('customName', '').strip()
    if custom_name:
        custom_name = secure_filename(custom_name)
        if not custom_name:
            return api_error('Invalid backup name', 400)
        if not custom_name.lower().endswith('.zip'):
            custom_name += '.zip'
        if (BACKUPS_DIR / server_id / custom_name).exists():
            return api_error('A backup with that name already exists', 409)

    cfg = server_manager.get_server_config(server_id) or {}
    server_name = cfg.get('name', server_id)
    job_params = {'serverId': server_id, 'compressionLevel': compression_level,
                  'backupType': backup_type}
    if custom_name:
        job_params['customName'] = custom_name

    def do_backup():
        job_id = job_manager.submit(
            'backup', f'Backup: {server_name}',
            params=job_params, created_by=user_id, server_id=server_id)
        return jsonify({'started': True, 'jobId': job_id}), 202

    result, status = check_action_policy(
        'backupCreate', user,
        {**job_params, 'serverName': server_name},
        target_id=server_id, execute_fn=do_backup,
        description=f'{user.get("username","Unknown")} created backup for "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status

@app.route('/api/servers/<server_id>/backups/download', methods=['GET'])
@server_access_required
def download_backup(server_id):
    """Download a backup"""
    backup_name = request.args.get('name', '')

    # Security: sanitize filename and prevent path traversal
    backup_name = secure_filename(backup_name)
    if not backup_name or '..' in backup_name or '/' in backup_name:
        return api_error('Invalid backup name', 400)

    backup_path = BACKUPS_DIR / server_id / backup_name

    # Additional security check: ensure path is within backups directory
    try:
        backup_path = backup_path.resolve()
        if not str(backup_path).startswith(str(BACKUPS_DIR.resolve())):
            return api_error('Invalid backup path', 400)
    except Exception:
        return api_error('Invalid backup path', 400)

    if not backup_path.exists():
        return api_error('Backup not found', 404)

    return send_file(backup_path, as_attachment=True)

@app.route('/api/servers/<server_id>/backups/delete', methods=['DELETE'])
@server_access_required
def delete_backup(server_id):
    """Delete a backup"""
    user_id, user = get_current_user()
    data = request.get_json()
    backup_name = data.get('name', '')

    backup_name = secure_filename(backup_name)
    if not backup_name or '..' in backup_name or '/' in backup_name:
        return api_error('Invalid backup name', 400)

    backup_path = BACKUPS_DIR / server_id / backup_name

    try:
        backup_path = backup_path.resolve()
        if not str(backup_path).startswith(str(BACKUPS_DIR.resolve())):
            return api_error('Invalid backup path', 400)
    except Exception:
        return api_error('Invalid backup path', 400)

    if not backup_path.exists():
        return api_error('Backup not found', 404)

    cfg = server_manager.get_server_config(server_id) or {}
    server_name = cfg.get('name', server_id)

    def do_delete():
        try:
            backup_path.unlink()
            return jsonify({'success': True}), 200
        except Exception as e:
            return api_error(str(e), 500)

    result, status = check_action_policy(
        'backupDelete', user,
        {'serverId': server_id, 'backupName': backup_name, 'serverName': server_name},
        target_id=server_id, execute_fn=do_delete,
        description=f'{user.get("username","Unknown")} deleted backup "{backup_name}" from "{server_name}".')
    return jsonify(result) if isinstance(result, dict) else result, status

@app.route('/api/servers/<server_id>/backups/rename', methods=['POST'])
@server_access_required
def rename_backup(server_id):
    data = request.get_json()
    old_name = secure_filename(data.get('oldName', ''))
    new_name = secure_filename(data.get('newName', ''))
    if not old_name or not new_name:
        return api_error('Invalid backup name', 400)
    if not new_name.lower().endswith('.zip'):
        new_name += '.zip'

    backup_dir = (BACKUPS_DIR / server_id).resolve()
    old_path = (BACKUPS_DIR / server_id / old_name).resolve()
    new_path = (BACKUPS_DIR / server_id / new_name).resolve()

    if not str(old_path).startswith(str(backup_dir)) or not str(new_path).startswith(str(backup_dir)):
        return api_error('Invalid backup path', 400)
    if not old_path.exists():
        return api_error('Backup not found', 404)
    if new_path.exists():
        return api_error('A backup with that name already exists', 409)

    try:
        old_path.rename(new_path)
        checksum_old = old_path.with_suffix('.sha256')
        if checksum_old.exists():
            checksum_old.rename(new_path.with_suffix('.sha256'))
        return jsonify({'success': True, 'newName': new_name})
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/servers/<server_id>/backups/restore', methods=['POST'])
@server_access_required
def restore_backup(server_id):
    """Restore a backup. Stops the server if running, clears the server directory,
    extracts the backup, then restarts the server if it was running.
    Returns 202 immediately; result is pushed via socket events:
      restore_completed / restore_failed
    """
    data = request.get_json()
    backup_name = data.get('name', '')

    # Security: sanitize filename and prevent path traversal
    backup_name = secure_filename(backup_name)
    if not backup_name or '..' in backup_name or '/' in backup_name:
        return api_error('Invalid backup name', 400)

    backup_path = BACKUPS_DIR / server_id / backup_name

    # Additional security check: ensure path is within backups directory
    try:
        backup_path = backup_path.resolve()
        if not str(backup_path).startswith(str(BACKUPS_DIR.resolve())):
            return api_error('Invalid backup path', 400)
    except Exception:
        return api_error('Invalid backup path', 400)

    if not backup_path.exists():
        return api_error('Backup not found', 404)

    cfg = server_manager.get_server_config(server_id) or {}
    server_name = cfg.get('name', server_id)
    job_id = job_manager.submit(
        'restore', f'Restore: {server_name}',
        params={'serverId': server_id, 'backupName': backup_name},
        created_by=get_current_user()[0],
        server_id=server_id
    )
    return jsonify({'started': True, 'jobId': job_id}), 202


@app.route('/api/servers/<server_id>/backups/import', methods=['POST'])
@server_access_required
def import_backup(server_id):
    """Import a backup ZIP file uploaded by the user"""
    if 'file' not in request.files:
        return api_error('No file provided', 400)

    f = request.files['file']
    if not f or not f.filename:
        return api_error('No file selected', 400)

    filename = secure_filename(f.filename)
    if not filename.lower().endswith('.zip'):
        return api_error('Only .zip files are supported', 400)

    backup_dir = BACKUPS_DIR / server_id
    backup_dir.mkdir(parents=True, exist_ok=True)

    dest_path = backup_dir / filename

    # Avoid overwriting an existing file by appending a timestamp
    if dest_path.exists():
        ts = datetime.now().strftime('%Y%m%dT%H%M%S')
        stem = filename[:-4]
        filename = f"{stem}-imported-{ts}.zip"
        dest_path = backup_dir / filename

    try:
        f.save(str(dest_path))

        # Validate it is a real zip
        if not zipfile.is_zipfile(dest_path):
            dest_path.unlink()
            return api_error('Uploaded file is not a valid ZIP archive', 400)

        size = dest_path.stat().st_size
        return jsonify({'success': True, 'backup': filename, 'size': size})
    except Exception as e:
        if dest_path.exists():
            dest_path.unlink()
        return api_error(str(e), 500)


# ==================== Backup Schedule API ====================

@app.route('/api/servers/<server_id>/backups/schedule', methods=['GET'])
@server_access_required
def get_backup_schedule(server_id):
    """Get the backup schedule for a server"""
    schedule = backup_scheduler.get_schedule(server_id)
    if schedule:
        return api_success({'schedule': schedule})
    return api_success({'schedule': None})

@app.route('/api/servers/<server_id>/backups/schedule', methods=['POST'])
@server_access_required
def set_backup_schedule(server_id):
    """Set or update the backup schedule for a server"""
    data = request.get_json()
    
    # Validate server exists
    server_config = server_manager.get_server_config(server_id)
    if not server_config:
        return api_error('Server not found', 404)

    schedule = backup_scheduler.set_schedule(server_id, {
        'enabled': data.get('enabled', True),
        'type': data.get('type', 'daily'),
        'hour': data.get('hour', 3),
        'minute': data.get('minute', 0),
        'dayOfWeek': data.get('dayOfWeek', 0),
        'cron': data.get('cron', ''),
        'stopServer': data.get('stopServer', True),
        'restartAfter': data.get('restartAfter', True),
        'compressionLevel': data.get('compressionLevel', 6),
    })
    
    return jsonify({'success': True, 'schedule': schedule})

@app.route('/api/servers/<server_id>/backups/schedule', methods=['DELETE'])
@server_access_required
def delete_backup_schedule(server_id):
    """Delete the backup schedule for a server"""
    if backup_scheduler.delete_schedule(server_id):
        return jsonify({'success': True})
    return api_error('No schedule found for this server', 404)

@app.route('/api/servers/<server_id>/backups/delete-expired', methods=['POST'])
@server_access_required
def delete_expired_backups_for_server(server_id):
    """Delete all expired backups for a single server"""
    max_backups = settings_manager.get_app_settings().get('globalMaxBackups', 0)
    if max_backups <= 0:
        return api_error('No backup retention limit is configured. Set "Hold X Backups" in Game Server Settings first.', 400)
    deleted = backup_scheduler._cleanup_old_backups(server_id, max_backups)
    return jsonify({'success': True, 'deleted': deleted})

@app.route('/api/backups/delete-expired', methods=['POST'])
@permission_required('panel.settings.manage')
def delete_all_expired_backups():
    """Delete expired backups across all servers (admin only)"""
    max_backups = settings_manager.get_app_settings().get('globalMaxBackups', 0)
    if max_backups <= 0:
        return api_error('No backup retention limit is configured. Set "Hold X Backups" in Game Server Settings first.', 400)
    total_deleted = 0
    for server_id in list(server_manager.get_all_server_ids()):
        total_deleted += backup_scheduler._cleanup_old_backups(server_id, max_backups)
    return api_success(deleted=total_deleted)

@app.route('/api/servers/<server_id>/backups/history', methods=['GET'])
@server_access_required
def get_backup_history(server_id):
    """Get the backup event history for a server"""
    events = backup_scheduler.get_backup_history(server_id)
    return api_success({'events': events})


@app.route('/api/servers/<server_id>/backups/verify', methods=['POST'])
@server_access_required
def verify_backup(server_id):
    """Verify a backup file's integrity and compute its checksum"""
    data = request.get_json()
    backup_name = data.get('name', '')

    backup_name = secure_filename(backup_name)
    if not backup_name or '..' in backup_name or '/' in backup_name:
        return api_error('Invalid backup name', 400)

    backup_path = BACKUPS_DIR / server_id / backup_name
    try:
        backup_path = backup_path.resolve()
        if not str(backup_path).startswith(str(BACKUPS_DIR.resolve())):
            return api_error('Invalid backup path', 400)
    except Exception:
        return api_error('Invalid backup path', 400)

    if not backup_path.exists():
        return api_error('Backup not found', 404)

    ok, checksum, error = verify_backup_file(backup_path)

    return jsonify({
        'success': ok,
        'backup': backup_name,
        'checksum': checksum,
        'error': error
    })


# ==================== Task Scheduler API ====================

@app.route('/api/servers/<server_id>/tasks', methods=['GET'])
@server_access_required
def get_server_tasks(server_id):
    """Get all tasks for a server"""
    tasks = task_scheduler.get_tasks(server_id)
    return api_success({'tasks': tasks})

@app.route('/api/servers/<server_id>/tasks', methods=['POST'])
@server_access_required
def create_server_task(server_id):
    """Create a new task for a server"""
    data = request.get_json()

    # Validate server exists
    server_config = server_manager.get_server_config(server_id)
    if not server_config:
        return api_error('Server not found', 404)

    # Validate required fields
    if not data.get('name'):
        return api_error('Task name is required', 400)

    if not data.get('action'):
        return api_error('Task action is required', 400)

    if data.get('action') == 'COMMAND' and not data.get('command'):
        return api_error('Command is required for COMMAND action', 400)

    task = task_scheduler.create_task(server_id, {
        'name': data.get('name'),
        'action': data.get('action', 'START'),
        'interval': data.get('interval', '0 3 * * *'),
        'command': data.get('command', ''),
        'runs': data.get('runs', 0),
        'enabled': data.get('enabled', True),
        'deleteAfterExecution': data.get('deleteAfterExecution', False),
        'deleteAfterRunsCount': data.get('deleteAfterRunsCount', False)
    })

    return api_success({'task': task})

@app.route('/api/servers/<server_id>/tasks/<task_id>', methods=['GET'])
@server_access_required
def get_server_task(server_id, task_id):
    """Get a specific task"""
    task = task_scheduler.get_task(server_id, task_id)
    if task:
        return api_success({'task': task})
    return api_error('Task not found', 404)

@app.route('/api/servers/<server_id>/tasks/<task_id>', methods=['PUT'])
@server_access_required
def update_server_task(server_id, task_id):
    """Update an existing task"""
    data = request.get_json()

    task = task_scheduler.update_task(server_id, task_id, {
        'name': data.get('name'),
        'action': data.get('action'),
        'interval': data.get('interval'),
        'command': data.get('command', ''),
        'runs': data.get('runs'),
        'enabled': data.get('enabled'),
        'deleteAfterExecution': data.get('deleteAfterExecution'),
        'deleteAfterRunsCount': data.get('deleteAfterRunsCount')
    })

    if task:
        return api_success({'task': task})
    return api_error('Task not found', 404)

@app.route('/api/servers/<server_id>/tasks/<task_id>', methods=['DELETE'])
@server_access_required
def delete_server_task(server_id, task_id):
    """Delete a task"""
    if task_scheduler.delete_task(server_id, task_id):
        return api_success()
    return api_error('Task not found', 404)


# ==================== Settings API ====================

@app.route('/api/settings/branding', methods=['GET'])
def get_branding():
    """Get branding settings (public)"""
    return api_success(settings_manager.get_branding())

@app.route('/api/settings/branding', methods=['PUT'])
@permission_required('panel.settings.manage')
def update_branding():
    """Update branding settings (admin only)"""
    site_title = request.form.get('siteTitle', '')
    footer_addition = request.form.get('footerAddition', '')
    base_url = request.form.get('baseUrl', '')
    game_hostname = request.form.get('gameHostname', '')
    favicon_file = request.files.get('favicon')

    branding_data = {
        'siteTitle': site_title,
        'footerAddition': footer_addition,
        'baseUrl': base_url,
        'gameHostname': game_hostname,
    }
    
    # Handle favicon file upload
    if favicon_file and favicon_file.filename != '':
        # Validate file type
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'ico'}
        file_ext = favicon_file.filename.rsplit('.', 1)[1].lower() if '.' in favicon_file.filename else ''
        
        if file_ext not in allowed_extensions:
            return api_error('Invalid file type. Allowed: PNG, JPEG, GIF, ICO', 400)

        rejected = reject_if_not_image(favicon_file, file_ext)
        if rejected:
            return rejected

        # Create favicons directory if it doesn't exist
        favicons_dir = os.path.join('public', 'favicons')
        os.makedirs(favicons_dir, exist_ok=True)
        
        # Generate a unique filename to prevent overwriting
        filename = f"{uuid.uuid4().hex}.{file_ext}"
        filepath = os.path.join(favicons_dir, filename)
        
        try:
            favicon_file.save(filepath)
            branding_data['siteIcon'] = filename
        except Exception as e:
            return api_error(f'Failed to save favicon: {str(e)}', 500)

    # Update branding
    try:
        branding = settings_manager.update_branding(branding_data)
        return api_success({'branding': branding})
    except Exception as e:
        return api_error(f'Failed to update branding: {str(e)}', 500)

@app.route('/api/settings/app', methods=['GET'])
@permission_required('panel.settings.view')
def get_app_settings():
    """Get app settings (admin only)"""
    return api_success(settings_manager.get_app_settings())

@app.route('/api/settings/app', methods=['PUT'])
@permission_required('panel.settings.manage')
def update_app_settings():
    """Update app settings (admin only)"""
    data = request.get_json()
    app_settings = settings_manager.update_app_settings(data)
    return api_success({'settings': app_settings})

@app.route('/api/settings/mfa', methods=['GET'])
@permission_required('panel.settings.view')
def get_mfa_settings():
    """Get MFA settings (admin only)"""
    settings = settings_manager.get_settings().get('mfa', {})
    return api_success(settings)

@app.route('/api/settings/mfa', methods=['PUT'])
@permission_required('panel.settings.manage')
def update_mfa_settings():
    """Update MFA settings (admin only)"""
    data = request.get_json()

    mfa_settings = {
        'requireMfaForAdmins': data.get('requireMfaForAdmins', False),
        'requireMfaForAllUsers': data.get('requireMfaForAllUsers', False)
    }

    settings_manager.update_mfa_settings(mfa_settings)
    return api_success({'settings': mfa_settings})

@app.route('/api/settings/smtp', methods=['GET'])
@permission_required('panel.settings.view')
def get_smtp_settings():
    """Get SMTP settings (admin only)"""
    return api_success(settings_manager.get_smtp_settings())

@app.route('/api/settings/smtp', methods=['PUT'])
@permission_required('panel.settings.manage')
def update_smtp_settings():
    """Update SMTP settings (admin only)"""
    data = request.get_json()
    smtp_settings = settings_manager.update_smtp_settings(data)
    return api_success({'settings': smtp_settings})

@app.route('/api/settings/smtp/test', methods=['POST'])
@permission_required('panel.settings.manage')
def test_smtp_settings():
    """Send a test email to verify SMTP configuration"""
    data = request.get_json()
    to_email = data.get('email')

    if not to_email:
        return api_error('Email address required', 400)

    success, message = email_service.send_test_email(to_email)

    if success:
        return api_success({'message': message})
    return api_error(message, 400)


# ==================== Webhook Settings API ====================

@app.route('/api/settings/webhook', methods=['GET'])
@permission_required('panel.settings.view')
def get_webhook_settings_api():
    """Get webhook settings (admin only; secret is masked)"""
    return api_success(settings_manager.get_webhook_settings())

@app.route('/api/settings/webhook', methods=['PUT'])
@permission_required('panel.settings.manage')
def update_webhook_settings_api():
    """Update webhook settings (admin only)"""
    data = request.get_json()
    url = data.get('url', '').strip()
    if url and not url.startswith(('http://', 'https://')):
        return api_error('Webhook URL must start with http:// or https://', 400)
    updated = settings_manager.update_webhook_settings(data)
    return api_success({'settings': updated})

@app.route('/api/settings/webhook/test', methods=['POST'])
@permission_required('panel.settings.manage')
def test_webhook_api():
    """Send a test webhook event"""
    success, message = webhook_service.dispatch('test', {
        'message': 'This is a test webhook from MServer'
    })
    if success:
        return api_success({'message': message})
    return api_error(message, 400)


# ==================== Email Templates API ====================

@app.route('/api/settings/email-templates', methods=['GET'])
@permission_required('panel.settings.view')
def get_email_templates_api():
    """Get all email templates (admin only)"""
    return api_success(settings_manager.get_email_templates())

@app.route('/api/settings/email-template/<name>', methods=['PUT'])
@permission_required('panel.settings.manage')
def update_email_template_api(name):
    """Override an email template (admin only)"""
    data = request.get_json()
    success, message = settings_manager.update_email_template(name, data)
    if success:
        return api_success()
    return api_error(message, 400)

@app.route('/api/settings/email-template/<name>/reset', methods=['POST'])
@permission_required('panel.settings.manage')
def reset_email_template_api(name):
    """Reset an email template to its built-in default (admin only)"""
    settings_manager.reset_email_template(name)
    return api_success()


# ==================== Network & Environment Settings API ====================

def _read_env_file():
    """Read the .env file and return a dict of key=value pairs."""
    env_path = BASE_DIR / '.env'
    data = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                k, v = line.split('=', 1)
                data[k.strip()] = v.strip()
    return data

def _write_env_value(key, value):
    """Update a single key in the .env file, preserving comments and order.
    If the key doesn't exist, append it."""
    # Guard against .env injection: a newline in the value (e.g. a crafted
    # corsOrigins/sessionCookieDomain) could otherwise smuggle extra env lines
    # such as FLASK_ENV or SECRET_KEY past the intended settings surface.
    if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', str(key)):
        raise ValueError(f'Invalid .env key: {key!r}')
    value = str(value).replace('\r', '').replace('\n', '')
    env_path = BASE_DIR / '.env'
    if not env_path.exists():
        env_path.write_text(f'{key}={value}\n')
        return
    lines = env_path.read_text().splitlines()
    found = False
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and '=' in stripped:
            k = stripped.split('=', 1)[0].strip()
            if k == key:
                new_lines.append(f'{key}={value}')
                found = True
                continue
        new_lines.append(line)
    if not found:
        new_lines.append(f'{key}={value}')
    env_path.write_text('\n'.join(new_lines) + '\n')

@app.route('/api/settings/network', methods=['GET'])
@permission_required('panel.settings.view')
def get_network_settings():
    """Get network/environment settings (admin only)."""
    env = _read_env_file()
    return api_success({
        'corsOrigins':             env.get('CORS_ORIGINS', '*'),
        'sessionCookieSecure':     env.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true',
        'sessionCookieDomain':     env.get('SESSION_COOKIE_DOMAIN', ''),
        'permanentSessionLifetime': int(env.get('PERMANENT_SESSION_LIFETIME', 604800)),
        'port':                    int(env.get('PORT', 3000)),
    })

@app.route('/api/settings/network', methods=['PUT'])
@permission_required('panel.settings.manage')
def update_network_settings():
    """Update network/environment settings (admin only).
    Changes are written to .env. A service restart is required for most to take effect."""
    data = request.get_json() or {}
    updated_keys = []

    if 'corsOrigins' in data:
        raw = data['corsOrigins'].strip()
        if raw and raw != '*':
            # Auto-prepend https:// to bare domains
            parts = [p.strip() for p in raw.split(',') if p.strip()]
            fixed = []
            for p in parts:
                if not p.startswith(('http://', 'https://')):
                    p = f'https://{p}'
                fixed.append(p)
            raw = ','.join(fixed)
        _write_env_value('CORS_ORIGINS', raw)
        updated_keys.append('CORS_ORIGINS')

    if 'sessionCookieSecure' in data:
        val = 'true' if data['sessionCookieSecure'] else 'false'
        _write_env_value('SESSION_COOKIE_SECURE', val)
        updated_keys.append('SESSION_COOKIE_SECURE')

    if 'sessionCookieDomain' in data:
        _write_env_value('SESSION_COOKIE_DOMAIN', data['sessionCookieDomain'].strip())
        updated_keys.append('SESSION_COOKIE_DOMAIN')

    if 'permanentSessionLifetime' in data:
        try:
            lifetime = int(data['permanentSessionLifetime'])
        except (TypeError, ValueError):
            return api_error('permanentSessionLifetime must be an integer number of seconds', 400)
        lifetime = _clamp_session_lifetime(lifetime)
        _write_env_value('PERMANENT_SESSION_LIFETIME', str(lifetime))
        updated_keys.append('PERMANENT_SESSION_LIFETIME')

    return api_success({
        'updated': updated_keys,
        'message': 'Settings saved. Restart the service for changes to take effect.'
    })


# ==================== User Notification Preferences API ====================

@app.route('/api/auth/profile/notifications', methods=['GET'])
@login_required
def get_notification_prefs_api():
    """Get current user's notification preferences"""
    user_id = session['user_id']
    prefs = user_manager.get_notification_prefs(user_id)
    if prefs is None:
        return api_error('User not found', 404)
    return api_success(prefs)

@app.route('/api/auth/profile/notifications', methods=['PUT'])
@login_required
def update_notification_prefs_api():
    """Update current user's notification preferences"""
    data = request.get_json()
    user_id = session['user_id']
    success = user_manager.update_notification_prefs(user_id, data)
    if success:
        return api_success()
    return api_error('User not found', 404)


@app.route('/api/settings/external-backup', methods=['GET'])
@permission_required('panel.settings.view')
def get_external_backup_settings_api():
    """Get external backup storage settings (admin only)"""
    return api_success(settings_manager.get_external_backup_settings())


@app.route('/api/settings/external-backup', methods=['PUT'])
@permission_required('panel.settings.manage')
def update_external_backup_settings_api():
    """Update external backup storage settings (admin only)"""
    data = request.get_json()
    updated = settings_manager.update_external_backup_settings(data)
    return api_success({'settings': updated})


@app.route('/api/settings/external-backup/test', methods=['POST'])
@permission_required('panel.settings.manage')
def test_external_backup_settings():
    """Test external backup storage connectivity by uploading a tiny probe file"""
    import tempfile

    ext = settings_manager.get_external_backup_settings_full()
    if not ext.get('enabled', False):
        return api_error('External backup is not enabled', 400)

    try:
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
            tmp_path = Path(tmp.name)
            with zipfile.ZipFile(tmp_path, 'w') as zf:
                zf.writestr('test.txt', 'MServer external backup test')

        ok, msg = upload_backup_to_external(tmp_path, '_test', 'connectivity-test.zip')
        tmp_path.unlink(missing_ok=True)
        # Remove sidecar (no checksum for test file)
        sidecar = tmp_path.with_suffix('.sha256')
        if sidecar.exists():
            sidecar.unlink()

        if ok:
            return api_success({'message': msg})
        return api_error(msg, 400)
    except Exception as e:
        return api_error(str(e), 500)


# ==================== Server Backup/Restore (All Servers) ====================

@app.route('/api/tools/servers/backup-all', methods=['POST'])
@permission_required('panel.panel.backup')
def backup_all_servers():
    """Create a ZIP archive of all server directories and stream it for download.
    Running servers are NOT stopped; their files are snapshotted live.
    The archive preserves the directory structure: servers/<server_id>/...
    """
    import tempfile
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        archive_name = f'mserver_backup_all_{timestamp}.zip'

        # Build the archive on disk under UPLOADS_DIR (not /tmp, which may be
        # RAM-backed tmpfs) so multi-GB installs don't get buffered in memory.
        tmp = tempfile.NamedTemporaryFile(suffix='.zip', dir=UPLOADS_DIR, delete=False)
        tmp_path = Path(tmp.name)
        tmp.close()
        try:
            with zipfile.ZipFile(tmp_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                if SERVERS_DIR.exists():
                    for server_dir in sorted(SERVERS_DIR.iterdir()):
                        if not server_dir.is_dir():
                            continue
                        for file_path in server_dir.rglob('*'):
                            if file_path.is_file():
                                # Store as servers/<server_id>/... so it restores cleanly
                                arcname = file_path.relative_to(SERVERS_DIR.parent)
                                try:
                                    zf.write(file_path, arcname)
                                except (PermissionError, OSError):
                                    pass  # Skip locked / unreadable files

            response = send_file(tmp_path, as_attachment=True,
                                 download_name=archive_name, mimetype='application/zip')
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise
        # send_file already holds the file open; unlinking now still lets the
        # download stream to completion (Linux) and guarantees cleanup.
        tmp_path.unlink(missing_ok=True)
        return response

    except Exception as e:
        return api_error(str(e), 500)


@app.route('/api/tools/servers/restore-all', methods=['POST'])
@permission_required('panel.panel.backup')
def restore_all_servers():
    """Restore servers from an uploaded backup ZIP.
    Expects a multipart/form-data POST with a 'backup' file field.
    Query param ?mode=merge (default) keeps existing servers not in the archive.
    Query param ?mode=replace stops and removes ALL existing server data first.
    Running servers inside the archive are stopped before their data is replaced.
    """
    if 'backup' not in request.files:
        return api_error('No backup file provided', 400)

    backup_file = request.files['backup']
    if not backup_file.filename:
        return api_error('Empty filename', 400)

    filename = secure_filename(backup_file.filename)
    if not filename.lower().endswith('.zip'):
        return api_error('Only ZIP archives are supported', 400)

    mode = request.args.get('mode', 'merge')
    if mode not in ('merge', 'replace'):
        return api_error('Invalid mode; use "merge" or "replace"', 400)

    import tempfile
    tmp_path = None
    try:
        # Stream the upload to disk instead of read()-ing it into RAM —
        # MAX_CONTENT_LENGTH allows archives far larger than available memory.
        tmp = tempfile.NamedTemporaryFile(suffix='.zip', dir=UPLOADS_DIR, delete=False)
        tmp_path = Path(tmp.name)
        tmp.close()
        backup_file.save(tmp_path)

        if not zipfile.is_zipfile(tmp_path):
            return api_error('Uploaded file is not a valid ZIP archive', 400)

        restored = []
        skipped = []

        with zipfile.ZipFile(tmp_path, 'r') as zf:
            # Collect server IDs inside the archive (top-level dirs under servers/)
            server_ids_in_archive = set()
            for name in zf.namelist():
                parts = Path(name).parts
                # Expected layout: servers/<server_id>/...
                # The id is later used in shutil.rmtree(SERVERS_DIR / sid), so
                # '..' or any other path-like segment must never be accepted.
                if (len(parts) >= 2 and parts[0] == 'servers'
                        and re.fullmatch(r'[A-Za-z0-9_-]+', parts[1])):
                    server_ids_in_archive.add(parts[1])

            if not server_ids_in_archive:
                return api_error('No server directories found in archive (expected servers/<id>/...)', 400)

            if mode == 'replace':
                # Stop all running servers and wipe SERVERS_DIR
                for sid in list(server_manager.servers.keys()):
                    inst = server_manager.servers.get(sid)
                    if inst and inst.is_running():
                        server_manager.stop_server(sid)
                if SERVERS_DIR.exists():
                    shutil.rmtree(SERVERS_DIR)
                SERVERS_DIR.mkdir(parents=True, exist_ok=True)
            else:
                # Merge: stop only the servers that will be overwritten
                for sid in server_ids_in_archive:
                    inst = server_manager.servers.get(sid)
                    if inst and inst.is_running():
                        server_manager.stop_server(sid)
                    target = SERVERS_DIR / sid
                    if target.exists():
                        shutil.rmtree(target)

            # Extract (only members under a validated server id)
            for name in zf.namelist():
                parts = Path(name).parts
                if (len(parts) >= 2 and parts[0] == 'servers'
                        and parts[1] in server_ids_in_archive):
                    # Security: prevent path traversal
                    safe_relative = Path(*parts)
                    dest = SERVERS_DIR.parent / safe_relative
                    try:
                        resolved = dest.resolve()
                        if not str(resolved).startswith(str(SERVERS_DIR.resolve())):
                            skipped.append(name)
                            continue
                    except Exception:
                        skipped.append(name)
                        continue

                    dest.parent.mkdir(parents=True, exist_ok=True)
                    if not name.endswith('/'):
                        with zf.open(name) as src, open(dest, 'wb') as dst:
                            shutil.copyfileobj(src, dst)
                        restored.append(name)

        return jsonify({
            'success': True,
            'mode': mode,
            'serversRestored': list(server_ids_in_archive),
            'filesRestored': len(restored),
            'filesSkipped': len(skipped)
        })

    except zipfile.BadZipFile:
        return api_error('Corrupt or invalid ZIP archive', 400)
    except Exception as e:
        return api_error(str(e), 500)
    finally:
        if tmp_path:
            tmp_path.unlink(missing_ok=True)


# ==================== System Stats API ====================

@app.route('/api/stats/current', methods=['GET'])
@permission_required('panel.stats.view')
def get_current_stats():
    """Get current system stats"""
    return api_success(stats_manager.get_current_stats())

@app.route('/api/stats/history', methods=['GET'])
@permission_required('panel.stats.view')
def get_stats_history():
    """Get stats history"""
    hours = request.args.get('hours', 24, type=int)
    # Limit to 7 days max
    hours = min(hours, 24 * 7)
    history = stats_manager.get_history(hours)
    return api_success({'history': history})


# ==================== System Info API ====================

@app.route('/api/system/version', methods=['GET'])
@login_required
def api_get_current_version():
    """Get current version from version file"""
    try:
        # Get current version (from file or fallback to git)
        version, source = get_current_version()

        # Get commit date
        commit_date = "unknown"
        try:
            result = subprocess.run(
                ['git', 'log', '-1', '--format=%ai'],
                cwd=BASE_DIR,
                capture_output=True,
                text=True,
                timeout=5
            )
            commit_date = result.stdout.strip() if result.returncode == 0 else "unknown"
        except:
            pass

        return api_success({
            'version': version,
            'versionSource': source,
            'commitDate': commit_date,
            'installedAt': str(BASE_DIR)
        })
    except Exception as e:
        print(f"[API] Error getting version: {e}")
        return api_error(str(e), 500)


# ==================== Host / OS Update API ====================
# The panel runs unprivileged (www-data). Host-layer actions are delegated to the
# root-owned helper /usr/local/sbin/mserver-hostctl, which is the ONLY command the
# scoped sudoers rule (installed by install.sh) permits www-data to run as root.
# Read-only status needs no privilege; applying updates / restarting requires the
# operator to supply the root password per request (piped to `sudo -S`, never stored).

HOSTCTL_PATH = '/usr/local/sbin/mserver-hostctl'


def _hostctl_auth_failed(output):
    """Heuristic: did sudo reject the supplied password (vs. the command failing)?"""
    o = (output or '').lower()
    return ('try again' in o or 'incorrect password' in o
            or 'password is required' in o or 'authentication failure' in o
            or 'sorry' in o)


def _run_hostctl_sudo(subcmd, password, timeout):
    """Run `sudo -S -k mserver-hostctl <subcmd>`, feeding the root password on
    stdin. `-k` forces re-auth every call (no cached credentials). Returns
    (returncode, combined_output). The password is never logged or returned."""
    proc = subprocess.run(
        ['sudo', '-S', '-k', '-p', '', HOSTCTL_PATH, subcmd],
        input=(password + '\n'),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc.returncode, ((proc.stdout or '') + (proc.stderr or ''))


@app.route('/api/system/os-status', methods=['GET'])
@admin_required
def api_system_os_status():
    """Read-only host/update status (pending package count, reboot flag, kernel,
    Java, app version). Runs the helper unprivileged — no password required."""
    try:
        result = subprocess.run(
            [HOSTCTL_PATH, 'status', '--kv'],
            capture_output=True, text=True, timeout=30
        )
    except FileNotFoundError:
        return api_error('host-control helper not installed', 503, detail=HOSTCTL_PATH)
    except subprocess.TimeoutExpired:
        return api_error('host status timed out', 504)
    except Exception as e:
        return api_error(str(e), 500)

    if result.returncode != 0:
        return api_error('host status failed', 500, detail=(result.stderr or '').strip())

    data = {}
    for line in result.stdout.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            data[k.strip()] = v.strip()
    try:
        pending = int(data.get('pending', '0'))
    except ValueError:
        pending = 0
    return api_success({
        'version': data.get('version', 'unknown'),
        'pending': pending,
        'rebootRequired': data.get('reboot_required') == '1',
        'kernel': data.get('kernel', ''),
        'java': data.get('java', ''),
    })


@app.route('/api/system/os-update', methods=['POST'])
@admin_required
def api_system_os_update():
    """Run the host OS update. Body: {mode: 'check'|'apply', password}.
    'check' is a dry run (apt refresh + report); 'apply' upgrades packages + Java."""
    data = request.get_json(silent=True) or {}
    mode = data.get('mode', 'check')
    password = data.get('password', '')
    if mode not in ('check', 'apply'):
        return api_error("mode must be 'check' or 'apply'", 400)
    if not password:
        return api_error('Root password is required', 400)

    subcmd = 'os-check' if mode == 'check' else 'os-update'
    timeout = 180 if mode == 'check' else 1800  # apt upgrade can take a while
    try:
        rc, output = _run_hostctl_sudo(subcmd, password, timeout)
    except subprocess.TimeoutExpired:
        return api_error('operation timed out', 504, ok=False)
    except FileNotFoundError:
        return api_error('sudo or host-control helper not found', 503, ok=False)
    except Exception as e:
        return api_error(str(e), 500, ok=False)
    finally:
        # Best-effort: drop our reference to the password (Python strings are
        # immutable, so this cannot truly wipe it from memory).
        password = None

    # 'ok' reflects the hostctl command's own outcome (mirrored into 'success' for
    # the standard envelope) — always HTTP 200, since the call itself succeeded.
    resp = {'ok': rc == 0, 'success': rc == 0, 'output': output, 'returncode': rc}
    if rc != 0 and _hostctl_auth_failed(output):
        resp['error'] = ('Authentication failed — check the root password. '
                         '(Requires the root account to have a password set.)')
    return jsonify(resp)


@app.route('/api/system/service-restart', methods=['POST'])
@admin_required
def api_system_service_restart():
    """Restart the mserver service. Body: {password}. The restart is detached, so
    this response returns before the service is bounced; the UI then polls to
    confirm the panel came back."""
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    if not password:
        return api_error('Root password is required', 400)
    try:
        rc, output = _run_hostctl_sudo('restart', password, 30)
    except subprocess.TimeoutExpired:
        return api_error('operation timed out', 504, ok=False)
    except FileNotFoundError:
        return api_error('sudo or host-control helper not found', 503, ok=False)
    except Exception as e:
        return api_error(str(e), 500, ok=False)
    finally:
        password = None

    resp = {'ok': rc == 0, 'success': rc == 0, 'output': output, 'returncode': rc}
    if rc != 0 and _hostctl_auth_failed(output):
        resp['error'] = 'Authentication failed — check the root password.'
    return jsonify(resp)


# ==================== JAR Bucket Manager ====================

SERVER_EXECUTABLES_DIR = BASE_DIR / 'serverexecutables'
JAR_CACHE_FILE = BASE_DIR / 'jar_cache.json'
JAR_CACHE_MAX_AGE_HOURS = 6  # Refresh cache every 6 hours
JAR_URL_CACHE_MAX_AGE_HOURS = 12  # How long to keep cached download URLs (hours)
JAR_BUCKET_LINKS_FILE = BASE_DIR / 'configs' / 'jar_bucket_links.json'  # Per-type upstream link overrides

class JarBucketManager:
    """
    Manager for downloading Minecraft server JAR files from various sources.
    Inspired by Crafty Controller's Big Bucket system.
    """

    # A filename the bucket can legitimately hold: the .jar/.zip artifact names
    # download_jar() writes and list_downloaded_jars() surfaces. Deliberately
    # excludes path separators and a leading dot, so it doubles as the traversal
    # guard for delete_jar().
    JAR_FILENAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+-]*\.(jar|zip)$')

    # Server type metadata with descriptions
    SERVER_TYPES = {
        'vanilla': {
            'name': 'Vanilla',
            'description': 'Official Minecraft Java Edition server',
            'category': 'java',
            'apiUrl': 'https://launchermeta.mojang.com/mc/game/version_manifest.json',
            'icon': '🎮'
        },
        'bedrock': {
            'name': 'Bedrock',
            'description': 'Official Minecraft Bedrock Edition server',
            'category': 'bedrock',
            'apiUrl': 'https://net-secondary.web.minecraft-services.net/api/v1.0/download/links',
            'icon': '🪨'
        },
        'paper': {
            'name': 'Paper',
            'description': 'High-performance Spigot fork with optimizations',
            'category': 'modded',
            'apiUrl': 'https://fill.papermc.io/v3/',
            'icon': '📄'
        },
        'purpur': {
            'name': 'Purpur',
            'description': 'Paper fork with extra features and configuration',
            'category': 'modded',
            'apiUrl': 'https://api.purpurmc.org/v2/purpur/',
            'icon': '💜'
        },
        'folia': {
            'name': 'Folia',
            'description': 'Paper fork for multi-threaded regions',
            'category': 'modded',
            'apiUrl': 'https://fill.papermc.io/v3/',
            'icon': '🌿'
        },
        'spigot': {
            'name': 'Spigot',
            'description': 'Modified Minecraft server with Bukkit plugin support',
            'category': 'modded',
            'apiUrl': 'https://hub.spigotmc.org/versions/',
            'icon': '🔧'
        },
        'fabric': {
            'name': 'Fabric',
            'description': 'Lightweight mod loader for Minecraft',
            'category': 'modded',
            'apiUrl': 'https://meta.fabricmc.net/v2/versions/',
            'icon': '🧵'
        },
        'forge': {
            'name': 'Forge',
            'description': 'Popular mod loader for Minecraft mods',
            'category': 'modded',
            'apiUrl': 'https://maven.minecraftforge.net/net/minecraftforge/forge/',

            'icon': '⚒️'
        },
        'neoforge': {
            'name': 'NeoForge',
            'description': 'Modern community-driven Forge fork',
            'category': 'modded',
            'apiUrl': 'https://maven.neoforged.net/releases/net/neoforged/neoforge/',
            'icon': '🔨'
        }
    }

    # Editable upstream link fields per server type. Operators can override any of
    # these via /api/jar-bucket/links (persisted to configs/jar_bucket_links.json);
    # unset overrides fall back to the defaults below. Fields with 'placeholders'
    # are str.format templates and must keep every listed placeholder.
    LINK_FIELDS = {
        'vanilla': {
            'apiUrl': {'label': 'Version manifest URL', 'default': SERVER_TYPES['vanilla']['apiUrl']},
        },
        'bedrock': {
            'apiUrl': {'label': 'Download links API URL', 'default': SERVER_TYPES['bedrock']['apiUrl']},
        },
        'paper': {
            'apiUrl': {'label': 'PaperMC API base URL', 'default': SERVER_TYPES['paper']['apiUrl']},
        },
        'purpur': {
            'apiUrl': {'label': 'Purpur API base URL', 'default': SERVER_TYPES['purpur']['apiUrl']},
        },
        'folia': {
            'apiUrl': {'label': 'PaperMC API base URL', 'default': SERVER_TYPES['folia']['apiUrl']},
        },
        'spigot': {
            'apiUrl': {'label': 'Version listing URL', 'default': SERVER_TYPES['spigot']['apiUrl']},
            'buildtoolsUrl': {
                'label': 'BuildTools JAR URL',
                'default': 'https://hub.spigotmc.org/jenkins/job/BuildTools/lastSuccessfulBuild/artifact/target/BuildTools.jar'
            },
        },
        'fabric': {
            'apiUrl': {'label': 'Fabric meta API base URL', 'default': SERVER_TYPES['fabric']['apiUrl']},
            'downloadTemplate': {
                'label': 'Server JAR URL template',
                'default': 'https://meta.fabricmc.net/v2/versions/loader/{game_version}/{loader_version}/{installer_version}/server/jar',
                'placeholders': ['game_version', 'loader_version', 'installer_version'],
            },
        },
        'forge': {
            'apiUrl': {'label': 'Maven base URL', 'default': SERVER_TYPES['forge']['apiUrl']},
            'metadataUrl': {
                'label': 'Maven metadata XML URL',
                'default': 'https://maven.minecraftforge.net/net/minecraftforge/forge/maven-metadata.xml'
            },
            'installerTemplate': {
                'label': 'Installer URL template',
                'default': 'https://maven.minecraftforge.net/net/minecraftforge/forge/{mc_version}-{forge_version}/forge-{mc_version}-{forge_version}-installer.jar',
                'placeholders': ['mc_version', 'forge_version'],
            },
        },
        'neoforge': {
            'apiUrl': {'label': 'Maven base URL', 'default': SERVER_TYPES['neoforge']['apiUrl']},
            'metadataUrl': {
                'label': 'Maven metadata XML URL',
                'default': 'https://maven.neoforged.net/releases/net/neoforged/neoforge/maven-metadata.xml'
            },
            'installerTemplate': {
                'label': 'Installer URL template',
                'default': 'https://maven.neoforged.net/releases/net/neoforged/neoforge/{neoforge_version}/neoforge-{neoforge_version}-installer.jar',
                'placeholders': ['neoforge_version'],
            },
        },
    }

    # How long a finished (complete/error) progress entry is retained before it
    # is pruned, so the dict cannot grow without bound across many downloads.
    PROGRESS_RETENTION_SECONDS = 3600  # 1 hour

    def __init__(self):
        self.cache = self._load_cache()
        # Download/refresh progress, keyed by a unique progress id. Written from
        # multiple background threads and read by the progress routes, so ALL
        # access goes through the locked helpers below — never touch this dict
        # directly (see issue #10).
        self.download_progress = {}
        self._progress_lock = threading.RLock()
        self.link_overrides = self._load_link_overrides()

    # --- Thread-safe progress accessors -------------------------------------
    def set_progress(self, progress_id, data):
        """Replace the progress entry for progress_id (thread-safe)."""
        with self._progress_lock:
            entry = dict(data)
            entry['updated_at'] = time.time()
            self.download_progress[progress_id] = entry
            self._prune_progress_locked()

    def update_progress(self, progress_id, **changes):
        """Merge changes into an existing progress entry (thread-safe)."""
        with self._progress_lock:
            entry = dict(self.download_progress.get(progress_id, {}))
            entry.update(changes)
            entry['updated_at'] = time.time()
            self.download_progress[progress_id] = entry

    def get_progress(self, progress_id):
        """Return a copy of one progress entry, or None (thread-safe)."""
        with self._progress_lock:
            entry = self.download_progress.get(progress_id)
            return dict(entry) if entry is not None else None

    def list_progress(self):
        """Return {progress_id: entry-copy} for every tracked task (thread-safe)."""
        with self._progress_lock:
            self._prune_progress_locked()
            return {pid: dict(entry) for pid, entry in self.download_progress.items()}

    def _prune_progress_locked(self):
        """Drop finished entries older than the retention window. Caller holds the lock."""
        cutoff = time.time() - self.PROGRESS_RETENTION_SECONDS
        stale = [
            pid for pid, entry in self.download_progress.items()
            if entry.get('status') in ('complete', 'error')
            and entry.get('updated_at', 0) < cutoff
        ]
        for pid in stale:
            del self.download_progress[pid]

    def _load_cache(self):
        """Load cached version data from file"""
        default = {'lastUpdated': None, 'versions': {}}
        if JAR_CACHE_FILE.exists():
            try:
                with open(JAR_CACHE_FILE, 'r') as f:
                    data = json.load(f)
                if not isinstance(data, dict):
                    raise ValueError(f'expected a JSON object, got {type(data).__name__}')
                return data
            except Exception as e:
                # Malformed or wrong-shaped cache file (issue #12) — rebuild it on
                # disk immediately so a corrupt file doesn't keep tripping this on
                # every restart, rather than just falling back in memory.
                print(f"[JarBucket] Cache file corrupt, rebuilding: {e}")
                try:
                    with open(JAR_CACHE_FILE, 'w') as f:
                        json.dump(default, f, indent=2)
                except Exception as write_err:
                    print(f"[JarBucket] Failed to rebuild cache file: {write_err}")
        return default
    
    def _save_cache(self):
        """Save version data to cache file"""
        try:
            with open(JAR_CACHE_FILE, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            print(f"[JarBucket] Error saving cache: {e}")

    def _load_link_overrides(self):
        """Load per-type link overrides from configs/jar_bucket_links.json (unknown keys dropped)"""
        if not JAR_BUCKET_LINKS_FILE.exists():
            return {}
        try:
            with open(JAR_BUCKET_LINKS_FILE, 'r') as f:
                data = json.load(f)
            overrides = {}
            for server_type, fields in (data or {}).items():
                if server_type not in self.LINK_FIELDS or not isinstance(fields, dict):
                    continue
                for field, value in fields.items():
                    if field in self.LINK_FIELDS[server_type] and isinstance(value, str) and value.strip():
                        overrides.setdefault(server_type, {})[field] = value.strip()
            return overrides
        except Exception as e:
            print(f"[JarBucket] Error loading link overrides: {e}")
            return {}

    def get_link(self, server_type, field='apiUrl'):
        """Effective link for a type/field: operator override if set, else built-in default"""
        override = self.link_overrides.get(server_type, {}).get(field)
        if override:
            return override
        return self.LINK_FIELDS[server_type][field]['default']

    def get_links_config(self):
        """Full link configuration for the admin UI: defaults, overrides and effective values"""
        config = {}
        for server_type, fields in self.LINK_FIELDS.items():
            type_info = self.SERVER_TYPES.get(server_type, {})
            config[server_type] = {
                'name': type_info.get('name', server_type.title()),
                'icon': type_info.get('icon', '📦'),
                'fields': {}
            }
            for field, meta in fields.items():
                override = self.link_overrides.get(server_type, {}).get(field)
                config[server_type]['fields'][field] = {
                    'label': meta['label'],
                    'default': meta['default'],
                    'override': override,
                    'effective': override or meta['default'],
                    'placeholders': meta.get('placeholders', [])
                }
        return config

    def _validate_link_value(self, server_type, field, value):
        """Validate one override value. Returns an error string or None if valid."""
        meta = self.LINK_FIELDS[server_type][field]
        if len(value) > 500:
            return f'{server_type}.{field}: URL too long (max 500 characters)'
        if not (value.startswith('http://') or value.startswith('https://')):
            return f'{server_type}.{field}: URL must start with http:// or https://'
        placeholders = meta.get('placeholders', [])
        for ph in placeholders:
            if '{' + ph + '}' not in value:
                return f'{server_type}.{field}: template must contain {{{ph}}}'
        if placeholders:
            try:
                value.format(**{ph: 'x' for ph in placeholders})
            except (KeyError, IndexError, ValueError) as e:
                return f'{server_type}.{field}: invalid template ({e})'
        return None

    def save_link_overrides(self, updates):
        """
        Validate and persist link overrides. `updates` maps server_type -> {field: url}.
        Only the provided types are touched; an empty/blank value resets that field
        to its default. Applies immediately (no restart) and clears the version/URL
        cache so stale upstream data isn't served for the new links.
        Returns {'success': bool, 'errors': [..]}.
        """
        errors = []
        validated = {}
        for server_type, fields in updates.items():
            if server_type not in self.LINK_FIELDS:
                errors.append(f'Unknown server type: {server_type}')
                continue
            if not isinstance(fields, dict):
                errors.append(f'{server_type}: expected an object of field values')
                continue
            validated[server_type] = {}
            for field, value in fields.items():
                if field not in self.LINK_FIELDS[server_type]:
                    errors.append(f'{server_type}: unknown field {field}')
                    continue
                if not isinstance(value, str):
                    errors.append(f'{server_type}.{field}: value must be a string')
                    continue
                value = value.strip()
                if not value or value == self.LINK_FIELDS[server_type][field]['default']:
                    continue  # blank or explicit default = no override
                error = self._validate_link_value(server_type, field, value)
                if error:
                    errors.append(error)
                    continue
                validated[server_type][field] = value

        if errors:
            return {'success': False, 'errors': errors}

        for server_type, fields in validated.items():
            if fields:
                self.link_overrides[server_type] = fields
            else:
                self.link_overrides.pop(server_type, None)

        try:
            JAR_BUCKET_LINKS_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(JAR_BUCKET_LINKS_FILE, 'w') as f:
                json.dump(self.link_overrides, f, indent=2)
        except Exception as e:
            return {'success': False, 'errors': [f'Failed to save overrides: {e}']}

        # Drop cached version lists and resolved download URLs — they were fetched
        # from the old links and may be stale or wrong for the new ones.
        self.cache = {'lastUpdated': None, 'versions': {}, 'downloadUrls': {}}
        self._save_cache()
        return {'success': True, 'errors': []}

    def test_links(self, server_type):
        """Network-test the effective links for one server type (used by the admin UI)"""
        if server_type not in self.LINK_FIELDS:
            return {'success': False, 'error': 'Unknown server type'}
        try:
            if server_type == 'bedrock':
                url, _ = self._fetch_bedrock_download_url()
                if url:
                    return {'success': True, 'message': 'Resolved Bedrock download URL'}
                return {'success': False, 'error': 'Could not resolve a Bedrock download URL'}
            if server_type == 'spigot':
                # _fetch_spigot_versions falls back to a static list on failure,
                # so probe the listing URL directly to get an honest result.
                response = requests.get(self.get_link('spigot'), timeout=15)
                if response.status_code == 200:
                    return {'success': True, 'message': 'Version listing reachable (note: Spigot JARs still require BuildTools)'}
                return {'success': False, 'error': f'Version listing returned HTTP {response.status_code}'}
            versions = self.get_versions(server_type, force_refresh=True)
            if versions:
                return {'success': True, 'message': f'Fetched {len(versions)} versions'}
            return {'success': False, 'error': 'No versions returned — check the URLs'}
        except Exception as e:
            return {'success': False, 'error': str(e)}


    def _is_cache_valid(self, server_type=None):
        """Check if cache is still valid (not too old)"""
        if not self.cache.get('lastUpdated'):
            return False
        
        # Check specific server type cache
        if server_type:
            type_cache = self.cache.get('versions', {}).get(server_type)
            if not type_cache or not type_cache.get('lastUpdated'):
                return False
            last_updated = datetime.fromisoformat(type_cache['lastUpdated'])
        else:
            last_updated = datetime.fromisoformat(self.cache['lastUpdated'])
        
        age_hours = (datetime.now() - last_updated).total_seconds() / 3600
        return age_hours < JAR_CACHE_MAX_AGE_HOURS
    
    def get_server_types(self):
        """Get list of available server types with metadata"""
        types_by_category = {'java': [], 'bedrock': [], 'modded': []}

        for type_id, info in self.SERVER_TYPES.items():
            category = info.get('category', 'java')
            if category == 'proxies':
                continue
            entry = {'id': type_id, **info}
            if type_id in self.LINK_FIELDS:
                entry['apiUrl'] = self.get_link(type_id)  # reflect operator overrides
            types_by_category.setdefault(category, []).append(entry)

        return types_by_category
    
    def _fetch_paper_versions(self, project='paper'):
        """Fetch versions from PaperMC's Fill API (Paper, Folia). Versions are
        grouped by major release, newest-first both across and within groups."""
        try:
            url = f"{self.get_link(project)}projects/{project}"
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                versions = []
                for group in data.get('versions', {}).values():
                    versions.extend(group)
                return versions
        except Exception as e:
            print(f"[JarBucket] Error fetching {project} versions: {e}")
        return []

    def _fetch_paper_download_url(self, project, version):
        """Get download URL for Paper-based project via PaperMC's Fill API"""
        try:
            base = self.get_link(project)
            url = f"{base}projects/{project}/versions/{version}/builds"
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                print(f"[JarBucket] {project} API returned status {response.status_code} for version {version}")
                return None, None

            try:
                builds = response.json()
            except ValueError as json_err:
                print(f"[JarBucket] Invalid JSON from {project} API for version {version}: {json_err}")
                print(f"[JarBucket] Response content: {response.text[:200]}")
                return None, None
            if not builds:
                return None, None

            latest_build = max(builds, key=lambda b: b.get('id', 0))
            application = latest_build.get('downloads', {}).get('server:default', {})
            jar_name = application.get('name')
            download_url = application.get('url')
            sha256 = application.get('checksums', {}).get('sha256')

            if jar_name and download_url:
                return download_url, sha256
        except Exception as e:
            print(f"[JarBucket] Error getting {project} download URL: {e}")
        return None, None
    
    def _fetch_purpur_versions(self):
        """Fetch versions from Purpur API"""
        try:
            response = requests.get(self.get_link('purpur'), timeout=15)
            if response.status_code == 200:
                data = response.json()
                return list(reversed(data.get('versions', [])))
        except Exception as e:
            print(f"[JarBucket] Error fetching Purpur versions: {e}")
        return []
    
    def _fetch_purpur_download_url(self, version):
        """Get download URL for Purpur"""
        try:
            base = self.get_link('purpur')
            url = f"{base}{version}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                builds = data.get('builds', {})
                latest = builds.get('latest')
                if latest:
                    return f"{base}{version}/{latest}/download", None
        except Exception as e:
            print(f"[JarBucket] Error getting Purpur download URL: {e}")
        return None, None
    
    def _fetch_vanilla_versions(self):
        """Fetch versions from Mojang manifest"""
        try:
            response = requests.get(self.get_link('vanilla'), timeout=15)
            if response.status_code == 200:
                data = response.json()
                versions = []
                for ver in data.get('versions', []):
                    if ver.get('type') == 'release':
                        versions.append({
                            'id': ver['id'],
                            'url': ver['url']
                        })
                return versions
        except Exception as e:
            print(f"[JarBucket] Error fetching Vanilla versions: {e}")
        return []
    
    def _fetch_vanilla_download_url(self, version_url):
        """Get download URL for Vanilla server"""
        try:
            response = requests.get(version_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                server = data.get('downloads', {}).get('server', {})
                return server.get('url'), server.get('sha1')
        except Exception as e:
            print(f"[JarBucket] Error getting Vanilla download URL: {e}")
        return None, None
    
    def _fetch_fabric_versions(self):
        """Fetch Fabric loader versions and game versions"""
        try:
            # Get supported game versions
            game_url = f"{self.get_link('fabric')}game"
            response = requests.get(game_url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                versions = []
                for ver in data:
                    if ver.get('stable'):
                        versions.append(ver['version'])
                return versions
        except Exception as e:
            print(f"[JarBucket] Error fetching Fabric versions: {e}")
        return []
    
    def _get_fabric_loader_version(self):
        """Get latest stable Fabric loader version"""
        try:
            url = f"{self.get_link('fabric')}loader"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for loader in data:
                    if loader.get('stable'):
                        return loader['version']
        except Exception as e:
            print(f"[JarBucket] Error getting Fabric loader version: {e}")
        return None

    def _get_fabric_installer_version(self):
        """Get latest stable Fabric installer version"""
        try:
            url = f"{self.get_link('fabric')}installer"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for installer in data:
                    if installer.get('stable'):
                        return installer['version']
        except Exception as e:
            print(f"[JarBucket] Error getting Fabric installer version: {e}")
        return None

    def _fetch_fabric_download_url(self, game_version):
        """Get download URL for Fabric server (uses latest stable loader + installer)"""
        try:
            loader_version = self._get_fabric_loader_version()
            installer_version = self._get_fabric_installer_version()
            if not loader_version or not installer_version:
                print(f"[JarBucket] Could not resolve Fabric loader/installer versions from API")
                return None, None
            download_url = self.get_link('fabric', 'downloadTemplate').format(
                game_version=game_version,
                loader_version=loader_version,
                installer_version=installer_version
            )
            return download_url, None
        except Exception as e:
            print(f"[JarBucket] Error getting Fabric download URL: {e}")
        return None, None
    
    def _fetch_bedrock_download_url(self):
        """Get the latest Bedrock server download URL from Minecraft services API"""
        try:
            response = requests.get(
                self.get_link('bedrock'),
                headers={
                    'User-Agent': 'Mozilla/5.0 (Linux; x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
                },
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            
            links = {}
            for link in data.get('result', {}).get('links', []):
                dtype = link.get('downloadType', '')
                url = link.get('downloadUrl', '')
                
                import re as _re
                match = _re.match(r'serverBedrock(Preview)?(Windows|Linux)', dtype)
                if match:
                    is_preview = match.group(1) is not None
                    platform = match.group(2).lower()
                    key = f"{platform}_{'preview' if is_preview else 'stable'}"
                    links[key] = url
            
            # Return Linux stable URL (since this runs on Linux)
            if os.name == 'nt':
                return links.get('windows_stable'), None
            else:
                return links.get('linux_stable'), None
                
        except Exception as e:
            print(f"[JarBucket] Error fetching Bedrock download URL: {e}")
        return None, None
    
    def _fetch_bedrock_versions(self):
        """Bedrock only has 'latest' version available"""
        return ['latest']

    def _fetch_forge_versions(self):
        """Dynamically fetch Forge versions from Maven metadata (mc_version -> forge_version map)"""
        import re
        import xml.etree.ElementTree as ET
        try:
            url = self.get_link('forge', 'metadataUrl')
            response = requests.get(url, timeout=20)
            if response.status_code == 200:
                root = ET.fromstring(response.text)
                versions_elem = root.find('.//versioning/versions')
                if versions_elem is None:
                    return {}
                forge_map = {}
                for v in versions_elem.findall('version'):
                    ver_str = v.text.strip()
                    ver_lower = ver_str.lower()
                    # Skip non-stable (rc, beta, pre, alpha)
                    if any(x in ver_lower for x in ['rc', 'beta', 'pre', 'alpha']):
                        continue
                    # Modern format: "1.21.5-55.1.6"
                    if '-' not in ver_str:
                        continue
                    mc_ver, forge_ver = ver_str.split('-', 1)
                    # Validate clean MC version format
                    if not re.match(r'^\d+\.\d+(?:\.\d+)?$', mc_ver):
                        continue
                    # Limit to MC 1.12+
                    try:
                        mc_parts = [int(x) for x in mc_ver.split('.')]
                        if mc_parts[1] < 12:
                            continue
                    except (ValueError, IndexError):
                        continue
                    # Last write wins — Maven lists ascending, so latest forge build per MC survives
                    forge_map[mc_ver] = forge_ver
                return forge_map
        except Exception as e:
            print(f'[JarBucket] Error fetching Forge versions from Maven: {e}')
        return {}

    def _fetch_neoforge_versions(self):
        """Dynamically fetch NeoForge versions from Maven metadata (mc_version -> neoforge_version map)"""
        import xml.etree.ElementTree as ET
        try:
            url = self.get_link('neoforge', 'metadataUrl')
            response = requests.get(url, timeout=20)
            if response.status_code == 200:
                root = ET.fromstring(response.text)
                versions_elem = root.find('.//versioning/versions')
                if versions_elem is None:
                    return {}
                neo_map = {}
                for v in versions_elem.findall('version'):
                    ver_str = v.text.strip()
                    ver_lower = ver_str.lower()
                    # Skip non-stable (rc, beta, pre, alpha)
                    if any(x in ver_lower for x in ['rc', 'beta', 'pre', 'alpha']):
                        continue
                    # NeoForge format: "21.5.96" -> MC "1.21.5"; "21.0.167" -> MC "1.21"
                    parts = ver_str.split('.')
                    if len(parts) < 2:
                        continue
                    mc_ver = f'1.{parts[0]}' if parts[1] == '0' else f'1.{parts[0]}.{parts[1]}'
                    # Last write wins — latest NeoForge build per MC version survives
                    neo_map[mc_ver] = ver_str
                return neo_map
        except Exception as e:
            print(f'[JarBucket] Error fetching NeoForge versions from Maven: {e}')
        return {}

    def _fetch_spigot_versions(self):
        """Fetch available Spigot build versions from hub.spigotmc.org directory listing"""
        import re
        try:
            response = requests.get(self.get_link('spigot'), timeout=15)
            if response.status_code == 200:
                # Parse HTML directory listing for version JSON file links (e.g. "1.21.5.json")
                matches = re.findall(r'href="(\d+\.\d+(?:\.\d+)?)\.json"', response.text)
                if matches:
                    # Filter to stable versions only
                    versions = [v for v in matches if not any(
                        x in v.lower() for x in ['rc', 'beta', 'pre', 'alpha', 'snapshot']
                    )]
                    # Sort newest first
                    def _ver_key(ver):
                        try:
                            return tuple(int(x) for x in ver.split('.'))
                        except Exception:
                            return (0,)
                    versions.sort(key=_ver_key, reverse=True)
                    return versions
        except Exception as e:
            print(f'[JarBucket] Error fetching Spigot versions: {e}')
        # Fallback to known stable versions
        return [
            '1.21.4', '1.21.3', '1.21.1', '1.21', '1.20.6', '1.20.4',
            '1.20.2', '1.20.1', '1.19.4', '1.19.3', '1.19.2', '1.18.2',
            '1.17.1', '1.16.5', '1.15.2', '1.14.4', '1.13.2', '1.12.2'
        ]

    def _get_cached_url(self, server_type, version):
        """Return a cached download URL entry if it is still within the max-age window"""
        cache_key = f'{server_type}::{version}'
        entry = self.cache.get('downloadUrls', {}).get(cache_key)
        if not entry or not entry.get('cachedAt'):
            return None
        try:
            cached_at = datetime.fromisoformat(entry['cachedAt'])
            age_hours = (datetime.now() - cached_at).total_seconds() / 3600
            if age_hours < JAR_URL_CACHE_MAX_AGE_HOURS:
                return entry
        except Exception:
            pass
        return None

    def _store_cached_url(self, server_type, version, url_info):
        """Persist a resolved download URL into the cache file"""
        cache_key = f'{server_type}::{version}'
        if 'downloadUrls' not in self.cache:
            self.cache['downloadUrls'] = {}
        self.cache['downloadUrls'][cache_key] = {
            **url_info,
            'cachedAt': datetime.now().isoformat()
        }
        self._save_cache()

    def get_versions(self, server_type, force_refresh=False):
        """Get available versions for a server type"""
        # Check cache first
        if not force_refresh and self._is_cache_valid(server_type):
            cached = self.cache.get('versions', {}).get(server_type, {}).get('data', [])
            if cached:
                return cached
        
        versions = []
        
        # Fetch based on server type
        if server_type == 'paper':
            versions = self._fetch_paper_versions('paper')
        elif server_type == 'folia':
            versions = self._fetch_paper_versions('folia')
        elif server_type == 'purpur':
            versions = self._fetch_purpur_versions()
        elif server_type == 'vanilla':
            vanilla_data = self._fetch_vanilla_versions()
            versions = [{'version': v['id'], 'manifestUrl': v['url']} for v in vanilla_data]
        elif server_type == 'fabric':
            versions = self._fetch_fabric_versions()
        elif server_type == 'forge':
            forge_map = self._fetch_forge_versions()
            def _mc_key(v):
                try:
                    return tuple(int(x) for x in v.split('.'))
                except Exception:
                    return (0,)
            if forge_map:
                versions = sorted(forge_map.keys(), key=_mc_key, reverse=True)
                # Persist the resolved map so get_download_info can use it without re-fetching
                if 'versions' not in self.cache:
                    self.cache['versions'] = {}
                self.cache['versions'].setdefault('forge', {})['forge_map'] = forge_map
        elif server_type == 'neoforge':
            neo_map = self._fetch_neoforge_versions()
            def _mc_key(v):
                try:
                    return tuple(int(x) for x in v.split('.'))
                except Exception:
                    return (0,)
            if neo_map:
                versions = sorted(neo_map.keys(), key=_mc_key, reverse=True)
                if 'versions' not in self.cache:
                    self.cache['versions'] = {}
                self.cache['versions'].setdefault('neoforge', {})['neoforge_map'] = neo_map
        elif server_type == 'spigot':
            versions = self._fetch_spigot_versions()
        elif server_type == 'bedrock':
            versions = self._fetch_bedrock_versions()
        
        # Update cache
        if versions:
            if 'versions' not in self.cache:
                self.cache['versions'] = {}
            self.cache['versions'][server_type] = {
                'lastUpdated': datetime.now().isoformat(),
                'data': versions
            }
            self.cache['lastUpdated'] = datetime.now().isoformat()
            self._save_cache()
        
        return versions
    
    def get_download_info(self, server_type, version):
        """Get download URL and hash for a specific version"""
        # Spigot has no downloadable JAR — short-circuit before cache check
        if server_type == 'spigot':
            return {
                'requiresBuild': True,
                'message': 'Spigot requires BuildTools to compile. Download BuildTools and run: java -jar BuildTools.jar --rev ' + version,
                'buildtoolsUrl': self.get_link('spigot', 'buildtoolsUrl')
            }

        # Return cached URL if still fresh
        cached = self._get_cached_url(server_type, version)
        if cached:
            return {
                'url': cached['url'],
                'hash': cached.get('hash'),
                'filename': cached['filename'],
                'hashType': cached.get('hashType', 'sha256')
            }

        download_url = None
        file_hash = None
        filename = None

        if server_type in ['paper', 'folia']:
            download_url, file_hash = self._fetch_paper_download_url(server_type, version)
            filename = f"{server_type}-{version}.jar"
        elif server_type == 'purpur':
            download_url, file_hash = self._fetch_purpur_download_url(version)
            filename = f"purpur-{version}.jar"
        elif server_type == 'vanilla':
            # Need to look up manifest URL
            vanilla_versions = self.get_versions('vanilla')
            for v in vanilla_versions:
                if isinstance(v, dict) and v.get('version') == version:
                    download_url, file_hash = self._fetch_vanilla_download_url(v['manifestUrl'])
                    break
            filename = f"vanilla-{version}.jar"
        elif server_type == 'fabric':
            download_url, file_hash = self._fetch_fabric_download_url(version)
            filename = f"fabric-{version}.jar"
        elif server_type == 'forge':
            # Prefer the dynamically fetched map stored during get_versions(); re-fetch on cache miss
            forge_map = self.cache.get('versions', {}).get('forge', {}).get('forge_map') or self._fetch_forge_versions()
            forge_ver = forge_map.get(version) if forge_map else None
            if forge_ver:
                download_url = self.get_link('forge', 'installerTemplate').format(
                    mc_version=version, forge_version=forge_ver)
                filename = f"forge-{version}-{forge_ver}-installer.jar"
        elif server_type == 'neoforge':
            neo_map = self.cache.get('versions', {}).get('neoforge', {}).get('neoforge_map') or self._fetch_neoforge_versions()
            neo_ver = neo_map.get(version) if neo_map else None
            if neo_ver:
                download_url = self.get_link('neoforge', 'installerTemplate').format(
                    neoforge_version=neo_ver)
                filename = f"neoforge-{neo_ver}-installer.jar"
        elif server_type == 'bedrock':
            download_url, file_hash = self._fetch_bedrock_download_url()
            filename = 'bedrock_server.zip'

        if download_url:
            result = {
                'url': download_url,
                'hash': file_hash,
                'filename': filename,
                'hashType': 'sha256' if file_hash and len(file_hash) == 64 else 'sha1'
            }
            # Cache the resolved URL so the next request doesn't need to poll the API
            self._store_cached_url(server_type, version, result)
            return result

        return None
    
    def download_jar(self, server_type, version, progress_id=None,
                     progress_cb=None, cancel=None):
        """Download a JAR file to serverexecutables folder.

        Progress is reported through whichever channels are supplied:
        - progress_id: legacy in-memory download_progress dict (poll route).
        - progress_cb: callable(pct, message) for the JobManager task queue.
        - cancel: threading.Event; when set, aborts and raises JobCancelled
          (used by the queued-download job so the user can cancel it).
        """
        download_info = self.get_download_info(server_type, version)

        if not download_info:
            return {'success': False, 'error': 'Could not find download URL for this version'}

        if download_info.get('requiresBuild'):
            return {'success': False, 'error': download_info.get('message'), 'requiresBuild': True}

        url = download_info['url']
        filename = download_info['filename']

        # Create directory
        type_dir = SERVER_EXECUTABLES_DIR / server_type
        type_dir.mkdir(parents=True, exist_ok=True)
        filepath = type_dir / filename

        try:
            # Download with progress tracking. Send a browser User-Agent: the
            # Bedrock CDN (www.minecraft.net) blocks the default python-requests
            # UA, and it is harmless for the other (Maven/PaperMC/etc.) hosts.
            # (connect, read) timeout — read applies per chunk, so a stalled
            # connection fails in seconds instead of holding the worker for
            # the full download budget (issue #13).
            response = requests.get(url, stream=True, timeout=(10, 30), headers={
                'User-Agent': 'Mozilla/5.0 (Linux; x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
            })
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0

            if progress_id:
                self.update_progress(
                    progress_id,
                    status='downloading',
                    total=total_size,
                    downloaded=0,
                    progress=0,
                )
            if progress_cb:
                progress_cb(0, f'Downloading {filename}…')

            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if cancel is not None and cancel.is_set():
                        raise JobCancelled()
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size:
                            pct = int((downloaded / total_size) * 100)
                            if progress_id:
                                self.update_progress(
                                    progress_id,
                                    status='downloading',
                                    total=total_size,
                                    downloaded=downloaded,
                                    progress=pct,
                                )
                            if progress_cb:
                                progress_cb(pct, f'Downloading {filename}… ({pct}%)')

            # Verify hash if available
            if download_info.get('hash'):
                file_hash = self._calculate_hash(filepath, download_info.get('hashType', 'sha256'))
                if file_hash != download_info['hash']:
                    filepath.unlink()  # Delete mismatched file
                    return {'success': False, 'error': 'Hash verification failed'}

            if progress_id:
                self.update_progress(
                    progress_id,
                    status='complete',
                    total=total_size,
                    downloaded=downloaded,
                    progress=100,
                )
            if progress_cb:
                progress_cb(100, f'Downloaded {filename}')

            return {
                'success': True,
                'message': f'Downloaded {filename} successfully',
                'path': str(filepath.relative_to(BASE_DIR)),
                'filename': filename,
                'size': downloaded
            }

        except JobCancelled:
            # Cooperative cancel: drop the partial file and let the job manager
            # mark the task cancelled (never swallowed by the generic handler below).
            if filepath.exists():
                filepath.unlink()
            raise
        except requests.exceptions.RequestException as e:
            if filepath.exists():
                filepath.unlink()
            if progress_id:
                self.update_progress(progress_id, status='error', error=str(e))
            return {'success': False, 'error': f'Download failed: {str(e)}'}
        except Exception as e:
            if filepath.exists():
                filepath.unlink()
            if progress_id:
                self.update_progress(progress_id, status='error', error=str(e))
            return {'success': False, 'error': f'Error: {str(e)}'}
    
    def _calculate_hash(self, filepath, hash_type='sha256'):
        """Calculate file hash"""
        if hash_type == 'sha1':
            hasher = hashlib.sha1()
        else:
            hasher = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(65536)
                if not data:
                    break
                hasher.update(data)
        
        return hasher.hexdigest()
    
    def list_downloaded_jars(self):
        """List all downloaded JAR files organized by type"""
        jars = {}
        
        if SERVER_EXECUTABLES_DIR.exists():
            for type_dir in SERVER_EXECUTABLES_DIR.iterdir():
                if type_dir.is_dir():
                    server_type = type_dir.name
                    type_info = self.SERVER_TYPES.get(server_type, {})
                    jars[server_type] = {
                        'name': type_info.get('name', server_type.title()),
                        'icon': type_info.get('icon', '📦'),
                        'files': []
                    }
                    
                    for jar_file in sorted(type_dir.iterdir(), reverse=True):
                        if jar_file.is_file() and jar_file.suffix in ['.jar', '.zip']:
                            # Extract version from filename
                            version = self._extract_version_from_filename(jar_file.name, server_type)
                            jars[server_type]['files'].append({
                                'filename': jar_file.name,
                                'version': version,
                                'size': jar_file.stat().st_size,
                                'path': str(jar_file.relative_to(BASE_DIR)),
                                'modified': datetime.fromtimestamp(jar_file.stat().st_mtime).isoformat()
                            })
        
        return jars
    
    def _extract_version_from_filename(self, filename, server_type):
        """Extract version from filename"""
        import re
        name = filename.replace('.jar', '').replace('.zip', '').replace('-installer', '')
        
        # Try to extract version pattern
        match = re.search(rf'{server_type}-([\d.]+(?:-[\d.]+)?(?:-beta)?)', name, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Generic version pattern
        match = re.search(r'(\d+\.\d+(?:\.\d+)?(?:-[\d.]+)?)', name)
        if match:
            return match.group(1)
        
        return 'unknown'
    
    def delete_jar(self, server_type, filename):
        """Delete a downloaded JAR file.

        Both arguments come straight from the client, so they are validated as
        simple names before being joined. This used to guard with
        filepath.relative_to(SERVER_EXECUTABLES_DIR), which treats '..' as a
        literal segment rather than resolving it — so type=".." filename="msc.db"
        passed the check and unlink() removed the panel database (issue #83).
        is_safe_path() resolves both sides first, which also rejects a symlink
        inside the bucket that points out of it.
        """
        if not re.match(r'^[a-z0-9-]+$', server_type or ''):
            return {'success': False, 'error': 'Invalid server type'}
        if not self.JAR_FILENAME_RE.match(filename or ''):
            return {'success': False, 'error': 'Invalid filename'}

        if not is_safe_path(SERVER_EXECUTABLES_DIR, f'{server_type}/{filename}'):
            return {'success': False, 'error': 'Invalid path'}

        filepath = SERVER_EXECUTABLES_DIR / server_type / filename

        if not filepath.is_file():
            return {'success': False, 'error': 'File not found'}

        try:
            filepath.unlink()
            return {'success': True, 'message': f'Deleted {filename}'}
        except Exception as e:
            return {'success': False, 'error': f'Failed to delete: {str(e)}'}

    def create_backup_zip(self, dest_path):
        """Zip up every downloaded JAR/executable into dest_path (a file on disk,
        not memory — the bucket can hold many GB), preserving the <type>/<filename> layout."""
        with zipfile.ZipFile(dest_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            if SERVER_EXECUTABLES_DIR.exists():
                for file_path in sorted(SERVER_EXECUTABLES_DIR.rglob('*')):
                    if file_path.is_file():
                        arcname = file_path.relative_to(SERVER_EXECUTABLES_DIR)
                        try:
                            zf.write(file_path, arcname)
                        except (PermissionError, OSError):
                            pass  # Skip locked / unreadable files

    def restore_from_zip(self, zip_path):
        """Restore JARs from a backup ZIP file on disk into serverexecutables/, merging with what's there."""
        if not zipfile.is_zipfile(zip_path):
            return {'success': False, 'error': 'Uploaded file is not a valid ZIP archive'}

        SERVER_EXECUTABLES_DIR.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                safe_extractall(zf, SERVER_EXECUTABLES_DIR)
                restored = sum(1 for info in zf.infolist() if not info.is_dir())
        except ValueError as e:
            return {'success': False, 'error': str(e)}
        except Exception as e:
            return {'success': False, 'error': f'Failed to extract archive: {str(e)}'}

        return {'success': True, 'restored': restored}


# Initialize JAR Bucket Manager
jar_bucket = JarBucketManager()


# ==================== JAR Bucket API Endpoints ====================

@app.route('/api/jar-bucket/types', methods=['GET'])
@permission_required('panel.jars.manage')
def api_jar_bucket_types():
    """Get available server types organized by category"""
    return api_success(jar_bucket.get_server_types())

def is_stable_version(version_string):
    """Check if a version is a stable release (not snapshot, RC, pre-release, or beta)"""
    version_lower = str(version_string).lower()

    # Substring-based exclusions for clearly unstable labels
    excluded_substrings = [
        'snapshot', '-pre', 'pre-', '-rc', 'rc-', 'release candidate',
        'beta', 'alpha', 'experimental',
    ]
    for pattern in excluded_substrings:
        if pattern in version_lower:
            return False

    # Weekly snapshot pattern like "24w14a" or "1.21-rc1"
    import re
    if re.match(r'^\d{2}w\d{2}[a-z]$', version_lower):
        return False
    # RC suffix attached to a version number, e.g. "1.21-rc1", "1.21.1-pre3"
    if re.search(r'-(rc|pre)\d+$', version_lower):
        return False

    return True

@app.route('/api/jar-bucket/versions/<server_type>', methods=['GET'])
@permission_required('panel.jars.manage')
def api_jar_bucket_versions(server_type):
    """Get available versions for a server type"""
    force_refresh = request.args.get('refresh', 'false').lower() == 'true'
    versions = jar_bucket.get_versions(server_type, force_refresh)
    
    # Normalize version format
    normalized = []
    for v in versions:
        if isinstance(v, dict):
            version_str = v.get('version', str(v))
        else:
            version_str = str(v)
        
        # Filter out non-stable versions (snapshots, RC, etc.)
        if is_stable_version(version_str):
            normalized.append(version_str)

    return api_success({
        'serverType': server_type,
        'versions': normalized,
        'count': len(normalized)
    })

@app.route('/api/jar-bucket/download', methods=['POST'])
@permission_required('panel.jars.manage')
def api_jar_bucket_download():
    """Download a specific server JAR"""
    data = request.get_json()
    server_type = data.get('type', '').strip().lower()
    version = data.get('version', '').strip()

    if not server_type or not version:
        return api_error('Missing server type or version', 400)

    # Validate server type
    import re
    if not re.match(r'^[a-z0-9-]+$', server_type):
        return api_error('Invalid server type', 400)
    
    # Generate progress ID
    progress_id = str(uuid.uuid4())

    # Initialize progress immediately to avoid race condition
    jar_bucket.set_progress(progress_id, {
        'status': 'initializing',
        'message': 'Starting download...',
        'kind': 'download',
        'type': server_type,
        'version': version,
    })

    # Start download in background thread
    def do_download():
        result = jar_bucket.download_jar(server_type, version, progress_id)
        jar_bucket.update_progress(
            progress_id,
            status='complete' if result.get('success') else 'error',
            **result
        )
    
    thread = threading.Thread(target=do_download, daemon=True)
    thread.start()

    return api_success(progressId=progress_id,
                        message=f'Starting download of {server_type} {version}')

@app.route('/api/jar-bucket/queue-download', methods=['POST'])
@permission_required('panel.jars.manage')
def api_jar_bucket_queue_download():
    """Queue a JAR download as a background task (JobManager).

    Unlike /download (a fire-and-forget thread whose progress lives only in the
    browser), this creates a persisted 'jar_download' job: it survives leaving
    the page or restarting the panel, runs in the shared job pool, and can be
    cancelled. The Server JAR Manager uses this so batches of downloads keep
    going in the background."""
    data = request.get_json() or {}
    server_type = data.get('type', '').strip().lower()
    version = data.get('version', '').strip()

    if not server_type or not version:
        return api_error('Missing server type or version', 400)

    import re
    if not re.match(r'^[a-z0-9-]+$', server_type):
        return api_error('Invalid server type', 400)

    user_id, user = get_current_user()
    is_admin = group_manager.is_admin_group(user.get('groupId'))

    # De-duplicate: if this exact type+version is already queued/running for the
    # user, return that job instead of starting a second identical download.
    existing = [
        j for j in job_manager.list_jobs(is_admin=is_admin, user_id=user_id, limit=200)
        if j['type'] == 'jar_download'
        and j['status'] in JobManager.ACTIVE_STATUSES
        and (j.get('params') or {}).get('type') == server_type
        and (j.get('params') or {}).get('version') == version
    ]
    if existing:
        return api_success(jobId=existing[0]['id'], duplicate=True,
                            message=f'{server_type} {version} is already downloading')

    job_id = job_manager.submit(
        'jar_download',
        title=f'Download {server_type} {version}',
        params={'type': server_type, 'version': version},
        created_by=user_id,
    )
    return api_success(jobId=job_id,
                        message=f'Queued download of {server_type} {version}')

@app.route('/api/jar-bucket/progress/<progress_id>', methods=['GET'])
@limiter.exempt
@permission_required('panel.jars.manage')
def api_jar_bucket_progress(progress_id):
    """Get download progress"""
    progress = jar_bucket.get_progress(progress_id)
    if progress:
        return api_success(progress)
    return api_error('Unknown progress ID', 404)

@app.route('/api/jar-bucket/list', methods=['GET'])
@permission_required('panel.jars.manage')
def api_jar_bucket_list():
    """List all downloaded JAR files"""
    return api_success(jars=jar_bucket.list_downloaded_jars())

@app.route('/api/jar-bucket/delete', methods=['DELETE'])
@permission_required('panel.jars.manage')
def api_jar_bucket_delete():
    """Delete a downloaded JAR file"""
    data = request.get_json()
    server_type = data.get('type', '').strip().lower()
    filename = data.get('filename', '').strip()

    if not server_type or not filename:
        return api_error('Missing type or filename', 400)

    # Same guard the /download and /queue-download routes apply. delete_jar()
    # re-validates both names at the sink; this just fails early and keeps the
    # error shape consistent across the jar-bucket routes.
    if not re.match(r'^[a-z0-9-]+$', server_type):
        return api_error('Invalid server type', 400)
    if not JarBucketManager.JAR_FILENAME_RE.match(filename):
        return api_error('Invalid filename', 400)

    result = jar_bucket.delete_jar(server_type, filename)
    if result.get('success'):
        return jsonify(result)
    return jsonify(result), 400

@app.route('/api/jar-bucket/backup-all', methods=['GET'])
@permission_required('panel.jars.manage')
def api_jar_bucket_backup_all():
    """Zip up every downloaded server JAR/executable and stream it for download."""
    import tempfile
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        archive_name = f'mserver_jars_backup_{timestamp}.zip'
        # Build the archive on disk under UPLOADS_DIR (not /tmp, which may be
        # RAM-backed tmpfs) so a multi-GB bucket doesn't get buffered in memory.
        tmp = tempfile.NamedTemporaryFile(suffix='.zip', dir=UPLOADS_DIR, delete=False)
        tmp_path = Path(tmp.name)
        tmp.close()
        try:
            jar_bucket.create_backup_zip(tmp_path)
            response = send_file(tmp_path, as_attachment=True,
                                 download_name=archive_name, mimetype='application/zip')
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise
        # send_file already holds the file open; unlinking now still lets the
        # download stream to completion (Linux) and guarantees cleanup.
        tmp_path.unlink(missing_ok=True)
        return response
    except Exception as e:
        return api_error(str(e), 500)

@app.route('/api/jar-bucket/restore-all', methods=['POST'])
@permission_required('panel.jars.manage')
def api_jar_bucket_restore_all():
    """Restore server JARs from an uploaded backup ZIP (merges with existing files)."""
    if 'backup' not in request.files:
        return api_error('No backup file provided', 400)

    backup_file = request.files['backup']
    if not backup_file.filename:
        return api_error('Empty filename', 400)
    if not backup_file.filename.lower().endswith('.zip'):
        return api_error('Only ZIP archives are supported', 400)

    import tempfile
    tmp_path = None
    try:
        # Stream the upload to disk instead of read()-ing it into RAM.
        tmp = tempfile.NamedTemporaryFile(suffix='.zip', dir=UPLOADS_DIR, delete=False)
        tmp_path = Path(tmp.name)
        tmp.close()
        backup_file.save(tmp_path)

        rejected = reject_if_not_zip(tmp_path)
        if rejected:
            return rejected

        result = jar_bucket.restore_from_zip(tmp_path)
    except Exception as e:
        return api_error(str(e), 500)
    finally:
        if tmp_path:
            tmp_path.unlink(missing_ok=True)
    if result.get('success'):
        return jsonify(result)
    return jsonify(result), 400

@app.route('/api/jar-bucket/info/<server_type>/<version>', methods=['GET'])
@permission_required('panel.jars.manage')
def api_jar_bucket_info(server_type, version):
    """Get download info for a specific version (URL, hash, etc.)"""
    info = jar_bucket.get_download_info(server_type, version)
    if info:
        return api_success(info)
    return api_error('Version not found', 404)

@app.route('/api/jar-bucket/links', methods=['GET'])
@admin_required
def api_jar_bucket_links_get():
    """Get the per-type download link configuration (defaults, overrides, effective)"""
    return api_success(types=jar_bucket.get_links_config())

@app.route('/api/jar-bucket/links', methods=['PUT'])
@admin_required
def api_jar_bucket_links_update():
    """
    Update per-type download link overrides.
    Body: {"overrides": {"<type>": {"<field>": "<url or '' to reset>"}}}
    Only the provided types are touched; blank values reset that field to default.
    """
    data = request.get_json(silent=True) or {}
    overrides = data.get('overrides')
    if not isinstance(overrides, dict):
        return api_error('Missing or invalid "overrides" object', 400)

    result = jar_bucket.save_link_overrides(overrides)
    if not result['success']:
        return api_error('Validation failed', 400, errors=result['errors'])
    return api_success(message='Download links updated',
                        types=jar_bucket.get_links_config())

@app.route('/api/jar-bucket/links/test/<server_type>', methods=['POST'])
@admin_required
def api_jar_bucket_links_test(server_type):
    """Network-test the effective links for one server type"""
    result = jar_bucket.test_links(server_type)
    status = 200 if result.get('success') else 400
    return jsonify(result), status

@app.route('/api/jar-bucket/refresh', methods=['POST'])
@permission_required('panel.jars.manage')
def api_jar_bucket_refresh():
    """Force refresh the version cache for one or all server types"""
    data = request.get_json() or {}
    server_type = data.get('type')

    if server_type:
        jar_bucket.get_versions(server_type, force_refresh=True)
        return api_success(message=f'Refreshed {server_type} versions')
    else:
        for st in jar_bucket.SERVER_TYPES.keys():
            jar_bucket.get_versions(st, force_refresh=True)
        return api_success(message='Refreshed all versions')

@app.route('/api/jar-bucket/check/<server_type>/<version>', methods=['GET'])
@login_required
def api_jar_bucket_check(server_type, version):
    """Check if a specific JAR version is downloaded locally"""
    # Check in both the old jar_manager and new jar_bucket
    local_jar = jar_manager.get_local_jar_info(server_type, version)
    
    if local_jar:
        return api_success(
            downloaded=True,
            filename=local_jar.get('filename'),
            size=local_jar.get('size'),
            path=local_jar.get('path')
        )

    return api_success(downloaded=False)

@app.route('/api/jar-bucket/all-types', methods=['GET'])
@login_required
def api_jar_bucket_all_types():
    """Get all JAR Bucket server types (regardless of local availability)"""
    types = []
    for type_id, info in jar_bucket.SERVER_TYPES.items():
        types.append({
            'id': type_id,
            'name': info['name'],
            'description': info['description'],
            'category': info['category'],
            'icon': info.get('icon', '📦')
        })
    types.sort(key=lambda x: x['name'])
    return api_success(types=types)

@app.route('/api/jar-bucket/all-versions/<server_type>', methods=['GET'])
@login_required
def api_jar_bucket_all_versions(server_type):
    """Get all available versions for a server type from JAR Bucket API (not just local)"""
    versions = jar_bucket.get_versions(server_type, force_refresh=False)
    
    # Also get list of locally downloaded versions
    downloaded = set()
    jars = jar_bucket.list_downloaded_jars()
    if server_type in jars:
        for jar in jars[server_type].get('files', []):
            downloaded.add(jar.get('version'))
    
    # Normalize version format and add download status - filter out non-stable versions
    result = []
    for v in versions:
        version_str = v.get('version', str(v)) if isinstance(v, dict) else str(v)
        
        # Filter out non-stable versions (snapshots, RC, etc.)
        if is_stable_version(version_str):
            result.append({
                'version': version_str,
                'downloaded': version_str in downloaded
            })

    return api_success({
        'serverType': server_type,
        'versions': result,
        'count': len(result)
    })


# ==================== Tools API ====================

@app.route('/api/tools', methods=['GET'])
@permission_required('panel.tools.manage')
def list_tools():
    """List available tools in the tools directory"""
    tools = []
    try:
        if TOOLS_DIR.exists():
            for item in TOOLS_DIR.iterdir():
                if item.suffix == '.py' and item.is_file():
                    # Read first line for description
                    description = ''
                    try:
                        with open(item, 'r') as f:
                            first_lines = f.readlines()[:5]
                            for line in first_lines:
                                if line.startswith('#') and not line.startswith('#!'):
                                    description = line[1:].strip()
                                    break
                                elif line.startswith('"""') or line.startswith("'''"):
                                    description = line.strip().strip('"\'')
                                    break
                    except Exception:
                        pass
                    
                    tools.append({
                        'name': item.stem,
                        'filename': item.name,
                        'description': description or 'No description'
                    })
        
        # Sort tools alphabetically
        tools.sort(key=lambda x: x['name'].lower())
        
    except Exception as e:
        return api_error(str(e), 500, tools=[])

    return api_success({'tools': tools})

@app.route('/api/tools/upload', methods=['POST'])
@permission_required('panel.tools.manage')
def upload_tool():
    """Upload a Python tool file"""
    if 'file' not in request.files:
        return api_error('No file provided', 400)

    file = request.files['file']

    if file.filename == '':
        return api_error('No file selected', 400)

    # Validate file extension - only allow .py files
    if not file.filename.lower().endswith('.py'):
        return api_error('Only Python (.py) files are allowed', 400)

    # Secure the filename
    filename = secure_filename(file.filename)

    # Ensure it still has .py extension after securing
    if not filename.lower().endswith('.py'):
        filename = filename + '.py'

    # Validate the file content is valid Python (basic check)
    try:
        content = file.read().decode('utf-8')
        file.seek(0)  # Reset file pointer

        # Check if file starts with shebang or comments (typical Python file)
        # Also compile to check for syntax errors
        compile(content, filename, 'exec')
    except SyntaxError as e:
        return api_error(f'Invalid Python syntax: {str(e)}', 400)
    except UnicodeDecodeError:
        return api_error('File must be valid UTF-8 text', 400)
    except Exception as e:
        return api_error(f'Invalid file: {str(e)}', 400)

    # Ensure tools directory exists
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)

    # Save the file
    tool_path = TOOLS_DIR / filename

    try:
        file.save(str(tool_path))
        return jsonify({
            'success': True,
            'message': f'Tool "{filename}" uploaded successfully',
            'filename': filename
        })
    except Exception as e:
        return api_error(f'Failed to save file: {str(e)}', 500)


@app.route('/api/tools/<tool_name>/delete', methods=['DELETE'])
@permission_required('panel.tools.manage')
def delete_tool(tool_name):
    """Delete a tool from the tools directory"""
    tool_path = TOOLS_DIR / f'{tool_name}.py'

    if not tool_path.exists():
        return api_error('Tool not found', 404)

    # Security: ensure path is within tools directory
    try:
        tool_path = tool_path.resolve()
        if not str(tool_path).startswith(str(TOOLS_DIR.resolve())):
            return api_error('Invalid tool path', 400)
    except Exception:
        return api_error('Invalid tool', 400)

    try:
        tool_path.unlink()
        return jsonify({
            'success': True,
            'message': f'Tool "{tool_name}" deleted successfully'
        })
    except Exception as e:
        return api_error(f'Failed to delete tool: {str(e)}', 500)


@app.route('/api/tools/<tool_name>/run', methods=['POST'])
@permission_required('panel.tools.manage')
def run_tool(tool_name):
    """Run a tool from the tools directory with optional arguments"""
    tool_path = TOOLS_DIR / f'{tool_name}.py'

    if not tool_path.exists():
        return api_error('Tool not found', 404)

    # Security: ensure path is within tools directory
    try:
        tool_path = tool_path.resolve()
        if not str(tool_path).startswith(str(TOOLS_DIR.resolve())):
            return api_error('Invalid tool path', 400)
    except Exception:
        return api_error('Invalid tool', 400)

    # Get optional arguments from request body
    data = request.get_json() or {}
    args_string = data.get('args', '').strip()
    timeout_seconds = min(data.get('timeout', 300), 600)  # Max 10 minutes

    # Parse arguments (split by whitespace, respecting quotes)
    import shlex
    try:
        args_list = shlex.split(args_string) if args_string else []
    except ValueError as e:
        return api_error(f'Invalid arguments: {str(e)}', 400)

    # Build command
    command = ['python3', str(tool_path)] + args_list

    try:
        # Run the tool and capture output
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=str(BASE_DIR)
        )

        # NOTE: `success` here reflects the tool process's own exit code, not
        # whether this API call succeeded — deliberately NOT api_success(),
        # since that would always force success:true regardless of returncode.
        return jsonify({
            'success': result.returncode == 0,
            'output': result.stdout,
            'error': result.stderr,
            'returnCode': result.returncode,
            'command': ' '.join(command)
        })
    except subprocess.TimeoutExpired:
        return api_error(f'Tool execution timed out ({timeout_seconds}s limit)', 408)
    except Exception as e:
        return api_error(str(e), 500)


# ==================== Database Connection Cleanup ====================

@app.teardown_request
def _cleanup_db_transaction(exc=None):
    """Roll back a stray open transaction on this thread's DB connection at
    the end of every request. Without this, a write that hits an expected,
    internally-handled error (e.g. a UNIQUE constraint on a duplicate
    username) leaves its implicit transaction open — and the write lock it
    holds — for the lifetime of the thread, silently blocking every future
    write across the whole app. Runs regardless of whether the request itself
    raised, since the vulnerable case is exactly one where it didn't."""
    rollback_stray_transaction()


# ==================== Security Headers Middleware ====================

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses for production hardening"""
    # Prevent clickjacking attacks.
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Prevent MIME-sniffing vulnerabilities
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Enable XSS protection for legacy browsers
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Strict Transport Security (HSTS) - enforce HTTPS in production
    if os.environ.get('FLASK_ENV') != 'development' and request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Content Security Policy - restrictive default, adjust for your needs
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.socket.io https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob: https:; "
        "connect-src 'self' ws: wss:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self';"
    )
    
    # Referrer Policy - prevent sensitive URL leakage
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions Policy - disable unnecessary features
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    return response


# ==================== WebSocket Events ====================

# ==================== Background Job Queue API ====================

def can_access_job(job):
    """A user may see a job if they are admin, created it, or own its server."""
    user_id, user = get_current_user()
    if not user:
        return False
    if user_manager.user_has_permission(user, 'servers.access.all'):
        return True
    if job.get('createdBy') == user_id:
        return True
    sid = job.get('serverId')
    if sid and can_access_server(sid):
        return True
    return False


@app.route('/api/jobs', methods=['GET'])
@login_required
def list_jobs_route():
    """List background jobs visible to the current user (admins see all)."""
    user_id, user = get_current_user()
    is_admin = group_manager.is_admin_group(user.get('groupId'))
    owned_server_ids = []
    if not is_admin:
        owned_server_ids = [
            r['id'] for r in get_db().execute(
                'SELECT id FROM servers WHERE owner=?', (user_id,)
            ).fetchall()
        ]
    jobs = job_manager.list_jobs(is_admin=is_admin, user_id=user_id,
                                 owned_server_ids=owned_server_ids)
    return api_success(jobs=jobs)


@app.route('/api/jobs/<job_id>', methods=['GET'])
@login_required
def get_job_route(job_id):
    """Poll a single job's status (Socket.IO is the primary push channel)."""
    job = job_manager.get_job(job_id)
    if not job:
        return api_error('Job not found', 404)
    if not can_access_job(job):
        return api_error('Access denied', 403)
    return api_success(job=job)


@app.route('/api/jobs/<job_id>/cancel', methods=['POST'])
@login_required
def cancel_job_route(job_id):
    """Request cooperative cancellation of an active job."""
    job = job_manager.get_job(job_id)
    if not job:
        return api_error('Job not found', 404)
    if not can_access_job(job):
        return api_error('Access denied', 403)
    cancelled = job_manager.cancel(job_id)
    if not cancelled:
        return api_error('Job is not active', 400)
    return api_success()


@app.route('/api/jobs/<job_id>', methods=['DELETE'])
@login_required
def dismiss_job_route(job_id):
    """Remove a finished job from the list (and delete its temp artifact)."""
    job = job_manager.get_job(job_id)
    if not job:
        return api_error('Job not found', 404)
    if not can_access_job(job):
        return api_error('Access denied', 403)
    if job['status'] in JobManager.ACTIVE_STATUSES:
        return api_error('Cannot dismiss an active job; cancel it first', 400)
    # Clean up any prepared zip artifact.
    tmp = JOBS_TMP_DIR / f'{job_id}.zip'
    try:
        if tmp.exists():
            tmp.unlink()
    except Exception:
        pass
    conn = get_db()
    conn.execute('DELETE FROM jobs WHERE id=?', (job_id,))
    conn.commit()
    return api_success()


@app.route('/api/jobs/<job_id>/download', methods=['GET'])
@login_required
def download_job_route(job_id):
    """Download the artifact produced by a completed zip_download job."""
    job = job_manager.get_job(job_id)
    if not job:
        return api_error('Job not found', 404)
    if not can_access_job(job):
        return api_error('Access denied', 403)
    if job['type'] != 'zip_download' or job['status'] != 'completed':
        return api_error('No downloadable artifact for this job', 400)
    tmp = JOBS_TMP_DIR / f'{job_id}.zip'
    if not tmp.exists():
        return api_error('Artifact no longer available', 404)
    download_name = (job.get('result') or {}).get('filename', 'download.zip')
    return send_file(tmp, as_attachment=True, download_name=download_name,
                     mimetype='application/zip')


def _accessible_server_ids(user, user_id):
    """Return the server ids the user may access (admin-all ∨ owner ∨ group-share).

    Mirrors can_access_server() but in bulk, for deciding which 'server_<id>'
    realtime rooms a socket client should join."""
    if user_manager.user_has_permission(user, 'servers.access.all'):
        return [s.get('id') for s in server_manager.get_servers_list()]
    gid = user.get('groupId')
    ids = []
    for s in server_manager.get_servers_list():
        sid = s.get('id')
        if s.get('owner') == user_id:
            ids.append(sid)
        elif gid and gid in group_manager.get_server_group_ids(sid):
            ids.append(sid)
    return ids


def _resync_user_rooms(user_id):
    """Re-validate a connected user's realtime room memberships against their
    current permissions, dropping any server/admin/stats room they're no
    longer entitled to. Room membership is otherwise only set at connect
    time, so without this an admin revoking a user's access (unsharing a
    server, editing group permissions, reassigning a user's group) would
    leave that live socket receiving console/status output until it happens
    to reconnect. Call after any admin action that can shrink access."""
    with _user_sockets_lock:
        sids = list(_user_sockets.get(user_id, ()))
    if not sids:
        return
    user = user_manager.get_user(user_id)
    allowed_servers = set(_accessible_server_ids(user, user_id)) if user else set()
    is_admin = bool(user) and group_manager.is_admin_group(user.get('groupId'))
    can_view_stats = bool(user) and user_manager.user_has_permission(user, 'panel.stats.view')
    for sid in sids:
        for server_id in server_manager.get_all_server_ids():
            if server_id not in allowed_servers:
                leave_room(f'server_{server_id}', sid=sid, namespace='/')
        if not is_admin:
            leave_room('admins', sid=sid, namespace='/')
        if not can_view_stats:
            leave_room('stats_viewers', sid=sid, namespace='/')


def _resync_all_connected_rooms():
    """Resync every currently-connected user's rooms. Use after a change
    whose blast radius isn't limited to a single user (group permission
    edits, group deletion, server re-sharing)."""
    with _user_sockets_lock:
        user_ids = list(_user_sockets.keys())
    for uid in user_ids:
        _resync_user_rooms(uid)


@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    # Check if user is authenticated
    if 'user_id' not in session:
        return False  # Reject connection
    # Join per-user (and, for admins, an 'admins') room so background job events
    # can be pushed only to the relevant clients.
    user_id = session['user_id']
    join_room(f'user_{user_id}')
    user = user_manager.get_user(user_id)
    if user and group_manager.is_admin_group(user.get('groupId')):
        join_room('admins')
    # Join a room for host-level stats (CPU/RAM/disk) so stats_update only
    # reaches clients permitted to view them — same permission that gates the
    # HTTP /api/stats/* routes — instead of broadcasting to every connection.
    if user and user_manager.user_has_permission(user, 'panel.stats.view'):
        join_room('stats_viewers')
    # Join a room per accessible server so live console/status (emitted via
    # ServerInstance._broadcast to 'server_<id>') reaches this client for every
    # server it may access — including the dashboard's multi-server status list —
    # without leaking servers it cannot access.
    if user:
        for server_id in _accessible_server_ids(user, user_id):
            join_room(f'server_{server_id}')
    with _user_sockets_lock:
        _user_sockets[user_id].add(request.sid)
    print(f'Client connected to WebSocket (user: {session.get("username", "unknown")})')

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    with _socket_rate_lock:
        for key in [k for k in _socket_rate_hits if k[0] == request.sid]:
            del _socket_rate_hits[key]
    user_id = session.get('user_id')
    if user_id:
        with _user_sockets_lock:
            _user_sockets[user_id].discard(request.sid)
            if not _user_sockets[user_id]:
                del _user_sockets[user_id]
    print('Client disconnected from WebSocket')

@socketio.on('command')
def handle_command(data):
    """Handle command from client"""
    # Verify user is authenticated
    if 'user_id' not in session:
        emit('message', {'type': 'error', 'data': 'Not authenticated\n'})
        return

    if _socket_rate_limited('command', SOCKET_COMMAND_RATE_LIMIT, SOCKET_COMMAND_RATE_WINDOW):
        emit('message', {'type': 'error', 'data': 'Rate limit exceeded — slow down.\n'})
        return

    server_id = data.get('serverId')
    command = data.get('command', '')

    if server_id:
        # Check if user has access to this server
        user = user_manager.get_user(session['user_id'])
        if not user:
            emit('message', {'type': 'error', 'data': 'User not found\n'})
            return
        
        server_config = server_manager.get_server_config(server_id)
        if not server_config:
            emit('message', {'type': 'error', 'data': 'Server not found\n'})
            return
        
        # Check access: admin can access all, users can only access owned servers
        if not user_manager.user_has_permission(user, 'servers.access.all') and server_config.get('owner') != session['user_id'] and user.get('groupId') not in group_manager.get_server_group_ids(server_id):
            emit('message', {'type': 'error', 'data': 'Access denied\n'})
            return
        
        success, message = server_manager.send_command(server_id, command)
        if not success:
            emit('message', {'type': 'error', 'data': f'{message}\n', 'serverId': server_id})

@socketio.on('subscribe')
def handle_subscribe(data):
    """Subscribe to a server's output"""
    # Verify user is authenticated
    if 'user_id' not in session:
        return

    if _socket_rate_limited('subscribe', SOCKET_SUBSCRIBE_RATE_LIMIT, SOCKET_SUBSCRIBE_RATE_WINDOW):
        return

    server_id = data.get('serverId')
    if server_id:
        # Check if user has access to this server
        user = user_manager.get_user(session['user_id'])
        if not user:
            return
        
        server_config = server_manager.get_server_config(server_id)
        if not server_config:
            return
        
        # Check access
        if not user_manager.user_has_permission(user, 'servers.access.all') and server_config.get('owner') != session['user_id'] and user.get('groupId') not in group_manager.get_server_group_ids(server_id):
            return

        # Join this server's realtime room so live output reaches the client.
        # (connect already joins accessible servers; this covers ones created
        # after connect, e.g. a server the user just made.)
        join_room(f'server_{server_id}')

        instance = server_manager.servers.get(server_id)
        if instance:
            # Only send recent output if server is running to avoid stale log spam
            if instance.is_running():
                for line in instance.get_recent_output():
                    emit('message', {'type': 'output', 'data': line, 'serverId': server_id})
            
            # Always send current status
            emit('message', {'type': 'status', 'running': instance.is_running(), 'serverId': server_id})


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='MServer - Minecraft Server Management System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Run the server (default)
  python server.py
  
  # Run on a custom port
  python server.py --port 8080
        '''
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=PORT,
        help=f'Port to run the server on (default: {PORT})'
    )
    
    parser.add_argument(
        '--host',
        type=str,
        default='0.0.0.0',
        help='Host address to bind to (default: 0.0.0.0)'
    )
    
    return parser.parse_args()


def _graceful_shutdown(signum=None, frame=None):
    """
    Gracefully stop all running Minecraft servers before the process exits.
    Called on SIGTERM (systemd stop/restart) and at Python interpreter exit.
    Sends the 'stop' command to each server and waits up to 60 seconds for
    them to save and shut down before allowing the process to end.
    """
    stats_manager.stop()

    running_ids = [
        sid for sid, inst in list(server_manager.servers.items())
        if inst.is_running()
    ]

    if running_ids:
        print(f"[Shutdown] Stopping {len(running_ids)} Minecraft server(s) gracefully...")
        for server_id in running_ids:
            try:
                inst = server_manager.servers.get(server_id)
                if inst and inst.is_running():
                    cfg = server_manager.get_server_config(server_id)
                    name = cfg.get('name', server_id) if cfg else server_id
                    print(f"[Shutdown] Sending stop to '{name}' ({server_id})")
                    inst.send_command('stop')
            except Exception as e:
                print(f"[Shutdown] Error stopping {server_id}: {e}")

        # Wait up to 60 seconds for all servers to stop
        deadline = time.time() + 60
        while time.time() < deadline:
            if not any(
                inst.is_running()
                for inst in server_manager.servers.values()
            ):
                break
            time.sleep(1)

        # Force-kill anything still alive
        for server_id, inst in list(server_manager.servers.items()):
            if inst.is_running():
                cfg = server_manager.get_server_config(server_id)
                name = cfg.get('name', server_id) if cfg else server_id
                print(f"[Shutdown] Force-killing '{name}' ({server_id}) after timeout")
                try:
                    inst.process.kill()
                    inst.process.wait()
                except Exception:
                    pass

        print("[Shutdown] All servers stopped.")

    if signum is not None:
        # Exit cleanly when invoked as a signal handler
        os._exit(0)


# Register graceful shutdown for normal interpreter exit (e.g. gunicorn reload)
atexit.register(_graceful_shutdown)

# Register for SIGTERM (systemd stop) and SIGINT (Ctrl-C)
signal.signal(signal.SIGTERM, _graceful_shutdown)
signal.signal(signal.SIGINT, _graceful_shutdown)


def run_server(host='0.0.0.0', port=3000):
    """Run the MServer server"""
    _is_dev = os.environ.get('FLASK_ENV', 'production') == 'development'
    _cors_display = os.environ.get('CORS_ORIGINS', '*') or '*'
    _cookie_secure = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'

    print('=' * 60)
    print('MServer')
    print('=' * 60)
    print(f'Web Interface: http{"s" if _cookie_secure else ""}://localhost:{port}')
    print(f'Listening on:  {host}:{port}')
    print(f'Environment:   {"development" if _is_dev else "production"}')
    print(f'CORS origins:  {_cors_display}')
    if _cors_display == '*':
        print('  ⚠️  CORS is open to all origins. Set CORS_ORIGINS in .env for production.')
    if not _cookie_secure:
        print('  ⚠️  SESSION_COOKIE_SECURE is False. Set SESSION_COOKIE_SECURE=true in .env when using HTTPS.')
    if user_manager.needs_setup():
        print('ℹ️  No admin account configured yet.')
        print('    Open the panel in a browser to create the first admin (first-run setup).')
    if not _is_dev:
        print()
        print('  ℹ️  The built-in server is suitable for production with moderate')
        print('     concurrent users. For higher loads, consider using gunicorn:')
        print('       gunicorn -w 1 --threads 100 -b 0.0.0.0:3000 "server:app"')
    print('=' * 60)

    # allow_unsafe_werkzeug=True is required when running under Werkzeug's dev
    # server (threading mode). In production we still allow it so that
    # `python server.py` works for simple deployments, but print the notice
    # above encouraging gunicorn for exposed instances.
    socketio.run(app, host=host, port=port, debug=_is_dev, allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    args = parse_arguments()

    run_server(host=args.host, port=args.port)
