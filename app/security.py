"""Security boundaries: encryption at rest, URL handling, CSRF, signed sessions."""
import hashlib
import hmac
import re
import secrets
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from .config import ENCRYPTION_KEY

_hasher = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
SLUG_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')


def hash_password(password):
    if len(password) < 12 or len(password) > 128:
        raise ValueError('Password must be 12–128 characters long')
    return _hasher.hash(password)


def password_ok(value, encoded):
    try:
        return _hasher.verify(encoded, value)
    except Exception:
        return False


def cipher():
    if not ENCRYPTION_KEY:
        raise RuntimeError('ENCRYPTION_KEY is required')
    return Fernet(ENCRYPTION_KEY.encode())


def encrypt(value):
    return cipher().encrypt(value.encode()).decode() if value else ''


def decrypt(value):
    return cipher().decrypt(value.encode()).decode() if value else ''


def constant_equal(a, b):
    return bool(a and b) and hmac.compare_digest(a, b)


def new_csrf():
    return secrets.token_urlsafe(32)


def clean_url(value):
    """Accept external http(s) links only; remove fragments and known tracking parameters."""
    if not value or len(value) > 2048:
        return ''
    value = value.strip()
    try:
        u = urlparse(value)
        if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password:
            return ''
        if u.hostname.lower() in {'localhost', '127.0.0.1', '0.0.0.0', '::1'}:
            return ''
        if '\\' in value or any(ord(c) < 32 for c in value):
            return ''
        query = urlencode([(k, v) for k, v in parse_qsl(u.query, keep_blank_values=True)
                           if not k.lower().startswith(('utm_', 'trk', 'tracking'))], doseq=True)
        return urlunparse((u.scheme, u.netloc, u.path, '', query, ''))
    except Exception:
        return ''


def normalize(value):
    return re.sub(r'[^a-z0-9]+', ' ', value.lower()).strip()


def fingerprint(title, company, location, source_id=''):
    """Cross-platform role matching; if company absent, distinguish source IDs."""
    base = '|'.join([normalize(company or ('unknown-' + source_id)), normalize(title), normalize(location)])
    return hashlib.sha256(base.encode()).hexdigest()


def safe_slug(value):
    if not SLUG_PATTERN.fullmatch(value):
        raise ValueError('Company board slug must use 1–64 letters, numbers, dashes or underscores')
    return value


def verified_ats_url(url, expected_kind=None):
    """Trusted links only when obtained from a direct official ATS feed, not an alert."""
    u = urlparse(clean_url(url))
    hosts = {
        'greenhouse': ('job-boards.greenhouse.io', 'boards.greenhouse.io', 'boards.greenhouse.io', 'boards.eu.greenhouse.io'),
        'lever': ('jobs.lever.co', 'jobs.eu.lever.co'),
        'ashby': ('jobs.ashbyhq.com',),
    }
    if u.scheme != 'https':
        return False
    if expected_kind:
        return u.hostname in hosts.get(expected_kind, ())
    return any(u.hostname in domains for domains in hosts.values())
