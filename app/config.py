import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
ROOT = Path(__file__).resolve().parent.parent

def cfg(key: str, default: str = '') -> str:
    return os.getenv(key, default).strip()

DB_URL = cfg('DATABASE_URL', 'sqlite:///./autonomousjobseeker.db')
if DB_URL.startswith('postgres://'):
    DB_URL = 'postgresql+psycopg://' + DB_URL[len('postgres://'):]
elif DB_URL.startswith('postgresql://'):
    DB_URL = 'postgresql+psycopg://' + DB_URL[len('postgresql://'):]
BASE_URL = cfg('APP_BASE_URL', 'http://127.0.0.1:8000').rstrip('/')
HTTPS_ONLY = cfg('SESSION_HTTPS_ONLY', 'false').lower() == 'true'
SESSION_SECRET = cfg('SESSION_SECRET', '')
ENCRYPTION_KEY = cfg('ENCRYPTION_KEY', '')
CRON_TOKEN = cfg('CRON_TOKEN', '')
INVITE_CODE = cfg('REGISTRATION_INVITE_CODE', '')
GOOGLE_CLIENT_ID = cfg('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = cfg('GOOGLE_CLIENT_SECRET')
ENABLE_CRON = cfg('ENABLE_CRON', 'false').lower() == 'true'
