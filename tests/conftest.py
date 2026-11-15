import os
import tempfile
import secrets
from pathlib import Path
from cryptography.fernet import Fernet
import pytest
from fastapi.testclient import TestClient

# Must be set before the app imports its config/module-level SQLAlchemy engine.
ROOT = Path(tempfile.mkdtemp(prefix='ajs-tests-'))
os.environ['DATABASE_URL'] = 'sqlite:///' + str(ROOT / 'test.db')
os.environ['SESSION_SECRET'] = secrets.token_hex(32)
os.environ['ENCRYPTION_KEY'] = Fernet.generate_key().decode()
os.environ['CRON_TOKEN'] = secrets.token_hex(32)
os.environ['REGISTRATION_INVITE_CODE'] = 'test-invite-protected'
os.environ['APP_BASE_URL'] = 'http://testserver'
os.environ['SESSION_HTTPS_ONLY'] = 'false'

from app.main import app
from app.models import SessionLocal, Base, engine
from bs4 import BeautifulSoup

@pytest.fixture(autouse=True)
def isolated_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    with SessionLocal() as db:
        db.rollback()

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def csrf(client, url):
    html = BeautifulSoup(client.get(url).text, 'html.parser')
    return html.select_one('input[name=csrf]')['value']


def signup(client, email):
    token = csrf(client, '/register')
    response = client.post('/register', data={'csrf': token, 'email': email,
                                             'password': 'long-safe-password-for-testing',
                                             'invite': 'test-invite-protected'}, follow_redirects=False)
    assert response.status_code == 303
    return response
