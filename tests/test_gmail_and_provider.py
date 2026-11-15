import base64
import json
import pytest
from email import message_from_bytes
from app.gmail import parse_alert, send_employer
from app.models import SessionLocal, User, Profile, Job
from app.security import encrypt
from app.resume import build_pdf, facts_from_lines
from app import gmail
from .conftest import csrf, signup


def _urlencoded_body(s):
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip('=')


def test_alert_parser_marks_links_unverified_and_rejects_forged_senders():
    content = '''<p>Latest jobs</p><a href="https://www.linkedin.com/jobs/view/123">Backend Engineer at Example Inc.</a>
     <a href="https://evil.example.com/steal">See your account</a>'''
    payload = {'payload': {'headers': [{'name': 'From', 'value': 'Jobs <alerts@linkedin.com>'}],
               'parts': [{'mimeType': 'text/html', 'body': {'data': _urlencoded_body(content)}}]}}
    jobs = parse_alert(payload)
    assert len(jobs) == 1
    assert jobs[0]['verified_link'] is False
    assert jobs[0]['incomplete'] is True
    payload['payload']['headers'][0]['value'] = 'attacker@linkedin.com.evil.example'
    assert parse_alert(payload) == []


def test_alert_parser_separates_card_fields_and_skips_navigation():
    html = '''<a href="https://www.naukri.com/job-listings/example-123"><span>Data Scientist</span>
      <span>Acme Analytics</span><span>Chennai</span></a>
      <a href="https://www.naukri.com/jobs">View all jobs</a>'''
    payload = {'payload': {'headers': [{'name': 'From', 'value': 'Jobs <alerts@naukri.com>'}],
              'parts': [{'mimeType': 'text/html', 'body': {'data': _urlencoded_body(html)}}]}}
    rows = parse_alert(payload)
    assert len(rows) == 1
    assert rows[0]['title'] == 'Data Scientist'
    assert rows[0]['company'] == 'Acme Analytics'
    assert rows[0]['location'] == 'Chennai'
    assert rows[0]['incomplete'] is True


def test_alert_without_company_is_not_imported():
    html = '<a href="https://www.naukri.com/job-listings/example-123">Data Scientist</a>'
    payload = {'payload': {'headers': [{'name': 'From', 'value': 'Jobs <alerts@naukri.com>'}],
              'parts': [{'mimeType': 'text/html', 'body': {'data': _urlencoded_body(html)}}]}}
    assert parse_alert(payload) == []


def test_employer_email_needs_verified_invitation_and_is_idempotent(monkeypatch):
    from app.models import utcnow
    with SessionLocal() as db:
        profile = Profile(full_name='Candidate', facts_json=json.dumps(facts_from_lines(['skills | Python'])),
                          gmail_credentials=encrypt('{"refresh_token":"mock"}'), gmail_address='sender@example.com')
        user = User(email='owner@example.com', password_hash='x', profile=profile)
        db.add(user)
        db.commit()
        job = Job(user_id=user.id, fingerprint='fixture', title='Python Developer',
                  company='Acme', description='Python backend development ' * 15, incomplete=False,
                  employer_email='jobs@acme.example', employer_email_confirmed=False,
                  pdf_blob=build_pdf(profile, user.email, facts_from_lines(['skills | Python'])))
        db.add(job)
        db.commit()
        with pytest.raises(ValueError):
            send_employer(db, profile, user, job, 'I am applying for your Python Developer position. Please find my resume.')
        job.employer_email_confirmed = True
        db.commit()
        sends = []
        def fake_api(p, method, resource, *, payload=None, params=None):
            raw = base64.urlsafe_b64decode(payload['raw'] + '==')
            m = message_from_bytes(raw)
            sends.append(m)
            return {'id': 'gmail-sent-id'}
        monkeypatch.setattr(gmail, 'gmail_api', fake_api)
        send_employer(db, profile, user, job, 'I am applying for your Python Developer position. Please find my resume.')
        assert job.status == 'applied'
        assert sends[0]['To'] == 'jobs@acme.example'
        assert sends[0].get_payload()[1].get_filename() == 'resume.pdf'
        with pytest.raises(ValueError):
            send_employer(db, profile, user, job, 'I am applying for your Python Developer position. Please find my resume.')
        assert len(sends) == 1


def test_package_goes_to_connected_gmail_not_registration_email(monkeypatch):
    from app.gmail import send_package
    with SessionLocal() as db:
        profile = Profile(full_name='Candidate', gmail_credentials=encrypt('{"refresh_token":"mock"}'),
                          gmail_address='connected@example.com')
        user = User(email='registration@example.com', password_hash='x', profile=profile)
        db.add(user)
        db.flush()
        job = Job(user_id=user.id, fingerprint='package', title='Developer', company='Acme',
                  description='Python development ' * 20, incomplete=False,
                  pdf_blob=build_pdf(profile, user.email, facts_from_lines(['skills | Python'])))
        db.add(job)
        db.commit()
        sent = []
        def fake_api(p, method, resource, *, payload=None, params=None):
            sent.append(message_from_bytes(base64.urlsafe_b64decode(payload['raw'] + '==')))
            return {'id': 'sent-1'}
        monkeypatch.setattr(gmail, 'gmail_api', fake_api)
        send_package(db, profile, user, job)
        assert sent[0]['To'] == 'connected@example.com'
        assert sent[0]['To'] != user.email


def test_provider_validation_button(client, monkeypatch):
    signup(client, 'owner@example.com')
    token = csrf(client, '/settings')
    client.post('/settings', data={'csrf': token, 'provider': 'gemini',
                                  'model_name': 'gemini-2.5-flash', 'api_key': 'fake',
                                  'daily_limit': 3, 'min_evidence_ratio': 60})
    from app import main
    calls = []
    def fake_provider(provider, model, key):
        calls.append((provider, model, key))
    monkeypatch.setattr(main, 'check_connection', fake_provider)
    token = csrf(client, '/settings')
    r = client.post('/settings/test-provider', data={'csrf': token}, follow_redirects=True)
    assert r.status_code == 200 and 'AI key and model are available' in r.text
    assert calls[0][2] == 'fake'


def test_provider_http_errors_are_specific_and_do_not_show_secrets():
    from app.ai import provider_http_error
    assert 'model' in provider_http_error('gemini', 404).lower()
    assert 'key' in provider_http_error('gemini', 403).lower()
    assert 'quota' in provider_http_error('gemini', 429).lower()
    for status in (400, 401, 403, 404, 429, 503):
        assert 'secret' not in provider_http_error('gemini', status)


def test_gemini_connection_checks_model_metadata_without_generation(monkeypatch):
    import httpx
    from app import ai
    calls = []
    real_client = httpx.Client
    def handle(request):
        calls.append((request.method, str(request.url), request.headers.get('x-goog-api-key')))
        return httpx.Response(200, json={'supportedGenerationMethods': ['generateContent']})
    monkeypatch.setattr(ai.httpx, 'Client', lambda **kwargs: real_client(transport=httpx.MockTransport(handle)))
    ai.check_connection('gemini', 'gemini-2.5-flash', 'test-secret')
    assert len(calls) == 1
    assert calls[0][0] == 'GET'
    assert calls[0][1].endswith('/models/gemini-2.5-flash')


def test_provider_validation_shows_safe_model_error(client, monkeypatch):
    from app import main
    from app.ai import AIError
    signup(client, 'owner@example.com')
    token = csrf(client, '/settings')
    client.post('/settings', data={'csrf': token, 'provider': 'gemini',
                'model_name': 'gemini-2.5-flash', 'api_key': 'secret-test-key',
                'daily_limit': 3, 'min_evidence_ratio': 60})
    monkeypatch.setattr(main, 'check_connection', lambda *a: (_ for _ in ()).throw(
        AIError('Gemini could not find this model (HTTP 404). Choose a model available to your project.')))
    token = csrf(client, '/settings')
    response = client.post('/settings/test-provider', data={'csrf': token}, follow_redirects=True)
    assert 'HTTP 404' in response.text
    assert 'secret-test-key' not in response.text


def test_switching_ai_service_requires_its_own_key(client):
    signup(client, 'owner@example.com')
    token = csrf(client, '/settings')
    client.post('/settings', data={'csrf': token, 'provider': 'gemini',
                'model_name': 'gemini-2.5-flash', 'api_key': 'gemini-only-key',
                'daily_limit': 3, 'min_evidence_ratio': 60})
    token = csrf(client, '/settings')
    response = client.post('/settings', data={'csrf': token, 'provider': 'groq',
                'model_name': 'llama-3.3-70b-versatile', 'daily_limit': 3,
                'min_evidence_ratio': 60}, follow_redirects=True)
    assert 'Enter a key for the new AI service' in response.text
    assert 'gemini-only-key' not in response.text
    with SessionLocal() as db:
        user = db.query(User).filter_by(email='owner@example.com').one()
        assert user.profile.provider == 'gemini'
        assert user.profile.model_name == 'gemini-2.5-flash'


def test_settings_page_explains_save_and_test_and_keeps_advanced_filter(client):
    signup(client, 'owner@example.com')
    page = client.get('/settings').text
    assert 'Save any changes above first' in page
    assert 'Add and save an API key' in page
    assert 'Advanced: choose which Gmail alerts to read' in page
    assert 'name="gmail_query"' in page


def test_disabled_alert_waits_for_selection_but_incomplete_card_is_not_saved(monkeypatch):
    from app.gmail import import_alerts
    from app.models import ImportedMessage
    from app.platforms import save_platforms
    content = '<a href="https://www.linkedin.com/jobs/view/123">Backend Engineer at Example Inc.</a>'
    payload = {'payload': {'headers': [{'name': 'From', 'value': 'Jobs <alerts@linkedin.com>'}],
               'parts': [{'mimeType': 'text/html', 'body': {'data': _urlencoded_body(content)}}]}}
    def fake_api(profile, method, resource, *, params=None, payload=None):
        return {'messages': [{'id': 'alert-1'}]} if resource == '/messages' else alert
    alert = payload
    monkeypatch.setattr(gmail, 'gmail_api', fake_api)
    with SessionLocal() as db:
        user = User(email='alerts@example.com', password_hash='x', profile=Profile())
        db.add(user)
        db.flush()
        save_platforms(db, user.id, ['indeed'])
        db.commit()
        assert import_alerts(db, user, user.profile)[0] == 0
        assert db.query(ImportedMessage).count() == 0
        save_platforms(db, user.id, ['linkedin'])
        db.commit()
        assert import_alerts(db, user, user.profile)[0] == 0
        assert db.query(ImportedMessage).count() == 1
        assert db.query(Job).count() == 0


def test_refresh_enriches_existing_alert_without_duplicate(monkeypatch):
    from app.gmail import import_alerts
    from app.models import ImportedMessage
    html = '<a href="https://www.naukri.com/job-listings/example-123"><span>Data Scientist</span><span>Acme Analytics</span><span>Chennai</span></a>'
    payload = {'payload': {'headers': [{'name': 'From', 'value': 'Jobs <alerts@naukri.com>'}],
               'parts': [{'mimeType': 'text/html', 'body': {'data': _urlencoded_body(html)}}]}}
    monkeypatch.setattr(gmail, 'gmail_api', lambda p, m, r, **kw:
                        {'messages': [{'id': 'saved-1'}]} if r == '/messages' else payload)
    with SessionLocal() as db:
        user = User(email='refresh@example.com', password_hash='x', profile=Profile())
        db.add(user)
        db.flush()
        db.add(Job(user_id=user.id, fingerprint='old', source='naukri',
                   title='Data Scientist Acme Analytics Chennai', company='Unknown employer',
                   listing_url='https://www.naukri.com/job-listings/example-123', incomplete=True))
        db.add(ImportedMessage(user_id=user.id, message_id='saved-1'))
        db.commit()
        count, errors = import_alerts(db, user, user.profile, refresh_existing=True)
        assert count == 1 and errors == []
        jobs = db.query(Job).all()
        assert len(jobs) == 1
        assert (jobs[0].title, jobs[0].company, jobs[0].location) == ('Data Scientist', 'Acme Analytics', 'Chennai')
        assert jobs[0].incomplete is True
