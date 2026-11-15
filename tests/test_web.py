from app.models import SessionLocal, User, Job
from sqlalchemy import select
from .conftest import csrf, signup

DESCRIPTION = ('Build Python backend services, design REST APIs and work with PostgreSQL databases. '
               'Collaborate with teams on cloud infrastructure, queues, testing, security and API reliability. ') * 3


def test_full_manual_lifecycle_and_tenant_isolation(client, monkeypatch):
    from app import ai
    signup(client, 'alpha@example.com')
    token = csrf(client, '/profile')
    r = client.post('/profile', data={'csrf': token, 'full_name': 'Alpha Tester',
         'headline': 'Backend Engineer', 'summary': 'Python backend developer',
         'fact_lines': 'skills | Python, PostgreSQL, FastAPI\nexperience | Developed secure REST APIs',
         'search_terms': 'Python, Backend'}, follow_redirects=False)
    assert r.status_code == 303
    token = csrf(client, '/settings')
    client.post('/settings', data={'csrf': token, 'provider': 'gemini', 'model_name': 'gemini-2.5-flash',
                 'api_key': 'fake-test-key', 'daily_limit': '3', 'min_evidence_ratio': '60'}, follow_redirects=False)
    token = csrf(client, '/jobs/new')
    r = client.post('/jobs/new', data={'csrf': token, 'title': 'Python Engineer',
       'company': 'A Company', 'location': 'Remote', 'source': 'manual', 'description': DESCRIPTION,
       'listing_url': 'https://jobs.lever.co/company/123'}, follow_redirects=False)
    joburl = r.headers['location']
    assert joburl.startswith('/jobs/')
    page = client.get(joburl).text
    assert 'Optimize my resume' in page
    assert 'Optimize my resume</button>' in page
    jobid = int(joburl.split('/')[-1])
    monkeypatch.setattr(ai, 'ask_llm', lambda *args, **kwargs: {
        'selected_fact_ids': ['F1', 'F2'],
        'requirements': [{'text': 'Python', 'supporting_fact_ids': ['F1']},
                         {'text': 'REST APIs', 'supporting_fact_ids': ['F2']}],
        'summary': 'Approved Python and API experience', 'missing_requirements': []})
    token = csrf(client, joburl)
    r = client.post(joburl + '/prepare', data={'csrf': token}, follow_redirects=False)
    assert r.status_code == 303
    pdf = client.get(joburl + '/resume.pdf')
    assert pdf.status_code == 200 and pdf.content.startswith(b'%PDF')
    assert 'Approved Python and API experience' in client.get(joburl).text
    # Sign out and register a second user who cannot read the first account's PDF or job page.
    token = csrf(client, '/')
    client.post('/logout', data={'csrf': token})
    signup(client, 'beta@example.com')
    assert client.get(joburl).status_code == 404
    assert client.get(joburl + '/resume.pdf').status_code == 404
    assert 'Python Engineer' not in client.get('/').text


def test_csrf_rejected(client):
    signup(client, 'alpha@example.com')
    assert client.post('/jobs/new', data={'title': 'Test', 'company': 'A'}, follow_redirects=False).status_code == 403


def test_duplicate_manual_submission(client):
    signup(client, 'alpha@example.com')
    csrfval = csrf(client, '/jobs/new')
    payload = {'csrf': csrfval, 'title': 'Backend Engineer', 'company': 'Acme',
               'location': 'Remote', 'description': DESCRIPTION}
    a = client.post('/jobs/new', data=payload, follow_redirects=False)
    b = client.post('/jobs/new', data=payload, follow_redirects=False)
    assert a.headers['location'] == b.headers['location']


def test_cron_token_guard(client):
    assert client.post('/api/cron/daily').status_code == 403


def test_job_platform_choices_are_saved_per_user(client):
    from app.platforms import selected_platforms
    signup(client, 'alpha@example.com')
    token = csrf(client, '/sources')
    response = client.post('/sources/platforms', data={'csrf': token,
        'platforms': ['linkedin', 'lever', 'naukrigulf']}, follow_redirects=False)
    assert response.status_code == 303
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == 'alpha@example.com'))
        assert selected_platforms(db, user.id) == {'linkedin', 'lever', 'naukrigulf'}
        assert user.profile.enable_gulf is True
    assert 'value="lever" checked' in client.get('/sources').text
    token = csrf(client, '/sources')
    client.post('/sources/platforms', data={'csrf': token}, follow_redirects=False)
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == 'alpha@example.com'))
        assert selected_platforms(db, user.id) == set()
        assert user.profile.enable_gulf is False


def test_invalid_platform_choice_does_not_replace_saved_choices(client):
    from app.platforms import selected_platforms
    signup(client, 'alpha@example.com')
    token = csrf(client, '/sources')
    client.post('/sources/platforms', data={'csrf': token, 'platforms': 'unknown'}, follow_redirects=False)
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == 'alpha@example.com'))
        assert 'linkedin' in selected_platforms(db, user.id)


def test_dashboard_search_review_filter_and_pagination(client):
    signup(client, 'alpha@example.com')
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == 'alpha@example.com'))
        for i in range(31):
            db.add(Job(user_id=user.id, fingerprint=f'job-{i}', title=f'Python Role {i}',
                       company='Acme', location='Remote', description=DESCRIPTION,
                       incomplete=i == 0, source='manual'))
        db.commit()
    first = client.get('/').text
    assert '31 jobs found' in first
    assert 'Page 1 of 2' in first
    assert 'Python Role 30' in first
    assert 'Python Role 0' not in first
    second = client.get('/?page=2').text
    assert 'Python Role 0' in second
    filtered = client.get('/?q=Role+0&review=needs_description').text
    assert '1 job found' in filtered
    assert 'Python Role 0' in filtered
    assert 'Python Role 30' not in filtered


def test_dashboard_search_does_not_show_another_users_jobs(client):
    signup(client, 'alpha@example.com')
    with SessionLocal() as db:
        other = User(email='beta@example.com', password_hash='x', profile=__import__('app.models', fromlist=['Profile']).Profile())
        db.add(other)
        db.flush()
        db.add(Job(user_id=other.id, fingerprint='private', title='Secret Role',
                   company='Private Co', incomplete=True))
        db.commit()
    response = client.get('/?q=Secret').text
    assert 'Secret Role' not in response
    assert '0 jobs found' in response


def test_jobs_without_company_are_hidden_from_list_counts_and_export(client):
    signup(client, 'alpha@example.com')
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == 'alpha@example.com'))
        db.add(Job(user_id=user.id, fingerprint='old-alert', title='Old alert',
                   company='Unknown employer', source='linkedin', incomplete=True))
        db.add(Job(user_id=user.id, fingerprint='good-alert', title='Verified role',
                   company='Acme', source='linkedin', incomplete=True))
        db.commit()
    page = client.get('/').text
    assert 'Old alert' not in page
    assert 'Verified role' in page
    assert '1 job found' in page
    export = client.get('/export/jobs.csv').text
    assert 'Old alert' not in export
    assert 'Verified role' in export
