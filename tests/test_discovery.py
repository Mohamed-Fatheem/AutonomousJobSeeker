from app.discovery import fetch_board, add_job, job_relevance
from app.models import SessionLocal, User, Profile, Job
from sqlalchemy import select


def test_local_match_respects_role_skills_location_and_exclusions():
    import json
    from app.discovery import job_relevance
    profile = Profile(search_terms='Backend, Python', preferred_locations='Remote, India',
                      excluded_terms='Internship, Trainee, Sales',
                      facts_json=json.dumps([{'id':'F1','category':'experience',
                          'text':'Built Python APIs with PostgreSQL and Docker', 'verified':True}]),
                      min_evidence_ratio=60)
    job = {'title':'Backend Engineer', 'company':'Acme', 'location':'Bengaluru, India',
           'description':('Build Python APIs with PostgreSQL and Docker. ' * 7)}
    assert job_relevance(job, profile) >= 60
    assert job_relevance({**job, 'title':'Sales Engineer'}, profile) == 0
    assert job_relevance({**job, 'location':'London'}, profile) == 0
    assert job_relevance({**job, 'description':'Build Python APIs. Internship role. ' * 8}, profile) == 0
    assert job_relevance({**job, 'description':''}, profile) == 0
    assert job_relevance({**job, 'title':'Account Manager'}, profile) == 0
    weak = {**job, 'description':('Python, React, Kubernetes, Terraform and AWS are required. ' * 5)}
    assert job_relevance(weak, profile) < 60


def test_greenhouse_feed():
    obj = {'jobs': [{'id': 17, 'title': 'AI Engineer', 'absolute_url': 'https://boards.greenhouse.io/acme/jobs/17',
                     'location': {'name': 'Remote'}, 'content': '<p>Python backend and AI platforms required. Build systems with SQL and distributed tasks.</p>'}]}
    jobs = fetch_board('greenhouse', 'acme', lambda url: obj)
    assert len(jobs) == 1
    assert jobs[0]['verified_link'] is True
    assert jobs[0]['title'] == 'AI Engineer'
    assert '<p>' not in jobs[0]['description']


def test_lever_feed():
    rows = [{'id': 'abc', 'text': 'Backend Engineer', 'descriptionPlain': 'Python SQL distributed data systems '*12,
             'categories': {'location': 'India'}, 'hostedUrl': 'https://jobs.lever.co/acme/abc',
             'applyUrl': 'https://jobs.lever.co/acme/abc/apply'}]
    jobs = fetch_board('lever', 'acme', lambda _: rows)
    assert jobs[0]['verified_link'] is True
    assert not jobs[0]['incomplete']


def test_ashby_feed():
    obj = {'jobs': [{'title': 'Applied Scientist', 'id': 'x', 'location': 'Remote',
                    'descriptionPlain': 'machine learning '*30,
                    'jobUrl': 'https://jobs.ashbyhq.com/acme/x',
                    'applyUrl': 'https://jobs.ashbyhq.com/acme/x/application'}]}
    assert fetch_board('ashby', 'acme', lambda _: obj)[0]['source'] == 'ashby'


def test_dedupe_and_alert_enrichment():
    with SessionLocal() as db:
        user = User(email='hi@example.com', password_hash='unused', profile=Profile(search_terms='Python'))
        db.add(user)
        db.commit()
        first = {'source': 'linkedin', 'title': 'Backend Engineer', 'company': 'Acme', 'location': 'Remote',
                 'description': '', 'listing_url': 'https://www.linkedin.com/jobs/view/222',
                 'incomplete': True}
        j1, fresh = add_job(db, user.id, first)
        assert fresh
        feed = {**first, 'source': 'greenhouse', 'description': 'Python and APIs '*40,
                'listing_url': 'https://boards.greenhouse.io/acme/jobs/15',
                'apply_url': 'https://boards.greenhouse.io/acme/jobs/15',
                'verified_link': True, 'incomplete': False}
        j2, fresh = add_job(db, user.id, feed)
        assert not fresh
        assert j1.id == j2.id
        assert j2.incomplete is False
        assert j2.verified_link is True


def test_board_scan_respects_platform_choices(monkeypatch):
    from app.models import Board
    from app.discovery import scan_boards
    from app.platforms import save_platforms
    calls = []
    monkeypatch.setattr('app.discovery.fetch_board', lambda kind, slug: calls.append(kind) or [])
    with SessionLocal() as db:
        user = User(email='source@example.com', password_hash='unused', profile=Profile())
        db.add(user)
        db.flush()
        db.add_all([Board(user_id=user.id, kind='lever', slug='acme'),
                    Board(user_id=user.id, kind='ashby', slug='acme')])
        save_platforms(db, user.id, ['lever'])
        db.commit()
        scan_boards(db, user, user.profile)
    assert calls == ['lever']
