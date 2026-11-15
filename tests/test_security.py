import pytest
from app.security import clean_url, safe_slug, fingerprint, encrypt, decrypt, verified_ats_url
from app.resume import facts_from_lines, parse_facts, build_pdf
from app.ai import validated_result, AIError
from types import SimpleNamespace


def test_secret_round_trip():
    assert decrypt(encrypt('sk_test_123-secret')) == 'sk_test_123-secret'
    assert 'sk_test_123-secret' not in encrypt('sk_test_123-secret')


def test_bad_urls_and_host_restrictions():
    for value in ['javascript:alert(1)', 'file:///etc/passwd', '//example.com',
                  'https://user:pass@jobs.lever.co/foo', 'http://127.0.0.1:999',
                  'https://example.com/\r\nX-Evil: yes']:
        assert clean_url(value) == ''
    assert verified_ats_url('https://jobs.lever.co/acme/xx/apply', 'lever')
    assert not verified_ats_url('https://jobs.lever.co.evil.test/acme', 'lever')
    assert not verified_ats_url('https://jobs.ashbyhq.com/acme', 'lever')


def test_board_slug_does_not_enable_ssrf():
    with pytest.raises(ValueError):
        safe_slug('../localhost')
    with pytest.raises(ValueError):
        safe_slug('foo?url=https://evil')
    assert safe_slug('Acme-2') == 'Acme-2'


def test_cross_source_fingerprint():
    assert fingerprint('Backend Engineer', 'ACME LTD', 'Remote') == fingerprint('Backend engineer!', 'Acme Ltd', 'remote')
    assert fingerprint('Backend Engineer', 'ACME LTD', 'Remote') != fingerprint('Backend Engineer', 'Other Company', 'Remote')


def test_resume_only_verified_and_fact_selection():
    facts = facts_from_lines(['skills | Python and PostgreSQL', 'experience | Built APIs'])
    facts.append({'id': 'BAD', 'category': 'education', 'text': 'PhD in robotics', 'verified': False})
    verified = parse_facts(__import__('json').dumps(facts))
    assert len(verified) == 2
    model = {'selected_fact_ids': ['BAD', 'F1', 'INVENTED', 'F1'],
             'requirements': [{'text': 'Python', 'supporting_fact_ids': ['BAD', 'F1', 'FAKE']}],
             'summary': 'Matches Python', 'missing_requirements': ['AWS certification']}
    checked = validated_result(model, verified)
    assert [f['id'] for f in checked['selected']] == ['F1']
    assert checked['requirements'][0]['fact_ids'] == ['F1']
    profile = SimpleNamespace(full_name='Example Candidate', phone='', location='Remote', headline='', summary='')
    document = build_pdf(profile, 'test@example.com', checked['selected'])
    assert document.startswith(b'%PDF')
    assert b'PhD in robotics' not in document


def test_ai_hallucinated_only_facts_rejected():
    facts = facts_from_lines(['skills | Python'])
    with pytest.raises(AIError):
        validated_result({'selected_fact_ids': ['FAKE']}, facts)
