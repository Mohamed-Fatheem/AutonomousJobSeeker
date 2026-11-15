"""Public, documented ATS job feeds. No job-board scraping or stealth browser."""
import html
import json
import re
from bs4 import BeautifulSoup
import httpx
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select, func
from .models import Job
from .security import fingerprint, safe_slug, clean_url, verified_ats_url
from .platforms import selected_platforms
from .resume import parse_facts

TIMEOUT = 15
MAX_PER_BOARD = 40


def plaintext(value):
    return BeautifulSoup(html.unescape(value or ''), 'html.parser').get_text(' ', strip=True)[:24000]


def fetch_board(kind, slug, transport=None):
    slug = safe_slug(slug)
    urls = {
        'greenhouse': f'https://boards-api.greenhouse.io/v1/boards/{slug}/jobs?content=true',
        'lever': f'https://api.lever.co/v0/postings/{slug}?mode=json&limit=100',
        'ashby': f'https://api.ashbyhq.com/posting-api/job-board/{slug}',
    }
    if kind not in urls:
        raise ValueError('Unsupported board type')
    if transport:
        result = transport(urls[kind])
    else:
        with httpx.Client(timeout=TIMEOUT, follow_redirects=False) as client:
            response = client.get(urls[kind])
            response.raise_for_status()
            result = response.json()
    records = result if kind == 'lever' else result.get('jobs', [])
    jobs = []
    for item in records[:250]:
        if kind == 'greenhouse':
            title = item.get('title', '')
            company = slug.replace('-', ' ').title()
            loc = (item.get('location') or {}).get('name', '')
            description = plaintext(item.get('content', ''))
            listing = clean_url(item.get('absolute_url', ''))
            # Greenhouse absolute_url may be custom employer domain, still sourced from official feed.
            apply_link = listing
            external_id = str(item.get('id', ''))
            verified = bool(listing)  # official API provides this link
        elif kind == 'lever':
            title = item.get('text', '')
            company = slug.replace('-', ' ').title()
            loc = (item.get('categories') or {}).get('location', '')
            description = plaintext(item.get('descriptionPlain') or item.get('description') or '')
            listing = clean_url(item.get('hostedUrl', ''))
            apply_link = clean_url(item.get('applyUrl', ''))
            external_id = str(item.get('id', ''))
            verified = verified_ats_url(apply_link, 'lever')
        else:
            title = item.get('title', '')
            company = slug.replace('-', ' ').title()
            loc = item.get('location', '') or ''
            description = plaintext(item.get('descriptionPlain') or item.get('descriptionHtml') or '')
            listing = clean_url(item.get('jobUrl', ''))
            apply_link = clean_url(item.get('applyUrl', ''))
            external_id = str(item.get('id', '') or item.get('jobUrl', ''))
            verified = verified_ats_url(apply_link, 'ashby')
        if title and listing:
            jobs.append({'source': kind, 'source_id': external_id, 'company': company,
                         'title': title[:300], 'location': loc[:250], 'description': description,
                         'listing_url': listing, 'apply_url': apply_link or listing,
                         'verified_link': verified, 'incomplete': len(description) < 180})
    return jobs


def source_allowed(source, profile):
    return source.lower() != 'naukrigulf' or bool(profile.enable_gulf)


MISSING_COMPANIES = ('', 'unknown employer', 'unknown company', 'company unknown',
                     'not provided', 'not supplied', 'n/a', 'na', '-')


def known_company(value):
    name = re.sub(r'\s+', ' ', str(value or '')).strip().casefold()
    return name not in MISSING_COMPANIES


def known_company_clause():
    return func.lower(func.trim(Job.company)).not_in(MISSING_COMPANIES)


SKILLS = ('python', 'java', 'javascript', 'typescript', 'sql', 'postgresql', 'mysql',
          'fastapi', 'django', 'flask', 'react', 'node.js', 'aws', 'azure', 'gcp',
          'docker', 'kubernetes', 'terraform', 'linux', 'git', 'rest api',
          'machine learning', 'deep learning', 'llm', 'langchain', 'langgraph',
          'pytorch', 'tensorflow', 'pandas', 'numpy', 'spark', 'airflow',
          'redis', 'kafka', 'mongodb', 'graphql', 'ci/cd', 'data engineering')
INDIAN_LOCATIONS = ('india', 'bengaluru', 'bangalore', 'chennai', 'hyderabad',
                    'mumbai', 'pune', 'delhi', 'noida', 'gurugram', 'gurgaon',
                    'kolkata', 'ahmedabad', 'kochi', 'coimbatore')


def _contains(text, phrase):
    return bool(re.search(r'(?<!\w)' + re.escape(phrase.casefold()) + r'(?!\w)', text.casefold()))


def job_relevance(job, profile):
    """Local 0–100 skill coverage after mandatory role/location/exclusion gates."""
    title = str(job.get('title') or '')
    company = str(job.get('company') or '')
    location = str(job.get('location') or '')
    description = str(job.get('description') or '')
    if not known_company(company) or len(description.strip()) < 180:
        return 0
    combined = ' '.join((title, company, location, description))
    excludes = [s.strip() for s in profile.excluded_terms.split(',') if s.strip()]
    if any(_contains(combined, word) for word in excludes):
        return 0
    roles = [s.strip() for s in profile.search_terms.split(',') if s.strip()]
    if not roles or not any(_contains(title, role) for role in roles):
        return 0
    locations = [s.strip().casefold() for s in profile.preferred_locations.split(',') if s.strip()]
    if locations:
        if not location:
            return 0
        allowed = any(_contains(location, place) for place in locations if place != 'india')
        if 'india' in locations:
            allowed = allowed or any(_contains(location, place) for place in INDIAN_LOCATIONS)
        if not allowed:
            return 0
        if (_contains(location, 'remote') and
                re.search(r'\b(us|usa|united states|uk|europe)\b', location, re.I) and
                not any(_contains(location, place) for place in INDIAN_LOCATIONS) and
                not _contains(location, 'global')):
            return 0
    facts = parse_facts(profile.facts_json)
    fact_text = ' '.join(f['text'] for f in facts)
    required = {skill for skill in SKILLS if _contains(title + ' ' + description, skill)}
    supported = {skill for skill in required if _contains(fact_text, skill)}
    if not required or not supported:
        return 0
    return round(100 * len(supported) / len(required))


def add_job(db, user_id, data, profile=None, apply_filter=False):
    if profile and not source_allowed(data.get('source', ''), profile):
        return None, False
    if apply_filter and profile:
        score = job_relevance(data, profile)
        if score == 0 or score < profile.min_evidence_ratio:
            return None, False
    title, company, loc = [str(data.get(k) or '').strip() for k in ('title', 'company', 'location')]
    if not title or not known_company(company):
        return None, False
    fp = fingerprint(title, company, loc, data.get('source_id', ''))
    existing = db.scalar(select(Job).where(Job.user_id == user_id, Job.fingerprint == fp))
    if existing:
        # Enhance incomplete email alerts when same role appears on employer's ATS feed.
        if existing.incomplete and not data.get('incomplete', True):
            existing.description = data.get('description', '')[:24000]
            existing.incomplete = False
        if data.get('verified_link') and data.get('apply_url'):
            existing.apply_url = clean_url(data['apply_url'])
            existing.verified_link = True
        db.flush()
        return existing, False
    new = Job(user_id=user_id, fingerprint=fp, title=title[:300], company=company[:250], location=loc[:250],
              source=data.get('source', 'manual'), source_id=str(data.get('source_id', ''))[:160],
              description=str(data.get('description', ''))[:24000],
              listing_url=clean_url(data.get('listing_url', '')),
              apply_url=clean_url(data.get('apply_url', '')),
              verified_link=bool(data.get('verified_link', False)),
              incomplete=bool(data.get('incomplete', True)))
    db.add(new)
    db.flush()
    return new, True


def scan_boards(db, user, profile):
    from .models import Board
    enabled = selected_platforms(db, user.id)
    boards = db.scalars(select(Board).where(Board.user_id == user.id)).all()
    added, errors = 0, []
    for board in boards[:12]:
        if board.kind not in enabled:
            continue
        try:
            jobs = fetch_board(board.kind, board.slug)
            jobs.sort(key=lambda item: job_relevance(item, profile), reverse=True)
            for item in jobs[:MAX_PER_BOARD]:
                _, fresh = add_job(db, user.id, item, profile, apply_filter=True)
                added += int(fresh)
            db.commit()
        except Exception as e:
            db.rollback()
            errors.append(f'{board.kind}/{board.slug}: {type(e).__name__}: {str(e)[:120]}')
    return added, errors
