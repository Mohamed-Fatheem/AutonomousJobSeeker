"""Gmail OAuth, authorized alert import and user-addressed package email.

No direct automation of LinkedIn, Indeed, Naukri or NaukriGulf webpages.
"""
import base64
import json
import re
import secrets
from email.message import EmailMessage
from email.utils import parseaddr
from urllib.parse import urlencode
import httpx
from bs4 import BeautifulSoup
from .config import BASE_URL, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
from .security import encrypt, decrypt, clean_url
from .models import ImportedMessage, Job, utcnow
from .discovery import add_job, known_company
from .platforms import selected_platforms, ALERTS
from sqlalchemy import select

SCOPES = ('https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send')
AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
TOKEN_URL = 'https://oauth2.googleapis.com/token'
GMAIL_URL = 'https://gmail.googleapis.com/gmail/v1/users/me'
SOURCES = {'linkedin.com': 'linkedin', 'indeed.com': 'indeed', 'naukri.com': 'naukri',
           'naukrigulf.com': 'naukrigulf'}


def oauth_link(state):
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise ValueError('Gmail OAuth has not been configured by the app operator')
    return AUTH_URL + '?' + urlencode({'client_id': GOOGLE_CLIENT_ID, 'redirect_uri': BASE_URL + '/gmail/callback',
                                       'response_type': 'code', 'scope': ' '.join(SCOPES),
                                       'access_type': 'offline', 'prompt': 'consent', 'state': state})


def exchange_code(code):
    with httpx.Client(timeout=20) as client:
        response = client.post(TOKEN_URL, data={'code': code, 'client_id': GOOGLE_CLIENT_ID,
                            'client_secret': GOOGLE_CLIENT_SECRET, 'redirect_uri': BASE_URL + '/gmail/callback',
                            'grant_type': 'authorization_code'})
        response.raise_for_status()
        obj = response.json()
    if 'refresh_token' not in obj:
        raise ValueError('Google did not grant an offline refresh token; disconnect and reconnect')
    return obj


def get_access_token(profile):
    if not profile.gmail_credentials:
        raise ValueError('Gmail is not connected')
    credentials = json.loads(decrypt(profile.gmail_credentials))
    if not credentials.get('refresh_token'):
        raise ValueError('Missing Gmail refresh token')
    with httpx.Client(timeout=20) as client:
        r = client.post(TOKEN_URL, data={'client_id': GOOGLE_CLIENT_ID,
                                        'client_secret': GOOGLE_CLIENT_SECRET,
                                        'refresh_token': credentials['refresh_token'],
                                        'grant_type': 'refresh_token'})
        r.raise_for_status()
        response = r.json()
    return response['access_token']


def gmail_api(profile, method, resource, *, params=None, payload=None):
    if not resource.startswith('/') or '..' in resource:
        raise ValueError('Invalid Gmail API path')
    token = get_access_token(profile)
    with httpx.Client(timeout=30, follow_redirects=False) as client:
        r = client.request(method, GMAIL_URL + resource,
                           headers={'Authorization': 'Bearer ' + token}, params=params, json=payload)
        r.raise_for_status()
        return r.json()


def connected_address(profile):
    result = gmail_api(profile, 'GET', '/profile')
    return result.get('emailAddress', '')


def _body_data(payload):
    pieces = []
    def walk(part):
        if not isinstance(part, dict):
            return
        if part.get('body', {}).get('data') and part.get('mimeType') in ('text/html', 'text/plain'):
            raw = part['body']['data']
            try:
                text = base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)).decode('utf-8', errors='replace')
                pieces.append((part['mimeType'], text))
            except Exception:
                pass
        for sub in part.get('parts', []):
            walk(sub)
    walk(payload)
    return pieces


def parse_alert(payload):
    """Conservative email-card extraction, no assumptions about a complete job description."""
    headers = {h.get('name', '').lower(): h.get('value', '') for h in payload.get('payload', {}).get('headers', [])}
    sender = parseaddr(headers.get('from', ''))[1].lower()
    domain = sender.rsplit('@', 1)[-1]
    # Sender domain is only classification, not proof an application link is trustworthy.
    source = next((code for root, code in SOURCES.items() if domain == root or domain.endswith('.' + root)), None)
    if not source:
        return []
    body = _body_data(payload.get('payload', {}))
    html_doc = next((s for mime, s in body if mime == 'text/html'), '')
    if not html_doc:
        return []
    soup = BeautifulSoup(html_doc[:150000], 'html.parser')
    rows = []
    seen = set()
    known = {'linkedin': ('linkedin.com',), 'indeed': ('indeed.com',),
             'naukri': ('naukri.com',), 'naukrigulf': ('naukrigulf.com',)}
    for anchor in soup.find_all('a', href=True)[:250]:
        href = clean_url(anchor.get('href', ''))
        if not href:
            continue
        from urllib.parse import urlparse
        host = (urlparse(href).hostname or '').lower()
        # Accept official source links, plus ATS links provided in alert; all remain unverified.
        if not (any(host == d or host.endswith('.' + d) for d in known[source]) or
                host in ('jobs.lever.co', 'jobs.ashbyhq.com', 'boards.greenhouse.io', 'job-boards.greenhouse.io')):
            continue
        path = urlparse(href).path.lower()
        if not any(s in path for s in ('job', 'position', 'posting', 'career')):
            continue
        pieces = [re.sub(r'\s+', ' ', s).strip() for s in anchor.stripped_strings]
        pieces = [s for s in pieces if s]
        if not pieces or href in seen:
            continue
        title = pieces[0]
        if not (8 <= len(title) <= 135) or re.search(r'^(view|see|apply|your job alert|jobs? since|for last|since |new jobs)', title, re.I):
            continue
        company, location = 'Unknown employer', ''
        if source in ('naukri', 'naukrigulf') and len(pieces) >= 3:
            company, location = pieces[1], pieces[2]
        elif source == 'linkedin' and len(pieces) >= 2:
            company_location = re.split(r'\s+[·\u00b7\ufffd]\s+', pieces[1], maxsplit=1)
            company = company_location[0]
            if len(company_location) > 1:
                location = company_location[1]
        elif source == 'linkedin':
            role_company = re.match(r'^(.*?)\s+at\s+(.+)$', title, re.I)
            if role_company:
                title, company = role_company.groups()
        if not (2 <= len(company) <= 150) or re.search(r'^(actively recruiting|view job)', company, re.I):
            company = 'Unknown employer'
        if len(location) > 150:
            location = ''
        if not known_company(company):
            continue
        seen.add(href)
        rows.append({'source': source, 'source_id': href[:160], 'title': title,
                     'company': company, 'location': location, 'description': '',
                     'listing_url': href, 'apply_url': href, 'verified_link': False, 'incomplete': True})
        if len(rows) >= 20:
            break
    return rows


def import_alerts(db, user, profile, *, refresh_existing=False):
    enabled = selected_platforms(db, user.id) & set(ALERTS)
    if not enabled:
        return 0, []
    if refresh_existing:
        ids = db.scalars(select(ImportedMessage.message_id).where(
            ImportedMessage.user_id == user.id).order_by(ImportedMessage.id.desc()).limit(100)).all()
        messages = [{'id': mid} for mid in ids]
    else:
        response = gmail_api(profile, 'GET', '/messages', params={'q': profile.gmail_query, 'maxResults': 35})
        messages = response.get('messages', [])[:35]
    added, errors = 0, []
    for item in messages:
        mid = str(item.get('id', ''))
        imported = db.scalar(select(ImportedMessage).where(ImportedMessage.user_id == user.id,
                                                           ImportedMessage.message_id == mid)) if mid else None
        if not mid or (imported and not refresh_existing):
            continue
        try:
            obj = gmail_api(profile, 'GET', '/messages/' + mid, params={'format': 'full'})
            entries = parse_alert(obj)
            # Leave disabled-source messages unread by this importer so selecting
            # that platform later can still import them within the Gmail query window.
            if entries and entries[0]['source'] not in enabled:
                continue
            for row in entries:
                existing = db.scalar(select(Job).where(Job.user_id == user.id,
                                                       Job.listing_url == row['listing_url']))
                if existing:
                    if existing.company == 'Unknown employer' and row['company'] != 'Unknown employer':
                        existing.title = row['title']
                        existing.company = row['company']
                        existing.location = row['location']
                        added += 1
                    elif not existing.location and row['location']:
                        existing.location = row['location']
                        added += 1
                elif not imported:
                    _, fresh = add_job(db, user.id, row, profile, apply_filter=True)
                    added += int(fresh)
            if not imported:
                db.add(ImportedMessage(user_id=user.id, message_id=mid))
            db.commit()
        except Exception as e:
            db.rollback()
            reason = str(e.orig)[:100] if hasattr(e, 'orig') else type(e).__name__
            errors.append('Message could not be imported (' + reason + ')')
    return added, errors


def send_package(db, profile, user, job):
    """Sends ONLY to the app user. Uncertain Gmail submission is never retried blindly."""
    if not job.pdf_blob or job.incomplete:
        raise ValueError('Prepare the verified resume first')
    if job.notification_attempted_at or job.status in ('applied', 'interview', 'offer', 'notification_pending', 'notification_uncertain'):
        raise ValueError('Already sent, sending, or outcome uncertain; check Gmail Sent')
    if not profile.gmail_credentials:
        raise ValueError('Connect Gmail first')
    if not profile.gmail_address:
        raise ValueError('Reconnect Gmail so the delivery address can be confirmed')
    msg = EmailMessage()
    msg['To'] = profile.gmail_address
    msg['From'] = profile.gmail_address or user.email
    msg['Subject'] = f'Application package · {job.title} at {job.company}'[:160]
    route = job.apply_url or job.listing_url
    verified = 'Official ATS feed' if job.verified_link else 'Unverified listing — check company and URL before applying'
    requirements = json.loads(job.missing_json or '[]')
    approved_facts = json.loads(job.facts_snapshot_json or '[]')
    change_log = '\n'.join('- ' + f.get('id', '?') + ': ' + f.get('text', '') for f in approved_facts[:16])
    msg.set_content(f'''AutonomousJobSeeker — ready-to-apply package

Role: {job.title}
Company: {job.company}
Location: {job.location or 'Not supplied'}
Source: {job.source}
Link: {route or 'Not available'}
Link confidence: {verified}

Why it may match:
{job.explanation or 'Review the verified resume facts and job description.'}

Unresolved requirements:
{chr(10).join('- ' + x for x in requirements) if requirements else 'No gaps identified by model; review manually.'}

Submission status: NOT APPLIED. Do not assume an application was submitted.
Reason manual application is required: unattended LinkedIn/Indeed/Naukri/NaukriGulf applications
and most ATS forms lack a user-authorized general submission interface. CAPTCHA,
unknown screening answers, account-policy concerns and unverified links always require review.

Resume tailoring: only user-approved facts were selected/reordered; no claims were added.
Selected/reordered verified resume facts:
{change_log or 'No fact snapshot available'}
No new qualifications were invented, and wording was not rewritten.
See the dashboard for evidence mapping and missing requirements.

Suggested cover note (review before using):
{job.cover_note or 'Not generated'}

Update status: {__import__('app.config', fromlist=['BASE_URL']).BASE_URL}/jobs/{job.id}

This is a notification to you, not an application to the employer.
''')
    msg.add_attachment(job.pdf_blob, maintype='application', subtype='pdf', filename='tailored_resume.pdf')
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode().rstrip('=')
    # Commit state before network I/O: unknown outcomes cannot result in blind duplicate mail.
    job.status = 'notification_pending'
    job.notification_attempted_at = utcnow()
    db.commit()
    try:
        result = gmail_api(profile, 'POST', '/messages/send', payload={'raw': raw})
        if not result.get('id'):
            raise ValueError('Gmail did not return a message ID')
        job.notified_at = utcnow()
        job.status = 'notified'
        db.commit()
        return result['id']
    except Exception:
        job.status = 'notification_uncertain'
        db.commit()
        raise RuntimeError('Gmail submission outcome is uncertain. Check Sent mail before another attempt.')


def send_employer(db, profile, user, job, note):
    """User-initiated email application only when employer explicitly invites email applications.

    All verification is an explicit user assertion, not something inferred by an LLM.
    This is the ONLY employer submission adapter in the pilot.
    """
    if not profile.gmail_credentials:
        raise ValueError('Connect Gmail before sending an employer application')
    if not job.employer_email_confirmed or not job.employer_email:
        raise ValueError('Confirm that the vacancy explicitly invites applications by employer email')
    if job.employer_email_attempted_at:
        raise ValueError('Employer email was already attempted. Check Sent mail; never retry blindly')
    if job.incomplete or not job.pdf_blob:
        raise ValueError('Prepare the resume from a complete job description first')
    if job.status in ('applied', 'interview', 'offer', 'rejected', 'skipped'):
        raise ValueError('This vacancy is already in a closed or submitted state')
    note = note.strip()
    if len(note) < 40 or len(note) > 2400:
        raise ValueError('Write a 40–2,400 character truthful, reviewed application email')
    msg = EmailMessage()
    msg['From'] = profile.gmail_address or user.email
    msg['To'] = job.employer_email
    msg['Subject'] = ('Application — ' + job.title)[:160]
    msg.set_content(note + '\n\n' + (profile.full_name or user.email))
    msg.add_attachment(job.pdf_blob, maintype='application', subtype='pdf', filename='resume.pdf')
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode().rstrip('=')
    # One-way idempotency lock before network call; only later manual reconciliation can unlock.
    job.employer_email_attempted_at = utcnow()
    db.commit()
    try:
        response = gmail_api(profile, 'POST', '/messages/send', payload={'raw': raw})
        if not response.get('id'):
            raise ValueError('Gmail did not return a message ID')
        job.employer_email_sent_at = utcnow()
        job.submitted_at = utcnow()
        job.status = 'applied'
        db.commit()
        return response['id']
    except Exception:
        job.status = 'employer_email_uncertain'
        db.commit()
        raise RuntimeError('Email outcome uncertain. Check Gmail Sent before considering any retry.')
