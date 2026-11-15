"""Server-rendered, multi-user pilot app. Accounts are isolated in every database query."""
import json
import secrets
from contextlib import asynccontextmanager
from datetime import datetime
from urllib.parse import urlencode
from pathlib import Path
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import select, func, or_
from sqlalchemy.exc import IntegrityError
import re
from . import config
from .models import Base, engine, SessionLocal, User, Profile, Board, Job, Audit
from .security import hash_password, password_ok, constant_equal, new_csrf, encrypt, clean_url, safe_slug, fingerprint
from .resume import facts_from_lines, parse_facts, resume_text_from_pdf
from .discovery import add_job, scan_boards, job_relevance, known_company_clause
from .gmail import oauth_link, exchange_code, encrypt as gmail_encrypt, connected_address, import_alerts, send_package, send_employer
from .ai import MODELS, prepare, AIError, check_connection
from .pipeline import process_user, cron_users
from .platforms import selected_platforms, save_platforms

TEMPLATE_DIR = Path(__file__).resolve().parent / 'templates'

@asynccontextmanager
async def lifespan(app):
    missing = [key for key in ('SESSION_SECRET', 'ENCRYPTION_KEY', 'REGISTRATION_INVITE_CODE') if not getattr(config, {'REGISTRATION_INVITE_CODE': 'INVITE_CODE'}.get(key, key))]
    if missing:
        raise RuntimeError('Set security environment variables before deployment: ' + ', '.join(missing))
    if config.SESSION_SECRET == config.CRON_TOKEN or config.SESSION_SECRET == config.INVITE_CODE:
        raise RuntimeError('Use different random secrets for each setting')
    Base.metadata.create_all(bind=engine)  # pilot only; migrate schemas before production beta
    yield

app = FastAPI(title='AutonomousJobSeeker', lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=config.SESSION_SECRET or 'development-only-not-for-deployment',
                   session_cookie='ajs_session', max_age=60 * 60 * 24 * 7,
                   same_site='lax', https_only=config.HTTPS_ONLY)
app.mount('/static', StaticFiles(directory=Path(__file__).resolve().parent / 'static'), name='static')
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def flash(request, message, kind='success'):
    request.session['flash'] = {'message': str(message)[:400], 'kind': kind}


def jump(url):
    return RedirectResponse(url, status_code=303)


def actor(request, db):
    try:
        uid = int(request.session.get('user_id', 0))
    except (ValueError, TypeError):
        return None
    return db.get(User, uid) if uid else None


def must_user(request, db):
    user = actor(request, db)
    if user is None:
        raise HTTPException(401, 'Please sign in')
    return user


def csrf_token(request):
    if 'csrf' not in request.session:
        request.session['csrf'] = new_csrf()
    return request.session['csrf']


def check_csrf(request, data):
    if not constant_equal(str(data.get('csrf') or ''), request.session.get('csrf', '')):
        raise HTTPException(403, 'Invalid or expired form security token')


def view(request, name, db, **extra):
    user = actor(request, db)
    data = {'request': request, 'user': user, 'profile': user.profile if user else None,
            'csrf': csrf_token(request), 'flash': request.session.pop('flash', None),
            'models': MODELS, **extra}
    return templates.TemplateResponse(request, name, data)


def audit(db, user_id, action, detail='', job_id=None):
    db.add(Audit(user_id=user_id, action=action, detail=detail[:1000], job_id=job_id))


def owned_job(db, user, job_id):
    job = db.scalar(select(Job).where(Job.id == job_id, Job.user_id == user.id))
    if not job:
        raise HTTPException(404, 'Job not found')
    return job

@app.exception_handler(401)
async def not_logged_in(request, exc):
    return jump('/login')

@app.get('/healthz')
async def healthz():
    return {'status': 'ok'}

@app.get('/register', response_class=HTMLResponse)
async def registration_page(request: Request):
    with SessionLocal() as db:
        return view(request, 'register.html', db)

@app.post('/register')
async def register(request: Request):
    form = await request.form()
    check_csrf(request, form)
    with SessionLocal() as db:
        if not constant_equal(str(form.get('invite') or ''), config.INVITE_CODE):
            flash(request, 'Invalid registration invite code', 'error')
            return jump('/register')
        try:
            email = str(form.get('email', '')).strip().lower()
            if len(email) > 254 or not re.fullmatch(r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", email):
                raise ValueError('Enter a valid email address')
            pwhash = hash_password(str(form.get('password', '')))
        except ValueError as exc:
            flash(request, str(exc), 'error')
            return jump('/register')
        user = User(email=email, password_hash=pwhash)
        user.profile = Profile()
        db.add(user)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            flash(request, 'Email address already registered', 'error')
            return jump('/register')
        request.session.clear()
        request.session['user_id'] = user.id
        csrf_token(request)
        audit(db, user.id, 'user.register')
        db.commit()
        flash(request, 'Account created. Add verified resume facts first.')
        return jump('/profile')

@app.get('/login', response_class=HTMLResponse)
async def login_page(request: Request):
    with SessionLocal() as db:
        return view(request, 'login.html', db)

@app.post('/login')
async def login(request: Request):
    form = await request.form()
    check_csrf(request, form)
    with SessionLocal() as db:
        email = str(form.get('email', '')).strip().lower()
        user = db.scalar(select(User).where(User.email == email))
        if not user or not password_ok(str(form.get('password', '')), user.password_hash):
            flash(request, 'Invalid email or password', 'error')
            return jump('/login')
        request.session.clear()
        request.session['user_id'] = user.id
        csrf_token(request)
        flash(request, 'Signed in')
        return jump('/')

@app.post('/logout')
async def logout(request: Request):
    check_csrf(request, await request.form())
    request.session.clear()
    return jump('/login')

@app.get('/', response_class=HTMLResponse)
async def dashboard(request: Request, source: str = '', state: str = '', q: str = '', review: str = '', page: int = 1):
    with SessionLocal() as db:
        user = must_user(request, db)
        q = q.strip()[:100]
        page = max(1, page)
        visible = known_company_clause()
        stmt = select(Job).where(Job.user_id == user.id, visible)
        if source:
            stmt = stmt.where(Job.source == source)
        if state:
            stmt = stmt.where(Job.status == state)
        if q:
            term = q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
            pattern = f'%{term}%'
            stmt = stmt.where(or_(Job.title.ilike(pattern, escape='\\'),
                                  Job.company.ilike(pattern, escape='\\'),
                                  Job.location.ilike(pattern, escape='\\')))
        if review == 'needs_description':
            stmt = stmt.where(Job.incomplete.is_(True))
        elif review == 'ready_to_prepare':
            stmt = stmt.where(Job.incomplete.is_(False), Job.pdf_blob.is_(None),
                              Job.status == 'discovered')
        total_filtered = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        page_size = 25
        pages = max(1, (total_filtered + page_size - 1) // page_size)
        page = min(page, pages)
        jobs = db.scalars(stmt.order_by(Job.created_at.desc(), Job.id.desc())
                          .offset((page - 1) * page_size).limit(page_size)).all()
        summary = {'total': db.scalar(select(func.count(Job.id)).where(Job.user_id == user.id, visible)),
                   'ready': db.scalar(select(func.count(Job.id)).where(Job.user_id == user.id, visible, Job.prepared_at.is_not(None))),
                   'notified': db.scalar(select(func.count(Job.id)).where(Job.user_id == user.id, visible, Job.notified_at.is_not(None))),
                   'applied': db.scalar(select(func.count(Job.id)).where(Job.user_id == user.id, visible, Job.status.in_(['applied','interview','offer'])))}
        summary['needs_description'] = db.scalar(select(func.count(Job.id)).where(
            Job.user_id == user.id, visible, Job.incomplete.is_(True)))
        summary['can_prepare'] = db.scalar(select(func.count(Job.id)).where(
            Job.user_id == user.id, visible, Job.incomplete.is_(False), Job.pdf_blob.is_(None), Job.status == 'discovered'))
        return view(request, 'dashboard.html', db, jobs=jobs, summary=summary,
                    selected_source=source, selected_state=state, search_query=q,
                    selected_review=review, page=page, pages=pages, total_filtered=total_filtered)

@app.get('/profile', response_class=HTMLResponse)
async def profile_page(request: Request):
    with SessionLocal() as db:
        user = must_user(request, db)
        fact_lines = '\n'.join(f"{f['category']} | {f['text']}" for f in parse_facts(user.profile.facts_json))
        return view(request, 'profile.html', db, facts_lines=fact_lines)

@app.post('/profile')
async def profile_save(request: Request):
    data = await request.form()
    check_csrf(request, data)
    with SessionLocal() as db:
        user = must_user(request, db)
        p = user.profile
        for key, limit in [('full_name', 200), ('phone', 90), ('location', 150), ('headline', 300),
                           ('summary', 1300), ('search_terms', 500), ('preferred_locations', 500),
                           ('excluded_terms', 500)]:
            setattr(p, key, str(data.get(key) or '')[:limit].strip())
        facts = facts_from_lines(str(data.get('fact_lines') or '').splitlines())
        p.facts_json = json.dumps(facts)
        db.add(p)
        audit(db, user.id, 'profile.save', f'{len(facts)} verified facts')
        db.commit()
        flash(request, f'Profile updated with {len(facts)} user-confirmed facts. Existing packages retain their earlier snapshot.')
        return jump('/profile')

@app.post('/profile/upload')
async def profile_upload(request: Request, file: UploadFile = File(...)):
    data = await request.form()
    check_csrf(request, data)
    with SessionLocal() as db:
        user = must_user(request, db)
        raw = await file.read(2_100_000)
        if not file.filename or not file.filename.lower().endswith('.pdf') or not raw.startswith(b'%PDF-'):
            flash(request, 'Only a genuine PDF is accepted (up to 2 MB)', 'error')
            return jump('/profile')
        try:
            content = resume_text_from_pdf(raw)
        except Exception:
            flash(request, 'Unable to extract PDF text; try a text-based PDF', 'error')
            return jump('/profile')
        user.profile.master_resume = content
        db.commit()
        flash(request, 'Master PDF extracted for reference. Verify individual facts manually in the editor; no claims were auto-approved.')
        return jump('/profile')

@app.get('/settings', response_class=HTMLResponse)
async def settings_page(request: Request):
    with SessionLocal() as db:
        must_user(request, db)
        return view(request, 'settings.html', db,
                    gmail_configured=bool(config.GOOGLE_CLIENT_ID and config.GOOGLE_CLIENT_SECRET),
                    local_app=config.BASE_URL.startswith(('http://127.0.0.1', 'http://localhost')))

@app.post('/settings')
async def settings_save(request: Request):
    form = await request.form()
    check_csrf(request, form)
    with SessionLocal() as db:
        user = must_user(request, db)
        p = user.profile
        provider = str(form.get('provider') or '')
        model = str(form.get('model_name') or '').strip()
        if provider not in MODELS:
            flash(request, 'Choose one of the available AI services.', 'error')
            return jump('/settings')
        if not re.fullmatch(r'[a-zA-Z0-9_.:/-]{2,100}', model):
            flash(request, 'Enter a valid model name for the AI service you selected.', 'error')
            return jump('/settings')
        key = str(form.get('api_key') or '').strip()
        if len(key) > 600:
            flash(request, 'The API key is too long.', 'error')
            return jump('/settings')
        if provider != p.provider and p.encrypted_api_key and not key:
            flash(request, 'Enter a key for the new AI service. Your saved key belongs to the previous service.', 'error')
            return jump('/settings')
        try:
            daily_limit = int(form.get('daily_limit') or '3')
            min_evidence_ratio = int(form.get('min_evidence_ratio') or '60')
        except ValueError:
            flash(request, 'Enter whole numbers for the daily limit and match threshold.', 'error')
            return jump('/settings')
        if not 1 <= daily_limit <= 10 or not 0 <= min_evidence_ratio <= 100:
            flash(request, 'Daily limit must be 1–10 and match threshold must be 0–100.', 'error')
            return jump('/settings')
        p.provider = provider
        p.model_name = model
        if key:
            p.encrypted_api_key = encrypt(key)
        p.daily_limit = daily_limit
        p.min_evidence_ratio = min_evidence_ratio
        p.auto_process = form.get('auto_process') == 'on'
        p.gmail_query = str(form.get('gmail_query') or '')[:500].strip()
        audit(db, user.id, 'settings.save', 'Provider and automation preferences updated')
        db.commit()
        flash(request, 'Settings saved. A valid AI key is needed to prepare resumes; Gmail is needed to import alerts and email packages.')
        return jump('/settings')

@app.post('/settings/test-provider')
async def test_provider(request: Request):
    """Opt-in tiny API call; consumes provider quota and never sends user data."""
    check_csrf(request, await request.form())
    with SessionLocal() as db:
        user = must_user(request, db)
        p = user.profile
        if not p.encrypted_api_key:
            flash(request, 'Save an AI API key before testing the model connection.', 'error')
        else:
            try:
                from .security import decrypt
                check_connection(p.provider, p.model_name, decrypt(p.encrypted_api_key))
                flash(request, 'AI key and model are available. Resume preparation makes a separate AI request.')
            except AIError as exc:
                flash(request, str(exc), 'error')
            except Exception:
                flash(request, 'AI connection failed. Verify key, model ID, access rights and remaining quota.', 'error')
        return jump('/settings')

@app.post('/settings/delete-key')
async def delete_key(request: Request):
    check_csrf(request, await request.form())
    with SessionLocal() as db:
        user = must_user(request, db)
        user.profile.encrypted_api_key = ''
        user.profile.auto_process = False
        audit(db, user.id, 'settings.key_deleted')
        db.commit()
        flash(request, 'Provider key deleted and automatic processing disabled')
    return jump('/settings')

@app.get('/sources', response_class=HTMLResponse)
async def sources_page(request: Request):
    with SessionLocal() as db:
        user = must_user(request, db)
        boards = db.scalars(select(Board).where(Board.user_id == user.id).order_by(Board.created_at.desc())).all()
        return view(request, 'sources.html', db, boards=boards,
                    selected_platforms=selected_platforms(db, user.id))

@app.post('/sources/platforms')
async def sources_platforms(request: Request):
    form = await request.form()
    check_csrf(request, form)
    with SessionLocal() as db:
        user = must_user(request, db)
        values = form.getlist('platforms')
        try:
            selected = save_platforms(db, user.id, values)
        except ValueError as exc:
            flash(request, str(exc), 'error')
            return jump('/sources')
        user.profile.enable_gulf = 'naukrigulf' in selected
        audit(db, user.id, 'sources.platforms', ','.join(sorted(selected)))
        db.commit()
        flash(request, 'Your job platform choices were saved.')
        return jump('/sources')

@app.post('/sources')
async def sources_add(request: Request):
    form = await request.form()
    check_csrf(request, form)
    with SessionLocal() as db:
        user = must_user(request, db)
        kind = str(form.get('kind') or '')
        try:
            slug = safe_slug(str(form.get('slug') or '').strip())
        except ValueError as exc:
            flash(request, str(exc), 'error')
            return jump('/sources')
        if kind not in ('greenhouse', 'lever', 'ashby'):
            raise HTTPException(400, 'Unsupported ATS source')
        db.add(Board(user_id=user.id, kind=kind, slug=slug))
        try:
            db.commit()
            flash(request, 'Employer feed saved; run discovery to import jobs')
        except IntegrityError:
            db.rollback()
            flash(request, 'Source already exists', 'error')
        return jump('/sources')

@app.post('/sources/{board_id}/delete')
async def source_delete(board_id: int, request: Request):
    check_csrf(request, await request.form())
    with SessionLocal() as db:
        user = must_user(request, db)
        board = db.scalar(select(Board).where(Board.id == board_id, Board.user_id == user.id))
        if not board:
            raise HTTPException(404)
        db.delete(board)
        db.commit()
        flash(request, 'Feed removed; imported jobs preserved')
        return jump('/sources')

@app.post('/sources/scan')
async def sources_scan(request: Request):
    check_csrf(request, await request.form())
    with SessionLocal() as db:
        user = must_user(request, db)
        added, errors = scan_boards(db, user, user.profile)
        detail = f' First issue: {errors[0][:180]}' if errors else ''
        flash(request, f'Saved {added} matching jobs. ' + (f'{len(errors)} company feed errors.{detail}' if errors else 'All company feeds checked.'), 'error' if errors else 'success')
        return jump('/sources')

@app.get('/jobs/new', response_class=HTMLResponse)
async def manual_page(request: Request):
    with SessionLocal() as db:
        must_user(request, db)
        return view(request, 'manual.html', db)

@app.post('/jobs/new')
async def manual_add(request: Request):
    form = await request.form()
    check_csrf(request, form)
    with SessionLocal() as db:
        user = must_user(request, db)
        description = str(form.get('description') or '').strip()[:24000]
        payload = {'title': str(form.get('title') or '')[:300],
                   'company': str(form.get('company') or '')[:250],
                   'location': str(form.get('location') or '')[:250],
                   'source': str(form.get('source') or 'manual'),
                   'description': description,
                   'listing_url': str(form.get('listing_url') or ''),
                   'apply_url': str(form.get('apply_url') or form.get('listing_url') or ''),
                   'verified_link': False, 'incomplete': len(description) < 180}
        job, fresh = add_job(db, user.id, payload, user.profile, apply_filter=True)
        if not job:
            flash(request, f'This job needs a company, full description, preferred location and at least a {user.profile.min_evidence_ratio}% local match to your roles and approved experience. Excluded words also block it.', 'error')
            return jump('/jobs/new')
        db.commit()
        flash(request, 'Job imported' if fresh else 'Existing job found; duplicate not created')
        return jump(f'/jobs/{job.id}')

@app.get('/jobs/{job_id}', response_class=HTMLResponse)
async def job_page(job_id: int, request: Request):
    with SessionLocal() as db:
        user = must_user(request, db)
        job = owned_job(db, user, job_id)
        facts = {f['id']: f['text'] for f in json.loads(job.facts_snapshot_json or '[]')}
        requirements = json.loads(job.evidence_json or '[]')
        evidence = sum(bool(x.get('fact_ids')) for x in requirements)
        return view(request, 'job.html', db, job=job, requirements=requirements, facts=facts,
                    missing=json.loads(job.missing_json or '[]'), evidence=evidence)

@app.post('/jobs/{job_id}/edit')
async def job_edit(job_id: int, request: Request):
    form = await request.form()
    check_csrf(request, form)
    with SessionLocal() as db:
        user = must_user(request, db)
        job = owned_job(db, user, job_id)
        if job.submitted_at:
            flash(request, 'This application is already recorded as submitted. Its original vacancy details are locked.', 'error')
            return jump(f'/jobs/{job_id}')
        new_title = str(form.get('title') or '').strip()[:300]
        new_company = str(form.get('company') or '').strip()[:250]
        if not new_title or not new_company:
            flash(request, 'Title and employer are mandatory', 'error')
            return jump(f'/jobs/{job_id}')
        new_loc = str(form.get('location') or '')[:250]
        new_desc = str(form.get('description') or '')[:24000]
        newfp = fingerprint(new_title, new_company, new_loc, job.source_id)
        duplicate = db.scalar(select(Job).where(Job.user_id == user.id, Job.fingerprint == newfp, Job.id != job.id))
        if duplicate:
            flash(request, 'Another job already has this role, company and location', 'error')
            return jump(f'/jobs/{job_id}')
        employer_email = str(form.get('employer_email') or '').strip().lower()
        if employer_email and (len(employer_email) > 254 or not re.fullmatch(r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", employer_email)):
            flash(request, 'Invalid employer email address', 'error')
            return jump(f'/jobs/{job_id}')
        revised = {'title': new_title, 'company': new_company, 'location': new_loc,
                   'description': new_desc}
        if job_relevance(revised, user.profile) < max(1, user.profile.min_evidence_ratio):
            flash(request, 'These job details no longer meet your role, location, skill, description and exclusion rules. Check the posting before saving.', 'error')
            return jump(f'/jobs/{job_id}')
        job.employer_email = employer_email
        job.employer_email_confirmed = bool(employer_email and form.get('email_invited') == 'on')
        changed = any([job.title != new_title, job.company != new_company, job.description != new_desc,
                       job.location != new_loc])
        job.title, job.company, job.location = new_title, new_company, new_loc
        job.description = new_desc
        job.fingerprint = newfp
        job.incomplete = len(new_desc.strip()) < 180
        job.listing_url = clean_url(str(form.get('listing_url') or ''))
        # User-edited links never become trusted, even if they appear to be ATS domains.
        job.apply_url = clean_url(str(form.get('apply_url') or ''))
        job.verified_link = False
        if changed:
            job.status = 'discovered'
            job.pdf_blob = None
            job.prepared_at = None
            job.selected_facts_json = '[]'
            job.facts_snapshot_json = '[]'
            job.evidence_json = '[]'
            job.missing_json = '[]'
            job.explanation = ''
            job.cover_note = ''
            # Keep notification history even if the user edits the listing.
            # Prevent a changed job description from silently triggering duplicate mail.
        db.commit()
        flash(request, 'Job details saved. Edited URLs are unverified; prepare again after any description change.')
        return jump(f'/jobs/{job_id}')

@app.post('/jobs/{job_id}/prepare')
async def job_prepare(job_id: int, request: Request):
    check_csrf(request, await request.form())
    with SessionLocal() as db:
        user = must_user(request, db)
        job = owned_job(db, user, job_id)
        if job.status in ('applied', 'interview', 'offer'):
            flash(request, 'Already applied. Do not regenerate a submitted application.', 'error')
            return jump(f'/jobs/{job_id}')
        try:
            prepare(db, user.profile, user, job)
            audit(db, user.id, 'resume.prepared', job_id=job.id)
            db.commit()
            flash(request, 'Tailored, fact-locked resume generated')
        except Exception as exc:
            db.rollback()
            flash(request, str(exc) if isinstance(exc, (ValueError, AIError)) else 'Preparation failed; check provider/model and logs', 'error')
        return jump(f'/jobs/{job_id}')

@app.get('/jobs/{job_id}/resume.pdf')
async def resume_download(job_id: int, request: Request):
    with SessionLocal() as db:
        user = must_user(request, db)
        job = owned_job(db, user, job_id)
        if not job.pdf_blob:
            raise HTTPException(404, 'Prepare resume first')
        return Response(content=job.pdf_blob, media_type='application/pdf', headers={
            'Content-Disposition': 'attachment; filename="tailored_resume.pdf"',
            'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff'})

@app.post('/jobs/{job_id}/notify')
async def job_notify(job_id: int, request: Request):
    check_csrf(request, await request.form())
    with SessionLocal() as db:
        user = must_user(request, db)
        job = owned_job(db, user, job_id)
        try:
            send_package(db, user.profile, user, job)
            audit(db, user.id, 'package.notified', job_id=job.id)
            db.commit()
            flash(request, 'Package sent to your registered email. This is NOT an employer application.')
        except Exception as exc:
            db.rollback()
            flash(request, str(exc) if isinstance(exc, (ValueError, RuntimeError)) else 'Could not send package', 'error')
        return jump(f'/jobs/{job_id}')

@app.post('/jobs/{job_id}/employer-email')
async def apply_by_email(job_id: int, request: Request):
    """Explicitly confirmed employer email route, no autonomous website submission."""
    form = await request.form()
    check_csrf(request, form)
    if form.get('confirm') != 'yes':
        raise HTTPException(400, 'Explicit approval required')
    with SessionLocal() as db:
        user = must_user(request, db)
        job = owned_job(db, user, job_id)
        try:
            send_employer(db, user.profile, user, job,
                          str(form.get('application_message') or ''))
            audit(db, user.id, 'employer.email_submitted', 'User-approved employer email submission', job_id)
            db.commit()
            flash(request, 'Gmail confirmed your employer email submission. You can track it as applied.')
        except Exception as exc:
            db.rollback()
            flash(request, str(exc) if isinstance(exc, (ValueError, RuntimeError)) else 'Employer email outcome uncertain; check Gmail Sent.', 'error')
        return jump(f'/jobs/{job_id}')

@app.post('/jobs/{job_id}/status')
async def update_status(job_id: int, request: Request):
    form = await request.form()
    check_csrf(request, form)
    with SessionLocal() as db:
        user = must_user(request, db)
        job = owned_job(db, user, job_id)
        status = str(form.get('status') or '')
        if status not in ('discovered', 'ready', 'notified', 'applied', 'interview', 'offer', 'rejected', 'skipped'):
            raise HTTPException(400, 'Invalid status')
        if status in ('ready', 'notified') and not job.pdf_blob:
            flash(request, 'Prepare a resume before marking a job ready', 'error')
            return jump(f'/jobs/{job_id}')
        job.status = status
        if status in ('applied', 'interview', 'offer') and not job.submitted_at:
            job.submitted_at = datetime.utcnow()
        audit(db, user.id, 'job.status', status, job.id)
        db.commit()
        flash(request, 'Application tracking status updated manually; no employer submission occurred')
        return jump(f'/jobs/{job_id}')

@app.get('/gmail/connect')
async def gmail_connect(request: Request):
    with SessionLocal() as db:
        must_user(request, db)
    state = secrets.token_urlsafe(32)
    request.session['gmail_oauth_state'] = state
    try:
        return RedirectResponse(oauth_link(state))
    except ValueError as exc:
        flash(request, str(exc), 'error')
        return jump('/settings')

@app.get('/gmail/callback')
async def gmail_callback(request: Request, state: str = '', code: str = '', error: str = ''):
    expected = request.session.pop('gmail_oauth_state', '')
    if not constant_equal(state, expected) or not code or error:
        flash(request, 'Gmail authorization canceled or state mismatch', 'error')
        return jump('/settings')
    with SessionLocal() as db:
        user = must_user(request, db)
        try:
            creds = exchange_code(code)
            user.profile.gmail_credentials = gmail_encrypt(json.dumps(creds))
            user.profile.gmail_address = connected_address(user.profile)
            audit(db, user.id, 'gmail.connected')
            db.commit()
            flash(request, f'Connected Gmail {user.profile.gmail_address}. Authorized alerts and delivery are now available.')
        except Exception:
            db.rollback()
            flash(request, 'Gmail connection failed. Review Google OAuth test users, redirect URI and permissions.', 'error')
        return jump('/settings')

@app.post('/gmail/disconnect')
async def gmail_disconnect(request: Request):
    check_csrf(request, await request.form())
    with SessionLocal() as db:
        user = must_user(request, db)
        user.profile.gmail_credentials = ''
        user.profile.gmail_address = ''
        user.profile.auto_process = False
        audit(db, user.id, 'gmail.disconnected')
        db.commit()
        flash(request, 'Gmail connection removed locally. Revoke the app in your Google account to revoke authorization.')
        return jump('/settings')

@app.post('/gmail/import')
async def gmail_import(request: Request):
    check_csrf(request, await request.form())
    with SessionLocal() as db:
        user = must_user(request, db)
        if not user.profile.gmail_credentials:
            flash(request, 'Connect Gmail first', 'error')
            return jump('/sources')
        try:
            count, errors = import_alerts(db, user, user.profile)
            flash(request, f'Imported {count} new alert links; {len(errors)} message errors. Incomplete alerts require a full job description.')
        except Exception:
            flash(request, 'Gmail import failed. Check permissions and alert filters.', 'error')
        return jump('/sources')

@app.post('/gmail/refresh-details')
async def gmail_refresh_details(request: Request):
    check_csrf(request, await request.form())
    with SessionLocal() as db:
        user = must_user(request, db)
        if not user.profile.gmail_credentials:
            flash(request, 'Connect Gmail to refresh alert details.', 'error')
            return jump('/sources')
        try:
            count, errors = import_alerts(db, user, user.profile, refresh_existing=True)
            flash(request, f'Updated or added {count} job records from recent alerts. {len(errors)} messages could not be read. Full descriptions may still need to be copied from the original posting.', 'error' if errors else 'success')
        except Exception:
            flash(request, 'Could not refresh alerts. Check your Gmail connection.', 'error')
        return jump('/sources')

@app.post('/pipeline/run')
async def manual_pipeline(request: Request):
    check_csrf(request, await request.form())
    with SessionLocal() as db:
        user = must_user(request, db)
        result = process_user(db, user)
        detail = f" First issue: {result['issues'][0][:180]}" if result['issues'] else ''
        flash(request, f"Found or updated {result['new']} jobs; prepared {result['prepared']} resumes; emailed {result['notified']} packages to you. {len(result['issues'])} issues.{detail}", 'error' if result['issues'] else 'success')
        return jump('/')

@app.post('/api/cron/daily')
async def cron_daily(request: Request):
    if not config.ENABLE_CRON or not constant_equal(request.headers.get('X-Cron-Token', ''), config.CRON_TOKEN):
        raise HTTPException(403, 'Not permitted')
    with SessionLocal() as db:
        return JSONResponse({'results': cron_users(db)}, headers={'Cache-Control': 'no-store'})

@app.get('/export/jobs.csv')
async def jobs_csv(request: Request):
    import csv
    import io
    with SessionLocal() as db:
        user = must_user(request, db)
        records = db.scalars(select(Job).where(Job.user_id == user.id, known_company_clause()).order_by(Job.created_at.desc())).all()
        stream = io.StringIO()
        writer = csv.writer(stream)
        writer.writerow(['title', 'company', 'location', 'source', 'status', 'apply_url', 'verified_link', 'created_at'])
        for j in records:
            writer.writerow([j.title, j.company, j.location, j.source, j.status, j.apply_url,
                             j.verified_link, j.created_at.isoformat() if j.created_at else ''])
        return Response(stream.getvalue(), media_type='text/csv; charset=utf-8',
                        headers={'Content-Disposition': 'attachment; filename="job-tracker.csv"',
                                 'Cache-Control': 'private, no-store'})
