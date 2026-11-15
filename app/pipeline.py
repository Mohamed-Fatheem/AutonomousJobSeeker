"""Bounded cron orchestration with once-per-day per-account lock."""
import json
from datetime import datetime, timedelta
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from .models import User, Profile, Job, RunLog, Audit, utcnow
from .discovery import scan_boards, job_relevance, known_company_clause
from .gmail import import_alerts, send_package
from .ai import prepare


def process_user(db, user, *, do_prepare=True):
    profile = user.profile
    added, issues = scan_boards(db, user, profile)
    if profile.gmail_credentials:
        try:
            n, errors = import_alerts(db, user, profile)
            added += n
            issues.extend(errors)
        except Exception as exc:
            issues.append('Gmail alert import failed: ' + type(exc).__name__)
    prepared = notified = 0
    if do_prepare and profile.auto_process and profile.encrypted_api_key:
        today = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        used = len(db.scalars(select(Job).where(Job.user_id == user.id,
                                                     Job.prepared_at >= today)).all())
        remaining = max(0, min(10, profile.daily_limit) - used)
        candidates = db.scalars(select(Job).where(Job.user_id == user.id, Job.incomplete.is_(False),
                                                  Job.prepared_at.is_(None), Job.status == 'discovered',
                                                  known_company_clause())
                                .order_by(Job.created_at.desc()).limit(80)).all()
        candidates.sort(key=lambda j: job_relevance({'title': j.title, 'description': j.description}, profile), reverse=True)
        for job in candidates[:remaining]:
            try:
                result = prepare(db, profile, user, job)
                prepared += 1
                if result['evidence_ratio'] >= profile.min_evidence_ratio and profile.gmail_credentials:
                    try:
                        send_package(db, profile, user, job)
                        notified += 1
                    except Exception as exc:
                        issues.append(f'Job {job.id} package notification: {type(exc).__name__}')
            except Exception as exc:
                db.rollback()
                issues.append(f'Job {job.id} preparation: {type(exc).__name__}')
    summary = {'new': added, 'prepared': prepared, 'notified': notified, 'issues': issues[:20]}
    db.add(Audit(user_id=user.id, action='pipeline.run', detail=json.dumps(summary)))
    db.commit()
    return summary


def cron_users(db):
    results = []
    day = utcnow().date().isoformat()
    ids = db.scalars(select(User.id).join(Profile).where(Profile.auto_process.is_(True))).all()
    for uid in ids[:40]:
        # DB unique constraint makes repeated GitHub executions idempotent for this day.
        try:
            record = RunLog(user_id=uid, day=day, status='running')
            db.add(record)
            db.commit()
        except IntegrityError:
            db.rollback()
            continue
        try:
            user = db.get(User, uid)
            summary = process_user(db, user)
            record.status = 'completed'
            record.summary = json.dumps(summary)
            results.append({'user_id': uid, **summary})
        except Exception as exc:
            db.rollback()
            record = db.scalar(select(RunLog).where(RunLog.user_id == uid, RunLog.day == day))
            if record:
                record.status = 'failed'
                record.summary = type(exc).__name__
            results.append({'user_id': uid, 'status': 'failed'})
        finally:
            record = db.scalar(select(RunLog).where(RunLog.user_id == uid, RunLog.day == day))
            if record:
                record.finished_at = utcnow()
            db.commit()
    return results
