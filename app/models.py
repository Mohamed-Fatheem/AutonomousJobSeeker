from datetime import datetime, timezone
from sqlalchemy import create_engine, String, Text, DateTime, Integer, Boolean, LargeBinary, ForeignKey, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from .config import DB_URL


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

engine = create_engine(
    DB_URL,
    connect_args={'check_same_thread': False} if DB_URL.startswith('sqlite') else {},
    pool_pre_ping=True,
    pool_size=3 if not DB_URL.startswith('sqlite') else 5,
    max_overflow=2,
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    profile: Mapped['Profile'] = relationship(back_populates='user', uselist=False, cascade='all, delete-orphan')

class Profile(Base):
    __tablename__ = 'profiles'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), unique=True, index=True)
    user: Mapped[User] = relationship(back_populates='profile')
    full_name: Mapped[str] = mapped_column(String(200), default='')
    phone: Mapped[str] = mapped_column(String(90), default='')
    location: Mapped[str] = mapped_column(String(150), default='')
    headline: Mapped[str] = mapped_column(String(300), default='')
    summary: Mapped[str] = mapped_column(Text, default='')
    master_resume: Mapped[str] = mapped_column(Text, default='')
    facts_json: Mapped[str] = mapped_column(Text, default='[]')
    search_terms: Mapped[str] = mapped_column(String(500), default='Python, Backend, AI')
    preferred_locations: Mapped[str] = mapped_column(String(500), default='Remote, India')
    excluded_terms: Mapped[str] = mapped_column(String(500), default='')
    min_evidence_ratio: Mapped[int] = mapped_column(Integer, default=60)
    provider: Mapped[str] = mapped_column(String(20), default='gemini')
    model_name: Mapped[str] = mapped_column(String(100), default='gemini-2.5-flash')
    encrypted_api_key: Mapped[str] = mapped_column(Text, default='')
    gmail_credentials: Mapped[str] = mapped_column(Text, default='')
    gmail_address: Mapped[str] = mapped_column(String(255), default='')
    gmail_query: Mapped[str] = mapped_column(String(500), default='newer_than:14d {from:linkedin.com from:indeed.com from:naukri.com from:naukrigulf.com}')
    enable_gulf: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_process: Mapped[bool] = mapped_column(Boolean, default=False)
    daily_limit: Mapped[int] = mapped_column(Integer, default=3)

class Board(Base):
    __tablename__ = 'boards'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    kind: Mapped[str] = mapped_column(String(15))
    slug: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint('user_id', 'kind', 'slug'),)

class SourcePreferences(Base):
    __tablename__ = 'source_preferences'
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), primary_key=True)
    platforms_json: Mapped[str] = mapped_column(Text, default='[]')

class Job(Base):
    __tablename__ = 'jobs'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(30), default='manual')
    source_id: Mapped[str] = mapped_column(String(160), default='')
    title: Mapped[str] = mapped_column(String(300))
    company: Mapped[str] = mapped_column(String(250))
    location: Mapped[str] = mapped_column(String(250), default='')
    description: Mapped[str] = mapped_column(Text, default='')
    listing_url: Mapped[str] = mapped_column(Text, default='')
    apply_url: Mapped[str] = mapped_column(Text, default='')
    verified_link: Mapped[bool] = mapped_column(Boolean, default=False)
    employer_email: Mapped[str] = mapped_column(String(254), default='')
    employer_email_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    employer_email_attempted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    employer_email_sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    incomplete: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(30), default='discovered')
    selected_facts_json: Mapped[str] = mapped_column(Text, default='[]')
    facts_snapshot_json: Mapped[str] = mapped_column(Text, default='[]')
    evidence_json: Mapped[str] = mapped_column(Text, default='[]')
    missing_json: Mapped[str] = mapped_column(Text, default='[]')
    explanation: Mapped[str] = mapped_column(Text, default='')
    cover_note: Mapped[str] = mapped_column(Text, default='')
    pdf_blob: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    prepared_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    notified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    notification_attempted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    __table_args__ = (UniqueConstraint('user_id', 'fingerprint'),)

class ImportedMessage(Base):
    __tablename__ = 'imported_messages'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    message_id: Mapped[str] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint('user_id', 'message_id'),)

class RunLog(Base):
    __tablename__ = 'run_logs'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    day: Mapped[str] = mapped_column(String(10))
    status: Mapped[str] = mapped_column(String(20), default='running')
    summary: Mapped[str] = mapped_column(Text, default='')
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    __table_args__ = (UniqueConstraint('user_id', 'day'),)

class Audit(Base):
    __tablename__ = 'audits'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[str] = mapped_column(Text, default='')
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
