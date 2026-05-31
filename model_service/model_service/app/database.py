from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, JSON, text
from sqlalchemy.orm import sessionmaker, declarative_base
import datetime

DATABASE_URL = "sqlite:///./pdas_logs.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ScanEvent(Base):
    __tablename__ = "scan_events"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String, index=True)           # "url" أو "file"
    target = Column(String)                     # الرابط أو اسم الملف
    verdict = Column(String)                    # allow / warn / block
    score = Column(Float)
    signals = Column(JSON)                      # تفاصيل إضافية (features, rules)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

EXPECTED_SCAN_EVENT_COLUMNS = {
    "id",
    "type",
    "target",
    "verdict",
    "score",
    "signals",
    "timestamp",
}


def _table_exists(conn, table_name: str) -> bool:
    row = conn.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name=:table_name"),
        {"table_name": table_name},
    ).fetchone()
    return row is not None


def _get_table_columns(conn, table_name: str) -> list[str]:
    rows = conn.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
    return [row[1] for row in rows]


def _migrate_legacy_scan_events(conn) -> None:
    backup_name = f"scan_events_legacy_{datetime.datetime.utcnow():%Y%m%d%H%M%S}"
    conn.execute(text(f"ALTER TABLE scan_events RENAME TO {backup_name}"))
    ScanEvent.__table__.create(bind=conn)
    conn.execute(
        text(
            f"""
            INSERT INTO scan_events (id, type, target, verdict, score, signals, timestamp)
            SELECT
                id,
                COALESCE(event_type, 'unknown'),
                target,
                verdict,
                score,
                signals,
                timestamp
            FROM {backup_name}
            """
        )
    )


# إنشاء الجداول لو مش موجودة مع ترحيل بسيط للنسخة القديمة
def init_db():
    with engine.begin() as conn:
        if not _table_exists(conn, "scan_events"):
            Base.metadata.create_all(bind=conn)
            return

        existing_columns = set(_get_table_columns(conn, "scan_events"))
        if EXPECTED_SCAN_EVENT_COLUMNS.issubset(existing_columns):
            Base.metadata.create_all(bind=conn)
            return

        if "event_type" in existing_columns and "type" not in existing_columns:
            _migrate_legacy_scan_events(conn)
            return

        # لو الـ schema غير متوقعة، احتفظ بالجدول القديم وأنشئ جدولاً جديداً نظيفاً.
        backup_name = f"scan_events_backup_{datetime.datetime.utcnow():%Y%m%d%H%M%S}"
        conn.execute(text(f"ALTER TABLE scan_events RENAME TO {backup_name}"))
        ScanEvent.__table__.create(bind=conn)
