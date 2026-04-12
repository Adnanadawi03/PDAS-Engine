from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, JSON
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

# إنشاء الجداول لو مش موجودة
def init_db():
    Base.metadata.create_all(bind=engine)
