"""
db.py — SQLAlchemy Database Setup
==================================
SQLite database for logging predictions.
Exposes: engine, SessionLocal, Base, Prediction model, get_db dependency.
"""

import os
from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, Float, String, DateTime, Index
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from typing import Generator

# ── Database location ─────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, "sentinel.db")
DB_URL     = f"sqlite:///{DB_PATH}"

engine         = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal   = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base           = declarative_base()


# ── ORM Model ─────────────────────────────────────────────────────────────────
class Prediction(Base):
    __tablename__ = "predictions"

    id                   = Column(Integer,  primary_key=True, index=True)
    timestamp            = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Key NSL-KDD features stored for analytics
    protocol_type        = Column(String(10),  nullable=False)
    service              = Column(String(30),  nullable=False)
    flag                 = Column(String(15),  nullable=False)
    src_bytes            = Column(Float,        default=0.0)
    dst_bytes            = Column(Float,        default=0.0)
    duration             = Column(Float,        default=0.0)
    count                = Column(Integer,      default=1)
    serror_rate          = Column(Float,        default=0.0)
    same_srv_rate        = Column(Float,        default=1.0)

    # Prediction output
    label                = Column(String(20),  nullable=False)   # "Normal" | "DoS Attack"
    confidence           = Column(Float,        nullable=False)   # 0.0 – 1.0
    raw_probability      = Column(Float,        nullable=False)   # probability of DoS class

    # Metadata
    source               = Column(String(20),  default="manual")  # manual | batch | simulation

    __table_args__ = (
        Index("ix_pred_timestamp", "timestamp"),
        Index("ix_pred_label",     "label"),
        Index("ix_pred_source",    "source"),
    )


# ── FastAPI dependency ────────────────────────────────────────────────────────
def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables (idempotent)."""
    Base.metadata.create_all(bind=engine)
