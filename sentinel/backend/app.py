"""
app.py — Sentinel FastAPI Backend
==================================
All API endpoints for the DoS Attack Detection dashboard.

Start server:
    uvicorn app:app --reload --port 8000
"""

import io
import json
import os
import random
import asyncio
from datetime import datetime, timedelta
from typing import Optional, List

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, Depends, File, UploadFile, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, case
from sqlalchemy.orm import Session

from preprocessing import (
    record_to_df, ALL_FEATURES,
    PROTOCOLS, SERVICES, FLAGS,
    FEATURE_DEFAULTS,
)
from db import init_db, get_db, SessionLocal, Prediction, DB_PATH

# ── Startup ───────────────────────────────────────────────────────────────────
BASE     = os.path.dirname(os.path.abspath(__file__))
PKL_PATH = os.path.join(BASE, "model.pkl")

if not os.path.exists(PKL_PATH):
    raise RuntimeError(
        "model.pkl not found. Run:  python train_model.py  first."
    )

artifact  = joblib.load(PKL_PATH)
pipeline  = artifact["pipeline"]
THRESHOLD = artifact["threshold"]

app = FastAPI(
    title="Sentinel — DoS Detection API",
    description="Real-time DoS attack detection via NSL-KDD Logistic Regression.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class TrafficRecord(BaseModel):
    protocol_type:          str   = Field("tcp",   description="tcp | udp | icmp")
    service:                str   = Field("http",  description="NSL-KDD service label")
    flag:                   str   = Field("SF",    description="Connection flag")
    src_bytes:              float = Field(0.0,     ge=0)
    dst_bytes:              float = Field(0.0,     ge=0)
    duration:               float = Field(0.0,     ge=0)
    land:                   int   = Field(0,       ge=0, le=1)
    wrong_fragment:         int   = Field(0,       ge=0)
    urgent:                 int   = Field(0,       ge=0)
    count:                  float = Field(1.0,     ge=0, le=511)
    srv_count:              float = Field(1.0,     ge=0, le=511)
    serror_rate:            float = Field(0.0,     ge=0, le=1)
    srv_serror_rate:        float = Field(0.0,     ge=0, le=1)
    rerror_rate:            float = Field(0.0,     ge=0, le=1)
    same_srv_rate:          float = Field(1.0,     ge=0, le=1)
    diff_srv_rate:          float = Field(0.0,     ge=0, le=1)
    srv_diff_host_rate:     float = Field(0.0,     ge=0, le=1)
    dst_host_count:         float = Field(100.0,   ge=0, le=255)
    dst_host_srv_count:     float = Field(100.0,   ge=0, le=255)
    dst_host_same_srv_rate: float = Field(0.5,     ge=0, le=1)
    dst_host_serror_rate:   float = Field(0.0,     ge=0, le=1)
    logged_in:              float = Field(0.0,     ge=0, le=1)


class PredictionOut(BaseModel):
    id:            int
    timestamp:     str
    label:         str
    confidence:    float
    probability:   float
    protocol_type: str
    service:       str
    flag:          str
    src_bytes:     float
    dst_bytes:     float


# ── Helpers ───────────────────────────────────────────────────────────────────

def _predict_record(record: dict) -> dict:
    """Run a single record through the pipeline and return result dict."""
    df   = record_to_df(record)
    prob = float(pipeline.predict_proba(df)[0][1])
    label      = "DoS Attack" if prob >= THRESHOLD else "Normal"
    confidence = prob if label == "DoS Attack" else 1.0 - prob
    return {"label": label, "confidence": round(confidence, 4), "probability": round(prob, 4)}


def _save_prediction(db: Session, record: dict, result: dict, source: str = "manual") -> Prediction:
    pred = Prediction(
        protocol_type  = str(record.get("protocol_type", "tcp")),
        service        = str(record.get("service", "http")),
        flag           = str(record.get("flag", "SF")),
        src_bytes      = float(record.get("src_bytes", 0)),
        dst_bytes      = float(record.get("dst_bytes", 0)),
        duration       = float(record.get("duration", 0)),
        count          = int(record.get("count", 1)),
        serror_rate    = float(record.get("serror_rate", 0)),
        same_srv_rate  = float(record.get("same_srv_rate", 1)),
        label          = result["label"],
        confidence     = result["confidence"],
        raw_probability= result["probability"],
        source         = source,
    )
    db.add(pred)
    db.commit()
    db.refresh(pred)
    return pred


def _random_traffic_record(attack: bool = False) -> dict:
    """Generate a synthetic traffic record for simulation."""
    rng = random.Random()
    if not attack:
        return {
            "protocol_type":          rng.choice(["tcp", "tcp", "tcp", "udp", "icmp"]),
            "service":                rng.choice(["http", "ftp_data", "smtp", "ssh", "auth", "other"]),
            "flag":                   rng.choice(["SF", "SF", "SF", "REJ"]),
            "src_bytes":              rng.expovariate(1 / 3000),
            "dst_bytes":              rng.expovariate(1 / 5000),
            "duration":               rng.expovariate(1 / 30),
            "land":                   0,
            "wrong_fragment":         0,
            "urgent":                 0,
            "count":                  rng.randint(1, 50),
            "srv_count":              rng.randint(1, 50),
            "serror_rate":            max(0.0, rng.gauss(0.01, 0.02)),
            "srv_serror_rate":        max(0.0, rng.gauss(0.01, 0.02)),
            "rerror_rate":            max(0.0, rng.gauss(0.0, 0.01)),
            "same_srv_rate":          min(1.0, max(0.0, rng.gauss(0.85, 0.1))),
            "diff_srv_rate":          min(1.0, max(0.0, rng.gauss(0.05, 0.05))),
            "srv_diff_host_rate":     min(1.0, max(0.0, rng.gauss(0.1, 0.05))),
            "dst_host_count":         rng.randint(50, 255),
            "dst_host_srv_count":     rng.randint(30, 255),
            "dst_host_same_srv_rate": min(1.0, max(0.0, rng.gauss(0.8, 0.1))),
            "dst_host_serror_rate":   max(0.0, rng.gauss(0.01, 0.02)),
            "logged_in":              rng.choice([0.0, 1.0]),
        }
    else:
        attack_type = rng.choice(["neptune", "smurf", "teardrop", "back"])
        if attack_type == "neptune":
            return {
                "protocol_type": "tcp", "service": rng.choice(["http", "private"]),
                "flag": "S0", "src_bytes": 0.0, "dst_bytes": 0.0, "duration": 0.0,
                "land": 0, "wrong_fragment": 0, "urgent": 0,
                "count": 511.0, "srv_count": 511.0,
                "serror_rate": 1.0, "srv_serror_rate": 1.0, "rerror_rate": 0.0,
                "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
                "dst_host_count": 255.0, "dst_host_srv_count": 255.0,
                "dst_host_same_srv_rate": 1.0, "dst_host_serror_rate": 1.0, "logged_in": 0.0,
            }
        elif attack_type == "smurf":
            sz = rng.choice([936.0, 1032.0])
            return {
                "protocol_type": "icmp", "service": "ecr_i", "flag": "SF",
                "src_bytes": sz, "dst_bytes": sz, "duration": 0.0,
                "land": 0, "wrong_fragment": 0, "urgent": 0,
                "count": 511.0, "srv_count": 511.0,
                "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
                "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
                "dst_host_count": 255.0, "dst_host_srv_count": 255.0,
                "dst_host_same_srv_rate": 1.0, "dst_host_serror_rate": 0.0, "logged_in": 0.0,
            }
        elif attack_type == "teardrop":
            return {
                "protocol_type": "udp", "service": "private", "flag": "SF",
                "src_bytes": float(rng.randint(20, 100)), "dst_bytes": 0.0, "duration": 0.0,
                "land": 0, "wrong_fragment": rng.randint(1, 3), "urgent": 0,
                "count": float(rng.randint(1, 10)), "srv_count": float(rng.randint(1, 10)),
                "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
                "same_srv_rate": 0.9, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
                "dst_host_count": float(rng.randint(1, 30)), "dst_host_srv_count": float(rng.randint(1, 20)),
                "dst_host_same_srv_rate": 0.8, "dst_host_serror_rate": 0.0, "logged_in": 0.0,
            }
        else:  # back
            return {
                "protocol_type": "tcp", "service": "http", "flag": "SF",
                "src_bytes": float(rng.randint(100, 500)),
                "dst_bytes": float(rng.randint(50000, 100000)),
                "duration": rng.random() * 2,
                "land": 0, "wrong_fragment": 0, "urgent": 0,
                "count": float(rng.randint(1, 20)), "srv_count": float(rng.randint(1, 20)),
                "serror_rate": 0.02, "srv_serror_rate": 0.02, "rerror_rate": 0.0,
                "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
                "dst_host_count": float(rng.randint(100, 255)),
                "dst_host_srv_count": float(rng.randint(100, 255)),
                "dst_host_same_srv_rate": 1.0, "dst_host_serror_rate": 0.01, "logged_in": 1.0,
            }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
def health():
    return {"status": "ok", "threshold": THRESHOLD, "timestamp": datetime.utcnow().isoformat()}


@app.post("/predict", tags=["Prediction"])
def predict(record: TrafficRecord, db: Session = Depends(get_db)):
    rec_dict = record.model_dump()
    result   = _predict_record(rec_dict)
    pred     = _save_prediction(db, rec_dict, result, source="manual")
    return {
        "id":            pred.id,
        "timestamp":     pred.timestamp.isoformat(),
        "label":         result["label"],
        "confidence":    result["confidence"],
        "probability":   result["probability"],
        "protocol_type": record.protocol_type,
        "service":       record.service,
        "flag":          record.flag,
        "src_bytes":     record.src_bytes,
        "dst_bytes":     record.dst_bytes,
    }


@app.post("/batch", tags=["Batch"])
async def batch_predict(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files accepted.")
    contents = await file.read()
    try:
        df = pd.read_csv(io.StringIO(contents.decode("utf-8")))
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"CSV parse error: {e}")

    results = []
    for _, row in df.iterrows():
        rec = {col: row[col] for col in ALL_FEATURES if col in df.columns}
        # Fill missing with defaults
        for k, v in FEATURE_DEFAULTS.items():
            rec.setdefault(k, v)
        try:
            res  = _predict_record(rec)
            pred = _save_prediction(db, rec, res, source="batch")
            results.append({
                "row_id":        int(_ + 1),
                "protocol_type": rec.get("protocol_type", "?"),
                "service":       rec.get("service", "?"),
                "flag":          rec.get("flag", "?"),
                "src_bytes":     float(rec.get("src_bytes", 0)),
                "dst_bytes":     float(rec.get("dst_bytes", 0)),
                "label":         res["label"],
                "confidence":    res["confidence"],
                "probability":   res["probability"],
                "timestamp":     pred.timestamp.isoformat(),
            })
        except Exception as e:
            results.append({"row_id": int(_ + 1), "error": str(e)})

    total   = len(results)
    n_dos   = sum(1 for r in results if r.get("label") == "DoS Attack")
    n_norm  = total - n_dos
    return {
        "total":   total,
        "normal":  n_norm,
        "dos":     n_dos,
        "rate":    round(n_dos / max(total, 1) * 100, 2),
        "results": results,
    }


@app.get("/simulate/stream", tags=["Simulation"])
async def simulate_stream(
    speed: float = Query(1.0,  ge=0.1, le=10.0),
    count: int   = Query(200,  ge=1,   le=2000),
    attack_rate: float = Query(0.3, ge=0.0, le=1.0),
):
    """
    Server-Sent Events stream — emits one network record per interval.
    speed      : records per second (0.1 – 10)
    count      : total records to emit
    attack_rate: fraction that are attack records (0 – 1)
    """
    async def generate():
        db = SessionLocal()
        delay = 1.0 / speed
        try:
            for i in range(count):
                is_attack = random.random() < attack_rate
                rec   = _random_traffic_record(attack=is_attack)
                result= _predict_record(rec)
                pred  = _save_prediction(db, rec, result, source="simulation")
                payload = json.dumps({
                    "id":           pred.id,
                    "seq":          i + 1,
                    "timestamp":    pred.timestamp.isoformat(),
                    "label":        result["label"],
                    "confidence":   result["confidence"],
                    "probability":  result["probability"],
                    "protocol_type": rec["protocol_type"],
                    "service":      rec["service"],
                    "flag":         rec["flag"],
                    "src_bytes":    round(rec["src_bytes"], 0),
                    "dst_bytes":    round(rec["dst_bytes"], 0),
                    "count":        rec["count"],
                    "serror_rate":  round(rec["serror_rate"], 3),
                })
                yield f"data: {payload}\n\n"
                await asyncio.sleep(delay)
            yield 'data: {"done": true}\n\n'
        finally:
            db.close()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":  "no-cache",
            "Connection":     "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/stats", tags=["Analytics"])
def get_stats(db: Session = Depends(get_db)):
    total  = db.query(func.count(Prediction.id)).scalar() or 0
    dos    = db.query(func.count(Prediction.id)).filter(Prediction.label == "DoS Attack").scalar() or 0
    normal = total - dos
    rate   = round(dos / max(total, 1) * 100, 2)
    recent = (
        db.query(Prediction)
        .order_by(Prediction.timestamp.desc())
        .limit(1)
        .first()
    )
    return {
        "total":        total,
        "normal":       normal,
        "dos":          dos,
        "alert_rate":   rate,
        "last_updated": recent.timestamp.isoformat() if recent else None,
    }


@app.get("/database/info", tags=["Database"])
def get_database_info(db: Session = Depends(get_db)):
    total  = db.query(func.count(Prediction.id)).scalar() or 0
    dos    = db.query(func.count(Prediction.id)).filter(Prediction.label == "DoS Attack").scalar() or 0
    normal = total - dos
    first  = db.query(Prediction).order_by(Prediction.timestamp.asc()).first()
    latest = db.query(Prediction).order_by(Prediction.timestamp.desc()).first()

    by_source = (
        db.query(Prediction.source, func.count(Prediction.id))
        .group_by(Prediction.source)
        .all()
    )
    by_protocol = (
        db.query(Prediction.protocol_type, func.count(Prediction.id))
        .group_by(Prediction.protocol_type)
        .all()
    )

    return {
        "engine": "SQLite",
        "database_path": DB_PATH,
        "table": Prediction.__tablename__,
        "total_records": total,
        "normal_records": normal,
        "dos_records": dos,
        "first_record_at": first.timestamp.isoformat() if first else None,
        "latest_record_at": latest.timestamp.isoformat() if latest else None,
        "source_counts": [{"source": source, "count": count} for source, count in by_source],
        "protocol_counts": [{"protocol": protocol, "count": count} for protocol, count in by_protocol],
    }


@app.get("/history", tags=["Analytics"])
def get_history(
    db:       Session = Depends(get_db),
    limit:    int     = Query(50,   ge=1, le=500),
    offset:   int     = Query(0,    ge=0),
    label:    Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    source:   Optional[str] = Query(None),
    since:    Optional[str] = Query(None),
):
    q = db.query(Prediction).order_by(Prediction.timestamp.desc())
    if label:    q = q.filter(Prediction.label    == label)
    if protocol: q = q.filter(Prediction.protocol_type == protocol)
    if source:   q = q.filter(Prediction.source   == source)
    if since:
        try:
            dt = datetime.fromisoformat(since)
            q  = q.filter(Prediction.timestamp >= dt)
        except ValueError:
            pass

    total   = q.count()
    records = q.offset(offset).limit(limit).all()
    return {
        "total":   total,
        "offset":  offset,
        "limit":   limit,
        "records": [
            {
                "id":            r.id,
                "timestamp":     r.timestamp.isoformat(),
                "protocol_type": r.protocol_type,
                "service":       r.service,
                "flag":          r.flag,
                "src_bytes":     r.src_bytes,
                "dst_bytes":     r.dst_bytes,
                "label":         r.label,
                "confidence":    r.confidence,
                "source":        r.source,
            }
            for r in records
        ],
    }


@app.get("/analytics", tags=["Analytics"])
def get_analytics(
    db:     Session = Depends(get_db),
    period: str     = Query("week", regex="^(day|week|month)$"),
):
    now = datetime.utcnow()
    if period == "day":
        since  = now - timedelta(hours=24)
    elif period == "month":
        since  = now - timedelta(days=30)
    else:
        since  = now - timedelta(days=7)

    records = (
        db.query(Prediction)
        .filter(Prediction.timestamp >= since)
        .order_by(Prediction.timestamp)
        .all()
    )

    # ── Time-series ───────────────────────────────────────────────────────────
    bucket_fmt = "%Y-%m-%dT%H:00" if period == "day" else "%Y-%m-%d"
    ts: dict   = {}
    for r in records:
        key = r.timestamp.strftime(bucket_fmt)
        if key not in ts:
            ts[key] = {"time": key, "normal": 0, "dos": 0}
        if r.label == "Normal":
            ts[key]["normal"] += 1
        else:
            ts[key]["dos"]    += 1
    time_series = sorted(ts.values(), key=lambda x: x["time"])

    # ── Protocol breakdown ───────────────────────────────────────────────────
    proto: dict = {}
    for r in records:
        p = r.protocol_type
        if p not in proto:
            proto[p] = {"protocol": p, "normal": 0, "dos": 0, "total": 0}
        proto[p]["total"] += 1
        if r.label == "Normal":
            proto[p]["normal"] += 1
        else:
            proto[p]["dos"]    += 1
    protocol_breakdown = list(proto.values())

    # ── Source breakdown ─────────────────────────────────────────────────────
    source: dict = {}
    for r in records:
        s = r.source
        source[s] = source.get(s, 0) + 1

    return {
        "period":             period,
        "since":              since.isoformat(),
        "total":              len(records),
        "time_series":        time_series,
        "protocol_breakdown": protocol_breakdown,
        "source_breakdown":   [{"source": k, "count": v} for k, v in source.items()],
    }
