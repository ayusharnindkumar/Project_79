# Sentinel Command Center

Production-style DoS attack detection dashboard for the NSL-KDD Logistic Regression model.

## Architecture

- `backend/` is the Python source of truth. It loads `model.pkl`, preserves the preprocessing pipeline and tuned threshold, logs predictions to SQLite, and exposes FastAPI endpoints.
- `frontend/` is the React + Tailwind security dashboard. It uses the Vite `/api` proxy to call the backend without changing prediction logic.

## Local Run

### 1. Backend

```bash
cd sentinel/backend
python3 -m pip install -r requirements.txt
python3 train_model.py
python3 -m uvicorn app:app --port 8000
```

The API runs at `http://127.0.0.1:8000`.

### 2. Frontend

```bash
cd sentinel/frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

Open `http://127.0.0.1:5173`.

## Features

- Overview dashboard with live summary cards, threat level, traffic chart, and recent predictions.
- Single record prediction form with NSL-KDD presets and animated verdict display.
- CSV batch upload with drag-and-drop, progress state, chart summary, table filters, and CSV export.
- Real-time simulation via Server-Sent Events from `/simulate/stream`.
- History and analytics using `/history` and `/analytics` with filters, charts, and searchable logs.
- Database console for viewing SQLite status, source/protocol counts, stored rows, filters, and CSV export.

## API Endpoints

- `GET /health`
- `POST /predict`
- `POST /batch`
- `GET /simulate/stream`
- `GET /stats`
- `GET /history`
- `GET /analytics`
- `GET /database/info`

## Production Build

```bash
cd sentinel/frontend
npm run build
```

Deploy `frontend/dist` to a static host and deploy `backend` to a Python host that supports FastAPI/uvicorn. Set the frontend proxy or reverse proxy so `/api/*` routes to the backend.

## Notes

- Do not edit `preprocessing.py`, model threshold values, or prediction logic unless retraining intentionally.
- SQLite logs are stored in `backend/sentinel.db`.
- The Database page reads from SQLite through the API and exports visible rows as CSV.
- If `model.pkl` is missing, run `python3 train_model.py` once before starting the API.
