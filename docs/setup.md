# Setup

## Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r ..\requirements.txt
uvicorn main:app --reload
```

Backend URL:

```text
http://localhost:8000
```

## Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend URL:

```text
http://localhost:5173
```

## Useful API Routes

- `GET /samples`
- `GET /analyze-sample/{filename}`
- `GET /monitoring/live`
- `POST /upload`
- `GET /detect/{filename}`
