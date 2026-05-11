# MITRE Incident Mapper - Backend API

Flask REST API for MITRE ATT&CK incident analysis. Deployed on Railway.app.

## 🚀 Live API

- **Production:** `https://mitre-mapper-api.up.railway.app`
- **Health Check:** `https://mitre-mapper-api.up.railway.app/api/health`

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | API info |
| GET | `/api/health` | Health check |
| POST | `/api/analyze` | Upload & analyze log file |
| GET | `/api/incident/<id>` | Get incident details |
| GET | `/api/download/<id>/<format>` | Download report (pdf/json/csv) |

## 🛠️ Local Development

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
# → http://localhost:5000
```

## 🚂 Deploy to Railway

1. Push to GitHub
2. Go to https://railway.app
3. New Project → Deploy from GitHub
4. Select repo → Set root directory to `/backend`
5. Generate domain in Settings → Networking

## 🧪 Test API

```bash
# Health check
curl https://your-api.up.railway.app/api/health

# Upload log
curl -X POST https://your-api.up.railway.app/api/analyze \
  -F "file=@data/sample_logs/incident_1.csv"
```

## 📦 Tech Stack

- Python 3.11
- Flask 2.3 + Flask-CORS
- Gunicorn (production WSGI)
- ReportLab (PDF generation)

## 🔗 Frontend

Frontend deployed separately on Vercel: https://mitre-incident-mapper.vercel.app
