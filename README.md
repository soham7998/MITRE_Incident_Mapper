# MITRE Incident Mapper

Upload a security log, get a MITRE ATT&CK-mapped incident timeline back in seconds. Built for SOC analysts and incident responders who need to move fast.

**Live:** https://mitre-incident-mapper.vercel.app  
**API Docs:** https://mitre-incident-mapper.vercel.app/docs  
**API:** https://mitreincident-product.up.railway.app

---

## What it does

Drop in a `.csv`, `.json`, `.txt`, or `.log` file and the tool:

- Maps each event to a MITRE ATT&CK technique using 120+ keyword patterns
- Builds an ordered incident timeline grouped by tactic
- Shows confidence scores per event
- Lets you export the full report as PDF, JSON, or CSV

No account needed, no setup.

---

## Stack

**Frontend** — deployed on Vercel  
Next.js 14 (App Router), TypeScript, Tailwind CSS, Lucide React

**Backend** — deployed on Railway  
Python 3.11, Flask, Flask-CORS, Gunicorn, ReportLab (PDF)

---

## Project structure

```
MITRE_Incident_Mapper/
├── backend/
│   ├── app.py                  # Flask API, all routes
│   ├── src/
│   │   ├── mitre_mapper.py     # Pattern matching logic
│   │   └── timeline_builder.py # Timeline + PDF generation
│   ├── data/sample_logs/       # Sample CSV for testing
│   ├── requirements.txt
│   ├── Procfile
│   └── railway.json
│
└── frontend/
    ├── src/app/
    │   ├── page.tsx            # Main upload + results UI
    │   └── docs/page.tsx       # API documentation
    ├── package.json
    └── vercel.json
```

---

## Running locally

**Backend**
```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app.py
# http://localhost:5000
```

**Frontend**
```bash
cd frontend
npm install
cp .env.example .env.local
# set NEXT_PUBLIC_API_URL=http://localhost:5000
npm run dev
# http://localhost:3000
```

Test it with `backend/data/sample_logs/incident_1.csv`.

---

## API

Full reference at https://mitre-incident-mapper.vercel.app/docs

```
POST /api/analyze          upload log file → incident analysis
GET  /api/incident/:id     fetch a previous result
GET  /api/download/:id/:format   export as pdf | json | csv
GET  /api/health           liveness check
```

---

## Deploying your own

**Backend → Railway**
1. New project → deploy from GitHub, root directory set to `backend/`
2. Generate a domain under Settings → Networking
3. No env vars required

**Frontend → Vercel**
1. Import repo, set root directory to `frontend/`
2. Add env var: `NEXT_PUBLIC_API_URL=https://your-railway-url.up.railway.app`
3. Deploy

---

Built by **Soham Shah** at **Happy Incident**  
[LinkedIn](https://linkedin.com/in/shahsoham2003) · [GitHub](https://github.com/soham7998/MITRE_Incident_Mapper)
