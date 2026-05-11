# MITRE Incident Mapper

Upload a security log or connect your SIEM and get a full MITRE ATT&CK-mapped incident timeline in seconds. Built for SOC analysts and incident responders who need to move fast.

**Live:** https://mitre-incident-mapper.vercel.app  
**Integrations:** https://mitre-incident-mapper.vercel.app/integrations  
**API Docs:** https://mitre-incident-mapper.vercel.app/docs  

---

## What we built

| Feature | Where | Details |
|---------|-------|---------|
| **File upload** | Main page | Upload `.csv`, `.json`, `.txt`, `.log` — up to 15 MB |
| **Paste log events** | Main page | Paste raw syslog, CEF, or plain text directly — no file needed |
| **CloudTrail auto-detect** | Main page | Upload a CloudTrail `.json` — `Records[]` format parsed automatically |
| **Splunk connector** | /integrations | Query your Splunk search head with a Bearer token + SPL query, results analyzed instantly |
| **Elasticsearch connector** | /integrations | Search any ES/OpenSearch index via API key or basic auth |
| **AWS CloudTrail connector** | /integrations | Paste or upload CloudTrail JSON, parses event name, user identity, source IP |
| **Raw log paste** | /integrations | Paste syslog, ArcSight CEF, or freeform text — CEF auto-detected |
| **ATT&CK heatmap** | Results view | Auto-generated kill-chain coverage grid across all 12 MITRE tactics, with technique IDs and event counts |
| **Event timeline** | Results view | Every log event with its MITRE mapping and confidence score (0–100) |
| **Technique list** | Results view | Deduplicated techniques sorted by tactic |
| **PDF export** | Results view | Compliance-ready incident report |
| **JSON / CSV export** | Results view | Machine-readable output for automation or Excel |
| **API** | /docs | Full REST API — all endpoints documented with curl examples |

---

## Stack

**Frontend** — deployed on Vercel  
Next.js 14 (App Router), TypeScript, Tailwind CSS, Lucide React

**Backend** — deployed on Railway  
Python 3.11, Flask, Flask-CORS, Gunicorn, ReportLab (PDF), Requests

---

## Project structure

```
MITRE_Incident_Mapper/
├── backend/
│   ├── app.py                   # Flask API — all routes + integration connectors
│   ├── src/
│   │   ├── mitre_mapper.py      # 120+ pattern MITRE ATT&CK mapping engine
│   │   └── timeline_builder.py  # Timeline ordering + PDF generation
│   ├── data/sample_logs/        # Sample CSV for testing
│   ├── requirements.txt
│   ├── Procfile
│   └── railway.json
│
└── frontend/
    ├── src/app/
    │   ├── page.tsx             # Main upload / paste / results UI
    │   ├── integrations/        # Splunk, Elastic, CloudTrail, raw paste connectors
    │   └── docs/                # API reference
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

Test with `backend/data/sample_logs/incident_1.csv`.

---

## API

Full reference at https://mitre-incident-mapper.vercel.app/docs

```
POST /api/analyze                    upload log file → incident analysis
POST /api/integrations/splunk        query Splunk REST API
POST /api/integrations/elastic       query Elasticsearch / OpenSearch
POST /api/integrations/cloudtrail    analyze CloudTrail Records[] JSON
POST /api/integrations/raw           analyze pasted syslog / CEF / text
GET  /api/incident/:id               fetch a stored result
GET  /api/download/:id/:format       export as pdf | json | csv
GET  /api/health                     liveness check
```

---

## Deploying your own

**Backend → Railway**
1. New project → deploy from GitHub, root directory `backend/`
2. Generate a public domain under Settings → Networking

**Frontend → Vercel**
1. Import repo, root directory `frontend/`
2. Add env var: `NEXT_PUBLIC_API_URL=https://your-railway-url.up.railway.app`

---

Built by **Soham Shah** at **Happy Incident**  
[LinkedIn](https://linkedin.com/in/shahsoham2003) · [GitHub](https://github.com/soham7998/MITRE_Incident_Mapper)
