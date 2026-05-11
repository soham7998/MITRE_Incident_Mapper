# MITRE Incident Mapper — Backend

Flask REST API that handles log parsing, MITRE ATT&CK pattern matching, timeline building, and report export.

**Production:** https://mitreincident-product.up.railway.app

---

## Endpoints

```
GET  /                          API info
GET  /api/health                liveness check
POST /api/analyze               upload log → analysis result
GET  /api/incident/:id          fetch stored incident
GET  /api/download/:id/:format  export as pdf | json | csv
```

Full docs: https://mitre-incident-mapper.vercel.app/docs

---

## Local setup

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app.py
# http://localhost:5000
```

Test with the included sample:
```bash
curl -X POST http://localhost:5000/api/analyze \
  -F "file=@data/sample_logs/incident_1.csv"
```

---

## Stack

- Python 3.11
- Flask + Flask-CORS
- Gunicorn (production)
- ReportLab (PDF export)

---

## How the mapping works

`src/mitre_mapper.py` holds 120+ keyword patterns tied to ATT&CK technique IDs. Each log line is scored against every pattern; the highest-confidence match above the threshold wins. Events with no match are labeled Unknown with confidence 0.

`src/timeline_builder.py` sorts matched events chronologically and groups them by tactic to build the kill-chain view.

---

Built by **Soham Shah** at **Happy Incident**
