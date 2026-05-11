# 🎯 MITRE ATT&CK Incident Mapper

**Full-stack security tool that converts raw incident logs into MITRE ATT&CK-mapped timelines with PDF reports.**

[![Backend](https://img.shields.io/badge/Backend-Railway-9333ea)](https://railway.app)
[![Frontend](https://img.shields.io/badge/Frontend-Vercel-000)](https://vercel.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

## 🏗️ Architecture

```
┌─────────────────────┐         ┌─────────────────────┐
│   Frontend (Vercel) │  HTTPS  │  Backend (Railway)  │
│   Next.js 14        │ ◄─────► │  Python Flask API   │
│   Tailwind CSS      │   API   │  MITRE ATT&CK Logic │
└─────────────────────┘         └─────────────────────┘
       ▲                                  ▲
       │                                  │
   User Browser                    PDF/JSON Export
```

**Why split?**
- ✅ **Vercel** is best-in-class for Next.js (free, instant deploys)
- ✅ **Railway** is best for Python APIs (always-on, $5/month free credit)
- ✅ Each scales independently
- ✅ Industry-standard pattern

## 📁 Repo Structure

```
MITRE_Incident_Mapper/
├── backend/              # Flask API → Railway
│   ├── app.py
│   ├── src/
│   ├── data/sample_logs/
│   ├── requirements.txt
│   ├── Procfile
│   └── railway.json
│
├── frontend/             # Next.js → Vercel
│   ├── src/app/
│   ├── package.json
│   ├── tailwind.config.js
│   └── vercel.json
│
└── README.md             # This file
```

## 🚀 Deployment Guide

### Part 1: Deploy Backend to Railway (5 min)

1. **Push to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/soham7998/MITRE_Incident_Mapper.git
   git branch -M main
   git push -u origin main
   ```

2. **Deploy on Railway:**
   - Go to https://railway.app → Login with GitHub
   - Click **New Project** → **Deploy from GitHub repo**
   - Select your repo
   - Click **Add variables** → leave empty (no env vars needed)
   - **Important:** Settings → **Root Directory:** `/backend`
   - Railway auto-detects Python + deploys

3. **Generate domain:**
   - Settings tab → **Networking** → **Generate Domain**
   - Save the URL: `https://your-app.up.railway.app`

4. **Test the API:**
   ```bash
   curl https://your-app.up.railway.app/api/health
   # Should return: {"status": "healthy", ...}
   ```

### Part 2: Deploy Frontend to Vercel (5 min)

1. **Go to Vercel:** https://vercel.com/new
2. **Import your GitHub repo**
3. **Configure:**
   - Framework Preset: **Next.js** (auto-detected)
   - **Root Directory:** `frontend`
   - Build Command: `npm run build` (auto)
   - Output Directory: `.next` (auto)
4. **Add environment variable:**
   ```
   Name:  NEXT_PUBLIC_API_URL
   Value: https://your-app.up.railway.app
   ```
   *(Use the Railway URL from Part 1)*
5. **Click Deploy** → Done in ~60 seconds

6. **Your live URLs:**
   - Frontend: `https://mitre-incident-mapper.vercel.app`
   - Backend: `https://your-app.up.railway.app`

### Part 3: Update Backend CORS (Important!)

After Vercel deploys, update CORS to allow your Vercel domain:

Edit `backend/app.py`:
```python
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "http://localhost:3000",
            "https://mitre-incident-mapper.vercel.app",  # ← Add your Vercel URL
            "https://*.vercel.app",
        ],
    }
})
```

Then push:
```bash
git add backend/app.py
git commit -m "Update CORS for Vercel"
git push
```

Railway auto-redeploys. ✅

## 💻 Local Development

### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
# → http://localhost:5000
```

### Frontend
```bash
cd frontend
npm install
cp .env.example .env.local
npm run dev
# → http://localhost:3000
```

## 🧪 Testing

Upload sample file: `backend/data/sample_logs/incident_1.csv`

Expected output:
- ✅ 15 events parsed
- ✅ 8+ MITRE techniques mapped
- ✅ Tactics: Initial Access → Execution → Credential Access → etc.
- ✅ Downloadable PDF report

## 📊 Tech Stack

### Backend
- **Python 3.11** + Flask 2.3
- **Flask-CORS** for cross-origin requests
- **Gunicorn** WSGI server
- **ReportLab** for PDF generation
- **Hosting:** Railway.app

### Frontend
- **Next.js 14** (App Router)
- **TypeScript** for type safety
- **Tailwind CSS** for styling
- **Lucide React** for icons
- **Hosting:** Vercel

## 💰 Cost

- **Vercel:** Free (Hobby plan — perfect for portfolios)
- **Railway:** $5/month free credit (covers small apps)
- **Total:** $0/month within free tier

## 🎓 What This Project Demonstrates

✅ **Full-stack architecture** (split frontend/backend)
✅ **Modern deployment** (Vercel + Railway)
✅ **CORS configuration** for production
✅ **REST API design** (clean endpoints)
✅ **React/TypeScript** with hooks
✅ **Tailwind CSS** for modern UI
✅ **Security domain knowledge** (MITRE ATT&CK)
✅ **DevOps skills** (Git, CI/CD, env vars)

## 📝 Resume Bullet

> Built and deployed full-stack MITRE ATT&CK incident analysis platform with Next.js frontend on Vercel and Python Flask API on Railway. Implemented 120+ pattern-based MITRE technique mappings, automated PDF report generation, and CORS-configured REST API. Architecture demonstrates production-grade frontend/backend separation.

## 🔗 Links

- **Live App:** https://mitre-incident-mapper.vercel.app
- **API Docs:** https://your-app.up.railway.app
- **GitHub:** https://github.com/soham7998/MITRE_Incident_Mapper
- **LinkedIn:** https://linkedin.com/in/shahsoham2003



**Built by [Soham Shah](https://linkedin.com/in/shahsoham2003)** | Cybersecurity Engineer |  SOC Analyst
