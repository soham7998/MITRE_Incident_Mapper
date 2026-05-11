# MITRE Incident Mapper - Frontend

Modern Next.js 14 frontend with Tailwind CSS. Deployed on Vercel.

## 🚀 Live Demo

**Frontend:** https://mitre-incident-mapper.vercel.app
**Backend API:** https://mitre-mapper-api.up.railway.app

## 🛠️ Local Development

```bash
npm install
cp .env.example .env.local
# Edit .env.local: NEXT_PUBLIC_API_URL=http://localhost:5000

npm run dev
# → http://localhost:3000
```

Make sure the backend is running on port 5000 first.

## ▲ Deploy to Vercel

### Option 1: One-click deploy (easiest)
1. Push frontend code to GitHub
2. Go to https://vercel.com/new
3. Import your repo
4. **Root Directory:** `frontend` (if monorepo)
5. Add environment variable:
   ```
   NEXT_PUBLIC_API_URL=https://your-railway-api.up.railway.app
   ```
6. Deploy

### Option 2: CLI
```bash
npm install -g vercel
vercel login
vercel
# Follow prompts → app deploys instantly
```

## 📦 Tech Stack

- **Framework:** Next.js 14 (App Router)
- **Language:** TypeScript
- **Styling:** Tailwind CSS
- **Icons:** Lucide React
- **Hosting:** Vercel (free tier)

## 🎨 Features

- Drag-and-drop file upload
- Real-time analysis with backend
- MITRE ATT&CK technique cards
- Event timeline visualization
- PDF/JSON/CSV export
- Responsive design
- Dark mode ready

## 🔗 Backend

API repo: `/backend` folder — deployed on Railway.app
