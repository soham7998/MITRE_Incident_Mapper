# MITRE Incident Mapper — Frontend

Next.js 14 frontend for uploading incident logs and viewing MITRE ATT&CK-mapped timelines.

**Live:** https://mitre-incident-mapper.vercel.app  
**API Docs:** https://mitre-incident-mapper.vercel.app/docs

---

## Local setup

```bash
npm install
cp .env.example .env.local
# set NEXT_PUBLIC_API_URL=http://localhost:5000
npm run dev
# http://localhost:3000
```

Backend needs to be running on port 5000 first.

---

## Stack

- Next.js 14 (App Router)
- TypeScript
- Tailwind CSS
- Lucide React

---

## Pages

- `/` — drag-and-drop upload, results view, export buttons
- `/docs` — API reference

---

## Deploy to Vercel

1. Import the repo, set root directory to `frontend/`
2. Add env var: `NEXT_PUBLIC_API_URL=https://mitreincident-product.up.railway.app`
3. Deploy

---

Built by **Soham Shah** at **Happy Incident**
