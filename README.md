# CipherNest — AI Threat Intelligence Platform

> Real-time network threat detection powered by Claude AI agents, built for CICIDS-format datasets.

## 🚀 Deploy to Vercel (3 steps)

### Option A — Vercel CLI (fastest)
```bash
npm install -g vercel
cd ciphernest
npm install
vercel
```
Follow the prompts. Done — your URL appears in ~60 seconds.

### Option B — GitHub + Vercel Dashboard
1. Push this folder to a GitHub repo:
   ```bash
   git init && git add . && git commit -m "init"
   gh repo create ciphernest --public --push
   ```
2. Go to [vercel.com/new](https://vercel.com/new) → Import that repo
3. Framework: **Vite** · Build: `npm run build` · Output: `dist`
4. Click **Deploy**

### Option C — Drag & Drop (no account needed for preview)
1. `npm install && npm run build` locally
2. Drag the `dist/` folder onto [vercel.com/new](https://vercel.com/new)

---

## ⚠️ Important: API Key

The app calls `https://api.anthropic.com/v1/messages` directly from the browser.  
**You must add your Anthropic API key** — there are two ways:

### Way 1 — Environment variable (recommended for production)
Add to Vercel Dashboard → Settings → Environment Variables:
```
VITE_ANTHROPIC_API_KEY=sk-ant-...
```
Then update the fetch call in `src/CipherNest.jsx` (line ~100):
```js
headers: {
  "Content-Type": "application/json",
  "x-api-key": import.meta.env.VITE_ANTHROPIC_API_KEY,
  "anthropic-version": "2023-06-01",
  "anthropic-dangerous-direct-browser-access": "true",
},
```

### Way 2 — Hardcode for personal use only
Replace the headers in the `streamClaude` function with your key directly.  
⚠️ Never commit an API key to a public repo.

---

## Local Development
```bash
npm install
npm run dev
# → http://localhost:5173
```

## Features
- **Live mode** — auto-generates CICIDS-format demo flows at 700ms intervals
- **Simulation mode** — upload a real CICIDS CSV or use demo data; replay up to 10,000 flows
- **5 AI agents** — CLASSIFIER, ANALYZER, LOG_ANALYZER, THREAT_DETECT, ORCHESTRATOR stream Claude responses
- **Auto-blocking** — RESPONDER blocks IPs scoring > 0.82 anomaly score
- **Reports** — downloadable HTML reports with AI executive summaries
- **Topology** — live canvas network flow map
