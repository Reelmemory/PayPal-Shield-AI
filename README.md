# 🛡️ PayPal Shield AI

**Real-time payment fraud firewall that uses AI + PayPal APIs to stop phishing invoices, coerced transfers, and carding botnets before they settle.**

Built for the **PayPal AI Hackathon 2026**.

## Demo Video

[Watch the 2-minute demo →](https://youtu.be/U7bSiyJLlhs)

---

## Live Demo (No Install Required)

The full 3-service stack is deployed on Render:

| Service | URL |
|---------|-----|
| **SOC Command Center** (Frontend) | [paypal-shield-soc-client.onrender.com](https://paypal-shield-soc-client.onrender.com) |
| **AI Engine** (Python + Isolation Forest) | [paypal-shield-ai-engine.onrender.com/docs](https://paypal-shield-ai-engine.onrender.com/docs) |
| **Orchestrator** (Express + PayPal Sandbox) | [paypal-shield-backend.onrender.com](https://paypal-shield-backend.onrender.com) |

> **Note:** Free Render instances sleep after ~15 minutes of inactivity. The first click may take 20–30 seconds while services wake up. Subsequent actions are fast.

---

## Judge’s 30-Second Testing Path

Open the **SOC Command Center** and click the numbered buttons in order:

| Step | Button | What happens |
|------|--------|--------------|
| **1** | `🚨 1. Phishing + Prompt-Injection Invoice` | Creates a draft via **PayPal Invoicing v2**, strips zero-width jailbreaks + homograph domains (`paypaI.com`), scores risk, then deletes the draft with `DELETE /v2/invoicing/invoices/{id}`. Click the `>` arrow on the row to open the forensic drawer. |
| **2** | `📞 2. Coerced F&F Trap → Orders v2` | Detects screen-share / phone coercion signals + commercial keywords and automatically reroutes an unprotected Friends & Family transfer into a protected **PayPal Orders v2** checkout. |
| **3** | `⚡ 3. Botnet Carding Wave (60 FPS)` | Simulates 20 headless card-testing probes, scores them with **Isolation Forest**, voids the holds, and streams the results into AG Grid at 60 FPS with velocity sparklines. |
| **4** | `⚖️ 4. "Proof a Human Paid" (Disputes v1)` | Packages biometric telemetry + a SHA-256 cryptographic receipt seal and submits it to **PayPal Disputes v1** as evidence. |
| **5** | `🧪 5. Open Live Telemetry Lab` + **Ask AG Grid AI** | Move your mouse and type to generate live telemetry. Then type a natural language command such as `Group by threat, filter risk > 0.85, sort amount desc` to restructure the grid. |

---

## The Problem

Phishing invoices, social-engineering / screen-share coercion, and automated carding attacks still reach settlement on PayPal because detection often happens too late (or not at all). Notes can contain hidden prompt-injection payloads, Friends & Family transfers have almost no buyer protection, and high-velocity card testing can slip through before risk systems react.

PayPal Shield AI sits in front of the critical PayPal APIs and blocks or reroutes these threats **before** money moves.

---

## How It Uses PayPal + AI

**PayPal (Sandbox)**
- Invoicing v2 → create + delete malicious drafts
- Orders v2 → protected checkout + authorization voiding
- Disputes v1 → submit cryptographic proof-of-human evidence
- Webhooks → real-time event ingestion

**AI / Detection**
- Prompt-injection & homograph sanitizer (zero-width Unicode + lookalike domains)
- Scikit-Learn Isolation Forest for carding / bot detection
- Rule-based + telemetry risk scoring with SHAP-style feature attributions
- Natural language control of the AG Grid SOC via structured grid-state commands

---

## Architecture
┌─────────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│  React SOC (AG Grid)│────▶│  Express Orchestrator │────▶│  Python AI Engine   │
│  60 FPS streaming   │     │  PayPal Sandbox APIs  │     │  Isolation Forest   │
│  Forensic drawers   │     │  Prisma + SQLite      │     │  Sanitizer + SHAP   │
└─────────────────────┘     └──────────────────────┘     └─────────────────────┘

1. **Frontend (`client/`)**  
   React 19 + TypeScript + Vite + **AG Grid Enterprise**  
   Features: 60 FPS streaming, Master/Detail forensic drawers, SVG velocity sparklines, right-click bulk actions, natural-language grid state controller.

2. **Backend (`server/`)**  
   Node.js + Express + TypeScript + Prisma (SQLite)  
   Handles all PayPal OAuth + REST calls, stores security events, and falls back to local evaluation if the Python service is cold.

3. **AI Engine (`ai-engine/`)**  
   Python + FastAPI + Scikit-Learn  
   Isolation Forest anomaly detection, Unicode/homograph sanitization, and explainable risk attributions.

---

## Key Features

- **Prompt-injection defense** — strips zero-width characters and blocks common jailbreak patterns before any PayPal call
- **Coercion detection** — uses window-blur + keyword signals to catch screen-share / phone scams
- **Carding firewall** — Isolation Forest + BIN velocity scoring that can void authorizations
- **Cryptographic receipt** — SHA-256 seal of the risk decision that can be submitted as Disputes evidence
- **AG Grid SOC** — real-time operations center with natural language querying (strong fit for the AG Grid sponsor prize)

---

## Limitations (Honest)

- Runs entirely on **PayPal Sandbox** (no live money)
- Free Render instances sleep after inactivity (first request is slow)
- Telemetry data in the demo is simulated for reproducibility
- Isolation Forest is pre-fitted on synthetic human baselines
- Not production-hardened (rate limits, auth, multi-tenant isolation, etc. are out of scope for the hackathon)

---

## Local Development

```bash
# 1. AI Engine (port 8000)
cd ai-engine
pip install -r requirements.txt
uvicorn classifier:app --reload --port 8000

# 2. Backend (port 4000)
cd ../server
cp .env.example .env          # add your PayPal Sandbox Client ID & Secret
npm install
npx prisma generate && npx prisma db push
npx tsx src/index.ts

# 3. Frontend (port 5173)
cd ../client
npm install
npm run dev
