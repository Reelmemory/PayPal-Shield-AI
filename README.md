# 🛡️ PayPal Shield AI

> **One-Sentence Summary:** PayPal Shield AI is a real-time payment fraud firewall, agentic prompt-injection sanitizer, and 60-FPS AG Grid Enterprise Security Operations Center (SOC) that intercepts phishing invoices, reroutes coerced transfers, and voids carding botnets directly through PayPal’s REST APIs before settlement.

---

## ⚡ JUDGE'S 30-SECOND TESTING GUIDE (NO INSTALL REQUIRED)

We deployed the entire 3-service stack on Render so you can test every PayPal API integration and AI model in **under 30 seconds**:

* 🌐 **Live SOC Command Center (Frontend):** `https://paypal-shield-soc-client.onrender.com`
* 🐍 **Live Python FastAPI & Isolation Forest Swagger Docs:** `https://paypal-shield-ai-engine.onrender.com/docs`
* ⚙️ **Live Express + PayPal Sandbox Orchestrator:** `https://paypal-shield-backend.onrender.com/api/events`

*(Note: Free-tier Render instances sleep after 15m of inactivity. If the first button click takes ~30 seconds, the backend is waking up—subsequent clicks run in <50ms!)*

### 👇 Click These 5 Buttons in Order on the Dashboard:

| Step | Dashboard Action | What Happens Behind the Scenes |
| :--- | :--- | :--- |
| **1** | Click **`🚨 1. Phishing + Prompt-Injection Invoice`** | Creates a draft invoice via **PayPal Invoicing v2 API**, strips hidden zero-width LLM jailbreaks (`[SYSTEM OVERRIDE]`) + homograph domains (`paypaI.com`), calculates **SHAP** risk weights, and fires `DELETE /v2/invoicing/invoices/{id}`. **Click the `>` row arrow** to inspect the forensic drawer! |
| **2** | Click **`📞 2. Coerced F&F Trap → Orders v2`** | Detects active phone/screen-share coercion (`windowBlurCount >= 3` + commercial keywords) and automatically reroutes an unprotected Friends & Family transfer into a protected **PayPal Orders v2** checkout (`POST /v2/checkout/orders`). |
| **3** | Click **`⚡ 3. Botnet Carding Wave (60FPS Stream)`** | Simulates 20 headless card-testing probes (`0ms` CVV paste cadence), scores BIN velocity via our **Scikit-Learn Isolation Forest**, voids the holds, and streams rows at **60 FPS** into AG Grid with inline SVG sparklines. |
| **4** | Click **`⚖️ 4. "Proof a Human Paid" (Disputes v1)`** | Packages verified human biometric telemetry + a tamper-proof `SHA-256` cryptographic receipt seal and submits it to **PayPal Disputes v1 API** (`POST /v1/customer/disputes/{id}/provide-evidence`). |
| **5** | Click **`🧪 5. Open Live Telemetry Lab`** & **Ask AG Grid AI** | Move your mouse and type inside the Lab to see real-time radian curvature & keystroke flight sensors. Then type **`Group by threat, filter risk > 0.85, sort amount desc`** into the **Ask AG Grid AI** bar to automatically restructure the grid. |

---

## 🏗️ System Architecture

1. **Frontend SOC (`client/`):** React 19, TypeScript, Vite, **AG Grid Enterprise** (`applyTransactionAsync` 60-FPS streaming, Master/Detail forensic drawers, custom SVG velocity sparklines, right-click batch enforcement context menu, and Natural Language Grid State controller).
2. **Orchestration Backend (`server/`):** Node.js, Express, TypeScript, Prisma ORM (SQLite), integrating **PayPal Sandbox REST APIs** (`OAuth 2.0`, `Invoicing v2`, `Orders v2`, `Disputes v1`, and `Webhook` signature verification) with an automatic sub-5ms local failover if the Python service is cold-starting.
3. **AI & Anomaly Microservice (`ai-engine/`):** Python, FastAPI, and **Scikit-Learn** (`IsolationForest` anomaly detection, Unicode/homograph sanitization, and explainable SHAP risk attribution).

---

## 💻 Local Development Quickstart (Optional)

If you wish to run the stack locally:

```bash
# 1. Start Python FastAPI Microservice (Port 8000)
cd ai-engine
pip install -r requirements.txt
uvicorn classifier:app --reload --port 8000

# 2. Start Node.js + Prisma Backend (Port 4000)
cd ../server
cp .env.example .env # Add your PayPal Sandbox Client ID & Secret
npm install
npx prisma generate && npx prisma db push
npx tsx src/index.ts

# 3. Start React + AG Grid Enterprise SOC (Port 5173)
cd ../client
npm install
npm run dev