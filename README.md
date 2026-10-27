# 🛡️ PayPal Shield AI

> **An AI-powered cybercrime firewall, agentic-commerce sanitizer, and 60-FPS Security Operations Center (SOC) built for the PayPal ecosystem** — neutralizing invoice phishing, indirect AI prompt injections, remote-access coercion scams, peer-to-peer payment traps, and automated carding botnets before funds move.

---

## 🧠 Core Architecture & Modules

1. **Phishing & Prompt-Injection Invoice Interceptor (`Invoicing v2` + `Webhooks API`)**
   * Intercepts draft invoices (`POST /v2/invoicing/invoices`) and signed `INVOICING.INVOICE.CREATED` webhooks (`/api/webhooks/paypal`).
   * Strips zero-width Unicode control characters (`\u200B-\u200D\uFEFF`), flags lookalike homograph domains (`paypaI.com`), redacts `[SYSTEM OVERRIDE]` LLM jailbreaks, and automatically executes `DELETE /v2/invoicing/invoices/{id}` in PayPal Sandbox.
2. **Coerced Friends & Family Scam-Trap Guardrail (`Orders v2` Reroute)**
   * Tracks real-time browser telemetry for rapid `window.onblur` tab switches (AnyDesk/TeamViewer remote coaching) and commercial keywords.
   * Triggers a high-friction **Social-Engineering Circuit Breaker Modal** and 1-click reroutes unsafe transfers into protected `POST /v2/checkout/orders` (`intent: "CAPTURE"`).
3. **Anti-Carding Bot Firewall (`Orders v2 Authorize & Void`)**
   * Combines client-side `0ms` clipboard paste detection and mouse arc curvature (radians) with an `IsolationForest` BIN velocity engine (`ai-engine/anomaly.py`) to void bot authorizations before capture.
4. **One-Click "Proof a Human Paid" Evidence Bridge (`Disputes v1 API`)**
   * Packages verified human session biometrics and the tamper-proof `SHA-256` risk seal into an evidence bundle submitted directly to `POST /v1/customer/disputes/{id}/provide-evidence`.
5. **Interactive Live Telemetry & Custom Attack Lab**
   * Built-in sandbox drawer that captures live mouse curvature, keystroke flight time (ms), `Alt+Tab` window-blur counts, and `Ctrl+V` clipboard pastes directly from the browser.

---

## 📊 Security Operations Center (AG Grid Enterprise)

* **Natural Language Grid Control:** Plain-English command bar that translates analyst queries into structured column grouping, risk filtering, and sorting states (`/api/ai/grid-state`).
* **60-FPS High-Velocity Streaming:** Streams automated card-testing waves in real time with cell change flashing and inline SVG 60-second velocity sparklines.
* **Master/Detail Forensic & Raw JSON Inspector:** Expandable row drawers featuring red-highlighted scam phrases, sanitized AI payloads, horizontal `SHAP` explainability bars, `SHA-256` cryptographic seals, and raw PayPal Sandbox JSON envelopes.
* **Batch Sandbox Enforcement & Compliance Exports:** Custom right-click context menu for bulk-deleting phishing drafts, bulk-voiding card authorizations, attaching dispute evidence, and exporting FinCEN CSV/Excel audit trails.

---

## 📂 Repository Structure

paypal-shield-ai/
├── ai-engine/
│   ├── classifier.py         # FastAPI + DeBERTa-v3 NLP phishing & prompt-injection sanitizer
│   ├── anomaly.py            # Scikit-Learn IsolationForest for BIN velocity & bot biometrics
│   └── requirements.txt      # Python AI microservice dependencies
├── server/
│   ├── src/
│   │   ├── index.ts          # Express SOC backend, PayPal OAuth2 & REST API orchestrator
│   │   └── paypalShieldTest.ts
│   └── prisma/
│       └── schema.prisma     # SQLite/PostgreSQL schema for forensic audit logs
├── client/
│   └── src/
│       └── App.tsx           # AG Grid Enterprise v34 SOC Command Center & Live Telemetry Lab
└── README.md                 # Architecture and setup guide