# Prompt-Astra

**Prompt-Astra** is an AI security platform that detects, scores, and logs malicious or risky prompts sent to LLMs in real time. It combines a machine learning classifier, a FastAPI analysis backend, a browser extension for in-context protection, and a Flask dashboard for monitoring and reviewing flagged activity — all backed by Supabase for persistent, queryable security event storage.

> Think of it as a lightweight "WAF for prompts": every prompt that flows through the system is scored for risk (e.g. prompt injection, jailbreak attempts, data-exfiltration patterns), logged as a `security_events` record, and surfaced on a live dashboard for review.

---

## ✨ Key Features

- **ML-based prompt classification** — a trained `scikit-learn` model (see `ML Model/`) scores incoming prompts for malicious intent.
- **Dual FastAPI backends** — `Backend/` (modular service) and `FastApi/` (single-file service), both writing to the same Supabase `security_events` table so you can run either depending on your deployment needs.
- **Browser extension** (`Extension/`) — intercepts and analyzes prompts at the point of entry, before they reach an LLM provider.
- **Live monitoring dashboard** (`frontend/`) — a Flask app with:
  - Real-time KPIs and threat-distribution charts.
  - A monitor feed of incoming prompt events
  - A review queue for triaging flagged prompts
  - Automatic **demo-mode fallback**: if Supabase isn't configured or is unreachable, the UI gracefully falls back to static demo data instead of crashing
- **Health checks** — `/health` and `/api/health` endpoints report whether the app is running against live Supabase data or demo JSON (`data_source: supabase | demo_json`).
- **Supabase-backed persistence** — a ready-to-use schema (`supabase_schema.sql`) defines the `security_events` table used across the frontend and both backends.

---

## 🏗️ Architecture

```
Prompt-Astra/
├── Backend/              # Modular FastAPI service (prompt analysis API)
├── FastApi/              # Single-file FastAPI service (alternative backend)
├── ML Model/             # Trained model + inference logic (scikit-learn)
├── Extension/            # Browser extension for real-time prompt interception
├── frontend/             # Flask dashboard (monitoring, review queue, KPIs)
│   └── utils/
│       ├── supabase_store.py   # Fail-safe Supabase read/write wrapper
│       └── data_manager.py     # Live-vs-demo data orchestration
├── supabase_schema.sql   # security_events table definition
├── requirements.txt      # Python dependencies
└── CHANGES.md            # Changelog / integration notes
```

**Data flow:** a prompt is submitted → the ML model / backend scores it → the result is written to Supabase's `security_events` table → the frontend dashboard reads from that table (or falls back to demo data) to render KPIs, the monitor feed, and the review queue.

> **Note:** the repository currently ships two FastAPI backends (`Backend/` and `FastApi/`) that both target the same Supabase table. Either can be run independently; consolidating them into a single service is a planned cleanup.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| ML / Inference | scikit-learn, joblib, numpy, pandas |
| Backend API | FastAPI, Uvicorn, Pydantic |
| Frontend | Flask |
| Database | Supabase (PostgreSQL) |
| Browser integration | Extension (Extension/) |
| Config | python-dotenv |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- A [Supabase](https://supabase.com/) project (optional — the app runs in demo mode without one)

### 1. Clone the repository

```bash
git clone https://github.com/Vividh-Prabu/Prompt-Astra.git
cd Prompt-Astra
```

### 2. Install dependencies

```bash
python -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure environment variables

Copy the example environment files and fill in your own Supabase credentials:

```bash
cp Backend/.env.example Backend/.env
cp frontend/.env.example frontend/.env
```

Set the following in each `.env` file as needed:

```env
SUPABASE_URL=your_supabase_project_url
SUPABASE_KEY=your_supabase_service_role_key
FRONTEND_WRITES_SUPABASE=false   # set true only if the frontend, not the backend, should log events
```

> ⚠️ **Security note:** never commit real `.env` files. `.gitignore` is already configured to exclude them — always rotate any credentials that may have been exposed previously.

### 4. Set up the database

Run `supabase_schema.sql` in your Supabase project's SQL editor to create the `security_events` table.

### 5. Run the backend

Choose one of the two available backends:

```bash
# Modular backend
uvicorn Backend.main:app --reload

# OR single-file backend
uvicorn FastApi.main:app --reload
```

### 6. Run the frontend dashboard

```bash
cd frontend
python app.py
```

Visit `http://localhost:5000` to view the dashboard. Check `http://localhost:5000/health` to confirm whether it's connected to Supabase or running in demo mode.

### 7. Load the browser extension

See `Extension/` for extension-specific setup and browser loading instructions.

---

## 📊 Dashboard Overview

The frontend dashboard provides:

- **KPIs** — high-level counts of prompts analyzed, threats detected, and protection status
- **Monitor feed** — a live stream of incoming prompt events
- **Review queue** — flagged prompts awaiting a human decision, with the ability to update their status
- **Threat distribution** — an aggregated breakdown of detected threat categories

All views work seamlessly whether backed by live Supabase data or local demo data.

---

## 🗺️ Roadmap

- [ ] Consolidate `Backend/` and `FastApi/` into a single service
- [ ] Expand ML model coverage for additional attack patterns
- [ ] Add authentication to the review-queue dashboard
- [ ] CI/CD pipeline for automated testing and deployment

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome. Feel free to open an issue or submit a pull request.

## 📄 License

_No license specified yet — consider adding one (e.g. MIT) to clarify usage terms for contributors and users._

## 👤 Author

**Vividh Prabu**
[GitHub](https://github.com/Vividh-Prabu)


## VYOMINI SHETTY — Frontend Developer

I was primarily responsible for the **frontend development and user interface of Prompt-Astra**. My contribution focused on designing and developing the security dashboard, prompt analysis interface, threat monitoring views, review interface, attack testing interface, model evaluation pages, and security settings.

### Frontend and UI/UX

* Developed the **Flask-based frontend dashboard** for Prompt-Astra.
* Designed the overall dashboard layout, navigation, sidebar, cards, tables, modals, and page structure.
* Developed the **cybersecurity-themed user interface** and overall visual presentation.
* Implemented responsive layouts and navigation for different screen sizes.
* Added interactive UI elements, animations, loading states, status indicators, and notifications.
* Worked on improving the overall **UI/UX and user interaction flow**.

### Prompt Analyzer

* Developed the **Prompt Analyzer interface** for entering and testing prompts.
* Designed the prompt input area and analysis result layout.
* Implemented the display of security-analysis information such as:

  * Risk Score
  * Risk Level
  * Confidence
  * Attack Category
  * Severity
  * Decision
  * Detection Signals
  * Latency
* Added **ALLOW, REVIEW, and BLOCK** visual indicators.
* Implemented prompt character counting.
* Added keyboard support for prompt submission.
* Added predefined prompt and attack-test scenarios.
* Developed the **Payload Sanitization and Safe Stream Recovery** interface.
* Added a visual comparison between the original payload and sanitized payload.

### Threat Monitor

* Developed the **Threat Monitor interface** for displaying security events.
* Designed the security-event table and its information layout.
* Added search functionality for security events.
* Implemented filtering options for attack type, severity, and decision.
* Developed the detailed **event inspection interface** for viewing individual security events.

### Review Queue

* Developed the **Security Review Queue interface** for flagged prompts.
* Designed the interface for reviewing quarantined or suspicious prompts.
* Added detailed event inspection views.
* Designed the interface for reviewer actions such as:

  * Approve
  * Reject
  * Escalate
* Added support for displaying analyst audit notes.
* Implemented visual status indicators for reviewed events.

### Attack Lab

* Developed the **Attack Lab interface** for testing adversarial prompts.

* Designed the visual security pipeline:

  Attack Input → PromptGuard → Risk Analysis → Decision Gate → ARGUS

* Added interactive attack-test scenarios.

* Designed the visual representation of ALLOW, REVIEW, and BLOCK outcomes.

* Added displays for risk score, confidence, latency, and security explanations.

* Implemented visual indicators showing when a malicious payload is blocked.

### Model Evaluation

* Developed the **Model Evaluation interface** for presenting model performance.
* Designed displays for:

  * Accuracy
  * Precision
  * Recall
  * F1 Score
  * False Positive Rate (FPR)
  * False Negative Rate (FNR)
* Implemented the **confusion matrix visualization**.
* Added category-level model performance displays.
* Designed the evaluation page to present security-model performance clearly.

### Security Settings and Policies

* Developed the **Security Settings and Policies interface**.
* Designed configurable security-threshold controls for ALLOW, REVIEW, and BLOCK decisions.
* Added confidence-level policy controls.
* Designed ARGUS integration and isolation status displays.
* Added alert and telemetry preference controls.
* Implemented interactive threshold sliders and policy controls.

### Frontend Reliability and Interaction

* Implemented frontend loading and empty states.
* Added user-friendly error and notification messages.
* Implemented interactive buttons, filters, modals, dropdowns, sliders, and navigation elements.
* Added responsive behavior across different screen sizes.
* Improved the consistency and usability of the overall dashboard.

### Technologies Used

**HTML, CSS, JavaScript, Jinja2, Flask, Git, GitHub, and VS Code**

