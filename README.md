# 🛡️ Cybersecurity Threat Advisor — SecureX v1.2.0

An intelligent, production-ready cybersecurity threat detection and response platform with:
- **Three interfaces:** CLI tool, web dashboard, native desktop GUI
- **Real-time monitoring:** System/network threat detection
- **AI-powered detection:** 50+ rules + ML anomaly detection (Isolation Forest)
- **Multi-channel alerts:** Email, SMS, webhooks
- **Enterprise features:** SIEM integration, email digests, threat history

**Status:** ✅ Production Ready | **Tests:** 52/52 Passing | **Code:** 5,000+ lines

## 🎓 B.Tech Final Year Project

**Domain:** Cybersecurity, Artificial Intelligence  
**Technologies:** Python, Machine Learning, SQLite, Flask  
**Approach:** Hybrid (Rule-Based + ML-Based Anomaly Detection)

---

## ✨ Features

- 🔍 **Real-time Activity Monitoring:** System processes, network connections, file access
- 🚨 **Threat Detection:** Rule-based + ML-based anomaly detection
- 📊 **Risk Classification:** Low, Medium, High severity levels
- 💬 **Human-Readable Advisories:** Plain-language security recommendations
- 📝 **Threat Logging:** Persistent storage with historical analysis
- 📈 **Dashboard:** Web-based visualization and reporting
- 🤖 **ML Enhancement:** Isolation Forest for anomaly detection

### AI Security Assistant

Available on the dashboard's **AI Assistant** page, and from **Explain with AI
Assistant** in any threat's detail dialog. The desktop app embeds the same
dashboard, so it is available there too.

What it does:
- Answers questions about malware, ransomware, phishing, suspicious processes and network threats.
- Explains why SecureX flagged a threat, using the stored threat record and its advisory.
- Answers questions about your recent detections ("What threats were detected recently?").
- Shows **evidence** (retrieved documentation and SecureX records) separately from
  **recommendations**, and shows a warning when evidence is missing or the answer is uncertain.
- Keeps per-user conversation history with timestamps.

What it cannot do: it has no tools. It cannot run commands, stop processes, or delete or
quarantine files. Retrieved documents, threat records and earlier messages are passed to
the model inside marked untrusted-data blocks, and the system prompt tells it to ignore
any instructions in them.

**Offline mode (default).** With `ai.enabled: false` the assistant answers from the local
knowledge base in [docs/security_knowledge/](docs/security_knowledge/) and the SecureX
database. No API key is needed.

**Retrieval (RAG).** With `ai.rag_enabled: true` (the default) and the optional packages
installed, documents are chunked with LangChain, embedded with Sentence Transformers
(`all-MiniLM-L6-v2`) and stored in ChromaDB at `data/chroma_db`. The model loads in the
background at startup. If the packages or model are unavailable, keyword retrieval is used.

```bash
pip install -r requirements-ai.txt
```

To add knowledge, drop `.md` or `.txt` files into `docs/security_knowledge/` and restart.

**Language model.** Set the key in the environment, then set `ai.enabled: true` in
`config/config.yaml`:

```powershell
$env:SECUREX_AI_API_KEY="your-key"     # never put it in config files or frontend code
```

| `ai.provider` | Default endpoint | Example `ai.model` |
|---|---|---|
| `openai-compatible` | `https://api.openai.com/v1/chat/completions` | `gpt-4o-mini` |
| `huggingface` | `https://router.huggingface.co/v1/chat/completions` (HF token as key) | `meta-llama/Llama-3.1-8B-Instruct` |
| `ollama` | `http://localhost:11434/v1/chat/completions` (no key) | `llama3.1` |

`ai.base_url` overrides the endpoint for any other OpenAI-compatible service. If the
provider fails or the key is missing, the assistant falls back to offline mode.

API (all require login): `POST /api/assistant/chat` `{"message": "..."}` (max 2000
characters), `GET /api/assistant/history`, `GET /api/assistant/explain/<threat_id>`.

### Email Alerts

1. Set SMTP credentials in the environment (use an app password for Gmail):
   ```powershell
   $env:SECUREX_SMTP_SENDER="alerts@example.com"
   $env:SECUREX_SMTP_PASSWORD="app-password"
   $env:SECUREX_DASHBOARD_URL="http://localhost:5000"   # used for links in emails
   ```
2. In `config/config.yaml`, set `notifications.enabled: true` and the `smtp` server and
   port (587 STARTTLS by default; port 465 uses implicit TLS).
3. Start the dashboard, open **Settings → Email Notifications**, add an address, and open
   the verification link sent to it. Only verified addresses (plus any listed under
   `notifications.recipients` in config) receive alerts.
4. Click **Send Test Notification**.

Behaviour:
- Every threat found by the dashboard's scan or monitoring loop is checked against the
  severity rules (High and Critical by default) and queued to a background email worker,
  so SMTP delays never block detection.
- **Duplicate suppression:** the same threat (rule, risk level, source, process or
  remote address) is emailed to a recipient at most once per `cooldown_seconds`
  (default 300). A failed send does not start the cooldown, so the next detection retries.
- **Retries:** each send uses a 15 s timeout and retries network and SMTP errors
  (`retry_attempts`, `retry_delay`). Authentication errors fail immediately.
- Every attempt is stored in the `notification_deliveries` table with its status and error,
  and shown under **Recent deliveries** in Settings.
- Preferences (enabled, severities, cooldown) are saved in the database and survive restarts.
- Emails include the threat name, category, severity, risk score, detection time, a
  whitelisted subset of technical details (process name, PID, remote IP and port), an
  explanation, recommended actions and a dashboard link. They never include passwords,
  API keys or file contents.

API (all require login except the emailed link): `GET /api/notifications/status`,
`PATCH /api/notifications/preferences`, `POST /api/notifications/recipients` (sends
verification), `GET /api/notifications/verify?token=...`,
`DELETE /api/notifications/recipients/<email>`, `POST /api/notifications/test`,
`GET /api/notifications/deliveries`.

### Testing the Assistant and Email Modules

```bash
pip install -r requirements.txt
set FLASK_ENV=testing            # PowerShell: $env:FLASK_ENV="testing"
python -m pytest tests/test_assistant_notifications_integration.py tests/test_assistant.py -v
```

These tests use mocks and temporary databases. They need no API key, SMTP account or
network. The vector-retrieval test runs only when `requirements-ai.txt` is installed and
the embedding model is cached; otherwise it is skipped. To check real delivery, configure
SMTP as above and use **Send Test Notification**.

Access model: every dashboard account is an administrator (accounts are created with
`scripts/create_admin_user.py`; there is no role system). All logged-in users can
therefore see system-wide threats and notification settings. Assistant conversation
history is private to each user.

### Risk Context, Graduated Response and Audit Log

- **Risk context:** scores are adjusted for the device's configured criticality,
  network exposure, privileged accounts and off-hours activity. The reasons are shown
  in each threat's details.
- **Graduated response:** High and Critical threats with a live process get proposals
  to suspend (reversible) or terminate it. A logged-in user must approve each one in
  the threat details or the **Response Center**. Execution is off by default
  (`response.execution_enabled: false`), so approvals are recorded as dry runs.
- **Audit log:** logins, configuration changes, status changes and every response
  decision are written to a hash-chained log. View and verify it on the **Audit Log** page.

Details: [docs/GOVERNANCE.md](docs/GOVERNANCE.md). How these map to the project's
research gaps: [docs/RESEARCH_GAPS.md](docs/RESEARCH_GAPS.md).

### Landing Page and Releases

A public product page is served at `/welcome` (no sign-in) and linked from the login
page. Its Download section shows an installer only when `releases/manifest.json`
exists **and** the file still matches the SHA-256 in it; otherwise it says no build
is published and shows how to run from source. To publish a build:

```bash
pyinstaller desktop_app.spec --noconfirm
python scripts/build_release.py --version 1.2.0 --notes "Preview build"   # runs the tests first
```

Builds are labelled `preview` unless you pass `--status stable`. Only do that after
installing and testing the build on a clean Windows machine. Builds are not code-signed.

### Attack Tester (testing the detectors)

`attacker/` is a separate tool that creates harmless activity that looks like an attack to SecureX, so you can watch the dashboard react. Start monitoring in the dashboard first, then open the tester window and click a scenario (or **Run all at once**):

```bash
python attacker/attacker_app.py                    # window with one button per scenario
python attacker/simulator.py all --parallel        # same scenarios from the command line
pyinstaller attacker/attacker.spec                 # build dist/SecureX Attack Tester.exe
```

Scenarios: a renamed `ping.exe` called `nmap_sim.exe` (suspicious process), a loopback connection to port 4444 (backdoor port), 120 loopback connections (port scan), a rename burst plus fake ransom note in a temporary `Documents/SecureX_Attack_Simulation` folder (ransomware), failed dashboard logins (brute force) and an optional `cpu` burn. Network traffic stays on 127.0.0.1 and everything is cleaned up afterwards.

### Dataset Evaluation

`scripts/evaluate_datasets.py` evaluates the Isolation Forest on CIC-IDS2017 or
UNSW-NB15 with a leakage-aware protocol and writes a report to `data/reports/`.
The datasets are not bundled. See [docs/DATASET_EVALUATION.md](docs/DATASET_EVALUATION.md)
for download links and commands.

### Deploy With Docker

Copy `.env.example` to `.env`, set a strong `SECRET_KEY`, add the AI key if
needed, enable `ai.enabled`, and run:

```bash
docker compose up --build -d
```

The container builds the frontend, serves it from Flask, and stores the SQLite
database and logs in the persistent `securex-data` volume. Open port `5000` (or
set `PORT`) on the host and use the host URL to access the dashboard.

---

## 🏗️ Architecture

```
User Interface (Dashboard/CLI)
        ↓
Advisory Generation Layer
        ↓
Threat Detection Engine (Rules + ML)
        ↓
Activity Monitoring Layer
        ↓
Data Storage (SQLite)
```

---

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment (recommended)

### Setup Steps

1. **Clone or navigate to the project:**
```bash
cd a:\codes\pbl
```

2. **Create virtual environment:**
```bash
python -m venv venv

```

3. **Activate virtual environment:**
```bash
# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

4. **Install dependencies:**
```bash
pip install -r requirements.txt
```

5. **Initialize the system:**
```bash
python main.py --init
```

6. **Set up authentication (required to use the web dashboard):**
```bash
# Set a session secret key (required — the app will not start without this)
python -c "import secrets; print(secrets.token_hex(32))"
set SECRET_KEY=<paste the value printed above>

# Create your admin login
python scripts/create_admin_user.py <your-username> <your-email>
```

---

## 🚀 Quick Start

### Run the System

```bash
# Start monitoring and detection
python main.py

# Run with web dashboard
python main.py --dashboard

# CLI mode
python main.py --cli
```

### View Threats

```bash
# List recent threats
python main.py --list-threats

# Generate report
python main.py --report
```

---

## 🎨 Frontend Development

The web dashboard is a React + TypeScript SPA in `frontend/`, talking to the Flask backend as a pure JSON API.

### Development (hot-reload)
```bash
# Terminal 1: backend API
set SECRET_KEY=<your-secret>
python src/dashboard/app.py

# Terminal 2: frontend dev server (proxies /api and /socket.io to Flask)
cd frontend
npm install
npm run dev
```
Open http://localhost:5173

### Production build
```bash
cd frontend
npm run build
```
This outputs static files to `frontend/dist/`, which Flask serves automatically when you run `python src/dashboard/app.py` — no separate frontend server needed in production.

---

## 📁 Project Structure

```
cybersecurity-threat-advisor/
├── config/                     # Configuration files
│   ├── config.yaml            # Main configuration
│   └── rules.json             # Detection rules
├── src/                        # Source code
│   ├── monitors/              # Activity monitoring modules
│   │   ├── system_monitor.py
│   │   ├── network_monitor.py
│   │   └── file_monitor.py
│   ├── detection/             # Threat detection
│   │   ├── rule_engine.py
│   │   ├── anomaly_detector.py
│   │   └── correlator.py
│   ├── risk_assessment/       # Risk scoring
│   │   └── risk_scorer.py
│   ├── advisory/              # Advisory generation
│   │   └── advisor.py
│   ├── database/              # Database operations
│   │   └── db_manager.py
│   ├── ml_models/             # ML models
│   │   └── anomaly_model.py
│   └── dashboard/             # Web interface
│       └── app.py
├── data/                       # Data storage
│   ├── logs/                  # Application logs
│   ├── datasets/              # Training datasets
│   └── db/                    # SQLite database
├── tests/                      # Unit tests
├── docs/                       # Documentation
├── notebooks/                  # Analysis notebooks
├── requirements.txt            # Python dependencies
└── main.py                    # Entry point
```

---

## 🔧 Configuration

Edit `config/config.yaml` to customize:
- Monitoring intervals
- Detection thresholds
- Risk scoring parameters
- Database settings
- Dashboard port

---

## 📚 Documentation

- [Project Overview](PROJECT_OVERVIEW.md) - Detailed architecture and design
- [API Documentation](docs/API.md) - Module interfaces (coming soon)
- [Viva Guide](docs/VIVA_GUIDE.md) - Presentation tips (coming soon)

---

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/

# Run specific module tests
python -m pytest tests/test_detection.py
```

---

## 🤝 Contributing

This is a student project. Suggestions and improvements welcome!

---

## 📄 License

MIT License - Free for educational use

---

## 👨‍🎓 Author

B.Tech Computer Science Final Year Project

---

## 🙏 Acknowledgments

- Open-source cybersecurity community
- Public datasets: KDD Cup, CICIDS2017
- Python security libraries: psutil, scapy

---

**Status:** 🚧 Under Development
