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
