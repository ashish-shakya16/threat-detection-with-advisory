# SecureX Architecture

## System Overview

SecureX is a two-tier cybersecurity platform:
1. **CLI/Desktop Application** - Real-time monitoring and scanning
2. **Web Dashboard** - Analytics and remote management

Both connect to a shared SQLite database and ML detection engine.

## Component Architecture

```
User Interface Layer
├─ Web Dashboard (Flask)
│  ├ Real-time updates (SocketIO)
│  ├ Charts (Plotly)
│  └ Responsive design (Bootstrap)
└─ CLI Application
   └ Command-line interface

REST API Layer
├─ /api/threats/ - Threat management
├─ /api/stats/ - Statistics
└─ /api/analytics/ - Analytics

Core Modules
├─ Monitoring Engine
│  ├ System monitoring (CPU, memory, processes)
│  ├ Network monitoring (connections, ports)
│  └ File monitoring
├─ Detection Engine
│  ├ Rule-based detection
│  ├ ML anomaly detection (Isolation Forest)
│  └ Event correlation
├─ Risk Assessment
│  └ Multi-factor risk scoring
├─ Advisory System
│  └ Human-readable threat explanations
└─ AI Assistant
   ├ Knowledge base
   └ FAQ system

Data Layer
├─ SQLite Database
│  ├ Threats table
│  ├ Events table
│  ├ Advisories table
│  └ Other tables
└─ Configuration
   └ YAML-based settings
```

## Data Flow

1. **Monitoring** collects system/network events
2. **Detection** checks against rules and ML model
3. **Risk Scoring** calculates severity
4. **Advisory** generates recommendations
5. **Database** stores results
6. **Dashboard** displays insights

## Key Technologies

- **Backend:** Python 3.8+, Flask
- **Database:** SQLite
- **ML:** scikit-learn (Isolation Forest)
- **AI:** LangChain, ChromaDB
- **Frontend:** HTML, CSS, JavaScript
- **Visualization:** Plotly, Matplotlib
