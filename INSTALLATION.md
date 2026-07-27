# SecureX Installation Guide

## System Requirements

- **Python:** 3.8 or higher
- **OS:** Windows 10+, Linux, or macOS
- **RAM:** 2GB minimum
- **Disk Space:** 500MB for installation and data

## Installation Steps

### Windows

1. **Clone or navigate to project:**
   ```bash
   cd path\to\SecureX
   ```

2. **Run installation script:**
   ```bash
   install.bat
   ```

3. **Activate virtual environment (if not auto-activated):**
   ```bash
   venv\Scripts\activate
   ```

### Linux/macOS

1. **Clone or navigate to project:**
   ```bash
   cd path/to/SecureX
   ```

2. **Make script executable and run:**
   ```bash
   chmod +x install.sh
   ./install.sh
   ```

3. **Activate virtual environment (if not auto-activated):**
   ```bash
   source venv/bin/activate
   ```

## Quick Start

### CLI Mode (Monitoring)

```bash
python main.py --monitor
```

### Single Scan

```bash
python main.py --scan
```

### List Recent Threats

```bash
python main.py --list-threats --hours 24
```

### View Statistics

```bash
python main.py --stats
```

### Web Dashboard

```bash
python -c "from src.dashboard.app import app; app.run()"
```

Then visit: `http://localhost:5000`

## Configuration

Edit `config/config.yaml` to customize:
- Monitoring intervals
- Detection thresholds
- Risk scoring parameters
- Database location
- Dashboard settings

## Troubleshooting

### ImportError: No module named...

```bash
pip install -r requirements.txt
```

### Database locked error

Close any other instances of SecureX and try again.

### Port already in use

Change port in config.yaml:
```yaml
dashboard:
  port: 5001
```

## Support

For issues, check the documentation in `/docs`.
