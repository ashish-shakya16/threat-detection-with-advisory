#!/bin/bash

# SecureX Installation Script for Linux/Mac

echo "============================================"
echo "SecureX Installation"
echo "============================================"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "Error: Python3 not installed"
    exit 1
fi

echo "[1/4] Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[2/4] Installing dependencies..."
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "Error: Failed to install dependencies"
    exit 1
fi

echo "[3/4] Initializing system..."
python main.py --init
if [ $? -ne 0 ]; then
    echo "Error: Failed to initialize system"
    exit 1
fi

echo ""
echo "============================================"
echo "Installation Complete!"
echo "============================================"
echo ""
echo "To start the system:"
echo "  - CLI Mode: python main.py"
echo "  - Web Dashboard: python -c \"from src.dashboard.app import app; app.run()\""
echo ""
