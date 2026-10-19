#!/usr/bin/env bash
# Install the STIS SOC application in this directory. Existing SQLite data is kept.

set -euo pipefail

echo '[1/5] Dependensi sistem'
sudo apt update
sudo apt install -y python3 python3-pip python3-venv curl git rsync iproute2 procps

echo '[2/5] Node.js'
NODE_VER=0
if command -v node >/dev/null 2>&1; then
    NODE_VER=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
fi

if [ "$NODE_VER" -lt 20 ] || [ "$NODE_VER" -eq 21 ]; then
    echo "Versi Node.js saat ini tidak cocok dengan lockfile frontend. Menginstal Node.js v22..."
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
    sudo apt install -y nodejs
else
    echo "Node.js $(node -v) sudah terpasang."
fi

echo '[3/5] Backend Flask'
SOC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SOC_DIR/backend"

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

venv/bin/python -m pip install --upgrade pip
venv/bin/python -m pip install -r requirements.txt

venv/bin/python init_db.py

echo '[4/5] Frontend Vite'
cd "$SOC_DIR/frontend"
npm ci

echo '[5/5] UFW'
if sudo ufw status | grep -q "Status: active"; then
    sudo ufw allow 5000/tcp comment "STIS SOC Backend API"
    sudo ufw allow 5173/tcp comment "STIS SOC Frontend Web"
fi

echo "Selesai. Jalankan: bash $SOC_DIR/start_soc.sh"
echo 'Dashboard lab dari Windows: http://192.168.1.10:5173/'
