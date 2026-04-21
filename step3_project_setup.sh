#!/bin/bash
# ============================================================
# STEP 3: Run this INSIDE the Azure VM after uploading project
# Sets up Python env, installs deps, configures .env for Azure
# ============================================================

set -e
PROJECT_DIR="$HOME/threatshield-project"
cd "$PROJECT_DIR"

echo "============================================"
echo "  ThreatShield Project Setup on Azure VM"
echo "============================================"

# ── Python virtual environment ───────────────────────────────
echo "Creating Python virtual environment..."
python3.10 -m venv venv
source venv/bin/activate

# ── Install Python dependencies ──────────────────────────────
echo "Installing Python dependencies..."
cd backend
pip install --upgrade pip
pip install -r requirements.txt

# Install liboqs-python for real PQC
pip install liboqs-python

# ── Update .env for Azure deployment ─────────────────────────
echo "Configuring .env for Azure..."
cat > .env << 'ENVEOF'
# ── Environment ──────────────────────────────────────────────
ENVIRONMENT=production

# ── API Keys (already configured) ────────────────────────────
OTX_API_KEY=92ad4e40ed7e971414bdf368a25b69a408531f11e6d9d23c3d37053f6ef79688
VIRUSTOTAL_API_KEY=42a4bf2e0f0b953c8d35df999ec890a485f23ce56ddb41edc63b77bfc77993e0
ETHERSCAN_API_KEY=RGFU3QGSKEU2GM1H1FWSFY1FSTPZWINVJF

# ── MISP (leave blank - not used) ────────────────────────────
MISP_URL=
MISP_API_KEY=

# ── Azure SGX Attestation ─────────────────────────────────────
SGX_ENABLED=true
AZURE_ATTESTATION_ENDPOINT=https://threatshieldattestation.eus.attest.azure.net

# ── Database ─────────────────────────────────────────────────
DATABASE_URL=sqlite:///./threatshield.db

# ── Redis (use local for now) ────────────────────────────────
REDIS_URL=redis://localhost:6379

# ── Security ─────────────────────────────────────────────────
SECRET_KEY=threatshield-azure-production-secret-2026
JWT_SECRET=threatshield-jwt-azure-2026
ENVEOF

echo ".env configured for Azure"

# ── Start Redis ──────────────────────────────────────────────
echo "Starting Redis..."
sudo apt-get install -y redis-server
sudo systemctl enable redis-server
sudo systemctl start redis-server

# ── Start backend ────────────────────────────────────────────
echo ""
echo "============================================"
echo "  Starting ThreatShield Backend..."
echo "============================================"
source venv/bin/activate
cd "$PROJECT_DIR/backend"

# Run with uvicorn on port 8000, bound to all interfaces
nohup uvicorn src.api.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 2 \
    --log-level info \
    > ~/backend.log 2>&1 &

echo "Backend PID: $!"
echo "Backend logs: tail -f ~/backend.log"
sleep 3

# Quick health check
curl -s http://localhost:8000/health | python3 -m json.tool || echo "Backend starting..."

echo ""
echo "✅ Backend running on port 8000"
