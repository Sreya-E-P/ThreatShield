#!/bin/bash
# ============================================================
# STEP 2: Run this INSIDE the Azure VM after SSH
# This installs everything needed for ThreatShield + SGX
# ============================================================

set -e
echo "============================================"
echo "  ThreatShield Azure VM Setup"
echo "============================================"

# ── Update system ────────────────────────────────────────────
sudo apt-get update -y
sudo apt-get upgrade -y

# ── Install Intel SGX DCAP driver and SDK ───────────────────
echo "Installing Intel SGX..."
# Add Intel SGX repo
curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main" \
    | sudo tee /etc/apt/sources.list.d/intel-sgx.list

sudo apt-get update -y
sudo apt-get install -y \
    libsgx-enclave-common \
    libsgx-dcap-ql \
    libsgx-dcap-default-qpl \
    libsgx-dcap-ql-dev \
    libsgx-quote-ex \
    sgx-aesm-service \
    libsgx-urts

# Start AESM service (required for attestation)
sudo systemctl enable aesmd
sudo systemctl start aesmd
echo "SGX AESM service: $(sudo systemctl is-active aesmd)"

# ── Install Python 3.10 + pip ────────────────────────────────
echo "Installing Python..."
sudo apt-get install -y python3.10 python3.10-venv python3-pip git curl unzip

# ── Install Docker ───────────────────────────────────────────
echo "Installing Docker..."
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER

# ── Install Azure CLI ────────────────────────────────────────
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# ── Install Node.js 18 (for frontend build) ─────────────────
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# ── Clone / upload project ───────────────────────────────────
echo ""
echo "============================================"
echo "  Now upload your project files."
echo "  From your Windows machine run:"
echo "  scp -r C:\\Users\\LENOVO\\Desktop\\threatshield-project azureuser@<VM_IP>:~/"
echo "============================================"
echo ""

# ── Verify SGX works ────────────────────────────────────────
echo "SGX devices:"
ls /dev/sgx* 2>/dev/null || echo "No /dev/sgx — check if VM has SGX enabled"

echo ""
echo "✅ VM base setup complete!"
