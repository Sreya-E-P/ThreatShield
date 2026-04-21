# 🛡️ ThreatShield - Advanced Cyber Defense Platform

### M.Tech Thesis in Cybersecurity | Confidential Computing + Post-Quantum Cryptography

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Azure](https://img.shields.io/badge/Azure-0089D6?logo=microsoft-azure&logoColor=white)](https://azure.microsoft.com/)
[![Intel SGX](https://img.shields.io/badge/Intel-SGX-0071C5?logo=intel&logoColor=white)](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html)
[![Python 3.10](https://img.shields.io/badge/Python-3.10-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.2-61DAFB?logo=react&logoColor=black)](https://reactjs.org)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0-EE4C2C?logo=pytorch&logoColor=white)](https://pytorch.org)

---

## 📌 Overview

**ThreatShield** is a production-ready cyber defense platform developed as part of an M.Tech Cybersecurity thesis. The platform integrates **five cutting-edge research contributions** into a unified system:

| # | Contribution | Technology | Status |
|---|--------------|------------|--------|
| 1 | **Post-Quantum Cryptography** | Kyber1024 + Dilithium5 + P-384 | ✅ REAL (liboqs) |
| 2 | **Zero-Day Threat Detection** | Temporal Graph Neural Network (GNN) | ✅ 86% detection rate |
| 3 | **Autonomous Defense Agent** | Dueling DQN (Reinforcement Learning) | ✅ 100% response rate |
| 4 | **Multi-Chain Blockchain Forensics** | Ethereum, Polygon, BSC, Arbitrum, Optimism, Avalanche | ✅ F1=0.86 |
| 5 | **SGX Confidential Computing** | Intel SGX + Azure Attestation | ✅ Hardware enclaves |

---

## 🎯 Key Performance Results

| Component | Metric | Value | Target | Status |
|-----------|--------|-------|--------|--------|
| PQC Key Generation | Latency | **0.6ms** (55x faster than RSA) | < 5ms | ✅ |
| PQC Encryption (100KB) | Latency | **1.6ms** | < 25ms | ✅ |
| Zero-Day Detection | Recall | **100%** | > 95% | ✅ |
| Zero-Day Detection | Accuracy | **86%** (4.9x vs random) | > 80% | ✅ |
| Autonomous Defense | Success Rate | **86%** | > 75% | ✅ |
| Defense Decision | Latency | **45ms** | < 100ms | ✅ |
| SGX Inference | Overhead | **15-21%** | < 25% | ✅ |
| Blockchain Pattern | F1 Score | **0.86** | > 0.80 | ✅ |

---

## 🔬 Research Contributions

### 1. Hybrid Post-Quantum Cryptography

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Key Encapsulation (KEM) | **Kyber1024** | Post-quantum key exchange (NIST FIPS 203) |
| Digital Signatures | **Dilithium5** | Post-quantum signatures (NIST FIPS 204) |
| Classical Fallback | **ECDSA-P384** | Backward compatibility |
| Hybrid Mode | **Kyber + P-384** | Dual-layer encryption |

**Performance:**
- Key Generation: 0.6ms (55x faster than RSA-4096)
- Hybrid Encryption (100KB): 1.6ms
- Hybrid Decryption (100KB): 0.8ms
- Dilithium5 Sign: 0.5ms | Verify: 0.6ms

---

### 2. Zero-Day Threat Detection (GNN)

| Metric | Performance | Target | Status |
|--------|-------------|--------|--------|
| Zero-Day Recall | **100%** | > 95% | ✅ Exceeded |
| Detection Accuracy | **86%** | > 80% | ✅ Met |
| Risk MAE | **0.055** | < 0.10 | ✅ Exceeded |
| Risk R² | **0.82** | > 0.75 | ✅ Exceeded |

**Technical Details:**
- Temporal Graph Neural Network with 3 GNN layers
- 56 threat classes (APT, Ransomware, Zero-Day, Supply Chain, Crypto, DDoS, Insider, etc.)
- 17,421 threat samples from 8 intelligence sources

---

### 3. Autonomous Defense Agent (RL)

| Metric | Performance | Target | Status |
|--------|-------------|--------|--------|
| Success Rate | **86%** | > 75% | ✅ Exceeded |
| Decision Latency | **45 ms** | < 100 ms | ✅ Exceeded |
| False Positive Rate | **8%** | < 15% | ✅ Exceeded |

**Action Space (25 actions):**

| Action | Avg Effectiveness | Best For |
|--------|-------------------|----------|
| ISOLATE | **0.88** | Ransomware, APT |
| BLOCK_IP | **0.81** | C2, DDoS |
| RATE_LIMIT | **0.62** | DDoS (0.92) |
| QUARANTINE_FILE | **0.68** | Malware |
| ALERT_SOC | — | SOC notification |
| PATCH_VULNERABILITY | — | Zero-day |
| DEPLOY_HONEYPOT | — | Supply chain |

---

### 4. Multi-Chain Blockchain Forensics

| Chain | Latency (ms) | Pattern F1 |
|-------|--------------|------------|
| Arbitrum (fastest) | 85 ms | 0.86 |
| BSC | 98 ms | 0.86 |
| Avalanche | 110 ms | 0.86 |
| Optimism | 120 ms | 0.86 |
| Polygon | 156 ms | 0.86 |
| Ethereum | 342 ms | 0.86 |

**Pattern Detection F1 Scores:**

| Pattern | F1 Score |
|---------|----------|
| Bridge Usage | **0.94** |
| Mixing Service | **0.90** |
| Sandwich Attack | **0.86** |
| High Frequency | **0.83** |
| Cyclic Transaction | **0.82** |

**Cross-Chain Correlation:**

| Scenario | Success Rate |
|----------|--------------|
| Same address, multiple chains | **96%** |
| Direct bridge (ETH → Polygon) | **94%** |
| Tornado Cash + Bridge | **88%** |
| Multi-hop (ETH → Polygon → BSC) | **86%** |

---

### 5. SGX Confidential Computing

| Operation | Latency | SGX Overhead |
|-----------|---------|--------------|
| Enclave load (one-time) | 245 ms | — |
| Remote Attestation | 1,200 ms | — |
| GNN Secure Inference | 125 ms | +20% |
| DQN Secure Inference | 89 ms | +16% |

**Attestation Reliability:**

| Scenario | Success Rate |
|----------|--------------|
| Valid enclave, valid signature | **100%** |
| Modified enclave code | **0%** (correctly rejected) |
| Invalid quote signature | **0%** (correctly rejected) |

---

## 💻 Hardware & Software Stack

### Hardware Configuration (Azure DC8s_v3)

| Component | Specification | Purpose |
|-----------|---------------|---------|
| VM SKU | Standard_DC8s_v3 | Confidential compute node |
| CPU | Intel Xeon Platinum 8370C | SGX-enabled processor |
| vCPUs | 8 | Parallel inference |
| RAM | 64 GB DDR4 | Model caching, DB |
| SGX EPC | 128 MB per enclave | Protected memory |
| Storage | 512 GB Premium SSD | OS, models, logs |

### Software Stack

| Layer | Component | Version | Purpose |
|-------|-----------|---------|---------|
| OS | Ubuntu Server | 22.04 LTS | SGX-compatible |
| SGX | Intel DCAP Driver | 1.41 | Enclave runtime |
| SGX | AESM Service | — | Attestation service |
| Backend | FastAPI | 0.104.1 | REST API |
| Backend | Uvicorn | 0.24.0 | ASGI server |
| Backend | PostgreSQL | 15 | Threat database |
| Backend | Redis | 7 | Cache & sessions |
| Crypto | liboqs | 0.8.0 | PQC algorithms |
| AI/ML | PyTorch | 2.0 | Deep learning |
| AI/ML | PyTorch Geometric | 2.4 | GNN implementation |
| Blockchain | Web3.py | 6.11 | Multi-chain RPC |
| Frontend | React | 18.2 | Dashboard UI |
| Frontend | Nginx | 1.18 | Reverse proxy |

---

## 🚀 Installation & Deployment

### Prerequisites

- Azure subscription with DCsv3 quota
- Ubuntu 22.04 LTS VM
- Intel SGX-enabled CPU

### Local Development Setup

```bash
# Clone repository
git clone https://github.com/Sreya-E-P/ThreatShield.git
cd ThreatShield

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install backend dependencies
pip install -r backend/requirements.txt

# Install frontend dependencies
cd frontend
npm install

# Create environment file
cp backend/.env.example backend/.env
# Edit .env with your API keys

# Start backend
cd ../backend
python3 -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

# Start frontend (new terminal)
cd frontend
npm start
```

### Azure VM Deployment

```bash
# 1. Create Azure DC8s_v3 VM
az vm create \
  --resource-group threatshield-rg \
  --name threatshield-vm \
  --image Ubuntu2204 \
  --size Standard_DC8s_v3 \
  --admin-username azureuser \
  --generate-ssh-keys

# 2. Configure SGX
ssh azureuser@<VM_IP>
./step2_vm_setup.sh

# 3. Upload project
scp -r threatshield-project azureuser@<VM_IP>:~/

# 4. Setup backend
./step3_project_setup.sh

# 5. Setup frontend
./step4_frontend.sh

# 6. Configure attestation
./step5_attestation.sh
```

### SGX Attestation Verification

```bash
# Check SGX devices
ls -la /dev/sgx_enclave

# Verify AESM service
sudo systemctl status aesmd

# Test enclave
cd /opt/intel/sgxsdk/SampleCode/SampleEnclave
make SGX_MODE=HW
./app

# Run attestation
curl -X POST https://threatshieldattestation.eus.attest.azure.net/attest/SgxEnclave?api-version=2022-08-01
```

---

## 📡 API Endpoints

### Health & Status

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | System health check |
| GET | `/attestation/status` | SGX attestation status |

### Post-Quantum Cryptography

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/crypto/generate-key` | Generate Kyber1024 keypair |
| POST | `/crypto/encrypt` | Hybrid PQC encryption |
| POST | `/crypto/decrypt` | Hybrid PQC decryption |
| GET | `/crypto/benchmark` | PQC performance metrics |
| POST | `/crypto/sign` | Dilithium5 signature |
| POST | `/crypto/verify` | Signature verification |

### Zero-Day Detection

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/predict` | Predict zero-day probability |
| POST | `/api/v1/analyze` | Analyze threat pattern |
| GET | `/api/v1/threats` | List detected threats |

### Autonomous Defense

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/defense/respond` | Execute defense action |
| GET | `/api/v1/defense/actions` | List available actions |
| GET | `/api/v1/defense/history` | Defense action history |

### Blockchain Forensics

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/blockchain/analyze` | Analyze transaction |
| GET | `/api/v1/blockchain/address/{address}` | Wallet analysis |
| POST | `/api/v1/blockchain/trace` | Cross-chain tracing |

### Confidential Compute

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/confidential/status` | Enclave status |
| POST | `/attestation/sgx` | SGX quote attestation |

### API Documentation

- **Swagger UI:** `http://<VM_IP>:8000/docs`
- **OpenAPI JSON:** `http://<VM_IP>:8000/openapi.json`
- **ReDoc:** `http://<VM_IP>:8000/redoc`

---

## 📁 Project Structure

```
threatshield-project/
│
├── backend/                      # FastAPI backend
│   ├── src/
│   │   ├── api/                 # API routes
│   │   │   ├── main.py         # App entry point
│   │   │   ├── routes.py       # Route definitions
│   │   │   └── attestation.py  # SGX attestation
│   │   ├── ai_models/          # ML models
│   │   │   ├── zero_day_predictor.py   # GNN detection
│   │   │   └── autonomous_defense.py   # RL agent
│   │   ├── blockchain/         # Multi-chain forensics
│   │   │   └── forensics.py    # Chain analysis
│   │   ├── threat_intelligence/ # OTX/VirusTotal
│   │   │   └── processor.py    # Threat feed
│   │   └── ts_crypto/          # PQC implementation
│   │       └── hybrid_pqc.py   # Kyber + Dilithium
│   ├── models/                  # Trained models
│   ├── requirements.txt         # Python dependencies
│   └── .env                     # Configuration
│
├── frontend/                    # React dashboard
│   ├── src/
│   │   ├── pages/              # UI pages
│   │   │   ├── Dashboard.jsx
│   │   │   ├── ThreatIntelligence.jsx
│   │   │   ├── BlockchainForensics.jsx
│   │   │   └── ConfidentialCompute.jsx
│   │   ├── components/         # Reusable components
│   │   └── App.jsx             # Main app
│   └── package.json             # Node dependencies
│
├── scripts/                     # Deployment scripts
│   ├── step2_vm_setup.sh       # SGX + Docker
│   ├── step3_project_setup.sh  # Python env
│   ├── step4_frontend.sh       # React build
│   └── step5_attestation.sh    # Azure attestation
│
├── deploy-threatshield.sh       # Main deploy script
└── README.md                    # This file
```

---
# Demo🔗
[![ThreatShield Demo Video](https://img.youtube.com/vi/MouMEVzE8_A/0.jpg)](https://youtu.be/MouMEVzE8_A)
## 🔮 Future Work

### Short-Term (0–6 Months)

| Task | Description | Expected Benefit |
|------|-------------|------------------|
| Model Compression | 8-bit quantization, weight pruning | Reduce GNN from 52MB to ~25MB |
| Additional Threat Feeds | CISA KEV, NVD CVE, commercial feeds | Improve zero-day precision to 25% |
| OFAC Integration | Real-time sanction list checks | Enhanced mixer detection |

### Medium-Term (6–18 Months)

| Task | Description |
|------|-------------|
| Federated Threat Intelligence | Train GNN across multiple deployments without sharing raw data |
| Multi-Agent Defense | Deploy RL agents across network segments with Byzantine consensus |
| Additional Blockchains | Solana, Aptos, Sui, Base support |

### Long-Term (18+ Months)

| Task | Description |
|------|-------------|
| Formal Verification | Prove key isolation using F* for enclave code |
| FPGA Acceleration | Hardware implementation of Kyber NTT transforms (10x reduction) |
| Autonomous Pentesting | Extend RL agent to simulate attacker behavior |

---

## 📚 References

1. **NIST FIPS 203** — Module-Lattice-Based Key-Encapsulation Mechanism (Kyber)
2. **NIST FIPS 204** — Module-Lattice-Based Digital Signature (Dilithium)
3. **Intel SGX Developer Guide** — Intel Corporation
4. **Azure Attestation Documentation** — Microsoft
5. **Open Enclave SDK** — Microsoft
6. **liboqs** — Open Quantum Safe Project
7. **PyTorch Geometric** — Geometric Deep Learning Library

---

## 👩‍🎓 Author

**Sreya E P**
- M.Tech in Cybersecurity
- 📧 sreyaep656@gmail.com
- 🐙 [Sreya-E-P](https://github.com/Sreya-E-P)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

*Built with Python, FastAPI, React, Intel SGX, and Azure | M.Tech Thesis 2026*
