#!/bin/bash
# ============================================================
# STEP 5: Configure Azure Attestation + verify SGX
# Run inside the Azure VM
# ============================================================

set -e

echo "============================================"
echo "  Azure Attestation Setup"
echo "============================================"

# ── Login to Azure from the VM (managed identity) ────────────
echo "Logging into Azure with managed identity..."
az login --identity 2>/dev/null || {
    echo "Managed identity not available - login manually:"
    az login
}

# ── Check attestation provider ───────────────────────────────
echo "Checking attestation provider..."
az attestation show \
    --name threatshieldattestation \
    --resource-group threatshield-confidential-rg \
    --query "{name:name, status:status, attestUri:attestUri}" \
    --output table

# Get the attestation URL
ATTEST_URL=$(az attestation show \
    --name threatshieldattestation \
    --resource-group threatshield-confidential-rg \
    --query attestUri \
    --output tsv)

echo "Attestation URL: $ATTEST_URL"

# ── Update .env with correct attestation URL ─────────────────
PROJECT_DIR="$HOME/threatshield-project/backend"
sed -i "s|AZURE_ATTESTATION_ENDPOINT=.*|AZURE_ATTESTATION_ENDPOINT=$ATTEST_URL|" "$PROJECT_DIR/.env"
echo "Updated .env with attestation URL: $ATTEST_URL"

# ── Verify SGX is working ────────────────────────────────────
echo ""
echo "============================================"
echo "  SGX Verification"
echo "============================================"

# Check SGX devices
echo "SGX devices:"
ls -la /dev/sgx* 2>/dev/null && echo "✅ SGX devices found" || echo "⚠️  No SGX devices - check VM SKU"

# Check AESM service
echo "AESM service: $(sudo systemctl is-active aesmd 2>/dev/null || echo 'not running')"

# Check SGX capabilities
if [ -f /proc/cpuinfo ]; then
    grep -q "sgx" /proc/cpuinfo && echo "✅ CPU supports SGX" || echo "⚠️  CPU SGX not detected in /proc/cpuinfo"
fi

# Try SGX quote generation test
if command -v sgx_quote_generation_test &>/dev/null; then
    sgx_quote_generation_test && echo "✅ SGX quote generation working" || echo "⚠️  SGX quote generation failed"
fi

# ── Test attestation endpoint ────────────────────────────────
echo ""
echo "Testing attestation endpoint..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "$ATTEST_URL/.well-known/openid-configuration" 2>/dev/null || echo "000")

if [ "$HTTP_CODE" == "200" ]; then
    echo "✅ Attestation endpoint reachable (HTTP $HTTP_CODE)"
else
    echo "⚠️  Attestation endpoint returned HTTP $HTTP_CODE"
fi

# ── Test the ThreatShield confidential compute API ───────────
echo ""
echo "Testing ThreatShield SGX endpoint..."
sleep 2
curl -s http://localhost:8000/api/v1/confidential/status | python3 -m json.tool 2>/dev/null | head -20 || echo "Backend not ready yet"

echo ""
echo "============================================"
echo "✅ Azure Attestation setup complete!"
echo "Attestation URL: $ATTEST_URL"
echo "============================================"
