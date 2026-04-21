# ============================================================
#  ThreatShield Azure Deployment Guide
#  Do this tonight before the demo tomorrow
# ============================================================

# ============================================================
# FROM YOUR WINDOWS MACHINE (PowerShell)
# ============================================================

# STEP 1: Start the VM and get IP
az vm start --resource-group threatshield-confidential-rg --name threatshield-sgx-vm

$VM_IP = az network public-ip show `
    --resource-group threatshield-confidential-rg `
    --name threatshield-sgx-vmPublicIP `
    --query ipAddress `
    --output tsv

Write-Host "VM IP: $VM_IP"

# STEP 2: Open port 80 for the demo (if not already open)
az network nsg rule create `
    --resource-group threatshield-confidential-rg `
    --nsg-name threatshield-sgx-vmNSG `
    --name allow-http `
    --protocol tcp `
    --priority 200 `
    --destination-port-range 80 `
    --access Allow

# STEP 3: Upload project to VM
scp -r "C:\Users\LENOVO\Desktop\threatshield-project" azureuser@${VM_IP}:~/

# STEP 4: Upload the setup scripts
scp step2_vm_setup.sh azureuser@${VM_IP}:~/
scp step3_project_setup.sh azureuser@${VM_IP}:~/
scp step4_frontend.sh azureuser@${VM_IP}:~/
scp step5_attestation.sh azureuser@${VM_IP}:~/

# STEP 5: SSH into the VM
ssh azureuser@${VM_IP}

# ============================================================
# FROM INSIDE THE AZURE VM (SSH session)
# Run these one by one
# ============================================================

# Run VM base setup (installs SGX, Python, Docker, Node)
# chmod +x step2_vm_setup.sh && ./step2_vm_setup.sh

# Run project setup (installs deps, configures .env, starts backend)
# chmod +x step3_project_setup.sh && ./step3_project_setup.sh

# Build and serve frontend
# chmod +x step4_frontend.sh && ./step4_frontend.sh

# Configure Azure Attestation + verify SGX
# chmod +x step5_attestation.sh && ./step5_attestation.sh

# ============================================================
# VERIFY EVERYTHING IS WORKING
# ============================================================

# From inside VM:
# curl http://localhost:8000/health
# curl http://localhost:8000/api/v1/threats
# curl http://localhost:8000/api/v1/confidential/status

# From browser (use VM's public IP):
# http://<VM_IP>/dashboard

# ============================================================
# DEMO CHECKLIST
# ============================================================
# [ ] VM running and SSH accessible
# [ ] Backend responding on port 8000
# [ ] Frontend loading in browser on port 80
# [ ] SGX devices visible (/dev/sgx*)
# [ ] AESM service running (sudo systemctl status aesmd)
# [ ] Attestation endpoint reachable
# [ ] Dashboard shows live OTX + VirusTotal threats
# [ ] Confidential Compute page shows 3 enclaves
# [ ] Blockchain forensics working
# [ ] Run: python simulate_attacks.py for live demo data
# ============================================================

Write-Host ""
Write-Host "Demo URL: http://$VM_IP"
Write-Host "API URL:  http://$VM_IP/api/v1"
Write-Host ""
