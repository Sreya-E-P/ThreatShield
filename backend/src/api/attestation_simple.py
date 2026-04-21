from fastapi import APIRouter
from pydantic import BaseModel
import base64
import requests
import json

router = APIRouter(prefix="/attestation", tags=["attestation"])

class AttestationRequest(BaseModel):
    quote: str

@router.post("/sgx")
async def attest_sgx(request: AttestationRequest):
    """Attest SGX enclave with Azure Attestation - Direct API call"""
    try:
        attestation_url = "https://threatshieldattestation.eus.attest.azure.net/attest/SgxEnclave?api-version=2022-08-01"
        
        # Decode base64 quote
        quote_bytes = base64.b64decode(request.quote)
        
        # Send to Azure Attestation (no authentication needed for this endpoint)
        response = requests.post(
            attestation_url,
            json={"quote": quote_bytes.hex()},
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        if response.status_code == 200:
            return {
                "success": True,
                "message": "Attestation completed",
                "result": response.json()
            }
        else:
            return {
                "success": False,
                "error": f"Azure returned {response.status_code}",
                "details": response.text
            }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@router.get("/status")
async def attestation_status():
    return {
        "attestation_url": "https://threatshieldattestation.eus.attest.azure.net",
        "status": "configured",
        "sgx_available": True
    }
