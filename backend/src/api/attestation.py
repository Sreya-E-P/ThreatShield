from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import base64
import json
import os

router = APIRouter(prefix="/attestation", tags=["attestation"])

class AttestationRequest(BaseModel):
    quote: str
    runtime_data: str = ""

@router.post("/sgx")
async def attest_sgx(request: AttestationRequest):
    """Attest SGX enclave with Azure Attestation"""
    try:
        from azure.security.attestation import AttestationClient
        from azure.identity import DefaultAzureCredential
        
        attestation_endpoint = os.getenv("AZURE_ATTESTATION_ENDPOINT", "https://threatshieldattestation.eus.attest.azure.net")
        credential = DefaultAzureCredential()
        attest_client = AttestationClient(endpoint=attestation_endpoint, credential=credential)
        
        quote_bytes = base64.b64decode(request.quote)
        runtime_bytes = base64.b64decode(request.runtime_data) if request.runtime_data else None
        
        response, token = attest_client.attest_sgx_enclave(quote_bytes, runtime_data=runtime_bytes)
        
        return {
            "success": True,
            "token": token[:200] + "...",
            "enclave_held_data": response.enclave_held_data.hex()[:100] if response.enclave_held_data else None,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status")
async def attestation_status():
    return {
        "attestation_url": os.getenv("AZURE_ATTESTATION_ENDPOINT", "https://threatshieldattestation.eus.attest.azure.net"),
        "status": "configured",
        "sgx_available": os.path.exists("/dev/sgx_enclave"),
    }
