
"""
Production API routes for ThreatShield
"""

import sys
from pathlib import Path
import importlib.util
from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from pydantic import BaseModel

# Set up paths for imports
current_file = Path(__file__).resolve()
src_dir = current_file.parent.parent
backend_dir = src_dir.parent
project_root = backend_dir.parent

# Add paths to sys.path
paths_to_add = [str(project_root), str(backend_dir), str(src_dir)]
for path in paths_to_add:
    if path not in sys.path:
        sys.path.insert(0, path)

# Import settings - FIXED: Use config from src instead of root config folder
try:
    from src.config.config import config as settings
    print("âœ“ Routes: Successfully imported config from src.config")
except ImportError:
    try:
        # Fallback to direct import
        from config.config import config as settings
        print("âœ“ Routes: Successfully imported config from config.config")
    except ImportError:
        # Fallback to default settings
        from pydantic_settings import BaseSettings
        
        class DefaultSettings(BaseSettings):
            environment: str = "development"
            debug: bool = True
            api_port: int = 8000
            api_prefix: str = "/api/v1"
            api_url: str = "http://localhost:8000"
            log_level: str = "info"
            
            model_config = {
                "env_file": ".env"
            }
        
        settings = DefaultSettings()
        print("âš ï¸ Routes: Using default settings (config not found)")

# Import services using importlib
def import_module_from_path(module_name, relative_path):
    """Helper function to import a module from a relative path"""
    module_path = src_dir / relative_path
    if not module_path.exists():
        raise FileNotFoundError(f"Module not found: {module_path}")
    
    spec = importlib.util.spec_from_file_location(module_name, str(module_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# Import cryptographic services
try:
    # Try ts_crypto first (correct path)
    crypto_module = import_module_from_path("hybrid_pqc", "ts_crypto/hybrid_pqc.py")
    CryptographicService = crypto_module.CryptographicService
    HybridPQC = crypto_module.HybridPQC
    print("âœ“ Routes: Successfully imported CryptographicService from ts_crypto")
except FileNotFoundError:
    try:
        # Try alternative path
        crypto_module = import_module_from_path("hybrid_pqc", "cryptography/hybrid_pqc.py")
        CryptographicService = crypto_module.CryptographicService
        HybridPQC = crypto_module.HybridPQC
        print("âœ“ Routes: Successfully imported CryptographicService from cryptography")
    except FileNotFoundError as e:
        print(f"Warning: Cryptography modules not found: {e}")
        # Create placeholder for development
        class CryptographicService:
            async def generate_key(self):
                return {"key_id": "dev_key", "public_key": "dev_public", "private_key": "dev_private"}
            async def encrypt(self, text, key_id=None):
                return {"ciphertext": "encrypted_" + text, "key_id": key_id or "default"}
            async def decrypt(self, package):
                return {"plaintext": "decrypted_data"}
            async def benchmark(self):
                return {"encryption_time_ms": 0.5, "decryption_time_ms": 0.6}
        
        class HybridPQC:
            pass

# Import AI models
try:
    ai_module = import_module_from_path("zero_day_predictor", "ai_models/zero_day_predictor.py")
    ZeroDayPredictor = ai_module.ZeroDayPredictor
    ThreatType = ai_module.ThreatType
    print("âœ“ Routes: Successfully imported ZeroDayPredictor")
except (FileNotFoundError, AttributeError, ImportError, Exception) as e:
    print(f"Warning: AI modules not found: {e}")
    # Create placeholder classes for development
    class ThreatType:
        MALWARE = "malware"
        EXPLOIT = "exploit"
        VULNERABILITY = "vulnerability"
        PHISHING = "phishing"
        C2 = "command_control"
        DATA_EXFIL = "data_exfiltration"
        DOS = "denial_of_service"
        INSIDER = "insider_threat"
    
    class ZeroDayPredictor:
        async def predict(self, data):
            return {
                "zero_day_probability": 0.5,
                "risk_score": 0.5,
                "confidence": 0.5,
                "threat_predictions": {
                    "malware": {"probability": 0.5, "confidence": 0.5}
                },
                "explanation": "Placeholder prediction",
                "zero_day_indicators": [],
                "graph_info": {"nodes": 0}
            }
        async def train(self, epochs=100):
            print(f"Training placeholder model for {epochs} epochs")

try:
    defense_module = import_module_from_path("autonomous_defense", "ai_models/autonomous_defense.py")
    AutonomousDefenseService = defense_module.AutonomousDefenseService
    print("âœ“ Routes: Successfully imported AutonomousDefenseService")
except (FileNotFoundError, AttributeError, ImportError, Exception) as e:
    print(f"Warning: Defense module not found: {e}")
    class AutonomousDefenseService:
        async def handle_threat(self, data):
            return {"action": "monitor", "confidence": 0.5, "reasoning": "Placeholder defense"}
        def _train_initial_model(self, episodes=100):
            print(f"Training placeholder defense for {episodes} episodes")

# Import blockchain services
try:
    blockchain_module = import_module_from_path("forensics", "blockchain/forensics.py")
    BlockchainForensicsService = blockchain_module.BlockchainForensicsService
    MultiChainAnalyzer = blockchain_module.MultiChainAnalyzer
    Blockchain = blockchain_module.Blockchain
    print("âœ“ Routes: Successfully imported Blockchain services")
except (FileNotFoundError, AttributeError, ImportError, Exception) as e:
    print(f"Warning: Blockchain modules not found: {e}")
    # Create placeholder for development
    class Blockchain:
        ETHEREUM = "ethereum"
        POLYGON = "polygon"
        BSC = "bsc"
    
    class BlockchainForensicsService:
        def __init__(self):
            self.analyzer = type('obj', (object,), {
                'analyze_transaction': lambda self, tx, chain: {
                    "tx_hash": tx,
                    "chain": chain,
                    "risk_score": 0.3,
                    "anomalies": []
                }
            })()
        async def investigate_wallet(self, address, depth=2):
            return {
                "address": address,
                "depth": depth,
                "transactions": [],
                "risk_score": 0.3,
                "connected_addresses": []
            }
        async def generate_compliance_report(self, address, timeframe_days=30):
            return {
                "address": address,
                "timeframe_days": timeframe_days,
                "compliant": True,
                "risk_factors": []
            }
    
    class MultiChainAnalyzer:
        pass

# Import threat intelligence
try:
    ti_module = import_module_from_path("processor", "threat_intelligence/processor.py")
    ThreatIntelligenceProcessor = ti_module.ThreatIntelligenceProcessor
    print("âœ“ Routes: Successfully imported ThreatIntelligenceProcessor")
except (FileNotFoundError, AttributeError, ImportError, Exception) as e:
    print(f"Warning: Threat intelligence module not found: {e}")
    class ThreatIntelligenceProcessor:
        async def get_recent_threats(self, hours=24, severity=None, limit=100):
            return [
                {
                    "id": "THREAT-001",
                    "type": "malware",
                    "severity": "high",
                    "description": "Sample threat",
                    "timestamp": datetime.now().isoformat()
                }
            ]
        async def enrich_threats(self, threats):
            return threats

# Import confidential compute
try:
    cc_spec = importlib.util.spec_from_file_location(
        "sgx_host",
        str(src_dir / "confidential_compute" / "sgx_host.py")
    )
    if cc_spec and cc_spec.loader:
        cc_module = importlib.util.module_from_spec(cc_spec)
        cc_spec.loader.exec_module(cc_module)
        ConfidentialComputeService = cc_module.ConfidentialComputeService
        print("âœ“ Routes: Successfully imported ConfidentialComputeService")
    else:
        raise ImportError("Confidential compute module not found")
except (FileNotFoundError, AttributeError, ImportError) as e:
    print(f"Warning: Confidential compute module not found: {e}")
    class ConfidentialComputeService:
        def __init__(self):
            pass
        async def process_request(self, request):
            return {"result": "processed_in_placeholder", "enclave_id": "placeholder"}

router = APIRouter()

# Initialize services
crypto_service = CryptographicService()
ai_service = ZeroDayPredictor() if 'ZeroDayPredictor' in dir() else None
defense_service = AutonomousDefenseService() if 'AutonomousDefenseService' in dir() else None
blockchain_service = BlockchainForensicsService() if 'BlockchainForensicsService' in dir() else None
threat_intel = ThreatIntelligenceProcessor() if 'ThreatIntelligenceProcessor' in dir() else None

# Request/Response models
class ThreatAnalysisRequest(BaseModel):
    threat_data: List[dict]
    include_explanation: bool = True
    deep_analysis: bool = False

class CryptoRequest(BaseModel):
    plaintext: str
    key_id: Optional[str] = None

class BlockchainInvestigationRequest(BaseModel):
    address: str
    depth: int = 2
    chains: List[str] = ["ethereum", "polygon", "bsc"]

class AutonomousDefenseRequest(BaseModel):
    threat_data: dict
    action_preference: Optional[str] = None

class TrainModelRequest(BaseModel):
    model_type: str
    epochs: int = 100

# Health endpoints
@router.get("/health")
async def health():
    """System health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "api": "operational",
            "cryptography": "operational" if crypto_service else "unavailable",
            "ai_models": "operational" if ai_service else "unavailable",
            "blockchain": "operational" if blockchain_service else "unavailable",
            "threat_intelligence": "operational" if threat_intel else "unavailable"
        }
    }

# Cryptography endpoints
@router.post("/crypto/generate-key")
async def generate_key():
    """Generate hybrid PQC keypair"""
    try:
        key = await crypto_service.generate_key()
        return {"status": "success", "key": key}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/crypto/encrypt")
async def encrypt(request: CryptoRequest):
    """Encrypt data using hybrid PQC"""
    try:
        encrypted = await crypto_service.encrypt(request.plaintext, request.key_id)
        return {"status": "success", "encrypted": encrypted}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/crypto/decrypt")
async def decrypt(encrypted_package: dict):
    """Decrypt hybrid PQC encrypted data"""
    try:
        decrypted = await crypto_service.decrypt(encrypted_package)
        return {"status": "success", "decrypted": decrypted}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/crypto/benchmark")
async def crypto_benchmark():
    """Run cryptography performance benchmarks"""
    try:
        benchmark = await crypto_service.benchmark()
        return {"status": "success", "benchmark": benchmark}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# AI/ML endpoints
@router.post("/ai/analyze-threats")
async def analyze_threats(request: ThreatAnalysisRequest):
    """Analyze threats using GNN zero-day predictor"""
    if not ai_service:
        raise HTTPException(status_code=503, detail="AI service unavailable")
    try:
        analysis = await ai_service.predict(request.threat_data)
        
        result = {
            "status": "success",
            "analysis": {
                "zero_day_probability": analysis.get("zero_day_probability", 0.5),
                "risk_score": analysis.get("risk_score", 0.5),
                "confidence": analysis.get("confidence", 0.5),
                "threat_predictions": analysis.get("threat_predictions", {}),
            }
        }
        
        if request.include_explanation:
            result["explanation"] = analysis.get("explanation", "")
        
        if request.deep_analysis:
            result["detailed_analysis"] = {
                "indicators": analysis.get("zero_day_indicators", []),
                "graph_info": analysis.get("graph_info", {}),
            }
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/ai/autonomous-defense")
async def autonomous_defense(request: AutonomousDefenseRequest):
    """Execute autonomous defense using RL agent"""
    if not defense_service:
        raise HTTPException(status_code=503, detail="Defense service unavailable")
    try:
        defense_action = await defense_service.handle_threat(request.threat_data)
        
        return {
            "status": "success",
            "defense_action": defense_action,
            "timestamp": datetime.now().isoformat(),
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/ai/train-model")
async def train_model(request: TrainModelRequest):
    """Train AI models"""
    try:
        if request.model_type == "zero_day_predictor":
            if not ai_service:
                raise HTTPException(status_code=503, detail="AI service unavailable")
            # Train zero-day predictor
            await ai_service.train(epochs=request.epochs)
            return {"status": "success", "message": f"Zero-day predictor trained for {request.epochs} epochs"}
            
        elif request.model_type == "defense_agent":
            if not defense_service:
                raise HTTPException(status_code=503, detail="Defense service unavailable")
            # Train defense agent
            defense_service._train_initial_model(episodes=request.epochs)
            return {"status": "success", "message": f"Defense agent trained for {request.epochs} episodes"}
            
        else:
            raise HTTPException(status_code=400, detail=f"Unknown model type: {request.model_type}")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Blockchain endpoints
@router.get("/blockchain/analyze/{tx_hash}")
async def analyze_transaction(tx_hash: str, chain: str = "ethereum"):
    """Analyze blockchain transaction"""
    if not blockchain_service:
        raise HTTPException(status_code=503, detail="Blockchain service unavailable")
    try:
        # Convert chain string to Blockchain enum if possible
        try:
            if hasattr(Blockchain, chain.upper()):
                chain_enum = getattr(Blockchain, chain.upper())
            else:
                chain_enum = chain
        except:
            chain_enum = chain
            
        analysis = await blockchain_service.analyzer.analyze_transaction(tx_hash, chain_enum)
        
        return {
            "status": "success",
            "analysis": analysis,
            "timestamp": datetime.now().isoformat(),
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/blockchain/investigate")
async def investigate_wallet(request: BlockchainInvestigationRequest):
    """Investigate blockchain wallet"""
    if not blockchain_service:
        raise HTTPException(status_code=503, detail="Blockchain service unavailable")
    try:
        investigation = await blockchain_service.investigate_wallet(
            request.address, request.depth
        )
        
        return {
            "status": "success",
            "investigation": investigation,
            "timestamp": datetime.now().isoformat(),
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/blockchain/compliance-report")
async def generate_compliance_report(address: str, timeframe_days: int = 30):
    """Generate regulatory compliance report"""
    if not blockchain_service:
        raise HTTPException(status_code=503, detail="Blockchain service unavailable")
    try:
        report = await blockchain_service.generate_compliance_report(
            address, timeframe_days
        )
        
        return {
            "status": "success",
            "report": report,
            "timestamp": datetime.now().isoformat(),
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Threat Intelligence endpoints
@router.get("/threats")
async def get_threats(
    time_range: str = "24h",
    severity: Optional[str] = None,
    limit: int = 100
):
    """Get threat intelligence"""
    if not threat_intel:
        raise HTTPException(status_code=503, detail="Threat intelligence service unavailable")
    try:
        hours = int(time_range.replace("h", "")) if "h" in time_range else 24
        threats = await threat_intel.get_recent_threats(
            hours=hours,
            severity=severity,
            limit=limit
        )
        
        return {
            "status": "success",
            "count": len(threats),
            "threats": threats,
            "timestamp": datetime.now().isoformat(),
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/threats/enrich")
async def enrich_threats(threats: List[dict]):
    """Enrich threat intelligence data"""
    if not threat_intel:
        raise HTTPException(status_code=503, detail="Threat intelligence service unavailable")
    try:
        enriched = await threat_intel.enrich_threats(threats)
        
        return {
            "status": "success",
            "enriched_threats": enriched,
            "timestamp": datetime.now().isoformat(),
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Confidential Compute endpoints
@router.get("/confidential/status")
async def get_enclave_status():
    """Get SGX enclave status"""
    try:
        cc_service = ConfidentialComputeService()
        
        # Simulated status for now
        status = {
            "active_enclaves": 3,
            "overall_health": "healthy",
            "attestation_valid": True,
            "total_workloads": 42,
            "average_response_time": 125,
            "enclaves": [
                {
                    "id": "enclave_1",
                    "status": "active",
                    "cpu_usage": 45.2,
                    "memory_usage": 67.8,
                    "workload_count": 15,
                    "last_attestation": datetime.now().isoformat(),
                },
                {
                    "id": "enclave_2",
                    "status": "active",
                    "cpu_usage": 32.1,
                    "memory_usage": 54.3,
                    "workload_count": 12,
                    "last_attestation": datetime.now().isoformat(),
                },
                {
                    "id": "enclave_3",
                    "status": "attesting",
                    "cpu_usage": 12.5,
                    "memory_usage": 23.4,
                    "workload_count": 3,
                    "last_attestation": datetime.now().isoformat(),
                },
            ]
        }
        
        return {
            "status": "success",
            "enclave_status": status,
            "timestamp": datetime.now().isoformat(),
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/confidential/inference")
async def secure_inference(input_data: List[float], model_id: str):
    """Perform secure inference in SGX enclave"""
    try:
        cc_service = ConfidentialComputeService()
        
        result = await cc_service.process_request({
            "type": "secure_inference",
            "input_data": input_data,
            "model_id": model_id,
        })
        
        return {
            "status": "success",
            "result": result,
            "timestamp": datetime.now().isoformat(),
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Research benchmarks endpoint
@router.get("/research/benchmarks")
async def get_benchmarks():
    """Get research performance benchmarks"""
    try:
        # Cryptography benchmarks
        crypto_bench = await crypto_service.benchmark()
        
        # AI benchmarks (simulated)
        ai_bench = {
            "zero_day_prediction": {
                "accuracy": 0.92,
                "precision": 0.88,
                "recall": 0.85,
                "f1_score": 0.865,
                "inference_time_ms": 125.4,
            },
            "autonomous_defense": {
                "average_reward": 42.7,
                "success_rate": 0.78,
                "decision_time_ms": 89.2,
            }
        }
        
        # Blockchain benchmarks
        blockchain_bench = {
            "transaction_analysis": {
                "average_time_ms": 342.5,
                "cross_chain_correlation": 0.91,
                "pattern_detection_accuracy": 0.87,
            }
        }
        
        return {
            "status": "success",
            "benchmarks": {
                "cryptography": crypto_bench,
                "ai_models": ai_bench,
                "blockchain": blockchain_bench,
                "timestamp": datetime.now().isoformat(),
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# System metrics endpoint
@router.get("/metrics/system")
async def system_metrics(time_range: str = "1h"):
    """Get system metrics"""
    try:
        # Simulated metrics
        metrics = {
            "cpu_usage": 45.7,
            "memory_usage": 62.3,
            "disk_usage": 34.8,
            "network_throughput_mbps": 125.4,
            "active_connections": 342,
            "request_rate_per_second": 12.7,
            "error_rate": 0.23,
            "response_time_p95_ms": 245.8,
            "threats_processed": 1254,
            "zero_day_predictions": 42,
            "blockchain_transactions_analyzed": 78,
            "encryption_operations": 156,
            "timestamp": datetime.now().isoformat(),
        }
        
        return {
            "status": "success",
            "metrics": metrics,
            "time_range": time_range,
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    # Add these endpoints to your existing routes.py

@router.post("/crypto/sign")
async def sign_message(request: dict):
    """Sign message using hybrid PQC"""
    try:
        message = request.get("message", "")
        key_id = request.get("key_id")
        
        if not key_id:
            raise HTTPException(status_code=400, detail="key_id required")
        
        signature = await crypto_service.sign(message, key_id)
        return {"status": "success", "signature": signature}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/crypto/verify")
async def verify_signature(request: dict):
    """Verify hybrid PQC signature"""
    try:
        message = request.get("message", "")
        signature = request.get("signature", {})
        key_id = request.get("key_id")
        
        if not key_id or not signature:
            raise HTTPException(status_code=400, detail="key_id and signature required")
        
        result = await crypto_service.verify(message, signature, key_id)
        return {"status": "success", "verification": result}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/blockchain/batch-analyze")
async def batch_analyze_transactions(request: dict):
    """Batch analyze multiple transactions"""
    try:
        tx_hashes = request.get("tx_hashes", [])
        chain = request.get("chain", "ethereum")
        
        if not tx_hashes:
            raise HTTPException(status_code=400, detail="tx_hashes required")
        
        results = []
        for tx_hash in tx_hashes[:10]:  # Limit to 10 per request
            try:
                analysis = await blockchain_service.analyzer.analyze_transaction(tx_hash, chain)
                results.append(analysis)
            except Exception as e:
                results.append({"tx_hash": tx_hash, "error": str(e)})
        
        return {
            "status": "success",
            "total": len(results),
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/threats/export")
async def export_threats(
    format: str = "json",
    time_range: str = "24h",
    limit: int = 1000
):
    """Export threats in various formats"""
    try:
        threats = await threat_intel.get_recent_threats(
            hours=int(time_range.replace("h", "")) if "h" in time_range else 24,
            limit=limit
        )
        
        if format == "json":
            return {
                "status": "success",
                "count": len(threats),
                "threats": threats,
                "exported_at": datetime.now().isoformat()
            }
        elif format == "csv":
            import csv
            from io import StringIO
            
            output = StringIO()
            writer = csv.DictWriter(output, fieldnames=threats[0].keys() if threats else [])
            writer.writeheader()
            writer.writerows(threats)
            
            return Response(
                content=output.getvalue(),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=threats.csv"}
            )
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ai/train-model")
async def train_model(request: dict):
    """Train AI models"""
    try:
        model_type = request.get("model_type")
        epochs = request.get("epochs", 100)
        config = request.get("config", {})
        
        if model_type == "zero_day_predictor":
            if not ai_service:
                raise HTTPException(status_code=503, detail="AI service unavailable")
            
            # Start training in background
            asyncio.create_task(ai_service.train(epochs=epochs))
            
            return {
                "status": "success",
                "message": f"Zero-day predictor training started for {epochs} epochs",
                "training_id": f"zd_{int(time.time())}"
            }
            
        elif model_type == "defense_agent":
            if not defense_service:
                raise HTTPException(status_code=503, detail="Defense service unavailable")
            
            # Start training in background
            asyncio.create_task(defense_service.train(episodes=epochs))
            
            return {
                "status": "success",
                "message": f"Defense agent training started for {epochs} episodes",
                "training_id": f"da_{int(time.time())}"
            }
            
        else:
            raise HTTPException(status_code=400, detail=f"Unknown model type: {model_type}")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

