from prometheus_client import Counter, Histogram, Gauge, generate_latest
import time
from functools import wraps
from typing import Callable, Any

# ============================================
# APPLICATION METRICS
# ============================================

# Threat metrics
THREATS_PROCESSED = Counter(
    'threatshield_threats_processed_total', 
    'Total threats processed',
    ['source', 'severity']
)

THREAT_PROCESSING_TIME = Histogram(
    'threatshield_threat_processing_seconds',
    'Time spent processing threats',
    ['threat_type']
)

# AI metrics
AI_PREDICTIONS = Counter(
    'threatshield_ai_predictions_total',
    'Total AI predictions made',
    ['model', 'result']
)

AI_TRAINING_TIME = Histogram(
    'threatshield_ai_training_seconds',
    'Time spent training AI models',
    ['model']
)

# Crypto metrics
ENCRYPTION_OPERATIONS = Counter(
    'threatshield_encryption_operations_total',
    'Total encryption/decryption operations',
    ['operation', 'algorithm']
)

KEY_GENERATIONS = Counter(
    'threatshield_key_generations_total',
    'Total cryptographic keys generated',
    ['algorithm']
)

# Blockchain metrics
BLOCKCHAIN_ANALYSIS = Counter(
    'threatshield_blockchain_analysis_total',
    'Total blockchain analyses',
    ['chain', 'analysis_type']
)

BLOCKCHAIN_QUERY_TIME = Histogram(
    'threatshield_blockchain_query_seconds',
    'Time spent querying blockchain',
    ['chain']
)

# Enclave metrics
ENCLAVE_REQUESTS = Counter(
    'threatshield_enclave_requests_total',
    'Total enclave requests',
    ['operation', 'status']
)

ENCLAVE_ACTIVE = Gauge(
    'threatshield_enclave_active',
    'Number of active enclaves'
)

# System metrics
SYSTEM_CPU_USAGE = Gauge(
    'threatshield_system_cpu_usage',
    'System CPU usage percentage'
)

SYSTEM_MEMORY_USAGE = Gauge(
    'threatshield_system_memory_usage',
    'System memory usage percentage'
)

ACTIVE_CONNECTIONS = Gauge(
    'threatshield_active_connections',
    'Number of active connections'
)

REQUEST_RATE = Gauge(
    'threatshield_request_rate',
    'Request rate per second'
)

# ============================================
# DECORATORS FOR METRICS TRACKING
# ============================================

def track_threat_processing(source: str = "unknown", severity: str = "unknown"):
    """Decorator to track threat processing"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            THREATS_PROCESSED.labels(source=source, severity=severity).inc()
            try:
                result = await func(*args, **kwargs)
                threat_type = result.get('type', 'unknown') if result else 'unknown'
                THREAT_PROCESSING_TIME.labels(threat_type=threat_type).observe(time.time() - start_time)
                return result
            except Exception as e:
                # Track failures
                raise e
        return wrapper
    return decorator

def track_ai_prediction(model: str = "unknown"):
    """Decorator to track AI predictions"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                AI_PREDICTIONS.labels(model=model, result="success").inc()
                return result
            except Exception as e:
                AI_PREDICTIONS.labels(model=model, result="failure").inc()
                raise e
            finally:
                AI_TRAINING_TIME.labels(model=model).observe(time.time() - start_time)
        return wrapper
    return decorator

def track_crypto_operation(operation: str, algorithm: str = "hybrid_pqc"):
    """Decorator to track crypto operations"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            ENCRYPTION_OPERATIONS.labels(operation=operation, algorithm=algorithm).inc()
            return await func(*args, **kwargs)
        return wrapper
    return decorator

def track_blockchain_analysis(chain: str, analysis_type: str):
    """Decorator to track blockchain analysis"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            BLOCKCHAIN_ANALYSIS.labels(chain=chain, analysis_type=analysis_type).inc()
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                BLOCKCHAIN_QUERY_TIME.labels(chain=chain).observe(time.time() - start_time)
        return wrapper
    return decorator

def track_enclave_request(operation: str):
    """Decorator to track enclave requests"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                result = await func(*args, **kwargs)
                ENCLAVE_REQUESTS.labels(operation=operation, status="success").inc()
                return result
            except Exception as e:
                ENCLAVE_REQUESTS.labels(operation=operation, status="failure").inc()
                raise e
        return wrapper
    return decorator

# ============================================
# METRICS COLLECTION FUNCTIONS
# ============================================

def update_system_metrics():
    """Update system metrics (call periodically)"""
    import psutil
    
    # CPU usage
    cpu_percent = psutil.cpu_percent(interval=1)
    SYSTEM_CPU_USAGE.set(cpu_percent)
    
    # Memory usage
    memory = psutil.virtual_memory()
    SYSTEM_MEMORY_USAGE.set(memory.percent)

def get_metrics():
    """Get all metrics in Prometheus format"""
    return generate_latest()