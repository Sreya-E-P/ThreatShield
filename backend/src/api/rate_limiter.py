import time
import hashlib
from typing import Dict, Tuple
from collections import defaultdict
from fastapi import Request

class RateLimiter:
    def __init__(self, redis_url: str = None):
        self.redis = None
        self.memory_requests: Dict[str, list] = defaultdict(list)
    
    async def check_rate_limit(self, key: str, limit: int, window: int, request: Request = None) -> Tuple[bool, int]:
        if request:
            client_ip = request.client.host if request.client else "unknown"
            user_agent = request.headers.get("user-agent", "")[:50]
            key = hashlib.md5(f"{key}:{client_ip}:{user_agent}".encode()).hexdigest()
        
        now = time.time()
        self.memory_requests[key] = [ts for ts in self.memory_requests[key] if now - ts < window]
        current = len(self.memory_requests[key])
        
        if current >= limit:
            return False, 0
        
        self.memory_requests[key].append(now)
        return True, limit - (current + 1)

public_limiter = RateLimiter()
authenticated_limiter = RateLimiter()

RATE_LIMITS = {
    "public": {"limit": 100, "window": 60},
    "authenticated": {"limit": 1000, "window": 60},
    "threat_analysis": {"limit": 50, "window": 60},
    "blockchain": {"limit": 30, "window": 60},
    "crypto": {"limit": 200, "window": 60},
    "training": {"limit": 5, "window": 3600},
}