# backend/src/api/middleware.py
import time
import json
import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from typing import Callable, Dict, Any
import uuid

logger = structlog.get_logger()

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable):
        request_id = str(uuid.uuid4())
        
        # Log request
        logger.info(
            "request_started",
            request_id=request_id,
            method=request.method,
            url=str(request.url),
            client_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        
        start_time = time.time()
        
        try:
            response = await call_next(request)
            process_time = time.time() - start_time
            
            # Log response
            logger.info(
                "request_completed",
                request_id=request_id,
                method=request.method,
                url=str(request.url),
                status_code=response.status_code,
                duration_ms=process_time * 1000,
            )
            
            # Add custom headers
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Process-Time"] = str(process_time)
            
            return response
            
        except Exception as e:
            process_time = time.time() - start_time
            logger.error(
                "request_failed",
                request_id=request_id,
                method=request.method,
                url=str(request.url),
                error=str(e),
                duration_ms=process_time * 1000,
            )
            raise

class MetricsMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        from .main import REQUEST_COUNT, REQUEST_LATENCY
        self.request_count = REQUEST_COUNT
        self.request_latency = REQUEST_LATENCY
    
    async def dispatch(self, request: Request, call_next: Callable):
        start_time = time.time()
        
        # Skip metrics endpoint
        if request.url.path == "/metrics":
            return await call_next(request)
        
        try:
            response = await call_next(request)
            duration = time.time() - start_time
            
            # Record metrics
            endpoint = request.url.path
            self.request_count.labels(
                method=request.method,
                endpoint=endpoint,
                status=response.status_code
            ).inc()
            
            self.request_latency.labels(
                method=request.method,
                endpoint=endpoint
            ).observe(duration)
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            endpoint = request.url.path
            self.request_count.labels(
                method=request.method,
                endpoint=endpoint,
                status=500
            ).inc()
            
            self.request_latency.labels(
                method=request.method,
                endpoint=endpoint
            ).observe(duration)
            
            raise

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, calls: int = 100, period: int = 60):
        super().__init__(app)
        self.calls = calls
        self.period = period
        self.requests: Dict[str, list] = {}
    
    async def dispatch(self, request: Request, call_next: Callable):
        client_ip = request.client.host if request.client else "unknown"
        
        # Clean old timestamps
        now = time.time()
        if client_ip in self.requests:
            self.requests[client_ip] = [
                ts for ts in self.requests[client_ip]
                if now - ts < self.period
            ]
        
        # Check rate limit
        if client_ip in self.requests:
            if len(self.requests[client_ip]) >= self.calls:
                return Response(
                    content=json.dumps({
                        "error": "Rate limit exceeded",
                        "retry_after": self.period
                    }),
                    status_code=429,
                    headers={"Retry-After": str(self.period)},
                )
        
        # Add current timestamp
        if client_ip not in self.requests:
            self.requests[client_ip] = []
        self.requests[client_ip].append(now)
        
        # Add headers
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.calls)
        response.headers["X-RateLimit-Remaining"] = str(
            self.calls - len(self.requests.get(client_ip, []))
        )
        response.headers["X-RateLimit-Reset"] = str(
            int(now + self.period)
        )
        
        return response