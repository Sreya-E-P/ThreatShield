# C:\Users\LENOVO\Desktop\threatshield-project\backend\src\config\config.py
"""
Central configuration management using .env
"""

import os
from pathlib import Path
from typing import List, Optional
from dotenv import load_dotenv

# Load .env file from project root
env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

class Config:
    """Central configuration class"""
    
    # ============================================
    # APPLICATION CONFIGURATION
    # ============================================
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    DEBUG = os.getenv("DEBUG", "true").lower() == "true"
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    API_PREFIX = os.getenv("API_PREFIX", "/api/v1")
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
    
    # Parse CORS_ORIGINS - handle both string and list
    cors_origins_env = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:8000")
    if isinstance(cors_origins_env, str):
        CORS_ORIGINS = [origin.strip() for origin in cors_origins_env.split(",")]
    else:
        CORS_ORIGINS = cors_origins_env
    
    # ============================================
    # DATABASE CONFIGURATION
    # ============================================
    DATABASE_URL = os.getenv("DATABASE_URL")
    POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
    
    # ============================================
    # REDIS CONFIGURATION
    # ============================================
    REDIS_URL = os.getenv("REDIS_URL")
    REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
    
    # ============================================
    # SECURITY & AUTHENTICATION
    # ============================================
    JWT_SECRET = os.getenv("JWT_SECRET")
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))
    REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    
    # ============================================
    # THREAT INTELLIGENCE APIS
    # ============================================
    MISP_URL = os.getenv("MISP_URL")
    MISP_API_KEY = os.getenv("MISP_API_KEY")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    OTX_API_KEY = os.getenv("OTX_API_KEY")
    
    # ============================================
    # BLOCKCHAIN ANALYSIS APIS
    # ============================================
    ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
    MORALIS_API_KEY = os.getenv("MORALIS_API_KEY")
    ALCHEMY_API_KEY = os.getenv("ALCHEMY_API_KEY")
    INFURA_API_KEY = os.getenv("INFURA_API_KEY")
    INFURA_API_SECRET = os.getenv("INFURA_API_SECRET")
    
    # ============================================
    # AZURE CLOUD SERVICES
    # ============================================
    AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
    AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
    AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
    AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")
    AZURE_RESOURCE_GROUP = os.getenv("AZURE_RESOURCE_GROUP")
    AZURE_ATTESTATION_ENDPOINT = os.getenv("AZURE_ATTESTATION_ENDPOINT")
    
    # ============================================
    # PERFORMANCE CONFIGURATION
    # ============================================
    MODEL_CACHE_DIR = os.getenv("MODEL_CACHE_DIR", "./models")
    KEY_CACHE_SIZE = int(os.getenv("KEY_CACHE_SIZE", "1000"))
    MAX_WORKERS = int(os.getenv("MAX_WORKERS", "4"))
    REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
    
    # ============================================
    # PQC (Post-Quantum Cryptography) SETTINGS
    # ============================================
    PQC_SECURITY_LEVEL = os.getenv("PQC_SECURITY_LEVEL", "high")
    USE_PQC = os.getenv("USE_PQC", "true").lower() == "true"
    KEY_ROTATION_DAYS = int(os.getenv("KEY_ROTATION_DAYS", "30"))
    KEY_STORAGE_PATH = os.getenv("KEY_STORAGE_PATH", "./keys")
    KEY_MAX_USAGE = int(os.getenv("KEY_MAX_USAGE", "10000"))

# Create global config instance
config = Config()