# config/settings.py
from pydantic_settings import BaseSettings
from typing import Optional, List
from enum import Enum
from pydantic import Field

class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

class DatabaseSettings(BaseSettings):
    url: str = Field(default="postgresql+asyncpg://threatshield:password@localhost/threatshield", validation_alias="DATABASE_URL")
    postgres_password: Optional[str] = Field(default=None, validation_alias="POSTGRES_PASSWORD")
    pool_size: int = 20
    max_overflow: int = 40
    pool_pre_ping: bool = True
    echo: bool = False

class CryptoSettings(BaseSettings):
    pqc_algorithm: str = "Kyber1024"
    hybrid_mode: bool = True
    key_cache_size: int = 1000
    key_rotation_days: int = 30

class AISettings(BaseSettings):
    zero_day_threshold: float = 0.7
    gnn_hidden_dim: int = 256
    rl_learning_rate: float = 0.001
    model_cache_dir: str = Field(default="./models", validation_alias="MODEL_CACHE_DIR")

class BlockchainSettings(BaseSettings):
    etherscan_api_key: Optional[str] = Field(default=None, validation_alias="ETHERSCAN_API_KEY")
    moralis_api_key: Optional[str] = Field(default=None, validation_alias="MORALIS_API_KEY")
    alchemy_api_key: Optional[str] = Field(default=None, validation_alias="ALCHEMY_API_KEY")
    infura_api_key: Optional[str] = Field(default=None, validation_alias="INFURA_API_KEY")
    infura_api_secret: Optional[str] = Field(default=None, validation_alias="INFURA_API_SECRET")
    polygon_rpc: str = "https://polygon-mainnet.g.alchemy.com/v2/demo"
    ethereum_rpc: str = "https://eth-mainnet.g.alchemy.com/v2/demo"
    bsc_rpc: str = "https://bsc-dataseed1.binance.org"

class ThreatIntelSettings(BaseSettings):
    misp_url: Optional[str] = Field(default=None, validation_alias="MISP_URL")
    misp_api_key: Optional[str] = Field(default=None, validation_alias="MISP_API_KEY")
    virustotal_api_key: Optional[str] = Field(default=None, validation_alias="VIRUSTOTAL_API_KEY")
    otx_api_key: Optional[str] = Field(default=None, validation_alias="OTX_API_KEY")
    update_interval_minutes: int = 5

class AzureSettings(BaseSettings):
    client_id: Optional[str] = Field(default=None, validation_alias="AZURE_CLIENT_ID")
    client_secret: Optional[str] = Field(default=None, validation_alias="AZURE_CLIENT_SECRET")
    tenant_id: Optional[str] = Field(default=None, validation_alias="AZURE_TENANT_ID")
    subscription_id: Optional[str] = Field(default=None, validation_alias="AZURE_SUBSCRIPTION_ID")
    resource_group: Optional[str] = Field(default=None, validation_alias="AZURE_RESOURCE_GROUP")
    attestation_endpoint: Optional[str] = Field(default=None, validation_alias="AZURE_ATTESTATION_ENDPOINT")

class SecuritySettings(BaseSettings):
    jwt_secret: str = Field(default="secret", validation_alias="JWT_SECRET")
    jwt_algorithm: str = Field(default="HS256", validation_alias="JWT_ALGORITHM")
    jwt_expire_minutes: int = Field(default=30, validation_alias="JWT_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, validation_alias="REFRESH_TOKEN_EXPIRE_DAYS")
    cors_origins: List[str] = ["http://localhost:3000"]

class RedisSettings(BaseSettings):
    url: str = Field(default="redis://localhost:6379", validation_alias="REDIS_URL")
    password: Optional[str] = Field(default=None, validation_alias="REDIS_PASSWORD")
    cache_ttl: int = 300 

class Settings(BaseSettings):
    environment: Environment = Field(default=Environment.DEVELOPMENT, validation_alias="ENVIRONMENT")
    debug: bool = Field(default=False, validation_alias="DEBUG")
    log_level: str = Field(default="INFO", validation_alias="LOG_LEVEL")
    api_prefix: str = Field(default="/api/v1", validation_alias="API_PREFIX")
    
    api_port: int = 8000
    websocket_port: int = 8001
    
    frontend_url: str = Field(default="http://localhost:3000", validation_alias="FRONTEND_URL")
    api_url: str = "http://localhost:8000"
    
    # Nested Service configurations
    database: DatabaseSettings = DatabaseSettings()
    crypto: CryptoSettings = CryptoSettings()
    ai: AISettings = AISettings()
    blockchain: BlockchainSettings = BlockchainSettings()
    threat_intel: ThreatIntelSettings = ThreatIntelSettings()
    azure: AzureSettings = AzureSettings()
    security: SecuritySettings = SecuritySettings()
    redis: RedisSettings = RedisSettings()

    # Performance Tuning
    max_workers: int = Field(default=4, validation_alias="MAX_WORKERS")
    request_timeout: int = Field(default=30, validation_alias="REQUEST_TIMEOUT")
    
    class Config:
        env_file = ".env"
        # This is the magic line that prevents the "Extra inputs" error
        extra = "ignore" 
        # Case sensitive can be set to False to be more forgiving
        case_sensitive = False

# Global settings instance
settings = Settings()