# C:\Users\LENOVO\Desktop\threatshield-project\backend\src\database\models.py
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float, JSON, Index
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class Threat(Base):
    __tablename__ = "threats"
    __table_args__ = (
        Index('idx_threats_timestamp', 'timestamp'),
        Index('idx_threats_severity', 'severity'),
        Index('idx_threats_type', 'type'),
    )
    
    id = Column(String, primary_key=True)
    type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    source = Column(String, nullable=False)
    risk_score = Column(Float, nullable=False)
    indicators = Column(JSON, default=list)
    metadata = Column(JSON, default=dict)
    enriched_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

class DefenseAction(Base):
    __tablename__ = "defense_actions"
    __table_args__ = (
        Index('idx_defense_timestamp', 'timestamp'),
        Index('idx_defense_threat', 'threat_id'),
    )
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    threat_id = Column(String, nullable=False)
    action = Column(String, nullable=False)
    effectiveness = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    executed_by = Column(String, nullable=False)  # 'ai' or 'human'
    success = Column(Boolean, default=True)
    details = Column(JSON, default=dict)

class BlockchainAnalysis(Base):
    __tablename__ = "blockchain_analyses"
    __table_args__ = (
        Index('idx_blockchain_timestamp', 'timestamp'),
        Index('idx_blockchain_address', 'address'),
    )
    
    id = Column(String, primary_key=True)
    address = Column(String, nullable=False)
    chain = Column(String, nullable=False)
    risk_score = Column(Float, nullable=False)
    findings = Column(JSON, default=list)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    report_data = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class CryptoKey(Base):
    __tablename__ = "crypto_keys"
    __table_args__ = (
        Index('idx_key_created', 'created_at'),
        Index('idx_key_expires', 'expires_at'),
    )
    
    key_id = Column(String, primary_key=True)
    algorithm = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    last_used = Column(DateTime, nullable=True)
    usage_count = Column(Integer, default=0)
    enabled = Column(Boolean, default=True)
    metadata = Column(JSON, default=dict)

class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        Index('idx_user_email', 'email'),
        Index('idx_user_created', 'created_at'),
    )
    
    id = Column(String, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    role = Column(String, default="user")
    permissions = Column(JSON, default=list)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)