# C:\Users\LENOVO\Desktop\threatshield-project\backend\src\ts_crypto\key_manager.py
"""
Production key management system for hybrid PQC
"""

import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import base64
import hashlib
import secrets
import asyncio
from pathlib import Path
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# 1. Official Library Imports
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# 2. Your Local Project Imports
from ts_crypto.hybrid_pqc import HybridPQC, HybridKeyPair

logger = logging.getLogger(__name__)

@dataclass
class KeyMetadata:
    """Metadata for key management"""
    key_id: str
    key_type: str
    algorithm: str
    created_at: datetime
    expires_at: datetime
    last_used: Optional[datetime] = None
    usage_count: int = 0
    rotation_count: int = 0
    tags: Dict[str, str] = None
    enabled: bool = True

class KeyManager:
    """Production key management system"""
    
    def __init__(self, storage_path: str = "./keys", security_level: str = "high"):
        # Get from environment
        self.storage_path = Path(os.getenv("KEY_STORAGE_PATH", storage_path))
        self.storage_path.mkdir(exist_ok=True, parents=True)
        
        self.security_level = os.getenv("PQC_SECURITY_LEVEL", security_level)
        self.crypto = HybridPQC(security_level=self.security_level)
        
        # Key rotation policy
        self.rotation_days = int(os.getenv("KEY_ROTATION_DAYS", "30"))
        self.max_usage_count = int(os.getenv("KEY_MAX_USAGE", "10000"))
        
        # Cache for performance
        self.key_cache = {}
        self.max_cache_size = int(os.getenv("KEY_CACHE_SIZE", "1000"))
        
        self.keys: Dict[str, HybridKeyPair] = {}
        self.metadata: Dict[str, KeyMetadata] = {}
        
        # Load existing keys
        self._load_keys()
        
        # Start background tasks
        asyncio.create_task(self._key_rotation_task())
        asyncio.create_task(self._key_expiry_check_task())
    
    def _load_keys(self):
        """Load keys from storage"""
        try:
            keys_file = self.storage_path / "keys.json"
            if keys_file.exists():
                with open(keys_file, 'r') as f:
                    data = json.load(f)
                
                for key_id, key_data in data.get("keys", {}).items():
                    # Convert string dates back to datetime
                    key_data["created_at"] = datetime.fromisoformat(key_data["created_at"])
                    key_data["expires_at"] = datetime.fromisoformat(key_data["expires_at"])
                    if key_data.get("last_used"):
                        key_data["last_used"] = datetime.fromisoformat(key_data["last_used"])
                    
                    # Recreate key objects
                    keypair = HybridKeyPair(
                        pq_public=base64.b64decode(key_data["pq_public"]),
                        pq_private=base64.b64decode(key_data["pq_private"]),
                        classical_public=base64.b64decode(key_data["classical_public"]),
                        classical_private=base64.b64decode(key_data["classical_private"]),
                        key_id=key_data["key_id"],
                        created_at=key_data["created_at"],
                        expires_at=key_data["expires_at"],
                        algorithm=key_data["algorithm"]
                    )
                    
                    self.keys[key_id] = keypair
                    
                    # Create metadata
                    metadata_data = key_data.get("metadata", {})
                    metadata_data["created_at"] = datetime.fromisoformat(metadata_data["created_at"])
                    metadata_data["expires_at"] = datetime.fromisoformat(metadata_data["expires_at"])
                    if metadata_data.get("last_used"):
                        metadata_data["last_used"] = datetime.fromisoformat(metadata_data["last_used"])
                    
                    self.metadata[key_id] = KeyMetadata(**metadata_data)
                
                logger.info(f"Loaded {len(self.keys)} keys from storage")
                
        except Exception as e:
            logger.error(f"Failed to load keys: {e}")
    
    def _save_keys(self):
        """Save keys to storage"""
        try:
            keys_file = self.storage_path / "keys.json"
            
            data = {
                "keys": {},
                "version": "1.0",
                "updated_at": datetime.now().isoformat()
            }
            
            for key_id, keypair in self.keys.items():
                metadata = self.metadata.get(key_id)
                if not metadata:
                    continue
                    
                key_data = {
                    "pq_public": base64.b64encode(keypair.pq_public).decode(),
                    "pq_private": base64.b64encode(keypair.pq_private).decode(),
                    "classical_public": base64.b64encode(keypair.classical_public).decode(),
                    "classical_private": base64.b64encode(keypair.classical_private).decode(),
                    "key_id": keypair.key_id,
                    "created_at": keypair.created_at.isoformat(),
                    "expires_at": keypair.expires_at.isoformat(),
                    "algorithm": keypair.algorithm,
                    "metadata": asdict(metadata)
                }
                data["keys"][key_id] = key_data
            
            with open(keys_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Backup keys
            backup_file = self.storage_path / f"keys_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(backup_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.debug(f"Saved {len(self.keys)} keys to storage")
            
        except Exception as e:
            logger.error(f"Failed to save keys: {e}")
    
    async def generate_key(self, 
                          tags: Optional[Dict[str, str]] = None,
                          expires_in_days: int = 30) -> Dict[str, any]:
        """Generate new hybrid key pair"""
        try:
            # Generate key pair
            keypair = self.crypto.generate_keypair()
            
            # Update expiration
            keypair.expires_at = datetime.now() + timedelta(days=expires_in_days)
            
            # Create metadata
            metadata = KeyMetadata(
                key_id=keypair.key_id,
                key_type="hybrid_pqc",
                algorithm=keypair.algorithm,
                created_at=keypair.created_at,
                expires_at=keypair.expires_at,
                tags=tags or {},
                enabled=True
            )
            
            # Store key
            self.keys[keypair.key_id] = keypair
            self.metadata[keypair.key_id] = metadata
            
            # Save to storage
            self._save_keys()
            
            logger.info(f"Generated new key: {keypair.key_id}")
            
            return {
                "key_id": keypair.key_id,
                "public_key": {
                    "pq": base64.b64encode(keypair.pq_public).decode(),
                    "classical": base64.b64encode(keypair.classical_public).decode(),
                },
                "algorithm": keypair.algorithm,
                "created_at": keypair.created_at.isoformat(),
                "expires_at": keypair.expires_at.isoformat(),
                "tags": tags or {},
            }
            
        except Exception as e:
            logger.error(f"Failed to generate key: {e}")
            raise
    
    async def get_key(self, key_id: str, increment_usage: bool = True) -> Optional[HybridKeyPair]:
        """Get key by ID"""
        if key_id not in self.keys:
            logger.warning(f"Key not found: {key_id}")
            return None
        
        keypair = self.keys[key_id]
        metadata = self.metadata.get(key_id)
        
        if not metadata:
            logger.warning(f"Metadata not found for key: {key_id}")
            return None
        
        # Check if key is enabled
        if not metadata.enabled:
            logger.warning(f"Key is disabled: {key_id}")
            return None
        
        # Check if key is expired
        if metadata.expires_at < datetime.now():
            logger.warning(f"Key is expired: {key_id}")
            await self.disable_key(key_id, "expired")
            return None
        
        # Update usage
        if increment_usage:
            metadata.last_used = datetime.now()
            metadata.usage_count += 1
            
            # Check if key needs rotation
            if metadata.usage_count >= self.max_usage_count:
                logger.info(f"Key reached max usage: {key_id}")
                asyncio.create_task(self.rotate_key(key_id))
        
        return keypair
    
    async def rotate_key(self, key_id: str) -> str:
        """Rotate key (generate new key, disable old)"""
        try:
            if key_id not in self.keys:
                raise ValueError(f"Key not found: {key_id}")
            
            # Get old key metadata
            old_metadata = self.metadata[key_id]
            
            # Generate new key with same tags
            new_key = await self.generate_key(
                tags=old_metadata.tags,
                expires_in_days=self.rotation_days
            )
            
            # Update old key metadata
            old_metadata.rotation_count += 1
            old_metadata.enabled = False
            
            # Add rotation reference
            if "rotated_to" not in old_metadata.tags:
                old_metadata.tags["rotated_to"] = new_key["key_id"]
            
            # Save changes
            self._save_keys()
            
            logger.info(f"Rotated key {key_id} -> {new_key['key_id']}")
            
            return new_key["key_id"]
            
        except Exception as e:
            logger.error(f"Failed to rotate key {key_id}: {e}")
            raise
    
    async def disable_key(self, key_id: str, reason: str = "manual"):
        """Disable key"""
        if key_id in self.metadata:
            self.metadata[key_id].enabled = False
            if "disabled_reason" not in self.metadata[key_id].tags:
                self.metadata[key_id].tags["disabled_reason"] = reason
            
            self._save_keys()
            logger.info(f"Disabled key {key_id}: {reason}")
    
    async def enable_key(self, key_id: str):
        """Enable key"""
        if key_id in self.metadata:
            self.metadata[key_id].enabled = True
            self._save_keys()
            logger.info(f"Enabled key {key_id}")
    
    async def delete_key(self, key_id: str):
        """Delete key (with backup)"""
        try:
            if key_id in self.keys:
                # Create backup before deletion
                backup_data = {
                    "key": {
                        "pq_public": base64.b64encode(self.keys[key_id].pq_public).decode(),
                        "pq_private": base64.b64encode(self.keys[key_id].pq_private).decode(),
                        "classical_public": base64.b64encode(self.keys[key_id].classical_public).decode(),
                        "classical_private": base64.b64encode(self.keys[key_id].classical_private).decode(),
                    },
                    "metadata": asdict(self.metadata[key_id]),
                    "deleted_at": datetime.now().isoformat()
                }
                
                # Save backup
                backup_file = self.storage_path / f"deleted_{key_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(backup_file, 'w') as f:
                    json.dump(backup_data, f, indent=2)
                
                # Remove from memory
                del self.keys[key_id]
                del self.metadata[key_id]
                
                # Save changes
                self._save_keys()
                
                logger.info(f"Deleted key {key_id} (backup saved)")
                
        except Exception as e:
            logger.error(f"Failed to delete key {key_id}: {e}")
            raise
    
    async def list_keys(self, 
                       enabled_only: bool = True,
                       expired_only: bool = False) -> List[Dict]:
        """List all keys with filtering"""
        keys_list = []
        
        for key_id, metadata in self.metadata.items():
            if enabled_only and not metadata.enabled:
                continue
            
            if expired_only and metadata.expires_at >= datetime.now():
                continue
            
            key_info = {
                "key_id": key_id,
                "key_type": metadata.key_type,
                "algorithm": metadata.algorithm,
                "created_at": metadata.created_at.isoformat(),
                "expires_at": metadata.expires_at.isoformat(),
                "last_used": metadata.last_used.isoformat() if metadata.last_used else None,
                "usage_count": metadata.usage_count,
                "rotation_count": metadata.rotation_count,
                "enabled": metadata.enabled,
                "tags": metadata.tags,
            }
            
            keys_list.append(key_info)
        
        return keys_list
    
    async def get_key_statistics(self) -> Dict:
        """Get key management statistics"""
        total_keys = len(self.keys)
        enabled_keys = sum(1 for m in self.metadata.values() if m.enabled)
        expired_keys = sum(1 for m in self.metadata.values() if m.expires_at < datetime.now())
        
        return {
            "total_keys": total_keys,
            "enabled_keys": enabled_keys,
            "disabled_keys": total_keys - enabled_keys,
            "expired_keys": expired_keys,
            "rotation_count_total": sum(m.rotation_count for m in self.metadata.values()),
            "usage_count_total": sum(m.usage_count for m in self.metadata.values()),
            "keys_expiring_soon": sum(1 for m in self.metadata.values() 
                                    if m.expires_at < datetime.now() + timedelta(days=7)),
        }
    
    async def _key_rotation_task(self):
        """Background task for automatic key rotation"""
        while True:
            try:
                now = datetime.now()
                
                for key_id, metadata in self.metadata.items():
                    if not metadata.enabled:
                        continue
                    
                    # Rotate if near expiration
                    days_until_expiry = (metadata.expires_at - now).days
                    if 0 < days_until_expiry <= 3:  # Rotate 3 days before expiry
                        logger.info(f"Auto-rotating key {key_id} (expires in {days_until_expiry} days)")
                        await self.rotate_key(key_id)
                
                await asyncio.sleep(3600)  # Check every hour
                
            except Exception as e:
                logger.error(f"Key rotation task failed: {e}")
                await asyncio.sleep(300)
    
    async def _key_expiry_check_task(self):
        """Background task for key expiry checks"""
        while True:
            try:
                now = datetime.now()
                expired_keys = []
                
                for key_id, metadata in self.metadata.items():
                    if metadata.enabled and metadata.expires_at < now:
                        expired_keys.append(key_id)
                
                if expired_keys:
                    logger.warning(f"Found {len(expired_keys)} expired keys")
                    for key_id in expired_keys:
                        await self.disable_key(key_id, "expired")
                
                await asyncio.sleep(1800)  # Check every 30 minutes
                
            except Exception as e:
                logger.error(f"Key expiry check failed: {e}")
                await asyncio.sleep(300)
    
    async def export_key(self, key_id: str, password: Optional[str] = None) -> Dict:
        """Export key for backup (encrypted if password provided)"""
        try:
            keypair = await self.get_key(key_id, increment_usage=False)
            if not keypair:
                raise ValueError(f"Key not found: {key_id}")
            
            metadata = self.metadata.get(key_id)
            if not metadata:
                raise ValueError(f"Metadata not found for key: {key_id}")
            
            export_data = {
                "key_id": keypair.key_id,
                "algorithm": keypair.algorithm,
                "created_at": keypair.created_at.isoformat(),
                "expires_at": keypair.expires_at.isoformat(),
                "public_key": {
                    "pq": base64.b64encode(keypair.pq_public).decode(),
                    "classical": base64.b64encode(keypair.classical_public).decode(),
                },
                "private_key": {
                    "pq": base64.b64encode(keypair.pq_private).decode(),
                    "classical": base64.b64encode(keypair.classical_private).decode(),
                },
                "metadata": asdict(metadata),
            }
            
            # Encrypt if password provided
            if password:
                from cryptography.fernet import Fernet
                
                # Derive key from password
                key = hashlib.sha256(password.encode()).digest()
                fernet = Fernet(base64.urlsafe_b64encode(key))
                
                encrypted = fernet.encrypt(json.dumps(export_data).encode())
                export_data = {
                    "encrypted": True,
                    "data": base64.b64encode(encrypted).decode(),
                }
            
            return export_data
            
        except Exception as e:
            logger.error(f"Failed to export key {key_id}: {e}")
            raise
    
    async def import_key(self, import_data: Dict, password: Optional[str] = None) -> str:
        """Import key from backup"""
        try:
            # Decrypt if password provided
            if password and import_data.get("encrypted"):
                from cryptography.fernet import Fernet
                
                key = hashlib.sha256(password.encode()).digest()
                fernet = Fernet(base64.urlsafe_b64encode(key))
                
                decrypted = fernet.decrypt(base64.b64decode(import_data["data"]))
                import_data = json.loads(decrypted.decode())
            
            # Recreate key pair
            keypair = HybridKeyPair(
                pq_public=base64.b64decode(import_data["public_key"]["pq"]),
                pq_private=base64.b64decode(import_data["private_key"]["pq"]),
                classical_public=base64.b64decode(import_data["public_key"]["classical"]),
                classical_private=base64.b64decode(import_data["private_key"]["classical"]),
                key_id=import_data["key_id"],
                created_at=datetime.fromisoformat(import_data["created_at"]),
                expires_at=datetime.fromisoformat(import_data["expires_at"]),
                algorithm=import_data["algorithm"]
            )
            
            # Create metadata
            metadata_data = import_data["metadata"]
            metadata_data["created_at"] = datetime.fromisoformat(metadata_data["created_at"])
            metadata_data["expires_at"] = datetime.fromisoformat(metadata_data["expires_at"])
            if metadata_data.get("last_used"):
                metadata_data["last_used"] = datetime.fromisoformat(metadata_data["last_used"])
            
            metadata = KeyMetadata(**metadata_data)
            
            # Store key
            self.keys[keypair.key_id] = keypair
            self.metadata[keypair.key_id] = metadata
            
            # Save
            self._save_keys()
            
            logger.info(f"Imported key: {keypair.key_id}")
            
            return keypair.key_id
            
        except Exception as e:
            logger.error(f"Failed to import key: {e}")
            raise

# Global key manager instance
key_manager = KeyManager()