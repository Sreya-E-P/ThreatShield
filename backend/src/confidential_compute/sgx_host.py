# backend/src/confidential_compute/sgx_host.py
"""
Production host application for SGX enclave management
"""

import os
import json
import base64
import asyncio
from typing import Dict, List, Optional
from datetime import datetime
import logging
import sgx
from azure.identity import DefaultAzureCredential
from azure.confidentialledger import ConfidentialLedgerClient
from azure.security.attestation import AttestationClient

logger = logging.getLogger(__name__)

class SGXEnclaveManager:
    """Production SGX enclave manager"""
    
    def __init__(self, enclave_path: str):
        self.enclave_path = enclave_path
        self.enclaves = {}
        self.attestation_cache = {}
        
        # Azure services
        self.credential = DefaultAzureCredential()
        
        # Initialize enclave
        self._init_enclave()
    
    def _init_enclave(self):
        """Initialize SGX enclave"""
        try:
            # Load enclave
            self.enclave = sgx.Enclave(
                self.enclave_path,
                debug=False,
                product_id=1,
                isv_svn=1
            )
            
            logger.info("SGX enclave initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize SGX enclave: {e}")
            raise
    
    async def create_enclave_instance(self, 
                                     instance_id: str,
                                     config: Dict) -> Dict:
        """Create and attest new enclave instance"""
        try:
            # Load enclave
            enclave = self.enclave.load()
            
            # Initialize
            result = enclave.initialize()
            if result != sgx.Status.SUCCESS:
                raise Exception(f"Enclave initialization failed: {result}")
            
            # Get local attestation report
            local_report = enclave.get_local_report()
            
            # Perform remote attestation with Azure
            attestation = await self._perform_remote_attestation(
                instance_id, local_report
            )
            
            # Store enclave instance
            self.enclaves[instance_id] = {
                'enclave': enclave,
                'created_at': datetime.now(),
                'attestation': attestation,
                'config': config,
                'status': 'ACTIVE'
            }
            
            # Record in confidential ledger
            await self._record_enclave_creation(instance_id, attestation)
            
            return {
                'instance_id': instance_id,
                'status': 'CREATED',
                'mr_enclave': base64.b64encode(attestation['mr_enclave']).decode(),
                'attestation_token': attestation['token']
            }
            
        except Exception as e:
            logger.error(f"Failed to create enclave instance: {e}")
            raise
    
    async def secure_inference(self,
                              instance_id: str,
                              input_data: List[float],
                              model_id: str) -> Dict:
        """Perform secure inference in enclave"""
        if instance_id not in self.enclaves:
            raise Exception(f"Enclave instance {instance_id} not found")
        
        enclave_info = self.enclaves[instance_id]
        
        try:
            # Verify attestation
            if not await self._verify_attestation(instance_id):
                raise Exception("Enclave attestation verification failed")
            
            # Prepare input
            input_bytes = self._float_array_to_bytes(input_data)
            
            # Encrypt input
            encrypted_input = await self._encrypt_for_enclave(input_bytes)
            
            # Call enclave
            output_buffer = bytearray(len(input_data) * 4)  # Float output
            
            result = enclave_info['enclave'].call(
                'ecall_secure_inference',
                encrypted_input, len(encrypted_input),
                output_buffer, len(output_buffer)
            )
            
            if result != sgx.Status.SUCCESS:
                raise Exception(f"Secure inference failed: {result}")
            
            # Decrypt output
            decrypted_output = await self._decrypt_from_enclave(output_buffer)
            output_data = self._bytes_to_float_array(decrypted_output)
            
            # Record inference
            await self._record_inference(instance_id, model_id, True)
            
            return {
                'success': True,
                'output': output_data,
                'instance_id': instance_id,
                'model_id': model_id,
                'timestamp': datetime.now().isoformat(),
                'attestation_valid': True
            }
            
        except Exception as e:
            logger.error(f"Secure inference failed: {e}")
            raise
    
    async def distributed_threat_verification(self,
                                            threat_data: Dict,
                                            peer_enclaves: List[str]) -> Dict:
        """Distributed threat verification using multiple enclaves"""
        try:
            # Serialize threat data
            threat_bytes = json.dumps(threat_data).encode('utf-8')
            
            # Send to primary enclave
            primary_instance = self._select_primary_enclave(peer_enclaves)
            
            verification_results = []
            
            for instance_id in peer_enclaves:
                if instance_id in self.enclaves:
                    enclave = self.enclaves[instance_id]['enclave']
                    
                    # Call distributed verification
                    result_buffer = bytearray(256)  # Result buffer
                    
                    result = enclave.call(
                        'ecall_distributed_verify_threat',
                        threat_bytes, len(threat_bytes),
                        result_buffer, len(result_buffer)
                    )
                    
                    if result == sgx.Status.SUCCESS:
                        result_data = json.loads(result_buffer.decode('utf-8').strip('\x00'))
                        verification_results.append(result_data)
            
            # Byzantine Fault Tolerant consensus
            consensus = self._bft_consensus(verification_results)
            
            return {
                'verified': consensus['verified'],
                'confidence': consensus['confidence'],
                'enclave_count': len(verification_results),
                'results': verification_results,
                'consensus_reached': consensus['reached'],
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Distributed verification failed: {e}")
            raise
    
    async def _perform_remote_attestation(self,
                                         instance_id: str,
                                         local_report: bytes) -> Dict:
        """Perform remote attestation with Azure Attestation Service"""
        try:
            client = AttestationClient(
                endpoint=os.getenv('AZURE_ATTESTATION_ENDPOINT'),
                credential=self.credential
            )
            
            # Get quote from enclave
            quote = self.enclave.get_quote(local_report)
            
            # Attest with Azure
            attestation_result = client.attest_sgx_enclave(
                quote=quote,
                runtime_data=b'threatshield-runtime',
                runtime_data_type='Binary'
            )
            
            if attestation_result.verification_result != 'Valid':
                raise Exception("Remote attestation failed")
            
            # Cache attestation
            attestation_data = {
                'token': attestation_result.token,
                'issued_at': datetime.now(),
                'expires_at': datetime.now() + timedelta(hours=24),
                'mr_enclave': attestation_result.sgx_metadata.get('mr_enclave'),
                'mr_signer': attestation_result.sgx_metadata.get('mr_signer'),
                'verification_result': 'Valid'
            }
            
            self.attestation_cache[instance_id] = attestation_data
            
            logger.info(f"Enclave {instance_id} attested successfully")
            
            return attestation_data
            
        except Exception as e:
            logger.error(f"Remote attestation failed: {e}")
            raise
    
    def _bft_consensus(self, results: List[Dict]) -> Dict:
        """Byzantine Fault Tolerant consensus algorithm"""
        if not results:
            return {'verified': False, 'confidence': 0.0, 'reached': False}
        
        # Count agreements
        verified_count = sum(1 for r in results if r.get('verified', False))
        total_count = len(results)
        
        # PBFT requires 2f+1 agreements (f = faulty nodes)
        f = total_count // 3  # Maximum faulty nodes
        
        consensus_reached = verified_count >= (2 * f + 1)
        
        if consensus_reached:
            # Calculate confidence based on agreement
            confidence = verified_count / total_count
            
            return {
                'verified': True,
                'confidence': confidence,
                'reached': True,
                'faulty_nodes': total_count - verified_count
            }
        else:
            return {
                'verified': False,
                'confidence': 0.0,
                'reached': False,
                'faulty_nodes': total_count - verified_count
            }

class ConfidentialComputeService:
    """Production confidential compute service"""
    
    def __init__(self):
        self.enclave_manager = SGXEnclaveManager('enclave.signed.so')
        self.enclave_pool = {}
        self.load_balancer = EnclaveLoadBalancer()
        
        # Start health monitoring
        asyncio.create_task(self._monitor_enclave_health())
    
    async def process_request(self, request: Dict) -> Dict:
        """Process request through confidential compute"""
        try:
            # Select enclave instance
            instance_id = self.load_balancer.select_enclave(request)
            
            if instance_id not in self.enclave_pool:
                # Create new enclave instance
                instance_config = {
                    'workload_type': request.get('workload_type', 'inference'),
                    'security_level': request.get('security_level', 'high')
                }
                
                instance = await self.enclave_manager.create_enclave_instance(
                    f"enclave_{len(self.enclave_pool)}",
                    instance_config
                )
                
                instance_id = instance['instance_id']
                self.enclave_pool[instance_id] = instance
            
            # Route request based on type
            if request['type'] == 'secure_inference':
                result = await self.enclave_manager.secure_inference(
                    instance_id,
                    request['input_data'],
                    request['model_id']
                )
                
            elif request['type'] == 'threat_verification':
                result = await self.enclave_manager.distributed_threat_verification(
                    request['threat_data'],
                    request.get('peer_enclaves', [])
                )
                
            elif request['type'] == 'secure_training':
                result = await self._secure_training(
                    instance_id,
                    request['training_data'],
                    request['model_config']
                )
                
            else:
                raise ValueError(f"Unknown request type: {request['type']}")
            
            # Update load balancer metrics
            self.load_balancer.update_metrics(instance_id, result)
            
            return {
                'success': True,
                'result': result,
                'instance_id': instance_id,
                'attestation_valid': True,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Confidential compute failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    async def _monitor_enclave_health(self):
        """Monitor enclave health and attestation"""
        while True:
            try:
                for instance_id in list(self.enclave_pool.keys()):
                    try:
                        # Check attestation validity
                        is_valid = await self.enclave_manager._verify_attestation(
                            instance_id
                        )
                        
                        if not is_valid:
                            logger.warning(f"Enclave {instance_id} attestation expired")
                            # Re-attest or remove
                            del self.enclave_pool[instance_id]
                        
                        # Check enclave health
                        health = await self._check_enclave_health(instance_id)
                        if not health['healthy']:
                            logger.warning(f"Enclave {instance_id} unhealthy: {health['reason']}")
                            del self.enclave_pool[instance_id]
                            
                    except Exception as e:
                        logger.error(f"Health check failed for {instance_id}: {e}")
                        del self.enclave_pool[instance_id]
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Health monitoring failed: {e}")
                await asyncio.sleep(30)
    
    async def scale_enclaves(self, min_instances: int = 3, max_instances: int = 10):
        """Auto-scale enclave instances based on load"""
        current_count = len(self.enclave_pool)
        
        if current_count < min_instances:
            # Scale up
            needed = min_instances - current_count
            for i in range(needed):
                instance_id = f"enclave_scale_{datetime.now().timestamp()}_{i}"
                instance = await self.enclave_manager.create_enclave_instance(
                    instance_id,
                    {'workload_type': 'general', 'security_level': 'high'}
                )
                self.enclave_pool[instance_id] = instance
            
            logger.info(f"Scaled up to {min_instances} enclave instances")
        
        elif current_count > max_instances:
            # Scale down
            excess = current_count - max_instances
            instances_to_remove = list(self.enclave_pool.keys())[:excess]
            
            for instance_id in instances_to_remove:
                del self.enclave_pool[instance_id]
            
            logger.info(f"Scaled down to {max_instances} enclave instances")