"""
Multi-chain blockchain integration
"""

from web3 import Web3
from web3.middleware import geth_poa_middleware
from typing import Dict, List, Optional, Tuple
import logging
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

class MultiChainClient:
    """Multi-chain blockchain client"""
    
    def __init__(self):
        # Get API keys from environment
        self.alchemy_key = os.getenv("ALCHEMY_API_KEY", "demo")
        
        # Public RPC endpoints
        self.rpc_endpoints = {
            'ethereum': f"https://eth-mainnet.g.alchemy.com/v2/{self.alchemy_key}",
            'polygon': f"https://polygon-mainnet.g.alchemy.com/v2/{self.alchemy_key}",
            'bsc': "https://bsc-dataseed1.binance.org",
            'arbitrum': "https://arb1.arbitrum.io/rpc",
            'optimism': "https://mainnet.optimism.io",
            'avalanche': "https://api.avax.network/ext/bc/C/rpc",
        }
        
        self.chains = {}
        self._initialize_chains()
    
    def _initialize_chains(self):
        """Initialize connections to multiple blockchains"""
        for name, endpoint in self.rpc_endpoints.items():
            try:
                w3 = Web3(Web3.HTTPProvider(endpoint))
                
                # Add POA middleware for certain chains
                if name in ['polygon', 'bsc', 'avalanche']:
                    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
                
                if w3.is_connected():
                    self.chains[name] = w3
                    logger.info(f"Connected to {name}")
                else:
                    logger.warning(f"Failed to connect to {name}")
                    
            except Exception as e:
                logger.error(f"Error connecting to {name}: {e}")
    
    def get_balance(self, address: str, chain: str = 'ethereum') -> Optional[float]:
        """Get balance for address on specific chain"""
        if chain not in self.chains:
            logger.error(f"Chain {chain} not initialized")
            return None
        
        try:
            w3 = self.chains[chain]
            balance_wei = w3.eth.get_balance(address)
            balance_eth = w3.from_wei(balance_wei, 'ether')
            return float(balance_eth)
        except Exception as e:
            logger.error(f"Failed to get balance for {address} on {chain}: {e}")
            return None
    
    def get_transaction(self, tx_hash: str, chain: str = 'ethereum') -> Optional[Dict]:
        """Get transaction details"""
        if chain not in self.chains:
            logger.error(f"Chain {chain} not initialized")
            return None
        
        try:
            w3 = self.chains[chain]
            tx = w3.eth.get_transaction(tx_hash)
            receipt = w3.eth.get_transaction_receipt(tx_hash)
            
            # Get block timestamp
            block = w3.eth.get_block(tx.blockNumber)
            timestamp = datetime.fromtimestamp(block.timestamp)
            
            return {
                'hash': tx_hash,
                'from': tx['from'],
                'to': tx['to'],
                'value': float(w3.from_wei(tx['value'], 'ether')),
                'block_number': tx.blockNumber,
                'gas_used': receipt.gasUsed,
                'gas_price': float(w3.from_wei(tx['gasPrice'], 'gwei')),
                'timestamp': timestamp.isoformat(),
                'status': receipt.status,
                'chain': chain,
            }
            
        except Exception as e:
            logger.error(f"Failed to get transaction {tx_hash} on {chain}: {e}")
            return None
    
    def get_block(self, block_number: int, chain: str = 'ethereum') -> Optional[Dict]:
        """Get block details"""
        if chain not in self.chains:
            logger.error(f"Chain {chain} not initialized")
            return None
        
        try:
            w3 = self.chains[chain]
            block = w3.eth.get_block(block_number)
            
            return {
                'number': block.number,
                'hash': block.hash.hex(),
                'timestamp': datetime.fromtimestamp(block.timestamp).isoformat(),
                'transactions': len(block.transactions),
                'gas_used': block.gasUsed,
                'gas_limit': block.gasLimit,
            }
            
        except Exception as e:
            logger.error(f"Failed to get block {block_number} on {chain}: {e}")
            return None
    
    def get_transactions(self, address: str, chain: str = 'ethereum', limit: int = 10) -> List[Dict]:
        """Get recent transactions for address"""
        # Note: This requires a blockchain explorer API
        # For production, integrate with Etherscan, Polygonscan, etc.
        logger.warning("get_transactions requires external API integration")
        return []