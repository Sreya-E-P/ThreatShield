"""
Simple bridge to import CryptographicService
"""

import sys
from pathlib import Path

# Get the path to our fixed hybrid_pqc.py file
current_file = Path(__file__).resolve()
crypto_file = current_file.parent / "ts_crypto" / "hybrid_pqc.py"
# Import it directly
import importlib.util

spec = importlib.util.spec_from_file_location("threatshield_crypto", crypto_file)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

# Export what we need
CryptographicService = module.CryptographicService
HybridPQC = module.HybridPQC
HybridKeyPair = module.HybridKeyPair

print("✓ Successfully loaded CryptographicService")
