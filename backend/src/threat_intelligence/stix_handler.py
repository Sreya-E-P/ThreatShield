# backend/src/threat_intelligence/stix_handler.py
"""
STIX 2.0/2.1 threat intelligence handler
"""

import json
import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# FIX: stix2 import made optional with graceful fallback
# Original: import stix2 / from stix2 import MemoryStore, Filter
# Crashes entire routes.py import if stix2 not installed
try:
    import stix2
    from stix2 import MemoryStore, Filter
    STIX2_AVAILABLE = True
    logger.info("stix2 package loaded successfully")
except ImportError:
    STIX2_AVAILABLE = False
    logger.warning("stix2 not installed. STIX indicators disabled. Install with: pip install stix2")
    
    class MemoryStore:
        def __init__(self):
            self._data = []
        def add(self, obj):
            self._data.append(obj)
        def query(self, filters):
            return []
    
    class Filter:
        def __init__(self, *args, **kwargs):
            pass

class STIXHandler:
    """STIX threat intelligence handler"""
    
    def __init__(self):
        self.memory_store = MemoryStore()
        self.loaded_sources = set()
        
    def load_stix_file(self, filepath: str):
        """Load STIX data from file"""
        if not STIX2_AVAILABLE:
            logger.warning("stix2 not installed, cannot load STIX file")
            return
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            if 'objects' in data:
                for obj in data['objects']:
                    try:
                        stix_obj = stix2.parse(obj, allow_custom=True)
                        self.memory_store.add(stix_obj)
                    except Exception as e:
                        logger.warning(f"Failed to parse STIX object: {e}")
            
            self.loaded_sources.add(filepath)
            logger.info(f"Loaded STIX data from {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to load STIX file {filepath}: {e}")
    
    def get_indicators(self, hours: int = 24) -> List[Dict]:
        """Get STIX indicators"""
        if not STIX2_AVAILABLE:
            return []
        try:
            # Filter by time
            cutoff = datetime.now() - timedelta(hours=hours)
            
            filters = [
                Filter('type', '=', 'indicator'),
                Filter('created', '>=', cutoff.isoformat())
            ]
            
            indicators = self.memory_store.query(filters)
            
            return [self._process_indicator(ind) for ind in indicators]
            
        except Exception as e:
            logger.error(f"Failed to get STIX indicators: {e}")
            return []
    
    def _process_indicator(self, indicator) -> Dict:
        """Process STIX indicator into threat format"""
        return {
            'id': indicator.id,
            'type': 'stix_indicator',
            'severity': 'medium',
            'title': indicator.get('name', 'STIX Indicator'),
            'description': indicator.get('description', ''),
            'timestamp': indicator.get('created'),
            'pattern': indicator.get('pattern', ''),
            'source': 'STIX',
            'risk_score': 0.5,
            'indicators': [{
                'type': 'stix_pattern',
                'value': indicator.get('pattern', '')
            }],
            'metadata': {
                'stix_type': indicator.type,
                'pattern_type': indicator.get('pattern_type', ''),
                'valid_from': indicator.get('valid_from'),
                'valid_until': indicator.get('valid_until'),
            }
        }