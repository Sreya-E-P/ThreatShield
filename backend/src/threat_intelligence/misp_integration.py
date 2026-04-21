# backend/src/threat_intelligence/misp_integration.py
"""
MISP (Malware Information Sharing Platform) integration
"""

import json
import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import aiohttp

logger = logging.getLogger(__name__)

class MISPIntegration:
    """MISP API integration for threat intelligence"""
    
    def __init__(self, url: str, api_key: str):
        self.url = url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'Authorization': api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        
    async def get_events(self, hours: int = 24, tags: Optional[List[str]] = None) -> List[Dict]:
        """Get events from MISP"""
        try:
            url = f"{self.url}/events/index"
            params = {
                'published': 1,
                'limit': 100,
                'page': 1,
            }
            
            if tags:
                params['tags'] = tags
            
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._process_misp_events(data)
                    else:
                        logger.error(f"MISP API error: {response.status}")
                        return []
                        
        except Exception as e:
            logger.error(f"Failed to fetch MISP events: {e}")
            return []
    
    def _process_misp_events(self, data: Dict) -> List[Dict]:
        """Process MISP events into threat format"""
        events = []
        
        for event in data.get('Event', []):
            processed = {
                'id': event.get('uuid'),
                'type': 'misp_event',
                'severity': self._get_severity(event.get('threat_level_id', 4)),
                'title': event.get('info', 'Unknown'),
                'description': event.get('info', ''),
                'timestamp': event.get('timestamp'),
                'source': 'MISP',
                'risk_score': self._calculate_risk_score(event),
                'indicators': self._extract_indicators(event),
                'metadata': {
                    'threat_level_id': event.get('threat_level_id'),
                    'analysis': event.get('analysis'),
                    'distribution': event.get('distribution'),
                    'published': event.get('published'),
                }
            }
            events.append(processed)
        
        return events
    
    def _get_severity(self, threat_level_id: int) -> str:
        """Convert MISP threat level to severity"""
        if threat_level_id == 1:
            return 'critical'
        elif threat_level_id == 2:
            return 'high'
        elif threat_level_id == 3:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_risk_score(self, event: Dict) -> float:
        """Calculate risk score from MISP event"""
        base_score = 0.5
        
        # Increase based on threat level
        threat_level = event.get('threat_level_id', 4)
        if threat_level == 1:
            base_score += 0.3
        elif threat_level == 2:
            base_score += 0.2
        elif threat_level == 3:
            base_score += 0.1
        
        # Increase based on attribute count
        attributes = event.get('Attribute', [])
        attribute_factor = len(attributes) * 0.02
        base_score += min(attribute_factor, 0.2)
        
        return min(base_score, 1.0)
    
    def _extract_indicators(self, event: Dict) -> List[Dict]:
        """Extract indicators from MISP event"""
        indicators = []
        
        for attr in event.get('Attribute', []):
            indicators.append({
                'type': attr.get('type'),
                'value': attr.get('value'),
                'category': attr.get('category'),
                'to_ids': attr.get('to_ids', False),
            })
        
        return indicators