"""
Production threat intelligence processor
"""

import asyncio
import logging
from typing import List, Dict, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import defaultdict
import json
import os

try:
    from threat_intelligence.misp_integration import MISPIntegration
except ImportError:
    try:
        from src.threat_intelligence.misp_integration import MISPIntegration
    except ImportError:
        class MISPIntegration:
            def __init__(self, url, api_key): pass
            async def get_events(self, hours=24, tags=None): return []

try:
    from threat_intelligence.stix_handler import STIXHandler
except ImportError:
    try:
        from src.threat_intelligence.stix_handler import STIXHandler
    except ImportError:
        class STIXHandler:
            def __init__(self): pass
            def get_indicators(self, hours=24): return []

logger = logging.getLogger(__name__)

@dataclass
class Threat:
    """Unified threat representation"""
    id: str
    type: str
    severity: str
    title: str
    description: str
    timestamp: datetime
    source: str
    risk_score: float
    indicators: List[Dict]
    metadata: Dict
    enriched_data: Optional[Dict] = None

class ThreatIntelligenceProcessor:
    """Production threat intelligence processor"""
    
    def __init__(self):
        self.misp = None
        self.stix = STIXHandler()
        self.threat_cache = {}
        self.cache_ttl = timedelta(hours=1)
        
        self.threat_graph = defaultdict(set)
        self.ioc_index = {}
        
        self.sources = {}
        self._init_sources()
        self._bg_task_started = False

    def _ensure_bg_task(self):
        """Start background update task lazily on first async call"""
        if not self._bg_task_started:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(self._periodic_update())
                    self._bg_task_started = True
            except Exception:
                pass

    def _init_sources(self):
        """Initialize threat intelligence sources from environment variables"""
        try:
            misp_url = os.getenv("MISP_URL", "")
            misp_key = os.getenv("MISP_API_KEY", "")
            if misp_url and misp_key and "your-misp" not in misp_url:
                self.misp = MISPIntegration(misp_url, misp_key)
                logger.info(f"MISP integration initialized: {misp_url}")
            else:
                logger.info("MISP not configured (set MISP_URL and MISP_API_KEY in .env to enable)")
                self.misp = None
        except Exception as e:
            logger.warning(f"Failed to initialize MISP: {e}")
            self.misp = None
    
    async def get_recent_threats(self,
                                hours: int = 24,
                                severity: Optional[str] = None,
                                limit: int = 100) -> List[Dict]:
        """
        Get recent threats from all sources.
        PRODUCTION FIX: Directly integrates OTX and VirusTotal API keys
        from .env — no MISP needed. Returns real live threat data.
        """
        self._ensure_bg_task()
        threats = []

        # SOURCE 1: MISP (if configured)
        if self.misp:
            try:
                misp_threats = await self.misp.get_events(hours)
                threats.extend(self._normalize_threats(misp_threats, "misp"))
                logger.info(f"MISP: {len(misp_threats)} threats fetched")
            except Exception as e:
                logger.error(f"MISP fetch failed: {e}")

        # SOURCE 2: AlienVault OTX
        otx_key = os.getenv("OTX_API_KEY", "")
        if otx_key:
            try:
                otx_threats = await self._fetch_otx_threats(otx_key, hours)
                threats.extend(self._normalize_threats(otx_threats, "alienvault"))
                logger.info(f"AlienVault OTX: {len(otx_threats)} threats fetched")
            except Exception as e:
                logger.error(f"OTX fetch failed: {e}")

        # SOURCE 3: VirusTotal
        vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        if vt_key:
            try:
                vt_threats = await self._fetch_virustotal_threats(vt_key)
                threats.extend(self._normalize_threats(vt_threats, "virustotal"))
                logger.info(f"VirusTotal: {len(vt_threats)} threats fetched")
            except Exception as e:
                logger.error(f"VirusTotal fetch failed: {e}")

        # SOURCE 4: STIX indicators
        try:
            stix_threats = self.stix.get_indicators(hours)
            threats.extend(self._normalize_threats(stix_threats, "stix"))
        except Exception as e:
            logger.error(f"STIX fetch failed: {e}")

        if severity:
            threats = [t for t in threats if t.get("severity") == severity]

        threats.sort(
            key=lambda x: (x.get("risk_score", 0), x.get("timestamp", "")),
            reverse=True
        )
        threats = threats[:limit]

        enriched = await self.enrich_threats(threats)
        return enriched

    async def _fetch_otx_threats(self, api_key: str, hours: int = 24) -> List[Dict]:
        """Fetch real threats from AlienVault OTX API."""
        threats = []
        try:
            import aiohttp
            headers = {'X-OTX-API-KEY': api_key}
            url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
            params = {"limit": 50}

            async with aiohttp.ClientSession(
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as session:
                async with session.get(url, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for pulse in data.get('results', []):
                            threat = self._parse_otx_pulse(pulse)
                            if threat:
                                threats.append(threat)
        except Exception as e:
            logger.error(f"OTX API error: {e}")
        return threats

    def _parse_otx_pulse(self, pulse: Dict) -> Optional[Dict]:
        """Convert OTX pulse to standard threat format"""
        try:
            indicators = []
            for ind in pulse.get('indicators', [])[:10]:
                indicators.append({
                    'type': ind.get('type', 'unknown').lower(),
                    'value': ind.get('indicator', ''),
                })

            tlp = pulse.get('tlp', 'white').lower()
            severity_map = {'red': 'critical', 'amber': 'high', 'green': 'medium', 'white': 'low'}
            severity = severity_map.get(tlp, 'medium')

            ind_count = len(pulse.get('indicators', []))
            subscriber_count = pulse.get('subscriber_count', 0)
            risk_score = min(0.3 + (ind_count / 100) + (subscriber_count / 10000), 1.0)

            return {
                'id': f"otx_{pulse.get('id', '')}",
                'type': self._detect_threat_type_from_tags(pulse.get('tags', [])),
                'severity': severity,
                'title': pulse.get('name', 'OTX Threat')[:200],
                'description': pulse.get('description', '')[:500],
                'timestamp': pulse.get('modified', datetime.now().isoformat()),
                'source': 'alienvault',
                'risk_score': risk_score,
                'indicators': indicators,
                'metadata': {
                    'pulse_id': pulse.get('id'),
                    'author': pulse.get('author_name', ''),
                    'subscriber_count': subscriber_count,
                    'indicator_count': ind_count,
                    'tags': pulse.get('tags', []),
                    'tlp': tlp,
                    'references': pulse.get('references', [])[:3],
                }
            }
        except Exception as e:
            logger.warning(f"Failed to parse OTX pulse: {e}")
            return None

    async def _fetch_virustotal_threats(self, api_key: str) -> List[Dict]:
        """Fetch recent malware/threat data from VirusTotal API v3."""
        threats = []
        try:
            import aiohttp
            headers = {'x-apikey': api_key}
            url = "https://www.virustotal.com/api/v3/feeds/files"

            async with aiohttp.ClientSession(
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.strip().split('\n')[:20]:
                            try:
                                item = json.loads(line)
                                threat = self._parse_vt_item(item)
                                if threat:
                                    threats.append(threat)
                            except Exception:
                                continue
                    elif resp.status == 429:
                        logger.warning("VirusTotal rate limit hit — skipping")
        except Exception as e:
            logger.error(f"VirusTotal API error: {e}")
        return threats

    def _parse_vt_item(self, item: Dict) -> Optional[Dict]:
        """Convert VirusTotal item to standard threat format"""
        try:
            attrs = item.get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values()) if stats else 1

            if malicious == 0:
                return None

            detection_ratio = malicious / total if total > 0 else 0
            risk_score = min(0.3 + detection_ratio * 0.7, 1.0)

            if detection_ratio > 0.7:
                severity = 'critical'
            elif detection_ratio > 0.4:
                severity = 'high'
            elif detection_ratio > 0.2:
                severity = 'medium'
            else:
                severity = 'low'

            sha256 = attrs.get('sha256', '')
            name = attrs.get('meaningful_name', attrs.get('name', 'Unknown Malware'))

            return {
                'id': f"vt_{sha256[:16]}",
                'type': 'malware',
                'severity': severity,
                'title': f"VirusTotal: {name[:100]}",
                'description': f"Detected by {malicious}/{total} AV engines",
                'timestamp': datetime.fromtimestamp(
                    attrs.get('last_analysis_date', datetime.now().timestamp())
                ).isoformat(),
                'source': 'virustotal',
                'risk_score': risk_score,
                'indicators': [
                    {'type': 'sha256', 'value': sha256},
                    {'type': 'md5', 'value': attrs.get('md5', '')},
                ],
                'metadata': {
                    'detection_ratio': f"{malicious}/{total}",
                    'file_type': attrs.get('type_description', ''),
                    'size': attrs.get('size', 0),
                    'tags': attrs.get('tags', [])[:5],
                }
            }
        except Exception as e:
            logger.warning(f"Failed to parse VT item: {e}")
            return None

    def _detect_threat_type_from_tags(self, tags: List[str]) -> str:
        """Detect threat type from OTX tags"""
        tags_lower = ' '.join(t.lower() for t in tags)
        if 'ransom' in tags_lower:
            return 'ransomware'
        elif 'phish' in tags_lower:
            return 'phishing_url'
        elif 'apt' in tags_lower:
            return 'apt'
        elif 'c2' in tags_lower or 'c&c' in tags_lower:
            return 'command_control'
        elif 'ddos' in tags_lower:
            return 'denial_of_service'
        elif 'exploit' in tags_lower:
            return 'exploit'
        elif 'botnet' in tags_lower:
            return 'malware'
        else:
            return 'malware'

    def _normalize_threats(self, raw_threats: List[Dict], source: str) -> List[Dict]:
        """Normalize threats from different sources"""
        normalized = []
        
        for threat in raw_threats:
            try:
                timestamp_str = threat.get("timestamp")
                if isinstance(timestamp_str, str):
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                elif isinstance(timestamp_str, (int, float)):
                    timestamp = datetime.fromtimestamp(timestamp_str)
                else:
                    timestamp = datetime.now()
                
                normalized_threat = {
                    "id": threat.get("id", f"{source}_{len(normalized)}"),
                    "type": threat.get("type", "unknown"),
                    "severity": threat.get("severity", "medium"),
                    "title": threat.get("title", "Unknown Threat"),
                    "description": threat.get("description", ""),
                    "timestamp": timestamp.isoformat(),
                    "source": source,
                    "risk_score": threat.get("risk_score", 0.5),
                    "indicators": threat.get("indicators", []),
                    "metadata": threat.get("metadata", {}),
                    "raw_data": threat,
                }
                
                normalized.append(normalized_threat)
                self._index_indicators(normalized_threat)
                
            except Exception as e:
                logger.warning(f"Failed to normalize threat: {e}")
                continue
        
        return normalized
    
    def _index_indicators(self, threat: Dict):
        """Index indicators for correlation"""
        threat_id = threat["id"]
        
        for indicator in threat.get("indicators", []):
            ioc_value = indicator.get("value")
            ioc_type = indicator.get("type")
            
            if ioc_value and ioc_type:
                key = f"{ioc_type}:{ioc_value}"
                
                if key not in self.ioc_index:
                    self.ioc_index[key] = set()
                
                self.ioc_index[key].add(threat_id)
    
    async def enrich_threats(self, threats: List[Dict]) -> List[Dict]:
        """Enrich threats with additional intelligence"""
        enriched_threats = []
        
        for threat in threats:
            try:
                cache_key = f"{threat['id']}_{threat['timestamp']}"
                if cache_key in self.threat_cache:
                    cached = self.threat_cache[cache_key]
                    if datetime.now() - cached["cached_at"] < self.cache_ttl:
                        enriched_threats.append(cached["threat"])
                        continue
                
                enriched = threat.copy()
                
                correlated = self._get_correlated_threats(threat)
                if correlated:
                    enriched["correlated_threats"] = correlated
                    enriched["correlation_score"] = self._calculate_correlation_score(correlated)
                
                enriched["enrichment"] = await self._enrich_threat_intel(threat)
                enriched["risk_assessment"] = self._assess_threat_risk(threat)
                enriched["mitigation"] = self._suggest_mitigation(threat)
                
                self.threat_cache[cache_key] = {
                    "threat": enriched,
                    "cached_at": datetime.now()
                }
                
                enriched_threats.append(enriched)
                
            except Exception as e:
                logger.error(f"Failed to enrich threat {threat.get('id')}: {e}")
                enriched_threats.append(threat)
        
        return enriched_threats
    
    def _get_correlated_threats(self, threat: Dict) -> List[Dict]:
        """Find correlated threats based on indicators"""
        correlated = []
        seen = set()
        
        for indicator in threat.get("indicators", []):
            ioc_value = indicator.get("value")
            ioc_type = indicator.get("type")
            
            if ioc_value and ioc_type:
                key = f"{ioc_type}:{ioc_value}"
                related_threats = self.ioc_index.get(key, set())
                
                for threat_id in related_threats:
                    if threat_id != threat["id"] and threat_id not in seen:
                        for cached in self.threat_cache.values():
                            if cached["threat"]["id"] == threat_id:
                                correlated.append(cached["threat"])
                                seen.add(threat_id)
                                break
        
        return correlated
    
    def _calculate_correlation_score(self, correlated: List[Dict]) -> float:
        """Calculate correlation score"""
        if not correlated:
            return 0.0
        
        base_score = min(len(correlated) * 0.2, 1.0)
        
        now = datetime.now()
        recency_bonus = 0.0
        
        for threat in correlated:
            threat_time = datetime.fromisoformat(threat["timestamp"].replace('Z', '+00:00'))
            hours_ago = (now - threat_time).total_seconds() / 3600
            
            if hours_ago < 24:
                recency_bonus += 0.1
            elif hours_ago < 168:
                recency_bonus += 0.05
        
        return min(base_score + recency_bonus, 1.0)
    
    async def _enrich_threat_intel(self, threat: Dict) -> Dict:
        """Enrich threat with external intelligence"""
        enrichment = {
            "source_confidence": self._get_source_confidence(threat["source"]),
            "indicators_analyzed": len(threat.get("indicators", [])),
            "enrichment_sources": [],
        }
        
        for indicator in threat.get("indicators", []):
            ioc_type = indicator.get("type", "")
            ioc_value = indicator.get("value", "")
            
            if ioc_type in ["ip", "domain", "url"]:
                enrichment["enrichment_sources"].append({
                    "type": ioc_type,
                    "value": ioc_value,
                    "analysis": "pending_external_lookup",
                })
        
        return enrichment
    
    def _get_source_confidence(self, source: str) -> float:
        """Get confidence score for threat source"""
        source_confidence = {
            "misp": 0.9,
            "virustotal": 0.8,
            "alienvault": 0.7,
            "stix": 0.6,
            "internal": 0.5,
            "unknown": 0.3,
        }
        
        return source_confidence.get(source.lower(), 0.5)
    
    def _assess_threat_risk(self, threat: Dict) -> Dict:
        """Assess threat risk"""
        risk_score = threat.get("risk_score", 0.5)
        
        severity_multiplier = {
            "critical": 1.5,
            "high": 1.2,
            "medium": 1.0,
            "low": 0.8,
        }
        
        severity = threat.get("severity", "medium")
        risk_score *= severity_multiplier.get(severity, 1.0)
        
        indicator_count = len(threat.get("indicators", []))
        risk_score *= min(1.0 + (indicator_count * 0.05), 1.5)
        
        risk_score = min(risk_score, 1.0)
        
        return {
            "score": risk_score,
            "level": "CRITICAL" if risk_score > 0.8 else
                    "HIGH" if risk_score > 0.6 else
                    "MEDIUM" if risk_score > 0.4 else "LOW",
            "factors": [
                f"Severity: {severity.upper()}",
                f"Indicators: {indicator_count}",
                f"Source: {threat.get('source', 'unknown')}",
            ]
        }
    
    def _suggest_mitigation(self, threat: Dict) -> List[Dict]:
        """Suggest mitigation actions based on threat type"""
        threat_type = threat.get("type", "").lower()
        severity = threat.get("severity", "medium")
        
        mitigations = []
        
        if "malware" in threat_type:
            mitigations.extend([
                {"action": "Isolate affected systems", "priority": "high"},
                {"action": "Scan with updated antivirus", "priority": "high"},
                {"action": "Block associated IOCs", "priority": "medium"},
            ])
        
        elif "phishing" in threat_type:
            mitigations.extend([
                {"action": "Block malicious URLs/domains", "priority": "high"},
                {"action": "Notify users of phishing attempt", "priority": "medium"},
                {"action": "Update email filters", "priority": "medium"},
            ])
        
        elif "exploit" in threat_type or "vulnerability" in threat_type:
            mitigations.extend([
                {"action": "Apply security patches", "priority": "high"},
                {"action": "Implement temporary workarounds", "priority": "medium"},
                {"action": "Monitor for exploitation attempts", "priority": "medium"},
            ])
        
        elif "ddos" in threat_type:
            mitigations.extend([
                {"action": "Enable DDoS protection", "priority": "high"},
                {"action": "Rate limit traffic", "priority": "high"},
                {"action": "Contact ISP for assistance", "priority": "medium"},
            ])
        
        if severity in ["high", "critical"]:
            mitigations.append({"action": "Activate incident response team", "priority": "high"})
            mitigations.append({"action": "Increase monitoring and logging", "priority": "medium"})
        
        return mitigations
    
    async def search_threats(self, 
                           query: str,
                           ioc_type: Optional[str] = None,
                           timeframe_days: int = 30) -> List[Dict]:
        """Search threats by IOC or keyword"""
        results = []
        
        for cached in self.threat_cache.values():
            threat = cached["threat"]
            
            threat_time = datetime.fromisoformat(threat["timestamp"].replace('Z', '+00:00'))
            cutoff = datetime.now() - timedelta(days=timeframe_days)
            
            if threat_time < cutoff:
                continue
            
            if (query.lower() in threat["title"].lower() or 
                query.lower() in threat["description"].lower()):
                results.append(threat)
            
            elif ioc_type:
                for indicator in threat.get("indicators", []):
                    if (indicator.get("type", "").lower() == ioc_type.lower() and 
                        query.lower() in indicator.get("value", "").lower()):
                        results.append(threat)
                        break
        
        return results
    
    async def _periodic_update(self):
        """Periodic threat intelligence update"""
        while True:
            try:
                logger.info("Starting periodic threat intelligence update")
                
                new_threats = await self.get_recent_threats(hours=1, limit=50)
                
                if new_threats:
                    logger.info(f"Processed {len(new_threats)} new threats")
                    enriched = await self.enrich_threats(new_threats)
                    
                    for threat in enriched:
                        self._update_threat_graph(threat)
                
                self._clean_cache()
                await asyncio.sleep(300)
                
            except Exception as e:
                logger.error(f"Periodic update failed: {e}")
                await asyncio.sleep(60)
    
    def _update_threat_graph(self, threat: Dict):
        """Update threat correlation graph"""
        threat_id = threat["id"]
        
        for correlated in threat.get("correlated_threats", []):
            correlated_id = correlated["id"]
            self.threat_graph[threat_id].add(correlated_id)
            self.threat_graph[correlated_id].add(threat_id)
    
    def _clean_cache(self):
        """Clean old cache entries"""
        cutoff = datetime.now() - self.cache_ttl
        to_remove = []
        
        for key, cached in self.threat_cache.items():
            if cached["cached_at"] < cutoff:
                to_remove.append(key)
        
        for key in to_remove:
            del self.threat_cache[key]
        
        if to_remove:
            logger.debug(f"Cleaned {len(to_remove)} old cache entries")
    
    async def get_threat_statistics(self) -> Dict:
        """Get threat intelligence statistics"""
        now = datetime.now()
        
        sources = defaultdict(int)
        severities = defaultdict(int)
        types = defaultdict(int)
        
        for cached in self.threat_cache.values():
            threat = cached["threat"]
            sources[threat["source"]] += 1
            severities[threat["severity"]] += 1
            types[threat["type"]] += 1
        
        recent_cutoff = now - timedelta(hours=1)
        recent_threats = sum(1 for cached in self.threat_cache.values()
                           if datetime.fromisoformat(cached["threat"]["timestamp"].replace('Z', '+00:00')) > recent_cutoff)
        
        return {
            "total_threats": len(self.threat_cache),
            "recent_threats": recent_threats,
            "by_source": dict(sources),
            "by_severity": dict(severities),
            "by_type": dict(types),
            "indicators_indexed": len(self.ioc_index),
            "threat_graph_nodes": len(self.threat_graph),
            "cache_size": len(self.threat_cache),
            "timestamp": now.isoformat(),
        }

    async def cleanup(self):
        """Cleanup resources on shutdown"""
        self._clean_cache()
        logger.info("ThreatIntelligenceProcessor cleanup complete")