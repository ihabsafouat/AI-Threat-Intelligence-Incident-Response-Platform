"""
Threat Intelligence Service
Integrates with multiple threat intelligence sources for comprehensive security analysis.
"""

import asyncio
import aiohttp
import json
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from app.core.config import settings
from app.core.cache import RedisCache
from app.models.threat import Threat, ThreatIndicator, ThreatFeed


class IOCType(Enum):
    """Types of Indicators of Compromise"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"


@dataclass
class ThreatIntelligenceResult:
    """Result from threat intelligence analysis"""
    ioc: str
    ioc_type: IOCType
    risk_score: float
    confidence: float
    sources: Dict[str, Any]
    tags: List[str]
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    description: Optional[str] = None


class RateLimiter:
    """Rate limiter for API calls"""
    
    def __init__(self, max_requests: int, time_window: int):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []
    
    async def __aenter__(self):
        now = time.time()
        # Remove old requests
        self.requests = [req for req in self.requests if now - req < self.time_window]
        
        if len(self.requests) >= self.max_requests:
            wait_time = self.time_window - (now - self.requests[0])
            await asyncio.sleep(wait_time)
        
        self.requests.append(now)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class NVDIntegration:
    """National Vulnerability Database (NVD) integration"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
        self.api_key = api_key or settings.CVE_API_KEY
        self.rate_limiter = RateLimiter(5, 30)  # 5 requests per 30 seconds
        self.cache = RedisCache()
    
    async def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch detailed CVE information"""
        cache_key = f"nvd:cve:{cve_id}"
        
        # Check cache first
        cached_data = await self.cache.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
        
        url = f"{self.base_url}?cveId={cve_id}"
        headers = {"apiKey": self.api_key} if self.api_key else {}
        
        async with self.rate_limiter:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Cache for 24 hours
                        await self.cache.set(cache_key, json.dumps(data), expire=86400)
                        return data
        
        return None
    
    async def search_cves(self, keyword: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Search CVEs by keyword"""
        url = f"{self.base_url}?keywordSearch={keyword}&resultsPerPage={limit}"
        headers = {"apiKey": self.api_key} if self.api_key else {}
        
        async with self.rate_limiter:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("vulnerabilities", [])
        
        return []
    
    async def get_recent_cves(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get recent CVEs from the last N days"""
        start_date = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S:000 UTC-00:00")
        url = f"{self.base_url}?pubStartDate={start_date}&resultsPerPage=100"
        headers = {"apiKey": self.api_key} if self.api_key else {}
        
        async with self.rate_limiter:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("vulnerabilities", [])
        
        return []


class VirusTotalIntegration:
    """VirusTotal API integration"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key or settings.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/vtapi/v2/"
        self.rate_limiter = RateLimiter(4, 60)  # 4 requests per minute
        self.cache = RedisCache()
    
    async def analyze_file(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Analyze file by hash"""
        cache_key = f"virustotal:file:{file_hash}"
        
        # Check cache first
        cached_data = await self.cache.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
        
        url = f"{self.base_url}file/report"
        params = {"apikey": self.api_key, "resource": file_hash}
        
        async with self.rate_limiter:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Cache for 1 hour
                        await self.cache.set(cache_key, json.dumps(data), expire=3600)
                        return data
        
        return None
    
    async def analyze_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Analyze URL for threats"""
        cache_key = f"virustotal:url:{hash(url)}"
        
        # Check cache first
        cached_data = await self.cache.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
        
        vt_url = f"{self.base_url}url/report"
        params = {"apikey": self.api_key, "resource": url}
        
        async with self.rate_limiter:
            async with aiohttp.ClientSession() as session:
                async with session.get(vt_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Cache for 1 hour
                        await self.cache.set(cache_key, json.dumps(data), expire=3600)
                        return data
        
        return None
    
    async def get_domain_report(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get domain intelligence report"""
        cache_key = f"virustotal:domain:{domain}"
        
        # Check cache first
        cached_data = await self.cache.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
        
        url = f"{self.base_url}domain/report"
        params = {"apikey": self.api_key, "domain": domain}
        
        async with self.rate_limiter:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Cache for 6 hours
                        await self.cache.set(cache_key, json.dumps(data), expire=21600)
                        return data
        
        return None
    
    async def get_ip_report(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get IP address intelligence report"""
        cache_key = f"virustotal:ip:{ip_address}"
        
        # Check cache first
        cached_data = await self.cache.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
        
        url = f"{self.base_url}ip-address/report"
        params = {"apikey": self.api_key, "ip": ip_address}
        
        async with self.rate_limiter:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Cache for 6 hours
                        await self.cache.set(cache_key, json.dumps(data), expire=21600)
                        return data
        
        return None


class ShodanIntegration:
    """Shodan API integration"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key or settings.SHODAN_API_KEY
        self.base_url = "https://api.shodan.io/"
        self.rate_limiter = RateLimiter(1, 1)  # 1 request per second
        self.cache = RedisCache()
    
    async def search_hosts(self, query: str, limit: int = 100) -> Optional[Dict[str, Any]]:
        """Search for hosts matching query"""
        cache_key = f"shodan:search:{hash(query)}"
        
        # Check cache first
        cached_data = await self.cache.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
        
        url = f"{self.base_url}shodan/host/search"
        params = {
            "key": self.api_key,
            "query": query,
            "limit": limit
        }
        
        async with self.rate_limiter:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Cache for 1 hour
                        await self.cache.set(cache_key, json.dumps(data), expire=3600)
                        return data
        
        return None
    
    async def get_host_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific host"""
        cache_key = f"shodan:host:{ip}"
        
        # Check cache first
        cached_data = await self.cache.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
        
        url = f"{self.base_url}shodan/host/{ip}"
        params = {"key": self.api_key}
        
        async with self.rate_limiter:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Cache for 6 hours
                        await self.cache.set(cache_key, json.dumps(data), expire=21600)
                        return data
        
        return None
    
    async def get_domain_info(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get information about a domain"""
        cache_key = f"shodan:domain:{domain}"
        
        # Check cache first
        cached_data = await self.cache.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
        
        url = f"{self.base_url}shodan/domain/{domain}"
        params = {"key": self.api_key}
        
        async with self.rate_limiter:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Cache for 6 hours
                        await self.cache.set(cache_key, json.dumps(data), expire=21600)
                        return data
        
        return None


class MitreAttackIntegration:
    """MITRE ATT&CK knowledge base integration"""
    
    def __init__(self):
        self.base_url = "https://attack.mitre.org/api/"
        self.rate_limiter = RateLimiter(10, 60)  # 10 requests per minute
        self.cache = RedisCache()
    
    async def get_techniques(self) -> List[Dict[str, Any]]:
        """Get all ATT&CK techniques"""
        cache_key = "mitre:techniques"
        
        # Check cache first
        cached_data = await self.cache.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
        
        url = f"{self.base_url}techniques/enterprise/"
        
        async with self.rate_limiter:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Cache for 24 hours
                        await self.cache.set(cache_key, json.dumps(data), expire=86400)
                        return data
        
        return []
    
    async def get_tactics(self) -> List[Dict[str, Any]]:
        """Get all ATT&CK tactics"""
        cache_key = "mitre:tactics"
        
        # Check cache first
        cached_data = await self.cache.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
        
        url = f"{self.base_url}tactics/enterprise/"
        
        async with self.rate_limiter:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Cache for 24 hours
                        await self.cache.set(cache_key, json.dumps(data), expire=86400)
                        return data
        
        return []
    
    async def get_groups(self) -> List[Dict[str, Any]]:
        """Get all threat groups"""
        cache_key = "mitre:groups"
        
        # Check cache first
        cached_data = await self.cache.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
        
        url = f"{self.base_url}groups/"
        
        async with self.rate_limiter:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Cache for 24 hours
                        await self.cache.set(cache_key, json.dumps(data), expire=86400)
                        return data
        
        return []
    
    async def get_software(self) -> List[Dict[str, Any]]:
        """Get all software/tools"""
        cache_key = "mitre:software"
        
        # Check cache first
        cached_data = await self.cache.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
        
        url = f"{self.base_url}software/"
        
        async with self.rate_limiter:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Cache for 24 hours
                        await self.cache.set(cache_key, json.dumps(data), expire=86400)
                        return data
        
        return []


class ThreatIntelligenceManager:
    """Unified threat intelligence manager"""
    
    def __init__(self):
        self.nvd = NVDIntegration()
        self.virustotal = VirusTotalIntegration(settings.VIRUSTOTAL_API_KEY)
        self.shodan = ShodanIntegration(settings.SHODAN_API_KEY)
        self.mitre = MitreAttackIntegration()
        self.cache = RedisCache()
    
    async def enrich_ioc(self, ioc: str, ioc_type: IOCType) -> ThreatIntelligenceResult:
        """Enrich IOC with multiple intelligence sources"""
        enriched_data = {
            "ioc": ioc,
            "type": ioc_type,
            "sources": {},
            "risk_score": 0.0,
            "confidence": 0.0,
            "tags": []
        }
        
        # Parallel enrichment from multiple sources
        tasks = []
        
        if ioc_type == IOCType.HASH:
            tasks.append(self.virustotal.analyze_file(ioc))
        elif ioc_type == IOCType.URL:
            tasks.append(self.virustotal.analyze_url(ioc))
        elif ioc_type == IOCType.DOMAIN:
            tasks.append(self.virustotal.get_domain_report(ioc))
            tasks.append(self.shodan.get_domain_info(ioc))
        elif ioc_type == IOCType.IP:
            tasks.append(self.virustotal.get_ip_report(ioc))
            tasks.append(self.shodan.get_host_info(ioc))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and calculate risk score
        for i, result in enumerate(results):
            if isinstance(result, dict):
                if i == 0 and ioc_type == IOCType.HASH:
                    enriched_data["sources"]["virustotal"] = result
                elif i == 0 and ioc_type == IOCType.URL:
                    enriched_data["sources"]["virustotal"] = result
                elif i == 0 and ioc_type == IOCType.DOMAIN:
                    enriched_data["sources"]["virustotal"] = result
                elif i == 1 and ioc_type == IOCType.DOMAIN:
                    enriched_data["sources"]["shodan"] = result
                elif i == 0 and ioc_type == IOCType.IP:
                    enriched_data["sources"]["virustotal"] = result
                elif i == 1 and ioc_type == IOCType.IP:
                    enriched_data["sources"]["shodan"] = result
        
        # Calculate composite risk score
        enriched_data["risk_score"] = self._calculate_risk_score(enriched_data)
        enriched_data["confidence"] = self._calculate_confidence(enriched_data)
        enriched_data["tags"] = self._extract_tags(enriched_data)
        
        return ThreatIntelligenceResult(**enriched_data)
    
    def _calculate_risk_score(self, enriched_data: Dict[str, Any]) -> float:
        """Calculate composite risk score from multiple sources"""
        score = 0.0
        weights = {
            "virustotal": 0.4,
            "shodan": 0.3,
            "nvd": 0.3
        }
        
        # VirusTotal reputation scoring
        if "virustotal" in enriched_data["sources"]:
            vt_data = enriched_data["sources"]["virustotal"]
            if "positives" in vt_data and "total" in vt_data:
                positives = vt_data["positives"]
                total = vt_data["total"]
                if total > 0:
                    reputation_score = (positives / total) * 10
                    score += reputation_score * weights["virustotal"]
        
        # Shodan exposure scoring
        if "shodan" in enriched_data["sources"]:
            shodan_data = enriched_data["sources"]["shodan"]
            vulns = len(shodan_data.get("vulns", []))
            ports = len(shodan_data.get("ports", []))
            exposure_score = min((vulns * 2) + (ports * 0.5), 10)
            score += exposure_score * weights["shodan"]
        
        return min(score, 10.0)
    
    def _calculate_confidence(self, enriched_data: Dict[str, Any]) -> float:
        """Calculate confidence score based on data quality and source reliability"""
        confidence = 0.0
        sources_count = len(enriched_data["sources"])
        
        if sources_count == 0:
            return 0.0
        elif sources_count == 1:
            confidence = 0.6
        elif sources_count == 2:
            confidence = 0.8
        else:
            confidence = 0.9
        
        # Adjust based on data quality
        for source, data in enriched_data["sources"].items():
            if data and isinstance(data, dict):
                confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _extract_tags(self, enriched_data: Dict[str, Any]) -> List[str]:
        """Extract tags from enriched data"""
        tags = []
        
        # Extract tags from VirusTotal
        if "virustotal" in enriched_data["sources"]:
            vt_data = enriched_data["sources"]["virustotal"]
            if "scans" in vt_data:
                for scanner, result in vt_data["scans"].items():
                    if result.get("detected"):
                        tags.append(f"malware:{result.get('result', 'unknown')}")
        
        # Extract tags from Shodan
        if "shodan" in enriched_data["sources"]:
            shodan_data = enriched_data["sources"]["shodan"]
            if "vulns" in shodan_data:
                tags.extend([f"vulnerability:{vuln}" for vuln in shodan_data["vulns"]])
            
            if "data" in shodan_data:
                for service in shodan_data["data"]:
                    if "product" in service:
                        tags.append(f"service:{service['product']}")
        
        return list(set(tags))  # Remove duplicates
    
    async def search_threats(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Search for threats across multiple sources"""
        results = []
        
        # Search NVD for CVEs
        cve_results = await self.nvd.search_cves(query, limit)
        results.extend([{"source": "nvd", "data": cve} for cve in cve_results])
        
        # Search Shodan for hosts
        shodan_results = await self.shodan.search_hosts(query, limit)
        if shodan_results and "matches" in shodan_results:
            results.extend([{"source": "shodan", "data": match} for match in shodan_results["matches"]])
        
        return results[:limit]
    
    async def get_threat_feed(self, feed_type: str) -> List[Dict[str, Any]]:
        """Get threat feed data"""
        cache_key = f"threat_feed:{feed_type}"
        
        # Check cache first
        cached_data = await self.cache.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
        
        if feed_type == "recent_cves":
            data = await self.nvd.get_recent_cves(days=7)
        elif feed_type == "mitre_techniques":
            data = await self.mitre.get_techniques()
        elif feed_type == "mitre_groups":
            data = await self.mitre.get_groups()
        else:
            data = []
        
        # Cache for 1 hour
        await self.cache.set(cache_key, json.dumps(data), expire=3600)
        
        return data 