# Threat Intelligence Feeds Integration

## Overview

The platform integrates with multiple threat intelligence sources to provide comprehensive security coverage. This document outlines the feeds, APIs, and integration strategies for each source.

## 1. National Vulnerability Database (NVD)

### Description
The NVD is the U.S. government repository of standards-based vulnerability management data represented using the Security Content Automation Protocol (SCAP).

### API Endpoints
- **Base URL**: `https://services.nvd.nist.gov/rest/json/cves/2.0/`
- **Rate Limit**: 5 requests per 30 seconds (unauthenticated), 50 requests per 30 seconds (authenticated)

### Key Features
- **CVE Data**: Comprehensive vulnerability information
- **CVSS Scoring**: Standardized vulnerability severity scoring
- **CPE Matching**: Common Platform Enumeration for affected products
- **Historical Data**: Complete vulnerability history

### Integration Strategy
```python
# NVD API Integration
class NVDIntegration:
    def __init__(self, api_key: str = None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
        self.api_key = api_key
        self.rate_limiter = RateLimiter(5, 30)  # 5 requests per 30 seconds
    
    async def get_cve_details(self, cve_id: str) -> dict:
        """Fetch detailed CVE information"""
        url = f"{self.base_url}?cveId={cve_id}"
        headers = {"apiKey": self.api_key} if self.api_key else {}
        
        async with self.rate_limiter:
            response = await self.client.get(url, headers=headers)
            return response.json()
    
    async def search_cves(self, keyword: str, limit: int = 20) -> List[dict]:
        """Search CVEs by keyword"""
        url = f"{self.base_url}?keywordSearch={keyword}&resultsPerPage={limit}"
        headers = {"apiKey": self.api_key} if self.api_key else {}
        
        async with self.rate_limiter:
            response = await self.client.get(url, headers=headers)
            return response.json()["vulnerabilities"]
```

### Data Schema
```json
{
  "cve": {
    "id": "CVE-2023-1234",
    "description": "Vulnerability description",
    "cvssMetricV31": [{
      "cvssData": {
        "baseScore": 8.1,
        "baseSeverity": "HIGH",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
      }
    }],
    "configurations": {
      "nodes": [{
        "cpeMatch": [{
          "vulnerable": true,
          "criteria": "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*:*"
        }]
      }]
    }
  }
}
```

---

## 2. VirusTotal API

### Description
VirusTotal is a service that analyzes suspicious files and URLs to detect types of malware and automatically shares them with the security community.

### API Endpoints
- **Base URL**: `https://www.virustotal.com/vtapi/v2/`
- **Rate Limit**: 4 requests per minute (public API), 500 requests per minute (private API)

### Key Features
- **File Analysis**: Malware detection and analysis
- **URL Reputation**: Phishing and malicious URL detection
- **Domain Intelligence**: Domain reputation and threat intelligence
- **IP Address Analysis**: IP reputation and threat data

### Integration Strategy
```python
# VirusTotal API Integration
class VirusTotalIntegration:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2/"
        self.rate_limiter = RateLimiter(4, 60)  # 4 requests per minute
    
    async def analyze_file(self, file_hash: str) -> dict:
        """Analyze file by hash"""
        url = f"{self.base_url}file/report"
        params = {"apikey": self.api_key, "resource": file_hash}
        
        async with self.rate_limiter:
            response = await self.client.get(url, params=params)
            return response.json()
    
    async def analyze_url(self, url: str) -> dict:
        """Analyze URL for threats"""
        vt_url = f"{self.base_url}url/report"
        params = {"apikey": self.api_key, "resource": url}
        
        async with self.rate_limiter:
            response = await self.client.get(vt_url, params=params)
            return response.json()
    
    async def get_domain_report(self, domain: str) -> dict:
        """Get domain intelligence report"""
        url = f"{self.base_url}domain/report"
        params = {"apikey": self.api_key, "domain": domain}
        
        async with self.rate_limiter:
            response = await self.client.get(url, params=params)
            return response.json()
```

### Data Schema
```json
{
  "response_code": 1,
  "positives": 45,
  "total": 70,
  "scans": {
    "vendor1": {
      "detected": true,
      "version": "1.0.0",
      "result": "Trojan.Generic",
      "update": "20231201"
    }
  },
  "sha256": "hash_value",
  "scan_date": "2023-12-01 10:00:00"
}
```

---

## 3. Shodan API

### Description
Shodan is a search engine for Internet-connected devices. It provides information about devices, services, and vulnerabilities exposed on the internet.

### API Endpoints
- **Base URL**: `https://api.shodan.io/`
- **Rate Limit**: 1 request per second (free), 10 requests per second (paid)

### Key Features
- **Device Discovery**: Find internet-connected devices
- **Service Enumeration**: Identify running services and versions
- **Vulnerability Scanning**: Detect exposed vulnerabilities
- **Geographic Intelligence**: Location-based threat intelligence

### Integration Strategy
```python
# Shodan API Integration
class ShodanIntegration:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.shodan.io/"
        self.rate_limiter = RateLimiter(1, 1)  # 1 request per second
    
    async def search_hosts(self, query: str, limit: int = 100) -> dict:
        """Search for hosts matching query"""
        url = f"{self.base_url}shodan/host/search"
        params = {
            "key": self.api_key,
            "query": query,
            "limit": limit
        }
        
        async with self.rate_limiter:
            response = await self.client.get(url, params=params)
            return response.json()
    
    async def get_host_info(self, ip: str) -> dict:
        """Get detailed information about a specific host"""
        url = f"{self.base_url}shodan/host/{ip}"
        params = {"key": self.api_key}
        
        async with self.rate_limiter:
            response = await self.client.get(url, params=params)
            return response.json()
    
    async def get_domain_info(self, domain: str) -> dict:
        """Get information about a domain"""
        url = f"{self.base_url}shodan/domain/{domain}"
        params = {"key": self.api_key}
        
        async with self.rate_limiter:
            response = await self.client.get(url, params=params)
            return response.json()
```

### Data Schema
```json
{
  "ip_str": "192.168.1.1",
  "port": 80,
  "hostnames": ["example.com"],
  "org": "Organization Name",
  "data": [{
    "product": "nginx",
    "version": "1.18.0",
    "http": {
      "title": "Welcome to nginx!",
      "server": "nginx/1.18.0"
    }
  }],
  "vulns": ["CVE-2021-1234"],
  "location": {
    "country_code": "US",
    "city": "New York",
    "latitude": 40.7128,
    "longitude": -74.0060
  }
}
```

---

## 4. MITRE ATT&CK Knowledge Base

### Description
MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.

### API Endpoints
- **Base URL**: `https://attack.mitre.org/api/`
- **Rate Limit**: No official limit, but respectful usage recommended

### Key Features
- **Tactics and Techniques**: Comprehensive attack framework
- **Threat Groups**: Known threat actor profiles
- **Software Tools**: Malware and tool information
- **Campaigns**: Historical attack campaigns

### Integration Strategy
```python
# MITRE ATT&CK Integration
class MitreAttackIntegration:
    def __init__(self):
        self.base_url = "https://attack.mitre.org/api/"
        self.rate_limiter = RateLimiter(10, 60)  # 10 requests per minute
    
    async def get_techniques(self) -> List[dict]:
        """Get all ATT&CK techniques"""
        url = f"{self.base_url}techniques/enterprise/"
        
        async with self.rate_limiter:
            response = await self.client.get(url)
            return response.json()
    
    async def get_tactics(self) -> List[dict]:
        """Get all ATT&CK tactics"""
        url = f"{self.base_url}tactics/enterprise/"
        
        async with self.rate_limiter:
            response = await self.client.get(url)
            return response.json()
    
    async def get_groups(self) -> List[dict]:
        """Get all threat groups"""
        url = f"{self.base_url}groups/"
        
        async with self.rate_limiter:
            response = await self.client.get(url)
            return response.json()
    
    async def get_software(self) -> List[dict]:
        """Get all software/tools"""
        url = f"{self.base_url}software/"
        
        async with self.rate_limiter:
            response = await self.client.get(url)
            return response.json()
```

### Data Schema
```json
{
  "id": "T1055",
  "name": "Process Injection",
  "description": "Adversaries may inject code into processes...",
  "tactic": "Defense Evasion",
  "technique": "Process Injection",
  "subtechnique": "Thread Local Storage",
  "platforms": ["Windows", "Linux", "macOS"],
  "permissions_required": ["User", "Administrator"],
  "data_sources": ["Process monitoring", "API monitoring"],
  "mitigations": [{
    "id": "M1040",
    "name": "Behavior Prevention on Endpoint"
  }]
}
```

---

## 5. Additional Threat Intelligence Sources

### AlienVault OTX
- **Purpose**: Open threat intelligence sharing
- **Features**: Threat indicators, malware samples, threat reports
- **API**: RESTful API with rate limiting

### Emerging Threats
- **Purpose**: Network security threat intelligence
- **Features**: IDS/IPS rules, threat feeds, malware analysis
- **API**: Various feed formats (STIX, JSON, CSV)

### ThreatFox
- **Purpose**: Malware intelligence platform
- **Features**: Malware samples, IOCs, threat actor information
- **API**: RESTful API with authentication

### URLhaus
- **Purpose**: Malicious URL tracking
- **Features**: Phishing URLs, malware distribution URLs
- **API**: RESTful API with rate limiting

---

## Integration Architecture

### Data Ingestion Layer
```python
# Unified Threat Intelligence Manager
class ThreatIntelligenceManager:
    def __init__(self):
        self.nvd = NVDIntegration()
        self.virustotal = VirusTotalIntegration(api_key)
        self.shodan = ShodanIntegration(api_key)
        self.mitre = MitreAttackIntegration()
        self.cache = RedisCache()
    
    async def enrich_ioc(self, ioc: str, ioc_type: str) -> dict:
        """Enrich IOC with multiple intelligence sources"""
        enriched_data = {
            "ioc": ioc,
            "type": ioc_type,
            "sources": {},
            "risk_score": 0,
            "tags": []
        }
        
        # Parallel enrichment from multiple sources
        tasks = []
        
        if ioc_type == "hash":
            tasks.append(self.virustotal.analyze_file(ioc))
        elif ioc_type == "url":
            tasks.append(self.virustotal.analyze_url(ioc))
        elif ioc_type == "domain":
            tasks.append(self.virustotal.get_domain_report(ioc))
            tasks.append(self.shodan.get_domain_info(ioc))
        elif ioc_type == "ip":
            tasks.append(self.shodan.get_host_info(ioc))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and calculate risk score
        for result in results:
            if isinstance(result, dict):
                enriched_data["sources"].update(result)
        
        enriched_data["risk_score"] = self.calculate_risk_score(enriched_data)
        return enriched_data
    
    def calculate_risk_score(self, enriched_data: dict) -> float:
        """Calculate composite risk score from multiple sources"""
        score = 0.0
        
        # NVD vulnerability scoring
        if "nvd" in enriched_data["sources"]:
            cvss_score = enriched_data["sources"]["nvd"].get("cvss_score", 0)
            score += cvss_score * 0.3
        
        # VirusTotal reputation
        if "virustotal" in enriched_data["sources"]:
            vt_data = enriched_data["sources"]["virustotal"]
            positives = vt_data.get("positives", 0)
            total = vt_data.get("total", 1)
            reputation_score = (positives / total) * 10
            score += reputation_score * 0.4
        
        # Shodan exposure
        if "shodan" in enriched_data["sources"]:
            shodan_data = enriched_data["sources"]["shodan"]
            vulns = len(shodan_data.get("vulns", []))
            score += min(vulns * 2, 10) * 0.3
        
        return min(score, 10.0)
```

### Data Storage Strategy
- **Structured Data**: PostgreSQL for relational threat data
- **Unstructured Data**: AWS S3 for files, reports, and artifacts
- **Vector Storage**: Pinecone/Weaviate for semantic search
- **Cache Layer**: Redis for frequently accessed data

### Rate Limiting and Caching
```python
# Rate Limiter Implementation
class RateLimiter:
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
```

This comprehensive threat intelligence integration provides the platform with rich, multi-source threat data for enhanced security analysis and response capabilities. 