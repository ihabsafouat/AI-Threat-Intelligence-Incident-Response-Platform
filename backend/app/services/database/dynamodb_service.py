from typing import Any, Dict, Optional, List, Union
from datetime import datetime, timedelta, timezone
import logging
import json
import re
import hashlib
from urllib.parse import urlparse

import boto3
from botocore.exceptions import ClientError

from app.core.config import settings

logger = logging.getLogger(__name__)


class DynamoDBService:
    """Service wrapper for AWS DynamoDB operations used by ingestion.

    Provides helpers to store structured threat data and to log ingestion events.
    """

    def __init__(self,
                 region_name: Optional[str] = None,
                 threat_table_name: str = "threat_intelligence",
                 metadata_table_name: str = "ingestion_metadata"):
        self.region_name = region_name or settings.AWS_REGION
        self._dynamodb = boto3.resource("dynamodb", region_name=self.region_name)
        self._threat_table = self._dynamodb.Table(threat_table_name)
        self._metadata_table = self._dynamodb.Table(metadata_table_name)
        # Initialize Secrets Manager client
        self._secrets_manager = boto3.client("secretsmanager", region_name=self.region_name)

    async def store_threat_data(self, item: Dict[str, Any]) -> bool:
        """Store a single structured threat item.

        Note: boto3 is synchronous; we call it directly inside this async method.
        """
        try:
            # Clean and normalize the data before storage
            cleaned_item = await self.clean_and_normalize_threat_data(item)
            self._threat_table.put_item(Item=cleaned_item)
            return True
        except ClientError as e:
            logger.error(f"Failed to store threat data in DynamoDB: {e}")
            return False

    async def store_threat_data_batch(self, items: List[Dict[str, Any]]) -> Dict[str, int]:
        """Store multiple threat data items with cleaning and normalization.
        
        Args:
            items: List of threat data items to store
            
        Returns:
            dict: Count of successful and failed items
        """
        cleaned_items = []
        failed_items = []
        
        for item in items:
            try:
                cleaned_item = await self.clean_and_normalize_threat_data(item)
                cleaned_items.append(cleaned_item)
            except Exception as e:
                logger.error(f"Failed to clean item: {e}")
                failed_items.append(item)
        
        # Store cleaned items in batches
        success_count = 0
        batch_size = 25  # DynamoDB batch write limit
        
        for i in range(0, len(cleaned_items), batch_size):
            batch = cleaned_items[i:i + batch_size]
            try:
                with self._threat_table.batch_writer() as batch_writer:
                    for item in batch:
                        batch_writer.put_item(Item=item)
                        success_count += 1
            except ClientError as e:
                logger.error(f"Failed to store batch: {e}")
                # Move failed items to failed list
                failed_items.extend(batch)
                success_count -= len(batch)
        
        return {
            "successful": success_count,
            "failed": len(failed_items),
            "total_processed": len(items)
        }

    # Data Cleaning and Normalization Methods

    async def clean_and_normalize_threat_data(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Clean and normalize incoming threat data for consistent storage.
        
        Args:
            item: Raw threat data item
            
        Returns:
            dict: Cleaned and normalized threat data
        """
        try:
            # Create a copy to avoid modifying the original
            cleaned_item = item.copy()
            
            # Generate unique ID if not present
            if "id" not in cleaned_item:
                cleaned_item["id"] = self._generate_threat_id(cleaned_item)
            
            # Normalize timestamps
            cleaned_item = await self._normalize_timestamps(cleaned_item)
            
            # Clean and validate IP addresses
            cleaned_item = await self._clean_ip_addresses(cleaned_item)
            
            # Clean and validate URLs
            cleaned_item = await self._clean_urls(cleaned_item)
            
            # Clean and validate domains
            cleaned_item = await self._clean_domains(cleaned_item)
            
            # Clean and validate file hashes
            cleaned_item = await self._clean_file_hashes(cleaned_item)
            
            # Normalize threat types and categories
            cleaned_item = await self._normalize_threat_types(cleaned_item)
            
            # Clean and validate confidence scores
            cleaned_item = await self._normalize_confidence_scores(cleaned_item)
            
            # Extract CVE data if present
            cleaned_item = await self.extract_cve_data(cleaned_item)
            
            # Add metadata
            cleaned_item = await self._add_metadata(cleaned_item)
            
            # Validate required fields
            cleaned_item = await self._validate_required_fields(cleaned_item)
            
            return cleaned_item
            
        except Exception as e:
            logger.error(f"Error cleaning threat data: {e}")
            raise

    def _generate_threat_id(self, item: Dict[str, Any]) -> str:
        """Generate a unique ID for threat data based on content."""
        # Create a hash from key identifying fields
        key_fields = [
            str(item.get("indicator", "")),
            str(item.get("threat_type", "")),
            str(item.get("source", "")),
            str(item.get("first_seen", ""))
        ]
        
        content_hash = hashlib.sha256("|".join(key_fields).encode()).hexdigest()
        return f"threat_{content_hash[:16]}"

    async def _normalize_timestamps(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize timestamp fields to ISO format."""
        timestamp_fields = ["first_seen", "last_seen", "created_at", "updated_at", "expires_at"]
        
        for field in timestamp_fields:
            if field in item and item[field]:
                try:
                    if isinstance(item[field], str):
                        # Try to parse various timestamp formats
                        parsed_time = self._parse_timestamp(item[field])
                        if parsed_time:
                            item[field] = parsed_time.isoformat()
                    elif isinstance(item[field], (int, float)):
                        # Handle Unix timestamps
                        item[field] = datetime.fromtimestamp(item[field], tz=timezone.utc).isoformat()
                except Exception as e:
                    logger.warning(f"Failed to normalize timestamp for {field}: {e}")
                    # Set to current time if parsing fails
                    item[field] = datetime.now(timezone.utc).isoformat()
        
        # Add created_at if not present
        if "created_at" not in item:
            item["created_at"] = datetime.now(timezone.utc).isoformat()
        
        return item

    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse various timestamp formats."""
        # Common timestamp formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%Y"
        ]
        
        for fmt in formats:
            try:
                parsed = datetime.strptime(timestamp_str, fmt)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed
            except ValueError:
                continue
        
        return None

    async def _clean_ip_addresses(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Clean and validate IP address fields."""
        ip_fields = ["source_ip", "destination_ip", "ip_address", "indicator"]
        
        for field in ip_fields:
            if field in item and item[field]:
                if isinstance(item[field], str):
                    # Clean IP address
                    cleaned_ip = self._normalize_ip_address(item[field])
                    if cleaned_ip:
                        item[field] = cleaned_ip
                    else:
                        # Remove invalid IP
                        del item[field]
        
        return item

    def _normalize_ip_address(self, ip_str: str) -> Optional[str]:
        """Normalize IP address string."""
        # Remove common prefixes/suffixes
        ip_str = re.sub(r'^(https?://|ftp://|smtp://)', '', ip_str)
        ip_str = re.sub(r'[:/].*$', '', ip_str)
        
        # IPv4 pattern
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.match(ipv4_pattern, ip_str):
            return ip_str
        
        # IPv6 pattern (simplified)
        ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        if re.match(ipv6_pattern, ip_str):
            return ip_str
        
        return None

    async def _clean_urls(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Clean and validate URL fields."""
        url_fields = ["url", "indicator", "source_url"]
        
        for field in url_fields:
            if field in item and item[field]:
                if isinstance(item[field], str):
                    cleaned_url = self._normalize_url(item[field])
                    if cleaned_url:
                        item[field] = cleaned_url
                    else:
                        # Remove invalid URL
                        del item[field]
        
        return item

    def _normalize_url(self, url_str: str) -> Optional[str]:
        """Normalize URL string."""
        try:
            # Add scheme if missing
            if not url_str.startswith(('http://', 'https://', 'ftp://')):
                url_str = 'https://' + url_str
            
            parsed = urlparse(url_str)
            if parsed.netloc and parsed.scheme:
                # Normalize to lowercase
                normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
                if parsed.path:
                    normalized += parsed.path
                if parsed.query:
                    normalized += f"?{parsed.query}"
                return normalized
        except Exception:
            pass
        
        return None

    async def _clean_domains(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Clean and validate domain fields."""
        domain_fields = ["domain", "indicator", "source_domain"]
        
        for field in domain_fields:
            if field in item and item[field]:
                if isinstance(item[field], str):
                    cleaned_domain = self._normalize_domain(item[field])
                    if cleaned_domain:
                        item[field] = cleaned_domain
                    else:
                        # Remove invalid domain
                        del item[field]
        
        return item

    def _normalize_domain(self, domain_str: str) -> Optional[str]:
        """Normalize domain string."""
        # Remove protocol and path
        domain_str = re.sub(r'^(https?://|ftp://)', '', domain_str)
        domain_str = re.sub(r'[:/].*$', '', domain_str)
        
        # Domain pattern
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.match(domain_pattern, domain_str):
            return domain_str.lower()
        
        return None

    async def _clean_file_hashes(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Clean and validate file hash fields."""
        hash_fields = ["file_hash", "md5", "sha1", "sha256", "indicator"]
        
        for field in hash_fields:
            if field in item and item[field]:
                if isinstance(item[field], str):
                    cleaned_hash = self._normalize_hash(item[field])
                    if cleaned_hash:
                        item[field] = cleaned_hash
                    else:
                        # Remove invalid hash
                        del item[field]
        
        return item

    def _normalize_hash(self, hash_str: str) -> Optional[str]:
        """Normalize hash string."""
        # Remove common prefixes and whitespace
        hash_str = re.sub(r'^(md5|sha1|sha256):', '', hash_str.strip())
        
        # Hash patterns
        if re.match(r'^[a-fA-F0-9]{32}$', hash_str):  # MD5
            return hash_str.lower()
        elif re.match(r'^[a-fA-F0-9]{40}$', hash_str):  # SHA1
            return hash_str.lower()
        elif re.match(r'^[a-fA-F0-9]{64}$', hash_str):  # SHA256
            return hash_str.lower()
        
        return None

    async def _normalize_threat_types(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize threat type and category fields."""
        if "threat_type" in item and item["threat_type"]:
            item["threat_type"] = self._standardize_threat_type(item["threat_type"])
        
        if "category" in item and item["category"]:
            item["category"] = self._standardize_category(item["category"])
        
        if "severity" in item and item["severity"]:
            item["severity"] = self._standardize_severity(item["severity"])
        
        return item

    def _standardize_threat_type(self, threat_type: str) -> str:
        """Standardize threat type values."""
        threat_type = threat_type.lower().strip()
        
        # Common threat type mappings
        type_mappings = {
            "malware": ["malware", "virus", "trojan", "worm", "ransomware", "spyware"],
            "phishing": ["phishing", "spearphishing", "whaling"],
            "apt": ["apt", "advanced persistent threat", "nation state"],
            "ddos": ["ddos", "dos", "denial of service"],
            "exploit": ["exploit", "vulnerability", "cve", "zero-day"],
            "botnet": ["botnet", "zombie", "command and control"],
            "social_engineering": ["social engineering", "social engineering attack"],
            "data_theft": ["data theft", "data breach", "exfiltration"],
            "insider_threat": ["insider threat", "insider attack"],
            "unknown": ["unknown", "unclassified", "other"]
        }
        
        for standard_type, variations in type_mappings.items():
            if threat_type in variations or any(var in threat_type for var in variations):
                return standard_type
        
        return threat_type

    def _standardize_category(self, category: str) -> str:
        """Standardize category values."""
        category = category.lower().strip()
        
        # Common category mappings
        category_mappings = {
            "network": ["network", "network security", "network attack"],
            "endpoint": ["endpoint", "host", "workstation", "server"],
            "web": ["web", "web application", "web attack", "web security"],
            "email": ["email", "email security", "email attack"],
            "mobile": ["mobile", "mobile device", "mobile security"],
            "cloud": ["cloud", "cloud security", "saas", "iaas"],
            "iot": ["iot", "internet of things", "smart device"],
            "supply_chain": ["supply chain", "third party", "vendor"],
            "unknown": ["unknown", "unclassified", "other"]
        }
        
        for standard_category, variations in category_mappings.items():
            if category in variations or any(var in category for var in variations):
                return standard_category
        
        return category

    def _standardize_severity(self, severity: str) -> str:
        """Standardize severity values."""
        severity = str(severity).lower().strip()
        
        # Common severity mappings
        severity_mappings = {
            "critical": ["critical", "5", "5.0", "high", "severe"],
            "high": ["high", "4", "4.0", "moderate"],
            "medium": ["medium", "3", "3.0", "moderate"],
            "low": ["low", "2", "2.0", "minor"],
            "info": ["info", "1", "1.0", "information", "informational"]
        }
        
        for standard_severity, variations in severity_mappings.items():
            if severity in variations or any(var in severity for var in variations):
                return standard_severity
        
        return "unknown"

    async def _normalize_confidence_scores(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize confidence scores to 0-100 scale."""
        if "confidence" in item and item["confidence"] is not None:
            try:
                confidence = float(item["confidence"])
                # Normalize to 0-100 scale
                if confidence > 1.0:  # Already in 0-100 scale
                    item["confidence"] = min(100, max(0, confidence))
                else:  # Convert from 0-1 scale
                    item["confidence"] = min(100, max(0, confidence * 100))
            except (ValueError, TypeError):
                item["confidence"] = 50  # Default confidence
        
        return item

    async def _add_metadata(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Add metadata fields to the item."""
        # Add processing metadata
        item["processed_at"] = datetime.now(timezone.utc).isoformat()
        item["data_version"] = "1.0"
        
        # Add source validation
        if "source" in item:
            item["source_verified"] = self._is_trusted_source(item["source"])
        
        # Add data quality score
        item["data_quality_score"] = self._calculate_data_quality_score(item)
        
        return item

    def _is_trusted_source(self, source: str) -> bool:
        """Check if source is in trusted sources list."""
        trusted_sources = [
            "virustotal", "alienvault", "threatfox", "abuseipdb",
            "phishtank", "urlhaus", "malwarebazaar", "misp"
        ]
        return source.lower() in trusted_sources

    def _calculate_data_quality_score(self, item: Dict[str, Any]) -> int:
        """Calculate data quality score based on completeness and validity."""
        score = 0
        max_score = 100
        
        # Required fields (20 points)
        required_fields = ["indicator", "threat_type", "source"]
        for field in required_fields:
            if field in item and item[field]:
                score += 20
        
        # Optional fields (10 points each)
        optional_fields = ["description", "category", "severity", "confidence"]
        for field in optional_fields:
            if field in item and item[field]:
                score += 10
        
        # Timestamp fields (5 points each)
        timestamp_fields = ["first_seen", "last_seen"]
        for field in timestamp_fields:
            if field in item and item[field]:
                score += 5
        
        return min(max_score, score)

    async def _validate_required_fields(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Validate that required fields are present and valid."""
        required_fields = ["indicator", "threat_type", "source"]
        
        for field in required_fields:
            if field not in item or not item[field]:
                raise ValueError(f"Required field '{field}' is missing or empty")
        
        # Ensure indicator is not empty
        if not str(item["indicator"]).strip():
            raise ValueError("Indicator field cannot be empty")
        
        return item

    # CVE Data Extraction Methods

    async def extract_cve_data(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and structure CVE data from threat intelligence items.
        
        Args:
            item: Threat data item that may contain CVE information
            
        Returns:
            dict: Enhanced item with extracted CVE data
        """
        try:
            # Extract CVE ID from various fields
            cve_id = self._extract_cve_id(item)
            if cve_id:
                item["cve_id"] = cve_id
                item["cve_data"] = await self._extract_cve_details(item)
            
            return item
        except Exception as e:
            logger.error(f"Error extracting CVE data: {e}")
            return item

    def _extract_cve_id(self, item: Dict[str, Any]) -> Optional[str]:
        """Extract CVE ID from various fields in the item."""
        # Common fields where CVE IDs might be found
        cve_fields = [
            "cve_id", "cve", "vulnerability_id", "vuln_id", "cve_reference",
            "indicator", "description", "references", "tags", "metadata"
        ]
        
        for field in cve_fields:
            if field in item and item[field]:
                cve_id = self._parse_cve_id(str(item[field]))
                if cve_id:
                    return cve_id
        
        return None

    def _parse_cve_id(self, text: str) -> Optional[str]:
        """Parse CVE ID from text using regex patterns."""
        # CVE ID pattern: CVE-YYYY-NNNNN
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        matches = re.findall(cve_pattern, text, re.IGNORECASE)
        
        if matches:
            # Return the first valid CVE ID found
            return matches[0].upper()
        
        return None

    async def _extract_cve_details(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Extract detailed CVE information from the item."""
        cve_data = {
            "cve_id": item.get("cve_id"),
            "description": self._extract_cve_description(item),
            "cvss_score": self._extract_cvss_score(item),
            "severity": self._extract_cve_severity(item),
            "affected_software": self._extract_affected_software(item),
            "affected_hardware": self._extract_affected_hardware(item),
            "exploit_links": self._extract_exploit_links(item),
            "references": self._extract_cve_references(item),
            "published_date": self._extract_cve_published_date(item),
            "last_updated": self._extract_cve_last_updated(item)
        }
        
        return {k: v for k, v in cve_data.items() if v is not None}

    def _extract_cve_description(self, item: Dict[str, Any]) -> Optional[str]:
        """Extract CVE description from various fields."""
        description_fields = [
            "description", "cve_description", "vulnerability_description",
            "summary", "details", "analysis"
        ]
        
        for field in description_fields:
            if field in item and item[field]:
                description = str(item[field]).strip()
                if len(description) > 10:  # Ensure meaningful description
                    return description
        
        return None

    def _extract_cvss_score(self, item: Dict[str, Any]) -> Optional[float]:
        """Extract CVSS score from various fields."""
        cvss_fields = [
            "cvss_score", "cvss", "score", "vulnerability_score",
            "risk_score", "severity_score"
        ]
        
        for field in cvss_fields:
            if field in item and item[field] is not None:
                try:
                    score = float(item[field])
                    if 0 <= score <= 10:
                        return round(score, 1)
                except (ValueError, TypeError):
                    continue
        
        return None

    def _extract_cve_severity(self, item: Dict[str, Any]) -> Optional[str]:
        """Extract CVE severity based on CVSS score or explicit severity field."""
        # Check explicit severity field first
        if "severity" in item and item["severity"]:
            return str(item["severity"]).lower()
        
        # Calculate severity from CVSS score
        cvss_score = self._extract_cvss_score(item)
        if cvss_score is not None:
            if cvss_score >= 9.0:
                return "critical"
            elif cvss_score >= 7.0:
                return "high"
            elif cvss_score >= 4.0:
                return "medium"
            elif cvss_score >= 0.1:
                return "low"
            else:
                return "none"
        
        return None

    def _extract_affected_software(self, item: Dict[str, Any]) -> List[str]:
        """Extract affected software information."""
        software_fields = [
            "affected_software", "software", "application", "product",
            "vendor", "component", "library", "framework"
        ]
        
        affected_software = []
        
        for field in software_fields:
            if field in item and item[field]:
                if isinstance(item[field], list):
                    affected_software.extend(item[field])
                elif isinstance(item[field], str):
                    # Split by common delimiters
                    software_list = re.split(r'[,;|]', item[field])
                    affected_software.extend([s.strip() for s in software_list if s.strip()])
                elif isinstance(item[field], dict):
                    # Extract from nested structure
                    for key, value in item[field].items():
                        if value:
                            affected_software.append(f"{key}: {value}")
        
        # Remove duplicates and clean
        return list(set([s for s in affected_software if len(s) > 2]))

    def _extract_affected_hardware(self, item: Dict[str, Any]) -> List[str]:
        """Extract affected hardware information."""
        hardware_fields = [
            "affected_hardware", "hardware", "device", "equipment",
            "platform", "architecture", "processor", "firmware"
        ]
        
        affected_hardware = []
        
        for field in hardware_fields:
            if field in item and item[field]:
                if isinstance(item[field], list):
                    affected_hardware.extend(item[field])
                elif isinstance(item[field], str):
                    # Split by common delimiters
                    hardware_list = re.split(r'[,;|]', item[field])
                    affected_hardware.extend([h.strip() for h in hardware_list if h.strip()])
                elif isinstance(item[field], dict):
                    # Extract from nested structure
                    for key, value in item[field].items():
                        if value:
                            affected_hardware.append(f"{key}: {value}")
        
        # Remove duplicates and clean
        return list(set([h for h in affected_hardware if len(h) > 2]))

    def _extract_exploit_links(self, item: Dict[str, Any]) -> List[str]:
        """Extract exploit-related links and references."""
        exploit_fields = [
            "exploit_links", "exploit_urls", "proof_of_concept", "poc",
            "exploit_db", "metasploit", "references", "urls", "links"
        ]
        
        exploit_links = []
        
        for field in exploit_fields:
            if field in item and item[field]:
                if isinstance(item[field], list):
                    exploit_links.extend(item[field])
                elif isinstance(item[field], str):
                    # Extract URLs from text
                    urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', item[field])
                    exploit_links.extend(urls)
                elif isinstance(item[field], dict):
                    # Extract from nested structure
                    for key, value in item[field].items():
                        if value and isinstance(value, str):
                            urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', value)
                            exploit_links.extend(urls)
        
        # Filter for exploit-related URLs
        exploit_keywords = [
            'exploit', 'poc', 'proof', 'metasploit', 'exploit-db',
            'github', 'raw.githubusercontent', 'pastebin', 'gist'
        ]
        
        filtered_links = []
        for link in exploit_links:
            if any(keyword in link.lower() for keyword in exploit_keywords):
                filtered_links.append(link)
        
        # Remove duplicates
        return list(set(filtered_links))

    def _extract_cve_references(self, item: Dict[str, Any]) -> List[str]:
        """Extract all CVE-related references and links."""
        reference_fields = [
            "references", "refs", "links", "urls", "sources",
            "external_links", "related_links"
        ]
        
        references = []
        
        for field in reference_fields:
            if field in item and item[field]:
                if isinstance(item[field], list):
                    references.extend(item[field])
                elif isinstance(item[field], str):
                    # Extract URLs from text
                    urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', item[field])
                    references.extend(urls)
                elif isinstance(item[field], dict):
                    # Extract from nested structure
                    for key, value in item[field].items():
                        if value and isinstance(value, str):
                            urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', value)
                            references.extend(urls)
        
        # Remove duplicates
        return list(set(references))

    def _extract_cve_published_date(self, item: Dict[str, Any]) -> Optional[str]:
        """Extract CVE published date."""
        date_fields = [
            "published_date", "disclosure_date", "release_date",
            "created_date", "announcement_date"
        ]
        
        for field in date_fields:
            if field in item and item[field]:
                try:
                    if isinstance(item[field], str):
                        parsed_time = self._parse_timestamp(item[field])
                        if parsed_time:
                            return parsed_time.isoformat()
                    elif isinstance(item[field], (int, float)):
                        return datetime.fromtimestamp(item[field], tz=timezone.utc).isoformat()
                except Exception:
                    continue
        
        return None

    def _extract_cve_last_updated(self, item: Dict[str, Any]) -> Optional[str]:
        """Extract CVE last updated date."""
        date_fields = [
            "last_updated", "modified_date", "updated_date",
            "last_modified", "revision_date"
        ]
        
        for field in date_fields:
            if field in item and item[field]:
                try:
                    if isinstance(item[field], str):
                        parsed_time = self._parse_timestamp(item[field])
                        if parsed_time:
                            return parsed_time.isoformat()
                    elif isinstance(item[field], (int, float)):
                        return datetime.fromtimestamp(item[field], tz=timezone.utc).isoformat()
                except Exception:
                    continue
        
        return None

    async def search_cve_by_software(self, software_name: str) -> List[Dict[str, Any]]:
        """Search for CVEs affecting specific software."""
        try:
            # Scan the threat table for CVE data
            response = self._threat_table.scan()
            items = response.get("Items", [])
            
            # Paginate if needed
            while response.get("LastEvaluatedKey"):
                response = self._threat_table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
                items.extend(response.get("Items", []))
            
            # Filter for CVEs affecting the specified software
            matching_cves = []
            software_lower = software_name.lower()
            
            for item in items:
                if "cve_data" in item and "affected_software" in item["cve_data"]:
                    affected_software = item["cve_data"]["affected_software"]
                    if any(software_lower in software.lower() for software in affected_software):
                        matching_cves.append(item)
            
            return matching_cves
            
        except ClientError as e:
            logger.error(f"Failed to search CVEs by software: {e}")
            return []

    async def get_cve_statistics(self) -> Dict[str, Any]:
        """Get statistics about stored CVE data."""
        try:
            response = self._threat_table.scan()
            items = response.get("Items", [])
            
            # Paginate if needed
            while response.get("LastEvaluatedKey"):
                response = self._threat_table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
                items.extend(response.get("Items", []))
            
            cve_items = [item for item in items if "cve_id" in item]
            
            # Calculate statistics
            total_cves = len(cve_items)
            severity_counts = {}
            cvss_ranges = {"0-3.9": 0, "4.0-6.9": 0, "7.0-8.9": 0, "9.0-10.0": 0}
            
            for item in cve_items:
                if "cve_data" in item:
                    cve_data = item["cve_data"]
                    
                    # Count by severity
                    severity = cve_data.get("severity", "unknown")
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    # Count by CVSS range
                    cvss_score = cve_data.get("cvss_score")
                    if cvss_score is not None:
                        if cvss_score < 4.0:
                            cvss_ranges["0-3.9"] += 1
                        elif cvss_score < 7.0:
                            cvss_ranges["4.0-6.9"] += 1
                        elif cvss_score < 9.0:
                            cvss_ranges["7.0-8.9"] += 1
                        else:
                            cvss_ranges["9.0-10.0"] += 1
            
            return {
                "total_cves": total_cves,
                "severity_distribution": severity_counts,
                "cvss_score_ranges": cvss_ranges,
                "last_updated": datetime.now(timezone.utc).isoformat()
            }
            
        except ClientError as e:
            logger.error(f"Failed to get CVE statistics: {e}")
            return {"total_cves": 0, "severity_distribution": {}, "cvss_score_ranges": {}}

    async def log_ingestion_event(
        self,
        *,
        source: str,
        data_type: str,
        timestamp: Optional[datetime] = None,
        record_count: Optional[int] = None,
        status: str = "success",
        error_message: Optional[str] = None,
        processing_time: Optional[float] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Log a single ingestion event to the metadata table.

        Required metadata: source, timestamp, data_type.
        """
        try:
            event: Dict[str, Any] = {
                "source": source,
                "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
                "data_type": data_type,
            }
            if record_count is not None:
                event["record_count"] = record_count
            if status:
                event["status"] = status
            if error_message is not None:
                event["error_message"] = error_message
            if processing_time is not None:
                event["processing_time"] = processing_time
            if extra:
                event.update(extra)

            self._metadata_table.put_item(Item=event)
            logger.info(f"Logged ingestion event to DynamoDB: {source} {data_type} {event['timestamp']}")
            return True
        except ClientError as e:
            logger.error(f"Failed to log ingestion event to DynamoDB: {e}")
            return False

    # AWS Secrets Manager Methods for API Key Vaulting

    async def store_api_key(self, secret_name: str, api_key: str, description: str = "", tags: Optional[Dict[str, str]] = None) -> bool:
        """Store an API key in AWS Secrets Manager.
        
        Args:
            secret_name: Name/identifier for the secret
            api_key: The API key to store
            description: Optional description of the secret
            tags: Optional tags for organization
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            secret_value = {
                "api_key": api_key,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "description": description
            }
            
            # Convert tags to AWS format if provided
            aws_tags = []
            if tags:
                aws_tags = [{"Key": k, "Value": v} for k, v in tags.items()]
            
            self._secrets_manager.create_secret(
                Name=secret_name,
                SecretString=json.dumps(secret_value),
                Description=description,
                Tags=aws_tags
            )
            
            logger.info(f"Successfully stored API key in Secrets Manager: {secret_name}")
            return True
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceExistsException':
                # Secret already exists, update it instead
                return await self.update_api_key(secret_name, api_key, description)
            else:
                logger.error(f"Failed to store API key in Secrets Manager: {e}")
                return False

    async def retrieve_api_key(self, secret_name: str) -> Optional[str]:
        """Retrieve an API key from AWS Secrets Manager.
        
        Args:
            secret_name: Name/identifier of the secret
            
        Returns:
            str: The API key if found, None otherwise
        """
        try:
            response = self._secrets_manager.get_secret_value(SecretId=secret_name)
            secret_data = json.loads(response['SecretString'])
            return secret_data.get('api_key')
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                logger.warning(f"Secret not found in Secrets Manager: {secret_name}")
            else:
                logger.error(f"Failed to retrieve API key from Secrets Manager: {e}")
            return None

    async def update_api_key(self, secret_name: str, new_api_key: str, description: str = "") -> bool:
        """Update an existing API key in AWS Secrets Manager.
        
        Args:
            secret_name: Name/identifier of the secret
            new_api_key: The new API key value
            description: Updated description
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get existing secret to preserve metadata
            try:
                response = self._secrets_manager.get_secret_value(SecretId=secret_name)
                existing_data = json.loads(response['SecretString'])
            except ClientError:
                existing_data = {}
            
            # Update with new values
            secret_value = {
                "api_key": new_api_key,
                "created_at": existing_data.get("created_at", datetime.now(timezone.utc).isoformat()),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "description": description or existing_data.get("description", "")
            }
            
            self._secrets_manager.update_secret(
                SecretId=secret_name,
                SecretString=json.dumps(secret_value),
                Description=description or existing_data.get("description", "")
            )
            
            logger.info(f"Successfully updated API key in Secrets Manager: {secret_name}")
            return True
            
        except ClientError as e:
            logger.error(f"Failed to update API key in Secrets Manager: {e}")
            return False

    async def delete_api_key(self, secret_name: str, recovery_window_days: int = 7) -> bool:
        """Delete an API key from AWS Secrets Manager.
        
        Args:
            secret_name: Name/identifier of the secret
            recovery_window_days: Days to wait before permanent deletion (0-30)
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self._secrets_manager.delete_secret(
                SecretId=secret_name,
                RecoveryWindowInDays=recovery_window_days
            )
            
            logger.info(f"Successfully deleted API key from Secrets Manager: {secret_name}")
            return True
            
        except ClientError as e:
            logger.error(f"Failed to delete API key from Secrets Manager: {e}")
            return False

    async def list_api_keys(self, max_results: int = 100) -> list:
        """List all API key secrets in AWS Secrets Manager.
        
        Args:
            max_results: Maximum number of results to return
            
        Returns:
            list: List of secret names
        """
        try:
            response = self._secrets_manager.list_secrets(MaxResults=max_results)
            secret_names = [secret['Name'] for secret in response.get('SecretList', [])]
            
            # Handle pagination
            while 'NextToken' in response and len(secret_names) < max_results:
                response = self._secrets_manager.list_secrets(
                    NextToken=response['NextToken'],
                    MaxResults=max_results - len(secret_names)
                )
                secret_names.extend([secret['Name'] for secret in response.get('SecretList', [])])
            
            return secret_names
            
        except ClientError as e:
            logger.error(f"Failed to list secrets from Secrets Manager: {e}")
            return []

    async def get_secret_metadata(self, secret_name: str) -> Optional[Dict[str, Any]]:
        """Get metadata about a secret without retrieving the actual value.
        
        Args:
            secret_name: Name/identifier of the secret
            
        Returns:
            dict: Secret metadata if found, None otherwise
        """
        try:
            response = self._secrets_manager.describe_secret(SecretId=secret_name)
            
            metadata = {
                "name": response.get('Name'),
                "description": response.get('Description'),
                "created_date": response.get('CreatedDate'),
                "last_modified_date": response.get('LastModifiedDate'),
                "tags": {tag['Key']: tag['Value'] for tag in response.get('Tags', [])},
                "version_id": response.get('VersionId'),
                "deleted_date": response.get('DeletedDate')
            }
            
            return metadata
            
        except ClientError as e:
            logger.error(f"Failed to get secret metadata from Secrets Manager: {e}")
            return None

    async def get_ingestion_metrics(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Basic ingestion metrics between dates based on metadata table scan.

        For production, prefer queries on keys and/or GSIs rather than a full scan.
        """
        try:
            # Fallback scan; assumes partition/sort keys include source/timestamp.
            # Narrow with FilterExpression if table is large.
            response = self._metadata_table.scan()
            items = response.get("Items", [])

            # Paginate if needed
            while response.get("LastEvaluatedKey"):
                response = self._metadata_table.scan(ExclusiveStartKey=response["LastEvaluatedKey"]) 
                items.extend(response.get("Items", []))

            # Filter by timestamp window
            def in_range(it: Dict[str, Any]) -> bool:
                try:
                    ts = datetime.fromisoformat(it.get("timestamp"))
                    return start_date <= ts <= end_date
                except Exception:
                    return False

            filtered = [it for it in items if in_range(it)]

            total_records = sum(int(it.get("record_count", 0)) for it in filtered)
            by_source: Dict[str, int] = {}
            for it in filtered:
                src = it.get("source", "unknown")
                by_source[src] = by_source.get(src, 0) + int(it.get("record_count", 0))

            return {
                "total_events": len(filtered),
                "total_records": total_records,
                "records_by_source": by_source,
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
            }
        except ClientError as e:
            logger.error(f"Failed to compute ingestion metrics: {e}")
            return {"total_events": 0, "total_records": 0, "records_by_source": {}}

    async def cleanup_old_records(self, days_old: int = 90) -> int:
        """Delete metadata events older than the cutoff. Uses scan + batch write."""
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days_old)
            response = self._metadata_table.scan()
            items = response.get("Items", [])
            while response.get("LastEvaluatedKey"):
                response = self._metadata_table.scan(ExclusiveStartKey=response["LastEvaluatedKey"]) 
                items.extend(response.get("Items", []))

            to_delete = []
            for it in items:
                try:
                    ts = datetime.fromisoformat(it.get("timestamp"))
                    if ts < cutoff:
                        to_delete.append({
                            "source": it["source"],
                            "timestamp": it["timestamp"],
                        })
                except Exception:
                    continue

            deleted = 0
            # BatchWrite supports up to 25 items per batch
            for i in range(0, len(to_delete), 25):
                batch = to_delete[i:i+25]
                with self._metadata_table.batch_writer() as batch_writer:
                    for key in batch:
                        batch_writer.delete_item(Key=key)
                        deleted += 1

            logger.info(f"Deleted {deleted} old ingestion metadata records from DynamoDB")
            return deleted
        except ClientError as e:
            logger.error(f"Failed to cleanup old records: {e}")
            return 0 