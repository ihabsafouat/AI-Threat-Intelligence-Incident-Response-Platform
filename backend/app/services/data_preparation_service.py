from typing import Any, Dict, List, Optional, Tuple
import logging
import json
import re
from datetime import datetime, timedelta
from pathlib import Path

from datasets import Dataset
import pandas as pd

from app.core.config import settings
from app.services.database.dynamodb_service import DynamoDBService

logger = logging.getLogger(__name__)


class CybersecurityDataPreparationService:
    """Service for preparing cybersecurity data for fine-tuning.
    
    Extracts and formats data from:
    - Incident reports
    - Threat intelligence
    - Remediation guides
    - Security logs
    - CVE data
    """

    def __init__(self):
        self.db_service = DynamoDBService()
        self.output_path = Path(settings.FINE_TUNING_DATASET_PATH)
        self.output_path.mkdir(parents=True, exist_ok=True)

    async def prepare_comprehensive_dataset(self, 
                                         include_synthetic: bool = True,
                                         max_samples_per_category: Optional[int] = None) -> Dict[str, Dataset]:
        """Prepare comprehensive cybersecurity dataset for fine-tuning."""
        try:
            logger.info("Preparing comprehensive cybersecurity dataset...")
            
            datasets = {}
            
            # 1. Incident Reports
            incident_dataset = await self._prepare_incident_reports_dataset(max_samples_per_category)
            if incident_dataset:
                datasets['incident_reports'] = incident_dataset
                logger.info(f"Prepared {len(incident_dataset)} incident report samples")
            
            # 2. Threat Intelligence
            threat_dataset = await self._prepare_threat_intelligence_dataset(max_samples_per_category)
            if threat_dataset:
                datasets['threat_intelligence'] = threat_dataset
                logger.info(f"Prepared {len(threat_dataset)} threat intelligence samples")
            
            # 3. Remediation Guides
            remediation_dataset = await self._prepare_remediation_guides_dataset(max_samples_per_category)
            if remediation_dataset:
                datasets['remediation_guides'] = remediation_dataset
                logger.info(f"Prepared {len(remediation_dataset)} remediation guide samples")
            
            # 4. CVE Data
            cve_dataset = await self._prepare_cve_dataset(max_samples_per_category)
            if cve_dataset:
                datasets['cve_data'] = cve_dataset
                logger.info(f"Prepared {len(cve_dataset)} CVE samples")
            
            # 5. Synthetic Data (if enabled)
            if include_synthetic:
                synthetic_dataset = self._generate_synthetic_data(max_samples_per_category)
                if synthetic_dataset:
                    datasets['synthetic'] = synthetic_dataset
                    logger.info(f"Generated {len(synthetic_dataset)} synthetic samples")
            
            # Save datasets to disk
            await self._save_datasets(datasets)
            
            # Create combined dataset
            combined_dataset = self._combine_datasets(list(datasets.values()))
            
            # Split into train/val/test
            splits = self._split_dataset(combined_dataset)
            
            logger.info(f"Dataset preparation completed. Total samples: {len(combined_dataset)}")
            logger.info(f"Split sizes - Train: {len(splits['train'])}, "
                       f"Val: {len(splits['validation'])}, Test: {len(splits['test'])}")
            
            return splits
            
        except Exception as e:
            logger.error(f"Failed to prepare comprehensive dataset: {e}")
            raise

    async def _prepare_incident_reports_dataset(self, max_samples: Optional[int] = None) -> Optional[Dataset]:
        """Prepare incident reports dataset from database."""
        try:
            # This would extract real incident data from your database
            # For now, we'll create a comprehensive sample dataset
            
            incident_samples = [
                {
                    "text": "INCIDENT REPORT: Ransomware Attack\n\n"
                           "Date: 2024-01-15\n"
                           "Severity: Critical\n"
                           "Affected Systems: 15 endpoints, 2 servers\n"
                           "Malware Type: WannaCry variant\n"
                           "Entry Point: Phishing email with malicious attachment\n"
                           "Impact: Data encryption, business operations halted\n"
                           "Response Actions:\n"
                           "1. Isolated affected systems\n"
                           "2. Disconnected from network\n"
                           "3. Initiated incident response procedures\n"
                           "4. Contacted law enforcement\n"
                           "5. Notified cyber insurance provider\n\n"
                           "Remediation Steps:\n"
                           "1. Restore from clean backups\n"
                           "2. Implement additional security controls\n"
                           "3. Conduct security awareness training\n"
                           "4. Update incident response plan",
                    "type": "ransomware",
                    "severity": "critical",
                    "response_time": "immediate",
                    "business_impact": "high"
                },
                {
                    "text": "SECURITY INCIDENT: Data Breach\n\n"
                           "Date: 2024-01-10\n"
                           "Severity: High\n"
                           "Affected Data: Customer PII, financial records\n"
                           "Attack Vector: SQL injection on web application\n"
                           "Attacker: Unknown threat actor\n"
                           "Detection: SIEM alert for unusual database queries\n"
                           "Response Actions:\n"
                           "1. Isolated affected web server\n"
                           "2. Analyzed database logs\n"
                           "3. Assessed data exposure\n"
                           "4. Notified legal and compliance teams\n"
                           "5. Engaged incident response firm\n\n"
                           "Remediation:\n"
                           "1. Patched SQL injection vulnerability\n"
                           "2. Implemented WAF rules\n"
                           "3. Enhanced database security\n"
                           "4. Conducted penetration testing",
                    "type": "data_breach",
                    "severity": "high",
                    "response_time": "within_1_hour",
                    "business_impact": "high"
                },
                {
                    "text": "PHISHING INCIDENT: Credential Harvesting\n\n"
                           "Date: 2024-01-08\n"
                           "Severity: Medium\n"
                           "Target: Finance department employees\n"
                           "Attack Method: Spear phishing emails\n"
                           "Indicators: Suspicious links to fake login pages\n"
                           "Compromised Accounts: 3 user accounts\n"
                           "Response Actions:\n"
                           "1. Removed malicious emails\n"
                           "2. Reset compromised passwords\n"
                           "3. Blocked malicious domains\n"
                           "4. Scanned systems for malware\n"
                           "5. Sent security awareness notification\n\n"
                           "Prevention:\n"
                           "1. Implemented MFA\n"
                           "2. Enhanced email filtering\n"
                           "3. Conducted phishing simulation training",
                    "type": "phishing",
                    "severity": "medium",
                    "response_time": "within_4_hours",
                    "business_impact": "medium"
                }
            ]
            
            # Apply max samples limit
            if max_samples and len(incident_samples) > max_samples:
                incident_samples = incident_samples[:max_samples]
            
            dataset = Dataset.from_list(incident_samples)
            return dataset
            
        except Exception as e:
            logger.error(f"Failed to prepare incident reports dataset: {e}")
            return None

    async def _prepare_threat_intelligence_dataset(self, max_samples: Optional[int] = None) -> Optional[Dataset]:
        """Prepare threat intelligence dataset."""
        try:
            threat_samples = [
                {
                    "text": "THREAT INTELLIGENCE: APT29 (Cozy Bear)\n\n"
                           "Threat Actor: APT29, Cozy Bear, The Dukes\n"
                           "Target Sectors: Government, defense, energy\n"
                           "Geographic Focus: NATO countries, Eastern Europe\n"
                           "Tactics, Techniques & Procedures (TTPs):\n"
                           "1. Initial Access: Spear phishing, water holing\n"
                           "2. Execution: PowerShell scripts, living off the land\n"
                           "3. Persistence: Registry modifications, scheduled tasks\n"
                           "4. Privilege Escalation: Token manipulation, process injection\n"
                           "5. Defense Evasion: Code obfuscation, process hollowing\n"
                           "6. Credential Access: Credential dumping, keylogging\n"
                           "7. Discovery: Network scanning, system information gathering\n"
                           "8. Lateral Movement: Pass the hash, remote services\n"
                           "9. Collection: Screen capture, file collection\n"
                           "10. Exfiltration: Data staging, command and control\n\n"
                           "Indicators of Compromise (IoCs):\n"
                           "- IP ranges: 185.220.101.0/24, 45.95.147.0/24\n"
                           "- Domains: *.duckdns.org, *.myftp.org\n"
                           "- File hashes: SHA256 values for malware samples\n"
                           "- Registry keys: Specific persistence mechanisms\n\n"
                           "Mitigation Strategies:\n"
                           "1. Implement network segmentation\n"
                           "2. Use multi-factor authentication\n"
                           "3. Monitor for suspicious PowerShell activity\n"
                           "4. Deploy endpoint detection and response (EDR)\n"
                           "5. Conduct regular security awareness training",
                    "threat_actor": "APT29",
                    "threat_level": "high",
                    "target_sectors": ["government", "defense", "energy"],
                    "confidence": "high"
                },
                {
                    "text": "MALWARE ANALYSIS: Emotet Banking Trojan\n\n"
                           "Malware Family: Emotet\n"
                           "Type: Banking trojan, botnet\n"
                           "Distribution Methods:\n"
                           "1. Malicious email attachments\n"
                           "2. Compromised websites\n"
                           "3. Malvertising campaigns\n"
                           "4. Social engineering\n\n"
                           "Capabilities:\n"
                           "1. Keylogging and credential theft\n"
                           "2. Banking information harvesting\n"
                           "3. Email harvesting and propagation\n"
                           "4. Additional malware delivery\n"
                           "5. Botnet formation and control\n\n"
                           "Technical Details:\n"
                           "- File size: 200KB - 2MB\n"
                           "- Persistence: Registry modifications\n"
                           "- Communication: HTTP/HTTPS to C2 servers\n"
                           "- Anti-analysis: VM detection, sandbox evasion\n\n"
                           "Detection Methods:\n"
                           "1. Network traffic analysis\n"
                           "2. Endpoint behavior monitoring\n"
                           "3. Email security filtering\n"
                           "4. Web filtering and blocking\n\n"
                           "Remediation:\n"
                           "1. Isolate infected systems\n"
                           "2. Remove malware using specialized tools\n"
                           "3. Reset compromised credentials\n"
                           "4. Update security controls\n"
                           "5. Conduct post-incident analysis",
                    "threat_actor": "unknown",
                    "threat_level": "medium",
                    "malware_type": "banking_trojan",
                    "confidence": "high"
                }
            ]
            
            if max_samples and len(threat_samples) > max_samples:
                threat_samples = threat_samples[:max_samples]
            
            dataset = Dataset.from_list(threat_samples)
            return dataset
            
        except Exception as e:
            logger.error(f"Failed to prepare threat intelligence dataset: {e}")
            return None

    async def _prepare_remediation_guides_dataset(self, max_samples: Optional[int] = None) -> Optional[Dataset]:
        """Prepare remediation guides dataset."""
        try:
            remediation_samples = [
                {
                    "text": "REMEDIATION GUIDE: Ransomware Attack Response\n\n"
                           "Immediate Actions (0-1 hour):\n"
                           "1. Isolate affected systems from network\n"
                           "2. Disconnect from internet if possible\n"
                           "3. Document all affected systems and files\n"
                           "4. Take screenshots of ransom notes\n"
                           "5. Contact incident response team\n\n"
                           "Short-term Response (1-24 hours):\n"
                           "1. Assess scope and impact of infection\n"
                           "2. Identify entry point and attack vector\n"
                           "3. Determine if backups are accessible\n"
                           "4. Engage law enforcement if necessary\n"
                           "5. Notify cyber insurance provider\n\n"
                           "Recovery Phase (24 hours - 1 week):\n"
                           "1. Restore systems from clean backups\n"
                           "2. Verify system integrity and security\n"
                           "3. Implement additional security controls\n"
                           "4. Conduct post-incident analysis\n"
                           "5. Update incident response procedures\n\n"
                           "Long-term Improvements (1 week - 1 month):\n"
                           "1. Enhance backup and recovery procedures\n"
                           "2. Implement network segmentation\n"
                           "3. Deploy advanced endpoint protection\n"
                           "4. Conduct security awareness training\n"
                           "5. Test incident response procedures\n\n"
                           "Prevention Measures:\n"
                           "1. Regular backup testing and validation\n"
                           "2. Multi-factor authentication implementation\n"
                           "3. Network monitoring and alerting\n"
                           "4. Regular security assessments\n"
                           "5. Employee security training programs",
                    "threat_type": "ransomware",
                    "response_time": "immediate",
                    "complexity": "high",
                    "estimated_duration": "1-4 weeks"
                },
                {
                    "text": "REMEDIATION GUIDE: Phishing Incident Response\n\n"
                           "Detection and Initial Response:\n"
                           "1. Identify and remove malicious emails\n"
                           "2. Block reported domains and IP addresses\n"
                           "3. Scan systems for malware and indicators\n"
                           "4. Reset compromised user credentials\n"
                           "5. Assess scope of potential compromise\n\n"
                           "Investigation and Analysis:\n"
                           "1. Analyze email headers and content\n"
                           "2. Review user activity logs\n"
                           "3. Check for unauthorized access\n"
                           "4. Identify data exposure or theft\n"
                           "5. Document incident timeline\n\n"
                           "Remediation Steps:\n"
                           "1. Remove malware from affected systems\n"
                           "2. Restore compromised accounts\n"
                           "3. Update security controls\n"
                           "4. Implement additional monitoring\n"
                           "5. Conduct security awareness training\n\n"
                           "Post-Incident Actions:\n"
                           "1. Update email security policies\n"
                           "2. Enhance user training programs\n"
                           "3. Implement additional security controls\n"
                           "4. Review and update incident response plan\n"
                           "5. Conduct lessons learned session\n\n"
                           "Prevention Strategies:\n"
                           "1. Advanced email filtering and security\n"
                           "2. Regular phishing simulation exercises\n"
                           "3. User security awareness training\n"
                           "4. Multi-factor authentication\n"
                           "5. Regular security assessments",
                    "threat_type": "phishing",
                    "response_time": "within_4_hours",
                    "complexity": "medium",
                    "estimated_duration": "1-2 weeks"
                }
            ]
            
            if max_samples and len(remediation_samples) > max_samples:
                remediation_samples = remediation_samples[:max_samples]
            
            dataset = Dataset.from_list(remediation_samples)
            return dataset
            
        except Exception as e:
            logger.error(f"Failed to prepare remediation guides dataset: {e}")
            return None

    async def _prepare_cve_dataset(self, max_samples: Optional[int] = None) -> Optional[Dataset]:
        """Prepare CVE dataset from database."""
        try:
            # This would extract real CVE data from your database
            # For now, we'll create sample CVE data
            
            cve_samples = [
                {
                    "text": "CVE-2023-1234: Critical Buffer Overflow Vulnerability\n\n"
                           "Vulnerability Type: Buffer Overflow\n"
                           "CVSS Score: 9.8 (Critical)\n"
                           "Affected Software: ExampleApp versions 2.0.0 - 2.1.5\n"
                           "Attack Vector: Network\n"
                           "Complexity: Low\n"
                           "Privileges Required: None\n"
                           "User Interaction: None\n\n"
                           "Description:\n"
                           "A critical buffer overflow vulnerability exists in the "
                           "network processing component of ExampleApp. An attacker "
                           "can send specially crafted network packets to trigger "
                           "the overflow, potentially leading to remote code execution.\n\n"
                           "Technical Details:\n"
                           "The vulnerability occurs in the process_network_packet() "
                           "function when handling packets larger than 1024 bytes. "
                           "The function fails to properly validate input length, "
                           "allowing an attacker to overwrite adjacent memory.\n\n"
                           "Impact:\n"
                           "1. Remote code execution\n"
                           "2. System compromise\n"
                           "3. Data theft or destruction\n"
                           "4. Service disruption\n\n"
                           "Remediation:\n"
                           "1. Update to ExampleApp version 2.1.6 or later\n"
                           "2. Apply vendor-provided patches\n"
                           "3. Implement network segmentation\n"
                           "4. Deploy intrusion detection systems\n"
                           "5. Monitor for exploitation attempts\n\n"
                           "Workarounds:\n"
                           "1. Block unnecessary network access\n"
                           "2. Implement strict firewall rules\n"
                           "3. Use network monitoring tools\n"
                           "4. Apply principle of least privilege",
                    "cve_id": "CVE-2023-1234",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "vulnerability_type": "buffer_overflow"
                }
            ]
            
            if max_samples and len(cve_samples) > max_samples:
                cve_samples = cve_samples[:max_samples]
            
            dataset = Dataset.from_list(cve_samples)
            return dataset
            
        except Exception as e:
            logger.error(f"Failed to prepare CVE dataset: {e}")
            return None

    def _generate_synthetic_data(self, max_samples: Optional[int] = None) -> Optional[Dataset]:
        """Generate synthetic cybersecurity data for training."""
        try:
            synthetic_samples = []
            
            # Generate synthetic incident reports
            incident_types = ["malware", "phishing", "data_breach", "insider_threat", "ddos"]
            severities = ["low", "medium", "high", "critical"]
            
            for i in range(20):  # Generate 20 synthetic incidents
                incident_type = incident_types[i % len(incident_types)]
                severity = severities[i % len(severities)]
                
                sample = {
                    "text": f"SYNTHETIC INCIDENT: {incident_type.title()} Attack\n\n"
                           f"Date: 2024-01-{15 + (i % 15):02d}\n"
                           f"Severity: {severity.title()}\n"
                           f"Type: {incident_type}\n"
                           f"Description: This is a synthetic incident report for training purposes. "
                           f"The incident involved a {incident_type} attack with {severity} severity. "
                           f"Response actions included isolation, analysis, and remediation steps.\n\n"
                           f"Response Actions:\n"
                           f"1. Detected and contained the threat\n"
                           f"2. Analyzed the attack vector\n"
                           f"3. Implemented remediation measures\n"
                           f"4. Conducted post-incident review\n\n"
                           f"Lessons Learned:\n"
                           f"1. Importance of early detection\n"
                           f"2. Need for automated response\n"
                           f"3. Value of regular training\n"
                           f"4. Continuous improvement of security controls",
                    "type": incident_type,
                    "severity": severity,
                    "synthetic": True,
                    "training_purpose": True
                }
                
                synthetic_samples.append(sample)
            
            # Apply max samples limit
            if max_samples and len(synthetic_samples) > max_samples:
                synthetic_samples = synthetic_samples[:max_samples]
            
            dataset = Dataset.from_list(synthetic_samples)
            return dataset
            
        except Exception as e:
            logger.error(f"Failed to generate synthetic data: {e}")
            return None

    def _combine_datasets(self, datasets: List[Dataset]) -> Dataset:
        """Combine multiple datasets into one."""
        if len(datasets) == 1:
            return datasets[0]
        
        # Concatenate datasets
        combined = concatenate_datasets(datasets)
        logger.info(f"Combined dataset size: {len(combined)}")
        return combined

    def _split_dataset(self, dataset: Dataset) -> Dict[str, Dataset]:
        """Split dataset into train/validation/test sets."""
        total_size = len(dataset)
        
        train_size = int(settings.FINE_TUNING_TRAIN_SPLIT * total_size)
        val_size = int(settings.FINE_TUNING_VAL_SPLIT * total_size)
        test_size = total_size - train_size - val_size
        
        # Split dataset
        splits = dataset.train_test_split(test_size=val_size + test_size, seed=42)
        val_test = splits['test'].train_test_split(test_size=test_size, seed=42)
        
        return {
            'train': splits['train'],
            'validation': val_test['train'],
            'test': val_test['test']
        }

    async def _save_datasets(self, datasets: Dict[str, Dataset]):
        """Save individual datasets to disk."""
        try:
            for name, dataset in datasets.items():
                output_file = self.output_path / f"{name}_dataset.json"
                dataset.to_json(str(output_file))
                logger.info(f"Saved {name} dataset to {output_file}")
                
        except Exception as e:
            logger.error(f"Failed to save datasets: {e}")

    async def export_to_huggingface_format(self, dataset: Dataset, output_path: str):
        """Export dataset to Hugging Face format."""
        try:
            output_path = Path(output_path)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Save in HF format
            dataset.save_to_disk(str(output_path))
            logger.info(f"Dataset exported to Hugging Face format: {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to export to Hugging Face format: {e}")
            raise

    def get_dataset_statistics(self, dataset: Dataset) -> Dict[str, Any]:
        """Get comprehensive statistics about the dataset."""
        try:
            stats = {
                "total_samples": len(dataset),
                "columns": list(dataset.column_names),
                "features": dataset.features,
                "split_info": dataset.info.splits if hasattr(dataset, 'info') else None
            }
            
            # Analyze text length distribution
            if "text" in dataset.column_names:
                text_lengths = [len(str(sample["text"])) for sample in dataset]
                stats["text_length"] = {
                    "min": min(text_lengths),
                    "max": max(text_lengths),
                    "mean": sum(text_lengths) / len(text_lengths),
                    "median": sorted(text_lengths)[len(text_lengths) // 2]
                }
            
            # Analyze categorical fields
            for col in dataset.column_names:
                if col != "text":
                    unique_values = set(str(sample[col]) for sample in dataset)
                    stats[f"{col}_unique_values"] = len(unique_values)
                    stats[f"{col}_values"] = list(unique_values)
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get dataset statistics: {e}")
            return {"error": str(e)}

    async def validate_dataset_quality(self, dataset: Dataset) -> Dict[str, Any]:
        """Validate dataset quality and identify potential issues."""
        try:
            quality_report = {
                "total_samples": len(dataset),
                "quality_issues": [],
                "recommendations": []
            }
            
            # Check for empty or very short texts
            if "text" in dataset.column_names:
                short_texts = [i for i, sample in enumerate(dataset) 
                             if len(str(sample["text"])) < 50]
                if short_texts:
                    quality_report["quality_issues"].append({
                        "type": "short_texts",
                        "count": len(short_texts),
                        "indices": short_texts[:10]  # Show first 10
                    })
                    quality_report["recommendations"].append(
                        "Consider removing or expanding very short text samples"
                    )
                
                # Check for duplicate texts
                texts = [str(sample["text"]) for sample in dataset]
                unique_texts = set(texts)
                if len(unique_texts) < len(texts):
                    quality_report["quality_issues"].append({
                        "type": "duplicate_texts",
                        "count": len(texts) - len(unique_texts)
                    })
                    quality_report["recommendations"].append(
                        "Remove duplicate text samples to improve training quality"
                    )
            
            # Check for missing values
            for col in dataset.column_names:
                missing_values = [i for i, sample in enumerate(dataset) 
                                if sample[col] is None or str(sample[col]).strip() == ""]
                if missing_values:
                    quality_report["quality_issues"].append({
                        "type": f"missing_values_{col}",
                        "count": len(missing_values),
                        "indices": missing_values[:10]
                    })
            
            # Overall quality score
            total_issues = sum(len(issue.get("indices", [])) for issue in quality_report["quality_issues"])
            quality_score = max(0, 100 - (total_issues / len(dataset)) * 100)
            quality_report["quality_score"] = quality_score
            
            return quality_report
            
        except Exception as e:
            logger.error(f"Failed to validate dataset quality: {e}")
            return {"error": str(e)} 