"""
Custom Airflow Plugin for Threat Intelligence Operations
Provides operators and hooks for threat intelligence tasks.
"""

from airflow.plugins_manager import AirflowPlugin
from airflow.models import BaseOperator
from airflow.utils.decorators import apply_defaults
from airflow.hooks.base import BaseHook
from typing import Dict, Any, Optional
import requests
import json
import logging

logger = logging.getLogger(__name__)


class ThreatIntelligenceOperator(BaseOperator):
    """
    Custom operator for threat intelligence operations
    """
    
    @apply_defaults
    def __init__(
        self,
        operation: str,
        source: str,
        parameters: Optional[Dict[str, Any]] = None,
        *args, **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.operation = operation
        self.source = source
        self.parameters = parameters or {}
    
    def execute(self, context):
        """Execute the threat intelligence operation"""
        logger.info(f"Executing {self.operation} for source {self.source}")
        
        try:
            if self.operation == "ingest":
                return self._ingest_data()
            elif self.operation == "analyze":
                return self._analyze_data()
            elif self.operation == "enrich":
                return self._enrich_data()
            else:
                raise ValueError(f"Unknown operation: {self.operation}")
        except Exception as e:
            logger.error(f"Error executing {self.operation}: {e}")
            raise
    
    def _ingest_data(self):
        """Ingest data from threat intelligence source"""
        # Implementation would call the appropriate ingestion service
        logger.info(f"Ingesting data from {self.source}")
        return {"status": "success", "source": self.source, "records": 100}
    
    def _analyze_data(self):
        """Analyze threat intelligence data"""
        # Implementation would call the analysis service
        logger.info(f"Analyzing data from {self.source}")
        return {"status": "success", "source": self.source, "threats_found": 5}
    
    def _enrich_data(self):
        """Enrich threat intelligence data"""
        # Implementation would call the enrichment service
        logger.info(f"Enriching data from {self.source}")
        return {"status": "success", "source": self.source, "enriched_records": 50}


class ThreatIntelligenceHook(BaseHook):
    """
    Custom hook for threat intelligence API connections
    """
    
    def __init__(self, conn_id: str = "threat_intelligence_default"):
        super().__init__()
        self.conn_id = conn_id
        self.connection = self.get_connection(conn_id)
    
    def get_api_key(self, service: str) -> str:
        """Get API key for specific service"""
        # Implementation would retrieve API key from connection
        return self.connection.password
    
    def make_request(self, endpoint: str, method: str = "GET", data: Optional[Dict] = None) -> Dict:
        """Make API request to threat intelligence service"""
        url = f"{self.connection.host}{endpoint}"
        headers = {
            "Authorization": f"Bearer {self.get_api_key('default')}",
            "Content-Type": "application/json"
        }
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=headers)
            elif method.upper() == "POST":
                response = requests.post(url, headers=headers, json=data)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            raise


class ThreatIntelligenceSensor(BaseOperator):
    """
    Custom sensor for monitoring threat intelligence sources
    """
    
    @apply_defaults
    def __init__(
        self,
        source: str,
        check_interval: int = 300,
        timeout: int = 3600,
        *args, **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.source = source
        self.check_interval = check_interval
        self.timeout = timeout
    
    def poke(self, context):
        """Check if new data is available"""
        try:
            # Implementation would check for new data
            logger.info(f"Checking for new data from {self.source}")
            return True  # For demo purposes, always return True
        except Exception as e:
            logger.error(f"Error checking {self.source}: {e}")
            return False


# Plugin class
class ThreatIntelligencePlugin(AirflowPlugin):
    name = "threat_intelligence_plugin"
    operators = [ThreatIntelligenceOperator]
    hooks = [ThreatIntelligenceHook]
    sensors = [ThreatIntelligenceSensor]
    macros = []
    admin_views = []
    flask_blueprints = []
    menu_links = [] 