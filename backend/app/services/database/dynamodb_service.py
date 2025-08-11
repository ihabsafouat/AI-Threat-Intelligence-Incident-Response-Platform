from typing import Any, Dict, Optional
from datetime import datetime, timedelta, timezone
import logging
import json

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
            self._threat_table.put_item(Item=item)
            return True
        except ClientError as e:
            logger.error(f"Failed to store threat data in DynamoDB: {e}")
            return False

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