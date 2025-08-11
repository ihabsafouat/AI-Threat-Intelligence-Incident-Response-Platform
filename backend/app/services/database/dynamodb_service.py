from typing import Any, Dict, Optional
from datetime import datetime, timedelta
import logging

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
                "timestamp": (timestamp or datetime.utcnow()).isoformat(),
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
            cutoff = datetime.utcnow() - timedelta(days=days_old)
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