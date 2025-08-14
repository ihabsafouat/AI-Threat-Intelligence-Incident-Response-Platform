"""
DynamoDB Service Module

Handles data storage and querying in Amazon DynamoDB for threat intelligence.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Union
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import logging

from .config import AWSConfig

logger = logging.getLogger(__name__)


class DynamoDBService:
    """Amazon DynamoDB Service for threat intelligence data"""
    
    def __init__(self, config: AWSConfig, table_name: Optional[str] = None):
        """
        Initialize DynamoDB service.
        
        Args:
            config: AWS configuration
            table_name: DynamoDB table name (defaults to environment variable)
        """
        self.config = config
        self.table_name = table_name or 'threat-intelligence'
        self.dynamodb_client = config.get_client('dynamodb')
        self.dynamodb_resource = config.get_resource('dynamodb')
        self.table = self.dynamodb_resource.Table(self.table_name)
    
    def create_threat_record(
        self,
        threat_data: Dict[str, Any],
        threat_id: Optional[str] = None,
        threat_type: str = 'malware',
        severity: str = 'medium',
        source: str = 'manual'
    ) -> Dict[str, Any]:
        """
        Create a new threat intelligence record in DynamoDB.
        
        Args:
            threat_data: Threat intelligence data
            threat_id: Unique threat identifier (auto-generated if not provided)
            threat_type: Type of threat (malware, phishing, etc.)
            severity: Threat severity (low, medium, high, critical)
            source: Data source
        
        Returns:
            Creation result dictionary
        """
        try:
            # Generate threat ID if not provided
            if not threat_id:
                threat_id = str(uuid.uuid4())
            
            # Create timestamp
            timestamp = datetime.now(timezone.utc).isoformat()
            
            # Prepare item for DynamoDB
            item = {
                'threat_id': threat_id,
                'timestamp': timestamp,
                'threat_type': threat_type,
                'severity': severity,
                'source': source,
                'data': threat_data,
                'created_at': timestamp,
                'updated_at': timestamp,
                'status': 'active'
            }
            
            # Add TTL if configured
            if 'TTL_DAYS' in threat_data:
                ttl_timestamp = int(datetime.now(timezone.utc).timestamp()) + (threat_data['TTL_DAYS'] * 24 * 60 * 60)
                item['ttl'] = ttl_timestamp
            
            # Put item in DynamoDB
            self.table.put_item(Item=item)
            
            logger.info(f"Successfully created threat record {threat_id}")
            
            return {
                'success': True,
                'threat_id': threat_id,
                'timestamp': timestamp,
                'item': item
            }
            
        except Exception as e:
            logger.error(f"Failed to create threat record: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_threat_record(self, threat_id: str) -> Dict[str, Any]:
        """
        Retrieve a threat record by ID.
        
        Args:
            threat_id: Threat identifier
            
        Returns:
            Threat record dictionary
        """
        try:
            response = self.table.get_item(
                Key={
                    'threat_id': threat_id
                }
            )
            
            if 'Item' not in response:
                return {'success': False, 'error': 'Threat record not found'}
            
            return {
                'success': True,
                'item': response['Item']
            }
            
        except Exception as e:
            logger.error(f"Failed to get threat record: {e}")
            return {'success': False, 'error': str(e)}
    
    def update_threat_record(
        self,
        threat_id: str,
        updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Update an existing threat record.
        
        Args:
            threat_id: Threat identifier
            updates: Fields to update
            
        Returns:
            Update result dictionary
        """
        try:
            # Prepare update expression
            update_expression = "SET "
            expression_attribute_values = {}
            expression_attribute_names = {}
            
            for key, value in updates.items():
                if key not in ['threat_id', 'timestamp']:  # Don't allow updating primary key
                    update_expression += f"#{key} = :{key}, "
                    expression_attribute_names[f"#{key}"] = key
                    expression_attribute_values[f":{key}"] = value
            
            # Add updated_at timestamp
            update_expression += "#updated_at = :updated_at"
            expression_attribute_names["#updated_at"] = "updated_at"
            expression_attribute_values[":updated_at"] = datetime.now(timezone.utc).isoformat()
            
            response = self.table.update_item(
                Key={
                    'threat_id': threat_id
                },
                UpdateExpression=update_expression,
                ExpressionAttributeNames=expression_attribute_names,
                ExpressionAttributeValues=expression_attribute_values,
                ReturnValues="ALL_NEW"
            )
            
            logger.info(f"Successfully updated threat record {threat_id}")
            
            return {
                'success': True,
                'item': response['Attributes']
            }
            
        except Exception as e:
            logger.error(f"Failed to update threat record: {e}")
            return {'success': False, 'error': str(e)}
    
    def delete_threat_record(self, threat_id: str) -> Dict[str, Any]:
        """
        Delete a threat record.
        
        Args:
            threat_id: Threat identifier
            
        Returns:
            Delete result dictionary
        """
        try:
            self.table.delete_item(
                Key={
                    'threat_id': threat_id
                }
            )
            
            logger.info(f"Successfully deleted threat record {threat_id}")
            
            return {'success': True, 'threat_id': threat_id}
            
        except Exception as e:
            logger.error(f"Failed to delete threat record: {e}")
            return {'success': False, 'error': str(e)}
    
    def query_threats_by_type(
        self,
        threat_type: str,
        limit: int = 100,
        start_key: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Query threats by type using GSI.
        
        Args:
            threat_type: Type of threat to query
            limit: Maximum number of results
            start_key: Pagination key
            
        Returns:
            Query results dictionary
        """
        try:
            query_params = {
                'IndexName': 'threat_type_index',
                'KeyConditionExpression': '#threat_type = :threat_type',
                'ExpressionAttributeNames': {
                    '#threat_type': 'threat_type'
                },
                'ExpressionAttributeValues': {
                    ':threat_type': threat_type
                },
                'Limit': limit
            }
            
            if start_key:
                query_params['ExclusiveStartKey'] = start_key
            
            response = self.table.query(**query_params)
            
            return {
                'success': True,
                'items': response.get('Items', []),
                'count': response.get('Count', 0),
                'last_evaluated_key': response.get('LastEvaluatedKey'),
                'scanned_count': response.get('ScannedCount', 0)
            }
            
        except Exception as e:
            logger.error(f"Failed to query threats by type: {e}")
            return {'success': False, 'error': str(e)}
    
    def query_threats_by_severity(
        self,
        severity: str,
        limit: int = 100,
        start_key: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Query threats by severity using GSI.
        
        Args:
            severity: Severity level to query
            limit: Maximum number of results
            start_key: Pagination key
            
        Returns:
            Query results dictionary
        """
        try:
            query_params = {
                'IndexName': 'severity_index',
                'KeyConditionExpression': '#severity = :severity',
                'ExpressionAttributeNames': {
                    '#severity': 'severity'
                },
                'ExpressionAttributeValues': {
                    ':severity': severity
                },
                'Limit': limit
            }
            
            if start_key:
                query_params['ExclusiveStartKey'] = start_key
            
            response = self.table.query(**query_params)
            
            return {
                'success': True,
                'items': response.get('Items', []),
                'count': response.get('Count', 0),
                'last_evaluated_key': response.get('LastEvaluatedKey'),
                'scanned_count': response.get('ScannedCount', 0)
            }
            
        except Exception as e:
            logger.error(f"Failed to query threats by severity: {e}")
            return {'success': False, 'error': str(e)}
    
    def scan_threats(
        self,
        filter_expression: Optional[str] = None,
        expression_attribute_names: Optional[Dict[str, str]] = None,
        expression_attribute_values: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        start_key: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Scan all threat records with optional filtering.
        
        Args:
            filter_expression: DynamoDB filter expression
            expression_attribute_names: Expression attribute names
            expression_attribute_values: Expression attribute values
            limit: Maximum number of results
            start_key: Pagination key
            
        Returns:
            Scan results dictionary
        """
        try:
            scan_params = {
                'Limit': limit
            }
            
            if filter_expression:
                scan_params['FilterExpression'] = filter_expression
            
            if expression_attribute_names:
                scan_params['ExpressionAttributeNames'] = expression_attribute_names
            
            if expression_attribute_values:
                scan_params['ExpressionAttributeValues'] = expression_attribute_values
            
            if start_key:
                scan_params['ExclusiveStartKey'] = start_key
            
            response = self.table.scan(**scan_params)
            
            return {
                'success': True,
                'items': response.get('Items', []),
                'count': response.get('Count', 0),
                'last_evaluated_key': response.get('LastEvaluatedKey'),
                'scanned_count': response.get('ScannedCount', 0)
            }
            
        except Exception as e:
            logger.error(f"Failed to scan threats: {e}")
            return {'success': False, 'error': str(e)}
    
    def batch_write_threats(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Write multiple threat records in batch.
        
        Args:
            threats: List of threat records to write
            
        Returns:
            Batch write result dictionary
        """
        try:
            # Prepare items for batch write
            items = []
            for threat in threats:
                threat_id = threat.get('threat_id') or str(uuid.uuid4())
                timestamp = datetime.now(timezone.utc).isoformat()
                
                item = {
                    'threat_id': threat_id,
                    'timestamp': timestamp,
                    'threat_type': threat.get('threat_type', 'unknown'),
                    'severity': threat.get('severity', 'medium'),
                    'source': threat.get('source', 'batch'),
                    'data': threat.get('data', {}),
                    'created_at': timestamp,
                    'updated_at': timestamp,
                    'status': threat.get('status', 'active')
                }
                
                items.append({
                    'PutRequest': {
                        'Item': item
                    }
                })
            
            # Split into batches of 25 (DynamoDB limit)
            batch_size = 25
            batches = [items[i:i + batch_size] for i in range(0, len(items), batch_size)]
            
            unprocessed_items = []
            
            for batch in batches:
                response = self.dynamodb_client.batch_write_item(
                    RequestItems={
                        self.table_name: batch
                    }
                )
                
                if 'UnprocessedItems' in response and response['UnprocessedItems']:
                    unprocessed_items.extend(response['UnprocessedItems'].get(self.table_name, []))
            
            logger.info(f"Successfully batch wrote {len(items) - len(unprocessed_items)} threat records")
            
            return {
                'success': True,
                'processed_count': len(items) - len(unprocessed_items),
                'unprocessed_count': len(unprocessed_items),
                'unprocessed_items': unprocessed_items
            }
            
        except Exception as e:
            logger.error(f"Failed to batch write threats: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_table_info(self) -> Dict[str, Any]:
        """
        Get DynamoDB table information.
        
        Returns:
            Table information dictionary
        """
        try:
            response = self.dynamodb_client.describe_table(
                TableName=self.table_name
            )
            
            table_info = response['Table']
            
            return {
                'success': True,
                'table_name': table_info['TableName'],
                'table_status': table_info['TableStatus'],
                'item_count': table_info.get('ItemCount', 0),
                'table_size_bytes': table_info.get('TableSizeBytes', 0),
                'creation_date': table_info['CreationDateTime'].isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get table info: {e}")
            return {'success': False, 'error': str(e)}
    
    def create_table_if_not_exists(self) -> Dict[str, Any]:
        """
        Create the DynamoDB table if it doesn't exist.
        
        Returns:
            Table creation result dictionary
        """
        try:
            # Check if table exists
            try:
                self.dynamodb_client.describe_table(TableName=self.table_name)
                return {'success': True, 'message': 'Table already exists'}
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceNotFoundException':
                    raise
            
            # Create table
            table = self.dynamodb_resource.create_table(
                TableName=self.table_name,
                KeySchema=[
                    {
                        'AttributeName': 'threat_id',
                        'KeyType': 'HASH'  # Partition key
                    },
                    {
                        'AttributeName': 'timestamp',
                        'KeyType': 'RANGE'  # Sort key
                    }
                ],
                AttributeDefinitions=[
                    {
                        'AttributeName': 'threat_id',
                        'AttributeType': 'S'
                    },
                    {
                        'AttributeName': 'timestamp',
                        'AttributeType': 'S'
                    },
                    {
                        'AttributeName': 'threat_type',
                        'AttributeType': 'S'
                    },
                    {
                        'AttributeName': 'severity',
                        'AttributeType': 'S'
                    }
                ],
                GlobalSecondaryIndexes=[
                    {
                        'IndexName': 'threat_type_index',
                        'KeySchema': [
                            {
                                'AttributeName': 'threat_type',
                                'KeyType': 'HASH'
                            },
                            {
                                'AttributeName': 'timestamp',
                                'KeyType': 'RANGE'
                            }
                        ],
                        'Projection': {
                            'ProjectionType': 'ALL'
                        },
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 5,
                            'WriteCapacityUnits': 5
                        }
                    },
                    {
                        'IndexName': 'severity_index',
                        'KeySchema': [
                            {
                                'AttributeName': 'severity',
                                'KeyType': 'HASH'
                            },
                            {
                                'AttributeName': 'timestamp',
                                'KeyType': 'RANGE'
                            }
                        ],
                        'Projection': {
                            'ProjectionType': 'ALL'
                        },
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 5,
                            'WriteCapacityUnits': 5
                        }
                    }
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 10,
                    'WriteCapacityUnits': 10
                }
            )
            
            # Wait for table to be created
            table.meta.client.get_waiter('table_exists').wait(TableName=self.table_name)
            
            logger.info(f"Successfully created DynamoDB table {self.table_name}")
            
            return {'success': True, 'table_name': self.table_name}
            
        except Exception as e:
            logger.error(f"Failed to create table: {e}")
            return {'success': False, 'error': str(e)} 