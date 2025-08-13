#!/usr/bin/env python3
"""
AWS CDK Infrastructure for AI Threat Intelligence Platform

This CDK app creates the complete infrastructure including:
- S3 buckets for data storage and ML models
- DynamoDB tables for threat intelligence and metadata
- Lambda functions for data processing
- ECS services for fine-tuning and RAG
- Supporting infrastructure (VPC, IAM, etc.)
"""

import os
from aws_cdk import (
    App, Stack, Duration, RemovalPolicy, CfnOutput,
    aws_s3 as s3,
    aws_dynamodb as dynamodb,
    aws_lambda as lambda_,
    aws_ecs as ecs,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_logs as logs,
    aws_secretsmanager as secretsmanager,
    aws_ecs_patterns as ecs_patterns,
    aws_apigateway as apigateway,
    aws_elasticache as elasticache,
    aws_rds as rds,
    aws_sqs as sqs,
    aws_sns as sns,
    aws_events as events,
    aws_events_targets as targets,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_s3_deployment as s3_deployment,
    aws_route53 as route53,
    aws_certificatemanager as acm,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_wafv2 as wafv2,
    aws_kms as kms,
    aws_backup as backup,
    aws_guardduty as guardduty,
    aws_config as config,
    aws_cloudtrail as cloudtrail,
    aws_ssm as ssm,
    aws_ecr as ecr,
    aws_batch as batch,
    aws_sagemaker as sagemaker,
    aws_opensearchservice as opensearch,
    aws_elasticloadbalancingv2 as elbv2,
    aws_autoscaling as autoscaling,
    aws_applicationautoscaling as appscaling,
    aws_servicediscovery as servicediscovery,
)
from constructs import Construct


class ThreatIntelligenceStack(Stack):
    """Main stack for the AI Threat Intelligence Platform."""
    
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Environment variables
        self.environment = os.getenv('ENVIRONMENT', 'dev')
        self.project_name = 'threat-intelligence-platform'
        self.domain_name = os.getenv('DOMAIN_NAME', 'threatintel.example.com')
        
        # Create KMS keys for encryption
        self.create_kms_keys()
        
        # Create VPC and networking
        self.create_networking()
        
        # Create S3 buckets
        self.create_s3_buckets()
        
        # Create DynamoDB tables
        self.create_dynamodb_tables()
        
        # Create ECR repositories
        self.create_ecr_repositories()
        
        # Create Lambda functions
        self.create_lambda_functions()
        
        # Create ECS cluster and services
        self.create_ecs_services()
        
        # Create API Gateway
        self.create_api_gateway()
        
        # Create supporting services
        self.create_supporting_services()
        
        # Create monitoring and alerting
        self.create_monitoring()
        
        # Create security services
        self.create_security_services()
        
        # Create backup and disaster recovery
        self.create_backup_recovery()
        
        # Output important values
        self.create_outputs()

    def create_kms_keys(self):
        """Create KMS keys for encryption."""
        # Main encryption key
        self.encryption_key = kms.Key(
            self, "EncryptionKey",
            description="KMS key for Threat Intelligence Platform encryption",
            enable_key_rotation=True,
            alias=f"{self.project_name}-encryption-key"
        )
        
        # S3 encryption key
        self.s3_encryption_key = kms.Key(
            self, "S3EncryptionKey",
            description="KMS key for S3 bucket encryption",
            enable_key_rotation=True,
            alias=f"{self.project_name}-s3-encryption-key"
        )
        
        # DynamoDB encryption key
        self.dynamodb_encryption_key = kms.Key(
            self, "DynamoDBEncryptionKey",
            description="KMS key for DynamoDB table encryption",
            enable_key_rotation=True,
            alias=f"{self.project_name}-dynamodb-encryption-key"
        )

    def create_networking(self):
        """Create VPC and networking infrastructure."""
        # VPC
        self.vpc = ec2.Vpc(
            self, "ThreatIntelligenceVPC",
            max_azs=3,
            nat_gateways=3,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name="Isolated",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24
                )
            ],
            gateway_endpoints={
                "S3": ec2.GatewayVpcEndpointAwsService.S3,
                "DynamoDB": ec2.GatewayVpcEndpointAwsService.DYNAMODB
            }
        )
        
        # Security Groups
        self.ecs_security_group = ec2.SecurityGroup(
            self, "ECSSecurityGroup",
            vpc=self.vpc,
            description="Security group for ECS services",
            allow_all_outbound=True
        )
        
        self.lambda_security_group = ec2.SecurityGroup(
            self, "LambdaSecurityGroup",
            vpc=self.vpc,
            description="Security group for Lambda functions",
            allow_all_outbound=True
        )
        
        # Allow Lambda to access ECS
        self.ecs_security_group.add_ingress_rule(
            peer=self.lambda_security_group,
            connection=ec2.Port.tcp(8080),
            description="Allow Lambda to access ECS services"
        )

    def create_s3_buckets(self):
        """Create S3 buckets for data storage."""
        # Main data bucket
        self.data_bucket = s3.Bucket(
            self, "ThreatIntelligenceData",
            bucket_name=f"{self.project_name}-data-{self.environment}-{self.account}",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.s3_encryption_key,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="DataLifecycle",
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INTELLIGENT_TIERING,
                            transition_after=Duration.days(30)
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(90)
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.DEEP_ARCHIVE,
                            transition_after=Duration.days(365)
                        )
                    ]
                )
            ]
        )
        
        # ML models bucket
        self.ml_models_bucket = s3.Bucket(
            self, "MLModelsBucket",
            bucket_name=f"{self.project_name}-ml-models-{self.environment}-{self.account}",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.s3_encryption_key,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Fine-tuning data bucket
        self.fine_tuning_bucket = s3.Bucket(
            self, "FineTuningDataBucket",
            bucket_name=f"{self.project_name}-fine-tuning-{self.environment}-{self.account}",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.s3_encryption_key,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Logs bucket
        self.logs_bucket = s3.Bucket(
            self, "LogsBucket",
            bucket_name=f"{self.project_name}-logs-{self.environment}-{self.account}",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.s3_encryption_key,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="LogsLifecycle",
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INTELLIGENT_TIERING,
                            transition_after=Duration.days(7)
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(30)
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.DEEP_ARCHIVE,
                            transition_after=Duration.days(90)
                        )
                    ],
                    expiration=Duration.days(2555)  # 7 years
                )
            ]
        )
        
        # Create CloudWatch log groups
        self.create_log_groups()

    def create_dynamodb_tables(self):
        """Create DynamoDB tables for threat intelligence data."""
        # Main threat intelligence table
        self.threat_intelligence_table = dynamodb.Table(
            self, "ThreatIntelligenceTable",
            table_name=f"{self.project_name}-threats-{self.environment}",
            partition_key=dynamodb.Attribute(
                name="threat_id",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.dynamodb_encryption_key,
            removal_policy=RemovalPolicy.RETAIN,
            point_in_time_recovery=True,
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES
        )
        
        # Add GSI for threat type queries
        self.threat_intelligence_table.add_global_secondary_index(
            index_name="ThreatTypeIndex",
            partition_key=dynamodb.Attribute(
                name="threat_type",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="severity",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )
        
        # Add GSI for source queries
        self.threat_intelligence_table.add_global_secondary_index(
            index_name="SourceIndex",
            partition_key=dynamodb.Attribute(
                name="source",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="confidence",
                type=dynamodb.AttributeType.NUMBER
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )
        
        # Ingestion metadata table
        self.ingestion_metadata_table = dynamodb.Table(
            self, "IngestionMetadataTable",
            table_name=f"{self.project_name}-ingestion-{self.environment}",
            partition_key=dynamodb.Attribute(
                name="source_id",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="ingestion_time",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.dynamodb_encryption_key,
            removal_policy=RemovalPolicy.RETAIN,
            point_in_time_recovery=True
        )
        
        # CVE data table
        self.cve_table = dynamodb.Table(
            self, "CVETable",
            table_name=f"{self.project_name}-cve-{self.environment}",
            partition_key=dynamodb.Attribute(
                name="cve_id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.dynamodb_encryption_key,
            removal_policy=RemovalPolicy.RETAIN,
            point_in_time_recovery=True
        )
        
        # Add GSI for affected software queries
        self.cve_table.add_global_secondary_index(
            index_name="AffectedSoftwareIndex",
            partition_key=dynamodb.Attribute(
                name="affected_software",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="cvss_score",
                type=dynamodb.AttributeType.NUMBER
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

    def create_ecr_repositories(self):
        """Create ECR repositories for container images."""
        # Main application repository
        self.app_repository = ecr.Repository(
            self, "AppRepository",
            repository_name=f"{self.project_name}-app",
            image_scan_on_push=True,
            encryption=ecr.RepositoryEncryption.KMS,
            encryption_key=self.encryption_key,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                ecr.LifecycleRule(
                    rule_priority=1,
                    description="Keep only 10 images",
                    max_image_count=10
                )
            ]
        )
        
        # Fine-tuning repository
        self.fine_tuning_repository = ecr.Repository(
            self, "FineTuningRepository",
            repository_name=f"{self.project_name}-fine-tuning",
            image_scan_on_push=True,
            encryption=ecr.RepositoryEncryption.KMS,
            encryption_key=self.encryption_key,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                ecr.LifecycleRule(
                    rule_priority=1,
                    description="Keep only 5 images",
                    max_image_count=5
                )
            ]
        )
        
        # RAG service repository
        self.rag_repository = ecr.Repository(
            self, "RAGRepository",
            repository_name=f"{self.project_name}-rag",
            image_scan_on_push=True,
            encryption=ecr.RepositoryEncryption.KMS,
            encryption_key=self.encryption_key,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                ecr.LifecycleRule(
                    rule_priority=1,
                    description="Keep only 5 images",
                    max_image_count=5
                )
            ]
        )

    def create_lambda_functions(self):
        """Create Lambda functions for data processing."""
        # Data ingestion Lambda
        self.data_ingestion_lambda = lambda_.Function(
            self, "DataIngestionLambda",
            function_name=f"{self.project_name}-data-ingestion-{self.environment}",
            runtime=lambda_.Runtime.PYTHON_3_11,
            code=lambda_.Code.from_asset("lambda/data_ingestion"),
            handler="index.handler",
            timeout=Duration.minutes(15),
            memory_size=1024,
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[self.lambda_security_group],
            environment={
                "DYNAMODB_TABLE": self.threat_intelligence_table.table_name,
                "S3_BUCKET": self.data_bucket.bucket_name,
                "ENVIRONMENT": self.environment
            },
            reserved_concurrent_executions=10
        )
        
        # Grant permissions
        self.threat_intelligence_table.grant_write_data(self.data_ingestion_lambda)
        self.data_bucket.grant_read_write(self.data_ingestion_lambda)
        
        # Data processing Lambda
        self.data_processing_lambda = lambda_.Function(
            self, "DataProcessingLambda",
            function_name=f"{self.project_name}-data-processing-{self.environment}",
            runtime=lambda_.Runtime.PYTHON_3_11,
            code=lambda_.Code.from_asset("lambda/data_processing"),
            handler="index.handler",
            timeout=Duration.minutes(15),
            memory_size=2048,
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[self.lambda_security_group],
            environment={
                "DYNAMODB_TABLE": self.threat_intelligence_table.table_name,
                "S3_BUCKET": self.data_bucket.bucket_name,
                "ENVIRONMENT": self.environment
            }
        )
        
        # Grant permissions
        self.threat_intelligence_table.grant_read_write_data(self.data_processing_lambda)
        self.data_bucket.grant_read_write(self.data_processing_lambda)

    def create_ecs_services(self):
        """Create ECS cluster and services."""
        # ECS Cluster
        self.ecs_cluster = ecs.Cluster(
            self, "ThreatIntelligenceCluster",
            cluster_name=f"{self.project_name}-cluster-{self.environment}",
            vpc=self.vpc,
            container_insights=True,
            capacity_providers=["FARGATE", "FARGATE_SPOT"],
            default_capacity_provider_strategy=[
                ecs.CapacityProviderStrategy(
                    capacity_provider="FARGATE",
                    weight=1
                ),
                ecs.CapacityProviderStrategy(
                    capacity_provider="FARGATE_SPOT",
                    weight=1
                )
            ]
        )
        
        # Task execution role
        self.task_execution_role = iam.Role(
            self, "TaskExecutionRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AmazonECSTaskExecutionRolePolicy")
            ]
        )
        
        # Task role
        self.task_role = iam.Role(
            self, "TaskRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3FullAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonDynamoDBFullAccess")
            ]
        )
        
        # Main application service
        self.app_service = ecs.FargateService(
            self, "AppService",
            cluster=self.ecs_cluster,
            task_definition=ecs.FargateTaskDefinition(
                self, "AppTaskDef",
                task_role=self.task_role,
                execution_role=self.task_execution_role,
                memory_limit_mib=2048,
                cpu=1024,
                family=f"{self.project_name}-app-{self.environment}",
                container_definitions=[
                    ecs.ContainerDefinition(
                        name="app",
                        image=ecs.ContainerImage.from_ecr_repository(self.app_repository, "latest"),
                        essential=True,
                        port_mappings=[ecs.PortMapping(container_port=8080)],
                        environment={
                            "DYNAMODB_TABLE": self.threat_intelligence_table.table_name,
                            "S3_BUCKET": self.data_bucket.bucket_name,
                            "ENVIRONMENT": self.environment
                        },
                        log_configuration=ecs.LogConfiguration(
                            log_driver=ecs.LogDriver.AWS_LOGS,
                            options={
                                "awslogs-group": self.app_log_group.log_group_name,
                                "awslogs-region": self.region,
                                "awslogs-stream-prefix": "app"
                            }
                        )
                    )
                ]
            ),
            service_name=f"{self.project_name}-app-{self.environment}",
            desired_count=2,
            security_groups=[self.ecs_security_group],
            assign_public_ip=False,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
        )
        
        # Fine-tuning service
        self.fine_tuning_service = ecs.FargateService(
            self, "FineTuningService",
            cluster=self.ecs_cluster,
            task_definition=ecs.FargateTaskDefinition(
                self, "FineTuningTaskDef",
                task_role=self.task_role,
                execution_role=self.task_execution_role,
                memory_limit_mib=8192,
                cpu=4096,
                family=f"{self.project_name}-fine-tuning-{self.environment}",
                container_definitions=[
                    ecs.ContainerDefinition(
                        name="fine-tuning",
                        image=ecs.ContainerImage.from_ecr_repository(self.fine_tuning_repository, "latest"),
                        essential=True,
                        port_mappings=[ecs.PortMapping(container_port=8080)],
                        environment={
                            "DYNAMODB_TABLE": self.threat_intelligence_table.table_name,
                            "S3_BUCKET": self.data_bucket.bucket_name,
                            "ENVIRONMENT": self.environment
                        },
                        log_configuration=ecs.LogConfiguration(
                            log_driver=ecs.LogDriver.AWS_LOGS,
                            options={
                                "awslogs-group": self.fine_tuning_log_group.log_group_name,
                                "awslogs-region": self.region,
                                "awslogs-stream-prefix": "fine-tuning"
                            }
                        )
                    )
                ]
            ),
            service_name=f"{self.project_name}-fine-tuning-{self.environment}",
            desired_count=1,
            security_groups=[self.ecs_security_group],
            assign_public_ip=False,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
        )
        
        # RAG service
        self.rag_service = ecs.FargateService(
            self, "RAGService",
            cluster=self.ecs_cluster,
            task_definition=ecs.FargateTaskDefinition(
                self, "RAGTaskDef",
                task_role=self.task_role,
                execution_role=self.task_execution_role,
                memory_limit_mib=4096,
                cpu=2048,
                family=f"{self.project_name}-rag-{self.environment}",
                container_definitions=[
                    ecs.ContainerDefinition(
                        name="rag",
                        image=ecs.ContainerImage.from_ecr_repository(self.rag_repository, "latest"),
                        essential=True,
                        port_mappings=[ecs.PortMapping(container_port=8080)],
                        environment={
                            "DYNAMODB_TABLE": self.threat_intelligence_table.table_name,
                            "S3_BUCKET": self.data_bucket.bucket_name,
                            "ENVIRONMENT": self.environment
                        },
                        log_configuration=ecs.LogConfiguration(
                            log_driver=ecs.LogDriver.AWS_LOGS,
                            options={
                                "awslogs-group": self.rag_log_group.log_group_name,
                                "awslogs-region": self.region,
                                "awslogs-stream-prefix": "rag"
                            }
                        )
                    )
                ]
            ),
            service_name=f"{self.project_name}-rag-{self.environment}",
            desired_count=2,
            security_groups=[self.ecs_security_group],
            assign_public_ip=False,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
        )

    def create_api_gateway(self):
        """Create API Gateway for the application."""
        # API Gateway
        self.api = apigateway.RestApi(
            self, "ThreatIntelligenceAPI",
            rest_api_name=f"{self.project_name}-api-{self.environment}",
            description="API Gateway for Threat Intelligence Platform",
            default_cors_preflight_options=apigateway.CorsOptions(
                allow_origins=["*"],
                allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                allow_headers=["*"]
            ),
            deploy_options=apigateway.StageOptions(
                stage_name=self.environment,
                logging_level=apigateway.MethodLoggingLevel.INFO,
                data_trace_enabled=True,
                metrics_enabled=True
            )
        )
        
        # Create API key and usage plan
        api_key = self.api.add_api_key(
            "ThreatIntelligenceAPIKey",
            api_key_name=f"{self.project_name}-api-key-{self.environment}"
        )
        
        usage_plan = self.api.add_usage_plan(
            "ThreatIntelligenceUsagePlan",
            name=f"{self.project_name}-usage-plan-{self.environment}",
            api_stages=[apigateway.UsagePlanPerApiStage(api=self.api, stage=self.api.deployment_stage)],
            throttle=apigateway.ThrottleSettings(
                rate_limit=1000,
                burst_limit=2000
            ),
            quota=apigateway.QuotaSettings(
                limit=1000000,
                period=apigateway.Period.MONTH
            )
        )
        
        usage_plan.add_api_key(api_key)

    def create_supporting_services(self):
        """Create supporting services like SQS, SNS, etc."""
        # SQS queue for data processing
        self.data_processing_queue = sqs.Queue(
            self, "DataProcessingQueue",
            queue_name=f"{self.project_name}-data-processing-{self.environment}",
            visibility_timeout=Duration.seconds(300),
            retention_period=Duration.days(14),
            encryption=sqs.QueueEncryption.KMS,
            encryption_master_key=self.encryption_key,
            dead_letter_queue=sqs.DeadLetterQueue(
                max_receive_count=3,
                queue=sqs.Queue(
                    self, "DataProcessingDLQ",
                    queue_name=f"{self.project_name}-data-processing-dlq-{self.environment}",
                    encryption=sqs.QueueEncryption.KMS,
                    encryption_master_key=self.encryption_key
                )
            )
        )
        
        # SNS topic for notifications
        self.notifications_topic = sns.Topic(
            self, "NotificationsTopic",
            topic_name=f"{self.project_name}-notifications-{self.environment}",
            display_name="Threat Intelligence Notifications"
        )
        
        # CloudWatch Events rule for scheduled tasks
        self.scheduled_rule = events.Rule(
            self, "ScheduledDataProcessing",
            rule_name=f"{self.project_name}-scheduled-processing-{self.environment}",
            schedule=events.Schedule.rate(Duration.hours(1)),
            targets=[
                targets.LambdaFunction(self.data_processing_lambda)
            ]
        )

    def create_monitoring(self):
        """Create monitoring and alerting infrastructure."""
        # CloudWatch dashboard
        dashboard = cloudwatch.Dashboard(
            self, "ThreatIntelligenceDashboard",
            dashboard_name=f"{self.project_name}-dashboard-{self.environment}"
        )
        
        # Add widgets to dashboard
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Lambda Invocations",
                left=[self.data_ingestion_lambda.metric_invocations()],
                right=[self.data_processing_lambda.metric_invocations()]
            ),
            cloudwatch.GraphWidget(
                title="Lambda Errors",
                left=[self.data_ingestion_lambda.metric_errors()],
                right=[self.data_processing_lambda.metric_errors()]
            ),
            cloudwatch.GraphWidget(
                title="DynamoDB Read/Write",
                left=[self.threat_intelligence_table.metric_consumed_read_capacity_units()],
                right=[self.threat_intelligence_table.metric_consumed_write_capacity_units()]
            )
        )
        
        # CloudWatch alarms
        # Lambda error alarm
        lambda_error_alarm = cloudwatch.Alarm(
            self, "LambdaErrorAlarm",
            metric=self.data_ingestion_lambda.metric_errors(),
            threshold=5,
            evaluation_periods=2,
            alarm_description="Lambda function errors exceeded threshold"
        )
        
        # DynamoDB throttling alarm
        dynamodb_throttle_alarm = cloudwatch.Alarm(
            self, "DynamoDBThrottleAlarm",
            metric=self.threat_intelligence_table.metric_throttled_requests(),
            threshold=10,
            evaluation_periods=2,
            alarm_description="DynamoDB throttling exceeded threshold"
        )
        
        # Add actions to alarms
        lambda_error_alarm.add_alarm_action(
            cw_actions.SnsAction(self.notifications_topic)
        )
        
        dynamodb_throttle_alarm.add_alarm_action(
            cw_actions.SnsAction(self.notifications_topic)
        )

    def create_security_services(self):
        """Create security services and configurations."""
        # GuardDuty
        guardduty.CfnDetector(
            self, "GuardDutyDetector",
            enable=True
        )
        
        # Config
        config.CfnConfigurationRecorder(
            self, "ConfigRecorder",
            role_arn=self.task_execution_role.role_arn,
            recording_group=config.CfnConfigurationRecorder.RecordingGroupProperty(
                all_supported=True,
                include_global_resources=True
            )
        )
        
        # CloudTrail
        cloudtrail.Trail(
            self, "CloudTrail",
            trail_name=f"{self.project_name}-trail-{self.environment}",
            s3_bucket=self.logs_bucket,
            include_global_service_events=True,
            is_multi_region_trail=True,
            enable_file_validation=True
        )
        
        # WAF for API Gateway
        waf_web_acl = wafv2.CfnWebACL(
            self, "WAFWebACL",
            default_action=wafv2.CfnWebACL.DefaultActionProperty(
                allow=wafv2.CfnWebACL.AllowActionProperty()
            ),
            scope="REGIONAL",
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="ThreatIntelligenceWAFMetrics",
                sampled_requests_enabled=True
            ),
            rules=[
                wafv2.CfnWebACL.RuleProperty(
                    name="RateLimitRule",
                    priority=1,
                    statement=wafv2.CfnWebACL.StatementProperty(
                        rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                            limit=2000,
                            aggregate_key_type="IP"
                        )
                    ),
                    action=wafv2.CfnWebACL.ActionProperty(
                        block=wafv2.CfnWebACL.BlockActionProperty()
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="RateLimitRule",
                        sampled_requests_enabled=True
                    )
                )
            ]
        )

    def create_backup_recovery(self):
        """Create backup and disaster recovery infrastructure."""
        # AWS Backup vault
        backup_vault = backup.CfnBackupVault(
            self, "BackupVault",
            backup_vault_name=f"{self.project_name}-backup-vault-{self.environment}",
            encryption_key_arn=self.encryption_key.key_arn
        )
        
        # Backup plan
        backup_plan = backup.CfnBackupPlan(
            self, "BackupPlan",
            backup_plan=backup.CfnBackupPlan.BackupPlanResourceTypeProperty(
                backup_plan_name=f"{self.project_name}-backup-plan-{self.environment}",
                backup_plan_rule=[
                    backup.CfnBackupPlan.BackupPlanRuleProperty(
                        rule_name="DailyBackup",
                        target_backup_vault=backup_vault.ref,
                        schedule_expression="cron(0 2 * * ? *)",
                        lifecycle=backup.CfnBackupPlan.LifecycleProperty(
                            delete_after_days=30
                        )
                    ),
                    backup.CfnBackupPlan.BackupPlanRuleProperty(
                        rule_name="WeeklyBackup",
                        target_backup_vault=backup_vault.ref,
                        schedule_expression="cron(0 2 ? * SUN *)",
                        lifecycle=backup.CfnBackupPlan.LifecycleProperty(
                            delete_after_days=90
                        )
                    )
                ]
            )
        )

    def create_outputs(self):
        """Create CloudFormation outputs."""
        CfnOutput(
            self, "VPCId",
            value=self.vpc.vpc_id,
            description="VPC ID for the Threat Intelligence Platform"
        )
        
        CfnOutput(
            self, "DataBucketName",
            value=self.data_bucket.bucket_name,
            description="S3 bucket for threat intelligence data"
        )
        
        CfnOutput(
            self, "MLModelsBucketName",
            value=self.ml_models_bucket.bucket_name,
            description="S3 bucket for ML models"
        )
        
        CfnOutput(
            self, "ThreatIntelligenceTableName",
            value=self.threat_intelligence_table.table_name,
            description="DynamoDB table for threat intelligence data"
        )
        
        CfnOutput(
            self, "ECSClusterName",
            value=self.ecs_cluster.cluster_name,
            description="ECS cluster name"
        )
        
        CfnOutput(
            self, "APIGatewayURL",
            value=self.api.url,
            description="API Gateway URL"
        )
        
        CfnOutput(
            self, "ECRRepositoryURI",
            value=self.app_repository.repository_uri,
            description="ECR repository URI for application images"
        )

    def create_log_groups(self):
        """Create CloudWatch log groups for ECS services."""
        # App service log group
        self.app_log_group = logs.LogGroup(
            self, "AppLogGroup",
            log_group_name=f"/ecs/app/{self.environment}",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Fine-tuning service log group
        self.fine_tuning_log_group = logs.LogGroup(
            self, "FineTuningLogGroup",
            log_group_name=f"/ecs/fine-tuning/{self.environment}",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # RAG service log group
        self.rag_log_group = logs.LogGroup(
            self, "RAGLogGroup",
            log_group_name=f"/ecs/rag/{self.environment}",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.RETAIN
        )


def main():
    """Main function to create the CDK app."""
    app = App()
    
    # Create the main stack
    ThreatIntelligenceStack(
        app, "ThreatIntelligenceStack",
        env={
            "account": os.getenv("CDK_DEFAULT_ACCOUNT"),
            "region": os.getenv("CDK_DEFAULT_REGION")
        }
    )
    
    app.synth()


if __name__ == "__main__":
    main() 