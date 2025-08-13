# Infrastructure as Code for AI Threat Intelligence Platform

This directory contains infrastructure as code (IaC) configurations for deploying the complete threat intelligence platform on AWS. We provide both **AWS CDK (Python)** and **Terraform** options to give you flexibility in choosing your preferred tool.

## 🏗️ **Architecture Overview**

The infrastructure creates a comprehensive, production-ready platform with:

### **Core Infrastructure**
- **VPC** with public, private, and isolated subnets across 3 AZs
- **NAT Gateways** for private subnet internet access
- **VPC Endpoints** for secure AWS service communication
- **Security Groups** with least-privilege access

### **Storage & Data**
- **S3 Buckets** for threat intelligence data, ML models, and logs
- **DynamoDB Tables** with GSIs for efficient querying
- **KMS Keys** for encryption at rest and in transit

### **Compute & Services**
- **ECS Fargate** cluster for containerized services
- **Lambda Functions** for serverless data processing
- **ECR Repositories** for container image management
- **API Gateway** for RESTful API access

### **Security & Monitoring**
- **GuardDuty** for threat detection
- **CloudTrail** for API logging
- **Config** for compliance monitoring
- **WAF** for API protection
- **CloudWatch** for metrics and alerting

### **Backup & Recovery**
- **AWS Backup** for automated backups
- **S3 Lifecycle Policies** for cost optimization
- **Cross-region replication** capabilities

## 🚀 **Quick Start**

### **Prerequisites**

1. **AWS CLI** configured with appropriate permissions
2. **Python 3.8+** (for CDK)
3. **Node.js 14+** (for CDK CLI)
4. **Terraform 1.0+** (for Terraform option)

### **Option 1: AWS CDK (Recommended)**

#### **Setup**
```bash
cd infrastructure/cdk

# Install CDK globally
npm install -g aws-cdk

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Bootstrap CDK (first time only)
cdk bootstrap
```

#### **Deploy**
```bash
# Deploy to dev environment
./deploy.sh deploy -e dev -r us-east-1

# Deploy to production
./deploy.sh deploy -e prod -r us-west-2

# Check status
./deploy.sh status

# Destroy infrastructure
./deploy.sh destroy
```

#### **Manual CDK Commands**
```bash
# Synthesize CloudFormation
cdk synth

# Deploy
cdk deploy

# Diff changes
cdk diff

# Destroy
cdk destroy
```

### **Option 2: Terraform**

#### **Setup**
```bash
cd infrastructure/terraform

# Initialize Terraform
terraform init

# Plan deployment
terraform plan

# Deploy
terraform apply

# Destroy
terraform destroy
```

#### **Using Terraform Workspaces**
```bash
# Create environment-specific workspace
terraform workspace new dev
terraform workspace new staging
terraform workspace new prod

# Switch to workspace
terraform workspace select dev

# Deploy to specific workspace
terraform apply -var-file="environments/dev.tfvars"
```

## ⚙️ **Configuration**

### **Environment Variables**

```bash
# CDK
export ENVIRONMENT=prod
export AWS_REGION=us-west-2
export AWS_ACCOUNT_ID=123456789012

# Terraform
export TF_VAR_environment=prod
export TF_VAR_aws_region=us-west-2
```

### **Customization**

#### **CDK Configuration**
```python
# app.py
class ThreatIntelligenceStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs):
        # Customize environment
        self.environment = os.getenv('ENVIRONMENT', 'dev')
        self.project_name = 'my-threat-intel-platform'
```

#### **Terraform Configuration**
```hcl
# terraform.tfvars
environment = "prod"
aws_region = "us-west-2"
project_name = "my-threat-intel-platform"
enable_high_availability = true
enable_cost_optimization = false
```

## 📊 **Resource Sizing**

### **Development Environment**
- **ECS**: 1 vCPU, 2GB RAM
- **Lambda**: 1GB RAM, 15min timeout
- **DynamoDB**: Pay-per-request
- **S3**: Standard storage

### **Production Environment**
- **ECS**: 2-4 vCPU, 4-8GB RAM
- **Lambda**: 2-4GB RAM, 15min timeout
- **DynamoDB**: Provisioned capacity
- **S3**: Intelligent tiering + lifecycle policies

## 🔒 **Security Features**

### **Network Security**
- Private subnets for sensitive resources
- Security groups with minimal required access
- VPC endpoints for AWS service communication
- WAF rules for API protection

### **Data Security**
- KMS encryption for all data at rest
- TLS 1.2+ for data in transit
- IAM roles with least privilege
- CloudTrail for audit logging

### **Access Control**
- API Gateway with API keys
- IAM policies for resource access
- Secrets Manager for sensitive configuration
- GuardDuty for threat detection

## 📈 **Monitoring & Alerting**

### **CloudWatch Metrics**
- Lambda invocations and errors
- DynamoDB read/write capacity
- ECS service health
- API Gateway performance

### **Alerts**
- Lambda function errors
- DynamoDB throttling
- High CPU/memory usage
- Security events

### **Dashboards**
- Operational metrics
- Security events
- Cost optimization
- Performance trends

## 💰 **Cost Optimization**

### **Development**
- Use spot instances where possible
- Single NAT Gateway
- Minimal backup retention
- S3 lifecycle policies

### **Production**
- Reserved instances for predictable workloads
- Multi-AZ for high availability
- Comprehensive backup strategy
- Cost allocation tags

## 🚨 **Troubleshooting**

### **Common Issues**

#### **CDK Deployment Fails**
```bash
# Check CDK version
cdk --version

# Verify AWS credentials
aws sts get-caller-identity

# Check CloudFormation events
aws cloudformation describe-stack-events --stack-name ThreatIntelligenceStack
```

#### **Terraform State Issues**
```bash
# Refresh state
terraform refresh

# Import existing resources
terraform import aws_s3_bucket.data bucket-name

# Plan with refresh
terraform plan -refresh=true
```

#### **Permission Errors**
```bash
# Verify IAM permissions
aws iam get-user
aws iam list-attached-user-policies --user-name your-username

# Check CloudFormation permissions
aws cloudformation list-stacks
```

### **Debug Commands**

#### **CDK**
```bash
# Verbose deployment
cdk deploy --verbose

# Debug mode
CDK_DEBUG=1 cdk deploy

# Check synthesized template
cdk synth --quiet
```

#### **Terraform**
```bash
# Verbose output
terraform apply -var="debug=true"

# Check state
terraform show

# Validate configuration
terraform validate
```

## 🔄 **Updates & Maintenance**

### **Infrastructure Updates**
```bash
# CDK
cdk deploy --require-approval never

# Terraform
terraform plan
terraform apply
```

### **Application Updates**
```bash
# Update ECS services
aws ecs update-service --cluster cluster-name --service service-name --force-new-deployment

# Update Lambda functions
aws lambda update-function-code --function-name function-name --zip-file fileb://deployment.zip
```

### **Security Updates**
```bash
# Rotate KMS keys
aws kms enable-key-rotation --key-id key-id

# Update security groups
# Modify security group rules in CDK/Terraform and redeploy
```

## 📚 **Additional Resources**

### **Documentation**
- [AWS CDK Developer Guide](https://docs.aws.amazon.com/cdk/)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)

### **Examples**
- [CDK Examples](https://github.com/aws-samples/aws-cdk-examples)
- [Terraform AWS Examples](https://github.com/hashicorp/terraform-provider-aws/tree/main/examples)

### **Community**
- [AWS CDK Community](https://github.com/aws/aws-cdk)
- [Terraform Community](https://community.hashicorp.com/)

## 🤝 **Contributing**

### **Adding New Resources**
1. Update the appropriate CDK stack or Terraform configuration
2. Add proper tagging and security groups
3. Include monitoring and alerting
4. Update documentation

### **Testing Changes**
```bash
# CDK
cdk synth
cdk diff

# Terraform
terraform plan
terraform validate
```

### **Code Quality**
- Use consistent naming conventions
- Include proper error handling
- Add comprehensive documentation
- Follow security best practices

---

## 🎯 **Next Steps**

1. **Choose your IaC tool** (CDK or Terraform)
2. **Customize configuration** for your environment
3. **Deploy infrastructure** using the provided scripts
4. **Configure monitoring** and alerting
5. **Deploy applications** to the infrastructure
6. **Set up CI/CD** for automated deployments

For questions or issues, please refer to the troubleshooting section or create an issue in the project repository. 