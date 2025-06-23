# Infrastructure Setup

This guide provides step-by-step instructions for setting up the infrastructure required for Temporal.io enterprise deployment, including Kubernetes cluster, networking, storage, and foundational services.

## Overview

The infrastructure setup includes:
- Kubernetes cluster provisioning
- Network configuration and security groups
- Storage provisioning and configuration
- Load balancer setup
- DNS and certificate management
- Monitoring infrastructure

## Prerequisites

### Required Tools

```bash
# Install required tools on macOS
brew install kubectl
brew install helm
brew install terraform
brew install aws-cli
brew install eksctl  # for AWS EKS
brew install k9s     # optional but recommended

# Verify installations
kubectl version --client
helm version
terraform version
aws --version
```

### Required Permissions

#### AWS IAM Permissions
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "eks:*",
                "ec2:*",
                "iam:*",
                "cloudformation:*",
                "autoscaling:*",
                "elasticloadbalancing:*",
                "route53:*",
                "acm:*",
                "rds:*",
                "elasticache:*"
            ],
            "Resource": "*"
        }
    ]
}
```

#### GCP IAM Roles
```bash
# Required roles for GKE deployment
gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="user:YOUR_EMAIL" \
    --role="roles/container.admin"

gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="user:YOUR_EMAIL" \
    --role="roles/compute.admin"

gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="user:YOUR_EMAIL" \
    --role="roles/iam.serviceAccountAdmin"
```

## Terraform Infrastructure

### Directory Structure

```
infrastructure/
├── terraform/
│   ├── modules/
│   │   ├── eks/
│   │   ├── vpc/
│   │   ├── rds/
│   │   └── elasticache/
│   └── environments/
│       ├── development/
│       ├── staging/
│       └── production/
├── scripts/
└── docs/
```

### VPC and Networking

#### VPC Module
```hcl
# terraform/modules/vpc/main.tf
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.cluster_name}-vpc"
    Environment = var.environment
    Project     = "temporal"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.cluster_name}-igw"
  }
}

# Public subnets
resource "aws_subnet" "public" {
  count = length(var.availability_zones)

  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name                     = "${var.cluster_name}-public-${count.index + 1}"
    "kubernetes.io/role/elb" = "1"
    Environment              = var.environment
  }
}

# Private subnets
resource "aws_subnet" "private" {
  count = length(var.availability_zones)

  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name                              = "${var.cluster_name}-private-${count.index + 1}"
    "kubernetes.io/role/internal-elb" = "1"
    Environment                       = var.environment
  }
}

# NAT Gateway
resource "aws_eip" "nat" {
  count = length(var.availability_zones)
  vpc   = true

  tags = {
    Name = "${var.cluster_name}-nat-eip-${count.index + 1}"
  }
}

resource "aws_nat_gateway" "main" {
  count = length(var.availability_zones)

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = {
    Name = "${var.cluster_name}-nat-${count.index + 1}"
  }

  depends_on = [aws_internet_gateway.main]
}

# Route tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.cluster_name}-public-rt"
  }
}

resource "aws_route_table" "private" {
  count  = length(var.availability_zones)
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }

  tags = {
    Name = "${var.cluster_name}-private-rt-${count.index + 1}"
  }
}

# Route table associations
resource "aws_route_table_association" "public" {
  count = length(var.availability_zones)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count = length(var.availability_zones)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}
```

#### VPC Variables
```hcl
# terraform/modules/vpc/variables.tf
variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
}
```

### EKS Cluster Setup

#### EKS Module
```hcl
# terraform/modules/eks/main.tf
resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  role_arn = aws_iam_role.cluster.arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids              = concat(var.public_subnet_ids, var.private_subnet_ids)
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = var.public_access_cidrs
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  depends_on = [
    aws_iam_role_policy_attachment.cluster_AmazonEKSClusterPolicy,
    aws_cloudwatch_log_group.cluster,
  ]

  tags = {
    Environment = var.environment
    Project     = "temporal"
  }
}

resource "aws_cloudwatch_log_group" "cluster" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = 7
}

# EKS Node Group
resource "aws_eks_node_group" "main" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${var.cluster_name}-nodes"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.private_subnet_ids

  capacity_type  = var.capacity_type
  instance_types = var.instance_types

  scaling_config {
    desired_size = var.desired_capacity
    max_size     = var.max_capacity
    min_size     = var.min_capacity
  }

  update_config {
    max_unavailable = 1
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  depends_on = [
    aws_iam_role_policy_attachment.node_AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.node_AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.node_AmazonEC2ContainerRegistryReadOnly,
  ]

  tags = {
    Environment = var.environment
    Project     = "temporal"
  }
}

# IAM Role for EKS Cluster
resource "aws_iam_role" "cluster" {
  name = "${var.cluster_name}-cluster-role"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "cluster_AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name
}

# IAM Role for EKS Node Group
resource "aws_iam_role" "node" {
  name = "${var.cluster_name}-node-role"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "node_AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node.name
}

resource "aws_iam_role_policy_attachment" "node_AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node.name
}

resource "aws_iam_role_policy_attachment" "node_AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node.name
}

# KMS Key for EKS encryption
resource "aws_kms_key" "eks" {
  description = "EKS Secret Encryption Key"
  
  tags = {
    Name        = "${var.cluster_name}-eks-key"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${var.cluster_name}-eks"
  target_key_id = aws_kms_key.eks.key_id
}
```

### RDS PostgreSQL Setup

#### RDS Module
```hcl
# terraform/modules/rds/main.tf
resource "aws_db_subnet_group" "main" {
  name       = "${var.cluster_name}-db-subnet-group"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name        = "${var.cluster_name}-db-subnet-group"
    Environment = var.environment
  }
}

resource "aws_security_group" "rds" {
  name_prefix = "${var.cluster_name}-rds-"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.cluster_name}-rds-sg"
    Environment = var.environment
  }
}

resource "aws_db_instance" "main" {
  allocated_storage           = var.allocated_storage
  max_allocated_storage       = var.max_allocated_storage
  storage_type                = "gp3"
  storage_encrypted           = true
  kms_key_id                  = aws_kms_key.rds.arn
  
  db_name  = var.database_name
  engine   = "postgres"
  engine_version = var.postgres_version
  instance_class = var.instance_class
  
  username = var.username
  password = var.password
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  backup_retention_period = var.backup_retention_period
  backup_window          = var.backup_window
  maintenance_window     = var.maintenance_window
  
  skip_final_snapshot = var.environment != "production"
  deletion_protection = var.environment == "production"
  
  performance_insights_enabled = true
  monitoring_interval         = 60
  monitoring_role_arn         = aws_iam_role.rds_monitoring.arn
  
  tags = {
    Name        = "${var.cluster_name}-postgres"
    Environment = var.environment
  }
}

# RDS Read Replica for production
resource "aws_db_instance" "replica" {
  count = var.environment == "production" ? 1 : 0
  
  identifier             = "${var.cluster_name}-postgres-replica"
  replicate_source_db    = aws_db_instance.main.id
  instance_class         = var.replica_instance_class
  publicly_accessible    = false
  auto_minor_version_upgrade = false
  
  tags = {
    Name        = "${var.cluster_name}-postgres-replica"
    Environment = var.environment
  }
}

# KMS Key for RDS encryption
resource "aws_kms_key" "rds" {
  description = "RDS encryption key"
  
  tags = {
    Name        = "${var.cluster_name}-rds-key"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${var.cluster_name}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

# IAM Role for RDS Enhanced Monitoring
resource "aws_iam_role" "rds_monitoring" {
  name = "${var.cluster_name}-rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}
```

### ElastiCache Redis Setup

#### ElastiCache Module
```hcl
# terraform/modules/elasticache/main.tf
resource "aws_elasticache_subnet_group" "main" {
  name       = "${var.cluster_name}-cache-subnet"
  subnet_ids = var.private_subnet_ids
}

resource "aws_security_group" "elasticache" {
  name_prefix = "${var.cluster_name}-cache-"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.cluster_name}-cache-sg"
    Environment = var.environment
  }
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id         = "${var.cluster_name}-redis"
  description                  = "Redis cluster for ${var.cluster_name}"
  
  node_type                    = var.node_type
  port                         = 6379
  parameter_group_name         = aws_elasticache_parameter_group.main.name
  subnet_group_name            = aws_elasticache_subnet_group.main.name
  security_group_ids           = [aws_security_group.elasticache.id]
  
  num_cache_clusters           = var.num_cache_clusters
  at_rest_encryption_enabled   = true
  transit_encryption_enabled   = true
  auth_token                   = var.auth_token
  
  maintenance_window           = var.maintenance_window
  snapshot_retention_limit     = var.snapshot_retention_limit
  snapshot_window              = var.snapshot_window
  
  tags = {
    Name        = "${var.cluster_name}-redis"
    Environment = var.environment
  }
}

resource "aws_elasticache_parameter_group" "main" {
  family = "redis7"
  name   = "${var.cluster_name}-redis-params"

  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }
}
```

## Environment-Specific Configurations

### Development Environment
```hcl
# terraform/environments/development/main.tf
module "vpc" {
  source = "../../modules/vpc"

  cluster_name             = "temporal-dev"
  environment             = "development"
  vpc_cidr                = "10.0.0.0/16"
  availability_zones      = ["us-west-2a", "us-west-2b"]
  public_subnet_cidrs     = ["10.0.1.0/24", "10.0.2.0/24"]
  private_subnet_cidrs    = ["10.0.10.0/24", "10.0.20.0/24"]
}

module "eks" {
  source = "../../modules/eks"

  cluster_name         = "temporal-dev"
  environment         = "development"
  kubernetes_version  = "1.28"
  public_subnet_ids   = module.vpc.public_subnet_ids
  private_subnet_ids  = module.vpc.private_subnet_ids
  
  instance_types      = ["t3.medium"]
  capacity_type       = "ON_DEMAND"
  desired_capacity    = 2
  min_capacity        = 1
  max_capacity        = 4
  
  public_access_cidrs = ["0.0.0.0/0"]
}

module "rds" {
  source = "../../modules/rds"

  cluster_name            = "temporal-dev"
  environment            = "development"
  vpc_id                 = module.vpc.vpc_id
  private_subnet_ids     = module.vpc.private_subnet_ids
  allowed_cidr_blocks    = [module.vpc.vpc_cidr]
  
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  max_allocated_storage  = 100
  postgres_version       = "15.4"
  
  database_name          = "temporal"
  username               = "temporal"
  password               = var.db_password
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
}

module "elasticache" {
  source = "../../modules/elasticache"

  cluster_name           = "temporal-dev"
  environment           = "development"
  vpc_id                = module.vpc.vpc_id
  private_subnet_ids    = module.vpc.private_subnet_ids
  allowed_cidr_blocks   = [module.vpc.vpc_cidr]
  
  node_type             = "cache.t3.micro"
  num_cache_clusters    = 1
  auth_token            = var.redis_auth_token
  
  maintenance_window         = "sun:05:00-sun:06:00"
  snapshot_retention_limit   = 1
  snapshot_window           = "03:00-05:00"
}
```

### Production Environment
```hcl
# terraform/environments/production/main.tf
module "vpc" {
  source = "../../modules/vpc"

  cluster_name             = "temporal-prod"
  environment             = "production"
  vpc_cidr                = "10.1.0.0/16"
  availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
  public_subnet_cidrs     = ["10.1.1.0/24", "10.1.2.0/24", "10.1.3.0/24"]
  private_subnet_cidrs    = ["10.1.10.0/24", "10.1.20.0/24", "10.1.30.0/24"]
}

module "eks" {
  source = "../../modules/eks"

  cluster_name         = "temporal-prod"
  environment         = "production"
  kubernetes_version  = "1.28"
  public_subnet_ids   = module.vpc.public_subnet_ids
  private_subnet_ids  = module.vpc.private_subnet_ids
  
  instance_types      = ["m5.large", "m5.xlarge"]
  capacity_type       = "ON_DEMAND"
  desired_capacity    = 6
  min_capacity        = 3
  max_capacity        = 12
  
  public_access_cidrs = ["203.0.113.0/24"] # Your office IP range
}

module "rds" {
  source = "../../modules/rds"

  cluster_name            = "temporal-prod"
  environment            = "production"
  vpc_id                 = module.vpc.vpc_id
  private_subnet_ids     = module.vpc.private_subnet_ids
  allowed_cidr_blocks    = [module.vpc.vpc_cidr]
  
  instance_class         = "db.r5.xlarge"
  replica_instance_class = "db.r5.large"
  allocated_storage      = 100
  max_allocated_storage  = 1000
  postgres_version       = "15.4"
  
  database_name          = "temporal"
  username               = "temporal"
  password               = var.db_password
  
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
}

module "elasticache" {
  source = "../../modules/elasticache"

  cluster_name           = "temporal-prod"
  environment           = "production"
  vpc_id                = module.vpc.vpc_id
  private_subnet_ids    = module.vpc.private_subnet_ids
  allowed_cidr_blocks   = [module.vpc.vpc_cidr]
  
  node_type             = "cache.r6g.large"
  num_cache_clusters    = 3
  auth_token            = var.redis_auth_token
  
  maintenance_window         = "sun:05:00-sun:06:00"
  snapshot_retention_limit   = 7
  snapshot_window           = "03:00-05:00"
}
```

## Deployment Scripts

### Infrastructure Deployment Script
```bash
#!/bin/bash
# scripts/deploy-infrastructure.sh

set -euo pipefail

ENVIRONMENT=${1:-development}
ACTION=${2:-plan}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Validate environment
if [[ ! "$ENVIRONMENT" =~ ^(development|staging|production)$ ]]; then
    error "Invalid environment. Must be one of: development, staging, production"
fi

# Validate action
if [[ ! "$ACTION" =~ ^(plan|apply|destroy)$ ]]; then
    error "Invalid action. Must be one of: plan, apply, destroy"
fi

TERRAFORM_DIR="terraform/environments/$ENVIRONMENT"

# Check if Terraform directory exists
if [[ ! -d "$TERRAFORM_DIR" ]]; then
    error "Terraform directory not found: $TERRAFORM_DIR"
fi

log "Deploying infrastructure for environment: $ENVIRONMENT"
log "Action: $ACTION"

cd "$TERRAFORM_DIR"

# Initialize Terraform
log "Initializing Terraform..."
terraform init

# Validate configuration
log "Validating Terraform configuration..."
terraform validate

# Plan or apply
case "$ACTION" in
    plan)
        log "Creating Terraform plan..."
        terraform plan -out=tfplan
        ;;
    apply)
        log "Applying Terraform configuration..."
        if [[ -f "tfplan" ]]; then
            terraform apply tfplan
        else
            terraform apply -auto-approve
        fi
        
        # Update kubeconfig
        if [[ "$ACTION" == "apply" ]]; then
            log "Updating kubeconfig..."
            CLUSTER_NAME=$(terraform output -raw cluster_name)
            REGION=$(terraform output -raw region)
            aws eks update-kubeconfig --region "$REGION" --name "$CLUSTER_NAME"
            
            log "Infrastructure deployment completed successfully!"
            log "Cluster endpoint: $(terraform output -raw cluster_endpoint)"
            log "Database endpoint: $(terraform output -raw database_endpoint)"
        fi
        ;;
    destroy)
        warn "This will destroy all infrastructure in $ENVIRONMENT environment!"
        read -p "Are you sure? Type 'yes' to confirm: " -r
        if [[ $REPLY == "yes" ]]; then
            terraform destroy -auto-approve
            log "Infrastructure destroyed successfully"
        else
            log "Destroy cancelled"
        fi
        ;;
esac
```

### Post-Deployment Setup Script
```bash
#!/bin/bash
# scripts/post-deployment-setup.sh

set -euo pipefail

ENVIRONMENT=${1:-development}

log() {
    echo -e "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')] $1\033[0m"
}

error() {
    echo -e "\033[0;31m[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1\033[0m"
    exit 1
}

log "Running post-deployment setup for environment: $ENVIRONMENT"

# Verify cluster connectivity
log "Verifying cluster connectivity..."
if ! kubectl cluster-info > /dev/null 2>&1; then
    error "Cannot connect to Kubernetes cluster"
fi

# Install cert-manager
log "Installing cert-manager..."
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
kubectl wait --for=condition=available --timeout=300s deployment/cert-manager -n cert-manager
kubectl wait --for=condition=available --timeout=300s deployment/cert-manager-cainjector -n cert-manager
kubectl wait --for=condition=available --timeout=300s deployment/cert-manager-webhook -n cert-manager

# Install AWS Load Balancer Controller
log "Installing AWS Load Balancer Controller..."
helm repo add eks https://aws.github.io/eks-charts
helm repo update

CLUSTER_NAME=$(kubectl config current-context | cut -d'/' -f2)
VPC_ID=$(aws eks describe-cluster --name "$CLUSTER_NAME" --query "cluster.resourcesVpcConfig.vpcId" --output text)

helm upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller \
    -n kube-system \
    --set clusterName="$CLUSTER_NAME" \
    --set serviceAccount.create=false \
    --set serviceAccount.name=aws-load-balancer-controller \
    --set region=us-west-2 \
    --set vpcId="$VPC_ID"

# Install external-secrets operator
log "Installing external-secrets operator..."
helm repo add external-secrets https://charts.external-secrets.io
helm upgrade --install external-secrets external-secrets/external-secrets \
    -n external-secrets-system \
    --create-namespace

# Create namespaces
log "Creating namespaces..."
kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: temporal-system
  labels:
    istio-injection: enabled
---
apiVersion: v1
kind: Namespace
metadata:
  name: temporal-app
  labels:
    istio-injection: enabled
---
apiVersion: v1
kind: Namespace
metadata:
  name: monitoring
  labels:
    istio-injection: enabled
EOF

# Install Prometheus Operator
log "Installing Prometheus Operator..."
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm upgrade --install prometheus-operator prometheus-community/kube-prometheus-stack \
    -n monitoring \
    --set grafana.adminPassword=admin123 \
    --set prometheus.prometheusSpec.retention=30d

log "Post-deployment setup completed successfully!"
log "Next steps:"
log "1. Configure DNS and certificates"
log "2. Set up external secrets"
log "3. Deploy Temporal cluster"
```

## Validation and Testing

### Infrastructure Validation Script
```bash
#!/bin/bash
# scripts/validate-infrastructure.sh

set -euo pipefail

ENVIRONMENT=${1:-development}

log() {
    echo -e "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')] $1\033[0m"
}

error() {
    echo -e "\033[0;31m[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1\033[0m"
    exit 1
}

warn() {
    echo -e "\033[1;33m[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1\033[0m"
}

log "Validating infrastructure for environment: $ENVIRONMENT"

# Check cluster connectivity
log "Checking cluster connectivity..."
if kubectl cluster-info > /dev/null 2>&1; then
    log "✓ Cluster connectivity OK"
else
    error "✗ Cannot connect to cluster"
fi

# Check node status
log "Checking node status..."
READY_NODES=$(kubectl get nodes --no-headers | grep -c "Ready")
TOTAL_NODES=$(kubectl get nodes --no-headers | wc -l)
if [[ $READY_NODES -eq $TOTAL_NODES ]] && [[ $TOTAL_NODES -gt 0 ]]; then
    log "✓ All $TOTAL_NODES nodes are ready"
else
    warn "✗ Only $READY_NODES out of $TOTAL_NODES nodes are ready"
fi

# Check essential services
log "Checking essential services..."
SERVICES=("kube-dns" "aws-load-balancer-controller" "cert-manager")
for service in "${SERVICES[@]}"; do
    if kubectl get pods -A | grep -q "$service.*Running"; then
        log "✓ $service is running"
    else
        warn "✗ $service is not running"
    fi
done

# Check database connectivity
log "Checking database connectivity..."
if kubectl run db-test --image=postgres:13 --rm -i --restart=Never -- \
    psql -h "$DB_ENDPOINT" -U temporal -d temporal -c "SELECT 1" > /dev/null 2>&1; then
    log "✓ Database connectivity OK"
else
    error "✗ Cannot connect to database"
fi

# Check Redis connectivity
log "Checking Redis connectivity..."
if kubectl run redis-test --image=redis:7 --rm -i --restart=Never -- \
    redis-cli -h "$REDIS_ENDPOINT" ping > /dev/null 2>&1; then
    log "✓ Redis connectivity OK"
else
    error "✗ Cannot connect to Redis"
fi

log "Infrastructure validation completed"
```

This infrastructure setup guide provides a comprehensive foundation for deploying Temporal.io in a production-ready environment with proper networking, security, and scalability considerations.
