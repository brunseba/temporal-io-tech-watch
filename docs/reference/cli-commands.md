# CLI Commands Reference

This comprehensive reference covers all Temporal CLI commands for managing workflows, activities, namespaces, and clusters. The guide includes detailed command syntax, options, and practical examples.

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Workflow Commands](#workflow-commands)
- [Activity Commands](#activity-commands)
- [Namespace Commands](#namespace-commands)
- [Task Queue Commands](#task-queue-commands)
- [Cluster Commands](#cluster-commands)
- [Search Commands](#search-commands)
- [Administrative Commands](#administrative-commands)
- [Monitoring Commands](#monitoring-commands)
- [Environment Variables](#environment-variables)
- [Output Formats](#output-formats)

## Installation

### Install Temporal CLI

#### Using Homebrew (macOS/Linux)
```bash
brew install temporal
```

#### Using GitHub Releases
```bash
# Download latest release
curl -sSf https://temporal.download/cli.sh | sh

# Or specific version
curl -sSf https://temporal.download/cli.sh | sh -s -- --version 0.10.0
```

#### Using Go
```bash
go install go.temporal.io/cli/temporal@latest
```

#### Using Docker
```bash
docker pull temporalio/cli:latest
alias temporal="docker run --rm -it temporalio/cli:latest"
```

### Verify Installation
```bash
temporal version
```

## Configuration

### Global Configuration

#### Initialize Configuration
```bash
temporal config set version 1.0.0
temporal config set namespace default
temporal config set address temporal.company.com:7233
temporal config set codec-endpoint http://localhost:8080
```

#### View Configuration
```bash
temporal config get
temporal config get namespace
```

#### Environment-based Configuration
```bash
# Set via environment variables
export TEMPORAL_ADDRESS=temporal.company.com:7233
export TEMPORAL_NAMESPACE=production
export TEMPORAL_TLS_CERT_PATH=/path/to/cert.pem
export TEMPORAL_TLS_KEY_PATH=/path/to/key.pem
export TEMPORAL_TLS_CA_PATH=/path/to/ca.pem
export TEMPORAL_HEADERS_PROVIDER=YOUR_HEADERS_PROVIDER
```

#### TLS Configuration
```bash
# Configure TLS
temporal config set tls.cert-path /etc/temporal/certs/client.crt
temporal config set tls.key-path /etc/temporal/certs/client.key
temporal config set tls.ca-path /etc/temporal/certs/ca.crt
temporal config set tls.server-name temporal.company.com
```

#### Authentication Configuration
```bash
# Configure API key authentication
temporal config set auth.api-key your-api-key

# Configure OAuth
temporal config set auth.oauth.client-id your-client-id
temporal config set auth.oauth.client-secret your-client-secret
temporal config set auth.oauth.token-url https://auth.company.com/oauth/token
```

## Workflow Commands

### Start Workflow

#### Basic Workflow Start
```bash
temporal workflow start \
  --workflow-type OrderProcessingWorkflow \
  --task-queue order-processing-queue \
  --workflow-id order-12345 \
  --input '{"orderId": "12345", "customerId": "customer-67890"}'
```

#### Advanced Workflow Start
```bash
temporal workflow start \
  --workflow-type OrderProcessingWorkflow \
  --task-queue order-processing-queue \
  --workflow-id order-12345 \
  --input-file order-input.json \
  --workflow-execution-timeout 24h \
  --workflow-run-timeout 1h \
  --workflow-task-timeout 10s \
  --retry-policy '{
    "initialInterval": "1s",
    "backoffCoefficient": 2.0,
    "maximumInterval": "100s",
    "maximumAttempts": 3
  }' \
  --cron-schedule "0 12 * * *" \
  --memo '{"environment": "production", "version": "v1.2.3"}' \
  --search-attribute 'OrderId="12345"' \
  --search-attribute 'CustomerId="customer-67890"' \
  --search-attribute 'Environment="production"'
```

#### Start with Input File
```bash
# Create input file
cat > order-input.json << EOF
{
  "orderId": "12345",
  "customerId": "customer-67890",
  "items": [
    {
      "productId": "product-001",
      "quantity": 2,
      "price": 29.99
    }
  ],
  "shippingAddress": {
    "street": "123 Main St",
    "city": "Anytown",
    "state": "CA",
    "zipCode": "12345"
  }
}
EOF

temporal workflow start \
  --workflow-type OrderProcessingWorkflow \
  --task-queue order-processing-queue \
  --workflow-id order-12345 \
  --input-file order-input.json
```

### Execute Workflow (Start and Wait)

```bash
# Execute workflow and wait for completion
temporal workflow execute \
  --workflow-type OrderProcessingWorkflow \
  --task-queue order-processing-queue \
  --workflow-id order-12345 \
  --input '{"orderId": "12345"}' \
  --workflow-execution-timeout 24h
```

### Describe Workflow

```bash
# Describe workflow execution
temporal workflow describe \
  --workflow-id order-12345

# Describe with specific run ID
temporal workflow describe \
  --workflow-id order-12345 \
  --run-id 01234567-89ab-cdef-0123-456789abcdef

# Raw output format
temporal workflow describe \
  --workflow-id order-12345 \
  --raw
```

### Show Workflow History

```bash
# Show workflow history
temporal workflow show \
  --workflow-id order-12345

# Show with pagination
temporal workflow show \
  --workflow-id order-12345 \
  --limit 10 \
  --no-pager

# Show specific event types
temporal workflow show \
  --workflow-id order-12345 \
  --event-type WorkflowExecutionStarted,ActivityTaskScheduled

# Show in JSON format
temporal workflow show \
  --workflow-id order-12345 \
  --output json

# Show with time range
temporal workflow show \
  --workflow-id order-12345 \
  --start-time "2023-01-01T00:00:00Z" \
  --end-time "2023-01-02T00:00:00Z"
```

### Signal Workflow

```bash
# Send signal to workflow
temporal workflow signal \
  --workflow-id order-12345 \
  --name payment_received \
  --input '{"paymentId": "payment-98765", "amount": 59.98}'

# Signal with input file
temporal workflow signal \
  --workflow-id order-12345 \
  --name payment_received \
  --input-file payment-info.json

# Signal with run ID
temporal workflow signal \
  --workflow-id order-12345 \
  --run-id 01234567-89ab-cdef-0123-456789abcdef \
  --name payment_received \
  --input '{"paymentId": "payment-98765"}'
```

### Query Workflow

```bash
# Query workflow state
temporal workflow query \
  --workflow-id order-12345 \
  --type get_order_status

# Query with arguments
temporal workflow query \
  --workflow-id order-12345 \
  --type get_item_details \
  --input '{"itemId": "item-001"}'

# Query with run ID
temporal workflow query \
  --workflow-id order-12345 \
  --run-id 01234567-89ab-cdef-0123-456789abcdef \
  --type get_order_status
```

### Terminate Workflow

```bash
# Terminate workflow
temporal workflow terminate \
  --workflow-id order-12345 \
  --reason "Order cancelled by customer"

# Terminate with details
temporal workflow terminate \
  --workflow-id order-12345 \
  --reason "System maintenance" \
  --details '{"maintenanceWindow": "2023-01-01T02:00:00Z"}'

# Terminate specific run
temporal workflow terminate \
  --workflow-id order-12345 \
  --run-id 01234567-89ab-cdef-0123-456789abcdef \
  --reason "Duplicate execution"
```

### Cancel Workflow

```bash
# Cancel workflow
temporal workflow cancel \
  --workflow-id order-12345 \
  --reason "Customer requested cancellation"

# Cancel with run ID
temporal workflow cancel \
  --workflow-id order-12345 \
  --run-id 01234567-89ab-cdef-0123-456789abcdef \
  --reason "Payment failed"
```

### Reset Workflow

```bash
# Reset workflow to specific event
temporal workflow reset \
  --workflow-id order-12345 \
  --event-id 25 \
  --reason "Fix data corruption"

# Reset to last workflow task
temporal workflow reset \
  --workflow-id order-12345 \
  --type LastWorkflowTask \
  --reason "Reprocess with updated logic"

# Reset to first workflow task
temporal workflow reset \
  --workflow-id order-12345 \
  --type FirstWorkflowTask \
  --reason "Complete restart"

# Reset with new run ID
temporal workflow reset \
  --workflow-id order-12345 \
  --event-id 25 \
  --reason "Fix data corruption" \
  --reapply-exclude-type ActivityTaskScheduled
```

### List Workflows

```bash
# List all workflows
temporal workflow list

# List with query filter
temporal workflow list \
  --query "WorkflowType='OrderProcessingWorkflow' AND ExecutionStatus='Running'"

# List with pagination
temporal workflow list \
  --limit 50 \
  --earliest-time "2023-01-01T00:00:00Z" \
  --latest-time "2023-01-31T23:59:59Z"

# List archived workflows
temporal workflow list \
  --archived \
  --query "WorkflowType='OrderProcessingWorkflow'"

# List with specific fields
temporal workflow list \
  --fields WorkflowId,WorkflowType,Status,StartTime
```

### Count Workflows

```bash
# Count all workflows
temporal workflow count

# Count with query
temporal workflow count \
  --query "WorkflowType='OrderProcessingWorkflow' AND ExecutionStatus='Running'"
```

## Activity Commands

### Show Activity

```bash
# Show activity details
temporal activity show \
  --workflow-id order-12345 \
  --activity-id process-payment-001

# Show activity history
temporal activity show \
  --workflow-id order-12345 \
  --activity-id process-payment-001 \
  --show-history
```

### Complete Activity

```bash
# Complete activity manually
temporal activity complete \
  --workflow-id order-12345 \
  --activity-id process-payment-001 \
  --result '{"paymentId": "payment-98765", "status": "completed"}'

# Complete activity from file
temporal activity complete \
  --workflow-id order-12345 \
  --activity-id process-payment-001 \
  --result-file payment-result.json
```

### Fail Activity

```bash
# Fail activity manually
temporal activity fail \
  --workflow-id order-12345 \
  --activity-id process-payment-001 \
  --reason "Payment provider unavailable" \
  --details '{"errorCode": "PROVIDER_DOWN", "retryable": true}'
```

## Namespace Commands

### Register Namespace

```bash
# Register new namespace
temporal namespace register development

# Register with configuration
temporal namespace register production \
  --description "Production environment namespace" \
  --owner-email "team-platform@company.com" \
  --retention 30d \
  --data environment=production \
  --data team=platform \
  --data cost-center=engineering
```

### Describe Namespace

```bash
# Describe namespace
temporal namespace describe default
temporal namespace describe production
```

### List Namespaces

```bash
# List all namespaces
temporal namespace list

# List with specific fields
temporal namespace list \
  --fields Name,Description,OwnerEmail,State
```

### Update Namespace

```bash
# Update namespace retention
temporal namespace update production \
  --retention 60d

# Update namespace description
temporal namespace update production \
  --description "Updated production environment"

# Update namespace data
temporal namespace update production \
  --data cost-center=platform
```

### Delete Namespace

```bash
# Delete namespace (if supported)
temporal namespace delete development \
  --yes
```

## Task Queue Commands

### Describe Task Queue

```bash
# Describe task queue
temporal task-queue describe order-processing-queue

# Describe with pollers information
temporal task-queue describe order-processing-queue \
  --include-pollers

# Describe specific task queue type
temporal task-queue describe order-processing-queue \
  --task-queue-type workflow
```

### List Task Queues

```bash
# List task queues in namespace
temporal task-queue list

# List with specific namespace
temporal task-queue list \
  --namespace production
```

### Get Task Queue History

```bash
# Get task queue build ID history
temporal task-queue get-build-id-history order-processing-queue

# Get history with maximum entries
temporal task-queue get-build-id-history order-processing-queue \
  --max-entries 100
```

### Update Task Queue Build IDs

```bash
# Add new compatible build ID
temporal task-queue update-build-ids add-new-compatible \
  --task-queue order-processing-queue \
  --build-id v1.2.3 \
  --existing-compatible-build-id v1.2.2

# Add new default build ID
temporal task-queue update-build-ids add-new-default \
  --task-queue order-processing-queue \
  --build-id v1.3.0
```

## Cluster Commands

### Describe Cluster

```bash
# Describe cluster
temporal cluster describe

# Get cluster information
temporal cluster system-info
```

### Health Check

```bash
# Check cluster health
temporal cluster health

# Check with verbose output
temporal cluster health --verbose
```

### Get Cluster Members

```bash
# List cluster members
temporal cluster list-members

# List with role filter
temporal cluster list-members --role frontend
temporal cluster list-members --role history
temporal cluster list-members --role matching
temporal cluster list-members --role worker
```

## Search Commands

### Search Workflows

```bash
# Search workflows with SQL-like query
temporal workflow list \
  --query "WorkflowType = 'OrderProcessingWorkflow'"

# Complex search query
temporal workflow list \
  --query "WorkflowType = 'OrderProcessingWorkflow' 
           AND ExecutionStatus = 'Running' 
           AND StartTime > '2023-01-01T00:00:00Z'"

# Search with custom search attributes
temporal workflow list \
  --query "CustomerId = 'customer-67890' 
           AND OrderStatus = 'pending'"

# Search archived workflows
temporal workflow list \
  --archived \
  --query "WorkflowType = 'OrderProcessingWorkflow' 
           AND CloseTime > '2023-01-01T00:00:00Z'"
```

### Search Operators

```bash
# Equality
temporal workflow list --query "WorkflowType = 'MyWorkflow'"

# Inequality
temporal workflow list --query "ExecutionDuration > 3600"

# Range queries
temporal workflow list --query "StartTime BETWEEN '2023-01-01T00:00:00Z' AND '2023-01-31T23:59:59Z'"

# IN operator
temporal workflow list --query "WorkflowType IN ('WorkflowA', 'WorkflowB')"

# Text search
temporal workflow list --query "WorkflowId STARTS_WITH 'order-'"

# Logical operators
temporal workflow list --query "(WorkflowType = 'OrderWorkflow' OR WorkflowType = 'PaymentWorkflow') AND ExecutionStatus = 'Running'"
```

## Administrative Commands

### Server Commands

#### Start Development Server

```bash
# Start local development server
temporal server start-dev

# Start with UI
temporal server start-dev --ui-port 8080

# Start with specific database
temporal server start-dev \
  --db-filename temporal.db \
  --port 7233

# Start with namespaces
temporal server start-dev \
  --namespace development \
  --namespace testing
```

#### Database Migration

```bash
# Setup database schema
temporal sql-tool \
  --database temporal \
  --plugin postgres \
  --endpoint postgres://user:pass@localhost/temporal \
  setup-schema

# Update database schema
temporal sql-tool \
  --database temporal \
  --plugin postgres \
  --endpoint postgres://user:pass@localhost/temporal \
  update-schema \
  --schema-dir ./schema/postgresql/v96

# Create initial database
temporal sql-tool \
  --database temporal \
  --plugin postgres \
  --endpoint postgres://user:pass@localhost/temporal \
  create-database
```

### Operator Commands

#### Shard Management

```bash
# Describe shard
temporal operator shard describe --shard-id 1

# Close shard
temporal operator shard close --shard-id 1 --reason "Maintenance"

# List shards
temporal operator shard list
```

#### Search Attribute Management

```bash
# List search attributes
temporal operator search-attribute list

# Add search attribute
temporal operator search-attribute create \
  --name OrderTotal \
  --type Double

# Remove search attribute
temporal operator search-attribute remove \
  --name OldAttribute \
  --yes
```

#### Cluster Metadata

```bash
# Get cluster metadata
temporal operator cluster describe

# Add cluster to metadata
temporal operator cluster add \
  --cluster-name production-west \
  --cluster-address temporal-west.company.com:7233

# Remove cluster from metadata
temporal operator cluster remove \
  --cluster-name old-cluster
```

## Monitoring Commands

### Workflow Monitoring

```bash
# Monitor workflow execution in real-time
temporal workflow observe \
  --workflow-id order-12345

# Monitor with specific events
temporal workflow observe \
  --workflow-id order-12345 \
  --event-type ActivityTaskCompleted,WorkflowExecutionCompleted
```

### Task Queue Monitoring

```bash
# Monitor task queue metrics
temporal task-queue describe order-processing-queue \
  --include-pollers

# Watch task queue continuously
watch -n 5 "temporal task-queue describe order-processing-queue"
```

### System Monitoring

```bash
# Get system information
temporal cluster system-info

# Monitor cluster health
watch -n 10 "temporal cluster health"

# Get namespace metrics
temporal namespace describe production
```

## Environment Variables

### Core Environment Variables

```bash
# Server connection
export TEMPORAL_ADDRESS=temporal.company.com:7233
export TEMPORAL_NAMESPACE=production

# TLS configuration
export TEMPORAL_TLS_CERT_PATH=/etc/temporal/certs/client.crt
export TEMPORAL_TLS_KEY_PATH=/etc/temporal/certs/client.key
export TEMPORAL_TLS_CA_PATH=/etc/temporal/certs/ca.crt
export TEMPORAL_TLS_SERVER_NAME=temporal.company.com
export TEMPORAL_TLS_DISABLE_HOST_VERIFICATION=false

# Authentication
export TEMPORAL_API_KEY=your-api-key
export TEMPORAL_OAUTH_CLIENT_ID=your-client-id
export TEMPORAL_OAUTH_CLIENT_SECRET=your-client-secret

# CLI behavior
export TEMPORAL_CLI_AUTO_CONFIRM=false
export TEMPORAL_CLI_OUTPUT_FORMAT=table
export TEMPORAL_CLI_PAGER=less
export TEMPORAL_CLI_COLOR=auto

# Development
export TEMPORAL_DEV_SERVER_DB_FILENAME=temporal.db
export TEMPORAL_DEV_SERVER_PORT=7233
export TEMPORAL_DEV_SERVER_UI_PORT=8080
```

### Advanced Environment Variables

```bash
# Codec configuration
export TEMPORAL_CODEC_ENDPOINT=http://localhost:8080
export TEMPORAL_CODEC_AUTH=bearer-token

# Headers provider
export TEMPORAL_HEADERS_PROVIDER_EXECUTABLE=/path/to/headers-provider
export TEMPORAL_HEADERS_PROVIDER_ARGUMENTS="arg1 arg2"

# Logging
export TEMPORAL_CLI_LOG_LEVEL=info
export TEMPORAL_CLI_LOG_FORMAT=json

# Plugin configuration
export TEMPORAL_PLUGIN_DIR=/etc/temporal/plugins
export TEMPORAL_PLUGIN_CONFIG_DIR=/etc/temporal/plugin-configs
```

## Output Formats

### Table Format (Default)

```bash
temporal workflow list
# ┌──────────────────┬────────────────┬──────────┬─────────────────────┐
# │ WORKFLOW ID      │ WORKFLOW TYPE  │ STATUS   │ START TIME          │
# ├──────────────────┼────────────────┼──────────┼─────────────────────┤
# │ order-12345      │ OrderWorkflow  │ Running  │ 2023-01-01 10:00:00 │
# └──────────────────┴────────────────┴──────────┴─────────────────────┘
```

### JSON Format

```bash
temporal workflow list --output json
# [
#   {
#     "workflowId": "order-12345",
#     "workflowType": "OrderWorkflow",
#     "status": "Running",
#     "startTime": "2023-01-01T10:00:00Z"
#   }
# ]
```

### YAML Format

```bash
temporal workflow describe --workflow-id order-12345 --output yaml
# workflowExecutionInfo:
#   workflowId: order-12345
#   workflowType: OrderWorkflow
#   status: Running
#   startTime: "2023-01-01T10:00:00Z"
```

### Card Format

```bash
temporal workflow describe --workflow-id order-12345 --output card
# ╭─ Workflow Execution ─────────────────────────────────────╮
# │ Workflow Id    order-12345                               │
# │ Run Id         01234567-89ab-cdef-0123-456789abcdef      │
# │ Type           OrderWorkflow                             │
# │ Namespace      default                                   │
# │ Task Queue     order-processing-queue                    │
# │ Status         Running                                   │
# │ Start Time     2023-01-01 10:00:00 UTC                   │
# │ Execution Time 2h 30m 45s                                │
# ╰───────────────────────────────────────────────────────────╯
```

### Raw Format

```bash
temporal workflow describe --workflow-id order-12345 --raw
# Outputs the raw protobuf response
```

## Command Categories

### Workflow Lifecycle Commands

```bash
# Start workflow
temporal workflow start --workflow-type MyWorkflow --task-queue my-queue --workflow-id wf-123

# Execute and wait
temporal workflow execute --workflow-type MyWorkflow --task-queue my-queue --workflow-id wf-123

# Signal workflow
temporal workflow signal --workflow-id wf-123 --name my-signal --input '{}'

# Query workflow
temporal workflow query --workflow-id wf-123 --type my-query

# Cancel workflow
temporal workflow cancel --workflow-id wf-123

# Terminate workflow
temporal workflow terminate --workflow-id wf-123 --reason "reason"

# Reset workflow
temporal workflow reset --workflow-id wf-123 --event-id 10
```

### Information Commands

```bash
# Describe workflow
temporal workflow describe --workflow-id wf-123

# Show workflow history
temporal workflow show --workflow-id wf-123

# List workflows
temporal workflow list

# Count workflows
temporal workflow count
```

### Administrative Commands

```bash
# Namespace operations
temporal namespace register my-namespace
temporal namespace describe my-namespace
temporal namespace list
temporal namespace update my-namespace --retention 30d

# Task queue operations
temporal task-queue describe my-queue
temporal task-queue list

# Cluster operations
temporal cluster describe
temporal cluster health
temporal cluster list-members
```

### Development Commands

```bash
# Start development server
temporal server start-dev

# Database operations
temporal sql-tool setup-schema
temporal sql-tool update-schema

# Operator commands
temporal operator shard describe --shard-id 1
temporal operator search-attribute list
```

This comprehensive CLI reference provides detailed information about all Temporal CLI commands, their options, and practical usage examples for various operational scenarios.
