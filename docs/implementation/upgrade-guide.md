# Temporal Upgrade Guide

This guide provides detailed instructions for upgrading your Temporal deployment from version 1.27.x to 1.29.1, including prerequisites, step-by-step procedures, rollback strategies, and troubleshooting.

## Overview

Upgrading Temporal requires careful planning and execution to ensure zero downtime and data integrity. This guide covers:

- Pre-upgrade checklist and preparation
- Database schema migrations
- Server component upgrades
- Worker and client updates
- Validation and verification
- Rollback procedures

## Upgrade Path: 1.27.x → 1.29.1

### Version Compatibility Matrix

| Current Version | Target Version | Direct Upgrade | Notes |
|----------------|----------------|----------------|-------|
| 1.27.x | 1.29.1 | ✅ Yes | Requires schema migration |
| 1.26.x | 1.29.1 | ✅ Yes | Requires schema migration |
| 1.25.x | 1.29.1 | ⚠️ Not recommended | Upgrade to 1.27 first |
| <1.25 | 1.29.1 | ❌ No | Multi-step upgrade required |

### Breaking Changes: 1.27 → 1.29

#### 1. Schema Changes (1.28+)
- **PostgreSQL Schema**: v1.16 → v1.17
- **MySQL Schema**: v1.16 → v1.17
- **Cassandra Schema**: v1.11 → v1.12
- **Visibility Schema**: Updates for improved query performance

#### 2. Docker Image Changes (1.29+)
- Slimmed images with reduced dependencies
- Separate admin-tools image required
- Base image changes may affect custom Dockerfiles

#### 3. Metrics Changes (1.29)
- Some metrics renamed for consistency
- Enhanced cardinality control
- Legacy metrics format deprecated

#### 4. Configuration Changes
- New eager workflow start settings (enabled by default)
- Worker versioning configuration options
- Enhanced authorization plugin API

## Pre-Upgrade Checklist

### 1. Environment Assessment

```bash
# Check current Temporal version
kubectl get deployment temporal-frontend -n temporal-backend -o jsonpath='{.spec.template.spec.containers[0].image}'

# Check database schema version
kubectl exec -it deployment/temporal-admintools -n temporal-backend -- \
  temporal-sql-tool --plugin postgres12 \
  --ep postgresql.example.com \
  -u temporal \
  --db temporal \
  show-schema-version

# Check current resource usage
kubectl top pods -n temporal-backend
kubectl top nodes
```

### 2. Backup Strategy

#### Database Backup

```bash
# PostgreSQL backup
kubectl exec -it postgresql-primary-0 -n temporal-backend -- \
  pg_dump -U temporal -Fc temporal > temporal-backup-$(date +%Y%m%d-%H%M%S).dump

# Verify backup
pg_restore --list temporal-backup-*.dump | head -20

# Store backup securely
aws s3 cp temporal-backup-*.dump s3://your-backup-bucket/temporal/$(date +%Y%m%d)/
```

#### Configuration Backup

```bash
# Backup Helm values
helm get values temporal -n temporal-backend > temporal-values-backup-$(date +%Y%m%d).yaml

# Backup Kubernetes resources
kubectl get all,configmap,secret -n temporal-backend -o yaml > k8s-resources-backup-$(date +%Y%m%d).yaml

# Backup custom configurations
cp -r /etc/temporal/config /backup/temporal-config-$(date +%Y%m%d)
```

#### Workflow State Verification

```bash
# Export critical workflow states
kubectl exec -it deployment/temporal-admintools -n temporal-backend -- \
  tctl workflow list --query 'ExecutionStatus="Running"' --more --pagesize 1000 \
  > running-workflows-$(date +%Y%m%d).txt

# Count running workflows by type
kubectl exec -it deployment/temporal-admintools -n temporal-backend -- \
  tctl workflow list --query 'ExecutionStatus="Running"' | \
  jq -r '.WorkflowType' | sort | uniq -c
```

### 3. Staging Environment Testing

**Critical**: Always test the upgrade in a staging environment first!

```bash
# Clone production data to staging (PostgreSQL example)
pg_dump -U temporal -h prod-postgres.example.com temporal | \
  psql -U temporal -h staging-postgres.example.com temporal

# Apply upgrade in staging
# (Follow upgrade procedures in staging first)

# Validate staging environment
./scripts/validate-staging.sh
```

## Upgrade Procedures

### Step 1: Prepare the Upgrade

#### 1.1. Download Schema Migration Files

```bash
# Download Temporal schema repository
git clone https://github.com/temporalio/temporal.git
cd temporal/schema

# Checkout the target version
git checkout v1.29.1

# Verify schema files
ls -la postgresql/v12/temporal/versioned/v1.17/
ls -la postgresql/v12/visibility/versioned/v1.17/
```

#### 1.2. Review Migration Scripts

```bash
# Review schema changes
cat postgresql/v12/temporal/versioned/v1.17/*.sql
cat postgresql/v12/visibility/versioned/v1.17/*.sql

# Check for breaking changes
grep -i "drop\|alter\|rename" postgresql/v12/temporal/versioned/v1.17/*.sql
```

#### 1.3. Schedule Maintenance Window

For production environments:
- **Recommended window**: 2-4 hours
- **Low-traffic period**: Preferred
- **Communication**: Notify stakeholders
- **Rollback time**: Reserve 50% of window for potential rollback

### Step 2: Database Schema Migration

#### 2.1. Pre-Migration Validation

```bash
# Verify database connectivity
temporal-sql-tool --plugin postgres12 \
  --ep postgresql.example.com \
  -u temporal \
  --db temporal \
  validate

# Check current schema version
temporal-sql-tool --plugin postgres12 \
  --ep postgresql.example.com \
  -u temporal \
  --db temporal \
  show-schema-version

# Expected output for 1.27.x:
# Current database schema version: 1.16
```

#### 2.2. Dry-Run Migration

```bash
# Dry-run schema update (no changes applied)
temporal-sql-tool --plugin postgres12 \
  --ep postgresql.example.com \
  -u temporal \
  -p 5432 \
  --db temporal \
  --tls \
  --tls-cert-file /path/to/client.crt \
  --tls-key-file /path/to/client.key \
  --tls-ca-file /path/to/ca.crt \
  update-schema \
  -d ./postgresql/v12/temporal/versioned \
  --dry-run

# Review the output carefully
```

#### 2.3. Apply Schema Migration

```bash
# Migrate default store (temporal database)
temporal-sql-tool --plugin postgres12 \
  --ep postgresql.example.com \
  -u temporal \
  -p 5432 \
  --db temporal \
  --tls \
  --tls-cert-file /path/to/client.crt \
  --tls-key-file /path/to/client.key \
  --tls-ca-file /path/to/ca.crt \
  update-schema \
  -d ./postgresql/v12/temporal/versioned

# Migrate visibility store
temporal-sql-tool --plugin postgres12 \
  --ep postgresql.example.com \
  -u temporal \
  -p 5432 \
  --db temporal_visibility \
  --tls \
  --tls-cert-file /path/to/client.crt \
  --tls-key-file /path/to/client.key \
  --tls-ca-file /path/to/ca.crt \
  update-schema \
  -d ./postgresql/v12/visibility/versioned
```

#### 2.4. Verify Schema Migration

```bash
# Verify new schema version
temporal-sql-tool --plugin postgres12 \
  --ep postgresql.example.com \
  -u temporal \
  --db temporal \
  show-schema-version

# Expected output:
# Current database schema version: 1.17

# Verify tables and indexes
psql -U temporal -h postgresql.example.com -d temporal -c "\dt"
psql -U temporal -h postgresql.example.com -d temporal -c "\di"
```

### Step 3: Update Helm Values

#### 3.1. Create Updated Values File

```yaml
# values-1.29.yaml
server:
  image:
    repository: temporalio/server
    tag: 1.29.1
    pullPolicy: IfNotPresent
  
  replicaCount: 3
  
  config:
    # Enable eager workflow start (new default in 1.29)
    services:
      frontend:
        eagerWorkflowStartEnabled: true
        rateLimit:
          eagerWorkflowStart:
            maxPerSecond: 100
            burstSize: 200
    
    # Existing persistence configuration
    persistence:
      defaultStore: default
      visibilityStore: visibility
      numHistoryShards: 4096
      
      datastores:
        default:
          driver: "postgres12"
          host: "postgresql.example.com"
          port: 5432
          database: "temporal"
          user: "temporal"
          existingSecret: "temporal-default-store"
          maxConns: 50
          maxIdleConns: 10
          maxConnLifetime: "1h"
        
        visibility:
          driver: "postgres12"
          host: "postgresql.example.com"
          port: 5432
          database: "temporal_visibility"
          user: "temporal"
          existingSecret: "temporal-visibility-store"
          maxConns: 20
          maxIdleConns: 5
          maxConnLifetime: "1h"
    
    # Update TLS settings to 1.3
    global:
      tls:
        internode:
          server:
            minVersion: "1.3"
            certFile: /etc/temporal/certs/tls.crt
            keyFile: /etc/temporal/certs/tls.key
            clientCAFile: /etc/temporal/certs/ca.crt
          client:
            minVersion: "1.3"
            certFile: /etc/temporal/certs/tls.crt
            keyFile: /etc/temporal/certs/tls.key
            caFile: /etc/temporal/certs/ca.crt

admintools:
  image:
    repository: temporalio/admin-tools
    tag: 1.29.1-tctl-1.18.2-cli-1.3.0
    pullPolicy: IfNotPresent

web:
  image:
    repository: temporalio/ui
    tag: 2.40.0  # Latest UI version
    pullPolicy: IfNotPresent
```

#### 3.2. Diff Current and New Configuration

```bash
# Compare configurations
helm get values temporal -n temporal-backend > current-values.yaml
diff -u current-values.yaml values-1.29.yaml

# Review differences carefully
```

### Step 4: Rolling Upgrade of Temporal Server

#### 4.1. Update Admin Tools First

```bash
# Upgrade admin tools (safe, no impact on running workflows)
helm upgrade temporal temporalio/temporal \
  -n temporal-backend \
  --reuse-values \
  --set admintools.image.tag=1.29.1-tctl-1.18.2-cli-1.3.0 \
  --wait

# Verify admin tools
kubectl get pods -n temporal-backend -l app=temporal-admintools
kubectl logs -n temporal-backend -l app=temporal-admintools --tail=50
```

#### 4.2. Upgrade Frontend Service

```bash
# Frontend handles client connections - upgrade carefully
helm upgrade temporal temporalio/temporal \
  -n temporal-backend \
  --reuse-values \
  --set server.image.tag=1.29.1 \
  --set server.frontend.replicaCount=3 \
  --wait \
  --timeout 10m

# Monitor frontend rollout
kubectl rollout status deployment/temporal-frontend -n temporal-backend

# Verify frontend health
kubectl exec -it deployment/temporal-admintools -n temporal-backend -- \
  tctl cluster health
```

#### 4.3. Upgrade History Service

```bash
# History service manages workflow state - critical component
helm upgrade temporal temporalio/temporal \
  -n temporal-backend \
  --reuse-values \
  --set server.image.tag=1.29.1 \
  --wait \
  --timeout 15m

# Monitor history rollout (this takes longest)
kubectl rollout status deployment/temporal-history -n temporal-backend

# Verify no workflow disruptions
kubectl logs -n temporal-backend -l app=temporal-history --tail=100 | \
  grep -i "error\|fatal"
```

#### 4.4. Upgrade Matching Service

```bash
# Matching service handles task queues
helm upgrade temporal temporalio/temporal \
  -n temporal-backend \
  --reuse-values \
  --set server.image.tag=1.29.1 \
  --wait

# Monitor matching rollout
kubectl rollout status deployment/temporal-matching -n temporal-backend
```

#### 4.5. Upgrade Worker Service

```bash
# Internal worker service
helm upgrade temporal temporalio/temporal \
  -n temporal-backend \
  --reuse-values \
  --set server.image.tag=1.29.1 \
  --wait

# Monitor worker rollout
kubectl rollout status deployment/temporal-worker -n temporal-backend
```

#### 4.6. Complete Upgrade with Full Values

```bash
# Apply all configuration changes
helm upgrade temporal temporalio/temporal \
  -n temporal-backend \
  -f values-1.29.yaml \
  --wait \
  --timeout 20m

# Verify all components
kubectl get pods -n temporal-backend
kubectl get deployment -n temporal-backend
```

### Step 5: Validate Upgrade

#### 5.1. Cluster Health Check

```bash
# Check cluster health
kubectl exec -it deployment/temporal-admintools -n temporal-backend -- \
  tctl cluster health

# Expected output:
# SERVING

# Check all services
kubectl exec -it deployment/temporal-admintools -n temporal-backend -- \
  tctl admin cluster describe
```

#### 5.2. Workflow Validation

```bash
# Verify running workflows
kubectl exec -it deployment/temporal-admintools -n temporal-backend -- \
  tctl workflow list --query 'ExecutionStatus="Running"'

# Test workflow start (using eager start)
kubectl exec -it deployment/temporal-admintools -n temporal-backend -- \
  tctl workflow start \
    --taskqueue test-queue \
    --workflow_type TestWorkflow \
    --execution_timeout 300 \
    --input '"test-upgrade"'

# Verify workflow execution
kubectl exec -it deployment/temporal-admintools -n temporal-backend -- \
  tctl workflow show -w <workflow-id>
```

#### 5.3. Metrics Verification

```bash
# Check Prometheus metrics
kubectl port-forward -n temporal-backend svc/temporal-frontend 9090:9090 &
curl http://localhost:9090/metrics | grep temporal_

# Verify new metrics are present
curl http://localhost:9090/metrics | grep "temporal_request_latency"
```

#### 5.4. API Testing

```python
# test_upgrade.py - Test client connectivity
from temporalio.client import Client
import asyncio

async def test_connection():
    client = await Client.connect("temporal.example.com:7233")
    
    # Test namespace access
    await client.list_workflows("WorkflowType='TestWorkflow'")
    
    # Test workflow start (validates eager start)
    handle = await client.start_workflow(
        TestWorkflow.run,
        id=f"test-upgrade-{int(time.time())}",
        task_queue="test-queue"
    )
    
    result = await handle.result()
    print(f"Upgrade validation successful: {result}")

asyncio.run(test_connection())
```

### Step 6: Update Workers and Clients

#### 6.1. Update Python SDK in Workers

```bash
# Update requirements.txt or pyproject.toml
# From: temporalio>=1.7.0
# To:   temporalio>=1.18.2

# Using uv (recommended)
cd /path/to/worker
uv pip install temporalio==1.18.2

# Or using pip
pip install --upgrade temporalio==1.18.2

# Rebuild worker images
docker build -t your-registry/temporal-worker:v2.0.0 .
docker push your-registry/temporal-worker:v2.0.0
```

#### 6.2. Deploy Updated Workers

```yaml
# k8s/worker-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: temporal-worker
  namespace: temporal-product
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0  # Zero downtime
  template:
    spec:
      containers:
      - name: worker
        image: your-registry/temporal-worker:v2.0.0
        env:
        - name: TEMPORAL_HOST
          value: "temporal-frontend.temporal-backend:7233"
        - name: SDK_VERSION
          value: "1.18.2"
```

```bash
# Deploy updated workers
kubectl apply -f k8s/worker-deployment.yaml

# Monitor rollout (zero downtime)
kubectl rollout status deployment/temporal-worker -n temporal-product

# Verify workers are processing tasks
kubectl logs -n temporal-product -l app=temporal-worker --tail=100
```

#### 6.3. Update Client Applications

```python
# Update client applications gradually
from temporalio.client import Client

# New features available in 1.18.2+
async def use_new_features():
    client = await Client.connect(
        "temporal.example.com:7233",
        namespace="production"
    )
    
    # Use Update-With-Start (GA in 1.28+)
    handle = await client.start_workflow(
        OrderWorkflow.run,
        id="order-12345",
        task_queue="orders"
    )
    
    # Execute update
    result = await handle.execute_update(
        OrderWorkflow.update_status,
        "processing"
    )
```

### Step 7: Post-Upgrade Monitoring

#### 7.1. Monitor for 24-48 Hours

```bash
# Setup monitoring dashboard
cat <<EOF > prometheus-queries.yaml
queries:
  # Request latency
  - temporal_request_latency_bucket
  
  # Error rates
  - rate(temporal_request_errors_total[5m])
  
  # Workflow execution rates
  - rate(temporal_workflow_execution_started[5m])
  
  # Worker polling
  - temporal_worker_task_slots_available
  
  # Database connections
  - temporal_persistence_requests_total
EOF

# Alert on anomalies
```

#### 7.2. Performance Comparison

```bash
# Compare metrics before/after upgrade
# - Workflow start latency (should improve with eager start)
# - Task processing throughput
# - Database query performance
# - Resource utilization
```

## Rollback Procedures

### When to Rollback

Rollback if you encounter:
- Persistent cluster health failures
- High error rates (>5% increase)
- Workflow execution failures
- Database connectivity issues
- Critical feature regressions

### Rollback Steps

#### 1. Rollback Temporal Server

```bash
# Rollback to previous version
helm rollback temporal -n temporal-backend

# Or specify specific revision
helm rollback temporal <revision-number> -n temporal-backend

# Verify rollback
kubectl get pods -n temporal-backend
kubectl exec -it deployment/temporal-admintools -n temporal-backend -- \
  tctl cluster health
```

#### 2. Rollback Database Schema (If Necessary)

```bash
# Restore database from backup
pg_restore -U temporal -h postgresql.example.com -d temporal \
  temporal-backup-YYYYMMDD-HHMMSS.dump

# Verify schema version
temporal-sql-tool --plugin postgres12 \
  --ep postgresql.example.com \
  -u temporal \
  --db temporal \
  show-schema-version
```

#### 3. Rollback Workers

```bash
# Revert to previous worker image
kubectl set image deployment/temporal-worker \
  worker=your-registry/temporal-worker:v1.0.0 \
  -n temporal-product

kubectl rollout status deployment/temporal-worker -n temporal-product
```

## Troubleshooting Common Issues

### Issue 1: Schema Migration Fails

**Symptoms:**
```
Error: schema version mismatch
```

**Resolution:**
```bash
# Check schema version
temporal-sql-tool --plugin postgres12 \
  --ep postgresql.example.com \
  -u temporal \
  --db temporal \
  show-schema-version

# Force schema update if stuck
temporal-sql-tool --plugin postgres12 \
  --ep postgresql.example.com \
  -u temporal \
  --db temporal \
  update-schema \
  -d ./postgresql/v12/temporal/versioned \
  --version 1.17
```

### Issue 2: Frontend Connection Errors

**Symptoms:**
```
rpc error: code = Unavailable desc = connection error
```

**Resolution:**
```bash
# Check frontend pods
kubectl get pods -n temporal-backend -l app=temporal-frontend

# Check frontend logs
kubectl logs -n temporal-backend -l app=temporal-frontend --tail=200

# Verify service endpoints
kubectl get endpoints temporal-frontend -n temporal-backend

# Test connectivity
kubectl run -it --rm debug --image=busybox --restart=Never -- \
  nc -zv temporal-frontend.temporal-backend.svc.cluster.local 7233
```

### Issue 3: Worker Version Mismatch

**Symptoms:**
```
Worker SDK version incompatible with server
```

**Resolution:**
```bash
# Update worker SDK
pip install --upgrade temporalio==1.18.2

# Rebuild and redeploy workers
docker build -t your-registry/temporal-worker:latest .
kubectl rollout restart deployment/temporal-worker -n temporal-product
```

### Issue 4: Eager Workflow Start Issues

**Symptoms:**
```
Eager workflow start failed, falling back to normal start
```

**Resolution:**
```yaml
# Adjust rate limits in Helm values
server:
  config:
    services:
      frontend:
        eagerWorkflowStartEnabled: true
        rateLimit:
          eagerWorkflowStart:
            maxPerSecond: 200  # Increase limit
            burstSize: 400
```

### Issue 5: High Database Load

**Symptoms:**
- Slow query performance
- Connection pool exhaustion

**Resolution:**
```yaml
# Adjust connection pool settings
server:
  config:
    persistence:
      datastores:
        default:
          maxConns: 100  # Increase connections
          maxIdleConns: 20
          maxConnLifetime: "30m"  # Reduce lifetime
```

## Best Practices

### 1. Gradual Rollout
- Upgrade staging first
- Use canary deployments for workers
- Monitor extensively at each stage

### 2. Communication
- Notify stakeholders of maintenance window
- Prepare rollback communications
- Document all changes

### 3. Automation
```bash
# Create upgrade automation script
#!/bin/bash
set -e

./scripts/backup-database.sh
./scripts/test-schema-migration.sh
./scripts/upgrade-temporal.sh
./scripts/validate-upgrade.sh
./scripts/monitor-health.sh
```

### 4. Testing
- Test all critical workflows post-upgrade
- Validate new features work as expected
- Performance benchmark comparison

## Additional Resources

- [Temporal Upgrade Documentation](https://docs.temporal.io/self-hosted-guide/upgrade-server)
- [Schema Migration Tools](https://docs.temporal.io/self-hosted-guide/schema-setup)
- [What's New in Temporal 1.29](../reference/whats-new.md)
- [Temporal GitHub Releases](https://github.com/temporalio/temporal/releases)

## Support

For upgrade assistance:
- [Temporal Community Forum](https://community.temporal.io/)
- [Temporal Slack](https://temporal.io/slack)
- Professional support: support@temporal.io
