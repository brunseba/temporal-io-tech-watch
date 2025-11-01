# What's New in Temporal.io

This document highlights the latest features and improvements in Temporal.io from versions 1.26 through 1.29.

## Temporal Server 1.29.x (October 2025)

### 🚀 Key Features

#### Eager Workflow Start (GA - Default Enabled)
Eager workflow start is now generally available and enabled by default. This feature significantly reduces the latency of starting workflows by executing the first workflow task immediately on the same worker that started the workflow.

**Benefits:**
- Reduced workflow start latency by up to 50%
- Lower load on the history service
- Improved overall system throughput

**Configuration:**
```yaml
server:
  config:
    services:
      frontend:
        eagerWorkflowStartEnabled: true  # Default in 1.29+
```

#### Task Queue Fairness (Pre-release)
Priority-based task distribution within task queues to ensure fair resource allocation across different workflow types.

**Use Case:** Prevent high-volume workflows from starving low-volume critical workflows.

```python
# Example: Setting workflow priority
from temporalio import workflow

@workflow.defn
class CriticalWorkflow:
    @workflow.run
    async def run(self) -> str:
        # This workflow gets higher priority
        return "critical task"

# Start with priority
await client.start_workflow(
    CriticalWorkflow.run,
    id="critical-wf-001",
    task_queue="critical-queue",
    task_queue_priority=10  # Higher number = higher priority
)
```

### ⚠️ Breaking Changes

#### Slimmed Docker Images
Starting with 1.29.x, official Docker images are significantly smaller:
- Removed unnecessary dependencies
- Multi-stage builds for optimized size
- Security improvements with minimal attack surface

**Migration:** Update your Kubernetes manifests if they rely on tools that were previously bundled.

### 🔧 Improvements

- **Activity and Workflow Metrics Changes**: Enhanced metrics with better cardinality control
- **Priority and Workflow Versioning Fixes**: Resolved issues in priority handling and versioning features
- **Workflow Retry Bug Fixes**: Improved reliability in workflow retry scenarios

## Temporal Server 1.28.x (June 2025)

### 🎯 Major Features

#### Update-With-Start (GA)
Update-With-Start is now generally available, allowing you to update a workflow at the same time you start it.

**Use Case:** Ensure workflows are created with the latest state without race conditions.

```python
from temporalio.client import Client, WorkflowUpdateStage

# Start workflow with update
handle = await client.start_workflow(
    MyWorkflow.run,
    id="workflow-123",
    task_queue="my-queue",
    start_signal="initialize",
    start_signal_args=["initial_data"]
)

# Or update existing, start if not exists
try:
    result = await client.get_workflow_handle("workflow-123").execute_update(
        "updateMethod",
        args=["new_data"],
        wait_for_stage=WorkflowUpdateStage.ACCEPTED,
        start_workflow=True,  # Start if doesn't exist
        start_workflow_operation=StartWorkflowOperation(
            MyWorkflow.run,
            task_queue="my-queue"
        )
    )
except WorkflowAlreadyStartedError:
    # Workflow already exists
    pass
```

#### Versioning / Safe-Deploy (Public Preview)
Worker deployment versioning enables safe rollout of workflow code changes without disrupting running workflows.

**Key Capabilities:**
- Pin running workflows to specific worker versions
- Gradual rollout of new workflow code
- Automatic routing based on worker build IDs

```python
from temporalio.worker import Worker

# Register worker with build ID
worker = Worker(
    client,
    task_queue="my-queue",
    workflows=[MyWorkflow],
    activities=[my_activity],
    build_id="v2.1.0",  # Version identifier
    use_worker_versioning=True
)
```

#### Simple Priority for Task Queues (Pre-release)
Assign priorities to task queues for better resource management.

```yaml
server:
  config:
    services:
      matching:
        taskQueuePriorityEnabled: true
```

### 📊 Schema Changes
- **MySQL Schema v1.17**
- **PostgreSQL Schema v1.17**
- **Cassandra Schema v1.12**

**Migration Required:** Run schema upgrade tools before deploying 1.28.x.

```bash
# PostgreSQL upgrade
temporal-sql-tool --plugin postgres12 \
  --ep postgresql.example.com \
  -u temporal \
  -p 5432 \
  --db temporal update-schema \
  -d /path/to/temporal/schema/postgresql/v12
```

## Temporal Server 1.27.x (February 2025)

### 🌐 Nexus (GA)
Nexus is now generally available, providing cross-namespace and cross-cluster workflow orchestration.

**Use Cases:**
- Microservices orchestration across teams
- Multi-tenant workflow coordination
- Cross-cluster workflow dependencies

```python
from temporalio import workflow
from temporalio.workflow import nexus_operation

@workflow.defn
class ParentWorkflow:
    @workflow.run
    async def run(self) -> str:
        # Call operation in different namespace/cluster
        result = await nexus_operation(
            "remote-service",
            "processData",
            args=["data"],
            nexus_endpoint="https://remote-cluster.temporal.io"
        )
        return result
```

### 🚀 Safe Deploys
Enhanced worker versioning capabilities:
- Build ID-based workflow routing
- Automatic reachability checking
- Gradual traffic shifting

### 🗄️ Visibility Schema Changes
Updates to visibility schema for improved search performance and new query capabilities.

## Temporal Server 1.26.x (December 2024)

### ✅ Workflow Update (GA)
Workflow Update API is now generally available, allowing external systems to synchronously update running workflows.

**Benefits:**
- Synchronous workflow mutations
- Type-safe update handlers
- Guaranteed execution ordering

```python
from temporalio import workflow

@workflow.defn
class OrderWorkflow:
    def __init__(self) -> None:
        self._status = "pending"
    
    @workflow.run
    async def run(self, order_id: str) -> str:
        # Workflow logic
        await workflow.wait_condition(lambda: self._status == "completed")
        return "done"
    
    @workflow.update
    def update_status(self, new_status: str) -> str:
        """Update handler - called synchronously from client"""
        old_status = self._status
        self._status = new_status
        return f"Updated from {old_status} to {new_status}"

# Client code
handle = await client.get_workflow_handle("order-123")
result = await handle.execute_update(
    OrderWorkflow.update_status,
    "processing"
)
print(result)  # "Updated from pending to processing"
```

### 🔄 Update-With-Start (Public Preview)
Early preview of the update-with-start feature (GA in 1.28).

## Migration Guide

### Upgrading to 1.29.x

1. **Update Docker Images:**
```yaml
server:
  image:
    repository: temporalio/server
    tag: 1.29.1
```

2. **Review Metrics Changes:**
Check your monitoring dashboards for renamed or removed metrics.

3. **Test Eager Workflow Start:**
Verify your workflows work correctly with eager start (enabled by default).

4. **Update SDKs:**
- Python SDK: 1.18.2+
- Go SDK: Latest compatible version
- Java SDK: Latest compatible version

### Upgrading from 1.20.x to 1.29.x

1. **Database Schema Upgrades:**
```bash
# Run all intermediate schema migrations
# From 1.20 -> 1.26 -> 1.28 -> 1.29
temporal-sql-tool --plugin postgres12 update-schema
```

2. **Review Breaking Changes:**
- Docker image changes in 1.29
- Metrics changes across versions
- API deprecations

3. **Test in Staging:**
- Deploy to non-production environment first
- Verify existing workflows continue properly
- Test new features incrementally

4. **Rolling Upgrade Strategy:**
```bash
# 1. Upgrade database schema
temporal-sql-tool update-schema

# 2. Upgrade server components one by one
kubectl rollout restart deployment/temporal-frontend -n temporal-backend
kubectl rollout status deployment/temporal-frontend -n temporal-backend

kubectl rollout restart deployment/temporal-history -n temporal-backend
kubectl rollout status deployment/temporal-history -n temporal-backend

# 3. Update workers after server is stable
kubectl rollout restart deployment/temporal-workers -n temporal-product
```

## Deprecated Features

### Version 1.28+
- **Legacy metrics format**: Migrate to new metrics format
- **Old authorization plugin API**: Use new authorizer interface

### Version 1.29+
- **Bundled tools in Docker images**: Use separate tool images

## Performance Improvements

### 1.29.x
- **50% reduction** in workflow start latency (eager start)
- **30% improvement** in task queue throughput
- **Reduced memory footprint** in history service

### 1.28.x
- **Improved query performance** with schema changes
- **Better connection pooling** for database operations
- **Optimized workflow search** with enhanced visibility

### 1.27.x
- **Cross-cluster operations** with Nexus (minimal overhead)
- **Worker versioning** with efficient routing

## Resources

- [Official Release Notes](https://github.com/temporalio/temporal/releases)
- [Upgrade Guide](https://docs.temporal.io/self-hosted-guide/upgrade-server)
- [Schema Migration Tools](https://docs.temporal.io/self-hosted-guide/schema-setup)
- [Breaking Changes Policy](https://docs.temporal.io/dev-guide/temporal-versioning)

## Next Steps

1. Review the [complete implementation guide](../temporal-design-implementation-guide.md)
2. Update your [Helm configurations](../gitops/helm-configuration.md)
3. Test new features in development environment
4. Plan your upgrade strategy
