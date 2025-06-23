# Frequently Asked Questions (FAQ)

This comprehensive FAQ covers the most common questions about Temporal.io, including architecture, development, deployment, and operational concerns.

## Table of Contents

- [General Questions](#general-questions)
- [Architecture and Concepts](#architecture-and-concepts)
- [Development Questions](#development-questions)
- [Deployment and Operations](#deployment-and-operations)
- [Performance and Scaling](#performance-and-scaling)
- [Security and Compliance](#security-and-compliance)
- [Troubleshooting](#troubleshooting)
- [Integrations](#integrations)
- [Licensing and Support](#licensing-and-support)
- [Migration and Adoption](#migration-and-adoption)

## General Questions

### What is Temporal?

**Q: What is Temporal and what problems does it solve?**

A: Temporal is a distributed workflow orchestration platform that helps developers build reliable, scalable applications. It solves several key problems:

- **Reliability**: Automatic retries, timeouts, and failure handling
- **Durability**: Workflow state persists across failures and restarts
- **Visibility**: Complete observability into workflow execution
- **Scalability**: Handles millions of concurrent workflows
- **Developer Experience**: Simple programming model with strong consistency guarantees

### How does Temporal work?

**Q: Can you explain Temporal's core architecture?**

A: Temporal consists of several key components:

1. **Temporal Server**: The core orchestration engine with multiple services
   - Frontend: API gateway for client requests
   - History: Manages workflow state and history
   - Matching: Routes tasks to workers
   - Worker: Internal service tasks

2. **Workers**: Your application code that executes workflows and activities
3. **Database**: Stores workflow state and history (PostgreSQL, MySQL, etc.)
4. **Client SDKs**: Libraries for Go, Java, Python, TypeScript, etc.

Workflows are executed as code but their state is managed by the Temporal server, providing durability and reliability guarantees.

### Is Temporal open source?

**Q: What is Temporal's licensing model?**

A: Temporal has a dual licensing model:

- **Temporal Open Source**: MIT licensed, free to use with community support
- **Temporal Cloud**: Managed service with enterprise features and support
- **Temporal Enterprise**: Self-hosted enterprise version with additional features

The core Temporal Server and all client SDKs are open source and free to use.

### When should I use Temporal?

**Q: What are good use cases for Temporal?**

A: Temporal is ideal for:

- **Long-running workflows**: Order processing, user onboarding, data pipelines
- **Microservice orchestration**: Coordinating multiple services
- **Batch processing**: ETL jobs, data migration, report generation
- **Human-in-the-loop processes**: Approval workflows, manual reviews
- **Saga patterns**: Distributed transactions with compensation
- **Scheduled tasks**: Cron-like jobs with complex logic
- **Event-driven architectures**: Processing events reliably

### How does Temporal compare to other solutions?

**Q: How does Temporal compare to AWS Step Functions, Apache Airflow, or Kubernetes Jobs?**

A: Here's a comparison:

| Feature | Temporal | AWS Step Functions | Apache Airflow | Kubernetes Jobs |
|---------|----------|-------------------|----------------|----------------|
| **Programming Model** | Code-first | JSON/DSL | Python DAGs | YAML/Scripts |
| **Language Support** | Go, Java, Python, TS | Limited | Python mainly | Any language |
| **Local Development** | Full simulation | Limited | Docker setup | Complex |
| **Debugging** | Standard tools | CloudWatch | Web UI | kubectl logs |
| **Testing** | Unit/integration | Integration only | DAG validation | End-to-end |
| **Versioning** | Built-in | Manual | Manual | Image versioning |
| **Cost Model** | Self-hosted or SaaS | Pay-per-execution | Self-hosted | Infrastructure |

## Architecture and Concepts

### What are Workflows and Activities?

**Q: What's the difference between workflows and activities?**

A: 
- **Workflows**: Orchestration logic that defines the sequence of operations. Must be deterministic and can only interact with the outside world through activities.
- **Activities**: Individual units of work that can have side effects (API calls, database operations, file I/O). Can be retried independently.

```go
// Workflow - orchestration only
func OrderWorkflow(ctx workflow.Context, order Order) error {
    // Schedule activities
    var paymentResult PaymentResult
    err := workflow.ExecuteActivity(ctx, ProcessPayment, order.Payment).Get(ctx, &paymentResult)
    if err != nil {
        return err
    }
    
    // Continue with next steps...
    return workflow.ExecuteActivity(ctx, ShipOrder, order.ShippingInfo).Get(ctx, nil)
}

// Activity - does actual work
func ProcessPayment(ctx context.Context, payment PaymentInfo) (PaymentResult, error) {
    // Call external payment API
    return paymentAPI.ProcessPayment(payment)
}
```

### What is determinism and why is it important?

**Q: Why do workflows need to be deterministic?**

A: Determinism ensures that replaying a workflow's history produces the same result. This is crucial because:

1. **Failure Recovery**: Workflows can be resumed from any point
2. **Versioning**: Old workflows can be replayed with new code
3. **Testing**: Workflows behave predictably

**Deterministic Operations (✅ Allowed):**
- `workflow.ExecuteActivity()`
- `workflow.Sleep()`
- `workflow.Now()`
- `workflow.NewRandom()`

**Non-deterministic Operations (❌ Avoid):**
- `time.Now()`
- `rand.Int()`
- Network calls
- File I/O

### How does Temporal handle failures?

**Q: What happens when a workflow or activity fails?**

A: Temporal provides comprehensive failure handling:

**Activity Failures:**
- Automatic retries with exponential backoff
- Configurable retry policies
- Heartbeat timeout detection
- Circuit breaker patterns

**Workflow Failures:**
- Continue-as-new for long-running workflows
- Automatic replay on worker restart
- Child workflow failure propagation
- Compensation patterns (Saga)

**Infrastructure Failures:**
- Worker process crashes → workflows resume on other workers
- Database failures → automatic failover and recovery
- Network partitions → eventual consistency guarantees

### What are Task Queues?

**Q: How do Task Queues work in Temporal?**

A: Task Queues are the mechanism for distributing work between the Temporal server and workers:

- **Workflow Task Queues**: Deliver workflow tasks (orchestration decisions)
- **Activity Task Queues**: Deliver activity tasks (actual work)
- **Routing**: Workers poll specific task queues for work
- **Load Balancing**: Multiple workers can poll the same queue
- **Isolation**: Different workflows can use different queues

```go
// Worker polls specific task queues
w := worker.New(client, "order-processing", worker.Options{})
w.RegisterWorkflow(OrderWorkflow)
w.RegisterActivity(ProcessPayment)

// Workflow uses the same task queue
options := client.StartWorkflowOptions{
    TaskQueue: "order-processing",
}
```

## Development Questions

### How do I get started with Temporal?

**Q: What's the quickest way to start developing with Temporal?**

A: Follow these steps:

1. **Install Temporal CLI**:
   ```bash
   brew install temporal  # macOS
   # or download from GitHub releases
   ```

2. **Start local server**:
   ```bash
   temporal server start-dev
   ```

3. **Create a simple workflow** (Go example):
   ```go
   func HelloWorldWorkflow(ctx workflow.Context, name string) (string, error) {
       var result string
       err := workflow.ExecuteActivity(ctx, HelloWorldActivity, name).Get(ctx, &result)
       return result, err
   }
   
   func HelloWorldActivity(ctx context.Context, name string) (string, error) {
       return "Hello " + name, nil
   }
   ```

4. **Run a worker and start workflow**:
   ```bash
   go run worker/main.go  # Start worker
   go run starter/main.go # Start workflow
   ```

### How do I test Temporal workflows?

**Q: What's the best way to test workflows and activities?**

A: Temporal provides excellent testing support:

**Unit Testing Workflows:**
```go
func TestOrderWorkflow(t *testing.T) {
    testSuite := &testsuite.WorkflowTestSuite{}
    env := testSuite.NewTestWorkflowEnvironment()
    
    // Mock activity
    env.OnActivity(ProcessPayment, mock.Anything).Return(PaymentResult{Success: true}, nil)
    
    // Execute workflow
    env.ExecuteWorkflow(OrderWorkflow, Order{ID: "123"})
    
    // Assertions
    require.True(t, env.IsWorkflowCompleted())
    require.NoError(t, env.GetWorkflowError())
}
```

**Integration Testing:**
```go
func TestOrderWorkflowIntegration(t *testing.T) {
    client := createTestClient()
    
    // Start workflow
    workflowRun, err := client.ExecuteWorkflow(context.Background(), options, OrderWorkflow, order)
    require.NoError(t, err)
    
    // Wait for completion
    var result OrderResult
    err = workflowRun.Get(context.Background(), &result)
    require.NoError(t, err)
}
```

### How do I handle versioning?

**Q: How do I deploy new versions of workflows without breaking running instances?**

A: Temporal provides robust versioning support:

**Version Your Workflow Code:**
```go
func OrderWorkflow(ctx workflow.Context, order Order) error {
    version := workflow.GetVersion(ctx, "add-inventory-check", workflow.DefaultVersion, 1)
    
    if version >= 1 {
        // New logic - check inventory first
        err := workflow.ExecuteActivity(ctx, CheckInventory, order).Get(ctx, nil)
        if err != nil {
            return err
        }
    }
    
    // Existing logic continues...
    return workflow.ExecuteActivity(ctx, ProcessPayment, order).Get(ctx, nil)
}
```

**Use Patch for Simple Changes:**
```go
func MyWorkflow(ctx workflow.Context) error {
    if workflow.HasLastCompletionResult(ctx) {
        // Continue from where we left off
    }
    
    // Old logic
    workflow.ExecuteActivity(ctx, OldActivity).Get(ctx, nil)
    
    // Add new step with patch
    if workflow.IsReplaying(ctx) == false {
        workflow.UpsertSearchAttributes(ctx, map[string]interface{}{
            "NewAttribute": "value",
        })
    }
    
    return nil
}
```

### How do I handle long-running workflows?

**Q: What about workflows that run for months or years?**

A: Temporal handles long-running workflows through several mechanisms:

**Continue-As-New Pattern:**
```go
func LongRunningWorkflow(ctx workflow.Context, state WorkflowState) error {
    // Process batch of work
    for i := 0; i < 1000 && state.HasMoreWork(); i++ {
        err := workflow.ExecuteActivity(ctx, ProcessItem, state.NextItem()).Get(ctx, nil)
        if err != nil {
            return err
        }
    }
    
    // Continue with new execution to avoid large history
    if state.HasMoreWork() {
        return workflow.NewContinueAsNewError(ctx, LongRunningWorkflow, state)
    }
    
    return nil
}
```

**Cron Workflows:**
```go
// Start workflow with cron schedule
options := client.StartWorkflowOptions{
    CronSchedule: "0 12 * * *", // Daily at noon
}
```

**Child Workflows for Isolation:**
```go
func ParentWorkflow(ctx workflow.Context) error {
    for _, batch := range batches {
        // Each batch runs in separate child workflow
        child := workflow.ExecuteChildWorkflow(ctx, ProcessBatch, batch)
        // Can monitor or wait for completion
    }
    return nil
}
```

### How do I handle errors and retries?

**Q: How do I configure retry policies and handle different types of errors?**

A: Temporal provides flexible error handling:

**Configure Retry Policies:**
```go
retryPolicy := &temporal.RetryPolicy{
    InitialInterval:        time.Second,
    BackoffCoefficient:     2.0,
    MaximumInterval:        time.Minute,
    MaximumAttempts:        5,
    NonRetryableErrorTypes: []string{"InvalidInputError"},
}

activityOptions := workflow.ActivityOptions{
    TaskQueue:   "my-queue",
    RetryPolicy: retryPolicy,
}
```

**Handle Different Error Types:**
```go
func MyActivity(ctx context.Context, input Input) (Output, error) {
    if input.ID == "" {
        // Non-retryable error
        return Output{}, temporal.NewNonRetryableApplicationError(
            "invalid input", "InvalidInputError", nil)
    }
    
    result, err := externalAPI.Call(input)
    if err != nil {
        if isTemporaryError(err) {
            // Retryable error
            return Output{}, temporal.NewApplicationError(
                "service unavailable", "ServiceUnavailable", err)
        }
        // Permanent error
        return Output{}, temporal.NewNonRetryableApplicationError(
            "permanent failure", "PermanentError", err)
    }
    
    return result, nil
}
```

## Deployment and Operations

### How do I deploy Temporal?

**Q: What are the deployment options for Temporal?**

A: Temporal offers several deployment options:

**1. Temporal Cloud (Recommended for production)**
```bash
# Connect to Temporal Cloud
temporal config set address my-namespace.tmprl.cloud:7233
temporal config set namespace my-namespace.account
```

**2. Self-hosted with Docker Compose**
```yaml
# docker-compose.yml
version: '3.8'
services:
  temporal:
    image: temporalio/server:latest
    ports:
      - "7233:7233"
    environment:
      - DB=postgresql
      - DB_PORT=5432
      - POSTGRES_USER=temporal
      - POSTGRES_PWD=temporal
```

**3. Kubernetes with Helm**
```bash
helm repo add temporalio https://charts.temporal.io
helm install temporal temporalio/temporal
```

**4. Development Server**
```bash
temporal server start-dev --ui-port 8080
```

### What are the infrastructure requirements?

**Q: What infrastructure do I need to run Temporal?**

A: **Minimum Requirements:**
- **CPU**: 2 cores per service
- **Memory**: 4GB per service
- **Database**: PostgreSQL 10+ or MySQL 8+
- **Storage**: 100GB+ depending on workflow volume

**Production Recommendations:**
- **High Availability**: 3+ replicas per service
- **Load Balancing**: Frontend service behind load balancer
- **Database**: Managed database service (AWS RDS, Google Cloud SQL)
- **Monitoring**: Prometheus + Grafana
- **Logging**: Structured JSON logs with centralized collection

**Scaling Guidelines:**
- **Frontend**: Scale based on request volume (1 replica per 10k RPS)
- **History**: Scale based on workflow volume (1 replica per 100k active workflows)
- **Matching**: Scale based on task queue load
- **Database**: Monitor query performance and connection limits

### How do I monitor Temporal?

**Q: What monitoring and observability tools should I use?**

A: Temporal provides comprehensive observability:

**Metrics (Prometheus/Grafana)**
```yaml
# Expose metrics
global:
  metrics:
    prometheus:
      timerType: "histogram"
      listenAddress: "0.0.0.0:9090"
```

**Key Metrics to Monitor:**
- `temporal_request_latency`: API latency
- `temporal_workflow_completed_total`: Workflow completion rate
- `temporal_activity_failed_total`: Activity failure rate
- `temporal_persistence_latency`: Database latency

**Logging**
```yaml
log:
  stdout: true
  level: "info"
  format: "json"
```

**Web UI**
- Built-in UI at `http://temporal:8080`
- Workflow execution history
- Task queue status
- System health

**Custom Metrics**
```go
// Add custom metrics to workflows
workflow.GetMetricsScope(ctx).Counter("custom_counter").Inc(1)
workflow.GetMetricsScope(ctx).Gauge("custom_gauge").Update(value)
```

### How do I backup and restore Temporal?

**Q: What's the backup and disaster recovery strategy?**

A: **Database Backup:**
```bash
# PostgreSQL backup
pg_dump temporal > temporal_backup.sql

# MySQL backup
mysqldump temporal > temporal_backup.sql
```

**Backup Strategy:**
- **Frequency**: Daily full backups, hourly incremental
- **Retention**: 30 days of backups
- **Testing**: Regular restore testing
- **Cross-region**: Backup to different region/availability zone

**Disaster Recovery:**
```bash
# Restore from backup
psql temporal < temporal_backup.sql

# Verify cluster health
temporal cluster health

# Check workflow integrity
temporal workflow list --limit 10
```

**Multi-Region Setup:**
```yaml
clusterMetadata:
  enableGlobalNamespace: true
  clusterInformation:
    cluster1:
      enabled: true
      rpcAddress: "temporal-west.company.com:7233"
    cluster2:
      enabled: true
      rpcAddress: "temporal-east.company.com:7233"
```

## Performance and Scaling

### How does Temporal scale?

**Q: How many workflows can Temporal handle?**

A: Temporal can scale to handle:
- **Millions** of concurrent workflow executions
- **Thousands** of workflow starts per second
- **Petabytes** of workflow history data

**Scaling Factors:**
- **Database Performance**: Primary bottleneck
- **Worker Capacity**: CPU and memory for processing
- **Network Bandwidth**: For high-throughput scenarios

**Scaling Strategies:**
```yaml
# Scale services horizontally
history:
  numShards: 16  # Increase shards for more parallelism
  replicas: 10   # Multiple replicas per shard

matching:
  replicas: 5    # Scale matching service

frontend:
  replicas: 3    # Scale API layer
```

### How do I optimize performance?

**Q: What are best practices for Temporal performance?**

A: **Workflow Optimization:**
```go
// Use batch operations
func BatchWorkflow(ctx workflow.Context, items []Item) error {
    // Process in batches instead of individual activities
    futures := make([]workflow.Future, 0)
    for i := 0; i < len(items); i += 100 {
        batch := items[i:min(i+100, len(items))]
        future := workflow.ExecuteActivity(ctx, ProcessBatch, batch)
        futures = append(futures, future)
    }
    
    // Wait for all batches
    for _, future := range futures {
        err := future.Get(ctx, nil)
        if err != nil {
            return err
        }
    }
    return nil
}
```

**Activity Optimization:**
```go
// Use appropriate timeouts
activityOptions := workflow.ActivityOptions{
    StartToCloseTimeout: 30 * time.Second,  // Don't set too high
    HeartbeatTimeout:    10 * time.Second,  // For long activities
    RetryPolicy: &temporal.RetryPolicy{
        MaximumAttempts: 3,  // Don't retry forever
    },
}
```

**Database Optimization:**
```sql
-- Add indexes for common queries
CREATE INDEX CONCURRENTLY idx_executions_namespace_workflow_id 
ON executions(namespace_id, workflow_id);

-- Tune database settings
-- shared_buffers = 25% of RAM
-- max_connections = 200
-- work_mem = 256MB
```

### What are the resource limits?

**Q: Are there any limits I should be aware of?**

A: **Workflow Limits:**
- **History Size**: 50MB per workflow (use continue-as-new)
- **Input/Output**: 2MB per activity/workflow
- **Concurrent Activities**: 100k per workflow
- **Workflow Duration**: Unlimited (years if needed)

**Activity Limits:**
- **Execution Time**: No hard limit (configure timeouts)
- **Heartbeat**: Required for activities > 10 seconds
- **Retry Attempts**: Configurable (default: unlimited)

**System Limits:**
- **Namespace**: 10k workflows per second start rate
- **Task Queue**: 1M tasks per minute processing rate
- **Database**: Depends on infrastructure (typically 10k+ QPS)

```go
// Monitor and handle limits
func LargeWorkflow(ctx workflow.Context) error {
    // Check history size
    info := workflow.GetInfo(ctx)
    if info.HistoryLength > 10000 {
        // Continue as new to reset history
        return workflow.NewContinueAsNewError(ctx, LargeWorkflow)
    }
    
    // Process normally
    return nil
}
```

## Security and Compliance

### How secure is Temporal?

**Q: What security features does Temporal provide?**

A: **Transport Security:**
- TLS encryption for all communications
- mTLS for service-to-service authentication
- Certificate rotation support

**Authentication & Authorization:**
- JWT token-based authentication
- RBAC (Role-Based Access Control)
- API key authentication
- LDAP/SSO integration (Enterprise)

**Data Security:**
- Encryption at rest (database level)
- Data converter for payload encryption
- PII redaction capabilities
- Audit logging

```go
// Encrypt sensitive data
type EncryptedDataConverter struct {
    temporal.DataConverter
    encryptionKey []byte
}

func (edc *EncryptedDataConverter) ToPayload(value interface{}) (*commonpb.Payload, error) {
    // Encrypt sensitive fields before storing
    return edc.encrypt(value)
}
```

### Is Temporal GDPR/HIPAA compliant?

**Q: Can I use Temporal for regulated workloads?**

A: Temporal can be configured for compliance:

**GDPR Compliance:**
- Data encryption and access controls
- Right to be forgotten (workflow termination)
- Data portability (export capabilities)
- Audit trails and logging

**HIPAA Compliance:**
- Encryption in transit and at rest
- Access controls and authentication
- Audit logging
- Business Associate Agreement (BAA) available

**Implementation:**
```go
// GDPR data handling
func HandleDataDeletionRequest(ctx workflow.Context, userID string) error {
    // Find and terminate user workflows
    workflows := findUserWorkflows(userID)
    for _, wf := range workflows {
        err := workflow.RequestCancelExternalWorkflow(ctx, wf.ID, "").Get(ctx, nil)
        if err != nil {
            return err
        }
    }
    
    // Schedule data deletion activity
    return workflow.ExecuteActivity(ctx, DeleteUserData, userID).Get(ctx, nil)
}
```

### How do I encrypt workflow data?

**Q: How can I encrypt sensitive data in workflows?**

A: **Custom Data Converter:**
```go
type EncryptedPayloadConverter struct {
    temporal.DefaultDataConverter
    options PayloadConverterOptions
}

func (c *EncryptedPayloadConverter) ToPayload(value interface{}) (*commonpb.Payload, error) {
    // Check if value contains sensitive data
    if containsSensitiveData(value) {
        // Encrypt before storing
        encrypted, err := c.encrypt(value)
        if err != nil {
            return nil, err
        }
        return &commonpb.Payload{
            Metadata: map[string][]byte{
                "encoding":   []byte("binary/encrypted"),
                "encryption": []byte("aes256"),
            },
            Data: encrypted,
        }, nil
    }
    
    // Use default conversion for non-sensitive data
    return c.DefaultDataConverter.ToPayload(value)
}
```

**Usage:**
```go
// Configure client with encryption
client, err := client.Dial(client.Options{
    DataConverter: NewEncryptedDataConverter(encryptionKey),
})
```

## Troubleshooting

### Common Issues and Solutions

**Q: My workflows aren't starting. What should I check?**

A: **Troubleshooting checklist:**

1. **Check worker registration:**
   ```bash
   temporal task-queue describe my-queue --include-pollers
   ```

2. **Verify workflow registration:**
   ```go
   // Ensure workflow is registered
   w.RegisterWorkflow(MyWorkflow)
   ```

3. **Check for errors:**
   ```bash
   temporal workflow describe --workflow-id my-workflow
   ```

4. **Validate input:**
   ```bash
   echo '{"key": "value"}' | jq .  # Validate JSON
   ```

**Q: My activities are timing out. How do I fix this?**

A: **Activity timeout solutions:**

1. **Increase timeouts:**
   ```go
   activityOptions := workflow.ActivityOptions{
       StartToCloseTimeout: 5 * time.Minute,
       HeartbeatTimeout:    30 * time.Second,
   }
   ```

2. **Add heartbeats:**
   ```go
   func LongActivity(ctx context.Context) error {
       for i := 0; i < 1000; i++ {
           // Send heartbeat periodically
           activity.RecordHeartbeat(ctx, i)
           
           // Do work
           processItem(i)
       }
       return nil
   }
   ```

3. **Check worker capacity:**
   ```bash
   # Monitor worker resource usage
   kubectl top pods -l app=my-worker
   ```

**Q: How do I debug workflow execution?**

A: **Debugging techniques:**

1. **Use local development:**
   ```bash
   temporal server start-dev --ui-port 8080
   ```

2. **Add logging:**
   ```go
   func MyWorkflow(ctx workflow.Context) error {
       logger := workflow.GetLogger(ctx)
       logger.Info("Starting workflow", "workflowID", workflow.GetInfo(ctx).WorkflowExecution.ID)
       
       // Your workflow logic
       return nil
   }
   ```

3. **Use the Web UI:**
   - Navigate to `http://localhost:8080`
   - View workflow history and events
   - Check activity results and failures

4. **Query workflow state:**
   ```go
   // Add query handler
   workflow.SetQueryHandler(ctx, "getStatus", func() (string, error) {
       return currentStatus, nil
   })
   ```

   ```bash
   # Query from CLI
   temporal workflow query --workflow-id my-workflow --type getStatus
   ```

## Integrations

### Which programming languages are supported?

**Q: What SDKs are available for Temporal?**

A: **Official SDKs:**
- **Go**: Full-featured, production-ready
- **Java**: Full-featured, production-ready  
- **Python**: Full-featured, production-ready
- **TypeScript/Node.js**: Full-featured, production-ready
- **PHP**: Community-maintained
- **.NET**: Community-maintained

**Language-specific features:**
```go
// Go - Strong typing and performance
func TypedWorkflow(ctx workflow.Context, input TypedInput) (TypedOutput, error) {
    var result TypedOutput
    err := workflow.ExecuteActivity(ctx, TypedActivity, input).Get(ctx, &result)
    return result, err
}
```

```python
# Python - Async/await support
@workflow.defn
class MyWorkflow:
    @workflow.run
    async def run(self, input: MyInput) -> MyOutput:
        return await workflow.execute_activity(
            my_activity, input, 
            start_to_close_timeout=timedelta(seconds=30)
        )
```

### How do I integrate with other systems?

**Q: How does Temporal integrate with message queues, databases, and APIs?**

A: **Message Queue Integration:**
```go
// Kafka integration
func ProcessKafkaMessage(ctx context.Context, message KafkaMessage) error {
    // Process message in activity
    return processMessage(message)
}

func KafkaConsumerWorkflow(ctx workflow.Context) error {
    // Long-running workflow that processes messages
    for {
        var message KafkaMessage
        err := workflow.ExecuteActivity(ctx, ConsumeKafkaMessage).Get(ctx, &message)
        if err != nil {
            continue
        }
        
        // Process message
        err = workflow.ExecuteActivity(ctx, ProcessKafkaMessage, message).Get(ctx, nil)
        if err != nil {
            // Handle error or retry
        }
    }
}
```

**Database Integration:**
```go
// Database operations in activities
func UpdateUserActivity(ctx context.Context, userID string, data UserData) error {
    db := getDatabase()
    _, err := db.ExecContext(ctx, "UPDATE users SET data = $1 WHERE id = $2", data, userID)
    return err
}

// Saga pattern for distributed transactions
func SagaWorkflow(ctx workflow.Context, order Order) error {
    compensations := make([]workflow.Future, 0)
    
    // Step 1: Reserve inventory
    err := workflow.ExecuteActivity(ctx, ReserveInventory, order).Get(ctx, nil)
    if err != nil {
        return err
    }
    compensations = append(compensations, workflow.ExecuteActivity(ctx, ReleaseInventory, order))
    
    // Step 2: Process payment
    err = workflow.ExecuteActivity(ctx, ProcessPayment, order).Get(ctx, nil)
    if err != nil {
        // Compensate previous steps
        for _, compensation := range compensations {
            compensation.Get(ctx, nil)
        }
        return err
    }
    
    return nil
}
```

**API Integration:**
```go
// REST API calls
func CallExternalAPI(ctx context.Context, request APIRequest) (APIResponse, error) {
    client := &http.Client{Timeout: 30 * time.Second}
    
    resp, err := client.Post(request.URL, "application/json", bytes.NewBuffer(request.Body))
    if err != nil {
        return APIResponse{}, err
    }
    defer resp.Body.Close()
    
    var response APIResponse
    err = json.NewDecoder(resp.Body).Decode(&response)
    return response, err
}
```

### Can I use Temporal with Kubernetes?

**Q: How do I deploy Temporal workers in Kubernetes?**

A: **Worker Deployment:**
```yaml
# worker-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: temporal-worker
spec:
  replicas: 3
  selector:
    matchLabels:
      app: temporal-worker
  template:
    metadata:
      labels:
        app: temporal-worker
    spec:
      containers:
      - name: worker
        image: my-temporal-worker:latest
        env:
        - name: TEMPORAL_ADDRESS
          value: "temporal-frontend:7233"
        - name: TEMPORAL_NAMESPACE
          value: "default"
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
```

**Horizontal Pod Autoscaler:**
```yaml
# worker-hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: temporal-worker-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: temporal-worker
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## Licensing and Support

### What support options are available?

**Q: How do I get help with Temporal?**

A: **Support Channels:**

**Community Support (Free):**
- [Temporal Community Forum](https://community.temporal.io/)
- [GitHub Issues](https://github.com/temporalio/temporal)
- [Stack Overflow](https://stackoverflow.com/questions/tagged/temporal-workflow)
- [Discord Community](https://discord.gg/temporal)

**Professional Support:**
- **Temporal Cloud**: Included with managed service
- **Enterprise Support**: 24/7 support with SLA
- **Professional Services**: Implementation assistance

**Documentation:**
- [Official Documentation](https://docs.temporal.io/)
- [API Reference](https://docs.temporal.io/api/)
- [Sample Applications](https://github.com/temporalio/samples)

### What's included in Temporal Cloud?

**Q: What are the benefits of Temporal Cloud vs self-hosting?**

A: **Temporal Cloud Benefits:**
- **Managed Infrastructure**: No server management
- **Auto-scaling**: Handles traffic spikes automatically
- **High Availability**: 99.9% uptime SLA
- **Security**: SOC 2, GDPR compliant
- **Monitoring**: Built-in observability
- **Support**: Included professional support

**Pricing Model:**
- Pay-per-workflow execution
- No infrastructure costs
- Predictable billing
- Free tier available

**Migration:**
```bash
# Export from self-hosted
temporal workflow list --output json > workflows.json

# Import to Temporal Cloud
temporal --address my-namespace.tmprl.cloud:7233 workflow start ...
```

## Migration and Adoption

### How do I migrate from other workflow engines?

**Q: I'm using AWS Step Functions/Apache Airflow. How do I migrate?**

A: **Migration Strategy:**

**1. Assessment Phase:**
- Inventory existing workflows
- Identify dependencies and integrations
- Plan migration order (simple workflows first)

**2. Incremental Migration:**
```go
// Wrapper for existing Step Functions
func MigrateStepFunction(ctx workflow.Context, input StepFunctionInput) error {
    // Option 1: Call existing Step Function during migration
    if workflow.GetVersion(ctx, "migration", workflow.DefaultVersion, 1) == workflow.DefaultVersion {
        return workflow.ExecuteActivity(ctx, CallStepFunction, input).Get(ctx, nil)
    }
    
    // Option 2: Native Temporal implementation
    return workflow.ExecuteActivity(ctx, NativeImplementation, input).Get(ctx, nil)
}
```

**3. Data Migration:**
```bash
# Export Step Functions execution history
aws stepfunctions list-executions --state-machine-arn arn:aws:...

# Convert to Temporal format and import
temporal workflow start --workflow-type MigratedWorkflow --input converted_data.json
```

### How do I introduce Temporal to my team?

**Q: What's the best way to adopt Temporal in an organization?**

A: **Adoption Strategy:**

**1. Start Small:**
- Choose a simple, non-critical workflow
- Build proof of concept
- Demonstrate value to stakeholders

**2. Training and Education:**
- Hands-on workshops
- Code reviews and pair programming
- Internal documentation and best practices

**3. Gradual Rollout:**
```go
// Feature flag approach
func NewOrderWorkflow(ctx workflow.Context, order Order) error {
    if useTemporalWorkflow(order) {
        return TemporalOrderWorkflow(ctx, order)
    }
    
    // Fall back to existing system
    return LegacyOrderWorkflow(ctx, order)
}
```

**4. Success Metrics:**
- Reduced development time
- Improved reliability (fewer failures)
- Better observability
- Developer satisfaction

**5. Common Concerns and Responses:**

| Concern | Response |
|---------|----------|
| "Another tool to learn" | "Temporal reduces complexity overall by eliminating custom retry logic, state management, and error handling" |
| "Vendor lock-in" | "Temporal is open source with standard programming languages - easy to migrate if needed" |
| "Performance overhead" | "Temporal typically improves performance by optimizing retries and eliminating polling patterns" |
| "Infrastructure complexity" | "Start with Temporal Cloud to avoid infrastructure management" |

This comprehensive FAQ covers the most common questions about Temporal.io across all aspects of development, deployment, and operations.
