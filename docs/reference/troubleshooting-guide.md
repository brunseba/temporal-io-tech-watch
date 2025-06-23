# Troubleshooting Guide

This comprehensive troubleshooting guide helps diagnose and resolve common issues with Temporal.io deployments, workflows, activities, and operational problems.

## Table of Contents

- [General Troubleshooting](#general-troubleshooting)
- [Connection Issues](#connection-issues)
- [Workflow Issues](#workflow-issues)
- [Activity Issues](#activity-issues)
- [Worker Issues](#worker-issues)
- [Performance Issues](#performance-issues)
- [Database Issues](#database-issues)
- [Security Issues](#security-issues)
- [Monitoring and Observability](#monitoring-and-observability)
- [Common Error Messages](#common-error-messages)
- [Debugging Tools](#debugging-tools)
- [Recovery Procedures](#recovery-procedures)

## General Troubleshooting

### Initial Diagnosis Steps

1. **Check Service Health**
   ```bash
   # Check cluster health
   temporal cluster health
   
   # Check individual service status
   curl -f http://temporal-frontend:7233/health
   curl -f http://temporal-history:7234/health
   curl -f http://temporal-matching:7235/health
   curl -f http://temporal-worker:7239/health
   ```

2. **Verify Configuration**
   ```bash
   # Check current configuration
   temporal config get
   
   # Verify connectivity
   temporal namespace list
   ```

3. **Check Logs**
   ```bash
   # View service logs
   kubectl logs -n temporal-system deployment/temporal-frontend
   kubectl logs -n temporal-system deployment/temporal-history
   kubectl logs -n temporal-system deployment/temporal-matching
   kubectl logs -n temporal-system deployment/temporal-worker
   ```

4. **Verify Database Connectivity**
   ```bash
   # Test database connection
   temporal sql-tool \
     --database temporal \
     --plugin postgres \
     --endpoint postgres://user:pass@localhost/temporal \
     show-tables
   ```

### Environment Verification Checklist

- [ ] All services are running and healthy
- [ ] Database is accessible and contains expected schema
- [ ] Network connectivity between services
- [ ] TLS certificates are valid (if using TLS)
- [ ] Authentication configuration is correct
- [ ] Environment variables are set properly
- [ ] Resource limits are sufficient

## Connection Issues

### Cannot Connect to Temporal Server

**Symptoms:**
- Client timeout errors
- Connection refused messages
- DNS resolution failures

**Diagnosis:**
```bash
# Test basic connectivity
telnet temporal.company.com 7233

# Check DNS resolution
nslookup temporal.company.com

# Test with curl
curl -v grpc://temporal.company.com:7233

# Check certificate validity (if using TLS)
openssl s_client -connect temporal.company.com:7233 -servername temporal.company.com
```

**Solutions:**

1. **Network Connectivity Issues**
   ```bash
   # Check firewall rules
   sudo iptables -L
   
   # Test from different network locations
   ping temporal.company.com
   traceroute temporal.company.com
   ```

2. **TLS Configuration Problems**
   ```bash
   # Verify certificate chain
   openssl verify -CAfile ca.crt client.crt
   
   # Check certificate expiration
   openssl x509 -in client.crt -noout -dates
   
   # Test with proper TLS config
   temporal --tls-cert-path client.crt \
           --tls-key-path client.key \
           --tls-ca-path ca.crt \
           --address temporal.company.com:7233 \
           namespace list
   ```

3. **Load Balancer Issues**
   ```bash
   # Test direct backend connection
   temporal --address temporal-frontend-1.company.com:7233 namespace list
   
   # Check load balancer health
   curl -f http://load-balancer/health
   ```

### Authentication Failures

**Symptoms:**
- "Unauthenticated" error messages
- JWT token validation failures
- API key rejection

**Diagnosis:**
```bash
# Test without authentication
temporal --address temporal.company.com:7233 cluster health

# Verify JWT token
jwt-cli decode your-jwt-token

# Check API key format
echo "Authorization: Bearer $API_KEY" | base64 -d
```

**Solutions:**

1. **JWT Token Issues**
   ```bash
   # Generate new token
   jwt-cli encode \
     --iss "https://auth.company.com" \
     --sub "user@company.com" \
     --aud "temporal.company.com" \
     --exp $(date -d "+1 hour" +%s) \
     --secret "your-secret"
   
   # Verify token claims
   temporal --headers "Authorization=Bearer $JWT_TOKEN" namespace list
   ```

2. **API Key Problems**
   ```bash
   # Set API key correctly
   export TEMPORAL_API_KEY="your-api-key"
   temporal config set auth.api-key "$TEMPORAL_API_KEY"
   ```

## Workflow Issues

### Workflow Not Starting

**Symptoms:**
- Workflow start command hangs
- "Already exists" errors
- Task queue not found

**Diagnosis:**
```bash
# Check workflow existence
temporal workflow describe --workflow-id my-workflow

# Verify task queue
temporal task-queue describe my-task-queue

# Check namespace
temporal namespace describe my-namespace
```

**Solutions:**

1. **Workflow ID Conflicts**
   ```bash
   # Use unique workflow ID
   temporal workflow start \
     --workflow-type MyWorkflow \
     --task-queue my-queue \
     --workflow-id "my-workflow-$(date +%s)" \
     --input '{}'
   
   # Or allow duplicate failed executions
   temporal workflow start \
     --workflow-type MyWorkflow \
     --task-queue my-queue \
     --workflow-id my-workflow \
     --workflow-id-reuse-policy AllowDuplicateFailedOnly \
     --input '{}'
   ```

2. **Task Queue Issues**
   ```bash
   # Create/verify task queue by starting a worker
   temporal worker start \
     --task-queue my-queue \
     --workflow-type MyWorkflow
   ```

3. **Input Validation Problems**
   ```bash
   # Validate JSON input
   echo '{"key": "value"}' | jq .
   
   # Use input file for complex data
   temporal workflow start \
     --workflow-type MyWorkflow \
     --task-queue my-queue \
     --workflow-id my-workflow \
     --input-file input.json
   ```

### Workflow Stuck or Not Progressing

**Symptoms:**
- Workflow shows as running but no progress
- Activities not being scheduled
- No worker polling

**Diagnosis:**
```bash
# Check workflow history
temporal workflow show --workflow-id my-workflow

# Check task queue pollers
temporal task-queue describe my-queue --include-pollers

# Check for sticky task queue issues
temporal workflow describe --workflow-id my-workflow --raw | grep sticky
```

**Solutions:**

1. **No Workers Polling**
   ```bash
   # Start worker for the task queue
   temporal worker start \
     --task-queue my-queue \
     --workflow-type MyWorkflow \
     --activity-type MyActivity
   ```

2. **Sticky Task Queue Problems**
   ```bash
   # Reset workflow to clear sticky queue
   temporal workflow reset \
     --workflow-id my-workflow \
     --type LastWorkflowTask \
     --reason "Clear sticky queue"
   ```

3. **Workflow Task Timeout**
   ```bash
   # Check for workflow task timeouts in history
   temporal workflow show --workflow-id my-workflow | grep -i timeout
   
   # Increase workflow task timeout
   temporal workflow start \
     --workflow-type MyWorkflow \
     --task-queue my-queue \
     --workflow-id my-workflow \
     --workflow-task-timeout 60s \
     --input '{}'
   ```

### Workflow Failures

**Symptoms:**
- Workflow execution failed
- Unexpected termination
- Panic in workflow code

**Diagnosis:**
```bash
# Check failure details
temporal workflow show --workflow-id my-workflow | grep -A 10 -i "failed\|error"

# Get failure reason
temporal workflow describe --workflow-id my-workflow | grep -i failure

# Check worker logs
kubectl logs -l app=my-worker --tail=100
```

**Solutions:**

1. **Handle Application Errors**
   ```go
   // Go example - proper error handling
   func MyWorkflow(ctx workflow.Context, input MyInput) (MyOutput, error) {
       var result MyOutput
       err := workflow.ExecuteActivity(ctx, MyActivity, input).Get(ctx, &result)
       if err != nil {
           // Handle specific error types
           if temporal.IsApplicationError(err) {
               // Log and potentially retry
               workflow.GetLogger(ctx).Error("Application error", "error", err)
               return MyOutput{}, err
           }
           // Handle other error types
           return MyOutput{}, err
       }
       return result, nil
   }
   ```

2. **Fix Determinism Issues**
   ```go
   // Avoid non-deterministic operations
   func MyWorkflow(ctx workflow.Context) error {
       // WRONG: Don't use time.Now() directly
       // now := time.Now()
       
       // CORRECT: Use workflow.Now()
       now := workflow.Now(ctx)
       
       // WRONG: Don't use random numbers directly
       // rand := rand.Intn(100)
       
       // CORRECT: Use workflow.NewRandom()
       rand := workflow.NewRandom(ctx).Intn(100)
       
       return nil
   }
   ```

## Activity Issues

### Activity Timeouts

**Symptoms:**
- Activity timeout errors
- Activities appearing to hang
- Heartbeat timeout failures

**Diagnosis:**
```bash
# Check activity details
temporal workflow show --workflow-id my-workflow | grep -A 5 -i activity

# Look for timeout-related events
temporal workflow show --workflow-id my-workflow | grep -i timeout

# Check activity configuration
temporal workflow describe --workflow-id my-workflow --raw | jq '.workflowExecutionInfo.type'
```

**Solutions:**

1. **Configure Appropriate Timeouts**
   ```go
   // Go example - proper activity options
   ao := workflow.ActivityOptions{
       TaskQueue:               "my-queue",
       ScheduleToCloseTimeout:  time.Hour,     // Total time allowed
       ScheduleToStartTimeout:  time.Minute,   // Time to start execution
       StartToCloseTimeout:     30 * time.Minute, // Execution time
       HeartbeatTimeout:        time.Minute,   // Heartbeat interval
       RetryPolicy: &temporal.RetryPolicy{
           InitialInterval:    time.Second,
           BackoffCoefficient: 2.0,
           MaximumInterval:    time.Minute,
           MaximumAttempts:    3,
       },
   }
   ctx = workflow.WithActivityOptions(ctx, ao)
   ```

2. **Implement Activity Heartbeats**
   ```go
   // Go example - activity with heartbeat
   func MyLongRunningActivity(ctx context.Context, input MyInput) (MyOutput, error) {
       for i := 0; i < 100; i++ {
           // Do some work
           processItem(input.Items[i])
           
           // Send heartbeat every iteration
           activity.RecordHeartbeat(ctx, i)
           
           // Check for cancellation
           if ctx.Err() != nil {
               return MyOutput{}, ctx.Err()
           }
       }
       return MyOutput{}, nil
   }
   ```

### Activity Retries and Failures

**Symptoms:**
- Activities failing repeatedly
- Exhausted retry attempts
- Non-retryable errors

**Diagnosis:**
```bash
# Check activity retry history
temporal workflow show --workflow-id my-workflow --event-type ActivityTaskFailed,ActivityTaskCompleted

# Check error details
temporal workflow show --workflow-id my-workflow | grep -A 20 "ActivityTaskFailed"
```

**Solutions:**

1. **Configure Retry Policies**
   ```go
   // Go example - retry policy configuration
   retryPolicy := &temporal.RetryPolicy{
       InitialInterval:        time.Second,
       BackoffCoefficient:     2.0,
       MaximumInterval:        time.Minute,
       MaximumAttempts:        5,
       NonRetryableErrorTypes: []string{"InvalidArgumentError"},
   }
   
   ao := workflow.ActivityOptions{
       TaskQueue:   "my-queue",
       RetryPolicy: retryPolicy,
   }
   ```

2. **Handle Errors Appropriately**
   ```go
   // Go example - error classification
   func MyActivity(ctx context.Context, input MyInput) (MyOutput, error) {
       if input.ID == "" {
           // Non-retryable error
           return MyOutput{}, temporal.NewNonRetryableApplicationError(
               "invalid input", "InvalidArgumentError", nil)
       }
       
       result, err := externalService.Call(input)
       if err != nil {
           if isTransientError(err) {
               // Retryable error
               return MyOutput{}, temporal.NewApplicationError(
                   "service unavailable", "ServiceUnavailable", err)
           }
           // Non-retryable error
           return MyOutput{}, temporal.NewNonRetryableApplicationError(
               "permanent failure", "PermanentFailure", err)
       }
       
       return result, nil
   }
   ```

## Worker Issues

### Worker Not Polling

**Symptoms:**
- No tasks being processed
- Task queue shows no pollers
- Worker appears to be running but idle

**Diagnosis:**
```bash
# Check worker registration
temporal task-queue describe my-queue --include-pollers

# Check worker logs
kubectl logs -l app=my-worker

# Verify worker configuration
ps aux | grep temporal-worker
```

**Solutions:**

1. **Verify Worker Configuration**
   ```go
   // Go example - proper worker setup
   c, err := client.Dial(client.Options{
       HostPort:  "temporal.company.com:7233",
       Namespace: "my-namespace",
   })
   if err != nil {
       log.Fatal("Unable to create client", err)
   }
   defer c.Close()
   
   w := worker.New(c, "my-queue", worker.Options{
       MaxConcurrentActivityExecutionSize: 100,
       MaxConcurrentWorkflowTaskExecutionSize: 100,
   })
   
   // Register workflows and activities
   w.RegisterWorkflow(MyWorkflow)
   w.RegisterActivity(MyActivity)
   
   err = w.Run(worker.InterruptCh())
   if err != nil {
       log.Fatal("Unable to start worker", err)
   }
   ```

2. **Check Network Connectivity**
   ```bash
   # Test connection from worker host
   telnet temporal.company.com 7233
   
   # Check DNS resolution
   nslookup temporal.company.com
   ```

### Worker Performance Issues

**Symptoms:**
- High CPU or memory usage
- Slow task processing
- Worker crashes or restarts

**Diagnosis:**
```bash
# Check resource usage
top -p $(pgrep temporal-worker)
ps aux | grep temporal-worker

# Check memory usage
cat /proc/$(pgrep temporal-worker)/status | grep -i mem

# Check goroutine count (Go workers)
curl http://localhost:8080/debug/pprof/goroutine?debug=1
```

**Solutions:**

1. **Tune Worker Configuration**
   ```go
   // Go example - optimized worker options
   w := worker.New(c, "my-queue", worker.Options{
       MaxConcurrentActivityExecutionSize:     100,  // Adjust based on activity type
       MaxConcurrentWorkflowTaskExecutionSize: 100,  // Usually lower than activities
       MaxConcurrentActivityTaskPollers:       10,   // Number of pollers
       MaxConcurrentWorkflowTaskPollers:       10,   // Number of pollers
   })
   ```

2. **Monitor and Profile**
   ```go
   // Enable pprof endpoint
   import _ "net/http/pprof"
   
   func init() {
       go func() {
           log.Println(http.ListenAndServe("localhost:6060", nil))
       }()
   }
   ```

3. **Implement Resource Management**
   ```go
   // Go example - activity resource management
   func MyActivity(ctx context.Context, input MyInput) (MyOutput, error) {
       // Limit memory usage
       runtime.GC()
       
       // Use context for cancellation
       select {
       case <-ctx.Done():
           return MyOutput{}, ctx.Err()
       default:
           // Process normally
       }
       
       return processInput(input), nil
   }
   ```

## Performance Issues

### High Latency

**Symptoms:**
- Slow workflow execution
- High response times
- Delayed task processing

**Diagnosis:**
```bash
# Check service metrics
curl http://temporal-frontend:9090/metrics | grep temporal_request_latency

# Monitor database performance
EXPLAIN ANALYZE SELECT * FROM executions WHERE namespace_id = 'my-namespace';

# Check network latency
ping temporal.company.com
```

**Solutions:**

1. **Database Optimization**
   ```sql
   -- Add database indexes
   CREATE INDEX CONCURRENTLY idx_executions_namespace_workflow_id 
   ON executions(namespace_id, workflow_id);
   
   -- Analyze query plans
   EXPLAIN (ANALYZE, BUFFERS) 
   SELECT * FROM executions 
   WHERE namespace_id = 'my-namespace' 
   AND workflow_id = 'my-workflow';
   ```

2. **Configure Connection Pools**
   ```yaml
   # Database configuration
   persistence:
     defaultStore: default
     datastores:
       default:
         sql:
           maxConns: 50           # Increase connection pool
           maxIdleConns: 25       # Keep idle connections
           maxConnLifetime: "1h"  # Connection lifetime
   ```

3. **Tune Service Configuration**
   ```yaml
   # History service tuning
   history:
     taskProcessRPS: 2000          # Increase task processing rate
     persistenceMaxQPS: 5000       # Increase persistence QPS
     
   # Frontend service tuning  
   frontend:
     rps: 10000                    # Increase rate limits
   ```

### High Resource Usage

**Symptoms:**
- High CPU or memory usage
- OOM kills
- Disk space issues

**Diagnosis:**
```bash
# Monitor resource usage
kubectl top pods -n temporal-system

# Check memory usage
kubectl describe pod temporal-history-xxx -n temporal-system

# Monitor disk usage
df -h
du -sh /var/lib/temporal/*
```

**Solutions:**

1. **Resource Limit Configuration**
   ```yaml
   # Kubernetes resource limits
   resources:
     limits:
       memory: "4Gi"
       cpu: "2000m"
     requests:
       memory: "2Gi"
       cpu: "1000m"
   ```

2. **Memory Management**
   ```yaml
   # JVM heap size configuration
   env:
     - name: JVM_HEAP_SIZE
       value: "3g"
     - name: GC_OPTS
       value: "-XX:+UseG1GC -XX:MaxGCPauseMillis=200"
   ```

3. **Data Retention Policies**
   ```yaml
   # Configure retention periods
   namespaceDefaults:
     retention: "7d"              # Reduce retention period
     
   archival:
     history:
       state: "enabled"           # Enable archival
       enableRead: true
   ```

## Database Issues

### Connection Pool Exhaustion

**Symptoms:**
- "Too many connections" errors
- Connection timeouts
- Database unavailable errors

**Diagnosis:**
```sql
-- Check active connections
SELECT count(*) FROM pg_stat_activity WHERE state = 'active';

-- Check connection limits
SHOW max_connections;

-- Monitor connection usage
SELECT datname, count(*) FROM pg_stat_activity GROUP BY datname;
```

**Solutions:**

1. **Tune Connection Pool Settings**
   ```yaml
   persistence:
     datastores:
       default:
         sql:
           maxConns: 20           # Reduce if too high
           maxIdleConns: 10       # Maintain idle connections
           maxConnLifetime: "1h"  # Recycle connections
   ```

2. **Database Configuration**
   ```postgresql
   # postgresql.conf
   max_connections = 200
   shared_buffers = 256MB
   effective_cache_size = 1GB
   ```

### Slow Queries

**Symptoms:**
- Database performance issues
- Query timeouts
- High database load

**Diagnosis:**
```sql
-- Enable query logging
SET log_statement = 'all';
SET log_min_duration_statement = 1000;  -- Log queries > 1s

-- Check slow queries
SELECT query, mean_time, calls, total_time 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;

-- Check table sizes
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) 
FROM pg_tables 
WHERE schemaname = 'temporal';
```

**Solutions:**

1. **Add Database Indexes**
   ```sql
   -- Common indexes for Temporal
   CREATE INDEX CONCURRENTLY idx_executions_namespace_workflow_id 
   ON executions(namespace_id, workflow_id);
   
   CREATE INDEX CONCURRENTLY idx_executions_state 
   ON executions(namespace_id, state);
   
   CREATE INDEX CONCURRENTLY idx_history_events_workflow_id 
   ON history_events(namespace_id, workflow_id, run_id);
   ```

2. **Database Maintenance**
   ```sql
   -- Update statistics
   ANALYZE;
   
   -- Vacuum tables
   VACUUM ANALYZE executions;
   VACUUM ANALYZE history_events;
   
   -- Reindex if needed
   REINDEX TABLE executions;
   ```

## Security Issues

### TLS Certificate Problems

**Symptoms:**
- Certificate verification failures
- Expired certificate errors
- Certificate chain issues

**Diagnosis:**
```bash
# Check certificate validity
openssl x509 -in client.crt -noout -dates

# Verify certificate chain
openssl verify -CAfile ca.crt client.crt

# Test TLS connection
openssl s_client -connect temporal.company.com:7233 -cert client.crt -key client.key
```

**Solutions:**

1. **Certificate Renewal**
   ```bash
   # Generate new certificate
   openssl req -new -key client.key -out client.csr
   
   # Sign with CA
   openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -out client.crt -days 365
   
   # Update configuration
   temporal config set tls.cert-path /path/to/new/client.crt
   ```

2. **Certificate Chain Issues**
   ```bash
   # Create proper certificate chain
   cat client.crt intermediate.crt > client-chain.crt
   
   # Use chain certificate
   temporal config set tls.cert-path /path/to/client-chain.crt
   ```

### Authentication Issues

**Symptoms:**
- Authentication failures
- Permission denied errors
- Token validation failures

**Diagnosis:**
```bash
# Test without authentication
temporal --address temporal.company.com:7233 --disable-tls cluster health

# Validate JWT token
jwt-cli decode $JWT_TOKEN

# Check RBAC configuration
temporal operator cluster describe
```

**Solutions:**

1. **Fix JWT Configuration**
   ```bash
   # Ensure JWT is properly formatted
   export JWT_TOKEN=$(jwt-cli encode \
     --iss "https://auth.company.com" \
     --sub "user@company.com" \
     --aud "temporal.company.com" \
     --exp $(date -d "+1 hour" +%s) \
     --secret "your-secret")
   
   temporal --headers "Authorization=Bearer $JWT_TOKEN" namespace list
   ```

2. **Configure RBAC Properly**
   ```yaml
   authorization:
     rbac:
       enabled: true
       policies:
         - role: "developer"
           permissions:
             - "temporal:workflow:start"
             - "temporal:workflow:read"
           resources:
             - "namespace:development"
   ```

## Monitoring and Observability

### Missing Metrics

**Symptoms:**
- No metrics being exported
- Missing dashboards data
- Prometheus scraping failures

**Diagnosis:**
```bash
# Check metrics endpoint
curl http://temporal-frontend:9090/metrics

# Test Prometheus scraping
curl http://prometheus:9090/api/v1/query?query=temporal_request_latency

# Check service configuration
kubectl describe configmap temporal-config -n temporal-system
```

**Solutions:**

1. **Enable Metrics Export**
   ```yaml
   global:
     metrics:
       prometheus:
         timerType: "histogram"
         listenAddress: "0.0.0.0:9090"
   ```

2. **Configure Prometheus Scraping**
   ```yaml
   # prometheus.yml
   scrape_configs:
     - job_name: 'temporal'
       static_configs:
         - targets: ['temporal-frontend:9090']
       metrics_path: /metrics
       scrape_interval: 30s
   ```

### Log Analysis Issues

**Symptoms:**
- Missing log entries
- Log parsing failures
- Insufficient log details

**Solutions:**

1. **Configure Structured Logging**
   ```yaml
   log:
     stdout: true
     level: "info"
     format: "json"
   ```

2. **Log Aggregation Setup**
   ```yaml
   # Fluentd configuration
   <source>
     @type tail
     path /var/log/temporal/*.log
     pos_file /var/log/fluentd/temporal.log.pos
     tag temporal.*
     format json
   </source>
   ```

## Common Error Messages

### "Workflow execution already started"

**Error:** `WorkflowExecutionAlreadyStartedError`

**Cause:** Attempting to start a workflow with an existing workflow ID

**Solution:**
```bash
# Use unique workflow ID
temporal workflow start \
  --workflow-id "unique-id-$(date +%s)" \
  --workflow-type MyWorkflow \
  --task-queue my-queue

# Or allow duplicate failed executions
temporal workflow start \
  --workflow-id my-workflow \
  --workflow-id-reuse-policy AllowDuplicateFailedOnly \
  --workflow-type MyWorkflow \
  --task-queue my-queue
```

### "Task queue not found"

**Error:** `BadRequestError: Task queue not found`

**Cause:** No workers polling the specified task queue

**Solution:**
```bash
# Start a worker for the task queue
temporal worker start \
  --task-queue my-queue \
  --workflow-type MyWorkflow \
  --activity-type MyActivity
```

### "Deadline exceeded"

**Error:** `DeadlineExceeded: context deadline exceeded`

**Cause:** Operation timeout, network issues, or server overload

**Solution:**
```bash
# Increase timeout
temporal --timeout 60s workflow describe --workflow-id my-workflow

# Check network connectivity
telnet temporal.company.com 7233

# Check server health
temporal cluster health
```

### "Permission denied"

**Error:** `PermissionDenied: access denied`

**Cause:** Insufficient permissions or authentication issues

**Solution:**
```bash
# Check authentication
temporal --headers "Authorization=Bearer $JWT_TOKEN" namespace list

# Verify permissions
temporal operator cluster describe | grep -i auth
```

## Debugging Tools

### Enable Debug Logging

```bash
# Enable debug logging for CLI
export TEMPORAL_CLI_LOG_LEVEL=debug
temporal workflow describe --workflow-id my-workflow

# Enable debug logging for services
kubectl set env deployment/temporal-frontend LOG_LEVEL=debug -n temporal-system
```

### Use Development Tools

```bash
# Start development server with debug
temporal server start-dev --log-level debug --ui-port 8080

# Enable pprof for Go workers
go tool pprof http://worker:6060/debug/pprof/profile
```

### Network Debugging

```bash
# Capture network traffic
tcpdump -i any -w temporal.pcap port 7233

# Analyze with wireshark
wireshark temporal.pcap

# Test gRPC connectivity
grpcurl -plaintext temporal.company.com:7233 list
```

## Recovery Procedures

### Workflow Recovery

```bash
# Reset workflow to specific event
temporal workflow reset \
  --workflow-id stuck-workflow \
  --event-id 42 \
  --reason "Recovery from corrupted state"

# Reset to last workflow task
temporal workflow reset \
  --workflow-id stuck-workflow \
  --type LastWorkflowTask \
  --reason "Retry with fixed worker"
```

### Database Recovery

```sql
-- Backup before recovery
pg_dump temporal > temporal_backup.sql

-- Repair corrupted data
UPDATE executions SET state = 1 WHERE state IS NULL;

-- Rebuild indexes
REINDEX DATABASE temporal;
```

### Service Recovery

```bash
# Restart specific service
kubectl rollout restart deployment/temporal-history -n temporal-system

# Drain and restart nodes
kubectl drain node-name --ignore-daemonsets
kubectl uncordon node-name

# Scale services
kubectl scale deployment/temporal-frontend --replicas=3 -n temporal-system
```

This comprehensive troubleshooting guide provides systematic approaches to diagnosing and resolving common Temporal.io issues, from connection problems to complex workflow recovery scenarios.
