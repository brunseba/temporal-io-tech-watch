# Configuration Reference

This comprehensive reference guide covers all configuration options for Temporal.io deployments, including server configuration, database settings, security parameters, and operational tuning options.

## Table of Contents

- [Server Configuration](#server-configuration)
- [Database Configuration](#database-configuration)
- [Security Configuration](#security-configuration)
- [Observability Configuration](#observability-configuration)
- [Performance Tuning](#performance-tuning)
- [Environment Variables](#environment-variables)
- [Configuration Examples](#configuration-examples)

## Server Configuration

### Main Configuration File

The main Temporal server configuration file (`config.yaml`) defines all core settings:

```yaml
# config/server-config.yaml
log:
  stdout: true
  level: "info"
  format: "json"

persistence:
  defaultStore: default
  visibilityStore: visibility
  numHistoryShards: 4
  datastores:
    default:
      sql:
        pluginName: "postgres"
        databaseName: "temporal"
        connectAddr: "postgres.temporal.svc.cluster.local:5432"
        connectProtocol: "tcp"
        user: "temporal"
        password: "${TEMPORAL_DB_PASSWORD}"
        maxConns: 20
        maxIdleConns: 20
        maxConnLifetime: "1h"
        connectAttributes:
          sslmode: "require"
    visibility:
      sql:
        pluginName: "postgres"
        databaseName: "temporal_visibility"
        connectAddr: "postgres.temporal.svc.cluster.local:5432"
        connectProtocol: "tcp"
        user: "temporal"
        password: "${TEMPORAL_DB_PASSWORD}"
        maxConns: 10
        maxIdleConns: 10
        maxConnLifetime: "1h"
        connectAttributes:
          sslmode: "require"

global:
  membership:
    maxJoinDuration: 30s
    broadcastAddress: "0.0.0.0"
  pprof:
    port: 7936
  metrics:
    prometheus:
      timerType: "histogram"
      listenAddress: "0.0.0.0:9090"

services:
  frontend:
    rpc:
      grpcPort: 7233
      membershipPort: 6933
      bindOnLocalHost: false
    metrics:
      prometheus:
        handlerPath: "/metrics"
        listenAddress: "0.0.0.0:9090"

  matching:
    rpc:
      grpcPort: 7235
      membershipPort: 6935
      bindOnLocalHost: false

  history:
    rpc:
      grpcPort: 7234
      membershipPort: 6934
      bindOnLocalHost: false

  worker:
    rpc:
      grpcPort: 7239
      membershipPort: 6939
      bindOnLocalHost: false

clusterMetadata:
  enableGlobalNamespace: false
  failoverVersionIncrement: 10
  masterClusterName: "active"
  currentClusterName: "active"
  clusterInformation:
    active:
      enabled: true
      initialFailoverVersion: 1
      rpcName: "frontend"
      rpcAddress: "127.0.0.1:7233"

dcRedirectionPolicy:
  policy: "noop"

archival:
  history:
    state: "enabled"
    enableRead: true
    provider:
      filestore:
        fileMode: "0666"
        dirMode: "0766"
      gstorage:
        credentialsPath: "/tmp/gcloud/keyfile.json"
        workflowExecutionRetentionPeriod: "30d"
  visibility:
    state: "enabled"
    enableRead: true
    provider:
      filestore:
        fileMode: "0666"
        dirMode: "0766"

publicClient:
  hostPort: "temporal-frontend:7233"

dynamicConfigClient:
  filepath: "/etc/temporal/dynamicconfig/production.yaml"
  pollInterval: "10s"
```

### Service-Specific Configuration

#### Frontend Service Configuration

```yaml
# config/frontend-config.yaml
frontend:
  # RPC Configuration
  rpc:
    grpcPort: 7233
    membershipPort: 6933
    bindOnLocalHost: false
    bindOnIP: "0.0.0.0"
    disableLoopbackIP: false

  # Rate Limiting
  rps:
    maxDomainVisibilityListSize: 100
    maxDomainVisibilityReadQPS: 400
    maxDomainVisibilityWriteQPS: 300
    maxIDLengthLimit: 1000

  # Namespace Configuration
  namespaceDefaults:
    retention: "72h"
    emitMetrics: true
    archival:
      history:
        state: "disabled"
      visibility:
        state: "disabled"

  # Security Configuration
  authorization:
    jwtKeyProvider:
      keySourceURIs:
        - "file:///etc/temporal/auth/public.key"
      refreshInterval: "1h"
    permissionsClaimName: "permissions"
    authorizer: "default"

  # History Service Client Configuration
  historyClient:
    numberOfShards: 4
    rpcTimeout: "30s"
    maxRetryPolicy:
      initialInterval: "1s"
      maximumInterval: "30s"
      expirationInterval: "5m"
      maximumAttempts: 5

  # Search Attributes
  searchAttributes:
    forceSearchAttributesCacheRefreshOnRead: false
    cacheRefreshInterval: "1m"
```

#### History Service Configuration

```yaml
# config/history-config.yaml
history:
  # RPC Configuration
  rpc:
    grpcPort: 7234
    membershipPort: 6934
    bindOnLocalHost: false

  # Persistence Configuration
  historyMgrNumConns: 50
  executionMgrNumConns: 50

  # Task Processing
  taskProcessRPS: 1000
  taskSchedulerType: "weighted-round-robin"
  taskSchedulerWorkerCount: 200
  taskSchedulerShardWorkerCount: 0
  taskSchedulerQueueSize: 10000
  taskSchedulerDispatcherCount: 1

  # Replication
  replicationTaskProcessorStartWait: "5s"
  replicationTaskProcessorType: "task-processor"
  replicationTaskProcessorShardWorkerCount: 2

  # Transfer Queue
  transferTaskWorkerCount: 100
  transferTaskBatchSize: 100
  transferProcessorStartDelay: "5s"
  transferProcessorMaxPollRPS: 1000
  transferProcessorMaxPollInterval: "1m"
  transferProcessorMaxPollIntervalJitterCoefficient: 0.15
  transferProcessorUpdateAckInterval: "30s"

  # Timer Queue
  timerTaskWorkerCount: 100
  timerTaskBatchSize: 100
  timerProcessorStartDelay: "5s"
  timerProcessorMaxPollRPS: 1000
  timerProcessorMaxPollInterval: "5m"
  timerProcessorMaxPollIntervalJitterCoefficient: 0.15
  timerProcessorUpdateAckInterval: "30s"

  # Visibility Queue
  visibilityTaskWorkerCount: 100
  visibilityTaskBatchSize: 100
  visibilityProcessorStartDelay: "5s"
  visibilityProcessorMaxPollRPS: 1000
  visibilityProcessorMaxPollInterval: "1m"
  visibilityProcessorMaxPollIntervalJitterCoefficient: 0.15
  visibilityProcessorUpdateAckInterval: "30s"

  # Workflow Execution
  maxAutoResetPoints: 20
  defaultWorkflowExecutionTimeout: "72h"
  defaultWorkflowRunTimeout: "72h"
  defaultWorkflowTaskTimeout: "10s"

  # Shard Controller
  shardController:
    membershipUpdateListener:
      enabled: true
      type: "noop"
    shardGracefulCloseTimeout: "5m"
```

#### Matching Service Configuration

```yaml
# config/matching-config.yaml
matching:
  # RPC Configuration
  rpc:
    grpcPort: 7235
    membershipPort: 6935
    bindOnLocalHost: false

  # Task List Configuration
  numTasklistWritePartitions: 1
  numTasklistReadPartitions: 1
  forwarderMaxOutstandingPolls: 1000
  forwarderMaxOutstandingTasks: 1000
  forwarderMaxRatePerSecond: 10000
  forwarderMaxChildrenPerNode: 20

  # Poller Configuration
  longPollExpirationInterval: "1m"
  maxTasklistIdleTime: "5m"
  outstandingTaskAppendsThreshold: 250
  maxTaskBatchSize: 1000
  getTasksBatchSize: 1000
  updateAckInterval: "1m"
  idleTasklistCheckInterval: "5m"
  maxIdleTasklistAge: "5m"

  # Rate Limiting
  rps: 30000
  domainUserRPS: 300

  # Load Balancing
  loadBalancer:
    mode: "task"
    lookAheadCountPerPartition: 20
    defaultTaskDispatchRPS: 100000.0
    defaultTaskDispatchRPSTTL: "60s"
```

#### Worker Service Configuration

```yaml
# config/worker-config.yaml
worker:
  # RPC Configuration
  rpc:
    grpcPort: 7239
    membershipPort: 6939
    bindOnLocalHost: false

  # Archival Worker
  archiver:
    maxConcurrentActivityExecutionSize: 1000
    maxConcurrentWorkflowTaskExecutionSize: 1000
    maxConcurrentActivityTaskPollers: 20
    maxConcurrentWorkflowTaskPollers: 20

  # Indexer
  indexer:
    maxConcurrentActivityExecutionSize: 1000
    maxConcurrentWorkflowTaskExecutionSize: 1000
    maxConcurrentActivityTaskPollers: 3
    maxConcurrentWorkflowTaskPollers: 3

  # Replicator
  replicator:
    maxConcurrentActivityExecutionSize: 1000
    maxConcurrentWorkflowTaskExecutionSize: 1000
    maxConcurrentActivityTaskPollers: 1
    maxConcurrentWorkflowTaskPollers: 1

  # Scanner
  scanner:
    maxConcurrentActivityExecutionSize: 1000
    maxConcurrentWorkflowTaskExecutionSize: 1000
    maxConcurrentActivityTaskPollers: 1
    maxConcurrentWorkflowTaskPollers: 1
```

## Database Configuration

### PostgreSQL Configuration

```yaml
# config/database/postgres-config.yaml
persistence:
  defaultStore: default
  visibilityStore: visibility
  datastores:
    default:
      sql:
        pluginName: "postgres"
        databaseName: "temporal"
        connectAddr: "postgres.temporal.svc.cluster.local:5432"
        connectProtocol: "tcp"
        user: "temporal"
        password: "${TEMPORAL_DB_PASSWORD}"
        
        # Connection Pool Settings
        maxConns: 50
        maxIdleConns: 25
        maxConnLifetime: "1h"
        maxIdleTime: "15m"
        
        # Connection Attributes
        connectAttributes:
          sslmode: "require"
          sslcert: "/etc/temporal/certs/client.crt"
          sslkey: "/etc/temporal/certs/client.key"
          sslrootcert: "/etc/temporal/certs/ca.crt"
          application_name: "temporal"
          search_path: "temporal"
          
        # Advanced Settings
        taskScanPartitions: 4
        txIsolationLevel: "READ_COMMITTED"
        
    visibility:
      sql:
        pluginName: "postgres"
        databaseName: "temporal_visibility"
        connectAddr: "postgres.temporal.svc.cluster.local:5432"
        connectProtocol: "tcp"
        user: "temporal"
        password: "${TEMPORAL_DB_PASSWORD}"
        maxConns: 20
        maxIdleConns: 10
        maxConnLifetime: "1h"
        connectAttributes:
          sslmode: "require"
          application_name: "temporal-visibility"
```

### Elasticsearch Configuration

```yaml
# config/database/elasticsearch-config.yaml
persistence:
  visibilityStore: es-visibility
  datastores:
    es-visibility:
      elasticsearch:
        version: "v7"
        url:
          scheme: "https"
          host: "elasticsearch.temporal.svc.cluster.local:9200"
        indices:
          visibility: "temporal_visibility_v1_dev"
        username: "temporal"
        password: "${ELASTICSEARCH_PASSWORD}"
        
        # Connection Settings
        maxRetryPolicy:
          initialInterval: "1s"
          maximumInterval: "16s"
          expirationInterval: "5m"
          maximumAttempts: 9
          
        # TLS Configuration
        tls:
          enabled: true
          caFile: "/etc/temporal/certs/elasticsearch-ca.crt"
          certFile: "/etc/temporal/certs/elasticsearch-client.crt"
          keyFile: "/etc/temporal/certs/elasticsearch-client.key"
          serverName: "elasticsearch.temporal.svc.cluster.local"
          
        # Performance Settings
        closeIdleConnectionsInterval: "15s"
        enableSniff: false
        enableHealthcheck: true
        
        # Bulk Operations
        bulkProcessor:
          numWorkers: 1
          bulkActions: 1000
          bulkSize: "2MB"
          flushInterval: "1s"
```

### MySQL Configuration

```yaml
# config/database/mysql-config.yaml
persistence:
  defaultStore: default
  visibilityStore: visibility
  datastores:
    default:
      sql:
        pluginName: "mysql"
        databaseName: "temporal"
        connectAddr: "mysql.temporal.svc.cluster.local:3306"
        connectProtocol: "tcp"
        user: "temporal"
        password: "${TEMPORAL_DB_PASSWORD}"
        maxConns: 50
        maxIdleConns: 25
        maxConnLifetime: "1h"
        connectAttributes:
          tls: "true"
          interpolateParams: "true"
          parseTime: "true"
          
    visibility:
      sql:
        pluginName: "mysql"
        databaseName: "temporal_visibility"
        connectAddr: "mysql.temporal.svc.cluster.local:3306"
        connectProtocol: "tcp"
        user: "temporal"
        password: "${TEMPORAL_DB_PASSWORD}"
        maxConns: 20
        maxIdleConns: 10
        maxConnLifetime: "1h"
        connectAttributes:
          tls: "true"
          interpolateParams: "true"
          parseTime: "true"
```

## Security Configuration

### Authentication Configuration

```yaml
# config/security/auth-config.yaml
global:
  authorization:
    # JWT Configuration
    jwtKeyProvider:
      keySourceURIs:
        - "file:///etc/temporal/auth/public.key"
        - "https://auth.company.com/.well-known/jwks.json"
      refreshInterval: "1h"
    permissionsClaimName: "permissions"
    authorizer: "default"
    
    # Claims Mapping
    claimsMapper:
      roleClaimName: "roles"
      permissionClaimName: "permissions"
      namespaceClaimName: "namespace"

# TLS Configuration
tls:
  # Frontend TLS
  frontend:
    server:
      certFile: "/etc/temporal/certs/server.crt"
      keyFile: "/etc/temporal/certs/server.key"
      clientCaFiles:
        - "/etc/temporal/certs/ca.crt"
      requireClientAuth: false
      
  # Inter-node TLS
  internode:
    server:
      certFile: "/etc/temporal/certs/server.crt"
      keyFile: "/etc/temporal/certs/server.key"
      clientCaFiles:
        - "/etc/temporal/certs/ca.crt"
      requireClientAuth: true
    client:
      certFile: "/etc/temporal/certs/client.crt"
      keyFile: "/etc/temporal/certs/client.key"
      serverCaFiles:
        - "/etc/temporal/certs/ca.crt"
      serverName: "temporal.company.com"
      
  # Database TLS
  database:
    server:
      certFile: "/etc/temporal/certs/db-server.crt"
      keyFile: "/etc/temporal/certs/db-server.key"
      clientCaFiles:
        - "/etc/temporal/certs/ca.crt"
    client:
      certFile: "/etc/temporal/certs/db-client.crt"
      keyFile: "/etc/temporal/certs/db-client.key"
      serverCaFiles:
        - "/etc/temporal/certs/ca.crt"
```

### RBAC Configuration

```yaml
# config/security/rbac-config.yaml
authorization:
  rbac:
    enabled: true
    policies:
      # Admin Policies
      - role: "admin"
        permissions:
          - "temporal:workflow:*"
          - "temporal:activity:*"
          - "temporal:namespace:*"
          - "temporal:cluster:*"
        resources:
          - "*"
        
      # Developer Policies
      - role: "developer"
        permissions:
          - "temporal:workflow:start"
          - "temporal:workflow:signal"
          - "temporal:workflow:query"
          - "temporal:workflow:read"
          - "temporal:activity:execute"
        resources:
          - "namespace:development"
          - "namespace:testing"
          
      # Operator Policies
      - role: "operator"
        permissions:
          - "temporal:workflow:read"
          - "temporal:workflow:list"
          - "temporal:workflow:terminate"
          - "temporal:namespace:read"
          - "temporal:cluster:read"
        resources:
          - "*"
          
      # Read-only Policies
      - role: "viewer"
        permissions:
          - "temporal:workflow:read"
          - "temporal:workflow:list"
          - "temporal:namespace:read"
        resources:
          - "*"

    # Role Bindings
    roleBindings:
      - subject: "user:admin@company.com"
        role: "admin"
      - subject: "group:temporal-developers"
        role: "developer"
      - subject: "group:temporal-operators"
        role: "operator"
      - subject: "group:temporal-viewers"
        role: "viewer"
```

## Observability Configuration

### Logging Configuration

```yaml
# config/observability/logging-config.yaml
log:
  stdout: true
  level: "info"  # debug, info, warn, error
  format: "json"  # json, console
  
  # File Logging
  outputFile: "/var/log/temporal/server.log"
  maxSize: "100MB"
  maxAge: "7d"
  maxBackups: 10
  
  # Structured Logging
  fields:
    service: "temporal"
    version: "${TEMPORAL_VERSION}"
    environment: "${ENVIRONMENT}"
    cluster: "${CLUSTER_NAME}"
    
  # Log Sampling
  sampling:
    initial: 100
    thereafter: 100
```

### Metrics Configuration

```yaml
# config/observability/metrics-config.yaml
global:
  metrics:
    # Prometheus Configuration
    prometheus:
      timerType: "histogram"  # histogram, summary
      listenAddress: "0.0.0.0:9090"
      handlerPath: "/metrics"
      
      # Histogram Buckets
      defaultHistogramBuckets:
        - 0.0005
        - 0.001
        - 0.0025
        - 0.005
        - 0.01
        - 0.025
        - 0.05
        - 0.1
        - 0.25
        - 0.5
        - 1.0
        - 2.5
        - 5.0
        - 10.0
        - 25.0
        - 50.0
        - 100.0
        
    # StatsD Configuration (alternative)
    statsd:
      hostPort: "statsd.monitoring.svc.cluster.local:8125"
      prefix: "temporal"
      flushInterval: "10s"
      flushBytes: 512
      
    # M3 Configuration (alternative)
    m3:
      hostPort: "m3coordinator.monitoring.svc.cluster.local:7201"
      service: "temporal"
      env: "production"
      
  # Service-specific Metrics
  services:
    frontend:
      metrics:
        prometheus:
          handlerPath: "/metrics"
          listenAddress: "0.0.0.0:9090"
    history:
      metrics:
        prometheus:
          handlerPath: "/metrics"
          listenAddress: "0.0.0.0:9091"
    matching:
      metrics:
        prometheus:
          handlerPath: "/metrics"
          listenAddress: "0.0.0.0:9092"
    worker:
      metrics:
        prometheus:
          handlerPath: "/metrics"
          listenAddress: "0.0.0.0:9093"
```

### Tracing Configuration

```yaml
# config/observability/tracing-config.yaml
global:
  # OpenTelemetry Configuration
  opentelemetry:
    otel:
      # OTLP Exporter
      exporter:
        otlp:
          endpoint: "http://jaeger-collector.monitoring.svc.cluster.local:14268/api/traces"
          headers:
            Authorization: "Bearer ${TRACING_TOKEN}"
          compression: "gzip"
          timeout: "10s"
          
      # Trace Sampling
      traceSampler:
        type: "probabilistic"
        param: 0.1  # 10% sampling rate
        
      # Resource Attributes
      resource:
        attributes:
          service.name: "temporal"
          service.version: "${TEMPORAL_VERSION}"
          deployment.environment: "${ENVIRONMENT}"
          
    # Legacy Jaeger Configuration
    jaeger:
      agent:
        hostPort: "jaeger-agent.monitoring.svc.cluster.local:6831"
      collector:
        endpoint: "http://jaeger-collector.monitoring.svc.cluster.local:14268/api/traces"
      sampler:
        type: "probabilistic"
        param: 0.1
      reporter:
        logSpans: false
        maxQueueSize: 1000
        flushInterval: "1s"
```

## Performance Tuning

### Resource Limits Configuration

```yaml
# config/performance/resource-limits.yaml
# Frontend Service Limits
frontend:
  rpc:
    # Connection Limits
    maxConnectionAge: "5m"
    maxConnectionAgeGrace: "70s"
    maxConnectionIdle: "1m"
    keepAliveTime: "30s"
    keepAliveTimeout: "5s"
    
    # Request Limits
    maxReceiveMessageSize: "4MB"
    maxSendMessageSize: "4MB"
    
  # Rate Limiting
  rps:
    # Per-namespace Rate Limits
    namespaceMaxBurstRPS: 10000
    namespaceCountLimitError: 10000
    namespaceCountLimitWarn: 1000
    
    # Global Rate Limits
    globalNamespaceVisibilityMaxBurstRPS: 400
    globalNamespaceVisibilityMaxQPS: 300
    
# History Service Limits
history:
  # Task Processing Limits
  taskProcessRPS: 1000
  persistenceMaxQPS: 3000
  persistenceGlobalMaxQPS: 0
  
  # Workflow Execution Limits
  workflowExecutionMaxSize: "50MB"
  historyMaxPageSize: 1000
  defaultTransactionSizeLimit: "4MB"
  
  # Cache Settings
  historyCache:
    maxSize: 512
    ttl: "1h"
  eventsCache:
    maxSize: 512
    ttl: "1h"
    
# Matching Service Limits
matching:
  # Task List Limits
  taskListLoadBalancerHostRPS: 10000
  taskListLoadBalancerType: "default"
  
  # Polling Limits
  longPollExpirationInterval: "1m"
  maxTaskDeleteBatchSize: 100
  getAllTaskMaxPageSize: 1000
  
# Worker Service Limits
worker:
  # Archival Limits
  archiverMaxConcurrentActivityExecutionSize: 1000
  archiverMaxConcurrentWorkflowTaskExecutionSize: 1000
  
  # Indexer Limits
  indexerMaxConcurrentActivityExecutionSize: 1000
  indexerMaxConcurrentWorkflowTaskExecutionSize: 1000
```

### Memory and CPU Configuration

```yaml
# config/performance/resource-allocation.yaml
resources:
  # Frontend Service Resources
  frontend:
    limits:
      memory: "2Gi"
      cpu: "1000m"
    requests:
      memory: "1Gi"
      cpu: "500m"
    jvm:
      heapSize: "1536m"
      
  # History Service Resources
  history:
    limits:
      memory: "4Gi"
      cpu: "2000m"
    requests:
      memory: "2Gi"
      cpu: "1000m"
    jvm:
      heapSize: "3072m"
      
  # Matching Service Resources
  matching:
    limits:
      memory: "2Gi"
      cpu: "1000m"
    requests:
      memory: "1Gi"
      cpu: "500m"
    jvm:
      heapSize: "1536m"
      
  # Worker Service Resources
  worker:
    limits:
      memory: "2Gi"
      cpu: "1000m"
    requests:
      memory: "1Gi"
      cpu: "500m"
    jvm:
      heapSize: "1536m"
```

## Environment Variables

### Core Environment Variables

```bash
# Environment Variables Reference

# Database Configuration
TEMPORAL_DB_PASSWORD=<database_password>
TEMPORAL_VISIBILITY_DB_PASSWORD=<visibility_database_password>
ELASTICSEARCH_PASSWORD=<elasticsearch_password>

# Service Configuration
TEMPORAL_FRONTEND_PORT=7233
TEMPORAL_HISTORY_PORT=7234
TEMPORAL_MATCHING_PORT=7235
TEMPORAL_WORKER_PORT=7239

# Cluster Configuration
TEMPORAL_CLUSTER_NAME=temporal-cluster
TEMPORAL_BROADCAST_ADDRESS=0.0.0.0
NUM_HISTORY_SHARDS=4

# Security Configuration
TEMPORAL_TLS_ENABLED=true
TEMPORAL_AUTH_ENABLED=true
TEMPORAL_JWT_KEY_ID=temporal-jwt-key

# Logging Configuration
TEMPORAL_LOG_LEVEL=info
TEMPORAL_LOG_FORMAT=json

# Metrics Configuration
TEMPORAL_METRICS_PORT=9090
TEMPORAL_PROMETHEUS_ENABLED=true

# Development/Debug Settings
TEMPORAL_DEBUG_MODE=false
TEMPORAL_PROFILE_PORT=7936
TEMPORAL_SQL_TX_ISOLATION_COMPATIBLE=false

# Advanced Configuration
TEMPORAL_CONFIG_DIR=/etc/temporal/config
TEMPORAL_DYNAMIC_CONFIG_FILE_PATH=/etc/temporal/dynamicconfig/production.yaml
TEMPORAL_PLUGINS_DIR=/etc/temporal/plugins

# Kubernetes Specific
POD_NAME=${HOSTNAME}
POD_NAMESPACE=temporal
POD_IP=${POD_IP}
```

### Service-Specific Environment Variables

```bash
# Frontend Service Environment Variables
FRONTEND_GRPC_PORT=7233
FRONTEND_MEMBERSHIP_PORT=6933
FRONTEND_HTTP_PORT=7243
FRONTEND_METRICS_PORT=9090

# History Service Environment Variables
HISTORY_GRPC_PORT=7234
HISTORY_MEMBERSHIP_PORT=6934
HISTORY_METRICS_PORT=9091

# Matching Service Environment Variables
MATCHING_GRPC_PORT=7235
MATCHING_MEMBERSHIP_PORT=6935
MATCHING_METRICS_PORT=9092

# Worker Service Environment Variables
WORKER_GRPC_PORT=7239
WORKER_MEMBERSHIP_PORT=6939
WORKER_METRICS_PORT=9093

# Database Connection Variables
DB_HOST=postgres.temporal.svc.cluster.local
DB_PORT=5432
DB_NAME=temporal
DB_USER=temporal
DB_SSL_MODE=require

VISIBILITY_DB_HOST=postgres.temporal.svc.cluster.local
VISIBILITY_DB_PORT=5432
VISIBILITY_DB_NAME=temporal_visibility
VISIBILITY_DB_USER=temporal

# Elasticsearch Variables
ELASTICSEARCH_HOSTS=elasticsearch.temporal.svc.cluster.local:9200
ELASTICSEARCH_SCHEME=https
ELASTICSEARCH_USER=temporal
ELASTICSEARCH_INDEX=temporal_visibility_v1

# Security Variables
TLS_CERT_FILE=/etc/temporal/certs/server.crt
TLS_KEY_FILE=/etc/temporal/certs/server.key
TLS_CA_FILE=/etc/temporal/certs/ca.crt
```

## Configuration Examples

### Development Configuration

```yaml
# config/examples/development.yaml
log:
  stdout: true
  level: "debug"
  format: "console"

persistence:
  defaultStore: default
  visibilityStore: visibility
  numHistoryShards: 4
  datastores:
    default:
      sql:
        pluginName: "postgres"
        databaseName: "temporal_dev"
        connectAddr: "localhost:5432"
        connectProtocol: "tcp"
        user: "temporal"
        password: "temporal"
        maxConns: 10
        maxIdleConns: 5
        connectAttributes:
          sslmode: "disable"

global:
  membership:
    maxJoinDuration: 30s
    broadcastAddress: "127.0.0.1"
  pprof:
    port: 7936
  metrics:
    prometheus:
      timerType: "histogram"
      listenAddress: "127.0.0.1:9090"

services:
  frontend:
    rpc:
      grpcPort: 7233
      membershipPort: 6933
      bindOnLocalHost: true

clusterMetadata:
  enableGlobalNamespace: false
  failoverVersionIncrement: 10
  masterClusterName: "active"
  currentClusterName: "active"
  clusterInformation:
    active:
      enabled: true
      initialFailoverVersion: 1
      rpcName: "frontend"
      rpcAddress: "127.0.0.1:7233"

dynamicConfigClient:
  filepath: "/etc/temporal/dynamicconfig/development.yaml"
  pollInterval: "10s"
```

### Production Configuration

```yaml
# config/examples/production.yaml
log:
  stdout: true
  level: "info"
  format: "json"

persistence:
  defaultStore: default
  visibilityStore: es-visibility
  numHistoryShards: 16
  datastores:
    default:
      sql:
        pluginName: "postgres"
        databaseName: "temporal"
        connectAddr: "postgres-primary.temporal.svc.cluster.local:5432"
        connectProtocol: "tcp"
        user: "temporal"
        password: "${TEMPORAL_DB_PASSWORD}"
        maxConns: 50
        maxIdleConns: 25
        maxConnLifetime: "1h"
        connectAttributes:
          sslmode: "require"
          application_name: "temporal"
    es-visibility:
      elasticsearch:
        version: "v7"
        url:
          scheme: "https"
          host: "elasticsearch.temporal.svc.cluster.local:9200"
        indices:
          visibility: "temporal_visibility_v1_prod"
        username: "temporal"
        password: "${ELASTICSEARCH_PASSWORD}"
        tls:
          enabled: true
          caFile: "/etc/temporal/certs/es-ca.crt"

global:
  membership:
    maxJoinDuration: 30s
    broadcastAddress: "0.0.0.0"
  metrics:
    prometheus:
      timerType: "histogram"
      listenAddress: "0.0.0.0:9090"
  authorization:
    jwtKeyProvider:
      keySourceURIs:
        - "https://auth.company.com/.well-known/jwks.json"
      refreshInterval: "1h"
    permissionsClaimName: "permissions"
    authorizer: "default"

tls:
  frontend:
    server:
      certFile: "/etc/temporal/certs/server.crt"
      keyFile: "/etc/temporal/certs/server.key"
      clientCaFiles:
        - "/etc/temporal/certs/ca.crt"
  internode:
    server:
      certFile: "/etc/temporal/certs/server.crt"
      keyFile: "/etc/temporal/certs/server.key"
      clientCaFiles:
        - "/etc/temporal/certs/ca.crt"
      requireClientAuth: true
    client:
      certFile: "/etc/temporal/certs/client.crt"
      keyFile: "/etc/temporal/certs/client.key"
      serverCaFiles:
        - "/etc/temporal/certs/ca.crt"

services:
  frontend:
    rpc:
      grpcPort: 7233
      membershipPort: 6933
      bindOnLocalHost: false
    metrics:
      prometheus:
        handlerPath: "/metrics"
        listenAddress: "0.0.0.0:9090"

archival:
  history:
    state: "enabled"
    enableRead: true
    provider:
      s3store:
        region: "us-west-2"
        bucket: "temporal-archival-prod"
        keyPrefix: "temporal_archival/development"
  visibility:
    state: "enabled"
    enableRead: true
    provider:
      s3store:
        region: "us-west-2"
        bucket: "temporal-archival-prod"
        keyPrefix: "temporal_visibility_archival/development"

clusterMetadata:
  enableGlobalNamespace: true
  failoverVersionIncrement: 10
  masterClusterName: "active"
  currentClusterName: "active"
  clusterInformation:
    active:
      enabled: true
      initialFailoverVersion: 1
      rpcName: "frontend"
      rpcAddress: "temporal-frontend.temporal.svc.cluster.local:7233"

dynamicConfigClient:
  filepath: "/etc/temporal/dynamicconfig/production.yaml"
  pollInterval: "60s"
```

### Multi-Cluster Configuration

```yaml
# config/examples/multi-cluster.yaml
clusterMetadata:
  enableGlobalNamespace: true
  failoverVersionIncrement: 10
  masterClusterName: "cluster1"
  currentClusterName: "cluster1"
  clusterInformation:
    cluster1:
      enabled: true
      initialFailoverVersion: 1
      rpcName: "frontend"
      rpcAddress: "temporal-frontend-cluster1.temporal.svc.cluster.local:7233"
    cluster2:
      enabled: true
      initialFailoverVersion: 2
      rpcName: "frontend"
      rpcAddress: "temporal-frontend-cluster2.temporal.svc.cluster.local:7233"

dcRedirectionPolicy:
  policy: "selected-apis-forwarding"
  toDC: "cluster2"

# Replication Configuration
replication:
  replicationTaskFetcherParallelism: 4
  replicationTaskFetcherAggregationInterval: "2s"
  replicationTaskFetcherTimerJitterCoefficient: 0.15
  replicationTaskProcessorErrorRetryMaxAttempts: 10
  replicationTaskProcessorErrorRetryWait: "1s"
  replicationTaskProcessorStartWait: "5s"
  replicationTaskProcessorHostQPS: 1500
  replicationTaskProcessorShardQPS: 100
```

This configuration reference provides comprehensive coverage of all Temporal.io configuration options, from basic development setups to complex production deployments with advanced security, observability, and performance tuning capabilities.
