# Database Setup

This guide provides comprehensive database setup and configuration for Temporal.io enterprise deployment, covering PostgreSQL installation, configuration, optimization, backup, and maintenance procedures.

## Overview

The database setup includes:
- PostgreSQL cluster deployment and configuration
- High availability setup with replication
- Performance tuning and optimization
- Backup and recovery procedures
- Monitoring and maintenance
- Migration and schema management

## PostgreSQL Deployment

### High Availability PostgreSQL Cluster

#### PostgreSQL Helm Chart Configuration
```yaml
# helm/values/database/postgresql-ha.yaml
postgresql:
  image:
    tag: "15.4"
  
  # Authentication
  auth:
    postgresPassword: ""  # Set via secret
    username: "temporal"
    password: ""  # Set via secret
    database: "temporal"
    existingSecret: "postgresql-credentials"
    secretKeys:
      adminPasswordKey: "postgres-password"
      userPasswordKey: "password"
  
  # Architecture
  architecture: replication
  
  # Primary configuration
  primary:
    name: primary
    persistence:
      enabled: true
      storageClass: "gp3"
      size: 100Gi
    
    resources:
      limits:
        memory: 4Gi
        cpu: 2000m
      requests:
        memory: 2Gi
        cpu: 1000m
    
    configuration: |
      # PostgreSQL configuration
      max_connections = 200
      shared_buffers = 1GB
      effective_cache_size = 3GB
      maintenance_work_mem = 256MB
      checkpoint_completion_target = 0.9
      wal_buffers = 16MB
      default_statistics_target = 100
      random_page_cost = 1.1
      effective_io_concurrency = 200
      work_mem = 4MB
      min_wal_size = 1GB
      max_wal_size = 4GB
      
      # Logging
      log_destination = 'stderr'
      logging_collector = on
      log_directory = 'log'
      log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
      log_rotation_age = 1d
      log_rotation_size = 100MB
      log_min_duration_statement = 1000
      log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
      log_checkpoints = on
      log_connections = on
      log_disconnections = on
      log_lock_waits = on
      log_temp_files = 10MB
      
      # SSL
      ssl = on
      ssl_cert_file = '/etc/ssl/certs/tls.crt'
      ssl_key_file = '/etc/ssl/private/tls.key'
      ssl_ca_file = '/etc/ssl/certs/ca.crt'
    
    initdb:
      scripts:
        01_temporal_setup.sql: |
          -- Create temporal databases
          CREATE DATABASE temporal;
          CREATE DATABASE temporal_visibility;
          
          -- Create temporal user with proper permissions
          CREATE USER temporal WITH PASSWORD '${TEMPORAL_PASSWORD}';
          GRANT ALL PRIVILEGES ON DATABASE temporal TO temporal;
          GRANT ALL PRIVILEGES ON DATABASE temporal_visibility TO temporal;
          
          -- Create read-only user for monitoring
          CREATE USER temporal_monitor WITH PASSWORD '${MONITOR_PASSWORD}';
          GRANT CONNECT ON DATABASE temporal TO temporal_monitor;
          GRANT CONNECT ON DATABASE temporal_visibility TO temporal_monitor;
          GRANT USAGE ON SCHEMA public TO temporal_monitor;
          GRANT SELECT ON ALL TABLES IN SCHEMA public TO temporal_monitor;
          ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO temporal_monitor;
  
  # Read replica configuration
  readReplicas:
    replicaCount: 2
    
    persistence:
      enabled: true
      storageClass: "gp3"
      size: 100Gi
    
    resources:
      limits:
        memory: 2Gi
        cpu: 1000m
      requests:
        memory: 1Gi
        cpu: 500m

  # Backup configuration
  backup:
    enabled: true
    cronjob:
      schedule: "0 2 * * *"  # Daily at 2 AM
      restartPolicy: OnFailure
      storage:
        storageClass: "gp3"
        size: 500Gi
    
    retention:
      days: 30
    
    s3:
      enabled: true
      bucket: "temporal-backups"
      region: "us-west-2"
      endpoint: ""
      accessKey: ""  # Set via secret
      secretKey: ""  # Set via secret

  # Metrics
  metrics:
    enabled: true
    image:
      tag: "0.11.1"
    
    serviceMonitor:
      enabled: true
      namespace: "monitoring"
      interval: "30s"
    
    resources:
      limits:
        memory: 256Mi
        cpu: 250m
      requests:
        memory: 128Mi
        cpu: 100m

  # Network policy
  networkPolicy:
    enabled: true
    allowExternal: false
    explicitNamespacesSelector:
      matchLabels:
        name: "temporal-system"
```

### Database Secrets Management

#### PostgreSQL Credentials Secret
```yaml
# k8s/database/secrets/postgresql-credentials.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: postgresql-credentials
  namespace: temporal-system
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: postgresql-credentials
    creationPolicy: Owner
    template:
      type: Opaque
      data:
        postgres-password: "{{ .postgres_password }}"
        password: "{{ .temporal_password }}"
        monitor-password: "{{ .monitor_password }}"
        replication-password: "{{ .replication_password }}"
  data:
  - secretKey: postgres_password
    remoteRef:
      key: temporal/database
      property: postgres_password
  - secretKey: temporal_password
    remoteRef:
      key: temporal/database
      property: temporal_password
  - secretKey: monitor_password
    remoteRef:
      key: temporal/database
      property: monitor_password
  - secretKey: replication_password
    remoteRef:
      key: temporal/database
      property: replication_password
```

### Database Schema Management

#### Temporal Schema Setup Job
```yaml
# k8s/database/jobs/schema-setup.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: temporal-schema-setup
  namespace: temporal-system
  annotations:
    "helm.sh/hook": post-install,post-upgrade
    "helm.sh/hook-weight": "1"
    "helm.sh/hook-delete-policy": before-hook-creation
spec:
  template:
    metadata:
      name: temporal-schema-setup
    spec:
      restartPolicy: OnFailure
      containers:
      - name: temporal-admin-tools
        image: temporalio/admin-tools:1.20.0
        command:
        - /bin/bash
        - -c
        - |
          set -euo pipefail
          
          echo "Setting up Temporal database schema..."
          
          # Wait for database to be ready
          until pg_isready -h $DB_HOST -p $DB_PORT -U $DB_USER; do
            echo "Waiting for database to be ready..."
            sleep 5
          done
          
          # Setup default database
          temporal-sql-tool \
            --plugin postgres \
            --ep $DB_HOST \
            --port $DB_PORT \
            --user $DB_USER \
            --password $DB_PASSWORD \
            --database $DB_NAME \
            setup-schema -v 0.0
          
          temporal-sql-tool \
            --plugin postgres \
            --ep $DB_HOST \
            --port $DB_PORT \
            --user $DB_USER \
            --password $DB_PASSWORD \
            --database $DB_NAME \
            update-schema -d /etc/temporal/schema/postgresql/v96
          
          # Setup visibility database
          temporal-sql-tool \
            --plugin postgres \
            --ep $DB_HOST \
            --port $DB_PORT \
            --user $DB_USER \
            --password $DB_PASSWORD \
            --database $DB_VISIBILITY_NAME \
            setup-schema -v 0.0
          
          temporal-sql-tool \
            --plugin postgres \
            --ep $DB_HOST \
            --port $DB_PORT \
            --user $DB_USER \
            --password $DB_PASSWORD \
            --database $DB_VISIBILITY_NAME \
            update-schema -d /etc/temporal/schema/postgresql/visibility/versioned
          
          echo "Temporal database schema setup completed successfully"
        
        env:
        - name: DB_HOST
          value: "postgresql-primary"
        - name: DB_PORT
          value: "5432"
        - name: DB_USER
          value: "temporal"
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgresql-credentials
              key: password
        - name: DB_NAME
          value: "temporal"
        - name: DB_VISIBILITY_NAME
          value: "temporal_visibility"
        
        resources:
          limits:
            memory: 512Mi
            cpu: 500m
          requests:
            memory: 256Mi
            cpu: 250m
      
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
```

## Performance Optimization

### PostgreSQL Tuning Configuration

#### Performance Tuning ConfigMap
```yaml
# k8s/database/config/postgresql-performance.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: postgresql-performance-config
  namespace: temporal-system
data:
  postgresql.conf: |
    # Connection Settings
    max_connections = 200
    superuser_reserved_connections = 3
    
    # Memory Settings
    shared_buffers = 1GB                    # 25% of RAM
    effective_cache_size = 3GB              # 75% of RAM
    maintenance_work_mem = 256MB
    work_mem = 4MB
    
    # Checkpoint Settings
    checkpoint_completion_target = 0.9
    checkpoint_timeout = 10min
    max_wal_size = 4GB
    min_wal_size = 1GB
    wal_buffers = 16MB
    
    # Query Planning
    default_statistics_target = 100
    constraint_exclusion = partition
    cursor_tuple_fraction = 0.1
    
    # Disk I/O Settings
    random_page_cost = 1.1                  # For SSD storage
    effective_io_concurrency = 200
    seq_page_cost = 1
    
    # Background Writer
    bgwriter_delay = 200ms
    bgwriter_lru_maxpages = 100
    bgwriter_lru_multiplier = 2.0
    bgwriter_flush_after = 512kB
    
    # Autovacuum Settings
    autovacuum = on
    autovacuum_max_workers = 3
    autovacuum_naptime = 1min
    autovacuum_vacuum_threshold = 50
    autovacuum_analyze_threshold = 50
    autovacuum_vacuum_scale_factor = 0.2
    autovacuum_analyze_scale_factor = 0.1
    autovacuum_freeze_max_age = 200000000
    autovacuum_multixact_freeze_max_age = 400000000
    autovacuum_vacuum_cost_delay = 20ms
    autovacuum_vacuum_cost_limit = 200
    
    # Logging Settings
    log_destination = 'stderr'
    logging_collector = on
    log_directory = 'log'
    log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
    log_rotation_age = 1d
    log_rotation_size = 100MB
    log_min_duration_statement = 1000
    log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
    log_checkpoints = on
    log_connections = on
    log_disconnections = on
    log_lock_waits = on
    log_temp_files = 10MB
    log_autovacuum_min_duration = 0
    log_error_verbosity = default
    
    # Replication Settings
    wal_level = replica
    max_wal_senders = 10
    max_replication_slots = 10
    hot_standby = on
    hot_standby_feedback = off
    
    # SSL Settings
    ssl = on
    ssl_cert_file = '/etc/ssl/certs/tls.crt'
    ssl_key_file = '/etc/ssl/private/tls.key'
    ssl_ca_file = '/etc/ssl/certs/ca.crt'
    ssl_ciphers = 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384'
    ssl_prefer_server_ciphers = on
    ssl_protocols = 'TLSv1.2,TLSv1.3'
```

### Database Indexes for Temporal

#### Temporal Optimization Script
```sql
-- k8s/database/sql/temporal-indexes.sql
-- Additional indexes for Temporal performance optimization

-- Indexes for executions table
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_executions_namespace_id 
ON executions (namespace_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_executions_workflow_id_run_id 
ON executions (workflow_id, run_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_executions_state_created_time 
ON executions (state, created_time);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_executions_start_time 
ON executions (start_time) WHERE start_time IS NOT NULL;

-- Indexes for history_events table
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_history_events_workflow_id_run_id_event_id 
ON history_events (workflow_id, run_id, event_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_history_events_created_time 
ON history_events (created_time);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_history_events_event_type 
ON history_events (event_type);

-- Indexes for tasks table
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tasks_task_queue_name_state 
ON tasks (task_queue_name, state);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tasks_created_time 
ON tasks (created_time);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tasks_visibility_timestamp 
ON tasks (visibility_timestamp) WHERE visibility_timestamp IS NOT NULL;

-- Indexes for activity_info_maps table
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_activity_info_maps_workflow_id_run_id 
ON activity_info_maps (workflow_id, run_id);

-- Indexes for timer_info_maps table
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_timer_info_maps_workflow_id_run_id 
ON timer_info_maps (workflow_id, run_id);

-- Indexes for child_execution_info_maps table
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_child_execution_info_maps_workflow_id_run_id 
ON child_execution_info_maps (workflow_id, run_id);

-- Indexes for visibility tables
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_executions_visibility_namespace_id_start_time 
ON executions_visibility (namespace_id, start_time);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_executions_visibility_workflow_type_start_time 
ON executions_visibility (workflow_type, start_time);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_executions_visibility_status_start_time 
ON executions_visibility (status, start_time);

-- Composite indexes for common queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_executions_visibility_namespace_status_start_time 
ON executions_visibility (namespace_id, status, start_time);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_executions_visibility_namespace_type_start_time 
ON executions_visibility (namespace_id, workflow_type, start_time);

-- Update table statistics
ANALYZE executions;
ANALYZE history_events;
ANALYZE tasks;
ANALYZE activity_info_maps;
ANALYZE timer_info_maps;
ANALYZE child_execution_info_maps;
ANALYZE executions_visibility;
```

## Backup and Recovery

### Automated Backup System

#### Backup CronJob
```yaml
# k8s/database/backup/backup-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgresql-backup
  namespace: temporal-system
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  concurrencyPolicy: Forbid
  failedJobsHistoryLimit: 3
  successfulJobsHistoryLimit: 3
  jobTemplate:
    spec:
      template:
        metadata:
          annotations:
            prometheus.io/scrape: "false"
        spec:
          restartPolicy: OnFailure
          containers:
          - name: postgresql-backup
            image: postgres:15.4
            command:
            - /bin/bash
            - -c
            - |
              set -euo pipefail
              
              TIMESTAMP=$(date +%Y%m%d_%H%M%S)
              BACKUP_DIR="/backups"
              
              echo "Starting PostgreSQL backup at $(date)"
              
              # Create backup directory
              mkdir -p "$BACKUP_DIR"
              
              # Backup main database
              echo "Backing up temporal database..."
              PGPASSWORD="$DB_PASSWORD" pg_dump \
                -h "$DB_HOST" \
                -U "$DB_USER" \
                -d temporal \
                --verbose \
                --no-owner \
                --no-privileges \
                --clean \
                --if-exists \
                --format=custom \
                -f "$BACKUP_DIR/temporal_${TIMESTAMP}.dump"
              
              # Backup visibility database
              echo "Backing up temporal_visibility database..."
              PGPASSWORD="$DB_PASSWORD" pg_dump \
                -h "$DB_HOST" \
                -U "$DB_USER" \
                -d temporal_visibility \
                --verbose \
                --no-owner \
                --no-privileges \
                --clean \
                --if-exists \
                --format=custom \
                -f "$BACKUP_DIR/temporal_visibility_${TIMESTAMP}.dump"
              
              # Compress backups
              echo "Compressing backup files..."
              gzip "$BACKUP_DIR/temporal_${TIMESTAMP}.dump"
              gzip "$BACKUP_DIR/temporal_visibility_${TIMESTAMP}.dump"
              
              # Upload to S3
              echo "Uploading backups to S3..."
              aws s3 cp "$BACKUP_DIR/temporal_${TIMESTAMP}.dump.gz" \
                "s3://${S3_BUCKET}/database/temporal_${TIMESTAMP}.dump.gz" \
                --storage-class STANDARD_IA
              
              aws s3 cp "$BACKUP_DIR/temporal_visibility_${TIMESTAMP}.dump.gz" \
                "s3://${S3_BUCKET}/database/temporal_visibility_${TIMESTAMP}.dump.gz" \
                --storage-class STANDARD_IA
              
              # Clean up local files
              rm -f "$BACKUP_DIR"/*.dump.gz
              
              # Clean up old backups (keep last 30 days)
              aws s3 ls "s3://${S3_BUCKET}/database/" | \
                grep "temporal_" | \
                sort | \
                head -n -60 | \
                awk '{print $4}' | \
                xargs -I {} aws s3 rm "s3://${S3_BUCKET}/database/{}" || true
              
              echo "Backup completed successfully at $(date)"
            
            env:
            - name: DB_HOST
              value: "postgresql-primary"
            - name: DB_USER
              value: "temporal"
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: postgresql-credentials
                  key: password
            - name: S3_BUCKET
              value: "temporal-backups"
            - name: AWS_REGION
              value: "us-west-2"
            
            volumeMounts:
            - name: backup-storage
              mountPath: /backups
            
            resources:
              limits:
                memory: 1Gi
                cpu: 500m
              requests:
                memory: 512Mi
                cpu: 250m
          
          volumes:
          - name: backup-storage
            emptyDir:
              sizeLimit: 10Gi
          
          serviceAccountName: postgresql-backup
          
          securityContext:
            runAsNonRoot: true
            runAsUser: 999
            fsGroup: 999
```

### Point-in-Time Recovery Setup

#### WAL-E Configuration for Continuous Archiving
```yaml
# k8s/database/backup/wal-e-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: wal-e-config
  namespace: temporal-system
data:
  wal-e.conf: |
    [wal-e]
    s3_prefix = s3://temporal-backups/wal-e
    aws_region = us-west-2
    
    [postgresql]
    archive_mode = on
    archive_command = 'wal-e wal-push %p'
    archive_timeout = 60
    
    max_wal_senders = 10
    wal_keep_size = 1GB
    wal_level = replica
  
  recovery.conf.template: |
    standby_mode = 'on'
    primary_conninfo = 'host=${PRIMARY_HOST} port=5432 user=replicator password=${REPLICATION_PASSWORD}'
    restore_command = 'wal-e wal-fetch %f %p'
    recovery_target_time = '${RECOVERY_TARGET_TIME}'
```

### Disaster Recovery Procedures

#### Recovery Script
```bash
#!/bin/bash
# scripts/database/disaster-recovery.sh

set -euo pipefail

BACKUP_DATE=${1:-latest}
RECOVERY_TYPE=${2:-full}  # full, point-in-time
TARGET_TIME=${3:-}

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

log "Starting disaster recovery process..."
log "Backup date: $BACKUP_DATE"
log "Recovery type: $RECOVERY_TYPE"

# Verify prerequisites
if ! command -v kubectl &> /dev/null; then
    error "kubectl is required but not installed"
fi

if ! command -v aws &> /dev/null; then
    error "aws CLI is required but not installed"
fi

# Get backup file
if [[ "$BACKUP_DATE" == "latest" ]]; then
    BACKUP_FILE=$(aws s3 ls s3://temporal-backups/database/ | sort | tail -n 1 | awk '{print $4}')
    if [[ -z "$BACKUP_FILE" ]]; then
        error "No backup files found"
    fi
    log "Using latest backup: $BACKUP_FILE"
else
    BACKUP_FILE="temporal_${BACKUP_DATE}.dump.gz"
fi

# Download backup
log "Downloading backup file..."
aws s3 cp "s3://temporal-backups/database/$BACKUP_FILE" "./backup.dump.gz"
gunzip backup.dump.gz

# Stop Temporal services
log "Stopping Temporal services..."
kubectl scale deployment temporal-frontend temporal-history temporal-matching temporal-worker --replicas=0 -n temporal-system

# Create recovery database
log "Creating recovery database..."
kubectl run recovery-db --image=postgres:15.4 --rm -i --restart=Never -- \
    createdb -h postgresql-primary -U postgres -O temporal temporal_recovery

# Restore backup
log "Restoring database backup..."
kubectl run restore-job --image=postgres:15.4 --rm -i --restart=Never -- \
    pg_restore -h postgresql-primary -U temporal -d temporal_recovery \
    --verbose --clean --if-exists < backup.dump

if [[ "$RECOVERY_TYPE" == "point-in-time" && -n "$TARGET_TIME" ]]; then
    log "Performing point-in-time recovery to $TARGET_TIME..."
    # Configure recovery.conf for point-in-time recovery
    kubectl run pitr-job --image=postgres:15.4 --rm -i --restart=Never -- \
        bash -c "
        echo \"recovery_target_time = '$TARGET_TIME'\" > /tmp/recovery.conf
        echo \"recovery_target_action = 'promote'\" >> /tmp/recovery.conf
        kubectl cp /tmp/recovery.conf postgresql-primary:/var/lib/postgresql/data/recovery.conf
        "
fi

# Validate recovery
log "Validating database recovery..."
RECORD_COUNT=$(kubectl run validate-job --image=postgres:15.4 --rm -i --restart=Never -- \
    psql -h postgresql-primary -U temporal -d temporal_recovery -t -c "SELECT COUNT(*) FROM executions;")

log "Database recovery validation: $RECORD_COUNT records found"

# Switch to recovered database
log "Switching to recovered database..."
kubectl run switch-db --image=postgres:15.4 --rm -i --restart=Never -- \
    bash -c "
    psql -h postgresql-primary -U postgres -c 'ALTER DATABASE temporal RENAME TO temporal_old;'
    psql -h postgresql-primary -U postgres -c 'ALTER DATABASE temporal_recovery RENAME TO temporal;'
    "

# Restart Temporal services
log "Restarting Temporal services..."
kubectl scale deployment temporal-frontend temporal-history temporal-matching temporal-worker --replicas=1 -n temporal-system

# Wait for services to be ready
kubectl wait --for=condition=available deployment/temporal-frontend -n temporal-system --timeout=300s

log "Disaster recovery completed successfully!"
log "Please verify system functionality before proceeding with normal operations"

# Clean up
rm -f backup.dump
```

## Monitoring and Maintenance

### Database Monitoring Setup

#### PostgreSQL Exporter Configuration
```yaml
# k8s/database/monitoring/postgres-exporter.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres-exporter
  namespace: temporal-system
  labels:
    app: postgres-exporter
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres-exporter
  template:
    metadata:
      labels:
        app: postgres-exporter
    spec:
      containers:
      - name: postgres-exporter
        image: quay.io/prometheuscommunity/postgres-exporter:v0.11.1
        ports:
        - containerPort: 9187
          name: metrics
        env:
        - name: DATA_SOURCE_NAME
          valueFrom:
            secretKeyRef:
              name: postgres-exporter-secret
              key: connection-string
        - name: PG_EXPORTER_QUERIES_PATH
          value: "/etc/postgres_exporter/queries.yaml"
        
        volumeMounts:
        - name: queries-config
          mountPath: /etc/postgres_exporter
        
        resources:
          limits:
            memory: 256Mi
            cpu: 250m
          requests:
            memory: 128Mi
            cpu: 100m
        
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 65534
      
      volumes:
      - name: queries-config
        configMap:
          name: postgres-exporter-queries
      
      serviceAccountName: postgres-exporter

---
apiVersion: v1
kind: Service
metadata:
  name: postgres-exporter
  namespace: temporal-system
  labels:
    app: postgres-exporter
spec:
  ports:
  - port: 9187
    targetPort: 9187
    name: metrics
  selector:
    app: postgres-exporter

---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: postgres-exporter
  namespace: temporal-system
spec:
  selector:
    matchLabels:
      app: postgres-exporter
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

#### Custom PostgreSQL Queries for Monitoring
```yaml
# k8s/database/monitoring/postgres-queries.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: postgres-exporter-queries
  namespace: temporal-system
data:
  queries.yaml: |
    pg_replication:
      query: "SELECT CASE WHEN NOT pg_is_in_recovery() THEN 0 ELSE GREATEST (0, EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))) END AS lag"
      master: true
      metrics:
        - lag:
            usage: "GAUGE"
            description: "Replication lag behind master in seconds"
    
    pg_postmaster:
      query: "SELECT pg_postmaster_start_time as start_time_seconds from pg_postmaster_start_time()"
      master: true
      metrics:
        - start_time_seconds:
            usage: "GAUGE"
            description: "Time at which postmaster started"
    
    pg_stat_user_tables:
      query: |
        SELECT
          current_database() datname,
          schemaname,
          relname,
          seq_scan,
          seq_tup_read,
          idx_scan,
          idx_tup_fetch,
          n_tup_ins,
          n_tup_upd,
          n_tup_del,
          n_tup_hot_upd,
          n_live_tup,
          n_dead_tup,
          n_mod_since_analyze,
          COALESCE(last_vacuum, '1970-01-01Z') as last_vacuum,
          COALESCE(last_autovacuum, '1970-01-01Z') as last_autovacuum,
          COALESCE(last_analyze, '1970-01-01Z') as last_analyze,
          COALESCE(last_autoanalyze, '1970-01-01Z') as last_autoanalyze,
          vacuum_count,
          autovacuum_count,
          analyze_count,
          autoanalyze_count
        FROM pg_stat_user_tables
      metrics:
        - datname:
            usage: "LABEL"
            description: "Name of current database"
        - schemaname:
            usage: "LABEL"
            description: "Name of the schema that this table is in"
        - relname:
            usage: "LABEL"
            description: "Name of this table"
        - seq_scan:
            usage: "COUNTER"
            description: "Number of sequential scans initiated on this table"
        - seq_tup_read:
            usage: "COUNTER"
            description: "Number of live rows fetched by sequential scans"
        - idx_scan:
            usage: "COUNTER"
            description: "Number of index scans initiated on this table"
        - idx_tup_fetch:
            usage: "COUNTER"
            description: "Number of live rows fetched by index scans"
        - n_tup_ins:
            usage: "COUNTER"
            description: "Number of rows inserted"
        - n_tup_upd:
            usage: "COUNTER"
            description: "Number of rows updated"
        - n_tup_del:
            usage: "COUNTER"
            description: "Number of rows deleted"
        - n_tup_hot_upd:
            usage: "COUNTER"
            description: "Number of rows HOT updated"
        - n_live_tup:
            usage: "GAUGE"
            description: "Estimated number of live rows"
        - n_dead_tup:
            usage: "GAUGE"
            description: "Estimated number of dead rows"
        - n_mod_since_analyze:
            usage: "GAUGE"
            description: "Estimated number of rows modified since this table was last analyzed"
        - last_vacuum:
            usage: "GAUGE"
            description: "Last time at which this table was manually vacuumed"
        - last_autovacuum:
            usage: "GAUGE"
            description: "Last time at which this table was vacuumed by the autovacuum daemon"
        - last_analyze:
            usage: "GAUGE"
            description: "Last time at which this table was manually analyzed"
        - last_autoanalyze:
            usage: "GAUGE"
            description: "Last time at which this table was analyzed by the autovacuum daemon"
        - vacuum_count:
            usage: "COUNTER"
            description: "Number of times this table has been manually vacuumed"
        - autovacuum_count:
            usage: "COUNTER"
            description: "Number of times this table has been vacuumed by the autovacuum daemon"
        - analyze_count:
            usage: "COUNTER"
            description: "Number of times this table has been manually analyzed"
        - autoanalyze_count:
            usage: "COUNTER"
            description: "Number of times this table has been analyzed by the autovacuum daemon"
    
    temporal_executions:
      query: |
        SELECT
          namespace_id,
          COUNT(*) as total_executions,
          COUNT(*) FILTER (WHERE state = 1) as running_executions,
          COUNT(*) FILTER (WHERE state = 2) as completed_executions,
          COUNT(*) FILTER (WHERE state = 3) as failed_executions,
          COUNT(*) FILTER (WHERE state = 4) as cancelled_executions,
          COUNT(*) FILTER (WHERE state = 5) as terminated_executions
        FROM executions
        GROUP BY namespace_id
      metrics:
        - namespace_id:
            usage: "LABEL"
            description: "Temporal namespace ID"
        - total_executions:
            usage: "GAUGE"
            description: "Total number of workflow executions"
        - running_executions:
            usage: "GAUGE"
            description: "Number of running workflow executions"
        - completed_executions:
            usage: "GAUGE"
            description: "Number of completed workflow executions"
        - failed_executions:
            usage: "GAUGE"
            description: "Number of failed workflow executions"
        - cancelled_executions:
            usage: "GAUGE"
            description: "Number of cancelled workflow executions"
        - terminated_executions:
            usage: "GAUGE"
            description: "Number of terminated workflow executions"
```

### Database Maintenance Scripts

#### Maintenance CronJob
```yaml
# k8s/database/maintenance/maintenance-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgresql-maintenance
  namespace: temporal-system
spec:
  schedule: "0 3 * * 0"  # Weekly on Sunday at 3 AM
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
          - name: maintenance
            image: postgres:15.4
            command:
            - /bin/bash
            - -c
            - |
              set -euo pipefail
              
              echo "Starting database maintenance at $(date)"
              
              # Vacuum and analyze all databases
              for db in temporal temporal_visibility; do
                echo "Maintaining database: $db"
                
                # Vacuum analyze
                PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$db" -c "VACUUM ANALYZE;"
                
                # Reindex
                PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$db" -c "REINDEX DATABASE $db;"
                
                # Update statistics
                PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$db" -c "ANALYZE;"
              done
              
              echo "Database maintenance completed at $(date)"
            
            env:
            - name: DB_HOST
              value: "postgresql-primary"
            - name: DB_USER
              value: "temporal"
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: postgresql-credentials
                  key: password
            
            resources:
              limits:
                memory: 512Mi
                cpu: 500m
              requests:
                memory: 256Mi
                cpu: 250m
```

This comprehensive database setup guide provides enterprise-grade PostgreSQL deployment with high availability, performance optimization, backup/recovery procedures, and monitoring capabilities specifically tuned for Temporal.io workloads.
