# API Reference

This comprehensive API reference covers all Temporal.io APIs, including the Frontend Service API, Worker API, Admin API, and client SDKs. The reference includes detailed endpoint documentation, request/response schemas, and practical examples.

## Table of Contents

- [Frontend Service API](#frontend-service-api)
- [Worker API](#worker-api)
- [Admin API](#admin-api)
- [Client SDK APIs](#client-sdk-apis)
- [Authentication & Authorization](#authentication--authorization)
- [Error Codes](#error-codes)
- [Rate Limiting](#rate-limiting)
- [Versioning](#versioning)

## Frontend Service API

The Frontend Service API is the main interface for client interactions with Temporal. All client SDKs communicate through this API.

### Base URL and Authentication

```
Base URL: https://temporal.company.com:7233
Protocol: gRPC over HTTP/2
Authentication: JWT Bearer Token (optional)
```

### Workflow Operations

#### StartWorkflowExecution

Starts a new workflow execution.

**Method:** `POST /api/v1/namespaces/{namespace}/workflows`

**Request Schema:**
```protobuf
message StartWorkflowExecutionRequest {
  string namespace = 1;
  string workflow_id = 2;
  temporal.api.common.v1.WorkflowType workflow_type = 3;
  string task_queue = 4;
  google.protobuf.Any input = 5;
  google.protobuf.Duration workflow_execution_timeout = 6;
  google.protobuf.Duration workflow_run_timeout = 7;
  google.protobuf.Duration workflow_task_timeout = 8;
  string identity = 9;
  string request_id = 10;
  temporal.api.enums.v1.WorkflowIdReusePolicy workflow_id_reuse_policy = 11;
  temporal.api.common.v1.RetryPolicy retry_policy = 12;
  string cron_schedule = 13;
  temporal.api.common.v1.Memo memo = 14;
  temporal.api.common.v1.SearchAttributes search_attributes = 15;
  temporal.api.common.v1.Header header = 16;
}
```

**Response Schema:**
```protobuf
message StartWorkflowExecutionResponse {
  string run_id = 1;
  bool started = 2;
}
```

**Example Request:**
```json
{
  "namespace": "default",
  "workflow_id": "order-processing-12345",
  "workflow_type": {
    "name": "OrderProcessingWorkflow"
  },
  "task_queue": "order-processing-queue",
  "input": {
    "order_id": "12345",
    "customer_id": "customer-67890",
    "items": [
      {
        "product_id": "product-001",
        "quantity": 2,
        "price": 29.99
      }
    ]
  },
  "workflow_execution_timeout": "86400s",
  "workflow_run_timeout": "3600s",
  "workflow_task_timeout": "10s",
  "identity": "order-service-v1.2.3",
  "workflow_id_reuse_policy": "ALLOW_DUPLICATE_FAILED_ONLY",
  "retry_policy": {
    "initial_interval": "1s",
    "backoff_coefficient": 2.0,
    "maximum_interval": "100s",
    "maximum_attempts": 3
  },
  "memo": {
    "fields": {
      "environment": {
        "data": "production"
      },
      "version": {
        "data": "v1.2.3"
      }
    }
  },
  "search_attributes": {
    "indexed_fields": {
      "OrderId": {
        "data": "12345"
      },
      "CustomerId": {
        "data": "customer-67890"
      },
      "Environment": {
        "data": "production"
      }
    }
  }
}
```

**Example Response:**
```json
{
  "run_id": "01234567-89ab-cdef-0123-456789abcdef",
  "started": true
}
```

#### GetWorkflowExecution

Retrieves information about a workflow execution.

**Method:** `GET /api/v1/namespaces/{namespace}/workflows/{workflow_id}/runs/{run_id}`

**Request Schema:**
```protobuf
message GetWorkflowExecutionRequest {
  string namespace = 1;
  temporal.api.common.v1.WorkflowExecution execution = 2;
}
```

**Response Schema:**
```protobuf
message GetWorkflowExecutionResponse {
  temporal.api.workflowservice.v1.WorkflowExecutionInfo execution_info = 1;
  repeated temporal.api.history.v1.HistoryEvent workflow_execution_history = 2;
  bytes next_page_token = 3;
}
```

#### TerminateWorkflowExecution

Terminates a running workflow execution.

**Method:** `POST /api/v1/namespaces/{namespace}/workflows/{workflow_id}/runs/{run_id}/terminate`

**Request Schema:**
```protobuf
message TerminateWorkflowExecutionRequest {
  string namespace = 1;
  temporal.api.common.v1.WorkflowExecution workflow_execution = 2;
  string reason = 3;
  google.protobuf.Any details = 4;
  string identity = 5;
}
```

#### SignalWorkflowExecution

Sends a signal to a running workflow execution.

**Method:** `POST /api/v1/namespaces/{namespace}/workflows/{workflow_id}/runs/{run_id}/signal`

**Request Schema:**
```protobuf
message SignalWorkflowExecutionRequest {
  string namespace = 1;
  temporal.api.common.v1.WorkflowExecution workflow_execution = 2;
  string signal_name = 3;
  google.protobuf.Any input = 4;
  string identity = 5;
  string request_id = 6;
  string control = 7;
  temporal.api.common.v1.Header header = 8;
}
```

**Example Request:**
```json
{
  "namespace": "default",
  "workflow_execution": {
    "workflow_id": "order-processing-12345",
    "run_id": "01234567-89ab-cdef-0123-456789abcdef"
  },
  "signal_name": "payment_received",
  "input": {
    "payment_id": "payment-98765",
    "amount": 59.98,
    "currency": "USD",
    "method": "credit_card"
  },
  "identity": "payment-service-v1.1.0",
  "request_id": "signal-request-12345"
}
```

#### QueryWorkflow

Queries the current state of a workflow execution.

**Method:** `POST /api/v1/namespaces/{namespace}/workflows/{workflow_id}/runs/{run_id}/query`

**Request Schema:**
```protobuf
message QueryWorkflowRequest {
  string namespace = 1;
  temporal.api.common.v1.WorkflowExecution execution = 2;
  temporal.api.query.v1.WorkflowQuery query = 3;
  temporal.api.enums.v1.QueryRejectCondition query_reject_condition = 4;
  temporal.api.common.v1.Header header = 5;
}
```

**Example Request:**
```json
{
  "namespace": "default",
  "execution": {
    "workflow_id": "order-processing-12345",
    "run_id": "01234567-89ab-cdef-0123-456789abcdef"
  },
  "query": {
    "query_type": "get_order_status",
    "query_args": {}
  },
  "query_reject_condition": "NOT_OPEN"
}
```

### Activity Operations

#### RecordActivityTaskHeartbeat

Records a heartbeat for an activity task.

**Method:** `POST /api/v1/namespaces/{namespace}/activities/heartbeat`

**Request Schema:**
```protobuf
message RecordActivityTaskHeartbeatRequest {
  string namespace = 1;
  bytes task_token = 2;
  google.protobuf.Any details = 3;
  string identity = 4;
}
```

#### RespondActivityTaskCompleted

Responds to an activity task with completion.

**Method:** `POST /api/v1/namespaces/{namespace}/activities/complete`

**Request Schema:**
```protobuf
message RespondActivityTaskCompletedRequest {
  string namespace = 1;
  bytes task_token = 2;
  google.protobuf.Any result = 3;
  string identity = 4;
}
```

#### RespondActivityTaskFailed

Responds to an activity task with failure.

**Method:** `POST /api/v1/namespaces/{namespace}/activities/fail`

**Request Schema:**
```protobuf
message RespondActivityTaskFailedRequest {
  string namespace = 1;
  bytes task_token = 2;
  temporal.api.failure.v1.Failure failure = 3;
  string identity = 4;
  int64 last_heartbeat_time = 5;
}
```

### Task Queue Operations

#### PollWorkflowTaskQueue

Polls for workflow tasks from a task queue.

**Method:** `POST /api/v1/namespaces/{namespace}/task-queues/{task_queue}/workflow-tasks/poll`

**Request Schema:**
```protobuf
message PollWorkflowTaskQueueRequest {
  string namespace = 1;
  string task_queue = 2;
  string identity = 3;
  string binary_checksum = 4;
  temporal.api.taskqueue.v1.TaskQueueMetadata task_queue_metadata = 5;
}
```

**Response Schema:**
```protobuf
message PollWorkflowTaskQueueResponse {
  bytes task_token = 1;
  temporal.api.common.v1.WorkflowExecution workflow_execution = 2;
  temporal.api.common.v1.WorkflowType workflow_type = 3;
  int64 previous_started_event_id = 4;
  int64 started_event_id = 5;
  int64 attempt = 6;
  int64 backlog_count_hint = 7;
  google.protobuf.Timestamp scheduled_time = 8;
  google.protobuf.Timestamp started_time = 9;
  repeated temporal.api.history.v1.HistoryEvent history = 10;
  bytes next_page_token = 11;
  temporal.api.query.v1.WorkflowQuery query = 12;
  temporal.api.taskqueue.v1.TaskQueue workflow_execution_task_queue = 13;
  google.protobuf.Duration workflow_task_timeout = 14;
  repeated temporal.api.sdk.v1.WorkflowTaskCompletedMetadata messages = 15;
}
```

#### PollActivityTaskQueue

Polls for activity tasks from a task queue.

**Method:** `POST /api/v1/namespaces/{namespace}/task-queues/{task_queue}/activity-tasks/poll`

**Request Schema:**
```protobuf
message PollActivityTaskQueueRequest {
  string namespace = 1;
  string task_queue = 2;
  string identity = 3;
  temporal.api.taskqueue.v1.TaskQueueMetadata task_queue_metadata = 4;
}
```

### Namespace Operations

#### RegisterNamespace

Registers a new namespace.

**Method:** `POST /api/v1/namespaces`

**Request Schema:**
```protobuf
message RegisterNamespaceRequest {
  string namespace = 1;
  string description = 2;
  string owner_email = 3;
  google.protobuf.Duration workflow_execution_retention_period = 4;
  map<string, string> data = 5;
  bool is_global_namespace = 6;
  repeated temporal.api.replication.v1.ClusterReplicationConfig clusters = 7;
  string active_cluster_name = 8;
  temporal.api.namespace.v1.ArchivalConfig history_archival_config = 9;
  temporal.api.namespace.v1.ArchivalConfig visibility_archival_config = 10;
}
```

**Example Request:**
```json
{
  "namespace": "order-processing",
  "description": "Namespace for order processing workflows",
  "owner_email": "team-orders@company.com",
  "workflow_execution_retention_period": "2592000s",
  "data": {
    "environment": "production",
    "team": "orders",
    "cost_center": "engineering"
  },
  "is_global_namespace": false,
  "history_archival_config": {
    "state": "ENABLED",
    "uri": "s3://temporal-archival/order-processing/history"
  },
  "visibility_archival_config": {
    "state": "ENABLED",
    "uri": "s3://temporal-archival/order-processing/visibility"
  }
}
```

#### DescribeNamespace

Describes a namespace and its configuration.

**Method:** `GET /api/v1/namespaces/{namespace}`

**Response Schema:**
```protobuf
message DescribeNamespaceResponse {
  temporal.api.namespace.v1.NamespaceInfo namespace_info = 1;
  temporal.api.namespace.v1.NamespaceConfig config = 2;
  temporal.api.replication.v1.NamespaceReplicationConfig replication_config = 3;
  int64 failover_version = 4;
  bool is_global_namespace = 5;
}
```

#### ListNamespaces

Lists all namespaces.

**Method:** `GET /api/v1/namespaces`

**Query Parameters:**
- `page_size`: Maximum number of namespaces to return
- `next_page_token`: Token for pagination

### Search and Visibility

#### ListWorkflowExecutions

Lists workflow executions with optional filtering.

**Method:** `GET /api/v1/namespaces/{namespace}/workflows`

**Query Parameters:**
- `query`: SQL-like query string for filtering
- `page_size`: Maximum number of results to return
- `next_page_token`: Token for pagination

**Example Query:**
```
GET /api/v1/namespaces/default/workflows?query=WorkflowType='OrderProcessingWorkflow' AND ExecutionStatus='Running' AND StartTime > '2023-01-01T00:00:00Z'
```

**Response Schema:**
```protobuf
message ListWorkflowExecutionsResponse {
  repeated temporal.api.workflow.v1.WorkflowExecutionInfo executions = 1;
  bytes next_page_token = 2;
}
```

#### ScanWorkflowExecutions

Scans workflow executions without requiring an index.

**Method:** `POST /api/v1/namespaces/{namespace}/workflows/scan`

#### CountWorkflowExecutions

Counts workflow executions matching a query.

**Method:** `GET /api/v1/namespaces/{namespace}/workflows/count`

**Query Parameters:**
- `query`: SQL-like query string for filtering

## Worker API

The Worker API is used by worker processes to poll for tasks and respond with results.

### Worker Registration

#### RegisterWorker

Registers a worker with the Temporal service.

**Request Schema:**
```protobuf
message RegisterWorkerRequest {
  string namespace = 1;
  string task_queue = 2;
  string identity = 3;
  repeated string workflow_types = 4;
  repeated string activity_types = 5;
  temporal.api.sdk.v1.WorkerVersionCapabilities version_capabilities = 6;
}
```

### Task Processing

#### RespondWorkflowTaskCompleted

Responds to a workflow task with completion.

**Method:** `POST /api/v1/namespaces/{namespace}/workflow-tasks/complete`

**Request Schema:**
```protobuf
message RespondWorkflowTaskCompletedRequest {
  string namespace = 1;
  bytes task_token = 2;
  repeated temporal.api.command.v1.Command commands = 3;
  string identity = 4;
  bool sticky_attributes = 5;
  bool return_new_workflow_task = 6;
  bool force_create_new_workflow_task = 7;
  string binary_checksum = 8;
  temporal.api.sdk.v1.WorkflowTaskCompletedMetadata sdk_metadata = 9;
  map<string, temporal.api.common.v1.Payloads> query_results = 10;
  temporal.api.common.v1.Memo memo_update = 11;
}
```

#### RespondWorkflowTaskFailed

Responds to a workflow task with failure.

**Method:** `POST /api/v1/namespaces/{namespace}/workflow-tasks/fail`

**Request Schema:**
```protobuf
message RespondWorkflowTaskFailedRequest {
  string namespace = 1;
  bytes task_token = 2;
  temporal.api.enums.v1.WorkflowTaskFailedCause cause = 3;
  temporal.api.failure.v1.Failure failure = 4;
  string identity = 5;
  string binary_checksum = 6;
}
```

## Admin API

The Admin API provides administrative operations for cluster management.

### Cluster Operations

#### DescribeCluster

Describes the cluster configuration and status.

**Method:** `GET /api/v1/cluster`

**Response Schema:**
```protobuf
message DescribeClusterResponse {
  temporal.api.cluster.v1.ClusterInfo cluster_info = 1;
  repeated temporal.api.cluster.v1.ClusterMember membership_info = 2;
}
```

#### ListClusterMembers

Lists all members of the cluster.

**Method:** `GET /api/v1/cluster/members`

### Shard Management

#### DescribeShard

Describes a specific shard.

**Method:** `GET /api/v1/shards/{shard_id}`

#### CloseShard

Closes a specific shard.

**Method:** `POST /api/v1/shards/{shard_id}/close`

### Task Queue Management

#### DescribeTaskQueue

Describes a task queue's status and configuration.

**Method:** `GET /api/v1/namespaces/{namespace}/task-queues/{task_queue}`

**Response Schema:**
```protobuf
message DescribeTaskQueueResponse {
  repeated temporal.api.taskqueue.v1.PollerInfo pollers = 1;
  temporal.api.taskqueue.v1.TaskQueueStatus task_queue_status = 2;
}
```

#### ListTaskQueuePartitions

Lists partitions for a task queue.

**Method:** `GET /api/v1/namespaces/{namespace}/task-queues/{task_queue}/partitions`

### History Management

#### GetWorkflowExecutionHistory

Retrieves the complete history of a workflow execution.

**Method:** `GET /api/v1/namespaces/{namespace}/workflows/{workflow_id}/runs/{run_id}/history`

**Query Parameters:**
- `maximum_page_size`: Maximum number of events per page
- `next_page_token`: Token for pagination
- `wait_new_event`: Whether to wait for new events
- `history_event_filter_type`: Filter for event types

**Response Schema:**
```protobuf
message GetWorkflowExecutionHistoryResponse {
  repeated temporal.api.history.v1.HistoryEvent history = 1;
  bytes next_page_token = 2;
  bool archived = 3;
}
```

## Client SDK APIs

### Go SDK API

#### Client Creation

```go
package main

import (
    "go.temporal.io/sdk/client"
    "go.temporal.io/sdk/worker"
)

// Create a Temporal client
func createClient() (client.Client, error) {
    c, err := client.Dial(client.Options{
        HostPort:  "temporal.company.com:7233",
        Namespace: "default",
        ConnectionOptions: client.ConnectionOptions{
            TLS: &tls.Config{
                ServerName: "temporal.company.com",
            },
        },
        Credentials: client.NewAPIKeyStaticCredentials("your-api-key"),
    })
    return c, err
}
```

#### Workflow Execution

```go
// Start a workflow
func startWorkflow(c client.Client) error {
    options := client.StartWorkflowOptions{
        ID:                 "order-processing-12345",
        TaskQueue:          "order-processing-queue",
        WorkflowRunTimeout: time.Hour * 24,
        WorkflowTaskTimeout: time.Second * 10,
        RetryPolicy: &temporal.RetryPolicy{
            InitialInterval:    time.Second,
            BackoffCoefficient: 2.0,
            MaximumInterval:    time.Second * 100,
            MaximumAttempts:    3,
        },
        Memo: map[string]interface{}{
            "environment": "production",
            "version":     "v1.2.3",
        },
        SearchAttributes: map[string]interface{}{
            "OrderId":     "12345",
            "CustomerId":  "customer-67890",
            "Environment": "production",
        },
    }
    
    we, err := c.ExecuteWorkflow(context.Background(), options, OrderProcessingWorkflow, OrderInput{
        OrderID:    "12345",
        CustomerID: "customer-67890",
        Items: []OrderItem{
            {ProductID: "product-001", Quantity: 2, Price: 29.99},
        },
    })
    return err
}

// Signal a workflow
func signalWorkflow(c client.Client, workflowID, runID string) error {
    return c.SignalWorkflow(context.Background(), workflowID, runID, "payment_received", PaymentInfo{
        PaymentID: "payment-98765",
        Amount:    59.98,
        Currency:  "USD",
        Method:    "credit_card",
    })
}

// Query a workflow
func queryWorkflow(c client.Client, workflowID, runID string) (OrderStatus, error) {
    var result OrderStatus
    value, err := c.QueryWorkflow(context.Background(), workflowID, runID, "get_order_status")
    if err != nil {
        return result, err
    }
    err = value.Get(&result)
    return result, err
}
```

#### Worker Setup

```go
// Create and start a worker
func startWorker() error {
    c, err := createClient()
    if err != nil {
        return err
    }
    defer c.Close()
    
    w := worker.New(c, "order-processing-queue", worker.Options{
        MaxConcurrentActivityExecutionSize: 100,
        MaxConcurrentWorkflowTaskExecutionSize: 100,
        MaxConcurrentActivityTaskPollers: 10,
        MaxConcurrentWorkflowTaskPollers: 10,
    })
    
    // Register workflows and activities
    w.RegisterWorkflow(OrderProcessingWorkflow)
    w.RegisterActivity(ProcessPaymentActivity)
    w.RegisterActivity(UpdateInventoryActivity)
    w.RegisterActivity(SendNotificationActivity)
    
    return w.Run(worker.InterruptCh())
}
```

### Java SDK API

#### Client Creation

```java
import io.temporal.client.WorkflowClient;
import io.temporal.client.WorkflowClientOptions;
import io.temporal.serviceclient.WorkflowServiceStubs;
import io.temporal.serviceclient.WorkflowServiceStubsOptions;

public class TemporalClient {
    public static WorkflowClient createClient() {
        WorkflowServiceStubsOptions serviceOptions = WorkflowServiceStubsOptions.newBuilder()
            .setTarget("temporal.company.com:7233")
            .build();
            
        WorkflowServiceStubs service = WorkflowServiceStubs.newServiceStubs(serviceOptions);
        
        WorkflowClientOptions clientOptions = WorkflowClientOptions.newBuilder()
            .setNamespace("default")
            .build();
            
        return WorkflowClient.newInstance(service, clientOptions);
    }
}
```

#### Workflow Operations

```java
import io.temporal.client.WorkflowOptions;
import io.temporal.common.RetryOptions;

public class WorkflowOperations {
    private final WorkflowClient client;
    
    public void startWorkflow() {
        WorkflowOptions options = WorkflowOptions.newBuilder()
            .setWorkflowId("order-processing-12345")
            .setTaskQueue("order-processing-queue")
            .setWorkflowRunTimeout(Duration.ofHours(24))
            .setWorkflowTaskTimeout(Duration.ofSeconds(10))
            .setRetryOptions(RetryOptions.newBuilder()
                .setInitialInterval(Duration.ofSeconds(1))
                .setBackoffCoefficient(2.0)
                .setMaximumInterval(Duration.ofSeconds(100))
                .setMaximumAttempts(3)
                .build())
            .setMemo(ImmutableMap.of(
                "environment", "production",
                "version", "v1.2.3"
            ))
            .setSearchAttributes(ImmutableMap.of(
                "OrderId", "12345",
                "CustomerId", "customer-67890",
                "Environment", "production"
            ))
            .build();
            
        OrderProcessingWorkflow workflow = client.newWorkflowStub(OrderProcessingWorkflow.class, options);
        
        OrderInput input = new OrderInput();
        input.setOrderId("12345");
        input.setCustomerId("customer-67890");
        
        WorkflowExecution execution = WorkflowClient.start(workflow::processOrder, input);
    }
    
    public void signalWorkflow(String workflowId) {
        OrderProcessingWorkflow workflow = client.newWorkflowStub(OrderProcessingWorkflow.class, workflowId);
        
        PaymentInfo payment = new PaymentInfo();
        payment.setPaymentId("payment-98765");
        payment.setAmount(59.98);
        payment.setCurrency("USD");
        payment.setMethod("credit_card");
        
        workflow.paymentReceived(payment);
    }
}
```

### Python SDK API

#### Client Creation

```python
import asyncio
from temporalio.client import Client, TLSConfig
from temporalio.worker import Worker

async def create_client():
    return await Client.connect(
        "temporal.company.com:7233",
        namespace="default",
        tls=TLSConfig(
            server_root_ca_cert=None,  # Use system CA
            client_cert=None,
            client_private_key=None,
        ),
        api_key="your-api-key",
    )
```

#### Workflow Operations

```python
from temporalio.common import RetryPolicy
from datetime import timedelta

async def start_workflow():
    client = await create_client()
    
    result = await client.execute_workflow(
        OrderProcessingWorkflow.run,
        OrderInput(
            order_id="12345",
            customer_id="customer-67890",
            items=[
                OrderItem(product_id="product-001", quantity=2, price=29.99)
            ]
        ),
        id="order-processing-12345",
        task_queue="order-processing-queue",
        execution_timeout=timedelta(hours=24),
        task_timeout=timedelta(seconds=10),
        retry_policy=RetryPolicy(
            initial_interval=timedelta(seconds=1),
            backoff_coefficient=2.0,
            maximum_interval=timedelta(seconds=100),
            maximum_attempts=3,
        ),
        memo={
            "environment": "production",
            "version": "v1.2.3",
        },
        search_attributes={
            "OrderId": "12345",
            "CustomerId": "customer-67890",
            "Environment": "production",
        },
    )
    
    return result

async def signal_workflow():
    client = await create_client()
    handle = client.get_workflow_handle("order-processing-12345")
    
    await handle.signal(
        OrderProcessingWorkflow.payment_received,
        PaymentInfo(
            payment_id="payment-98765",
            amount=59.98,
            currency="USD",
            method="credit_card",
        )
    )

async def query_workflow():
    client = await create_client()
    handle = client.get_workflow_handle("order-processing-12345")
    
    result = await handle.query(OrderProcessingWorkflow.get_order_status)
    return result
```

### TypeScript SDK API

#### Client Creation

```typescript
import { Connection, Client } from '@temporalio/client';
import { Worker } from '@temporalio/worker';
import fs from 'fs';

async function createClient(): Promise<Client> {
  const connection = await Connection.connect({
    address: 'temporal.company.com:7233',
    tls: {
      serverNameOverride: 'temporal.company.com',
      serverRootCACertificate: fs.readFileSync('./certs/ca.crt'),
      clientCertPair: {
        crt: fs.readFileSync('./certs/client.crt'),
        key: fs.readFileSync('./certs/client.key'),
      },
    },
    metadata: {
      'authorization': 'Bearer your-api-key',
    },
  });

  return new Client({
    connection,
    namespace: 'default',
  });
}
```

#### Workflow Operations

```typescript
import { WorkflowHandle } from '@temporalio/client';

async function startWorkflow(): Promise<WorkflowHandle<typeof orderProcessingWorkflow>> {
  const client = await createClient();
  
  const handle = await client.workflow.start(orderProcessingWorkflow, {
    workflowId: 'order-processing-12345',
    taskQueue: 'order-processing-queue',
    args: [{
      orderId: '12345',
      customerId: 'customer-67890',
      items: [
        { productId: 'product-001', quantity: 2, price: 29.99 }
      ]
    }],
    workflowRunTimeout: '24h',
    workflowTaskTimeout: '10s',
    retry: {
      initialInterval: '1s',
      backoffCoefficient: 2.0,
      maximumInterval: '100s',
      maximumAttempts: 3,
    },
    memo: {
      environment: 'production',
      version: 'v1.2.3',
    },
    searchAttributes: {
      OrderId: ['12345'],
      CustomerId: ['customer-67890'],
      Environment: ['production'],
    },
  });
  
  return handle;
}

async function signalWorkflow(): Promise<void> {
  const client = await createClient();
  const handle = client.workflow.getHandle('order-processing-12345');
  
  await handle.signal(paymentReceivedSignal, {
    paymentId: 'payment-98765',
    amount: 59.98,
    currency: 'USD',
    method: 'credit_card',
  });
}

async function queryWorkflow(): Promise<OrderStatus> {
  const client = await createClient();
  const handle = client.workflow.getHandle('order-processing-12345');
  
  const result = await handle.query(getOrderStatusQuery);
  return result;
}
```

## Authentication & Authorization

### JWT Authentication

Temporal supports JWT-based authentication for securing API access.

#### JWT Token Format

```json
{
  "iss": "https://auth.company.com",
  "sub": "user@company.com",
  "aud": "temporal.company.com",
  "exp": 1640995200,
  "iat": 1640908800,
  "permissions": [
    "temporal:workflow:start",
    "temporal:workflow:signal",
    "temporal:workflow:read"
  ],
  "namespace": "default"
}
```

#### API Key Authentication

```bash
# Using Bearer token in Authorization header
curl -H "Authorization: Bearer your-api-key" \
     -H "Content-Type: application/json" \
     https://temporal.company.com:7233/api/v1/namespaces/default/workflows
```

### RBAC Permissions

#### Permission Hierarchy

```
temporal:*                          # Full access
├── temporal:cluster:*              # Cluster administration
├── temporal:namespace:*            # Namespace management
│   ├── temporal:namespace:create
│   ├── temporal:namespace:read
│   ├── temporal:namespace:update
│   └── temporal:namespace:delete
└── temporal:workflow:*             # Workflow operations
    ├── temporal:workflow:start
    ├── temporal:workflow:signal
    ├── temporal:workflow:query
    ├── temporal:workflow:read
    ├── temporal:workflow:list
    ├── temporal:workflow:terminate
    └── temporal:workflow:cancel
```

## Error Codes

### Standard Error Codes

| Code | Name | Description |
|------|------|-------------|
| `INVALID_ARGUMENT` | Invalid Argument | The request contains invalid parameters |
| `ALREADY_EXISTS` | Already Exists | The workflow execution already exists |
| `NOT_FOUND` | Not Found | The requested resource was not found |
| `PERMISSION_DENIED` | Permission Denied | Insufficient permissions for the operation |
| `RESOURCE_EXHAUSTED` | Resource Exhausted | Rate limit exceeded or quota reached |
| `FAILED_PRECONDITION` | Failed Precondition | Operation cannot be performed in current state |
| `ABORTED` | Aborted | Operation was aborted due to conflict |
| `OUT_OF_RANGE` | Out of Range | Parameter value is out of valid range |
| `UNIMPLEMENTED` | Unimplemented | Operation is not implemented |
| `INTERNAL` | Internal Error | Internal server error |
| `UNAVAILABLE` | Unavailable | Service is temporarily unavailable |
| `DATA_LOSS` | Data Loss | Unrecoverable data loss or corruption |
| `UNAUTHENTICATED` | Unauthenticated | Authentication credentials are missing or invalid |

### Workflow-Specific Error Codes

| Code | Name | Description |
|------|------|-------------|
| `WORKFLOW_EXECUTION_ALREADY_STARTED` | Workflow Already Started | Workflow with the same ID is already running |
| `WORKFLOW_EXECUTION_NOT_FOUND` | Workflow Not Found | No workflow execution found with the given ID |
| `WORKFLOW_EXECUTION_COMPLETED` | Workflow Completed | Operation not allowed on completed workflow |
| `WORKFLOW_TASK_TIMEOUT` | Workflow Task Timeout | Workflow task timed out |
| `ACTIVITY_TASK_TIMEOUT` | Activity Task Timeout | Activity task timed out |
| `NAMESPACE_NOT_FOUND` | Namespace Not Found | The specified namespace does not exist |
| `TASK_QUEUE_NOT_FOUND` | Task Queue Not Found | The specified task queue does not exist |

### Error Response Format

```json
{
  "error": {
    "code": "INVALID_ARGUMENT",
    "message": "Workflow ID cannot be empty",
    "details": [
      {
        "type": "BadRequest",
        "field": "workflow_id",
        "description": "workflow_id is required and cannot be empty"
      }
    ]
  }
}
```

## Rate Limiting

### Rate Limit Headers

API responses include rate limiting information in headers:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
X-RateLimit-Scope: namespace:default
```

### Rate Limit Categories

#### Global Rate Limits
- **API Requests**: 10,000 requests per minute per cluster
- **Workflow Starts**: 1,000 starts per minute per namespace
- **Activity Executions**: 10,000 executions per minute per namespace

#### Per-Namespace Rate Limits
- **Workflow Executions**: 100 concurrent executions per namespace
- **Task Queue Operations**: 1,000 operations per minute per task queue
- **History Events**: 100,000 events per minute per namespace

#### Per-Client Rate Limits
- **API Calls**: 100 requests per second per client
- **Long Polls**: 10 concurrent long polls per client
- **Heartbeats**: 1,000 heartbeats per minute per client

### Rate Limit Error Response

```json
{
  "error": {
    "code": "RESOURCE_EXHAUSTED",
    "message": "Rate limit exceeded for namespace 'default'",
    "details": [
      {
        "type": "RateLimitExceeded",
        "scope": "namespace:default",
        "limit": 1000,
        "window": "1m",
        "retry_after": 30
      }
    ]
  }
}
```

## Versioning

### API Versioning Strategy

Temporal uses semantic versioning for API compatibility:

- **Major Version**: Breaking changes (e.g., v1 → v2)
- **Minor Version**: Backward-compatible additions
- **Patch Version**: Bug fixes and improvements

### Version Headers

Include API version in requests:

```bash
curl -H "Temporal-API-Version: v1" \
     -H "Content-Type: application/json" \
     https://temporal.company.com:7233/api/v1/namespaces
```

### Supported API Versions

| Version | Status | Support End Date |
|---------|--------|------------------|
| `v1` | Current | N/A |
| `v1beta1` | Deprecated | 2024-12-31 |

### Version Compatibility

#### Client SDK Compatibility Matrix

| SDK Version | API v1 | API v1beta1 |
|-------------|--------|-------------|
| Go SDK 1.x | ✅ | ✅ |
| Java SDK 1.x | ✅ | ✅ |
| Python SDK 1.x | ✅ | ✅ |
| TypeScript SDK 1.x | ✅ | ✅ |

This comprehensive API reference provides detailed information about all Temporal.io APIs, including request/response schemas, authentication methods, error handling, and practical examples across multiple programming languages.
