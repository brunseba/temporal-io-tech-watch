# Testing

This document provides comprehensive testing strategies and implementation guidelines for Temporal.io workflows, activities, and FastAPI integrations in enterprise environments.

## Overview

Testing Temporal applications requires specialized approaches due to their distributed, asynchronous nature. This guide covers unit testing, integration testing, load testing, and end-to-end testing strategies using Temporal's testing framework and best practices.

## Testing Framework Setup

### Dependencies

```python
# requirements-test.txt
pytest>=7.0.0
pytest-asyncio>=0.21.0
pytest-cov>=4.0.0
pytest-mock>=3.10.0
temporalio[testing]>=1.0.0
httpx>=0.24.0  # For FastAPI testing
factory-boy>=3.2.0  # For test data generation
freezegun>=1.2.0  # For time mocking
```

### Test Configuration

```python
# tests/conftest.py
import asyncio
import pytest
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker
from httpx import AsyncClient

from src.temporal_workflows.workflows import OrderProcessingWorkflow
from src.temporal_workflows.activities import PaymentActivity, InventoryActivity
from src.temporal_api.main import app

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
async def temporal_env():
    """Create Temporal test environment"""
    async with WorkflowEnvironment() as env:
        yield env

@pytest.fixture
async def temporal_worker(temporal_env):
    """Create Temporal worker for testing"""
    async with Worker(
        temporal_env.client,
        task_queue="test-queue",
        workflows=[OrderProcessingWorkflow],
        activities=[
            PaymentActivity.process_payment,
            InventoryActivity.reserve_inventory,
            InventoryActivity.release_inventory,
        ]
    ):
        yield

@pytest.fixture
async def fastapi_client():
    """Create FastAPI test client"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client

@pytest.fixture
def sample_order_data():
    """Sample order data for testing"""
    return {
        "id": "order-123",
        "customer_id": "cust-456",
        "items": [
            {
                "id": "item-1",
                "name": "Test Product",
                "sku": "TEST-001",
                "quantity": 2,
                "unit_price": 50.00
            }
        ],
        "shipping_address": {
            "street": "123 Test St",
            "city": "Test City",
            "state": "TS",
            "zip_code": "12345"
        },
        "payment_method": "credit_card",
        "payment_details": {"token": "test_token_123"}
    }
```

## Unit Testing Workflows

### Workflow Testing

```python
# tests/test_workflows.py
import pytest
from datetime import timedelta
from temporalio.testing import WorkflowEnvironment
from temporalio.common import RetryPolicy

from src.temporal_workflows.workflows import OrderProcessingWorkflow
from src.temporal_workflows.models import OrderData, OrderStatus

class TestOrderProcessingWorkflow:
    """Test cases for order processing workflow"""
    
    @pytest.mark.asyncio
    async def test_successful_order_processing(self, temporal_env, sample_order_data):
        """Test successful order processing flow"""
        
        async with Worker(
            temporal_env.client,
            task_queue="test-queue",
            workflows=[OrderProcessingWorkflow],
            activities=[
                # Mock activities that always succeed
                self.mock_payment_success,
                self.mock_inventory_success,
                self.mock_shipping_success,
            ]
        ):
            # Start workflow
            handle = await temporal_env.client.start_workflow(
                OrderProcessingWorkflow.run,
                OrderData(**sample_order_data),
                id="test-order-123",
                task_queue="test-queue",
                execution_timeout=timedelta(minutes=5)
            )
            
            # Wait for completion
            result = await handle.result()
            
            # Assertions
            assert result.status == OrderStatus.COMPLETED
            assert result.id == "order-123"
            assert result.total_amount == 100.00
    
    @pytest.mark.asyncio
    async def test_payment_failure_rollback(self, temporal_env, sample_order_data):
        """Test rollback when payment fails"""
        
        async with Worker(
            temporal_env.client,
            task_queue="test-queue",
            workflows=[OrderProcessingWorkflow],
            activities=[
                self.mock_payment_failure,  # Payment fails
                self.mock_inventory_success,
                self.mock_inventory_release,  # Should be called for rollback
            ]
        ):
            handle = await temporal_env.client.start_workflow(
                OrderProcessingWorkflow.run,
                OrderData(**sample_order_data),
                id="test-order-payment-fail",
                task_queue="test-queue"
            )
            
            result = await handle.result()
            
            assert result.status == OrderStatus.FAILED
            assert "payment_failed" in result.failure_reason
    
    @pytest.mark.asyncio
    async def test_workflow_signals(self, temporal_env, sample_order_data):
        """Test workflow signal handling"""
        
        async with Worker(
            temporal_env.client,
            task_queue="test-queue",
            workflows=[OrderProcessingWorkflow],
            activities=[self.mock_long_running_activity]
        ):
            handle = await temporal_env.client.start_workflow(
                OrderProcessingWorkflow.run,
                OrderData(**sample_order_data),
                id="test-order-signal",
                task_queue="test-queue"
            )
            
            # Send cancel signal
            await handle.signal(OrderProcessingWorkflow.cancel, {"reason": "customer_request"})
            
            result = await handle.result()
            
            assert result.status == OrderStatus.CANCELLED
            assert result.cancellation_reason == "customer_request"
    
    @pytest.mark.asyncio
    async def test_workflow_queries(self, temporal_env, sample_order_data):
        """Test workflow query handling"""
        
        async with Worker(
            temporal_env.client,
            task_queue="test-queue",
            workflows=[OrderProcessingWorkflow],
            activities=[self.mock_slow_activity]
        ):
            handle = await temporal_env.client.start_workflow(
                OrderProcessingWorkflow.run,
                OrderData(**sample_order_data),
                id="test-order-query",
                task_queue="test-queue"
            )
            
            # Query workflow status
            status = await handle.query(OrderProcessingWorkflow.get_status)
            
            assert status["current_step"] in ["payment", "inventory", "shipping"]
            assert status["progress"] >= 0
    
    # Mock activity implementations
    async def mock_payment_success(self, payment_data):
        return {"status": "success", "transaction_id": "txn_123"}
    
    async def mock_payment_failure(self, payment_data):
        raise Exception("Payment processing failed")
    
    async def mock_inventory_success(self, items):
        return {"status": "reserved", "reservation_id": "res_123"}
    
    async def mock_inventory_release(self, reservation_id):
        return {"status": "released"}
    
    async def mock_shipping_success(self, shipping_data):
        return {"status": "scheduled", "tracking_number": "TRK_123"}
    
    async def mock_long_running_activity(self, data):
        # Simulate long-running activity for signal testing
        await asyncio.sleep(10)
        return {"status": "completed"}
    
    async def mock_slow_activity(self, data):
        # Simulate activity for query testing
        await asyncio.sleep(2)
        return {"status": "completed"}
```

## Unit Testing Activities

### Activity Testing

```python
# tests/test_activities.py
import pytest
from unittest.mock import AsyncMock, patch
from decimal import Decimal

from src.temporal_workflows.activities import PaymentActivity, InventoryActivity

class TestPaymentActivity:
    """Test cases for payment activities"""
    
    @pytest.mark.asyncio
    async def test_process_payment_success(self):
        """Test successful payment processing"""
        
        payment_data = {
            "amount": Decimal("100.00"),
            "currency": "USD",
            "payment_method": "credit_card",
            "customer_id": "cust_123",
            "payment_details": {"token": "tok_123"}
        }
        
        with patch('src.temporal_workflows.activities.PaymentClient') as mock_client:
            mock_client.return_value.process_payment.return_value = {
                "status": "success",
                "transaction_id": "txn_123456",
                "amount_charged": Decimal("100.00")
            }
            
            result = await PaymentActivity.process_payment(payment_data)
            
            assert result["status"] == "success"
            assert result["transaction_id"] == "txn_123456"
            assert result["amount_charged"] == Decimal("100.00")
    
    @pytest.mark.asyncio
    async def test_process_payment_insufficient_funds(self):
        """Test payment failure due to insufficient funds"""
        
        payment_data = {
            "amount": Decimal("1000.00"),
            "currency": "USD",
            "payment_method": "credit_card",
            "customer_id": "cust_123",
            "payment_details": {"token": "tok_invalid"}
        }
        
        with patch('src.temporal_workflows.activities.PaymentClient') as mock_client:
            mock_client.return_value.process_payment.side_effect = Exception("Insufficient funds")
            
            with pytest.raises(Exception) as exc_info:
                await PaymentActivity.process_payment(payment_data)
            
            assert "Insufficient funds" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_refund_payment(self):
        """Test payment refund"""
        
        refund_data = {
            "transaction_id": "txn_123456",
            "amount": Decimal("50.00"),
            "reason": "partial_refund"
        }
        
        with patch('src.temporal_workflows.activities.PaymentClient') as mock_client:
            mock_client.return_value.refund_payment.return_value = {
                "status": "success",
                "refund_id": "ref_789",
                "amount_refunded": Decimal("50.00")
            }
            
            result = await PaymentActivity.refund_payment(refund_data)
            
            assert result["status"] == "success"
            assert result["refund_id"] == "ref_789"

class TestInventoryActivity:
    """Test cases for inventory activities"""
    
    @pytest.mark.asyncio
    async def test_reserve_inventory_success(self):
        """Test successful inventory reservation"""
        
        items = [
            {"sku": "TEST-001", "quantity": 2},
            {"sku": "TEST-002", "quantity": 1}
        ]
        
        with patch('src.temporal_workflows.activities.InventoryClient') as mock_client:
            mock_client.return_value.reserve_items.return_value = {
                "status": "success",
                "reservation_id": "res_123",
                "reserved_items": items
            }
            
            result = await InventoryActivity.reserve_inventory(items)
            
            assert result["status"] == "success"
            assert result["reservation_id"] == "res_123"
            assert len(result["reserved_items"]) == 2
    
    @pytest.mark.asyncio
    async def test_reserve_inventory_insufficient_stock(self):
        """Test inventory reservation with insufficient stock"""
        
        items = [{"sku": "OUT-OF-STOCK", "quantity": 10}]
        
        with patch('src.temporal_workflows.activities.InventoryClient') as mock_client:
            mock_client.return_value.reserve_items.side_effect = Exception("Insufficient stock")
            
            with pytest.raises(Exception) as exc_info:
                await InventoryActivity.reserve_inventory(items)
            
            assert "Insufficient stock" in str(exc_info.value)
```

## Integration Testing

### FastAPI Integration Tests

```python
# tests/test_api_integration.py
import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient

from src.temporal_api.main import app

class TestOrderAPI:
    """Integration tests for order API endpoints"""
    
    @pytest.mark.asyncio
    async def test_create_order_success(self, fastapi_client: AsyncClient):
        """Test successful order creation via API"""
        
        order_request = {
            "customer_id": "cust_123",
            "items": [
                {
                    "id": "item_1",
                    "name": "Test Product",
                    "sku": "TEST-001",
                    "quantity": 2,
                    "unit_price": 29.99
                }
            ],
            "shipping_address": {
                "street": "123 Test St",
                "city": "Test City",
                "state": "TS",
                "zip_code": "12345"
            },
            "payment_method": "credit_card",
            "payment_details": {"token": "tok_123"}
        }
        
        with patch('src.temporal_api.services.temporal_client.TemporalClientService') as mock_service:
            mock_handle = AsyncMock()
            mock_handle.id = "order-test-123"
            mock_service.return_value.start_workflow.return_value = mock_handle
            
            response = await fastapi_client.post(
                "/api/v1/orders/",
                json=order_request,
                headers={"Authorization": "Bearer test-token"}
            )
        
        assert response.status_code == 201
        data = response.json()
        assert data["customer_id"] == "cust_123"
        assert data["status"] == "PENDING"
        assert data["total_amount"] == 59.98
        assert data["workflow_id"] == "order-test-123"
    
    @pytest.mark.asyncio
    async def test_get_order_status(self, fastapi_client: AsyncClient):
        """Test getting order status via API"""
        
        with patch('src.temporal_api.services.temporal_client.TemporalClientService') as mock_service:
            mock_service.return_value.get_workflow_status.return_value = {
                "workflow_id": "order-test-123",
                "run_id": "run-456",
                "status": "RUNNING",
                "workflow_type": "order_processing",
                "history_length": 15
            }
            
            response = await fastapi_client.get(
                "/api/v1/orders/test-123",
                headers={"Authorization": "Bearer test-token"}
            )
        
        assert response.status_code == 200
        data = response.json()
        assert data["workflow_id"] == "order-test-123"
        assert data["status"] == "RUNNING"
    
    @pytest.mark.asyncio
    async def test_cancel_order(self, fastapi_client: AsyncClient):
        """Test order cancellation via API"""
        
        with patch('src.temporal_api.services.temporal_client.TemporalClientService') as mock_service:
            mock_service.return_value.signal_workflow.return_value = None
            
            response = await fastapi_client.post(
                "/api/v1/orders/test-123/cancel",
                headers={"Authorization": "Bearer test-token"}
            )
        
        assert response.status_code == 204
    
    @pytest.mark.asyncio
    async def test_unauthorized_request(self, fastapi_client: AsyncClient):
        """Test API request without authorization"""
        
        response = await fastapi_client.get("/api/v1/orders/test-123")
        assert response.status_code == 401
```

## Load Testing

### Temporal Load Tests

```python
# tests/test_load.py
import asyncio
import pytest
from concurrent.futures import ThreadPoolExecutor
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from src.temporal_workflows.workflows import OrderProcessingWorkflow

class TestWorkflowLoad:
    """Load tests for workflow execution"""
    
    @pytest.mark.asyncio
    async def test_concurrent_workflow_execution(self, temporal_env):
        """Test concurrent workflow execution under load"""
        
        async with Worker(
            temporal_env.client,
            task_queue="load-test-queue",
            workflows=[OrderProcessingWorkflow],
            activities=[self.mock_fast_activity]
        ):
            # Start multiple workflows concurrently
            concurrent_workflows = 50
            handles = []
            
            for i in range(concurrent_workflows):
                handle = await temporal_env.client.start_workflow(
                    OrderProcessingWorkflow.run,
                    {"id": f"load-test-{i}", "items": [{"sku": "TEST", "quantity": 1}]},
                    id=f"load-test-workflow-{i}",
                    task_queue="load-test-queue"
                )
                handles.append(handle)
            
            # Wait for all workflows to complete
            results = await asyncio.gather(*[handle.result() for handle in handles])
            
            # Verify all workflows completed successfully
            assert len(results) == concurrent_workflows
            for result in results:
                assert result.status in ["COMPLETED", "FAILED"]  # Allow some failures under load
    
    async def mock_fast_activity(self, data):
        """Fast mock activity for load testing"""
        await asyncio.sleep(0.1)  # Simulate minimal processing time
        return {"status": "success"}
```

### API Load Tests with Locust

```python
# tests/locustfile.py
from locust import HttpUser, task, between
import json
import random

class OrderAPIUser(HttpUser):
    """Load test user for Order API"""
    
    wait_time = between(1, 3)
    
    def on_start(self):
        """Setup test user"""
        self.auth_header = {"Authorization": "Bearer test-token"}
    
    @task(3)
    def create_order(self):
        """Create new order - most common operation"""
        order_data = {
            "customer_id": f"cust_{random.randint(1000, 9999)}",
            "items": [
                {
                    "id": f"item_{random.randint(1, 100)}",
                    "name": "Test Product",
                    "sku": f"SKU-{random.randint(100, 999)}",
                    "quantity": random.randint(1, 5),
                    "unit_price": round(random.uniform(10, 100), 2)
                }
            ],
            "shipping_address": {
                "street": "123 Load Test St",
                "city": "Test City",
                "state": "TS",
                "zip_code": "12345"
            },
            "payment_method": "credit_card",
            "payment_details": {"token": f"tok_{random.randint(10000, 99999)}"}
        }
        
        response = self.client.post(
            "/api/v1/orders/",
            json=order_data,
            headers=self.auth_header
        )
        
        if response.status_code == 201:
            # Store order ID for subsequent operations
            order_data = response.json()
            self.order_id = order_data["id"]
    
    @task(2)
    def get_order_status(self):
        """Check order status"""
        if hasattr(self, 'order_id'):
            self.client.get(
                f"/api/v1/orders/{self.order_id}",
                headers=self.auth_header
            )
    
    @task(1)
    def cancel_order(self):
        """Cancel order - less common operation"""
        if hasattr(self, 'order_id'):
            self.client.post(
                f"/api/v1/orders/{self.order_id}/cancel",
                headers=self.auth_header
            )
    
    @task(1)
    def health_check(self):
        """Health check endpoint"""
        self.client.get("/health")
```

## End-to-End Testing

### Complete Workflow Tests

```python
# tests/test_e2e.py
import pytest
import asyncio
from datetime import timedelta
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

class TestEndToEndFlow:
    """End-to-end tests for complete order processing flow"""
    
    @pytest.mark.asyncio
    async def test_complete_order_lifecycle(self, temporal_env):
        """Test complete order processing from start to finish"""
        
        # Setup real-like activities (with mocked external services)
        async with Worker(
            temporal_env.client,
            task_queue="e2e-test-queue",
            workflows=[OrderProcessingWorkflow],
            activities=[
                self.realistic_payment_activity,
                self.realistic_inventory_activity,
                self.realistic_shipping_activity,
            ]
        ):
            order_data = {
                "id": "e2e-order-123",
                "customer_id": "e2e-customer-456",
                "items": [
                    {"sku": "E2E-PRODUCT-1", "quantity": 2, "unit_price": 50.00},
                    {"sku": "E2E-PRODUCT-2", "quantity": 1, "unit_price": 25.00}
                ],
                "total_amount": 125.00,
                "shipping_address": {
                    "street": "123 E2E Test St",
                    "city": "E2E City",
                    "state": "E2E",
                    "zip_code": "12345"
                },
                "payment_method": "credit_card",
                "payment_details": {"token": "e2e_test_token"}
            }
            
            # Start workflow
            handle = await temporal_env.client.start_workflow(
                OrderProcessingWorkflow.run,
                order_data,
                id="e2e-order-workflow-123",
                task_queue="e2e-test-queue",
                execution_timeout=timedelta(minutes=10)
            )
            
            # Monitor workflow progress
            status_checks = 0
            while status_checks < 10:  # Maximum checks to prevent infinite loop
                try:
                    status = await handle.query(OrderProcessingWorkflow.get_status)
                    print(f"Workflow status: {status}")
                    
                    if status.get("current_step") == "completed":
                        break
                        
                    await asyncio.sleep(1)
                    status_checks += 1
                except:
                    # Workflow might not be ready for queries yet
                    await asyncio.sleep(1)
                    status_checks += 1
            
            # Get final result
            result = await handle.result()
            
            # Verify end-to-end flow
            assert result.status == "COMPLETED"
            assert result.payment_transaction_id is not None
            assert result.inventory_reservation_id is not None
            assert result.shipping_tracking_number is not None
            assert result.total_amount == 125.00
    
    async def realistic_payment_activity(self, payment_data):
        """Realistic payment processing with delays"""
        await asyncio.sleep(2)  # Simulate external API call
        return {
            "status": "success",
            "transaction_id": f"txn_{payment_data['customer_id']}_123",
            "amount_charged": payment_data["amount"]
        }
    
    async def realistic_inventory_activity(self, items):
        """Realistic inventory processing with delays"""
        await asyncio.sleep(1.5)  # Simulate database operations
        return {
            "status": "reserved",
            "reservation_id": f"res_{len(items)}_456",
            "reserved_items": items
        }
    
    async def realistic_shipping_activity(self, shipping_data):
        """Realistic shipping processing with delays"""
        await asyncio.sleep(3)  # Simulate shipping partner API
        return {
            "status": "scheduled",
            "tracking_number": f"TRK{shipping_data['zip_code']}789",
            "estimated_delivery": "2024-01-15"
        }
```

## Test Data Management

### Test Factories

```python
# tests/factories.py
import factory
from datetime import datetime, timedelta
from decimal import Decimal

class OrderDataFactory(factory.Factory):
    """Factory for generating test order data"""
    
    class Meta:
        model = dict
    
    id = factory.Sequence(lambda n: f"order-{n}")
    customer_id = factory.Sequence(lambda n: f"customer-{n}")
    total_amount = factory.LazyFunction(lambda: Decimal(str(factory.Faker('pydecimal', left_digits=3, right_digits=2).generate())))
    created_at = factory.LazyFunction(datetime.utcnow)
    
    @factory.lazy_attribute
    def items(self):
        return [
            {
                "id": factory.Faker('uuid4').generate(),
                "name": factory.Faker('commerce_product_name').generate(),
                "sku": factory.Faker('bothify', text='SKU-###').generate(),
                "quantity": factory.Faker('random_int', min=1, max=5).generate(),
                "unit_price": float(factory.Faker('pydecimal', left_digits=2, right_digits=2).generate())
            }
            for _ in range(factory.Faker('random_int', min=1, max=3).generate())
        ]
    
    shipping_address = factory.SubFactory('tests.factories.AddressFactory')
    payment_method = "credit_card"
    payment_details = {"token": factory.Faker('uuid4')}

class AddressFactory(factory.Factory):
    """Factory for generating test addresses"""
    
    class Meta:
        model = dict
    
    street = factory.Faker('street_address')
    city = factory.Faker('city')
    state = factory.Faker('state_abbr')
    zip_code = factory.Faker('zipcode')
```

## CI/CD Integration

### GitHub Actions Test Configuration

```yaml
# .github/workflows/test.yml
name: Test Suite

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.9, 3.10, 3.11]
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install -r requirements-test.txt
    
    - name: Run unit tests
      run: |
        pytest tests/test_workflows.py tests/test_activities.py -v --cov=src --cov-report=xml
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml

  integration-tests:
    runs-on: ubuntu-latest
    needs: unit-tests
    
    services:
      temporal:
        image: temporalio/auto-setup:1.20.0
        ports:
          - 7233:7233
        env:
          - DB=postgresql
          - DB_PORT=5432
          - POSTGRES_USER=temporal
          - POSTGRES_PWD=temporal
          - POSTGRES_SEEDS=postgres
      
      postgres:
        image: postgres:13
        ports:
          - 5432:5432
        env:
          POSTGRES_PASSWORD: temporal
          POSTGRES_USER: temporal
          POSTGRES_DB: temporal
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: 3.11
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install -r requirements-test.txt
    
    - name: Wait for Temporal to be ready
      run: |
        sleep 30
        curl -f http://localhost:7233/ || exit 1
    
    - name: Run integration tests
      run: |
        pytest tests/test_api_integration.py tests/test_e2e.py -v
      env:
        TEMPORAL_SERVER_URL: localhost:7233
        TEMPORAL_NAMESPACE: default

  load-tests:
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: 3.11
    
    - name: Install dependencies
      run: |
        pip install locust
    
    - name: Run load tests
      run: |
        locust -f tests/locustfile.py --headless -u 10 -r 2 -t 60s --host http://localhost:8000
```

This comprehensive testing guide provides robust strategies for testing Temporal workflows, activities, and FastAPI integrations across unit, integration, load, and end-to-end testing scenarios.
