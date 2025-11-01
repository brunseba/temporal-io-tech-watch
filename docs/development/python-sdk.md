# Python SDK Guide

This document provides comprehensive guidance for using the Temporal Python SDK in enterprise environments, covering setup, configuration, best practices, and advanced features for building production-ready Temporal applications.

## Overview

The Temporal Python SDK enables developers to build workflows and activities using Python, providing a powerful and flexible foundation for orchestrating business processes. This guide focuses on enterprise-specific considerations including performance, reliability, observability, and maintainability.

## Installation and Setup

### Project Structure

```
temporal-python-project/
├── pyproject.toml              # Project configuration with uv
├── uv.lock                     # Dependency lock file
├── README.md
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml
├── src/
│   └── temporal_app/
│       ├── __init__.py
│       ├── activities/
│       │   ├── __init__.py
│       │   ├── base.py         # Base activity class
│       │   ├── payment.py      # Payment activities
│       │   ├── inventory.py    # Inventory activities
│       │   └── notification.py # Notification activities
│       ├── workflows/
│       │   ├── __init__.py
│       │   ├── base.py         # Base workflow class
│       │   ├── order_processing.py
│       │   └── user_onboarding.py
│       ├── models/
│       │   ├── __init__.py
│       │   ├── orders.py       # Order-related data models
│       │   └── users.py        # User-related data models
│       ├── workers/
│       │   ├── __init__.py
│       │   ├── main.py         # Main worker entry point
│       │   └── config.py       # Worker configuration
│       ├── clients/
│       │   ├── __init__.py
│       │   ├── temporal_client.py
│       │   └── external_apis.py
│       └── utils/
│           ├── __init__.py
│           ├── logging.py      # Logging configuration
│           ├── metrics.py      # Metrics utilities
│           └── config.py       # Application configuration
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── unit/
│   │   ├── test_activities.py
│   │   └── test_workflows.py
│   ├── integration/
│   │   └── test_workflows_integration.py
│   └── fixtures/
│       └── sample_data.py
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
└── k8s/
    ├── deployment.yaml
    ├── service.yaml
    └── configmap.yaml
```

### Dependencies Configuration

```toml
# pyproject.toml
[project]
name = "temporal-enterprise-app"
version = "1.0.0"
description = "Enterprise Temporal application"
authors = [
    {name = "DevOps Team", email = "devops@example.com"}
]
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.11"

dependencies = [
    # Temporal SDK
    "temporalio>=1.18.2",
    
    # Async HTTP client
    "httpx>=0.25.0",
    
    # Data validation and serialization
    "pydantic>=2.5.0",
    "pydantic-settings>=2.1.0",
    
    # Database
    "asyncpg>=0.29.0",
    "sqlalchemy[asyncio]>=2.0.0",
    "alembic>=1.13.0",
    
    # Observability
    "structlog>=23.2.0",
    "prometheus-client>=0.19.0",
    "opentelemetry-api>=1.21.0",
    "opentelemetry-sdk>=1.21.0",
    "opentelemetry-exporter-prometheus>=1.12.0",
    "opentelemetry-instrumentation-sqlalchemy>=0.42b0",
    
    # Configuration
    "python-dotenv>=1.0.0",
    
    # Utilities
    "tenacity>=8.2.0",
    "click>=8.1.0",
    "rich>=13.7.0",
]

[project.optional-dependencies]
dev = [
    # Testing
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",
    "pytest-cov>=4.0.0",
    "pytest-mock>=3.12.0",
    "factory-boy>=3.3.0",
    
    # Code quality
    "black>=23.11.0",
    "ruff>=0.1.6",
    "mypy>=1.7.0",
    "pre-commit>=3.6.0",
    
    # Documentation
    "mkdocs>=1.5.0",
    "mkdocs-material>=9.4.0",
    
    # Development tools
    "ipython>=8.17.0",
    "rich>=13.7.0",
]

[project.scripts]
temporal-worker = "temporal_app.workers.main:main"
temporal-client = "temporal_app.clients.temporal_client:cli"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

# Tool configurations
[tool.black]
line-length = 88
target-version = ['py311']
include = '\.pyi?$'
extend-exclude = '''
/(
  # directories
  \.eggs
  | \.git
  | \.hg
  | \.mypy_cache
  | \.tox
  | \.venv
  | build
  | dist
)/
'''

[tool.ruff]
target-version = "py311"
line-length = 88
select = [
    "E",   # pycodestyle errors
    "W",   # pycodestyle warnings
    "F",   # pyflakes
    "UP",  # pyupgrade
    "B",   # flake8-bugbear
    "SIM", # flake8-simplify
    "I",   # isort
    "N",   # pep8-naming
    "C4",  # flake8-comprehensions
    "PTH", # flake8-use-pathlib
]

[tool.mypy]
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
disallow_untyped_decorators = true

[[tool.mypy.overrides]]
module = "tests.*"
disallow_untyped_defs = false

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
addopts = [
    "-ra",
    "--strict-markers",
    "--strict-config",
    "--cov=temporal_app",
    "--cov-report=html",
    "--cov-report=term-missing",
]
markers = [
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "integration: marks tests as integration tests",
    "unit: marks tests as unit tests",
]
asyncio_mode = "auto"
```

## Base Classes and Utilities

### Base Activity Class

```python
# src/temporal_app/activities/base.py
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Type, TypeVar
from datetime import datetime

from temporalio import activity
from pydantic import BaseModel, ValidationError
from opentelemetry import trace

from ..utils.metrics import ActivityMetrics
from ..utils.logging import get_structured_logger

T = TypeVar('T', bound=BaseModel)

class BaseActivity(ABC):
    """Base class for all Temporal activities with enterprise features"""
    
    def __init__(self):
        self.logger = get_structured_logger(self.__class__.__name__)
        self.metrics = ActivityMetrics()
        self.tracer = trace.get_tracer(__name__)
    
    async def execute_with_instrumentation(
        self, 
        input_data: BaseModel,
        operation_name: Optional[str] = None
    ) -> Any:
        """Execute activity with comprehensive instrumentation"""
        
        operation_name = operation_name or self.__class__.__name__
        
        # Start metrics timer
        timer = self.metrics.start_timer(operation_name)
        
        # Start OpenTelemetry span
        with self.tracer.start_as_current_span(operation_name) as span:
            try:
                # Add span attributes
                span.set_attribute("activity.name", self.__class__.__name__)
                span.set_attribute("activity.input_type", type(input_data).__name__)
                
                # Log activity start
                self.logger.info(
                    "Activity started",
                    activity_name=self.__class__.__name__,
                    input_type=type(input_data).__name__,
                    workflow_id=activity.info().workflow_id,
                    activity_id=activity.info().activity_id
                )
                
                # Send heartbeat
                activity.heartbeat("Activity execution started")
                
                # Execute the actual activity logic
                result = await self.execute(input_data)
                
                # Log success
                self.logger.info(
                    "Activity completed successfully",
                    activity_name=self.__class__.__name__,
                    execution_time=timer.stop()
                )
                
                # Record success metrics
                self.metrics.record_success(operation_name)
                span.set_attribute("activity.status", "success")
                
                return result
                
            except ValidationError as e:
                # Handle validation errors
                self.logger.error(
                    "Activity validation error",
                    activity_name=self.__class__.__name__,
                    error=str(e),
                    execution_time=timer.stop()
                )
                
                self.metrics.record_error(operation_name, "validation_error")
                span.set_attribute("activity.status", "validation_error")
                span.record_exception(e)
                
                raise
                
            except Exception as e:
                # Handle all other errors
                self.logger.error(
                    "Activity execution failed",
                    activity_name=self.__class__.__name__,
                    error=str(e),
                    error_type=type(e).__name__,
                    execution_time=timer.stop()
                )
                
                self.metrics.record_error(operation_name, type(e).__name__)
                span.set_attribute("activity.status", "error")
                span.record_exception(e)
                
                raise
    
    @abstractmethod
    async def execute(self, input_data: BaseModel) -> Any:
        """Execute the activity logic - to be implemented by subclasses"""
        pass
    
    async def validate_input(self, input_data: Any, model_class: Type[T]) -> T:
        """Validate and parse input data using Pydantic model"""
        try:
            if isinstance(input_data, model_class):
                return input_data
            elif isinstance(input_data, dict):
                return model_class(**input_data)
            else:
                return model_class.model_validate(input_data)
        except ValidationError as e:
            self.logger.error(
                "Input validation failed",
                error=str(e),
                input_type=type(input_data).__name__
            )
            raise
    
    async def call_external_service(
        self,
        service_name: str,
        method: str,
        *args,
        **kwargs
    ) -> Any:
        """Call external service with retry and instrumentation"""
        
        with self.tracer.start_as_current_span(f"external_call_{service_name}") as span:
            span.set_attribute("service.name", service_name)
            span.set_attribute("service.method", method)
            
            try:
                # Implement your external service call logic here
                # This is a placeholder for demonstration
                result = await self._make_external_call(service_name, method, *args, **kwargs)
                
                span.set_attribute("external_call.status", "success")
                return result
                
            except Exception as e:
                span.set_attribute("external_call.status", "error")
                span.record_exception(e)
                
                self.logger.error(
                    "External service call failed",
                    service=service_name,
                    method=method,
                    error=str(e)
                )
                raise
    
    async def _make_external_call(self, service_name: str, method: str, *args, **kwargs) -> Any:
        """Placeholder for actual external service calls"""
        # Implement actual external service calling logic
        pass

# Activity decorator with base class integration
def enterprise_activity(name: Optional[str] = None):
    """Decorator for enterprise activities with built-in instrumentation"""
    def decorator(cls: Type[BaseActivity]):
        
        @activity.defn(name=name or cls.__name__)
        async def activity_wrapper(*args, **kwargs):
            instance = cls()
            
            # Assume first argument is the input data
            input_data = args[0] if args else kwargs.get('input_data')
            
            return await instance.execute_with_instrumentation(input_data)
        
        # Store original class for reference
        activity_wrapper._original_class = cls
        return activity_wrapper
    
    return decorator
```

### Base Workflow Class

```python
# src/temporal_app/workflows/base.py
import asyncio
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Type, TypeVar
from datetime import datetime, timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from pydantic import BaseModel

from ..utils.logging import get_structured_logger
from ..utils.metrics import WorkflowMetrics

T = TypeVar('T', bound=BaseModel)

class BaseWorkflow(ABC):
    """Base class for all Temporal workflows with enterprise features"""
    
    def __init__(self):
        self.logger = get_structured_logger(self.__class__.__name__)
        self.metrics = WorkflowMetrics()
        self._execution_started = workflow.now()
        self._steps_completed: set[str] = set()
        
    async def execute_with_instrumentation(self, input_data: BaseModel) -> Any:
        """Execute workflow with comprehensive instrumentation"""
        
        try:
            # Log workflow start
            workflow.logger.info(
                "Workflow started",
                workflow_name=self.__class__.__name__,
                workflow_id=workflow.info().workflow_id,
                run_id=workflow.info().run_id,
                input_type=type(input_data).__name__
            )
            
            # Execute the actual workflow logic
            result = await self.execute(input_data)
            
            # Calculate execution time
            execution_time = workflow.now() - self._execution_started
            
            # Log workflow completion
            workflow.logger.info(
                "Workflow completed successfully",
                workflow_name=self.__class__.__name__,
                execution_time=execution_time.total_seconds(),
                steps_completed=len(self._steps_completed)
            )
            
            return result
            
        except Exception as e:
            # Calculate execution time for failed workflow
            execution_time = workflow.now() - self._execution_started
            
            # Log workflow failure
            workflow.logger.error(
                "Workflow execution failed",
                workflow_name=self.__class__.__name__,
                error=str(e),
                error_type=type(e).__name__,
                execution_time=execution_time.total_seconds(),
                steps_completed=len(self._steps_completed)
            )
            
            raise
    
    @abstractmethod
    async def execute(self, input_data: BaseModel) -> Any:
        """Execute the workflow logic - to be implemented by subclasses"""
        pass
    
    async def execute_activity_step(
        self,
        activity_function: Any,
        input_data: Any,
        step_name: str,
        timeout: timedelta = timedelta(minutes=10),
        retry_policy: Optional[RetryPolicy] = None,
        heartbeat_timeout: Optional[timedelta] = None,
        task_queue: Optional[str] = None
    ) -> Any:
        """Execute an activity with standardized error handling and logging"""
        
        # Check if step was already completed (for replay safety)
        if step_name in self._steps_completed:
            workflow.logger.debug(f"Step '{step_name}' already completed, skipping")
            return
        
        # Default retry policy for enterprise activities
        if retry_policy is None:
            retry_policy = RetryPolicy(
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=60),
                maximum_attempts=3,
                non_retryable_error_types=[
                    "ValidationError",
                    "AuthenticationError",
                    "AuthorizationError"
                ]
            )
        
        try:
            workflow.logger.info(f"Starting activity step: {step_name}")
            
            result = await workflow.execute_activity(
                activity_function,
                input_data,
                start_to_close_timeout=timeout,
                retry_policy=retry_policy,
                heartbeat_timeout=heartbeat_timeout,
                task_queue=task_queue
            )
            
            # Mark step as completed
            self._steps_completed.add(step_name)
            
            workflow.logger.info(f"Completed activity step: {step_name}")
            return result
            
        except Exception as e:
            workflow.logger.error(
                f"Activity step failed: {step_name}",
                error=str(e),
                error_type=type(e).__name__
            )
            raise
    
    async def execute_parallel_activities(
        self,
        activities: Dict[str, tuple],  # step_name -> (activity_function, input_data, options)
        gather_exceptions: bool = True
    ) -> Dict[str, Any]:
        """Execute multiple activities in parallel"""
        
        workflow.logger.info(f"Starting {len(activities)} parallel activities")
        
        # Create tasks for all activities
        tasks = {}
        for step_name, (activity_func, input_data, options) in activities.items():
            task = workflow.execute_activity(
                activity_func,
                input_data,
                **options
            )
            tasks[step_name] = task
        
        # Wait for all tasks to complete
        if gather_exceptions:
            results = {}
            for step_name, task in tasks.items():
                try:
                    results[step_name] = await task
                    self._steps_completed.add(step_name)
                except Exception as e:
                    workflow.logger.error(f"Parallel activity failed: {step_name}", error=str(e))
                    results[step_name] = e
            return results
        else:
            # Use asyncio.gather for fail-fast behavior
            task_list = list(tasks.values())
            step_names = list(tasks.keys())
            
            results_list = await asyncio.gather(*task_list)
            
            # Mark all steps as completed
            for step_name in step_names:
                self._steps_completed.add(step_name)
            
            return dict(zip(step_names, results_list))
    
    async def wait_for_condition_with_timeout(
        self,
        condition: callable,
        timeout: timedelta,
        check_interval: timedelta = timedelta(seconds=1)
    ) -> bool:
        """Wait for a condition with timeout"""
        
        start_time = workflow.now()
        
        while workflow.now() - start_time < timeout:
            if condition():
                return True
            await asyncio.sleep(check_interval.total_seconds())
        
        return False
    
    def get_execution_metrics(self) -> Dict[str, Any]:
        """Get workflow execution metrics"""
        execution_time = workflow.now() - self._execution_started
        
        return {
            "workflow_name": self.__class__.__name__,
            "workflow_id": workflow.info().workflow_id,
            "run_id": workflow.info().run_id,
            "execution_time_seconds": execution_time.total_seconds(),
            "steps_completed": len(self._steps_completed),
            "completed_steps": list(self._steps_completed)
        }

# Workflow decorator with base class integration
def enterprise_workflow(name: Optional[str] = None):
    """Decorator for enterprise workflows with built-in instrumentation"""
    def decorator(cls: Type[BaseWorkflow]):
        
        @workflow.defn(name=name or cls.__name__)
        class WorkflowWrapper:
            async def run(self, *args, **kwargs):
                instance = cls()
                
                # Assume first argument is the input data
                input_data = args[0] if args else kwargs.get('input_data')
                
                return await instance.execute_with_instrumentation(input_data)
        
        # Store original class for reference
        WorkflowWrapper._original_class = cls
        return WorkflowWrapper
    
    return decorator
```

## Data Models and Validation

### Pydantic Models for Type Safety

```python
# src/temporal_app/models/orders.py
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, validator, root_validator

class OrderStatus(str, Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    PROCESSING = "processing"
    SHIPPED = "shipped"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"
    REFUNDED = "refunded"

class PaymentMethod(str, Enum):
    CREDIT_CARD = "credit_card"
    DEBIT_CARD = "debit_card"
    PAYPAL = "paypal"
    BANK_TRANSFER = "bank_transfer"

class Address(BaseModel):
    """Shipping/billing address model"""
    street: str = Field(..., min_length=1, max_length=255)
    city: str = Field(..., min_length=1, max_length=100)
    state: str = Field(..., min_length=2, max_length=50)
    zip_code: str = Field(..., regex=r'^\d{5}(-\d{4})?$')
    country: str = Field(default="US", min_length=2, max_length=2)
    
    class Config:
        schema_extra = {
            "example": {
                "street": "123 Main St",
                "city": "Anytown",
                "state": "CA",
                "zip_code": "12345",
                "country": "US"
            }
        }

class OrderItem(BaseModel):
    """Individual order item"""
    id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1, max_length=255)
    sku: str = Field(..., min_length=1, max_length=100)
    quantity: int = Field(..., gt=0, le=1000)
    unit_price: Decimal = Field(..., gt=0, max_digits=10, decimal_places=2)
    total_price: Optional[Decimal] = None
    
    @root_validator
    def calculate_total_price(cls, values):
        quantity = values.get('quantity')
        unit_price = values.get('unit_price')
        if quantity is not None and unit_price is not None:
            values['total_price'] = quantity * unit_price
        return values

class Order(BaseModel):
    """Complete order model"""
    id: str = Field(default_factory=lambda: str(uuid4()))
    customer_id: str = Field(..., min_length=1)
    items: List[OrderItem] = Field(..., min_items=1)
    shipping_address: Address
    billing_address: Optional[Address] = None
    payment_method: PaymentMethod
    payment_details: Dict[str, Any] = Field(default_factory=dict)
    
    subtotal: Optional[Decimal] = None
    tax_amount: Optional[Decimal] = None
    shipping_amount: Optional[Decimal] = None
    total_amount: Optional[Decimal] = None
    
    status: OrderStatus = OrderStatus.PENDING
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    
    notes: Optional[str] = Field(None, max_length=1000)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @root_validator
    def calculate_totals(cls, values):
        items = values.get('items', [])
        
        # Calculate subtotal
        subtotal = sum(item.total_price or Decimal('0') for item in items)
        values['subtotal'] = subtotal
        
        # Calculate tax (example: 8.5%)
        tax_rate = Decimal('0.085')
        tax_amount = subtotal * tax_rate
        values['tax_amount'] = tax_amount.quantize(Decimal('0.01'))
        
        # Calculate shipping (example: flat rate)
        shipping_amount = Decimal('9.99') if subtotal < 100 else Decimal('0')
        values['shipping_amount'] = shipping_amount
        
        # Calculate total
        total_amount = subtotal + tax_amount + shipping_amount
        values['total_amount'] = total_amount.quantize(Decimal('0.01'))
        
        return values
    
    @validator('billing_address', always=True)
    def set_billing_address(cls, v, values):
        if v is None:
            return values.get('shipping_address')
        return v

# Activity input/output models
class OrderValidationRequest(BaseModel):
    order: Order
    
class OrderValidationResult(BaseModel):
    is_valid: bool
    order_id: str
    validation_errors: List[str] = Field(default_factory=list)
    estimated_shipping_date: Optional[datetime] = None
    
class PaymentProcessingRequest(BaseModel):
    order_id: str
    amount: Decimal
    payment_method: PaymentMethod
    payment_details: Dict[str, Any]
    idempotency_key: str
    
class PaymentProcessingResult(BaseModel):
    success: bool
    transaction_id: Optional[str] = None
    error_message: Optional[str] = None
    payment_method_verified: bool = False
    
class ShippingRequest(BaseModel):
    order_id: str
    items: List[OrderItem]
    shipping_address: Address
    shipping_method: str = "standard"
    
class ShippingResult(BaseModel):
    success: bool
    tracking_number: Optional[str] = None
    estimated_delivery_date: Optional[datetime] = None
    shipping_cost: Optional[Decimal] = None
    carrier: Optional[str] = None

# Workflow result models
class OrderProcessingResult(BaseModel):
    order_id: str
    status: OrderStatus
    validation_result: Optional[OrderValidationResult] = None
    payment_result: Optional[PaymentProcessingResult] = None
    shipping_result: Optional[ShippingResult] = None
    processing_duration_seconds: Optional[float] = None
    completed_at: datetime = Field(default_factory=datetime.utcnow)
```

## Activity Implementation Examples

### Payment Processing Activity

```python
# src/temporal_app/activities/payment.py
import asyncio
from decimal import Decimal
from typing import Optional
import httpx
from temporalio import activity
from temporalio.exceptions import ApplicationError

from .base import BaseActivity, enterprise_activity
from ..models.orders import PaymentProcessingRequest, PaymentProcessingResult, PaymentMethod
from ..utils.config import get_settings

class PaymentProcessor(BaseActivity):
    """Payment processing activity with enterprise features"""
    
    def __init__(self):
        super().__init__()
        self.settings = get_settings()
        self.client = httpx.AsyncClient(
            timeout=30.0,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5)
        )
    
    async def execute(self, input_data: PaymentProcessingRequest) -> PaymentProcessingResult:
        """Process payment with comprehensive error handling"""
        
        # Validate input
        request = await self.validate_input(input_data, PaymentProcessingRequest)
        
        # Send heartbeat
        activity.heartbeat("Starting payment processing")
        
        try:
            # Verify payment method
            is_verified = await self._verify_payment_method(request)
            if not is_verified:
                return PaymentProcessingResult(
                    success=False,
                    error_message="Payment method verification failed",
                    payment_method_verified=False
                )
            
            # Process payment based on method
            if request.payment_method == PaymentMethod.CREDIT_CARD:
                result = await self._process_credit_card_payment(request)
            elif request.payment_method == PaymentMethod.PAYPAL:
                result = await self._process_paypal_payment(request)
            else:
                raise ApplicationError(
                    f"Unsupported payment method: {request.payment_method}",
                    type="UnsupportedPaymentMethod"
                )
            
            # Log successful payment
            self.logger.info(
                "Payment processed successfully",
                order_id=request.order_id,
                transaction_id=result.transaction_id,
                amount=str(request.amount)
            )
            
            return result
            
        except Exception as e:
            self.logger.error(
                "Payment processing failed",
                order_id=request.order_id,
                error=str(e),
                payment_method=request.payment_method
            )
            
            # Return structured error result
            return PaymentProcessingResult(
                success=False,
                error_message=str(e),
                payment_method_verified=is_verified if 'is_verified' in locals() else False
            )
    
    async def _verify_payment_method(self, request: PaymentProcessingRequest) -> bool:
        """Verify payment method details"""
        activity.heartbeat("Verifying payment method")
        
        try:
            # Simulate payment method verification
            await asyncio.sleep(0.1)  # Simulate API call
            
            # Add actual payment method verification logic here
            return True
            
        except Exception as e:
            self.logger.error(f"Payment method verification failed: {e}")
            return False
    
    async def _process_credit_card_payment(
        self, 
        request: PaymentProcessingRequest
    ) -> PaymentProcessingResult:
        """Process credit card payment"""
        activity.heartbeat("Processing credit card payment")
        
        # Prepare payment request
        payment_data = {
            "amount": str(request.amount),
            "currency": "USD",
            "payment_method": request.payment_details,
            "idempotency_key": request.idempotency_key,
            "metadata": {
                "order_id": request.order_id
            }
        }
        
        try:
            # Call external payment processor
            response = await self.call_external_service(
                "payment_processor",
                "charge",
                data=payment_data
            )
            
            if response.get("status") == "succeeded":
                return PaymentProcessingResult(
                    success=True,
                    transaction_id=response.get("id"),
                    payment_method_verified=True
                )
            else:
                return PaymentProcessingResult(
                    success=False,
                    error_message=response.get("error", "Payment failed"),
                    payment_method_verified=True
                )
                
        except Exception as e:
            raise ApplicationError(
                f"Credit card payment processing failed: {str(e)}",
                type="PaymentProcessingError"
            )
    
    async def _process_paypal_payment(
        self, 
        request: PaymentProcessingRequest
    ) -> PaymentProcessingResult:
        """Process PayPal payment"""
        activity.heartbeat("Processing PayPal payment")
        
        # Implement PayPal-specific payment logic
        try:
            # Simulate PayPal API call
            await asyncio.sleep(0.2)
            
            return PaymentProcessingResult(
                success=True,
                transaction_id=f"pp_{request.idempotency_key}",
                payment_method_verified=True
            )
            
        except Exception as e:
            raise ApplicationError(
                f"PayPal payment processing failed: {str(e)}",
                type="PaymentProcessingError"
            )

# Register the activity
@enterprise_activity("process_payment")
class ProcessPaymentActivity(PaymentProcessor):
    pass
```

### Inventory Management Activity

```python
# src/temporal_app/activities/inventory.py
import asyncio
from typing import Dict, List
from temporalio import activity
from temporalio.exceptions import ApplicationError

from .base import BaseActivity, enterprise_activity
from ..models.orders import OrderItem
from ..utils.database import get_database_connection

class InventoryManager(BaseActivity):
    """Inventory management activity"""
    
    async def execute(self, order_items: List[OrderItem]) -> Dict[str, bool]:
        """Check and reserve inventory for order items"""
        
        activity.heartbeat("Starting inventory check")
        
        results = {}
        
        try:
            async with get_database_connection() as db:
                for item in order_items:
                    # Check availability
                    available_quantity = await self._check_inventory(db, item.sku)
                    
                    if available_quantity >= item.quantity:
                        # Reserve inventory
                        success = await self._reserve_inventory(
                            db, item.sku, item.quantity
                        )
                        results[item.sku] = success
                    else:
                        self.logger.warning(
                            "Insufficient inventory",
                            sku=item.sku,
                            requested=item.quantity,
                            available=available_quantity
                        )
                        results[item.sku] = False
                
                # Check if all items were successfully reserved
                if not all(results.values()):
                    # Rollback reservations for failed order
                    await self._rollback_reservations(db, order_items, results)
                    raise ApplicationError(
                        "Insufficient inventory for some items",
                        type="InsufficientInventory",
                        details={"failed_items": [sku for sku, success in results.items() if not success]}
                    )
                
                activity.heartbeat("Inventory reservation completed")
                return results
                
        except Exception as e:
            self.logger.error(f"Inventory management failed: {e}")
            raise
    
    async def _check_inventory(self, db, sku: str) -> int:
        """Check available inventory for SKU"""
        query = "SELECT available_quantity FROM inventory WHERE sku = $1"
        result = await db.fetchval(query, sku)
        return result or 0
    
    async def _reserve_inventory(self, db, sku: str, quantity: int) -> bool:
        """Reserve inventory for SKU"""
        query = """
        UPDATE inventory 
        SET available_quantity = available_quantity - $2,
            reserved_quantity = reserved_quantity + $2
        WHERE sku = $1 AND available_quantity >= $2
        """
        result = await db.execute(query, sku, quantity)
        return result == "UPDATE 1"
    
    async def _rollback_reservations(self, db, order_items: List[OrderItem], results: Dict[str, bool]):
        """Rollback successful reservations"""
        for item in order_items:
            if results.get(item.sku, False):
                query = """
                UPDATE inventory 
                SET available_quantity = available_quantity + $2,
                    reserved_quantity = reserved_quantity - $2
                WHERE sku = $1
                """
                await db.execute(query, item.sku, item.quantity)

@enterprise_activity("reserve_inventory")
class ReserveInventoryActivity(InventoryManager):
    pass
```

## Workflow Implementation Example

### Order Processing Workflow

```python
# src/temporal_app/workflows/order_processing.py
from datetime import timedelta
from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError

from .base import BaseWorkflow, enterprise_workflow
from ..models.orders import (
    Order, OrderProcessingResult, OrderStatus,
    OrderValidationRequest, PaymentProcessingRequest, ShippingRequest
)
from ..activities.payment import ProcessPaymentActivity
from ..activities.inventory import ReserveInventoryActivity

class OrderProcessingWorkflow(BaseWorkflow):
    """Enterprise order processing workflow with comprehensive error handling"""
    
    async def execute(self, order: Order) -> OrderProcessingResult:
        """Execute order processing workflow"""
        
        result = OrderProcessingResult(
            order_id=order.id,
            status=OrderStatus.PENDING
        )
        
        try:
            # Step 1: Validate order
            validation_result = await self.execute_activity_step(
                self._validate_order,
                OrderValidationRequest(order=order),
                step_name="validate_order",
                timeout=timedelta(minutes=5)
            )
            result.validation_result = validation_result
            
            if not validation_result.is_valid:
                result.status = OrderStatus.CANCELLED
                raise ApplicationError(
                    "Order validation failed",
                    type="OrderValidationError",
                    details={"errors": validation_result.validation_errors}
                )
            
            # Step 2: Reserve inventory
            inventory_result = await self.execute_activity_step(
                ReserveInventoryActivity,
                order.items,
                step_name="reserve_inventory",
                timeout=timedelta(minutes=10)
            )
            
            # Step 3: Process payment
            payment_request = PaymentProcessingRequest(
                order_id=order.id,
                amount=order.total_amount,
                payment_method=order.payment_method,
                payment_details=order.payment_details,
                idempotency_key=f"payment_{order.id}"
            )
            
            payment_result = await self.execute_activity_step(
                ProcessPaymentActivity,
                payment_request,
                step_name="process_payment",
                timeout=timedelta(minutes=15),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=2),
                    maximum_interval=timedelta(minutes=1),
                    maximum_attempts=3,
                    non_retryable_error_types=["InsufficientFunds", "InvalidPaymentMethod"]
                )
            )
            result.payment_result = payment_result
            
            if not payment_result.success:
                # Payment failed - release inventory
                await self._compensate_inventory_reservation(order.items)
                result.status = OrderStatus.CANCELLED
                raise ApplicationError(
                    "Payment processing failed",
                    type="PaymentError",
                    details={"error": payment_result.error_message}
                )
            
            # Step 4: Create shipping label
            shipping_request = ShippingRequest(
                order_id=order.id,
                items=order.items,
                shipping_address=order.shipping_address
            )
            
            shipping_result = await self.execute_activity_step(
                self._create_shipping_label,
                shipping_request,
                step_name="create_shipping",
                timeout=timedelta(minutes=10)
            )
            result.shipping_result = shipping_result
            
            # Step 5: Send confirmation notifications
            await self.execute_activity_step(
                self._send_order_confirmation,
                {
                    "order_id": order.id,
                    "customer_id": order.customer_id,
                    "payment_result": payment_result,
                    "shipping_result": shipping_result
                },
                step_name="send_confirmation",
                timeout=timedelta(minutes=5)
            )
            
            # Mark order as confirmed
            result.status = OrderStatus.CONFIRMED
            
            # Calculate processing duration
            execution_metrics = self.get_execution_metrics()
            result.processing_duration_seconds = execution_metrics["execution_time_seconds"]
            
            workflow.logger.info(
                "Order processing completed successfully",
                order_id=order.id,
                processing_time=result.processing_duration_seconds
            )
            
            return result
            
        except Exception as e:
            # Handle workflow failure
            await self._handle_workflow_failure(order, result, e)
            raise
    
    async def _validate_order(self, request: OrderValidationRequest):
        """Validate order details"""
        # This would be implemented as a separate activity
        pass
    
    async def _create_shipping_label(self, request: ShippingRequest):
        """Create shipping label"""
        # This would be implemented as a separate activity
        pass
    
    async def _send_order_confirmation(self, data: dict):
        """Send order confirmation"""
        # This would be implemented as a separate activity
        pass
    
    async def _compensate_inventory_reservation(self, items):
        """Release reserved inventory (compensation)"""
        try:
            await workflow.execute_activity(
                self._release_inventory,
                items,
                start_to_close_timeout=timedelta(minutes=5)
            )
        except Exception as e:
            workflow.logger.error(f"Failed to release inventory: {e}")
    
    async def _release_inventory(self, items):
        """Release inventory activity"""
        # This would be implemented as a separate activity
        pass
    
    async def _handle_workflow_failure(self, order: Order, result: OrderProcessingResult, error: Exception):
        """Handle workflow failure with proper cleanup"""
        workflow.logger.error(
            "Order processing workflow failed",
            order_id=order.id,
            error=str(error),
            error_type=type(error).__name__
        )
        
        # Attempt to send failure notification
        try:
            await workflow.execute_activity(
                self._send_failure_notification,
                {
                    "order_id": order.id,
                    "customer_id": order.customer_id,
                    "error": str(error)
                },
                start_to_close_timeout=timedelta(minutes=2)
            )
        except Exception as notification_error:
            workflow.logger.error(f"Failed to send failure notification: {notification_error}")

# Register the workflow
@enterprise_workflow("order_processing")
class OrderProcessingWorkflowRegistered(OrderProcessingWorkflow):
    pass
```

## Worker Configuration and Startup

### Worker Implementation

```python
# src/temporal_app/workers/main.py
import asyncio
import signal
import sys
from contextlib import asynccontextmanager
from typing import Optional

import click
from temporalio.client import Client
from temporalio.worker import Worker

from ..activities.payment import ProcessPaymentActivity
from ..activities.inventory import ReserveInventoryActivity
from ..workflows.order_processing import OrderProcessingWorkflowRegistered
from ..utils.config import get_settings
from ..utils.logging import setup_logging
from ..utils.metrics import setup_metrics

class TemporalWorker:
    """Enterprise Temporal worker with comprehensive configuration"""
    
    def __init__(self, settings):
        self.settings = settings
        self.client: Optional[Client] = None
        self.worker: Optional[Worker] = None
        self.running = False
    
    async def start(self):
        """Start the Temporal worker"""
        
        # Setup logging and metrics
        setup_logging(self.settings.log_level)
        setup_metrics()
        
        # Connect to Temporal server
        self.client = await Client.connect(
            self.settings.temporal_server_url,
            namespace=self.settings.temporal_namespace,
            tls=self.settings.temporal_tls_config if self.settings.temporal_tls_enabled else False
        )
        
        # Create worker
        self.worker = Worker(
            self.client,
            task_queue=self.settings.task_queue,
            workflows=[OrderProcessingWorkflowRegistered],
            activities=[
                ProcessPaymentActivity,
                ReserveInventoryActivity,
            ],
            max_concurrent_activities=self.settings.max_concurrent_activities,
            max_concurrent_workflows=self.settings.max_concurrent_workflows,
            max_concurrent_local_activities=self.settings.max_concurrent_local_activities,
        )
        
        print(f"Starting Temporal worker on task queue: {self.settings.task_queue}")
        print(f"Connected to: {self.settings.temporal_server_url}")
        print(f"Namespace: {self.settings.temporal_namespace}")
        
        # Start worker
        self.running = True
        await self.worker.run()
    
    async def stop(self):
        """Stop the Temporal worker gracefully"""
        if self.running and self.worker:
            print("Shutting down Temporal worker...")
            self.running = False
            await self.worker.shutdown()
        
        if self.client:
            await self.client.close()

# Global worker instance
worker_instance = None

async def create_worker():
    """Create and configure worker instance"""
    settings = get_settings()
    worker = TemporalWorker(settings)
    return worker

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print(f"\nReceived signal {signum}. Initiating graceful shutdown...")
    if worker_instance:
        # Create a new event loop if needed
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        loop.run_until_complete(worker_instance.stop())
    sys.exit(0)

@click.command()
@click.option('--task-queue', default='temporal-product-queue', help='Task queue name')
@click.option('--log-level', default='INFO', help='Logging level')
@click.option('--max-concurrent-activities', default=100, type=int, help='Max concurrent activities')
@click.option('--max-concurrent-workflows', default=100, type=int, help='Max concurrent workflows')
def main(task_queue: str, log_level: str, max_concurrent_activities: int, max_concurrent_workflows: int):
    """Start the Temporal worker"""
    global worker_instance
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    async def run_worker():
        global worker_instance
        
        # Override settings with CLI arguments
        settings = get_settings()
        settings.task_queue = task_queue
        settings.log_level = log_level
        settings.max_concurrent_activities = max_concurrent_activities
        settings.max_concurrent_workflows = max_concurrent_workflows
        
        worker_instance = TemporalWorker(settings)
        
        try:
            await worker_instance.start()
        except KeyboardInterrupt:
            print("\nReceived interrupt signal. Shutting down...")
        except Exception as e:
            print(f"Worker error: {e}")
            raise
        finally:
            if worker_instance:
                await worker_instance.stop()
    
    # Run the worker
    asyncio.run(run_worker())

if __name__ == "__main__":
    main()
```

## Configuration Management

### Settings Configuration

```python
# src/temporal_app/utils/config.py
from functools import lru_cache
from typing import Optional, Dict, Any
from pydantic import BaseSettings, Field

class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # Temporal configuration
    temporal_server_url: str = Field(default="localhost:7233", env="TEMPORAL_SERVER_URL")
    temporal_namespace: str = Field(default="default", env="TEMPORAL_NAMESPACE")
    temporal_tls_enabled: bool = Field(default=False, env="TEMPORAL_TLS_ENABLED")
    temporal_tls_config: Optional[Dict[str, Any]] = None
    
    # Worker configuration
    task_queue: str = Field(default="temporal-product-queue", env="TASK_QUEUE")
    max_concurrent_activities: int = Field(default=100, env="MAX_CONCURRENT_ACTIVITIES")
    max_concurrent_workflows: int = Field(default=100, env="MAX_CONCURRENT_WORKFLOWS")
    max_concurrent_local_activities: int = Field(default=100, env="MAX_CONCURRENT_LOCAL_ACTIVITIES")
    
    # Database configuration
    database_url: str = Field(..., env="DATABASE_URL")
    database_pool_size: int = Field(default=10, env="DATABASE_POOL_SIZE")
    database_max_overflow: int = Field(default=20, env="DATABASE_MAX_OVERFLOW")
    
    # External services
    payment_processor_url: str = Field(..., env="PAYMENT_PROCESSOR_URL")
    payment_processor_api_key: str = Field(..., env="PAYMENT_PROCESSOR_API_KEY")
    
    # Logging configuration
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="json", env="LOG_FORMAT")
    
    # Metrics configuration
    metrics_port: int = Field(default=8080, env="METRICS_PORT")
    metrics_enabled: bool = Field(default=True, env="METRICS_ENABLED")
    
    # Application configuration
    environment: str = Field(default="development", env="ENVIRONMENT")
    debug: bool = Field(default=False, env="DEBUG")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()
```

This comprehensive Python SDK guide provides enterprise-ready patterns and practices for building robust Temporal applications with proper error handling, observability, and maintainability.
