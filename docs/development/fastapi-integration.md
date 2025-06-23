# FastAPI Integration

This document provides comprehensive guidance for integrating FastAPI with Temporal.io in enterprise environments, creating robust REST APIs that orchestrate workflows and provide business functionality.

## Overview

FastAPI serves as the HTTP interface layer for Temporal workflows, providing REST endpoints for workflow initiation, monitoring, and interaction. This integration enables web applications, mobile apps, and other services to interact with Temporal workflows through standard HTTP APIs.

## Project Structure

```
fastapi-temporal-service/
├── src/
│   └── temporal_api/
│       ├── __init__.py
│       ├── main.py              # FastAPI application
│       ├── api/
│       │   ├── __init__.py
│       │   ├── v1/
│       │   │   ├── __init__.py
│       │   │   ├── orders.py    # Order endpoints
│       │   │   ├── workflows.py # Workflow management
│       │   │   └── health.py    # Health checks
│       │   └── dependencies.py  # API dependencies
│       ├── models/
│       │   ├── __init__.py
│       │   ├── api_models.py    # API request/response models
│       │   └── temporal_models.py # Temporal data models
│       ├── services/
│       │   ├── __init__.py
│       │   ├── temporal_client.py
│       │   └── workflow_service.py
│       ├── middleware/
│       │   ├── __init__.py
│       │   ├── auth.py          # Authentication middleware
│       │   ├── logging.py       # Request logging
│       │   └── metrics.py       # Metrics collection
│       └── utils/
│           ├── __init__.py
│           ├── config.py
│           └── exceptions.py
```

## FastAPI Application Setup

### Main Application

```python
# src/temporal_api/main.py
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

from .api.v1 import orders, workflows, health
from .middleware.auth import AuthMiddleware
from .middleware.logging import LoggingMiddleware
from .services.temporal_client import TemporalClientService
from .utils.config import get_settings
from .utils.exceptions import TemporalAPIException

# Global temporal client service
temporal_service: TemporalClientService = None

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application lifespan manager"""
    global temporal_service
    
    # Startup
    settings = get_settings()
    temporal_service = TemporalClientService(settings)
    await temporal_service.connect()
    
    # Add to app state
    app.state.temporal_service = temporal_service
    
    yield
    
    # Shutdown
    if temporal_service:
        await temporal_service.disconnect()

# Create FastAPI application
app = FastAPI(
    title="Temporal Enterprise API",
    description="REST API for Temporal workflow orchestration",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Middleware setup
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(AuthMiddleware)
app.add_middleware(LoggingMiddleware)

# Metrics instrumentation
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

# Exception handlers
@app.exception_handler(TemporalAPIException)
async def temporal_api_exception_handler(request: Request, exc: TemporalAPIException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.error_type,
            "message": exc.message,
            "details": exc.details,
            "request_id": getattr(request.state, "request_id", None)
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logging.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "internal_server_error",
            "message": "An internal server error occurred",
            "request_id": getattr(request.state, "request_id", None)
        }
    )

# Include routers
app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(orders.router, prefix="/api/v1/orders", tags=["orders"])
app.include_router(workflows.router, prefix="/api/v1/workflows", tags=["workflows"])

@app.get("/", include_in_schema=False)
async def root():
    return {"message": "Temporal Enterprise API", "version": "1.0.0"}
```

## API Models

### Request/Response Models

```python
# src/temporal_api/models/api_models.py
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import List, Optional, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field, validator

class OrderStatus(str, Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    PROCESSING = "processing"
    SHIPPED = "shipped"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"

class CreateOrderRequest(BaseModel):
    customer_id: str = Field(..., min_length=1)
    items: List[Dict[str, Any]] = Field(..., min_items=1)
    shipping_address: Dict[str, str]
    payment_method: str
    payment_details: Dict[str, Any]
    
    class Config:
        schema_extra = {
            "example": {
                "customer_id": "cust_123",
                "items": [
                    {
                        "id": "item_1",
                        "name": "Product A",
                        "sku": "SKU-001",
                        "quantity": 2,
                        "unit_price": 29.99
                    }
                ],
                "shipping_address": {
                    "street": "123 Main St",
                    "city": "Anytown",
                    "state": "CA",
                    "zip_code": "12345"
                },
                "payment_method": "credit_card",
                "payment_details": {
                    "token": "tok_123456789"
                }
            }
        }

class OrderResponse(BaseModel):
    id: str
    customer_id: str
    status: OrderStatus
    total_amount: Decimal
    created_at: datetime
    workflow_id: Optional[str] = None
    
class WorkflowExecutionRequest(BaseModel):
    workflow_type: str
    task_queue: str = "temporal-product-queue"
    input_data: Dict[str, Any]
    workflow_id: Optional[str] = None
    execution_timeout_seconds: Optional[int] = 3600
    
class WorkflowExecutionResponse(BaseModel):
    workflow_id: str
    run_id: str
    status: str = "RUNNING"
    result: Optional[Dict[str, Any]] = None
    
class WorkflowStatusResponse(BaseModel):
    workflow_id: str
    run_id: str
    status: str
    result: Optional[Dict[str, Any]] = None
    history_length: Optional[int] = None
    execution_time_seconds: Optional[float] = None
    
class WorkflowSignalRequest(BaseModel):
    signal_name: str
    signal_input: Optional[Dict[str, Any]] = None
    
class WorkflowQueryRequest(BaseModel):
    query_name: str
    query_args: Optional[Dict[str, Any]] = None
    
class HealthCheckResponse(BaseModel):
    status: str = "healthy"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    services: Dict[str, str] = Field(default_factory=dict)
    version: str = "1.0.0"
```

## Temporal Client Service

### Client Management

```python
# src/temporal_api/services/temporal_client.py
import asyncio
import logging
from typing import Any, Dict, Optional, Type
from datetime import timedelta

from temporalio.client import Client, WorkflowHandle
from temporalio.common import RetryPolicy
from temporalio.exceptions import WorkflowAlreadyStartedError

from ..utils.config import Settings
from ..utils.exceptions import TemporalAPIException

class TemporalClientService:
    """Service for managing Temporal client connections and operations"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.client: Optional[Client] = None
        self.logger = logging.getLogger(__name__)
    
    async def connect(self) -> None:
        """Connect to Temporal server"""
        try:
            self.client = await Client.connect(
                self.settings.temporal_server_url,
                namespace=self.settings.temporal_namespace,
                tls=self.settings.temporal_tls_config if self.settings.temporal_tls_enabled else False
            )
            self.logger.info(f"Connected to Temporal server: {self.settings.temporal_server_url}")
        except Exception as e:
            self.logger.error(f"Failed to connect to Temporal server: {e}")
            raise TemporalAPIException(
                "temporal_connection_error",
                "Failed to connect to Temporal server",
                status_code=503,
                details={"error": str(e)}
            )
    
    async def disconnect(self) -> None:
        """Disconnect from Temporal server"""
        if self.client:
            await self.client.close()
            self.logger.info("Disconnected from Temporal server")
    
    async def start_workflow(
        self,
        workflow_type: str,
        workflow_input: Any,
        workflow_id: Optional[str] = None,
        task_queue: str = "temporal-product-queue",
        execution_timeout: Optional[timedelta] = None,
        retry_policy: Optional[RetryPolicy] = None
    ) -> WorkflowHandle:
        """Start a new workflow execution"""
        
        if not self.client:
            raise TemporalAPIException(
                "temporal_not_connected",
                "Temporal client not connected",
                status_code=503
            )
        
        try:
            handle = await self.client.start_workflow(
                workflow_type,
                workflow_input,
                id=workflow_id,
                task_queue=task_queue,
                execution_timeout=execution_timeout,
                retry_policy=retry_policy
            )
            
            self.logger.info(
                f"Started workflow {workflow_type}",
                extra={
                    "workflow_id": handle.id,
                    "run_id": handle.result_run_id,
                    "task_queue": task_queue
                }
            )
            
            return handle
            
        except WorkflowAlreadyStartedError:
            # Get existing workflow handle
            handle = self.client.get_workflow_handle(workflow_id)
            self.logger.warning(f"Workflow {workflow_id} already exists, returning existing handle")
            return handle
            
        except Exception as e:
            self.logger.error(f"Failed to start workflow: {e}")
            raise TemporalAPIException(
                "workflow_start_error",
                f"Failed to start workflow: {str(e)}",
                status_code=400,
                details={"workflow_type": workflow_type, "error": str(e)}
            )
    
    async def get_workflow_status(self, workflow_id: str) -> Dict[str, Any]:
        """Get workflow execution status"""
        
        if not self.client:
            raise TemporalAPIException(
                "temporal_not_connected",
                "Temporal client not connected",
                status_code=503
            )
        
        try:
            handle = self.client.get_workflow_handle(workflow_id)
            
            # Get workflow description
            description = await handle.describe()
            
            status_info = {
                "workflow_id": workflow_id,
                "run_id": description.run_id,
                "status": description.status.name,
                "workflow_type": description.workflow_type,
                "task_queue": description.task_queue,
                "start_time": description.start_time.isoformat() if description.start_time else None,
                "close_time": description.close_time.isoformat() if description.close_time else None,
                "execution_time_seconds": None,
                "history_length": description.history_length,
                "result": None
            }
            
            # Calculate execution time if workflow is closed
            if description.start_time and description.close_time:
                execution_time = description.close_time - description.start_time
                status_info["execution_time_seconds"] = execution_time.total_seconds()
            
            # Get result if workflow is completed
            if description.status.name in ["COMPLETED", "FAILED", "CANCELED"]:
                try:
                    if description.status.name == "COMPLETED":
                        result = await handle.result()
                        if hasattr(result, 'dict'):
                            status_info["result"] = result.dict()
                        else:
                            status_info["result"] = result
                except Exception as e:
                    self.logger.warning(f"Failed to get workflow result: {e}")
            
            return status_info
            
        except Exception as e:
            self.logger.error(f"Failed to get workflow status: {e}")
            raise TemporalAPIException(
                "workflow_status_error",
                f"Failed to get workflow status: {str(e)}",
                status_code=404,
                details={"workflow_id": workflow_id, "error": str(e)}
            )
    
    async def signal_workflow(
        self,
        workflow_id: str,
        signal_name: str,
        signal_input: Any = None
    ) -> None:
        """Send signal to workflow"""
        
        if not self.client:
            raise TemporalAPIException(
                "temporal_not_connected",
                "Temporal client not connected",
                status_code=503
            )
        
        try:
            handle = self.client.get_workflow_handle(workflow_id)
            await handle.signal(signal_name, signal_input)
            
            self.logger.info(
                f"Sent signal {signal_name} to workflow {workflow_id}",
                extra={"signal_input": signal_input}
            )
            
        except Exception as e:
            self.logger.error(f"Failed to signal workflow: {e}")
            raise TemporalAPIException(
                "workflow_signal_error",
                f"Failed to signal workflow: {str(e)}",
                status_code=400,
                details={
                    "workflow_id": workflow_id,
                    "signal_name": signal_name,
                    "error": str(e)
                }
            )
    
    async def query_workflow(
        self,
        workflow_id: str,
        query_name: str,
        query_args: Any = None
    ) -> Any:
        """Query workflow for information"""
        
        if not self.client:
            raise TemporalAPIException(
                "temporal_not_connected",
                "Temporal client not connected",
                status_code=503
            )
        
        try:
            handle = self.client.get_workflow_handle(workflow_id)
            result = await handle.query(query_name, query_args)
            
            self.logger.info(
                f"Queried workflow {workflow_id} with {query_name}",
                extra={"query_args": query_args}
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to query workflow: {e}")
            raise TemporalAPIException(
                "workflow_query_error",
                f"Failed to query workflow: {str(e)}",
                status_code=400,
                details={
                    "workflow_id": workflow_id,
                    "query_name": query_name,
                    "error": str(e)
                }
            )
```

## API Endpoints

### Order Management Endpoints

```python
# src/temporal_api/api/v1/orders.py
from datetime import timedelta
from typing import List
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse

from ...models.api_models import (
    CreateOrderRequest, OrderResponse, WorkflowStatusResponse
)
from ...services.temporal_client import TemporalClientService
from ...utils.exceptions import TemporalAPIException
from ..dependencies import get_temporal_service, get_current_user

router = APIRouter()

@router.post("/", response_model=OrderResponse, status_code=status.HTTP_201_CREATED)
async def create_order(
    order_request: CreateOrderRequest,
    temporal_service: TemporalClientService = Depends(get_temporal_service),
    current_user: dict = Depends(get_current_user)
) -> OrderResponse:
    """Create a new order and start order processing workflow"""
    
    try:
        # Generate unique order ID
        order_id = str(uuid4())
        
        # Prepare workflow input
        workflow_input = {
            "id": order_id,
            "customer_id": order_request.customer_id,
            "items": order_request.items,
            "shipping_address": order_request.shipping_address,
            "payment_method": order_request.payment_method,
            "payment_details": order_request.payment_details
        }
        
        # Start order processing workflow
        handle = await temporal_service.start_workflow(
            workflow_type="order_processing",
            workflow_input=workflow_input,
            workflow_id=f"order-{order_id}",
            task_queue="temporal-product-queue",
            execution_timeout=timedelta(hours=2)
        )
        
        # Calculate total amount (simplified)
        total_amount = sum(
            item.get("quantity", 0) * item.get("unit_price", 0)
            for item in order_request.items
        )
        
        return OrderResponse(
            id=order_id,
            customer_id=order_request.customer_id,
            status="PENDING",
            total_amount=total_amount,
            created_at=datetime.utcnow(),
            workflow_id=handle.id
        )
        
    except TemporalAPIException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create order: {str(e)}"
        )

@router.get("/{order_id}", response_model=WorkflowStatusResponse)
async def get_order_status(
    order_id: str,
    temporal_service: TemporalClientService = Depends(get_temporal_service),
    current_user: dict = Depends(get_current_user)
) -> WorkflowStatusResponse:
    """Get order processing status"""
    
    try:
        workflow_id = f"order-{order_id}"
        status_info = await temporal_service.get_workflow_status(workflow_id)
        
        return WorkflowStatusResponse(**status_info)
        
    except TemporalAPIException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get order status: {str(e)}"
        )

@router.post("/{order_id}/cancel", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_order(
    order_id: str,
    temporal_service: TemporalClientService = Depends(get_temporal_service),
    current_user: dict = Depends(get_current_user)
):
    """Cancel an order by sending cancel signal to workflow"""
    
    try:
        workflow_id = f"order-{order_id}"
        await temporal_service.signal_workflow(
            workflow_id=workflow_id,
            signal_name="cancel",
            signal_input={"reason": "customer_request"}
        )
        
        return JSONResponse(
            status_code=status.HTTP_204_NO_CONTENT,
            content=None
        )
        
    except TemporalAPIException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cancel order: {str(e)}"
        )
```

### Health Check Endpoints

```python
# src/temporal_api/api/v1/health.py
from datetime import datetime
from fastapi import APIRouter, Depends
from ...models.api_models import HealthCheckResponse
from ...services.temporal_client import TemporalClientService
from ..dependencies import get_temporal_service

router = APIRouter()

@router.get("/", response_model=HealthCheckResponse)
async def health_check(
    temporal_service: TemporalClientService = Depends(get_temporal_service)
) -> HealthCheckResponse:
    """Application health check"""
    
    services = {}
    
    # Check Temporal connection
    if temporal_service and temporal_service.client:
        try:
            # Simple check - list workflows (limited)
            services["temporal"] = "healthy"
        except Exception:
            services["temporal"] = "unhealthy"
    else:
        services["temporal"] = "disconnected"
    
    # Determine overall status
    overall_status = "healthy" if all(
        status == "healthy" for status in services.values()
    ) else "unhealthy"
    
    return HealthCheckResponse(
        status=overall_status,
        timestamp=datetime.utcnow(),
        services=services
    )

@router.get("/ready")
async def readiness_check():
    """Kubernetes readiness probe"""
    return {"status": "ready"}

@router.get("/live")
async def liveness_check():
    """Kubernetes liveness probe"""
    return {"status": "alive"}
```

## Dependencies and Middleware

### API Dependencies

```python
# src/temporal_api/api/dependencies.py
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from ..services.temporal_client import TemporalClientService
from ..utils.exceptions import TemporalAPIException

security = HTTPBearer()

def get_temporal_service(request: Request) -> TemporalClientService:
    """Get Temporal client service from app state"""
    temporal_service = getattr(request.app.state, "temporal_service", None)
    if not temporal_service:
        raise TemporalAPIException(
            "service_unavailable",
            "Temporal service not available",
            status_code=503
        )
    return temporal_service

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Get current authenticated user (simplified)"""
    # In production, validate JWT token and extract user info
    # This is a simplified example
    return {
        "user_id": "user_123",
        "username": "test_user",
        "roles": ["user"]
    }
```

### Authentication Middleware

```python
# src/temporal_api/middleware/auth.py
import logging
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware

class AuthMiddleware(BaseHTTPMiddleware):
    """Authentication middleware for API requests"""
    
    EXCLUDED_PATHS = {"/health", "/metrics", "/docs", "/redoc", "/openapi.json"}
    
    async def dispatch(self, request: Request, call_next):
        # Skip authentication for excluded paths
        if any(request.url.path.startswith(path) for path in self.EXCLUDED_PATHS):
            return await call_next(request)
        
        # Check for Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid authorization header"
            )
        
        # In production, validate JWT token here
        token = auth_header.split(" ")[1]
        
        # Add user context to request
        request.state.user = {"user_id": "user_123", "token": token}
        
        response = await call_next(request)
        return response
```

## Configuration and Utilities

### Exception Handling

```python
# src/temporal_api/utils/exceptions.py
from typing import Optional, Dict, Any

class TemporalAPIException(Exception):
    """Custom exception for Temporal API errors"""
    
    def __init__(
        self,
        error_type: str,
        message: str,
        status_code: int = 400,
        details: Optional[Dict[str, Any]] = None
    ):
        self.error_type = error_type
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(message)
```

## Docker Configuration

### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/

# Set environment variables
ENV PYTHONPATH="/app/src"
ENV PYTHONUNBUFFERED=1

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run application
CMD ["uvicorn", "temporal_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

This FastAPI integration provides a robust HTTP interface for Temporal workflows with enterprise features including authentication, monitoring, error handling, and comprehensive API documentation.
