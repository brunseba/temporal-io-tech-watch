# Temporal.io Enterprise Deployment Guide

Welcome to the comprehensive documentation for deploying Temporal.io in enterprise Kubernetes environments. This guide provides everything you need to design, implement, and operate a production-ready Temporal deployment.

## What is Temporal?

Temporal is a distributed, scalable, durable, and highly available orchestration engine that executes asynchronous long-running business logic in a scalable and resilient way. It enables developers to build reliable applications by abstracting away the complexity of distributed systems.

## What You'll Learn

This documentation covers:

- **Architecture Design**: Complete system architecture with security, monitoring, and scalability considerations
- **Implementation**: Step-by-step deployment guides for production environments
- **Operations**: Monitoring, troubleshooting, backup, and disaster recovery procedures
- **Development**: Best practices for building workflows and integrating applications
- **Security**: Enterprise-grade security implementation with SSO, TLS, and secrets management
- **GitOps**: Automated deployment strategies using ArgoCD and modern DevOps practices

## Target Audience

This guide is designed for:

- **Developers** building workflows and activities
- **Product Owners** defining business requirements
- **Architects** designing system integration
- **SRE/DevOps Engineers** operating and maintaining infrastructure

## Architecture Overview

Our target architecture includes:

- **Temporal Backend**: Deployed in `temporal-backend` namespace
- **Business Applications**: Deployed in `temporal-product` namespace
- **Database**: PostgreSQL for persistence and visibility
- **Search**: Elasticsearch for advanced visibility
- **Monitoring**: Prometheus + Grafana + OpenTelemetry
- **Security**: Authentik SSO + HashiCorp Vault + cert-manager
- **GitOps**: ArgoCD for deployment automation

## Quick Navigation

### 🚀 **Getting Started**
New to this deployment? Start with our [Getting Started](getting-started/overview.md) section.

### 🏗️ **Architecture & Design**
Understand the system architecture and design decisions in our [Architecture](architecture/system-architecture.md) section.

### 📋 **Implementation**
Follow our comprehensive [Implementation Guide](temporal-design-implementation-guide.md) for complete deployment instructions.

### ⚙️ **Operations**
Learn about monitoring, troubleshooting, and maintenance in the [Operations](operations/monitoring.md) section.

### 🔒 **Security**
Implement enterprise-grade security with our [Security](security/auth.md) guides.

### 🔄 **GitOps**
Set up automated deployments with [GitOps & Deployment](gitops/argocd-setup.md) practices.

## Key Features

### Enterprise-Grade Security
- SSO integration with Authentik
- HashiCorp Vault for secrets management
- End-to-end TLS encryption
- Network policies and RBAC

### Production-Ready Monitoring
- Prometheus metrics collection
- Grafana dashboards
- OpenTelemetry tracing
- Custom business metrics

### High Availability
- Multi-node Kubernetes deployment
- Database replication
- Auto-scaling capabilities
- Disaster recovery procedures

### Developer Experience
- Python SDK integration
- FastAPI service templates
- Testing frameworks
- CI/CD pipeline templates

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|----------|
| **Orchestration Platform** | Kubernetes | Container orchestration |
| **Workflow Engine** | Temporal.io | Workflow orchestration |
| **Database** | PostgreSQL | Persistence and visibility |
| **Search** | Elasticsearch | Advanced search capabilities |
| **Monitoring** | Prometheus + Grafana | Metrics and dashboards |
| **Security** | Authentik + Vault | Authentication and secrets |
| **GitOps** | ArgoCD | Automated deployment |
| **Service Mesh** | Istio (Optional) | Service communication |
| **Package Manager** | Helm | Kubernetes application management |

## Prerequisites

Before starting, ensure you have:

- Kubernetes cluster (v1.25+)
- Helm 3.x installed
- GitLab or similar Git repository
- JFrog Artifactory or container registry
- Basic understanding of Kubernetes concepts

## What's New

- **Temporal 1.29.1 (October 2025)**: Eager Workflow Start (GA), Task Queue Fairness, Slimmed Docker Images
- **Temporal 1.28.x (June 2025)**: Update-With-Start (GA), Worker Versioning (Preview), Priority Task Queues
- **Temporal 1.27.x (February 2025)**: Nexus (GA), Enhanced Safe Deploys
- **Temporal 1.26.x (December 2024)**: Workflow Update API (GA)

For detailed information, see [What's New in Temporal.io](reference/whats-new.md).

## Temporal Cloud

Temporal Cloud is a fully managed, hosted version of Temporal that eliminates operational overhead:

- **No Infrastructure Management**: Temporal handles servers, databases, and scaling
- **Global Availability**: Multi-region deployments with automatic failover
- **Enterprise Security**: SOC 2 Type 2 certified, HIPAA compliant
- **Built-in Observability**: Metrics, logging, and distributed tracing included
- **Free Trial**: $1,000 in credits for new users

Learn more at [temporal.io](https://temporal.io) or review our [self-hosted deployment guide](temporal-design-implementation-guide.md).

## Support and Contributing

- **Documentation Issues**: Open an issue in the GitLab repository
- **Feature Requests**: Submit through GitLab issues
- **Security Issues**: Contact the security team directly
- **Temporal Community**: [community.temporal.io](https://community.temporal.io/)
- **Official Documentation**: [docs.temporal.io](https://docs.temporal.io/)

## Next Steps

1. **Start with Prerequisites**: Review [Prerequisites](getting-started/prerequisites.md)
2. **Understand the Architecture**: Read [System Architecture](architecture/system-architecture.md)
3. **Follow the Implementation**: Use the [Complete Implementation Guide](temporal-design-implementation-guide.md)
4. **Set up Monitoring**: Configure [Monitoring & Observability](operations/monitoring.md)

---

**Ready to deploy Temporal.io in your enterprise environment?** 

[Get Started](getting-started/overview.md){ .md-button .md-button--primary }
[View Architecture](architecture/system-architecture.md){ .md-button }
