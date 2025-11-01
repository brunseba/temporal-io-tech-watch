# Temporal Helm Deployment Guide

This guide covers deploying Temporal using Helm with specific enterprise requirements including external PostgreSQL, security context configuration, Docker proxy registry, nginx ingress, and external-secrets integration.

## Prerequisites

- Kubernetes cluster (1.19+)
- Helm 3.x
- kubectl configured
- PostgreSQL database (external)
- nginx-ingress controller
- external-secrets operator (optional)

## Helm Charts Dependencies

The Temporal Helm chart includes the following dependencies:

| Chart Name | Version | Repository URL | App Version | Purpose |
|------------|---------|----------------|-------------|----------|
| **temporal** | 0.64.0 | https://go.temporal.io/helm-charts | 1.28.0 | Main Temporal orchestration engine |
| cassandra | 0.14.3 | https://charts.helm.sh/incubator | 3.11.3 | Database storage (optional) |
| prometheus | 25.22.0 | https://prometheus-community.github.io/helm-charts | v2.53.0 | Metrics collection and monitoring |
| elasticsearch | 7.17.3 | https://helm.elastic.co | 7.17.3 | Advanced visibility store (optional) |
| grafana | 8.0.2 | https://grafana.github.io/helm-charts | 10.4.2 | Monitoring dashboards |

### Prometheus Sub-Dependencies

The Prometheus chart includes additional sub-charts:

| Chart Name | Version | Repository URL | Purpose |
|------------|---------|----------------|---------|
| alertmanager | 1.11.* | https://prometheus-community.github.io/helm-charts | Alert management |
| kube-state-metrics | 5.20.* | https://prometheus-community.github.io/helm-charts | Kubernetes metrics |
| prometheus-node-exporter | 4.36.* | https://prometheus-community.github.io/helm-charts | Node-level metrics |
| prometheus-pushgateway | 2.13.* | https://prometheus-community.github.io/helm-charts | Push gateway for batch jobs |

### Repository Setup

To add all required Helm repositories:

```bash
# Add Temporal repository
helm repo add temporalio https://go.temporal.io/helm-charts

# Add dependency repositories (if deploying components separately)
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add elastic https://helm.elastic.co
helm repo add grafana https://grafana.github.io/helm-charts
helm repo add incubator https://charts.helm.sh/incubator

# Update repositories
helm repo update
```

## External PostgreSQL Database Configuration

### Basic PostgreSQL Configuration

Create a custom values file (`values-postgresql.yaml`) to configure Temporal with external PostgreSQL:

```yaml
server:
  config:
    persistence:
      default:
        driver: "sql"
        sql:
          driver: "postgres12"
          host: "postgresql.example.com"
          port: 5432
          database: "temporal"
          user: "temporal_user"
          # Use existingSecret instead of password for production
          existingSecret: "temporal-default-store"
          maxConns: 20
          maxIdleConns: 20
          maxConnLifetime: "1h"
      
      visibility:
        driver: "sql"
        sql:
          driver: "postgres12"
          host: "postgresql.example.com"
          port: 5432
          database: "temporal_visibility"
          user: "temporal_user"
          existingSecret: "temporal-visibility-store"
          maxConns: 20
          maxIdleConns: 20
          maxConnLifetime: "1h"

# Disable embedded databases
cassandra:
  enabled: false
mysql:
  enabled: false
postgresql:
  enabled: false
```

### Kubernetes Secrets for Database Credentials

Create secrets for database credentials:

```bash
# Create secret for default store
kubectl create secret generic temporal-default-store \
  --from-literal=password='your-password-here'

# Create secret for visibility store
kubectl create secret generic temporal-visibility-store \
  --from-literal=password='your-password-here'
```

### PostgreSQL with TLS

For TLS-enabled PostgreSQL connections:

```yaml
server:
  config:
    persistence:
      default:
        sql:
          tls:
            enabled: true
            enableHostVerification: true
            serverName: "postgresql.example.com"
            caFile: /etc/temporal/certs/ca.crt
            certFile: /etc/temporal/certs/client.crt
            keyFile: /etc/temporal/certs/client.key
  
  additionalVolumes:
    - name: postgres-tls-certs
      secret:
        secretName: postgres-tls-certs
  
  additionalVolumeMounts:
    - name: postgres-tls-certs
      mountPath: /etc/temporal/certs
      readOnly: true
```

## Security Context Configuration (UID/GID > 10000)

Configure security context with UID/GID greater than 10000 for compliance:

```yaml
server:
  securityContext:
    fsGroup: 10001
    runAsUser: 10001
    runAsGroup: 10001
    runAsNonRoot: true

admintools:
  securityContext:
    fsGroup: 10001
    runAsUser: 10001
    runAsGroup: 10001
    runAsNonRoot: true
  containerSecurityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop:
        - ALL

web:
  securityContext:
    fsGroup: 10001
    runAsUser: 10001
    runAsGroup: 10001
    runAsNonRoot: true
  containerSecurityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop:
        - ALL
```

## Docker Registry Proxy Configuration

Configure all Temporal components to use `docker.proxyregistry.org` as the registry proxy:

```yaml
server:
  image:
    repository: docker.proxyregistry.org/temporalio/server
    tag: 1.29.1
    pullPolicy: IfNotPresent

admintools:
  image:
    repository: docker.proxyregistry.org/temporalio/admin-tools
    tag: 1.29.1-tctl-1.18.2-cli-1.3.0
    pullPolicy: IfNotPresent

web:
  image:
    repository: docker.proxyregistry.org/temporalio/ui
    tag: 2.37.1
    pullPolicy: IfNotPresent

# Configure image pull secrets if required
imagePullSecrets:
  - name: docker-proxy-registry-secret

# Override dependency chart images
elasticsearch:
  image: docker.proxyregistry.org/elasticsearch/elasticsearch
  imageTag: 7.17.3

prometheus:
  server:
    image:
      repository: docker.proxyregistry.org/prom/prometheus
  alertmanager:
    image:
      repository: docker.proxyregistry.org/prom/alertmanager

grafana:
  image:
    repository: docker.proxyregistry.org/grafana/grafana
```

## Nginx Ingress Configuration

### Web UI Ingress

Configure ingress for the Temporal Web UI:

```yaml
web:
  ingress:
    enabled: true
    className: "nginx"
    annotations:
      nginx.ingress.kubernetes.io/rewrite-target: /
      nginx.ingress.kubernetes.io/ssl-redirect: "true"
      nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
      cert-manager.io/cluster-issuer: "letsencrypt-prod"
      nginx.ingress.kubernetes.io/proxy-body-size: "100m"
      nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
      nginx.ingress.kubernetes.io/proxy-send-timeout: "300"
    hosts:
      - "temporal-ui.example.com"
    tls:
      - secretName: temporal-ui-tls
        hosts:
          - "temporal-ui.example.com"
```

### Frontend Service Ingress

Configure ingress for the Temporal frontend service (gRPC):

```yaml
server:
  frontend:
    ingress:
      enabled: true
      className: "nginx"
      annotations:
        nginx.ingress.kubernetes.io/backend-protocol: "GRPC"
        nginx.ingress.kubernetes.io/grpc-backend: "true"
        nginx.ingress.kubernetes.io/ssl-redirect: "true"
        cert-manager.io/cluster-issuer: "letsencrypt-prod"
      hosts:
        - "temporal-grpc.example.com"
      tls:
        - secretName: temporal-grpc-tls
          hosts:
            - "temporal-grpc.example.com"
```

### Grafana Ingress

Configure ingress for the Grafana dashboard:

```yaml
grafana:
  ingress:
    enabled: true
    ingressClassName: "nginx"
    annotations:
      nginx.ingress.kubernetes.io/rewrite-target: /
      nginx.ingress.kubernetes.io/ssl-redirect: "true"
      nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
      cert-manager.io/cluster-issuer: "letsencrypt-prod"
      nginx.ingress.kubernetes.io/proxy-body-size: "100m"
      nginx.ingress.kubernetes.io/auth-type: basic
      nginx.ingress.kubernetes.io/auth-secret: grafana-basic-auth
      nginx.ingress.kubernetes.io/auth-realm: 'Authentication Required - Grafana'
    path: /
    pathType: Prefix
    hosts:
      - "grafana.example.com"
    tls:
      - secretName: grafana-tls
        hosts:
          - "grafana.example.com"
```

## External Secrets Integration

### Using External Secrets Operator

Configure ExternalSecret resources to manage database credentials dynamically:

```yaml
# external-secrets-config.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: temporal-database-credentials
  namespace: temporal
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: temporal-default-store
    creationPolicy: Owner
  data:
    - secretKey: password
      remoteRef:
        key: secret/temporal/database
        property: default_password

---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: temporal-visibility-credentials
  namespace: temporal
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: temporal-visibility-store
    creationPolicy: Owner
  data:
    - secretKey: password
      remoteRef:
        key: secret/temporal/database
        property: visibility_password
```

### TLS Certificate Management

Use external-secrets for automatic certificate provisioning:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: temporal-tls-certificates
  namespace: temporal
spec:
  refreshInterval: 24h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: postgres-tls-certs
    creationPolicy: Owner
    template:
      type: kubernetes.io/tls
  data:
    - secretKey: ca.crt
      remoteRef:
        key: secret/temporal/certs
        property: ca_certificate
    - secretKey: tls.crt
      remoteRef:
        key: secret/temporal/certs
        property: client_certificate
    - secretKey: tls.key
      remoteRef:
        key: secret/temporal/certs
        property: client_key
```

### Grafana Authentication

For Grafana basic authentication with external secrets:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: grafana-credentials
  namespace: temporal
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: grafana-basic-auth
    creationPolicy: Owner
    template:
      type: Opaque
      data:
        auth: "{{ .username }}:{{ .password | htpasswd }}"
  data:
    - secretKey: username
      remoteRef:
        key: secret/temporal/grafana
        property: admin_username
    - secretKey: password
      remoteRef:
        key: secret/temporal/grafana
        property: admin_password
```

Alternatively, create the basic auth secret manually:

```bash
# Create basic auth secret for Grafana
htpasswd -c auth admin
kubectl create secret generic grafana-basic-auth \
  --from-file=auth \
  --namespace=temporal
```

## OIDC Configuration

Configure OpenID Connect (OIDC) authentication for various components in the Temporal stack.

### Temporal Server OIDC/JWT Authorization

Temporal supports JWT-based authorization with OIDC providers. Configure JWT key provider and authorization:

```yaml
server:
  config:
    # Define your Authorizer and ClaimMapper configuration
    # See https://docs.temporal.io/self-hosted-guide/security#authorization
    authorization:
      jwtKeyProvider:
        keySourceURIs:
          - "https://your-oidc-provider.com/.well-known/jwks.json"
          - "https://your-oidc-provider.com/oauth2/v1/keys"
        refreshInterval: "1h"
      permissionsClaimName: "permissions"
      authorizer: "default"
      claimMapper: "default"
  
  # Mount OIDC certificates if needed
  additionalVolumes:
    - name: oidc-certs
      secret:
        secretName: oidc-tls-certs
  
  additionalVolumeMounts:
    - name: oidc-certs
      mountPath: /etc/temporal/oidc-certs
      readOnly: true
```

### Grafana OIDC Configuration

Configure Grafana to use OIDC for authentication:

```yaml
grafana:
  grafana.ini:
    server:
      domain: "grafana.example.com"
      root_url: "https://grafana.example.com"
    
    auth.generic_oauth:
      enabled: true
      name: "OIDC"
      allow_sign_up: true
      auto_login: false
      client_id: "grafana-client-id"
      client_secret: "${OIDC_CLIENT_SECRET}"
      scopes: "openid profile email groups"
      empty_scopes: false
      auth_url: "https://your-oidc-provider.com/oauth2/v1/authorize"
      token_url: "https://your-oidc-provider.com/oauth2/v1/token"
      api_url: "https://your-oidc-provider.com/oauth2/v1/userinfo"
      allowed_domains: "example.com"
      team_ids: ""
      allowed_organizations: ""
      role_attribute_path: "contains(groups[*], 'grafana-admin') && 'Admin' || contains(groups[*], 'grafana-editor') && 'Editor' || 'Viewer'"
      role_attribute_strict: false
      allow_assign_grafana_admin: true
      skip_org_role_sync: false
      use_pkce: true
  
  # Store OIDC client secret securely
  envFromSecrets:
    - name: grafana-oidc-secret
      keys:
        - key: client-secret
          name: OIDC_CLIENT_SECRET
```

### Prometheus OIDC with OAuth Proxy

Prometheus doesn't natively support OIDC, but you can use oauth2-proxy as a sidecar:

```yaml
prometheus:
  server:
    # Add oauth2-proxy as sidecar
    extraContainers:
      - name: oauth2-proxy
        image: quay.io/oauth2-proxy/oauth2-proxy:v7.4.0
        args:
          - --provider=oidc
          - --email-domain=*
          - --upstream=http://localhost:9090
          - --http-address=0.0.0.0:4180
          - --oidc-issuer-url=https://your-oidc-provider.com
          - --client-id=$(OAUTH2_PROXY_CLIENT_ID)
          - --client-secret=$(OAUTH2_PROXY_CLIENT_SECRET)
          - --cookie-secret=$(OAUTH2_PROXY_COOKIE_SECRET)
          - --cookie-secure=true
          - --skip-provider-button=true
        ports:
          - containerPort: 4180
            name: oauth-proxy
        env:
          - name: OAUTH2_PROXY_CLIENT_ID
            valueFrom:
              secretKeyRef:
                name: prometheus-oidc-secret
                key: client-id
          - name: OAUTH2_PROXY_CLIENT_SECRET
            valueFrom:
              secretKeyRef:
                name: prometheus-oidc-secret
                key: client-secret
          - name: OAUTH2_PROXY_COOKIE_SECRET
            valueFrom:
              secretKeyRef:
                name: prometheus-oidc-secret
                key: cookie-secret
    
    # Update service to expose oauth2-proxy port
    service:
      additionalPorts:
        - name: oauth-proxy
          port: 4180
          targetPort: 4180
  
  # Update ingress to point to oauth2-proxy
  server:
    ingress:
      enabled: true
      className: "nginx"
      annotations:
        nginx.ingress.kubernetes.io/backend-protocol: "HTTP"
        nginx.ingress.kubernetes.io/ssl-redirect: "true"
        cert-manager.io/cluster-issuer: "letsencrypt-prod"
      hosts:
        - "prometheus.example.com"
      tls:
        - secretName: prometheus-tls
          hosts:
            - "prometheus.example.com"
      # Override port to use oauth2-proxy
      paths:
        - path: /
          pathType: Prefix
          backend:
            service:
              name: temporal-prometheus-server
              port:
                number: 4180
```

### OIDC Secrets Management with External Secrets

Manage OIDC secrets using external-secrets:

```yaml
# Temporal OIDC secrets
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: temporal-oidc-config
  namespace: temporal
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: temporal-oidc-secret
    creationPolicy: Owner
  data:
    - secretKey: jwks-url
      remoteRef:
        key: secret/temporal/oidc
        property: jwks_url

---
# Grafana OIDC secrets
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: grafana-oidc-config
  namespace: temporal
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: grafana-oidc-secret
    creationPolicy: Owner
  data:
    - secretKey: client-secret
      remoteRef:
        key: secret/temporal/grafana-oidc
        property: client_secret

---
# Prometheus OAuth2-Proxy secrets
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: prometheus-oidc-config
  namespace: temporal
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: prometheus-oidc-secret
    creationPolicy: Owner
    template:
      type: Opaque
      data:
        cookie-secret: "{{ .cookie_secret | b64enc }}"
  data:
    - secretKey: client-id
      remoteRef:
        key: secret/temporal/prometheus-oidc
        property: client_id
    - secretKey: client-secret
      remoteRef:
        key: secret/temporal/prometheus-oidc
        property: client_secret
    - secretKey: cookie_secret
      remoteRef:
        key: secret/temporal/prometheus-oidc
        property: cookie_secret
```

### OIDC Provider Configuration Requirements

For each component, configure your OIDC provider with the following redirect URIs:

- **Temporal**: No redirect URI needed (JWT validation only)
- **Grafana**: `https://grafana.example.com/login/generic_oauth`
- **Prometheus (oauth2-proxy)**: `https://prometheus.example.com/oauth2/callback`

### Claims and Groups Mapping

Configure role mapping based on OIDC claims:

```yaml
# Example for Keycloak groups mapping
# Grafana role mapping in grafana.ini:
auth.generic_oauth:
  role_attribute_path: "contains(groups[*], 'temporal-admins') && 'Admin' || contains(groups[*], 'temporal-editors') && 'Editor' || 'Viewer'"

# Temporal permissions in JWT claims:
# {
#   "sub": "user@example.com",
#   "groups": ["temporal-admins", "temporal-users"],
#   "permissions": ["temporal:read", "temporal:write", "temporal:admin"]
# }
```

## Complete Deployment Example

### 1. Create Namespace

```bash
kubectl create namespace temporal
```

### 2. Deploy External Secrets (if using)

```bash
kubectl apply -f external-secrets-config.yaml
```

### 3. Add Helm Repositories

If not already done, add the required Helm repositories (see [Repository Setup](#repository-setup) section above):

```bash
helm repo add temporalio https://go.temporal.io/helm-charts
helm repo update
```

### 4. Create Values File

Combine all configurations into a single `values-production.yaml`:

```yaml
# Complete production configuration
nameOverride: ""
fullnameOverride: ""

imagePullSecrets:
  - name: docker-proxy-registry-secret

server:
  image:
    repository: docker.proxyregistry.org/temporalio/server
    tag: 1.29.1
    pullPolicy: IfNotPresent
  
  securityContext:
    fsGroup: 10001
    runAsUser: 10001
    runAsGroup: 10001
    runAsNonRoot: true
  
  config:
    persistence:
      default:
        driver: "sql"
        sql:
          driver: "postgres12"
          host: "postgresql.example.com"
          port: 5432
          database: "temporal"
          user: "temporal_user"
          existingSecret: "temporal-default-store"
          maxConns: 20
          maxIdleConns: 20
          maxConnLifetime: "1h"
      
      visibility:
        driver: "sql"
        sql:
          driver: "postgres12"
          host: "postgresql.example.com"
          port: 5432
          database: "temporal_visibility"
          user: "temporal_user"
          existingSecret: "temporal-visibility-store"
          maxConns: 20
          maxIdleConns: 20
          maxConnLifetime: "1h"

web:
  image:
    repository: docker.proxyregistry.org/temporalio/ui
    tag: 2.37.1
    pullPolicy: IfNotPresent
  
  securityContext:
    fsGroup: 10001
    runAsUser: 10001
    runAsGroup: 10001
    runAsNonRoot: true
  
  ingress:
    enabled: true
    className: "nginx"
    annotations:
      nginx.ingress.kubernetes.io/rewrite-target: /
      nginx.ingress.kubernetes.io/ssl-redirect: "true"
      cert-manager.io/cluster-issuer: "letsencrypt-prod"
    hosts:
      - "temporal-ui.example.com"
    tls:
      - secretName: temporal-ui-tls
        hosts:
          - "temporal-ui.example.com"

admintools:
  image:
    repository: docker.proxyregistry.org/temporalio/admin-tools
    tag: 1.29.1-tctl-1.18.2-cli-1.3.0
    pullPolicy: IfNotPresent
  
  securityContext:
    fsGroup: 10001
    runAsUser: 10001
    runAsGroup: 10001
    runAsNonRoot: true

# Disable embedded databases
cassandra:
  enabled: false
mysql:
  enabled: false
postgresql:
  enabled: false

# Configure monitoring stack with proxy registry
prometheus:
  enabled: true
  server:
    image:
      repository: docker.proxyregistry.org/prom/prometheus

grafana:
  enabled: true
  image:
    repository: docker.proxyregistry.org/grafana/grafana
  ingress:
    enabled: true
    ingressClassName: "nginx"
    annotations:
      nginx.ingress.kubernetes.io/rewrite-target: /
      nginx.ingress.kubernetes.io/ssl-redirect: "true"
      cert-manager.io/cluster-issuer: "letsencrypt-prod"
    path: /
    pathType: Prefix
    hosts:
      - "grafana.example.com"
    tls:
      - secretName: grafana-tls
        hosts:
          - "grafana.example.com"

elasticsearch:
  enabled: true
  image: docker.proxyregistry.org/elasticsearch/elasticsearch
  imageTag: 7.17.3
```

### 5. Deploy Temporal

```bash
helm install temporal temporalio/temporal \
  --namespace temporal \
  --values values-production.yaml \
  --wait
```

### 6. Verify Deployment

```bash
# Check pods
kubectl get pods -n temporal

# Check services
kubectl get svc -n temporal

# Check ingress
kubectl get ingress -n temporal

# Check secrets
kubectl get secrets -n temporal
```

### 7. Access Services

After successful deployment, you can access the following services:

- **Temporal Web UI**: https://temporal-ui.example.com
- **Temporal gRPC Frontend**: temporal-grpc.example.com:443 (for client connections)
- **Grafana Dashboard**: https://grafana.example.com (with basic auth if configured)

#### Default Grafana Credentials

If not using external secrets, Grafana uses default credentials:
- Username: `admin`
- Password: Check the grafana secret: `kubectl get secret temporal-grafana -n temporal -o jsonpath="{.data.admin-password}" | base64 --decode`

#### Temporal CLI Access

Connect to Temporal using the CLI:

```bash
# Using external endpoint
tctl --address temporal-grpc.example.com:443 --tls namespace list

# Using port-forward for testing
kubectl port-forward -n temporal svc/temporal-frontend 7233:7233
tctl --address localhost:7233 namespace list
```

## Troubleshooting

### Common Issues

1. **Database Connection Issues**: Verify secrets and network connectivity
2. **Image Pull Errors**: Check imagePullSecrets and registry configuration
3. **Permission Denied**: Verify securityContext and volume permissions
4. **Ingress Not Working**: Check ingress controller and DNS configuration

### Useful Commands

```bash
# View logs
kubectl logs -n temporal deployment/temporal-frontend

# Port forward for testing
kubectl port-forward -n temporal svc/temporal-frontend 7233:7233

# Execute into admintools
kubectl exec -n temporal deployment/temporal-admintools -it -- bash
```

This comprehensive guide enables enterprise-grade deployment of Temporal with external dependencies, security compliance, and operational best practices.
