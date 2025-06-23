# Security Configuration

This guide provides comprehensive security configuration for Temporal.io enterprise deployment, covering network security, authentication, authorization, encryption, and compliance requirements.

## Overview

Security configuration includes:
- Network policies and segmentation
- TLS/SSL certificate management
- Authentication and authorization
- Secrets management
- RBAC configuration
- Audit logging and compliance
- Security scanning and vulnerability management

## Network Security

### Network Policies

#### Default Deny Policy
```yaml
# k8s/security/network-policies/default-deny.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: temporal-system
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

#### Temporal Backend Network Policy
```yaml
# k8s/security/network-policies/temporal-backend.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: temporal-backend-policy
  namespace: temporal-system
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: temporal
  policyTypes:
  - Ingress
  - Egress
  ingress:
  # Allow ingress from workers and API services
  - from:
    - namespaceSelector:
        matchLabels:
          name: temporal-app
    - podSelector:
        matchLabels:
          app.kubernetes.io/component: web
    ports:
    - protocol: TCP
      port: 7233  # Frontend service
    - protocol: TCP
      port: 7234  # History service
    - protocol: TCP
      port: 7235  # Matching service
  # Allow ingress from load balancer
  - from:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: TCP
      port: 8080  # Web UI
  egress:
  # Allow egress to database
  - to: []
    ports:
    - protocol: TCP
      port: 5432  # PostgreSQL
  # Allow egress to Redis
  - to: []
    ports:
    - protocol: TCP
      port: 6379  # Redis
  # Allow DNS resolution
  - to: []
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
  # Allow HTTPS for external services
  - to: []
    ports:
    - protocol: TCP
      port: 443
```

#### Application Network Policy
```yaml
# k8s/security/network-policies/temporal-app.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: temporal-app-policy
  namespace: temporal-app
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/part-of: temporal-app
  policyTypes:
  - Ingress
  - Egress
  ingress:
  # Allow ingress from load balancer
  - from:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: TCP
      port: 8000  # FastAPI
  egress:
  # Allow egress to Temporal backend
  - to:
    - namespaceSelector:
        matchLabels:
          name: temporal-system
    ports:
    - protocol: TCP
      port: 7233
  # Allow egress to Redis
  - to: []
    ports:
    - protocol: TCP
      port: 6379
  # Allow DNS resolution
  - to: []
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
  # Allow HTTPS for external APIs
  - to: []
    ports:
    - protocol: TCP
      port: 443
```

### Security Groups (AWS)

#### Database Security Group
```hcl
# terraform/modules/security-groups/rds.tf
resource "aws_security_group" "rds" {
  name_prefix = "${var.cluster_name}-rds-"
  vpc_id      = var.vpc_id
  description = "Security group for RDS database"

  # Allow connections from EKS nodes only
  ingress {
    description     = "PostgreSQL from EKS"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_nodes.id]
  }

  # Allow connections from bastion host for administration
  ingress {
    description     = "PostgreSQL from bastion"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.cluster_name}-rds-sg"
    Environment = var.environment
  }
}
```

#### EKS Nodes Security Group
```hcl
# terraform/modules/security-groups/eks.tf
resource "aws_security_group" "eks_nodes" {
  name_prefix = "${var.cluster_name}-eks-nodes-"
  vpc_id      = var.vpc_id
  description = "Security group for EKS worker nodes"

  # Allow nodes to communicate with each other
  ingress {
    description = "Node to node communication"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }

  # Allow pods to communicate with the cluster API Server
  ingress {
    description     = "Cluster API Server"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_cluster.id]
  }

  # Allow NodePort services
  ingress {
    description = "NodePort services"
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.cluster_name}-eks-nodes-sg"
    Environment = var.environment
  }
}
```

## TLS/SSL Configuration

### Certificate Manager Setup

#### ClusterIssuer for Let's Encrypt
```yaml
# k8s/security/certificates/cluster-issuer.yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@yourcompany.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - dns01:
        route53:
          region: us-west-2
          accessKeyID: AKIAIOSFODNN7EXAMPLE
          secretAccessKeySecretRef:
            name: route53-credentials
            key: secret-access-key
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    email: admin@yourcompany.com
    privateKeySecretRef:
      name: letsencrypt-staging
    solvers:
    - dns01:
        route53:
          region: us-west-2
          accessKeyID: AKIAIOSFODNN7EXAMPLE
          secretAccessKeySecretRef:
            name: route53-credentials
            key: secret-access-key
```

#### Certificate for Temporal Services
```yaml
# k8s/security/certificates/temporal-cert.yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: temporal-tls
  namespace: temporal-system
spec:
  secretName: temporal-tls-secret
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  commonName: temporal.yourcompany.com
  dnsNames:
  - temporal.yourcompany.com
  - temporal-web.yourcompany.com
  - temporal-frontend.temporal-system.svc.cluster.local
  usages:
  - digital signature
  - key encipherment
  - server auth
  - client auth
```

### TLS Configuration for Temporal

#### Temporal TLS Configuration
```yaml
# helm/values/security/tls.yaml
server:
  config:
    tls:
      frontend:
        server:
          certFile: /etc/temporal/certs/tls.crt
          keyFile: /etc/temporal/certs/tls.key
          clientCAFile: /etc/temporal/certs/ca.crt
          requireClientAuth: true
        client:
          serverName: temporal-frontend
          certFile: /etc/temporal/certs/tls.crt
          keyFile: /etc/temporal/certs/tls.key
          caFile: /etc/temporal/certs/ca.crt
      history:
        server:
          certFile: /etc/temporal/certs/tls.crt
          keyFile: /etc/temporal/certs/tls.key
          clientCAFile: /etc/temporal/certs/ca.crt
          requireClientAuth: true
        client:
          serverName: temporal-history
          certFile: /etc/temporal/certs/tls.crt
          keyFile: /etc/temporal/certs/tls.key
          caFile: /etc/temporal/certs/ca.crt
      matching:
        server:
          certFile: /etc/temporal/certs/tls.crt
          keyFile: /etc/temporal/certs/tls.key
          clientCAFile: /etc/temporal/certs/ca.crt
          requireClientAuth: true
        client:
          serverName: temporal-matching
          certFile: /etc/temporal/certs/tls.crt
          keyFile: /etc/temporal/certs/tls.key
          caFile: /etc/temporal/certs/ca.crt
```

## Authentication and Authorization

### OIDC Integration

#### OIDC Configuration for Temporal Web
```yaml
# k8s/security/auth/oidc-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: temporal-web-auth-config
  namespace: temporal-system
data:
  config.yaml: |
    auth:
      enabled: true
      providers:
        - label: "Company SSO"
          type: oidc
          providerUrl: "https://auth.yourcompany.com"
          clientId: "temporal-web"
          clientSecret: "${OIDC_CLIENT_SECRET}"
          scopes:
            - openid
            - profile
            - email
          callbackUrl: "https://temporal.yourcompany.com/auth/callback"
          usernameAttribute: "email"
          groupsAttribute: "groups"
      authorizer:
        roleMapping:
          admin:
            - "temporal-admins"
          read:
            - "temporal-readers"
          write:
            - "temporal-writers"
```

#### External Secret for OIDC
```yaml
# k8s/security/auth/oidc-secret.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: temporal-oidc-secret
  namespace: temporal-system
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: temporal-oidc-secret
    creationPolicy: Owner
  data:
  - secretKey: client-secret
    remoteRef:
      key: temporal/oidc
      property: client_secret
```

### JWT Configuration

#### JWT Authorizer Configuration
```yaml
# k8s/security/auth/jwt-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: temporal-auth-config
  namespace: temporal-system
data:
  auth.yaml: |
    authorization:
      jwtKeyProvider:
        keySourceURIs:
          - "https://auth.yourcompany.com/.well-known/jwks.json"
        refreshInterval: "1h"
      permissionsClaimName: "permissions"
      
    claims:
      mappers:
        - name: "admin"
          role: "admin"
          permissions:
            - "system:admin"
            - "namespace:admin"
            - "workflow:admin"
        - name: "developer"
          role: "developer"
          permissions:
            - "namespace:read"
            - "namespace:write"
            - "workflow:read"
            - "workflow:write"
        - name: "readonly"
          role: "readonly"
          permissions:
            - "namespace:read"
            - "workflow:read"
```

### RBAC Configuration

#### Kubernetes RBAC for Temporal
```yaml
# k8s/security/rbac/temporal-rbac.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: temporal-admin
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints", "persistentvolumeclaims", "events", "configmaps", "secrets"]
  verbs: ["*"]
- apiGroups: ["apps"]
  resources: ["deployments", "daemonsets", "replicasets", "statefulsets"]
  verbs: ["*"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["*"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: temporal-operator
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets", "statefulsets"]
  verbs: ["get", "list", "watch", "update", "patch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: temporal-admin-binding
subjects:
- kind: User
  name: temporal-admin@yourcompany.com
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: temporal-admin
  apiGroup: rbac.authorization.k8s.io

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: temporal-operator-binding
  namespace: temporal-system
subjects:
- kind: ServiceAccount
  name: temporal-server
  namespace: temporal-system
roleRef:
  kind: ClusterRole
  name: temporal-operator
  apiGroup: rbac.authorization.k8s.io
```

## Secrets Management

### HashiCorp Vault Integration

#### Vault SecretStore Configuration
```yaml
# k8s/security/secrets/vault-secretstore.yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
  namespace: temporal-system
spec:
  provider:
    vault:
      server: "https://vault.yourcompany.com"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "temporal-role"
          serviceAccountRef:
            name: "temporal-external-secrets"
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: temporal-external-secrets
  namespace: temporal-system
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/temporal-external-secrets-role
```

#### Database Credentials Secret
```yaml
# k8s/security/secrets/database-secret.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: temporal-database-secret
  namespace: temporal-system
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: temporal-database-credentials
    creationPolicy: Owner
    template:
      type: Opaque
      data:
        host: "{{ .host }}"
        port: "{{ .port }}"
        database: "{{ .database }}"
        username: "{{ .username }}"
        password: "{{ .password }}"
        connection_string: "postgres://{{ .username }}:{{ .password }}@{{ .host }}:{{ .port }}/{{ .database }}?sslmode=require"
  data:
  - secretKey: host
    remoteRef:
      key: temporal/database
      property: host
  - secretKey: port
    remoteRef:
      key: temporal/database
      property: port
  - secretKey: database
    remoteRef:
      key: temporal/database
      property: database
  - secretKey: username
    remoteRef:
      key: temporal/database
      property: username
  - secretKey: password
    remoteRef:
      key: temporal/database
      property: password
```

#### Application Secrets
```yaml
# k8s/security/secrets/app-secrets.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: temporal-app-secrets
  namespace: temporal-app
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: temporal-app-secrets
    creationPolicy: Owner
  data:
  - secretKey: jwt-secret
    remoteRef:
      key: temporal/app
      property: jwt_secret
  - secretKey: encryption-key
    remoteRef:
      key: temporal/app
      property: encryption_key
  - secretKey: api-key
    remoteRef:
      key: temporal/app
      property: api_key
```

### Encryption at Rest

#### Database Encryption
```hcl
# terraform/modules/rds/encryption.tf
resource "aws_kms_key" "rds" {
  description             = "RDS encryption key for ${var.cluster_name}"
  deletion_window_in_days = var.environment == "production" ? 30 : 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow RDS Service"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "${var.cluster_name}-rds-kms"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${var.cluster_name}-rds"
  target_key_id = aws_kms_key.rds.key_id
}
```

#### Kubernetes Secret Encryption
```yaml
# k8s/security/encryption/secret-encryption.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - kms:
      name: aws-kms
      endpoint: arn:aws:kms:us-west-2:ACCOUNT:key/KEY-ID
      cachesize: 1000
      timeout: 3s
  - identity: {}
```

## Pod Security

### Pod Security Standards
```yaml
# k8s/security/pod-security/pod-security-policy.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: temporal-system
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
apiVersion: v1
kind: Namespace
metadata:
  name: temporal-app
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### Security Context Configuration
```yaml
# k8s/security/pod-security/security-context.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: temporal-security-context
  namespace: temporal-system
data:
  security-context.yaml: |
    securityContext:
      runAsNonRoot: true
      runAsUser: 10001
      runAsGroup: 10001
      fsGroup: 10001
      seccompProfile:
        type: RuntimeDefault
    containerSecurityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 10001
      runAsGroup: 10001
      capabilities:
        drop:
        - ALL
      seccompProfile:
        type: RuntimeDefault
```

## Audit Logging

### Audit Policy Configuration
```yaml
# k8s/security/audit/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
# Don't log requests for events
- level: None
  resources:
  - group: ""
    resources: ["events"]

# Don't log authenticated requests to certain non-resource URL paths
- level: None
  userGroups: ["system:authenticated"]
  nonResourceURLs:
  - "/api*" # Wildcard matching.
  - "/version"
  - "/healthz"

# Log the request body of configmap changes in kube-system
- level: Request
  resources:
  - group: ""
    resources: ["configmaps"]
  namespaces: ["kube-system"]

# Log configmap and secret changes in all other namespaces at the Metadata level
- level: Metadata
  resources:
  - group: ""
    resources: ["secrets", "configmaps"]

# Log all other requests at the Metadata level
- level: Metadata
  # Long-running requests like watches that fall under this rule will not
  # generate an audit event in RequestReceived.
  omitStages:
  - RequestReceived
```

### Falco Security Monitoring
```yaml
# k8s/security/monitoring/falco.yaml
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: falco
  namespace: kube-system
spec:
  chart: falco
  repo: https://falcosecurity.github.io/charts
  targetNamespace: falco
  valuesContent: |-
    driver:
      kind: ebpf
    falco:
      rules_file:
        - /etc/falco/falco_rules.yaml
        - /etc/falco/falco_rules.local.yaml
        - /etc/falco/k8s_audit_rules.yaml
        - /etc/falco/rules.d
      json_output: true
      json_include_output_property: true
      log_stderr: true
      log_syslog: false
      priority: debug
      buffered_outputs: false
      outputs:
        rate: 1
        max_burst: 1000
      syscall_event_drops:
        actions:
          - log
          - alert
        rate: 0.03333
        max_burst: 10
    customRules:
      temporal_rules.yaml: |-
        - rule: Temporal Database Connection
          desc: Detect connections to Temporal database
          condition: >
            spawned_process and
            proc.name=psql and
            proc.args contains "temporal"
          output: >
            Temporal database connection detected
            (user=%user.name command=%proc.cmdline pid=%proc.pid container=%container.name)
          priority: INFO
          tags: [temporal, database]
        
        - rule: Temporal Secret Access
          desc: Detect access to Temporal secrets
          condition: >
            ka.verb in (get, list) and
            ka.uri.param[name] contains "temporal" and
            ka.resource.resource=secrets
          output: >
            Temporal secret accessed
            (user=%ka.user.name verb=%ka.verb resource=%ka.target.name)
          priority: WARNING
          tags: [temporal, secrets]
```

## Compliance and Security Scanning

### Vulnerability Scanning with Trivy
```yaml
# k8s/security/scanning/trivy-operator.yaml
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: trivy-operator
  namespace: kube-system
spec:
  chart: trivy-operator
  repo: https://aquasecurity.github.io/helm-charts/
  targetNamespace: trivy-system
  valuesContent: |-
    operator:
      scannerReportTTL: "24h"
      vulnerabilityReportsPlugin: "Trivy"
      configAuditReportsPlugin: "Trivy"
    
    trivy:
      serverURL: ""
      timeout: "5m0s"
      resources:
        requests:
          cpu: 100m
          memory: 100M
        limits:
          cpu: 500m
          memory: 500M
```

### CIS Kubernetes Benchmark
```bash
#!/bin/bash
# scripts/security/run-cis-benchmark.sh

set -euo pipefail

log() {
    echo -e "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')] $1\033[0m"
}

log "Running CIS Kubernetes Benchmark..."

# Install kube-bench
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml

# Wait for job completion
kubectl wait --for=condition=complete job/kube-bench --timeout=300s

# Get results
kubectl logs job/kube-bench > cis-benchmark-results.txt

log "CIS Benchmark completed. Results saved to cis-benchmark-results.txt"

# Clean up
kubectl delete job kube-bench

# Parse results for critical findings
CRITICAL_FINDINGS=$(grep -c "FAIL" cis-benchmark-results.txt || true)
if [[ $CRITICAL_FINDINGS -gt 0 ]]; then
    log "WARNING: Found $CRITICAL_FINDINGS critical security findings"
    grep "FAIL" cis-benchmark-results.txt
    exit 1
else
    log "No critical security findings detected"
fi
```

### OPA Gatekeeper Policies
```yaml
# k8s/security/policies/gatekeeper-constraints.yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        type: object
        properties:
          labels:
            type: array
            items:
              type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        
        violation[{"msg": msg}] {
          required := input.parameters.labels
          provided := input.review.object.metadata.labels
          missing := required[_]
          not provided[missing]
          msg := sprintf("Missing required label: %v", [missing])
        }

---
apiVersion: config.gatekeeper.sh/v1alpha1
kind: K8sRequiredLabels
metadata:
  name: must-have-temporal-labels
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment"]
    namespaces: ["temporal-system", "temporal-app"]
  parameters:
    labels: ["app.kubernetes.io/name", "app.kubernetes.io/version", "environment"]
```

## Security Automation Scripts

### Security Configuration Script
```bash
#!/bin/bash
# scripts/security/configure-security.sh

set -euo pipefail

ENVIRONMENT=${1:-development}

log() {
    echo -e "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')] $1\033[0m"
}

error() {
    echo -e "\033[0;31m[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1\033[0m"
    exit 1
}

log "Configuring security for environment: $ENVIRONMENT"

# Apply network policies
log "Applying network policies..."
kubectl apply -f k8s/security/network-policies/

# Configure RBAC
log "Configuring RBAC..."
kubectl apply -f k8s/security/rbac/

# Setup certificate management
log "Setting up certificate management..."
kubectl apply -f k8s/security/certificates/

# Configure secrets management
log "Configuring secrets management..."
kubectl apply -f k8s/security/secrets/

# Apply pod security policies
log "Applying pod security policies..."
kubectl apply -f k8s/security/pod-security/

# Setup audit logging
log "Setting up audit logging..."
kubectl apply -f k8s/security/audit/

# Install security monitoring
log "Installing security monitoring..."
kubectl apply -f k8s/security/monitoring/

# Install OPA Gatekeeper
log "Installing OPA Gatekeeper..."
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm upgrade --install gatekeeper gatekeeper/gatekeeper \
    --namespace gatekeeper-system \
    --create-namespace

# Apply Gatekeeper policies
log "Applying Gatekeeper policies..."
kubectl apply -f k8s/security/policies/

log "Security configuration completed successfully!"
```

### Security Validation Script
```bash
#!/bin/bash
# scripts/security/validate-security.sh

set -euo pipefail

log() {
    echo -e "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')] $1\033[0m"
}

warn() {
    echo -e "\033[1;33m[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1\033[0m"
}

error() {
    echo -e "\033[0;31m[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1\033[0m"
}

log "Validating security configuration..."

# Check network policies
log "Checking network policies..."
NETWORK_POLICIES=$(kubectl get networkpolicies -A --no-headers | wc -l)
if [[ $NETWORK_POLICIES -gt 0 ]]; then
    log "✓ Network policies are configured ($NETWORK_POLICIES policies found)"
else
    warn "✗ No network policies found"
fi

# Check pod security
log "Checking pod security..."
PRIVILEGED_PODS=$(kubectl get pods -A -o jsonpath='{.items[?(@.spec.securityContext.privileged==true)].metadata.name}' | wc -w)
if [[ $PRIVILEGED_PODS -eq 0 ]]; then
    log "✓ No privileged pods found"
else
    warn "✗ Found $PRIVILEGED_PODS privileged pods"
fi

# Check certificate management
log "Checking certificate management..."
if kubectl get clusterissuer letsencrypt-prod &>/dev/null; then
    log "✓ Certificate management is configured"
else
    error "✗ Certificate management not configured"
fi

# Check secrets encryption
log "Checking secrets encryption..."
if kubectl get secret -n kube-system | grep -q encryption-config; then
    log "✓ Secrets encryption is enabled"
else
    warn "✗ Secrets encryption not detected"
fi

# Check RBAC
log "Checking RBAC..."
CLUSTER_ROLES=$(kubectl get clusterroles | grep -c temporal || true)
if [[ $CLUSTER_ROLES -gt 0 ]]; then
    log "✓ Temporal RBAC is configured"
else
    warn "✗ Temporal RBAC not found"
fi

# Check audit logging
log "Checking audit logging..."
if kubectl get configmap -n kube-system audit-policy &>/dev/null; then
    log "✓ Audit logging is configured"
else
    warn "✗ Audit logging not configured"
fi

log "Security validation completed"
```

This comprehensive security configuration guide provides enterprise-grade security for Temporal.io deployments with defense-in-depth principles, compliance requirements, and automated security monitoring.
