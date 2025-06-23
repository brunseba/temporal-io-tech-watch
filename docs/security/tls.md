# TLS Configuration

This guide provides comprehensive TLS configuration strategies for Temporal.io deployments, ensuring encrypted communication across all components including server-to-server, client-to-server, and database connections.

## Overview

TLS security in Temporal.io encompasses:
- **Server TLS**: Securing external client connections
- **mTLS**: Mutual TLS for service-to-service communication
- **Database TLS**: Encrypted database connections
- **Certificate Management**: Automated certificate lifecycle
- **Certificate Rotation**: Secure certificate renewal processes

## Architecture

```mermaid
graph TB
    subgraph "Certificate Authority"
        ROOT_CA[Root CA]
        INTER_CA[Intermediate CA]
        CERT_MANAGER[Cert Manager]
    end
    
    subgraph "External Load Balancer"
        ALB[Application Load Balancer]
        TLS_TERM[TLS Termination]
    end
    
    subgraph "Temporal Cluster"
        FRONTEND[Frontend Service]
        HISTORY[History Service]
        MATCHING[Matching Service]
        WORKER[Worker Service]
    end
    
    subgraph "Data Persistence"
        POSTGRES[(PostgreSQL)]
        ELASTICSEARCH[(Elasticsearch)]
    end
    
    subgraph "Clients"
        SDK_CLIENT[SDK Client]
        CLI_CLIENT[CLI Client]
        WEB_UI[Web UI]
        APP_WORKERS[Application Workers]
    end
    
    ROOT_CA --> INTER_CA
    INTER_CA --> CERT_MANAGER
    CERT_MANAGER --> ALB
    CERT_MANAGER --> FRONTEND
    CERT_MANAGER --> HISTORY
    CERT_MANAGER --> MATCHING
    CERT_MANAGER --> WORKER
    CERT_MANAGER --> POSTGRES
    CERT_MANAGER --> ELASTICSEARCH
    
    SDK_CLIENT -->|TLS| ALB
    CLI_CLIENT -->|TLS| ALB
    WEB_UI -->|TLS| ALB
    APP_WORKERS -->|mTLS| ALB
    
    ALB -->|mTLS| FRONTEND
    FRONTEND -->|mTLS| HISTORY
    FRONTEND -->|mTLS| MATCHING
    FRONTEND -->|mTLS| WORKER
    
    FRONTEND -->|TLS| POSTGRES
    HISTORY -->|TLS| POSTGRES
    HISTORY -->|TLS| ELASTICSEARCH
```

## Certificate Management

### 1. Certificate Authority Setup

#### Root CA Configuration
```bash
#!/bin/bash
# scripts/setup-ca.sh

set -euo pipefail

CA_DIR="ca"
ROOT_CA_KEY="$CA_DIR/root-ca-key.pem"
ROOT_CA_CERT="$CA_DIR/root-ca-cert.pem"
INTER_CA_KEY="$CA_DIR/intermediate-ca-key.pem"
INTER_CA_CERT="$CA_DIR/intermediate-ca-cert.pem"
INTER_CA_CSR="$CA_DIR/intermediate-ca-csr.pem"

log() {
    echo -e "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')] $1\033[0m"
}

error() {
    echo -e "\033[0;31m[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1\033[0m"
    exit 1
}

# Create CA directory
mkdir -p "$CA_DIR"
chmod 700 "$CA_DIR"

# Generate Root CA private key
if [[ ! -f "$ROOT_CA_KEY" ]]; then
    log "Generating Root CA private key..."
    openssl genrsa -aes256 -out "$ROOT_CA_KEY" 4096
    chmod 600 "$ROOT_CA_KEY"
fi

# Generate Root CA certificate
if [[ ! -f "$ROOT_CA_CERT" ]]; then
    log "Generating Root CA certificate..."
    cat > "$CA_DIR/root-ca.conf" << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = Company Name
OU = IT Department
CN = Company Root CA

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
EOF

    openssl req -new -x509 -key "$ROOT_CA_KEY" -sha256 -days 3650 \
        -out "$ROOT_CA_CERT" -config "$CA_DIR/root-ca.conf"
    
    rm "$CA_DIR/root-ca.conf"
fi

# Generate Intermediate CA private key
if [[ ! -f "$INTER_CA_KEY" ]]; then
    log "Generating Intermediate CA private key..."
    openssl genrsa -aes256 -out "$INTER_CA_KEY" 4096
    chmod 600 "$INTER_CA_KEY"
fi

# Generate Intermediate CA certificate
if [[ ! -f "$INTER_CA_CERT" ]]; then
    log "Generating Intermediate CA certificate..."
    cat > "$CA_DIR/intermediate-ca.conf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_intermediate_ca
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = Company Name
OU = IT Department
CN = Company Intermediate CA

[v3_intermediate_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
EOF

    # Create CSR for intermediate CA
    openssl req -new -key "$INTER_CA_KEY" -out "$INTER_CA_CSR" \
        -config "$CA_DIR/intermediate-ca.conf"
    
    # Sign intermediate CA with root CA
    openssl x509 -req -in "$INTER_CA_CSR" -CA "$ROOT_CA_CERT" \
        -CAkey "$ROOT_CA_KEY" -CAcreateserial -out "$INTER_CA_CERT" \
        -days 1825 -extensions v3_intermediate_ca \
        -extfile "$CA_DIR/intermediate-ca.conf"
    
    # Create certificate chain
    cat "$INTER_CA_CERT" "$ROOT_CA_CERT" > "$CA_DIR/ca-chain.pem"
    
    # Clean up
    rm "$CA_DIR/intermediate-ca.conf" "$INTER_CA_CSR"
fi

log "✓ Certificate Authority setup completed"
log "Root CA: $ROOT_CA_CERT"
log "Intermediate CA: $INTER_CA_CERT"
log "CA Chain: $CA_DIR/ca-chain.pem"
```

#### Cert-Manager Integration
```yaml
# k8s/cert-manager/cluster-issuer.yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: temporal-ca-issuer
spec:
  ca:
    secretName: temporal-ca-key-pair

---
apiVersion: v1
kind: Secret
metadata:
  name: temporal-ca-key-pair
  namespace: cert-manager
type: Opaque
data:
  tls.crt: LS0tLS1CRUdJTi... # Base64 encoded intermediate CA cert
  tls.key: LS0tLS1CRUdJTi... # Base64 encoded intermediate CA key

---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-production
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@company.com
    privateKeySecretRef:
      name: letsencrypt-production
    solvers:
    - http01:
        ingress:
          class: alb
    - dns01:
        route53:
          region: us-west-2
          accessKeyID: AKIAIOSFODNN7EXAMPLE
          secretAccessKeySecretRef:
            name: route53-credentials
            key: secret-access-key
```

### 2. Server TLS Configuration

#### Frontend Service TLS
```yaml
# config/frontend-tls.yaml
tls:
  frontend:
    server:
      certFile: "/etc/temporal/certs/server.crt"
      keyFile: "/etc/temporal/certs/server.key"
      clientCaFiles:
        - "/etc/temporal/certs/ca-chain.pem"
      requireClientAuth: false  # For external clients
      cipherSuites:
        - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        - "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        - "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
      minVersion: "1.2"
      maxVersion: "1.3"

  # Alternative configuration for client certificate authentication
  frontend_mtls:
    server:
      certFile: "/etc/temporal/certs/server.crt"
      keyFile: "/etc/temporal/certs/server.key"
      clientCaFiles:
        - "/etc/temporal/certs/ca-chain.pem"
      requireClientAuth: true   # For mTLS clients
      clientCertPolicy: "RequireAndVerifyClientCert"
```

#### Certificate Request Template
```yaml
# k8s/certificates/server-cert.yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: temporal-server-cert
  namespace: temporal
spec:
  secretName: temporal-server-tls
  issuerRef:
    name: temporal-ca-issuer
    kind: ClusterIssuer
  commonName: temporal.company.com
  dnsNames:
  - temporal.company.com
  - temporal-frontend
  - temporal-frontend.temporal.svc.cluster.local
  - temporal-history
  - temporal-history.temporal.svc.cluster.local
  - temporal-matching
  - temporal-matching.temporal.svc.cluster.local
  - temporal-worker
  - temporal-worker.temporal.svc.cluster.local
  ipAddresses:
  - 127.0.0.1
  usages:
  - digital signature
  - key encipherment
  - server auth
  duration: 8760h  # 1 year
  renewBefore: 720h  # 30 days
```

### 3. Mutual TLS (mTLS) Configuration

#### Inter-Service Communication
```yaml
# config/internode-mtls.yaml
tls:
  internode:
    server:
      certFile: "/etc/temporal/certs/internode.crt"
      keyFile: "/etc/temporal/certs/internode.key"
      clientCaFiles:
        - "/etc/temporal/certs/ca-chain.pem"
      requireClientAuth: true
      clientCertPolicy: "RequireAndVerifyClientCert"
    client:
      certFile: "/etc/temporal/certs/internode.crt"
      keyFile: "/etc/temporal/certs/internode.key"
      serverCaFiles:
        - "/etc/temporal/certs/ca-chain.pem"
      serverName: "temporal.company.com"
      insecureSkipVerify: false
```

#### Client Certificate Configuration
```yaml
# k8s/certificates/client-cert.yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: temporal-client-cert
  namespace: temporal
spec:
  secretName: temporal-client-tls
  issuerRef:
    name: temporal-ca-issuer
    kind: ClusterIssuer
  commonName: temporal-client
  usages:
  - digital signature
  - key encipherment
  - client auth
  duration: 2160h  # 90 days
  renewBefore: 168h  # 7 days

---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: temporal-worker-cert
  namespace: temporal
spec:
  secretName: temporal-worker-tls
  issuerRef:
    name: temporal-ca-issuer
    kind: ClusterIssuer
  commonName: temporal-worker
  usages:
  - digital signature
  - key encipherment
  - client auth
  duration: 2160h  # 90 days
  renewBefore: 168h  # 7 days
```

## Database TLS Configuration

### 1. PostgreSQL TLS Setup

#### Database TLS Configuration
```yaml
# config/database-tls.yaml
persistence:
  default:
    sql:
      driver: "postgres"
      datasourceName: "postgres://temporal:${POSTGRES_PASSWORD}@postgres.company.com:5432/temporal?sslmode=require"
      tls:
        enabled: true
        caFile: "/etc/temporal/certs/postgres-ca.crt"
        certFile: "/etc/temporal/certs/postgres-client.crt"
        keyFile: "/etc/temporal/certs/postgres-client.key"
        serverName: "postgres.company.com"
        insecureSkipVerify: false
        
  visibility:
    sql:
      driver: "postgres"
      datasourceName: "postgres://temporal:${POSTGRES_PASSWORD}@postgres.company.com:5432/temporal_visibility?sslmode=require"
      tls:
        enabled: true
        caFile: "/etc/temporal/certs/postgres-ca.crt"
        certFile: "/etc/temporal/certs/postgres-client.crt"
        keyFile: "/etc/temporal/certs/postgres-client.key"
        serverName: "postgres.company.com"
```

#### PostgreSQL Server Configuration
```postgresql
# postgresql.conf
ssl = on
ssl_ca_file = '/etc/postgresql/certs/ca-chain.pem'
ssl_cert_file = '/etc/postgresql/certs/server.crt'
ssl_key_file = '/etc/postgresql/certs/server.key'
ssl_ciphers = 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384'
ssl_prefer_server_ciphers = on
ssl_protocols = 'TLSv1.2,TLSv1.3'

# Client certificate authentication
ssl_client_ca_file = '/etc/postgresql/certs/ca-chain.pem'
```

### 2. Elasticsearch TLS Setup

#### Elasticsearch TLS Configuration
```yaml
# config/elasticsearch-tls.yaml
cluster:
  metadata:
    elasticsearch:
      version: "v7"
      url:
        scheme: "https"
        host: "elasticsearch.company.com:9200"
      username: "temporal"
      password: "${ELASTICSEARCH_PASSWORD}"
      closeIdleConnectionsInterval: 15s
      tls:
        enabled: true
        caFile: "/etc/temporal/certs/elasticsearch-ca.crt"
        certFile: "/etc/temporal/certs/elasticsearch-client.crt"
        keyFile: "/etc/temporal/certs/elasticsearch-client.key"
        serverName: "elasticsearch.company.com"
        insecureSkipVerify: false
```

## Kubernetes TLS Integration

### 1. TLS Secret Management
```yaml
# k8s/tls-secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: temporal-server-tls
  namespace: temporal
type: kubernetes.io/tls
data:
  tls.crt: LS0tLS1CRUdJTi... # Server certificate
  tls.key: LS0tLS1CRUdJTi... # Server private key
  ca.crt: LS0tLS1CRUdJTi...  # CA chain

---
apiVersion: v1
kind: Secret
metadata:
  name: temporal-client-tls
  namespace: temporal
type: kubernetes.io/tls
data:
  tls.crt: LS0tLS1CRUdJTi... # Client certificate
  tls.key: LS0tLS1CRUdJTi... # Client private key
  ca.crt: LS0tLS1CRUdJTi...  # CA chain

---
apiVersion: v1
kind: Secret
metadata:
  name: temporal-database-tls
  namespace: temporal
type: Opaque
data:
  ca.crt: LS0tLS1CRUdJTi...     # Database CA
  client.crt: LS0tLS1CRUdJTi... # Database client cert
  client.key: LS0tLS1CRUdJTi... # Database client key
```

### 2. Deployment Configuration
```yaml
# k8s/temporal-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: temporal-frontend
  namespace: temporal
spec:
  replicas: 3
  selector:
    matchLabels:
      app: temporal-frontend
  template:
    metadata:
      labels:
        app: temporal-frontend
    spec:
      serviceAccountName: temporal-server
      containers:
      - name: temporal
        image: temporalio/auto-setup:1.22.0
        ports:
        - containerPort: 7233
          name: rpc
        - containerPort: 7234
          name: membership
        volumeMounts:
        - name: server-certs
          mountPath: /etc/temporal/certs
          readOnly: true
        - name: config
          mountPath: /etc/temporal/config
        env:
        - name: SERVICES
          value: "frontend"
        - name: TLS_CONFIG_FILE
          value: "/etc/temporal/config/tls.yaml"
        resources:
          requests:
            memory: 1Gi
            cpu: 500m
          limits:
            memory: 2Gi
            cpu: 1000m
      volumes:
      - name: server-certs
        secret:
          secretName: temporal-server-tls
      - name: config
        configMap:
          name: temporal-config

---
apiVersion: v1
kind: Service
metadata:
  name: temporal-frontend
  namespace: temporal
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-ssl-cert: arn:aws:acm:us-west-2:ACCOUNT:certificate/CERT-ID
    service.beta.kubernetes.io/aws-load-balancer-backend-protocol: ssl
    service.beta.kubernetes.io/aws-load-balancer-ssl-ports: "443"
spec:
  type: LoadBalancer
  ports:
  - port: 443
    targetPort: 7233
    protocol: TCP
    name: rpc-tls
  selector:
    app: temporal-frontend
```

### 3. Ingress TLS Configuration
```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: temporal-ingress
  namespace: temporal
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTP": 80}, {"HTTPS": 443}]'
    alb.ingress.kubernetes.io/ssl-redirect: "443"
    alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:us-west-2:ACCOUNT:certificate/CERT-ID
    alb.ingress.kubernetes.io/backend-protocol: HTTPS
    alb.ingress.kubernetes.io/backend-protocol-version: GRPC
    cert-manager.io/cluster-issuer: temporal-ca-issuer
spec:
  tls:
  - hosts:
    - temporal.company.com
    secretName: temporal-ingress-tls
  rules:
  - host: temporal.company.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: temporal-frontend
            port:
              number: 443
```

## Client SDK TLS Configuration

### 1. Go SDK Configuration
```go
// client/tls-client.go
package client

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io/ioutil"
    
    "go.temporal.io/sdk/client"
)

type TLSConfig struct {
    ServerName   string
    CertFile     string
    KeyFile      string
    CaFile       string
    InsecureSkip bool
}

func NewTLSClient(hostPort, namespace string, tlsConfig TLSConfig) (client.Client, error) {
    var tlsConf *tls.Config
    
    if tlsConfig.CertFile != "" && tlsConfig.KeyFile != "" {
        // Client certificate authentication
        cert, err := tls.LoadX509KeyPair(tlsConfig.CertFile, tlsConfig.KeyFile)
        if err != nil {
            return nil, fmt.Errorf("failed to load client certificates: %w", err)
        }
        
        tlsConf = &tls.Config{
            Certificates: []tls.Certificate{cert},
            ServerName:   tlsConfig.ServerName,
        }
    } else {
        // Server verification only
        tlsConf = &tls.Config{
            ServerName: tlsConfig.ServerName,
        }
    }
    
    // Load CA certificates
    if tlsConfig.CaFile != "" {
        caCert, err := ioutil.ReadFile(tlsConfig.CaFile)
        if err != nil {
            return nil, fmt.Errorf("failed to read CA file: %w", err)
        }
        
        caCertPool := x509.NewCertPool()
        if !caCertPool.AppendCertsFromPEM(caCert) {
            return nil, fmt.Errorf("failed to parse CA certificate")
        }
        
        tlsConf.RootCAs = caCertPool
    }
    
    tlsConf.InsecureSkipVerify = tlsConfig.InsecureSkip
    
    return client.Dial(client.Options{
        HostPort:  hostPort,
        Namespace: namespace,
        ConnectionOptions: client.ConnectionOptions{
            TLS: tlsConf,
        },
    })
}

// Example usage
func ExampleTLSClient() (client.Client, error) {
    return NewTLSClient("temporal.company.com:443", "default", TLSConfig{
        ServerName: "temporal.company.com",
        CertFile:   "/etc/temporal/certs/client.crt",
        KeyFile:    "/etc/temporal/certs/client.key",
        CaFile:     "/etc/temporal/certs/ca-chain.pem",
    })
}
```

### 2. Java SDK Configuration
```java
// TLSClientFactory.java
package com.company.temporal.client;

import io.temporal.client.WorkflowClient;
import io.temporal.client.WorkflowClientOptions;
import io.temporal.serviceclient.WorkflowServiceStubs;
import io.temporal.serviceclient.WorkflowServiceStubsOptions;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.security.KeyStore;

public class TLSClientFactory {
    
    public static WorkflowClient createTLSClient(String hostPort, String namespace, TLSConfiguration config) 
            throws Exception {
        
        SSLContext sslContext = createSSLContext(config);
        
        WorkflowServiceStubsOptions serviceOptions = WorkflowServiceStubsOptions.newBuilder()
                .setTarget(hostPort)
                .setSslContext(sslContext)
                .build();
        
        WorkflowServiceStubs service = WorkflowServiceStubs.newServiceStubs(serviceOptions);
        
        WorkflowClientOptions clientOptions = WorkflowClientOptions.newBuilder()
                .setNamespace(namespace)
                .build();
        
        return WorkflowClient.newInstance(service, clientOptions);
    }
    
    private static SSLContext createSSLContext(TLSConfiguration config) throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        
        // Load truststore (CA certificates)
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream(config.getTrustStorePath()), 
                       config.getTrustStorePassword().toCharArray());
        
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        
        // Load keystore (client certificates) if available
        KeyManagerFactory keyManagerFactory = null;
        if (config.getKeyStorePath() != null) {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(config.getKeyStorePath()), 
                         config.getKeyStorePassword().toCharArray());
            
            keyManagerFactory = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, config.getKeyStorePassword().toCharArray());
        }
        
        sslContext.init(
                keyManagerFactory != null ? keyManagerFactory.getKeyManagers() : null,
                trustManagerFactory.getTrustManagers(),
                null
        );
        
        return sslContext;
    }
}

class TLSConfiguration {
    private String trustStorePath;
    private String trustStorePassword;
    private String keyStorePath;
    private String keyStorePassword;
    
    // Getters and setters
    public String getTrustStorePath() { return trustStorePath; }
    public void setTrustStorePath(String trustStorePath) { this.trustStorePath = trustStorePath; }
    
    public String getTrustStorePassword() { return trustStorePassword; }
    public void setTrustStorePassword(String trustStorePassword) { this.trustStorePassword = trustStorePassword; }
    
    public String getKeyStorePath() { return keyStorePath; }
    public void setKeyStorePath(String keyStorePath) { this.keyStorePath = keyStorePath; }
    
    public String getKeyStorePassword() { return keyStorePassword; }
    public void setKeyStorePassword(String keyStorePassword) { this.keyStorePassword = keyStorePassword; }
}
```

## Certificate Rotation

### 1. Automated Certificate Rotation
```bash
#!/bin/bash
# scripts/rotate-certificates.sh

set -euo pipefail

NAMESPACE="temporal"
CERT_MANAGER_NAMESPACE="cert-manager"

log() {
    echo -e "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')] $1\033[0m"
}

error() {
    echo -e "\033[0;31m[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1\033[0m"
    exit 1
}

# Function to trigger certificate renewal
renew_certificate() {
    local cert_name="$1"
    local namespace="$2"
    
    log "Renewing certificate: $cert_name in namespace: $namespace"
    
    # Annotate certificate to trigger renewal
    kubectl annotate certificate "$cert_name" -n "$namespace" \
        cert-manager.io/issue-temporary-certificate="$(date +%s)" --overwrite
    
    # Wait for renewal to complete
    kubectl wait certificate "$cert_name" -n "$namespace" \
        --for=condition=Ready --timeout=300s
    
    log "✓ Certificate $cert_name renewed successfully"
}

# Function to restart deployments after certificate renewal
restart_deployment() {
    local deployment="$1"
    local namespace="$2"
    
    log "Restarting deployment: $deployment"
    
    kubectl rollout restart deployment "$deployment" -n "$namespace"
    kubectl rollout status deployment "$deployment" -n "$namespace" --timeout=300s
    
    log "✓ Deployment $deployment restarted successfully"
}

# Check certificate expiration
check_certificate_expiration() {
    local cert_name="$1"
    local namespace="$2"
    
    local cert_info=$(kubectl get certificate "$cert_name" -n "$namespace" -o json)
    local not_after=$(echo "$cert_info" | jq -r '.status.notAfter')
    
    if [[ "$not_after" != "null" ]]; then
        local expiry_date=$(date -d "$not_after" +%s)
        local current_date=$(date +%s)
        local days_until_expiry=$(( (expiry_date - current_date) / 86400 ))
        
        log "Certificate $cert_name expires in $days_until_expiry days"
        
        # Renew if expires within 30 days
        if [[ $days_until_expiry -lt 30 ]]; then
            log "Certificate $cert_name is due for renewal"
            return 0
        fi
    fi
    
    return 1
}

main() {
    log "Starting certificate rotation process..."
    
    # List of certificates to check and potentially renew
    certificates=(
        "temporal-server-cert:$NAMESPACE"
        "temporal-client-cert:$NAMESPACE"
        "temporal-worker-cert:$NAMESPACE"
        "temporal-database-cert:$NAMESPACE"
    )
    
    # Check and renew certificates
    for cert_entry in "${certificates[@]}"; do
        IFS=':' read -r cert_name cert_namespace <<< "$cert_entry"
        
        if check_certificate_expiration "$cert_name" "$cert_namespace"; then
            renew_certificate "$cert_name" "$cert_namespace"
            
            # Restart relevant deployments
            case "$cert_name" in
                "temporal-server-cert")
                    restart_deployment "temporal-frontend" "$NAMESPACE"
                    restart_deployment "temporal-history" "$NAMESPACE"
                    restart_deployment "temporal-matching" "$NAMESPACE"
                    restart_deployment "temporal-worker" "$NAMESPACE"
                    ;;
                "temporal-client-cert")
                    # Restart client applications
                    restart_deployment "temporal-worker" "$NAMESPACE"
                    ;;
                "temporal-worker-cert")
                    restart_deployment "temporal-worker" "$NAMESPACE"
                    ;;
                "temporal-database-cert")
                    # Restart all services that connect to database
                    restart_deployment "temporal-frontend" "$NAMESPACE"
                    restart_deployment "temporal-history" "$NAMESPACE"
                    ;;
            esac
        fi
    done
    
    log "✓ Certificate rotation process completed"
}

main "$@"
```

### 2. Certificate Monitoring
```yaml
# k8s/monitoring/certificate-monitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: cert-manager-metrics
  namespace: cert-manager
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: cert-manager
  endpoints:
  - port: http-metrics
    interval: 30s
    path: /metrics

---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: certificate-expiry-alerts
  namespace: cert-manager
spec:
  groups:
  - name: certificate-expiry
    rules:
    - alert: CertificateExpiringSoon
      expr: certmanager_certificate_expiration_timestamp_seconds - time() < 7 * 24 * 3600
      for: 1h
      labels:
        severity: warning
      annotations:
        summary: "Certificate {{ $labels.name }} in namespace {{ $labels.namespace }} is expiring soon"
        description: "Certificate {{ $labels.name }} in namespace {{ $labels.namespace }} will expire in less than 7 days"
    
    - alert: CertificateExpired
      expr: certmanager_certificate_expiration_timestamp_seconds - time() <= 0
      for: 0m
      labels:
        severity: critical
      annotations:
        summary: "Certificate {{ $labels.name }} in namespace {{ $labels.namespace }} has expired"
        description: "Certificate {{ $labels.name }} in namespace {{ $labels.namespace }} has expired and needs immediate attention"
```

This comprehensive TLS configuration guide provides enterprise-grade encryption and certificate management for Temporal.io deployments, ensuring secure communication across all components with automated certificate lifecycle management.
