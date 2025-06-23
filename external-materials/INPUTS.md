# A temporal.io design and deployement guide

## Installation

Helm Package
local helm-temporal folder as input

# Ecosystem

Kubernetes cluster
python language
gitlab as vcs and ci engine
uv for python packaging
external-sso with go-authentik
external-secret with hcvault kv2 engine
deployment with argocd gitops controller
kubernetes secret management with external-secret
kubenetes certificat management with cert-manager and issuer
opentelemetry as monitor stack
grafana for technical and bussiness dashboards
personnas : developer, product owner, architect, SRE devops
jfrog as artifactory for docker artefact
jfrog as artifactory for helm artefact
jfrog as artifactory for python wheel package

For Apps deploy on temporal-product namespace, 2 microservices : temporal-worker, fastapi for datamodel

API access is securised through an API Manager, as example gravitee.io

## Git ecosystem

version and release with semver
conventionnal-commit
changelog managemant

## Deployment

Kubernetes
Namespace restriction without clusterrole access
Namespace Name for temporal : temporal-backend
Namespace Name for temporal business worker : temporal-product
