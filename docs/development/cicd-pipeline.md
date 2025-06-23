# CI/CD Pipeline

This document provides comprehensive CI/CD pipeline implementation for Temporal.io enterprise deployments, covering automated testing, building, security scanning, deployment, and monitoring.

## Overview

The CI/CD pipeline ensures reliable, secure, and automated delivery of Temporal workflows and applications. This guide covers GitHub Actions workflows, GitLab CI, Jenkins pipelines, and deployment strategies for enterprise environments.

## Pipeline Architecture

```mermaid
graph TD
    A[Code Commit] --> B[Pre-commit Hooks]
    B --> C[CI Pipeline Trigger]
    C --> D[Code Quality Checks]
    D --> E[Unit Tests]
    E --> F[Integration Tests]
    F --> G[Security Scans]
    G --> H[Build Artifacts]
    H --> I[Container Images]
    I --> J[Deploy to Staging]
    J --> K[E2E Tests]
    K --> L[Performance Tests]
    L --> M[Deploy to Production]
    M --> N[Health Checks]
    N --> O[Monitoring & Alerts]
```

## GitHub Actions Workflows

### Main CI/CD Workflow

```yaml
# .github/workflows/cicd.yml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  release:
    types: [ published ]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}
  PYTHON_VERSION: "3.11"

jobs:
  # =====================================================================
  # Code Quality and Security
  # =====================================================================
  code-quality:
    name: Code Quality Checks
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: ${{ env.PYTHON_VERSION }}

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install black isort flake8 mypy bandit safety
          pip install -r requirements.txt

      - name: Code formatting check (Black)
        run: black --check --diff .

      - name: Import sorting check (isort)
        run: isort --check-only --diff .

      - name: Linting (flake8)
        run: flake8 --max-line-length=88 --extend-ignore=E203,W503 .

      - name: Type checking (mypy)
        run: mypy src/ --ignore-missing-imports

      - name: Security check (Bandit)
        run: bandit -r src/ -f json -o bandit-report.json
        continue-on-error: true

      - name: Dependency security check (Safety)
        run: safety check --json --output safety-report.json
        continue-on-error: true

      - name: Upload security reports
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-reports
          path: |
            bandit-report.json
            safety-report.json

  # =====================================================================
  # Unit Tests
  # =====================================================================
  unit-tests:
    name: Unit Tests
    runs-on: ubuntu-latest
    needs: code-quality
    strategy:
      matrix:
        python-version: ["3.9", "3.10", "3.11"]

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}

      - name: Cache dependencies
        uses: actions/cache@v3
        with:
          path: ~/.cache/pip
          key: ${{ runner.os }}-pip-${{ hashFiles('**/requirements*.txt') }}
          restore-keys: |
            ${{ runner.os }}-pip-

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install -r requirements-test.txt

      - name: Run unit tests
        run: |
          pytest tests/unit/ -v \
            --cov=src \
            --cov-report=xml \
            --cov-report=html \
            --junitxml=junit.xml

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
          fail_ci_if_error: true

      - name: Upload test results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: test-results-${{ matrix.python-version }}
          path: |
            junit.xml
            htmlcov/

  # =====================================================================
  # Integration Tests
  # =====================================================================
  integration-tests:
    name: Integration Tests
    runs-on: ubuntu-latest
    needs: unit-tests
    
    services:
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

      temporal:
        image: temporalio/auto-setup:1.20.0
        ports:
          - 7233:7233
        env:
          DB: postgresql
          DB_PORT: 5432
          POSTGRES_USER: temporal
          POSTGRES_PWD: temporal
          POSTGRES_SEEDS: postgres

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: ${{ env.PYTHON_VERSION }}

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install -r requirements-test.txt

      - name: Wait for services to be ready
        run: |
          timeout 60 bash -c 'until curl -f http://localhost:7233/; do sleep 2; done'

      - name: Run integration tests
        run: |
          pytest tests/integration/ -v \
            --junitxml=integration-junit.xml
        env:
          TEMPORAL_SERVER_URL: localhost:7233
          TEMPORAL_NAMESPACE: default
          DATABASE_URL: postgresql://temporal:temporal@localhost:5432/temporal

      - name: Upload integration test results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: integration-test-results
          path: integration-junit.xml

  # =====================================================================
  # Build and Push Container Images
  # =====================================================================
  build-images:
    name: Build Container Images
    runs-on: ubuntu-latest
    needs: [unit-tests, integration-tests]
    if: github.event_name != 'pull_request'
    
    outputs:
      image-tag: ${{ steps.meta.outputs.tags }}
      image-digest: ${{ steps.build.outputs.digest }}

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=sha,prefix={{branch}}-
            type=raw,value=latest,enable={{is_default_branch}}

      - name: Build and push API image
        id: build
        uses: docker/build-push-action@v5
        with:
          context: .
          file: ./docker/api/Dockerfile
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
          platforms: linux/amd64,linux/arm64

      - name: Build and push Worker image
        uses: docker/build-push-action@v5
        with:
          context: .
          file: ./docker/worker/Dockerfile
          push: true
          tags: ${{ steps.meta.outputs.tags }}-worker
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
          platforms: linux/amd64,linux/arm64

  # =====================================================================
  # Security Scanning
  # =====================================================================
  security-scan:
    name: Container Security Scan
    runs-on: ubuntu-latest
    needs: build-images
    if: github.event_name != 'pull_request'

    steps:
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ needs.build-images.outputs.image-tag }}
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload Trivy scan results to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'

  # =====================================================================
  # Deploy to Staging
  # =====================================================================
  deploy-staging:
    name: Deploy to Staging
    runs-on: ubuntu-latest
    needs: [build-images, security-scan]
    if: github.ref == 'refs/heads/develop'
    environment: staging

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up kubectl
        uses: azure/setup-kubectl@v3
        with:
          version: 'v1.28.0'

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-west-2

      - name: Update kubeconfig
        run: |
          aws eks update-kubeconfig --region us-west-2 --name temporal-staging-cluster

      - name: Deploy to staging
        run: |
          helm upgrade --install temporal-staging ./helm/temporal-stack \
            --namespace temporal-staging \
            --create-namespace \
            --set image.tag=${{ needs.build-images.outputs.image-tag }} \
            --set environment=staging \
            --values ./helm/values/staging.yaml \
            --wait --timeout=10m

      - name: Run smoke tests
        run: |
          kubectl wait --for=condition=ready pod -l app=temporal-api -n temporal-staging --timeout=300s
          kubectl port-forward svc/temporal-api 8080:80 -n temporal-staging &
          sleep 10
          curl -f http://localhost:8080/health || exit 1

  # =====================================================================
  # End-to-End Tests
  # =====================================================================
  e2e-tests:
    name: End-to-End Tests
    runs-on: ubuntu-latest
    needs: deploy-staging
    if: github.ref == 'refs/heads/develop'

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: ${{ env.PYTHON_VERSION }}

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements-test.txt

      - name: Run E2E tests
        run: |
          pytest tests/e2e/ -v \
            --junitxml=e2e-junit.xml \
            --base-url=${{ secrets.STAGING_BASE_URL }} \
            --api-key=${{ secrets.STAGING_API_KEY }}

      - name: Upload E2E test results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: e2e-test-results
          path: e2e-junit.xml

  # =====================================================================
  # Performance Tests
  # =====================================================================
  performance-tests:
    name: Performance Tests
    runs-on: ubuntu-latest
    needs: deploy-staging
    if: github.ref == 'refs/heads/develop'

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: ${{ env.PYTHON_VERSION }}

      - name: Install Locust
        run: pip install locust

      - name: Run performance tests
        run: |
          locust -f tests/performance/locustfile.py \
            --headless \
            --users 50 \
            --spawn-rate 5 \
            --run-time 5m \
            --host ${{ secrets.STAGING_BASE_URL }} \
            --html performance-report.html \
            --csv performance

      - name: Upload performance test results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: performance-test-results
          path: |
            performance-report.html
            performance*.csv

  # =====================================================================
  # Deploy to Production
  # =====================================================================
  deploy-production:
    name: Deploy to Production
    runs-on: ubuntu-latest
    needs: [e2e-tests, performance-tests]
    if: github.event_name == 'release' && github.event.action == 'published'
    environment: production

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up kubectl
        uses: azure/setup-kubectl@v3
        with:
          version: 'v1.28.0'

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-west-2

      - name: Update kubeconfig
        run: |
          aws eks update-kubeconfig --region us-west-2 --name temporal-production-cluster

      - name: Deploy to production
        run: |
          helm upgrade --install temporal-production ./helm/temporal-stack \
            --namespace temporal-production \
            --create-namespace \
            --set image.tag=${{ github.event.release.tag_name }} \
            --set environment=production \
            --values ./helm/values/production.yaml \
            --wait --timeout=15m

      - name: Post-deployment verification
        run: |
          kubectl wait --for=condition=ready pod -l app=temporal-api -n temporal-production --timeout=600s
          kubectl get pods -n temporal-production
          curl -f ${{ secrets.PRODUCTION_BASE_URL }}/health

      - name: Notify deployment success
        uses: 8398a7/action-slack@v3
        with:
          status: success
          text: "✅ Production deployment successful: ${{ github.event.release.tag_name }}"
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### Feature Branch Workflow

```yaml
# .github/workflows/feature-branch.yml
name: Feature Branch CI

on:
  push:
    branches-ignore: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  validate:
    name: Validate Feature Branch
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install -r requirements-test.txt

      - name: Code quality checks
        run: |
          black --check .
          isort --check-only .
          flake8 .
          mypy src/

      - name: Run unit tests
        run: |
          pytest tests/unit/ -v --cov=src

      - name: Build test image
        run: |
          docker build -t temporal-test:${{ github.sha }} -f docker/api/Dockerfile .

      - name: Comment PR
        uses: actions/github-script@v6
        if: github.event_name == 'pull_request'
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '✅ Feature branch validation passed! Ready for review.'
            })
```

## GitLab CI Configuration

### Complete Pipeline

```yaml
# .gitlab-ci.yml
stages:
  - validate
  - test
  - build
  - security
  - deploy-staging
  - test-staging
  - deploy-production

variables:
  DOCKER_DRIVER: overlay2
  DOCKER_TLS_CERTDIR: "/certs"
  PYTHON_VERSION: "3.11"
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

cache:
  paths:
    - .cache/pip
    - venv/

before_script:
  - python -m venv venv
  - source venv/bin/activate
  - pip install --upgrade pip

# =====================================================================
# Validation Stage
# =====================================================================
code-quality:
  stage: validate
  image: python:$PYTHON_VERSION
  script:
    - pip install black isort flake8 mypy bandit
    - black --check --diff .
    - isort --check-only --diff .
    - flake8 --max-line-length=88 .
    - mypy src/ --ignore-missing-imports
    - bandit -r src/
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
    - if: $CI_COMMIT_BRANCH == "develop"

# =====================================================================
# Test Stage
# =====================================================================
unit-tests:
  stage: test
  image: python:$PYTHON_VERSION
  services:
    - name: postgres:13
      alias: postgres
  variables:
    POSTGRES_DB: test_db
    POSTGRES_USER: test_user
    POSTGRES_PASSWORD: test_pass
  script:
    - pip install -r requirements.txt -r requirements-test.txt
    - pytest tests/unit/ -v --cov=src --cov-report=xml --junitxml=report.xml
  coverage: '/(?i)total.*? (100(?:\.0+)?\%|[1-9]?\d(?:\.\d+)?\%)$/'
  artifacts:
    reports:
      junit: report.xml
      coverage_report:
        coverage_format: cobertura
        path: coverage.xml
    paths:
      - coverage.xml
    expire_in: 1 week

integration-tests:
  stage: test
  image: python:$PYTHON_VERSION
  services:
    - name: postgres:13
      alias: postgres
    - name: temporalio/auto-setup:1.20.0
      alias: temporal
  variables:
    POSTGRES_DB: temporal
    POSTGRES_USER: temporal
    POSTGRES_PASSWORD: temporal
    TEMPORAL_SERVER_URL: temporal:7233
  script:
    - pip install -r requirements.txt -r requirements-test.txt
    - sleep 30 # Wait for Temporal to start
    - pytest tests/integration/ -v --junitxml=integration-report.xml
  artifacts:
    reports:
      junit: integration-report.xml
    expire_in: 1 week

# =====================================================================
# Build Stage
# =====================================================================
build-api:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - echo $CI_REGISTRY_PASSWORD | docker login -u $CI_REGISTRY_USER --password-stdin $CI_REGISTRY
  script:
    - docker build -t $CI_REGISTRY_IMAGE/api:$CI_COMMIT_SHA -f docker/api/Dockerfile .
    - docker push $CI_REGISTRY_IMAGE/api:$CI_COMMIT_SHA
    - |
      if [ "$CI_COMMIT_BRANCH" == "main" ]; then
        docker tag $CI_REGISTRY_IMAGE/api:$CI_COMMIT_SHA $CI_REGISTRY_IMAGE/api:latest
        docker push $CI_REGISTRY_IMAGE/api:latest
      fi
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
    - if: $CI_COMMIT_BRANCH == "develop"
    - if: $CI_COMMIT_TAG

build-worker:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - echo $CI_REGISTRY_PASSWORD | docker login -u $CI_REGISTRY_USER --password-stdin $CI_REGISTRY
  script:
    - docker build -t $CI_REGISTRY_IMAGE/worker:$CI_COMMIT_SHA -f docker/worker/Dockerfile .
    - docker push $CI_REGISTRY_IMAGE/worker:$CI_COMMIT_SHA
    - |
      if [ "$CI_COMMIT_BRANCH" == "main" ]; then
        docker tag $CI_REGISTRY_IMAGE/worker:$CI_COMMIT_SHA $CI_REGISTRY_IMAGE/worker:latest
        docker push $CI_REGISTRY_IMAGE/worker:latest
      fi
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
    - if: $CI_COMMIT_BRANCH == "develop"
    - if: $CI_COMMIT_TAG

# =====================================================================
# Security Stage
# =====================================================================
container-scanning:
  stage: security
  image: docker:stable
  services:
    - docker:dind
  script:
    - docker run --rm -v /var/run/docker.sock:/var/run/docker.sock 
      -v $PWD:/tmp aquasec/trivy:latest image --exit-code 1 --format template 
      --template "@contrib/gitlab.tpl" -o gl-container-scanning-report.json 
      $CI_REGISTRY_IMAGE/api:$CI_COMMIT_SHA
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
    - if: $CI_COMMIT_BRANCH == "develop"

dependency-scanning:
  stage: security
  image: python:$PYTHON_VERSION
  script:
    - pip install safety
    - safety check --json --output safety-report.json --continue-on-error
  artifacts:
    reports:
      dependency_scanning: safety-report.json
  allow_failure: true

# =====================================================================
# Staging Deployment
# =====================================================================
deploy-staging:
  stage: deploy-staging
  image: 
    name: alpine/helm:latest
    entrypoint: [""]
  before_script:
    - apk add --no-cache curl
    - curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    - chmod +x kubectl && mv kubectl /usr/local/bin/
  script:
    - echo $KUBE_CONFIG | base64 -d > ~/.kube/config
    - |
      helm upgrade --install temporal-staging ./helm/temporal-stack \
        --namespace temporal-staging \
        --create-namespace \
        --set image.tag=$CI_COMMIT_SHA \
        --set environment=staging \
        --values ./helm/values/staging.yaml \
        --wait --timeout=10m
  environment:
    name: staging
    url: https://temporal-staging.example.com
  rules:
    - if: $CI_COMMIT_BRANCH == "develop"

# =====================================================================
# Staging Tests
# =====================================================================
e2e-tests-staging:
  stage: test-staging
  image: python:$PYTHON_VERSION
  script:
    - pip install -r requirements-test.txt
    - pytest tests/e2e/ -v --base-url=$STAGING_BASE_URL --api-key=$STAGING_API_KEY
  rules:
    - if: $CI_COMMIT_BRANCH == "develop"

# =====================================================================
# Production Deployment
# =====================================================================
deploy-production:
  stage: deploy-production
  image: 
    name: alpine/helm:latest
    entrypoint: [""]
  before_script:
    - apk add --no-cache curl
    - curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    - chmod +x kubectl && mv kubectl /usr/local/bin/
  script:
    - echo $KUBE_CONFIG_PROD | base64 -d > ~/.kube/config
    - |
      helm upgrade --install temporal-production ./helm/temporal-stack \
        --namespace temporal-production \
        --create-namespace \
        --set image.tag=$CI_COMMIT_TAG \
        --set environment=production \
        --values ./helm/values/production.yaml \
        --wait --timeout=15m
  environment:
    name: production
    url: https://temporal.example.com
  rules:
    - if: $CI_COMMIT_TAG
  when: manual
```

## Jenkins Pipeline

### Jenkinsfile

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        REGISTRY = 'your-registry.com'
        IMAGE_NAME = 'temporal-app'
        PYTHON_VERSION = '3.11'
        KUBECONFIG = credentials('kubeconfig')
    }
    
    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 60, unit: 'MINUTES')
        skipStagesAfterUnstable()
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.GIT_COMMIT_SHORT = sh(
                        script: "git rev-parse --short HEAD",
                        returnStdout: true
                    ).trim()
                }
            }
        }
        
        stage('Setup Python Environment') {
            steps {
                sh """
                    python${PYTHON_VERSION} -m venv venv
                    . venv/bin/activate
                    pip install --upgrade pip
                    pip install -r requirements.txt
                    pip install -r requirements-test.txt
                """
            }
        }
        
        stage('Code Quality') {
            parallel {
                stage('Linting') {
                    steps {
                        sh """
                            . venv/bin/activate
                            black --check --diff .
                            isort --check-only --diff .
                            flake8 --max-line-length=88 .
                        """
                    }
                }
                stage('Type Checking') {
                    steps {
                        sh """
                            . venv/bin/activate
                            mypy src/ --ignore-missing-imports
                        """
                    }
                }
                stage('Security Check') {
                    steps {
                        sh """
                            . venv/bin/activate
                            bandit -r src/ -f json -o bandit-report.json
                            safety check --json --output safety-report.json
                        """
                        publishHTML([
                            allowMissing: false,
                            alwaysLinkToLastBuild: true,
                            keepAll: true,
                            reportDir: '.',
                            reportFiles: '*-report.json',
                            reportName: 'Security Reports'
                        ])
                    }
                }
            }
        }
        
        stage('Tests') {
            parallel {
                stage('Unit Tests') {
                    steps {
                        sh """
                            . venv/bin/activate
                            pytest tests/unit/ -v --cov=src --cov-report=xml --junitxml=unit-test-results.xml
                        """
                        junit 'unit-test-results.xml'
                        publishCoverage adapters: [
                            coberturaAdapter('coverage.xml')
                        ], sourceFileResolver: sourceFiles('STORE_LAST_BUILD')
                    }
                }
                stage('Integration Tests') {
                    when {
                        anyOf {
                            branch 'main'
                            branch 'develop'
                        }
                    }
                    steps {
                        sh """
                            docker-compose -f docker-compose.test.yml up -d
                            sleep 30
                            . venv/bin/activate
                            pytest tests/integration/ -v --junitxml=integration-test-results.xml
                            docker-compose -f docker-compose.test.yml down
                        """
                        junit 'integration-test-results.xml'
                    }
                }
            }
        }
        
        stage('Build Images') {
            when {
                anyOf {
                    branch 'main'
                    branch 'develop'
                    buildingTag()
                }
            }
            parallel {
                stage('API Image') {
                    steps {
                        script {
                            def apiImage = docker.build("${REGISTRY}/${IMAGE_NAME}-api:${GIT_COMMIT_SHORT}", "-f docker/api/Dockerfile .")
                            docker.withRegistry("https://${REGISTRY}", 'docker-registry-credentials') {
                                apiImage.push()
                                if (env.BRANCH_NAME == 'main') {
                                    apiImage.push('latest')
                                }
                            }
                        }
                    }
                }
                stage('Worker Image') {
                    steps {
                        script {
                            def workerImage = docker.build("${REGISTRY}/${IMAGE_NAME}-worker:${GIT_COMMIT_SHORT}", "-f docker/worker/Dockerfile .")
                            docker.withRegistry("https://${REGISTRY}", 'docker-registry-credentials') {
                                workerImage.push()
                                if (env.BRANCH_NAME == 'main') {
                                    workerImage.push('latest')
                                }
                            }
                        }
                    }
                }
            }
        }
        
        stage('Security Scan') {
            when {
                anyOf {
                    branch 'main'
                    branch 'develop'
                }
            }
            steps {
                sh """
                    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \\
                        aquasec/trivy:latest image \\
                        --format json --output trivy-report.json \\
                        ${REGISTRY}/${IMAGE_NAME}-api:${GIT_COMMIT_SHORT}
                """
                archiveArtifacts artifacts: 'trivy-report.json', fingerprint: true
            }
        }
        
        stage('Deploy to Staging') {
            when {
                branch 'develop'
            }
            steps {
                sh """
                    helm upgrade --install temporal-staging ./helm/temporal-stack \\
                        --namespace temporal-staging \\
                        --create-namespace \\
                        --set image.tag=${GIT_COMMIT_SHORT} \\
                        --set environment=staging \\
                        --values ./helm/values/staging.yaml \\
                        --wait --timeout=10m
                """
            }
        }
        
        stage('E2E Tests') {
            when {
                branch 'develop'
            }
            steps {
                sh """
                    . venv/bin/activate
                    pytest tests/e2e/ -v --junitxml=e2e-test-results.xml \\
                        --base-url=\$STAGING_BASE_URL \\
                        --api-key=\$STAGING_API_KEY
                """
                junit 'e2e-test-results.xml'
            }
        }
        
        stage('Deploy to Production') {
            when {
                buildingTag()
            }
            steps {
                input message: 'Deploy to production?', ok: 'Deploy'
                sh """
                    helm upgrade --install temporal-production ./helm/temporal-stack \\
                        --namespace temporal-production \\
                        --create-namespace \\
                        --set image.tag=${env.TAG_NAME} \\
                        --set environment=production \\
                        --values ./helm/values/production.yaml \\
                        --wait --timeout=15m
                """
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
        success {
            slackSend(
                channel: '#deployments',
                color: 'good',
                message: "✅ Build succeeded: ${env.JOB_NAME} - ${env.BUILD_NUMBER}"
            )
        }
        failure {
            slackSend(
                channel: '#deployments',
                color: 'danger',
                message: "❌ Build failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}"
            )
        }
    }
}
```

## Docker Configuration

### Multi-stage Dockerfile for API

```dockerfile
# docker/api/Dockerfile
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim as production

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r temporal && useradd -r -g temporal temporal

# Copy installed packages from builder
COPY --from=builder /root/.local /home/temporal/.local

# Copy application code
COPY src/ ./src/
COPY alembic.ini ./
COPY alembic/ ./alembic/

# Set up permissions
RUN chown -R temporal:temporal /app
USER temporal

# Add local packages to PATH
ENV PATH=/home/temporal/.local/bin:$PATH
ENV PYTHONPATH=/app/src

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Run application
CMD ["uvicorn", "temporal_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Worker Dockerfile

```dockerfile
# docker/worker/Dockerfile
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim as production

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r temporal && useradd -r -g temporal temporal

# Copy installed packages from builder
COPY --from=builder /root/.local /home/temporal/.local

# Copy application code
COPY src/ ./src/

# Set up permissions
RUN chown -R temporal:temporal /app
USER temporal

# Add local packages to PATH
ENV PATH=/home/temporal/.local/bin:$PATH
ENV PYTHONPATH=/app/src

# Run worker
CMD ["python", "-m", "temporal_workflows.worker"]
```

## Deployment Scripts

### Deployment Automation Script

```bash
#!/bin/bash
# scripts/deploy.sh

set -euo pipefail

# Configuration
ENVIRONMENT=${1:-staging}
IMAGE_TAG=${2:-latest}
NAMESPACE="temporal-${ENVIRONMENT}"
HELM_CHART="./helm/temporal-stack"
VALUES_FILE="./helm/values/${ENVIRONMENT}.yaml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

# Pre-deployment checks
pre_deploy_checks() {
    log "Running pre-deployment checks..."
    
    # Check if kubectl is configured
    if ! kubectl cluster-info > /dev/null 2>&1; then
        error "kubectl is not configured or cluster is not reachable"
    fi
    
    # Check if namespace exists
    if ! kubectl get namespace "$NAMESPACE" > /dev/null 2>&1; then
        log "Creating namespace: $NAMESPACE"
        kubectl create namespace "$NAMESPACE"
    fi
    
    # Check if Helm chart exists
    if [[ ! -d "$HELM_CHART" ]]; then
        error "Helm chart not found at: $HELM_CHART"
    fi
    
    # Check if values file exists
    if [[ ! -f "$VALUES_FILE" ]]; then
        error "Values file not found at: $VALUES_FILE"
    fi
    
    log "Pre-deployment checks passed ✓"
}

# Deploy application
deploy() {
    log "Deploying to $ENVIRONMENT environment..."
    log "Image tag: $IMAGE_TAG"
    log "Namespace: $NAMESPACE"
    
    helm upgrade --install "temporal-${ENVIRONMENT}" "$HELM_CHART" \
        --namespace "$NAMESPACE" \
        --set image.tag="$IMAGE_TAG" \
        --set environment="$ENVIRONMENT" \
        --values "$VALUES_FILE" \
        --wait --timeout=15m \
        --history-max=10
    
    log "Deployment completed ✓"
}

# Post-deployment verification
post_deploy_verification() {
    log "Running post-deployment verification..."
    
    # Wait for pods to be ready
    log "Waiting for pods to be ready..."
    kubectl wait --for=condition=ready pod \
        -l app.kubernetes.io/instance="temporal-${ENVIRONMENT}" \
        -n "$NAMESPACE" \
        --timeout=300s
    
    # Check pod status
    log "Pod status:"
    kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/instance="temporal-${ENVIRONMENT}"
    
    # Health check
    if [[ "$ENVIRONMENT" == "production" ]]; then
        log "Running health check..."
        if curl -f "https://temporal.example.com/health" > /dev/null 2>&1; then
            log "Health check passed ✓"
        else
            error "Health check failed"
        fi
    fi
    
    log "Post-deployment verification completed ✓"
}

# Rollback function
rollback() {
    warn "Rolling back deployment..."
    
    helm rollback "temporal-${ENVIRONMENT}" -n "$NAMESPACE"
    
    log "Rollback completed"
}

# Main execution
main() {
    log "Starting deployment process..."
    log "Environment: $ENVIRONMENT"
    log "Image tag: $IMAGE_TAG"
    
    # Set trap for cleanup on failure
    trap rollback ERR
    
    pre_deploy_checks
    deploy
    post_deploy_verification
    
    log "Deployment successful! 🎉"
}

# Execute main function
main "$@"
```

### Database Migration Script

```bash
#!/bin/bash
# scripts/migrate.sh

set -euo pipefail

ENVIRONMENT=${1:-staging}
NAMESPACE="temporal-${ENVIRONMENT}"

log() {
    echo -e "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')] $1\033[0m"
}

error() {
    echo -e "\033[0;31m[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1\033[0m"
    exit 1
}

# Run database migrations
migrate_database() {
    log "Running database migrations for $ENVIRONMENT..."
    
    # Get database connection details from secret
    DB_HOST=$(kubectl get secret temporal-db-credentials -n "$NAMESPACE" -o jsonpath='{.data.host}' | base64 -d)
    DB_USER=$(kubectl get secret temporal-db-credentials -n "$NAMESPACE" -o jsonpath='{.data.username}' | base64 -d)
    DB_PASS=$(kubectl get secret temporal-db-credentials -n "$NAMESPACE" -o jsonpath='{.data.password}' | base64 -d)
    DB_NAME=$(kubectl get secret temporal-db-credentials -n "$NAMESPACE" -o jsonpath='{.data.database}' | base64 -d)
    
    # Run migrations using kubectl job
    kubectl create job --from=cronjob/temporal-migration "migration-$(date +%s)" -n "$NAMESPACE"
    
    # Wait for migration to complete
    kubectl wait --for=condition=complete job -l job-name=migration -n "$NAMESPACE" --timeout=300s
    
    log "Database migrations completed ✓"
}

migrate_database
```

This comprehensive CI/CD pipeline guide provides enterprise-grade automation for Temporal.io deployments with robust testing, security scanning, and deployment strategies across multiple environments.
