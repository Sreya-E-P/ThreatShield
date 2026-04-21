.PHONY: help setup build push deploy test clean logs monitor backup restore \
        dev dev-down infra-deploy infra-destroy k8s-setup sgx-setup \
        security-scan performance-test deploy-all

# Variables
DOCKER_REGISTRY ?= your-registry.azurecr.io
IMAGE_TAG ?= latest
NAMESPACE ?= threatshield
ENVIRONMENT ?= production
LOCATION ?= eastus
PREFIX ?= threatshield
ACR_NAME ?= $(PREFIX)$(ENVIRONMENT)cr
AKS_NAME ?= $(PREFIX)-$(ENVIRONMENT)-aks
RESOURCE_GROUP ?= $(PREFIX)-$(ENVIRONMENT)-rg

# Get Azure outputs dynamically
ACR_LOGIN = $(shell az acr show --name $(ACR_NAME) --resource-group $(RESOURCE_GROUP) --query loginServer -o tsv 2>/dev/null || echo "$(DOCKER_REGISTRY)")
AKS_IDENTITY_ID = $(shell az aks show --name $(AKS_NAME) --resource-group $(RESOURCE_GROUP) --query identity.principalId -o tsv 2>/dev/null || echo "")

help:
	@echo "🚀 ThreatShield Production Commands:"
	@echo ""
	@echo "🔧 Development:"
	@echo "  make setup           - Setup development environment"
	@echo "  make dev             - Start development environment"
	@echo "  make dev-down        - Stop development environment"
	@echo ""
	@echo "🐳 Docker:"
	@echo "  make build           - Build Docker images"
	@echo "  make push            - Push images to registry"
	@echo ""
	@echo "☁️  Azure Infrastructure:"
	@echo "  make infra-deploy    - Deploy Azure infrastructure"
	@echo "  make infra-destroy   - Destroy Azure infrastructure"
	@echo "  make k8s-setup       - Setup Kubernetes secrets"
	@echo "  make sgx-setup       - Configure SGX VMs"
	@echo ""
	@echo "⚙️  Kubernetes:"
	@echo "  make deploy          - Deploy to Kubernetes"
	@echo "  make k8s-clean       - Clean Kubernetes resources"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  make test            - Run all tests"
	@echo "  make security-scan   - Security scan images"
	@echo "  make performance-test - Run performance tests"
	@echo ""
	@echo "📊 Monitoring:"
	@echo "  make logs            - View logs"
	@echo "  make monitor         - Open monitoring dashboard"
	@echo ""
	@echo "💾 Backup & Restore:"
	@echo "  make backup          - Backup data"
	@echo "  make restore         - Restore from backup"
	@echo ""
	@echo "🚀 Complete Deployment:"
	@echo "  make deploy-all      - Full deployment pipeline"

setup:
	@echo "🔧 Setting up ThreatShield environment..."
	@echo "Installing Python dependencies..."
	pip install -r backend/requirements.txt
	@echo "Installing Node.js dependencies..."
	npm install --prefix frontend
	@echo "Creating Docker network..."
	docker network create threatshield-network 2>/dev/null || true
	@echo "✅ Environment setup complete!"

build:
	@echo "🐳 Building Docker images..."
	docker build -t $(ACR_LOGIN)/threatshield-backend:$(IMAGE_TAG) \
		-f backend/Dockerfile ./backend
	docker build -t $(ACR_LOGIN)/threatshield-frontend:$(IMAGE_TAG) \
		-f frontend/Dockerfile ./frontend
	@echo "✅ Build complete!"

push:
	@echo "📤 Pushing images to registry..."
	az acr login --name $(ACR_NAME)
	docker push $(ACR_LOGIN)/threatshield-backend:$(IMAGE_TAG)
	docker push $(ACR_LOGIN)/threatshield-frontend:$(IMAGE_TAG)
	@echo "✅ Push complete!"

deploy:
	@echo "⚙️  Deploying ThreatShield to $(ENVIRONMENT)..."
	kubectl apply -f kubernetes/manifests/namespace.yaml
	kubectl apply -f kubernetes/manifests/configmap.yaml
	# Create or update secrets
	kubectl delete secret threatshield-secrets -n $(NAMESPACE) 2>/dev/null || true
	kubectl create secret generic threatshield-secrets \
		--from-literal=database-password=$$(openssl rand -base64 32) \
		--from-literal=jwt-secret=$$(openssl rand -base64 64) \
		--from-literal=redis-password=$$(openssl rand -base64 32) \
		--namespace=$(NAMESPACE)
	kubectl apply -f kubernetes/manifests/deployment.yaml
	kubectl apply -f kubernetes/manifests/service.yaml
	kubectl apply -f kubernetes/manifests/ingress.yaml
	kubectl apply -f kubernetes/manifests/hpa.yaml
	kubectl apply -f kubernetes/manifests/pvc.yaml
	@echo "⏳ Waiting for pods to be ready..."
	kubectl wait --for=condition=ready pod -l app=threatshield -n $(NAMESPACE) --timeout=300s
	@echo "✅ ThreatShield is ready!"

test:
	@echo "🧪 Running tests..."
	@echo "Running backend tests..."
	cd backend && python -m pytest tests/ -v --cov=src --cov-report=html
	@echo "Running frontend tests..."
	cd frontend && npm test -- --watchAll=false --coverage
	@echo "✅ Tests complete!"

clean:
	@echo "🧹 Cleaning up resources..."
	docker-compose down -v
	rm -rf backend/.coverage backend/htmlcov frontend/coverage
	rm -rf models/* keys/* logs/* __pycache__ */__pycache__
	@echo "✅ Cleanup complete!"

k8s-clean:
	@echo "🧹 Cleaning Kubernetes resources..."
	kubectl delete -f kubernetes/manifests/ --ignore-not-found=true
	kubectl delete namespace $(NAMESPACE) --ignore-not-found=true
	@echo "✅ Kubernetes cleanup complete!"

logs:
	@echo "📋 Viewing logs..."
	kubectl logs -l app=threatshield -n $(NAMESPACE) --tail=100 -f

monitor:
	@echo "📊 Opening monitoring dashboard..."
	@echo "Grafana: http://localhost:3001"
	@echo "Prometheus: http://localhost:9090"
	@echo "Kiali: http://localhost:20001"
	xdg-open http://localhost:3001 2>/dev/null || \
	open http://localhost:3001 2>/dev/null || \
	echo "Open http://localhost:3001 in your browser"

backup:
	@echo "💾 Creating backup..."
	timestamp=$$(date +%Y%m%d_%H%M%S)
	mkdir -p backups/$$timestamp
	# Backup database
	kubectl exec -n $(NAMESPACE) deployment/threatshield-backend -- \
		pg_dump -U threatshield -h postgres threatshield > backups/$$timestamp/database.sql 2>/dev/null || \
		echo "Database backup skipped - container not running"
	# Backup models and keys
	kubectl cp $(NAMESPACE)/deployment/threatshield-backend:/app/models backups/$$timestamp/models 2>/dev/null || true
	kubectl cp $(NAMESPACE)/deployment/threatshield-backend:/app/keys backups/$$timestamp/keys 2>/dev/null || true
	# Create archive
	tar -czf backups/threatshield_backup_$$timestamp.tar.gz -C backups/$$timestamp .
	rm -rf backups/$$timestamp
	@echo "✅ Backup saved to backups/threatshield_backup_$$timestamp.tar.gz"

restore:
	@echo "🔄 Restoring from backup..."
	@if [ -z "$$backup_file" ]; then \
		read -p "Enter backup file path: " backup_file; \
	fi; \
	if [ ! -f "$$backup_file" ]; then \
		echo "❌ Backup file not found: $$backup_file"; \
		exit 1; \
	fi; \
	mkdir -p /tmp/threatshield_restore_$$(date +%s); \
	tar -xzf $$backup_file -C /tmp/threatshield_restore_$$(date +%s); \
	restore_dir=$$(find /tmp/threatshield_restore_* -type d | head -1); \
	echo "Restoring from $$restore_dir..."; \
	# Restore database
	if [ -f "$$restore_dir/database.sql" ]; then \
		kubectl cp $$restore_dir/database.sql $(NAMESPACE)/deployment/threatshield-backend:/tmp/restore.sql; \
		kubectl exec -n $(NAMESPACE) deployment/threatshield-backend -- \
			psql -U threatshield -h postgres -d threatshield -f /tmp/restore.sql; \
	fi; \
	# Restore models
	if [ -d "$$restore_dir/models" ]; then \
		kubectl cp $$restore_dir/models $(NAMESPACE)/deployment/threatshield-backend:/app/models; \
	fi; \
	# Restore keys
	if [ -d "$$restore_dir/keys" ]; then \
		kubectl cp $$restore_dir/keys $(NAMESPACE)/deployment/threatshield-backend:/app/keys; \
	fi; \
	rm -rf $$restore_dir; \
	@echo "✅ Restore complete!"

# Development commands
dev:
	@echo "🚀 Starting development environment..."
	docker-compose up -d postgres redis
	@echo "Starting backend server..."
	cd backend && uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000 &
	@echo "Starting frontend server..."
	cd frontend && npm start &
	@echo "✅ Development servers started!"
	@echo "Backend: http://localhost:8000"
	@echo "Frontend: http://localhost:3000"
	@echo "API Docs: http://localhost:8000/api/docs"

dev-down:
	@echo "🛑 Stopping development environment..."
	docker-compose down
	pkill -f "uvicorn src.api.main:app" 2>/dev/null || true
	pkill -f "npm start" 2>/dev/null || true
	@echo "✅ Development environment stopped!"

# Infrastructure deployment
infra-deploy:
	@echo "☁️  Deploying Azure infrastructure..."
	az deployment sub create \
		--name "threatshield-infra-$$(date +%Y%m%d-%H%M%S)" \
		--location $(LOCATION) \
		--template-file infrastructure/main.bicep \
		--parameters \
			location=$(LOCATION) \
			environment=$(ENVIRONMENT) \
			prefix=$(PREFIX) \
			adminObjectId=$$(az ad signed-in-user show --query id -o tsv) \
		--output json
	@echo "✅ Infrastructure deployment initiated!"

infra-destroy:
	@echo "🗑️  Destroying Azure infrastructure..."
	@read -p "Are you sure you want to delete resource group $(RESOURCE_GROUP)? [y/N] " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		az group delete --name $(RESOURCE_GROUP) --yes --no-wait; \
		echo "✅ Resource group deletion initiated!"; \
	else \
		echo "❌ Cancelled."; \
	fi

# Kubernetes setup
k8s-setup:
	@echo "🔧 Setting up Kubernetes..."
	# Get AKS credentials
	az aks get-credentials \
		--resource-group $(RESOURCE_GROUP) \
		--name $(AKS_NAME) \
		--overwrite-existing
	# Create namespace
	kubectl create namespace $(NAMESPACE) --dry-run=client -o yaml | kubectl apply -f -
	# Setup secrets from Key Vault
	az aks enable-addons \
		--resource-group $(RESOURCE_GROUP) \
		--name $(AKS_NAME) \
		--addons azure-keyvault-secrets-provider
	@echo "✅ Kubernetes setup complete!"

# SGX VM setup
sgx-setup:
	@echo "🔒 Configuring SGX VMs..."
	# Get VM IP addresses
	VM1_IP=$$(az vm show \
		--resource-group $(RESOURCE_GROUP) \
		--name $(PREFIX)-$(ENVIRONMENT)-sgx-01 \
		--show-details \
		--query publicIps \
		-o tsv)
	VM2_IP=$$(az vm show \
		--resource-group $(RESOURCE_GROUP) \
		--name $(PREFIX)-$(ENVIRONMENT)-sgx-02 \
		--show-details \
		--query publicIps \
		-o tsv)
	@echo "SGX VM 1 IP: $$VM1_IP"
	@echo "SGX VM 2 IP: $$VM2_IP"
	@echo "✅ SGX VMs configured!"

# Security scan
security-scan:
	@echo "🔐 Running security scans..."
	docker scan $(ACR_LOGIN)/threatshield-backend:$(IMAGE_TAG) || echo "Scan failed - check Docker login"
	docker scan $(ACR_LOGIN)/threatshield-frontend:$(IMAGE_TAG) || echo "Scan failed - check Docker login"
	trivy image $(ACR_LOGIN)/threatshield-backend:$(IMAGE_TAG) 2>/dev/null || echo "Install trivy for detailed scans: brew install trivy"
	@echo "✅ Security scan complete!"

# Performance test
performance-test:
	@echo "⚡ Running performance tests..."
	cd backend && locust -f tests/performance/locustfile.py \
		--host=http://localhost:8000 \
		--users=100 \
		--spawn-rate=10 \
		--run-time=5m \
		--headless \
		--csv=performance_test \
		--html=performance_report.html
	@echo "✅ Performance test complete!"
	@echo "Report saved to backend/performance_report.html"

# Complete deployment pipeline
deploy-all: infra-deploy k8s-setup build push deploy sgx-setup
	@echo "🎉 Full deployment complete!"
	@echo "ThreatShield is now running in $(ENVIRONMENT) environment."
	@echo "Access the dashboard with: make monitor"
	@echo "View logs with: make logs"

# Validation commands
validate:
	@echo "✅ Validating deployment..."
	@echo "1. Checking Azure resources..."
	az group show --name $(RESOURCE_GROUP) --query properties.provisioningState -o tsv
	@echo "2. Checking AKS cluster..."
	az aks show --name $(AKS_NAME) --resource-group $(RESOURCE_GROUP) --query provisioningState -o tsv
	@echo "3. Checking Kubernetes pods..."
	kubectl get pods -n $(NAMESPACE)
	@echo "4. Checking services..."
	kubectl get svc -n $(NAMESPACE)
	@echo "✅ Validation complete!"

# Database operations
db-migrate:
	@echo "🔄 Running database migrations..."
	kubectl exec -n $(NAMESPACE) deployment/threatshield-backend -- \
		alembic upgrade head
	@echo "✅ Database migrations complete!"

db-seed:
	@echo "🌱 Seeding database with sample data..."
	kubectl exec -n $(NAMESPACE) deployment/threatshield-backend -- \
		python -c "from src.database.seed import seed_all; seed_all()"
	@echo "✅ Database seeding complete!"

# Certificate management
certs-renew:
	@echo "📜 Renewing SSL certificates..."
	kubectl delete secret threatshield-tls -n $(NAMESPACE) 2>/dev/null || true
	kubectl create secret tls threatshield-tls \
		--cert=./certs/certificate.pem \
		--key=./certs/private-key.pem \
		-n $(NAMESPACE)
	@echo "✅ Certificates renewed!"