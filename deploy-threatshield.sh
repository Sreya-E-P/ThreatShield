#!/bin/bash
# deploy-threatshield.sh
set -e

echo "🚀 ThreatShield Production Deployment"
echo "====================================="

# Configuration
ENVIRONMENT=${1:-"staging"}
LOCATION=${2:-"eastus2"}
RESOURCE_GROUP="threatshield-${ENVIRONMENT}-rg"
AKS_NAME="threatshield-aks-${ENVIRONMENT}"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Azure CLI
    if ! command -v az &> /dev/null; then
        log_error "Azure CLI not installed. Install from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    fi
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl not installed. Install from: https://kubernetes.io/docs/tasks/tools/"
    fi
    
    # Check helm
    if ! command -v helm &> /dev/null; then
        log_error "helm not installed. Install from: https://helm.sh/docs/intro/install/"
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker not installed. Install from: https://docs.docker.com/get-docker/"
    fi
    
    log_success "All prerequisites met"
}

azure_login() {
    log_info "Logging into Azure..."
    
    if ! az account show &> /dev/null; then
        az login
    fi
    
    # Set subscription if provided
    if [ -n "$AZURE_SUBSCRIPTION_ID" ]; then
        az account set --subscription "$AZURE_SUBSCRIPTION_ID"
        log_success "Using subscription: $AZURE_SUBSCRIPTION_ID"
    fi
}

create_infrastructure() {
    log_info "Creating Azure infrastructure..."
    
    # Create resource group
    az group create \
        --name "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --tags "Environment=$ENVIRONMENT" "Project=ThreatShield" \
        --output none
    
    log_success "Resource group created: $RESOURCE_GROUP"
    
    # Deploy Bicep template
    az deployment group create \
        --resource-group "$RESOURCE_GROUP" \
        --template-file "infrastructure/main.bicep" \
        --parameters \
            environment="$ENVIRONMENT" \
            location="$LOCATION" \
            adminUsername="threatshieldadmin" \
            adminPassword="$(openssl rand -base64 32)" \
        --name "threatshield-deploy-$(date +%Y%m%d-%H%M%S)" \
        --output none
    
    log_success "Azure infrastructure deployed"
}

build_and_push_images() {
    log_info "Building and pushing Docker images..."
    
    # Get ACR name
    ACR_NAME=$(az acr list --resource-group "$RESOURCE_GROUP" --query "[0].name" -o tsv)
    
    if [ -z "$ACR_NAME" ]; then
        log_error "ACR not found"
    fi
    
    # Login to ACR
    az acr login --name "$ACR_NAME"
    
    # Build and push backend
    log_info "Building backend image..."
    docker build -t "$ACR_NAME.azurecr.io/threatshield-backend:latest" -f backend/Dockerfile .
    docker push "$ACR_NAME.azurecr.io/threatshield-backend:latest"
    
    # Build and push frontend
    log_info "Building frontend image..."
    docker build -t "$ACR_NAME.azurecr.io/threatshield-frontend:latest" -f frontend/Dockerfile .
    docker push "$ACR_NAME.azurecr.io/threatshield-frontend:latest"
    
    log_success "Docker images built and pushed"
}

deploy_to_aks() {
    log_info "Deploying to AKS..."
    
    # Get AKS credentials
    az aks get-credentials \
        --resource-group "$RESOURCE_GROUP" \
        --name "$AKS_NAME" \
        --overwrite-existing
    
    # Create namespace
    kubectl create namespace threatshield --dry-run=client -o yaml | kubectl apply -f -
    
    # Create secrets
    kubectl create secret docker-registry acr-secret \
        --docker-server="$ACR_NAME.azurecr.io" \
        --docker-username=$(az acr credential show --name "$ACR_NAME" --query username -o tsv) \
        --docker-password=$(az acr credential show --name "$ACR_NAME" --query passwords[0].value -o tsv) \
        --namespace=threatshield
    
    # Deploy applications
    kubectl apply -f kubernetes/ -n threatshield
    
    # Wait for deployments
    kubectl wait --for=condition=available --timeout=300s deployment/threatshield-backend -n threatshield
    kubectl wait --for=condition=available --timeout=300s deployment/threatshield-frontend -n threatshield
    
    log_success "Applications deployed to AKS"
}

run_tests() {
    log_info "Running smoke tests..."
    
    # Get service IP
    SERVICE_IP=$(kubectl get service threatshield-frontend -n threatshield -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    
    # Wait for service to be ready
    sleep 30
    
    # Test API health
    if curl -s "http://$SERVICE_IP/api/health" | grep -q "healthy"; then
        log_success "Smoke tests passed"
    else
        log_error "Smoke tests failed"
    fi
}

display_results() {
    SERVICE_IP=$(kubectl get service threatshield-frontend -n threatshield -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    
    echo ""
    echo "🎉 DEPLOYMENT COMPLETE!"
    echo "======================="
    echo ""
    echo "🌐 Access URLs:"
    echo "   Dashboard:      http://$SERVICE_IP"
    echo "   API:            http://$SERVICE_IP/api"
    echo "   API Docs:       http://$SERVICE_IP/api/docs"
    echo ""
    echo "🔑 Admin Credentials:"
    echo "   Username: admin"
    echo "   Password: $(kubectl get secret threatshield-secrets -n threatshield -o jsonpath='{.data.admin-password}' | base64 -d)"
    echo ""
    echo "📊 Monitoring:"
    echo "   kubectl get pods -n threatshield"
    echo "   kubectl get svc -n threatshield"
    echo ""
    echo "🚀 Next Steps:"
    echo "   1. Configure SSL certificates"
    echo "   2. Set up alerting"
    echo "   3. Import threat intelligence feeds"
    echo "   4. Train AI models"
    echo ""
}

main() {
    check_prerequisites
    azure_login
    create_infrastructure
    build_and_push_images
    deploy_to_aks
    run_tests
    display_results
}

main "$@"