# deployment/scripts/setup-azure.ps1
param(
    [string]$Environment = "production",
    [string]$Location = "eastus2",
    [string]$SubscriptionId = ""
)

$ErrorActionPreference = "Stop"

# Colors for output
$Green = "`e[32m"
$Yellow = "`e[33m"
$Red = "`e[31m"
$Reset = "`e[0m"

function Write-Info {
    param([string]$Message)
    Write-Host "$Yellow[INFO]$Reset $Message"
}

function Write-Success {
    param([string]$Message)
    Write-Host "$Green[SUCCESS]$Reset $Message"
}

function Write-Error {
    param([string]$Message)
    Write-Host "$Red[ERROR]$Reset $Message"
    exit 1
}

function Check-Prerequisites {
    Write-Info "Checking prerequisites..."
    
    # Check Azure CLI
    if (!(Get-Command az -ErrorAction SilentlyContinue)) {
        Write-Error "Azure CLI not installed. Please install from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    }
    
    # Check kubectl
    if (!(Get-Command kubectl -ErrorAction SilentlyContinue)) {
        Write-Error "kubectl not installed. Please install from: https://kubernetes.io/docs/tasks/tools/"
    }
    
    # Check helm
    if (!(Get-Command helm -ErrorAction SilentlyContinue)) {
        Write-Error "helm not installed. Please install from: https://helm.sh/docs/intro/install/"
    }
    
    Write-Success "All prerequisites met"
}

function Login-Azure {
    Write-Info "Logging into Azure..."
    
    $account = az account show --query id -o tsv 2>$null
    if ($LASTEXITCODE -ne 0) {
        az login
    }
    
    if ($SubscriptionId) {
        az account set --subscription $SubscriptionId
        Write-Success "Using subscription: $SubscriptionId"
    }
    
    $currentSub = az account show --query "name" -o tsv
    Write-Success "Logged in to Azure subscription: $currentSub"
}

function Deploy-Infrastructure {
    param(
        [string]$Environment,
        [string]$Location
    )
    
    Write-Info "Deploying Azure infrastructure..."
    
    $prefix = "threatshield"
    $resourceGroup = "$prefix-$Environment-rg"
    
    # Create resource group
    az group create `
        --name $resourceGroup `
        --location $Location `
        --tags "Environment=$Environment" "Application=ThreatShield" `
        --output none
    
    Write-Success "Resource group created: $resourceGroup"
    
    # Deploy Bicep template
    az deployment group create `
        --resource-group $resourceGroup `
        --template-file "../infrastructure/main.bicep" `
        --parameters `
            environment=$Environment `
            location=$Location `
            prefix=$prefix `
        --name "threatshield-deploy-$(Get-Date -Format 'yyyyMMdd-HHmmss')" `
        --output none
    
    Write-Success "Azure infrastructure deployed"
    
    # Get outputs
    $outputs = az deployment group show `
        --resource-group $resourceGroup `
        --name "threatshield-deploy-*" `
        --query properties.outputs `
        --output json | ConvertFrom-Json
    
    return @{
        ResourceGroup = $resourceGroup
        AKSClusterName = $outputs.aksClusterName.value
        ACRLoginServer = $outputs.acrLoginServer.value
        KeyVaultUri = $outputs.keyVaultUri.value
    }
}

function Build-Push-Images {
    param(
        [string]$ACRLoginServer
    )
    
    Write-Info "Building and pushing Docker images..."
    
    # Login to ACR
    az acr login --name $ACRLoginServer.Split('.')[0]
    
    # Build and push backend
    Write-Info "Building backend image..."
    docker build -t "$ACRLoginServer/backend:latest" -f ../../backend/Dockerfile ../../backend
    docker push "$ACRLoginServer/backend:latest"
    
    # Build and push frontend
    Write-Info "Building frontend image..."
    docker build -t "$ACRLoginServer/frontend:latest" -f ../../frontend/Dockerfile ../../frontend
    docker push "$ACRLoginServer/frontend:latest"
    
    Write-Success "Docker images built and pushed"
}

function Deploy-Kubernetes {
    param(
        [string]$ResourceGroup,
        [string]$AKSClusterName,
        [string]$ACRLoginServer
    )
    
    Write-Info "Deploying to AKS..."
    
    # Get AKS credentials
    az aks get-credentials `
        --resource-group $ResourceGroup `
        --name $AKSClusterName `
        --overwrite-existing
    
    # Create namespace
    kubectl create namespace threatshield --dry-run=client -o yaml | kubectl apply -f -
    
    # Create ACR secret
    $acrName = $ACRLoginServer.Split('.')[0]
    $username = az acr credential show --name $acrName --query username -o tsv
    $password = az acr credential show --name $acrName --query passwords[0].value -o tsv
    
    kubectl create secret docker-registry acr-secret `
        --docker-server=$ACRLoginServer `
        --docker-username=$username `
        --docker-password=$password `
        --namespace=threatshield
    
    # Create secrets
    $secrets = @"
apiVersion: v1
kind: Secret
metadata:
  name: threatshield-secrets
  namespace: threatshield
type: Opaque
data:
  database-url: $(echo "postgresql://threatshield:$(openssl rand -base64 32)@postgres:5432/threatshield" | base64)
  redis-url: $(echo "redis://redis:6379" | base64)
  jwt-secret: $(openssl rand -base64 32 | base64)
  misp-key: $(echo "your-misp-key-here" | base64)
"@
    
    echo $secrets | kubectl apply -f -
    
    # Deploy applications
    kubectl apply -f ../../kubernetes/manifests/ -n threatshield
    
    # Wait for deployments
    kubectl wait --for=condition=available --timeout=300s deployment/threatshield-backend -n threatshield
    kubectl wait --for=condition=available --timeout=300s deployment/threatshield-frontend -n threatshield
    
    Write-Success "Applications deployed to AKS"
}

function Get-Endpoints {
    param(
        [string]$Namespace = "threatshield"
    )
    
    Write-Info "Getting service endpoints..."
    
    # Get external IP
    $frontendIp = kubectl get service threatshield-frontend -n $Namespace -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
    
    if (!$frontendIp) {
        Write-Info "Waiting for LoadBalancer IP..."
        Start-Sleep -Seconds 30
        $frontendIp = kubectl get service threatshield-frontend -n $Namespace -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
    }
    
    return @{
        FrontendUrl = "http://$frontendIp"
        ApiUrl = "http://$frontendIp/api"
        ApiDocs = "http://$frontendIp/api/docs"
    }
}

function Run-SmokeTests {
    param(
        [string]$ApiUrl
    )
    
    Write-Info "Running smoke tests..."
    
    try {
        $health = Invoke-RestMethod -Uri "$ApiUrl/health" -Method Get
        if ($health.status -eq "healthy") {
            Write-Success "Smoke tests passed"
            return $true
        }
    }
    catch {
        Write-Error "Smoke tests failed: $_"
        return $false
    }
}

function Main {
    param(
        [string]$Environment,
        [string]$Location
    )
    
    Write-Host "`n🚀 ThreatShield Deployment to Azure`n" -ForegroundColor Cyan
    
    # Check prerequisites
    Check-Prerequisites
    
    # Login to Azure
    Login-Azure
    
    # Deploy infrastructure
    $infra = Deploy-Infrastructure -Environment $Environment -Location $Location
    
    # Build and push images
    Build-Push-Images -ACRLoginServer $infra.ACRLoginServer
    
    # Deploy to Kubernetes
    Deploy-Kubernetes `
        -ResourceGroup $infra.ResourceGroup `
        -AKSClusterName $infra.AKSClusterName `
        -ACRLoginServer $infra.ACRLoginServer
    
    # Get endpoints
    $endpoints = Get-Endpoints
    
    # Run smoke tests
    $testsPassed = Run-SmokeTests -ApiUrl $endpoints.ApiUrl
    
    if ($testsPassed) {
        Write-Host "`n🎉 DEPLOYMENT COMPLETE!`n" -ForegroundColor Green
        Write-Host "🌐 Access URLs:" -ForegroundColor Yellow
        Write-Host "   Dashboard:      $($endpoints.FrontendUrl)" -ForegroundColor White
        Write-Host "   API:            $($endpoints.ApiUrl)" -ForegroundColor White
        Write-Host "   API Docs:       $($endpoints.ApiDocs)" -ForegroundColor White
        
        Write-Host "`n🔑 Admin Credentials:" -ForegroundColor Yellow
        Write-Host "   Username: admin" -ForegroundColor White
        Write-Host "   Password: admin123" -ForegroundColor White
        
        Write-Host "`n📊 Monitoring:" -ForegroundColor Yellow
        Write-Host "   kubectl get pods -n threatshield" -ForegroundColor White
        Write-Host "   kubectl get svc -n threatshield" -ForegroundColor White
        
        Write-Host "`n🚀 Next Steps:" -ForegroundColor Yellow
        Write-Host "   1. Configure SSL certificates" -ForegroundColor White
        Write-Host "   2. Set up alerting in Azure Monitor" -ForegroundColor White
        Write-Host "   3. Import threat intelligence feeds" -ForegroundColor White
        Write-Host "   4. Train AI models with your data" -ForegroundColor White
    }
    else {
        Write-Error "Deployment completed with issues. Check logs for details."
    }
}

# Run main function
Main -Environment $Environment -Location $Location