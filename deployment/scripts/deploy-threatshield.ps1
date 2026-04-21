<#
.SYNOPSIS
Deploy ThreatShield to production

.DESCRIPTION
This script deploys the ThreatShield platform to Kubernetes with all
5 research contributions enabled.

.PARAMETER Environment
Deployment environment (development, staging, production)

.PARAMETER Registry
Docker registry URL

.PARAMETER Tag
Docker image tag

.PARAMETER Domain
Domain name for the deployment

.EXAMPLE
.\deploy-threatshield.ps1 -Environment production -Registry "your-registry.io" -Tag "latest" -Domain "threatshield.yourdomain.com"
#>

param(
    [string]$Environment = "production",
    [string]$Registry = "your-registry.io",
    [string]$Tag = "latest",
    [string]$Domain = "threatshield.yourdomain.com",
    [switch]$DryRun = $false
)

$ErrorActionPreference = "Stop"

# Colors for output
$Green = "`e[32m"
$Yellow = "`e[33m"
$Red = "`e[31m"
$Blue = "`e[34m"
$Reset = "`e[0m"

function Write-Info {
    param([string]$Message)
    Write-Host "$Blue[INFO]$Reset $Message"
}

function Write-Success {
    param([string]$Message)
    Write-Host "$Green[SUCCESS]$Reset $Message"
}

function Write-Warning {
    param([string]$Message)
    Write-Host "$Yellow[WARNING]$Reset $Message"
}

function Write-Error {
    param([string]$Message)
    Write-Host "$Red[ERROR]$Reset $Message"
    exit 1
}

function Check-Prerequisites {
    Write-Info "Checking prerequisites..."
    
    # Check kubectl
    if (!(Get-Command kubectl -ErrorAction SilentlyContinue)) {
        Write-Error "kubectl not installed. Please install from: https://kubernetes.io/docs/tasks/tools/"
    }
    
    # Check helm
    if (!(Get-Command helm -ErrorAction SilentlyContinue)) {
        Write-Error "helm not installed. Please install from: https://helm.sh/docs/intro/install/"
    }
    
    # Check Docker
    if (!(Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Error "Docker not installed. Please install from: https://docs.docker.com/get-docker/"
    }
    
    Write-Success "All prerequisites met"
}

function Validate-Environment {
    param([string]$Env)
    
    $validEnvironments = @("development", "staging", "production")
    if ($validEnvironments -notcontains $Env) {
        Write-Error "Invalid environment: $Env. Valid options: $($validEnvironments -join ', ')"
    }
    
    if ($Env -eq "production") {
        Write-Warning "You are deploying to PRODUCTION. Ensure you have:"
        Write-Warning "  1. Valid SSL certificates"
        Write-Warning "  2. Proper backup strategy"
        Write-Warning "  3. Monitoring and alerting configured"
        Write-Warning "  4. Security review completed"
        
        $confirmation = Read-Host "Are you sure you want to continue? (yes/no)"
        if ($confirmation -ne "yes") {
            Write-Info "Deployment cancelled"
            exit 0
        }
    }
}

function Build-Images {
    param([string]$Registry, [string]$Tag)
    
    Write-Info "Building Docker images..."
    
    # Build backend
    Write-Info "Building backend image..."
    docker build -t "$Registry/threatshield-backend:$Tag" -f ../backend/Dockerfile ../backend
    
    # Build frontend
    Write-Info "Building frontend image..."
    docker build -t "$Registry/threatshield-frontend:$Tag" -f ../frontend/Dockerfile ../frontend
    
    Write-Success "Images built successfully"
}

function Push-Images {
    param([string]$Registry, [string]$Tag)
    
    Write-Info "Pushing images to registry..."
    
    # Push backend
    Write-Info "Pushing backend image..."
    docker push "$Registry/threatshield-backend:$Tag"
    
    # Push frontend
    Write-Info "Pushing frontend image..."
    docker push "$Registry/threatshield-frontend:$Tag"
    
    Write-Success "Images pushed successfully"
}

function Create-Secrets {
    param([string]$Environment)
    
    Write-Info "Creating Kubernetes secrets..."
    
    $secretsFile = "secrets-$Environment.yaml"
    
    if (!(Test-Path $secretsFile)) {
        Write-Warning "Secrets file not found: $secretsFile"
        Write-Info "Creating sample secrets file..."
        
        @"
apiVersion: v1
kind: Secret
metadata:
  name: threatshield-secrets
  namespace: threatshield-$Environment
type: Opaque
stringData:
  database-url: "postgresql://threatshield:\${POSTGRES_PASSWORD}@postgres:5432/threatshield"
  redis-url: "redis://:\${REDIS_PASSWORD}@redis:6379/0"
  jwt-secret: "\${JWT_SECRET}"
  postgres-password: "\${POSTGRES_PASSWORD}"
  misp-key: "\${MISP_API_KEY}"
  virustotal-key: "\${VIRUSTOTAL_API_KEY}"
  etherscan-key: "\${ETHERSCAN_API_KEY}"
  moralis-key: "\${MORALIS_API_KEY}"
  alchemy-key: "\${ALCHEMY_API_KEY}"
  grafana-password: "\${GRAFANA_PASSWORD}"
"@ | Out-File $secretsFile
        
        Write-Warning "Please update $secretsFile with actual secrets before continuing"
        exit 1
    }
    
    kubectl apply -f $secretsFile
    Write-Success "Secrets created"
}

function Deploy-Helm {
    param(
        [string]$Environment,
        [string]$Registry,
        [string]$Tag,
        [string]$Domain,
        [switch]$DryRun
    )
    
    Write-Info "Deploying with Helm..."
    
    # Create namespace
    kubectl create namespace "threatshield-$Environment" --dry-run=client -o yaml | kubectl apply -f -
    
    # Update Helm dependencies
    helm dependency update ../kubernetes/helm
    
    # Deploy with Helm
    $helmArgs = @(
        "upgrade", "--install",
        "threatshield-$Environment",
        "../kubernetes/helm",
        "--namespace", "threatshield-$Environment",
        "--create-namespace",
        "--set", "global.environment=$Environment",
        "--set", "global.registry=$Registry",
        "--set", "global.imageTag=$Tag",
        "--set", "global.domain=$Domain",
        "--set", "backend.replicaCount=3",
        "--set", "frontend.replicaCount=2",
        "--set", "monitoring.enabled=true",
        "--values", "../kubernetes/helm/values.yaml",
        "--values", "values-$Environment.yaml"
    )
    
    if ($DryRun) {
        $helmArgs += "--dry-run"
    }
    
    helm @helmArgs
    
    if (!$DryRun) {
        Write-Success "Helm deployment completed"
    }
}

function Wait-For-Deployment {
    param([string]$Environment)
    
    Write-Info "Waiting for deployment to be ready..."
    
    $namespace = "threatshield-$Environment"
    
    # Wait for pods
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=threatshield -n $namespace --timeout=300s
    
    # Wait for services
    $services = @("backend", "frontend", "postgres", "redis")
    foreach ($service in $services) {
        kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=$service -n $namespace --timeout=300s
    }
    
    Write-Success "All services are ready"
}

function Test-Deployment {
    param([string]$Environment, [string]$Domain)
    
    Write-Info "Testing deployment..."
    
    $namespace = "threatshield-$Environment"
    
    # Get frontend service
    $frontendIp = kubectl get service "threatshield-$Environment-frontend" -n $namespace -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
    
    if (!$frontendIp) {
        Write-Warning "Frontend LoadBalancer IP not ready yet"
        return $false
    }
    
    # Test health endpoints
    try {
        $healthUrl = "http://$frontendIp/api/health"
        $response = Invoke-RestMethod -Uri $healthUrl -Method Get -TimeoutSec 10
        
        if ($response.status -eq "healthy") {
            Write-Success "Deployment health check passed"
            return $true
        }
    }
    catch {
        Write-Warning "Health check failed: $_"
        return $false
    }
}

function Show-Endpoints {
    param([string]$Environment, [string]$Domain)
    
    Write-Host "`n🚀 ThreatShield Deployment Complete!" -ForegroundColor Cyan
    Write-Host "`n🌐 Access URLs:" -ForegroundColor Yellow
    
    if ($Environment -eq "production") {
        Write-Host "   Dashboard:      https://$Domain" -ForegroundColor White
        Write-Host "   API:            https://$Domain/api" -ForegroundColor White
        Write-Host "   API Docs:       https://$Domain/api/docs" -ForegroundColor White
        Write-Host "   Grafana:        https://$Domain/grafana" -ForegroundColor White
    }
    else {
        $namespace = "threatshield-$Environment"
        $frontendIp = kubectl get service "threatshield-$Environment-frontend" -n $namespace -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
        
        if ($frontendIp) {
            Write-Host "   Dashboard:      http://$frontendIp" -ForegroundColor White
            Write-Host "   API:            http://$frontendIp/api" -ForegroundColor White
            Write-Host "   API Docs:       http://$frontendIp/api/docs" -ForegroundColor White
        }
    }
    
    Write-Host "`n🔑 Admin Credentials:" -ForegroundColor Yellow
    Write-Host "   Username: admin" -ForegroundColor White
    Write-Host "   Password: Check Kubernetes secrets" -ForegroundColor White
    
    Write-Host "`n📊 Monitoring Commands:" -ForegroundColor Yellow
    Write-Host "   kubectl get pods -n threatshield-$Environment" -ForegroundColor White
    Write-Host "   kubectl get svc -n threatshield-$Environment" -ForegroundColor White
    Write-Host "   kubectl get ingress -n threatshield-$Environment" -ForegroundColor White
    
    Write-Host "`n📈 Research Contributions:" -ForegroundColor Yellow
    Write-Host "   1. ✅ Hybrid Post-Quantum Cryptography" -ForegroundColor Green
    Write-Host "   2. ✅ AI for Zero-Day Threat Prediction" -ForegroundColor Green
    Write-Host "   3. ✅ Autonomous Cyber Defense with RL" -ForegroundColor Green
    Write-Host "   4. ✅ Multi-chain Blockchain Forensics" -ForegroundColor Green
    Write-Host "   5. ✅ Confidential Edge Computing with SGX" -ForegroundColor Green
}

function Main {
    param(
        [string]$Environment,
        [string]$Registry,
        [string]$Tag,
        [string]$Domain,
        [switch]$DryRun
    )
    
    Write-Host "`n🛡️  ThreatShield Production Deployment`n" -ForegroundColor Cyan
    
    # Validate
    Check-Prerequisites
    Validate-Environment -Env $Environment
    
    if (!$DryRun) {
        # Build and push
        Build-Images -Registry $Registry -Tag $Tag
        Push-Images -Registry $Registry -Tag $Tag
        
        # Create secrets
        Create-Secrets -Environment $Environment
    }
    
    # Deploy with Helm
    Deploy-Helm -Environment $Environment -Registry $Registry -Tag $Tag -Domain $Domain -DryRun:$DryRun
    
    if (!$DryRun) {
        # Wait and test
        Wait-For-Deployment -Environment $Environment
        
        $deploymentTest = Test-Deployment -Environment $Environment -Domain $Domain
        if ($deploymentTest) {
            Show-Endpoints -Environment $Environment -Domain $Domain
        }
        else {
            Write-Warning "Deployment completed but tests failed. Check logs with:"
            Write-Warning "  kubectl logs -l app.kubernetes.io/name=threatshield -n threatshield-$Environment --tail=100"
        }
    }
    else {
        Write-Success "Dry run completed successfully"
    }
}

# Run main function
Main -Environment $Environment -Registry $Registry -Tag $Tag -Domain $Domain -DryRun:$DryRun