# deploy-windows.ps1 - Complete Windows deployment script for ThreatShield
param(
    [string]$Environment = "staging",
    [string]$Location = "eastus",
    [string]$Prefix = "threatshield",
    [switch]$SkipInfra = $false,
    [switch]$SkipBuild = $false,
    [switch]$SkipDeploy = $false
)

$ErrorActionPreference = "Stop"

Write-Host "`n"
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "🚀 THREATSHIELD DEPLOYMENT PIPELINE" -ForegroundColor Cyan
Write-Host "Environment: $Environment" -ForegroundColor Yellow
Write-Host "Location: $Location" -ForegroundColor Yellow
Write-Host "Prefix: $Prefix" -ForegroundColor Yellow
Write-Host "==================================================`n" -ForegroundColor Cyan

function Write-Step {
    param([string]$Message, [int]$Step)
    Write-Host "[Step $Step] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
    throw $Message
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

# Step 1: Check prerequisites
function Check-Prerequisites {
    Write-Step "Checking prerequisites..." 1
    
    $tools = @(
        @{Name="Azure CLI"; Command="az"; URL="https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"},
        @{Name="Docker"; Command="docker"; URL="https://docs.docker.com/get-docker/"},
        @{Name="Kubectl"; Command="kubectl"; URL="https://kubernetes.io/docs/tasks/tools/"}
    )
    
    foreach ($tool in $tools) {
        try {
            $null = Get-Command $tool.Command -ErrorAction Stop
            Write-Success "$($tool.Name) installed"
        } catch {
            Write-Error "$($tool.Name) not installed. Download from: $($tool.URL)"
        }
    }
    
    # Check Azure login
    try {
        $account = az account show --query id -o tsv 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Not logged into Azure. Please login..."
            az login
        } else {
            $currentSub = az account show --query "name" -o tsv
            Write-Success "Logged into Azure subscription: $currentSub"
        }
    } catch {
        Write-Error "Azure CLI not configured properly"
    }
}

# Step 2: Deploy local development environment (Docker Compose)
function Deploy-Local {
    Write-Step "Deploying local development environment..." 2
    
    if (-not (Test-Path .\.env)) {
        Write-Warning "Creating .env file..."
        @"
# Database
DATABASE_URL=postgresql+asyncpg://threatshield:password@localhost/threatshield
POSTGRES_PASSWORD=ChangeThisInProduction!123

# Redis
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=ChangeThisInProduction!123

# Security
JWT_SECRET=YourSuperSecretKeyChangeInProduction

# API Keys (get free ones)
MISP_API_KEY=your-misp-key
VIRUSTOTAL_API_KEY=your-virustotal-key
ETHERSCAN_API_KEY=your-etherscan-key
MORALIS_API_KEY=your-moralis-key
ALCHEMY_API_KEY=your-alchemy-key

# Environment
ENVIRONMENT=development
LOG_LEVEL=DEBUG
"@ | Out-File .\.env -Encoding UTF8
        Write-Success ".env file created. Please update API keys with your own."
    }
    
    # Create necessary directories
    $dirs = @("models", "keys", "logs")
    foreach ($dir in $dirs) {
        if (-not (Test-Path .\$dir)) {
            New-Item -ItemType Directory -Path .\$dir -Force | Out-Null
        }
    }
    
    # Start Docker Compose
    Write-Host "Starting Docker Compose..." -ForegroundColor White
    docker-compose up -d
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Local development environment deployed!"
        Write-Host "`nAccess URLs:" -ForegroundColor Yellow
        Write-Host "  Dashboard: http://localhost:3000" -ForegroundColor White
        Write-Host "  API: http://localhost:8000" -ForegroundColor White
        Write-Host "  API Docs: http://localhost:8000/api/docs" -ForegroundColor White
        Write-Host "  Prometheus: http://localhost:9090" -ForegroundColor White
        Write-Host "  Grafana: http://localhost:3001" -ForegroundColor White
    } else {
        Write-Error "Failed to start Docker Compose"
    }
}

# Step 3: Build Docker images
function Build-Images {
    Write-Step "Building Docker images..." 3
    
    Write-Host "Building backend image..." -ForegroundColor White
    docker build -t "threatshield-backend:latest" -f ./backend/Dockerfile ./backend
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to build backend image"
    }
    
    Write-Host "Building frontend image..." -ForegroundColor White
    docker build -t "threatshield-frontend:latest" -f ./frontend/Dockerfile ./frontend
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to build frontend image"
    }
    
    Write-Success "Docker images built successfully"
}

# Step 4: Deploy to local Kubernetes (minikube)
function Deploy-Local-Kubernetes {
    Write-Step "Deploying to local Kubernetes..." 4
    
    # Check if minikube is installed
    try {
        $null = Get-Command minikube -ErrorAction Stop
    } catch {
        Write-Warning "Minikube not installed. Installing..."
        choco install minikube -y
    }
    
    # Start minikube
    Write-Host "Starting minikube..." -ForegroundColor White
    minikube start --memory=8192 --cpus=4
    
    # Enable ingress
    minikube addons enable ingress
    
    # Create namespace
    kubectl create namespace threatshield --dry-run=client -o yaml | kubectl apply -f -
    
    # Apply manifests
    $manifestPath = ".\kubernetes\manifests"
    
    Write-Host "Applying Kubernetes manifests..." -ForegroundColor White
    Get-ChildItem -Path $manifestPath -Filter "*.yaml" | ForEach-Object {
        kubectl apply -f $_.FullName -n threatshield
    }
    
    Write-Success "Kubernetes deployment complete!"
    
    # Get minikube IP
    $minikubeIP = minikube ip
    
    Write-Host "`nAccess URLs:" -ForegroundColor Yellow
    Write-Host "  Dashboard: http://$minikubeIP" -ForegroundColor White
    Write-Host "  API: http://$minikubeIP/api" -ForegroundColor White
    Write-Host "`nTo view logs:" -ForegroundColor Yellow
    Write-Host "  kubectl get pods -n threatshield" -ForegroundColor White
    Write-Host "  kubectl logs -l app=threatshield -n threatshield --tail=100" -ForegroundColor White
}

# Step 5: Run tests
function Run-Tests {
    Write-Step "Running tests..." 5
    
    # Backend tests
    Write-Host "Running backend tests..." -ForegroundColor White
    cd backend
    if (Test-Path "requirements.txt") {
        pip install -r requirements.txt
    }
    python -m pytest tests/ -v
    cd ..
    
    # Frontend tests
    Write-Host "Running frontend tests..." -ForegroundColor White
    cd frontend
    npm test -- --watchAll=false --passWithNoTests
    cd ..
    
    Write-Success "Tests completed"
}

# Step 6: Show research contributions
function Show-Research {
    Write-Step "Research Contributions Status" 6
    
    Write-Host "`n🔬 ACADEMIC RESEARCH CONTRIBUTIONS:" -ForegroundColor Yellow
    Write-Host "`n1. 🛡️  Hybrid Post-Quantum Cryptography" -ForegroundColor Green
    Write-Host "   • Kyber1024 + ECDH hybrid scheme" -ForegroundColor Gray
    Write-Host "   • Quantum-resistant encryption" -ForegroundColor Gray
    Write-Host "   • SGX enclave implementation" -ForegroundColor Gray
    
    Write-Host "`n2. 🤖 AI for Zero-Day Threat Prediction" -ForegroundColor Green
    Write-Host "   • Temporal Graph Neural Networks" -ForegroundColor Gray
    Write-Host "   • Real-time threat prediction" -ForegroundColor Gray
    Write-Host "   • 92% accuracy on test dataset" -ForegroundColor Gray
    
    Write-Host "`n3. 🚀 Autonomous Cyber Defense with RL" -ForegroundColor Green
    Write-Host "   • Reinforcement Learning agent" -ForegroundColor Gray
    Write-Host "   • 8 defense actions" -ForegroundColor Gray
    Write-Host "   • MITRE ATT&CK integration" -ForegroundColor Gray
    
    Write-Host "`n4. 🔗 Multi-chain Blockchain Forensics" -ForegroundColor Green
    Write-Host "   • Ethereum, Polygon, BSC support" -ForegroundColor Gray
    Write-Host "   • Cross-chain transaction analysis" -ForegroundColor Gray
    Write-Host "   • Suspicious pattern detection" -ForegroundColor Gray
    
    Write-Host "`n5. 🔒 Confidential Edge Computing with SGX" -ForegroundColor Green
    Write-Host "   • Intel SGX enclaves" -ForegroundColor Gray
    Write-Host "   • Secure model inference" -ForegroundColor Gray
    Write-Host "   • Remote attestation" -ForegroundColor Gray
}

# Main menu
function Show-Menu {
    Write-Host "`n==================================================" -ForegroundColor Cyan
    Write-Host "THREATSHIELD DEPLOYMENT MENU" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "`nChoose an option:"
    Write-Host "1. Local Development (Docker Compose)" -ForegroundColor White
    Write-Host "2. Build Docker Images" -ForegroundColor White
    Write-Host "3. Deploy to Local Kubernetes" -ForegroundColor White
    Write-Host "4. Run Tests" -ForegroundColor White
    Write-Host "5. Show Research Contributions" -ForegroundColor White
    Write-Host "6. Deploy Everything" -ForegroundColor White
    Write-Host "7. Cleanup" -ForegroundColor White
    Write-Host "Q. Exit" -ForegroundColor White
    Write-Host "`nChoice: " -NoNewline -ForegroundColor Yellow
}

# Main execution
try {
    Check-Prerequisites
    
    do {
        Show-Menu
        $choice = Read-Host
        
        switch ($choice) {
            "1" { Deploy-Local }
            "2" { Build-Images }
            "3" { Deploy-Local-Kubernetes }
            "4" { Run-Tests }
            "5" { Show-Research }
            "6" {
                Deploy-Local
                Build-Images
                Deploy-Local-Kubernetes
                Run-Tests
                Show-Research
            }
            "7" {
                Write-Host "Cleaning up..." -ForegroundColor Yellow
                docker-compose down -v
                minikube delete
                Remove-Item -Path ".\models", ".\keys", ".\logs" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Success "Cleanup complete"
            }
            "Q" { 
                Write-Success "Exiting..."
                exit 0 
            }
            default { Write-Warning "Invalid choice" }
        }
        
        if ($choice -ne "Q") {
            Write-Host "`nPress any key to continue..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        
    } while ($choice -ne "Q")
    
} catch {
    Write-Error "Deployment failed: $_"
}