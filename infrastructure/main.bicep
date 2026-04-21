param location string = 'eastus'
param environment string = 'staging'
param prefix string = 'threatshield'
param adminObjectId string

@secure()
param databasePassword string = newGuid()

@secure()
param jwtSecret string = newGuid()

@secure()
param vmAdminPassword string = newGuid()

var resourceName = '${prefix}-${environment}'

// Resource Group
resource resourceGroup 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: '${resourceName}-rg'
  location: location
  tags: {
    Environment: environment
    Application: 'ThreatShield'
    DeploymentType: 'confidential'
  }
}

// AKS Cluster
module aks './modules/aks.bicep' = {
  name: 'aks'
  scope: resourceGroup
  params: {
    location: location
    clusterName: '${resourceName}-aks'
    nodeCount: 3
    vmSize: 'Standard_D4s_v3'
    enableAutoScaling: true
    minCount: 2
    maxCount: 5
    tags: {
      Environment: environment
      Application: 'ThreatShield'
    }
  }
}

// Key Vault
module keyVault './modules/keyvault.bicep' = {
  name: 'keyvault'
  scope: resourceGroup
  params: {
    location: location
    vaultName: '${resourceName}-kv'
    adminObjectId: adminObjectId
    aksIdentityId: aks.outputs.aksIdentityId
    databasePassword: databasePassword
    jwtSecret: jwtSecret
    tags: {
      Environment: environment
      Application: 'ThreatShield'
    }
  }
}

// Network
module network './modules/network.bicep' = {
  name: 'network'
  scope: resourceGroup
  params: {
    location: location
    vnetName: '${resourceName}-vnet'
    tags: {
      Environment: environment
      Application: 'ThreatShield'
    }
  }
}

// Container Registry
resource containerRegistry 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: toLower('${resourceName}cr${uniqueString(resourceGroup.id)}')
  location: location
  sku: {
    name: 'Premium'
  }
  properties: {
    adminUserEnabled: true
    policies: {
      quarantinePolicy: {
        status: 'disabled'
      }
      trustPolicy: {
        type: 'Notary'
        status: 'disabled'
      }
      retentionPolicy: {
        days: 7
        status: 'disabled'
      }
    }
  }
  tags: {
    Environment: environment
    Application: 'ThreatShield'
  }
}

// Confidential VMs for SGX workloads
module sgxVm1 './modules/confidential-vm.bicep' = {
  name: 'sgx-vm1'
  scope: resourceGroup
  params: {
    location: location
    vmName: '${resourceName}-sgx-01'
    adminUsername: 'threatshield'
    adminPassword: vmAdminPassword
    subnetId: network.outputs.sgxSubnetId
    tags: {
      Environment: environment
      Application: 'ThreatShield'
      Workload: 'sgx-enclave'
      Confidential: 'true'
    }
  }
}

module sgxVm2 './modules/confidential-vm.bicep' = {
  name: 'sgx-vm2'
  scope: resourceGroup
  params: {
    location: location
    vmName: '${resourceName}-sgx-02'
    adminUsername: 'threatshield'
    adminPassword: vmAdminPassword
    subnetId: network.outputs.sgxSubnetId
    tags: {
      Environment: environment
      Application: 'ThreatShield'
      Workload: 'sgx-enclave'
      Confidential: 'true'
    }
  }
}

// PostgreSQL Flexible Server for threat database
resource postgresServer 'Microsoft.DBforPostgreSQL/flexibleServers@2023-06-01-preview' = {
  name: '${resourceName}-psql'
  location: location
  sku: {
    name: 'Standard_D4s_v3'
    tier: 'GeneralPurpose'
  }
  properties: {
    administratorLogin: 'threatshield'
    administratorLoginPassword: databasePassword
    version: '15'
    storage: {
      storageSizeGB: 128
    }
    backup: {
      backupRetentionDays: 7
      geoRedundantBackup: 'Disabled'
    }
    network: {
      delegatedSubnetResourceId: network.outputs.dbSubnetId
      privateDnsZoneArmResourceId: network.outputs.privateDnsZoneId
    }
    highAvailability: {
      mode: 'Disabled'
    }
  }
  tags: {
    Environment: environment
    Application: 'ThreatShield'
    Confidential: 'true'
  }
}

// Redis Cache for threat intelligence caching
resource redisCache 'Microsoft.Cache/redis@2023-08-01' = {
  name: '${resourceName}-redis'
  location: location
  properties: {
    sku: {
      name: 'Premium'
      family: 'P'
      capacity: 1
    }
    enableNonSslPort: false
    minimumTlsVersion: '1.2'
    redisConfiguration: {
      maxmemoryPolicy: 'allkeys-lru'
    }
    subnetId: network.outputs.redisSubnetId
    staticIP: '10.0.4.10'
  }
  tags: {
    Environment: environment
    Application: 'ThreatShield'
  }
}

// Storage Account for models and keys
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: toLower('${resourceName}st${uniqueString(resourceGroup.id)}')
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: true
    networkAcls: {
      bypass: 'AzureServices'
      virtualNetworkRules: [
        {
          id: network.outputs.storageSubnetId
          action: 'Allow'
        }
      ]
      defaultAction: 'Deny'
    }
    encryption: {
      services: {
        blob: {
          enabled: true
        }
        file: {
          enabled: true
        }
      }
      keySource: 'Microsoft.Storage'
    }
  }
  tags: {
    Environment: environment
    Application: 'ThreatShield'
  }
}

// Outputs
output resourceGroupName string = resourceGroup.name
output aksClusterName string = aks.outputs.clusterName
output aksIdentityId string = aks.outputs.aksIdentityId
output acrLoginServer string = containerRegistry.properties.loginServer
output keyVaultUri string = keyVault.outputs.vaultUri
output postgresHost string = postgresServer.properties.fullyQualifiedDomainName
output redisHost string = '${redisCache.name}.redis.cache.windows.net'
output sgxVm1PublicIp string = sgxVm1.outputs.publicIpAddress
output sgxVm2PublicIp string = sgxVm2.outputs.publicIpAddress
output storageAccountName string = storageAccount.name