param location string
param clusterName string
param nodeCount int
param vmSize string
param enableAutoScaling bool
param minCount int
param maxCount int
param tags object

resource aks 'Microsoft.ContainerService/managedClusters@2023-07-02-preview' = {
  name: clusterName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    dnsPrefix: '${clusterName}-dns'
    agentPoolProfiles: [
      {
        name: 'systempool'
        count: nodeCount
        vmSize: vmSize
        osType: 'Linux'
        osDiskSizeGB: 128
        mode: 'System'
        enableAutoScaling: enableAutoScaling
        minCount: enableAutoScaling ? minCount : nodeCount
        maxCount: enableAutoScaling ? maxCount : nodeCount
        nodeLabels: {
          'pool': 'system'
          'workload': 'general'
        }
      }
    ]
    kubernetesVersion: '1.27'
    networkProfile: {
      networkPlugin: 'azure'
      networkPolicy: 'calico'
      loadBalancerSku: 'standard'
      serviceCidr: '10.0.0.0/16'
      dnsServiceIP: '10.0.0.10'
    }
    autoUpgradeProfile: {
      upgradeChannel: 'stable'
    }
    securityProfile: {
      defender: {
        securityMonitoring: {
          enabled: true
        }
      }
      workloadIdentity: {
        enabled: true
      }
    }
    oidcIssuerProfile: {
      enabled: true
    }
    addonProfiles: {
      azureKeyvaultSecretsProvider: {
        enabled: true
        config: {
          enableSecretRotation: 'true'
          rotationPollInterval: '2m'
        }
      }
      httpApplicationRouting: {
        enabled: false
      }
    }
  }
  tags: tags
}

// Create User Assigned Identity for AKS
resource aksIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${clusterName}-identity'
  location: location
  tags: tags
}

// Assign necessary roles
resource aksIdentityRole1 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: resourceGroup()
  name: guid(aksIdentity.id, 'acr-pull')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d') // AcrPull
    principalId: aksIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource aksIdentityRole2 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: subscription()
  name: guid(aksIdentity.id, 'network-contributor')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4d97b98b-1d4f-4787-a291-c67834d212e7') // Network Contributor
    principalId: aksIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

output clusterName string = aks.name
output aksIdentityId string = aksIdentity.id
output kubeConfig string = aks.properties.privateFQDN
output oidcIssuerUrl string = aks.properties.oidcIssuerProfile.issuerUrl