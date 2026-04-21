param location string
param vnetName string
param tags object

resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'aks-system'
        properties: {
          addressPrefix: '10.0.1.0/24'
          delegations: [
            {
              name: 'aks-delegation'
              properties: {
                serviceName: 'Microsoft.ContainerService/managedClusters'
              }
            }
          ]
        }
      },
      {
        name: 'aks-user'
        properties: {
          addressPrefix: '10.0.2.0/24'
          delegations: [
            {
              name: 'aks-delegation'
              properties: {
                serviceName: 'Microsoft.ContainerService/managedClusters'
              }
            }
          ]
        }
      },
      {
        name: 'sgx-vms'
        properties: {
          addressPrefix: '10.0.3.0/24'
        }
      },
      {
        name: 'database'
        properties: {
          addressPrefix: '10.0.4.0/24'
          delegations: [
            {
              name: 'postgres-delegation'
              properties: {
                serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers'
              }
            }
          ]
        }
      },
      {
        name: 'redis'
        properties: {
          addressPrefix: '10.0.5.0/24'
          delegations: [
            {
              name: 'redis-delegation'
              properties: {
                serviceName: 'Microsoft.Cache/redis'
              }
            }
          ]
        }
      },
      {
        name: 'storage'
        properties: {
          addressPrefix: '10.0.6.0/24'
          privateEndpointNetworkPolicies: 'Enabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
    ]
  }
  tags: tags
}

// Private DNS Zone for PostgreSQL
resource privateDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: '${resourceName}.postgres.database.azure.com'
  location: 'global'
  tags: tags
}

// Link Private DNS Zone to VNET
resource privateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: privateDnsZone
  name: '${vnetName}-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

// Network Security Group for SGX VMs
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: '${vnetName}-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-ssh'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '22'
          sourceAddressPrefix: 'Internet'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      },
      {
        name: 'allow-https'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'Internet'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 110
          direction: 'Inbound'
        }
      },
      {
        name: 'allow-internal'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 120
          direction: 'Inbound'
        }
      },
      {
        name: 'deny-all'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Deny'
          priority: 4096
          direction: 'Inbound'
        }
      }
    ]
  }
  tags: tags
}

output vnetId string = vnet.id
output aksSubnetId string = vnet.properties.subnets[0].id
output sgxSubnetId string = vnet.properties.subnets[2].id
output dbSubnetId string = vnet.properties.subnets[3].id
output redisSubnetId string = vnet.properties.subnets[4].id
output storageSubnetId string = vnet.properties.subnets[5].id
output privateDnsZoneId string = privateDnsZone.id
output nsgId string = nsg.id