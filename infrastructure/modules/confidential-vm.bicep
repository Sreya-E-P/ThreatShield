param location string
param vmName string
param adminUsername string
@secure()
param adminPassword string
param subnetId string
param tags object

// Public IP
resource publicIp 'Microsoft.Network/publicIPAddresses@2023-05-01' = {
  name: '${vmName}-ip'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
  tags: tags
}

// Network Interface
resource nic 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: '${vmName}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: subnetId
          }
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
    enableAcceleratedNetworking: true
  }
  tags: tags
}

// Confidential VM
resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
  name: vmName
  location: location
  plan: {
    name: '20_04-lts-cvm'
    publisher: 'Canonical'
    product: '0001-com-ubuntu-confidential-vm-focal'
  }
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_DC2s_v3'  // SGX-enabled VM
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-confidential-vm-focal'
        sku: '20_04-lts-cvm'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
          securityProfile: {
            securityEncryptionType: 'VMGuestStateOnly'
          }
        }
        diskSizeGB: 100
        caching: 'ReadOnly'
      }
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      adminPassword: adminPassword
      linuxConfiguration: {
        disablePasswordAuthentication: false
        provisionVMAgent: true
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    }
    securityProfile: {
      securityType: 'ConfidentialVM'
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
      encryptionAtHost: true
    }
  }
  tags: union(tags, {
    Confidential: 'true'
    SGX: 'enabled'
    Attestation: 'required'
  })
}

// Disk Encryption Set (optional for extra security)
resource diskEncryptionSet 'Microsoft.Compute/diskEncryptionSets@2023-01-02' = {
  name: '${vmName}-des'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    activeKey: {
      sourceVault: {
        id: keyVault.id
      }
      keyUrl: '${keyVault.properties.vaultUri}keys/disk-encryption-key'
    }
    encryptionType: 'EncryptionAtRestWithPlatformAndCustomerKeys'
  }
  tags: tags
}

output vmId string = vm.id
output privateIp string = nic.properties.ipConfigurations[0].properties.privateIPAddress
output publicIpAddress string = publicIp.properties.ipAddress
output vmName string = vm.name