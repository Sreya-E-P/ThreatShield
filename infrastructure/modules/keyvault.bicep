param location string
param vaultName string
param adminObjectId string
param aksIdentityId string
param tags object

@secure()
param databasePassword string

@secure()
param jwtSecret string

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    accessPolicies: [
      {
        tenantId: subscription().tenantId
        objectId: adminObjectId
        permissions: {
          keys: [
            'Get'
            'List'
            'Create'
            'Import'
            'Delete'
            'Backup'
            'Restore'
            'Recover'
            'Decrypt'
            'Encrypt'
            'UnwrapKey'
            'WrapKey'
            'Verify'
            'Sign'
            'Purge'
          ]
          secrets: [
            'Get'
            'List'
            'Set'
            'Delete'
            'Backup'
            'Restore'
            'Recover'
            'Purge'
          ]
          certificates: [
            'Get'
            'List'
            'Create'
            'Import'
            'Delete'
            'ManageContacts'
            'ManageIssuers'
            'GetIssuers'
            'ListIssuers'
            'SetIssuers'
            'DeleteIssuers'
            'Purge'
          ]
        }
      }
    ]
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    enableRbacAuthorization: false
  }
  tags: tags
}

// Create secrets
resource secretDatabaseUrl 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  name: 'DatabaseUrl'
  parent: keyVault
  properties: {
    value: 'postgresql://threatshield:${databasePassword}@${postgresServer.properties.fullyQualifiedDomainName}:5432/threatshield'
    contentType: 'Database connection string'
  }
}

resource secretJwt 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  name: 'JwtSecret'
  parent: keyVault
  properties: {
    value: jwtSecret
    contentType: 'JWT signing secret'
  }
}

resource secretRedis 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  name: 'RedisConnectionString'
  parent: keyVault
  properties: {
    value: 'rediss://:${listKeys(redisCache.id, redisCache.apiVersion).primaryKey}@${redisCache.name}.redis.cache.windows.net:6380?ssl=true'
    contentType: 'Redis connection string'
  }
}

resource secretStorage 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  name: 'StorageConnectionString'
  parent: keyVault
  properties: {
    value: listKeys(storageAccount.id, storageAccount.apiVersion).keys[0].value
    contentType: 'Storage account connection string'
  }
}

output vaultUri string = keyVault.properties.vaultUri
output vaultName string = keyVault.name
output keyVaultId string = keyVault.id