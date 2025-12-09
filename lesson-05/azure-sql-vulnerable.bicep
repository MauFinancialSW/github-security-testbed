// =============================================================================
// VULNERABLE Azure SQL configuration - DO NOT USE IN PRODUCTION
// =============================================================================
// Course: GitHub Copilot for Cybersecurity Specialists
// Lesson: 05 - Compliance, IR, Configuration Management
//
// This Bicep template intentionally includes common Azure SQL
// misconfigurations for comparison with the hardened version.
// =============================================================================

@description('Deployment location')
param location string = resourceGroup().location

// INSECURE: Hard-coded server name and admin credentials
@description('Azure SQL logical server name (intentionally predictable)')
param sqlServerName string = 'vuln-sql-${uniqueString(resourceGroup().id)}'

@description('Administrator login (not using Azure AD auth)')
param administratorLogin string = 'sqladmin'

// INSECURE: Not marked as secure, and value is hard-coded in the template
@description('INSECURE: Hard-coded administrator password stored in template')
param administratorLoginPassword string = 'Adm1nPassword!234'

// -----------------------------------------------------------------------------
// VULNERABLE SQL SERVER
// -----------------------------------------------------------------------------
resource sqlServer 'Microsoft.Sql/servers@2023-02-01-preview' = {
  name: sqlServerName
  location: location
  properties: {
    administratorLogin: administratorLogin
    administratorLoginPassword: administratorLoginPassword

    // VULNERABILITY: Weaker TLS version; best practice is 1.2 or higher
    // See PSRule Azure.SQL.MinTLS guidance.
    minimalTlsVersion: '1.0'

    // VULNERABILITY: Public network access fully enabled
    // Safer pattern is to disable public endpoint and use private endpoints.
    publicNetworkAccess: 'Enabled'
  }
}

// VULNERABILITY: Firewall open to the entire internet
// 0.0.0.0 - 255.255.255.255 effectively allows any IP to connect.
resource allowAllIps 'Microsoft.Sql/servers/firewallRules@2024-11-01-preview' = {
  name: 'AllowAllIps'
  parent: sqlServer
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '255.255.255.255'
  }
}

// -----------------------------------------------------------------------------
// VULNERABLE DATABASE
// -----------------------------------------------------------------------------
@description('Primary application database name')
param databaseName string = 'appdb'

resource database 'Microsoft.Sql/servers/databases@2023-08-01-preview' = {
  name: '${sqlServer.name}/${databaseName}'
  location: location
  sku: {
    // Small but production-looking SKU for demo
    name: 'GP_Gen5_2'
    tier: 'GeneralPurpose'
  }
  properties: {
    maxSizeBytes: 1073741824 // 1 GB
  }
}

// VULNERABILITY: Transparent Data Encryption (TDE) explicitly disabled
// Best practice is to enable TDE for all production databases.
resource tde 'Microsoft.Sql/servers/databases/transparentDataEncryption@2023-02-01-preview' = {
  name: 'current'
  parent: database
  properties: {
    state: 'Disabled'
  }
}

output sqlServerName string = sqlServer.name
output databaseNameOut string = database.name
