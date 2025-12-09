// =============================================================================
// HARDENED Azure SQL configuration - Security best practices
// =============================================================================
// Course: GitHub Copilot for Cybersecurity Specialists
// Lesson: 05 - Compliance, IR, Configuration Management
//
// This Bicep template demonstrates a more secure baseline for Azure SQL:
// - Strong TLS settings
// - Locked-down firewall rules
// - Enforced Transparent Data Encryption
// - No credentials stored in source control
// =============================================================================

@description('Deployment location')
param location string = resourceGroup().location

@description('Azure SQL logical server name prefix')
param sqlServerName string = 'secure-sql-${uniqueString(resourceGroup().id)}'

@description('SQL administrator login (use for emergency / break-glass only)')
param administratorLogin string = 'sqladminsecure'

@secure()
@description('Administrator password (provided securely at deployment time)')
param administratorLoginPassword string

@description('Trusted client IP in CIDR format (for example, 203.0.113.10)')
param allowedClientIp string

@description('Primary application database name')
param databaseName string = 'appdb'

// -----------------------------------------------------------------------------
// HARDENED SQL SERVER
// -----------------------------------------------------------------------------
resource sqlServer 'Microsoft.Sql/servers@2023-02-01-preview' = {
  name: sqlServerName
  location: location
  properties: {
    administratorLogin: administratorLogin
    administratorLoginPassword: administratorLoginPassword

    // CONTROL: Enforce modern TLS (1.2 or higher recommended)
    minimalTlsVersion: '1.2'

    // CONTROL: Public network access enabled here only so the
    // firewall rule below is meaningful for the demo.
    // In stricter environments, set this to 'Disabled' and use
    // private endpoints / VNet integration instead.
    publicNetworkAccess: 'Enabled'
  }
}

// CONTROL: Narrowly scoped firewall rule
// Only a single trusted IP can connect. In reality this might be
// a jump host, VPN egress IP, or app gateway.
resource limitedFirewall 'Microsoft.Sql/servers/firewallRules@2024-11-01-preview' = {
  name: 'AllowTrustedClient'
  parent: sqlServer
  properties: {
    startIpAddress: allowedClientIp
    endIpAddress: allowedClientIp
  }
}

// -----------------------------------------------------------------------------
// HARDENED DATABASE
// -----------------------------------------------------------------------------
resource database 'Microsoft.Sql/servers/databases@2023-08-01-preview' = {
  name: '${sqlServer.name}/${databaseName}'
  location: location
  sku: {
    name: 'GP_Gen5_2'
    tier: 'GeneralPurpose'
  }
  properties: {
    maxSizeBytes: 1073741824 // 1 GB
  }
}

// CONTROL: Transparent Data Encryption (TDE) explicitly enabled
// This mirrors Azure security guidance and many compliance frameworks.
resource tde 'Microsoft.Sql/servers/databases/transparentDataEncryption@2023-02-01-preview' = {
  name: 'current'
  parent: database
  properties: {
    state: 'Enabled'
  }
}

output sqlServerName string = sqlServer.name
output databaseNameOut string = database.name
