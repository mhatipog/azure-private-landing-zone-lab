targetScope = 'resourceGroup'

param location string
param environment string
param deployFirewall bool
param deployContainerApps bool

var prefix = 'plz-${environment}'
var hubPrefix = '10.84.0.0/16'
var spokePrefix = '10.85.0.0/16'
var firewallSubnetPrefix = '10.84.0.0/26'
var endpointsPrefix = '10.85.0.0/24'
var containerInfrastructurePrefix = '10.85.4.0/23'
var storageName = 'plz${environment}${uniqueString(resourceGroup().id)}'
var vaultName = 'kv${environment}${uniqueString(resourceGroup().id)}'

resource hub 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${prefix}-hub'
  location: location
  properties: {
    addressSpace: { addressPrefixes: [hubPrefix] }
    subnets: [
      {
        name: 'AzureFirewallSubnet'
        properties: { addressPrefix: firewallSubnetPrefix }
      }
    ]
  }
}

resource firewallPolicy 'Microsoft.Network/firewallPolicies@2024-05-01' = if (deployFirewall) {
  name: '${prefix}-fw-policy'
  location: location
  properties: {
    sku: { tier: 'Premium' }
    dnsSettings: { enableProxy: true }
    intrusionDetection: { mode: 'Alert' } // Safer initial deployment; tune then enforce Deny.
    threatIntelMode: 'Alert'
  }
}

resource firewallPublicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = if (deployFirewall) {
  name: '${prefix}-fw-public-ip'
  location: location
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource firewall 'Microsoft.Network/azureFirewalls@2024-05-01' = if (deployFirewall) {
  name: '${prefix}-fw'
  location: location
  properties: {
    firewallPolicy: { id: firewallPolicy.id }
    sku: { name: 'AZFW_VNet', tier: 'Premium' }
    ipConfigurations: [
      {
        name: 'configuration'
        properties: {
          subnet: { id: '${hub.id}/subnets/AzureFirewallSubnet' }
          publicIPAddress: { id: firewallPublicIp.id }
        }
      }
    ]
  }
}

var fwPrivateIp = deployFirewall ? firewall.properties.ipConfigurations[0].properties.privateIPAddress : ''

resource routeTable 'Microsoft.Network/routeTables@2024-05-01' = if (deployFirewall) {
  name: '${prefix}-spoke-egress'
  location: location
  properties: {
    disableBgpRoutePropagation: false
    routes: [
      {
        name: 'default-via-firewall'
        properties: {
          addressPrefix: '0.0.0.0/0'
          nextHopType: 'VirtualAppliance'
          nextHopIpAddress: fwPrivateIp
        }
      }
    ]
  }
}

resource workloadNsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${prefix}-workload-nsg'
  location: location
  properties: {
    securityRules: [] // Default NSG denies unsolicited inbound from Internet.
  }
}

resource spoke 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${prefix}-spoke'
  location: location
  properties: {
    addressSpace: { addressPrefixes: [spokePrefix] }
    subnets: [
      {
        name: 'private-endpoints'
        properties: {
          addressPrefix: endpointsPrefix
          privateEndpointNetworkPolicies: 'Disabled'
          networkSecurityGroup: { id: workloadNsg.id }
          routeTable: deployFirewall ? { id: routeTable.id } : null
        }
      }
      {
        name: 'container-infrastructure'
        properties: {
          addressPrefix: containerInfrastructurePrefix
          delegations: [
            {
              name: 'containerapps'
              properties: { serviceName: 'Microsoft.App/environments' }
            }
          ]
          networkSecurityGroup: { id: workloadNsg.id }
          routeTable: deployFirewall ? { id: routeTable.id } : null
        }
      }
    ]
  }
}

resource hubToSpoke 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-05-01' = {
  parent: hub
  name: 'hub-to-spoke'
  properties: {
    remoteVirtualNetwork: { id: spoke.id }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    allowGatewayTransit: false
    useRemoteGateways: false
  }
}

resource spokeToHub 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-05-01' = {
  parent: spoke
  name: 'spoke-to-hub'
  properties: {
    remoteVirtualNetwork: { id: hub.id }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    allowGatewayTransit: false
    useRemoteGateways: false
  }
}

resource zoneBlob 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.blob.core.windows.net'
  location: 'global'
}
resource zoneVault 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.vaultcore.azure.net'
  location: 'global'
}
resource blobVnetLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: zoneBlob
  name: '${prefix}-spoke-link'
  location: 'global'
  properties: { registrationEnabled: false, virtualNetwork: { id: spoke.id } }
}
resource vaultVnetLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: zoneVault
  name: '${prefix}-spoke-link'
  location: 'global'
  properties: { registrationEnabled: false, virtualNetwork: { id: spoke.id } }
}

resource storage 'Microsoft.Storage/storageAccounts@2024-01-01' = {
  name: storageName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    publicNetworkAccess: 'Disabled'
    allowSharedKeyAccess: false
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    networkAcls: { defaultAction: 'Deny', bypass: 'None' }
  }
}

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enablePurgeProtection: true
    softDeleteRetentionInDays: 90
    publicNetworkAccess: 'Disabled'
    networkAcls: { defaultAction: 'Deny', bypass: 'None' }
  }
}

resource storageEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: '${prefix}-blob-pe'
  location: location
  properties: {
    subnet: { id: '${spoke.id}/subnets/private-endpoints' }
    privateLinkServiceConnections: [
      {
        name: 'blob'
        properties: {
          privateLinkServiceId: storage.id
          groupIds: ['blob']
        }
      }
    ]
  }
}
resource vaultEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: '${prefix}-vault-pe'
  location: location
  properties: {
    subnet: { id: '${spoke.id}/subnets/private-endpoints' }
    privateLinkServiceConnections: [
      {
        name: 'vault'
        properties: {
          privateLinkServiceId: vault.id
          groupIds: ['vault']
        }
      }
    ]
  }
}
resource blobZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: storageEndpoint
  name: 'default'
  properties: { privateDnsZoneConfigs: [{ name: 'blob', properties: { privateDnsZoneId: zoneBlob.id } }] }
}
resource vaultZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: vaultEndpoint
  name: 'default'
  properties: { privateDnsZoneConfigs: [{ name: 'vault', properties: { privateDnsZoneId: zoneVault.id } }] }
}

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = if (deployContainerApps) {
  name: '${prefix}-logs'
  location: location
  properties: { retentionInDays: 30 }
  sku: { name: 'PerGB2018' }
}

resource containerEnv 'Microsoft.App/managedEnvironments@2024-03-01' = if (deployContainerApps) {
  name: '${prefix}-internal-apps'
  location: location
  properties: {
    vnetConfiguration: {
      infrastructureSubnetId: '${spoke.id}/subnets/container-infrastructure'
      internal: true
    }
    publicNetworkAccess: 'Disabled'
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
    workloadProfiles: [{ name: 'Consumption', workloadProfileType: 'Consumption' }]
    zoneRedundant: false
  }
}

// Internal ACA environment DNS must be bound in the organization's private
// resolver after its defaultDomain/staticIp are known. Not done implicitly.

output hubVnetId string = hub.id
output spokeVnetId string = spoke.id
output firewallPrivateIp string = fwPrivateIp
output storageAccountName string = storage.name
output keyVaultName string = vault.name
output internalContainerEnvId string = deployContainerApps ? containerEnv.id : ''
output internalContainerDefaultDomain string = deployContainerApps ? containerEnv.properties.defaultDomain : ''
output internalContainerIp string = deployContainerApps ? containerEnv.properties.staticIp : ''
