targetScope = 'subscription'

@description('Environment suffix for deterministic resource names (dev/test/acc/preprod/prod).')
@allowed(['dev', 'test', 'acc', 'preprod', 'prod'])
param environment string

@description('Region for the sandbox; ensure Container Apps/Private Link availability.')
param location string = 'westeurope'

@description('Explicit resource group for the environment. Uses a fresh name to avoid touching existing estate.')
param resourceGroupName string = 'rg-plz-${environment}'

@description('Azure Firewall Premium has material hourly cost and is disabled by default.')
param deployFirewall bool = false

@description('Creates an internal VNet-integrated Azure Container Apps managed environment (may incur cost).')
param deployContainerApps bool = false

@description('Require explicit acknowledgement before creating billable resources in Azure.')
@allowed(['I_ACCEPT_AZURE_CHARGES'])
param costAcknowledgement string

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
  tags: {
    workload: 'azure-private-landing-zone-lab'
    environment: environment
    managedBy: 'bicep'
  }
}

module foundation './modules/foundation.bicep' = {
  name: 'plz-${environment}'
  scope: rg
  params: {
    location: location
    environment: environment
    deployFirewall: deployFirewall
    deployContainerApps: deployContainerApps
  }
}

output resourceGroup string = rg.name
output spokeVnetId string = foundation.outputs.spokeVnetId
output firewallPrivateIp string = foundation.outputs.firewallPrivateIp
output storageAccountName string = foundation.outputs.storageAccountName
output keyVaultName string = foundation.outputs.keyVaultName
