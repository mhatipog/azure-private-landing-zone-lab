# Read-only Azure tenant assessment

This process produces evidence for an engineering review; it **does not** certify that your workload is private or compliant.

## Permissions and boundaries

- Install Azure CLI and `az extension add --name resource-graph` on a **trusted** workstation.
- `az login --tenant <your-tenant>` or use a tightly scoped workload-federated Azure service connection.
- Grant **Reader** over the intended subscriptions; more granular scopes may result in incomplete results. Export is read-only. Never use an Owner/Contributor token just to collect inventory.
- No direct subscriptions are queried on import or when running offline tests. The `export` subcommand is the only live inventory path.
- Metadata includes resource IDs and names and may reveal topology, even after allowlisting: treat exported files as internal.

```bash
az-private-ready export \
  --subscription 00000000-0000-0000-0000-000000000000 \
  --output artifacts/tenant.json
az-private-ready assess artifacts/tenant.json --relationships --format markdown \
  --output artifacts/readiness.md --fail-on high
az-private-ready assess artifacts/tenant.json --relationships --format sarif \
  --output artifacts/readiness.sarif --fail-on none
```

The `export` command queries only an explicit list of relevant Azure resource types, retrieves records with finite ordered pagination and emits **allowlisted** metadata. It does *not* export full unredacted `properties`, access tokens, Key Vault secrets or SQL credentials. It refuses to emit a partial inventory after a pagination error. Azure Resource Graph indexing is eventually consistent; some child resources may be omitted or exposed differently. An `UNKNOWN` finding requires investigation, not a change request by itself.

## Deployment drift

```bash
az-private-ready diff artifacts/approved-baseline.json artifacts/tenant.json \
  --relationships --fail-on-regression --output artifacts/drift.json
```

Changes in status, new resources/rules and resources no longer observed are separate events. A disappearing resource is reported `not_observed`, **not** as a remediated finding. Export drift is not the same as effective configuration drift: validate with Azure Activity Log, Network Watcher and network probes.

## Exceptions with expiry

An exception is *exact-match only* for a resource ID and rule. It must identify its approver and why it exists, and it expires. No globbing, implicit defaults or permanent blanket skips.

```bash
az-private-ready assess artifacts/tenant.json --relationships \
  --waivers governance/waivers.json --strict-unknown
```

A waived FAIL/UNKNOWN is still visible with its original status and reason. Waivers must be version-controlled in a private authorized repository, **not in a public fork** when they contain tenant IDs or internal architecture.

## What else to verify manually

1. `az network nic show-effective-route-table` and Network Watcher **next hop** from the actual workload NIC; a UDR alone does not prove egress.
2. DNS from a machine attached to the target VNet, not a GitHub-hosted public runner; test split-horizon DNS and conditional forwarding.
3. Authentication from **managed identity** with minimum data-plane RBAC; check private endpoint approval and A record.
4. Firewall Premium TLS inspection certificate chain, compatibility exemptions and IDPS mode, in a controlled pilot.
5. SQL PITR restore in a nonproduction target; Key Vault certificate rotation; Service Bus managed-identity send/receive tests.
6. Azure Policy exemptions, Defender recommendations, change tickets and cost budgets from their authoritative systems.

## Out-of-scope evidence

Resource Graph is a control-plane index, not a connection test. This scanner does not inspect TLS traffic, perform active security testing, read identities' tokens, decrypt communications or provide NIS2/ISO 27001 compliance certification. Missing resource types are *not* evidence that a control was absent. A DNS/TLS probe checks the local vantage point only.

## Stronger NIC route evidence

Resource Graph identifies a declared UDR, not the effective route. Capture a running VM's NIC table (from a trusted operator workstation):

```bash
az network nic show-effective-route-table -g <resource-group> -n <nic-name> -o json > routes.json
az-private-ready effective-routes routes.json --destination 8.8.8.8 --firewall-ip 10.80.0.4
```

The analyzer applies longest-prefix match and, for equal-length prefixes, User > BGP > Default priority. It deliberately reports ambiguous equally ranked evidence as `UNKNOWN`. Test destination-specific overrides: a more-specific route can bypass your default firewall even when the 0/0 route is correct.
