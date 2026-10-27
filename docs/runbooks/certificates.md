# Runbook: TLS certificate renewal without a production outage

1. Inventory expiry date, FQDN/SAN coverage, issuer, root/intermediate chain, Key Vault certificate version and all referencing listeners/gateways. Open a change ticket with a backout plan.
2. Generate a fresh CSR and private key using your organization's approved cryptographic standard. Example (demo only):

```bash
openssl req -new -newkey rsa:3072 -nodes -keyout service.key -out service.csr \
  -subj '/CN=service.example.invalid' -addext 'subjectAltName=DNS:service.example.invalid'
```

3. Supply the CSR to the approved CA and obtain signed leaf and intermediate certificates. Validate the chain, expiry, EKU and hostnames; never store private keys in the Git repository or pipeline logs.
4. Build the PFX **offline in a trusted environment** when needed by the target service, protect it with an ephemeral secret from your secret manager, and import only into an RBAC-controlled Key Vault. Prefer native Key Vault certificate lifecycle when supported.
5. Bind a **versioned** Key Vault secret/certificate to a staging listener if available. Validate SNI/certificate chain, client trust, OCSP/CRL expectations and backend health. Schedule the listener swap under change approval.
6. Keep old version during an agreed rollback window, then revoke/retire according to policy. Document proof of certificate version, listener mapping and recovery test.

Azure Front Door, App Gateway, APIM and Firewall Premium have different Key Vault integration and rotation semantics. This is a runbook, **not** an automatic listener-mutating script.
