# Monolith Vendor License Generator Tool

`vendor-keygen` is a specialized developer utility for generating Ed25519-signed enterprise license files (`.lic`) for Monolith EDR deployments.

## Functionality

- Generates vendor Ed25519 keypairs.
- Embeds customer details, endpoint seat limits, expiration dates, and feature flags into signed base64 payload bundles.
- Formats signed licenses into `-----BEGIN EDR LICENSE v1-----` ASCII-armored files.

## Execution

```powershell
cargo run -p vendor-keygen -- --config vendor-keygen/license-config.json --out configs/license.lic
```
