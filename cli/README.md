# Monolith CLI Administration Tool (`mono-cli`)

`mono-cli` is a command-line interface written in Rust for administering the Monolith EDR backend, querying alerts, triggering scans, managing IOC allowlists, and exporting reports directly from the terminal.

## Usage Commands

```powershell
# Authenticate against backend
cargo run -p mono-cli -- login --url https://127.0.0.1:8443 --username admin --password admin

# Query dashboard metrics
cargo run -p mono-cli -- dashboard

# Trigger a file system scan
cargo run -p mono-cli -- scan start --type quick

# Query active threat alerts
cargo run -p mono-cli -- alert list
```
