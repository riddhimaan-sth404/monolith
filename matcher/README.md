# Monolith YARA Matcher Sidecar

`monolith-matcher` is a high-performance YARA pattern matching microservice written in Rust using `yara-x` and `axum`. It compiles YARA rule sets into memory and exposes HTTP endpoints for file content matching.

## Endpoints

- **`POST /match`**: Accepts JSON containing a file `path` or base64-encoded `data` buffer. Returns matched rule names and extracted metadata.
- **`GET /health`**: Health check endpoint returning HTTP 200 OK.

## Running the Matcher

```powershell
cargo run -p monolith-matcher -- --rules scanner/yara/rules --listen 127.0.0.1:50074
```
