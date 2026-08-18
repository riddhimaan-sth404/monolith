$env:RUSTLS_CRYPTO_PROVIDER="ring"
$env:PATH="$env:PATH;target\release"
& "target\release\monolith-agent.exe"
