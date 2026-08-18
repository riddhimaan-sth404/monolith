use std::path::PathBuf;

use base64::Engine;
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use ed25519_dalek::ed25519::signature::Signer;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

const LICENSE_BEGIN: &str = "-----BEGIN EDR LICENSE v1-----";
const LICENSE_END: &str = "-----END EDR LICENSE v1-----";

#[derive(Debug, Serialize, Deserialize)]
struct LicenseConfig {
    #[serde(default)]
    jwt_secret: String,
    #[serde(default)]
    quarantine_key: String,
    #[serde(default)]
    server_port: Option<u16>,
    #[serde(default)]
    grpc_port: Option<u16>,
    #[serde(default)]
    ws_port: Option<u16>,
    #[serde(default)]
    tls_cert_pem: Option<String>,
    #[serde(default)]
    tls_key_pem: Option<String>,
    #[serde(default)]
    features: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LicensePayload {
    vendor: String,
    issued: String,
    expires: String,
    #[serde(default)]
    hw_fingerprint: String,
    config: LicenseConfig,
    /// HMAC-SHA256 activation key for kernel driver restore gating.
    /// Embedded in driver/restore.c as EdrRestoreHmacKey.
    /// The driver verifies HMAC-SHA256(payload, this_key) on activation.
    #[serde(default)]
    restore_activation_key_hex: String,
}

#[derive(Parser)]
#[command(name = "vendor-keygen", about = "Monolith EDR license signing tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 keypair + HMAC activation key
    GenKeypair {
        /// Output path for the private key (hex-encoded)
        #[arg(short, long, default_value = "vendor-key.hex")]
        output: PathBuf,
    },
    /// Sign a license payload JSON file and produce a .lic file
    SignLicense {
        /// Path to license config JSON (LicenseConfig)
        #[arg(short, long)]
        config: PathBuf,
        /// Path to hex-encoded private key
        #[arg(short, long, default_value = "vendor-key.hex")]
        private_key: PathBuf,
        /// Path to hex-encoded HMAC activation key
        #[arg(short = 'k', long, default_value = "restore-hmac-key.hex")]
        hmac_key: PathBuf,
        /// Output .lic file path
        #[arg(short, long, default_value = "license.lic")]
        output: PathBuf,
        /// Vendor name
        #[arg(long, default_value = "Monolith EDR")]
        vendor: String,
        /// Validity period in days
        #[arg(long, default_value = "730")]
        validity_days: u64,
        /// Hardware fingerprint (empty = any machine)
        #[arg(long, default_value = "")]
        hw_fingerprint: String,
    },
    /// Show the public key from a private key file
    Pubkey {
        /// Path to hex-encoded private key
        #[arg(short, long, default_value = "vendor-key.hex")]
        private_key: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::GenKeypair { output } => cmd_gen_keypair(&output),
        Commands::SignLicense { config, private_key, hmac_key, output, vendor, validity_days, hw_fingerprint } => {
            cmd_sign_license(&config, &private_key, &hmac_key, &output, &vendor, validity_days, &hw_fingerprint);
        }
        Commands::Pubkey { private_key } => cmd_pubkey(&private_key),
    }
}

fn cmd_gen_keypair(output: &PathBuf) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let priv_hex = hex::encode(signing_key.to_bytes());
    let pub_hex = hex::encode(verifying_key.to_bytes());

    std::fs::write(output, &priv_hex).expect("failed to write private key");
    println!("Private key saved to: {}", output.display());
    println!("Public key (hex, 64 hex chars): {}", pub_hex);
    println!();

    // Generate HMAC activation key for restore feature
    let mut hmac_key = [0u8; 32];
    OsRng.fill_bytes(&mut hmac_key);
    let hmac_hex = hex::encode(hmac_key);
    let hmac_path = output.parent().unwrap_or(&PathBuf::from(".")).join("restore-hmac-key.hex");
    std::fs::write(&hmac_path, &hmac_hex).expect("failed to write HMAC key");
    println!("HMAC restore key saved to: {}", hmac_path.display());
    println!();

    // Print C array for embedding in restore.c
    println!("Embed this in driver/restore.c as EdrRestoreHmacKey:");
    print_c_array("EdrRestoreHmacKey", &hmac_key);
    println!();
    println!("Update these files:");
    println!("  shared/src/license.rs  — const VENDOR_PUBLIC_KEY_HEX = \"{}\"", pub_hex);
    println!("  driver/restore.c       — EdrRestoreHmacKey (C array above)");
}

fn print_c_array(name: &str, bytes: &[u8]) {
    print!("static const UCHAR {}[{}] = {{", name, bytes.len());
    for (i, b) in bytes.iter().enumerate() {
        if i % 8 == 0 { print!("\n    "); }
        print!("0x{:02x}", b);
        if i < bytes.len() - 1 { print!(", "); }
    }
    println!("\n}};");
}

fn cmd_pubkey(private_key: &PathBuf) {
    let priv_hex = std::fs::read_to_string(private_key)
        .expect("failed to read private key file")
        .trim()
        .to_string();
    let priv_bytes = hex::decode(&priv_hex).expect("invalid hex private key");
    let arr: [u8; 32] = priv_bytes.try_into().expect("private key must be 32 bytes");
    let signing_key = SigningKey::from_bytes(&arr);
    let verifying_key = signing_key.verifying_key();
    let pub_hex = hex::encode(verifying_key.to_bytes());
    println!("{}", pub_hex);
}

fn cmd_sign_license(
    config_path: &PathBuf,
    private_key_path: &PathBuf,
    hmac_key_path: &PathBuf,
    output_path: &PathBuf,
    vendor: &str,
    validity_days: u64,
    hw_fingerprint: &str,
) {
    let priv_hex = std::fs::read_to_string(private_key_path)
        .expect("failed to read private key file")
        .trim()
        .to_string();
    let priv_bytes = hex::decode(&priv_hex).expect("invalid hex private key");
    let arr: [u8; 32] = priv_bytes.try_into().expect("private key must be 32 bytes");
    let signing_key = SigningKey::from_bytes(&arr);

    let config_json = std::fs::read_to_string(config_path)
        .expect("failed to read config file");
    let config: LicenseConfig = serde_json::from_str(&config_json)
        .expect("invalid license config JSON");

    let hmac_hex = std::fs::read_to_string(hmac_key_path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let now = Utc::now();
    let expires = now + Duration::days(validity_days as i64);

    let payload = LicensePayload {
        vendor: vendor.to_string(),
        issued: now.to_rfc3339(),
        expires: expires.to_rfc3339(),
        hw_fingerprint: hw_fingerprint.to_string(),
        config,
        restore_activation_key_hex: hmac_hex,
    };

    let payload_json = serde_json::to_string(&payload).expect("serialization failed");
    let payload_bytes = payload_json.as_bytes();

    let signature = signing_key.sign(payload_bytes);
    let sig_bytes = signature.to_bytes();

    let engine = base64::engine::general_purpose::STANDARD;
    let b64_payload = engine.encode(payload_bytes);
    let b64_sig = engine.encode(sig_bytes);

    let lic_content = format!(
        "{}\n{}.{}\n{}\n",
        LICENSE_BEGIN, b64_payload, b64_sig, LICENSE_END
    );

    std::fs::write(output_path, &lic_content).expect("failed to write license file");
    println!("License signed and saved to: {}", output_path.display());
    println!("  Vendor: {}", vendor);
    println!("  Issued: {}", payload.issued);
    println!("  Expires: {}", payload.expires);
    println!("  Features: {:?}", payload.config.features);
    println!("  HW Fingerprint: {}", if hw_fingerprint.is_empty() { "(any)" } else { hw_fingerprint });
    println!();
    println!("Payload (base64): {}", b64_payload);
    println!("Signature (base64): {}", b64_sig);
}
