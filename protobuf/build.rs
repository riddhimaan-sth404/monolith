#![allow(missing_docs)]
use std::path::Path;

fn find_protoc() -> Option<std::path::PathBuf> {
    if let Ok(path) = std::env::var("PROTOC") {
        return Some(path.into());
    }

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let workspace_root = Path::new(&manifest_dir).parent()?;

    let local = workspace_root
        .join(".tools")
        .join("protoc")
        .join("bin")
        .join("protoc.exe");
    if local.exists() {
        return Some(local);
    }

    std::env::var_os("PATH").as_ref().and_then(|paths| {
        std::env::split_paths(paths).find_map(|dir| {
            let exe = dir.join("protoc.exe");
            if exe.exists() { Some(exe) } else { None }
        })
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = ".";
    let out_dir = Path::new(&std::env::var("OUT_DIR")?).join("protos");

    std::fs::create_dir_all(&out_dir)?;

    let proto_files = &[
        "edr/proto/v1/common.proto",
        "edr/proto/v1/alert.proto",
        "edr/proto/v1/driver.proto",
        "edr/proto/v1/endpoint.proto",
        "edr/proto/v1/event.proto",
        "edr/proto/v1/ioc.proto",
        "edr/proto/v1/policy.proto",
        "edr/proto/v1/scan.proto",
        "edr/proto/v1/service.proto",
    ];

    let protoc_path = find_protoc();
    let mut config = prost_build::Config::new();
    if let Some(ref path) = protoc_path {
        println!("cargo:rustc-env=PROTOC={}", path.display());
        config.protoc_executable(path);
    }
    config.out_dir(&out_dir);
    // Well-known types (google.protobuf.*) provided by prost-types crate

    tonic_build::configure()
        .out_dir(&out_dir)
        .compile_protos_with_config(config, proto_files, &[proto_dir])?;

    println!("cargo:rerun-if-changed=build.rs");
    for proto in proto_files {
        println!("cargo:rerun-if-changed={}", proto);
    }

    Ok(())
}
