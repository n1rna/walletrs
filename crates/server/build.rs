use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let proto = PathBuf::from(&manifest_dir).join("../../proto/walletrpc.proto");
    let proto = proto
        .canonicalize()
        .map_err(|e| format!("walletrpc.proto not found at {}: {}", proto.display(), e))?;

    tonic_build::compile_protos(&proto)?;
    println!("cargo:rerun-if-changed={}", proto.display());
    Ok(())
}
