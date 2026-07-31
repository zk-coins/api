//! Compile the workspace-owned `kernel.v1` contract into tonic/prost stubs.
//!
//! The `.proto` lives at the workspace root under `proto/kernel/v1/kernel.proto`
//! (copied from zk-coins/node; identity is enforced by a unit test in the
//! **api** package). Paths are anchored at `CARGO_MANIFEST_DIR` so the build
//! is cwd-independent.

use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let proto = manifest_dir.join("../proto/kernel/v1/kernel.proto");
    let include = manifest_dir.join("../proto");

    println!("cargo:rerun-if-changed={}", proto.display());

    // Pure client: the api never hosts a kernel service. In-process handler
    // tests use a trait double (`KernelRpc`), not generated server stubs.
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&[proto], &[include])?;

    Ok(())
}
