//! Identity gate for the carried `kernel.v1` `.proto`.
//!
//! The api repo cannot path-depend on zk-coins/node (separate checkouts).
//! The contract file is therefore carried under `proto/kernel/v1/kernel.proto`
//! (workspace root) and pinned by content hash. When a sibling node checkout
//! is present at `../node/proto/kernel/v1/kernel.proto`, the test also
//! requires byte-identity with that file so local multi-repo worktrees catch
//! drift immediately.
//!
//! Lives in the **api** package (not `kernel-proto`) so `cargo test -p api`
//! always runs the pin; codegen isolation is a separate concern.

/// SHA-256 (lowercase hex) of `proto/kernel/v1/kernel.proto` as shipped with
/// this tree. Source: zk-coins/node `proto/kernel/v1/kernel.proto` at the
/// worktree used for this stage (`31bffc90…`). Updating the proto **requires**
/// updating this pin in the same change.
pub const KERNEL_PROTO_SHA256_HEX: &str =
    "31bffc90fec10dea7d7198861af8097c6102ea82bcc4d71fd772231cef6ad559";

/// Relative path of the carried contract from the workspace / api crate root.
pub const KERNEL_PROTO_REL: &str = "proto/kernel/v1/kernel.proto";

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::path::{Path, PathBuf};

    fn manifest_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn local_proto_path() -> PathBuf {
        manifest_dir().join(KERNEL_PROTO_REL)
    }

    fn sibling_node_proto_path() -> PathBuf {
        manifest_dir()
            .join("..")
            .join("node")
            .join("proto/kernel/v1/kernel.proto")
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        let mut out = String::with_capacity(64);
        for b in digest {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    #[test]
    fn carried_proto_matches_pinned_sha256() {
        let path = local_proto_path();
        let bytes = std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "failed to read carried kernel proto at {}: {e}",
                path.display()
            )
        });
        let got = sha256_hex(&bytes);
        assert_eq!(
            got, KERNEL_PROTO_SHA256_HEX,
            "carried {KERNEL_PROTO_REL} SHA-256 drifted from the pin; \
             if the node contract changed, copy the new file and update \
             KERNEL_PROTO_SHA256_HEX in the same change"
        );
        assert!(!bytes.is_empty(), "carried kernel proto must be non-empty");
        let text = std::str::from_utf8(&bytes).expect("proto is UTF-8");
        assert!(
            text.contains("package kernel.v1;"),
            "carried proto must declare package kernel.v1"
        );
        assert!(
            text.contains("rpc SubmitTransition"),
            "carried proto must include SubmitTransition"
        );
        assert!(
            text.contains("rpc StreamJob"),
            "carried proto must include StreamJob"
        );
    }

    #[test]
    fn carried_proto_matches_sibling_node_when_present() {
        let sibling = sibling_node_proto_path();
        if !Path::new(&sibling).is_file() {
            // Standalone api checkout: pin above is the identity gate.
            return;
        }
        let local = std::fs::read(local_proto_path()).expect("local proto");
        let node = std::fs::read(&sibling).unwrap_or_else(|e| {
            panic!(
                "failed to read sibling node proto at {}: {e}",
                sibling.display()
            )
        });
        assert_eq!(
            local,
            node,
            "carried api proto must be byte-identical to sibling node proto at {}",
            sibling.display()
        );
        assert_eq!(
            sha256_hex(&node),
            KERNEL_PROTO_SHA256_HEX,
            "sibling node proto SHA-256 must equal the pin (node moved without api update)"
        );
    }
}
