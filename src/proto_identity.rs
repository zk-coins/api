//! Identity gate for the carried `kernel.v1` `.proto`.
//!
//! The api repo cannot path-depend on zk-coins/node (separate checkouts).
//! The contract file is therefore carried under `proto/kernel/v1/kernel.proto`
//! (workspace root) and pinned by content hash.
//!
//! ## CI vs local
//!
//! - **CI gate (always):** [`KERNEL_PROTO_SHA256_HEX`] must match the bytes of
//!   the carried file. This is the only identity check that can fail in a
//!   standalone api checkout (the usual CI shape).
//! - **Local multi-repo worktree (optional):** when a sibling node checkout
//!   is present at `../node/proto/kernel/v1/kernel.proto`, the test also
//!   requires byte-identity with that file so local stacks catch drift
//!   immediately.
//!
//! The sibling comparison is **intentionally not a CI gate**. CI does not
//! check out `zk-coins/node` next to this tree, so a silent `return` on
//! absence would always be green without testing anything. The test below
//! therefore **names** that absence (`eprintln` + early return) and keeps
//! the pin-vs-file assertion as the real, always-on gate.
//!
//! ## PROTO_IDENTITY_CI_BOUNDARY (named follow-up; not fixed here)
//!
//! Pin-vs-file alone does not prove identity with the node contract: a PR can
//! change both the carried proto and the pin together. Closing that gap needs
//! CI to check out node at a fixed ref (or consume an externally versioned
//! proto artefact) and fail closed when the reference is missing — cross-repo
//! CI-checkout follow-up block, not this change.
//!
//! Lives in the **api** package (not `kernel-proto`) so `cargo test -p api`
//! always runs the pin; codegen isolation is a separate concern.

/// SHA-256 (lowercase hex) of `proto/kernel/v1/kernel.proto` as shipped with
/// this tree. Source: zk-coins/node `proto/kernel/v1/kernel.proto` at the
/// worktree used for this stage (`31bffc90…`). Updating the proto **requires**
/// updating this pin in the same change.
pub const KERNEL_PROTO_SHA256_HEX: &str =
    "6216ce66e7a5f35194feab32c2b73f077fbc5011a8a8e4d56459ede2c7f6d34c";

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

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "zkcoins-proto-{}-{}-{}",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    /// Restores original permissions on drop so chmod tests leave no sticky mode.
    #[cfg(unix)]
    struct RestorePerm {
        path: PathBuf,
        perm: std::fs::Permissions,
    }

    #[cfg(unix)]
    impl Drop for RestorePerm {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.path, self.perm.clone());
        }
    }

    #[derive(Debug)]
    enum SiblingCheck {
        SkippedAbsent,
        Matched,
    }

    /// Pure sibling compare: absence, match against pin, or named mismatch.
    fn check_sibling(local: &Path, sibling: &Path) -> Result<SiblingCheck, String> {
        if !sibling.is_file() {
            return Ok(SiblingCheck::SkippedAbsent);
        }
        let local_bytes = std::fs::read(local).map_err(|e| {
            format!(
                "failed to read local kernel proto at {}: {e}",
                local.display()
            )
        })?;
        let sibling_bytes = std::fs::read(sibling).map_err(|e| {
            format!(
                "failed to read sibling node proto at {}: {e}",
                sibling.display()
            )
        })?;
        if local_bytes != sibling_bytes {
            return Err(format!(
                "carried api proto must be byte-identical to sibling node proto at {}",
                sibling.display()
            ));
        }
        let got = sha256_hex(&sibling_bytes);
        if got != KERNEL_PROTO_SHA256_HEX {
            return Err(format!(
                "sibling node proto SHA-256 must equal the pin (node moved without api update); \
                 got {got}, pin {KERNEL_PROTO_SHA256_HEX}"
            ));
        }
        Ok(SiblingCheck::Matched)
    }

    /// Apply the local-only sibling match arms (named skip / Matched / panic).
    fn apply_sibling_check(result: Result<SiblingCheck, String>) {
        match result {
            Ok(SiblingCheck::SkippedAbsent) => {
                // Named skip: absence is expected in CI and standalone api clones.
                // Do not treat this as proof that the node contract matches.
                eprintln!(
                    "proto_identity: sibling node proto absent — \
                     skipping local multi-repo byte compare (CI gate is pin==file)"
                );
            }
            Ok(SiblingCheck::Matched) => {}
            Err(msg) => panic!("{msg}"),
        }
    }

    /// **CI-relevant gate:** carried file bytes must equal the pin.
    #[test]
    fn carried_proto_matches_pinned_sha256() {
        let path = local_proto_path();
        let bytes = std::fs::read(&path).expect("failed to read carried kernel proto");
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

    /// **Local-only optional check** — not a CI gate.
    ///
    /// When `../node` is absent (standalone / CI checkout), this test
    /// **explicitly skips** after documenting why. It must never be a silent
    /// green success that pretends the sibling was compared. The pin test
    /// above is the real CI identity gate.
    #[test]
    fn carried_proto_matches_sibling_node_when_present_local_only() {
        let sibling = sibling_node_proto_path();
        let local = local_proto_path();
        apply_sibling_check(check_sibling(&local, &sibling));
    }

    #[test]
    fn apply_sibling_check_matched_is_silent() {
        apply_sibling_check(Ok(SiblingCheck::Matched));
    }

    #[test]
    #[should_panic(expected = "sibling compare failed for unit test")]
    fn apply_sibling_check_err_panics() {
        apply_sibling_check(Err("sibling compare failed for unit test".to_string()));
    }

    #[test]
    fn check_sibling_absent_is_skipped() {
        let root = temp_root("absent");
        std::fs::create_dir_all(&root).expect("temp dir");
        let local = root.join("local.proto");
        let sibling = root.join("missing.proto");
        std::fs::write(&local, b"placeholder").expect("local");
        let result = check_sibling(&local, &sibling);
        assert!(matches!(result, Ok(SiblingCheck::SkippedAbsent)));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn check_sibling_identical_pinned_files_match() {
        let root = temp_root("match");
        std::fs::create_dir_all(&root).expect("temp dir");
        let bytes = std::fs::read(local_proto_path()).expect("read carried proto");
        let local = root.join("local.proto");
        let sibling = root.join("sibling.proto");
        std::fs::write(&local, &bytes).expect("local");
        std::fs::write(&sibling, &bytes).expect("sibling");
        let result = check_sibling(&local, &sibling);
        assert!(matches!(result, Ok(SiblingCheck::Matched)));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn check_sibling_different_files_is_err() {
        let root = temp_root("diff");
        std::fs::create_dir_all(&root).expect("temp dir");
        let local = root.join("local.proto");
        let sibling = root.join("sibling.proto");
        std::fs::write(&local, b"aaa").expect("local");
        std::fs::write(&sibling, b"bbb").expect("sibling");
        let result = check_sibling(&local, &sibling);
        assert!(result.is_err(), "different bytes must err: {result:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Sibling is a regular file; local is a directory so `read` fails.
    #[test]
    fn check_sibling_local_unreadable_is_err() {
        let root = temp_root("local-unreadable");
        std::fs::create_dir_all(&root).expect("temp dir");
        let local = root.join("local.proto");
        let sibling = root.join("sibling.proto");
        std::fs::create_dir(&local).expect("local as directory");
        std::fs::write(&sibling, b"sibling-bytes").expect("sibling file");
        let result = check_sibling(&local, &sibling);
        let err = result.expect_err("local directory must make read fail");
        assert!(
            err.contains("failed to read local kernel proto"),
            "message must name local read failure, got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Both paths are files; sibling mode 0o000 so `read` fails.
    #[cfg(unix)]
    #[test]
    fn check_sibling_sibling_unreadable_is_err() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("sibling-unreadable");
        std::fs::create_dir_all(&root).expect("temp dir");
        let local = root.join("local.proto");
        let sibling = root.join("sibling.proto");
        std::fs::write(&local, b"same-bytes").expect("local");
        std::fs::write(&sibling, b"same-bytes").expect("sibling");

        let original = std::fs::metadata(&sibling).expect("meta").permissions();
        let _restore = RestorePerm {
            path: sibling.clone(),
            perm: original.clone(),
        };
        let mut locked = original;
        locked.set_mode(0o000);
        std::fs::set_permissions(&sibling, locked).expect("chmod sibling 000");

        // If this process can still read mode 0o000 (e.g. root), the arm is not
        // exercised — fail closed rather than pretend success.
        match std::fs::read(&sibling) {
            Ok(_) => {
                drop(_restore);
                let _ = std::fs::remove_dir_all(&root);
                panic!(
                    "sibling mode 0o000 is still readable in this process; \
                     cannot exercise failed-to-read-sibling arm without root"
                );
            }
            Err(_) => {}
        }

        let result = check_sibling(&local, &sibling);
        let err = result.expect_err("unreadable sibling must err");
        assert!(
            err.contains("failed to read sibling node proto"),
            "message must name sibling read failure, got {err:?}"
        );
        drop(_restore);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Byte-identical local/sibling whose content is not the pin.
    #[test]
    fn check_sibling_identical_but_not_pinned_is_err() {
        let root = temp_root("not-pin");
        std::fs::create_dir_all(&root).expect("temp dir");
        let local = root.join("local.proto");
        let sibling = root.join("sibling.proto");
        let bytes = b"not-the-kernel-proto-bytes";
        std::fs::write(&local, bytes).expect("local");
        std::fs::write(&sibling, bytes).expect("sibling");
        let result = check_sibling(&local, &sibling);
        let err = result.expect_err("non-pin content must err");
        assert!(
            err.contains("sibling node proto SHA-256 must equal the pin"),
            "message must name pin mismatch, got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
