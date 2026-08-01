//! Content-addressed blob store on the local filesystem (§7.4 / §4.2.1).
//!
//! ## Address = content
//!
//! `blob_id = SHA-256(body)` (lowercase hex). The on-disk filename is that
//! hex string and **nothing else**. Path parameters are validated as exactly
//! 64 lowercase hex characters *before* they become a path component, so
//! traversal (`..`, separators, uppercase, Unicode tricks) is structurally
//! impossible — not filtered after the fact.
//!
//! ## Atomic write
//!
//! Upload writes to a temporary file in the same directory, then `rename`s
//! onto the final address. An aborted upload cannot leave a half-written
//! blob under a valid content address (that would break the content-
//! addressed invariant: address would no longer hash to content).
//!
//! ## Uploader note
//!
//! Beside each blob lives `{blob_id}.uploader` holding the original uploader's
//! `op` pubkey as 64 lowercase hex characters. DELETE is authorised against
//! that note. **Fail-closed:** if the note is missing, DELETE is refused —
//! never "no note ⇒ allow".

use crate::error::ApiError;
use crate::hexutil::encode_hex;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Exactly 64 lowercase hex characters (32 decoded bytes).
pub const BLOB_ID_HEX_LEN: usize = 64;

/// Content-addressed store rooted at `root`.
#[derive(Debug, Clone)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    /// Open (or create) a store at `root`. No default path — the caller must
    /// supply a configured root.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, ApiError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| {
            ApiError::internal(format!(
                "blossom store: cannot create root {}: {e}",
                root.display()
            ))
        })?;
        let meta = fs::metadata(&root).map_err(|e| {
            ApiError::internal(format!(
                "blossom store: cannot stat root {}: {e}",
                root.display()
            ))
        })?;
        if !meta.is_dir() {
            return Err(ApiError::internal(format!(
                "blossom store: root {} is not a directory",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    /// Filesystem root (tests / diagnostics).
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Parse a path parameter into a content address.
    ///
    /// Accepts **only** exactly 64 lowercase ASCII hex characters. Everything
    /// else — wrong length, uppercase, non-hex, separators — is `400` and
    /// never becomes a path component.
    pub fn parse_blob_id(param: &str) -> Result<[u8; 32], ApiError> {
        if param.len() != BLOB_ID_HEX_LEN {
            return Err(ApiError::malformed(format!(
                "blob path parameter must be exactly {BLOB_ID_HEX_LEN} lowercase hex characters, got {}",
                param.len()
            )));
        }
        if !param
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(ApiError::malformed(
                "blob path parameter must be lowercase hex [0-9a-f] only \
                 (uppercase, separators, and non-hex are rejected before any path join)",
            ));
        }
        let mut out = [0u8; 32];
        let bytes = param.as_bytes();
        for i in 0..32 {
            let hi = nibble(bytes[i * 2]);
            let lo = nibble(bytes[i * 2 + 1]);
            out[i] = (hi << 4) | lo;
        }
        Ok(out)
    }

    /// Lowercase-hex form of a blob id (the only form used as a filename).
    pub fn blob_id_hex(id: &[u8; 32]) -> String {
        encode_hex(id)
    }

    /// Absolute path of the blob file. Caller **must** have validated `id`
    /// via [`Self::parse_blob_id`] or by hashing trusted body bytes — this
    /// method does not re-interpret user strings.
    fn blob_path(&self, id: &[u8; 32]) -> PathBuf {
        self.root.join(Self::blob_id_hex(id))
    }

    /// Absolute path of the uploader-note sidecar.
    fn uploader_path(&self, id: &[u8; 32]) -> PathBuf {
        self.root
            .join(format!("{}.uploader", Self::blob_id_hex(id)))
    }

    /// `true` when a durable blob exists under this address.
    pub fn exists(&self, id: &[u8; 32]) -> bool {
        self.blob_path(id).is_file()
    }

    /// Byte length of a stored blob, or `None` if absent.
    pub fn size(&self, id: &[u8; 32]) -> Result<Option<u64>, ApiError> {
        let path = self.blob_path(id);
        match fs::metadata(&path) {
            Ok(m) if m.is_file() => Ok(Some(m.len())),
            Ok(_) => Err(ApiError::internal(format!(
                "blossom store: path {} is not a regular file",
                path.display()
            ))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ApiError::internal(format!(
                "blossom store: stat {}: {e}",
                path.display()
            ))),
        }
    }

    /// Read the full blob body, or `None` if absent.
    pub fn read(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, ApiError> {
        let path = self.blob_path(id);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ApiError::internal(format!(
                "blossom store: read {}: {e}",
                path.display()
            ))),
        }
    }

    /// Read the original uploader's `op` pubkey, or `None` if the note is
    /// absent. DELETE treats absence as refuse (fail-closed).
    pub fn read_uploader(&self, id: &[u8; 32]) -> Result<Option<[u8; 32]>, ApiError> {
        let path = self.uploader_path(id);
        let text = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(ApiError::internal(format!(
                    "blossom store: read uploader note {}: {e}",
                    path.display()
                )));
            }
        };
        let text = text.trim();
        // Notes we wrote are 64 lowercase hex; anything else is corruption.
        let id = Self::parse_blob_id(text).map_err(|e| {
            ApiError::internal(format!(
                "blossom store: corrupt uploader note {}: {}",
                path.display(),
                e.body.message
            ))
        })?;
        Ok(Some(id))
    }

    /// Store `body` under `blob_id = H(body)`. Idempotent: if the address
    /// already holds a file, the body is not rewritten and the uploader note
    /// is left alone (first-uploader wins for DELETE).
    ///
    /// Returns the content address.
    pub fn put(&self, body: &[u8], uploader_op: &[u8; 32]) -> Result<[u8; 32], ApiError> {
        let id: [u8; 32] = Sha256::digest(body).into();
        let final_path = self.blob_path(&id);

        if final_path.is_file() {
            // Content-addressed: same bytes ⇒ same address. Do not touch the
            // original uploader note.
            return Ok(id);
        }

        // Atomic blob write: temp in same directory, then rename.
        let tmp_name = format!(".{}.tmp.{}", Self::blob_id_hex(&id), std::process::id());
        let tmp_path = self.root.join(&tmp_name);
        write_exclusive(&tmp_path, body).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            ApiError::internal(format!(
                "blossom store: write temp {}: {e}",
                tmp_path.display()
            ))
        })?;
        fs::rename(&tmp_path, &final_path).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            ApiError::internal(format!(
                "blossom store: rename {} → {}: {e}",
                tmp_path.display(),
                final_path.display()
            ))
        })?;

        // Uploader note — also atomic. Failure after the blob rename is
        // reported loudly; DELETE will fail-closed without the note.
        let note_path = self.uploader_path(&id);
        let note_tmp = self.root.join(format!(
            ".{}.uploader.tmp.{}",
            Self::blob_id_hex(&id),
            std::process::id()
        ));
        let note_hex = encode_hex(uploader_op);
        write_exclusive(&note_tmp, note_hex.as_bytes()).map_err(|e| {
            let _ = fs::remove_file(&note_tmp);
            ApiError::internal(format!(
                "blossom store: write uploader temp {}: {e}",
                note_tmp.display()
            ))
        })?;
        fs::rename(&note_tmp, &note_path).map_err(|e| {
            let _ = fs::remove_file(&note_tmp);
            ApiError::internal(format!(
                "blossom store: rename uploader note {}: {e}",
                note_path.display()
            ))
        })?;

        Ok(id)
    }

    /// Delete blob and uploader note. Returns `true` if the blob existed.
    pub fn delete(&self, id: &[u8; 32]) -> Result<bool, ApiError> {
        let blob = self.blob_path(id);
        let note = self.uploader_path(id);
        let existed = match fs::remove_file(&blob) {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => {
                return Err(ApiError::internal(format!(
                    "blossom store: delete {}: {e}",
                    blob.display()
                )));
            }
        };
        // Note removal after blob removal; absence is fine (fail-closed only
        // applies when authorising DELETE, not when cleaning up).
        match fs::remove_file(&note) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(ApiError::internal(format!(
                    "blossom store: delete uploader note {}: {e}",
                    note.display()
                )));
            }
        }
        Ok(existed)
    }

    /// Test/diagnostic: list names of regular files directly under the root.
    /// Never follows the path parameter — used only to prove traversal tests
    /// did not touch files outside the store.
    #[cfg(test)]
    pub fn list_root_names(&self) -> Result<Vec<String>, ApiError> {
        let mut names = Vec::new();
        let rd = fs::read_dir(&self.root).map_err(|e| {
            ApiError::internal(format!(
                "blossom store: read_dir {}: {e}",
                self.root.display()
            ))
        })?;
        for entry in rd {
            let entry = entry
                .map_err(|e| ApiError::internal(format!("blossom store: read_dir entry: {e}")))?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }
}

fn nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => unreachable!("caller validated lowercase hex"),
    }
}

/// Create a new file exclusively and write all bytes, then sync.
fn write_exclusive(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    // Drop closes the file before rename.
    drop(f);
    // Touch parent directory durability on platforms that need it is
    // best-effort; rename is still atomic for the directory entry.
    let _ = File::open(path.parent().unwrap_or(Path::new("."))).and_then(|d| d.sync_all());
    Ok(())
}

/// SHA-256 of raw bytes — the normative `blob_id` (§4.2.1).
pub fn blob_id_of(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "zkcoins-blossom-store-{}-{}",
            std::process::id(),
            nanos
        ));
        let _ = fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn parse_blob_id_accepts_exact_lowercase_hex() {
        let hex = "a".repeat(64);
        let id = BlobStore::parse_blob_id(&hex).expect("valid");
        assert_eq!(id, [0xaa; 32]);
    }

    #[test]
    fn parse_blob_id_rejects_uppercase() {
        let hex = "A".repeat(64);
        let err = BlobStore::parse_blob_id(&hex).expect_err("uppercase");
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(err.body.error, "malformed_request");
        assert!(
            err.body.message.contains("lowercase"),
            "cause must name lowercase rule: {}",
            err.body.message
        );
    }

    #[test]
    fn parse_blob_id_rejects_wrong_lengths() {
        for bad in [
            "a".repeat(63),
            "a".repeat(65),
            String::new(),
            "zz".to_string(),
        ] {
            let err = BlobStore::parse_blob_id(&bad).expect_err("bad length/chars");
            assert_eq!(err.body.error, "malformed_request");
        }
    }

    #[test]
    fn parse_blob_id_rejects_traversal_shapes() {
        for bad in [
            "../".to_string() + &"a".repeat(61),
            "a".repeat(32) + "/../" + &"b".repeat(28),
            "a".repeat(32) + ".." + &"b".repeat(30),
            "%2e%2e%2f".to_string() + &"a".repeat(55),
        ] {
            let err = BlobStore::parse_blob_id(&bad).expect_err("traversal shape");
            assert_eq!(
                err.body.error, "malformed_request",
                "traversal-shaped input must be 400, got {:?}",
                err
            );
        }
    }

    #[test]
    fn put_get_roundtrip_and_idempotent() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let body = b"hello blossom ciphertext";
        let uploader = [0x11u8; 32];
        let id = store.put(body, &uploader).expect("put");
        assert_eq!(id, blob_id_of(body));
        let got = store.read(&id).expect("read").expect("present");
        assert_eq!(got, body);
        assert_eq!(store.size(&id).expect("size"), Some(body.len() as u64));
        // Second put same bytes: same id, original uploader preserved.
        let other = [0x22u8; 32];
        let id2 = store.put(body, &other).expect("put again");
        assert_eq!(id2, id);
        let note = store.read_uploader(&id).expect("note").expect("present");
        assert_eq!(note, uploader);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn aborted_temp_is_not_a_readable_blob() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let body = b"partial-write-simulation";
        let id = blob_id_of(body);
        // Simulate an aborted upload: temp file left behind, no rename.
        let tmp = root.join(format!(".{}.tmp.aborted", BlobStore::blob_id_hex(&id)));
        fs::write(&tmp, body).expect("write temp");
        assert!(
            store.read(&id).expect("read").is_none(),
            "temp file must not be readable under the content address"
        );
        assert!(!store.exists(&id));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn delete_without_uploader_note_is_detectable() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let body = b"orphan-blob";
        let id = store.put(body, &[0x33; 32]).expect("put");
        // Remove only the note — DELETE auth path must refuse.
        fs::remove_file(store.uploader_path(&id)).expect("rm note");
        assert!(store.read_uploader(&id).expect("read").is_none());
        assert!(store.exists(&id));
        let _ = fs::remove_dir_all(&root);
    }
}
