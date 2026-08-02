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
//! ## Atomic write (no-replace)
//!
//! Upload writes blob and uploader-note to unique temp files in the same
//! directory, then installs each final name with **hard-link create-new**
//! semantics (`hard_link` fails with `AlreadyExists` if the target is
//! present). That closes the TOCTOU between `is_file()` and `rename()`, and
//! never replaces an existing content-addressed object or note.
//!
//! Temp names include process id, a monotonic counter, and a time component
//! so concurrent puts never share a temp path.
//!
//! ## Blob + note pair
//!
//! A durable object is the pair `(blob, note)`. Install order is blob then
//! note; if note install fails after blob install, the blob we just created
//! is rolled back. A crash between the two can leave a blob without a note
//! — **incomplete**. `put` refuses while incomplete (no new note on an
//! orphan). Recovery on `open` removes incomplete pairs. A complete pair is
//! never reported for an incomplete address, so a foreign retry cannot
//! inherit DELETE ownership.
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Exactly 64 lowercase hex characters (32 decoded bytes).
pub const BLOB_ID_HEX_LEN: usize = 64;

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Content-addressed store rooted at `root`.
#[derive(Debug, Clone)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    /// Open (or create) a store at `root`. No default path — the caller must
    /// supply a configured root. Runs incomplete-pair recovery before return.
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
        let store = Self { root };
        store.recover_incomplete_pairs()?;
        Ok(store)
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

    /// `true` when a **complete** durable pair (blob + note) exists.
    pub fn exists(&self, id: &[u8; 32]) -> bool {
        self.blob_path(id).is_file() && self.uploader_path(id).is_file()
    }

    /// Byte length of a stored blob, or `None` if the complete pair is absent.
    pub fn size(&self, id: &[u8; 32]) -> Result<Option<u64>, ApiError> {
        if !self.exists(id) {
            // Incomplete orphan: not a readable object.
            return Ok(None);
        }
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

    /// Read the full blob body, or `None` if the complete pair is absent.
    pub fn read(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, ApiError> {
        if !self.exists(id) {
            return Ok(None);
        }
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

    /// Store `body` under `blob_id = H(body)`. Idempotent when a **complete**
    /// pair already exists: body is not rewritten and the uploader note is
    /// left alone (first-uploader wins for DELETE).
    ///
    /// Incomplete pairs (blob without note) are recovered away before install
    /// so a retry never inherits foreign DELETE ownership.
    ///
    /// Returns the content address.
    pub fn put(&self, body: &[u8], uploader_op: &[u8; 32]) -> Result<[u8; 32], ApiError> {
        let id: [u8; 32] = Sha256::digest(body).into();
        let final_path = self.blob_path(&id);
        let note_path = self.uploader_path(&id);

        // Complete pair: first-uploader wins; do not rewrite note.
        if final_path.is_file() && note_path.is_file() {
            return Ok(id);
        }

        // Incomplete pair (blob xor note): do **not** attach a new uploader
        // note — that would hand DELETE ownership to a foreign retry. Fail
        // closed; `open` / operator recovery clears orphans.
        if final_path.is_file() || note_path.is_file() {
            return Err(ApiError::internal(
                "blossom store: incomplete blob/note pair present; \
                 refuse put so a foreign retry cannot claim DELETE ownership \
                 (run store open recovery or remove the orphan)",
            ));
        }

        let tag = unique_tmp_tag();
        let hex = Self::blob_id_hex(&id);
        let blob_tmp = self.root.join(format!(".{hex}.blob.tmp.{tag}"));
        let note_tmp = self.root.join(format!(".{hex}.note.tmp.{tag}"));

        // Both temps first (unique names — no collision across concurrent puts).
        if let Err(e) = write_exclusive(&blob_tmp, body) {
            let _ = fs::remove_file(&blob_tmp);
            return Err(ApiError::internal(format!(
                "blossom store: write blob temp {}: {e}",
                blob_tmp.display()
            )));
        }
        let note_hex = encode_hex(uploader_op);
        if let Err(e) = write_exclusive(&note_tmp, note_hex.as_bytes()) {
            let _ = fs::remove_file(&blob_tmp);
            let _ = fs::remove_file(&note_tmp);
            return Err(ApiError::internal(format!(
                "blossom store: write note temp {}: {e}",
                note_tmp.display()
            )));
        }

        // Install blob with no-replace. Concurrent winner may have finished a
        // complete pair in the meantime.
        match install_no_replace(&blob_tmp, &final_path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&note_tmp);
                // Another put won the blob slot. If they also installed the
                // note, we are the idempotent loser — success, original note.
                // If note is still missing, do not attach ours (ownership).
                if note_path.is_file() {
                    return Ok(id);
                }
                return Err(ApiError::internal(
                    "blossom store: concurrent put left incomplete pair; retry after recovery",
                ));
            }
            Err(e) => {
                let _ = fs::remove_file(&note_tmp);
                return Err(ApiError::internal(format!(
                    "blossom store: install blob {}: {e}",
                    final_path.display()
                )));
            }
        }

        // Install note; roll back our blob if this fails so we do not leave
        // an incomplete pair that a foreign retry could claim as success.
        match install_no_replace(&note_tmp, &note_path) {
            Ok(()) => Ok(id),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // Note appeared (shouldn't under normal exclusive install of
                // the same id by us) — treat complete pair as success.
                if note_path.is_file() {
                    Ok(id)
                } else {
                    let _ = fs::remove_file(&final_path);
                    Err(ApiError::internal(format!(
                        "blossom store: install note race on {}: {e}",
                        note_path.display()
                    )))
                }
            }
            Err(e) => {
                let _ = fs::remove_file(&final_path);
                Err(ApiError::internal(format!(
                    "blossom store: install note {}: {e}",
                    note_path.display()
                )))
            }
        }
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

    /// Remove incomplete pairs under the store root (blob without note, or
    /// note without blob). Temp files are left for the next put's unique
    /// names / OS cleanup of abandoned temps is best-effort.
    fn recover_incomplete_pairs(&self) -> Result<(), ApiError> {
        let rd = fs::read_dir(&self.root).map_err(|e| {
            ApiError::internal(format!(
                "blossom store: read_dir {}: {e}",
                self.root.display()
            ))
        })?;
        let mut blob_hexes = Vec::new();
        let mut note_hexes = Vec::new();
        for entry in rd {
            let entry = entry
                .map_err(|e| ApiError::internal(format!("blossom store: read_dir entry: {e}")))?;
            let name = match entry.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue,
            };
            if name.len() == BLOB_ID_HEX_LEN
                && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                if entry.path().is_file() {
                    blob_hexes.push(name);
                }
                continue;
            }
            if let Some(hex) = name.strip_suffix(".uploader") {
                if hex.len() == BLOB_ID_HEX_LEN
                    && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                    && entry.path().is_file()
                {
                    note_hexes.push(hex.to_string());
                }
            }
        }
        for hex in &blob_hexes {
            let note = self.root.join(format!("{hex}.uploader"));
            if !note.is_file() {
                let blob = self.root.join(hex);
                let _ = fs::remove_file(&blob);
            }
        }
        for hex in &note_hexes {
            let blob = self.root.join(hex);
            if !blob.is_file() {
                let note = self.root.join(format!("{hex}.uploader"));
                let _ = fs::remove_file(&note);
            }
        }
        Ok(())
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

fn unique_tmp_tag() -> String {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{}-{}", std::process::id(), nanos, seq)
}

/// Create a new file exclusively and write all bytes, then sync.
fn write_exclusive(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    // Drop closes the file before link/rename.
    drop(f);
    // Touch parent directory durability on platforms that need it is
    // best-effort; the directory entry install below is still atomic.
    let _ = File::open(path.parent().unwrap_or(Path::new("."))).and_then(|d| d.sync_all());
    Ok(())
}

/// Install `tmp` at `final_path` only if `final_path` does not already exist.
///
/// Uses `hard_link` (fails with `AlreadyExists` when the target is present)
/// then removes the temp. Never rename-over.
fn install_no_replace(tmp: &Path, final_path: &Path) -> io::Result<()> {
    match fs::hard_link(tmp, final_path) {
        Ok(()) => {
            let _ = fs::remove_file(tmp);
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(tmp);
            Err(e)
        }
        Err(e) => {
            let _ = fs::remove_file(tmp);
            Err(e)
        }
    }
}

/// SHA-256 of raw bytes — the normative `blob_id` (§4.2.1).
pub fn blob_id_of(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

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
        // Simulate an aborted upload: temp file left behind, no install.
        let tmp = root.join(format!(".{}.blob.tmp.aborted", BlobStore::blob_id_hex(&id)));
        fs::write(&tmp, body).expect("write temp");
        assert!(
            store.read(&id).expect("read").is_none(),
            "temp file must not be readable under the content address"
        );
        assert!(!store.exists(&id));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn incomplete_blob_without_note_refuses_put_and_open_recovers() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let body = b"orphan-blob-body";
        let id = blob_id_of(body);
        // Simulate crash after blob install, before note.
        fs::write(store.blob_path(&id), body).expect("orphan blob");
        assert!(store.read_uploader(&id).expect("read").is_none());
        assert!(
            !store.exists(&id),
            "incomplete pair must not count as exists"
        );
        // Foreign retry must not claim DELETE ownership via a new note.
        let uploader = [0x33u8; 32];
        let err = store
            .put(body, &uploader)
            .expect_err("put must refuse incomplete");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("incomplete"),
            "cause must name incomplete pair, got {:?}",
            err.cause()
        );
        // open recovery clears the orphan; a subsequent put may then succeed.
        drop(store);
        let store = BlobStore::open(&root).expect("re-open recovers");
        assert!(!store.blob_path(&id).is_file());
        let id2 = store.put(body, &uploader).expect("put after recovery");
        assert_eq!(id2, id);
        assert_eq!(store.read_uploader(&id).unwrap().unwrap(), uploader);
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
        // exists requires the complete pair.
        assert!(!store.exists(&id));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn open_recovers_incomplete_pairs() {
        let root = temp_root();
        fs::create_dir_all(&root).unwrap();
        let body = b"recover-me";
        let id = blob_id_of(body);
        let hex = BlobStore::blob_id_hex(&id);
        fs::write(root.join(&hex), body).unwrap();
        // No note — open must clear the orphan.
        let store = BlobStore::open(&root).expect("open");
        assert!(!store.blob_path(&id).is_file());
        let _ = fs::remove_dir_all(&root);
    }

    /// Parallel puts of the **same** content by different uploaders: exactly
    /// one note wins (first complete pair); no panic; both observe Ok.
    #[test]
    fn parallel_puts_same_bytes_single_uploader_note() {
        let root = temp_root();
        let store = Arc::new(BlobStore::open(&root).expect("open"));
        let body = b"parallel-same-bytes";
        let mut handles = Vec::new();
        for i in 0..8u8 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let mut op = [0u8; 32];
                op[0] = i;
                store.put(body, &op)
            }));
        }
        let mut oks = 0;
        for h in handles {
            if h.join().expect("thread").is_ok() {
                oks += 1;
            }
        }
        assert!(oks >= 1, "at least one put must succeed");
        let id = blob_id_of(body);
        let note = store
            .read_uploader(&id)
            .expect("note")
            .expect("complete pair must have a note");
        // Note is some single uploader — stable after all joins.
        assert_eq!(store.read(&id).unwrap().unwrap(), body);
        // Second wave still preserves that note.
        let late = store.put(body, &[0xff; 32]).expect("late put");
        assert_eq!(late, id);
        assert_eq!(
            store.read_uploader(&id).unwrap().unwrap(),
            note,
            "first complete uploader must win DELETE ownership"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// Parallel puts of **different** content by different uploaders all
    /// succeed with their own notes.
    #[test]
    fn parallel_puts_distinct_uploaders_and_bodies() {
        let root = temp_root();
        let store = Arc::new(BlobStore::open(&root).expect("open"));
        let mut handles = Vec::new();
        for i in 0..8u8 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let body = vec![i; 32];
                let mut op = [0u8; 32];
                op[0] = i;
                op[1] = 0xaa;
                let id = store.put(&body, &op)?;
                let note = store
                    .read_uploader(&id)?
                    .ok_or_else(|| ApiError::internal("missing note after put"))?;
                if note != op {
                    return Err(ApiError::internal("note mismatch after put"));
                }
                Ok::<_, ApiError>(id)
            }));
        }
        for h in handles {
            h.join().expect("thread").expect("put");
        }
        let _ = fs::remove_dir_all(&root);
    }
}
