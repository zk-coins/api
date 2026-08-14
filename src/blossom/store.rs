//! Content-addressed blob store on the local filesystem (§7.4 / §4.2.1).
//!
//! ## Data permanence (Requirement 12)
//!
//! The store is **append-only**. Received bytes are never deleted by this
//! process: there is no public DELETE, no retention sweep, no orphan prune on
//! open, and no post-install rollback of an installed content-addressed object.
//! Temp files used during a single `put` may be cleaned up (they are not
//! durable names).
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
//! ## Blob + note pair
//!
//! A durable object is the pair `(blob, note)`. Install order is blob then
//! note. A crash between the two can leave a blob without a note —
//! **incomplete**. `put` refuses while incomplete (no new note on a partial
//! write; fail-closed). Incomplete pairs are **left on disk** (data permanence);
//! they are never auto-pruned. A complete pair is only reported when both
//! files exist.
//!
//! ## Concurrency (single process)
//!
//! - **Root `RwLock`:** reserved for future exclusive operators; `put` takes a
//!   read lock so exclusive work cannot interleave with mutation.
//! - **Per-blob `Mutex`:** concurrent puts of the same content address are
//!   serialised. Parallel idempotent uploads of the same bytes all succeed
//!   (loser waits for the complete pair). Lock map entries are removed when
//!   no waiter holds the Arc anymore — so one-shot id touches cannot grow
//!   process memory without bound.
//!
//! ## BLOSSOM_MULTI_INSTANCE_BOUNDARY (named follow-up; not fixed here)
//!
//! The locks above are **process-local** only. Multiple API processes sharing
//! one store root are **not** coordinated by this implementation. Safe
//! multi-instance deployment requires either single-writer affinity to the
//! store root or an external shared lock manager / atomic blob+note
//! publication — do not scale out against a shared filesystem without that.
//! Tracking: deployment-topology follow-up block, not this PR.

use crate::error::ApiError;
use crate::hexutil::encode_hex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Exactly 64 lowercase hex characters (32 decoded bytes).
pub const BLOB_ID_HEX_LEN: usize = 64;

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Content-addressed store rooted at `root`.
#[derive(Debug)]
pub struct BlobStore {
    root: PathBuf,
    /// See module docs — exclusive operators (write) vs put (read).
    root_lock: RwLock<()>,
    /// Per-blob serialisation of put.
    ///
    /// Entries are created on demand and **removed** when the last holder
    /// finishes (`release_blob_lock`), so the map cannot grow unboundedly
    /// from one-shot id touches.
    blob_locks: Mutex<HashMap<[u8; 32], Arc<Mutex<()>>>>,
}

impl BlobStore {
    /// Open (or create) a store at `root`. No default path — the caller must
    /// supply a configured root. Does **not** prune incomplete pairs (data
    /// permanence).
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, ApiError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| {
            ApiError::internal(format!(
                "blossom store: cannot create root {}: {e}",
                root.display()
            ))
        })?;
        let meta = fs::metadata(&root).map_err(|e| {
            // race/chmod-after-create: create_dir_all succeeded then metadata fails
            #[cfg_attr(coverage_nightly, coverage(off))]
            {
                ApiError::internal(format!(
                    "blossom store: cannot stat root {}: {e}",
                    root.display()
                ))
            }
        })?;
        if !meta.is_dir() {
            // create_dir_all already fails when the path is a non-directory
            #[cfg_attr(coverage_nightly, coverage(off))]
            return Err(ApiError::internal(format!(
                "blossom store: root {} is not a directory",
                root.display()
            )));
        }
        Ok(Self {
            root,
            root_lock: RwLock::new(()),
            blob_locks: Mutex::new(HashMap::new()),
        })
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

    fn blob_path(&self, id: &[u8; 32]) -> PathBuf {
        self.root.join(Self::blob_id_hex(id))
    }

    fn uploader_path(&self, id: &[u8; 32]) -> PathBuf {
        self.root
            .join(format!("{}.uploader", Self::blob_id_hex(id)))
    }

    /// Fsync the store root directory. A complete pair is durable only after
    /// this succeeds; callers must fail-closed on error (names on disk ≠ durable).
    fn sync_store_root(&self) -> Result<(), ApiError> {
        File::open(&self.root)
            .and_then(|d| d.sync_all())
            .map_err(|e| {
                ApiError::internal(format!(
                    "blossom store: sync store root {}: {e}",
                    self.root.display()
                ))
            })
    }

    /// Acquire the per-blob serialisation lock (creates the map entry if needed).
    fn acquire_blob_lock(&self, id: &[u8; 32]) -> Arc<Mutex<()>> {
        let mut map = self.blob_locks.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(*id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Drop the caller's Arc and remove the map entry when no other holder
    /// remains. Must be called **after** the per-blob `Mutex` guard is dropped.
    ///
    /// Under the map lock, `strong_count == 2` means only the map entry and
    /// `held` reference this Arc (any concurrent acquirer would have bumped
    /// the count while holding the map lock). Removal is then race-free.
    fn release_blob_lock(&self, id: &[u8; 32], held: Arc<Mutex<()>>) {
        let mut map = self.blob_locks.lock().unwrap_or_else(|e| e.into_inner());
        if Arc::strong_count(&held) == 2 {
            if let Some(current) = map.get(id) {
                if Arc::ptr_eq(current, &held) {
                    map.remove(id);
                }
            }
        }
        // `held` drops at end of scope; after a successful remove the map no
        // longer retains the Arc.
        drop(held);
    }

    /// Run `f` under the per-blob lock, then clean up the map entry if unused.
    fn with_blob_lock<R>(&self, id: &[u8; 32], f: impl FnOnce() -> R) -> R {
        let arc = self.acquire_blob_lock(id);
        let result = {
            let _guard = arc.lock().unwrap_or_else(|e| e.into_inner());
            f()
        };
        self.release_blob_lock(id, arc);
        result
    }

    /// Test/diagnostic: number of live per-blob lock map entries.
    #[cfg(test)]
    fn blob_lock_entry_count(&self) -> usize {
        self.blob_locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// `true` when a **complete** durable pair (blob + note) exists.
    ///
    /// `NotFound` on either path is absence (`Ok(false)`). Any other IO error
    /// (e.g. permission denied) is `internal_error` — never silent false.
    pub fn exists(&self, id: &[u8; 32]) -> Result<bool, ApiError> {
        let blob_ok = match fs::metadata(self.blob_path(id)) {
            Ok(m) => m.is_file(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => {
                return Err(ApiError::internal(format!(
                    "blossom store: stat {}: {e}",
                    self.blob_path(id).display()
                )));
            }
        };
        let note_ok = match fs::metadata(self.uploader_path(id)) {
            Ok(m) => m.is_file(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => {
                return Err(ApiError::internal(format!(
                    "blossom store: stat {}: {e}",
                    self.uploader_path(id).display()
                )));
            }
        };
        Ok(blob_ok && note_ok)
    }

    /// Byte length of a stored blob, or `None` if the complete pair is absent.
    pub fn size(&self, id: &[u8; 32]) -> Result<Option<u64>, ApiError> {
        if !self.exists(id)? {
            return Ok(None);
        }
        let path = self.blob_path(id);
        match fs::metadata(&path) {
            Ok(m) if m.is_file() => Ok(Some(m.len())),
            // TOCTOU: exists() already requires blob_path to be a regular file
            Ok(_) => {
                #[cfg_attr(coverage_nightly, coverage(off))]
                {
                    Err(ApiError::internal(format!(
                        "blossom store: path {} is not a regular file",
                        path.display()
                    )))
                }
            }
            // TOCTOU: exists() said the complete pair was present
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                #[cfg_attr(coverage_nightly, coverage(off))]
                {
                    Ok(None)
                }
            }
            // TOCTOU / untestable without race after exists() succeeded
            Err(e) => {
                #[cfg_attr(coverage_nightly, coverage(off))]
                {
                    Err(ApiError::internal(format!(
                        "blossom store: stat {}: {e}",
                        path.display()
                    )))
                }
            }
        }
    }

    /// Read the full blob body, or `None` if the complete pair is absent.
    pub fn read(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, ApiError> {
        if !self.exists(id)? {
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
    /// absent. Incomplete pairs are fail-closed for readers (`exists`/`read`).
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
    /// left alone (first-uploader wins).
    ///
    /// Concurrent puts of the same content are serialised on a per-blob lock;
    /// losers that observe a complete pair return success.
    pub fn put(&self, body: &[u8], uploader_op: &[u8; 32]) -> Result<[u8; 32], ApiError> {
        let id: [u8; 32] = Sha256::digest(body).into();

        // Root read lock: exclusive operators (write) cannot run while put is active.
        let _root = self.root_lock.read().unwrap_or_else(|e| e.into_inner());
        self.with_blob_lock(&id, || self.put_locked(body, uploader_op, &id))
    }

    fn put_locked(
        &self,
        body: &[u8],
        uploader_op: &[u8; 32],
        id: &[u8; 32],
    ) -> Result<[u8; 32], ApiError> {
        let final_path = self.blob_path(id);
        let note_path = self.uploader_path(id);

        // Complete pair: first-uploader wins; do not rewrite note.
        // Names on disk ≠ durable until store-root fsync succeeds.
        if final_path.is_file() && note_path.is_file() {
            self.sync_store_root()?;
            return Ok(*id);
        }

        // Incomplete pair under the exclusive blob lock can only be a
        // crash leftover — refuse so a foreign retry cannot claim ownership.
        // Data permanence: incomplete objects are never auto-pruned.
        if final_path.is_file() || note_path.is_file() {
            return Err(ApiError::internal(
                "blossom store: incomplete blob/note pair present; \
                 refuse put (data permanence: incomplete objects are never deleted)",
            ));
        }

        let tag = unique_tmp_tag();
        let hex = Self::blob_id_hex(id);
        let blob_tmp = self.root.join(format!(".{hex}.blob.tmp.{tag}"));
        let note_tmp = self.root.join(format!(".{hex}.note.tmp.{tag}"));

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

        match install_no_replace(&blob_tmp, &final_path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&note_tmp);
                // Under per-blob lock this should not race another put, but
                // if a complete pair appeared, treat as idempotent success.
                if note_path.is_file() && final_path.is_file() {
                    // per-blob lock makes this a crash leftover, not a concurrent race
                    #[cfg_attr(coverage_nightly, coverage(off))]
                    {
                        self.sync_store_root()?;
                        return Ok(*id);
                    }
                }
                return Err(ApiError::internal(
                    "blossom store: blob slot occupied without complete pair; \
                     refuse put (data permanence: incomplete objects are never deleted)",
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

        match install_no_replace(&note_tmp, &note_path) {
            Ok(()) => {
                // Both final names installed; durable only after store-root fsync.
                self.sync_store_root()?;
                Ok(*id)
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if note_path.is_file() {
                    self.sync_store_root()?;
                    Ok(*id)
                } else {
                    // Data permanence: do not roll back the installed blob.
                    Err(ApiError::internal(format!(
                        "blossom store: install note race on {} (blob retained): {e}",
                        note_path.display()
                    )))
                }
            }
            Err(e) => {
                // Data permanence: do not roll back the installed blob.
                // Incomplete pair remains; subsequent put refuses.
                Err(ApiError::internal(format!(
                    "blossom store: install note {} (blob retained): {e}",
                    note_path.display()
                )))
            }
        }
    }

    /// Test/diagnostic: list names of regular files directly under the root.
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
    let nanos = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos(),
        // untestable without mocking SystemTime before UNIX_EPOCH
        Err(_) => {
            #[cfg_attr(coverage_nightly, coverage(off))]
            {
                0
            }
        }
    };
    format!("{}-{}-{}", std::process::id(), nanos, seq)
}

fn write_exclusive(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()?;
    Ok(())
}

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
    use std::os::unix::fs::PermissionsExt;
    use std::thread;

    static TEMP_ROOT_SEQ: AtomicU64 = AtomicU64::new(0);

    /// Restores original permissions on drop so chmod tests leave no sticky mode.
    struct RestorePerm {
        path: PathBuf,
        perm: std::fs::Permissions,
    }

    impl Drop for RestorePerm {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.path, self.perm.clone());
        }
    }

    fn temp_root() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let seq = TEMP_ROOT_SEQ.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "zkcoins-blossom-store-{}-{}-{}",
            std::process::id(),
            nanos,
            seq
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
        let other = [0x22u8; 32];
        let id2 = store.put(body, &other).expect("put again");
        assert_eq!(id2, id);
        let note = store.read_uploader(&id).expect("note").expect("present");
        assert_eq!(note, uploader);
        let _ = fs::remove_dir_all(&root);
    }

    /// Incomplete pairs refuse put and are never auto-pruned on re-open.
    #[test]
    fn incomplete_blob_without_note_refuses_put_and_survives_reopen() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let body = b"orphan-blob-body";
        let id = blob_id_of(body);
        fs::write(store.blob_path(&id), body).expect("orphan blob");
        assert!(store.read_uploader(&id).expect("read").is_none());
        assert!(!store.exists(&id).expect("exists"));
        let uploader = [0x33u8; 32];
        let err = store
            .put(body, &uploader)
            .expect_err("put must refuse incomplete");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            store.blob_path(&id).is_file(),
            "data permanence: incomplete blob must remain on disk"
        );
        drop(store);
        let store = BlobStore::open(&root).expect("re-open must not prune");
        assert!(
            store.blob_path(&id).is_file(),
            "re-open must not delete incomplete pairs"
        );
        let err2 = store
            .put(body, &uploader)
            .expect_err("still incomplete after re-open");
        assert_eq!(err2.body.error, "internal_error");
        let _ = fs::remove_dir_all(&root);
    }

    /// Complete objects stay readable after open; no path deletes them.
    #[test]
    fn complete_pair_survives_reopen() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let body = b"durable-blob";
        let uploader = [0x44u8; 32];
        let id = store.put(body, &uploader).expect("put");
        drop(store);
        let store = BlobStore::open(&root).expect("re-open");
        assert!(store.exists(&id).expect("exists"));
        assert_eq!(store.read(&id).unwrap().unwrap(), body);
        assert_eq!(store.read_uploader(&id).unwrap().unwrap(), uploader);
        let _ = fs::remove_dir_all(&root);
    }

    /// One-shot put of many distinct ids must not retain per-id lock map entries.
    #[test]
    fn put_does_not_retain_blob_lock_entries() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let op = [0x66u8; 32];
        assert_eq!(store.blob_lock_entry_count(), 0);
        for i in 0..64u32 {
            let mut body = [0u8; 8];
            body[0..4].copy_from_slice(&i.to_le_bytes());
            store.put(&body, &op).expect("put");
        }
        assert_eq!(
            store.blob_lock_entry_count(),
            0,
            "put must release per-blob lock map entries"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// Parallel puts of the **same** content: **all** succeed (serialised);
    /// single uploader note wins.
    #[test]
    fn parallel_puts_same_bytes_all_succeed() {
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
            h.join()
                .expect("thread")
                .expect("every parallel put must succeed");
            oks += 1;
        }
        assert_eq!(oks, 8, "all parallel puts must succeed");
        let id = blob_id_of(body);
        let note = store
            .read_uploader(&id)
            .expect("note")
            .expect("complete pair must have a note");
        assert_eq!(store.read(&id).unwrap().unwrap(), body);
        let late = store.put(body, &[0xff; 32]).expect("late put");
        assert_eq!(late, id);
        assert_eq!(
            store.read_uploader(&id).unwrap().unwrap(),
            note,
            "first complete uploader note must win"
        );
        let _ = fs::remove_dir_all(&root);
    }

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
                Ok::<_, ApiError>((id, op, body))
            }));
        }
        for h in handles {
            let (id, op, body) = h.join().expect("thread").expect("put");
            assert_eq!(id, blob_id_of(&body));
            assert_eq!(store.read_uploader(&id).unwrap().unwrap(), op);
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn open_on_file_cannot_create_root_is_internal_error() {
        let file_path = temp_root();
        fs::write(&file_path, b"not-a-dir").expect("write file at root path");
        let err = BlobStore::open(&file_path).expect_err("file is not a store root");
        assert_eq!(err.body.error, "internal_error");
        let cause = err.cause().unwrap_or("");
        assert!(
            cause.contains("cannot create root")
                || cause.contains("not a directory")
                || cause.contains("File exists"),
            "diagnostic must mention cannot create root / not a directory / File exists, got {cause:?}"
        );
        let _ = fs::remove_file(&file_path);
        let _ = fs::remove_dir_all(&file_path);
    }

    /// Poisoned map lock must recover via `into_inner` so put still works.
    #[test]
    fn put_recovers_from_poisoned_blob_locks_map() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = store.blob_locks.lock().expect("map lock");
            panic!("intentional poison for recover path");
        }));
        let body = b"poison-map-recover-body";
        let uploader = [0x55u8; 32];
        let id = store
            .put(body, &uploader)
            .expect("put after map poison recover");
        assert_eq!(id, blob_id_of(body));
        assert_eq!(store.read(&id).unwrap().unwrap(), body);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn list_root_names_after_root_deleted_is_internal_error() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let gone = store.root().with_extension("gone");
        fs::rename(store.root(), &gone).expect("rename store root away");
        let _ = fs::remove_dir_all(&gone);
        let err = store.list_root_names().expect_err("root gone");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("read_dir"),
            "diagnostic must mention read_dir, got {:?}",
            err.cause()
        );
    }

    #[test]
    fn read_uploader_corrupt_note_is_internal_error() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let id = blob_id_of(b"x");
        fs::write(store.uploader_path(&id), b"not-a-hex-note").expect("corrupt note");
        let err = store.read_uploader(&id).expect_err("corrupt note");
        assert_eq!(err.body.error, "internal_error");
        let cause = err.cause().unwrap_or("");
        assert!(
            cause.contains("corrupt") || cause.contains("uploader note"),
            "diagnostic must mention corrupt uploader note, got {cause:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// Permission errors on the store root must not look like absence (404).
    #[cfg(unix)]
    #[test]
    fn exists_size_read_permission_error_is_internal_not_absence() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let body = b"perm-denied-body";
        let uploader = [0x77u8; 32];
        let id = store.put(body, &uploader).expect("put");
        assert!(store.exists(&id).expect("exists before chmod"));

        let original = fs::metadata(&root).expect("meta").permissions();
        let _restore = RestorePerm {
            path: root.clone(),
            perm: original.clone(),
        };
        let mut locked = original.clone();
        locked.set_mode(0o000);
        fs::set_permissions(&root, locked).expect("chmod root 000");

        let err = store.exists(&id).expect_err("exists under locked root");
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.body.message, crate::error::PUBLIC_INTERNAL_MESSAGE);

        let err = store.size(&id).expect_err("size under locked root");
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);

        let err = store.read(&id).expect_err("read under locked root");
        assert_eq!(err.body.error, "internal_error");
        assert_eq!(err.status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);

        // Restore before remove_dir_all (RestorePerm Drop also restores).
        fs::set_permissions(&root, original).expect("restore root mode");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn put_refuses_incomplete_blob_without_note() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let body = b"incomplete-blob";
        let id = blob_id_of(body);
        let op = [0x11u8; 32];
        fs::write(store.blob_path(&id), body).expect("orphan blob");
        let err = store
            .put(body, &op)
            .expect_err("put must refuse incomplete");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("incomplete"),
            "cause must mention incomplete, got {:?}",
            err.cause()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn put_refuses_incomplete_note_without_blob() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let body = b"incomplete-note";
        let id = blob_id_of(body);
        let op = [0x11u8; 32];
        fs::write(store.uploader_path(&id), encode_hex(&op).as_bytes()).expect("orphan note");
        let err = store
            .put(body, &op)
            .expect_err("put must refuse incomplete");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("incomplete"),
            "cause must mention incomplete, got {:?}",
            err.cause()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn read_uploader_io_error_other_than_not_found() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let body = b"read-uploader-dir-note-body";
        let op = [0x11u8; 32];
        let id = store.put(body, &op).expect("put");
        let note_path = store.uploader_path(&id);
        fs::remove_file(&note_path).expect("remove note file");
        fs::create_dir(&note_path).expect("dir at note path");
        let err = store
            .read_uploader(&id)
            .expect_err("directory note must error");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("uploader note"),
            "cause must mention uploader note, got {:?}",
            err.cause()
        );
        let _ = fs::remove_dir(&note_path);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn read_io_error_other_than_not_found() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let body = b"read-chmod-zero-blob-body";
        let op = [0x11u8; 32];
        let id = store.put(body, &op).expect("put");
        let blob = store.blob_path(&id);
        let original = fs::metadata(&blob).expect("meta").permissions();
        let _restore = RestorePerm {
            path: blob.clone(),
            perm: original,
        };
        fs::set_permissions(&blob, fs::Permissions::from_mode(0o000)).expect("chmod 0");
        match store.read(&id) {
            Ok(Some(_)) => panic!("expected permission error on chmod 0 blob"),
            Ok(None) => panic!("expected permission error on chmod 0 blob, got None"),
            Err(err) => {
                assert_eq!(err.body.error, "internal_error");
                assert!(
                    err.cause().unwrap_or("").contains("read"),
                    "cause must mention read, got {:?}",
                    err.cause()
                );
            }
        }
        drop(_restore);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn put_write_blob_temp_fails_when_root_is_readonly() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let original = fs::metadata(&root).expect("meta").permissions();
        let _restore = RestorePerm {
            path: root.clone(),
            perm: original,
        };
        fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).expect("readonly root");
        let op = [0x11u8; 32];
        match store.put(b"readonly-root-body", &op) {
            Ok(_) => panic!("readonly root must reject put"),
            Err(err) => {
                assert_eq!(err.body.error, "internal_error");
                assert!(
                    err.cause().unwrap_or("").contains("write blob temp"),
                    "cause must mention write blob temp, got {:?}",
                    err.cause()
                );
            }
        }
        drop(_restore);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn write_exclusive_create_new_fails_if_exists() {
        let root = temp_root();
        fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("already-exists.tmp");
        fs::write(&path, b"seed").expect("seed file");
        let err = write_exclusive(&path, b"x").expect_err("create_new must fail");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn install_no_replace_already_exists() {
        let root = temp_root();
        fs::create_dir_all(&root).expect("create temp root");
        let tmp = root.join("install.tmp");
        let final_path = root.join("install.final");
        fs::write(&tmp, b"tmp").expect("tmp");
        fs::write(&final_path, b"final").expect("final");
        let err = install_no_replace(&tmp, &final_path).expect_err("must not replace");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(!tmp.exists(), "tmp must be removed on AlreadyExists");
        assert!(final_path.is_file(), "final must remain");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn install_no_replace_missing_parent() {
        let root = temp_root();
        fs::create_dir_all(&root).expect("create temp root");
        let tmp = root.join("missing-parent.tmp");
        fs::write(&tmp, b"tmp").expect("tmp");
        let final_path = root.join("no-such-dir").join("final");
        let err = install_no_replace(&tmp, &final_path).expect_err("missing parent");
        assert_ne!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(!tmp.exists(), "tmp must be removed on install error");
        let _ = fs::remove_dir_all(&root);
    }

    // --- lock recovery / release branches ---

    /// Poisoned per-blob mutex recovers via `into_inner` for a fresh complete put.
    #[test]
    fn put_recovers_from_poisoned_per_blob_mutex() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let body = b"poison-per-blob-mutex-unique-body";
        let id = blob_id_of(body);
        // Leave a poisoned Arc in the map; put → with_blob_lock recovers via into_inner.
        let arc = store.acquire_blob_lock(&id);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = arc.lock().expect("blob lock");
            panic!("intentional per-blob mutex poison for put path");
        }));
        drop(arc);
        let uploader = [0x91u8; 32];
        let got = store
            .put(body, &uploader)
            .expect("put must recover from poisoned per-blob mutex");
        assert_eq!(got, id);
        assert_eq!(store.read(&id).unwrap().unwrap(), body);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn blob_lock_entry_count_recovers_from_poisoned_map() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = store.blob_locks.lock().expect("map lock");
            panic!("intentional map poison for entry_count");
        }));
        let n = store.blob_lock_entry_count();
        assert_eq!(n, 0);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn put_recovers_from_poisoned_root_lock() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = store.root_lock.write().expect("root write");
            panic!("intentional root_lock poison");
        }));
        let body = b"poison-root-lock-unique-body";
        let uploader = [0x92u8; 32];
        let id = store
            .put(body, &uploader)
            .expect("put must recover from poisoned root_lock");
        assert_eq!(id, blob_id_of(body));
        assert_eq!(store.read(&id).unwrap().unwrap(), body);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn release_blob_lock_keeps_entry_while_extra_holder_lives() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let id = blob_id_of(b"extra-holder-body");
        let held = store.acquire_blob_lock(&id);
        let extra = Arc::clone(&held);
        store.release_blob_lock(&id, held);
        assert_eq!(
            store.blob_lock_entry_count(),
            1,
            "extra Arc must prevent map removal"
        );
        drop(extra);
        let drain = store.acquire_blob_lock(&id);
        store.release_blob_lock(&id, drain);
        assert_eq!(store.blob_lock_entry_count(), 0);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn release_blob_lock_does_not_remove_replaced_entry() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let id = blob_id_of(b"replace-entry-body");
        let held = store.acquire_blob_lock(&id);
        // Keep strong_count == 2 on `held` after map replace so the
        // `ptr_eq` false arm (not remove) is reached.
        let extra = Arc::clone(&held);
        let replacement = Arc::new(Mutex::new(()));
        {
            let mut map = store.blob_locks.lock().unwrap_or_else(|e| e.into_inner());
            map.insert(id, Arc::clone(&replacement));
        }
        store.release_blob_lock(&id, held);
        drop(extra);
        {
            let map = store.blob_locks.lock().unwrap_or_else(|e| e.into_inner());
            let current = map.get(&id).expect("replacement must remain");
            assert!(
                Arc::ptr_eq(current, &replacement),
                "release must not remove a non-ptr_eq map entry"
            );
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn release_blob_lock_missing_entry_is_noop() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let id = blob_id_of(b"missing-entry-body");
        let held = store.acquire_blob_lock(&id);
        // Keep strong_count == 2 while the map entry is gone so the
        // `if let Some(current) = map.get(id)` None path is exercised.
        let extra = Arc::clone(&held);
        {
            let mut map = store.blob_locks.lock().unwrap_or_else(|e| e.into_inner());
            map.remove(&id);
        }
        store.release_blob_lock(&id, held);
        drop(extra);
        assert_eq!(store.blob_lock_entry_count(), 0);
        let _ = fs::remove_dir_all(&root);
    }

    // --- exists / size / read branches ---

    #[test]
    fn exists_unknown_id_is_false() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let id = blob_id_of(b"never-stored");
        assert!(!store.exists(&id).expect("exists"));
        let _ = fs::remove_dir_all(&root);
    }

    /// Note path metadata fails (EACCES via symlink into mode-0 dir) while blob is a file.
    #[cfg(unix)]
    #[test]
    fn exists_note_stat_error_is_internal_error() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let body = b"exists-note-stat-error-body";
        let uploader = [0x93u8; 32];
        let id = store.put(body, &uploader).expect("put");
        let note = store.uploader_path(&id);
        assert!(note.is_file());

        let locked = root.join("locked-note-dir");
        fs::create_dir(&locked).expect("locked dir");
        let target = locked.join("note-target");
        fs::rename(&note, &target).expect("move note into locked dir");
        std::os::unix::fs::symlink(&target, &note).expect("symlink note path");

        let original = fs::metadata(&locked).expect("meta").permissions();
        let _restore = RestorePerm {
            path: locked.clone(),
            perm: original.clone(),
        };
        let mut mode = original.clone();
        mode.set_mode(0o000);
        fs::set_permissions(&locked, mode).expect("chmod locked 000");

        let err = store
            .exists(&id)
            .expect_err("note stat EACCES must be internal_error");
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("stat"),
            "cause must mention stat, got {:?}",
            err.cause()
        );

        fs::set_permissions(&locked, original).expect("restore locked mode");
        drop(_restore);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn size_and_read_unknown_id_are_none() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let id = blob_id_of(b"size-read-absent");
        assert_eq!(store.size(&id).expect("size"), None);
        assert_eq!(store.read(&id).expect("read"), None);
        let _ = fs::remove_dir_all(&root);
    }

    // TOCTOU size/read arms (250, 254-255, 270) need a race after internal
    // `exists()`; omitted here — not reliably deterministic without changing
    // production size/read logic.

    // --- put_locked install / temp-write errors ---

    fn list_names_with_prefix(root: &Path, prefix: &str) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Ok(rd) = fs::read_dir(root) {
            for entry in rd.flatten() {
                let name = entry.file_name();
                if let Some(s) = name.to_str() {
                    if s.starts_with(prefix) {
                        out.push(entry.path());
                    }
                }
            }
        }
        out
    }

    #[test]
    fn put_write_note_temp_fails_when_precreated() {
        let root = temp_root();
        let store = Arc::new(BlobStore::open(&root).expect("open"));
        let body = b"write-note-temp-fail-body";
        let id = blob_id_of(body);
        let hex = BlobStore::blob_id_hex(&id);
        let blob_prefix = format!(".{hex}.blob.tmp.");
        let root_t = root.clone();
        // Spin for the whole put window so the note temp is occupied as soon as
        // the tag is known from the blob temp name.
        let watcher = thread::spawn(move || {
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_secs(2) {
                for blob_tmp in list_names_with_prefix(&root_t, &blob_prefix) {
                    let name = blob_tmp.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if let Some(tag) = name.rsplit(".blob.tmp.").next() {
                        let note_tmp = root_t.join(format!(".{hex}.note.tmp.{tag}"));
                        let _ = fs::write(&note_tmp, b"occupied");
                    }
                }
                thread::yield_now();
            }
        });
        let op = [0xa1u8; 32];
        let err = store
            .put(body, &op)
            .expect_err("precreated note temp must fail write_exclusive");
        let _ = watcher.join();
        assert_eq!(err.body.error, "internal_error");
        assert!(
            err.cause().unwrap_or("").contains("write note temp"),
            "cause must mention write note temp, got {:?}",
            err.cause()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn put_install_blob_already_exists_incomplete_is_internal_error() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let body = b"install-blob-dir-occupied-body";
        let id = blob_id_of(body);
        // Directory at blob path: is_file() is false → incomplete guard does not fire.
        fs::create_dir(store.blob_path(&id)).expect("dir at blob path");
        let op = [0xa2u8; 32];
        let err = store
            .put(body, &op)
            .expect_err("directory at blob path must refuse put");
        assert_eq!(err.body.error, "internal_error");
        let cause = err.cause().unwrap_or("");
        assert!(
            cause.contains("occupied")
                || cause.contains("incomplete")
                || cause.contains("refuse put"),
            "cause must mention occupied/incomplete/refuse put, got {cause:?}"
        );
        let _ = fs::remove_dir(store.blob_path(&id));
        let _ = fs::remove_dir_all(&root);
    }

    /// After both temps exist, delete the blob temp so hard_link fails ≠ AlreadyExists.
    #[test]
    fn put_install_blob_other_error_when_temp_deleted() {
        let root = temp_root();
        let store = Arc::new(BlobStore::open(&root).expect("open"));
        let body = b"install-blob-other-error-body";
        let id = blob_id_of(body);
        let hex = BlobStore::blob_id_hex(&id);
        let blob_prefix = format!(".{hex}.blob.tmp.");
        let note_prefix = format!(".{hex}.note.tmp.");
        let root_t = root.clone();
        let watcher = thread::spawn(move || {
            let start = std::time::Instant::now();
            let mut armed = false;
            while start.elapsed() < std::time::Duration::from_secs(2) {
                let blobs = list_names_with_prefix(&root_t, &blob_prefix);
                let notes = list_names_with_prefix(&root_t, &note_prefix);
                if !blobs.is_empty() && !notes.is_empty() {
                    armed = true;
                }
                if armed {
                    for p in list_names_with_prefix(&root_t, &blob_prefix) {
                        let _ = fs::remove_file(&p);
                    }
                }
                thread::yield_now();
            }
        });
        let op = [0xa4u8; 32];
        let result = store.put(body, &op);
        let _ = watcher.join();
        match result {
            Err(err) => {
                assert_eq!(err.body.error, "internal_error");
                let cause = err.cause().unwrap_or("");
                assert!(
                    cause.contains("install blob"),
                    "cause must mention install blob, got {cause:?}"
                );
            }
            Ok(_) => panic!("expected install blob failure when blob temp deleted"),
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn put_install_note_already_exists_file_is_ok() {
        let root = temp_root();
        let store = Arc::new(BlobStore::open(&root).expect("open"));
        let body = b"install-note-exists-file-body";
        let id = blob_id_of(body);
        let final_blob = store.blob_path(&id);
        let final_note = store.uploader_path(&id);
        let watcher = thread::spawn(move || {
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_secs(2) {
                if final_blob.is_file() {
                    let _ = fs::write(&final_note, encode_hex(&[0xa5u8; 32]).as_bytes());
                }
                thread::yield_now();
            }
        });
        let op = [0xa5u8; 32];
        let got = store
            .put(body, &op)
            .expect("note AlreadyExists as file must be Ok");
        let _ = watcher.join();
        assert_eq!(got, id);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn put_install_note_already_exists_not_file_is_internal_error() {
        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        let body = b"install-note-dir-occupied-body";
        let id = blob_id_of(body);
        // Directory at note path; blob absent → incomplete guard: note_path.is_file() is false,
        // blob_path.is_file() is false → guard does not fire. put installs blob then note hard_link EEXIST.
        fs::create_dir(store.uploader_path(&id)).expect("dir at note path");
        let op = [0xa6u8; 32];
        let err = store
            .put(body, &op)
            .expect_err("directory at note path must fail install note");
        assert_eq!(err.body.error, "internal_error");
        let cause = err.cause().unwrap_or("");
        assert!(
            cause.contains("install note race") && cause.contains("blob retained"),
            "cause must mention install note race and blob retained, got {cause:?}"
        );
        assert!(
            store.blob_path(&id).is_file(),
            "data permanence: installed blob must remain"
        );
        let _ = fs::remove_dir(store.uploader_path(&id));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn put_install_note_other_error_retains_blob() {
        let root = temp_root();
        let body = b"install-note-other-error-body";
        let id = blob_id_of(body);
        let hex = BlobStore::blob_id_hex(&id);
        let note_prefix = format!(".{hex}.note.tmp.");
        let op = [0xa7u8; 32];
        // Watcher races the note-tmp (exists before final blob hard_link), not the final blob.
        // Deleting note-tmp as soon as it appears widens the install-note failure window.
        let mut saw_err = false;
        for _ in 0..50 {
            let store = Arc::new(BlobStore::open(&root).expect("open"));
            let _ = fs::remove_file(store.blob_path(&id));
            let _ = fs::remove_file(store.uploader_path(&id));
            let root_t = root.clone();
            let prefix = note_prefix.clone();
            let watcher = thread::spawn(move || {
                let start = std::time::Instant::now();
                while start.elapsed() < std::time::Duration::from_secs(2) {
                    for p in list_names_with_prefix(&root_t, &prefix) {
                        let _ = fs::remove_file(&p);
                    }
                    thread::yield_now();
                }
            });
            let result = store.put(body, &op);
            let _ = watcher.join();
            if let Err(err) = result {
                assert_eq!(err.body.error, "internal_error");
                let cause = err.cause().unwrap_or("");
                assert!(
                    cause.contains("install note") && cause.contains("blob retained"),
                    "cause must mention install note and blob retained, got {cause:?}"
                );
                assert!(
                    store.blob_path(&id).is_file(),
                    "data permanence: blob must remain after note install failure"
                );
                saw_err = true;
                break;
            }
        }
        let _ = fs::remove_dir_all(&root);
        assert!(
            saw_err,
            "expected install note failure when note temp deleted (50 attempts)"
        );
    }

    // --- list_root_names / non-UTF8 ---

    #[cfg(unix)]
    #[test]
    fn list_root_names_skips_non_utf8_and_lists_utf8() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = temp_root();
        let store = BlobStore::open(&root).expect("open");
        fs::write(root.join("visible-utf8"), b"ok").expect("utf8 file");
        // APFS/macOS rejects some non-UTF8 names (Illegal byte sequence); skip that arm then.
        let non_utf8 = OsString::from_vec(vec![0xff, 0xfe]);
        let non_utf8_path = root.join(&non_utf8);
        let created_non_utf8 = fs::write(&non_utf8_path, b"bin").is_ok();
        let names = store.list_root_names().expect("list");
        assert!(
            names.iter().any(|n| n == "visible-utf8"),
            "utf8 name must be listed, got {names:?}"
        );
        if created_non_utf8 {
            // Non-UTF8 name must not appear (to_str() skip arm).
            assert_eq!(
                names.len(),
                1,
                "only the utf8 name must be listed, got {names:?}"
            );
            let _ = fs::remove_file(&non_utf8_path);
        }
        let _ = fs::remove_dir_all(&root);
    }
}
