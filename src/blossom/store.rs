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
    pub fn exists(&self, id: &[u8; 32]) -> bool {
        self.blob_path(id).is_file() && self.uploader_path(id).is_file()
    }

    /// Byte length of a stored blob, or `None` if the complete pair is absent.
    pub fn size(&self, id: &[u8; 32]) -> Result<Option<u64>, ApiError> {
        if !self.exists(id) {
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
        if final_path.is_file() && note_path.is_file() {
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
                    return Ok(*id);
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
            Ok(()) => Ok(*id),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if note_path.is_file() {
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
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{}-{}", std::process::id(), nanos, seq)
}

fn write_exclusive(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    let _ = File::open(path.parent().unwrap_or(Path::new("."))).and_then(|d| d.sync_all());
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
        assert!(!store.exists(&id));
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
        assert!(store.exists(&id));
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
}
