//! On-disk spill-over for large request / response bodies.
//!
//! Most exchanges carry tiny bodies — JSON API replies, empty GETs,
//! small form posts. Those stay inline in SQLite (the `req_body_inline`
//! / `res_body_inline` BLOB columns) so the detail pane can materialise
//! them with a single query. But the proxy also sees the occasional
//! large download (PDFs, images, zip archives) and even the
//! occasional pathological case — a video stream, a full-page HTML
//! dump, a large JSON export. Keeping every one of those in the DB
//! bloats the file and slows every SELECT.
//!
//! The policy is simple:
//!
//! * **≤ 512 KB** → stored inline in SQLite.
//! * **> 512 KB and ≤ 32 MB** → written to a blob file at
//!   `<db-dir>/proxy_blobs/<session>/<exchange>.<kind>`; the DB row
//!   stores the path instead of the bytes.
//! * **> 32 MB** → forwarded to the peer in full but only the first
//!   32 MB are captured (the exchange is tagged `body-truncated` so
//!   the UI can say so).
//!
//! This module owns the on-disk layout; the listener and writer
//! choose inline-vs-spill at insert time.

use std::path::{Path, PathBuf};

use crate::exchange::{ExchangeId, SessionId};

/// Size ≤ this number of bytes is kept inline in SQLite.
pub const INLINE_THRESHOLD: usize = 512 * 1024;

/// Absolute upper bound on captured body size. Bytes beyond this are
/// forwarded to the peer but not recorded, and the exchange gains a
/// `body-truncated` tag so the UI can show the caveat.
pub const HARD_CAP: usize = 32 * 1024 * 1024;

/// Which side of the exchange a blob belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    Request,
    Response,
}

impl BodyKind {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Request => "req",
            Self::Response => "res",
        }
    }
}

/// Root-relative blob-file locator. Handles the on-disk layout and
/// cleans up after itself when the DB is wiped.
#[derive(Debug, Clone)]
pub struct BodyStore {
    root: PathBuf,
}

impl BodyStore {
    /// Build a store rooted at `root`. The directory is created on
    /// demand at write time — instantiating is cheap.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn session_dir(&self, session: &SessionId) -> PathBuf {
        self.root.join(session.to_string())
    }

    /// Canonical path for a given exchange + side. Does not touch the
    /// filesystem — use [`BodyStore::write`] to actually persist.
    pub fn path_for(
        &self,
        session: &SessionId,
        exchange: &ExchangeId,
        kind: BodyKind,
    ) -> PathBuf {
        self.session_dir(session)
            .join(format!("{}.{}", exchange, kind.extension()))
    }

    /// Write the bytes to disk and return the absolute path. Creates
    /// intermediate directories as needed. Caller is responsible for
    /// having already decided the bytes should spill (length >
    /// [`INLINE_THRESHOLD`]).
    pub fn write(
        &self,
        session: &SessionId,
        exchange: &ExchangeId,
        kind: BodyKind,
        bytes: &[u8],
    ) -> std::io::Result<PathBuf> {
        let dir = self.session_dir(session);
        std::fs::create_dir_all(&dir)?;
        let path = self.path_for(session, exchange, kind);
        std::fs::write(&path, bytes)?;
        Ok(path)
    }

    /// Read a spilled body back. Returns `Ok(None)` if the file is
    /// missing — SQLite rows can outlive their blobs if a session's
    /// directory is manually deleted.
    pub fn read(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_roundtrips() {
        let tmp = std::env::temp_dir().join(format!(
            "corvex-body-store-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let store = BodyStore::new(&tmp);
        let session = SessionId::new();
        let exchange = ExchangeId::new();
        let payload = vec![0xABu8; 1024];
        let path = store
            .write(&session, &exchange, BodyKind::Response, &payload)
            .unwrap();
        let back = BodyStore::read(&path).unwrap().unwrap();
        assert_eq!(back, payload);
        assert_eq!(
            path,
            store.path_for(&session, &exchange, BodyKind::Response)
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn read_missing_returns_none() {
        let tmp = std::env::temp_dir().join(format!(
            "corvex-body-store-missing-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let store = BodyStore::new(&tmp);
        let session = SessionId::new();
        let exchange = ExchangeId::new();
        let path = store.path_for(&session, &exchange, BodyKind::Request);
        let read = BodyStore::read(&path).unwrap();
        assert!(read.is_none());
    }
}
