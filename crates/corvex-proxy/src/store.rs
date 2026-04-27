//! SQLite-backed persistence for proxy sessions, exchanges, scan runs,
//! and exchange findings.
//!
//! The proxy opens its own connection to the same `history.sqlite`
//! file the rest of the desktop app uses. WAL mode lets multiple
//! connections coexist: the existing `HistoryDb` handles scan history,
//! this `ProxyDb` handles the new proxy tables.
//!
//! The schema uses `CREATE TABLE IF NOT EXISTS` statements so existing
//! databases pick up the proxy tables automatically on first launch
//! after upgrade.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension, Result as SqlResult};
use time::OffsetDateTime;

use crate::body_store::{BodyKind, BodyStore, INLINE_THRESHOLD};
use crate::exchange::{
    Exchange, ExchangeId, ExchangeSummary, ScopeDecision, SessionId,
};
use crate::csrf::{CsrfRule, TokenInject, TokenSource};
use crate::intercept_rules::{InterceptRule, InterceptRules, PhaseFilter, RuleCondition, RuleKind};
use crate::scope::{ScopeRule, ScopeRules};
use crate::ws::{WsDirection, WsFrame};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS proxy_sessions (
    id          TEXT PRIMARY KEY,
    started_at  INTEGER NOT NULL,
    ended_at    INTEGER,
    listen_addr TEXT NOT NULL,
    note        TEXT
);

CREATE TABLE IF NOT EXISTS exchanges (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    origin_kind     TEXT NOT NULL,
    origin_parent   TEXT,
    method          TEXT NOT NULL,
    scheme          TEXT NOT NULL,
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL,
    path            TEXT NOT NULL,
    query           TEXT,
    status          INTEGER,
    mime            TEXT,
    req_headers     BLOB NOT NULL,
    req_body_inline BLOB,
    req_body_path   TEXT,
    req_body_size   INTEGER NOT NULL,
    res_headers     BLOB,
    res_body_inline BLOB,
    res_body_path   TEXT,
    res_body_size   INTEGER,
    started_at      INTEGER NOT NULL,
    duration_ms     INTEGER,
    scope           TEXT NOT NULL,
    intercepted     INTEGER NOT NULL DEFAULT 0,
    tags            TEXT,
    notes           TEXT,
    FOREIGN KEY (session_id) REFERENCES proxy_sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    started_at  INTEGER NOT NULL,
    ended_at    INTEGER,
    config      BLOB NOT NULL,
    status      TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES proxy_sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS exchange_scan_findings (
    id              TEXT PRIMARY KEY,
    scan_run_id     TEXT,
    exchange_id     TEXT NOT NULL,
    check_id        TEXT NOT NULL,
    severity        TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    evidence        BLOB,
    created_at      INTEGER NOT NULL,
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
    FOREIGN KEY (exchange_id) REFERENCES exchanges(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ws_frames (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    exchange_id     TEXT NOT NULL,
    sequence        INTEGER NOT NULL,
    direction       TEXT NOT NULL,
    opcode          INTEGER NOT NULL,
    fin             INTEGER NOT NULL,
    payload         BLOB NOT NULL,
    payload_size    INTEGER NOT NULL,
    captured_at     INTEGER NOT NULL,
    FOREIGN KEY (exchange_id) REFERENCES exchanges(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ws_frames_exchange ON ws_frames(exchange_id, sequence);

CREATE TABLE IF NOT EXISTS proxy_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS proxy_scope_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    host        TEXT NOT NULL,
    path_regex  TEXT,
    port        INTEGER,
    ordinal     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS proxy_csrf_rules (
    rule_id      TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 1,
    host_glob    TEXT,
    source_kind  TEXT NOT NULL,
    source_value TEXT NOT NULL,
    inject_kind  TEXT NOT NULL,
    inject_value TEXT NOT NULL,
    ordinal      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS proxy_intercept_rules (
    rule_id    TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,           -- 'include' | 'exclude'
    phase      TEXT NOT NULL,           -- 'request' | 'response' | 'both'
    enabled    INTEGER NOT NULL DEFAULT 1,
    -- Conditions stored as a JSON array of tagged-enum values; the
    -- rule shape is too irregular for a flat columns layout, and the
    -- JSON blob round-trips cleanly through the existing
    -- serde-tagged-enum encoding.
    conditions TEXT NOT NULL,
    ordinal    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exchanges_session_started ON exchanges(session_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_exchanges_host_path       ON exchanges(host, path);
CREATE INDEX IF NOT EXISTS idx_exchanges_status          ON exchanges(status) WHERE status IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_findings_exchange         ON exchange_scan_findings(exchange_id);
CREATE INDEX IF NOT EXISTS idx_findings_run              ON exchange_scan_findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_scope_rules_kind_ordinal  ON proxy_scope_rules(kind, ordinal);
"#;

/// SQLite-backed proxy store. Holds a single connection behind a mutex;
/// every query takes the lock briefly. A batched writer task (landing
/// in a follow-up) will replace the per-insert lock for the high-volume
/// exchanges table.
pub struct ProxyDb {
    conn: Mutex<Connection>,
    /// Blob directory sibling to the SQLite file — big bodies spill
    /// here rather than inflating the DB. Created on first write.
    body_store: BodyStore,
}

impl ProxyDb {
    pub fn open<P: AsRef<Path>>(path: P) -> SqlResult<Self> {
        let path_ref = path.as_ref();
        let blobs_root = path_ref
            .parent()
            .unwrap_or(Path::new("."))
            .join("proxy_blobs");
        let conn = Connection::open(path_ref)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\n\
             PRAGMA synchronous=NORMAL;\n\
             PRAGMA foreign_keys=ON;",
        )?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
            body_store: BodyStore::new(blobs_root),
        })
    }

    pub fn body_store(&self) -> &BodyStore {
        &self.body_store
    }

    /// Record a new proxy session. Called from [`ProxyState::start`].
    pub fn insert_session(
        &self,
        id: &SessionId,
        listen_addr: &str,
        note: Option<&str>,
    ) -> SqlResult<()> {
        let now = now_secs();
        let conn = self.conn.lock().expect("proxy db mutex");
        conn.execute(
            "INSERT INTO proxy_sessions (id, started_at, listen_addr, note) VALUES (?1, ?2, ?3, ?4)",
            params![id.to_string(), now, listen_addr, note],
        )?;
        Ok(())
    }

    pub fn finish_session(&self, id: &SessionId) -> SqlResult<()> {
        let now = now_secs();
        let conn = self.conn.lock().expect("proxy db mutex");
        conn.execute(
            "UPDATE proxy_sessions SET ended_at = ?1 WHERE id = ?2",
            params![now, id.to_string()],
        )?;
        Ok(())
    }

    /// Insert a fully-completed exchange. Bodies exceeding
    /// [`crate::body_store::INLINE_THRESHOLD`] are written to the
    /// sibling blob store and the DB row records the path instead of
    /// the bytes; smaller bodies stay inline. Spill failures are
    /// non-fatal — we fall back to inline storage and log a warning so
    /// the exchange still lands in the traffic log.
    pub fn insert_exchange(&self, exchange: &Exchange) -> SqlResult<()> {
        let summary = exchange.summary();
        let req_headers =
            bincode::serialize(&exchange.request.headers).map_err(sql_err)?;
        let res_headers = exchange
            .response
            .as_ref()
            .map(|r| bincode::serialize(&r.headers))
            .transpose()
            .map_err(sql_err)?;

        let (req_inline, req_path) = self.place_body(
            &exchange.session_id,
            &exchange.id,
            BodyKind::Request,
            &exchange.request.body,
        );
        let response_body_ref = exchange.response.as_ref().map(|r| &r.body);
        let (res_inline, res_path) = match response_body_ref {
            Some(body) => self.place_body(
                &exchange.session_id,
                &exchange.id,
                BodyKind::Response,
                body,
            ),
            None => (None, None),
        };
        let res_size = response_body_ref.map(|b| b.len() as i64).unwrap_or(0);

        let conn = self.conn.lock().expect("proxy db mutex");
        conn.execute(
            "INSERT OR REPLACE INTO exchanges (
                id, session_id, origin_kind, origin_parent,
                method, scheme, host, port, path, query, status, mime,
                req_headers, req_body_inline, req_body_path, req_body_size,
                res_headers, res_body_inline, res_body_path, res_body_size,
                started_at, duration_ms, scope, intercepted, tags, notes
             ) VALUES (
                ?1, ?2, ?3, ?4,
                ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16,
                ?17, ?18, ?19, ?20,
                ?21, ?22, ?23, ?24, ?25, ?26
             )",
            params![
                exchange.id.to_string(),
                exchange.session_id.to_string(),
                summary.origin_kind,
                exchange.origin.parent().map(|p| p.to_string()),
                exchange.request.method,
                summary.scheme,
                exchange.request.host,
                exchange.request.port as i64,
                summary.path,
                summary.query,
                summary.status.map(|s| s as i64),
                summary.mime,
                req_headers,
                req_inline,
                req_path,
                exchange.request.body.len() as i64,
                res_headers,
                res_inline,
                res_path,
                res_size,
                exchange.started_at.unix_timestamp(),
                exchange.duration_ms.map(|d| d as i64),
                scope_str(exchange.scope),
                exchange.intercepted.bits() as i64,
                if exchange.tags.is_empty() {
                    None
                } else {
                    Some(exchange.tags.join(","))
                },
                exchange.notes,
            ],
        )?;
        Ok(())
    }

    /// Decide how to store a body: inline bytes vs spilled path.
    /// Spill failures degrade gracefully to inline storage.
    fn place_body(
        &self,
        session: &SessionId,
        exchange: &ExchangeId,
        kind: BodyKind,
        body: &[u8],
    ) -> (Option<Vec<u8>>, Option<String>) {
        if body.len() <= INLINE_THRESHOLD {
            return (Some(body.to_vec()), None);
        }
        match self.body_store.write(session, exchange, kind, body) {
            Ok(path) => (None, Some(path.to_string_lossy().into_owned())),
            Err(e) => {
                tracing::warn!(
                    target: "proxy",
                    "body spill failed ({} bytes): {e} — storing inline",
                    body.len()
                );
                (Some(body.to_vec()), None)
            }
        }
    }

    /// Paginated list view used by the traffic log. Filters by session;
    /// a later revision will add host/method/status predicates.
    pub fn list_exchanges(
        &self,
        session: &SessionId,
        limit: usize,
        offset: usize,
    ) -> SqlResult<Vec<ExchangeSummary>> {
        let conn = self.conn.lock().expect("proxy db mutex");
        let mut stmt = conn.prepare(
            "SELECT id, session_id, origin_kind, method, scheme, host, port,
                    path, query, status, mime, req_body_size, res_body_size,
                    started_at, duration_ms, scope, intercepted, tags
               FROM exchanges
              WHERE session_id = ?1
              ORDER BY started_at DESC, id DESC
              LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(
            params![session.to_string(), limit as i64, offset as i64],
            |row| Ok(row_to_summary(row)),
        )?;
        let mut out = Vec::with_capacity(limit);
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// Load a single exchange by id — used by the detail pane. When a
    /// body was spilled to disk, the inline column is NULL and the
    /// bytes are read back from the blob file. Missing blob files are
    /// treated the same as missing bodies — a warning is logged and
    /// the caller sees an empty body rather than a failed query.
    pub fn get_exchange_raw(&self, id: &ExchangeId) -> SqlResult<Option<StoredExchange>> {
        let conn = self.conn.lock().expect("proxy db mutex");
        let row = conn
            .query_row(
                "SELECT method, scheme, host, port, path, query, status,
                        req_headers, req_body_inline, req_body_path, req_body_size,
                        res_headers, res_body_inline, res_body_path, res_body_size,
                        started_at, duration_ms
                   FROM exchanges
                  WHERE id = ?1",
                params![id.to_string()],
                |row| {
                    let req_body_inline: Option<Vec<u8>> = row.get(8)?;
                    let req_body_path: Option<String> = row.get(9)?;
                    let req_body_size: i64 = row.get(10)?;
                    let res_body_inline: Option<Vec<u8>> = row.get(12)?;
                    let res_body_path: Option<String> = row.get(13)?;
                    let res_body_size: Option<i64> = row.get(14)?;
                    Ok(StoredExchange {
                        method: row.get(0)?,
                        scheme: row.get(1)?,
                        host: row.get(2)?,
                        port: row.get::<_, i64>(3)? as u16,
                        path: row.get(4)?,
                        query: row.get(5)?,
                        status: row.get::<_, Option<i64>>(6)?.map(|s| s as u16),
                        req_headers: row.get(7)?,
                        req_body: resolve_body(req_body_inline, req_body_path.as_deref()),
                        req_body_size: req_body_size.max(0) as u64,
                        res_headers: row.get(11)?,
                        res_body: resolve_body(res_body_inline, res_body_path.as_deref()),
                        res_body_size: res_body_size.unwrap_or(0).max(0) as u64,
                        started_at: row.get(15)?,
                        duration_ms: row.get::<_, Option<i64>>(16)?.map(|d| d as u64),
                    })
                },
            )
            .optional()?;
        Ok(row)
    }
}

impl ProxyDb {
    /// Stream every exchange for `session` in insert order, oldest
    /// first, invoking `sink` with the hydrated [`StoredExchange`].
    /// Sink returning `Err(_)` aborts iteration and the error
    /// propagates back. Used by HAR export to avoid materialising the
    /// full session in memory.
    ///
    /// Iteration is done in one SQL pass + N spilled-blob reads; the
    /// DB mutex is released between rows so the listener keeps
    /// inserting while export runs.
    pub fn for_each_exchange<F>(
        &self,
        session: &SessionId,
        mut sink: F,
    ) -> SqlResult<()>
    where
        F: FnMut(ExchangeId, StoredExchange) -> SqlResult<()>,
    {
        // Collect IDs under the lock, then hydrate row-by-row via
        // `get_exchange_raw` so `sink` can run without blocking the
        // writer's mutex access. Trades one extra round-trip per row
        // for lower write contention — fine for export speeds.
        let ids: Vec<ExchangeId> = {
            let conn = self.conn.lock().expect("proxy db mutex");
            let mut stmt = conn.prepare(
                "SELECT id FROM exchanges
                  WHERE session_id = ?1
                  ORDER BY started_at ASC, id ASC",
            )?;
            let rows = stmt.query_map(params![session.to_string()], |row| {
                row.get::<_, String>(0)
            })?;
            let mut out = Vec::new();
            for r in rows {
                let s = r?;
                let id = uuid::Uuid::parse_str(&s).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
                out.push(ExchangeId(id));
            }
            out
        };

        for id in ids {
            if let Some(row) = self.get_exchange_raw(&id)? {
                sink(id, row)?;
            }
        }
        Ok(())
    }
}

fn resolve_body(inline: Option<Vec<u8>>, path: Option<&str>) -> Option<Vec<u8>> {
    if let Some(bytes) = inline {
        return Some(bytes);
    }
    let path = path?;
    match BodyStore::read(std::path::Path::new(path)) {
        Ok(opt) => opt,
        Err(e) => {
            tracing::warn!(target: "proxy", "body blob read at {path} failed: {e}");
            None
        }
    }
}

impl ProxyDb {
    /// Insert a finding row linked to an exchange. Scan-run linkage is
    /// optional — passive findings emitted on every exchange leave
    /// `scan_run_id` null; active-check runs supply their run id.
    pub fn insert_finding(&self, f: &StoredFinding) -> SqlResult<()> {
        let conn = self.conn.lock().expect("proxy db mutex");
        conn.execute(
            "INSERT OR REPLACE INTO exchange_scan_findings (
                id, scan_run_id, exchange_id, check_id, severity, title,
                description, evidence, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                f.id,
                f.scan_run_id,
                f.exchange_id,
                f.check_id,
                f.severity,
                f.title,
                f.description,
                f.evidence,
                f.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn findings_for_exchange(&self, id: &ExchangeId) -> SqlResult<Vec<StoredFinding>> {
        let conn = self.conn.lock().expect("proxy db mutex");
        let mut stmt = conn.prepare(
            "SELECT id, scan_run_id, exchange_id, check_id, severity, title,
                    description, evidence, created_at
               FROM exchange_scan_findings
              WHERE exchange_id = ?1
              ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![id.to_string()], |row| {
            Ok(StoredFinding {
                id: row.get(0)?,
                scan_run_id: row.get(1)?,
                exchange_id: row.get(2)?,
                check_id: row.get(3)?,
                severity: row.get(4)?,
                title: row.get(5)?,
                description: row.get(6)?,
                evidence: row.get(7)?,
                created_at: row.get(8)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn findings_for_session(
        &self,
        session: &SessionId,
        limit: usize,
    ) -> SqlResult<Vec<StoredFinding>> {
        let conn = self.conn.lock().expect("proxy db mutex");
        let mut stmt = conn.prepare(
            "SELECT f.id, f.scan_run_id, f.exchange_id, f.check_id, f.severity, f.title,
                    f.description, f.evidence, f.created_at
               FROM exchange_scan_findings f
               JOIN exchanges e ON e.id = f.exchange_id
              WHERE e.session_id = ?1
              ORDER BY f.created_at DESC
              LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            params![session.to_string(), limit as i64],
            |row| {
                Ok(StoredFinding {
                    id: row.get(0)?,
                    scan_run_id: row.get(1)?,
                    exchange_id: row.get(2)?,
                    check_id: row.get(3)?,
                    severity: row.get(4)?,
                    title: row.get(5)?,
                    description: row.get(6)?,
                    evidence: row.get(7)?,
                    created_at: row.get(8)?,
                })
            },
        )?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

impl ProxyDb {
    /// Fetch a proxy-wide setting by key. Returns `Ok(None)` when the
    /// key has never been written.
    pub fn get_setting(&self, key: &str) -> SqlResult<Option<String>> {
        let conn = self.conn.lock().expect("proxy db mutex");
        let row = conn
            .query_row(
                "SELECT value FROM proxy_settings WHERE key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(row)
    }

    /// Upsert a proxy-wide setting.
    pub fn set_setting(&self, key: &str, value: &str) -> SqlResult<()> {
        let conn = self.conn.lock().expect("proxy db mutex");
        conn.execute(
            "INSERT INTO proxy_settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Total exchanges captured for one session. Cheap — covered by
    /// the `(session_id, started_at)` composite index.
    pub fn count_exchanges_for_session(&self, session: &SessionId) -> SqlResult<i64> {
        let conn = self.conn.lock().expect("proxy db mutex");
        conn.query_row(
            "SELECT COUNT(1) FROM exchanges WHERE session_id = ?1",
            params![session.to_string()],
            |row| row.get(0),
        )
    }

    /// Drop everything past `keep` for `session`, oldest first. FK
    /// cascades take care of dependent findings / ws frames. Returns
    /// the number of rows deleted.
    ///
    /// `keep == 0` is treated as "unbounded" — nothing is deleted.
    pub fn evict_oldest_for_session(
        &self,
        session: &SessionId,
        keep: usize,
    ) -> SqlResult<usize> {
        if keep == 0 {
            return Ok(0);
        }
        let conn = self.conn.lock().expect("proxy db mutex");
        let n = conn.execute(
            "DELETE FROM exchanges
              WHERE session_id = ?1
                AND id NOT IN (
                    SELECT id FROM exchanges
                     WHERE session_id = ?1
                     ORDER BY started_at DESC, id DESC
                     LIMIT ?2
                )",
            params![session.to_string(), keep as i64],
        )?;
        // Also sweep any blob files the cascade couldn't catch — the
        // FK drops the DB row but the on-disk spill file lingers.
        // We don't know which blobs vanished inside this delete, so
        // best-effort GC the whole session directory for any files
        // whose row no longer exists. Cheap because spilled bodies
        // are rare.
        let _ = self.sweep_orphan_blobs(session);
        Ok(n)
    }

    /// Remove blob files whose owning exchange row no longer exists.
    /// Called after retention-driven deletes.
    fn sweep_orphan_blobs(&self, session: &SessionId) -> std::io::Result<()> {
        let dir = self.body_store.root().join(session.to_string());
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Ok(());
        };
        let conn = self.conn.lock().expect("proxy db mutex");
        let mut stmt = conn
            .prepare("SELECT 1 FROM exchanges WHERE id = ?1 LIMIT 1")
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(stem) = path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.to_string())
            else {
                continue;
            };
            let exists: Option<i64> = stmt
                .query_row(params![stem], |row| row.get(0))
                .optional()
                .unwrap_or(None);
            if exists.is_none() {
                let _ = std::fs::remove_file(&path);
            }
        }
        Ok(())
    }

    /// Load the persisted scope rules. Include and exclude rules are
    /// returned in their saved order; callers treat the vectors as
    /// append-only lists and rewrite the whole set via
    /// [`ProxyDb::save_scope_rules`].
    pub fn load_scope_rules(&self) -> SqlResult<ScopeRules> {
        let conn = self.conn.lock().expect("proxy db mutex");
        let mut stmt = conn.prepare(
            "SELECT kind, host, path_regex, port
               FROM proxy_scope_rules
              ORDER BY kind ASC, ordinal ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let kind: String = row.get(0)?;
            let host: String = row.get(1)?;
            let path_regex: Option<String> = row.get(2)?;
            let port: Option<i64> = row.get(3)?;
            Ok((
                kind,
                ScopeRule {
                    host,
                    path_regex,
                    port: port.map(|p| p as u16),
                },
            ))
        })?;
        let mut out = ScopeRules::default();
        for row in rows {
            let (kind, rule) = row?;
            match kind.as_str() {
                "include" => out.include.push(rule),
                "exclude" => out.exclude.push(rule),
                _ => {}
            }
        }
        Ok(out)
    }

    /// Replace every persisted scope rule with the supplied set. The
    /// writes happen in a single transaction so a partial rewrite can't
    /// land on disk.
    pub fn save_scope_rules(&self, rules: &ScopeRules) -> SqlResult<()> {
        let mut conn = self.conn.lock().expect("proxy db mutex");
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM proxy_scope_rules", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO proxy_scope_rules (kind, host, path_regex, port, ordinal)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for (i, rule) in rules.include.iter().enumerate() {
                stmt.execute(params![
                    "include",
                    rule.host,
                    rule.path_regex,
                    rule.port.map(|p| p as i64),
                    i as i64,
                ])?;
            }
            for (i, rule) in rules.exclude.iter().enumerate() {
                stmt.execute(params![
                    "exclude",
                    rule.host,
                    rule.path_regex,
                    rule.port.map(|p| p as i64),
                    i as i64,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Load every persisted CSRF rule, ordered by `ordinal` so the UI
    /// renders them in the order they were saved. Source / inject
    /// shapes are tagged-enum-encoded as `(kind, value)` columns —
    /// see [`encode_csrf_source`] / [`decode_csrf_source`].
    pub fn load_csrf_rules(&self) -> SqlResult<Vec<CsrfRule>> {
        let conn = self.conn.lock().expect("proxy db mutex");
        let mut stmt = conn.prepare(
            "SELECT rule_id, name, enabled, host_glob,
                    source_kind, source_value, inject_kind, inject_value
               FROM proxy_csrf_rules
              ORDER BY ordinal ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let rule_id: String = row.get(0)?;
            let name: String = row.get(1)?;
            let enabled: i64 = row.get(2)?;
            let host_glob: Option<String> = row.get(3)?;
            let source_kind: String = row.get(4)?;
            let source_value: String = row.get(5)?;
            let inject_kind: String = row.get(6)?;
            let inject_value: String = row.get(7)?;
            Ok(CsrfRule {
                id: rule_id,
                name,
                enabled: enabled != 0,
                host_glob,
                source: decode_csrf_source(&source_kind, &source_value),
                inject: decode_csrf_inject(&inject_kind, &inject_value),
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Replace every persisted CSRF rule. One transaction so a
    /// partial rewrite can't land on disk.
    pub fn save_csrf_rules(&self, rules: &[CsrfRule]) -> SqlResult<()> {
        let mut conn = self.conn.lock().expect("proxy db mutex");
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM proxy_csrf_rules", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO proxy_csrf_rules (rule_id, name, enabled, host_glob,
                    source_kind, source_value, inject_kind, inject_value, ordinal)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            for (i, rule) in rules.iter().enumerate() {
                let (sk, sv) = encode_csrf_source(&rule.source);
                let (ik, iv) = encode_csrf_inject(&rule.inject);
                stmt.execute(params![
                    rule.id,
                    rule.name,
                    if rule.enabled { 1_i64 } else { 0_i64 },
                    rule.host_glob,
                    sk,
                    sv,
                    ik,
                    iv,
                    i as i64,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}

fn encode_csrf_source(s: &TokenSource) -> (&'static str, String) {
    match s {
        TokenSource::HtmlInput { name_regex } => ("html_input", name_regex.clone()),
        TokenSource::MetaTag { name_regex } => ("meta_tag", name_regex.clone()),
        TokenSource::JsonPath { pointer } => ("json_path", pointer.clone()),
        TokenSource::SetCookie { name } => ("set_cookie", name.clone()),
        TokenSource::ResponseHeader { name } => ("response_header", name.clone()),
    }
}

fn decode_csrf_source(kind: &str, value: &str) -> TokenSource {
    match kind {
        "meta_tag" => TokenSource::MetaTag {
            name_regex: value.to_string(),
        },
        "json_path" => TokenSource::JsonPath {
            pointer: value.to_string(),
        },
        "set_cookie" => TokenSource::SetCookie {
            name: value.to_string(),
        },
        "response_header" => TokenSource::ResponseHeader {
            name: value.to_string(),
        },
        // Default to html_input — the most common shape, and a
        // forward-compatible fallback for any future kind we don't
        // recognise (the rule will be visible in the UI as broken
        // rather than being silently dropped).
        _ => TokenSource::HtmlInput {
            name_regex: value.to_string(),
        },
    }
}

fn encode_csrf_inject(s: &TokenInject) -> (&'static str, String) {
    match s {
        TokenInject::FormField { name } => ("form_field", name.clone()),
        TokenInject::JsonField { pointer } => ("json_field", pointer.clone()),
        TokenInject::Header { name } => ("header", name.clone()),
        TokenInject::Cookie { name } => ("cookie", name.clone()),
    }
}

fn decode_csrf_inject(kind: &str, value: &str) -> TokenInject {
    match kind {
        "json_field" => TokenInject::JsonField {
            pointer: value.to_string(),
        },
        "header" => TokenInject::Header {
            name: value.to_string(),
        },
        "cookie" => TokenInject::Cookie {
            name: value.to_string(),
        },
        _ => TokenInject::FormField {
            name: value.to_string(),
        },
    }
}

fn encode_rule_kind(k: RuleKind) -> &'static str {
    match k {
        RuleKind::Include => "include",
        RuleKind::Exclude => "exclude",
    }
}

fn decode_rule_kind(s: &str) -> RuleKind {
    match s {
        "exclude" => RuleKind::Exclude,
        _ => RuleKind::Include,
    }
}

fn encode_phase_filter(p: PhaseFilter) -> &'static str {
    match p {
        PhaseFilter::Request => "request",
        PhaseFilter::Response => "response",
        PhaseFilter::Both => "both",
    }
}

fn decode_phase_filter(s: &str) -> PhaseFilter {
    match s {
        "response" => PhaseFilter::Response,
        "both" => PhaseFilter::Both,
        _ => PhaseFilter::Request,
    }
}

impl ProxyDb {
    /// Load every persisted intercept rule, ordered by `ordinal` so
    /// the UI lists them in the order the user saved them.
    /// Conditions are JSON-decoded — corruption in the blob is
    /// logged and the rule is skipped (rather than failing the
    /// whole load and locking the user out of every other rule).
    pub fn load_intercept_rules(&self) -> SqlResult<InterceptRules> {
        let conn = self.conn.lock().expect("proxy db mutex");
        let mut stmt = conn.prepare(
            "SELECT rule_id, kind, phase, enabled, conditions
               FROM proxy_intercept_rules
              ORDER BY ordinal ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let rule_id: String = row.get(0)?;
            let kind: String = row.get(1)?;
            let phase: String = row.get(2)?;
            let enabled: i64 = row.get(3)?;
            let conditions_json: String = row.get(4)?;
            Ok((rule_id, kind, phase, enabled, conditions_json))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (rule_id, kind, phase, enabled, conditions_json) = row?;
            let conditions: Vec<RuleCondition> =
                match serde_json::from_str(&conditions_json) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(
                            target: "proxy",
                            "skipping intercept rule {rule_id}: bad conditions JSON ({e})"
                        );
                        continue;
                    }
                };
            out.push(InterceptRule {
                id: rule_id,
                kind: decode_rule_kind(&kind),
                phase: decode_phase_filter(&phase),
                enabled: enabled != 0,
                conditions,
            });
        }
        Ok(InterceptRules { rules: out })
    }

    /// Replace every persisted intercept rule. Single transaction so
    /// a partial rewrite can't land on disk.
    pub fn save_intercept_rules(&self, rules: &InterceptRules) -> SqlResult<()> {
        let mut conn = self.conn.lock().expect("proxy db mutex");
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM proxy_intercept_rules", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO proxy_intercept_rules
                    (rule_id, kind, phase, enabled, conditions, ordinal)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for (i, rule) in rules.rules.iter().enumerate() {
                let conditions_json =
                    serde_json::to_string(&rule.conditions).map_err(|e| {
                        rusqlite::Error::ToSqlConversionFailure(Box::new(e))
                    })?;
                stmt.execute(params![
                    rule.id,
                    encode_rule_kind(rule.kind),
                    encode_phase_filter(rule.phase),
                    if rule.enabled { 1_i64 } else { 0_i64 },
                    conditions_json,
                    i as i64,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Persist a captured WebSocket frame. Called from the splice loop
    /// — the `sequence` field is set per direction so frames stay
    /// ordered within each stream even if the two directions race.
    pub fn insert_ws_frame(&self, frame: &WsFrame) -> SqlResult<()> {
        let conn = self.conn.lock().expect("proxy db mutex");
        conn.execute(
            "INSERT INTO ws_frames (
                exchange_id, sequence, direction, opcode, fin,
                payload, payload_size, captured_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                frame.exchange_id.to_string(),
                frame.sequence as i64,
                frame.direction.as_str(),
                frame.opcode as i64,
                if frame.fin { 1i64 } else { 0 },
                frame.payload,
                frame.payload.len() as i64,
                frame.captured_at.unix_timestamp(),
            ],
        )?;
        Ok(())
    }

    /// Count the frames captured for one exchange. Used to decorate
    /// traffic-list rows without fetching payloads.
    pub fn ws_frame_count(&self, id: &ExchangeId) -> SqlResult<u64> {
        let conn = self.conn.lock().expect("proxy db mutex");
        let n: i64 = conn.query_row(
            "SELECT COUNT(1) FROM ws_frames WHERE exchange_id = ?1",
            params![id.to_string()],
            |row| row.get(0),
        )?;
        Ok(n.max(0) as u64)
    }

    /// Count the frames for every exchange listed in `ids`. Returns a
    /// map keyed by exchange id; exchanges with no frames are absent.
    pub fn ws_frame_counts(
        &self,
        ids: &[ExchangeId],
    ) -> SqlResult<std::collections::HashMap<ExchangeId, u64>> {
        let mut out = std::collections::HashMap::new();
        if ids.is_empty() {
            return Ok(out);
        }
        let conn = self.conn.lock().expect("proxy db mutex");
        let mut stmt = conn.prepare(
            "SELECT exchange_id, COUNT(1)
               FROM ws_frames
              WHERE exchange_id = ?1",
        )?;
        for id in ids {
            let row = stmt
                .query_row(params![id.to_string()], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                })
                .optional()?;
            if let Some((_, n)) = row {
                if n > 0 {
                    out.insert(*id, n as u64);
                }
            }
        }
        Ok(out)
    }

    /// Full frame list for one exchange. Payloads come back inline —
    /// the UI caps its decode to a preview prefix when rendering.
    pub fn list_ws_frames(&self, id: &ExchangeId) -> SqlResult<Vec<WsFrame>> {
        let conn = self.conn.lock().expect("proxy db mutex");
        let mut stmt = conn.prepare(
            "SELECT sequence, direction, opcode, fin, payload, captured_at
               FROM ws_frames
              WHERE exchange_id = ?1
              ORDER BY captured_at ASC, id ASC",
        )?;
        let rows = stmt.query_map(params![id.to_string()], |row| {
            let dir: String = row.get(1)?;
            let direction = match dir.as_str() {
                "server" => WsDirection::Server,
                _ => WsDirection::Client,
            };
            let opcode: i64 = row.get(2)?;
            let fin: i64 = row.get(3)?;
            let payload: Vec<u8> = row.get(4)?;
            let captured_at: i64 = row.get(5)?;
            Ok(WsFrame {
                exchange_id: *id,
                sequence: row.get::<_, i64>(0)? as u64,
                direction,
                opcode: opcode as u8,
                fin: fin != 0,
                payload,
                captured_at: OffsetDateTime::from_unix_timestamp(captured_at)
                    .unwrap_or(OffsetDateTime::UNIX_EPOCH),
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

/// Row shape for a persisted finding. Pure serde-ready primitives — the
/// desktop layer converts from `corvex-checks::Finding` into this
/// before hitting SQLite.
#[derive(Debug, Clone)]
pub struct StoredFinding {
    pub id: String,
    pub scan_run_id: Option<String>,
    pub exchange_id: String,
    pub check_id: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub evidence: Option<Vec<u8>>,
    pub created_at: i64,
}

/// Intermediate projection used by the detail command. Headers are
/// bincoded `IndexMap<String,String>` blobs — the desktop command layer
/// decodes them into a JSON-friendly shape before returning to the UI.
#[derive(Debug, Clone)]
pub struct StoredExchange {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: Option<String>,
    pub status: Option<u16>,
    pub req_headers: Vec<u8>,
    pub req_body: Option<Vec<u8>>,
    /// Original body size captured at insert time, even when the body
    /// was spilled or truncated.
    pub req_body_size: u64,
    pub res_headers: Option<Vec<u8>>,
    pub res_body: Option<Vec<u8>>,
    pub res_body_size: u64,
    pub started_at: i64,
    pub duration_ms: Option<u64>,
}

fn row_to_summary(row: &rusqlite::Row<'_>) -> SqlResult<ExchangeSummary> {
    let id_s: String = row.get(0)?;
    let session_s: String = row.get(1)?;
    let origin_kind: String = row.get(2)?;
    let method: String = row.get(3)?;
    let scheme: String = row.get(4)?;
    let host: String = row.get(5)?;
    let port: i64 = row.get(6)?;
    let path: String = row.get(7)?;
    let query: Option<String> = row.get(8)?;
    let status: Option<i64> = row.get(9)?;
    let mime: Option<String> = row.get(10)?;
    let size_request: i64 = row.get(11)?;
    let size_response: Option<i64> = row.get(12)?;
    let started_at_unix: i64 = row.get(13)?;
    let duration_ms: Option<i64> = row.get(14)?;
    let scope: String = row.get(15)?;
    let intercepted: i64 = row.get(16)?;
    let tags_csv: Option<String> = row.get(17)?;

    Ok(ExchangeSummary {
        id: parse_id(&id_s)?,
        session_id: parse_session(&session_s)?,
        origin_kind,
        method,
        scheme,
        host,
        port: port as u16,
        path,
        status: status.map(|s| s as u16),
        mime,
        size_request: size_request as u64,
        size_response: size_response.map(|s| s as u64).unwrap_or(0),
        started_at: OffsetDateTime::from_unix_timestamp(started_at_unix)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        duration_ms: duration_ms.map(|d| d as u64),
        scope: scope_from_str(&scope),
        intercepted: intercepted as u8,
        tags: tags_csv
            .map(|s| s.split(',').map(|p| p.to_string()).collect())
            .unwrap_or_default(),
        query,
    })
}

fn parse_id(s: &str) -> SqlResult<ExchangeId> {
    uuid::Uuid::parse_str(s)
        .map(ExchangeId)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))
}

fn parse_session(s: &str) -> SqlResult<SessionId> {
    uuid::Uuid::parse_str(s)
        .map(SessionId)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))
}

fn scope_str(decision: ScopeDecision) -> &'static str {
    decision.as_str()
}

fn scope_from_str(s: &str) -> ScopeDecision {
    match s {
        "in" => ScopeDecision::InScope,
        "excluded" => ScopeDecision::Excluded,
        _ => ScopeDecision::OutOfScope,
    }
}

fn sql_err(e: bincode::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(e))
}

fn now_secs() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body_store::INLINE_THRESHOLD;
    use crate::exchange::{Exchange, ExchangeOrigin, ScopeDecision};

    #[test]
    fn scope_rules_round_trip() {
        let path = std::env::temp_dir().join(format!(
            "corvex-proxy-scope-rt-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let db = ProxyDb::open(&path).expect("open");

        // Empty state returns defaults.
        let initial = db.load_scope_rules().expect("load empty");
        assert!(initial.include.is_empty());
        assert!(initial.exclude.is_empty());

        let rules = ScopeRules {
            include: vec![
                ScopeRule {
                    host: "*.example.com".into(),
                    path_regex: Some("^/api/".into()),
                    port: Some(443),
                },
                ScopeRule {
                    host: "staging.internal".into(),
                    path_regex: None,
                    port: None,
                },
            ],
            exclude: vec![ScopeRule {
                host: "telemetry.example.com".into(),
                path_regex: None,
                port: None,
            }],
        };
        db.save_scope_rules(&rules).expect("save");

        let reloaded = db.load_scope_rules().expect("load saved");
        assert_eq!(reloaded.include.len(), 2);
        assert_eq!(reloaded.exclude.len(), 1);
        assert_eq!(reloaded.include[0].host, "*.example.com");
        assert_eq!(reloaded.include[0].path_regex.as_deref(), Some("^/api/"));
        assert_eq!(reloaded.include[0].port, Some(443));
        assert_eq!(reloaded.exclude[0].host, "telemetry.example.com");

        // A second save overwrites (not appends).
        let replaced = ScopeRules {
            include: vec![ScopeRule {
                host: "only.example.com".into(),
                path_regex: None,
                port: None,
            }],
            exclude: vec![],
        };
        db.save_scope_rules(&replaced).expect("save 2");
        let after = db.load_scope_rules().expect("load 2");
        assert_eq!(after.include.len(), 1);
        assert!(after.exclude.is_empty());
        assert_eq!(after.include[0].host, "only.example.com");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn exchange_body_spills_when_over_inline_threshold() {
        // Put the DB inside a temp directory so the sibling
        // `proxy_blobs/` dir lands there too and we can clean up after.
        let tmp_dir = std::env::temp_dir().join(format!(
            "corvex-proxy-spill-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let db_path = tmp_dir.join("proxy.sqlite");
        let db = ProxyDb::open(&db_path).expect("open");

        // Session row is needed because exchanges.session_id FKs it.
        let session = SessionId::new();
        db.insert_session(&session, "127.0.0.1:0", None)
            .expect("session");

        let mut req = corvex_core::http::request::Request::new(
            "example.com",
            443,
            "POST",
            "/upload",
        );
        // Body right above the inline threshold forces a spill.
        req.body = vec![0x42u8; INLINE_THRESHOLD + 1024];

        let exchange = Exchange::new(
            session,
            ExchangeOrigin::Proxy {
                client_addr: "127.0.0.1:0".parse().unwrap(),
            },
            req,
            ScopeDecision::InScope,
        );
        let exchange_id = exchange.id;
        db.insert_exchange(&exchange).expect("insert");

        // DB row should have NULL inline + a populated blob path.
        {
            let conn = db.conn.lock().unwrap();
            let (inline_len, path): (Option<i64>, Option<String>) = conn
                .query_row(
                    "SELECT length(req_body_inline), req_body_path
                       FROM exchanges
                      WHERE id = ?1",
                    params![exchange_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert!(
                inline_len.is_none(),
                "inline column should be NULL for spilled bodies"
            );
            let path = path.expect("spilled rows must record the blob path");
            assert!(
                std::path::Path::new(&path).exists(),
                "blob file should exist at {path}"
            );
        }

        // Read path reassembles the body transparently.
        let stored = db.get_exchange_raw(&exchange_id).unwrap().unwrap();
        let back = stored.req_body.expect("req body");
        assert_eq!(back.len(), INLINE_THRESHOLD + 1024);
        assert_eq!(stored.req_body_size, back.len() as u64);

        // Clean up.
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn retention_evicts_oldest_and_preserves_newest() {
        use std::net::SocketAddr;
        let tmp_dir = std::env::temp_dir().join(format!(
            "corvex-proxy-retention-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let db = ProxyDb::open(tmp_dir.join("proxy.sqlite")).unwrap();

        let session = SessionId::new();
        db.insert_session(&session, "127.0.0.1:0", None).unwrap();

        // Insert 10 exchanges with increasing started_at so ordering is
        // deterministic.
        let mut ids = Vec::new();
        for i in 0..10u64 {
            let mut req = corvex_core::http::request::Request::new(
                "example.com",
                80,
                "GET",
                "/",
            );
            req.body = vec![];
            let mut ex = Exchange::new(
                session,
                ExchangeOrigin::Proxy {
                    client_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                },
                req,
                ScopeDecision::InScope,
            );
            // started_at is set in Exchange::new; nudge it forward so
            // ORDER BY started_at DESC can distinguish rows.
            ex.started_at = time::OffsetDateTime::from_unix_timestamp(
                1_700_000_000 + i as i64,
            )
            .unwrap();
            db.insert_exchange(&ex).unwrap();
            ids.push(ex.id);
        }

        assert_eq!(db.count_exchanges_for_session(&session).unwrap(), 10);
        let evicted = db.evict_oldest_for_session(&session, 3).unwrap();
        assert_eq!(evicted, 7);
        assert_eq!(db.count_exchanges_for_session(&session).unwrap(), 3);

        // The three newest rows survived — ids[7], ids[8], ids[9].
        let rows = db
            .list_exchanges(&session, 10, 0)
            .expect("list after evict");
        let surviving: std::collections::HashSet<_> =
            rows.iter().map(|r| r.id).collect();
        assert!(surviving.contains(&ids[7]));
        assert!(surviving.contains(&ids[8]));
        assert!(surviving.contains(&ids[9]));
        assert!(!surviving.contains(&ids[0]));

        // Passing keep=0 is the "unlimited" sentinel — no rows removed.
        let n = db.evict_oldest_for_session(&session, 0).unwrap();
        assert_eq!(n, 0);
        assert_eq!(db.count_exchanges_for_session(&session).unwrap(), 3);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn proxy_settings_round_trip() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "corvex-proxy-settings-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let db = ProxyDb::open(tmp_dir.join("proxy.sqlite")).unwrap();

        assert!(db.get_setting("missing").unwrap().is_none());
        db.set_setting("retention.max_exchanges_per_session", "2500")
            .unwrap();
        assert_eq!(
            db.get_setting("retention.max_exchanges_per_session").unwrap(),
            Some("2500".to_string())
        );
        // Upsert semantics — second write replaces, doesn't error.
        db.set_setting("retention.max_exchanges_per_session", "10000")
            .unwrap();
        assert_eq!(
            db.get_setting("retention.max_exchanges_per_session").unwrap(),
            Some("10000".to_string())
        );
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn exchange_body_stays_inline_when_small() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "corvex-proxy-inline-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let db = ProxyDb::open(tmp_dir.join("proxy.sqlite")).unwrap();
        let session = SessionId::new();
        db.insert_session(&session, "127.0.0.1:0", None).unwrap();

        let mut req = corvex_core::http::request::Request::new(
            "example.com",
            80,
            "GET",
            "/",
        );
        req.body = vec![0x01u8; 128];
        let exchange = Exchange::new(
            session,
            ExchangeOrigin::Proxy {
                client_addr: "127.0.0.1:0".parse().unwrap(),
            },
            req,
            ScopeDecision::InScope,
        );
        let id = exchange.id;
        db.insert_exchange(&exchange).unwrap();

        let conn = db.conn.lock().unwrap();
        let (inline_len, path): (Option<i64>, Option<String>) = conn
            .query_row(
                "SELECT length(req_body_inline), req_body_path
                   FROM exchanges
                  WHERE id = ?1",
                params![id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        drop(conn);
        assert_eq!(inline_len, Some(128));
        assert!(path.is_none());

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
