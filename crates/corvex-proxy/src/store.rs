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

use crate::exchange::{
    Exchange, ExchangeId, ExchangeSummary, ScopeDecision, SessionId,
};

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

CREATE INDEX IF NOT EXISTS idx_exchanges_session_started ON exchanges(session_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_exchanges_host_path       ON exchanges(host, path);
CREATE INDEX IF NOT EXISTS idx_exchanges_status          ON exchanges(status) WHERE status IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_findings_exchange         ON exchange_scan_findings(exchange_id);
CREATE INDEX IF NOT EXISTS idx_findings_run              ON exchange_scan_findings(scan_run_id);
"#;

/// SQLite-backed proxy store. Holds a single connection behind a mutex;
/// every query takes the lock briefly. A batched writer task (landing
/// in a follow-up) will replace the per-insert lock for the high-volume
/// exchanges table.
pub struct ProxyDb {
    conn: Mutex<Connection>,
}

impl ProxyDb {
    pub fn open<P: AsRef<Path>>(path: P) -> SqlResult<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\n\
             PRAGMA synchronous=NORMAL;\n\
             PRAGMA foreign_keys=ON;",
        )?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
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

    /// Insert a fully-completed exchange. Used in the Phase 1 unbatched
    /// path; the batched writer task will replace this once the listener
    /// lands.
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
                ?13, ?14, NULL, ?15,
                ?16, ?17, NULL, ?18,
                ?19, ?20, ?21, ?22, ?23, ?24
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
                exchange.request.body.clone(),
                exchange.request.body.len() as i64,
                res_headers,
                exchange.response.as_ref().map(|r| r.body.clone()),
                exchange.response.as_ref().map(|r| r.body.len() as i64).unwrap_or(0),
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

    /// Load a single exchange by id — used by the detail pane. Bodies
    /// come back inline until the spill-to-file path is implemented.
    pub fn get_exchange_raw(&self, id: &ExchangeId) -> SqlResult<Option<StoredExchange>> {
        let conn = self.conn.lock().expect("proxy db mutex");
        let row = conn
            .query_row(
                "SELECT method, scheme, host, port, path, query, status,
                        req_headers, req_body_inline, res_headers, res_body_inline,
                        started_at, duration_ms
                   FROM exchanges
                  WHERE id = ?1",
                params![id.to_string()],
                |row| {
                    Ok(StoredExchange {
                        method: row.get(0)?,
                        scheme: row.get(1)?,
                        host: row.get(2)?,
                        port: row.get::<_, i64>(3)? as u16,
                        path: row.get(4)?,
                        query: row.get(5)?,
                        status: row.get::<_, Option<i64>>(6)?.map(|s| s as u16),
                        req_headers: row.get(7)?,
                        req_body: row.get(8)?,
                        res_headers: row.get(9)?,
                        res_body: row.get(10)?,
                        started_at: row.get(11)?,
                        duration_ms: row.get::<_, Option<i64>>(12)?.map(|d| d as u64),
                    })
                },
            )
            .optional()?;
        Ok(row)
    }
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
    pub res_headers: Option<Vec<u8>>,
    pub res_body: Option<Vec<u8>>,
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
