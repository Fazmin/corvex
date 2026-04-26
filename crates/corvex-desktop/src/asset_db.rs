//! Cross-table asset reads.
//!
//! The asset view aggregates data across four schemas that already live
//! in `history.sqlite` — proxy `exchanges`, `exchange_scan_findings`,
//! `recon_findings`, and the new `probe_open_ports`. Routing every query
//! through one of the per-feature stores would mean N round-trips
//! per panel and no way to express SQL joins across the schemas.
//!
//! `AssetDb` opens its own connection (WAL keeps the ring of writers
//! safe — proxy / history / recon / probe / asset all share the file)
//! and exposes read-only helpers tuned for the panels in
//! [`AssetDetailView`].

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEndpointRow {
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub method: String,
    pub path: String,
    pub last_status: Option<u16>,
    pub exchange_count: u32,
    pub finding_count: u32,
    pub last_seen_unix: i64,
    /// One representative exchange id — lets the UI deep-link a row to
    /// the proxy exchange detail without an extra round-trip.
    pub last_exchange_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetFindingRow {
    pub id: String,
    pub exchange_id: String,
    pub check_id: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub evidence_json: Option<String>,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub created_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetExchangeRef {
    pub id: String,
    pub method: String,
    pub scheme: String,
    pub port: u16,
    pub path: String,
    pub status: Option<u16>,
    pub started_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSummaryRow {
    pub host: String,
    pub finding_count: u32,
    pub exchange_count: u32,
    pub probe_port_count: u32,
    pub recon_hit_count: u32,
    pub scan_count: u32,
    pub last_seen_unix: i64,
}

pub struct AssetDb {
    conn: Mutex<Connection>,
}

impl AssetDb {
    pub fn open<P: AsRef<Path>>(path: P) -> SqlResult<Self> {
        let conn = Connection::open(path)?;
        // Read-mostly connection; share the same PRAGMAs the other
        // stores use so the WAL flag and cache size stay consistent.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\n\
             PRAGMA synchronous=NORMAL;\n\
             PRAGMA temp_store=MEMORY;\n\
             PRAGMA cache_size=-20000;\n\
             PRAGMA mmap_size=268435456;",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// All endpoints (path/method) ever seen for `host` across every
    /// proxy session, with exchange + finding counts and a
    /// representative `last_exchange_id` for deep-linking.
    pub fn endpoints_for_host(
        &self,
        host: &str,
        port: Option<u16>,
        limit: usize,
    ) -> SqlResult<Vec<AssetEndpointRow>> {
        let conn = self.conn.lock().expect("asset db mutex");
        // The subquery picks the latest exchange per (host, port,
        // method, path) tuple; the outer aggregation gives counts and
        // the latest status. We avoid CTEs so the prepared statement
        // can be cached across calls.
        let sql = if port.is_some() {
            "SELECT e.host, e.port, e.scheme, e.method, e.path,
                    (SELECT status FROM exchanges
                       WHERE host=e.host AND port=e.port AND method=e.method AND path=e.path
                       ORDER BY started_at DESC LIMIT 1) AS last_status,
                    COUNT(*) AS xc,
                    (SELECT COUNT(*) FROM exchange_scan_findings f
                       JOIN exchanges xe ON xe.id = f.exchange_id
                      WHERE xe.host=e.host AND xe.port=e.port
                        AND xe.method=e.method AND xe.path=e.path) AS fc,
                    MAX(e.started_at) AS last_seen,
                    (SELECT id FROM exchanges
                       WHERE host=e.host AND port=e.port AND method=e.method AND path=e.path
                       ORDER BY started_at DESC LIMIT 1) AS last_id
               FROM exchanges e
              WHERE e.host = ?1 AND e.port = ?2
              GROUP BY e.host, e.port, e.scheme, e.method, e.path
              ORDER BY xc DESC, last_seen DESC
              LIMIT ?3"
        } else {
            "SELECT e.host, e.port, e.scheme, e.method, e.path,
                    (SELECT status FROM exchanges
                       WHERE host=e.host AND port=e.port AND method=e.method AND path=e.path
                       ORDER BY started_at DESC LIMIT 1) AS last_status,
                    COUNT(*) AS xc,
                    (SELECT COUNT(*) FROM exchange_scan_findings f
                       JOIN exchanges xe ON xe.id = f.exchange_id
                      WHERE xe.host=e.host AND xe.port=e.port
                        AND xe.method=e.method AND xe.path=e.path) AS fc,
                    MAX(e.started_at) AS last_seen,
                    (SELECT id FROM exchanges
                       WHERE host=e.host AND port=e.port AND method=e.method AND path=e.path
                       ORDER BY started_at DESC LIMIT 1) AS last_id
               FROM exchanges e
              WHERE e.host = ?1
              GROUP BY e.host, e.port, e.scheme, e.method, e.path
              ORDER BY xc DESC, last_seen DESC
              LIMIT ?2"
        };
        let mut stmt = conn.prepare_cached(sql)?;
        let row_to = |row: &rusqlite::Row<'_>| {
            let status: Option<i64> = row.get(5)?;
            Ok(AssetEndpointRow {
                host: row.get(0)?,
                port: row.get::<_, i64>(1)? as u16,
                scheme: row.get(2)?,
                method: row.get(3)?,
                path: row.get(4)?,
                last_status: status.map(|s| s as u16),
                exchange_count: row.get::<_, i64>(6)? as u32,
                finding_count: row.get::<_, i64>(7)? as u32,
                last_seen_unix: row.get(8)?,
                last_exchange_id: row.get(9)?,
            })
        };
        let mut out = Vec::new();
        if let Some(p) = port {
            let rows = stmt.query_map(params![host, p as i64, limit as i64], row_to)?;
            for r in rows {
                out.push(r?);
            }
        } else {
            let rows = stmt.query_map(params![host, limit as i64], row_to)?;
            for r in rows {
                out.push(r?);
            }
        }
        Ok(out)
    }

    /// Findings for `host` from both finding sources:
    ///   * proxy/checks pipeline → `exchange_scan_findings` (joined
    ///     through `exchanges` on host)
    ///   * dashboard scan engine → `scan_findings` (host stored
    ///     directly on the row)
    /// Both are unioned, newest first. The dedup pass happens in the
    /// command layer so each query stays trivially indexable.
    pub fn findings_for_host(
        &self,
        host: &str,
        port: Option<u16>,
        limit: usize,
    ) -> SqlResult<Vec<AssetFindingRow>> {
        let conn = self.conn.lock().expect("asset db mutex");
        let mut out: Vec<AssetFindingRow> = Vec::new();

        // -- proxy / checks findings --
        {
            let sql = if port.is_some() {
                "SELECT f.id, f.exchange_id, f.check_id, f.severity, f.title,
                        f.description, f.evidence, e.host, e.port, e.path, f.created_at
                   FROM exchange_scan_findings f
                   JOIN exchanges e ON e.id = f.exchange_id
                  WHERE e.host = ?1 AND e.port = ?2
                  ORDER BY f.created_at DESC
                  LIMIT ?3"
            } else {
                "SELECT f.id, f.exchange_id, f.check_id, f.severity, f.title,
                        f.description, f.evidence, e.host, e.port, e.path, f.created_at
                   FROM exchange_scan_findings f
                   JOIN exchanges e ON e.id = f.exchange_id
                  WHERE e.host = ?1
                  ORDER BY f.created_at DESC
                  LIMIT ?2"
            };
            let mut stmt = conn.prepare_cached(sql)?;
            let row_to = |row: &rusqlite::Row<'_>| {
                let evidence: Option<Vec<u8>> = row.get(6)?;
                let evidence_json = evidence.and_then(|b| String::from_utf8(b).ok());
                Ok(AssetFindingRow {
                    id: row.get(0)?,
                    exchange_id: row.get(1)?,
                    check_id: row.get(2)?,
                    severity: row.get(3)?,
                    title: row.get(4)?,
                    description: row.get(5)?,
                    evidence_json,
                    host: row.get(7)?,
                    port: row.get::<_, i64>(8)? as u16,
                    path: row.get(9)?,
                    created_at_unix: row.get(10)?,
                })
            };
            if let Some(p) = port {
                let rows = stmt.query_map(params![host, p as i64, limit as i64], row_to)?;
                for r in rows {
                    out.push(r?);
                }
            } else {
                let rows = stmt.query_map(params![host, limit as i64], row_to)?;
                for r in rows {
                    out.push(r?);
                }
            }
        }

        // -- dashboard scan findings --
        {
            let sql = if port.is_some() {
                "SELECT id, plugin, severity, message, refs, host, port, uri,
                        created_at, corvex_id, cve, cvss, fix_version,
                        component, component_version
                   FROM scan_findings
                  WHERE host = ?1 AND (port = 0 OR port = ?2)
                  ORDER BY created_at DESC
                  LIMIT ?3"
            } else {
                "SELECT id, plugin, severity, message, refs, host, port, uri,
                        created_at, corvex_id, cve, cvss, fix_version,
                        component, component_version
                   FROM scan_findings
                  WHERE host = ?1
                  ORDER BY created_at DESC
                  LIMIT ?2"
            };
            let mut stmt = conn.prepare_cached(sql)?;
            let row_to = |row: &rusqlite::Row<'_>| {
                let id: i64 = row.get(0)?;
                let refs: Option<String> = row.get(4)?;
                let corvex_id: Option<String> = row.get(9)?;
                let cve: Option<String> = row.get(10)?;
                let cvss: Option<f64> = row.get(11)?;
                let fix_version: Option<String> = row.get(12)?;
                let component: Option<String> = row.get(13)?;
                let component_version: Option<String> = row.get(14)?;
                // Pack the scan-only metadata into the JSON evidence
                // blob so the UI's existing AssetFinding renderer can
                // surface CVE / CVSS / fix info without a separate
                // schema branch.
                let evidence = serde_json::json!({
                    "source": "dashboard_scan",
                    "corvex_id": corvex_id,
                    "cve": cve,
                    "cvss": cvss,
                    "fix_version": fix_version,
                    "component": component,
                    "component_version": component_version,
                });
                Ok(AssetFindingRow {
                    id: format!("scan-{id}"),
                    exchange_id: String::new(),
                    check_id: row.get::<_, String>(1)?,
                    severity: row.get::<_, String>(2)?,
                    title: row.get::<_, String>(3)?,
                    description: refs,
                    evidence_json: serde_json::to_string(&evidence).ok(),
                    host: row.get::<_, String>(5)?,
                    port: row.get::<_, i64>(6)? as u16,
                    path: row.get::<_, String>(7)?,
                    created_at_unix: row.get(8)?,
                })
            };
            if let Some(p) = port {
                let rows = stmt.query_map(params![host, p as i64, limit as i64], row_to)?;
                for r in rows {
                    out.push(r?);
                }
            } else {
                let rows = stmt.query_map(params![host, limit as i64], row_to)?;
                for r in rows {
                    out.push(r?);
                }
            }
        }

        out.sort_by(|a, b| b.created_at_unix.cmp(&a.created_at_unix));
        out.truncate(limit);
        Ok(out)
    }

    /// Most recent exchanges for a host — feeds the timeline panel.
    pub fn recent_exchanges_for_host(
        &self,
        host: &str,
        limit: usize,
    ) -> SqlResult<Vec<AssetExchangeRef>> {
        let conn = self.conn.lock().expect("asset db mutex");
        let mut stmt = conn.prepare_cached(
            "SELECT id, method, scheme, port, path, status, started_at
               FROM exchanges
              WHERE host = ?1
              ORDER BY started_at DESC
              LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![host, limit as i64], |row| {
            let status: Option<i64> = row.get(5)?;
            Ok(AssetExchangeRef {
                id: row.get(0)?,
                method: row.get(1)?,
                scheme: row.get(2)?,
                port: row.get::<_, i64>(3)? as u16,
                path: row.get(4)?,
                status: status.map(|s| s as u16),
                started_at_unix: row.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Distinct hosts seen across the proxy, probe and recon stores
    /// plus the dashboard scan history — drives the asset browser. The
    /// proxy/probe/recon counts come from one SQL pass; scan rows are
    /// merged in Rust because `scans.host` may be a full URL or a
    /// host:port that needs URL-aware extraction.
    ///
    /// `query` is matched as a `LIKE %query%` against the host name;
    /// pass an empty string for "all".
    pub fn list_assets(
        &self,
        query: &str,
        limit: usize,
    ) -> SqlResult<Vec<AssetSummaryRow>> {
        use crate::asset_identity::extract_host_from_scan_target;
        use std::collections::BTreeMap;

        let conn = self.conn.lock().expect("asset db mutex");
        let mut by_host: BTreeMap<String, AssetSummaryRow> = BTreeMap::new();

        // First pass: union over the three SQL-native sources. We
        // intentionally don't `LIMIT` here — the scan-host merge below
        // could push a previously-trimmed host above the cutoff once
        // its scan count is added in.
        {
            let mut stmt = conn.prepare_cached(
                "WITH hosts AS (
                    SELECT DISTINCT host FROM exchanges
                    UNION
                    SELECT DISTINCT host FROM probe_open_ports
                    UNION
                    SELECT DISTINCT lower(name) FROM recon_findings WHERE kind = 'subdomain'
                    UNION
                    SELECT DISTINCT host FROM scan_findings
                 )
                 SELECT host,
                        ((SELECT COUNT(*) FROM exchange_scan_findings f
                           JOIN exchanges e ON e.id = f.exchange_id
                          WHERE e.host = hosts.host)
                         + (SELECT COUNT(*) FROM scan_findings WHERE host = hosts.host)) AS fc,
                        (SELECT COUNT(*) FROM exchanges e WHERE e.host = hosts.host) AS xc,
                        (SELECT COUNT(*) FROM probe_open_ports p WHERE p.host = hosts.host) AS pc,
                        (SELECT COUNT(*) FROM recon_findings r
                          WHERE lower(r.name) = hosts.host) AS rc,
                        COALESCE(
                           (SELECT MAX(started_at) FROM exchanges WHERE host = hosts.host),
                           (SELECT MAX(observed_at) FROM probe_open_ports WHERE host = hosts.host),
                           (SELECT MAX(discovered_at) FROM recon_findings
                             WHERE lower(name) = hosts.host),
                           (SELECT MAX(created_at) FROM scan_findings WHERE host = hosts.host),
                           0
                        ) AS last_seen
                   FROM hosts
                  WHERE host != ''",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(AssetSummaryRow {
                    host: row.get(0)?,
                    finding_count: row.get::<_, i64>(1)? as u32,
                    exchange_count: row.get::<_, i64>(2)? as u32,
                    probe_port_count: row.get::<_, i64>(3)? as u32,
                    recon_hit_count: row.get::<_, i64>(4)? as u32,
                    scan_count: 0,
                    last_seen_unix: row.get(5)?,
                })
            })?;
            for r in rows {
                let row = r?;
                by_host.insert(row.host.clone(), row);
            }
        }

        // Second pass: scan history. `scans.host` is the raw user input
        // (URL, host:port, bare host) — extract the hostname so the
        // joiner matches probe/proxy/recon rows.
        {
            let mut stmt =
                conn.prepare_cached("SELECT host, started_at FROM scans")?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                ))
            })?;
            for r in rows {
                let (raw_host, started_at) = r?;
                let host = extract_host_from_scan_target(&raw_host);
                if host.is_empty() {
                    continue;
                }
                let entry = by_host.entry(host.clone()).or_insert_with(|| {
                    AssetSummaryRow {
                        host: host.clone(),
                        finding_count: 0,
                        exchange_count: 0,
                        probe_port_count: 0,
                        recon_hit_count: 0,
                        scan_count: 0,
                        last_seen_unix: 0,
                    }
                });
                entry.scan_count += 1;
                if started_at > entry.last_seen_unix {
                    entry.last_seen_unix = started_at;
                }
            }
        }

        // Apply the LIKE filter, sort by last_seen DESC, host ASC,
        // truncate to the caller's limit.
        let q = query.to_lowercase();
        let mut out: Vec<AssetSummaryRow> = by_host
            .into_values()
            .filter(|r| q.is_empty() || r.host.contains(&q))
            .collect();
        out.sort_by(|a, b| {
            b.last_seen_unix
                .cmp(&a.last_seen_unix)
                .then_with(|| a.host.cmp(&b.host))
        });
        out.truncate(limit);
        Ok(out)
    }

    /// Single-row counts for `host`. Same projection as `list_assets`
    /// but with an equality match — used by `asset_overview` so the
    /// caller doesn't have to scan a LIKE result set. Scan-history
    /// joining is done in Rust because `scans.host` may be a URL or
    /// host:port that needs URL-aware extraction.
    pub fn summary_for_host(&self, host: &str) -> SqlResult<AssetSummaryRow> {
        use crate::asset_identity::extract_host_from_scan_target;

        let conn = self.conn.lock().expect("asset db mutex");
        let mut row = {
            let mut stmt = conn.prepare_cached(
                "SELECT ((SELECT COUNT(*) FROM exchange_scan_findings f
                           JOIN exchanges e ON e.id = f.exchange_id
                          WHERE e.host = ?1)
                         + (SELECT COUNT(*) FROM scan_findings WHERE host = ?1)) AS fc,
                        (SELECT COUNT(*) FROM exchanges WHERE host = ?1) AS xc,
                        (SELECT COUNT(*) FROM probe_open_ports WHERE host = ?1) AS pc,
                        (SELECT COUNT(*) FROM recon_findings
                          WHERE lower(name) = ?1) AS rc,
                        COALESCE(
                           (SELECT MAX(started_at)  FROM exchanges       WHERE host = ?1),
                           (SELECT MAX(observed_at) FROM probe_open_ports WHERE host = ?1),
                           (SELECT MAX(discovered_at) FROM recon_findings
                             WHERE lower(name) = ?1),
                           (SELECT MAX(created_at)  FROM scan_findings    WHERE host = ?1),
                           0
                        ) AS last_seen",
            )?;
            stmt.query_row(params![host], |row| {
                Ok(AssetSummaryRow {
                    host: host.to_string(),
                    finding_count: row.get::<_, i64>(0)? as u32,
                    exchange_count: row.get::<_, i64>(1)? as u32,
                    probe_port_count: row.get::<_, i64>(2)? as u32,
                    recon_hit_count: row.get::<_, i64>(3)? as u32,
                    scan_count: 0,
                    last_seen_unix: row.get(4)?,
                })
            })?
        };

        let mut stmt =
            conn.prepare_cached("SELECT host, started_at FROM scans")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?;
        for r in rows {
            let (raw_host, started_at) = r?;
            if extract_host_from_scan_target(&raw_host) == host {
                row.scan_count += 1;
                if started_at > row.last_seen_unix {
                    row.last_seen_unix = started_at;
                }
            }
        }
        Ok(row)
    }

    /// IPs recorded for this host in `recon_findings.value` (CSV) and
    /// recent probe rows. Returns deduped, lower-cased IP strings.
    pub fn ips_for_host(&self, host: &str) -> SqlResult<Vec<String>> {
        let conn = self.conn.lock().expect("asset db mutex");
        let mut out = std::collections::BTreeSet::<String>::new();
        // From recon — value is a CSV of IPs for subdomain rows.
        {
            let mut stmt = conn.prepare_cached(
                "SELECT value FROM recon_findings
                  WHERE kind='subdomain' AND lower(name) = lower(?1)
                    AND value IS NOT NULL",
            )?;
            let rows = stmt.query_map(params![host], |row| row.get::<_, String>(0))?;
            for r in rows {
                let v = r?;
                for piece in v.split(',') {
                    let p = piece.trim();
                    if !p.is_empty() {
                        out.insert(p.to_string());
                    }
                }
            }
        }
        // From probe — direct ip column.
        {
            let mut stmt = conn.prepare_cached(
                "SELECT DISTINCT ip FROM probe_open_ports
                  WHERE host = ?1 AND ip IS NOT NULL",
            )?;
            let rows = stmt.query_map(params![host], |row| row.get::<_, String>(0))?;
            for r in rows {
                out.insert(r?);
            }
        }
        Ok(out.into_iter().collect())
    }

    /// Recon DNS records (A/AAAA/CNAME/MX/NS/TXT/etc.) tied to `host`.
    /// Returned as `(record_type, value, sources_csv)` triples.
    pub fn dns_records_for_host(
        &self,
        host: &str,
    ) -> SqlResult<Vec<(String, String, String)>> {
        let conn = self.conn.lock().expect("asset db mutex");
        let mut stmt = conn.prepare_cached(
            "SELECT COALESCE(record_type, ''), COALESCE(value, ''), COALESCE(sources, '')
               FROM recon_findings
              WHERE kind = 'record' AND lower(name) = lower(?1)
              ORDER BY discovered_at DESC",
        )?;
        let rows = stmt.query_map(params![host], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Recon-discovered sibling subdomains — every subdomain whose
    /// registrable suffix matches `suffix`. Caller pre-computes the
    /// suffix using [`crate::asset_identity::registrable_suffix`].
    pub fn siblings_under_suffix(
        &self,
        suffix: &str,
        limit: usize,
    ) -> SqlResult<Vec<String>> {
        let conn = self.conn.lock().expect("asset db mutex");
        let mut stmt = conn.prepare_cached(
            "SELECT DISTINCT lower(name)
               FROM recon_findings
              WHERE kind = 'subdomain'
                AND (lower(name) = ?1 OR lower(name) LIKE '%.' || ?1)
              ORDER BY lower(name)
              LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![suffix, limit as i64], |row| {
            row.get::<_, String>(0)
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Hosts whose recorded IP falls into the same `/24` as any of
    /// `cidrs`. Used to surface "neighbor" hosts in the related-assets
    /// panel as a coarse stand-in for ASN clustering.
    pub fn hosts_in_cidrs(&self, cidrs: &[String]) -> SqlResult<Vec<String>> {
        if cidrs.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock().expect("asset db mutex");
        // Build host candidates from probe rows + recon CSVs. The
        // CIDR check is done in Rust because SQLite doesn't speak CIDR
        // and the candidate set is small.
        let mut candidates = std::collections::BTreeMap::<String, Vec<String>>::new();
        {
            let mut stmt = conn.prepare_cached(
                "SELECT host, ip FROM probe_open_ports WHERE ip IS NOT NULL",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for r in rows {
                let (h, ip) = r?;
                candidates.entry(h).or_default().push(ip);
            }
        }
        {
            let mut stmt = conn.prepare_cached(
                "SELECT lower(name), value
                   FROM recon_findings
                  WHERE kind='subdomain' AND value IS NOT NULL",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for r in rows {
                let (h, csv) = r?;
                let entry = candidates.entry(h).or_default();
                for piece in csv.split(',') {
                    let p = piece.trim();
                    if !p.is_empty() {
                        entry.push(p.to_string());
                    }
                }
            }
        }
        // CIDRs come in as "a.b.c.0/24"; collapse to first three octets
        // for the membership check.
        let prefixes: Vec<[u8; 3]> = cidrs
            .iter()
            .filter_map(|c| {
                let base = c.split('/').next()?;
                let v4: std::net::Ipv4Addr = base.parse().ok()?;
                let o = v4.octets();
                Some([o[0], o[1], o[2]])
            })
            .collect();

        let mut out = Vec::new();
        for (host, ips) in candidates {
            for ip in ips {
                if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
                    let o = v4.octets();
                    if prefixes.iter().any(|p| p[0] == o[0] && p[1] == o[1] && p[2] == o[2]) {
                        out.push(host.clone());
                        break;
                    }
                }
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }
}
