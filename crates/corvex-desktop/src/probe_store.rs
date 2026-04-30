//! SQLite persistence for probe runs + open ports.
//!
//! Opens its own connection to the same `history.sqlite` file the rest
//! of the app uses (WAL + foreign_keys ON, same as ReconDb). Probes are
//! cheap and frequent — keeping them in the shared DB lets the asset
//! view join probe data with proxy exchanges and recon findings without
//! crossing process boundaries.
//!
//! One row per host+port observation. The same host probed twice (e.g.
//! Rapid then Deep) writes a fresh row each time so the asset view can
//! show "first seen / last seen" by aggregating `observed_at`.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS probe_runs (
    id          TEXT PRIMARY KEY,
    started_at  INTEGER NOT NULL,
    ended_at    INTEGER,
    status      TEXT NOT NULL DEFAULT 'running',
    targets     TEXT
);

CREATE TABLE IF NOT EXISTS probe_open_ports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_run_id    TEXT NOT NULL,
    host            TEXT NOT NULL,
    ip              TEXT,
    port            INTEGER NOT NULL,
    over_tls        INTEGER NOT NULL DEFAULT 0,
    service         TEXT,
    product         TEXT,
    vendor          TEXT,
    version         TEXT,
    info            TEXT,
    cpe_json        TEXT,
    jarm            TEXT,
    banner          TEXT,
    observed_at     INTEGER NOT NULL,
    FOREIGN KEY (probe_run_id) REFERENCES probe_runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_probe_open_host ON probe_open_ports(host);
CREATE INDEX IF NOT EXISTS idx_probe_open_jarm ON probe_open_ports(jarm) WHERE jarm IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_probe_open_run  ON probe_open_ports(probe_run_id);

CREATE TABLE IF NOT EXISTS probe_device_match (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_run_id  TEXT NOT NULL,
    host          TEXT NOT NULL,
    ip            TEXT,
    os            TEXT NOT NULL,
    vendor        TEXT NOT NULL,
    device_type   TEXT NOT NULL,
    source        TEXT NOT NULL,
    sys_descr     TEXT,
    sys_object_id TEXT,
    observed_at   INTEGER NOT NULL,
    FOREIGN KEY (probe_run_id) REFERENCES probe_runs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_probe_dev_host ON probe_device_match(host);
CREATE INDEX IF NOT EXISTS idx_probe_dev_run  ON probe_device_match(probe_run_id);

CREATE TABLE IF NOT EXISTS probe_host_mac (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_run_id  TEXT NOT NULL,
    host          TEXT NOT NULL,
    ip            TEXT,
    mac           TEXT NOT NULL,
    mac_vendor    TEXT,
    observed_at   INTEGER NOT NULL,
    FOREIGN KEY (probe_run_id) REFERENCES probe_runs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_probe_host_mac_host ON probe_host_mac(host);
CREATE INDEX IF NOT EXISTS idx_probe_host_mac_run  ON probe_host_mac(probe_run_id);
"#;

/// One open-port observation handed to [`ProbeStore::insert_open_ports`].
/// The fields mirror the `ProbeOpenPort` event payload the UI already
/// consumes — we persist exactly what the user sees.
#[derive(Debug, Clone)]
pub struct PendingOpenPort {
    pub host: String,
    pub ip: Option<String>,
    pub port: u16,
    pub over_tls: bool,
    pub service: Option<String>,
    pub product: Option<String>,
    pub vendor: Option<String>,
    pub version: Option<String>,
    pub info: Option<String>,
    pub cpe: Vec<String>,
    pub jarm: Option<String>,
    pub banner: String,
}

/// One device-match observation, written once per host per probe run
/// when SNMP fingerprinting fired and the matcher returned a hit.
#[derive(Debug, Clone)]
pub struct PendingDeviceMatch {
    pub host: String,
    pub ip: Option<String>,
    pub os: String,
    pub vendor: String,
    pub device_type: String,
    pub source: String,
    pub sys_descr: Option<String>,
    pub sys_object_id: Option<String>,
}

/// One MAC-resolution observation. Captured after the TCP scan
/// completes, so it only carries useful data for L2-adjacent hosts.
#[derive(Debug, Clone)]
pub struct PendingHostMac {
    pub host: String,
    pub ip: Option<String>,
    /// Lower-case colon-separated MAC.
    pub mac: String,
    /// OUI vendor name resolved against the bundled `ieee_oui` table.
    pub mac_vendor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostMacRow {
    pub host: String,
    pub ip: Option<String>,
    pub mac: String,
    pub mac_vendor: Option<String>,
    pub observed_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceMatchRow {
    pub host: String,
    pub ip: Option<String>,
    pub os: String,
    pub vendor: String,
    pub device_type: String,
    pub source: String,
    pub sys_descr: Option<String>,
    pub sys_object_id: Option<String>,
    pub observed_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeServiceRow {
    pub host: String,
    pub ip: Option<String>,
    pub port: u16,
    pub over_tls: bool,
    pub service: Option<String>,
    pub product: Option<String>,
    pub vendor: Option<String>,
    pub version: Option<String>,
    pub info: Option<String>,
    pub cpe: Vec<String>,
    pub jarm: Option<String>,
    pub banner: String,
    pub first_seen_unix: i64,
    pub last_seen_unix: i64,
    pub observation_count: u32,
}

pub struct ProbeStore {
    conn: Mutex<Connection>,
}

impl ProbeStore {
    pub fn open<P: AsRef<Path>>(path: P) -> SqlResult<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\n\
             PRAGMA synchronous=NORMAL;\n\
             PRAGMA foreign_keys=ON;\n\
             PRAGMA temp_store=MEMORY;\n\
             PRAGMA cache_size=-20000;\n\
             PRAGMA mmap_size=268435456;",
        )?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn insert_run(&self, id: &Uuid, targets: &[String]) -> SqlResult<()> {
        let conn = self.conn.lock().expect("probe db mutex");
        conn.execute(
            "INSERT INTO probe_runs (id, started_at, status, targets)
             VALUES (?1, ?2, 'running', ?3)",
            params![
                id.to_string(),
                now_secs(),
                if targets.is_empty() {
                    None
                } else {
                    Some(targets.join(","))
                },
            ],
        )?;
        Ok(())
    }

    pub fn finish_run(&self, id: &Uuid, status: &str) -> SqlResult<()> {
        let conn = self.conn.lock().expect("probe db mutex");
        conn.execute(
            "UPDATE probe_runs SET ended_at = ?1, status = ?2 WHERE id = ?3",
            params![now_secs(), status, id.to_string()],
        )?;
        Ok(())
    }

    /// Bulk-insert one host's open ports in a single transaction. The
    /// probe pipeline emits one `open-port` IPC event per host with the
    /// full port list; folding the inserts into the same transaction
    /// matches that batching.
    pub fn insert_open_ports(
        &self,
        run_id: &Uuid,
        rows: &[PendingOpenPort],
    ) -> SqlResult<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().expect("probe db mutex");
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO probe_open_ports
                    (probe_run_id, host, ip, port, over_tls, service,
                     product, vendor, version, info, cpe_json, jarm,
                     banner, observed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                         ?12, ?13, ?14)",
            )?;
            let now = now_secs();
            let run_s = run_id.to_string();
            for r in rows {
                let cpe_json = if r.cpe.is_empty() {
                    None
                } else {
                    serde_json::to_string(&r.cpe).ok()
                };
                stmt.execute(params![
                    run_s,
                    r.host,
                    r.ip,
                    r.port as i64,
                    if r.over_tls { 1i64 } else { 0 },
                    r.service,
                    r.product,
                    r.vendor,
                    r.version,
                    r.info,
                    cpe_json,
                    r.jarm,
                    r.banner,
                    now,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Latest known service rows for a host, deduped by (port, service,
    /// product, version) — the asset Services panel wants one line per
    /// distinct observation, not one per probe run.
    pub fn services_for_host(&self, host: &str) -> SqlResult<Vec<ProbeServiceRow>> {
        let conn = self.conn.lock().expect("probe db mutex");
        let mut stmt = conn.prepare_cached(
            "SELECT host, ip, port, over_tls, service, product, vendor,
                    version, info, cpe_json, jarm, banner,
                    MIN(observed_at) AS first_seen,
                    MAX(observed_at) AS last_seen,
                    COUNT(*)         AS obs_count
               FROM probe_open_ports
              WHERE host = ?1
              GROUP BY port, COALESCE(service,''), COALESCE(product,''),
                       COALESCE(version,''), COALESCE(jarm,'')
              ORDER BY port ASC",
        )?;
        let rows = stmt.query_map(params![host], |row| {
            let cpe_json: Option<String> = row.get(9)?;
            let cpe = cpe_json
                .as_deref()
                .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
                .unwrap_or_default();
            let over_tls: i64 = row.get(3)?;
            Ok(ProbeServiceRow {
                host: row.get(0)?,
                ip: row.get(1)?,
                port: row.get::<_, i64>(2)? as u16,
                over_tls: over_tls != 0,
                service: row.get(4)?,
                product: row.get(5)?,
                vendor: row.get(6)?,
                version: row.get(7)?,
                info: row.get(8)?,
                cpe,
                jarm: row.get(10)?,
                banner: row.get::<_, Option<String>>(11)?.unwrap_or_default(),
                first_seen_unix: row.get(12)?,
                last_seen_unix: row.get(13)?,
                observation_count: row.get::<_, i64>(14)? as u32,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Other hosts that share a JARM hash with `host`. Used by the
    /// related-assets panel — same JARM strongly implies the same TLS
    /// stack and often the same operator.
    pub fn hosts_sharing_jarm(&self, host: &str) -> SqlResult<Vec<(String, String)>> {
        let conn = self.conn.lock().expect("probe db mutex");
        let mut stmt = conn.prepare_cached(
            "SELECT DISTINCT other.host, other.jarm
               FROM probe_open_ports me
               JOIN probe_open_ports other
                 ON me.jarm = other.jarm
                AND other.host <> me.host
              WHERE me.host = ?1
                AND me.jarm IS NOT NULL
              ORDER BY other.host ASC",
        )?;
        let rows = stmt.query_map(params![host], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Insert one device-match row. Idempotent at the row level — we
    /// always insert a fresh row so the asset view can show a history
    /// (latest wins on read).
    pub fn insert_device_match(
        &self,
        run_id: &Uuid,
        m: &PendingDeviceMatch,
    ) -> SqlResult<()> {
        let conn = self.conn.lock().expect("probe db mutex");
        conn.execute(
            "INSERT INTO probe_device_match
                (probe_run_id, host, ip, os, vendor, device_type, source,
                 sys_descr, sys_object_id, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                run_id.to_string(),
                m.host,
                m.ip,
                m.os,
                m.vendor,
                m.device_type,
                m.source,
                m.sys_descr,
                m.sys_object_id,
                now_secs(),
            ],
        )?;
        Ok(())
    }

    /// Most-recent device-match observation for a host, or `None` if
    /// SNMP has never produced a hit. Used by the asset detail view.
    pub fn latest_device_match_for_host(
        &self,
        host: &str,
    ) -> SqlResult<Option<DeviceMatchRow>> {
        let conn = self.conn.lock().expect("probe db mutex");
        let mut stmt = conn.prepare_cached(
            "SELECT host, ip, os, vendor, device_type, source,
                    sys_descr, sys_object_id, observed_at
               FROM probe_device_match
              WHERE host = ?1
              ORDER BY observed_at DESC
              LIMIT 1",
        )?;
        stmt.query_row(params![host], |row| {
            Ok(DeviceMatchRow {
                host: row.get(0)?,
                ip: row.get(1)?,
                os: row.get(2)?,
                vendor: row.get(3)?,
                device_type: row.get(4)?,
                source: row.get(5)?,
                sys_descr: row.get(6)?,
                sys_object_id: row.get(7)?,
                observed_at_unix: row.get(8)?,
            })
        })
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
    }

    /// Insert one MAC observation. The same host probed twice writes a
    /// fresh row so the asset view can show first/last-seen aggregates.
    pub fn insert_host_mac(
        &self,
        run_id: &Uuid,
        m: &PendingHostMac,
    ) -> SqlResult<()> {
        let conn = self.conn.lock().expect("probe db mutex");
        conn.execute(
            "INSERT INTO probe_host_mac
                (probe_run_id, host, ip, mac, mac_vendor, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                run_id.to_string(),
                m.host,
                m.ip,
                m.mac,
                m.mac_vendor,
                now_secs(),
            ],
        )?;
        Ok(())
    }

    /// Most-recent MAC observation for a host, or `None` if MAC
    /// scanning has never produced a hit. Used by the asset detail
    /// view's Identity / Device panel.
    pub fn latest_host_mac(
        &self,
        host: &str,
    ) -> SqlResult<Option<HostMacRow>> {
        let conn = self.conn.lock().expect("probe db mutex");
        let mut stmt = conn.prepare_cached(
            "SELECT host, ip, mac, mac_vendor, observed_at
               FROM probe_host_mac
              WHERE host = ?1
              ORDER BY observed_at DESC
              LIMIT 1",
        )?;
        stmt.query_row(params![host], |row| {
            Ok(HostMacRow {
                host: row.get(0)?,
                ip: row.get(1)?,
                mac: row.get(2)?,
                mac_vendor: row.get(3)?,
                observed_at_unix: row.get(4)?,
            })
        })
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
    }

    /// Most-recent observed_at per host — feeds the asset list's
    /// "last seen" column and the timeline panel's probe events.
    pub fn last_seen_for_host(&self, host: &str) -> SqlResult<Option<i64>> {
        let conn = self.conn.lock().expect("probe db mutex");
        let mut stmt = conn.prepare_cached(
            "SELECT MAX(observed_at) FROM probe_open_ports WHERE host = ?1",
        )?;
        stmt.query_row(params![host], |row| row.get::<_, Option<i64>>(0))
            .map_err(Into::into)
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db() -> (ProbeStore, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "corvex-probe-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.sqlite");
        let db = ProbeStore::open(&path).expect("open");
        (db, dir)
    }

    #[test]
    fn round_trip_one_run() {
        let (db, dir) = tmp_db();
        let run = Uuid::new_v4();
        db.insert_run(&run, &["example.com".into()]).unwrap();
        db.insert_open_ports(
            &run,
            &[PendingOpenPort {
                host: "example.com".into(),
                ip: Some("93.184.216.34".into()),
                port: 443,
                over_tls: true,
                service: Some("https".into()),
                product: Some("nginx".into()),
                vendor: None,
                version: Some("1.18.0".into()),
                info: None,
                cpe: vec!["cpe:2.3:a:nginx:nginx:1.18.0".into()],
                jarm: Some("AAAA".into()),
                banner: "HTTP/1.1 200".into(),
            }],
        )
        .unwrap();
        db.finish_run(&run, "complete").unwrap();

        let svcs = db.services_for_host("example.com").unwrap();
        assert_eq!(svcs.len(), 1);
        assert_eq!(svcs[0].port, 443);
        assert_eq!(svcs[0].product.as_deref(), Some("nginx"));
        assert_eq!(svcs[0].cpe.len(), 1);

        let last = db.last_seen_for_host("example.com").unwrap();
        assert!(last.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn jarm_join_finds_siblings() {
        let (db, dir) = tmp_db();
        let r1 = Uuid::new_v4();
        let r2 = Uuid::new_v4();
        db.insert_run(&r1, &["a.example".into()]).unwrap();
        db.insert_run(&r2, &["b.example".into()]).unwrap();
        let mk = |host: &str| PendingOpenPort {
            host: host.into(),
            ip: None,
            port: 443,
            over_tls: true,
            service: Some("https".into()),
            product: None,
            vendor: None,
            version: None,
            info: None,
            cpe: vec![],
            jarm: Some("BBBB".into()),
            banner: String::new(),
        };
        db.insert_open_ports(&r1, &[mk("a.example")]).unwrap();
        db.insert_open_ports(&r2, &[mk("b.example")]).unwrap();

        let siblings = db.hosts_sharing_jarm("a.example").unwrap();
        assert_eq!(siblings.len(), 1);
        assert_eq!(siblings[0].0, "b.example");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_match_round_trip() {
        let (db, dir) = tmp_db();
        let run = Uuid::new_v4();
        db.insert_run(&run, &["sw1.example".into()]).unwrap();
        db.insert_device_match(
            &run,
            &PendingDeviceMatch {
                host: "sw1.example".into(),
                ip: Some("10.0.0.1".into()),
                os: "ios".into(),
                vendor: "cisco".into(),
                device_type: "network".into(),
                source: "sysobjectid".into(),
                sys_descr: Some("Cisco IOS Software".into()),
                sys_object_id: Some("1.3.6.1.4.1.9.1.516".into()),
            },
        )
        .unwrap();
        let m = db
            .latest_device_match_for_host("sw1.example")
            .unwrap()
            .expect("row");
        assert_eq!(m.os, "ios");
        assert_eq!(m.vendor, "cisco");
        assert_eq!(m.source, "sysobjectid");

        // No hit for an unrelated host.
        assert!(db
            .latest_device_match_for_host("other.example")
            .unwrap()
            .is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn host_mac_round_trip() {
        let (db, dir) = tmp_db();
        let run = Uuid::new_v4();
        db.insert_run(&run, &["sw1.example".into()]).unwrap();
        db.insert_host_mac(
            &run,
            &PendingHostMac {
                host: "sw1.example".into(),
                ip: Some("10.0.0.1".into()),
                mac: "00:11:22:aa:bb:cc".into(),
                mac_vendor: Some("Cisco Systems, Inc".into()),
            },
        )
        .unwrap();
        let row = db.latest_host_mac("sw1.example").unwrap().expect("row");
        assert_eq!(row.mac, "00:11:22:aa:bb:cc");
        assert_eq!(row.mac_vendor.as_deref(), Some("Cisco Systems, Inc"));
        assert!(db.latest_host_mac("nope.example").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cascade_on_run_delete() {
        let (db, dir) = tmp_db();
        let run = Uuid::new_v4();
        db.insert_run(&run, &["example.com".into()]).unwrap();
        db.insert_open_ports(
            &run,
            &[PendingOpenPort {
                host: "example.com".into(),
                ip: None,
                port: 80,
                over_tls: false,
                service: Some("http".into()),
                product: None,
                vendor: None,
                version: None,
                info: None,
                cpe: vec![],
                jarm: None,
                banner: String::new(),
            }],
        )
        .unwrap();
        assert_eq!(db.services_for_host("example.com").unwrap().len(), 1);

        let conn = db.conn.lock().unwrap();
        conn.execute("DELETE FROM probe_runs WHERE id = ?1", params![run.to_string()])
            .unwrap();
        drop(conn);

        assert!(db.services_for_host("example.com").unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
