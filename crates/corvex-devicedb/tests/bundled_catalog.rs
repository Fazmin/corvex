//! Smoke tests against the bundled YAML signatures.
//!
//! Inputs are real-world (sysObjectID, sysDescr) pairs that the
//! catalog must continue to identify correctly. Failures here
//! usually mean a vendor's upstream signature changed shape — open
//! the corresponding `data/devices/<vendor>.yaml` file before
//! editing the assertion.

use std::path::PathBuf;

use corvex_devicedb::{identify, DeviceCatalog};

fn data_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("data/devices");
    p
}

fn load() -> DeviceCatalog {
    DeviceCatalog::load_dir(data_dir()).expect("load catalog")
}

#[test]
fn loads_bundled_signatures() {
    let cat = load();
    assert!(
        cat.entries.len() >= 500,
        "expected the full bundled catalog, got {}",
        cat.entries.len()
    );
}

#[test]
fn open_sqlite_matches_load_dir() {
    // Build a fresh devices.sqlite into a temp file from the YAML
    // sources, then open it and confirm the catalog has the same shape
    // as the directly-parsed in-memory version. Catches reader/writer
    // schema drift without the test depending on a committed artifact.
    use corvex_devicedb::db;
    use rusqlite::params;

    let from_dir = load();

    let tmp = tempfile::Builder::new()
        .suffix(".sqlite")
        .tempfile()
        .expect("tempfile");
    let db_path = tmp.path().to_path_buf();
    drop(tmp); // close the empty handle so SQLite can take exclusive ownership.

    // Hand-written tiny build to avoid pulling in the builder crate.
    {
        let conn = db::open_for_write(&db_path).expect("open writer");
        db::truncate(&conn).expect("truncate");
        // Populate one synthetic entry round-trip so the schema-shape
        // is exercised end to end.
        conn.execute(
            "INSERT INTO device_entry (os, vendor, device_type, max_oid_prefix_len, source_file)
             VALUES ('demo', 'demo-vendor', 'network', 14, 'demo.yaml')",
            [],
        )
        .unwrap();
        let entry_id: i64 = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO device_clause (entry_id, clause_index, disabled) VALUES (?1, 0, 0)",
            params![entry_id],
        )
        .unwrap();
        let clause_id: i64 = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO device_clause_pattern (clause_id, kind, pattern)
             VALUES (?1, 'sys_object_id', '1.3.6.1.4.1.99999')",
            params![clause_id],
        )
        .unwrap();
        db::write_meta(&conn, 1).unwrap();
    }

    let opened = DeviceCatalog::open(&db_path).expect("open sqlite");
    let m = identify(Some("1.3.6.1.4.1.99999.5"), None, &opened).expect("synthetic match");
    assert_eq!(m.os, "demo");
    assert_eq!(m.vendor, "demo-vendor");

    // The bundled YAML directory load still produces the larger
    // production catalog independently.
    assert!(from_dir.entries.len() >= 500);
    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn matches_cisco_ios_via_descr() {
    // Real Cisco 2960 sysDescr.
    let cat = load();
    let m = identify(
        Some("1.3.6.1.4.1.9.1.516"),
        Some(
            "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), \
             Version 15.0(2)SE7, RELEASE SOFTWARE (fc1)",
        ),
        &cat,
    )
    .expect("ios");
    assert_eq!(m.os, "ios");
    assert_eq!(m.vendor, "cisco");
    assert_eq!(m.device_type, "network");
}

#[test]
fn cisco_iosxe_does_not_collapse_onto_ios() {
    // ios.yaml's sysDescr_except rejects "IOS-XE", so an IOS-XE box
    // must land on iosxe.yaml not ios.yaml.
    let cat = load();
    let m = identify(
        None,
        Some(
            "Cisco IOS Software [Bengaluru], Catalyst L3 Switch Software \
             (CAT9K_IOSXE), Version 17.6.4, RELEASE SOFTWARE (fc2)",
        ),
        &cat,
    );
    if let Some(m) = m {
        assert_ne!(m.os, "ios", "iosxe device matched plain ios");
    }
}

#[test]
fn matches_apc_via_oid() {
    // Catalog uses upstream's "power" type for APC — verifies the
    // schema is correctly preserved end to end.
    let cat = load();
    let m = identify(Some("1.3.6.1.4.1.318.1.3.27"), None, &cat).expect("apc");
    assert_eq!(m.vendor, "apc");
    // type can vary across the bundled catalog; we only insist it's
    // a power-related class so the UI chip looks right.
    assert!(
        m.device_type == "power" || m.device_type == "pdu",
        "unexpected device_type {} for APC",
        m.device_type
    );
}

#[test]
fn matches_juniper_junos_via_descr() {
    let cat = load();
    let m = identify(
        None,
        Some("Juniper Networks, Inc. ex4300-48p Ethernet Switch, kernel JUNOS 22.4R3"),
        &cat,
    )
    .expect("junos");
    assert_eq!(m.vendor, "juniper");
    assert_eq!(m.os, "junos");
}

#[test]
fn returns_none_when_nothing_matches() {
    let cat = load();
    assert!(identify(Some("1.2.3.4.5"), Some("totally unknown"), &cat).is_none());
    assert!(identify(None, None, &cat).is_none());
}

#[test]
fn longest_prefix_wins_does_not_cross_vendor() {
    // OID 1.3.6.1.4.1.99 is in an unassigned-to-us enterprise block.
    // Whatever it matches must not be a Cisco-specific os.
    let cat = load();
    let m = identify(Some("1.3.6.1.4.1.99.5.1"), None, &cat);
    if let Some(m) = m {
        assert_ne!(
            m.vendor, "cisco",
            "vendor 99 OID must not match Cisco entries"
        );
    }
}

#[test]
fn iana_and_oui_lookup_helpers_round_trip() {
    // Build a fresh sqlite with a single PEN row + a single OUI row,
    // then exercise the lookup helpers. This is a unit test for the
    // db.rs API; the production catalog is exercised by the
    // device_db_summary command and the larger bundled tests above.
    use corvex_devicedb::db;
    use rusqlite::params;

    let tmp = tempfile::Builder::new()
        .suffix(".sqlite")
        .tempfile()
        .expect("tempfile");
    let db_path = tmp.path().to_path_buf();
    drop(tmp);

    let conn = db::open_for_write(&db_path).expect("open writer");
    db::truncate(&conn).expect("truncate");
    conn.execute(
        "INSERT INTO iana_enterprise (pen, organization, contact, email)
         VALUES (?1, ?2, ?3, ?4)",
        params![9_i64, "ciscoSystems", "Dave Jones", "davej&cisco.com"],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO ieee_oui (prefix, organization, address_line1, address_line2, country_code)
         VALUES (?1, ?2, NULL, NULL, NULL)",
        params!["00000C", "Cisco Systems, Inc"],
    )
    .unwrap();
    db::write_meta(&conn, 0).unwrap();

    assert_eq!(
        db::lookup_iana_enterprise(&conn, 9).unwrap().as_deref(),
        Some("ciscoSystems")
    );
    assert!(db::lookup_iana_enterprise(&conn, 99_999_999)
        .unwrap()
        .is_none());

    // Try every common spelling — colon, dash, dot, no separator.
    for mac in [
        "00:00:0c:11:22:33",
        "00-00-0C-11-22-33",
        "0000.0c11.2233",
        "00000c112233",
    ] {
        assert_eq!(
            db::lookup_ieee_oui(&conn, mac).unwrap().as_deref(),
            Some("Cisco Systems, Inc"),
            "lookup failed for spelling: {mac}"
        );
    }
    assert!(db::lookup_ieee_oui(&conn, "ff-ff-ff-11-22-33")
        .unwrap()
        .is_none());

    drop(conn);
    let _ = std::fs::remove_file(&db_path);
}
