//! Smoke test: the baked Recog DB loads, and the seed SSH fingerprint
//! extracts OpenSSH product + version from a canonical banner.

use corvex_sonar::db::sonar_db;
use corvex_sonar::recog::match_response;

#[test]
fn ssh_banner_identifies_openssh() {
    let db = sonar_db();
    assert!(
        !db.recog.is_empty(),
        "baked probe DB should contain the seed fingerprints"
    );

    let sets = vec!["ssh.banner".to_string()];
    let hit = match_response(&db, &sets, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4")
        .expect("canonical OpenSSH banner should match a seed fingerprint");

    assert_eq!(hit.product.as_deref(), Some("OpenSSH"));
    assert_eq!(hit.version.as_deref(), Some("9.6p1"));
    assert!(
        hit.cpe.iter().any(|c| c.contains("openssh")),
        "cpe should contain openssh: {:?}",
        hit.cpe
    );
}

#[test]
fn nginx_server_header_identifies_nginx() {
    let db = sonar_db();
    let sets = vec!["http_header.server".to_string()];
    let hit = match_response(&db, &sets, "nginx/1.25.3")
        .expect("nginx/1.25.3 server header should match");
    assert_eq!(hit.product.as_deref(), Some("nginx"));
    assert_eq!(hit.version.as_deref(), Some("1.25.3"));
    assert!(hit.cpe.iter().any(|c| c.contains("nginx:nginx:1.25.3")));
}

#[test]
fn unrelated_text_does_not_match() {
    let db = sonar_db();
    let sets = vec!["ssh.banner".to_string(), "http_header.server".to_string()];
    assert!(match_response(&db, &sets, "hello world").is_none());
}
