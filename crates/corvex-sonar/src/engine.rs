use crate::connector::TcpConnector;
use crate::db::SonarDb;
use crate::probe::ProbeCtx;
use crate::probes::tls::TlsProbe;
use crate::recog::match_response;
use crate::types::{Evidence, ProbeMatch, ProbeTarget, ScanMode, SonarOpts};
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub async fn identify(
    db: &SonarDb,
    host: &str,
    ip: IpAddr,
    port: u16,
    mode: ScanMode,
    opts: &SonarOpts,
    connect_timeout_ms: u64,
    probe_budget_ms: u64,
    tls_handshake: bool,
) -> Option<ProbeMatch> {
    if !matches!(mode, ScanMode::Deep) {
        return None;
    }

    let deadline = Instant::now() + Duration::from_millis(probe_budget_ms.max(1));
    let target = ProbeTarget {
        host: host.to_string(),
        ip,
        port,
        deadline,
    };
    let connector = TcpConnector::new(
        ProbeTarget {
            host: host.to_string(),
            ip,
            port,
            deadline,
        },
        connect_timeout_ms,
    );

    let mut over_tls = false;
    let mut tls_meta = None;
    let mut best: Option<ProbeMatch> = None;

    if tls_handshake {
        let tls_probe = TlsProbe::default();
        let mut ctx = ProbeCtx {
            target: &target,
            connector: &connector,
            over_tls: false,
        };
        if let Ok(ev) = <TlsProbe as crate::probe::Probe>::run(&tls_probe, &mut ctx).await {
            over_tls = true;
            tls_meta = ev.tls_meta.clone();
            if let Some(hint) = &ev.service_hint {
                best = Some(seed_match("tls_handshake", hint, over_tls, tls_meta.clone()));
            }
        }
    }

    for probe in &db.scripted_probes {
        if !probe.matches_port(port, over_tls) {
            continue;
        }
        let use_tls = match probe.requires_tls() {
            crate::types::TlsRequirement::Plain => false,
            crate::types::TlsRequirement::Tls => true,
            crate::types::TlsRequirement::Either => over_tls,
        };
        let mut ctx = ProbeCtx {
            target: &target,
            connector: &connector,
            over_tls: use_tls,
        };
        let ev = match probe.run(&mut ctx).await {
            Ok(ev) => ev,
            Err(_) => continue,
        };
        if let Some(m) = match_evidence(db, probe.id(), probe.fingerprint_sets(), &ev, over_tls, tls_meta.clone()) {
            best = Some(m);
            break;
        }
        if best.is_none() {
            if let Some(hint) = &ev.service_hint {
                best = Some(seed_match(probe.id(), hint, over_tls, tls_meta.clone()));
            }
        }
        if Instant::now() >= deadline {
            break;
        }
    }

    for sp in &db.static_probes {
        if Instant::now() >= deadline {
            break;
        }
        let port_hit = if over_tls {
            sp.sslports.contains(&port)
        } else {
            sp.ports.contains(&port)
        };
        let is_null = sp.payload.is_empty() && sp.ports.is_empty() && sp.sslports.is_empty();
        if !port_hit && !is_null {
            continue;
        }

        let connector_for_probe = TcpConnector::new(
            ProbeTarget {
                host: host.to_string(),
                ip,
                port,
                deadline,
            },
            connect_timeout_ms,
        );

        let payload = render_payload(&sp.payload, sp.payload_has_host_token, host);
        let ev = match run_static_probe(
            &connector_for_probe,
            over_tls,
            &payload,
            Duration::from_millis(sp.wait_ms),
        )
        .await
        {
            Ok(ev) => ev,
            Err(_) => continue,
        };

        let sets: Vec<String> = sp.fingerprints.clone();
        if let Some(m) = match_evidence_owned(db, &sp.id, &sets, &ev, over_tls, tls_meta.clone()) {
            best = Some(m);
            break;
        }
    }

    if let Some(ref mut m) = best {
        if opts.jarm && over_tls {
            m.jarm = Some(String::from("jarm_not_implemented_v1"));
        }
        if over_tls && m.service == "http" {
            m.service = "https".into();
        }
    }

    best
}

fn seed_match(
    probe_id: &str,
    hint: &str,
    over_tls: bool,
    tls_meta: Option<crate::types::TlsMeta>,
) -> ProbeMatch {
    ProbeMatch {
        service: hint.to_string(),
        probe_id: probe_id.to_string(),
        over_tls,
        tls: tls_meta,
        ..Default::default()
    }
}

fn match_evidence(
    db: &SonarDb,
    probe_id: &str,
    sets: &[&'static str],
    ev: &Evidence,
    over_tls: bool,
    tls_meta: Option<crate::types::TlsMeta>,
) -> Option<ProbeMatch> {
    let owned: Vec<String> = sets.iter().map(|s| s.to_string()).collect();
    match_evidence_owned(db, probe_id, &owned, ev, over_tls, tls_meta)
}

fn match_evidence_owned(
    db: &SonarDb,
    probe_id: &str,
    sets: &[String],
    ev: &Evidence,
    over_tls: bool,
    tls_meta: Option<crate::types::TlsMeta>,
) -> Option<ProbeMatch> {
    let full_text = String::from_utf8_lossy(&ev.response).into_owned();
    let mut out = ProbeMatch {
        service: ev.service_hint.clone().unwrap_or_default(),
        probe_id: probe_id.to_string(),
        over_tls,
        tls: tls_meta,
        ..Default::default()
    };
    let mut matched_any = false;

    for (banner_name, banner_bytes) in &ev.multi_banner {
        let banner_text = String::from_utf8_lossy(banner_bytes);
        let narrowed_sets: Vec<String> = vec![banner_name.clone()];
        if let Some(hit) = match_response(db, &narrowed_sets, &banner_text) {
            hit.merge_into(&mut out);
            matched_any = true;
        }
    }

    if let Some(hit) = match_response(db, sets, &full_text) {
        hit.merge_into(&mut out);
        matched_any = true;
    }

    if matched_any {
        if out.service.is_empty() {
            out.service = ev
                .service_hint
                .clone()
                .unwrap_or_else(|| "unknown".into());
        }
        Some(out)
    } else {
        None
    }
}

fn render_payload(payload: &[u8], has_host_token: bool, host: &str) -> Vec<u8> {
    if !has_host_token {
        return payload.to_vec();
    }
    let s = String::from_utf8_lossy(payload);
    s.replace("{host}", host).into_bytes()
}

async fn run_static_probe(
    connector: &TcpConnector,
    over_tls: bool,
    payload: &[u8],
    wait: Duration,
) -> anyhow::Result<Evidence> {
    use crate::probe::Connector;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    let mut stream = if over_tls {
        connector.connect_tls().await?.0
    } else {
        connector.connect_plain().await?
    };

    if !payload.is_empty() {
        stream.write_all(payload).await?;
    }

    let mut buf = vec![0u8; 4096];
    let mut total = 0usize;
    loop {
        let n = match timeout(wait, stream.read(&mut buf[total..])).await {
            Ok(Ok(n)) => n,
            _ => break,
        };
        if n == 0 {
            break;
        }
        total += n;
        if total >= buf.len() {
            break;
        }
    }
    buf.truncate(total);

    Ok(Evidence {
        service_hint: None,
        response: buf,
        tls_meta: None,
        jarm: None,
        multi_banner: Vec::new(),
    })
}
