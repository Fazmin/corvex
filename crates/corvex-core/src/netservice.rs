//! Network service vulnerability checks — protocol-level tests for
//! non-HTTP services discovered during port scanning.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::error::Result;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Result of a network service check.
#[derive(Debug, Clone)]
pub struct ServiceCheckResult {
    pub port: u16,
    pub service: String,
    pub finding: Option<String>,
    pub severity: &'static str,
    pub banner: String,
}

async fn connect(ip: IpAddr, port: u16) -> std::io::Result<TcpStream> {
    let addr = SocketAddr::new(ip, port);
    timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))?
}

async fn read_banner(stream: &mut TcpStream) -> String {
    let mut buf = [0u8; 2048];
    match timeout(READ_TIMEOUT, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&buf[..n]).to_string(),
        _ => String::new(),
    }
}

async fn send_recv(stream: &mut TcpStream, data: &[u8]) -> String {
    let _ = stream.write_all(data).await;
    let _ = stream.flush().await;
    read_banner(stream).await
}

/// Check FTP for anonymous login.
pub async fn check_ftp_anon(ip: IpAddr, port: u16) -> Result<ServiceCheckResult> {
    let mut stream = connect(ip, port).await?;
    let banner = read_banner(&mut stream).await;

    // Try anonymous login
    let user_resp = send_recv(&mut stream, b"USER anonymous\r\n").await;
    let pass_resp = send_recv(&mut stream, b"PASS anonymous@test.com\r\n").await;

    let finding = if pass_resp.starts_with("230") {
        Some("FTP anonymous login is allowed.".into())
    } else if user_resp.starts_with("331") && pass_resp.starts_with("230") {
        Some("FTP anonymous login is allowed.".into())
    } else {
        None
    };

    let _ = stream.write_all(b"QUIT\r\n").await;

    Ok(ServiceCheckResult {
        port,
        service: "ftp".into(),
        finding,
        severity: "MEDIUM",
        banner: banner.chars().take(200).collect(),
    })
}

/// Check SMTP for open relay.
pub async fn check_smtp_relay(ip: IpAddr, port: u16) -> Result<ServiceCheckResult> {
    let mut stream = connect(ip, port).await?;
    let banner = read_banner(&mut stream).await;

    let ehlo = send_recv(&mut stream, b"EHLO test.local\r\n").await;
    let mail = send_recv(&mut stream, b"MAIL FROM:<test@test.local>\r\n").await;
    let rcpt = send_recv(
        &mut stream,
        b"RCPT TO:<relay-test@example.com>\r\n",
    )
    .await;

    let finding = if rcpt.starts_with("250") {
        Some("SMTP server may be an open relay — accepted RCPT TO for external domain.".into())
    } else if mail.starts_with("250") && (rcpt.starts_with("250") || rcpt.starts_with("251")) {
        Some("SMTP server accepted relay attempt.".into())
    } else {
        None
    };

    let _ = stream.write_all(b"QUIT\r\n").await;
    let _ = ehlo; // used in protocol exchange

    Ok(ServiceCheckResult {
        port,
        service: "smtp".into(),
        finding,
        severity: "HIGH",
        banner: banner.chars().take(200).collect(),
    })
}

/// Check for SNMP default community strings.
pub async fn check_snmp_community(ip: IpAddr, port: u16) -> Result<ServiceCheckResult> {
    // SNMP uses UDP — we'll do a simple UDP probe for default community "public"
    let addr = SocketAddr::new(ip, port);
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;

    // SNMPv1 GET request for sysDescr with community "public"
    let snmp_get_public: &[u8] = &[
        0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
        0xa0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e,
        0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05,
        0x00,
    ];

    let _ = socket.send_to(snmp_get_public, addr).await;

    let mut buf = [0u8; 2048];
    let finding = match timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            Some("SNMP default community string 'public' is accessible.".into())
        }
        _ => None,
    };

    Ok(ServiceCheckResult {
        port,
        service: "snmp".into(),
        finding,
        severity: "MEDIUM",
        banner: String::new(),
    })
}

/// Check SSH version for known weak versions.
pub async fn check_ssh(ip: IpAddr, port: u16) -> Result<ServiceCheckResult> {
    let mut stream = connect(ip, port).await?;
    let banner = read_banner(&mut stream).await;
    let _ = stream.shutdown().await;

    let lower = banner.to_ascii_lowercase();
    let finding = if lower.contains("ssh-1.") {
        Some("SSH protocol version 1 detected — cryptographically broken.".into())
    } else if lower.contains("dropbear_0.") || lower.contains("dropbear_2015") || lower.contains("dropbear_2016") {
        Some(format!("Outdated SSH implementation detected: {}", banner.trim()))
    } else {
        None
    };

    let severity = if lower.contains("ssh-1.") { "HIGH" } else { "MEDIUM" };

    Ok(ServiceCheckResult {
        port,
        service: "ssh".into(),
        finding,
        severity,
        banner: banner.chars().take(200).collect(),
    })
}

/// Report telnet as a cleartext protocol.
pub fn check_telnet(port: u16) -> ServiceCheckResult {
    ServiceCheckResult {
        port,
        service: "telnet".into(),
        finding: Some("Telnet service detected — credentials transmitted in cleartext.".into()),
        severity: "MEDIUM",
        banner: String::new(),
    }
}
