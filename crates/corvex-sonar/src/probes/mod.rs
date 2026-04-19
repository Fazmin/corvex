use crate::probe::Probe;
use std::sync::Arc;

pub mod http;
pub mod ldap;
pub mod mysql;
pub mod postgres;
pub mod rdp;
pub mod smb;
pub mod ssh;
pub mod tls;

pub fn registry() -> Vec<Arc<dyn Probe>> {
    vec![
        Arc::new(http::HttpProbe::default()) as Arc<dyn Probe>,
        Arc::new(ssh::SshProbe::default()),
        Arc::new(mysql::MySqlProbe::default()),
        Arc::new(postgres::PostgresProbe::default()),
        Arc::new(smb::SmbProbe::default()),
        Arc::new(rdp::RdpProbe::default()),
        Arc::new(ldap::LdapProbe::default()),
    ]
}
