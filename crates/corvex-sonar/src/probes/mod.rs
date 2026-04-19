use crate::probe::Probe;
use std::sync::Arc;

pub mod http;
pub mod ssh;
pub mod tls;

pub fn registry() -> Vec<Arc<dyn Probe>> {
    vec![
        Arc::new(http::HttpProbe::default()) as Arc<dyn Probe>,
        Arc::new(ssh::SshProbe::default()),
    ]
}
