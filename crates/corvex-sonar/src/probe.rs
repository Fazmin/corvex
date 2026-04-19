use crate::types::{Evidence, ProbeTarget, TlsMeta, TlsRequirement};
use async_trait::async_trait;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

pub type ProbeStream = Pin<Box<dyn AsyncReadWrite>>;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> AsyncReadWrite for T {}

#[async_trait]
pub trait Connector: Send + Sync {
    async fn connect_plain(&self) -> anyhow::Result<ProbeStream>;
    async fn connect_tls(&self) -> anyhow::Result<(ProbeStream, TlsMeta)>;
}

pub struct ProbeCtx<'a> {
    pub target: &'a ProbeTarget,
    pub connector: &'a dyn Connector,
    pub over_tls: bool,
}

#[async_trait]
pub trait Probe: Send + Sync + 'static {
    fn id(&self) -> &'static str;
    fn rarity(&self) -> u8 {
        5
    }
    fn matches_port(&self, port: u16, over_tls: bool) -> bool;
    fn requires_tls(&self) -> TlsRequirement {
        TlsRequirement::Either
    }
    fn fingerprint_sets(&self) -> &'static [&'static str] {
        &[]
    }
    async fn run(&self, ctx: &mut ProbeCtx<'_>) -> anyhow::Result<Evidence>;
}
