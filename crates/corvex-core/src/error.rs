use thiserror::Error;

pub type Result<T> = std::result::Result<T, CorvexError>;

#[derive(Debug, Error)]
pub enum CorvexError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("http: {0}")]
    Http(String),

    #[error("tls: {0}")]
    Tls(String),

    #[error("config: {0}")]
    Config(String),

    #[error("dsl: {0}")]
    Dsl(String),

    #[error("dns: {0}")]
    Dns(String),

    #[error("plugin `{name}`: {msg}")]
    Plugin { name: String, msg: String },

    #[error("{0}")]
    Other(String),
}

impl CorvexError {
    pub fn other<S: Into<String>>(s: S) -> Self {
        CorvexError::Other(s.into())
    }
}

impl From<anyhow::Error> for CorvexError {
    fn from(e: anyhow::Error) -> Self {
        CorvexError::Other(format!("{e:#}"))
    }
}

impl From<regex::Error> for CorvexError {
    fn from(e: regex::Error) -> Self {
        CorvexError::Dsl(e.to_string())
    }
}
