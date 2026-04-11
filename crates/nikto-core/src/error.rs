use thiserror::Error;

pub type Result<T> = std::result::Result<T, NiktoError>;

#[derive(Debug, Error)]
pub enum NiktoError {
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

impl NiktoError {
    pub fn other<S: Into<String>>(s: S) -> Self {
        NiktoError::Other(s.into())
    }
}

impl From<anyhow::Error> for NiktoError {
    fn from(e: anyhow::Error) -> Self {
        NiktoError::Other(format!("{e:#}"))
    }
}

impl From<regex::Error> for NiktoError {
    fn from(e: regex::Error) -> Self {
        NiktoError::Dsl(e.to_string())
    }
}
