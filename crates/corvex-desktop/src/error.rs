use serde::Serialize;

/// Wrapper error type that serializes cleanly into the Tauri command
/// boundary. The Tauri command machinery requires `Serialize` so we
/// flatten everything into a plain string.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("corvex: {0}")]
    Corvex(#[from] corvex_core::CorvexError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("tauri: {0}")]
    Tauri(String),

    #[error("{0}")]
    Other(String),
}

impl From<tauri::Error> for AppError {
    fn from(e: tauri::Error) -> Self {
        AppError::Tauri(e.to_string())
    }
}

impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub type AppResult<T> = std::result::Result<T, AppError>;
