use thiserror::Error;

/// Errors that can occur within omnihook operations.
#[derive(Debug, Error)]
pub enum OmnihookError {
    /// An error related to invalid or missing configuration.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// An error indicating that the payload could not be serialized.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// An error indicating that the payload could not be signed.
    #[error("Signing error: {0}")]
    SigningError(String),

    /// An error indicating that the notification failed to be sent.
    #[error("Notification failed: {0}")]
    NotifyFailed(String),

    /// An error from the underlying `reqwest` or `reqwest_middleware`
    /// libraries.
    #[error("Request error: {0}")]
    RequestError(#[from] reqwest_middleware::Error),
}
