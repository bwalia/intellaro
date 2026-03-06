//! CLI error types.
//!
//! Centralizes all error variants the CLI can produce, providing
//! user-friendly messages and structured error propagation.


/// Top-level CLI error type.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Server returned an API-level error.
    #[error("Server error: {message}")]
    ServerError {
        status: u16,
        message: String,
    },

    /// Network / HTTP transport error.
    #[error("Connection error: {0}")]
    ConnectionError(#[from] reqwest::Error),

    /// Failed to parse a server response.
    #[error("Response parse error: {0}")]
    ParseError(String),

    /// Local configuration file error.
    #[error("Config error: {0}")]
    ConfigError(String),

    /// Authentication failure.
    #[error("Authentication failed: {0}")]
    AuthError(String),

    /// Invalid CLI input or argument.
    #[error("Invalid input: {0}")]
    InputError(String),

    /// File I/O error.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Feature not yet implemented on the server.
    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

/// Standard API response envelope from the server.
#[derive(Debug, serde::Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    /// Convert an API response into a Result, extracting the data on success
    /// or producing a `CliError::ServerError` on failure.
    pub fn into_result(self, status: u16) -> Result<T, CliError> {
        if self.success {
            self.data.ok_or_else(|| CliError::ParseError(
                "Server returned success but no data".to_string(),
            ))
        } else {
            Err(CliError::ServerError {
                status,
                message: self.error.unwrap_or_else(|| "Unknown server error".to_string()),
            })
        }
    }
}

/// Convenience type alias used throughout the CLI.
pub type CliResult<T> = Result<T, CliError>;
