use crate::authentication::AuthenticationError;
use crate::events::CircuitEvent;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Protocol(String),

    #[error("{message}")]
    OperationFailed {
        code: Option<String>,
        message: String,
    },

    #[error("{message}")]
    Unsatisfiable {
        code: Option<String>,
        message: String,
    },

    #[error("{message}")]
    CircuitExtensionFailed {
        message: String,
        circuit: Option<Box<CircuitEvent>>,
    },

    #[error("{0}")]
    DescriptorUnavailable(String),

    #[error("{0}")]
    Timeout(String),

    #[error("{message}")]
    InvalidRequest {
        code: Option<String>,
        message: String,
    },

    #[error("{message}")]
    InvalidArguments {
        code: Option<String>,
        message: String,
        arguments: Vec<String>,
    },

    #[error("{0}")]
    Socket(String),

    #[error("socket closed")]
    SocketClosed,

    #[error("Failed to download from {url}: {message}")]
    DownloadFailed { url: String, message: String },

    #[error("Failed to download from {url}: {seconds:.1} second timeout reached")]
    DownloadTimeout { url: String, seconds: f64 },

    #[error("{0}")]
    Authentication(#[from] AuthenticationError),

    #[error("{0}")]
    InvalidInput(String),

    #[error("{0}")]
    Parse(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Error {
    pub fn protocol(message: impl Into<String>) -> Self {
        Error::Protocol(message.into())
    }

    pub fn parse(message: impl Into<String>) -> Self {
        Error::Parse(message.into())
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Error::InvalidInput(message.into())
    }

    pub fn operation_failed(code: &str, message: impl Into<String>) -> Self {
        Error::OperationFailed {
            code: Some(code.to_string()),
            message: message.into(),
        }
    }

    pub fn unsatisfiable(message: impl Into<String>) -> Self {
        Error::Unsatisfiable {
            code: None,
            message: message.into(),
        }
    }

    pub fn invalid_request(code: &str, message: impl Into<String>) -> Self {
        Error::InvalidRequest {
            code: Some(code.to_string()),
            message: message.into(),
        }
    }

    pub fn invalid_arguments(
        code: &str,
        message: impl Into<String>,
        arguments: Vec<String>,
    ) -> Self {
        Error::InvalidArguments {
            code: Some(code.to_string()),
            message: message.into(),
            arguments,
        }
    }

    pub fn is_socket_closed(&self) -> bool {
        matches!(self, Error::SocketClosed)
    }
}

impl Clone for Error {
    fn clone(&self) -> Self {
        match self {
            Error::Protocol(message) => Error::Protocol(message.clone()),
            Error::OperationFailed { code, message } => Error::OperationFailed {
                code: code.clone(),
                message: message.clone(),
            },
            Error::Unsatisfiable { code, message } => Error::Unsatisfiable {
                code: code.clone(),
                message: message.clone(),
            },
            Error::CircuitExtensionFailed { message, circuit } => {
                Error::CircuitExtensionFailed {
                    message: message.clone(),
                    circuit: circuit.clone(),
                }
            }
            Error::DescriptorUnavailable(message) => {
                Error::DescriptorUnavailable(message.clone())
            }
            Error::Timeout(message) => Error::Timeout(message.clone()),
            Error::InvalidRequest { code, message } => Error::InvalidRequest {
                code: code.clone(),
                message: message.clone(),
            },
            Error::InvalidArguments {
                code,
                message,
                arguments,
            } => Error::InvalidArguments {
                code: code.clone(),
                message: message.clone(),
                arguments: arguments.clone(),
            },
            Error::Socket(message) => Error::Socket(message.clone()),
            Error::SocketClosed => Error::SocketClosed,
            Error::DownloadFailed { url, message } => Error::DownloadFailed {
                url: url.clone(),
                message: message.clone(),
            },
            Error::DownloadTimeout { url, seconds } => Error::DownloadTimeout {
                url: url.clone(),
                seconds: *seconds,
            },
            Error::Authentication(error) => Error::Authentication(error.clone()),
            Error::InvalidInput(message) => Error::InvalidInput(message.clone()),
            Error::Parse(message) => Error::Parse(message.clone()),
            Error::Io(error) => {
                Error::Io(std::io::Error::new(error.kind(), error.to_string()))
            }
        }
    }
}
