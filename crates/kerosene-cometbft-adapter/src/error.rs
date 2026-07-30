use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum AppError {
    #[error("invalid transaction format: {0}")]
    InvalidTxFormat(String),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("replay attack detected: sequence {1} from {0} already used")]
    DuplicateSequence(String, u64),

    #[error("unknown command type: {0}")]
    UnknownCommand(String),

    #[error("unauthorized key: {0}")]
    UnauthorizedKey(String),

    #[error("network mismatch: expected {0}, got {1}")]
    NetworkMismatch(String, String),

    #[error("state error: {0}")]
    State(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("kernel bridge error: {0}")]
    KfeBridge(String),
}

/// ABCI error codes returned to CometBFT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Ok = 0,
    EncodingError = 1,
    InvalidNonce = 2,
    InvalidSignature = 3,
    InternalError = 4,
    UnknownCommand = 5,
    KfeBridgeError = 6,
    TxAlreadyInCache = 7,
    NetworkMismatch = 8,
    UnauthorizedKey = 9,
}

impl Code {
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

impl From<&AppError> for Code {
    fn from(err: &AppError) -> Self {
        match err {
            AppError::InvalidTxFormat(_) => Code::EncodingError,
            AppError::InvalidSignature => Code::InvalidSignature,
            AppError::DuplicateSequence(_, _) => Code::InvalidNonce,
            AppError::UnknownCommand(_) => Code::UnknownCommand,
            AppError::UnauthorizedKey(_) => Code::UnauthorizedKey,
            AppError::NetworkMismatch(_, _) => Code::NetworkMismatch,
            AppError::State(_) => Code::InternalError,
            AppError::Config(_) => Code::InternalError,
            AppError::KfeBridge(_) => Code::KfeBridgeError,
        }
    }
}
