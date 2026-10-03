//! The one error type `lcoat-core` returns.
//!
//! [`Error::User`] carries a message meant for the operator; the CLI prints
//! it as `error: <message>` and exits 1, matching the shell build's `fail`.
//! Everything else is an underlying failure with its source attached.

use std::fmt;
use std::io;

use lcoat_format::envfile::EnvError;
use lcoat_format::ndjson::NdjsonError;

/// Core error.
#[derive(Debug)]
pub enum Error {
    /// An operator-facing refusal or explanation.
    User(String),
    /// Filesystem failure.
    Io(io::Error),
    /// A malformed env record.
    Env(EnvError),
    /// A malformed NDJSON file.
    Ndjson(NdjsonError),
}

impl Error {
    /// Build an operator-facing error.
    pub fn user(msg: impl Into<String>) -> Self {
        Error::User(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::User(m) => f.write_str(m),
            Error::Io(e) => write!(f, "{e}"),
            Error::Env(e) => write!(f, "{e}"),
            Error::Ndjson(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<EnvError> for Error {
    fn from(e: EnvError) -> Self {
        Error::Env(e)
    }
}

impl From<NdjsonError> for Error {
    fn from(e: NdjsonError) -> Self {
        Error::Ndjson(e)
    }
}

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// `fail!("...")` builds an `Err(Error::User(format!(...)))`.
#[macro_export]
macro_rules! fail {
    ($($arg:tt)*) => { return Err($crate::error::Error::User(format!($($arg)*))) };
}

/// `user_err!("...")` builds the error value without returning.
#[macro_export]
macro_rules! user_err {
    ($($arg:tt)*) => { $crate::error::Error::User(format!($($arg)*)) };
}
