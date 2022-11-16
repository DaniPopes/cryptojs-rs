//! # cryptojs-rs
//!
//! CryptoJS equivalents in Rust
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use base64::DecodeError;
use core::{convert::From, fmt};

mod encrypted_value;
pub use encrypted_value::EncryptedValue;

mod evpkdf;
pub use evpkdf::evpkdf;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidPassword,
    InvalidInput,
    InvalidSalt,
    DecodeError(DecodeError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPassword => write!(f, "Invalid password"),
            Self::InvalidInput => write!(f, "Invalid input"),
            Self::InvalidSalt => write!(f, "Invalid salt"),
            Self::DecodeError(inner) => write!(f, "Failed decoding base64: {inner}"),
        }
    }
}

impl From<DecodeError> for Error {
    fn from(value: DecodeError) -> Self {
        Self::DecodeError(value)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
