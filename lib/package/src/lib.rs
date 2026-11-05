#[macro_use]
#[cfg(all(test, feature = "authoring"))]
mod macros;

mod error;

#[cfg(feature = "acquisition")]
pub mod http;
#[cfg(feature = "acquisition")]
pub mod resolver;

#[cfg(feature = "authoring")]
pub use error::AuthoringError;
pub use error::WasmerPackageError;

#[cfg(feature = "authoring")]
pub mod convert;
#[cfg(feature = "authoring")]
pub mod package;
#[cfg(feature = "execution")]
pub mod utils;
