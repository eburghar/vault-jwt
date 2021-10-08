use isahc::http::StatusCode;
#[cfg(feature = "nom")]
use nom::error::ErrorKind;
use serde::Deserialize;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error("not logged to vault server")]
	NotLogged,
	#[error("http error code {0}\n{1}")]
	VaultError(StatusCode, String),
	#[error("token error")]
	TokenError {
		#[from]
		source: std::io::Error,
	},
	#[error(transparent)]
	HttpError {
		#[from]
		source: isahc::http::Error,
	},
	#[error("client error")]
	ClientError {
		#[from]
		source: isahc::error::Error,
	},
	#[error("response parse error")]
	ParseError {
		#[from]
		source: serde_json::error::Error,
	},
	#[error("unable to get vault mount")]
	MountsNotFound,
	#[error("undefined mount type {0}")]
	UndefinedMountType(String),
	#[error("unknown backend \"{0}\"")]
	UnknowBackend(String),
	#[error("missing the backend argument")]
	NoBackend,
	#[error("missing a \":\" to separate backend from arguments \"{0}\"")]
	NoArgs(String),
	#[error("missing a \":\" to separate arguments from path \"{0}\"")]
	NoPath(String),
	#[cfg(feature = "nom")]
	#[error("extra data after path \"{0}\"")]
	ExtraData(String),
	#[cfg(feature = "nom")]
	#[error("error with {} somewhere in \"{0}\"", .1.description())]
	Nom(String, ErrorKind),
	#[cfg(feature = "nom")]
	#[error("incomplete data")]
	Incomplete,
}

/// Vault errors deserialized
#[derive(Debug, Deserialize)]
pub struct VaultErrors {
	pub errors: Vec<String>,
}
