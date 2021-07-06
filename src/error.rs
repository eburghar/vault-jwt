use isahc::http::StatusCode;

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
}
