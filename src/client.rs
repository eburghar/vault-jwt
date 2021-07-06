use crate::error::{Error, Result};

use isahc::{
	config::{CaCertificate, Configurable},
	http::{Request, StatusCode},
	AsyncReadResponseExt, HttpClient,
};
use serde::Deserialize;
use serde_json::Value;
use std::{
	collections::HashMap,
	fs::File,
	io::Read,
	time::{Duration, SystemTime},
};

/// Keep token from vault login response
#[derive(Debug, Deserialize)]
pub struct Auth {
	/// token used with all api calls
	pub client_token: String,
	/// the validity of the token counting from time
	pub lease_duration: Duration,
	/// if the token needs refresh
	pub renewable: bool,
	/// time of the successful login
	pub time: SystemTime,
}

impl Auth {
	/// check if the token is still valid
	pub fn is_valid(&self) -> bool {
		self.client_token != "" && SystemTime::now() < self.time + self.lease_duration
	}

	/// check if the token needs a renewal
	pub fn to_renew(&self) -> bool {
		self.client_token != ""
			&& self.renewable
			&& SystemTime::now() > self.time + self.lease_duration * 2 / 3
	}
}

/// Vault errors deserialized
#[derive(Debug, Deserialize)]
struct VaultErrors {
	errors: Vec<String>,
}

/// Vault client that cache its auth tokens
pub struct VaultClient {
	pub url: String,
	jwt: String,
	client: HttpClient,
	/// map a role to an authentification token
	pub auth: HashMap<String, Auth>,
}

impl VaultClient {
	/// Create a new vault client given an url, a token path and a ca certificate path
	pub async fn new(url: &str, token: &str, cacert: &str) -> Result<Self> {
		let mut jwt = String::new();
		File::open(token)
			.map_err(|e| Error::TokenError { source: e })?
			.read_to_string(&mut jwt)
			.map_err(|e| Error::TokenError { source: e })?;
		let client = HttpClient::builder()
			.ssl_ca_certificate(CaCertificate::file(cacert))
			.default_header("Content-Type", "application/json")
			.build()?;
		Ok(VaultClient {
			url: url.to_owned(),
			jwt,
			client,
			auth: HashMap::new(),
		})
	}

	/// Log in to the vault client and return Auth.
	pub async fn login(&mut self, role: &str) -> Result<&Auth> {
		// login if we are not already logged in or if it's time to renew token
		let do_login = self
			.auth
			.get(role)
			.filter(|v| v.is_valid() && !v.to_renew())
			.is_none();

		if do_login {
			let url = format!("{}/auth/kubernetes/login", &self.url);
			let body = format!(r#"{{"role": "{}", "jwt": "{}"}}"#, role, &self.jwt);
			let mut res = self
				.client
				.post_async(url, body)
				.await
				.map_err(|e| Error::ClientError { source: e })?;
			let status = res.status();
			if status == StatusCode::OK {
				// parse vault response and cache important information
				let auth_value: Value = res
					.json()
					.await
					.map_err(|e| Error::ParseError { source: e })?;
				let lease_duration = auth_value["auth"]["lease_duration"]
					.as_u64()
					.unwrap_or(0u64);
				let renewable = auth_value["auth"]["renewable"].as_bool().unwrap_or(false);
				let auth = Auth {
					client_token: auth_value["auth"]["client_token"]
						.as_str()
						.unwrap_or("")
						.to_owned(),
					lease_duration: Duration::from_secs(lease_duration),
					renewable,
					time: SystemTime::now(),
				};
				// insert and forget old value if any
				let _ = self.auth.insert(role.to_owned(), auth);
			} else {
				// parse vault error
				let errors: VaultErrors = res
					.json()
					.await
					.map_err(|e| Error::ParseError { source: e })?;
				return Err(Error::VaultError(status, errors.errors.join("\n")));
			}
		}

		Ok(self.auth.get(role).unwrap())
	}

	/// Get a secret from vault server and reschedule a renew with role if necessary
	pub async fn get_secret(&self, role: &str, path: &str) -> Result<Value> {
		if let Some(auth) = self.auth.get(role) {
			let url = format!("{}/{}", &self.url, path);
			let request = Request::get(url)
				.header("X-Vault-Token", auth.client_token.as_str())
				.body(())
				.map_err(|e| Error::HttpError { source: e })?;
			let mut res = self
				.client
				.send_async(request)
				.await
				.map_err(|e| Error::ClientError { source: e })?;
			let status = res.status();
			return if status == StatusCode::OK {
				// parse vault response
				let secret_value: Value = res
					.json()
					.await
					.map_err(|e| Error::ParseError { source: e })?;

				// return the parsed secret
				Ok(secret_value)
			} else {
				// parse vault error
				let errors: VaultErrors = res
					.json()
					.await
					.map_err(|e| Error::ParseError { source: e })?;
				Err(Error::VaultError(status, errors.errors.join("\n")))
			};
		} else {
			Err(Error::NotLogged)
		}
	}
}
