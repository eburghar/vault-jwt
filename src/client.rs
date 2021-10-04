use crate::{
	auth::Auth,
	error::{Error, Result, VaultErrors},
	secret::Secret,
};

use isahc::{
	config::{CaCertificate, Configurable},
	http::{Request, StatusCode},
	AsyncReadResponseExt, HttpClient, ReadResponseExt,
};
use serde_json::{Map, Value};
use std::{collections::HashMap, time::Duration};

/// Vault client that cache its auth tokens
#[derive(Debug)]
pub struct VaultClient {
	pub url: String,
	login_path: String,
	jwt: String,
	client: HttpClient,
	/// map a role to an authentification token
	pub auth: HashMap<String, Auth>,
}

impl VaultClient {
	/// Create a new vault client given an url, a jwt token and a ca certificate path
	pub fn new(url: &str, login_path: &str, jwt: &str, cacert_path: Option<&str>) -> Result<Self> {
		let mut builder = HttpClient::builder().default_header("Content-Type", "application/json");
		if let Some(cacert) = cacert_path {
			builder = builder.ssl_ca_certificate(CaCertificate::file(cacert));
		}
		let client = builder.build()?;
		Ok(VaultClient {
			url: url.to_owned(),
			login_path: login_path.to_owned(),
			jwt: jwt.to_owned(),
			client,
			auth: HashMap::new(),
		})
	}

	pub fn is_logged(&self, role: &str) -> bool {
		self.auth
			.get(role)
			.filter(|v| v.is_valid() && !v.to_renew())
			.is_some()
	}

	/// Log in to the vault client and return Auth.
	pub fn login(&mut self, role: &str) -> Result<&Auth> {
		if !self.is_logged(role) {
			let url = format!("{}{}", &self.url, &self.login_path);
			let body = format!(r#"{{"role": "{}", "jwt": "{}"}}"#, role, &self.jwt);
			let mut res = self
				.client
				.post(url, body)
				.map_err(|e| Error::ClientError { source: e })?;
			let status = res.status();
			if status == StatusCode::OK {
				// parse vault response and cache important information
				let auth_value: Value = res.json().map_err(|e| Error::ParseError { source: e })?;
				let lease_duration = auth_value["auth"]["lease_duration"]
					.as_u64()
					.unwrap_or(0u64);
				let renewable = auth_value["auth"]["renewable"].as_bool().unwrap_or(false);
				let auth = Auth::new(
					auth_value["auth"]["client_token"].as_str().unwrap_or(""),
					if renewable {
						Some(Duration::from_secs(lease_duration))
					} else {
						None
					},
				);
				// insert and forget old value if any
				let _ = self.auth.insert(role.to_owned(), auth);
			} else {
				// parse vault error
				let errors: VaultErrors =
					res.json().map_err(|e| Error::ParseError { source: e })?;
				return Err(Error::VaultError(status, errors.errors.join("\n")));
			}
		}

		Ok(self.auth.get(role).unwrap())
	}

	/// Log in asynchronously to the vault client and return Auth.
	pub async fn login_async(&mut self, role: &str) -> Result<&Auth> {
		// login if we are not already logged in or if it's time to renew token

		if !self.is_logged(role) {
			let url = format!("{}{}", &self.url, &self.login_path);
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
				let auth = Auth::new(
					auth_value["auth"]["client_token"].as_str().unwrap_or(""),
					if renewable {
						Some(Duration::from_secs(lease_duration))
					} else {
						None
					},
				);
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
	pub fn get_secret(
		&self,
		role: &str,
		method: &str,
		path: &str,
		kwargs: Option<&Vec<(&str, &str)>>,
	) -> Result<Secret> {
		if let Some(auth) = self.auth.get(role) {
			let uri = format!("{}/{}", &self.url, path);
			// transform the kwargs into a json object
			let body = kwargs
				.map(|kwargs| {
					kwargs.iter().fold(Map::new(), |mut m, (k, v)| {
						m.insert((*k).to_owned(), Value::String((*v).to_owned()));
						m
					})
				})
				.map(|o| Value::Object(o))
				.unwrap_or(Value::Null);
			// build the request
			let request = Request::builder()
				.uri(uri)
				.method(method)
				.header("X-Vault-Token", auth.client_token.as_str())
				.body(body.to_string())
				.map_err(|e| Error::HttpError { source: e })?;
			// async send the request
			let mut res = self
				.client
				.send(request)
				.map_err(|e| Error::ClientError { source: e })?;
			// handle the response
			let status = res.status();
			return if status == StatusCode::OK {
				// parse vault response
				let mut secret_value: Value =
					res.json().map_err(|e| Error::ParseError { source: e })?;

				let duration = secret_value
					.get("lease_duration")
					.map(|o| o.as_u64().unwrap_or(0u64))
					.filter(|o| *o != 0u64)
					.map(|o| Duration::from_secs(o * 2 / 3));
				// return the parsed secret (only the data part)
				Ok(Secret::new(secret_value["data"].take(), duration))
			} else {
				// parse vault error
				let errors: VaultErrors =
					res.json().map_err(|e| Error::ParseError { source: e })?;
				Err(Error::VaultError(status, errors.errors.join("\n")))
			};
		} else {
			Err(Error::NotLogged)
		}
	}

	/// Get a secret asynchronously from vault server and reschedule a renew with role if necessary
	pub async fn get_secret_async(
		&self,
		role: &str,
		method: &str,
		path: &str,
		kwargs: Option<&Vec<(&str, &str)>>,
	) -> Result<Secret> {
		if let Some(auth) = self.auth.get(role) {
			let uri = format!("{}/{}", &self.url, path);
			// transform the kwargs into a json object
			let body = kwargs
				.map(|kwargs| {
					kwargs.iter().fold(Map::new(), |mut m, (k, v)| {
						m.insert((*k).to_owned(), Value::String((*v).to_owned()));
						m
					})
				})
				.map(|o| Value::Object(o))
				.unwrap_or(Value::Null);
			// build the request
			let request = Request::builder()
				.uri(uri)
				.method(method)
				.header("X-Vault-Token", auth.client_token.as_str())
				.body(body.to_string())
				.map_err(|e| Error::HttpError { source: e })?;
			// async send the request
			let mut res = self
				.client
				.send_async(request)
				.await
				.map_err(|e| Error::ClientError { source: e })?;
			// handle the response
			let status = res.status();
			return if status == StatusCode::OK {
				// parse vault response
				let mut secret_value: Value = res
					.json()
					.await
					.map_err(|e| Error::ParseError { source: e })?;

				let duration = secret_value
					.get("lease_duration")
					.map(|o| o.as_u64().unwrap_or(0u64))
					.filter(|o| *o != 0u64)
					.map(|o| Duration::from_secs(o * 2 / 3));
				// return the parsed secret (only the data part)
				Ok(Secret::new(secret_value["data"].take(), duration))
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

	/// Return a hashmap of mountpoints and backend type concatenated with `options.version` if present
	/// the given role should have read access to vault api /sys/mounts
	pub fn get_mounts(&self, role: &str) -> Result<HashMap<String, String>> {
		if let Some(auth) = self.auth.get(role) {
			let uri = format!("{}/sys/mounts", &self.url);
			let request = Request::builder()
				.uri(uri)
				.method("GET")
				.header("X-Vault-Token", auth.client_token.as_str())
				.body(())
				.map_err(|e| Error::HttpError { source: e })?;
			let mut res = self
				.client
				.send(request)
				.map_err(|e| Error::ClientError { source: e })?;
			let status = res.status();
			return if status == StatusCode::OK {
				// parse vault response
				let mounts_value: Value =
					res.json().map_err(|e| Error::ParseError { source: e })?;

				if let Some(Value::Object(map)) = mounts_value.get("data") {
					let mut mounts = HashMap::new();
					for (mount_point, mount) in map.iter() {
						let mount_type = mount
							.get("type")
							.and_then(|v| v.as_str())
							.ok_or_else(|| Error::UndefinedMountType(mount_point.to_owned()))?;
						let mount_version = mount
							.get("options")
							.and_then(|v| v.get("version"))
							.and_then(|v| v.as_str());
						mounts.insert(
							mount_point.to_owned(),
							mount_version
								.and_then(|s| Some(mount_type.to_owned() + s))
								.or(Some(mount_type.to_owned()))
								.unwrap(),
						);
					}
					Ok(mounts)
				} else {
					Err(Error::MountsNotFound)
				}
			} else {
				// parse vault error
				let errors: VaultErrors =
					res.json().map_err(|e| Error::ParseError { source: e })?;
				Err(Error::VaultError(status, errors.errors.join("\n")))
			};
		} else {
			Err(Error::NotLogged)
		}
	}
}
