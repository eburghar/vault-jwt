use crate::lease::Lease;

use serde_json::Value;
use std::{convert::TryFrom, fmt, time::Duration};

/// A secret is a json value tied to an optional lease
#[derive(Debug)]
pub struct Secret {
	pub value: Value,
	lease: Option<Lease>,
}

impl Secret {
	/// create a secret with an optional duration
	pub fn new(value: Value, dur: Option<Duration>) -> Self {
		Self {
			value,
			lease: dur.and_then(|dur| Some(Lease::new(dur))),
		}
	}

	/// check if the secret is valid
	pub fn is_valid(&self) -> bool {
		self.lease.is_none() || self.lease.as_ref().filter(|l| l.is_valid()).is_some()
	}

	pub fn has_lease(&self) -> bool {
		return match self.lease {
			// TODO: replace with .is_zero() when stable
			Some(ref lease) if lease.lease_duration != Duration::from_secs(0) => true,
			_ => false,
		};
	}

	/// check if the secret need to be renewed
	pub fn to_renew(&self) -> bool {
		self.lease.as_ref().filter(|l| l.to_renew()).is_some()
	}

	pub fn duration(&self) -> Option<Duration> {
		self.lease.as_ref().and_then(|l| {
			if l.lease_duration != Duration::from_secs(0) {
				Some(l.lease_duration)
			} else {
				None
			}
		})
	}

	pub fn renew_delay(&self) -> Option<Duration> {
		self.lease.as_ref().and_then(|l| {
			if l.renew_delay != Duration::from_secs(0) {
				Some(l.renew_delay)
			} else {
				None
			}
		})
	}
}

/// Compare secret by their inner value
impl PartialEq for Secret {
	fn eq(&self, other: &Self) -> bool {
		self.value == other.value
	}
}

/// Deserialize a SecretPath
#[derive(PartialEq, Debug)]
pub struct SecretPath<'a, T>
where
	T: TryFrom<&'a str> + fmt::Display,
{
	pub backend: T,
	pub args: Vec<&'a str>,
	pub kwargs: Option<Vec<(&'a str, &'a str)>>,
	pub full_path: &'a str,
	pub path: &'a str,
	pub anchor: Option<&'a str>,
}

/// Serialize a SecretPath
impl<'a, T> fmt::Display for SecretPath<'a, T>
where
	T: TryFrom<&'a str> + fmt::Display,
{
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}:", self.backend)?;
		write!(f, "{}", self.args.join(","))?;
		if let Some(ref kwargs) = self.kwargs {
			for (k, v) in kwargs.iter() {
				write!(f, ",{}={}", k, v)?;
			}
		}
		write!(f, ":{}", self.full_path)
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn without_lease_is_valid() {
		let secret = Secret::new(Value::String("secret".to_owned()), None);
		assert_eq!(secret.is_valid(), true)
	}

	#[test]
	fn without_lease_needs_no_renew() {
		let secret = Secret::new(Value::String("secret".to_owned()), None);
		assert_eq!(secret.to_renew(), false)
	}

	#[test]
	fn with_valid_lease_is_valid() {
		let secret = Secret::new(
			Value::String("secret".to_owned()),
			Some(Duration::from_secs(10)),
		);
		assert_eq!(secret.is_valid(), true)
	}

	#[test]
	fn with_expired_lease_is_invalid() {
		let secret = Secret::new(
			Value::String("secret".to_owned()),
			Some(Duration::from_secs(0)),
		);
		assert_eq!(secret.is_valid(), false)
	}
}
