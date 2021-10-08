use crate::lease::Lease;

use std::time::Duration;

/// tie an auth token to a lease
#[derive(Debug)]
pub struct Auth {
	pub client_token: String,
	pub lease: Option<Lease>,
}

impl Auth {
	/// create new Auth with an optional duration
	pub fn new(token: &str, dur: Option<Duration>) -> Self {
		Self {
			client_token: token.to_owned(),
			lease: dur.and_then(|dur| Some(Lease::new(dur))),
		}
	}

	/// check if the token is still valid
	pub fn is_valid(&self) -> bool {
		!self.client_token.is_empty() && self.lease.is_none()
			|| self.lease.as_ref().filter(|l| l.is_valid()).is_some()
	}

	/// check if the token needs a renewal
	pub fn to_renew(&self) -> bool {
		self.lease.as_ref().filter(|l| l.to_renew()).is_some()
	}

	pub fn duration(&self) -> Option<Duration> {
		self.lease.as_ref().and_then(|l| Some(l.lease_duration))
	}

	pub fn renew_delay(&self) -> Option<Duration> {
		self.lease.as_ref().and_then(|l| Some(l.renew_delay))
	}
}

#[test]
fn empty_token_is_invalid() {
	let auth = Auth::new("", None);
	assert_eq!(auth.is_valid(), false);
}
