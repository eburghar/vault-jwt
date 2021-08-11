use std::time::{SystemTime, Duration};

#[derive(Debug)]
pub struct Lease {
	/// start of the Lease
	pub time: SystemTime,
	/// duration of the lease
	pub lease_duration: Duration,
	/// renew delay
	pub renew_delay: Duration
}

impl Lease {
	pub fn new(dur: Duration) -> Self {
		Self {
			time: SystemTime::now(),
			lease_duration: dur,
			renew_delay: dur * 2 / 3
		}
	}

	/// returns true if the lease is still valid
	pub fn is_valid(&self) -> bool {
		// TODO: replace with .is_zero() when stable
		self.lease_duration != Duration::from_secs(0) && SystemTime::now() < self.time + self.lease_duration
	}

	/// returns true if the lease is about to expire
	pub fn to_renew(&self) -> bool {
		// TODO: replace with .is_zero() when stable
		self.lease_duration != Duration::from_secs(0) && SystemTime::now() > self.time + self.renew_delay
	}
}
