use crate::{
	error::{Error, Result},
	secret::SecretPath,
};

use std::{convert::TryFrom, fmt::Display};

/// States of finite state machine for parsing secretpath
enum Pos {
	Backend,
	Args,
	Path,
}

/// Iterator, that returns the 3 successives slices separated by a colon from an expression
/// backend:args:path. backend and args can't contain ':' and there is no escaping mechanism
pub struct SecretPathIterator<'a> {
	remainder: &'a str,
	pos: Pos,
}

impl<'a> SecretPathIterator<'a> {
	pub fn new(s: &'a str) -> Self {
		Self {
			remainder: s,
			pos: Pos::Backend,
		}
	}

	/// simply return remainder
	pub fn yield_remainder(&mut self) -> Option<&'a str> {
		let remainder = self.remainder;
		if self.remainder.is_empty() {
			None
		} else {
			self.remainder = "";
			Some(remainder)
		}
	}

	/// returns the slice up to ':' and advances after the ':'
	pub fn yield_colon(&mut self) -> Option<&'a str> {
		match self.remainder.find(":") {
			Some(pos) => {
				let res = &self.remainder[..pos];
				self.remainder = if pos + 1 < self.remainder.len() {
					&self.remainder[pos + 1..]
				} else {
					""
				};
				Some(res)
			}
			None => None,
		}
	}
}

impl<'a> Iterator for SecretPathIterator<'a> {
	type Item = &'a str;

	fn next(&mut self) -> Option<Self::Item> {
		if self.remainder.is_empty() {
			None
		} else {
			match self.pos {
				Pos::Backend => {
					self.pos = Pos::Args;
					self.yield_colon()
				}
				Pos::Args => {
					self.pos = Pos::Path;
					self.yield_colon()
				}
				Pos::Path => self.yield_remainder(),
			}
		}
	}
}

/// Simple SecretPath parser: backend:arg_1(,arg_n)*(,key_n=val_n):path:jsonpointer
impl<'a, T> TryFrom<&'a str> for SecretPath<'a, T>
where
	T: TryFrom<&'a str> + Display,
{
	type Error = Error;

	fn try_from(path: &'a str) -> Result<Self> {
		// split all path components
		let mut it = SecretPathIterator::new(path);
		let backend_str = it.next().ok_or(Error::NoBackend)?;
		let backend =
			T::try_from(backend_str).map_err(|_| Error::UnknowBackend(backend_str.to_owned()))?;
		let args_ = it.next().ok_or(Error::NoArgs(path.to_owned()))?;
		let path_anchor = it.next().ok_or(Error::NoPath(args_.to_owned()))?;
		let (path, anchor) = if let Some(i) = path_anchor.rfind("#") {
			let anchor = if i + 1 == path_anchor.len() {
				""
			} else {
				&path_anchor[i + 1..]
			};
			(&path_anchor[..i], Some(anchor))
		} else {
			(path_anchor, None)
		};
		// split simple and keyword arguments in separate lists
		let mut args = Vec::with_capacity(args_.len());
		let mut kwargs = Vec::with_capacity(args_.len());
		for arg in args_.split(",") {
			if let Some(pos) = arg.find('=') {
				kwargs.push((&arg[..pos], &arg[pos + 1..]));
			} else {
				args.push(arg);
			}
		}

		Ok(Self {
			backend,
			args,
			kwargs: if kwargs.is_empty() {
				None
			} else {
				Some(kwargs)
			},
			path_anchor,
			path,
			anchor,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Basic implementation of a Backend for test purposes
	#[derive(Debug, PartialEq)]
	enum Backend {
		Vault,
		Const,
	}

	impl Display for Backend {
		fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			match self {
				Backend::Vault => write!(f, "vault"),
				Backend::Const => write!(f, "const"),
			}
		}
	}

	impl<'a> TryFrom<&'a str> for Backend {
		type Error = Error;

		fn try_from(value: &'a str) -> Result<Self> {
			if value == "vault" {
				Ok(Backend::Vault)
			} else if value == "const" {
				Ok(Backend::Const)
			} else {
				Err(Error::UnknowBackend(value.to_owned()))
			}
		}
	}

	#[test]
	fn parse_anchor() {
		let path = "vault:role,POST,common_name=example.com:pki/issue/example.com#/data";
		let secret_path = SecretPath::try_from(path).unwrap();
		assert_eq!(
			secret_path,
			SecretPath {
				backend: Backend::Vault,
				args: vec!["role", "POST"],
				kwargs: Some(vec![("common_name", "example.com")]),
				path_anchor: "pki/issue/example.com#/data",
				path: "pki/issue/example.com",
				anchor: Some("/data")
			}
		);
	}

	#[test]
	fn parse_const_str() {
		let path = "const:str:https://localhost:8200#";
		let secret_path = SecretPath::try_from(path).unwrap();
		assert_eq!(
			secret_path,
			SecretPath {
				backend: Backend::Const,
				args: vec!["str"],
				kwargs: None,
				path_anchor: "https://localhost:8200#",
				path: "https://localhost:8200",
				anchor: Some("")
			}
		);
	}

	#[test]
	fn parse_const_json() {
		let path = r#"const:js:{"key": "val"}"#;
		let secret_path = SecretPath::try_from(path).unwrap();
		assert_eq!(
			secret_path,
			SecretPath {
				backend: Backend::Const,
				args: vec!["js"],
				kwargs: None,
				path_anchor: r#"{"key": "val"}"#,
				path: r#"{"key": "val"}"#,
				anchor: None
			}
		);
	}

	#[test]
	/// assert that we can serialize and deserialize a secret path
	fn secret_path_from_str() {
		assert_eq!(
			SecretPath::<Backend>::try_from("vault:arg1,arg2,cn=test:comp1/comp2/comp3#anchor")
				.unwrap()
				.to_string(),
			"vault:arg1,arg2,cn=test:comp1/comp2/comp3#anchor"
		)
	}
}
