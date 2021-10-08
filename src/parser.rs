use crate::{
	error::{Error, Result},
	secret::SecretPath,
};

use nom::{
	branch::alt,
	bytes::complete::{is_not, tag},
	character::complete::alpha1,
	combinator::{map, map_res, opt, recognize, rest},
	error::{ErrorKind, FromExternalError, ParseError},
	multi::{many1, separated_list1},
	sequence::{separated_pair, terminated, tuple, preceded},
	Err,
};
use std::{
	convert::TryFrom,
	fmt::{self, Display},
};

/// define our own IResult as we only parse &str and return Error in case of error
type IResult<'a, Output> = nom::IResult<&'a str, Output, Error>;

/// Mandatory trait to be used as error type in IResult
impl<'a> ParseError<&'a str> for Error {
	fn from_error_kind(input: &'a str, kind: ErrorKind) -> Self {
		Error::Nom(input.to_owned(), kind)
	}

	fn append(_input: &'a str, _kind: ErrorKind, other: Self) -> Self {
		other
	}
}

/// Mandatory trait when the type is returned in map_res fn.
/// Certainly a missing default of implementation when ExternalError is Self
impl<'a> FromExternalError<&'a str, Self> for Error {
	fn from_external_error(_input: &'a str, _kind: ErrorKind, e: Self) -> Self {
		e
	}
}

/// Convert a nom Err to Error
impl From<Err<Error>> for Error {
	fn from(e: Err<Error>) -> Self {
		match e {
			Err::Incomplete(_) => Error::Incomplete,
			Err::Error(e) | Err::Failure(e) => e,
		}
	}
}

#[derive(Debug, PartialEq, Eq)]
pub enum Arg<'a> {
	Arg(&'a str),
	KwArg((&'a str, &'a str)),
}

impl<'a> Display for Arg<'a> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Arg::Arg(s) => write!(f, "{}", s),
			Arg::KwArg((k, v)) => write!(f, "{}={}", k, v),
		}
	}
}

/// Args is a list of Arg
type Args<'a> = Vec<Arg<'a>>;

/// Deserialize a SecretPath
impl<'a, T> TryFrom<&'a str> for SecretPath<'a, T>
where
	T: TryFrom<&'a str> + Display,
	Error: FromExternalError<&'a str, T::Error>,
{
	type Error = Error;

	/// Build a SecretPath from a reference of a String
	fn try_from(path: &'a str) -> Result<Self> {
		if path.is_empty() {
			Err(Error::NoBackend)?;
		}
		let (rest, (backend, args, path, anchor)) = secret_path(path)?;
		if !rest.is_empty() {
			Err(Error::ExtraData(rest.to_owned()))?;
		}
		let (args, kwargs) = splitargs(args);
		Ok(Self {
			backend,
			args,
			kwargs,
			path,
			anchor
		})
	}
}

fn no_args(input: &str) -> IResult<&str> {
	Err(Err::Failure(Error::NoArgs(input.to_owned())))
}

fn no_path(input: &str) -> IResult<&str> {
	Err(Err::Failure(Error::NoPath(input.to_owned())))
}

/// parse a literal which is anything that is not a delimiter of other token
fn literal(input: &str) -> IResult<&str> {
	recognize(many1(is_not(":,=")))(input)
}

fn path(input: &str) -> IResult<&str> {
	recognize(many1(is_not("#")))(input)
}

/// parse a backend a convert to the Backend enum
fn backend<'a, T>(input: &'a str) -> IResult<T>
where
	T: TryFrom<&'a str> + Display,
	Error: FromExternalError<&'a str, T::Error>,
{
	map_res(alpha1, T::try_from)(input)
}

/// parse a keyword argument
fn kwarg(input: &str) -> IResult<Arg> {
	map(separated_pair(literal, tag("="), literal), Arg::KwArg)(input)
}

// parse a simple argument
/// a token is a literal or a variable
fn arg(input: &str) -> IResult<Arg> {
	map(literal, Arg::Arg)(input)
}

/// One or more tokens
fn arg1(input: &str) -> IResult<Args> {
	separated_list1(tag(","), alt((kwarg, arg)))(input)
}

/// separate argurments into simple and keyword arguments
fn splitargs(args: Args) -> (Vec<&str>, Option<Vec<(&str, &str)>>) {
	let mut args_: Vec<&str> = Vec::with_capacity(args.len());
	let mut kwargs_: Vec<(&str, &str)> = Vec::with_capacity(args.len());
	for arg in args.into_iter() {
		match arg {
			Arg::Arg(s) => args_.push(s),
			Arg::KwArg(ss) => kwargs_.push(ss),
		}
	}
	(
		args_,
		if kwargs_.is_empty() {
			None
		} else {
			Some(kwargs_)
		},
	)
}

/// parse the secret path which has the folowing structure
/// backend:arg1,arg2,k1=v1,k2=v2:path
fn secret_path<'a, T>(input: &'a str) -> IResult<(T, Args, &str, Option<&str>)>
where
	T: TryFrom<&'a str> + Display,
	Error: FromExternalError<&'a str, T::Error>,
{
	tuple((
		terminated(backend, alt((tag(":"), no_args))),
		terminated(arg1, alt((tag(":"), no_path))),
		path,
		opt(preceded(tag("#"), rest)),
	))(input)
}

#[cfg(test)]
mod test {
	use super::*;

	/// Basic implementation of a Backend for test purposes
	#[derive(Debug, PartialEq)]
	enum Backend {
		Vault,
	}

	impl Display for Backend {
		fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
			write!(f, "vault")
		}
	}

	impl<'a> TryFrom<&'a str> for Backend {
		type Error = Error;

		fn try_from(value: &'a str) -> Result<Self> {
			if value == "vault" {
				Ok(Backend::Vault)
			} else {
				Err(Error::UnknowBackend(value.to_owned()))
			}
		}
	}

	#[test]
	/// test backend convertion from &str
	fn backend_parse() {
		assert_eq!(backend("vault:").unwrap(), (":", Backend::Vault));
	}

	#[test]
	/// test parsing of positional arguments
	fn parse_args() {
		assert_eq!(
			arg1("test,role").unwrap(),
			("", vec![Arg::Arg("test"), Arg::Arg("role")])
		);
	}

	#[test]
	/// test parsing of keywords arguments
	fn parse_kwargs() {
		assert_eq!(
			arg1("role,cn=test").unwrap(),
			("", vec![Arg::Arg("role"), Arg::KwArg(("cn", "test"))])
		)
	}

	#[test]
	/// test parsing of secret path with only positional arguments and no anchor
	fn secret_path_parse() {
		assert_eq!(
			secret_path("vault:arg1,arg2:comp1/comp2/comp3").unwrap(),
			(
				"",
				(
					Backend::Vault,
					vec![Arg::Arg("arg1"), Arg::Arg("arg2")],
					"comp1/comp2/comp3",
					None
				)
			)
		);
	}

	#[test]
	/// assert that path can contain colon
	fn secret_path_parse_colon() {
		assert_eq!(
			secret_path("vault:arg1,arg2:comp1/comp2:comp3").unwrap(),
			(
				"",
				(
					Backend::Vault,
					vec![Arg::Arg("arg1"), Arg::Arg("arg2")],
					"comp1/comp2:comp3",
					None
				)
			)
		);
	}

	#[test]
	/// test parsing of secret path with only positional arguments and anchor
	fn secret_path_with_anchor() {
		assert_eq!(
			secret_path("vault:arg1,arg2:comp1/comp2:comp3#anchor").unwrap(),
			(
				"",
				(
					Backend::Vault,
					vec![Arg::Arg("arg1"), Arg::Arg("arg2")],
					"comp1/comp2:comp3",
					Some("anchor")
				)
			)
		);
	}

	#[test]
	/// test secret path with positional arguments, keywords arguments and anchor
	fn secret_path_kw_parse() {
		assert_eq!(
			secret_path("vault:arg1,arg2,cn=test:comp1/comp2/comp3#anchor").unwrap(),
			(
				"",
				(
					Backend::Vault,
					vec![
						Arg::Arg("arg1"),
						Arg::Arg("arg2"),
						Arg::KwArg(("cn", "test"))
					],
					"comp1/comp2/comp3",
					Some("anchor")
				)
			)
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
