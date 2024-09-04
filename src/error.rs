use std::{error, fmt, io};

#[derive(Debug)]
pub struct Error(pub String);

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self(value.to_string())
    }
}
