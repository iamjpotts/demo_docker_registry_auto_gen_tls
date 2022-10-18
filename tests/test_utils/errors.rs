use std::string::FromUtf8Error;

#[derive(Debug, thiserror::Error)]
pub enum TestUtilsError {

    #[error("Hyper error: {0}")]
    Hyper(hyper::Error),

    #[error("Hyper http error: {0}")]
    HyperHttp(hyper::http::Error),

    #[error("UTF8 parse error: {0}")]
    Utf8(FromUtf8Error)
}

impl From<hyper::Error> for TestUtilsError {
    fn from(other: hyper::Error) -> Self {
        Self::Hyper(other)
    }
}

impl From<hyper::http::Error> for TestUtilsError {
    fn from(other: hyper::http::Error) -> Self {
        Self::HyperHttp(other)
    }
}

impl From<FromUtf8Error> for TestUtilsError {
    fn from(other: FromUtf8Error) -> Self {
        Self::Utf8(other)
    }
}
