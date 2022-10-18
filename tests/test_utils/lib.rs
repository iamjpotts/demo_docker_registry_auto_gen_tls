use std::fmt::Display;

pub mod cert_gen;
pub mod errors;
pub mod images;

pub fn random_name<S: Into<String> + Display>(prefix: S) -> String {
    let suffix: u64 = rand::random();
    format!("{}_{}", prefix, suffix)
}