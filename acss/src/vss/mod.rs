pub mod acss;
pub mod simple_acss;
pub mod messages;
pub mod keys;
pub mod public_parameters;
pub mod common;

pub enum NiVSSError {
    /// Struct to be signed does not serialize correctly.
    DealingError,
}