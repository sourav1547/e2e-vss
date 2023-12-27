pub mod simple_acss;
pub mod yurek_acss;
pub mod low_ed_acss;
pub mod sigs;
pub mod messages;
pub mod keys;
pub mod public_parameters;
pub mod common;

pub enum NiVSSError {
    /// Struct to be signed does not serialize correctly.
    DealingError,
}