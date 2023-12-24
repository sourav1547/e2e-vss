use bincode::{DefaultOptions, Options};
use bincode::config::{Bounded, WithOtherLimit};
use lazy_static::lazy_static;

mod cache;
mod sender;
mod receiver;
pub mod manager;
mod listener;
mod messages;
pub mod statistics;

pub const CHANNEL_LIMIT: usize = 10_000;
const BINCODE_BYTE_LIMIT: u64 = 1_024 * 1_024 * 8;  // bytes
const SENDER_BUFFER_LIMIT: usize = 100;
const SENDER_BACKOFF_BASE: u64 = 500;  // ms
const SENDER_BACKOFF_MAX_DELAY: Option<u64> = Some(300_000);  // ms

lazy_static! {
    static ref BINCODE: WithOtherLimit<DefaultOptions, Bounded> = bincode::DefaultOptions::new().with_limit(BINCODE_BYTE_LIMIT);
}