use std::collections::HashMap;
use std::fmt::Debug;
use std::net::SocketAddr;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use crate::message::Message;
use crate::network::cache::CacheKey;
use crate::network::statistics::{FinalizedManagerStats, HandleStats};

#[derive(Debug)]
pub(super) struct ShutdownMsg(pub(super) oneshot::Sender<()>);

#[derive(Debug)]
pub(super) enum CacheMsg<T> {
    Shutdown(oneshot::Sender<()>),
    Subscribe(CacheKey, mpsc::Sender<Message<T>>),
    Unsubscribe(CacheKey),
    Round(usize),
}

#[derive(Debug)]
pub(super) enum SenderMsg {
    Shutdown(oneshot::Sender<()>),
    Send(Bytes),
}

#[derive(Debug)]
pub(super) enum ManagerMsg<T> {
    Shutdown(oneshot::Sender<()>),
    Subscribe(CacheKey, mpsc::Sender<Message<T>>),
    Unsubscribe(CacheKey),
    Send(T, Bytes),
    Broadcast(Bytes),
    Round(usize, Option<HashMap<T, SocketAddr>>),
    PutStats(HandleStats),
    Stats(oneshot::Sender<Option<FinalizedManagerStats>>),
}