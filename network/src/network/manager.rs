use std::collections::HashMap;
use std::net::SocketAddr;

use anyhow::Result;
use bincode::Options;
use bytes::Bytes;
use futures::future::try_join_all;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::{mpsc, oneshot};

use utils::{close_and_drain, shutdown, shutdown_done, shutdown_oneshot};
use utils::spawn;

use crate::message::{Id, Message, SerializableMessage};
use crate::network::BINCODE;
use crate::network::cache::CacheKey;
use crate::network::statistics::{FinalizedManagerStats, HandleStats, ManagerStats};

use super::cache::Cache;
use super::CHANNEL_LIMIT;
use super::listener::Listener;
use super::messages::{CacheMsg, ManagerMsg, SenderMsg, ShutdownMsg};
use super::sender::Sender;

/// The [Manager] handles control messages to the appropriate tasks. Most importantly, it acts as a
/// multiplexer for sending messages.
///
/// Communication with the [Manager] is solely conducted with a [ManagerHandle].
struct Manager<T> {
    handle: mpsc::Receiver<ManagerMsg<T>>,
    listener: Option<oneshot::Sender<ShutdownMsg>>,
    cache: mpsc::Sender<CacheMsg<T>>,
    peers: HashMap<T, SocketAddr>,
    senders: HashMap<SocketAddr, mpsc::Sender<SenderMsg>>,
    stats: Option<ManagerStats>,
}

impl<T> Manager<T>
    where
        T: 'static + Send + Sync + Eq + std::hash::Hash + std::fmt::Debug + Clone + Serialize + DeserializeOwned
{
    /// Creates a new manager. It spawns a [Cache], [Sender]s for each peer in [peers] and a
    /// [Listener] listening for incoming messages on [port].
    ///
    /// The [Manager] starts in round 0.
    fn new(handle: mpsc::Receiver<ManagerMsg<T>>, port: u16, peers: HashMap<T, SocketAddr>, stats: bool) -> Self {
        let (cache, cache_rx) = mpsc::channel(CHANNEL_LIMIT);
        let (recv_cache_tx, recv_cache_rx) = mpsc::channel(CHANNEL_LIMIT);
        spawn!(Cache::new(cache_rx, recv_cache_rx));

        let (listener, listener_rx) = oneshot::channel();
        spawn!(Listener::new(listener_rx, port, recv_cache_tx));

        let mut senders = HashMap::with_capacity(peers.len());
        for (_, peer_addr) in peers.clone().into_iter() {
            let (sender_tx, sender_rx) = mpsc::channel(CHANNEL_LIMIT);
            senders.insert(peer_addr.clone(), sender_tx);
            spawn!(Sender::new(sender_rx, peer_addr));
        };

        let stats = if stats { Some(ManagerStats::new(peers.len())) } else { None };

        Self { handle, listener: Some(listener), cache, peers, senders, stats }
    }

    /// Runs the [Manager].
    async fn run(&mut self) {
         while let Some(msg) = self.handle.recv().await {
            match msg {
                ManagerMsg::Shutdown(tx) => {
                    log::debug!("Initiating shutdown.");
                    // We ignore errors on shutdown and only wait for the response in case send was
                    // successful.
                    shutdown_oneshot!(self.listener.take().unwrap(), ShutdownMsg);
                    for (_, sender) in self.senders.iter() {
                        shutdown!(sender, SenderMsg::Shutdown);
                    }
                    shutdown!(self.cache, CacheMsg::Shutdown);
                    // This can cause an error if a handle still tries to send something. Thus,
                    // it needs to be ensured that no handles will do anything when one calls
                    // shutdown.
                    if let Some(manager_stats) = &mut self.stats {
                        self.handle.close();
                        while let Some(msg) = self.handle.recv().await {
                            if let ManagerMsg::PutStats(stats) = msg {
                                manager_stats.add_handle_stats(stats);
                            }
                        }
                    } else {
                        close_and_drain!(self.handle);
                    }
                    log::debug!("Shut down.");
                    shutdown_done!(tx);
                },
                ManagerMsg::Subscribe(key, tx) => {
                    self.cache.send(CacheMsg::Subscribe(key, tx)).await
                        .expect("Cache unreachable!");
                },
                ManagerMsg::Unsubscribe(id) => {
                    self.cache.send(CacheMsg::Unsubscribe(id)).await
                        .expect("Cache unreachable!");
                },
                ManagerMsg::Send(node, bytes) => {
                    if let Some(stats) = &mut self.stats {
                        stats.send(bytes.len());
                    }
                    self.senders.get(self.peers.get(&node).expect("Node in peers not found!"))
                        .expect("Sender in peers not found!")
                        .send(SenderMsg::Send(bytes)).await
                        .expect(format!("Sender unreachable!").as_str());
                },
                ManagerMsg::Broadcast(bytes) => {
                    if let Some(stats) = &mut self.stats {
                        stats.broadcast(bytes.len());
                    }
                    try_join_all(self.senders.iter().map(|(_, s)| s.send(SenderMsg::Send(bytes.clone())))).await
                        .expect("At least one Sender unreachable!");
                },
                ManagerMsg::Round(round, new_peers) => {
                    if let Some(new_peers) = new_peers {
                        // TODO: For the current use-case it's fine but this should probably be able to handle dynamically changing peers.
                        self.peers = new_peers;
                    }
                    self.cache.send(CacheMsg::Round(round)).await
                        .expect("Cache unreachable!");
                },
                ManagerMsg::Stats(tx) => {
                        tx.send(self.stats.take().and_then(|s| Some(s.finalize()))).expect("Handle unreachable!");
                    },
                    ManagerMsg::PutStats(handle_stats) => {
                        if let Some(manager_stats) = &mut self.stats {
                            manager_stats.add_handle_stats(handle_stats);
                        }
                    }
                }
            }
        }
}

/// A [ManagerHandle] is used to communicate with the [Manager].
#[derive(Debug)]
pub struct ManagerHandle<T> {
    handle: mpsc::Sender<ManagerMsg<T>>,
    own_idx: T,
    stats: Option<HandleStats>
}

impl<T> Clone for ManagerHandle<T>
    where
        T: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self { handle: self.handle.clone(), own_idx: self.own_idx.clone(), stats: self.stats.as_ref().and_then(|_| Some(HandleStats::default()) )}
    }
}

impl<T> ManagerHandle<T>
    where
        T: 'static + Eq + std::hash::Hash + Send + Sync + std::fmt::Debug + Serialize + DeserializeOwned + Clone
{
    /// Spawns a new [Manager] and returns a handle to it.
    /// The [Manager] will listen for incoming messages on [port] and will connect to every peer in
    /// [peers]. The latter are identified by the type [T], e.g., [usize].
    ///
    /// The [Manager] starts in round 0.
    ///
    /// This function is usually only called once per program execution.
    pub fn new(own_idx: T, port: u16, peers: HashMap<T, SocketAddr>, stats: bool) -> Self {
        let (rx, tx) = mpsc::channel(CHANNEL_LIMIT);
        spawn!(Manager::new(tx, port, peers, stats));
        let stats = if stats { Some(HandleStats::default()) } else { None };
        Self { handle: rx, own_idx, stats }
    }

    fn content_to_bytes<M: 'static + Serialize>(&self, id: &Id, content: &M) -> Result<Bytes> {
        let ser_msg = SerializableMessage::new(&self.own_idx, id, content)?;
        Ok(Bytes::from(BINCODE.serialize(&ser_msg)?))
    }

    /// Sends a message for protocol id [id] with [content] to the peer with index [receiver].
    pub async fn send<M: 'static + Serialize>(&self, receiver: T, id: &Id, content: &M) {
        let bytes = self.content_to_bytes(id, content).expect("Serializing message failed!");
        self.handle.send(ManagerMsg::Send(receiver, bytes)).await.expect("Manager unreachable!")
    }

    /// Broadcasts a message for protocol [id] with [content].
    pub async fn broadcast<M: 'static + Serialize>(&self, id: &Id, content: &M) {
        let bytes = self.content_to_bytes(id, content).expect("Serializing message failed!");
        self.handle.send(ManagerMsg::Broadcast(bytes)).await.expect("Manager unreachable!")
    }

    /// Subscribe to messages for protocol [id]. The messages will be received by the [Receiver]
    /// corresponding to [tx].
    ///
    /// The subscription will be ignored if either one applies:
    /// (i) has been subscribed to already at some point in time
    /// (ii) is for a round greater or equal to last round being set by [round()]
    ///
    /// It follows from (i) that **at most one subscriber per ID may exist**.
    pub async fn subscribe<M: 'static>(&self, id: &Id, tx: mpsc::Sender<Message<T>>) {
        self.handle.send(ManagerMsg::Subscribe(CacheKey::new::<M>(id.clone()), tx)).await
            .expect("Manager unreachable!")
    }

    /// Unsubscribes from all messages for protocol [id].
    pub async fn unsubscribe<M: 'static>(&self, id: &Id) {
        self.handle.send(ManagerMsg::Unsubscribe(CacheKey::new::<M>(id.clone()))).await
            .expect("Manager unreachable!")
    }

    /// Set the current [round] and optionally allows for [new_peers] to be specified.
    ///
    /// For the system to function correctly, it must be ensured that [round] is
    /// not decreasing for every call.
    #[inline]
    pub async fn round(&self, round: usize, new_peers: Option<HashMap<T, SocketAddr>>) {
        self.handle.send(ManagerMsg::Round(round, new_peers)).await
            .expect("Manager unreachable!")
    }

    /// Shuts down all components of the network safely.
    /// It must be ensured that no other handle will be used anymore after calling this method.
    #[inline]
    pub async fn shutdown(mut self) {
        self.handle_stats_end().await;
        shutdown!(self.handle, ManagerMsg::Shutdown);
    }

    /// Returns performance statistics if the handle was initially created with [stats] set to [true].
    #[inline]
    pub async fn sender_stats(&self) -> Option<FinalizedManagerStats> {
        let (tx, rx) = oneshot::channel();
        self.handle.send(ManagerMsg::Stats(tx)).await.expect("Manager unreachable!");
        rx.await.expect("sender_stats await failed!")
    }

    /// Starts tracking the execution of this handle with the human-readable `label`.
    ///
    /// If any of the above conditions does not hold or statistics are disabled, this is a no-op.
    #[inline]
    pub fn handle_stats_start<L: Into<String>>(&mut self, label: L) {
        if let Some(stats) = &mut self.stats {
            stats.set_label(label);
            stats.start();
        }
    }

    /// Ends tracking the execution of this handle and transfers the stats to the manager.
    ///
    /// The caller must ensure that this is only called (i) once per handle and (ii) after
    /// [handle_stats_start].
    ///
    /// If any of the above conditions does not hold or statistics are disabled, this is a no-op.
    #[inline]
    pub async fn handle_stats_end(&mut self) {
        if let Some(mut stats) = self.stats.take() {
            stats.end();
            self.handle.send(ManagerMsg::PutStats(stats)).await.expect("Manager unreachable!");
        }
    }

    /// Registers an event with human-readable `label` identifying the event. The labels must not
    /// necessarily be unique but it is recommended that they are.
    ///
    /// The caller must ensure that this is only called (i) after [handle_stats_start] and (ii)
    /// before [handle_stats_end].
    ///
    /// If any of the above conditions does not hold or statistics are disabled, this is a no-op.
    #[inline]
    pub fn handle_stats_event<L: Into<String>>(&mut self, label: L) {
        if let Some(stats) = &mut self.stats {
            stats.event(label);
        }
    }
}