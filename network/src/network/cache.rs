use std::collections::{HashMap, HashSet};

use log;
use tokio::sync::mpsc;

use utils::{close_and_drain, shutdown_done};

use crate::message;
use crate::message::{Id, Message};

use super::messages::CacheMsg;

#[derive(Debug, Hash, PartialEq, Eq)]
pub(super) struct CacheKey {
    pub id: Id,
    pub content_type: u64,
}

impl CacheKey {
    pub fn new<T: 'static>(id: Id) -> Self {
        Self::new_with_type(id, message::content_type::<T>())
    }

    fn new_with_type(id: Id, content_type: u64) -> Self {
        Self {id, content_type }
    }
}

/// A cache receives control m
pub(super) struct Cache<T> {
    manager: mpsc::Receiver<CacheMsg<T>>,
    cache: HashMap<CacheKey, Vec<Message<T>>>,
    round: usize,
    receivers: mpsc::Receiver<Message<T>>,
    subscribers: HashMap<CacheKey, mpsc::Sender<Message<T>>>,
    ignore: HashSet<CacheKey>,
    recv_bytes: usize,
    recv_count: usize,
}

impl<T> Cache<T>
    where
        T: 'static + Send + Clone
{
    /// Creates a new [Cache].
    pub(super) fn new(manager: mpsc::Receiver<CacheMsg<T>>, receivers: mpsc::Receiver<Message<T>>) -> Self {
        Self { manager, receivers, round: 0, subscribers: HashMap::new(), cache: HashMap::new(), ignore: HashSet::new(), recv_bytes: 0, recv_count: 0 }
    }

    pub(super) async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.manager.recv() => match msg {
                    // Handle Shutdown here so that return actually stops run()
                    CacheMsg::Shutdown(tx) => {
                        close_and_drain!(self.manager);
                        // This will never result in a send error by a receiver since the manager shuts
                        // down the listener (and thus all receivers) before shutting down the cache.
                        close_and_drain!(self.receivers);
                        log::debug!("Shut down.");
                        // println!("Cache received {} messages with a total size of {} bytes.", self.recv_count, self.recv_bytes);
                        println!("{},{}", self.recv_count, self.recv_bytes);
                        shutdown_done!(tx);
                    },
                    msg => self.handle_cache_msg(msg).await,
                },
                Some(msg) = self.receivers.recv() => {
                    self.recv_bytes += msg.get_size();
                    self.recv_count += 1;
                    self.handle_msg(msg).await;
                },
            }
        }
    }

    async fn handle_msg(&mut self, msg: Message<T>) {
        let key = CacheKey::new_with_type(msg.get_id().clone(), msg.get_content_type());

        // Discard messages from previous rounds or IDs that have been unsubscribed from already
        if self.filter_message(&key) { return; }
        log::debug!("Received message with key {:?}.", key);

        // Store message
        match self.subscribers.get(&key) {
            None => {
                let mut v = match self.cache.remove(&key) {
                    None => Vec::new(),
                    Some(v) => v,
                };
                v.push(msg);
                self.cache.insert(key, v);
            }
            Some(tx) => {
                if let Err(e) = tx.send(msg).await {
                    // There might be a case that a subscriber has already unsubscribed and terminated
                    // but the cache has yet to process it. In any case, we unsubscribe malfunctioning
                    // subscribers.
                    log::info!("Could not reach Subscriber: {}!", e);
                    self.unsubscribe(key);
                }
            }
        }
    }

    async fn handle_cache_msg(&mut self, msg: CacheMsg<T>) {
        match msg {
            // Subscribe.
            CacheMsg::Subscribe(key, tx) => {
                log::debug!("Subscribe for key {:?}.", &key);
                // Subscriptions must be fresh and must not be for a prior round.
                if self.filter_message(&key) || self.subscribers.contains_key(&key) {
                    log::warn!("Subscription {:?} for already subscribed, unsubscribed key or prior round (current is {})!", key, self.round);
                    return;
                }

                // Send subscriber all messages received thus far.
                let cached = self.cache.remove(&key);
                if let Some(msgs) = cached {
                    log::debug!("Sending {} cached messages.", msgs.len());
                    for msg in msgs {
                        if let Err(e) = tx.send(msg).await {
                            // Similar case to above in handle_raw_received_msg but extremely unlikely
                            // to happen.
                            log::info!("Could not reach Subscriber: {}!", e);
                            self.unsubscribe(key);  // This is needed to insert it into ignore.
                            return;
                        }
                    }
                }

                // Insert subscriber
                self.subscribers.insert(key, tx);
            }
            // Unsubscribe.
            CacheMsg::Unsubscribe(id) => self.unsubscribe(id),
            // Advance to a new round.
            CacheMsg::Round(round) => {
                // Retain only information that belongs to the current or future round
                self.cache.retain(|x, _| x.id.get_round() >= round);
                self.subscribers.retain(|x, _| x.id.get_round() >= round);
                self.ignore.retain(|x| x.id.get_round() >= round);

                // Finally, update round
                self.round = round;
            },
            CacheMsg::Shutdown(_) => unreachable!(),  // Handled in run()
        }
    }

    /// Filters a message if it's round is lower than the current round or if it is contained in
    /// [self.ignore].
    fn filter_message(&self, key: &CacheKey) -> bool {
        key.id.get_round() < self.round || self.ignore.contains(key)
    }

    /// Removes a subscriber. If a subscriber existed, the [id] will be added to [self.ignore].
    fn unsubscribe(&mut self, key: CacheKey) {
        log::debug!("Unsubscribe key {:?}.", &key);
        match self.subscribers.remove(&key) {
            None => (),
            Some(_) => {
                self.ignore.insert(key);
            }
        }
    }
}
