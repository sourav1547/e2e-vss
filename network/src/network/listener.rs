use std::collections::HashMap;

use futures::prelude::stream::FuturesUnordered;
use futures::StreamExt;
use serde::de::DeserializeOwned;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

use utils::{close_and_drain_oneshot, shutdown_done, shutdown_oneshot};
use utils::spawn;

use crate::message::Message;

use super::messages::ShutdownMsg;
use super::receiver::Receiver;

/// A [Listener] waits for incoming TCP connections on the given port and spawns a new [Receiver]
/// for each connection.
pub(super) struct Listener<T> {
    port: u16,
    manager: oneshot::Receiver<ShutdownMsg>,
    cache: mpsc::Sender<Message<T>>,
    receivers: HashMap<usize, oneshot::Sender<ShutdownMsg>>,
    counter: usize,
    removal_handlers: FuturesUnordered<oneshot::Receiver<usize>>,
}

// TODO: This currently does not impose any limits on the amount of receivers.
impl<T> Listener<T>
    where
        T: 'static + Send + std::fmt::Debug + DeserializeOwned
{
    /// Creates a new [Listener].
    pub(super) fn new(manager: oneshot::Receiver<ShutdownMsg>, port: u16, cache: mpsc::Sender<Message<T>>) -> Self {
        Self { port, manager, cache, receivers: HashMap::new(), counter: 0, removal_handlers: FuturesUnordered::new() }
    }

    pub(super) async fn run(&mut self) {
        // Bind to specified port
        let listener = TcpListener::bind(("0.0.0.0", self.port)).await.expect("TCP listener failed to bind!");

        loop {
            tokio::select! {
                // Listen for TCP connections and spawn a new receiver for each one
                con = listener.accept() => match con {
                    Ok((socket, _)) => {
                        log::debug!("Accepted new connection.");
                        // Oneshot shutdown channel for receiver
                        let (tx, rx) = oneshot::channel();
                        self.receivers.insert(self.counter, tx);

                        // Removal handler that is used by the receiver to notify the listener of a
                        // connection being dropped.
                        let (tx_one, rx_one) = oneshot::channel::<usize>();
                        self.removal_handlers.push(rx_one);
                        let counter = self.counter;  // Otherwise we get some compiler lifetime issues.

                        // Spawn new receiver
                        let cache = self.cache.clone();
                        spawn!(Receiver::new(rx, cache, socket, counter, tx_one));
                        self.counter = self.counter + 1;
                    }
                    Err(e) => {
                        log::warn!("TCP listener error: {}", e)
                    }
                },
                // Remove terminated receiver
                Some(res) = self.removal_handlers.next() => {
                    match res {
                        Ok(i) => {
                            self.receivers.remove(&i);
                        },
                        Err(e) => log::warn!("Oneshot removal handler failed {}", e),
                    }
                }
                // Shutdown
                res = &mut self.manager => match res {
                    Ok(tx) => {
                        for (_, receiver) in self.receivers.drain() {
                            // This shutdown might error given certain races (Receiver sends removal
                            // and terminates just as manager is executing shutdown). However, the
                            // below macro ignores errors so it's fine.
                            shutdown_oneshot!(receiver, ShutdownMsg);
                        }
                        // We drain after shutting down the Receiver so that none of them can send
                        // a message to a closed oneshot channel.
                        for c in self.removal_handlers.iter_mut() {
                            close_and_drain_oneshot!(c);
                        }
                        log::debug!("Shut down.");
                        shutdown_done!(tx.0);
                    },
                    Err(e) => {
                        // The oneshot channel error'd. So we just shut down.
                        log::warn!("Receiver shutdown oneshot error: {}!", e);
                        return
                    },
                },
            }
        }
    }
}
