use anyhow::Context;
use bincode::Options;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use futures::prelude::stream::SplitStream;
use futures::stream::SplitSink;
use log;
use serde::de::DeserializeOwned;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use utils::shutdown_done;

use crate::message::Message;
use crate::network::BINCODE;

use super::messages::ShutdownMsg;

pub(super) struct Receiver<T> {
    listener: oneshot::Receiver<ShutdownMsg>,
    cache: mpsc::Sender<Message<T>>,
    tx: SplitSink<Framed<TcpStream, LengthDelimitedCodec>, Bytes>,
    rx: SplitStream<Framed<TcpStream, LengthDelimitedCodec>>,
    id: usize,
    removal: Option<oneshot::Sender<usize>>,
}

impl<T> Receiver<T>
    where
        T: 'static + Send + std::fmt::Debug + DeserializeOwned
{
pub(super) fn new(listener: oneshot::Receiver<ShutdownMsg>, cache: mpsc::Sender<Message<T>>, stream: TcpStream, id: usize, removal: oneshot::Sender<usize>) -> Self {
        let framed = Framed::new(stream, LengthDelimitedCodec::new());
        let (tx, rx) = framed.split();
        Self { listener, cache, tx, rx, id, removal: Some(removal) }
    }

    pub(super) async fn run(&mut self) {
        loop {
            tokio::select! {
                // Incoming message
                Some(res) = self.rx.next() => {

                    match res.with_context(|| "Receive error!").and_then(|r| BINCODE.deserialize::<Message<T>>(&r).with_context(|| "Deserialize error!")) {
                        Ok(msg) => {
                            log::debug!("Got incoming message.");
                            // Forward to cache
                            self.cache.send(msg).await.expect("Cache unreachable!");
                            
                            // Reply ACK
                            if let Err(e) = self.tx.send(Bytes::from("0")).await {
                                log::info!("Ack error: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            // Break connection on error
                            log::info!("Connection error: {}", e);
                            break;
                        }
                    }
                },
                // Shutdown.
                res = &mut self.listener => match res {
                    Ok(tx) => {
                        let _ = self.tx.close().await;
                        log::debug!("Receiver {} shut down.", self.id);
                        shutdown_done!(tx.0);
                    },
                    Err(e) => {
                        // The oneshot channel error'd. So we just shut down.
                        log::warn!("Shutdown oneshot error: {}!", e);
                        return;
                    },
                },
            }
        }
        // Unwrap is safe here since removal is initialized in new()
        self.removal.take().unwrap().send(self.id).expect("Listener unreachable!");
    }
}

