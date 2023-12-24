use std::cmp;
use std::collections::VecDeque;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use log;
use rand::Rng;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task;
use tokio::time::{Duration, sleep};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use utils::{close_and_drain, shutdown_done};

use crate::network::{SENDER_BACKOFF_BASE, SENDER_BACKOFF_MAX_DELAY, SENDER_BUFFER_LIMIT};

use super::messages::SenderMsg;

/// A [Sender] forwards received [Message]s to a remote [peer].
/// It is reliable in the sense that it buffers received messages and retries to failed the
/// connections.
pub(super) struct Sender {
    peer: SocketAddr,
    manager: mpsc::Receiver<SenderMsg>,
    buffer: VecDeque<Bytes>,
    backoff: ExponentialBackoff,
    exit: Option<oneshot::Sender<()>>,
}

// Helper macro for correctly managing the various queues on an error inside [send_loop].
// Takes a Result<T, E> and either returns T or returns from the method with
// anyhow::Result<()>::Err.
macro_rules! throw {
    ($x: expr, $buf: expr, $ack: expr) => {
        match $x {
            Ok(x) => x,
            x => {
                while let Some(msg) = $ack.pop_back() {
                    // Ignore the oldest messages in ack queue if the buffer limit is exceeded
                    if $buf.len() < SENDER_BUFFER_LIMIT {
                        $buf.push_front(msg);
                    }
                    task::yield_now().await;
                }
                // This turns any Result<T, E> into anyhow::Result<()>
                return Err(x.with_context(|| "Sender error").expect_err(""));
            }
        }
    }
}

impl Sender {
    /// Creates a new [Sender] for the given [peer].
    pub(super) fn new(manager: mpsc::Receiver<SenderMsg>, peer: SocketAddr) -> Self {
        Self { peer, manager, buffer: VecDeque::new(), exit: None,
            backoff: ExponentialBackoff::new(SENDER_BACKOFF_BASE, SENDER_BACKOFF_MAX_DELAY)
        }
    }

    pub(super) async fn run(&mut self) {
        loop {
            match TcpStream::connect(self.peer).await {
                Ok(stream) => {
                    // Successful connection. Reset backoff.
                    self.backoff.reset();
                    match self.send_loop(stream).await {
                        Ok(_) => {
                            // Ok(_) indicates that send_loop stopped without error, i.e., Shutdown.
                            // We can unwrap here since we know self.exit must be set.
                            log::debug!("Sender for {} shut down.", self.peer);
                            shutdown_done!(self.exit.take().unwrap());
                        },
                        Err(e) => {
                            log::debug!("Connection dropped: {}! Retrying...", e);
                        }
                    }
                }
                Err(e) => {
                    log::debug!("Can't connect: {}! Retrying...", e);
                    let sleep = sleep(self.backoff.duration());
                    tokio::pin!(sleep);

                    if let Some(tx) = self.exit.take() {
                        log::info!("Failed to send remaining messages on shutdown to {} as peer is still unreachable!", self.peer);
                        close_and_drain!(self.manager);
                        log::debug!("Sender for {} shut down.", self.peer);
                        shutdown_done!(tx);
                    }

                    loop {
                        tokio::select! {
                            // Wake up
                            _ = &mut sleep => break,
                            // Check if we are getting messages from manager while sleeping
                            Some(msg) = self.manager.recv() => {
                                if self.handle_sender_msg(msg) {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    async fn send_loop(&mut self, stream: TcpStream) -> Result<()>{
        let (mut tx, mut rx) = Framed::new(stream, LengthDelimitedCodec::new()).split();
        let mut pending_ack = VecDeque::new();
        let mut ack_overflow = 0usize;  // This tracks pending_ack messages that have been discarded due to buffer overflow.
        loop {
            // First, try to clear the buffer.
            while let Some(bytes) = self.buffer.pop_front() {
                pending_ack.push_back(bytes.clone());
                // If the pending_ack queue exceeds the buffer limit, we forget the last message and won't retransmit it.
                if pending_ack.len() > SENDER_BUFFER_LIMIT {
                    pending_ack.pop_front();
                    ack_overflow = ack_overflow + 1;
                }
                throw!(tx.send(bytes).await, self.buffer, pending_ack);
            }

            // If the exit flag is set, we close tx and drain the manager channel.
            if let Some(_) = &self.exit {
                let _ = tx.close().await;
                close_and_drain!(self.manager);
                return Ok(())
            }

            // Second, Check other channels
            // If a new message to send is received, this select returns and control flow resumes at
            // the top of the loop and will thus attempt to send the message.
            tokio::select! {
                // Handle ACKs. TCP ensures that messages are in order so we can just pop the front.
                Some(ack) = rx.next() => {
                    throw!(ack, self.buffer, pending_ack);
                    // Here the message is confirmed to be received
                    // If we threw away some pending_ack messages, we need to decrement the overflow
                    // counter. Otherwise, just pop the front of pending_ack.
                    if ack_overflow != 0 {
                        ack_overflow = ack_overflow - 1;
                    } else {
                        pending_ack.pop_front();
                    }
                },
                Some(msg) = self.manager.recv() => {
                    // If we should shutdown here, we will anyways enter the if let above the select!.
                    let _ =  self.handle_sender_msg(msg);
                }
            }
        }
    }

    fn handle_sender_msg(&mut self, msg: SenderMsg) -> bool {
        match msg {
            SenderMsg::Shutdown(tx) => {
                self.exit = Some(tx);
                true
            },
            SenderMsg::Send(msg) => {
                self.buffer.push_back(msg);

                // If we exceed the buffer limit, we drop the first message
                if self.buffer.len() > SENDER_BUFFER_LIMIT {
                    let _ = self.buffer.pop_front();
                }
                false
            },
        }
    }
}

/// Keeps track of a delay counter that follows an exponential backoff approach.
/// The delay is the minimum of [base * 2^i] (where [i] is the current attempt) and [max_delay].
/// Additionally, jitter is added by multiplying this value by a random value (0,1].
struct ExponentialBackoff {
    base: u64,
    max_delay: Option<u64>,
    delay: u64,
}

impl ExponentialBackoff {
    /// Creates a new instance with [base] and [max_delay] set, both in ms.
    fn new(base: u64, max_delay: Option<u64>) -> Self {
        Self { base, max_delay, delay: base }
    }

    /// Resets the attempts.
    fn reset(&mut self) {
        self.delay = self.base;
    }

    /// Returns the current delay and increments the delay.
    fn duration(&mut self) -> Duration {
        // Duration to sleep for. Multiplies the delay with jitter in the range (0,1].
        let duration = Duration::from_millis(self.delay)
            .mul_f64(rand::thread_rng().sample(rand::distributions::OpenClosed01));

        // Increment
        self.delay = match self.max_delay {
            None => 2 * self.delay,
            Some(min) => cmp::min(2 * self.delay, min),
        };

        duration
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff() {
        let mut eb = ExponentialBackoff::new(500, Some(1_500));
        assert_eq!(eb.delay, 500);
        let d = eb.duration();
        assert!(d > Duration::from_millis(0) && d <= Duration::from_millis(500));
        assert_eq!(eb.delay, 1_000);
        let d = eb.duration();
        assert!(d > Duration::from_millis(0) && d <= Duration::from_millis(1_000));
        assert_eq!(eb.delay, 1_500);
        let d = eb.duration();
        assert!(d > Duration::from_millis(0) && d <= Duration::from_millis(1_500));
        assert_eq!(eb.delay, 1_500);
        let d = eb.duration();
        assert!(d > Duration::from_millis(0) && d <= Duration::from_millis(1_500));
        eb.reset();
        assert_eq!(eb.delay, 500);
    }
}
