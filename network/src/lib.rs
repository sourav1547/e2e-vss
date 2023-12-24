pub use tokio;

pub mod network;
pub mod message;

#[macro_export]
macro_rules! subscribe_msg {
    ($handle: expr, $id: expr, $t: ty) => {{
        let (tx, mut rx) = tokio::sync::mpsc::channel(network::network::CHANNEL_LIMIT);
        $handle.subscribe::<$t>($id, tx).await;
        rx
    }};
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;
    use std::time::Duration;

    use tokio;
    use tokio::sync::mpsc;
    use tokio::time::sleep;

    use crate::message::Id;
    use crate::network::manager::ManagerHandle;

    use super::*;

    #[tokio::test]
    async fn test_basic() {
        let port0 = 10080u16;
        let port1 = 10081u16;
        let mut peers = HashMap::new();
        peers.insert(0usize, SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), port0));
        peers.insert(1usize, SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), port1));

        let ping = "Ping".to_string();
        let pong = "Pong".to_string();
        let id = Id::new(0, vec![]);

        let mh0 = ManagerHandle::new(0usize, port0, peers.clone(), true);
        let mh1 = ManagerHandle::new(1usize, port1, peers.clone(), false);
        let (tx0, mut rx0) = mpsc::channel(8);
        let (tx1, mut rx1) = mpsc::channel(8);

        // Subscribe and send Ping
        mh1.subscribe::<String>(&id, tx1).await;
        mh0.send(1, &id, &ping).await;
        let ping_rcv = rx1.recv().await.unwrap();
        assert_eq!(ping_rcv.get_id(), &id);
        assert_eq!(ping_rcv.get_sender(), &0);
        assert_eq!(ping_rcv.get_content::<String>().unwrap(), ping);

        // Reply with Pong, sleep and then subscribe (so that it will be read from cache).
        mh1.send(0, &id, &pong).await;
        sleep(Duration::from_millis(500)).await;
        mh0.subscribe::<String>(&id, tx0).await;
        let pong_rcv = rx0.recv().await.unwrap();
        assert_eq!(pong_rcv.get_id(), &id);
        assert_eq!(pong_rcv.get_sender(), &1);
        assert_eq!(pong_rcv.get_content::<String>().unwrap(), pong);

        // Increment rounds. This should cause both senders to be dropped and the rx to return None.
        mh0.round(1, None).await;
        mh1.round(1, None).await;
        assert!(rx1.recv().await.is_none());
        assert!(rx0.recv().await.is_none());

        // Test unsubscribe
        let id0 = Id::new(1, vec![0]);

        let (tx1, mut rx1) = mpsc::channel(8);
        mh1.subscribe::<String>(&id0, tx1).await;
        mh1.unsubscribe::<String>(&id0).await;
        sleep(Duration::from_millis(500)).await;
        mh0.send(1, &id0, &"X".to_string()).await;
        assert!(rx1.recv().await.is_none());

        mh0.shutdown().await;
        mh1.shutdown().await;
    }
}