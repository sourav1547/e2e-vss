pub use tokio;
pub use rayon;
pub use anyhow;

/// Spawns a Tokio task by calling the run() method. Can optionally pass arguments
#[macro_export]
macro_rules! spawn {
    ($x: expr $(, $arg: expr)*) => {
        tokio::spawn(async move { $x.run($($arg),*).await });
    };
}

/// Executes a CPU-bound computation [$e] in a rayon task.
#[macro_export]
macro_rules! spawn_blocking {
    ($e: expr) => {{
        let (tx, rx) = tokio::sync::oneshot::channel();
        rayon::scope(|s| {
            s.spawn(|_| {
                let x = $e;
                let _ = tx.send(x);  // This shouldn't error.
            });
        });
        rx.await.expect("Spawn blocking rx failed!")
    }};
}



/// Sends a shutdown message of type [$t] to the given process [$x] where the latter is an [mpsc]
/// channel. Blocks until the shutdown succeeded.
#[macro_export]
macro_rules! shutdown {
    ($x: expr, $t: expr) => {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        if let Ok(_) = $x.send($t(tx)).await {
            let _ = rx.await;
        }
    };
}

/// Sends a shutdown message of type [$t] to the given process [$x] where the latter is a [oneshot]
/// channel. Blocks until the shutdown succeeded.
#[macro_export]
macro_rules! shutdown_oneshot {
    ($x: expr, $t: expr) => {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        if let Ok(_) = $x.send($t(tx)) {
            let _ = rx.await;
        }
    };
}

/// Given the shutdown channel, signals that the process is done and returns. Optionally, a return
/// value can be specified.
#[macro_export]
macro_rules! shutdown_done {
    ($x: expr $(, $r: expr)?) => {
        let _ = $x.send(());
        return $($r)?;
    }
}

/// Closes a channel and drains all messages.
#[macro_export]
macro_rules! close_and_drain {
    ($x: expr) => {
        $x.close();
        while let Some(_) = $x.recv().await {};
    }
}

/// Closes a oneshot channel and drains the message.
#[macro_export]
macro_rules! close_and_drain_oneshot {
    ($x: expr) => {
        $x.close();
        let _ = $x.try_recv();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_spawn_blocking() {
        let a = 7usize;
        let b = 42usize;
        let x = spawn_blocking!(a + b);
        assert_eq!(x, a + b)
    }
}
