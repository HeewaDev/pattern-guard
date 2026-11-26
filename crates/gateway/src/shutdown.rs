//! Graceful shutdown. On SIGTERM or SIGINT (see [`signal`]) the gateway
//!
//! 1. stops accepting: the protected and the admin listener are closed, so new
//!    connections are refused;
//! 2. asks every open connection to finish. hyper's graceful shutdown closes an idle
//!    keep-alive connection at once and lets a request in progress complete; its
//!    response is the connection's last;
//! 3. closes the connections still open once `limits.shutdown_grace_secs` have passed;
//! 4. flushes the decision log (until the end of the grace period, at least
//!    [`FLUSH_MIN`]) and returns.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

use crate::state::State;

/// The decision log always gets this long to be written at exit, even when the
/// connections used up the whole grace period.
pub const FLUSH_MIN: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Phase {
    Running,
    /// Stop accepting; finish the request in progress, then close.
    Draining,
    /// The grace period is over: close now.
    Closing,
}

/// Starts a shutdown. Every [`Token`] it hands out follows it.
pub(crate) struct Drain {
    tx: watch::Sender<Phase>,
}

/// Held by an accept loop or a connection for as long as it runs: [`Drain::drain`]
/// waits until all of them are dropped.
pub(crate) struct Token {
    /// `None`: a shutdown never comes.
    rx: Option<watch::Receiver<Phase>>,
}

impl Drain {
    pub fn new() -> Self {
        Self {
            tx: watch::channel(Phase::Running).0,
        }
    }

    pub fn token(&self) -> Token {
        Token {
            rx: Some(self.tx.subscribe()),
        }
    }

    /// Stops the accept loops and lets connections finish until `deadline`, then
    /// closes the rest. Returns how many were still open at the deadline.
    pub async fn drain(&self, deadline: Instant) -> usize {
        self.tx.send_replace(Phase::Draining);
        if tokio::time::timeout_at(deadline, self.tx.closed())
            .await
            .is_ok()
        {
            return 0;
        }
        let open = self.tx.receiver_count();
        self.tx.send_replace(Phase::Closing);
        // each drops its connection the next time it is polled
        let _ = tokio::time::timeout(Duration::from_millis(100), self.tx.closed()).await;
        open
    }
}

impl Token {
    /// A token whose shutdown never comes ([`crate::serve`] without [`crate::run`]).
    pub fn never() -> Self {
        Self { rx: None }
    }

    /// Another token for a connection accepted under this one.
    pub fn child(&self) -> Self {
        Self {
            rx: self.rx.clone(),
        }
    }

    async fn reached(&mut self, phase: Phase) {
        match &mut self.rx {
            // `Err`: the `Drain` was dropped, which also means stop
            Some(rx) => {
                let _ = rx.wait_for(|p| *p >= phase).await;
            }
            None => std::future::pending().await,
        }
    }

    /// Completes when the gateway starts shutting down.
    pub async fn draining(&mut self) {
        self.reached(Phase::Draining).await
    }
}

/// Drives one connection. When the shutdown starts, `graceful` asks it to finish
/// (hyper's `graceful_shutdown`); when the grace period is over, it is dropped.
pub(crate) async fn serve_conn<C: Future>(
    conn: C,
    mut token: Token,
    graceful: impl FnOnce(Pin<&mut C>),
) {
    let mut conn = std::pin::pin!(conn);
    tokio::select! {
        _ = conn.as_mut() => return,
        _ = token.reached(Phase::Draining) => {}
    }
    graceful(conn.as_mut());
    tokio::select! {
        _ = conn.as_mut() => {}
        _ = token.reached(Phase::Closing) => {}
    }
}

/// Completes on SIGTERM (`docker stop`, `systemctl stop`) or SIGINT (Ctrl-C).
pub async fn signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => tokio::select! {
                _ = term.recv() => {}
                _ = ctrl_c() => {}
            },
            Err(e) => {
                eprintln!(
                    "pattern-guard-gateway: cannot listen for SIGTERM ({e}); stopping on Ctrl-C only"
                );
                ctrl_c().await
            }
        }
    }
    #[cfg(not(unix))]
    ctrl_c().await
}

async fn ctrl_c() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Steps 1–4 of the module docs, once the signal has arrived.
pub(crate) async fn finish(state: &State, drain: &Drain) {
    let grace = state.compiled().cfg.limits.shutdown_grace_secs; // as reloaded
    let deadline = Instant::now() + Duration::from_secs(grace);
    eprintln!("pattern-guard-gateway: shutting down; requests in progress have {grace}s to finish");
    let cut = drain.drain(deadline).await;
    if cut > 0 {
        eprintln!("pattern-guard-gateway: closed {cut} connections still open after {grace}s");
    }
    if let Some(log) = &state.runtime.log {
        let until = deadline.max(Instant::now() + FLUSH_MIN);
        if tokio::time::timeout_at(until, log.flush()).await.is_err() {
            eprintln!(
                "pattern-guard-gateway: the disk is too slow; decision-log lines still queued are lost"
            );
        }
    }
}
