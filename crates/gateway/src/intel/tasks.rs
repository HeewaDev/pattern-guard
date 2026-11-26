//! The config-driven intel tasks: the CrowdSec bouncer and one tail per alert feed.
//! They are kept here so a reload can restart the ones whose config changed and leave
//! the others running.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::runtime::Handle;
use tokio::task::JoinHandle;

use super::{IntelStore, crowdsec, feeds};
use crate::config::{CrowdSecConfig, FeedConfig, GatewayConfig};
use crate::observability::metrics::Metrics;

/// The running tasks; empty until [`start`](Self::start).
#[derive(Default)]
pub struct IntelTasks(Mutex<Option<Running>>);

struct Running {
    /// The runtime the tasks run on, so a reload from any thread can start new ones.
    rt: Handle,
    intel: Arc<IntelStore>,
    metrics: Arc<Metrics>,
    crowdsec: Option<(CrowdSecConfig, JoinHandle<()>)>,
    /// Removes a stopped bouncer's decisions once the bouncer has really ended. A bouncer
    /// started later waits for it.
    crowdsec_cleanup: Option<JoinHandle<()>>,
    feeds: Vec<(FeedConfig, JoinHandle<()>)>,
}

/// The CrowdSec API key `cfg` needs, if CrowdSec is enabled. Read before anything
/// starts or changes, so a missing key fails the startup or the reload.
pub fn crowdsec_key(cfg: &GatewayConfig) -> Result<Option<String>, String> {
    cfg.crowdsec
        .enabled
        .then(|| crowdsec::api_key(&cfg.crowdsec))
        .transpose()
}

impl IntelTasks {
    fn lock(&self) -> MutexGuard<'_, Option<Running>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts the tasks `cfg` asks for (`key`: from [`crowdsec_key`]) on the current
    /// Tokio runtime.
    pub fn start(
        &self,
        cfg: &GatewayConfig,
        key: Option<String>,
        intel: &Arc<IntelStore>,
        metrics: &Arc<Metrics>,
    ) {
        let mut running = Running {
            rt: Handle::current(),
            intel: intel.clone(),
            metrics: metrics.clone(),
            crowdsec: None,
            crowdsec_cleanup: None,
            feeds: Vec::new(),
        };
        running.crowdsec = key.map(|k| {
            let task = running.spawn_crowdsec(cfg, k, None);
            (cfg.crowdsec.clone(), task)
        });
        running.feeds = (cfg.feeds.iter())
            .map(|f| (f.clone(), running.spawn_feed(f)))
            .collect();
        if let Some(old) = self.lock().replace(running) {
            old.stop();
        }
    }

    /// Brings the tasks in line with `cfg`: a task whose config is unchanged keeps
    /// running, one whose config changed is restarted, one that is no longer configured
    /// is stopped. Does nothing if the tasks were never started (a gateway embedded
    /// without `start_background`). Returns what changed, for the reload's log line.
    ///
    /// When CrowdSec is turned off, its decisions are removed with it, once the aborted
    /// bouncer has ended (`abort` takes effect at its next `.await`, so it may still be
    /// writing a poll's decisions). A restarted bouncer waits for the one it replaces to
    /// end, then asks for the full decision list again (`startup=true`). A restarted feed
    /// starts at the end of its file, like at startup. Entries from a stopped feed
    /// expire on their own (`block_secs`).
    pub fn update(&self, cfg: &GatewayConfig, key: Option<String>) -> Vec<String> {
        let mut g = self.lock();
        let Some(r) = g.as_mut() else {
            return Vec::new();
        };
        let mut changed = Vec::new();
        let unchanged = match (&r.crowdsec, &key) {
            (Some((old, _)), Some(_)) => *old == cfg.crowdsec,
            (None, None) => true,
            _ => false,
        };
        if !unchanged {
            let previous = r.crowdsec.take().map(|(_, task)| {
                task.abort();
                task
            });
            match key {
                Some(k) => {
                    let after = previous.or_else(|| r.crowdsec_cleanup.take());
                    let task = r.spawn_crowdsec(cfg, k, after);
                    r.crowdsec = Some((cfg.crowdsec.clone(), task));
                    changed.push("crowdsec restarted".to_string());
                }
                None => {
                    let intel = r.intel.clone();
                    r.crowdsec_cleanup = Some(r.rt.spawn(async move {
                        if let Some(task) = previous {
                            let _ = task.await;
                        }
                        intel.clear_source("crowdsec");
                    }));
                    changed.push("crowdsec stopped".to_string());
                }
            }
        }
        let mut old: Vec<Option<(FeedConfig, JoinHandle<()>)>> =
            r.feeds.drain(..).map(Some).collect();
        for f in &cfg.feeds {
            let same = old
                .iter_mut()
                .find(|o| o.as_ref().is_some_and(|(c, _)| c == f))
                .and_then(Option::take);
            let entry = same.unwrap_or_else(|| {
                changed.push(format!("feed {} started", f.path.display()));
                (f.clone(), r.spawn_feed(f))
            });
            r.feeds.push(entry);
        }
        for (f, task) in old.into_iter().flatten() {
            task.abort();
            changed.push(format!("feed {} stopped", f.path.display()));
        }
        changed
    }
}

impl Running {
    /// Starts a bouncer once `after` (the bouncer it replaces, or the clean-up of a
    /// stopped one) has ended, so their writes can't land after its full refresh.
    fn spawn_crowdsec(
        &self,
        cfg: &GatewayConfig,
        key: String,
        after: Option<JoinHandle<()>>,
    ) -> JoinHandle<()> {
        let bouncer = crowdsec::run(
            cfg.crowdsec.clone(),
            key,
            self.intel.clone(),
            self.metrics.clone(),
        );
        self.rt.spawn(async move {
            if let Some(task) = after {
                let _ = task.await;
            }
            bouncer.await;
        })
    }

    fn spawn_feed(&self, f: &FeedConfig) -> JoinHandle<()> {
        self.rt.spawn(feeds::run(
            f.clone(),
            self.intel.clone(),
            self.metrics.clone(),
        ))
    }

    fn stop(self) {
        if let Some((_, task)) = self.crowdsec {
            task.abort();
        }
        for (_, task) in self.feeds {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(toml: &str) -> GatewayConfig {
        GatewayConfig::from_toml_str(&format!("upstream = \"http://127.0.0.1:1\"\n{toml}")).unwrap()
    }

    #[tokio::test]
    async fn only_changed_tasks_are_restarted() {
        let (intel, metrics) = (
            Arc::new(IntelStore::default()),
            Arc::new(Metrics::default()),
        );
        let tasks = IntelTasks::default();
        let feeds = |paths: &[&str]| {
            paths.iter().fold(String::new(), |mut s, p| {
                s.push_str("[[feeds]]\nkind = \"suricata\"\npath = \"/nonexistent/");
                s.push_str(p);
                s.push_str("\"\n");
                s
            })
        };
        let none = cfg(&feeds(&["a", "b"]));
        assert!(tasks.update(&none, None).is_empty(), "not started");
        tasks.start(&none, None, &intel, &metrics);
        assert!(tasks.update(&none, None).is_empty());
        let changed = tasks.update(&cfg(&feeds(&["b", "c"])), None);
        assert_eq!(
            changed,
            ["feed /nonexistent/c started", "feed /nonexistent/a stopped"]
        );
        // CrowdSec turned on, then off: its decisions go with it
        let on = cfg(&format!(
            "{}[crowdsec]\nenabled = true\napi_key = \"k\"\nurl = \"http://127.0.0.1:1\"\n",
            feeds(&["b", "c"])
        ));
        let key = crowdsec_key(&on).unwrap();
        assert_eq!(tasks.update(&on, key.clone()), ["crowdsec restarted"]);
        assert!(tasks.update(&on, key).is_empty());
        intel.add(
            crate::ipnet::Cidr::parse("192.0.2.1").unwrap(),
            crate::intel::IntelEntry {
                action: crate::intel::IntelAction::Ban,
                source: "crowdsec:CAPI".into(),
                reason: "x".into(),
                expires: None,
            },
        );
        let off = cfg(&feeds(&["b", "c"]));
        assert_eq!(tasks.update(&off, None), ["crowdsec stopped"]);
        // removed once the aborted bouncer has ended
        for _ in 0..100 {
            if intel.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(intel.is_empty());
        // turned on again: the new bouncer runs after the clean-up
        let key = crowdsec_key(&on).unwrap();
        assert_eq!(tasks.update(&on, key), ["crowdsec restarted"]);
        let r = tasks.lock();
        let r = r.as_ref().unwrap();
        assert!(r.crowdsec.is_some() && r.crowdsec_cleanup.is_none());
    }

    /// The clean-up of a stopped bouncer waits for the bouncer: decisions it writes after
    /// `abort` (in the middle of applying a poll, between two awaits) are removed too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn crowdsec_decisions_written_after_the_abort_are_removed() {
        let (intel, metrics) = (
            Arc::new(IntelStore::default()),
            Arc::new(Metrics::default()),
        );
        let on = cfg("[crowdsec]\nenabled = true\napi_key = \"k\"\nurl = \"http://127.0.0.1:1\"\n");
        let tasks = IntelTasks::default();
        tasks.start(&on, crowdsec_key(&on).unwrap(), &intel, &metrics);
        // in place of the bouncer: a task that is inside synchronous work when it is
        // aborted, and writes a decision when that work ends
        let (started, running) = tokio::sync::oneshot::channel::<()>();
        let busy = {
            let intel = intel.clone();
            tokio::spawn(async move {
                let _ = started.send(());
                std::thread::sleep(std::time::Duration::from_millis(200)); // no await
                intel.add(
                    crate::ipnet::Cidr::parse("192.0.2.9").unwrap(),
                    crate::intel::IntelEntry {
                        action: crate::intel::IntelAction::Ban,
                        source: "crowdsec:CAPI".into(),
                        reason: "late".into(),
                        expires: None,
                    },
                );
            })
        };
        if let Some((_, task)) = tasks.lock().as_mut().unwrap().crowdsec.as_mut() {
            task.abort();
            *task = busy;
        }
        running.await.unwrap();
        assert_eq!(tasks.update(&cfg(""), None), ["crowdsec stopped"]);
        let cleanup = tasks.lock().as_mut().unwrap().crowdsec_cleanup.take();
        cleanup.unwrap().await.unwrap();
        assert!(intel.is_empty(), "the late decision is removed too");
    }
}
