//! End-to-end behaviour of the adaptive engine with the built-in model.

use std::time::{Duration, SystemTime};

use pattern_guard::{Decision, Event, Guard};

fn at(t: f64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000) + Duration::from_secs_f64(t)
}

fn browser(ip: &str, path: &str, t: f64) -> Event {
    Event::new(format!("ip:{ip}"), "GET", path, at(t))
        .with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0")
}

/// 30 browsing users for 10 minutes: html + api + images, 20–40 s between pages.
fn browse(g: &Guard, until: f64) -> (usize, usize) {
    let (mut total, mut stopped) = (0, 0);
    let mut events = Vec::new();
    for u in 0..30u64 {
        let ip = format!("198.51.100.{}", u + 1);
        let mut t = u as f64 * 3.0;
        let mut page = u * 101;
        while t < until {
            page = (page * 7 + 13) % 5000;
            for (k, p) in [
                format!("/product/{page}"),
                format!("/api/product/{page}"),
                "/api/cart".to_string(),
                format!("/img/{page}_0.jpg"),
                format!("/img/{page}_1.jpg"),
            ]
            .into_iter()
            .enumerate()
            {
                events.push((t + k as f64 * 0.1, ip.clone(), p));
            }
            t += 20.0 + (page % 20) as f64;
        }
    }
    events.sort_by(|a, b| a.0.total_cmp(&b.0));
    for (t, ip, p) in events {
        let e = browser(&ip, &p, t);
        let a = g.assess(&e);
        g.observe_response(&e, 200);
        total += 1;
        stopped += a.decision.is_mitigation() as usize;
    }
    (total, stopped)
}

#[test]
fn normal_browsing_is_not_stopped() {
    let g = Guard::from_toml_str("").unwrap();
    let (total, stopped) = browse(&g, 600.0);
    assert!(total > 1000);
    assert!(
        (stopped as f64) < total as f64 * 0.005,
        "{stopped} of {total} legitimate requests stopped"
    );
}

#[test]
fn single_ip_flood_is_blocked_with_reasons() {
    let g = Guard::from_toml_str("").unwrap();
    browse(&g, 400.0);
    let mut last = None;
    for i in 0..2000 {
        let t = 400.0 + i as f64 * 0.02;
        let e = Event::new("ip:192.0.2.66", "GET", format!("/search?q={i}"), at(t))
            .with_user_agent("curl/8.5.0");
        let a = g.assess(&e);
        g.observe_response(&e, 200);
        last = Some(a);
    }
    let a = last.unwrap();
    assert_eq!(a.decision, Decision::Block);
    assert!(a.bot_score <= 5, "bot score {}", a.bot_score);
    assert!(!a.reasons.is_empty());
}

#[test]
fn sequential_scraper_is_caught() {
    let g = Guard::from_toml_str("").unwrap();
    browse(&g, 300.0);
    let mut stopped = 0;
    for i in 0..120 {
        let t = 300.0 + i as f64 * 7.3;
        let e = Event::new(
            "ip:192.0.2.77",
            "GET",
            format!("/product/{}", 1000 + i),
            at(t),
        )
        .with_user_agent("Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/130.0");
        let a = g.assess(&e);
        g.observe_response(&e, 200);
        if i >= 20 {
            stopped += a.decision.is_mitigation() as usize;
        }
    }
    assert!(
        stopped >= 90,
        "only {stopped} of 100 scraper requests stopped"
    );
}

#[test]
fn custom_model_from_config_path() {
    let dir = std::env::temp_dir().join(format!("pg_model_cfg_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("m.toml"),
        pattern_guard::Model::builtin().to_toml_string(),
    )
    .unwrap();
    std::fs::write(dir.join("guard.toml"), "[guard]\nmodel = \"m.toml\"\n").unwrap();
    let g = Guard::from_config_path(dir.join("guard.toml")).unwrap();
    assert!(g.model().description.starts_with("built-in"));
    std::fs::write(dir.join("bad.toml"), "[guard]\nmodel = \"missing.toml\"\n").unwrap();
    assert!(Guard::from_config_path(dir.join("bad.toml")).is_err());
}
