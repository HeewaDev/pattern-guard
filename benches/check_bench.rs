use criterion::{Criterion, black_box, criterion_group, criterion_main};
use pattern_guard::{Event, Guard};
use std::time::{Duration, SystemTime};

fn bench_check_with_risk(c: &mut Criterion) {
    let config = concat!(env!("CARGO_MANIFEST_DIR"), "/guard.toml.demo");
    let guard = Guard::from_config_path(config).unwrap();
    c.bench_function("rules_only_demo_config", |b| {
        b.iter(|| {
            let event = Event::new("bench", "run", "cmd", SystemTime::now());
            guard.check_with_risk(black_box(&event))
        });
    });
}

fn bench_flood_single_actor(c: &mut Criterion) {
    // 0.2 slowed down linearly with the flood size; this must stay flat.
    let guard = Guard::from_toml_str("[guard]\nburst_max_events = 100\n").unwrap();
    let t0 = SystemTime::now();
    for _ in 0..50_000 {
        guard.check(&Event::new("ip:6.6.6.6", "GET", "/search?q=x", t0));
    }
    c.bench_function("hybrid_check_after_50k_flood_events", |b| {
        b.iter(|| {
            guard.check(black_box(&Event::new(
                "ip:6.6.6.6",
                "GET",
                "/search?q=x",
                t0,
            )))
        });
    });
}

criterion_group!(
    benches,
    bench_check_with_risk,
    bench_flood_single_actor
);
criterion_main!(benches);
