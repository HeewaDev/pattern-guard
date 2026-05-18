use criterion::{Criterion, black_box, criterion_group, criterion_main};
use pattern_guard::{Event, Guard};
use std::time::SystemTime;

fn bench_check_with_risk(c: &mut Criterion) {
    let config = concat!(env!("CARGO_MANIFEST_DIR"), "/guard.toml.demo");
    let guard = Guard::from_config_path(config).unwrap();
    c.bench_function("check_with_risk_demo_config", |b| {
        b.iter(|| {
            let event = Event::new("bench", "run", "cmd", SystemTime::now());
            guard.check_with_risk(black_box(&event))
        });
    });
}

criterion_group!(benches, bench_check_with_risk);
criterion_main!(benches);
