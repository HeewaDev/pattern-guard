//! `cargo run -p pattern-guard --example burst_demo` — uses config/demo/burst.toml

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let guard = pattern_guard::Guard::from_config_path(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../config/demo/burst.toml"
    ))?;

    for i in 1..=8 {
        let event = pattern_guard::Event::new(
            "demo",
            "run",
            format!("iteration {}", i),
            std::time::SystemTime::now(),
        );
        let (decision, risk) = guard.check_with_risk(&event);
        println!("  {}: risk = {:.2}  ->  {:?}", i, risk, decision);
    }

    Ok(())
}
