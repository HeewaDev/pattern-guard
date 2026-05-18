//! `cargo run --example burst_demo` — uses guard.toml.demo

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let guard = pattern_guard::Guard::from_config_path("guard.toml.demo")?;

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
