//! `cargo run --example repetition_demo` — uses guard.toml.repetition_demo

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let guard = pattern_guard::Guard::from_config_path("guard.toml.repetition_demo")?;

    let action = "GET";
    let target = "/api/foo";

    for i in 1..=8 {
        let event = pattern_guard::Event::new("demo", action, target, std::time::SystemTime::now());
        let (decision, risk) = guard.check_with_risk(&event);
        println!("  {}: risk = {:.2}  ->  {:?}", i, risk, decision);
    }

    Ok(())
}
