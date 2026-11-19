//! `cargo run -p pattern-guard --example repetition_demo` — uses config/demo/repetition.toml

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let guard = pattern_guard::Guard::from_config_path(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../config/demo/repetition.toml"
    ))?;

    let action = "GET";
    let target = "/api/foo";

    for i in 1..=8 {
        let event = pattern_guard::Event::new("demo", action, target, std::time::SystemTime::now());
        let (decision, risk) = guard.check_with_risk(&event);
        println!("  {}: risk = {:.2}  ->  {:?}", i, risk, decision);
    }

    Ok(())
}
