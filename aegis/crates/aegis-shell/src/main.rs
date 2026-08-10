fn main() {
    let outcome = aegis_shell::demo::run();
    println!(
        "result: {} required escalation attempts were all rejected",
        outcome.failed_escalations
    );
    println!("OK: the ceiling held; every authorized action succeeded.");
}
