//! I6 regression probe: a zero-rights naming cap must not let the holder push
//! capabilities into a task's CSpace. Before the fix this saturated the victim's
//! 256-slot CSpace ("attacker injected 255 caps ... CspaceFull for legit grants").
//! After the fix the first injection attempt is rejected. Run: cargo run -p capability-core --example probe3

use capability_core::{CapHandle, Kernel, Rights};

fn main() {
    let mut k = Kernel::new();
    let (root, _self, creator) = k.boot("root").unwrap();
    let (_victim, victim_cap) = k.create_task(root, creator, "victim").unwrap();
    let (attacker, attacker_cap) = k.create_task(root, creator, "attacker").unwrap();

    // attacker gets ONLY a zero-rights naming reference to victim — no CONTROL,
    // no GRANT, no RECEIVE. It only proves the victim exists.
    k.grant(root, victim_cap, attacker_cap, Rights::NONE, None)
        .unwrap();
    let victim_naming = CapHandle(1);

    // One reusable GRANT-capable resource: grant() mints a fresh cap into a fresh
    // slot on every call, even from the same source.
    let (_r, r_cap) = k.create_task(root, creator, "junk").unwrap();
    k.grant(root, r_cap, attacker_cap, Rights::GRANT, None)
        .unwrap();
    let resource = CapHandle(2);

    let mut successes = 0;
    for _ in 0..260 {
        match k.grant(attacker, resource, victim_naming, Rights::CONTROL, None) {
            Ok(()) => successes += 1,
            Err(e) => {
                println!("first injection attempt => Err({e})");
                break;
            }
        }
    }
    assert_eq!(
        successes, 0,
        "attacker injected {successes} caps without consent"
    );
    println!("[PASS] attacker with a zero-rights naming cap injected {successes} caps");

    // The legitimate orchestrator's grants still land — the victim's CSpace is open.
    let (_svc, svc_cap) = k.create_task(root, creator, "legit-service").unwrap();
    let legit = k.grant(root, svc_cap, victim_cap, Rights::CONTROL, None);
    println!("legitimate grant to victim after the fix => {legit:?}");
    assert!(legit.is_ok());
    println!("[PASS] legitimate grant to victim still works (I6 respects consent, not lockdown)");
    println!("result: zero-rights naming cap confers no write access to a task's CSpace");
}
