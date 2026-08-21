use capability_audit::audit::audit;
use capability_audit::manifests;
use capability_core::{CapHandle, Kernel, ObjectKind, Rights, TaskHandle};
use fleet::{Fleet, NodeId, RemoteCapability};
use orchestration::{Action, Decision, Orchestrator};
use resources::{Alloc, Budget};
use supervision_tree::{RestartPolicy, Supervisor};

const MAX_CAPS: usize = 4096;
const MAX_TASKS: usize = 256;

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
    fn chance(&mut self, p: u64) -> bool {
        self.below(100) < p
    }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        let i = self.below(v.len() as u64) as usize;
        &v[i]
    }
}

struct World {
    rng: Rng,
    k: Kernel,
    creator: CapHandle,
    tasks: Vec<(TaskHandle, CapHandle)>,
    caps: Vec<CapHandle>,
    orch: Orchestrator,
    sup: Supervisor,
    sub_caps: Vec<CapHandle>,
    subsystems: u32,
    alloc: Alloc,
    fleet: Fleet,
    fleet_a: Fleet,
    fleet_b: Fleet,
    peer_a: NodeId,
    peer_b: NodeId,
    max_restarts: u32,
    last_audit_len: usize,
    steps: u64,
    checks: u64,
}

fn node_id(b: u8) -> NodeId {
    NodeId([b; 32])
}

fn random_rights(w: &mut World) -> Rights {
    let all = [
        Rights::READ,
        Rights::WRITE,
        Rights::CONTROL,
        Rights::SEND,
        Rights::RECV,
        Rights::GRANT,
        Rights::RECEIVE,
    ];
    let mut r = Rights::NONE;
    for &c in all.iter() {
        if w.rng.chance(40) {
            r = r.union(c);
        }
    }
    r
}

fn new_world(seed: u64) -> World {
    let rng = Rng::new(seed);
    let mut k = Kernel::new();
    let (root, root_cap, creator) = k.boot("soak-root").expect("boot");
    let mut tasks = vec![(root, root_cap)];
    let mut caps = vec![root_cap, creator];

    for _ in 0..8u64 {
        if let Ok((t, tc)) = k.create_task(root, creator, "soak-child") {
            tasks.push((t, tc));
            if let Ok(c) = k.create_endpoint(root, creator) {
                caps.push(c);
            }
            if let Ok(c) = k.create_mem(root, creator, vec![0u8; 64]) {
                caps.push(c);
            }
            if let Ok(c) = k.create_grant_root(root, creator) {
                caps.push(c);
            }
        }
    }

    let orch = Orchestrator::start(&mut k).expect("orchestrator start");

    let mut sup = Supervisor::new(root);
    let mut sub_caps: Vec<CapHandle> = Vec::new();
    let mut svc = 0;
    for t in tasks.iter().take(3).skip(1) {
        svc += 1;
        if sup
            .add(
                &mut k,
                &format!("svc{svc}"),
                t.0,
                t.1,
                RestartPolicy { max_restarts: 2 },
            )
            .is_ok()
        {
            sub_caps.push(t.1);
        }
    }
    let subsystems = sub_caps.len() as u32;

    let mut fleet = Fleet::new(node_id(1), [7u8; 32]);
    let peer_a = node_id(2);
    let peer_b = node_id(3);
    fleet.register_peer(peer_a, [9u8; 32]).expect("peer a");
    fleet.register_peer(peer_b, [11u8; 32]).expect("peer b");
    fleet.heartbeat(peer_a).expect("hb a");
    let mut fleet_a = Fleet::new(peer_a, [9u8; 32]);
    let mut fleet_b = Fleet::new(peer_b, [11u8; 32]);
    fleet_a
        .register_peer(node_id(1), [7u8; 32])
        .expect("a knows node1");
    fleet_b
        .register_peer(node_id(1), [7u8; 32])
        .expect("b knows node1");

    let alloc = Alloc::root(
        root,
        Budget {
            cpu: 1000,
            mem: 1000,
        },
    );

    World {
        rng,
        k,
        creator,
        tasks,
        caps,
        orch,
        sup,
        sub_caps,
        subsystems,
        alloc,
        fleet,
        fleet_a,
        fleet_b,
        peer_a,
        peer_b,
        max_restarts: 2,
        last_audit_len: 0,
        steps: 0,
        checks: 0,
    }
}

fn check_invariants(w: &mut World) -> Result<(), String> {
    w.checks += 1;
    let al = w.k.audit().len();
    if al < w.last_audit_len {
        return Err(format!("audit log shrank {} -> {}", w.last_audit_len, al));
    }
    w.last_audit_len = al;
    for a in w.k.authorized(w.tasks[0].0) {
        if a.slot >= 256 {
            return Err(format!("root cspace slot {} out of bounds", a.slot));
        }
    }
    Ok(())
}

fn kernel_chaos(w: &mut World) -> Result<(), String> {
    let sub = w.rng.below(11);
    match sub {
        0 => {
            if w.tasks.len() < MAX_TASKS {
                if let Ok((t, tc)) = w.k.create_task(w.tasks[0].0, w.creator, "soak-child") {
                    w.tasks.push((t, tc));
                    if w.caps.len() < MAX_CAPS {
                        w.caps.push(tc);
                    }
                }
            }
        }
        1 => {
            if let Ok(c) = w.k.create_endpoint(w.tasks[0].0, w.creator) {
                if w.caps.len() < MAX_CAPS {
                    w.caps.push(c);
                }
            }
        }
        2 => {
            if let Ok(c) = w.k.create_mem(
                w.tasks[0].0,
                w.creator,
                vec![0u8; (w.rng.below(64) + 1) as usize],
            ) {
                if w.caps.len() < MAX_CAPS {
                    w.caps.push(c);
                }
            }
        }
        3 => {
            let source = *w.rng.pick(&w.caps);
            let rights = random_rights(w);
            if let Ok(si) = w.k.cap_info(w.tasks[0].0, source) {
                if let Ok(nc) = w.k.copy(w.tasks[0].0, source, rights) {
                    if let Ok(ni) = w.k.cap_info(w.tasks[0].0, nc) {
                        if !si.rights.superset_of(ni.rights) {
                            return Err("copy expanded rights beyond source".into());
                        }
                    }
                    if w.caps.len() < MAX_CAPS {
                        w.caps.push(nc);
                    }
                }
            }
        }
        4 => {
            let grant_root = *w.rng.pick(&w.caps);
            let source = *w.rng.pick(&w.caps);
            let (into_task, into_cap) = w.tasks[w.rng.below(w.tasks.len() as u64) as usize];
            let rights = random_rights(w);
            let expiry = if w.rng.chance(50) {
                None
            } else {
                Some(w.k.now() + w.rng.below(1000))
            };
            if let Ok(si) = w.k.cap_info(w.tasks[0].0, source) {
                if let Ok(nc) =
                    w.k.grant_mint(w.tasks[0].0, grant_root, source, into_cap, rights, expiry)
                {
                    if let Ok(ni) = w.k.cap_info(into_task, nc) {
                        if !si.rights.superset_of(ni.rights) {
                            return Err("grant_mint expanded rights beyond source".into());
                        }
                    }
                    if w.caps.len() < MAX_CAPS {
                        w.caps.push(nc);
                    }
                }
            }
        }
        5 => {
            let cap = *w.rng.pick(&w.caps);
            let obj_before = w.k.cap_info(w.tasks[0].0, cap).map(|i| i.obj).ok();
            let revoked = w.k.revoke(w.tasks[0].0, cap).is_ok();
            if revoked && obj_before.is_some() && w.k.cap_info(w.tasks[0].0, cap).is_ok() {
                return Err("revoked cap still resolvable (subtree removal failed)".into());
            }
        }
        6 => {
            let cap = *w.rng.pick(&w.caps);
            if w.k.destroy(w.tasks[0].0, cap).is_ok() && w.k.cap_info(w.tasks[0].0, cap).is_ok() {
                return Err("destroyed cap still resolvable".into());
            }
        }
        7 => {
            let ep = *w.rng.pick(&w.caps);
            let msg = vec![w.rng.below(256) as u8; (w.rng.below(8) + 1) as usize];
            let _ = w.k.ep_send(w.tasks[0].0, ep, msg);
            let _ = w.k.ep_recv(w.tasks[0].0, ep);
        }
        8 => {
            let m = *w.rng.pick(&w.caps);
            let off = w.rng.below(32) as usize;
            let bytes = vec![w.rng.below(256) as u8; (w.rng.below(8) + 1) as usize];
            let _ = w.k.mem_write(w.tasks[0].0, m, off, bytes);
            let _ = w.k.mem_read(w.tasks[0].0, m, off, 8);
        }
        9 => {
            let (_, tcap) = w.tasks[w.rng.below(w.tasks.len() as u64) as usize];
            let _ = w.k.task_kill(w.tasks[0].0, tcap);
            let _ = w.k.task_spawn(w.tasks[0].0, tcap);
        }
        _ => {
            w.k.advance(w.rng.below(50));
        }
    }
    Ok(())
}

fn orch_chaos(w: &mut World) -> Result<(), String> {
    let action = match w.rng.below(4) {
        0 => Action::ReadServiceState,
        1 => Action::RestartService,
        2 => {
            let t = w.tasks[w.rng.below(w.tasks.len() as u64) as usize].0;
            Action::KillForeign(t.id())
        }
        _ => Action::ReadStateBurst(w.rng.below(8) as usize + 1),
    };
    let before = w.k.audit().len();
    let d = w.orch.act(&mut w.k, action);
    match d {
        Decision::CeilingDenied { .. } | Decision::SuspendedGate { .. } => {
            if w.k.audit().len() != before {
                return Err("denied action mutated kernel before execution".into());
            }
        }
        Decision::Approved { .. } => {}
    }
    if w.rng.chance(30) {
        w.orch.supervise(&mut w.k);
    }
    if w.rng.chance(20) {
        let _ = w.orch.monitor_pass(&mut w.k);
    }
    Ok(())
}

fn sup_chaos(w: &mut World) -> Result<(), String> {
    if w.subsystems == 0 {
        return Ok(());
    }
    let idx = w.rng.below(w.subsystems as u64) as usize;
    let tcap = w.sub_caps[idx];
    let _ = w.k.task_kill(w.tasks[0].0, tcap);
    w.sup.pump(&mut w.k);
    for i in 0..w.subsystems {
        let r = w.sup.restarts_of(i as usize);
        if r > w.max_restarts {
            return Err(format!(
                "supervisor exceeded restart budget: {} > {}",
                r, w.max_restarts
            ));
        }
    }
    Ok(())
}

fn fleet_chaos(w: &mut World) -> Result<(), String> {
    if w.rng.chance(50) {
        let _ = w.fleet.heartbeat(w.peer_a);
        let chain = w
            .fleet_a
            .issue(0x200, ObjectKind::MemRegion, Rights::READ, None);
        let remote = w
            .fleet_a
            .send_to(chain, node_id(1))
            .map_err(|e| format!("send_to a: {e:?}"))?;
        if w.fleet.verify(&remote).is_err() {
            return Err("fleet verify failed on reachable peer (happy path)".into());
        }
    } else {
        let chain = w
            .fleet_b
            .issue(0x300, ObjectKind::Endpoint, Rights::SEND, None);
        let remote = w
            .fleet_b
            .send_to(chain, node_id(1))
            .map_err(|e| format!("send_to b: {e:?}"))?;
        let _ = w.fleet.mark_unreachable(w.peer_b);
        if w.fleet.verify(&remote).is_ok() {
            return Err("fleet verify succeeded on unreachable issuer (fail-closed)".into());
        }
    }
    let chain = w.fleet.issue(0x400, ObjectKind::Task, Rights::ALL, None);
    let local: RemoteCapability = w.fleet.hold_local(chain);
    let bytes = Fleet::serialize(&local).map_err(|e| format!("serialize: {e:?}"))?;
    let back = Fleet::deserialize(&bytes).map_err(|e| format!("deserialize: {e:?}"))?;
    if w.fleet.verify(&back).is_err() {
        return Err("fleet serialize/deserialize roundtrip verify failed".into());
    }
    Ok(())
}

fn res_chaos(w: &mut World) -> Result<(), String> {
    if w.tasks.len() <= 2 {
        return Ok(());
    }
    let pi = 1 + w.rng.below((w.tasks.len() - 1) as u64) as usize;
    let ci = 1 + w.rng.below((w.tasks.len() - 1) as u64) as usize;
    if pi == ci {
        return Ok(());
    }
    let parent = w.tasks[pi].0;
    let child = w.tasks[ci].0;
    let budget = Budget {
        cpu: w.rng.below(100),
        mem: w.rng.below(100),
    };
    if let Ok(()) = w.alloc.give(parent, child, budget) {
        match w.alloc.remaining(child) {
            Some(b) => {
                if b.cpu != budget.cpu || b.mem != budget.mem {
                    return Err(format!(
                        "resource ledger mismatch: gave {:?} child has {:?}",
                        budget, b
                    ));
                }
            }
            None => return Err("child missing from ledger after successful give".into()),
        }
    }
    Ok(())
}

fn audit_smoke(w: &mut World) {
    let bindings = [(w.tasks[0].0, &manifests::session())];
    let report = audit(&w.k, &bindings);
    let _ = report.violation_count();
    let _ = report.warning_count();
}

fn step(w: &mut World) -> Result<(), String> {
    match w.rng.below(6) {
        0 => kernel_chaos(w)?,
        1 => orch_chaos(w)?,
        2 => sup_chaos(w)?,
        3 => fleet_chaos(w)?,
        4 => res_chaos(w)?,
        _ => audit_smoke(w),
    }
    check_invariants(w)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut seed: u64 = 0x50_0a_50_0a;
    let mut duration_s: u64 = 1200;
    let mut max_steps: u64 = u64::MAX;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                seed = args
                    .get(i + 1)
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                    .unwrap_or(seed);
                i += 2;
            }
            "--duration" => {
                duration_s = args
                    .get(i + 1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(duration_s);
                i += 2;
            }
            "--steps" => {
                max_steps = args
                    .get(i + 1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(max_steps);
                i += 2;
            }
            _ => i += 1,
        }
    }

    let mut w = new_world(seed);
    w.last_audit_len = w.k.audit().len();
    let start = std::time::Instant::now();
    let result = loop {
        if let Err(e) = step(&mut w) {
            eprintln!(
                "SOAK FAILURE after {} steps / {} invariant checks: {}",
                w.steps, w.checks, e
            );
            break Err(e);
        }
        w.steps += 1;
        if w.steps % 2000 == 0 {
            eprintln!(
                "[soak] step {} checks {} audit_len {}",
                w.steps,
                w.checks,
                w.k.audit().len()
            );
        }
        if duration_s != 0 && start.elapsed().as_secs() >= duration_s {
            break Ok(());
        }
        if w.steps >= max_steps {
            break Ok(());
        }
    };

    match result {
        Ok(()) => {
            println!(
                "SOAK OK: {} steps, {} invariant checks, audit_len {}",
                w.steps,
                w.checks,
                w.k.audit().len()
            );
            std::process::exit(0);
        }
        Err(_) => std::process::exit(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soak_smoke_bounded() {
        let mut w = new_world(0x50_0a_50_0a);
        w.last_audit_len = w.k.audit().len();
        for _ in 0..400 {
            step(&mut w).expect("soak smoke invariant violation");
        }
    }
}
