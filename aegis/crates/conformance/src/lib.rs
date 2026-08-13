//! Phase 4 conformance harness (master roadmap): replay the *kernel's* live
//! capability trace against the capability-core model and assert that the
//! model's authorization verdict agrees with the kernel's recorded verdict at
//! every step.
//!
//! The kernel (`aegis-kernel`, feature `trace`) emits one `C:op` line per
//! capability-relevant syscall at the dispatch choke point and one `C:spawn`
//! line per task, to COM1. This crate parses that stream into `Ev` events,
//! reconstructs the authority state in the model (`Kernel`), and drives the
//! corresponding model operation for every event. Each event is compared as
//! a two-way verdict: the kernel recorded `ok`/`denied`, the model produces
//! `Ok`/`Err`; a disagreement is a `divergence`.
//!
//! The fixture `traces/ring3-demo.trace` was captured from a verified QEMU
//! boot of the ring-3 capability-denial demo (a task granted nothing attempts
//! gated ops). The replay test asserts zero divergences: the model agrees that
//! the denied task's `ipc_call`/`mem_len`/`task_state` are all denied, that the
//! client's `ipc_call` is authorized, and that the server's create/grant/
//! serve/reply are authorized.
//!
//! ## What is compared, and what is adapted
//!
//! Compared faithfully: the authorization verdict of every traced op — the
//! model resolves each op through its own CSpace and rights rules, entirely
//! independent of the kernel's recorded `y` field. The kernel's `y` is the
//! ground truth; the model is the oracle; agreement is the conformance claim.
//!
//! Adapted (documented divergences between the two implementations' mechanics,
//! none of which can flip an authorized op into a denied one):
//!
//! * **Creator caps.** The kernel mints endpoints/regions from a global pool
//!   with no creation-cap gate; the model requires a `Creator` cap. Before
//!   replaying an endpoint/region create by a non-root task, the harness has
//!   the root grant that task a `Creator` cap (the model's own creation
//!   ceremony). The created object and its rights are the same.
//! * **Consent (I6).** The kernel's `grant` names a destination task by raw
//!   index; the model requires a Task-naming cap carrying `RECEIVE` in the
//!   grantor's CSpace. The harness synthesizes that consent cap (root grants
//!   the grantor a `CONTROL|RECEIVE` naming cap to the grantee) before
//!   replaying the grant. The GRANT-right gate on the source is exercised
//!   faithfully by the model.
//! * **Revocation scope (I4).** The kernel's `revoke` clears one named
//!   instance; the model's `revoke` removes the derivation subtree. Only the
//!   verdict is compared; on agreement the harness treats the destination's
//!   instance as gone.
//! * **`reply` gating.** The kernel gates `ipc_reply` on `RECV`; the model has
//!   no reply op, so it is compared through `ep_recv` (the RECV-gated pop),
//!   whose verdict — not its queue effect — is what the harness checks.

use capability_core::{CapHandle, Kernel, ObjectKind, Rights, TaskHandle};
use std::collections::HashMap;

/// The checked-in fixture: a trace captured from a verified QEMU boot of the
/// ring-3 capability-denial demo.
pub const RING3_DEMO_TRACE: &str = include_str!("../traces/ring3-demo.trace");

/// A traced kernel operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Call,
    Serve,
    Reply,
    Endpoint,
    Grant,
    Revoke,
    Mem,
    MemLen,
    MemRead,
    MemWrite,
    TaskState,
    TaskKill,
    TaskRestart,
}

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::Call => "call",
            Op::Serve => "serve",
            Op::Reply => "reply",
            Op::Endpoint => "endpoint",
            Op::Grant => "grant",
            Op::Revoke => "revoke",
            Op::Mem => "mem",
            Op::MemLen => "mem_len",
            Op::MemRead => "mem_read",
            Op::MemWrite => "mem_write",
            Op::TaskState => "task_state",
            Op::TaskKill => "task_kill",
            Op::TaskRestart => "task_restart",
        }
    }
}

/// The kind of object a traced cap names. `Any` is the trace's `-` (empty
/// slot): the op resolved no object at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Endpoint,
    MemRegion,
    Task,
    Channel,
    Any,
}

impl Kind {
    fn parse(c: char) -> Option<Kind> {
        Some(match c {
            'e' => Kind::Endpoint,
            'm' => Kind::MemRegion,
            't' => Kind::Task,
            'c' => Kind::Channel,
            '-' => Kind::Any,
            _ => return None,
        })
    }

    /// The model object kind this trace kind names, if any.
    fn model(self) -> Option<ObjectKind> {
        Some(match self {
            Kind::Endpoint => ObjectKind::Endpoint,
            Kind::MemRegion => ObjectKind::MemRegion,
            Kind::Task => ObjectKind::Task,
            Kind::Channel | Kind::Any => return None,
        })
    }
}

/// One parsed trace event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ev {
    Spawn {
        line: usize,
        idx: u32,
        label: String,
    },
    Op {
        line: usize,
        p: Op,
        o: u32,
        s: i64,
        k: Kind,
        j: u32,
        r: u8,
        rg: u8,
        y: bool,
        d: Option<u32>,
        ds: Option<u32>,
        pg: Option<u64>,
    },
}

/// Parse a `C:` trace stream into events. Blank lines are skipped; any other
/// line that does not start with `C:` is an error (feed it extracted lines, or
/// the raw serial log pre-filtered to `^C:`).
pub fn parse_trace(text: &str) -> Result<Vec<Ev>, String> {
    let mut evs = Vec::new();
    for (line_no, raw) in text.lines().enumerate() {
        let line = raw.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }
        let body = line
            .strip_prefix("C:")
            .ok_or_else(|| format!("line {} is not a C: trace line: {line}", line_no + 1))?;
        let mut f: HashMap<&str, &str> = HashMap::new();
        let mut p_override: Option<&str> = None;
        for tok in body.split_whitespace() {
            match tok.split_once('=') {
                Some((k, v)) => {
                    f.insert(k, v);
                }
                None => {
                    // A leading bare token is the event name (`spawn`); op
                    // lines carry it as `p=...`.
                    if f.is_empty() && p_override.is_none() {
                        p_override = Some(tok);
                    } else {
                        return Err(format!("line {}: not a key=val token: {tok}", line_no + 1));
                    }
                }
            }
        }
        let num = |f: &HashMap<&str, &str>, k: &str| -> Result<u32, String> {
            f.get(k)
                .ok_or_else(|| format!("line {}: missing field {k}", line_no + 1))?
                .parse()
                .map_err(|e| format!("line {}: field {k} not a u32: {e}", line_no + 1))
        };
        let pname = if p_override == Some("op") {
            // `C:op p=call ...`: the bare `op` marks an op event; the
            // operation name rides in the `p=` field.
            f.get("p").copied()
        } else {
            // `C:spawn idx=...`: the bare `spawn` is the event name.
            p_override
        };
        evs.push(match pname {
            Some("spawn") => Ev::Spawn {
                line: line_no + 1,
                idx: num(&f, "idx")?,
                label: f
                    .get("label")
                    .ok_or_else(|| format!("line {}: missing label", line_no + 1))?
                    .to_string(),
            },
            Some(pname) => {
                let p = match pname {
                    "call" => Op::Call,
                    "serve" => Op::Serve,
                    "reply" => Op::Reply,
                    "endpoint" => Op::Endpoint,
                    "grant" => Op::Grant,
                    "revoke" => Op::Revoke,
                    "mem" => Op::Mem,
                    "mem_len" => Op::MemLen,
                    "mem_read" => Op::MemRead,
                    "mem_write" => Op::MemWrite,
                    "task_state" => Op::TaskState,
                    "task_kill" => Op::TaskKill,
                    "task_restart" => Op::TaskRestart,
                    other => return Err(format!("line {}: unknown op {other}", line_no + 1)),
                };
                let k = f
                    .get("k")
                    .ok_or_else(|| format!("line {}: missing kind", line_no + 1))?
                    .chars()
                    .next()
                    .and_then(Kind::parse)
                    .ok_or_else(|| format!("line {}: bad kind", line_no + 1))?;
                Ev::Op {
                    line: line_no + 1,
                    p,
                    o: num(&f, "o")?,
                    s: f.get("s")
                        .ok_or_else(|| format!("line {}: missing slot", line_no + 1))?
                        .parse()
                        .map_err(|e| format!("line {}: bad slot {e}", line_no + 1))?,
                    k,
                    j: num(&f, "j")?,
                    r: f.get("r")
                        .ok_or_else(|| format!("line {}: missing r", line_no + 1))?
                        .parse()
                        .map_err(|_| format!("line {}: bad r", line_no + 1))?,
                    rg: f
                        .get("rg")
                        .ok_or_else(|| format!("line {}: missing rg", line_no + 1))?
                        .parse()
                        .map_err(|_| format!("line {}: bad rg", line_no + 1))?,
                    y: match f.get("y").copied() {
                        Some("ok") => true,
                        Some("denied") => false,
                        _ => return Err(format!("line {}: bad y", line_no + 1)),
                    },
                    d: f.get("d").and_then(|v| v.parse().ok()),
                    ds: f.get("ds").and_then(|v| v.parse().ok()),
                    pg: f.get("pg").and_then(|v| v.parse().ok()),
                }
            }
            None => return Err(format!("line {}: missing p field", line_no + 1)),
        });
    }
    Ok(evs)
}

/// The outcome of a replay: per-event verdict agreement statistics plus any
/// divergences (where the model and the kernel disagreed on whether an op was
/// authorized).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub spawned: usize,
    pub grants: usize,
    pub revokes: usize,
    pub ops: usize,
    pub kernel_ok: usize,
    pub kernel_denied: usize,
    pub model_ok: usize,
    pub model_denied: usize,
    /// Human-readable disagreements. Empty == conformance holds.
    pub divergences: Vec<String>,
}

impl Report {
    /// True iff every traced verdict matched the model's verdict.
    pub fn agreed(&self) -> bool {
        self.divergences.is_empty()
    }
}

/// A slot handle that no task holds. Passing it to a model op yields
/// `Err(NoCap)` — the model's way of saying "this task does not hold a cap on
/// that object", which is exactly what the kernel's empty-slot `-1` means.
const NO_SLOT: CapHandle = CapHandle(0xFFFF_FFF0);

/// Mirror one traced authority state in the model and compare every verdict.
pub struct Replayer {
    k: Kernel,
    root: TaskHandle,
    root_creator: CapHandle,
    /// kernel task idx -> model TaskHandle
    tasks: HashMap<u32, TaskHandle>,
    /// kernel task idx -> the root's ALL-rights cap to that task (its naming
    /// cap; the model's `create_task` return value).
    root_caps: HashMap<u32, CapHandle>,
    /// (holder idx, kind, object id) -> the model caps the holder has to it.
    caps: HashMap<(u32, Kind, u32), Vec<CapHandle>>,
    /// (grantor idx, grantee idx) -> a RECEIVE-bearing naming cap to the
    /// grantee in the grantor's CSpace (synthesized consent, I6).
    naming: HashMap<(u32, u32), CapHandle>,
    /// kernel task idx -> a `Creator` cap in that task's CSpace (synthesized
    /// creation authority).
    creator: HashMap<u32, CapHandle>,
    pub report: Report,
}

impl Replayer {
    /// Fresh model kernel booted to a root task (the kernel's own boot context;
    /// the fixture's ring-3 tasks are created under it).
    pub fn new() -> Replayer {
        let mut k = Kernel::new();
        let (root, _self_cap, root_creator) = k.boot("kernel").expect("model boots");
        Replayer {
            k,
            root,
            root_creator,
            tasks: HashMap::new(),
            root_caps: HashMap::new(),
            caps: HashMap::new(),
            naming: HashMap::new(),
            creator: HashMap::new(),
            report: Report::default(),
        }
    }

    fn diverged(&mut self, ev_line: usize, p: &str, actor: u32, k: Kind, obj: u32, kernel: bool) {
        self.report.divergences.push(format!(
            "trace line {ev_line}: {p} actor={actor} target={k:?}#{obj}: kernel={} model={}",
            if kernel { "ok" } else { "denied" },
            if kernel { "denied" } else { "ok" },
        ));
    }

    #[allow(clippy::too_many_arguments)]
    fn compare(
        &mut self,
        line: usize,
        p: Op,
        actor: u32,
        k: Kind,
        obj: u32,
        kernel_ok: bool,
        model_ok: bool,
    ) {
        self.report.ops += 1;
        if kernel_ok {
            self.report.kernel_ok += 1;
        } else {
            self.report.kernel_denied += 1;
        }
        if model_ok {
            self.report.model_ok += 1;
        } else {
            self.report.model_denied += 1;
        }
        if kernel_ok != model_ok {
            self.diverged(line, p.name(), actor, k, obj, kernel_ok);
        }
    }

    /// Find the model cap a task holds matching (kind, rights) exactly — used
    /// to discover the slot of caps that model ops mint but do not return.
    fn find_cap(&self, task: TaskHandle, kind: ObjectKind, rights: Rights) -> Option<CapHandle> {
        self.k
            .authorized(task)
            .into_iter()
            .find(|a| a.kind == kind && a.rights == rights)
            .map(|a| CapHandle(a.slot))
    }

    /// Grant `task` a copy of the root's Creator cap (model creation ceremony).
    fn ensure_creator(&mut self, task: u32) {
        if self.creator.contains_key(&task) {
            return;
        }
        let naming = self.root_caps[&task];
        self.k
            .grant(self.root, self.root_creator, naming, Rights::ALL, None)
            .expect("root grants a Creator cap to the creator");
        let h = self
            .find_cap(self.tasks[&task], ObjectKind::Creator, Rights::ALL)
            .expect("Creator cap minted into the task");
        self.creator.insert(task, h);
    }

    /// Ensure the grantor holds a RECEIVE-bearing naming cap to the grantee
    /// (model consent, I6), so the model's grant can target the grantee.
    fn ensure_consent(&mut self, grantor: u32, grantee: u32) {
        if self.naming.contains_key(&(grantor, grantee)) {
            return;
        }
        let src = self.root_caps[&grantee];
        let into = self.root_caps[&grantor];
        self.k
            .grant(
                self.root,
                src,
                into,
                Rights::CONTROL.union(Rights::RECEIVE),
                None,
            )
            .expect("root consents to the grantee");
        let h = self
            .find_cap(
                self.tasks[&grantor],
                ObjectKind::Task,
                Rights::CONTROL.union(Rights::RECEIVE),
            )
            .expect("consent naming cap minted into the grantor");
        self.naming.insert((grantor, grantee), h);
    }

    /// One cap the holder has to `(k, obj)`, if any.
    fn held(&self, holder: u32, k: Kind, obj: u32) -> Option<CapHandle> {
        self.caps
            .get(&(holder, k, obj))
            .and_then(|v| v.first())
            .copied()
    }

    pub fn replay(&mut self, evs: &[Ev]) -> &Report {
        for ev in evs {
            match *ev {
                Ev::Spawn {
                    line,
                    idx,
                    ref label,
                } => self.spawn(line, idx, label),
                Ev::Op {
                    line,
                    p,
                    o,
                    k,
                    j,
                    rg,
                    y,
                    d,
                    pg,
                    ..
                } => match p {
                    Op::Endpoint => self.create_endpoint(line, o, j, rg, y),
                    Op::Mem => self.create_mem(line, o, j, rg, pg.unwrap_or(0), y),
                    Op::Grant => self.grant(line, o, k, j, rg, d.unwrap_or(0), y),
                    Op::Revoke => self.revoke(line, o, k, j, d.unwrap_or(0), y),
                    _ => self.access(line, p, o, k, j, y),
                },
            }
        }
        &self.report
    }

    fn spawn(&mut self, _line: usize, idx: u32, label: &str) {
        if idx == 0 {
            // The boot context is the model root; already created in `new`.
            self.tasks.insert(0, self.root);
            self.report.spawned += 1;
            return;
        }
        let (h, creator_cap) = self
            .k
            .create_task(self.root, self.root_creator, label)
            .expect("model creates the traced task");
        self.tasks.insert(idx, h);
        self.root_caps.insert(idx, creator_cap);
        self.report.spawned += 1;
    }

    fn create_endpoint(&mut self, line: usize, owner: u32, obj: u32, rg: u8, kernel_ok: bool) {
        self.ensure_creator(owner);
        let res = self
            .k
            .create_endpoint(self.tasks[&owner], self.creator[&owner]);
        let model_ok = res.is_ok();
        self.compare(
            line,
            Op::Endpoint,
            owner,
            Kind::Endpoint,
            obj,
            kernel_ok,
            model_ok,
        );
        if let Ok(h) = res {
            let info = self
                .k
                .cap_info(self.tasks[&owner], h)
                .expect("created endpoint cap exists");
            if info.rights != Rights::new(rg.into()) {
                self.report.divergences.push(format!(
                    "trace line {line}: endpoint {owner}#{obj} minted with model rights {} but the kernel recorded {}",
                    info.rights, rg
                ));
            }
            self.caps
                .entry((owner, Kind::Endpoint, obj))
                .or_default()
                .push(h);
        }
    }

    fn create_mem(
        &mut self,
        line: usize,
        owner: u32,
        obj: u32,
        rg: u8,
        pages: u64,
        kernel_ok: bool,
    ) {
        self.ensure_creator(owner);
        let len = (pages * 4096) as usize;
        let res = self
            .k
            .create_mem(self.tasks[&owner], self.creator[&owner], vec![0u8; len]);
        let model_ok = res.is_ok();
        self.compare(
            line,
            Op::Mem,
            owner,
            Kind::MemRegion,
            obj,
            kernel_ok,
            model_ok,
        );
        if let Ok(h) = res {
            let info = self
                .k
                .cap_info(self.tasks[&owner], h)
                .expect("created memory cap exists");
            if info.rights != Rights::new(rg.into()) {
                self.report.divergences.push(format!(
                    "trace line {line}: region {owner}#{obj} minted with model rights {} but the kernel recorded {}",
                    info.rights, rg
                ));
            }
            self.caps
                .entry((owner, Kind::MemRegion, obj))
                .or_default()
                .push(h);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn grant(
        &mut self,
        line: usize,
        src: u32,
        k: Kind,
        obj: u32,
        rg: u8,
        dst: u32,
        kernel_ok: bool,
    ) {
        let Some(src_handle) = self.held(src, k, obj) else {
            self.report.divergences.push(format!(
                "trace line {line}: grant by {src} names object {k:?}#{obj} the grantor never held (trace state inconsistent)"
            ));
            return;
        };
        self.ensure_consent(src, dst);
        let rights = Rights::new(rg.into());
        let res = self.k.grant(
            self.tasks[&src],
            src_handle,
            self.naming[&(src, dst)],
            rights,
            None,
        );
        let model_ok = res.is_ok();
        self.compare(line, Op::Grant, src, k, obj, kernel_ok, model_ok);
        self.report.grants += 1;
        if model_ok {
            // Discover the minted cap in the grantee's CSpace and remember it
            // so later access ops resolve through the model handle.
            let h = self
                .find_cap(self.tasks[&dst], k.model().expect("granted kind"), rights)
                .expect("granted cap visible in the grantee's CSpace");
            self.caps.entry((dst, k, obj)).or_default().push(h);
        }
    }

    fn revoke(&mut self, line: usize, src: u32, k: Kind, obj: u32, dst: u32, kernel_ok: bool) {
        let Some(src_handle) = self.held(src, k, obj) else {
            self.report.divergences.push(format!(
                "trace line {line}: revoke by {src} names object {k:?}#{obj} the grantor never held (trace state inconsistent)"
            ));
            return;
        };
        let res = self.k.revoke(self.tasks[&src], src_handle);
        let model_ok = res.is_ok();
        self.compare(line, Op::Revoke, src, k, obj, kernel_ok, model_ok);
        self.report.revokes += 1;
        if model_ok {
            // Kernel clears the named instance; the model removes the subtree
            // (I4). Either way the destination no longer reaches the object.
            self.caps.remove(&(dst, k, obj));
        }
    }

    fn access(&mut self, line: usize, p: Op, actor: u32, k: Kind, obj: u32, kernel_ok: bool) {
        let handle = self.held(actor, k, obj).unwrap_or(NO_SLOT);
        let task = self.tasks[&actor];
        let model_ok = match p {
            Op::Call => self.k.ep_send(task, handle, Vec::new()).is_ok(),
            Op::Serve => self.k.ep_recv(task, handle).map(|_| ()).is_ok(),
            Op::Reply => self.k.ep_recv(task, handle).map(|_| ()).is_ok(),
            Op::MemLen => self.k.mem_len(task, handle).map(|_| ()).is_ok(),
            Op::MemRead => self.k.mem_read(task, handle, 0, 0).map(|_| ()).is_ok(),
            Op::MemWrite => self.k.mem_write(task, handle, 0, Vec::new()).is_ok(),
            Op::TaskState => self.k.task_running(task, handle).map(|_| ()).is_ok(),
            Op::TaskKill => self.k.task_kill(task, handle).is_ok(),
            Op::TaskRestart => self.k.task_spawn(task, handle).is_ok(),
            _ => {
                self.report.divergences.push(format!(
                    "trace line {line}: internal error: {p:?} handled as access"
                ));
                return;
            }
        };
        self.compare(line, p, actor, k, obj, kernel_ok, model_ok);
    }
}

impl Default for Replayer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_parses_to_events() {
        let evs = parse_trace(RING3_DEMO_TRACE).expect("fixture parses");
        assert_eq!(evs.len(), 15);
        assert!(matches!(evs[0], Ev::Spawn { idx: 2, .. }));
        assert!(matches!(
            evs[5],
            Ev::Op {
                p: Op::Endpoint,
                y: true,
                ..
            }
        ));
        assert!(matches!(
            evs[14],
            Ev::Op {
                p: Op::TaskState,
                y: false,
                ..
            }
        ));
    }

    #[test]
    fn replay_of_the_ring3_denial_demo_agrees_with_the_kernel() {
        let evs = parse_trace(RING3_DEMO_TRACE).expect("fixture parses");
        let mut r = Replayer::new();
        let rep = r.replay(&evs).clone();
        assert!(
            rep.agreed(),
            "model disagreed with the kernel:\n{}",
            rep.divergences.join("\n")
        );
        // The demo's three gated ops on an empty CSpace must all be denied by
        // the model too, and the client's call authorized.
        assert_eq!(rep.kernel_denied, 5);
        assert_eq!(rep.model_denied, 5);
        assert_eq!(rep.kernel_ok, 5);
        assert_eq!(rep.model_ok, 5);
        assert_eq!(rep.ops, 10);
        assert_eq!(rep.spawned, 5);
        assert_eq!(rep.grants, 1);
    }

    #[test]
    fn a_denied_kernel_op_flipped_authorized_is_a_divergence() {
        let evs = parse_trace(RING3_DEMO_TRACE).expect("fixture parses");
        // Flip the kernel's recorded verdict on one denied call to ok: the
        // model (which still has no cap to grant it) must disagree.
        let mut evs = evs;
        if let Ev::Op { y, .. } = &mut evs[6] {
            *y = true;
        }
        let mut r = Replayer::new();
        let rep = r.replay(&evs).clone();
        assert!(!rep.agreed());
        assert!(rep
            .divergences
            .iter()
            .any(|d| d.contains("call") && d.contains("actor=3")));
    }
}
