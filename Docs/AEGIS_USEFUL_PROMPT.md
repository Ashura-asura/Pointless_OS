# Aegis — Toward Actually Useful (a course-correction prompt)

*Repo: github.com/Ashura-asura/Pointless_OS. Current verified state: `d61a650`
(bridge-phase gap inventory landed, hardening phases AF–AH closed, 1,015 live
tests, external audit fixed). This document is self-contained — hand it to
whoever works on the repo next, alongside `Docs/os-from-first-principles.md`
(the design doc it's grounded in) and `Docs/BRIDGE_GAPS.md` (which it
narrows, not replaces).

---

## 0. The diagnosis, stated plainly, with the doc's own words

`os-from-first-principles.md` predicted this exact failure mode before a
line of code existed, in two places:

> §7: "'Desktop' and 'AI' shouldn't be phase 7/8 afterthoughts if AI-native
> is a load-bearing design goal — the capability model has to be validated
> against AI-agent workloads early, or you'll redesign the capability
> delegation API late and expensively."

> §11.G ("First 12 months"): "do nothing on Windows compatibility,
> distributed systems, or a graphical shell — those are all later-phase and
> premature before the core claim is validated."

What actually happened, measured directly against the source tree at
`d61a650`:

| Subsystem | Size / count | What it is |
|---|---|---|
| `desktop.rs` | 4,165 lines | Compositor, window chrome, taskbar, and toy apps (calculator, PPM viewer, package-manager stub, text editor, file browser) |
| `fleet.rs` + `mesh.rs` | ~49K + substantial | Cross-machine capability transport, 2-node consensus, remote invocation |
| Hypervisor (`vm.rs` + guest device models) | Phases U through Z | VMX run loop, EPT, Linux guest boot, UHCI USB, Sound Blaster 16 |
| `role.rs` | 812 lines | **Exactly 3 roles**: `restart-service`, `observe-service`, `query-advisor` — all narrow ops-demo roles, none doing work a person would actually want done |
| `object_graph.rs` | 296 lines | The "AI-native reasoning over relationships" primitive §5 calls the single strongest differentiator of the whole design |

This is the doc's own predicted ordering, inverted: the graphical shell, the
distributed layer, and deep hypervisor/guest-device work — all explicitly
named in §11.G as *premature before the core claim is validated* — got
years of phases. The core claim itself (§9's actual delegation mechanism:
role-shaped grants, ephemeral-by-default, diff-confirmed expansion, a
persistent audit trail, anomaly-detection circuit breaking, two-party
confirmation for irreversible actions) has **none of its five mechanisms
built**. What exists is three hardcoded roles proving the capability *gate*
works, which was always necessary but was never the hard part — §11.H says
this outright: *"not the kernel — it's already solved... the capability
delegation UX... is where real systems get it wrong."*

This is not a claim that any of the built work is bad or was wasted —
Ground Rule 6 applies to this document too, so: the hypervisor, fleet, and
desktop work are all real, tested, honestly documented engineering, and
none of it needs to be torn out. The claim is narrower and more useful than
that: **none of it is the payoff the design doc says this project is
actually betting on**, and continuing to add infrastructure depth (a
Windows guest, more device emulation, a fourth desktop toy app) before
building *any* of §9's mechanism is the same mistake, again, with more
sunk cost behind it each time.

"Useful," concretely, for this repo, is not "runs more software" (that's
the compatibility-moat trap §11 already said this design cannot win purely
on) and it is not "has more phases closed." It is: **a person can hand
Aegis a real task, get it done inside an honestly-scoped, auditable,
non-self-escalating capability boundary, and trust the result** — because
that is the one thing this specific architecture can do that a general-
purpose OS with an AI plugin bolted on cannot honestly claim. Everything
below is in service of making that sentence true for at least one real
task, not a demo task.

---

## 1. Three tracks, not one — pick the order, keep all three alive

Don't collapse this into "just do the AI thing." The bridge phase's own
gap inventory (`BRIDGE_GAPS.md`) already identified real, low-risk,
high-leverage next work (deepening the Linux guest) — that stays valid and
useful. What changes is *sequencing and target-picking*, per the doc's own
"first 12 months" guidance: validate the core claim first, then let the
already-real guest/hypervisor substrate serve it, rather than growing
independently of it.

**Track 1 (do first): build §9's actual delegation mechanism, against one
real task.** This is the un-de-risked, highest-novelty, most load-bearing
part of the whole design, and it's the one place where "the design doc
said do this first and nobody did" is a straight, checkable fact.

**Track 2 (do in parallel, it's cheap and already-scoped): retarget the
Linux-guest bridge phase at usefulness, not an arbitrary app battery.**
`BRIDGE_GAPS.md` candidate 1 ("which real apps fail today") is right in
spirit but picks targets by "whatever fails" rather than "whatever would
make this genuinely useful to the person running it." Point it at a small,
named battery instead (§3 below).

**Track 3 (defer, don't abandon): everything else in `BRIDGE_GAPS.md`'s
candidate list (fuller distro image, Windows guest) and any further
hypervisor device-model depth.** Not because it's bad work — it's real and
well-tested — but because §11.G is explicit that it's premature relative
to the core claim, and every day of new development attention on it
extends exactly the ordering problem this document exists to correct.
Nothing here says stop maintaining it (fuzzing/CI/hardening on existing
code continues as-is, per the existing Ground Rules) — it says stop
*growing* it until Track 1 has a real result.

---

## 2. Track 1 — Phase RoleLib: build §9's mechanism for real, against a real task

**Closes:** §9's delegation-UX mechanism (currently 0 of 5 pieces built),
validated against §11.F's original test target, generalized to at least
one task that isn't "restart a service."

### 2.1 Pick the one real task first — don't build the mechanism in the
   abstract

Per §11.F, the smallest real prototype is one task, done for real, under
adversarial testing. Pick a task from the actual person's actual working
context, not an invented ops scenario, because a role designed against a
task nobody will really run is exactly how the mechanism ends up looking
correct on paper and wrong in practice (§9's own warning about permission
systems that only work in demos). Concretely, a strong first candidate:
**"summarize what changed in this object-store subtree since a given
point"** — it's read-only (lowest blast radius for a first real grant),
it's genuinely useful (this is the shape of thing a person actually wants
an assistant to do), and it exercises the object store + capability model
together instead of just the role gate in isolation. A second, slightly
higher-risk candidate once the first is real: **"propose a specific,
named edit to a specific, named file; do not apply it without
confirmation"** — this one exercises §9 point 3 (confirmation only at
trust-boundary crossings) for real, because "propose" and "apply" are
different capabilities, not different messages.

### 2.2 Build the five §9 mechanisms, against those tasks, in this order

1. **Role-shaped grants (§9.1).** Extend `role.rs`'s role library beyond
   the 3 ops-demo roles with the task(s) picked above, each expanding to a
   specific, narrow, system-defined capability set — the agent asks for
   the role, never assembles its own capability list. Reuse the existing
   `role_grant` gate mechanics; this is additive to `role.rs`, not a
   rewrite (same discipline `mesh.rs` used composing `fleet.rs` — extend,
   don't touch what's already adversarially tested).
2. **Ephemeral-by-default grants (§9.2).** A granted role's capability
   expires when the task completes or after a short bound, whichever
   first — add expiry to the grant path (the model crate's `macaroon`
   already carries an `expiry` field end-to-end; the kernel port
   (`fleet.rs`'s `CapabilityToken::expiry`) already threads it too — this
   is largely wiring existing plumbing into `role.rs`'s grant path, not
   new cryptographic machinery).
3. **Diff-based confirmation at scope expansion (§9.3).** When a task
   needs more than its current role grants, the request must show what's
   being *added* (not the full accumulated set) and block on human
   confirmation before proceeding — contract-test both the "stays inside
   granted scope, no prompt" path and the "requests expansion, must
   block" path explicitly, adversarially, the same way `role.rs`'s
   existing self-escalation-denied tests work.
4. **Persistent audit trail with stable queryable identity (§9.4).**
   `audit.rs` already exists and is used by every other syscall gate in
   this kernel — extend its existing `OpKind` pattern with role-grant and
   role-exercise records carrying enough identity (which grant, which
   task, which capability) to answer "what did this agent actually do
   with what it was given" after the fact. This is the one piece of §9
   this repo is closest to already having; close the gap, don't rebuild
   the mechanism.
5. **Anomaly circuit-breaking + two-party confirmation for irreversible
   actions (§10's "reduced, not closed" mitigation).** Lower priority
   than 1–4 — the design doc itself frames this as a further reduction of
   an inherent risk, not a closable gap — but once 1–4 exist for a task
   that includes a write/irreversible action (the "apply the edit"
   candidate above), this is the natural next increment: a lightweight,
   non-TCB monitor comparing actual capability usage against the role's
   expected shape, and a distinct two-click/two-party path specifically
   for the "apply" capability, not the "propose" one.

### 2.3 Adversarial testing is not optional and is not step 6

Every role added under 2.2 needs the same adversarial discipline
`role.rs`'s existing tests already establish: self-grant attempts, foreign-
target grant attempts, scope-expansion-without-confirmation attempts, and
(new) expired-grant-reuse attempts, each denied at the kernel capability
gate specifically — not by the agent's own code declining to try. This
isn't a follow-up phase; each of 2.2's five items ships with its
adversarial test in the same commit, same as every phase in this project's
history.

**Definition of Done:** at least one real, non-ops-demo task
("summarize changes in a subtree," minimum) runs end-to-end through a
role-shaped, ephemeral, audited grant; a second task exercises the diff-
confirmation path on a real scope-expansion request; all adversarial
tests pass specifically because of kernel-level denial. Say plainly, per
Ground Rule 6, which of the five §9 mechanisms are closed and which
remain reduced — anomaly detection and two-party confirmation are the
likely "reduced, do more later" items on a first pass, and that's fine to
state as such rather than rushed to false-closure.

**Verify:** `cargo test role::` plus a boot-log demo (same pattern as
every other live-verified phase) showing the granted task actually
running against real object-store data, the diff-confirmation prompt
actually blocking until confirmed, and the audit log actually answering
"what did it do" after the fact with a real query, not a description of
one.

---

## 3. Track 2 — Phase Bridge-Retarget: pick the guest app battery by
   usefulness, not by "whatever's missing"

`BRIDGE_GAPS.md` is right that "boot the guest, run apps, log what fails"
beats guessing, but an unscoped battery produces an unscoped gap list.
Fix: name the battery first, from what would make the guest genuinely
usable for real work, and let *that* drive which syscalls/devices get
closed.

**Target battery, in priority order** (a working developer/research
toolchain, not an arbitrary sample): a shell with real job control,
`python3` (interpreter only, no exotic C-extension packages yet), `git`
(clone/commit/log against a local repo — this is a meaningfully harder
target than BusyBox's coreutils subset and will surface real gaps:
`mmap`, more of the filesystem syscall surface, process-group signals),
`vim` or `nano` (proves interactive terminal I/O through the guest path,
not just batch commands), and a C toolchain (`gcc`/`make`, minimal) only
after the above are solid. Each addition gets the project's standard: a
named missing syscall/device, a contract test, closed with the same
audit discipline as the rest of the kernel — this doesn't relax
`BRIDGE_GAPS.md`'s own methodology, it just points it at a battery a
person would actually reach for, so that "the Linux guest works" starts
meaning "you can actually get real work done in it" rather than "five
BusyBox utilities ran once."

**Definition of Done:** git and python3 both run real, non-trivial
operations (a real clone against a real repo over the existing e1000e
path; a real script doing real file I/O against the guest's view of
storage) inside the guest, each gap that had to close named and
contract-tested, same as Phase V's original BusyBox proof.

**Verify:** boot logs showing the real commands and their real output,
committed the same way every other phase's evidence has been.

---

## 4. Track 3 — explicitly deferred, not abandoned

`BRIDGE_GAPS.md` candidates 2 (fuller distro image) and 3 (Windows guest),
and any further hypervisor device-model breadth (more virtio devices,
more USB device classes) beyond what Track 2's named battery actually
needs: **park these until Track 1 has a real Definition-of-Done result.**
This is a direct application of §11.G, not a new opinion — the design doc
already said a graphical shell, distributed systems, and (by clear
extension) deep guest-compatibility breadth are "later-phase and
premature before the core claim is validated," and the core claim still
isn't validated. Existing fuzzing/CI/hardening on this code continues
unchanged; new *growth* effort on it doesn't start until Track 1 ships.

---

## 5. Ground Rules (unchanged, restated because this document changes
   priority, not process)

1. Clean lockfiles before every test run.
2. Full suite, not just new tests.
3. Raw `cargo test` output in the commit message.
4. Count totals yourself before writing them anywhere.
5. Any failure: stop, fix, restart.
6. Closed / reduced / inherent — say which, honestly, every time. This
   document itself follows that rule: nothing above claims the desktop,
   fleet, or hypervisor work was a mistake — it claims the *order* was
   inverted relative to the design doc's own explicit sequencing, which
   is a narrower, checkable claim, not a broad indictment.
7. Any log or capture cited as evidence is committed to the repo.
8. Independently-checkable claims ship with the one-line command to
   check them.

---

## 6. What "actually useful" will honestly still not mean, even after
   this

Per §11's own closing verdict: this does not make Aegis a general-purpose
Linux/Windows/macOS replacement, and pretending otherwise after Track 1/2
land would be exactly the kind of overclaiming this project has
consistently avoided elsewhere. What it means, honestly: one real,
capability-scoped, audited AI-agent task actually works, on a person's
actual data, with a mechanism (not a demo) behind the trust boundary —
which is the specific, narrow, genuinely-hard-to-fake claim §11.I says is
the credible version of this project. That claim, proven once for real,
is worth more to the project's actual thesis than another ten phases of
device emulation.
