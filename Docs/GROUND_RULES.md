# Ground Rules — Pointless OS / Aegis

These are non-negotiable. Violating any rule means the work is not done.

## 1. One commit per task, verified clean before push

Every completed task gets its own commit. Before pushing:

1. Delete `Cargo.lock`: `del aegis\Cargo.lock`
2. Run `cargo test --workspace 2>&1` from `aegis/` — the FULL workspace, not individual crates
3. Paste the raw terminal output (every line) into the commit message or PR
4. Count the tests yourself from the raw output — do not trust any summary
5. If any line says `FAILED` or `error`, stop. Fix it. Re-run from step 1.

**Never report "N tests, 0 failures" without the raw `cargo test --workspace` output to prove it.**

## 2. Never report per-crate counts as workspace totals

If you run `cargo test -p foo` and it passes, that means `foo` passes. It does NOT mean the workspace passes. A workspace build can fail even if individual crates compile. The only valid proof of "0 failures" is `cargo test --workspace` from a clean lockfile, with the raw output pasted.

## 3. Raw output, not summaries

When reporting test results, paste the literal terminal output. Do not summarize. Do not skip lines. Do not count yourself and report the count — let the output speak. If the output is too long, paste at minimum:
- The last 5 lines of each `test result:` block
- The final summary line
- Any `error` or `FAILED` lines (there should be none)

## 4. No flattery, no marketing

Every status update, doc section, and commit message states what exists, what doesn't, and why. No "groundbreaking," no "revolutionary," no "the first ever." If a claim is honest, say so. If it's partial, say that too.

## 5. Contract tests for every claim

If a model-doc section says "X works," there must be a Rust contract test that proves X works. The test constructs a kernel, exercises the operation, and asserts the expected outcome (success or specific error). No test = no claim.

## 6. Model-doc sections for every implemented claim

Every new capability gets a section in `spec/capability-model.md` with:
- A `### Machine-checked verification (executable): <name> (§N)` heading
- The honest-limits paragraph (what the test proves and what it doesn't)

## 7. No external dependencies in the kernel crates

The kernel crates (the bare-metal `aegis-kernel` and the model `capability-core`)
stay zero-dependency. All crypto, serialization, and networking happen in
sibling crates. This is a hard boundary, not a suggestion.

## 8. No scope creep

Implement exactly what the spec says. No extra refactors. No unrequested features. No "while I'm here, I'll also clean up X." The reviewer will reject it.

## 9. Honest limits on every page

Every doc, every section, every status update includes what's NOT proven:
- The kernel is a single-threaded in-process model, not real hardware isolation
- TLA+ is finite-instance (2 tasks, 3 slots), not inductive proof
- Contract tests prove the model, not production behavior
- AI behavior is monitored, not verified

## 10. Verify before claiming

Before writing any status doc or commit message:
1. Delete `Cargo.lock`
2. `cargo test --workspace` — paste raw output
3. `cargo run -p capability-audit` — paste raw output
4. `cargo run -p aegis-shell` — paste raw output
5. Only then is the claim verified.

If step 2 fails to compile, the claim is false. Period.

## 11. Update HONEST_STATUS.md after every batch of changes

After any implementation work, update HONEST_STATUS.md to reflect the new state. Keep the table honest. Remove completed items from "What doesn't exist." Add new items if discovered.

## 12. If in doubt, re-run

If anyone questions whether "0 failures" is true, the answer is always: delete Cargo.lock, run `cargo test --workspace`, paste output. No exceptions. No "I already ran it." The proof is the output, not the claim.
