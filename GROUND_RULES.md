# Ground Rules — Pointless OS / Aegis

These are the non-negotiable constraints every implementation session follows.

## 1. One todo per commit
Every completed task gets its own commit with a descriptive message. No batch commits. No "WIP" commits. Each commit must be green (`cargo test` passes, `cargo run -p aegis-shell` works).

## 2. No flattery, no marketing
Every status update, doc section, and commit message states what exists, what doesn't, and why. No "groundbreaking," no "revolutionary," no "the first ever." If a claim is honest, say so. If it's partial, say that too.

## 3. Contract tests for every claim
If a model-doc section says "X works," there must be a Rust contract test that proves X works. The test constructs a kernel, exercises the operation, and asserts the expected outcome (success or specific error). No test = no claim.

## 4. Model-doc sections for every implemented claim
Every new capability gets a section in `spec/capability-model.md` with:
- A `### Machine-checked verification (executable): <name> (§N)` heading
- The honest-limits paragraph (what the test proves and what it doesn't)

## 5. No external dependencies in capability-core
The kernel crate (`capability-core`) stays zero-dependency. All crypto, serialization, and networking happen in sibling crates. This is a hard boundary, not a suggestion.

## 6. No scope creep
Implement exactly what the spec says. No extra refactors. No unrequested features. No "while I'm here, I'll also clean up X." The reviewer will reject it.

## 7. Every implementation must compile and test
`cargo test` must pass at 0 failures after every commit. `cargo run -p capability-audit` must show 0 violations. `cargo run -p aegis-shell` must run clean.

## 8. Honest limits on every page
Every doc, every section, every status update includes what's NOT proven:
- The kernel is a single-threaded in-process model, not real hardware isolation
- TLA+ is finite-instance (2 tasks, 3 slots), not inductive proof
- Contract tests prove the model, not production behavior
- AI behavior is monitored, not verified

## 9. Verify before claiming
Run `cargo test`, `cargo run -p capability-audit`, and `cargo run -p aegis-shell` before writing any status doc or commit message. If the tests don't pass, the claim isn't verified.

## 10. Update HONEST_STATUS.md after every batch of changes
After any implementation work, update HONEST_STATUS.md to reflect the new state. Keep the table honest. Remove completed items from "What doesn't exist." Add new items if discovered.
