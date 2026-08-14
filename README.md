# Pointless OS (Aegis-inspired research substrate)

Pointless OS is an experimental operating system research repository exploring capability-based substrates and AI-native orchestration for adaptive, auditable, and resilient system behavior. The project focuses on a small, verifiable kernel boundary and a userspace stack that treats AI agents as ordinary, capability-scoped principals rather than part of the trusted computing base.

This repository contains kernel and userspace prototypes, formal models, test harnesses, and design artifacts intended for research, evaluation, and engineering experimentation.

## Quick links
- Architecture notes: ARCHITECTURE.md
- Design monograph: os-from-first-principles.md
- Honest status and limits: HONEST_STATUS.md
- Security audit notes: SECURITY_AUDIT.md

## Vision
- Minimal trusted computing base: enforce isolation and capability semantics in a small kernel.
- Capability-first model: capabilities are the only authority tokens; no ambient root.
- AI as a principal (not TCB): AI agents receive explicit, auditable, and revocable capabilities.
- Modularity and observability: services run in userspace with supervision, extensive telemetry, and a persistent audit trail to support diagnosis and controlled automation.

## Key design principles
- Safety: prioritize memory- and type-safety in system components (Rust is the primary implementation language).
- Verifiability: keep the kernel and core primitives auditable and small enough for formal reasoning and contract tests.
- Least privilege: issuance of capabilities is explicit, role-shaped, and ephemeral by default.
- Separation of concerns: adaptive/AI orchestration is implemented outside the kernel as a userspace service under the same capability constraints.
- Compatibility via projection: present POSIX/Windows compatibility as projection or translation layers that run unprivileged and do not expand the TCB.

## Status
This project is an active research prototype. Many features are implemented as experiments; APIs and layouts may change. See HONEST_STATUS.md and ARCHITECTURE.md for granular completion status, known limits, and verification claims.

Notable implemented and documented items include:
- Kernel and userspace model artifacts (TLA+ and contract tests).
- Boot and test paths under QEMU (UEFI loader, ELF loader, kernel demo).
- Capability-addressed object storage design and userspace projections.
Refer to ARCHITECTURE.md and the repository subprojects for full details.

## Language composition
- Rust: ~95%
- Python: ~3%
- TLA+: ~1%
- Other: ~0.4%

## Repository layout (typical)
- `aegis-kernel/` — kernel and core primitives (Rust)
- `uefi-boot/` — bootloader and image build support
- `aegis/`, `userspace/`, `tools/` — userspace services, tooling, and demos
- `specs/` and `os-from-first-principles.md` — formal models and design monograph
- `docs/` — supplemental documentation and developer notes

Use per-component README files for exact build/run instructions.

## Build & run (high level)
Exact commands vary by component. Common workflow examples:
- Run the workspace tests:
  - cargo test --workspace
- Run specific packages:
  - cargo test -p aegis-kernel
  - cargo test -p uefi-boot
  - cargo run -p capability-audit
- Boot kernel under QEMU (example):
  - cd uefi-boot
  - cargo build --release --features uefi --target x86_64-unknown-uefi
  - python build_image.py
  - qemu-system-x86_64 -machine q35 -m 512 -drive format=raw,file=aegis-boot.img -serial file:serial-dbg.log -display none

If you want a detailed, component-by-component guide, I can generate one after inspecting the relevant subprojects and scripts.

## Contribution guidelines
- Open issues to discuss proposals and non-trivial changes before implementation.
- Keep pull requests focused and include tests, documentation, or reproducible verification steps.
- Follow project formatting and lint rules (run `rustfmt` and Clippy where applicable).
- Consider adding CONTRIBUTING.md and CODE_OF_CONDUCT.md to formalize onboarding.

## Research and verification
This repository emphasizes honest claims: verify what can be proven (kernel isolation, capability enforcement) and clearly document limits where verification cannot apply (learned model behavior, cross-machine transparency under partition). See os-from-first-principles.md for the full architectural rationale and the verification strategy.

## Roadmap (high level)
Principal next steps (research-first ordering):
1. Harden and audit the core kernel and capability enforcement.
2. Stabilize userspace supervision and resource manager prototypes.
3. Implement and evaluate capability-scoped AI orchestration prototypes under supervision.
4. Expand test coverage, CI, and reproducible VM/QEMU-based test harnesses.
5. Provide compatibility projections (Linux translation, VM-based Windows) as unprivileged services.

## License
Refer to the repository LICENSE file for licensing terms. If a license is not present and you want one added, recommend MIT or Apache-2.0.

## Contact & attribution
Repository: https://github.com/Ashura-asura/Pointless_OS  
Maintainer: @Ashura-asura

---

For deeper context and the full design rationale, see os-from-first-principles.md and ARCHITECTURE.md.
