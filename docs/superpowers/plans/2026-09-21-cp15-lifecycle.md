# CP15 Live Lifecycle Implementation Plan

> Execute inline with superpowers:executing-plans. The user has explicitly requested implementation and actual CI execution of the CP15 continuation in NEXT_CHAT_PROMPT_TR.md; no additional design selection is necessary.

**Goal:** Exercise CONNECT, forward HTTP and transparent TCP through the pinned OpenShell gateway, supervisor and sandbox, preserving the CP14 journal across reconnect and process replacement.

**Architecture:** Reuse the existing Docker E2E wrapper and CP14 integration. Add opt-in supervisor-only persistent evidence storage, independently validate raw journal commitments, and drive lifecycle changes through the real gateway CLI. A receiver challenge identifies each bounded test operation; no general flow-completeness certificate is minted.

**Tech Stack:** OpenShell commit 484f0768fc6a0d93e0a2be295c1679aed24e18a9, Rust 1.95.0, Docker, Python standard library, GitHub Actions.

**Spec:** CP14 package NEXT_CHAT_PROMPT_TR.md and this session's explicit CP15 request. Required paths: CONNECT, forward HTTP, transparent TCP. Remote authenticated witnesses remain a separate checkpoint.

## Global Constraints

- Preserve the CP14 source pin and all 29 existing durable-egress regressions.
- Run in an isolated branch; preserve the existing CP15 branches and active run.
- Persist journal, lock and witness outside container tmpfs, in a supervisor-only volume stable across sandbox stop/start.
- Enable the added storage only from trusted gateway configuration for the CP15 lane.
- A skipped test or absent runtime evidence must fail CP15 acceptance.
- Raw journal hashes must be recomputed, including Rust struct serialization order; equality of stored hash fields is insufficient.
- Do not infer durable ordering from committed_unix_ns: CP14 samples it before fsync.
- Preserve raw evidence and exact source/build identifiers. Joint rollback, authenticated remote witness and physical power loss remain NOT_ESTABLISHED.

## Review Focus

1. tmpfs restart loss: inspect the real mount and compare exact journal prefixes after replacement.
2. Missing one network path: require a distinct receiver challenge and matching permit for every path in every successful lifecycle phase.
3. False hash validation: mutate a permit field while leaving stored hashes intact; verification must reject it.
4. Disabled or skipped test: require Docker explicitly and a nonempty scenario results artifact.
5. Session/process confusion: reconnect must bind a new accepted session; replacement must retain the old journal prefix and use a new writer token.

### Task 1: Independent raw evidence verifier

**Files:** openshell_cp15/evidence.py, openshell_cp15/test_evidence.py.
**Interfaces:** verify(journal: bytes, witness: bytes, sandbox_id: str) -> dict with count, head and records; raise ValueError on invalid framing, identity, commitments or witness.

- [ ] Write negative tests for changed payload, deleted tail, duplicate fields, empty evidence, wrong sandbox and changed witness; use the CP14 exact serialization contract.
- [ ] Run `python -m unittest discover -s openshell_cp15 -p 'test_*.py'`; observe missing verifier failure.
- [ ] Implement strict parsing and four independent commitment checks without upgrading coverage or outcome.
- [ ] Run the same command; require every negative control to reject and a valid journal to pass.

### Task 2: Real lifecycle test and persistent storage

**Files:** openshell_cp15/apply_cp15.py, openshell_cp15/blackbox_lifecycle.rs, .github/workflows/cp15-lifecycle.yml.
**Interfaces:** application script consumes an exact pinned checkout and installs CP14 plus CP15; Rust test consumes the verifier CLI and exports raw snapshots and scenario receipts under CP15_EVIDENCE_DIR.

- [ ] Assert the supervisor evidence mount is a writable Docker volume and absent from the workload; the current tmpfs-based integration fails this requirement.
- [ ] Create a stable sandbox-specific evidence volume, initialize ownership in the supervisor image, and pass journal/witness paths only to that companion.
- [ ] Exercise one unique challenge per path before reconnect, after an observed HTTP/2 timeout during gateway SIGSTOP/SIGCONT, after stop/start and after forced stop/start of a frozen supervisor. Use the real SandboxGuard and the wrapper-owned gateway PID. A gateway restart replaces the supervisor in this pinned Docker driver and cannot represent same-process reconnect.
- [ ] Validate every snapshot with Task 1, checking identity, unique operation IDs, exact prefix preservation, new sessions and replacement writer tokens.
- [ ] Reject missing Docker and absent markers. Copy files using Docker's archive API (`docker cp`); the distroless supervisor has no `cat` executable.

### Task 3: Execute and package actual evidence

**Files:** CI workflow, CP15_CI_EVIDENCE.json, CHECKPOINT_15_STATUS.md, delivery ZIP.
**Interfaces:** CI exports exact head SHAs, build output, runtime receipts and raw evidence. Acceptance consumes the downloaded artifacts, never handwritten PASS fields.

- [ ] Apply the patch to a clean checkout and run Python verifier controls locally.
- [ ] Run focused Rust regressions and the full Docker lifecycle job in CI.
- [ ] On failure, preserve the failing output, fix the specific root cause and rerun the affected job on an exact commit.
- [ ] Independently inspect artifacts against every required scenario before assigning a status.
- [ ] Package code, commands, raw evidence and limitations. If runtime remains blocked, label the checkpoint incomplete and identify the exact blocker.
