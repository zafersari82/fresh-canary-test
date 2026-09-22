# CP15 execution ledger

Plan: 2026-09-21-cp15-lifecycle.md

- Source package SHA verified against d7853514f5158085064a615525a4c2c2fe3a909d418069d0306b48b93e83e7f6. CP14 Python baseline: 165 passed.
- Task 1: 13 independent parser controls passed after missing-verifier failure; payload mutations and stored-hash equality are rejected.
- Task 2: native Docker test and persistent supervisor-only volume implemented; complete patch applies to clean upstream pin. CI pending.
- Ruling: use actual CP14 CI branch as integration base because the ZIP apply script omits copying its required new durable_egress.rs module (transparent-origin changes ARE present in the patch). Cost if wrong: mismatch with supplied package; raw patch is regenerated in CI.
- Corrected ruling: both graceful shutdown and gateway restart invalidate the intended same-supervisor scenario. Pinned startup replaces the Docker supervisor, even after SIGKILL. Pause the owned gateway, observe a new real transport-failure event, resume with SIGCONT, and require the same supervisor/writer plus a new accepted session. A pause guard resumes the gateway on panic/unwind.
- Ruling: upstream treats unexpected supervisor death as terminal. Forced stop/start freezes supervisor before native stop; do not claim unplanned-crash auto-recovery.
- Ruling: new-writer acquisition also fences dispatch admission, checked under the same flock. Previously admitted operations may finish. CI must first reproduce the missing check, then pass all CP12-14 regressions with the fix.
- Ruling: no source SEAL, authenticated witness, general receiver operation-ID protocol or fsync-observation barrier is added here. Coverage and outcome stay NOT_ESTABLISHED/OUTCOME_UNKNOWN; a green lifecycle is a scoped test result, not production certification.
- Task 3: CI run 35653624859 on 86d3107c2e10c2d37575fe6bb901f5f563b01f04 completed with failure. Parser controls, stale-dispatch red control, fixed Rust regressions and supervisor/sandbox builds passed. The full lifecycle step failed. Public job metadata confirms these statuses; raw logs are currently inaccessible. The actual runtime failure cause remains unknown.

- Review resumed on 2026-09-22 and identified the gateway-restart scenario mismatch above. The correction was reviewed again: no further concrete findings in the diff; this is source review only, not a runtime verdict.
- Local correction: Python verifier controls 13/13 passed and git diff --check passed. Rust compilation and live execution of the correction are pending.
- Access blocker: authenticated GitHub tools return HTTP 400 / Invalid MCP request metadata. Plugin discovery returns the same transport error. Public API job logs require authentication (403); artifact ZIP requires authentication (401). Local execution has no Docker daemon/socket, Rust toolchain or effective Linux capabilities. Do not substitute synthetic execution for the required runtime lane.

- 2026-09-22 follow-up: authenticated GitHub access recovered. Raw job log proves all 30 Rust regressions passed and lifecycle failed during provisioning because the native GNU supervisor needs libgcc_s.so.1, absent from base-nossl. No receiver operation ran. Stage this required runtime library, record its hash and ldd output, and require a restricted-user image startup smoke check before lifecycle. Prior unknown-cause/access-blocker entries describe the earlier state only. CI rerun pending.
