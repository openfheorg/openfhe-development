# Plan: paper-style real-FFT bootstrapping for native CI-CKKS (OpenFHE v1.6.1)

Branch: `ci-ckks-fft-v1.6.1` (reapply of `ci-ckks-2026` onto v1.6.1). Code edited in WSL, built/run on ICELAKE.
Reference: Liu, Ma, Wang, Wang, "Efficient (Functional) Bootstrapping for CKKS over the Conjugate-Invariant Ring", ePrint 2026/2618.

0. Port: squashed 3-way reapply of v1.5.1..ci-ckks-2026 onto v1.6.1. DONE.
1. Build + smoke test on ICELAKE (tmux, logs on disk, resumable). No unit tests.
2. Quick & dirty real FFT:
   - Python oracle of the paper's real factorization in the fork's g=5 slot order; check S*F_l...F_1*V is a
     signed permutation; count diagonals.
   - C++: build the sparse real factors directly as diagonals (no dense N x N), collapse to the level budget,
     evaluate single-channel. Replaces CICollapseNatFats + twoChannel. Drop the lvlb | log2N restriction.
3. Precision: CI vs std at identical params; stage-by-stage decrypt; fix the floor.
4. Optimization: BSGS over the nonzero-diagonal progression only; minimal rotation keys; setup-time
   precompute; sparse secret if feasible; single-thread N=2^16 benchmark (CI 1 ct vs std 2 separate boots).
5. Engineering: remove debug hooks, tests, docs; unit tests run once at the very end.

Run guarding: every ICELAKE job runs in tmux with nohup + log file + exit-status file; WSL only edits/syncs.
