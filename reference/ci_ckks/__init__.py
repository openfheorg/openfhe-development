"""Phase-0 cleartext oracle for native conjugate-invariant (real) CKKS bootstrapping.

This package is the high-precision (mpmath, 256-bit) source of truth that all later
homomorphic C++ code is verified against. It is pure Python so it imports unchanged
inside Sage (`sage -python`) for optional scheduled algebraic cross-checks.

IRON RULE: no numpy/scipy in the math path — float64 (53-bit) would silently violate
the 2^-100 correctness contract.
"""
