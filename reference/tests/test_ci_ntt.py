"""Spec for the C++ twisted CI NTT: the s4.3 fast factorization equals direct node
evaluation, the transform inverts, and Hadamard product in the NTT domain equals CI
ring multiplication (cross-checked against an independent negacyclic-convolution oracle)."""
import random

import pytest

from ci_ckks.ci_ntt import (
    ci_ntt_forward_direct, ci_ntt_forward_fast, ci_ntt_inverse,
    ci_ring_mult_negacyclic, find_4Nth_root,
)

# primes q = 1 mod 4N for N up to 32 (4N up to 128): 257 = 1 + 2*128; 769 = 1 + 6*128.
CASES = [(4, 257), (8, 257), (16, 257), (32, 257), (16, 769)]


@pytest.mark.parametrize("N,q", CASES)
def test_fast_equals_direct(N, q):
    wm = find_4Nth_root(q, N)
    rng = random.Random(7 + N)
    a = [rng.randrange(q) for _ in range(N)]
    assert ci_ntt_forward_fast(a, N, q, wm) == ci_ntt_forward_direct(a, N, q, wm)


@pytest.mark.parametrize("N,q", CASES)
def test_forward_inverse_identity(N, q):
    wm = find_4Nth_root(q, N)
    rng = random.Random(11 + N)
    a = [rng.randrange(q) for _ in range(N)]
    assert ci_ntt_inverse(ci_ntt_forward_direct(a, N, q, wm), N, q, wm) == a


@pytest.mark.parametrize("N,q", CASES)
def test_hadamard_is_ci_multiplication(N, q):
    wm = find_4Nth_root(q, N)
    rng = random.Random(23 + N)
    a = [rng.randrange(q) for _ in range(N)]
    b = [rng.randrange(q) for _ in range(N)]
    ahat = ci_ntt_forward_direct(a, N, q, wm)
    bhat = ci_ntt_forward_direct(b, N, q, wm)
    chat = [(x * y) % q for x, y in zip(ahat, bhat)]
    c_via_ntt = ci_ntt_inverse(chat, N, q, wm)
    c_oracle = ci_ring_mult_negacyclic(a, b, N, q)
    assert c_via_ntt == c_oracle
