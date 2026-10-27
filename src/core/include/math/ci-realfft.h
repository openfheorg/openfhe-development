//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Real FFT for the conjugate-invariant (CI) CKKS canonical embedding, following
  Liu, Ma, Wang, Wang, "Efficient (Functional) Bootstrapping for CKKS over the
  Conjugate-Invariant Ring", ePrint 2026/2618, Section 3.

  Slots are indexed in the g=5 cyclic order (position p <-> root zeta_{4N}^{5^p}); a CI
  rotation by Galois element 5^k is a cyclic shift by k in this order. With
  V[p][j] = 1 (j = 0), 2 cos(pi 5^p j / (2N)) (j > 0), the plan gives real orthogonal
  factors F_1..F_l (l = log2 N, <= 7 cyclic diagonals each) and S such that
      S * F_l ... F_1 * V = P0,   P0[pos[j]][j] = 1.
  It yields O(N log N) CI encode/decode and the sparse CtS/StC of the CI bootstrap.
 */

#ifndef LBCRYPTO_MATH_CI_REALFFT_H
#define LBCRYPTO_MATH_CI_REALFFT_H

#include <cstdint>
#include <map>
#include <vector>

namespace lbcrypto {

// Sparse real N x N matrix by cyclic diagonals: A[p][(p + k) mod N] = diag_k[p].
using CISparse = std::map<uint32_t, std::vector<double>>;

struct CIRealFFTPlan {
    uint32_t N = 0;
    std::vector<CISparse> F;     // F_1..F_l in apply order
    std::vector<double> S;       // diagonal scale (length N)
    std::vector<uint32_t> pos;   // coefficient j -> g=5 position
    std::vector<uint32_t> perm;  // g=5 position p -> natural CI slot index
};

// Cached, thread-safe.
const CIRealFFTPlan& GetCIRealFFTPlan(uint32_t N);

// coeffs = U^{-1} * slots (natural CI slot order), O(N log N).
void CIRealFFTEncode(uint32_t N, const std::vector<double>& slots, std::vector<double>& coeffs);
// slots = U * coeffs (natural CI slot order), O(N log N).
void CIRealFFTDecode(uint32_t N, const std::vector<double>& coeffs, std::vector<double>& slots);

// Sparse helpers. C = A * B (B applied first); T = A^T.
CISparse CISparseMul(const CISparse& A, const CISparse& B, uint32_t N);
CISparse CISparseTranspose(const CISparse& A, uint32_t N);

}  // namespace lbcrypto

#endif
