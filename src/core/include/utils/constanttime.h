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
  Branch-free helpers for modular arithmetic on the decrypt hot path.

  These routines are drop-in replacements for the common conditional
  Barrett / sign-correction idioms that appear throughout the integer
  backend. The intent is to remove data-dependent branches (and thus
  a known class of timing side channels) from every primitive that
  is reachable from Decrypt.

  Methodology follows the PermNet-RM constant-time encoder
  (https://github.com/BAder82t/PermNet-RM, Issaei 2026): branchless
  bitmask select plus a per-call compiler barrier that survives
  -O0..-Ofast on GCC/Clang.

  Each helper is a short inline template so it compiles to the same
  three or four instructions the optimizer would emit for the
  original ternary on typical x86-64 / arm64 builds, but *without*
  depending on optimizer heuristics for the branchlessness.
*/

#ifndef LBCRYPTO_UTILS_CONSTANTTIME_H
#define LBCRYPTO_UTILS_CONSTANTTIME_H

#include <cstddef>
#include <type_traits>

namespace lbcrypto {
namespace ct {

// Compiler barrier: opaque the given scalar to the optimizer so that
// aggressive passes cannot reconstruct a data-dependent branch via
// value-range propagation. Expands to nothing on compilers that do
// not support the inline-asm form; on those compilers the branchless
// expression survives on its own at -O0..-O3 today, and the guard is
// here as a future-proofing reminder.
#if defined(__GNUC__) || defined(__clang__)
#define OPENFHE_CT_OPAQUE(x) __asm__ volatile("" : "+r"(x))
#else
#define OPENFHE_CT_OPAQUE(x) ((void)0)
#endif

// Return x + m if x is negative, x otherwise, without a branch.
// Requires S to be a signed integral type; m is interpreted in the
// signed domain so callers passing an unsigned m should ensure
// m < 2^(bits(S)-1) (true for all RLWE moduli in OpenFHE).
template <typename S>
inline S AddIfNeg(S x, S m) noexcept {
    static_assert(std::is_signed_v<S>, "AddIfNeg requires a signed type");
    constexpr int kSignShift = static_cast<int>(sizeof(S) * 8 - 1);
    // Arithmetic right shift replicates the sign bit across the word.
    const S mask = x >> kSignShift;  // -1 if x < 0, else 0
    S y          = x + (mask & m);
    OPENFHE_CT_OPAQUE(y);
    return y;
}

// Return x - m if x >= m, x otherwise, without a branch.
// Precondition: x < 2*m, m < 2^(bits(U)-1). All OpenFHE RLWE moduli
// satisfy the latter; the former is guaranteed by every caller of
// this routine (the canonical Barrett / Montgomery post-reduction).
template <typename U>
inline U SubIfGE(U x, U m) noexcept {
    static_assert(std::is_unsigned_v<U>, "SubIfGE requires an unsigned type");
    constexpr int kTopBit = static_cast<int>(sizeof(U) * 8 - 1);
    const U diff          = x - m;  // underflows (wraps) iff x < m
    // Top bit of diff is 1 iff underflow happened iff x < m.
    const U under = diff >> kTopBit;
    const U mask  = U(0) - under;  // all-ones if underflow, else zero
    U y           = diff + (mask & m);
    OPENFHE_CT_OPAQUE(y);
    return y;
}

// Return a - b mod m, without a branch.
// Precondition: a, b in [0, m), m < 2^(bits(U)-1).
template <typename U>
inline U ModSubFast(U a, U b, U m) noexcept {
    static_assert(std::is_unsigned_v<U>, "ModSubFast requires an unsigned type");
    constexpr int kTopBit = static_cast<int>(sizeof(U) * 8 - 1);
    const U diff          = a - b;  // underflows iff a < b
    const U under         = diff >> kTopBit;
    const U mask          = U(0) - under;
    U y                   = diff + (mask & m);
    OPENFHE_CT_OPAQUE(y);
    return y;
}

// Return x - m if x > halfQ (the centered-lift threshold), x otherwise.
// Used for signed modular reduction of plaintext-encoded values.
// Precondition: x in [0, m), halfQ = m / 2.
template <typename U>
inline U SubIfAboveHalf(U x, U m, U halfQ) noexcept {
    static_assert(std::is_unsigned_v<U>, "SubIfAboveHalf requires an unsigned type");
    constexpr int kTopBit = static_cast<int>(sizeof(U) * 8 - 1);
    // x > halfQ  <=>  halfQ - x underflows  <=>  (halfQ - x) >> top is 1.
    const U diff  = halfQ - x;
    const U above = diff >> kTopBit;       // 1 if x > halfQ, else 0
    const U mask  = U(0) - above;          // all-ones if x > halfQ
    U y           = x - (mask & m);
    OPENFHE_CT_OPAQUE(y);
    return y;
}

}  // namespace ct
}  // namespace lbcrypto

#endif  // LBCRYPTO_UTILS_CONSTANTTIME_H
