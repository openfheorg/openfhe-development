//==================================================================================
// BSD 2-Clause License
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
// All rights reserved.
//==================================================================================

//
// Twisted conjugate-invariant (CI) NTT for native (NativeVector) ring towers.
//
// The CI ring R_q = {a in Z_q[X]/(X^{2N}+1) : a(X)=a(X^{-1})}, stored as a length-N
// coefficient vector, is isomorphic to Z_q^N via evaluation at the N real CI nodes
// w_m^{4j+1} (w_m a primitive 4N-th root mod q). The transform (Kim-Song s4.3) is computed as
//   forward  (COEFFICIENT -> EVALUATION): the NTT modulo X^N - w_m^N of the fold
//            g_i = a_i - w_m^N a_{N-i}, the fold fused into the first CT stage;
//   inverse  (EVALUATION -> COEFFICIENT): GS stages, the unfold fused into the last one
//   (raw-word kernels in NumberTheoreticTransformNat; outputs in bit-reversed node order).
// Hadamard product in EVALUATION format then equals CI ring multiplication.
//
// A CI modulus is opted in via RegisterCIModulus(); only registered native moduli take
// the CI path (everything else is byte-identical standard arithmetic). Validated
// against reference/ci_ckks/ci_ntt.py (the Phase-0 oracle).
//

#ifndef LBCRYPTO_MATH_CI_TRANSFORM_H
#define LBCRYPTO_MATH_CI_TRANSFORM_H

#include "math/hal/nativeintbackend.h"

#include <cstdint>

namespace lbcrypto {

using CINativeInteger = NativeInteger;
using CINativeVector  = NativeVector;

// Register modulus q (which must satisfy q = 1 mod 4N) as a CI tower of ring dimension
// N with primitive 4N-th root wm = RootOfUnity(4N, q). Idempotent. Precomputes tables.
void RegisterCIModulus(const CINativeInteger& modulus, uint32_t N, const CINativeInteger& wm);

// True if `modulus` was registered as a CI tower.
bool IsCIModulus(const CINativeInteger& modulus);

// Test/teardown helper: drop all registered CI moduli.
void ClearCIModuli();

// In-place CI transforms on a single ring tower (length N, modulus a registered CI q).
void CIForwardTransform(CINativeVector& vals);   // COEFFICIENT -> EVALUATION
void CIInverseTransform(CINativeVector& vals);   // EVALUATION  -> COEFFICIENT
// Original O(N log N) reference implementation (slow path), kept for validation.
void CIForwardTransformRef(CINativeVector& vals);
void CIInverseTransformRef(CINativeVector& vals);

}  // namespace lbcrypto

#endif
