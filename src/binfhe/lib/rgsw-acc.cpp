//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
  FHEW scheme (RingGSW accumulator) implementation
  The scheme is described in https://eprint.iacr.org/2014/816 and in Daniele Micciancio and Yuriy Polyakov
  "Bootstrapping in FHEW-like Cryptosystems", Cryptology ePrint Archive, Report 2020/086,
  https://eprint.iacr.org/2020/086.

  Full reference to https://eprint.iacr.org/2014/816:
  @misc{cryptoeprint:2014:816,
    author = {Leo Ducas and Daniele Micciancio},
    title = {FHEW: Bootstrapping Homomorphic Encryption in less than a second},
    howpublished = {Cryptology ePrint Archive, Report 2014/816},
    year = {2014},
    note = {\url{https://eprint.iacr.org/2014/816}},
 */

#include "lattice/lat-hal.h"
#include "rgsw-acc.h"

#include <memory>
#include <vector>

namespace lbcrypto {

void RingGSWAccumulator::SignedDigitDecompose(const std::shared_ptr<RingGSWCryptoParams>& params,
                                              const std::vector<NativePoly>& input,
                                              std::vector<NativePoly>& output) const {
    auto Q{params->GetQ().ConvertToInt<BasicInteger>()};
    auto QHalf{Q >> 1};
    auto gBits{static_cast<uint32_t>(__builtin_ctz(params->GetBaseG()))};
    auto gHalf{static_cast<BasicInteger>(params->GetBaseG() >> 1)};
    auto gMask{static_cast<BasicInteger>(params->GetBaseG() - 1)};
    auto QmHalf{Q - gHalf};
    uint32_t digitsG{params->GetDigitsG()};
    // Biasing by H (gHalf in every digit position) turns balanced-digit extraction into
    // independent unsigned windows: digit_k(x) = (((x + H) >> k*gBits) & gMask) - gHalf.
    // Requires digitsG*gBits < MaxBits, which holds for all supported parameter sets.
    BasicInteger H{0};
    for (uint32_t i{0}; i < digitsG; ++i)
        H += gHalf << (i * gBits);
    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG2{(digitsG - 1) << 1};
    uint32_t N{params->GetN()};

    std::vector<BasicInteger> w0(N), w1(N);
    for (uint32_t k{0}; k < N; ++k) {
        auto t0{input[0][k].ConvertToInt<BasicInteger>()};
        w0[k] = t0 + H - (t0 < QHalf ? 0 : Q);
        auto t1{input[1][k].ConvertToInt<BasicInteger>()};
        w1[k] = t1 + H - (t1 < QHalf ? 0 : Q);
    }

    for (uint32_t d{0}; d < digitsG2; d += 2) {
        uint32_t shift{((d >> 1) + 1) * gBits};
        auto& out0{output[d + 0]};
        auto& out1{output[d + 1]};
        for (uint32_t k{0}; k < N; ++k) {
            auto r0{(w0[k] >> shift) & gMask};
            out0[k] += (r0 < gHalf) ? r0 + QmHalf : r0 - gHalf;
            auto r1{(w1[k] >> shift) & gMask};
            out1[k] += (r1 < gHalf) ? r1 + QmHalf : r1 - gHalf;
        }
    }
}

// Decompose a ring element, not ciphertext
void RingGSWAccumulator::SignedDigitDecompose(const std::shared_ptr<RingGSWCryptoParams>& params,
                                              const NativePoly& input, std::vector<NativePoly>& output) const {
    auto Q{params->GetQ().ConvertToInt<BasicInteger>()};
    auto QHalf{Q >> 1};
    auto gBits{static_cast<uint32_t>(__builtin_ctz(params->GetBaseG()))};
    auto gHalf{static_cast<BasicInteger>(params->GetBaseG() >> 1)};
    auto gMask{static_cast<BasicInteger>(params->GetBaseG() - 1)};
    auto QmHalf{Q - gHalf};
    uint32_t digitsG{params->GetDigitsG()};
    // see the ciphertext overload above for the excess-H digit-extraction identity
    BasicInteger H{0};
    for (uint32_t i{0}; i < digitsG; ++i)
        H += gHalf << (i * gBits);
    uint32_t N{params->GetN()};

    std::vector<BasicInteger> w(N);
    for (uint32_t k{0}; k < N; ++k) {
        auto t0{input[k].ConvertToInt<BasicInteger>()};
        w[k] = t0 + H - (t0 < QHalf ? 0 : Q);
    }

    // approximate gadget decomposition is used; the first digit is ignored
    for (uint32_t d{0}; d < digitsG - 1; ++d) {
        uint32_t shift{(d + 1) * gBits};
        auto& out{output[d]};
        for (uint32_t k{0}; k < N; ++k) {
            auto r0{(w[k] >> shift) & gMask};
            out[k] += (r0 < gHalf) ? r0 + QmHalf : r0 - gHalf;
        }
    }
}

};  // namespace lbcrypto
