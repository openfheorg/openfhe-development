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

static inline NativeInteger::SignedNativeInt SignExtend(NativeInteger::SignedNativeInt d,
                                                        NativeInteger::SignedNativeInt bits) {
    return static_cast<NativeInteger::SignedNativeInt>(static_cast<NativeInteger::Integer>(d) << bits) >> bits;
}

void RingGSWAccumulator::SignedDigitDecompose(const std::shared_ptr<RingGSWCryptoParams>& params,
                                              const std::vector<NativePoly>& input,
                                              std::vector<NativePoly>& output) const {
    auto QHalf{params->GetQ().ConvertToInt<BasicInteger>() >> 1};
    auto Q_int{params->GetQ().ConvertToInt<NativeInteger::SignedNativeInt>()};
    auto gBits{static_cast<NativeInteger::SignedNativeInt>(__builtin_ctz(params->GetBaseG()))};
    auto gBitsMaxBits{static_cast<NativeInteger::SignedNativeInt>(NativeInteger::MaxBits() - gBits)};
    auto gHalf{static_cast<NativeInteger::SignedNativeInt>(params->GetBaseG() >> 1)};
    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG2{(params->GetDigitsG() - 1) << 1};
    uint32_t N{params->GetN()};

    // digit-major order: carry0/carry1 hold the running quotient for every coefficient so
    // that each inner loop is unit-stride and vectorizable
    std::vector<NativeInteger::SignedNativeInt> carry0(N), carry1(N);
    for (uint32_t k{0}; k < N; ++k) {
        auto t0{input[0][k].ConvertToInt<BasicInteger>()};
        auto d0{static_cast<NativeInteger::SignedNativeInt>(t0 < QHalf ? t0 : t0 - Q_int)};
        carry0[k] = (d0 + gHalf) >> gBits;
        auto t1{input[1][k].ConvertToInt<BasicInteger>()};
        auto d1{static_cast<NativeInteger::SignedNativeInt>(t1 < QHalf ? t1 : t1 - Q_int)};
        carry1[k] = (d1 + gHalf) >> gBits;
    }

    for (uint32_t d{0}; d < digitsG2; d += 2) {
        auto& out0{output[d + 0]};
        auto& out1{output[d + 1]};
        for (uint32_t k{0}; k < N; ++k) {
            auto r0{SignExtend(carry0[k], gBitsMaxBits)};
            carry0[k] = (carry0[k] + gHalf) >> gBits;
            if (r0 < 0)
                r0 += Q_int;
            out0[k] += r0;

            auto r1{SignExtend(carry1[k], gBitsMaxBits)};
            carry1[k] = (carry1[k] + gHalf) >> gBits;
            if (r1 < 0)
                r1 += Q_int;
            out1[k] += r1;
        }
    }
}

// Decompose a ring element, not ciphertext
void RingGSWAccumulator::SignedDigitDecompose(const std::shared_ptr<RingGSWCryptoParams>& params,
                                              const NativePoly& input, std::vector<NativePoly>& output) const {
    auto QHalf{params->GetQ().ConvertToInt<BasicInteger>() >> 1};
    auto Q_int{params->GetQ().ConvertToInt<NativeInteger::SignedNativeInt>()};
    auto gBits{static_cast<NativeInteger::SignedNativeInt>(__builtin_ctz(params->GetBaseG()))};
    auto gBitsMaxBits{static_cast<NativeInteger::SignedNativeInt>(NativeInteger::MaxBits() - gBits)};
    auto gHalf{static_cast<NativeInteger::SignedNativeInt>(params->GetBaseG() >> 1)};
    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG{params->GetDigitsG() - 1};
    uint32_t N{params->GetN()};

    // digit-major order: carry holds the running quotient for every coefficient so that
    // each inner loop is unit-stride and vectorizable
    std::vector<NativeInteger::SignedNativeInt> carry(N);
    for (uint32_t k{0}; k < N; ++k) {
        auto t0{input[k].ConvertToInt<BasicInteger>()};
        auto d0{static_cast<NativeInteger::SignedNativeInt>(t0 < QHalf ? t0 : t0 - Q_int)};
        carry[k] = (d0 + gHalf) >> gBits;
    }

    for (uint32_t d{0}; d < digitsG; ++d) {
        auto& out{output[d]};
        for (uint32_t k{0}; k < N; ++k) {
            auto r0{SignExtend(carry[k], gBitsMaxBits)};
            carry[k] = (carry[k] + gHalf) >> gBits;
            if (r0 < 0)
                r0 += Q_int;
            out[k] += r0;
        }
    }
}

};  // namespace lbcrypto
