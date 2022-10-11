//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
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

#include "rgsw-acc.h"

#include <string>

namespace lbcrypto {

// SignedDigitDecompose is a bottleneck operation
// There are two approaches to do it.
// The current approach appears to give the best performance
// results. The two variants are labeled A and B.
void RingGSWAccumulator::SignedDigitDecompose(const std::shared_ptr<RingGSWCryptoParams> params,
                                              const std::vector<NativePoly>& input,
                                              std::vector<NativePoly>& output) const {
    uint32_t N                           = params->GetN();
    uint32_t digitsG                     = params->GetDigitsG();
    NativeInteger Q                      = params->GetQ();
    NativeInteger QHalf                  = Q >> 1;
    NativeInteger::SignedNativeInt Q_int = Q.ConvertToInt();

    NativeInteger::SignedNativeInt baseG = NativeInteger(params->GetBaseG()).ConvertToInt();

    NativeInteger::SignedNativeInt d = 0;

    NativeInteger::SignedNativeInt gBits = (NativeInteger::SignedNativeInt)std::log2(baseG);

    // VARIANT A
    NativeInteger::SignedNativeInt gBitsMaxBits = NativeInteger::MaxBits() - gBits;

    // VARIANT B
    // NativeInteger::SignedNativeInt gminus1 = (1 << gBits) - 1;
    // NativeInteger::SignedNativeInt baseGdiv2 =
    // (baseG >> 1)-1;

    // Signed digit decomposition
    for (size_t j = 0; j < 2; ++j) {
        for (size_t k = 0; k < N; ++k) {
            NativeInteger t = input[j][k];
            if (t < QHalf)
                d += t.ConvertToInt();
            else
                d += (NativeInteger::SignedNativeInt)t.ConvertToInt() - Q_int;

            for (size_t l = 0; l < digitsG; ++l) {
                // remainder is signed

                // This approach gives a slightly better performance
                // VARIANT A
                NativeInteger::SignedNativeInt r = d << gBitsMaxBits;
                r >>= gBitsMaxBits;

                // VARIANT B
                // NativeInteger::SignedNativeInt r = d & gminus1;
                // if (r > baseGdiv2) r -= baseG;

                d -= r;
                d >>= gBits;

                if (r >= 0)
                    output[j + 2 * l][k] += NativeInteger(r);
                else
                    output[j + 2 * l][k] += NativeInteger(r + Q_int);
            }
            d = 0;
        }
    }
}

};  // namespace lbcrypto
