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

#include "rgsw-acc-dm.h"

#include "rgsw-acc-common.h"

#include <string>

namespace lbcrypto {

// Key generation as described in Section 4 of https://eprint.iacr.org/2014/816
RingGSWACCKey RingGSWAccumulatorDM::KeyGenAcc(const std::shared_ptr<RingGSWCryptoParams>& params,
                                              const NativePoly& skNTT, ConstLWEPrivateKey& LWEsk) const {
    auto sv{LWEsk->GetElement()};
    auto mod{sv.GetModulus().ConvertToInt<int32_t>()};
    auto modHalf{mod >> 1};
    uint32_t n(sv.GetLength());
    params->VerifyBaseGCoverage(n);
    int32_t baseR(params->GetBaseR());
    const auto& digitsR = params->GetDigitsR();
    RingGSWACCKey ek    = std::make_shared<RingGSWACCKeyImpl>(n, baseR, digitsR.size());

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(n))
    for (uint32_t i = 0; i < n; ++i) {
        for (int32_t j = 1; j < baseR; ++j) {
            for (size_t k = 0; k < digitsR.size(); ++k) {
                auto s{sv[i].ConvertToInt<int32_t>()};
                (*ek)[i][j][k] =
                    KeyGenDM(params, skNTT, (s > modHalf ? s - mod : s) * j * digitsR[k].ConvertToInt<int32_t>(), i);
            }
        }
    }
    return ek;
}

#if NATIVEINT != 32
RingGSWACCKey32 RingGSWAccumulatorDM::KeyGenAcc32(const std::shared_ptr<RingGSWCryptoParams>& params,
                                                  const NativePoly& skNTT, ConstLWEPrivateKey& LWEsk) const {
    auto sv{LWEsk->GetElement()};
    auto mod{sv.GetModulus().ConvertToInt<int32_t>()};
    auto modHalf{mod >> 1};
    uint32_t n(sv.GetLength());
    params->VerifyBaseGCoverage(n);
    int32_t baseR(params->GetBaseR());
    const auto& digitsR = params->GetDigitsR();

    auto acc = std::make_shared<RingGSWACCKey32Impl>(params, n, baseR, digitsR.size());

    // identical per-index body to KeyGenAcc above; each 64-bit eval key is a temporary that dies
    // at the end of its statement, so the full 64-bit refreshing key is never materialised
    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(n))
    for (uint32_t i = 0; i < n; ++i) {
        for (int32_t j = 1; j < baseR; ++j) {
            for (size_t k = 0; k < digitsR.size(); ++k) {
                auto s{sv[i].ConvertToInt<int32_t>()};
                acc->SetEvalKey(
                    i, j, k,
                    *KeyGenDM(params, skNTT, (s > modHalf ? s - mod : s) * j * digitsR[k].ConvertToInt<int32_t>(), i));
            }
        }
    }
    return acc;
}

void RingGSWAccumulatorDM::EvalAcc32(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWACCKey32& ek,
                                     RLWECiphertext& acc, const NativeVector& a) const {
    const auto& polyParams = params->GetPolyParams32();
    uint32_t Q{static_cast<uint32_t>(params->GetQ().ConvertToInt())};

    auto acc32 = NarrowAcc32(polyParams, acc->GetElements());

    DMAccSchedule(params->Getq(), params->GetBaseR(), params->GetDigitsR().size(), a,
                  [&](uint32_t i, uint32_t a0, size_t k) {
                      AddToAccNoMonomial(polyParams, Q, params->GetBaseGParams(i), (*ek)[i][a0][k], acc32);
                  });

    WidenAcc32Into(acc32, acc->GetElements());
}
#endif

void RingGSWAccumulatorDM::EvalAcc(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWACCKey& ek,
                                   RLWECiphertext& acc, const NativeVector& a) const {
    DMAccSchedule(params->Getq(), params->GetBaseR(), params->GetDigitsR().size(), a,
                  [&](uint32_t i, uint32_t a0, size_t k) { AddToAccDM(params, (*ek)[i][a0][k], acc, i); });
}

// Encryption as described in Section 5 of https://eprint.iacr.org/2014/816
// skNTT corresponds to the secret key z
RingGSWEvalKey RingGSWAccumulatorDM::KeyGenDM(const std::shared_ptr<RingGSWCryptoParams>& params,
                                              const NativePoly& skNTT, LWEPlaintext m, uint32_t index) const {
    const auto& polyParams = params->GetPolyParams();

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    NativeInteger Q{params->GetQ()};

    // Reduce mod q (dealing with negative number as well)
    uint64_t q = params->Getq().ConvertToInt();
    uint32_t N = params->GetN();
    int64_t mm = (((m % q) + q) % q) * (2 * N / q);
    bool isReducedMM;
    if ((isReducedMM = (mm >= N)))
        mm -= N;

    // approximate gadget decomposition is used; the first digit is ignored
    const auto& bp = params->GetBaseGParams(index);
    uint32_t digitsG2{(bp.digitsG - 1) << 1};
    const auto& Gpow{*bp.gpow};

    RingGSWEvalKeyImpl result(digitsG2, 2);
    NativePoly tmp;
    for (uint32_t i = 0; i < digitsG2; ++i) {
        result[i][0] = NativePoly(dug, polyParams, Format::COEFFICIENT);
        tmp          = result[i][0];
        tmp.SetFormat(Format::EVALUATION);
        result[i][1] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);
        if (!isReducedMM)
            result[i][i & 0x1][mm].ModAddFastEq(Gpow[(i >> 1) + 1], Q);
        else
            result[i][i & 0x1][mm].ModSubFastEq(Gpow[(i >> 1) + 1], Q);
        result[i][0].SetFormat(Format::EVALUATION);
        result[i][1].SetFormat(Format::EVALUATION);
        result[i][1] += (tmp *= skNTT);
    }
    return std::make_shared<RingGSWEvalKeyImpl>(std::move(result));
}

// AP Accumulation as described in https://eprint.iacr.org/2020/086
void RingGSWAccumulatorDM::AddToAccDM(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWEvalKey& ek,
                                      RLWECiphertext& acc, uint32_t index) const {
    AddToAccNoMonomial(params->GetPolyParams(), params->GetQ().ConvertToInt<BasicInteger>(),
                       params->GetBaseGParams(index), ek->GetElements(), acc->GetElements());
}

};  // namespace lbcrypto
