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

#include "rgsw-acc-lmkcdey.h"

#include "rgsw-acc-common.h"

namespace lbcrypto {

// Key generation as described in https://eprint.iacr.org/2022/198
RingGSWACCKey RingGSWAccumulatorLMKCDEY::KeyGenAcc(const std::shared_ptr<RingGSWCryptoParams>& params,
                                                   const NativePoly& skNTT, ConstLWEPrivateKey& LWEsk) const {
    auto sv{LWEsk->GetElement()};
    auto mod{sv.GetModulus().ConvertToInt<int32_t>()};
    auto modHalf{mod >> 1};
    uint32_t N{params->GetN()};
    size_t n{sv.GetLength()};
    params->VerifyBaseGCoverage(static_cast<uint32_t>(n));
    uint32_t numAutoKeys{params->GetNumAutoKeys()};

    // dim2, 0: for RGSW(X^si), 1: for automorphism keys
    // only w automorphism keys required
    // allocates (n - w) more memory for pointer (not critical for performance)
    RingGSWACCKey ek = std::make_shared<RingGSWACCKeyImpl>(1, 2, n);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(n))
    for (size_t i = 0; i < n; ++i) {
        auto s{sv[i].ConvertToInt<int32_t>()};
        (*ek)[0][0][i] = KeyGenLMKCDEY(params, skNTT, s > modHalf ? s - mod : s, i);
    }

    NativeInteger gen = NativeInteger(5);

    (*ek)[0][1][0] = KeyGenAuto(params, skNTT, 2 * N - gen.ConvertToInt());

    // m_window: window size, consider parameterization in the future
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numAutoKeys))
    for (uint32_t i = 1; i <= numAutoKeys; ++i)
        (*ek)[0][1][i] = KeyGenAuto(params, skNTT, gen.ModExp(i, 2 * N).ConvertToInt<LWEPlaintext>());
    return ek;
}

#if NATIVEINT != 32
RingGSWACCKey32 RingGSWAccumulatorLMKCDEY::KeyGenAcc32(const std::shared_ptr<RingGSWCryptoParams>& params,
                                                       const NativePoly& skNTT, ConstLWEPrivateKey& LWEsk) const {
    auto sv{LWEsk->GetElement()};
    auto mod{sv.GetModulus().ConvertToInt<int32_t>()};
    auto modHalf{mod >> 1};
    uint32_t N{params->GetN()};
    size_t n{sv.GetLength()};
    params->VerifyBaseGCoverage(static_cast<uint32_t>(n));
    uint32_t numAutoKeys{params->GetNumAutoKeys()};

    auto acc = std::make_shared<RingGSWACCKey32Impl>(params, 1, 2, static_cast<uint32_t>(n));

    const auto& polyParams32 = params->GetPolyParams32();
    const auto skNTT32       = NarrowPoly32(skNTT, polyParams32);
    DiscreteGaussianGeneratorImpl<NativeVector32> dgg32(params->GetDgg().GetStd());

    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(n))
    for (size_t i = 0; i < n; ++i) {
        auto s{sv[i].ConvertToInt<int32_t>()};
        const auto mono = MonomialOf(params, s > modHalf ? s - mod : s);
        acc->SetEvalKey(0, 0, i, RGSWEncrypt(params, polyParams32, skNTT32, dgg32, i, mono));
    }

    NativeInteger gen = NativeInteger(5);

    acc->SetEvalKey(0, 1, 0, RGSWEncryptAutomorphism(params, polyParams32, skNTT32, dgg32, 2 * N - gen.ConvertToInt()));

    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numAutoKeys))
    for (uint32_t i = 1; i <= numAutoKeys; ++i)
        acc->SetEvalKey(0, 1, i,
                        RGSWEncryptAutomorphism(params, polyParams32, skNTT32, dgg32,
                                                gen.ModExp(i, 2 * N).ConvertToInt<LWEPlaintext>()));
    return acc;
}

void RingGSWAccumulatorLMKCDEY::EvalAcc32(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWACCKey32& ek,
                                          RLWECiphertext& acc, const NativeVector& a) const {
    const auto& polyParams = params->GetPolyParams32();
    uint32_t Q{static_cast<uint32_t>(params->GetQ().ConvertToInt())};
    uint32_t M{2 * params->GetN()};

    auto acc32 = NarrowAcc32(polyParams, acc->GetElements());
    acc32[1]   = acc32[1].AutomorphismTransform(M - 5);

    LMKCDEYAccSchedule(
        params->Getq(), params->GetN(), params->GetNumAutoKeys(), params->GetLogGen(), a,
        [&](int32_t idx) { AddToAccNoMonomial(polyParams, Q, params->GetBaseGParams(idx), (*ek)[0][0][idx], acc32); },
        [&](NativeInteger power, uint32_t k) {
            uint32_t p{power.ConvertToInt<uint32_t>()};
            AutomorphismKeySwitch(p, params->GetAutoMap(p), polyParams, Q, params->GetDefaultBaseGParams(),
                                  (*ek)[0][1][k], acc32);
        });

    WidenAcc32Into(acc32, acc->GetElements());
}
#endif

void RingGSWAccumulatorLMKCDEY::EvalAcc(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWACCKey& ek,
                                        RLWECiphertext& acc, const NativeVector& a) const {
    uint32_t M            = 2 * params->GetN();
    acc->GetElements()[1] = (acc->GetElements()[1]).AutomorphismTransform(M - 5);

    LMKCDEYAccSchedule(
        params->Getq(), params->GetN(), params->GetNumAutoKeys(), params->GetLogGen(), a,
        [&](int32_t idx) { AddToAccLMKCDEY(params, (*ek)[0][0][idx], acc, idx); },
        [&](NativeInteger power, uint32_t k) { Automorphism(params, power, (*ek)[0][1][k], acc); });
}

// Encryption as described in Section 5 of https://eprint.iacr.org/2022/198
// Same as KeyGenAP, but only for X^{s_i}
// skNTT corresponds to the secret key z
RingGSWEvalKey RingGSWAccumulatorLMKCDEY::KeyGenLMKCDEY(const std::shared_ptr<RingGSWCryptoParams>& params,
                                                        const NativePoly& skNTT, LWEPlaintext m, uint32_t index) const {
    return std::make_shared<RingGSWEvalKeyImpl>(
        RGSWEncrypt(params, params->GetPolyParams(), skNTT, params->GetDgg(), index, MonomialOf(params, m)));
}

// Generation of an autormorphism key
RingGSWEvalKey RingGSWAccumulatorLMKCDEY::KeyGenAuto(const std::shared_ptr<RingGSWCryptoParams>& params,
                                                     const NativePoly& skNTT, LWEPlaintext k) const {
    return std::make_shared<RingGSWEvalKeyImpl>(
        RGSWEncryptAutomorphism(params, params->GetPolyParams(), skNTT, params->GetDgg(), k));
}

// LMKCDEY Accumulation as described in https://eprint.iacr.org/2022/198
// Same as AP, but multiplied once
void RingGSWAccumulatorLMKCDEY::AddToAccLMKCDEY(const std::shared_ptr<RingGSWCryptoParams>& params,
                                                ConstRingGSWEvalKey& ek, RLWECiphertext& acc, uint32_t index) const {
    AddToAccNoMonomial(params->GetPolyParams(), params->GetQ().ConvertToInt<BasicInteger>(),
                       params->GetBaseGParams(index), ek->GetElements(), acc->GetElements());
}

void RingGSWAccumulatorLMKCDEY::Automorphism(const std::shared_ptr<RingGSWCryptoParams>& params, NativeInteger a,
                                             ConstRingGSWEvalKey& ak, RLWECiphertext& acc) const {
    uint32_t aInt{a.ConvertToInt<uint32_t>()};
    AutomorphismKeySwitch(aInt, params->GetAutoMap(aInt), params->GetPolyParams(),
                          params->GetQ().ConvertToInt<BasicInteger>(), params->GetDefaultBaseGParams(),
                          ak->GetElements(), acc->GetElements());
}

};  // namespace lbcrypto
