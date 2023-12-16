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

#include "rgsw-acc-lmkcdey.h"

#include <string>

namespace lbcrypto {

// Key generation as described in https://eprint.iacr.org/2022/198
RingGSWACCKey RingGSWAccumulatorLMKCDEY::KeyGenAcc(const std::shared_ptr<RingGSWCryptoParams>& params,
                                                   const NativePoly& skNTT, ConstLWEPrivateKey& LWEsk) const {
    auto sv{LWEsk->GetElement()};
    auto mod{sv.GetModulus().ConvertToInt<int32_t>()};
    auto modHalf{mod >> 1};
    uint32_t N{params->GetN()};
    size_t n{sv.GetLength()};
    uint32_t numAutoKeys{params->GetNumAutoKeys()};

    // dim2, 0: for RGSW(X^si), 1: for automorphism keys
    // only w automorphism keys required
    // allocates (n - w) more memory for pointer (not critical for performance)
    RingGSWACCKey ek = std::make_shared<RingGSWACCKeyImpl>(1, 2, n);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(n))
    for (size_t i = 0; i < n; ++i) {
        auto s{sv[i].ConvertToInt<int32_t>()};
        (*ek)[0][0][i] = KeyGenLMKCDEY(params, skNTT, s > modHalf ? s - mod : s);
    }

    NativeInteger gen = NativeInteger(5);

    (*ek)[0][1][0] = KeyGenAuto(params, skNTT, 2 * N - gen.ConvertToInt());

    // m_window: window size, consider parameterization in the future
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numAutoKeys))
    for (uint32_t i = 1; i <= numAutoKeys; ++i)
        (*ek)[0][1][i] = KeyGenAuto(params, skNTT, gen.ModExp(i, 2 * N).ConvertToInt<LWEPlaintext>());
    return ek;
}

void RingGSWAccumulatorLMKCDEY::EvalAcc(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWACCKey& ek,
                                        RLWECiphertext& acc, const NativeVector& a) const {
    // assume a is all-odd ciphertext (using round-to-odd technique)
    size_t n             = a.GetLength();
    uint32_t Nh          = params->GetN() / 2;
    uint32_t M           = 2 * params->GetN();
    uint32_t numAutoKeys = params->GetNumAutoKeys();

    NativeInteger MNative(M);

    auto logGen = params->GetLogGen();
    std::unordered_map<int32_t, std::vector<int32_t>> permuteMap;

    for (size_t i = 0; i < n; i++) {  // put ail a_i in the permuteMap
        // make it odd; round-to-odd(https://eprint.iacr.org/2022/198) will improve error.
        int32_t aIOdd = NativeInteger(0).ModSubFast(a[i], MNative).ConvertToInt<uint32_t>() | 0x1;
        int32_t index = logGen[aIOdd];

        if (permuteMap.find(index) == permuteMap.end()) {
            std::vector<int32_t> indexVec;
            permuteMap[index] = indexVec;
        }
        auto& indexVec = permuteMap[index];
        indexVec.push_back(i);
    }

    NativeInteger gen(5);
    uint32_t genInt       = 5;
    uint32_t nSkips       = 0;
    acc->GetElements()[1] = (acc->GetElements()[1]).AutomorphismTransform(M - genInt);

    // for a_j = -5^i
    for (uint32_t i = Nh - 1; i > 0; i--) {
        if (permuteMap.find(-i) != permuteMap.end()) {
            if (nSkips != 0) {  // Rotation by 5^nSkips
                Automorphism(params, gen.ModExp(nSkips, M), (*ek)[0][1][nSkips], acc);
                nSkips = 0;
            }
            auto& indexVec = permuteMap[-i];
            for (size_t j = 0; j < indexVec.size(); j++) {
                AddToAccLMKCDEY(params, (*ek)[0][0][indexVec[j]], acc);
            }
        }
        nSkips++;

        if (nSkips == numAutoKeys || i == 1) {
            Automorphism(params, gen.ModExp(nSkips, M), (*ek)[0][1][nSkips], acc);
            nSkips = 0;
        }
    }

    // for -1
    if (permuteMap.find(M) != permuteMap.end()) {
        auto& indexVec = permuteMap[M];
        for (size_t j = 0; j < indexVec.size(); j++) {
            AddToAccLMKCDEY(params, (*ek)[0][0][indexVec[j]], acc);
        }
    }

    Automorphism(params, NativeInteger(M - genInt), (*ek)[0][1][0], acc);
    // for a_j = 5^i
    for (size_t i = Nh - 1; i > 0; i--) {
        if (permuteMap.find(i) != permuteMap.end()) {
            if (nSkips != 0) {  // Rotation by 5^nSkips
                Automorphism(params, gen.ModExp(nSkips, M), (*ek)[0][1][nSkips], acc);
                nSkips = 0;
            }

            auto& indexVec = permuteMap[i];
            for (size_t j = 0; j < indexVec.size(); j++) {
                AddToAccLMKCDEY(params, (*ek)[0][0][indexVec[j]], acc);
            }
        }
        nSkips++;

        if (nSkips == numAutoKeys || i == 1) {
            Automorphism(params, gen.ModExp(nSkips, M), (*ek)[0][1][nSkips], acc);
            nSkips = 0;
        }
    }

    // for 0
    if (permuteMap.find(0) != permuteMap.end()) {
        auto& indexVec = permuteMap[0];
        for (size_t j = 0; j < indexVec.size(); j++) {
            AddToAccLMKCDEY(params, (*ek)[0][0][indexVec[j]], acc);
        }
    }
}

// Encryption as described in Section 5 of https://eprint.iacr.org/2022/198
// Same as KeyGenAP, but only for X^{s_i}
// skNTT corresponds to the secret key z
RingGSWEvalKey RingGSWAccumulatorLMKCDEY::KeyGenLMKCDEY(const std::shared_ptr<RingGSWCryptoParams>& params,
                                                        const NativePoly& skNTT, LWEPlaintext m) const {
    auto polyParams = params->GetPolyParams();
    auto Gpow       = params->GetGPower();

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    NativeInteger Q{params->GetQ()};

    // Reduce mod q (dealing with negative number as well)
    int64_t q  = params->Getq().ConvertToInt<int64_t>();
    int64_t N  = params->GetN();
    int64_t mm = (((m % q) + q) % q) * (2 * N / q);
    bool isReducedMM{false};
    if (mm >= N) {
        mm -= N;
        isReducedMM = true;
    }

    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG2{(params->GetDigitsG() - 1) << 1};
    std::vector<NativePoly> tempA(digitsG2, NativePoly(dug, polyParams, Format::COEFFICIENT));
    RingGSWEvalKeyImpl result(digitsG2, 2);

    for (uint32_t i = 0; i < digitsG2; ++i) {
        result[i][0] = tempA[i];
        tempA[i].SetFormat(Format::EVALUATION);
        result[i][1] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);
        if (!isReducedMM)
            result[i][i & 0x1][mm].ModAddFastEq(Gpow[(i >> 1) + 1],
                                                Q);  // (i even) Add G Multiple, (i odd) [a,as+e] + X^m*G
        else
            result[i][i & 0x1][mm].ModSubFastEq(Gpow[(i >> 1) + 1],
                                                Q);  // (i even) Sub G Multiple, (i odd) [a,as+e] - X^m*G
        result[i][0].SetFormat(Format::EVALUATION);
        result[i][1].SetFormat(Format::EVALUATION);
        result[i][1] += (tempA[i] *= skNTT);
    }
    return std::make_shared<RingGSWEvalKeyImpl>(result);
}

// Generation of an autormorphism key
RingGSWEvalKey RingGSWAccumulatorLMKCDEY::KeyGenAuto(const std::shared_ptr<RingGSWCryptoParams>& params,
                                                     const NativePoly& skNTT, LWEPlaintext k) const {
    auto polyParams{params->GetPolyParams()};
    auto Gpow{params->GetGPower()};

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    NativeInteger Q{params->GetQ()};

    auto skAuto{skNTT.AutomorphismTransform(k)};

    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG{params->GetDigitsG() - 1};
    RingGSWEvalKeyImpl result(digitsG, 2);

    for (uint32_t i = 0; i < digitsG; ++i) {
        result[i][0] = NativePoly(dug, polyParams, EVALUATION);
        result[i][1] = NativePoly(params->GetDgg(), polyParams, EVALUATION) - skAuto * Gpow[i + 1];
        result[i][1] += result[i][0] * skNTT;
    }
    return std::make_shared<RingGSWEvalKeyImpl>(result);
}

// LMKCDEY Accumulation as described in https://eprint.iacr.org/2022/198
// Same as AP, but multiplied once
void RingGSWAccumulatorLMKCDEY::AddToAccLMKCDEY(const std::shared_ptr<RingGSWCryptoParams>& params,
                                                ConstRingGSWEvalKey& ek, RLWECiphertext& acc) const {
    std::vector<NativePoly> ct(acc->GetElements());
    ct[0].SetFormat(Format::COEFFICIENT);
    ct[1].SetFormat(Format::COEFFICIENT);

    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG2{(params->GetDigitsG() - 1) << 1};

    std::vector<NativePoly> dct(digitsG2, NativePoly(params->GetPolyParams(), Format::COEFFICIENT, true));

    SignedDigitDecompose(params, ct, dct);

    // calls digitsG2 NTTs
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(digitsG2))
    for (uint32_t d = 0; d < digitsG2; ++d)
        dct[d].SetFormat(Format::EVALUATION);

    // acc = dct * ek (matrix product);
    const std::vector<std::vector<NativePoly>>& ev = ek->GetElements();
    acc->GetElements()[0]                          = (dct[0] * ev[0][0]);
    for (uint32_t d = 1; d < digitsG2; ++d)
        acc->GetElements()[0] += (dct[d] * ev[d][0]);
    acc->GetElements()[1] = (dct[0] *= ev[0][1]);
    for (uint32_t d = 1; d < digitsG2; ++d)
        acc->GetElements()[1] += (dct[d] *= ev[d][1]);
}

// Automorphism
void RingGSWAccumulatorLMKCDEY::Automorphism(const std::shared_ptr<RingGSWCryptoParams>& params, const NativeInteger& a,
                                             ConstRingGSWEvalKey& ak, RLWECiphertext& acc) const {
    // precompute bit reversal for the automorphism into vec
    uint32_t N{params->GetN()};
    std::vector<usint> vec(N);
    PrecomputeAutoMap(N, a.ConvertToInt<usint>(), &vec);

    acc->GetElements()[1] = acc->GetElements()[1].AutomorphismTransform(a.ConvertToInt<usint>(), vec);

    NativePoly cta(acc->GetElements()[0]);
    acc->GetElements()[0].SetValuesToZero();
    cta = cta.AutomorphismTransform(a.ConvertToInt<usint>(), vec);
    cta.SetFormat(COEFFICIENT);

    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG{params->GetDigitsG() - 1};
    std::vector<NativePoly> dcta(digitsG, NativePoly(params->GetPolyParams(), Format::COEFFICIENT, true));

    SignedDigitDecompose(params, cta, dcta);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(digitsG))
    for (uint32_t d = 0; d < digitsG; ++d)
        dcta[d].SetFormat(Format::EVALUATION);

    // acc = dct * input (matrix product);
    const std::vector<std::vector<NativePoly>>& ev = ak->GetElements();
    for (uint32_t d = 0; d < digitsG; ++d)
        acc->GetElements()[0] += (dcta[d] * ev[d][0]);
    for (uint32_t d = 0; d < digitsG; ++d)
        acc->GetElements()[1] += (dcta[d] *= ev[d][1]);
}

};  // namespace lbcrypto
