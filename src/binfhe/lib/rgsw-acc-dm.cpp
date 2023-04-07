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

#include "rgsw-acc-dm.h"

#include <string>

namespace lbcrypto {

// Key generation as described in Section 4 of https://eprint.iacr.org/2014/816
RingGSWACCKey RingGSWAccumulatorDM::KeyGenAcc(const std::shared_ptr<RingGSWCryptoParams> params,
                                              const NativePoly& skNTT, ConstLWEPrivateKey LWEsk) const {
    auto sv     = LWEsk->GetElement();
    int32_t mod = sv.GetModulus().ConvertToInt();

    int32_t modHalf = mod >> 1;

    uint32_t baseR                            = params->GetBaseR();
    const std::vector<NativeInteger>& digitsR = params->GetDigitsR();
    uint32_t n                                = sv.GetLength();
    RingGSWACCKey ek                          = std::make_shared<RingGSWACCKeyImpl>(n, baseR, digitsR.size());

#pragma omp parallel for
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 1; j < baseR; ++j) {
            for (size_t k = 0; k < digitsR.size(); ++k) {
                int32_t s = (int32_t)sv[i].ConvertToInt();
                if (s > modHalf) {
                    s -= mod;
                }

                (*ek)[i][j][k] = KeyGenDM(params, skNTT, s * j * (int32_t)digitsR[k].ConvertToInt());
            }
        }
    }

    return ek;
}

void RingGSWAccumulatorDM::EvalAcc(const std::shared_ptr<RingGSWCryptoParams> params, const RingGSWACCKey ek,
                                   RLWECiphertext& acc, const NativeVector& a) const {
    uint32_t baseR = params->GetBaseR();
    auto digitsR   = params->GetDigitsR();
    auto q         = params->Getq();
    uint32_t n     = a.GetLength();

    for (size_t i = 0; i < n; ++i) {
        NativeInteger aI = q.ModSub(a[i], q);
        for (size_t k = 0; k < digitsR.size(); ++k, aI /= NativeInteger(baseR)) {
            uint32_t a0 = (aI.Mod(baseR)).ConvertToInt();
            if (a0)
                AddToAccDM(params, (*ek)[i][a0][k], acc);
        }
    }
}

// Encryption as described in Section 5 of https://eprint.iacr.org/2014/816
// skNTT corresponds to the secret key z
RingGSWEvalKey RingGSWAccumulatorDM::KeyGenDM(const std::shared_ptr<RingGSWCryptoParams> params,
                                              const NativePoly& skNTT, const LWEPlaintext& m) const {
    NativeInteger Q   = params->GetQ();
    uint64_t q        = params->Getq().ConvertToInt();
    uint32_t N        = params->GetN();
    uint32_t digitsG  = params->GetDigitsG();
    uint32_t digitsG2 = digitsG << 1;
    auto polyParams   = params->GetPolyParams();
    auto Gpow         = params->GetGPower();
    auto result       = std::make_shared<RingGSWEvalKeyImpl>(digitsG2, 2);

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(Q);
    
    // Reduce mod q (dealing with negative number as well)
    int64_t mm       = (((m % q) + q) % q) * (2 * N / q);
    bool isReducedMM = false;
    if (mm >= N) {
        mm -= N;
        isReducedMM = true;
    }

    // tempA is introduced to minimize the number of NTTs
    std::vector<NativePoly> tempA(digitsG2);

    for (size_t i = 0; i < digitsG2; ++i) {
        // populate result[i][0] with uniform random a
        (*result)[i][0] = NativePoly(dug, polyParams, Format::COEFFICIENT);
        tempA[i]        = (*result)[i][0];
        // populate result[i][1] with error e
        (*result)[i][1] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);
    }

    for (size_t i = 0; i < digitsG; ++i) {
        if (!isReducedMM) {
            // Add G Multiple
            (*result)[2 * i][0][mm].ModAddEq(Gpow[i], Q);
            // [a,as+e] + X^m*G
            (*result)[2 * i + 1][1][mm].ModAddEq(Gpow[i], Q);
        }
        else {
            // Subtract G Multiple
            (*result)[2 * i][0][mm].ModSubEq(Gpow[i], Q);
            // [a,as+e] - X^m*G
            (*result)[2 * i + 1][1][mm].ModSubEq(Gpow[i], Q);
        }
    }

    // 3*digitsG2 NTTs are called
    result->SetFormat(Format::EVALUATION);
    for (size_t i = 0; i < digitsG2; ++i) {
        tempA[i].SetFormat(Format::EVALUATION);
        (*result)[i][1] += tempA[i] * skNTT;
    }

    return result;
}

// AP Accumulation as described in https://eprint.iacr.org/2020/086
void RingGSWAccumulatorDM::AddToAccDM(const std::shared_ptr<RingGSWCryptoParams> params, const RingGSWEvalKey ek,
                                      RLWECiphertext& acc) const {
    uint32_t digitsG2 = params->GetDigitsG() << 1;
    auto polyParams   = params->GetPolyParams();

    std::vector<NativePoly> ct = acc->GetElements();
    std::vector<NativePoly> dct(digitsG2);

    // initialize dct to zeros
    for (size_t i = 0; i < digitsG2; i++)
        dct[i] = NativePoly(polyParams, Format::COEFFICIENT, true);

    // calls 2 NTTs
    for (size_t i = 0; i < 2; ++i)
        ct[i].SetFormat(Format::COEFFICIENT);

    SignedDigitDecompose(params, ct, dct);

    // calls digitsG2 NTTs
    for (size_t j = 0; j < digitsG2; ++j)
        dct[j].SetFormat(Format::EVALUATION);

    // acc = dct * ek (matrix product);
    // uses in-place * operators for the last call to dct[i] to gain performance
    // improvement
    const std::vector<std::vector<NativePoly>>& ev = ek->GetElements();
    // for elements[0]:
    acc->GetElements()[0].SetValuesToZero();
    for (size_t l = 1; l < digitsG2; ++l)
        acc->GetElements()[0] += (dct[l] * ev[l][0]);
    // for elements[1]:
    acc->GetElements()[1].SetValuesToZero();
    for (size_t l = 1; l < digitsG2; ++l)
        acc->GetElements()[1] += (dct[l] *= ev[l][1]);
}

};  // namespace lbcrypto
