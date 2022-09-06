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

#include <string>

#include "rgsw-acc-cggi.h"

namespace lbcrypto {

// Key generation as described in Section 4 of https://eprint.iacr.org/2014/816
RingGSWACCKey RingGSWAccumulatorCGGI::KeyGenACC(const std::shared_ptr<RingGSWCryptoParams> params,
                                                const NativePoly& skNTT, ConstLWEPrivateKey LWEsk) const {
    int32_t qInt  = (int32_t)params->Getq().ConvertToInt();
    int32_t qHalf = qInt >> 1;
    auto sv       = LWEsk->GetElement();
    uint32_t n    = sv.GetLength();
    auto ek       = std::make_shared<RingGSWACCKeyImpl>(1, 2, n);

    // handles ternary secrets using signed mod 3 arithmetic; 0 -> {0,0}, 1 ->
    // {1,0}, -1 -> {0,1}
#pragma omp parallel for
    for (uint32_t i = 0; i < n; ++i) {
        int32_t s = (int32_t)sv[i].ConvertToInt();
        if (s > qHalf) {
            s -= qInt;
        }

        switch (s) {
            case 0:
                (*ek)[0][0][i] = KeyGenGINX(params, skNTT, 0);
                (*ek)[0][1][i] = KeyGenGINX(params, skNTT, 0);
                break;
            case 1:
                (*ek)[0][0][i] = KeyGenGINX(params, skNTT, 1);
                (*ek)[0][1][i] = KeyGenGINX(params, skNTT, 0);
                break;
            case -1:
                (*ek)[0][0][i] = KeyGenGINX(params, skNTT, 0);
                (*ek)[0][1][i] = KeyGenGINX(params, skNTT, 1);
                break;
            default:
                std::string errMsg = "ERROR: only ternary secret key distributions are supported.";
                OPENFHE_THROW(not_implemented_error, errMsg);
        }
    }

    return ek;
}

void RingGSWAccumulatorCGGI::EvalACC(const std::shared_ptr<RingGSWCryptoParams> params, const RingGSWACCKey ek,
                                     RingGSWCiphertext& acc, const NativeVector& a) const {
    auto q     = params->Getq();
    uint32_t n = a.GetLength();

    for (uint32_t i = 0; i < n; i++) {
        // handles -a*E(1) and handles -a*E(-1) = a*E(1)
        AddToACCGINX(params, (*ek)[0][0][i], (*ek)[0][1][i], q.ModSub(a[i], q), acc);
    }
}

// Encryption for the GINX variant, as described in https://eprint.iacr.org/2020/08
RingGSWEvalKey RingGSWAccumulatorCGGI::KeyGenGINX(const std::shared_ptr<RingGSWCryptoParams> params,
                                                  const NativePoly& skNTT, const LWEPlaintext& m) const {
    NativeInteger Q   = params->GetQ();
    uint32_t digitsG  = params->GetDigitsG();
    uint32_t digitsG2 = params->GetDigitsG2();
    auto Gpow         = params->GetGPower();
    auto polyParams   = params->GetPolyParams();
    auto result       = std::make_shared<RingGSWEvalKeyImpl>(digitsG2, 2);

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(Q);

    // tempA is introduced to minimize the number of NTTs
    std::vector<NativePoly> tempA(digitsG2);

    for (uint32_t i = 0; i < digitsG2; ++i) {
        (*result)[i][0] = NativePoly(dug, polyParams, Format::COEFFICIENT);
        tempA[i]        = (*result)[i][0];
        (*result)[i][1] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);
    }

    for (uint32_t i = 0; i < digitsG; ++i) {
        if (m > 0) {
            // Add G Multiple
            (*result)[2 * i][0][0].ModAddEq(Gpow[i], Q);
            // [a,as+e] + G
            (*result)[2 * i + 1][1][0].ModAddEq(Gpow[i], Q);
        }
    }

    // 3*digitsG2 NTTs are called
    result->SetFormat(Format::EVALUATION);
    for (uint32_t i = 0; i < digitsG2; ++i) {
        tempA[i].SetFormat(Format::EVALUATION);
        (*result)[i][1] += tempA[i] * skNTT;
    }

    return result;
}

// GINX Accumulation as described in https://eprint.iacr.org/2020/08
// Added ternary MUX introduced in paper https://eprint.iacr.org/2022/074.pdf section 5
// We optimize the algorithm by multiplying the monomial after the external product
// This reduces the number of polynomial multiplications which further reduces the runtime
void RingGSWAccumulatorCGGI::AddToACCGINX(const std::shared_ptr<RingGSWCryptoParams> params, const RingGSWEvalKey ek1,
                                          const RingGSWEvalKey ek2, const NativeInteger& a,
                                          RingGSWCiphertext& acc) const {
    // cycltomic order
    uint32_t m        = 2 * params->GetN();
    uint32_t digitsG2 = params->GetDigitsG2();
    int64_t q         = params->Getq().ConvertToInt();
    auto polyParams   = params->GetPolyParams();

    std::vector<NativePoly> ct = acc->GetElements()[0];
    std::vector<NativePoly> dct(digitsG2);

    // initialize dct to zeros
    for (uint32_t i = 0; i < digitsG2; i++)
        dct[i] = NativePoly(polyParams, Format::COEFFICIENT, true);

    // calls 2 NTTs
    for (uint32_t i = 0; i < 2; i++)
        ct[i].SetFormat(Format::COEFFICIENT);

    SignedDigitDecompose(params, ct, &dct);

    for (uint32_t j = 0; j < digitsG2; j++)
        dct[j].SetFormat(Format::EVALUATION);

    // First obtain both monomial(index) for sk = 1 and monomial(-index) for sk = -1
    auto aNeg         = params->Getq().ModSub(a, q);
    uint64_t index    = a.ConvertToInt() * (m / q);
    uint64_t indexNeg = aNeg.ConvertToInt() * (m / q);
    // index is in range [0,m] - so we need to adjust the edge case when
    // index = m to index = 0
    if (index == m)
        index = 0;
    if (indexNeg == m)
        indexNeg = 0;
    const NativePoly& monomial    = params->GetMonomial(index);
    const NativePoly& monomialNeg = params->GetMonomial(indexNeg);

    // acc = acc + dct * ek1 * monomial + dct * ek2 * negative_monomial;
    // uses in-place * operators for the last call to dct[i] to gain performance
    // improvement. Needs to be done using two loops for ternary secrets.
    const std::vector<std::vector<NativePoly>>& ev1 = ek1->GetElements();
    for (uint32_t j = 0; j < 2; j++) {
        NativePoly temp1 = (j < 1) ? dct[0] * ev1[0][j] : (dct[0] * ev1[0][j]);
        for (uint32_t l = 1; l < digitsG2; l++) {
            if (j == 0)
                temp1 += dct[l] * ev1[l][j];
            else
                temp1 += (dct[l] * ev1[l][j]);
        }
        (*acc)[0][j] += (temp1 * monomial);
    }

    const std::vector<std::vector<NativePoly>>& ev2 = ek2->GetElements();
    for (uint32_t j = 0; j < 2; j++) {
        NativePoly temp1 = (j < 1) ? dct[0] * ev2[0][j] : (dct[0] * ev2[0][j]);
        for (uint32_t l = 1; l < digitsG2; l++) {
            if (j == 0)
                temp1 += dct[l] * ev2[l][j];
            else
                temp1 += (dct[l] * ev2[l][j]);
        }
        (*acc)[0][j] += (temp1 * monomialNeg);
    }
}

};  // namespace lbcrypto
