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

#include "rgsw-acc-cggi.h"

#include <string>

namespace lbcrypto {

// Key generation as described in Section 4 of https://eprint.iacr.org/2014/816
RingGSWACCKey RingGSWAccumulatorCGGI::KeyGenAcc(const std::shared_ptr<RingGSWCryptoParams> params,
                                                const NativePoly& skNTT, ConstLWEPrivateKey LWEsk) const {
    auto sv         = LWEsk->GetElement();
    int32_t mod     = sv.GetModulus().ConvertToInt();
    int32_t modHalf = mod >> 1;
    uint32_t n      = sv.GetLength();
    auto ek         = std::make_shared<RingGSWACCKeyImpl>(1, 2, n);

    // handles ternary secrets using signed mod 3 arithmetic; 0 -> {0,0}, 1 ->
    // {1,0}, -1 -> {0,1}
#pragma omp parallel for
    for (size_t i = 0; i < n; ++i) {
        int32_t s = (int32_t)sv[i].ConvertToInt();
        if (s > modHalf) {
            s -= mod;
        }

        switch (s) {
            case 0:
                (*ek)[0][0][i] = KeyGenCGGI(params, skNTT, 0);
                (*ek)[0][1][i] = KeyGenCGGI(params, skNTT, 0);
                break;
            case 1:
                (*ek)[0][0][i] = KeyGenCGGI(params, skNTT, 1);
                (*ek)[0][1][i] = KeyGenCGGI(params, skNTT, 0);
                break;
            case -1:
                (*ek)[0][0][i] = KeyGenCGGI(params, skNTT, 0);
                (*ek)[0][1][i] = KeyGenCGGI(params, skNTT, 1);
                break;
            default:
                std::string errMsg = "ERROR: only ternary secret key distributions are supported.";
                OPENFHE_THROW(not_implemented_error, errMsg);
        }
    }

    return ek;
}

void RingGSWAccumulatorCGGI::EvalAcc(const std::shared_ptr<RingGSWCryptoParams> params, const RingGSWACCKey ek,
                                     RLWECiphertext& acc, const NativeVector& a) const {
    auto mod        = a.GetModulus();
    uint32_t n      = a.GetLength();
    uint32_t M      = 2 * params->GetN();
    uint32_t modInt = mod.ConvertToInt();

    for (size_t i = 0; i < n; ++i) {
        // handles -a*E(1) and handles -a*E(-1) = a*E(1)
        AddToAccCGGI(params, (*ek)[0][0][i], (*ek)[0][1][i], mod.ModSub(a[i], mod) * (M / modInt), acc);
    }
}

// Encryption for the CGGI variant, as described in https://eprint.iacr.org/2020/086
RingGSWEvalKey RingGSWAccumulatorCGGI::KeyGenCGGI(const std::shared_ptr<RingGSWCryptoParams> params,
                                                  const NativePoly& skNTT, const LWEPlaintext& m) const {
    NativeInteger Q   = params->GetQ();
    uint32_t digitsG  = params->GetDigitsG();
    uint32_t digitsG2 = digitsG << 1;
    auto Gpow         = params->GetGPower();
    auto polyParams   = params->GetPolyParams();
    auto result       = std::make_shared<RingGSWEvalKeyImpl>(digitsG2, 2);

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(Q);
    //std::cout << "digits size d_g " << digitsG << std::endl;
    // tempA is introduced to minimize the number of NTTs
    std::vector<NativePoly> tempA(digitsG2);

    for (size_t i = 0; i < digitsG2; ++i) {
        (*result)[i][0] = NativePoly(dug, polyParams, Format::COEFFICIENT);
        tempA[i]        = (*result)[i][0];
        (*result)[i][1] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);
    }

    if (m > 0) {
        for (size_t i = 0; i < digitsG; ++i) {
            // Add G Multiple
            (*result)[2 * i][0][0].ModAddEq(Gpow[i], Q);
            // [a,as+e] + G
            (*result)[2 * i + 1][1][0].ModAddEq(Gpow[i], Q);
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

// CGGI Accumulation as described in https://eprint.iacr.org/2020/086
// Added ternary MUX introduced in paper https://eprint.iacr.org/2022/074.pdf section 5
// We optimize the algorithm by multiplying the monomial after the external product
// This reduces the number of polynomial multiplications which further reduces the runtime
void RingGSWAccumulatorCGGI::AddToAccCGGI(const std::shared_ptr<RingGSWCryptoParams> params, const RingGSWEvalKey ek1,
                                          const RingGSWEvalKey ek2, const NativeInteger& a, RLWECiphertext& acc) const {
    // cycltomic order
    uint64_t MInt = 2 * params->GetN();
    NativeInteger M(MInt);
    uint32_t digitsG2 = params->GetDigitsG() << 1;
    auto polyParams   = params->GetPolyParams();

    std::vector<NativePoly> ct = acc->GetElements();
    std::vector<NativePoly> dct(digitsG2);

    // initialize dct to zeros
    for (size_t i = 0; i < digitsG2; ++i)
        dct[i] = NativePoly(polyParams, Format::COEFFICIENT, true);

    // calls 2 NTTs
    for (size_t i = 0; i < 2; ++i)
        ct[i].SetFormat(Format::COEFFICIENT);

    SignedDigitDecompose(params, ct, dct);

    for (size_t i = 0; i < digitsG2; ++i)
        dct[i].SetFormat(Format::EVALUATION);

    // First obtain both monomial(index) for sk = 1 and monomial(-index) for sk = -1
    auto aNeg         = M.ModSub(a, M);
    uint64_t indexPos = a.ConvertToInt();
    uint64_t indexNeg = aNeg.ConvertToInt();
    // index is in range [0,m] - so we need to adjust the edge case when
    // index = m to index = 0
    if (indexPos == MInt)
        indexPos = 0;
    if (indexNeg == MInt)
        indexNeg = 0;
    const NativePoly& monomial    = params->GetMonomial(indexPos);
    const NativePoly& monomialNeg = params->GetMonomial(indexNeg);

    // acc = acc + dct * ek1 * monomial + dct * ek2 * negative_monomial;
    // uses in-place * operators for the last call to dct[i] to gain performance
    // improvement. Needs to be done using two loops for ternary secrets.
    // TODO (dsuponit): benchmark cases with operator*() and operator*=(). Make a copy of dct?
    const std::vector<std::vector<NativePoly>>& ev1 = ek1->GetElements();
    for (size_t j = 0; j < 2; ++j) {
        NativePoly temp1(dct[0] * ev1[0][j]);
        for (size_t l = 1; l < digitsG2; ++l)
            temp1 += (dct[l] * ev1[l][j]);
        acc->GetElements()[j] += (temp1 *= monomial);
    }

    const std::vector<std::vector<NativePoly>>& ev2 = ek2->GetElements();
    // for elements[0]:
    NativePoly temp1(dct[0] * ev2[0][0]);
    for (size_t l = 1; l < digitsG2; ++l)
        temp1 += (dct[l] * ev2[l][0]);
    acc->GetElements()[0] += (temp1 *= monomialNeg);
    // for elements[1]:
    NativePoly temp2(dct[0] * ev2[0][1]);
    for (size_t l = 1; l < digitsG2; ++l)
        temp2 += (dct[l] *= ev2[l][1]);
    acc->GetElements()[1] += (temp2 *= monomialNeg);
}

};  // namespace lbcrypto
