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
RingGSWACCKey RingGSWAccumulatorCGGI::KeyGenAcc(const std::shared_ptr<RingGSWCryptoParams>& params,
                                                const NativePoly& skNTT, ConstLWEPrivateKey& LWEsk) const {
    auto sv    = LWEsk->GetElement();
    auto neg   = sv.GetModulus().ConvertToInt() - 1;
    uint32_t n = sv.GetLength();
    auto ek    = std::make_shared<RingGSWACCKeyImpl>(1, 2, n);
    auto& ek00 = (*ek)[0][0];
    auto& ek01 = (*ek)[0][1];

    // handles ternary secrets using signed mod 3 arithmetic; 0 -> {0,0}, 1 ->
    // {1,0}, -1 -> {0,1}
#pragma omp parallel for
    for (uint32_t i = 0; i < n; ++i) {
        auto s  = sv[i].ConvertToInt();
        ek00[i] = KeyGenCGGI(params, skNTT, s == 1 ? 1 : 0);
        ek01[i] = KeyGenCGGI(params, skNTT, s == neg ? 1 : 0);
    }
    return ek;
}

void RingGSWAccumulatorCGGI::EvalAcc(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWACCKey& ek,
                                     RLWECiphertext& acc, const NativeVector& a) const {
    auto mod        = a.GetModulus();
    uint32_t n      = a.GetLength();
    uint32_t MbyMod = 2 * params->GetN() / mod.ConvertToInt();
    for (uint32_t i = 0; i < n; ++i) {
        // handles -a*E(1) and handles -a*E(-1) = a*E(1)
        AddToAccCGGI(params, (*ek)[0][0][i], (*ek)[0][1][i], NativeInteger(0).ModSubFast(a[i], mod) * MbyMod, acc);
    }
}

// Encryption for the CGGI variant, as described in https://eprint.iacr.org/2020/086
RingGSWEvalKey RingGSWAccumulatorCGGI::KeyGenCGGI(const std::shared_ptr<RingGSWCryptoParams>& params,
                                                  const NativePoly& skNTT, LWEPlaintext m) const {
    const auto& Gpow       = params->GetGPower();
    const auto& polyParams = params->GetPolyParams();

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    NativeInteger Q{params->GetQ()};
    dug.SetModulus(Q);

    uint32_t digitsG2{params->GetDigitsG() << 1};
    std::vector<NativePoly> tempA(digitsG2, NativePoly(dug, polyParams, Format::COEFFICIENT));
    auto result = std::make_shared<RingGSWEvalKeyImpl>(digitsG2, 2);

    for (uint32_t i = 0; i < digitsG2; ++i) {
        (*result)[i][0] = tempA[i];
        tempA[i].SetFormat(Format::EVALUATION);
        (*result)[i][1] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);
        if (m)
            (*result)[i][i & 0x1][0].ModAddFastEq(Gpow[i >> 1], Q);
        (*result)[i][0].SetFormat(Format::EVALUATION);
        (*result)[i][1].SetFormat(Format::EVALUATION);
        (*result)[i][1] += tempA[i] * skNTT;
    }
    return result;
}

// CGGI Accumulation as described in https://eprint.iacr.org/2020/086
// Added ternary MUX introduced in paper https://eprint.iacr.org/2022/074.pdf section 5
// We optimize the algorithm by multiplying the monomial after the external product
// This reduces the number of polynomial multiplications which further reduces the runtime
void RingGSWAccumulatorCGGI::AddToAccCGGI(const std::shared_ptr<RingGSWCryptoParams>& params, const RingGSWEvalKey& ek1,
                                          const RingGSWEvalKey& ek2, const NativeInteger& a,
                                          RLWECiphertext& acc) const {
    size_t digitsG2{params->GetDigitsG() << 1};
    std::vector<NativePoly> dct(digitsG2, NativePoly(params->GetPolyParams(), Format::COEFFICIENT, true));

    std::vector<NativePoly> ct(acc->GetElements());
    ct[0].SetFormat(Format::COEFFICIENT);
    ct[1].SetFormat(Format::COEFFICIENT);

    SignedDigitDecompose(params, ct, dct);

    for (size_t i = 0; i < digitsG2; ++i)
        dct[i].SetFormat(Format::EVALUATION);

    // obtain both monomial(index) for sk = 1 and monomial(-index) for sk = -1
    // index is in range [0,m] - so we need to adjust the edge case when index == m to index = 0
    uint64_t MInt{2 * params->GetN()};
    NativeInteger M{MInt};
    uint64_t indexPos{a.ConvertToInt()};
    const NativePoly& monomial = params->GetMonomial(indexPos == MInt ? 0 : indexPos);
    uint64_t indexNeg{NativeInteger(0).ModSubFast(a, M).ConvertToInt()};
    const NativePoly& monomialNeg = params->GetMonomial(indexNeg == MInt ? 0 : indexNeg);

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
    NativePoly temp1(dct[0] * ev2[0][0]);
    for (size_t l = 1; l < digitsG2; ++l)
        temp1 += (dct[l] * ev2[l][0]);
    acc->GetElements()[0] += (temp1 *= monomialNeg);
    NativePoly temp2(dct[0] * ev2[0][1]);
    for (size_t l = 1; l < digitsG2; ++l)
        temp2 += (dct[l] *= ev2[l][1]);
    acc->GetElements()[1] += (temp2 *= monomialNeg);
}

};  // namespace lbcrypto
