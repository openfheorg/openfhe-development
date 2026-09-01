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

#include <memory>
#include <vector>

namespace lbcrypto {

// Key generation as described in Section 4 of https://eprint.iacr.org/2014/816
RingGSWACCKey RingGSWAccumulatorCGGI::KeyGenAcc(const std::shared_ptr<RingGSWCryptoParams>& params,
                                                const NativePoly& skNTT, ConstLWEPrivateKey& LWEsk) const {
    auto sv    = LWEsk->GetElement();
    auto neg   = sv.GetModulus().ConvertToInt() - 1;
    uint32_t n = sv.GetLength();
    params->VerifyBaseGCoverage(n);
    for (uint32_t i = 0; i < n; ++i) {
        auto s = sv[i].ConvertToInt();
        if (s != 0 && s != 1 && s != neg)
            OPENFHE_THROW("GINX/CGGI requires a ternary LWE secret key");
    }

    auto ek    = std::make_shared<RingGSWACCKeyImpl>(1, 2, n);
    auto& ek00 = (*ek)[0][0];
    auto& ek01 = (*ek)[0][1];

    // handles ternary secrets using signed mod 3 arithmetic
    // 0 -> {0,0}, 1 -> {1,0}, -1 -> {0,1}
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(n))
    for (uint32_t i = 0; i < n; ++i) {
        auto s  = sv[i].ConvertToInt();
        ek00[i] = KeyGenCGGI(params, skNTT, s == 1 ? 1 : 0, i);
        ek01[i] = KeyGenCGGI(params, skNTT, s == neg ? 1 : 0, i);
    }
    return ek;
}

void RingGSWAccumulatorCGGI::EvalAcc(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWACCKey& ek,
                                     RLWECiphertext& acc, const NativeVector& a) const {
    uint32_t n(a.GetLength());
    auto mod{a.GetModulus()};
    auto MbyMod{NativeInteger(2 * params->GetN()) / mod};
    for (uint32_t i = 0; i < n; ++i) {
        // handles -a*E(1) and handles -a*E(-1) = a*E(1)
        AddToAccCGGI(params, (*ek)[0][0][i], (*ek)[0][1][i], NativeInteger(0).ModSubFast(a[i], mod) * MbyMod, acc, i);
    }
}

// Encryption for the CGGI variant, as described in https://eprint.iacr.org/2020/086
RingGSWEvalKey RingGSWAccumulatorCGGI::KeyGenCGGI(const std::shared_ptr<RingGSWCryptoParams>& params,
                                                  const NativePoly& skNTT, LWEPlaintext m, uint32_t index) const {
    const auto& polyParams = params->GetPolyParams();

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    NativeInteger Q{params->GetQ()};

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
        if (m)
            result[i][i & 0x1][0].ModAddFastEq(Gpow[(i >> 1) + 1], Q);
        result[i][0].SetFormat(Format::EVALUATION);
        result[i][1].SetFormat(Format::EVALUATION);
        result[i][1] += (tmp *= skNTT);
    }
    return std::make_shared<RingGSWEvalKeyImpl>(std::move(result));
}

// CGGI Accumulation as described in https://eprint.iacr.org/2020/086
// Added ternary MUX introduced in paper https://eprint.iacr.org/2022/074.pdf section 5
// We optimize the algorithm by multiplying the monomial after the external product
// This reduces the number of polynomial multiplications which further reduces the runtime
void RingGSWAccumulatorCGGI::AddToAccCGGI(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWEvalKey& ek1,
                                          ConstRingGSWEvalKey& ek2, NativeInteger a, RLWECiphertext& acc,
                                          uint32_t index) const {
    std::vector<NativePoly> ct(acc->GetElements());

    // approximate gadget decomposition is used; the first digit is ignored
    const auto& bp = params->GetBaseGParams(index);
    uint32_t digitsG2{(bp.digitsG - 1) << 1};
    std::vector<NativePoly> dct(digitsG2, NativePoly(params->GetPolyParams(), Format::COEFFICIENT, true));

    // obtain both monomial(index) for sk = 1 and monomial(-index) for sk = -1
    // index is in range [0,m] - so we need to adjust the edge case when index == m to index = 0
    uint32_t MInt{2 * params->GetN()};
    NativeInteger M{MInt};
    uint32_t indexPos{a.ConvertToInt<uint32_t>()};
    const NativePoly& monomial = params->GetMonomial(indexPos == MInt ? 0 : indexPos);
    uint32_t indexNeg{NativeInteger(0).ModSubFast(a, M).ConvertToInt<uint32_t>()};
    const NativePoly& monomialNeg = params->GetMonomial(indexNeg == MInt ? 0 : indexNeg);

    // acc = acc + dct * ek1 * monomial + dct * ek2 * negative_monomial
    const auto& ev1(ek1->GetElements());
    const auto& ev2(ek2->GetElements());
    NativePoly tmp[4];

    int nthreads = OpenFHEParallelControls.GetThreadLimit(digitsG2 > 4 ? digitsG2 : 4);

    if (nthreads < 2) {
        ct[0].SetFormat(Format::COEFFICIENT);
        ct[1].SetFormat(Format::COEFFICIENT);
        SignedDigitDecomposeImpl(params, ct, dct, bp);
        for (uint32_t i = 0; i < digitsG2; ++i)
            dct[i].SetFormat(Format::EVALUATION);
        for (uint32_t j = 0; j < 4; ++j) {
            const auto& ev = (j < 2) ? ev1 : ev2;
            uint32_t col{j & 0x1};
            NativePoly t(dct[0] * ev[0][col]);
            for (uint32_t i = 1; i < digitsG2; ++i)
                t.MultAccEqNoCheck(dct[i], ev[i][col]);
            acc->GetElements()[col] += (t *= (j < 2) ? monomial : monomialNeg);
        }
        return;
    }

#pragma omp parallel num_threads(nthreads)
    {
#pragma omp for schedule(static) nowait
        for (uint32_t i = 0; i < 2; ++i)
            ct[i].SetFormat(Format::COEFFICIENT);

#pragma omp barrier
#pragma omp single
        SignedDigitDecomposeImpl(params, ct, dct, bp);

#pragma omp for schedule(static)
        for (uint32_t i = 0; i < digitsG2; ++i)
            dct[i].SetFormat(Format::EVALUATION);

#pragma omp for schedule(static)
        for (uint32_t j = 0; j < 4; ++j) {
            const auto& ev = (j < 2) ? ev1 : ev2;
            uint32_t col{j & 0x1};
            tmp[j] = dct[0] * ev[0][col];
            for (uint32_t i = 1; i < digitsG2; ++i)
                tmp[j].MultAccEqNoCheck(dct[i], ev[i][col]);
            tmp[j] *= (j < 2) ? monomial : monomialNeg;
        }
    }

    acc->GetElements()[0] += tmp[0];
    acc->GetElements()[1] += tmp[1];
    acc->GetElements()[0] += tmp[2];
    acc->GetElements()[1] += tmp[3];
}

};  // namespace lbcrypto
