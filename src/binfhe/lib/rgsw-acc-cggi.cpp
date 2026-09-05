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

#include "rgsw-acc-cggi.h"

#include "rgsw-acc-common.h"

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

#if NATIVEINT != 32
namespace {

// native 32-bit twin of KeyGenCGGI: RGSW encryption of m*G built directly on NativePoly32
RingGSWACCKey32Impl::EvalKey32 KeyGenCGGI32(const std::shared_ptr<RingGSWCryptoParams>& params,
                                            const std::shared_ptr<ILNativeParams32>& polyParams,
                                            const NativePoly32& skNTT32,
                                            const DiscreteGaussianGeneratorImpl<NativeVector32>& dgg, LWEPlaintext m,
                                            uint32_t index) {
    DiscreteUniformGeneratorImpl<NativeVector32> dug;
    NativeInteger32 Q32{static_cast<uint32_t>(params->GetQ().ConvertToInt())};

    // approximate gadget decomposition is used; the first digit is ignored
    const auto& bp = params->GetBaseGParams(index);
    uint32_t digitsG2{(bp.digitsG - 1) << 1};
    const auto& Gpow{*bp.gpow};

    RingGSWACCKey32Impl::EvalKey32 result(digitsG2, std::vector<NativePoly32>(2));
    NativePoly32 tmp;
    for (uint32_t i = 0; i < digitsG2; ++i) {
        result[i][0] = NativePoly32(dug, polyParams, Format::COEFFICIENT);
        tmp          = result[i][0];
        tmp.SetFormat(Format::EVALUATION);
        result[i][1] = NativePoly32(dgg, polyParams, Format::COEFFICIENT);
        if (m)
            result[i][i & 0x1][0].ModAddFastEq(NativeInteger32(Gpow[(i >> 1) + 1].ConvertToInt<uint32_t>()), Q32);
        result[i][0].SetFormat(Format::EVALUATION);
        result[i][1].SetFormat(Format::EVALUATION);
        result[i][1] += (tmp *= skNTT32);
    }
    return result;
}

}  // namespace

RingGSWACCKey32 RingGSWAccumulatorCGGI::KeyGenAcc32(const std::shared_ptr<RingGSWCryptoParams>& params,
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

    auto acc = std::make_shared<RingGSWACCKey32Impl>(params, 1, 2, n);

    const auto& polyParams32 = params->GetPolyParams32();
    const auto skNTT32       = NarrowPoly32(skNTT, polyParams32);
    DiscreteGaussianGeneratorImpl<NativeVector32> dgg32(params->GetDgg().GetStd());

    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(n))
    for (uint32_t i = 0; i < n; ++i) {
        auto s = sv[i].ConvertToInt();
        acc->SetEvalKey(0, 0, i, KeyGenCGGI32(params, polyParams32, skNTT32, dgg32, s == 1 ? 1 : 0, i));
        acc->SetEvalKey(0, 1, i, KeyGenCGGI32(params, polyParams32, skNTT32, dgg32, s == neg ? 1 : 0, i));
    }
    return acc;
}
#endif

#if NATIVEINT != 32
namespace {

void AddToAccCGGI32(const std::shared_ptr<ILNativeParams32>& polyParams, uint32_t Q, uint64_t mu, uint32_t M,
                    const RingGSWCryptoParams::BaseGParams& bp, const RingGSWACCKey32Impl::EvalKey32& ek1,
                    const RingGSWACCKey32Impl::EvalKey32& ek2, const std::vector<NativePoly32>& monomials,
                    const std::vector<NativeVector32>& monomialsPrecon, const NativeInteger& a,
                    std::vector<NativePoly32>& acc) {
    thread_local std::vector<NativePoly32> ctScratch, dctScratch, tmpScratch;
    auto& ct  = ctScratch;
    auto& dct = dctScratch;
    auto& tmp = tmpScratch;
    ct        = acc;

    uint32_t digitsG2{(bp.digitsG - 1) << 1};
    if (dct.size() != digitsG2 || dct[0].GetParams() != polyParams) {
        dct.assign(digitsG2, NativePoly32(polyParams, Format::COEFFICIENT, true));
        tmp.assign(4, NativePoly32(polyParams, Format::EVALUATION, true));
    }
    else {
        for (auto& d : dct)
            d.OverrideFormat(Format::COEFFICIENT);
    }

    uint32_t N{static_cast<uint32_t>(polyParams->GetRingDimension())};
    uint32_t indexPos{a.ConvertToInt<uint32_t>()};
    if (indexPos == M)
        indexPos = 0;
    uint32_t indexNeg{NativeInteger(0).ModSubFast(a, NativeInteger(M)).ConvertToInt<uint32_t>()};
    if (indexNeg == M)
        indexNeg = 0;
    const NativePoly32& monomial         = monomials[indexPos];
    const NativePoly32& monomialNeg      = monomials[indexNeg];
    const NativeVector32& monomialPre    = monomialsPrecon[indexPos];
    const NativeVector32& monomialPreNeg = monomialsPrecon[indexNeg];

    int nthreads = OpenFHEParallelControls.GetThreadLimit(digitsG2 > 4 ? digitsG2 : 4);

    if (nthreads < 2) {
        ct[0].SetFormat(Format::COEFFICIENT);
        ct[1].SetFormat(Format::COEFFICIENT);
        ExcessHDigitDecompose(Q, bp, ct, dct);
        for (uint32_t i = 0; i < digitsG2; ++i)
            dct[i].SetFormat(Format::EVALUATION);
        for (uint32_t j = 0; j < 4; ++j) {
            const auto& ev = (j < 2) ? ek1 : ek2;
            uint32_t col{j & 0x1};
            LazyInnerProduct32(tmp[j], dct, ev, col, digitsG2, 0, N, N, Q, mu);
            ShoupMulEq32(tmp[j], (j < 2) ? monomial : monomialNeg, (j < 2) ? monomialPre : monomialPreNeg, Q);
            acc[col] += tmp[j];
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
        ExcessHDigitDecompose(Q, bp, ct, dct);

    #pragma omp for schedule(static)
        for (uint32_t i = 0; i < digitsG2; ++i)
            dct[i].SetFormat(Format::EVALUATION);

    #pragma omp for schedule(static)
        for (uint32_t j = 0; j < 4; ++j) {
            const auto& ev = (j < 2) ? ek1 : ek2;
            uint32_t col{j & 0x1};
            LazyInnerProduct32(tmp[j], dct, ev, col, digitsG2, 0, N, N, Q, mu);
            ShoupMulEq32(tmp[j], (j < 2) ? monomial : monomialNeg, (j < 2) ? monomialPre : monomialPreNeg, Q);
        }
    }

    acc[0] += tmp[0];
    acc[1] += tmp[1];
    acc[0] += tmp[2];
    acc[1] += tmp[3];
}

}  // namespace

void RingGSWAccumulatorCGGI::EvalAcc32(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWACCKey32& ek,
                                       RLWECiphertext& acc, const NativeVector& a) const {
    const auto& polyParams      = params->GetPolyParams32();
    const auto& monomials       = *params->GetMonomials32();
    const auto& monomialsPrecon = *params->GetMonomialsPrecon32();
    uint32_t Q{static_cast<uint32_t>(params->GetQ().ConvertToInt())};
    uint64_t mu{static_cast<uint64_t>(-1) / Q};  // == floor(2^64/Q); Q is odd so it never divides 2^64
    uint32_t M{2 * params->GetN()};

    auto acc32 = NarrowAcc32(polyParams, acc->GetElements());

    uint32_t n{static_cast<uint32_t>(a.GetLength())};
    auto mod{a.GetModulus()};
    auto MbyMod{NativeInteger(M) / mod};
    for (uint32_t i = 0; i < n; ++i) {
        AddToAccCGGI32(polyParams, Q, mu, M, params->GetBaseGParams(i), (*ek)[0][0][i], (*ek)[0][1][i], monomials,
                       monomialsPrecon, NativeInteger(0).ModSubFast(a[i], mod) * MbyMod, acc32);
    }

    WidenAcc32Into(acc32, acc->GetElements());
}
#endif  // NATIVEINT != 32

void RingGSWAccumulatorCGGI::EvalAcc(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWACCKey& ek,
                                     RLWECiphertext& acc, const NativeVector& a) const {
    if (!params->HasMonomials())
        OPENFHE_THROW("the 64-bit monomials were released; regenerate keys or reload them through the context");
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
    thread_local std::vector<NativePoly> ctScratch, dctScratch, tmpScratch;
    auto& ct  = ctScratch;
    auto& dct = dctScratch;
    auto& tmp = tmpScratch;
    ct        = acc->GetElements();

    // approximate gadget decomposition is used; the first digit is ignored
    const auto& bp = params->GetBaseGParams(index);
    uint32_t digitsG2{(bp.digitsG - 1) << 1};
    const auto& polyParams = params->GetPolyParams();
    if (dct.size() != digitsG2 || dct[0].GetParams() != polyParams) {
        dct.assign(digitsG2, NativePoly(polyParams, Format::COEFFICIENT, true));
    }
    else {
        for (auto& d : dct)
            d.OverrideFormat(Format::COEFFICIENT);
    }
    if (tmp.size() != 4)
        tmp.resize(4);

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
            NativePoly& t = tmp[j];
            t             = dct[0];
            t *= ev[0][col];
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
            tmp[j] = dct[0];
            tmp[j] *= ev[0][col];
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
