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

#ifndef _RGSW_ACC_COMMON_H_
#define _RGSW_ACC_COMMON_H_

#include "rgsw-cryptoparameters.h"
#include "utils/parallel.h"

#include <memory>
#include <unordered_map>
#include <vector>

// Accumulator bodies shared between the 64-bit accumulators and the 32-bit internal path,
// templated on the polynomial type so each algorithm exists exactly once. P's word type is
// P::Integer::Integer (BasicInteger for NativePoly, uint32_t for NativePoly32).

namespace lbcrypto {

// Excess-H signed digit decomposition of an RLWE ciphertext (both components) into digitsG2
// digits. Biasing by H (gHalf in every digit position) turns balanced-digit extraction into
// independent unsigned windows: digit_k(x) = (((x + H) >> k*gBits) & gMask) - gHalf.
// Requires digitsG*gBits + 1 <= word bits, which holds for all supported parameter sets.
template <typename P>
void ExcessHDigitDecompose(typename P::Integer::Integer Q, const RingGSWCryptoParams::BaseGParams& bp,
                           const std::vector<P>& input, std::vector<P>& output) {
    using I = typename P::Integer::Integer;
    I QHalf{Q >> 1};
    uint32_t gBits{bp.gBits};
    I gHalf{static_cast<I>(bp.baseG >> 1)};
    I gMask{static_cast<I>(bp.baseG - 1)};
    I QmHalf{Q - gHalf};
    uint32_t digitsG{bp.digitsG};
    I H{0};
    for (uint32_t i{0}; i < digitsG; ++i)
        H += gHalf << (i * gBits);
    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG2{(digitsG - 1) << 1};
    uint32_t N{input[0].GetLength()};

    std::vector<I> w0(N), w1(N);
    for (uint32_t k{0}; k < N; ++k) {
        auto t0{input[0][k].template ConvertToInt<I>()};
        w0[k] = t0 + H - (t0 < QHalf ? 0 : Q);
        auto t1{input[1][k].template ConvertToInt<I>()};
        w1[k] = t1 + H - (t1 < QHalf ? 0 : Q);
    }

    for (uint32_t d{0}; d < digitsG2; d += 2) {
        uint32_t shift{((d >> 1) + 1) * gBits};
        // Q/2 + H can exceed baseG^digitsG, so the top window must keep the carry out of digitsG*gBits.
        auto mask{(d + 2 < digitsG2) ? gMask : static_cast<I>(-1)};
        auto& out0{output[d + 0]};
        auto& out1{output[d + 1]};
        for (uint32_t k{0}; k < N; ++k) {
            auto r0{(w0[k] >> shift) & mask};
            out0[k] = (r0 < gHalf) ? r0 + QmHalf : r0 - gHalf;
            auto r1{(w1[k] >> shift) & mask};
            out1[k] = (r1 < gHalf) ? r1 + QmHalf : r1 - gHalf;
        }
    }
}

// Single-ring-element overload producing digitsG - 1 digits (for LMKCDEY automorphism key switch)
template <typename P>
void ExcessHDigitDecompose(typename P::Integer::Integer Q, const RingGSWCryptoParams::BaseGParams& bp, const P& input,
                           std::vector<P>& output) {
    using I = typename P::Integer::Integer;
    I QHalf{Q >> 1};
    uint32_t gBits{bp.gBits};
    I gHalf{static_cast<I>(bp.baseG >> 1)};
    I gMask{static_cast<I>(bp.baseG - 1)};
    I QmHalf{Q - gHalf};
    uint32_t digitsG{bp.digitsG};
    I H{0};
    for (uint32_t i{0}; i < digitsG; ++i)
        H += gHalf << (i * gBits);
    uint32_t N{input.GetLength()};

    std::vector<I> w(N);
    for (uint32_t k{0}; k < N; ++k) {
        auto t0{input[k].template ConvertToInt<I>()};
        w[k] = t0 + H - (t0 < QHalf ? 0 : Q);
    }

    // approximate gadget decomposition is used; the first digit is ignored
    for (uint32_t d{0}; d < digitsG - 1; ++d) {
        uint32_t shift{(d + 1) * gBits};
        // Q/2 + H can exceed baseG^digitsG, so the top window must keep the carry out of digitsG*gBits.
        auto mask{(d + 2 < digitsG) ? gMask : static_cast<I>(-1)};
        auto& out{output[d]};
        for (uint32_t k{0}; k < N; ++k) {
            auto r0{(w[k] >> shift) & mask};
            out[k] = (r0 < gHalf) ? r0 + QmHalf : r0 - gHalf;
        }
    }
}

// acc = dct * ev (matrix product over the gadget digits);
template <typename P>
void GadgetMatrixProduct(std::vector<P>& acc, std::vector<P>& dct, const std::vector<std::vector<P>>& ev,
                         uint32_t rows) {
    acc[0] = (dct[0] * ev[0][0]);
    for (uint32_t d = 1; d < rows; ++d)
        acc[0].MultAccEqNoCheck(dct[d], ev[d][0]);
    acc[1] = (dct[0] *= ev[0][1]);
    for (uint32_t d = 1; d < rows; ++d)
        acc[1].MultAccEqNoCheck(dct[d], ev[d][1]);
}

// DM/LMKCDEY acc (no monomial): decompose, NTT the digits, external product with one RGSW key.
template <typename P, typename PP>
void AddToAccNoMonomial(const PP& polyParams, typename P::Integer::Integer Q,
                        const RingGSWCryptoParams::BaseGParams& bp, const std::vector<std::vector<P>>& ev,
                        std::vector<P>& acc) {
    using I = typename P::Integer::Integer;
    thread_local std::vector<P> ctScratch, dctScratch;
    thread_local std::vector<I> w0Scratch, w1Scratch;
    auto& ct  = ctScratch;
    auto& dct = dctScratch;
    auto& w0  = w0Scratch;
    auto& w1  = w1Scratch;
    ct        = acc;

    uint32_t N{acc[0].GetLength()};
    if (w0.size() != N) {
        w0.resize(N);
        w1.resize(N);
    }

    uint32_t digitsG2{(bp.digitsG - 1) << 1};
    if (dct.size() != digitsG2 || dct[0].GetParams() != polyParams) {
        dct.assign(digitsG2, P(polyParams, Format::COEFFICIENT, true));
    }
    else {
        for (auto& d : dct)
            d.OverrideFormat(Format::COEFFICIENT);
    }

    int nthreads = OpenFHEParallelControls.GetThreadLimit(digitsG2 > 8 ? (digitsG2 >> 1) : 4);
    if (nthreads < 2) {
        ct[0].SetFormat(Format::COEFFICIENT);
        ct[1].SetFormat(Format::COEFFICIENT);
        ExcessHDigitDecompose(Q, bp, ct, dct);
        for (uint32_t d = 0; d < digitsG2; ++d)
            dct[d].SetFormat(Format::EVALUATION);
        GadgetMatrixProduct(acc, dct, ev, digitsG2);
        return;
    }

#pragma omp parallel num_threads(nthreads)
    {
#pragma omp for schedule(static) nowait
        for (uint32_t i = 0; i < 2; ++i)
            ct[i].SetFormat(Format::COEFFICIENT);

#pragma omp barrier
        // the shared form spreads the decomposition across the region at the price of one
        // more barrier, which only repays itself once the gadget is wide and the split deep
        if (digitsG2 >= 8 && nthreads >= 4) {
            ExcessHDigitDecomposeShared(Q, bp, ct, dct, w0, w1);
        }
        else {
#pragma omp single
            ExcessHDigitDecompose(Q, bp, ct, dct);
        }

#pragma omp for schedule(static)
        for (uint32_t d = 0; d < digitsG2; ++d)
            dct[d].SetFormat(Format::EVALUATION);

            // each column writes only its own acc element, so GadgetMatrixProduct's in-place
            // reuse of dct[0] for the second column cannot be used here. nowait: the region's
            // own closing barrier is the one the caller needs
#pragma omp for schedule(static) nowait
        for (uint32_t j = 0; j < 2; ++j) {
            acc[j] = dct[0];
            acc[j] *= ev[0][j];
            for (uint32_t d = 1; d < digitsG2; ++d)
                acc[j].MultAccEqNoCheck(dct[d], ev[d][j]);
        }
    }
}

// As above, but the two loops are worksharing constructs that bind to the region the caller
// already opened, so the decomposition runs across that region's threads instead of on one.
// w0 and w1 are the caller's, and must be sized N before the region opens: every thread runs
// this body and each fills part of the one shared pair.
template <typename P>
void ExcessHDigitDecomposeShared(typename P::Integer::Integer Q, const RingGSWCryptoParams::BaseGParams& bp,
                                 const std::vector<P>& input, std::vector<P>& output,
                                 std::vector<typename P::Integer::Integer>& w0,
                                 std::vector<typename P::Integer::Integer>& w1) {
    using I = typename P::Integer::Integer;
    I QHalf{Q >> 1};
    uint32_t gBits{bp.gBits};
    I gHalf{static_cast<I>(bp.baseG >> 1)};
    I gMask{static_cast<I>(bp.baseG - 1)};
    I QmHalf{Q - gHalf};
    uint32_t digitsG{bp.digitsG};
    I H{0};
    for (uint32_t i{0}; i < digitsG; ++i)
        H += gHalf << (i * gBits);
    uint32_t digitsG2{(digitsG - 1) << 1};
    uint32_t N{input[0].GetLength()};

#pragma omp for schedule(static)
    for (uint32_t k = 0; k < N; ++k) {
        auto t0{input[0][k].template ConvertToInt<I>()};
        w0[k] = t0 + H - (t0 < QHalf ? 0 : Q);
        auto t1{input[1][k].template ConvertToInt<I>()};
        w1[k] = t1 + H - (t1 < QHalf ? 0 : Q);
    }

#pragma omp for schedule(static)
    for (uint32_t d = 0; d < digitsG2; d += 2) {
        uint32_t shift{((d >> 1) + 1) * gBits};
        auto mask{(d + 2 < digitsG2) ? gMask : static_cast<I>(-1)};
        auto& out0{output[d + 0]};
        auto& out1{output[d + 1]};
        for (uint32_t k{0}; k < N; ++k) {
            auto r0{(w0[k] >> shift) & mask};
            out0[k] = (r0 < gHalf) ? r0 + QmHalf : r0 - gHalf;
            auto r1{(w1[k] >> shift) & mask};
            out1[k] = (r1 < gHalf) ? r1 + QmHalf : r1 - gHalf;
        }
    }
}

// The LMKCDEY automorphism: permute both components by X -> X^a, then switch key of
// a-component back with automorphism key ak. Uses default gadget base and digitsG - 1 digits.
template <typename P, typename PP>
void AutomorphismKeySwitch(uint32_t a, const std::vector<uint32_t>& autoMap, const PP& polyParams,
                           typename P::Integer::Integer Q, const RingGSWCryptoParams::BaseGParams& bp,
                           const std::vector<std::vector<P>>& ev, std::vector<P>& acc) {
    acc[1] = acc[1].AutomorphismTransform(a, autoMap);

    P cta(acc[0].AutomorphismTransform(a, autoMap));
    acc[0].SetValuesToZero();
    cta.SetFormat(Format::COEFFICIENT);

    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG{bp.digitsG - 1};
    thread_local std::vector<P> dctaScratch;
    auto& dcta = dctaScratch;
    if (dcta.size() != digitsG || dcta[0].GetParams() != polyParams) {
        dcta.assign(digitsG, P(polyParams, Format::COEFFICIENT, true));
    }
    else {
        for (auto& d : dcta)
            d.OverrideFormat(Format::COEFFICIENT);
    }

    ExcessHDigitDecompose(Q, bp, cta, dcta);

    int nthreads = OpenFHEParallelControls.GetThreadLimit(digitsG > 4 ? digitsG : 4);
    if (nthreads < 2) {
        for (uint32_t d = 0; d < digitsG; ++d)
            dcta[d].SetFormat(Format::EVALUATION);
        for (uint32_t d = 0; d < digitsG; ++d)
            acc[0].MultAccEqNoCheck(dcta[d], ev[d][0]);
        for (uint32_t d = 0; d < digitsG; ++d)
            acc[1].MultAccEqNoCheck(dcta[d], ev[d][1]);
        return;
    }

#pragma omp parallel num_threads(nthreads)
    {
#pragma omp for schedule(static)
        for (uint32_t d = 0; d < digitsG; ++d)
            dcta[d].SetFormat(Format::EVALUATION);

#pragma omp for schedule(static) nowait
        for (uint32_t j = 0; j < 2; ++j)
            for (uint32_t d = 0; d < digitsG; ++d)
                acc[j].MultAccEqNoCheck(dcta[d], ev[d][j]);
    }
}

#if NATIVEINT != 32
// a *= b (mod q) using b's Shoup constants: one high-word estimate per lane, vectorizable at
// every ISA where the Barrett form is not
inline void ShoupMulEq32(NativePoly32& a, const NativePoly32& b, const NativeVector32& bPrecon, uint32_t q) {
    uint32_t N{static_cast<uint32_t>(a.GetLength())};
    for (size_t k = 0; k < N; ++k) {
        uint32_t x{static_cast<uint32_t>(a[k].ConvertToInt())};
        uint32_t hi{static_cast<uint32_t>((static_cast<uint64_t>(x) * bPrecon[k].ConvertToInt()) >> 32)};
        uint32_t r{x * static_cast<uint32_t>(b[k].ConvertToInt()) - hi * q};
        a[k] = NativeInteger32(r - (q & (uint32_t(0) - static_cast<uint32_t>(r >= q))));
    }
}

// Inner product over the gadget digits with ONE modular reduction instead of one per digit.
inline void LazyInnerProduct32(NativePoly32& out, const std::vector<NativePoly32>& dct,
                               const std::vector<std::vector<NativePoly32>>& ev, uint32_t col, uint32_t rows,
                               uint32_t kBegin, uint32_t kEnd, uint32_t N, uint32_t q, uint64_t mu) {
    thread_local std::vector<uint64_t> acc;
    if (acc.size() < N)
        acc.resize(N);
    {
        const auto& d0{dct[0].GetValues()};
        const auto& e0{ev[0][col].GetValues()};
        for (uint32_t k = kBegin; k < kEnd; ++k)
            acc[k] = static_cast<uint64_t>(d0[k].ConvertToInt()) * e0[k].ConvertToInt();
    }
    for (uint32_t i = 1; i < rows; ++i) {
        const auto& di{dct[i].GetValues()};
        const auto& ei{ev[i][col].GetValues()};
        for (uint32_t k = kBegin; k < kEnd; ++k)
            acc[k] += static_cast<uint64_t>(di[k].ConvertToInt()) * ei[k].ConvertToInt();
    }
    for (uint32_t k = kBegin; k < kEnd; ++k) {
    #if defined(HAVE_INT128)
        uint64_t x{acc[k]};
        uint64_t hi{static_cast<uint64_t>((static_cast<uint128_t>(x) * mu) >> 64)};
        uint64_t r{x - hi * q};
        // mu = floor(2^64/q) underestimates the quotient by up to 2, so r is in [0, 3q):
        // the correction is repeated on purpose
        if (r >= q)
            r -= q;
        if (r >= q)
            r -= q;
    #else
        // no double-width type: the lazy accumulation still stands, only the single reduction
        // falls back to a hardware divide -- still far better than reducing once per digit.
        uint64_t r{acc[k] % q};
    #endif
        out[k] = NativeInteger32(static_cast<uint32_t>(r));
    }
}

// 32-bit overload of the accumulation body above: identical shape, with the lazy inner product
// replacing the per-digit reduction. Exact-match overload resolution routes the NativePoly32
// instantiations here; results are bit-identical to the generic body. The automorphism key
// switch stays on the generic poly-op body: its row count (digitsG - 1) is too small for the
// lazy kernel to pay.
inline void AddToAccNoMonomial(const std::shared_ptr<ILNativeParams32>& polyParams, uint32_t Q,
                               const RingGSWCryptoParams::BaseGParams& bp,
                               const std::vector<std::vector<NativePoly32>>& ev, std::vector<NativePoly32>& acc) {
    thread_local std::vector<NativePoly32> ctScratch, dctScratch;
    thread_local std::vector<uint32_t> w0Scratch, w1Scratch;
    auto& ct  = ctScratch;
    auto& dct = dctScratch;
    ct        = acc;

    uint32_t digitsG2{(bp.digitsG - 1) << 1};
    if (dct.size() != digitsG2 || dct[0].GetParams() != polyParams) {
        dct.assign(digitsG2, NativePoly32(polyParams, Format::COEFFICIENT, true));
    }
    else {
        for (auto& d : dct)
            d.OverrideFormat(Format::COEFFICIENT);
    }

    uint32_t N{static_cast<uint32_t>(polyParams->GetRingDimension())};
    auto& w0 = w0Scratch;
    auto& w1 = w1Scratch;
    if (w0.size() != N) {
        w0.resize(N);
        w1.resize(N);
    }
    uint64_t mu{static_cast<uint64_t>(-1) / Q};

    int nthreads = OpenFHEParallelControls.GetThreadLimit(digitsG2 > 8 ? (digitsG2 >> 1) : 4);
    if (nthreads < 2) {
        ct[0].SetFormat(Format::COEFFICIENT);
        ct[1].SetFormat(Format::COEFFICIENT);
        ExcessHDigitDecompose(Q, bp, ct, dct);
        for (uint32_t d = 0; d < digitsG2; ++d)
            dct[d].SetFormat(Format::EVALUATION);
        LazyInnerProduct32(acc[0], dct, ev, 0, digitsG2, 0, N, N, Q, mu);
        LazyInnerProduct32(acc[1], dct, ev, 1, digitsG2, 0, N, N, Q, mu);
        return;
    }

    #pragma omp parallel num_threads(nthreads)
    {
    #pragma omp for schedule(static) nowait
        for (uint32_t i = 0; i < 2; ++i)
            ct[i].SetFormat(Format::COEFFICIENT);

    #pragma omp barrier
        if (digitsG2 >= 8 && nthreads >= 4) {
            ExcessHDigitDecomposeShared(Q, bp, ct, dct, w0, w1);
        }
        else {
    #pragma omp single
            ExcessHDigitDecompose(Q, bp, ct, dct);
        }

    #pragma omp for schedule(static)
        for (uint32_t d = 0; d < digitsG2; ++d)
            dct[d].SetFormat(Format::EVALUATION);

    #pragma omp for schedule(static) nowait
        for (uint32_t blk = 0; blk < static_cast<uint32_t>(nthreads); ++blk) {
            uint32_t kb{(N * blk) / static_cast<uint32_t>(nthreads)};
            uint32_t ke{(N * (blk + 1)) / static_cast<uint32_t>(nthreads)};
            LazyInnerProduct32(acc[0], dct, ev, 0, digitsG2, kb, ke, N, Q, mu);
            LazyInnerProduct32(acc[1], dct, ev, 1, digitsG2, kb, ke, N, Q, mu);
        }
    }
}

#endif  // NATIVEINT != 32

// The DM digit schedule: one accumulation per nonzero base-R digit of each LWE coefficient.
template <typename AddFn>
void DMAccSchedule(NativeInteger q, uint32_t baseR, size_t digitsRCount, const NativeVector& a, AddFn&& addToAcc) {
    NativeInteger baseRN{baseR};
    uint32_t n{static_cast<uint32_t>(a.GetLength())};
    for (uint32_t i = 0; i < n; ++i) {
        auto aI = NativeInteger(0).ModSubFast(a[i], q);
        for (size_t k = 0; k < digitsRCount; ++k, aI /= baseRN) {
            auto a0 = (aI.Mod(baseRN)).ConvertToInt<uint32_t>();
            if (a0)
                addToAcc(i, a0, k);
        }
    }
}

// The LMKCDEY rotation schedule over the generator's orbit, as described in
// https://eprint.iacr.org/2022/198: group the coefficients by discrete log, walk the orbit
// applying at most numAutoKeys-sized automorphism hops between accumulations. The caller applies
// the initial X -> X^{-gen} transform of the accumulator body before invoking this.
// addToAcc(i) performs the external product for LWE coefficient i;
// automorphism(power, k) applies X -> X^power using automorphism key k.
template <typename AddFn, typename AutoFn>
void LMKCDEYAccSchedule(uint32_t N, uint32_t numAutoKeys, const std::vector<int32_t>& logGen, const NativeVector& a,
                        AddFn&& addToAcc, AutoFn&& automorphism) {
    // assume a is all-odd ciphertext (using round-to-odd technique)
    size_t n{a.GetLength()};
    uint32_t Nh{N / 2};
    uint32_t M{2 * N};
    NativeInteger MNative{M};

    std::unordered_map<int32_t, std::vector<int32_t>> permuteMap;
    for (size_t i = 0; i < n; i++) {  // put all a_i in the permuteMap
        // make it odd; round-to-odd(https://eprint.iacr.org/2022/198) will improve error.
        int32_t aIOdd = NativeInteger(0).ModSubFast(a[i], MNative).ConvertToInt<uint32_t>() | 0x1;
        permuteMap[logGen[aIOdd]].push_back(i);
    }

    NativeInteger gen(5);
    uint32_t genInt{5};
    uint32_t nSkips{0};

    // for a_j = -5^i
    for (uint32_t i = Nh - 1; i > 0; i--) {
        auto it = permuteMap.find(-static_cast<int32_t>(i));
        if (it != permuteMap.end()) {
            if (nSkips != 0) {  // Rotation by 5^nSkips
                automorphism(gen.ModExp(nSkips, M), nSkips);
                nSkips = 0;
            }
            for (auto idx : it->second)
                addToAcc(idx);
        }
        nSkips++;

        if (nSkips == numAutoKeys || i == 1) {
            automorphism(gen.ModExp(nSkips, M), nSkips);
            nSkips = 0;
        }
    }

    // for -1
    auto itM = permuteMap.find(M);
    if (itM != permuteMap.end()) {
        for (auto idx : itM->second)
            addToAcc(idx);
    }

    automorphism(NativeInteger(M - genInt), 0);

    // for a_j = 5^i
    for (size_t i = Nh - 1; i > 0; i--) {
        auto it = permuteMap.find(i);
        if (it != permuteMap.end()) {
            if (nSkips != 0) {  // Rotation by 5^nSkips
                automorphism(gen.ModExp(nSkips, M), nSkips);
                nSkips = 0;
            }
            for (auto idx : it->second)
                addToAcc(idx);
        }
        nSkips++;

        if (nSkips == numAutoKeys || i == 1) {
            automorphism(gen.ModExp(nSkips, M), nSkips);
            nSkips = 0;
        }
    }

    // for 0
    auto it0 = permuteMap.find(0);
    if (it0 != permuteMap.end()) {
        for (auto idx : it0->second)
            addToAcc(idx);
    }
}

}  // namespace lbcrypto

#endif  // _RGSW_ACC_COMMON_H_
