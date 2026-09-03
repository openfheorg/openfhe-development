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
    std::vector<P> ct(acc);
    ct[0].SetFormat(Format::COEFFICIENT);
    ct[1].SetFormat(Format::COEFFICIENT);

    uint32_t digitsG2{(bp.digitsG - 1) << 1};
    std::vector<P> dct(digitsG2, P(polyParams, Format::COEFFICIENT, true));

    ExcessHDigitDecompose(Q, bp, ct, dct);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(digitsG2))
    for (uint32_t d = 0; d < digitsG2; ++d)
        dct[d].SetFormat(Format::EVALUATION);

    GadgetMatrixProduct(acc, dct, ev, digitsG2);
}

// The LMKCDEY automorphism: permute both components by X -> X^a, then switch key of
// a-component back with automorphism key ak. Uses default gadget base and digitsG - 1 digits.
template <typename P, typename PP>
void AutomorphismKeySwitch(uint32_t a, const std::vector<uint32_t>& autoMap, const PP& polyParams,
                           typename P::Integer::Integer Q, const RingGSWCryptoParams::BaseGParams& bp,
                           const std::vector<std::vector<P>>& ev, std::vector<P>& acc) {
    acc[1] = acc[1].AutomorphismTransform(a, autoMap);

    P cta(acc[0]);
    acc[0].SetValuesToZero();
    cta = cta.AutomorphismTransform(a, autoMap);
    cta.SetFormat(Format::COEFFICIENT);

    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG{bp.digitsG - 1};
    std::vector<P> dcta(digitsG, P(polyParams, Format::COEFFICIENT, true));

    ExcessHDigitDecompose(Q, bp, cta, dcta);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(digitsG))
    for (uint32_t d = 0; d < digitsG; ++d)
        dcta[d].SetFormat(Format::EVALUATION);

    // acc = dct * input (matrix product);
    for (uint32_t d = 0; d < digitsG; ++d)
        acc[0].MultAccEqNoCheck(dcta[d], ev[d][0]);
    for (uint32_t d = 0; d < digitsG; ++d)
        acc[1].MultAccEqNoCheck(dcta[d], ev[d][1]);
}

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
