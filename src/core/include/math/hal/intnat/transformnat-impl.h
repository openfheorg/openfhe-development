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

#ifndef __TRANSFORMNAT_IMPL_H__
#define __TRANSFORMNAT_IMPL_H__

// ATTENTION: this file contains implementations of the functions
//            declared in math/intnat/transformnat.h and
//            MUST be included in the end of math/intnat/transformnat.h ONLY
//            and nowhere else
#include "math/hal/basicint.h"
#include "math/hal/intnat/ubintnat.h"
#include "math/hal/intnat/mubintvecnat.h"
#include "math/hal/intnat/transformnat.h"
#include "math/nbtheory.h"

#include "utils/debug.h"
#include "utils/exception.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

#include <map>
#include <memory>
#include <utility>
#include <vector>

namespace intnat {

using namespace lbcrypto;

template <typename NInt>
static inline NInt condSubNoCmp(NInt v, NInt q) {
#if defined(__clang__) && defined(__x86_64__) && !defined(__AVX2__)
    const NInt t{static_cast<NInt>(v - q)};
    return static_cast<NInt>(t + (q & (NInt(0) - static_cast<NInt>(t >> (8 * sizeof(NInt) - 1)))));
#else
    return static_cast<NInt>(v - (q & (NInt(0) - static_cast<NInt>(v >= q))));
#endif
}

// Shoup high-word multiply for the raw-lane butterflies. gcc's vectorizer takes the
// 32-bit-halves form with AVX2+ lanes and never takes the double-width form; clang vectorizes
// the double-width form on its own and is slower with the halves form, so the halves
// form is gcc-only. Scalar, the double-width form always wins, hence the fallbacks.
static inline uint32_t shoupMulHi(uint32_t a, uint32_t b) {
    return static_cast<uint32_t>((static_cast<uint64_t>(a) * b) >> 32);
}
static inline uint64_t shoupMulHi(uint64_t a, uint64_t b) {
#if defined(__AVX2__) && defined(__GNUC__) && !defined(__clang__)
    uint64_t al{a & 0xffffffffu}, ah{a >> 32}, bl{b & 0xffffffffu}, bh{b >> 32};
    uint64_t t0{al * bl};
    uint64_t t1{al * bh + (t0 >> 32)};
    uint64_t t2{ah * bl + (t1 & 0xffffffffu)};
    return ah * bh + (t1 >> 32) + (t2 >> 32);
#elif defined(HAVE_INT128)
    return static_cast<uint64_t>((static_cast<uint128_t>(a) * b) >> 64);
#elif defined(__x86_64__)
    uint64_t lo, hi;
    __asm__("mulq %[b]" : "=a"(lo), "=d"(hi) : "a"(a), [b] "rm"(b) : "cc");
    return hi;
#else
    uint64_t al{a & 0xffffffffu}, ah{a >> 32}, bl{b & 0xffffffffu}, bh{b >> 32};
    uint64_t t0{al * bl};
    uint64_t t1{al * bh + (t0 >> 32)};
    uint64_t t2{ah * bl + (t1 & 0xffffffffu)};
    return ah * bh + (t1 >> 32) + (t2 >> 32);
#endif
}
#if defined(HAVE_INT128)
static inline uint128_t shoupMulHi(uint128_t a, uint128_t b) {
    constexpr uint128_t mask{(static_cast<uint128_t>(1) << 64) - 1};
    uint128_t al{a & mask}, ah{a >> 64}, bl{b & mask}, bh{b >> 64};
    uint128_t t0{al * bl};
    uint128_t t1{al * bh + (t0 >> 64)};
    uint128_t t2{ah * bl + (t1 & mask)};
    return ah * bh + (t1 >> 64) + (t2 >> 64);
}
#endif

// pair loops (2i, 2i + 1) over words wider than 32 bits only vectorize with AVX2+ lanes; the
// peeled butterfly stages fall back to the classic i += 2 scalar form without them
#if defined(__AVX2__)
inline constexpr bool kPairLoop64 = true;
#else
inline constexpr bool kPairLoop64 = false;
#endif

// builds the Shoup constants for a root table, so the table-less transform overloads can
// delegate to the vectorized precon kernels
template <typename VecType, typename IntType>
static VecType prepShoupConsts(const VecType& table, const IntType& modulus) {
    const uint32_t n(table.GetLength());
    VecType precon(n, modulus);
    for (size_t i = 0; i < n; ++i)
        precon[i] = table[i].PrepModMulConst(modulus);
    return precon;
}

template <typename VecType>
std::map<typename VecType::Integer, std::shared_ptr<const typename ChineseRemainderTransformFTTNat<VecType>::Tables>>
    ChineseRemainderTransformFTTNat<VecType>::m_tablesByModulus;

template <typename VecType>
std::map<typename VecType::Integer, VecType> ChineseRemainderTransformArbNat<VecType>::m_cyclotomicPolyMap;

template <typename VecType>
std::map<typename VecType::Integer, VecType> ChineseRemainderTransformArbNat<VecType>::m_cyclotomicPolyReverseNTTMap;

template <typename VecType>
std::map<typename VecType::Integer, VecType> ChineseRemainderTransformArbNat<VecType>::m_cyclotomicPolyNTTMap;

template <typename VecType>
std::map<ModulusRoot<typename VecType::Integer>, VecType> BluesteinFFTNat<VecType>::m_rootOfUnityTableByModulusRoot;

template <typename VecType>
std::map<ModulusRoot<typename VecType::Integer>, VecType>
    BluesteinFFTNat<VecType>::m_rootOfUnityInverseTableByModulusRoot;

template <typename VecType>
std::map<ModulusRoot<typename VecType::Integer>, VecType> BluesteinFFTNat<VecType>::m_powersTableByModulusRoot;

template <typename VecType>
std::map<ModulusRootPair<typename VecType::Integer>, VecType> BluesteinFFTNat<VecType>::m_RBTableByModulusRootPair;

template <typename VecType>
std::map<ModulusRoot<typename VecType::Integer>, VecType>
    BluesteinFFTNat<VecType>::m_preconRootOfUnityTableByModulusRoot;

template <typename VecType>
std::map<ModulusRoot<typename VecType::Integer>, VecType>
    BluesteinFFTNat<VecType>::m_preconRootOfUnityInverseTableByModulusRoot;

template <typename VecType>
std::map<typename VecType::Integer, ModulusRoot<typename VecType::Integer>>
    BluesteinFFTNat<VecType>::m_defaultNTTModulusRoot;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
    ChineseRemainderTransformArbNat<VecType>::m_rootOfUnityDivisionTableByModulus;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
    ChineseRemainderTransformArbNat<VecType>::m_rootOfUnityDivisionInverseTableByModulus;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
    ChineseRemainderTransformArbNat<VecType>::m_rootOfUnityDivisionPreconTableByModulus;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
    ChineseRemainderTransformArbNat<VecType>::m_rootOfUnityDivisionInversePreconTableByModulus;

template <typename VecType>
std::map<typename VecType::Integer, typename VecType::Integer>
    ChineseRemainderTransformArbNat<VecType>::m_DivisionNTTModulus;

template <typename VecType>
std::map<typename VecType::Integer, typename VecType::Integer>
    ChineseRemainderTransformArbNat<VecType>::m_DivisionNTTRootOfUnity;

template <typename VecType>
std::map<uint32_t, uint32_t> ChineseRemainderTransformArbNat<VecType>::m_nttDivisionDim;

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::ForwardTransformIterative(const VecType& element,
                                                                     const VecType& rootOfUnityTable, VecType* r) {
    uint32_t n = element.GetLength();
    if (r->GetLength() != n)
        OPENFHE_THROW("size of input element and size of output element not of same size");
    ForwardTransformIterative(element, rootOfUnityTable, prepShoupConsts(rootOfUnityTable, element.GetModulus()), r);
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::InverseTransformIterative(const VecType& element,
                                                                     const VecType& rootInvTable, VecType* r) {
    InverseTransformIterative(element, rootInvTable, prepShoupConsts(rootInvTable, element.GetModulus()), r);
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::ForwardTransformIterative(const VecType& element,
                                                                     const VecType& rootOfUnityTable,
                                                                     const VecType& preconRootOfUnityTable,
                                                                     VecType* result) {
    uint32_t n = element.GetLength();
    if (result->GetLength() != n)
        OPENFHE_THROW("size of input element and size of output element not of same size");
    const auto modulus = element.GetModulus();
    result->SetModulus(modulus);

    uint32_t logn = GetMSB(n - 1);
    for (size_t i = 0; i < n; ++i) {
        (*result)[i] = element[ReverseBits(i, logn)];
    }

    // raw-lane Shoup butterflies in the same branchless shape as the power-of-two
    // butterfly, so the loop stays auto-vectorizable (clang lowers the element-level
    // ModMulFastConst select to a branch/scalar chain at this ISA)
    using NInt = decltype(modulus.m_value);
    const NInt mv{modulus.m_value};
    // the standard-order table is read at stride 2^shift, which no compiler vectorizes;
    // compacting each stage's twiddles into unit-stride scratch lets the butterfly loop vectorize
    std::vector<NInt> omega(n >> 1);
    std::vector<NInt> preconOmega(n >> 1);
    for (size_t logm = 1; logm <= logn; ++logm) {
        uint32_t m     = 1u << (logm - 1);
        uint32_t shift = logn - logm;
        for (size_t i = 0; i < m; ++i) {
            omega[i]       = rootOfUnityTable[i << shift].m_value;
            preconOmega[i] = preconRootOfUnityTable[i << shift].m_value;
        }
        for (size_t j = 0; j < n; j += (m << 1)) {
            for (size_t i = 0; i < m; ++i) {
                size_t indexEven = j + i;
                size_t indexOdd  = indexEven + m;
                NInt odd{(*result)[indexOdd].m_value};
                NInt even{(*result)[indexEven].m_value};
                NInt of{static_cast<NInt>(odd * omega[i] - shoupMulHi(odd, preconOmega[i]) * mv)};
                of = condSubNoCmp(of, mv);
                NInt sum{static_cast<NInt>(even + of)};
                (*result)[indexEven].m_value = condSubNoCmp(sum, mv);
                NInt dif{static_cast<NInt>(even - of + mv)};
                (*result)[indexOdd].m_value = condSubNoCmp(dif, mv);
            }
        }
    }
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::InverseTransformIterative(const VecType& element,
                                                                     const VecType& rootOfUnityInverseTable,
                                                                     const VecType& preconRootOfUnityInverseTable,
                                                                     VecType* result) {
    uint32_t n         = element.GetLength();
    const auto modulus = element.GetModulus();
    NumberTheoreticTransformNat<VecType>().ForwardTransformIterative(element, rootOfUnityInverseTable,
                                                                     preconRootOfUnityInverseTable, result);
    using NInt = decltype(modulus.m_value);
    const NInt mv{modulus.m_value};
    IntType cycloOrderInv(IntType(n).ModInverse(modulus));
    const NInt nInv{cycloOrderInv.m_value};
    const NInt preconNInv{cycloOrderInv.PrepModMulConst(modulus).m_value};
    for (size_t i = 0; i < n; ++i) {
        NInt v{(*result)[i].m_value};
        NInt r{static_cast<NInt>(v * nInv - shoupMulHi(v, preconNInv) * mv)};
        (*result)[i].m_value = condSubNoCmp(r, mv);
    }
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::ForwardTransformToBitReverseInPlace(const VecType& rootTable,
                                                                               VecType* element) {
    // compute the Shoup constants once and share the vectorized precon kernel
    ForwardTransformToBitReverseInPlace(rootTable, prepShoupConsts(rootTable, element->GetModulus()), element);
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::ForwardTransformToBitReverse(const VecType& element,
                                                                        const VecType& rootOfUnityTable,
                                                                        VecType* result) {
    uint32_t n = element.GetLength();
    if (result->GetLength() != n)
        OPENFHE_THROW("size of input element and size of output element not of same size");

    *result = element;
    ForwardTransformToBitReverseInPlace(rootOfUnityTable, result);
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::ForwardTransformToBitReverseInPlace(const VecType& rootOfUnityTable,
                                                                               const VecType& preconRootOfUnityTable,
                                                                               VecType* element) {
    // NTT based on the Cooley-Tukey (CT) butterfly
    // Inputs: element (vector of size n in standard ordering)
    //         rootOfUnityTable (precomputed roots of unity in bit-reversed ordering)
    // Output: NTT(element) in bit-reversed ordering
    //
    // for (m = 1, t = n, logt = log(t); m < n; m=2*m, t=t/2, --logt) do
    //     for (i = 0; i < m; ++i) do
    //         omega = rootOfUnityInverseTable[i + m]
    //         for (j1 = (i << logt), j2 = (j1 + t); j1 < j2; ++j1) do
    //             loVal = element[j1 + 0]
    //             hiVal = element[j1 + t]*omega
    //             element[j1 + 0] = (loVal + hiVal) mod modulus
    //             element[j1 + t] = (loVal - hiVal) mod modulus
    //

    // Harvey lazy-reduction butterflies (https://arxiv.org/abs/1205.2926): values stay in
    // [0, 4*modulus) between stages (requires modulus < 2^(MaxBits-2), which
    // MAX_MODULUS_SIZE guarantees); the full reduction to [0, modulus) is folded into the
    // peeled final stage. Loops work on the raw word values so they stay vectorizable.
    using NInt = typename IntType::Integer;
    const NInt mv{element->GetModulus().m_value};
    const NInt mv2{static_cast<NInt>(mv + mv)};
    const uint32_t n(element->GetLength() >> 1);
    // Deferred reduction: from [0, modulus) inputs the values grow by 2*modulus per stage, so
    // when (2*stages + 3)*modulus fits the word the per-butterfly conditional subtract can be
    // dropped from every stage and the peeled final stage folds the values back down with a
    // fixed chain.
    const uint32_t stages{GetMSB(n)};
#if defined(__clang__) && !defined(__AVX2__)
    constexpr bool kLazyWide{sizeof(NInt) == 4};
#else
    constexpr bool kLazyWide{true};
#endif
    const bool lazy{kLazyWide && mv <= static_cast<NInt>(-1) / static_cast<NInt>(2 * stages + 3)};
    if (lazy) {
        for (size_t m{1}, t{n}, logt{GetMSB(t)}; m < n; m <<= 1, t >>= 1, --logt) {
            for (size_t i{0}; i < m; ++i) {
                const NInt omega{rootOfUnityTable[i + m].m_value};
                const NInt preconOmega{preconRootOfUnityTable[i + m].m_value};
                // size_t induction keeps [j1] and [j1 + t] affine for the vectorizer
                for (size_t j1{i << logt}, j2{j1 + t}; j1 < j2; ++j1) {
                    NInt hi{(*element)[j1 + t].m_value};
                    NInt of{static_cast<NInt>(hi * omega - shoupMulHi(hi, preconOmega) * mv)};
                    NInt lo{(*element)[j1 + 0].m_value};
                    (*element)[j1 + 0].m_value = lo + of;
                    (*element)[j1 + t].m_value = lo - of + mv2;  // of < 2*modulus, so the offset holds
                }
            }
        }
    }
    else {
        for (size_t m{1}, t{n}, logt{GetMSB(t)}; m < n; m <<= 1, t >>= 1, --logt) {
            for (size_t i{0}; i < m; ++i) {
                const NInt omega{rootOfUnityTable[i + m].m_value};
                const NInt preconOmega{preconRootOfUnityTable[i + m].m_value};
                // size_t induction keeps [j1] and [j1 + t] affine for the vectorizer (u32 indexing could wrap)
                for (size_t j1{i << logt}, j2{j1 + t}; j1 < j2; ++j1) {
                    NInt hi{(*element)[j1 + t].m_value};
                    NInt of{static_cast<NInt>(hi * omega - shoupMulHi(hi, preconOmega) * mv)};
                    NInt lo{(*element)[j1 + 0].m_value};
                    lo                         = condSubNoCmp(lo, mv2);
                    (*element)[j1 + 0].m_value = lo + of;
                    (*element)[j1 + t].m_value = lo - of + mv2;
                }
            }
        }
    }
    // peeled final stage, reducing the outputs to [0, modulus). When the stages ran lazily the
    // values sit in [0, (2*stages + 1)*modulus) and fold down through a fixed four-step chain
    // of halving multiples of the modulus (steps at or below the value are no-ops, and every
    // step is a multiple of the modulus, so residues are untouched).
    NInt c0{mv2}, c1{mv2}, c2{mv2}, c3{mv2};
    if (lazy) {
        // largest halving chain start below the value bound; comparing against bound/2 keeps
        // the doubling itself from overflowing (the bound fits the word by the lazy test)
        const NInt bound{static_cast<NInt>(mv * (2 * stages + 1))};
        while (c0 < static_cast<NInt>(bound >> 1))
            c0 <<= 1;
        c1 = (c0 >> 1 > mv2) ? c0 >> 1 : mv2;
        c2 = (c1 >> 1 > mv2) ? c1 >> 1 : mv2;
        c3 = (c2 >> 1 > mv2) ? c2 >> 1 : mv2;
    }
    if constexpr (sizeof(NInt) == 4 || kPairLoop64) {
        // the index-doubled pair form (2i, 2i + 1) is the stride-2 shape gcc's vectorizer
        // accepts, i += 2 is not
        if (lazy) {
            for (size_t i{0}; i < n; ++i) {
                const NInt omega{rootOfUnityTable[i + n].m_value};
                const NInt preconOmega{preconRootOfUnityTable[i + n].m_value};
                NInt hi{(*element)[2 * i + 1].m_value};
                NInt of{static_cast<NInt>(hi * omega - shoupMulHi(hi, preconOmega) * mv)};
                NInt lo{(*element)[2 * i + 0].m_value};
                lo = condSubNoCmp(lo, c0);
                lo = condSubNoCmp(lo, c1);
                lo = condSubNoCmp(lo, c2);
                lo = condSubNoCmp(lo, c3);
                lo = condSubNoCmp(lo, mv2);
                NInt s{static_cast<NInt>(lo + of)};
                s = condSubNoCmp(s, mv2);
                s = condSubNoCmp(s, mv);
                NInt d{static_cast<NInt>(lo - of + mv2)};
                d                             = condSubNoCmp(d, mv2);
                d                             = condSubNoCmp(d, mv);
                (*element)[2 * i + 0].m_value = s;
                (*element)[2 * i + 1].m_value = d;
            }
            return;
        }
        for (size_t i{0}; i < n; ++i) {
            const NInt omega{rootOfUnityTable[i + n].m_value};
            const NInt preconOmega{preconRootOfUnityTable[i + n].m_value};
            NInt hi{(*element)[2 * i + 1].m_value};
            NInt of{static_cast<NInt>(hi * omega - shoupMulHi(hi, preconOmega) * mv)};
            NInt lo{(*element)[2 * i + 0].m_value};
            lo = condSubNoCmp(lo, mv2);
            NInt s{static_cast<NInt>(lo + of)};
            s = condSubNoCmp(s, mv2);
            s = condSubNoCmp(s, mv);
            NInt d{static_cast<NInt>(lo - of + mv2)};
            d                             = condSubNoCmp(d, mv2);
            d                             = condSubNoCmp(d, mv);
            (*element)[2 * i + 0].m_value = s;
            (*element)[2 * i + 1].m_value = d;
        }
    }
    else {
        // wide words without wide lanes: nothing vectorizes here and the classic i += 2 form
        // is the faster scalar
        if (lazy) {
            for (size_t i{0}; i < (static_cast<size_t>(n) << 1); i += 2) {
                const NInt omega{rootOfUnityTable[(i >> 1) + n].m_value};
                const NInt preconOmega{preconRootOfUnityTable[(i >> 1) + n].m_value};
                NInt hi{(*element)[i + 1].m_value};
                NInt of{static_cast<NInt>(hi * omega - shoupMulHi(hi, preconOmega) * mv)};
                NInt lo{(*element)[i + 0].m_value};
                lo = condSubNoCmp(lo, c0);
                lo = condSubNoCmp(lo, c1);
                lo = condSubNoCmp(lo, c2);
                lo = condSubNoCmp(lo, c3);
                lo = condSubNoCmp(lo, mv2);
                NInt s{static_cast<NInt>(lo + of)};
                s = condSubNoCmp(s, mv2);
                s = condSubNoCmp(s, mv);
                NInt d{static_cast<NInt>(lo - of + mv2)};
                d                         = condSubNoCmp(d, mv2);
                d                         = condSubNoCmp(d, mv);
                (*element)[i + 0].m_value = s;
                (*element)[i + 1].m_value = d;
            }
            return;
        }
        for (size_t i{0}; i < (static_cast<size_t>(n) << 1); i += 2) {
            const NInt omega{rootOfUnityTable[(i >> 1) + n].m_value};
            const NInt preconOmega{preconRootOfUnityTable[(i >> 1) + n].m_value};
            NInt hi{(*element)[i + 1].m_value};
            NInt of{static_cast<NInt>(hi * omega - shoupMulHi(hi, preconOmega) * mv)};
            NInt lo{(*element)[i + 0].m_value};
            lo = condSubNoCmp(lo, mv2);
            NInt s{static_cast<NInt>(lo + of)};
            s = condSubNoCmp(s, mv2);
            s = condSubNoCmp(s, mv);
            NInt d{static_cast<NInt>(lo - of + mv2)};
            d                         = condSubNoCmp(d, mv2);
            d                         = condSubNoCmp(d, mv);
            (*element)[i + 0].m_value = s;
            (*element)[i + 1].m_value = d;
        }
    }
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::ForwardTransformToBitReverse(const VecType& element,
                                                                        const VecType& rootOfUnityTable,
                                                                        const VecType& preconRootOfUnityTable,
                                                                        VecType* result) {
    if (result->GetLength() != element.GetLength())
        OPENFHE_THROW("size of input element and size of output element not of same size");
    *result = element;
    ForwardTransformToBitReverseInPlace(rootOfUnityTable, preconRootOfUnityTable, result);
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::InverseTransformFromBitReverseInPlace(const VecType& rootInvTable,
                                                                                 const IntType& coInv,
                                                                                 VecType* element) {
    // compute the Shoup constants once and share the vectorized precon kernel
    const auto modulus = element->GetModulus();
    const auto precon  = prepShoupConsts(rootInvTable, modulus);
    InverseTransformFromBitReverseInPlace(rootInvTable, precon, coInv, coInv.PrepModMulConst(modulus), element);
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::InverseTransformFromBitReverse(const VecType& element,
                                                                          const VecType& rootOfUnityInverseTable,
                                                                          const IntType& cycloOrderInv,
                                                                          VecType* result) {
    uint32_t n = element.GetLength();
    if (result->GetLength() != n)
        OPENFHE_THROW("size of input element and size of output element not of same size");
    *result = element;
    InverseTransformFromBitReverseInPlace(rootOfUnityInverseTable, cycloOrderInv, result);
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::InverseTransformFromBitReverseInPlace(
    const VecType& rootOfUnityInverseTable, const VecType& preconRootOfUnityInverseTable, const IntType& cycloOrderInv,
    const IntType& preconCycloOrderInv, VecType* element) {
    //
    // INTT based on the Gentleman-Sande (GS) butterfly
    // Inputs: element (vector of size n in bit-reversed ordering)
    //         rootOfUnityInverseTable (precomputed roots of unity in bit-reversed ordering)
    //         cycloOrderInv (n inverse)
    // Output: INTT(element) in standard ordering
    //
    // for (m = n/2, t = 1, logt = 1; m >= 1; m=m/2, t=2*t, ++logt) do
    //     for (i = 0; i < m; ++i) do
    //         omega = rootOfUnityInverseTable[i + m]
    //         for (j1 = (i << logt), j2 = (j1 + t); j1 < j2; ++j1) do
    //             loVal = element[j1 + 0]
    //             hiVal = element[j1 + t]
    //             element[j1 + 0] = (loVal + hiVal) mod modulus
    //             element[j1 + t] = (loVal - hiVal)*omega mod modulus
    // for (i = 0; i < n; ++i) do
    //     element[i] = element[i]*cycloOrderInv mod modulus
    //

    // Harvey lazy-reduction GS butterflies: values stay in [0, 2*modulus) between stages;
    // the full reduction to [0, modulus) is folded into the peeled final stage and the
    // trailing n/2 scalar multiplies by (n inverse). Loops work on the raw word values so
    // they stay vectorizable.
    using NInt = typename IntType::Integer;
    const auto modulus{element->GetModulus()};
    const NInt mv{modulus.m_value};
    const NInt mv2{static_cast<NInt>(mv + mv)};
    const uint32_t n(element->GetLength());

    // precomputed omega[bitreversed(1)] * (n inverse). used in final stage of intt.
    // Please see https://github.com/openfheorg/openfhe-development/issues/872 for details.
    const auto omega1Inv{rootOfUnityInverseTable[1].ModMulFastConst(cycloOrderInv, modulus, preconCycloOrderInv)};
    const NInt o1{omega1Inv.m_value};
    const NInt preconO1{omega1Inv.PrepModMulConst(modulus).m_value};

    if (n > 2) {
        // peeled off first stage for performance; the index-doubled pair form (2i, 2i + 1)
        // is the stride-2 shape gcc's vectorizer accepts, i += 2 is not
        const uint32_t nh{n >> 1};
        for (size_t i{0}; i < nh; ++i) {
            const NInt omega{rootOfUnityInverseTable[i + nh].m_value};
            const NInt preconOmega{preconRootOfUnityInverseTable[i + nh].m_value};
            NInt lo{(*element)[2 * i + 0].m_value};
            NInt hi{(*element)[2 * i + 1].m_value};
            NInt s{static_cast<NInt>(lo + hi)};
            s = condSubNoCmp(s, mv2);
            NInt d{static_cast<NInt>(lo - hi + mv2)};
            (*element)[2 * i + 0].m_value = s;
            (*element)[2 * i + 1].m_value = d * omega - shoupMulHi(d, preconOmega) * mv;
        }
    }
    // inner stages
    for (size_t m{n >> 2}, t{2}, logt{2}; m > 1; m >>= 1, t <<= 1, ++logt) {
        for (size_t i{0}; i < m; ++i) {
            const NInt omega{rootOfUnityInverseTable[i + m].m_value};
            const NInt preconOmega{preconRootOfUnityInverseTable[i + m].m_value};
            // size_t induction keeps [j1] and [j1 + t] affine for the vectorizer (u32 indexing could wrap)
            for (size_t j1{i << logt}, j2{j1 + t}; j1 < j2; ++j1) {
                NInt lo{(*element)[j1 + 0].m_value};
                NInt hi{(*element)[j1 + t].m_value};
                NInt s{static_cast<NInt>(lo + hi)};
                s = condSubNoCmp(s, mv2);
                NInt d{static_cast<NInt>(lo - hi + mv2)};
                (*element)[j1 + 0].m_value = s;
                (*element)[j1 + t].m_value = d * omega - shoupMulHi(d, preconOmega) * mv;
            }
        }
    }

    // peeled off final stage where n/2 of the scalar multiplies by (n inverse) are
    // incorporated into the omegaFactor calculation; outputs reduced to [0, modulus)
    const size_t j2{n >> 1};
    for (size_t j1{0}; j1 < j2; ++j1) {
        NInt lo{(*element)[j1 + 0].m_value};
        NInt hi{(*element)[j1 + j2].m_value};
        NInt s{static_cast<NInt>(lo + hi)};
        s = condSubNoCmp(s, mv2);
        NInt d{static_cast<NInt>(lo - hi + mv2)};
        NInt y{static_cast<NInt>(d * o1 - shoupMulHi(d, preconO1) * mv)};
        y                           = condSubNoCmp(y, mv);
        (*element)[j1 + 0].m_value  = s;
        (*element)[j1 + j2].m_value = y;
    }
    // perform remaining n/2 scalar multiplies by (n inverse), reducing to [0, modulus)
    const NInt nInv{cycloOrderInv.m_value};
    const NInt preconNInv{preconCycloOrderInv.m_value};
    for (size_t i{0}; i < j2; ++i) {
        NInt v{(*element)[i].m_value};
        NInt r{static_cast<NInt>(v * nInv - shoupMulHi(v, preconNInv) * mv)};
        r                     = condSubNoCmp(r, mv);
        (*element)[i].m_value = r;
    }
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::InverseTransformFromBitReverse(
    const VecType& element, const VecType& rootOfUnityInverseTable, const VecType& preconRootOfUnityInverseTable,
    const IntType& cycloOrderInv, const IntType& preconCycloOrderInv, VecType* result) {
    uint32_t n = element.GetLength();
    if (result->GetLength() != n)
        OPENFHE_THROW("size of input element and size of output element not of same size");

    result->SetModulus(element.GetModulus());

    for (size_t i = 0; i < n; i++) {
        (*result)[i] = element[i];
    }
    InverseTransformFromBitReverseInPlace(rootOfUnityInverseTable, preconRootOfUnityInverseTable, cycloOrderInv,
                                          preconCycloOrderInv, result);

    return;
}

template <typename VecType>
void ChineseRemainderTransformFTTNat<VecType>::ForwardTransformToBitReverseInPlace(const IntType& rootOfUnity,
                                                                                   const uint32_t cycloOrder,
                                                                                   VecType* element) {
    if (rootOfUnity == IntType(1) || rootOfUnity == IntType(0))
        return;
    auto tables = GetTables(rootOfUnity, cycloOrder, element->GetModulus());
    NumberTheoreticTransformNat<VecType>().ForwardTransformToBitReverseInPlace(tables->rootReverse,
                                                                               tables->preconRootReverse, element);
}

template <typename VecType>
void ChineseRemainderTransformFTTNat<VecType>::ForwardTransformToBitReverse(const VecType& element,
                                                                            const IntType& rootOfUnity,
                                                                            const uint32_t cycloOrder,
                                                                            VecType* result) {
    if (rootOfUnity == IntType(1) || rootOfUnity == IntType(0)) {
        *result = element;
        return;
    }
    auto tables = GetTables(rootOfUnity, cycloOrder, element.GetModulus());
    NumberTheoreticTransformNat<VecType>().ForwardTransformToBitReverse(element, tables->rootReverse,
                                                                        tables->preconRootReverse, result);
}

template <typename VecType>
void ChineseRemainderTransformFTTNat<VecType>::InverseTransformFromBitReverseInPlace(const IntType& rootOfUnity,
                                                                                     const uint32_t cycloOrder,
                                                                                     VecType* element) {
    if (rootOfUnity == IntType(1) || rootOfUnity == IntType(0))
        return;
    auto tables  = GetTables(rootOfUnity, cycloOrder, element->GetModulus());
    uint32_t msb = GetMSB((cycloOrder >> 1) - 1);
    NumberTheoreticTransformNat<VecType>().InverseTransformFromBitReverseInPlace(
        tables->rootInverseReverse, tables->preconRootInverseReverse, tables->cycloOrderInverse[msb],
        tables->preconCycloOrderInverse[msb], element);
}

template <typename VecType>
void ChineseRemainderTransformFTTNat<VecType>::InverseTransformFromBitReverse(const VecType& element,
                                                                              const IntType& rootOfUnity,
                                                                              const uint32_t cycloOrder,
                                                                              VecType* result) {
    if (rootOfUnity == IntType(1) || rootOfUnity == IntType(0)) {
        *result = element;
        return;
    }
    auto tables = GetTables(rootOfUnity, cycloOrder, element.GetModulus());
    result->SetModulus(element.GetModulus());
    uint32_t n = element.GetLength();
    for (size_t i = 0; i < n; ++i)
        (*result)[i] = element[i];
    uint32_t msb = GetMSB(n - 1);
    NumberTheoreticTransformNat<VecType>().InverseTransformFromBitReverseInPlace(
        tables->rootInverseReverse, tables->preconRootInverseReverse, tables->cycloOrderInverse[msb],
        tables->preconCycloOrderInverse[msb], result);
}

template <typename VecType>
std::shared_ptr<const typename ChineseRemainderTransformFTTNat<VecType>::Tables>
ChineseRemainderTransformFTTNat<VecType>::GetTables(const IntType& rootOfUnity, const uint32_t cycloOrder,
                                                    const IntType& modulus) {
    const uint32_t ringDim = (cycloOrder >> 1);
    {
        std::shared_lock<std::shared_mutex> rlk(TablesMutex());
        auto it = m_tablesByModulus.find(modulus);
        if (it != m_tablesByModulus.end() && it->second->rootReverse.GetLength() == ringDim)
            return it->second;
    }
    std::unique_lock<std::shared_mutex> wlk(TablesMutex());
    auto it = m_tablesByModulus.find(modulus);
    if (it != m_tablesByModulus.end() && it->second->rootReverse.GetLength() == ringDim)
        return it->second;

    auto t = std::make_shared<Tables>();
    IntType x(1), xinv(1);
    uint32_t msb               = GetMSB(ringDim - 1);
    IntType mu                 = modulus.ComputeMu();
    IntType rootOfUnityInverse = rootOfUnity.ModInverse(modulus);
    const IntType& nModulus{modulus};
    VecType Table(ringDim, modulus);
    VecType TableI(ringDim, modulus);
    VecType preconTable(ringDim, nModulus);
    VecType preconTableI(ringDim, nModulus);
    for (size_t i = 0; i < ringDim; ++i) {
        auto iinv         = ReverseBits(i, msb);
        Table[iinv]       = x;
        preconTable[iinv] = x.PrepModMulConst(nModulus);
        x.ModMulEq(rootOfUnity, modulus, mu);
        TableI[iinv]       = xinv;
        preconTableI[iinv] = xinv.PrepModMulConst(nModulus);
        xinv.ModMulEq(rootOfUnityInverse, modulus, mu);
    }
    t->rootReverse              = std::move(Table);
    t->rootInverseReverse       = std::move(TableI);
    t->preconRootReverse        = std::move(preconTable);
    t->preconRootInverseReverse = std::move(preconTableI);

    IntType coInv(1);
    VecType TableCOI(msb + 1, modulus);
    VecType preconTableCOI(msb + 1, nModulus);
    for (size_t i = 0; i <= msb; ++i) {
        TableCOI[i]       = coInv.ModInverse(modulus);
        preconTableCOI[i] = TableCOI[i].PrepModMulConst(nModulus);
        coInv <<= 1;
    }
    t->cycloOrderInverse       = std::move(TableCOI);
    t->preconCycloOrderInverse = std::move(preconTableCOI);

    std::shared_ptr<const Tables> ct(std::move(t));
    m_tablesByModulus[modulus] = ct;
    return ct;
}

template <typename VecType>
void ChineseRemainderTransformFTTNat<VecType>::PreCompute(const IntType& rootOfUnity, const uint32_t cycloOrder,
                                                          const IntType& modulus) {
    GetTables(rootOfUnity, cycloOrder, modulus);
}

template <typename VecType>
void ChineseRemainderTransformFTTNat<VecType>::PreCompute(std::vector<IntType>& rootOfUnity, const uint32_t cycloOrder,
                                                          std::vector<IntType>& moduliiChain) {
    uint32_t numOfRootU = rootOfUnity.size();
    uint32_t numModulii = moduliiChain.size();
    if (numOfRootU != numModulii)
        OPENFHE_THROW("size of root of unity and size of moduli chain not of same size");
    for (size_t i = 0; i < numOfRootU; ++i)
        PreCompute(rootOfUnity[i], cycloOrder, moduliiChain[i]);
}

template <typename VecType>
void ChineseRemainderTransformFTTNat<VecType>::Reset() {
    std::unique_lock<std::shared_mutex> lk(TablesMutex());
    m_tablesByModulus.clear();
}

template <typename VecType>
void BluesteinFFTNat<VecType>::PreComputeDefaultNTTModulusRoot(uint32_t cycloOrder, const IntType& modulus) {
    std::lock_guard<std::recursive_mutex> lk(CacheMutex());
    uint32_t nttDim                           = 1u << GetMSB(2 * cycloOrder - 2);
    const auto nttModulus                     = LastPrime<IntType>(std::log2(nttDim) + 2 * modulus.GetMSB(), nttDim);
    const auto nttRoot                        = RootOfUnity<IntType>(nttDim, nttModulus);
    const ModulusRoot<IntType> nttModulusRoot = {nttModulus, nttRoot};
    m_defaultNTTModulusRoot[modulus]          = nttModulusRoot;

    PreComputeRootTableForNTT(cycloOrder, nttModulusRoot);
}

template <typename VecType>
void BluesteinFFTNat<VecType>::PreComputeRootTableForNTT(uint32_t cyclotoOrder,
                                                         const ModulusRoot<IntType>& nttModulusRoot) {
    std::lock_guard<std::recursive_mutex> lk(CacheMutex());
    uint32_t nttDim        = 1u << GetMSB(2 * cyclotoOrder - 2);
    const auto& nttModulus = nttModulusRoot.first;
    const auto& nttRoot    = nttModulusRoot.second;

    IntType root(nttRoot);
    auto rootInv = root.ModInverse(nttModulus);

    uint32_t nttDimHf = (nttDim >> 1);
    VecType rootTable(nttDimHf, nttModulus);
    VecType rootTableInverse(nttDimHf, nttModulus);
    VecType preconTable(nttDimHf, nttModulus);
    VecType preconTableInverse(nttDimHf, nttModulus);

    IntType x(1), y(1);
    for (size_t i = 0; i < nttDimHf; ++i) {
        rootTable[i]   = x;
        preconTable[i] = x.PrepModMulConst(nttModulus);
        x.ModMulEq(root, nttModulus);
        rootTableInverse[i]   = y;
        preconTableInverse[i] = y.PrepModMulConst(nttModulus);
        y.ModMulEq(rootInv, nttModulus);
    }

    m_rootOfUnityTableByModulusRoot[nttModulusRoot]              = std::move(rootTable);
    m_rootOfUnityInverseTableByModulusRoot[nttModulusRoot]       = std::move(rootTableInverse);
    m_preconRootOfUnityTableByModulusRoot[nttModulusRoot]        = std::move(preconTable);
    m_preconRootOfUnityInverseTableByModulusRoot[nttModulusRoot] = std::move(preconTableInverse);
}

template <typename VecType>
void BluesteinFFTNat<VecType>::PreComputePowers(uint32_t cycloOrder, const ModulusRoot<IntType>& modulusRoot) {
    std::lock_guard<std::recursive_mutex> lk(CacheMutex());
    const auto& modulus = modulusRoot.first;
    const auto& root    = modulusRoot.second;

    VecType powers(cycloOrder, modulus);
    powers[0] = 1;
    for (size_t i = 1; i < cycloOrder; i++) {
        auto iSqr = (i * i) % (2 * cycloOrder);
        auto val  = root.ModExp(IntType(iSqr), modulus);
        powers[i] = val;
    }
    m_powersTableByModulusRoot[modulusRoot] = std::move(powers);
}

template <typename VecType>
void BluesteinFFTNat<VecType>::PreComputeRBTable(uint32_t cycloOrder, const ModulusRootPair<IntType>& modulusRootPair) {
    std::lock_guard<std::recursive_mutex> lk(CacheMutex());
    const auto& modulusRoot = modulusRootPair.first;
    const auto& modulus     = modulusRoot.first;
    const auto& root        = modulusRoot.second;
    const auto rootInv      = root.ModInverse(modulus);

    const auto& nttModulusRoot = modulusRootPair.second;
    const auto& nttModulus     = nttModulusRoot.first;
    const auto& rootTable      = m_rootOfUnityTableByModulusRoot[nttModulusRoot];
    const auto& preconTable    = m_preconRootOfUnityTableByModulusRoot[nttModulusRoot];
    uint32_t nttDim            = 1u << GetMSB(2 * cycloOrder - 2);

    VecType b(2 * cycloOrder - 1, modulus);
    b[cycloOrder - 1] = 1;
    for (size_t i = 1; i < cycloOrder; i++) {
        auto iSqr             = (i * i) % (2 * cycloOrder);
        auto val              = rootInv.ModExp(IntType(iSqr), modulus);
        b[cycloOrder - 1 + i] = val;
        b[cycloOrder - 1 - i] = val;
    }

    auto Rb = PadZeros(b, nttDim);
    Rb.SetModulus(nttModulus);

    VecType RB(nttDim);
    NumberTheoreticTransformNat<VecType>().ForwardTransformIterative(Rb, rootTable, preconTable, &RB);
    m_RBTableByModulusRootPair[modulusRootPair] = std::move(RB);
}

template <typename VecType>
VecType BluesteinFFTNat<VecType>::ForwardTransform(const VecType& element, const IntType& root,
                                                   const uint32_t cycloOrder) {
    const auto& modulus = element.GetModulus();
    std::unique_lock<std::recursive_mutex> lk(CacheMutex());
    const auto nttModulusRoot = m_defaultNTTModulusRoot[modulus];
    lk.unlock();
    return ForwardTransform(element, root, cycloOrder, nttModulusRoot);
}

template <typename VecType>
VecType BluesteinFFTNat<VecType>::ForwardTransform(const VecType& element, const IntType& root,
                                                   const uint32_t cycloOrder,
                                                   const ModulusRoot<IntType>& nttModulusRoot) {
    if (element.GetLength() != cycloOrder)
        OPENFHE_THROW("expected size of element vector should be equal to cyclotomic order");

    const auto& modulus                            = element.GetModulus();
    const ModulusRoot<IntType> modulusRoot         = {modulus, root};
    const ModulusRootPair<IntType> modulusRootPair = {modulusRoot, nttModulusRoot};

    // all tables are precomputed by the callers; take stable references under the cache
    // lock (map nodes never move), then compute without it
    std::unique_lock<std::recursive_mutex> lk(CacheMutex());
    const VecType& powers             = m_powersTableByModulusRoot.at(modulusRoot);
    const VecType& rootTable          = m_rootOfUnityTableByModulusRoot.at(nttModulusRoot);
    const VecType& preconTable        = m_preconRootOfUnityTableByModulusRoot.at(nttModulusRoot);
    const VecType& rootTableInverse   = m_rootOfUnityInverseTableByModulusRoot.at(nttModulusRoot);
    const VecType& preconTableInverse = m_preconRootOfUnityInverseTableByModulusRoot.at(nttModulusRoot);
    const VecType& RB                 = m_RBTableByModulusRootPair.at(modulusRootPair);
    lk.unlock();

    const auto& nttModulus = nttModulusRoot.first;
    VecType x              = element.ModMul(powers);

    uint32_t nttDim = 1u << GetMSB(2 * cycloOrder - 2);
    auto Ra         = PadZeros(x, nttDim);
    Ra.SetModulus(nttModulus);
    VecType RA(nttDim);
    NumberTheoreticTransformNat<VecType>().ForwardTransformIterative(Ra, rootTable, preconTable, &RA);

    auto RC = RA.ModMul(RB);
    VecType Rc(nttDim);
    NumberTheoreticTransformNat<VecType>().InverseTransformIterative(RC, rootTableInverse, preconTableInverse, &Rc);
    auto resizeRc = Resize(Rc, cycloOrder - 1, 2 * (cycloOrder - 1));
    resizeRc.SetModulus(modulus);
    resizeRc.ModReduceEq();
    auto result = resizeRc.ModMul(powers);

    return result;
}

template <typename VecType>
VecType BluesteinFFTNat<VecType>::PadZeros(const VecType& a, const uint32_t finalSize) {
    uint32_t s = a.GetLength();
    VecType result(finalSize, a.GetModulus());
    for (size_t i = 0; i < s; i++)
        result[i] = a[i];
    for (size_t i = a.GetLength(); i < finalSize; i++)
        result[i] = IntType(0);
    return result;
}

template <typename VecType>
VecType BluesteinFFTNat<VecType>::Resize(const VecType& a, uint32_t lo, uint32_t hi) {
    VecType result(hi - lo + 1, a.GetModulus());
    for (size_t i = lo, j = 0; i <= hi; i++, j++)
        result[j] = a[i];
    return result;
}

template <typename VecType>
void BluesteinFFTNat<VecType>::Reset() {
    std::lock_guard<std::recursive_mutex> lk(CacheMutex());
    m_rootOfUnityTableByModulusRoot.clear();
    m_rootOfUnityInverseTableByModulusRoot.clear();
    m_preconRootOfUnityTableByModulusRoot.clear();
    m_preconRootOfUnityInverseTableByModulusRoot.clear();
    m_powersTableByModulusRoot.clear();
    m_RBTableByModulusRootPair.clear();
    m_defaultNTTModulusRoot.clear();
}

template <typename VecType>
void ChineseRemainderTransformArbNat<VecType>::SetCylotomicPolynomial(const VecType& poly, const IntType& mod) {
    std::lock_guard<std::recursive_mutex> lk(BluesteinFFTNat<VecType>::CacheMutex());
    m_cyclotomicPolyMap[mod] = poly;
}

template <typename VecType>
void ChineseRemainderTransformArbNat<VecType>::PreCompute(const uint32_t cyclotoOrder, const IntType& modulus) {
    BluesteinFFTNat<VecType>().PreComputeDefaultNTTModulusRoot(cyclotoOrder, modulus);
}

template <typename VecType>
void ChineseRemainderTransformArbNat<VecType>::SetPreComputedNTTModulus(uint32_t cyclotoOrder, const IntType& modulus,
                                                                        const IntType& nttModulus,
                                                                        const IntType& nttRoot) {
    const ModulusRoot<IntType> nttModulusRoot = {nttModulus, nttRoot};
    std::lock_guard<std::recursive_mutex> lk(BluesteinFFTNat<VecType>::CacheMutex());
    BluesteinFFTNat<VecType>().PreComputeRootTableForNTT(cyclotoOrder, nttModulusRoot);
}

template <typename VecType>
void ChineseRemainderTransformArbNat<VecType>::SetPreComputedNTTDivisionModulus(uint32_t cyclotoOrder,
                                                                                const IntType& modulus,
                                                                                const IntType& nttMod,
                                                                                const IntType& nttRootBig) {
    std::lock_guard<std::recursive_mutex> lk(BluesteinFFTNat<VecType>::CacheMutex());
    OPENFHE_DEBUG_FLAG(false);

    uint32_t n = GetTotient(cyclotoOrder);
    OPENFHE_DEBUG("GetTotient(" << cyclotoOrder << ")= " << n);

    uint32_t power                 = cyclotoOrder - n;
    m_nttDivisionDim[cyclotoOrder] = 2u << GetMSB(power - 1);

    uint32_t nttDimBig = 1u << GetMSB(2 * cyclotoOrder - 2);

    // Computes the root of unity for the division NTT based on the root of unity
    // for regular NTT
    IntType nttRoot = nttRootBig.ModExp(IntType(nttDimBig / m_nttDivisionDim[cyclotoOrder]), nttMod);

    m_DivisionNTTModulus[modulus]     = nttMod;
    m_DivisionNTTRootOfUnity[modulus] = nttRoot;
    // part0 setting of rootTable and inverse rootTable
    uint32_t nttDim = m_nttDivisionDim[cyclotoOrder];
    IntType root(nttRoot);
    auto rootInv = root.ModInverse(nttMod);

    uint32_t nttDimHf = (nttDim >> 1);
    VecType rootTable(nttDimHf, nttMod);
    VecType rootTableInverse(nttDimHf, nttMod);
    VecType preconTable(nttDimHf, nttMod);
    VecType preconTableInverse(nttDimHf, nttMod);

    IntType x(1);
    for (size_t i = 0; i < nttDimHf; i++) {
        rootTable[i]   = x;
        preconTable[i] = x.PrepModMulConst(nttMod);
        x              = x.ModMul(root, nttMod);
    }

    x = 1;
    for (size_t i = 0; i < nttDimHf; i++) {
        rootTableInverse[i]   = x;
        preconTableInverse[i] = x.PrepModMulConst(nttMod);
        x                     = x.ModMul(rootInv, nttMod);
    }

    m_rootOfUnityDivisionTableByModulus[nttMod]              = std::move(rootTable);
    m_rootOfUnityDivisionInverseTableByModulus[nttMod]       = std::move(rootTableInverse);
    m_rootOfUnityDivisionPreconTableByModulus[nttMod]        = std::move(preconTable);
    m_rootOfUnityDivisionInversePreconTableByModulus[nttMod] = std::move(preconTableInverse);

    // end of part0
    // part1
    const auto& RevCPM = InversePolyMod(m_cyclotomicPolyMap[modulus], modulus, power);
    auto RevCPMPadded  = BluesteinFFTNat<VecType>().PadZeros(RevCPM, nttDim);
    RevCPMPadded.SetModulus(nttMod);
    // end of part1

    const auto& divTable  = m_rootOfUnityDivisionTableByModulus[nttMod];
    const auto& divPrecon = m_rootOfUnityDivisionPreconTableByModulus[nttMod];
    VecType RA(nttDim);
    NumberTheoreticTransformNat<VecType>().ForwardTransformIterative(RevCPMPadded, divTable, divPrecon, &RA);
    m_cyclotomicPolyReverseNTTMap[modulus] = std::move(RA);

    const auto& cycloPoly = m_cyclotomicPolyMap[modulus];

    VecType QForwardTransform(nttDim, nttMod);
    for (size_t i = 0; i < cycloPoly.GetLength(); i++)
        QForwardTransform[i] = cycloPoly[i];

    VecType QFwdResult(nttDim);
    NumberTheoreticTransformNat<VecType>().ForwardTransformIterative(QForwardTransform, divTable, divPrecon,
                                                                     &QFwdResult);

    m_cyclotomicPolyNTTMap[modulus] = std::move(QFwdResult);
}

template <typename VecType>
VecType ChineseRemainderTransformArbNat<VecType>::InversePolyMod(const VecType& cycloPoly, const IntType& modulus,
                                                                 uint32_t power) {
    VecType result(power, modulus);
    uint32_t r = (power > 1) ? GetMSB(power - 1) : 0;
    VecType h(1, modulus);  // h is a unit polynomial
    h[0] = 1;

    // Precompute the Barrett mu parameter
    IntType mu = modulus.ComputeMu();

    for (size_t i = 0; i < r; i++) {
        uint32_t qDegree = 1u << (i + 1);
        VecType q(qDegree + 1, modulus);  // q = x^(2^i+1)
        q[qDegree]   = 1;
        auto hSquare = PolynomialMultiplication(h, h);

        auto a = h * IntType(2);
        auto b = PolynomialMultiplication(hSquare, cycloPoly);
        // b = 2h - gh^2
        for (size_t j = 0; j < b.GetLength(); j++) {
            if (j < a.GetLength()) {
                b[j] = a[j].ModSub(b[j], modulus, mu);
            }
            else {
                b[j] = modulus.ModSub(b[j], modulus, mu);
            }
        }
        h = PolyMod(b, q, modulus);
    }
    // take modulo x^power
    for (size_t i = 0; i < power; i++) {
        result[i] = h[i];
    }

    return result;
}

template <typename VecType>
VecType ChineseRemainderTransformArbNat<VecType>::ForwardTransform(const VecType& element, const IntType& root,
                                                                   const IntType& nttModulus, const IntType& nttRoot,
                                                                   const uint32_t cycloOrder) {
    uint32_t phim = GetTotient(cycloOrder);
    if (element.GetLength() != phim)
        OPENFHE_THROW("element size should be equal to phim");

    const auto& modulus                    = element.GetModulus();
    const ModulusRoot<IntType> modulusRoot = {modulus, root};

    const ModulusRoot<IntType> nttModulusRoot      = {nttModulus, nttRoot};
    const ModulusRootPair<IntType> modulusRootPair = {modulusRoot, nttModulusRoot};

    {
        std::lock_guard<std::recursive_mutex> lk(BluesteinFFTNat<VecType>::CacheMutex());
        if (BluesteinFFTNat<VecType>::m_rootOfUnityTableByModulusRoot[nttModulusRoot].GetLength() == 0) {
            BluesteinFFTNat<VecType>().PreComputeRootTableForNTT(cycloOrder, nttModulusRoot);
        }

        if (BluesteinFFTNat<VecType>::m_powersTableByModulusRoot[modulusRoot].GetLength() == 0) {
            BluesteinFFTNat<VecType>().PreComputePowers(cycloOrder, modulusRoot);
        }

        if (BluesteinFFTNat<VecType>::m_RBTableByModulusRootPair[modulusRootPair].GetLength() == 0) {
            BluesteinFFTNat<VecType>().PreComputeRBTable(cycloOrder, modulusRootPair);
        }
    }

    VecType inputToBluestein = Pad(element, cycloOrder, true);
    auto outputBluestein =
        BluesteinFFTNat<VecType>().ForwardTransform(inputToBluestein, root, cycloOrder, nttModulusRoot);
    VecType output = Drop(outputBluestein, cycloOrder, true, nttModulus, nttRoot);

    return output;
}

template <typename VecType>
VecType ChineseRemainderTransformArbNat<VecType>::InverseTransform(const VecType& element, const IntType& root,
                                                                   const IntType& nttModulus, const IntType& nttRoot,
                                                                   const uint32_t cycloOrder) {
    uint32_t phim = GetTotient(cycloOrder);
    if (element.GetLength() != phim)
        OPENFHE_THROW("element size should be equal to phim");

    const auto& modulus = element.GetModulus();
    auto rootInverse(root.ModInverse(modulus));
    const ModulusRoot<IntType> modulusRootInverse = {modulus, rootInverse};

    const ModulusRoot<IntType> nttModulusRoot      = {nttModulus, nttRoot};
    const ModulusRootPair<IntType> modulusRootPair = {modulusRootInverse, nttModulusRoot};

    {
        std::lock_guard<std::recursive_mutex> lk(BluesteinFFTNat<VecType>::CacheMutex());
        if (BluesteinFFTNat<VecType>::m_rootOfUnityTableByModulusRoot[nttModulusRoot].GetLength() == 0) {
            BluesteinFFTNat<VecType>().PreComputeRootTableForNTT(cycloOrder, nttModulusRoot);
        }

        if (BluesteinFFTNat<VecType>::m_powersTableByModulusRoot[modulusRootInverse].GetLength() == 0) {
            BluesteinFFTNat<VecType>().PreComputePowers(cycloOrder, modulusRootInverse);
        }

        if (BluesteinFFTNat<VecType>::m_RBTableByModulusRootPair[modulusRootPair].GetLength() == 0) {
            BluesteinFFTNat<VecType>().PreComputeRBTable(cycloOrder, modulusRootPair);
        }
    }
    VecType inputToBluestein = Pad(element, cycloOrder, false);
    auto outputBluestein =
        BluesteinFFTNat<VecType>().ForwardTransform(inputToBluestein, rootInverse, cycloOrder, nttModulusRoot);
    auto cyclotomicInverse((IntType(cycloOrder)).ModInverse(modulus));
    outputBluestein = outputBluestein * cyclotomicInverse;
    VecType output  = Drop(outputBluestein, cycloOrder, false, nttModulus, nttRoot);
    return output;
}

template <typename VecType>
VecType ChineseRemainderTransformArbNat<VecType>::Pad(const VecType& element, const uint32_t cycloOrder, bool forward) {
    uint32_t n = GetTotient(cycloOrder);

    const auto& modulus = element.GetModulus();
    VecType inputToBluestein(cycloOrder, modulus);

    if (forward) {  // Forward transform padding
        for (size_t i = 0; i < n; i++) {
            inputToBluestein[i] = element[i];
        }
    }
    else {  // Inverse transform padding
        auto tList = GetTotientList(cycloOrder);
        size_t i   = 0;
        for (auto& coprime : tList) {
            inputToBluestein[coprime] = element[i++];
        }
    }

    return inputToBluestein;
}

template <typename VecType>
VecType ChineseRemainderTransformArbNat<VecType>::Drop(const VecType& element, const uint32_t cycloOrder, bool forward,
                                                       const IntType& bigMod, const IntType& bigRoot) {
    uint32_t n = GetTotient(cycloOrder);

    const auto& modulus = element.GetModulus();
    VecType output(n, modulus);

    if (forward) {  // Forward transform drop
        auto tList = GetTotientList(cycloOrder);
        for (size_t i = 0; i < n; i++) {
            output[i] = element[tList[i]];
        }
    }
    else {  // Inverse transform drop
        if ((n + 1) == cycloOrder) {
            IntType mu = modulus.ComputeMu();  // Precompute the Barrett mu parameter
            // cycloOrder is prime: Reduce mod Phi_{n+1}(x)
            // Reduction involves subtracting the coeff of x^n from all terms
            auto coeff_n = element[n];
            for (size_t i = 0; i < n; i++) {
                output[i] = element[i].ModSub(coeff_n, modulus, mu);
            }
        }
        else if ((n + 1) * 2 == cycloOrder) {
            IntType mu = modulus.ComputeMu();  // Precompute the Barrett mu parameter
            // cycloOrder is 2*prime: 2 Step reduction
            // First reduce mod x^(n+1)+1 (=(x+1)*Phi_{2*(n+1)}(x))
            // Subtract co-efficient of x^(i+n+1) from x^(i)
            for (size_t i = 0; i < n; i++) {
                auto coeff_i  = element[i];
                auto coeff_ip = element[i + n + 1];
                output[i]     = coeff_i.ModSub(coeff_ip, modulus, mu);
            }
            auto coeff_n = element[n].ModSub(element[2 * n + 1], modulus, mu);
            // Now reduce mod Phi_{2*(n+1)}(x)
            // Similar to the prime case but with alternating signs
            for (size_t i = 0; i < n; i++) {
                if (i % 2 == 0) {
                    output[i].ModSubEq(coeff_n, modulus, mu);
                }
                else {
                    output[i].ModAddEq(coeff_n, modulus, mu);
                }
            }
        }
        else {
            // precompute root of unity tables for division NTT
            std::unique_lock<std::recursive_mutex> lk(BluesteinFFTNat<VecType>::CacheMutex());
            if ((m_rootOfUnityDivisionTableByModulus[bigMod].GetLength() == 0) ||
                (m_DivisionNTTModulus[modulus] != bigMod)) {
                SetPreComputedNTTDivisionModulus(cycloOrder, modulus, bigMod, bigRoot);
            }

            // cycloOrder is arbitrary
            const auto nttMod                 = m_DivisionNTTModulus[modulus];
            const VecType& rootTable          = m_rootOfUnityDivisionTableByModulus.at(nttMod);
            const VecType& preconTable        = m_rootOfUnityDivisionPreconTableByModulus.at(nttMod);
            const VecType& rootTableInverse   = m_rootOfUnityDivisionInverseTableByModulus.at(nttMod);
            const VecType& preconTableInverse = m_rootOfUnityDivisionInversePreconTableByModulus.at(nttMod);
            const VecType& cycloReverseNTT    = m_cyclotomicPolyReverseNTTMap.at(modulus);
            const VecType& cycloNTT           = m_cyclotomicPolyNTTMap.at(modulus);
            const uint32_t nttDivDim          = m_nttDivisionDim.at(cycloOrder);
            lk.unlock();

            VecType aPadded2(nttDivDim, nttMod);
            // perform mod operation
            uint32_t power = cycloOrder - n;
            for (size_t i = n; i < element.GetLength(); i++) {
                aPadded2[power - (i - n) - 1] = element[i];
            }
            VecType A(nttDivDim);
            NumberTheoreticTransformNat<VecType>().ForwardTransformIterative(aPadded2, rootTable, preconTable, &A);
            auto AB = A * cycloReverseNTT;
            VecType a(nttDivDim);
            NumberTheoreticTransformNat<VecType>().InverseTransformIterative(AB, rootTableInverse, preconTableInverse,
                                                                             &a);

            VecType quotient(nttDivDim, modulus);
            for (size_t i = 0; i < power; i++) {
                quotient[i] = a[i];
            }
            quotient.ModReduceEq();
            quotient.SetModulus(nttMod);

            VecType newQuotient(nttDivDim);
            NumberTheoreticTransformNat<VecType>().ForwardTransformIterative(quotient, rootTable, preconTable,
                                                                             &newQuotient);
            newQuotient *= cycloNTT;

            VecType newQuotient2(nttDivDim);
            NumberTheoreticTransformNat<VecType>().InverseTransformIterative(newQuotient, rootTableInverse,
                                                                             preconTableInverse, &newQuotient2);
            newQuotient2.SetModulus(modulus);
            newQuotient2.ModReduceEq();

            IntType mu = modulus.ComputeMu();  // Precompute the Barrett mu parameter

            for (size_t i = 0; i < n; i++) {
                output[i] = element[i].ModSub(newQuotient2[cycloOrder - 1 - i], modulus, mu);
            }
        }
    }
    return output;
}

template <typename VecType>
void ChineseRemainderTransformArbNat<VecType>::Reset() {
    std::lock_guard<std::recursive_mutex> lk(BluesteinFFTNat<VecType>::CacheMutex());
    m_cyclotomicPolyMap.clear();
    m_cyclotomicPolyReverseNTTMap.clear();
    m_cyclotomicPolyNTTMap.clear();
    m_rootOfUnityDivisionTableByModulus.clear();
    m_rootOfUnityDivisionInverseTableByModulus.clear();
    m_rootOfUnityDivisionPreconTableByModulus.clear();
    m_rootOfUnityDivisionInversePreconTableByModulus.clear();
    m_DivisionNTTModulus.clear();
    m_DivisionNTTRootOfUnity.clear();
    m_nttDivisionDim.clear();
    BluesteinFFTNat<VecType>().Reset();
}

}  // namespace intnat

#endif  // __TRANSFORMNAT_IMPL_H__
