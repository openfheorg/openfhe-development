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

#include "utils/exception.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

#include <map>
#include <utility>
#include <vector>

namespace intnat {

using namespace lbcrypto;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
    ChineseRemainderTransformFTTNat<VecType>::m_cycloOrderInverseTableByModulus;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
    ChineseRemainderTransformFTTNat<VecType>::m_cycloOrderInversePreconTableByModulus;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
    ChineseRemainderTransformFTTNat<VecType>::m_rootOfUnityReverseTableByModulus;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
    ChineseRemainderTransformFTTNat<VecType>::m_rootOfUnityInverseReverseTableByModulus;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
    ChineseRemainderTransformFTTNat<VecType>::m_rootOfUnityPreconReverseTableByModulus;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
    ChineseRemainderTransformFTTNat<VecType>::m_rootOfUnityInversePreconReverseTableByModulus;

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
std::map<typename VecType::Integer, ModulusRoot<typename VecType::Integer>>
    BluesteinFFTNat<VecType>::m_defaultNTTModulusRoot;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
    ChineseRemainderTransformArbNat<VecType>::m_rootOfUnityDivisionTableByModulus;

template <typename VecType>
std::map<typename VecType::Integer, VecType>
    ChineseRemainderTransformArbNat<VecType>::m_rootOfUnityDivisionInverseTableByModulus;

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
                                                                     const VecType& rootOfUnityTable, VecType* result) {
    uint32_t n = element.GetLength();
    if (result->GetLength() != n) {
        OPENFHE_THROW("size of input element and size of output element not of same size");
    }

    auto modulus = element.GetModulus();
    IntType mu   = modulus.ComputeMu();
    result->SetModulus(modulus);

    uint32_t msb = GetMSB(n - 1);
    for (size_t i = 0; i < n; i++) {
        (*result)[i] = element[ReverseBits(i, msb)];
    }

    IntType omega, omegaFactor, oddVal, evenVal;
    uint32_t logm, i, j, indexEven, indexOdd;

    uint32_t logn = GetMSB(n - 1);
    for (logm = 1; logm <= logn; logm++) {
        // calculate the i indexes into the root table one time per loop
        std::vector<uint32_t> indexes(1 << (logm - 1));
        for (i = 0; i < (uint32_t)(1 << (logm - 1)); i++) {
            indexes[i] = (i << (logn - logm));
        }

        for (j = 0; j < n; j = j + (1 << logm)) {
            for (i = 0; i < (uint32_t)(1 << (logm - 1)); i++) {
                omega     = rootOfUnityTable[indexes[i]];
                indexEven = j + i;
                indexOdd  = indexEven + (1 << (logm - 1));
                oddVal    = (*result)[indexOdd];

                omegaFactor = omega.ModMul(oddVal, modulus, mu);
                evenVal     = (*result)[indexEven];
                oddVal      = evenVal;
                oddVal += omegaFactor;
                if (oddVal >= modulus) {
                    oddVal -= modulus;
                }

                if (evenVal < omegaFactor) {
                    evenVal += modulus;
                }
                evenVal -= omegaFactor;

                (*result)[indexEven] = oddVal;
                (*result)[indexOdd]  = evenVal;
            }
        }
    }
    return;
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::InverseTransformIterative(const VecType& element,
                                                                     const VecType& rootOfUnityInverseTable,
                                                                     VecType* result) {
    uint32_t n = element.GetLength();

    IntType modulus = element.GetModulus();
    IntType mu      = modulus.ComputeMu();

    NumberTheoreticTransformNat<VecType>().ForwardTransformIterative(element, rootOfUnityInverseTable, result);
    IntType cycloOrderInv(IntType(n).ModInverse(modulus));
    for (uint32_t i = 0; i < n; i++) {
        (*result)[i].ModMulEq(cycloOrderInv, modulus, mu);
    }
    return;
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::ForwardTransformToBitReverseInPlace(const VecType& rootOfUnityTable,
                                                                               VecType* element) {
    uint32_t n      = element->GetLength();
    IntType modulus = element->GetModulus();
    IntType mu      = modulus.ComputeMu();

    uint32_t i, m, j1, j2, indexOmega, indexLo, indexHi;
    IntType omega, omegaFactor, loVal, hiVal;

    uint32_t t     = (n >> 1);
    uint32_t logt1 = GetMSB(t);
    for (m = 1; m < n; m <<= 1) {
        for (i = 0; i < m; ++i) {
            j1         = i << logt1;
            j2         = j1 + t;
            indexOmega = m + i;
            omega      = rootOfUnityTable[indexOmega];
            for (indexLo = j1; indexLo < j2; ++indexLo) {
                indexHi     = indexLo + t;
                loVal       = (*element)[indexLo];
                omegaFactor = (*element)[indexHi];
                omegaFactor.ModMulFastEq(omega, modulus, mu);

                hiVal = loVal + omegaFactor;
                if (hiVal >= modulus) {
                    hiVal -= modulus;
                }

                if (loVal < omegaFactor) {
                    loVal += modulus;
                }
                loVal -= omegaFactor;

                (*element)[indexLo] = hiVal;
                (*element)[indexHi] = loVal;
            }
        }
        t >>= 1;
        logt1--;
    }
    return;
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::ForwardTransformToBitReverse(const VecType& element,
                                                                        const VecType& rootOfUnityTable,
                                                                        VecType* result) {
    uint32_t n = element.GetLength();
    if (result->GetLength() != n) {
        OPENFHE_THROW("size of input element and size of output element not of same size");
    }

    IntType modulus = element.GetModulus();
    IntType mu      = modulus.ComputeMu();
    result->SetModulus(modulus);

    uint32_t i, m, j1, j2, indexOmega, indexLo, indexHi;
    IntType omega, omegaFactor, loVal, hiVal, zero(0);

    for (i = 0; i < n; ++i) {
        (*result)[i] = element[i];
    }

    uint32_t t     = (n >> 1);
    uint32_t logt1 = GetMSB(t);
    for (m = 1; m < n; m <<= 1) {
        for (i = 0; i < m; ++i) {
            j1         = i << logt1;
            j2         = j1 + t;
            indexOmega = m + i;
            omega      = rootOfUnityTable[indexOmega];
            for (indexLo = j1; indexLo < j2; ++indexLo) {
                indexHi     = indexLo + t;
                loVal       = (*result)[indexLo];
                omegaFactor = (*result)[indexHi];
                if (omegaFactor != zero) {
                    omegaFactor.ModMulFastEq(omega, modulus, mu);

                    hiVal = loVal + omegaFactor;
                    if (hiVal >= modulus) {
                        hiVal -= modulus;
                    }

                    if (loVal < omegaFactor) {
                        loVal += modulus;
                    }
                    loVal -= omegaFactor;

                    (*result)[indexLo] = hiVal;
                    (*result)[indexHi] = loVal;
                }
                else {
                    (*result)[indexHi] = loVal;
                }
            }
        }
        t >>= 1;
        logt1--;
    }
    return;
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::ForwardTransformToBitReverseInPlace(const VecType& rootOfUnityTable,
                                                                               const VecType& preconRootOfUnityTable,
                                                                               VecType* element) {
    //
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

    const auto modulus{element->GetModulus()};
    const uint32_t n(element->GetLength() >> 1);
    for (uint32_t m{1}, t{n}, logt{GetMSB(t)}; m < n; m <<= 1, t >>= 1, --logt) {
        for (uint32_t i{0}; i < m; ++i) {
            auto omega{rootOfUnityTable[i + m]};
            auto preconOmega{preconRootOfUnityTable[i + m]};
            for (uint32_t j1{i << logt}, j2{j1 + t}; j1 < j2; ++j1) {
                auto omegaFactor{(*element)[j1 + t]};
                omegaFactor.ModMulFastConstEq(omega, modulus, preconOmega);
                auto loVal{(*element)[j1 + 0]};
#if defined(__GNUC__) && !defined(__clang__)
                auto hiVal{loVal + omegaFactor};
                if (hiVal >= modulus)
                    hiVal -= modulus;
                if (loVal < omegaFactor)
                    loVal += modulus;
                loVal -= omegaFactor;
                (*element)[j1 + 0] = hiVal;
                (*element)[j1 + t] = loVal;
#else
                // fixes Clang slowdown issue, but requires lowVal be less than modulus
                (*element)[j1 + 0] += omegaFactor - (omegaFactor >= (modulus - loVal) ? modulus : 0);
                if (omegaFactor > loVal)
                    loVal += modulus;
                (*element)[j1 + t] = loVal - omegaFactor;
#endif
            }
        }
    }
    // peeled off last ntt stage for performance
    for (uint32_t i{0}; i < (n << 1); i += 2) {
        auto omegaFactor{(*element)[i + 1]};
        auto omega{rootOfUnityTable[(i >> 1) + n]};
        auto preconOmega{preconRootOfUnityTable[(i >> 1) + n]};
        omegaFactor.ModMulFastConstEq(omega, modulus, preconOmega);
        auto loVal{(*element)[i + 0]};
#if defined(__GNUC__) && !defined(__clang__)
        auto hiVal{loVal + omegaFactor};
        if (hiVal >= modulus)
            hiVal -= modulus;
        if (loVal < omegaFactor)
            loVal += modulus;
        loVal -= omegaFactor;
        (*element)[i + 0] = hiVal;
        (*element)[i + 1] = loVal;
#else
        (*element)[i + 0] += omegaFactor - (omegaFactor >= (modulus - loVal) ? modulus : 0);
        if (omegaFactor > loVal)
            loVal += modulus;
        (*element)[i + 1] = loVal - omegaFactor;
#endif
    }
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::ForwardTransformToBitReverse(const VecType& element,
                                                                        const VecType& rootOfUnityTable,
                                                                        const VecType& preconRootOfUnityTable,
                                                                        VecType* result) {
    uint32_t n = element.GetLength();

    if (result->GetLength() != n) {
        OPENFHE_THROW("size of input element and size of output element not of same size");
    }

    IntType modulus = element.GetModulus();

    result->SetModulus(modulus);

    for (uint32_t i = 0; i < n; ++i) {
        (*result)[i] = element[i];
    }

    uint32_t indexOmega, indexHi;
    NativeInteger preconOmega;
    IntType omega, omegaFactor, loVal, hiVal, zero(0);

    uint32_t t     = (n >> 1);
    uint32_t logt1 = GetMSB(t);
    for (uint32_t m = 1; m < n; m <<= 1, t >>= 1, --logt1) {
        uint32_t j1, j2;
        for (uint32_t i = 0; i < m; ++i) {
            j1          = i << logt1;
            j2          = j1 + t;
            indexOmega  = m + i;
            omega       = rootOfUnityTable[indexOmega];
            preconOmega = preconRootOfUnityTable[indexOmega];
            for (uint32_t indexLo = j1; indexLo < j2; ++indexLo) {
                indexHi     = indexLo + t;
                loVal       = (*result)[indexLo];
                omegaFactor = (*result)[indexHi];
                if (omegaFactor != zero) {
                    omegaFactor.ModMulFastConstEq(omega, modulus, preconOmega);

                    hiVal = loVal + omegaFactor;
                    if (hiVal >= modulus) {
                        hiVal -= modulus;
                    }

                    if (loVal < omegaFactor) {
                        loVal += modulus;
                    }
                    loVal -= omegaFactor;

                    (*result)[indexLo] = hiVal;
                    (*result)[indexHi] = loVal;
                }
                else {
                    (*result)[indexHi] = loVal;
                }
            }
        }
    }
    return;
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::InverseTransformFromBitReverseInPlace(const VecType& rootOfUnityInverseTable,
                                                                                 const IntType& cycloOrderInv,
                                                                                 VecType* element) {
    uint32_t n      = element->GetLength();
    IntType modulus = element->GetModulus();
    IntType mu      = modulus.ComputeMu();

    IntType loVal, hiVal, omega, omegaFactor;
    uint32_t i, m, j1, j2, indexOmega, indexLo, indexHi;

    uint32_t t     = 1;
    uint32_t logt1 = 1;
    for (m = (n >> 1); m >= 1; m >>= 1) {
        for (i = 0; i < m; ++i) {
            j1         = i << logt1;
            j2         = j1 + t;
            indexOmega = m + i;
            omega      = rootOfUnityInverseTable[indexOmega];

            for (indexLo = j1; indexLo < j2; ++indexLo) {
                indexHi = indexLo + t;

                hiVal = (*element)[indexHi];
                loVal = (*element)[indexLo];

                omegaFactor = loVal;
                if (omegaFactor < hiVal) {
                    omegaFactor += modulus;
                }

                omegaFactor -= hiVal;

                loVal += hiVal;
                if (loVal >= modulus) {
                    loVal -= modulus;
                }

                omegaFactor.ModMulFastEq(omega, modulus, mu);

                (*element)[indexLo] = loVal;
                (*element)[indexHi] = omegaFactor;
            }
        }
        t <<= 1;
        logt1++;
    }

    for (i = 0; i < n; i++) {
        (*element)[i].ModMulFastEq(cycloOrderInv, modulus, mu);
    }
    return;
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::InverseTransformFromBitReverse(const VecType& element,
                                                                          const VecType& rootOfUnityInverseTable,
                                                                          const IntType& cycloOrderInv,
                                                                          VecType* result) {
    uint32_t n = element.GetLength();

    if (result->GetLength() != n) {
        OPENFHE_THROW("size of input element and size of output element not of same size");
    }

    result->SetModulus(element.GetModulus());

    for (uint32_t i = 0; i < n; i++) {
        (*result)[i] = element[i];
    }
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

    auto modulus{element->GetModulus()};
    uint32_t n(element->GetLength());

    // precomputed omega[bitreversed(1)] * (n inverse). used in final stage of intt.
    auto omega1Inv{rootOfUnityInverseTable[1].ModMulFastConst(cycloOrderInv, modulus, preconCycloOrderInv)};
    auto preconOmega1Inv{omega1Inv.PrepModMulConst(modulus)};

    if (n > 2) {
        // peeled off first stage for performance
        for (uint32_t i{0}; i < n; i += 2) {
            auto omega{rootOfUnityInverseTable[(i + n) >> 1]};
            auto preconOmega{preconRootOfUnityInverseTable[(i + n) >> 1]};
            auto loVal{(*element)[i + 0]};
            auto hiVal{(*element)[i + 1]};
#if defined(__GNUC__) && !defined(__clang__)
            auto omegaFactor{loVal};
            if (omegaFactor < hiVal)
                omegaFactor += modulus;
            omegaFactor -= hiVal;
            loVal += hiVal;
            if (loVal >= modulus)
                loVal -= modulus;
            omegaFactor.ModMulFastConstEq(omega, modulus, preconOmega);
            (*element)[i + 0] = loVal;
            (*element)[i + 1] = omegaFactor;
#else
            auto omegaFactor{loVal + (hiVal > loVal ? modulus : 0) - hiVal};
            loVal += hiVal - (hiVal >= (modulus - loVal) ? modulus : 0);
            (*element)[i + 0] = loVal;
            omegaFactor.ModMulFastConstEq(omega, modulus, preconOmega);
            (*element)[i + 1] = omegaFactor;
#endif
        }
    }
    // inner stages
    for (uint32_t m{n >> 2}, t{2}, logt{2}; m > 1; m >>= 1, t <<= 1, ++logt) {
        for (uint32_t i{0}; i < m; ++i) {
            auto omega{rootOfUnityInverseTable[i + m]};
            auto preconOmega{preconRootOfUnityInverseTable[i + m]};
            for (uint32_t j1{i << logt}, j2{j1 + t}; j1 < j2; ++j1) {
                auto loVal{(*element)[j1 + 0]};
                auto hiVal{(*element)[j1 + t]};
#if defined(__GNUC__) && !defined(__clang__)
                auto omegaFactor{loVal};
                if (omegaFactor < hiVal)
                    omegaFactor += modulus;
                omegaFactor -= hiVal;
                loVal += hiVal;
                if (loVal >= modulus)
                    loVal -= modulus;
                omegaFactor.ModMulFastConstEq(omega, modulus, preconOmega);
                (*element)[j1 + 0] = loVal;
                (*element)[j1 + t] = omegaFactor;
#else
                (*element)[j1 + 0] += hiVal - (hiVal >= (modulus - loVal) ? modulus : 0);
                auto omegaFactor = loVal + (hiVal > loVal ? modulus : 0) - hiVal;
                omegaFactor.ModMulFastConstEq(omega, modulus, preconOmega);
                (*element)[j1 + t] = omegaFactor;
#endif
            }
        }
    }

    // peeled off final stage to implement optimization where n/2 scalar multiplies
    // by (n inverse) are incorporated into the omegaFactor calculation.
    // Please see https://github.com/openfheorg/openfhe-development/issues/872 for details.
    uint32_t j2{n >> 1};
    for (uint32_t j1{0}; j1 < j2; ++j1) {
        auto loVal{(*element)[j1]};
        auto hiVal{(*element)[j1 + j2]};
#if defined(__GNUC__) && !defined(__clang__)
        auto omegaFactor{loVal};
        if (omegaFactor < hiVal)
            omegaFactor += modulus;
        omegaFactor -= hiVal;
        loVal += hiVal;
        if (loVal >= modulus)
            loVal -= modulus;
        omegaFactor.ModMulFastConstEq(omega1Inv, modulus, preconOmega1Inv);
        (*element)[j1 + 0]  = loVal;
        (*element)[j1 + j2] = omegaFactor;
#else
        (*element)[j1] += hiVal - (hiVal >= (modulus - loVal) ? modulus : 0);
        auto omegaFactor = loVal + (hiVal > loVal ? modulus : 0) - hiVal;
        omegaFactor.ModMulFastConstEq(omega1Inv, modulus, preconOmega1Inv);
        (*element)[j1 + j2] = omegaFactor;
#endif
    }
    // perform remaining n/2 scalar multiplies by (n inverse)
    for (uint32_t i = 0; i < j2; ++i)
        (*element)[i].ModMulFastConstEq(cycloOrderInv, modulus, preconCycloOrderInv);
}

template <typename VecType>
void NumberTheoreticTransformNat<VecType>::InverseTransformFromBitReverse(
    const VecType& element, const VecType& rootOfUnityInverseTable, const VecType& preconRootOfUnityInverseTable,
    const IntType& cycloOrderInv, const IntType& preconCycloOrderInv, VecType* result) {
    uint32_t n = element.GetLength();
    if (result->GetLength() != n) {
        OPENFHE_THROW("size of input element and size of output element not of same size");
    }

    result->SetModulus(element.GetModulus());

    for (uint32_t i = 0; i < n; i++) {
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
    auto modulus = element->GetModulus();
    PreCompute(rootOfUnity, cycloOrder, modulus);
    NumberTheoreticTransformNat<VecType>().ForwardTransformToBitReverseInPlace(
        m_rootOfUnityReverseTableByModulus[modulus], m_rootOfUnityPreconReverseTableByModulus[modulus], element);
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
    auto modulus = element.GetModulus();
    PreCompute(rootOfUnity, cycloOrder, modulus);
    NumberTheoreticTransformNat<VecType>().ForwardTransformToBitReverse(
        element, m_rootOfUnityReverseTableByModulus[modulus], m_rootOfUnityPreconReverseTableByModulus[modulus],
        result);

    return;
}

template <typename VecType>
void ChineseRemainderTransformFTTNat<VecType>::InverseTransformFromBitReverseInPlace(const IntType& rootOfUnity,
                                                                                     const uint32_t cycloOrder,
                                                                                     VecType* element) {
    if (rootOfUnity == IntType(1) || rootOfUnity == IntType(0))
        return;
    auto modulus = element->GetModulus();
    PreCompute(rootOfUnity, cycloOrder, modulus);
    uint32_t msb = GetMSB((cycloOrder >> 1) - 1);
    NumberTheoreticTransformNat<VecType>().InverseTransformFromBitReverseInPlace(
        m_rootOfUnityInverseReverseTableByModulus[modulus], m_rootOfUnityInversePreconReverseTableByModulus[modulus],
        m_cycloOrderInverseTableByModulus[modulus][msb], m_cycloOrderInversePreconTableByModulus[modulus][msb],
        element);
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
    auto modulus = element.GetModulus();
    result->SetModulus(modulus);
    PreCompute(rootOfUnity, cycloOrder, modulus);
    uint32_t n = element.GetLength();
    for (uint32_t i = 0; i < n; ++i)
        (*result)[i] = element[i];
    uint32_t msb = GetMSB(n - 1);
    NumberTheoreticTransformNat<VecType>().InverseTransformFromBitReverseInPlace(
        m_rootOfUnityInverseReverseTableByModulus[modulus], m_rootOfUnityInversePreconReverseTableByModulus[modulus],
        m_cycloOrderInverseTableByModulus[modulus][msb], m_cycloOrderInversePreconTableByModulus[modulus][msb], result);
}

template <typename VecType>
void ChineseRemainderTransformFTTNat<VecType>::PreCompute(const IntType& rootOfUnity, const uint32_t cycloOrder,
                                                          const IntType& modulus) {
    auto ringDim   = (cycloOrder >> 1);
    auto mapSearch = m_rootOfUnityReverseTableByModulus.find(modulus);
    if (mapSearch == m_rootOfUnityReverseTableByModulus.end() || mapSearch->second.GetLength() != ringDim) {
#pragma omp critical
        {
            IntType x(1), xinv(1);
            uint32_t msb               = GetMSB(ringDim - 1);
            IntType mu                 = modulus.ComputeMu();
            IntType rootOfUnityInverse = rootOfUnity.ModInverse(modulus);
            NativeInteger nModulus     = modulus.ConvertToInt();
            VecType Table(ringDim, modulus);
            VecType TableI(ringDim, modulus);
            VecType preconTable(ringDim, nModulus);
            VecType preconTableI(ringDim, nModulus);
            for (uint32_t i = 0; i < ringDim; ++i) {
                auto iinv         = ReverseBits(i, msb);
                Table[iinv]       = x;
                preconTable[iinv] = NativeInteger(x.ConvertToInt()).PrepModMulConst(nModulus);
                x.ModMulEq(rootOfUnity, modulus, mu);
                TableI[iinv]       = xinv;
                preconTableI[iinv] = NativeInteger(xinv.ConvertToInt()).PrepModMulConst(nModulus);
                xinv.ModMulEq(rootOfUnityInverse, modulus, mu);
            }
            m_rootOfUnityReverseTableByModulus[modulus]              = std::move(Table);
            m_rootOfUnityInverseReverseTableByModulus[modulus]       = std::move(TableI);
            m_rootOfUnityPreconReverseTableByModulus[modulus]        = std::move(preconTable);
            m_rootOfUnityInversePreconReverseTableByModulus[modulus] = std::move(preconTableI);

            IntType coInv(1);
            VecType TableCOI(msb + 1, modulus);
            VecType preconTableCOI(msb + 1, nModulus);
            for (uint32_t i = 0; i <= msb; ++i) {
                TableCOI[i]       = coInv.ModInverse(modulus);
                preconTableCOI[i] = NativeInteger(TableCOI[i].ConvertToInt()).PrepModMulConst(nModulus);
                coInv <<= 1;
            }
            m_cycloOrderInverseTableByModulus[modulus]       = std::move(TableCOI);
            m_cycloOrderInversePreconTableByModulus[modulus] = std::move(preconTableCOI);
        }
    }
}

template <typename VecType>
void ChineseRemainderTransformFTTNat<VecType>::PreCompute(std::vector<IntType>& rootOfUnity, const uint32_t cycloOrder,
                                                          std::vector<IntType>& moduliiChain) {
    uint32_t numOfRootU = rootOfUnity.size();
    uint32_t numModulii = moduliiChain.size();
    if (numOfRootU != numModulii)
        OPENFHE_THROW("size of root of unity and size of moduli chain not of same size");
    for (uint32_t i = 0; i < numOfRootU; ++i)
        PreCompute(rootOfUnity[i], cycloOrder, moduliiChain[i]);
}

template <typename VecType>
void ChineseRemainderTransformFTTNat<VecType>::Reset() {
    m_cycloOrderInverseTableByModulus.clear();
    m_cycloOrderInversePreconTableByModulus.clear();
    m_rootOfUnityReverseTableByModulus.clear();
    m_rootOfUnityInverseReverseTableByModulus.clear();
    m_rootOfUnityPreconReverseTableByModulus.clear();
    m_rootOfUnityInversePreconReverseTableByModulus.clear();
}

template <typename VecType>
void BluesteinFFTNat<VecType>::PreComputeDefaultNTTModulusRoot(uint32_t cycloOrder, const IntType& modulus) {
    uint32_t nttDim                           = pow(2, ceil(log2(2 * cycloOrder - 1)));
    const auto nttModulus                     = LastPrime<IntType>(log2(nttDim) + 2 * modulus.GetMSB(), nttDim);
    const auto nttRoot                        = RootOfUnity<IntType>(nttDim, nttModulus);
    const ModulusRoot<IntType> nttModulusRoot = {nttModulus, nttRoot};
    m_defaultNTTModulusRoot[modulus]          = nttModulusRoot;

    PreComputeRootTableForNTT(cycloOrder, nttModulusRoot);
}

template <typename VecType>
void BluesteinFFTNat<VecType>::PreComputeRootTableForNTT(uint32_t cyclotoOrder,
                                                         const ModulusRoot<IntType>& nttModulusRoot) {
    uint32_t nttDim        = pow(2, ceil(log2(2 * cyclotoOrder - 1)));
    const auto& nttModulus = nttModulusRoot.first;
    const auto& nttRoot    = nttModulusRoot.second;

    IntType root(nttRoot);
    auto rootInv = root.ModInverse(nttModulus);

    uint32_t nttDimHf = (nttDim >> 1);
    VecType rootTable(nttDimHf, nttModulus);
    VecType rootTableInverse(nttDimHf, nttModulus);

    IntType x(1), y(1);
    for (uint32_t i = 0; i < nttDimHf; ++i) {
        rootTable[i] = x;
        x.ModMulEq(root, nttModulus);
        rootTableInverse[i] = y;
        y.ModMulEq(rootInv, nttModulus);
    }

    m_rootOfUnityTableByModulusRoot[nttModulusRoot]        = std::move(rootTable);
    m_rootOfUnityInverseTableByModulusRoot[nttModulusRoot] = std::move(rootTableInverse);
}

template <typename VecType>
void BluesteinFFTNat<VecType>::PreComputePowers(uint32_t cycloOrder, const ModulusRoot<IntType>& modulusRoot) {
    const auto& modulus = modulusRoot.first;
    const auto& root    = modulusRoot.second;

    VecType powers(cycloOrder, modulus);
    powers[0] = 1;
    for (uint32_t i = 1; i < cycloOrder; i++) {
        auto iSqr = (i * i) % (2 * cycloOrder);
        auto val  = root.ModExp(IntType(iSqr), modulus);
        powers[i] = val;
    }
    m_powersTableByModulusRoot[modulusRoot] = powers;
}

template <typename VecType>
void BluesteinFFTNat<VecType>::PreComputeRBTable(uint32_t cycloOrder, const ModulusRootPair<IntType>& modulusRootPair) {
    const auto& modulusRoot = modulusRootPair.first;
    const auto& modulus     = modulusRoot.first;
    const auto& root        = modulusRoot.second;
    const auto rootInv      = root.ModInverse(modulus);

    const auto& nttModulusRoot = modulusRootPair.second;
    const auto& nttModulus     = nttModulusRoot.first;
    // const auto &nttRoot = nttModulusRoot.second;
    // assumes rootTable is precomputed
    const auto& rootTable = m_rootOfUnityTableByModulusRoot[nttModulusRoot];
    uint32_t nttDim       = pow(2, ceil(log2(2 * cycloOrder - 1)));

    VecType b(2 * cycloOrder - 1, modulus);
    b[cycloOrder - 1] = 1;
    for (uint32_t i = 1; i < cycloOrder; i++) {
        auto iSqr             = (i * i) % (2 * cycloOrder);
        auto val              = rootInv.ModExp(IntType(iSqr), modulus);
        b[cycloOrder - 1 + i] = val;
        b[cycloOrder - 1 - i] = val;
    }

    auto Rb = PadZeros(b, nttDim);
    Rb.SetModulus(nttModulus);

    VecType RB(nttDim);
    NumberTheoreticTransformNat<VecType>().ForwardTransformIterative(Rb, rootTable, &RB);
    m_RBTableByModulusRootPair[modulusRootPair] = RB;
}

template <typename VecType>
VecType BluesteinFFTNat<VecType>::ForwardTransform(const VecType& element, const IntType& root,
                                                   const uint32_t cycloOrder) {
    const auto& modulus        = element.GetModulus();
    const auto& nttModulusRoot = m_defaultNTTModulusRoot[modulus];

    return ForwardTransform(element, root, cycloOrder, nttModulusRoot);
}

template <typename VecType>
VecType BluesteinFFTNat<VecType>::ForwardTransform(const VecType& element, const IntType& root,
                                                   const uint32_t cycloOrder,
                                                   const ModulusRoot<IntType>& nttModulusRoot) {
    if (element.GetLength() != cycloOrder) {
        OPENFHE_THROW("expected size of element vector should be equal to cyclotomic order");
    }

    const auto& modulus                    = element.GetModulus();
    const ModulusRoot<IntType> modulusRoot = {modulus, root};
    const VecType& powers                  = m_powersTableByModulusRoot[modulusRoot];

    const auto& nttModulus = nttModulusRoot.first;
    // assumes rootTable is precomputed
    const auto& rootTable = m_rootOfUnityTableByModulusRoot[nttModulusRoot];
    const auto& rootTableInverse =
        m_rootOfUnityInverseTableByModulusRoot[nttModulusRoot];  // assumes rootTableInverse is precomputed
    VecType x = element.ModMul(powers);

    uint32_t nttDim = pow(2, ceil(log2(2 * cycloOrder - 1)));
    auto Ra         = PadZeros(x, nttDim);
    Ra.SetModulus(nttModulus);
    VecType RA(nttDim);
    NumberTheoreticTransformNat<VecType>().ForwardTransformIterative(Ra, rootTable, &RA);

    const ModulusRootPair<IntType> modulusRootPair = {modulusRoot, nttModulusRoot};
    const auto& RB                                 = m_RBTableByModulusRootPair[modulusRootPair];

    auto RC = RA.ModMul(RB);
    VecType Rc(nttDim);
    NumberTheoreticTransformNat<VecType>().InverseTransformIterative(RC, rootTableInverse, &Rc);
    auto resizeRc = Resize(Rc, cycloOrder - 1, 2 * (cycloOrder - 1));
    resizeRc.SetModulus(modulus);
    resizeRc.ModEq(modulus);
    auto result = resizeRc.ModMul(powers);

    return result;
}

template <typename VecType>
VecType BluesteinFFTNat<VecType>::PadZeros(const VecType& a, const uint32_t finalSize) {
    uint32_t s = a.GetLength();
    VecType result(finalSize, a.GetModulus());

    for (uint32_t i = 0; i < s; i++) {
        result[i] = a[i];
    }

    for (uint32_t i = a.GetLength(); i < finalSize; i++) {
        result[i] = IntType(0);
    }

    return result;
}

template <typename VecType>
VecType BluesteinFFTNat<VecType>::Resize(const VecType& a, uint32_t lo, uint32_t hi) {
    VecType result(hi - lo + 1, a.GetModulus());

    for (uint32_t i = lo, j = 0; i <= hi; i++, j++) {
        result[j] = a[i];
    }

    return result;
}

template <typename VecType>
void BluesteinFFTNat<VecType>::Reset() {
    m_rootOfUnityTableByModulusRoot.clear();
    m_rootOfUnityInverseTableByModulusRoot.clear();
    m_powersTableByModulusRoot.clear();
    m_RBTableByModulusRootPair.clear();
    m_defaultNTTModulusRoot.clear();
}

template <typename VecType>
void ChineseRemainderTransformArbNat<VecType>::SetCylotomicPolynomial(const VecType& poly, const IntType& mod) {
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
    BluesteinFFTNat<VecType>().PreComputeRootTableForNTT(cyclotoOrder, nttModulusRoot);
}

template <typename VecType>
void ChineseRemainderTransformArbNat<VecType>::SetPreComputedNTTDivisionModulus(uint32_t cyclotoOrder,
                                                                                const IntType& modulus,
                                                                                const IntType& nttMod,
                                                                                const IntType& nttRootBig) {
    OPENFHE_DEBUG_FLAG(false);

    uint32_t n = GetTotient(cyclotoOrder);
    OPENFHE_DEBUG("GetTotient(" << cyclotoOrder << ")= " << n);

    uint32_t power                 = cyclotoOrder - n;
    m_nttDivisionDim[cyclotoOrder] = 2 * std::pow(2, ceil(log2(power)));

    uint32_t nttDimBig = std::pow(2, ceil(log2(2 * cyclotoOrder - 1)));

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

    IntType x(1);
    for (uint32_t i = 0; i < nttDimHf; i++) {
        rootTable[i] = x;
        x            = x.ModMul(root, nttMod);
    }

    x = 1;
    for (uint32_t i = 0; i < nttDimHf; i++) {
        rootTableInverse[i] = x;
        x                   = x.ModMul(rootInv, nttMod);
    }

    m_rootOfUnityDivisionTableByModulus[nttMod]        = rootTable;
    m_rootOfUnityDivisionInverseTableByModulus[nttMod] = rootTableInverse;

    // end of part0
    // part1
    const auto& RevCPM = InversePolyMod(m_cyclotomicPolyMap[modulus], modulus, power);
    auto RevCPMPadded  = BluesteinFFTNat<VecType>().PadZeros(RevCPM, nttDim);
    RevCPMPadded.SetModulus(nttMod);
    // end of part1

    VecType RA(nttDim);
    NumberTheoreticTransformNat<VecType>().ForwardTransformIterative(RevCPMPadded, rootTable, &RA);
    m_cyclotomicPolyReverseNTTMap[modulus] = RA;

    const auto& cycloPoly = m_cyclotomicPolyMap[modulus];

    VecType QForwardTransform(nttDim, nttMod);
    for (uint32_t i = 0; i < cycloPoly.GetLength(); i++) {
        QForwardTransform[i] = cycloPoly[i];
    }

    VecType QFwdResult(nttDim);
    NumberTheoreticTransformNat<VecType>().ForwardTransformIterative(QForwardTransform, rootTable, &QFwdResult);

    m_cyclotomicPolyNTTMap[modulus] = QFwdResult;
}

template <typename VecType>
VecType ChineseRemainderTransformArbNat<VecType>::InversePolyMod(const VecType& cycloPoly, const IntType& modulus,
                                                                 uint32_t power) {
    VecType result(power, modulus);
    uint32_t r = ceil(log2(power));
    VecType h(1, modulus);  // h is a unit polynomial
    h[0] = 1;

    // Precompute the Barrett mu parameter
    IntType mu = modulus.ComputeMu();

    for (uint32_t i = 0; i < r; i++) {
        uint32_t qDegree = std::pow(2, i + 1);
        VecType q(qDegree + 1, modulus);  // q = x^(2^i+1)
        q[qDegree]   = 1;
        auto hSquare = PolynomialMultiplication(h, h);

        auto a = h * IntType(2);
        auto b = PolynomialMultiplication(hSquare, cycloPoly);
        // b = 2h - gh^2
        for (uint32_t j = 0; j < b.GetLength(); j++) {
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
    for (uint32_t i = 0; i < power; i++) {
        result[i] = h[i];
    }

    return result;
}

template <typename VecType>
VecType ChineseRemainderTransformArbNat<VecType>::ForwardTransform(const VecType& element, const IntType& root,
                                                                   const IntType& nttModulus, const IntType& nttRoot,
                                                                   const uint32_t cycloOrder) {
    uint32_t phim = GetTotient(cycloOrder);
    if (element.GetLength() != phim) {
        OPENFHE_THROW("element size should be equal to phim");
    }

    const auto& modulus                    = element.GetModulus();
    const ModulusRoot<IntType> modulusRoot = {modulus, root};

    const ModulusRoot<IntType> nttModulusRoot      = {nttModulus, nttRoot};
    const ModulusRootPair<IntType> modulusRootPair = {modulusRoot, nttModulusRoot};

#pragma omp critical
    {
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
    if (element.GetLength() != phim) {
        OPENFHE_THROW("element size should be equal to phim");
    }

    const auto& modulus = element.GetModulus();
    auto rootInverse(root.ModInverse(modulus));
    const ModulusRoot<IntType> modulusRootInverse = {modulus, rootInverse};

    const ModulusRoot<IntType> nttModulusRoot      = {nttModulus, nttRoot};
    const ModulusRootPair<IntType> modulusRootPair = {modulusRootInverse, nttModulusRoot};

#pragma omp critical
    {
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
        for (uint32_t i = 0; i < n; i++) {
            inputToBluestein[i] = element[i];
        }
    }
    else {  // Inverse transform padding
        auto tList = GetTotientList(cycloOrder);
        uint32_t i = 0;
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
        for (uint32_t i = 0; i < n; i++) {
            output[i] = element[tList[i]];
        }
    }
    else {  // Inverse transform drop
        if ((n + 1) == cycloOrder) {
            IntType mu = modulus.ComputeMu();  // Precompute the Barrett mu parameter
            // cycloOrder is prime: Reduce mod Phi_{n+1}(x)
            // Reduction involves subtracting the coeff of x^n from all terms
            auto coeff_n = element[n];
            for (uint32_t i = 0; i < n; i++) {
                output[i] = element[i].ModSub(coeff_n, modulus, mu);
            }
        }
        else if ((n + 1) * 2 == cycloOrder) {
            IntType mu = modulus.ComputeMu();  // Precompute the Barrett mu parameter
            // cycloOrder is 2*prime: 2 Step reduction
            // First reduce mod x^(n+1)+1 (=(x+1)*Phi_{2*(n+1)}(x))
            // Subtract co-efficient of x^(i+n+1) from x^(i)
            for (uint32_t i = 0; i < n; i++) {
                auto coeff_i  = element[i];
                auto coeff_ip = element[i + n + 1];
                output[i]     = coeff_i.ModSub(coeff_ip, modulus, mu);
            }
            auto coeff_n = element[n].ModSub(element[2 * n + 1], modulus, mu);
            // Now reduce mod Phi_{2*(n+1)}(x)
            // Similar to the prime case but with alternating signs
            for (uint32_t i = 0; i < n; i++) {
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
            if ((m_rootOfUnityDivisionTableByModulus[bigMod].GetLength() == 0) ||
                (m_DivisionNTTModulus[modulus] != bigMod)) {
                SetPreComputedNTTDivisionModulus(cycloOrder, modulus, bigMod, bigRoot);
            }

            // cycloOrder is arbitrary
            // auto output = PolyMod(element, this->m_cyclotomicPolyMap[modulus],
            // modulus);

            const auto& nttMod    = m_DivisionNTTModulus[modulus];
            const auto& rootTable = m_rootOfUnityDivisionTableByModulus[nttMod];
            VecType aPadded2(m_nttDivisionDim[cycloOrder], nttMod);
            // perform mod operation
            uint32_t power = cycloOrder - n;
            for (uint32_t i = n; i < element.GetLength(); i++) {
                aPadded2[power - (i - n) - 1] = element[i];
            }
            VecType A(m_nttDivisionDim[cycloOrder]);
            NumberTheoreticTransformNat<VecType>().ForwardTransformIterative(aPadded2, rootTable, &A);
            auto AB                      = A * m_cyclotomicPolyReverseNTTMap[modulus];
            const auto& rootTableInverse = m_rootOfUnityDivisionInverseTableByModulus[nttMod];
            VecType a(m_nttDivisionDim[cycloOrder]);
            NumberTheoreticTransformNat<VecType>().InverseTransformIterative(AB, rootTableInverse, &a);

            VecType quotient(m_nttDivisionDim[cycloOrder], modulus);
            for (uint32_t i = 0; i < power; i++) {
                quotient[i] = a[i];
            }
            quotient.ModEq(modulus);
            quotient.SetModulus(nttMod);

            VecType newQuotient(m_nttDivisionDim[cycloOrder]);
            NumberTheoreticTransformNat<VecType>().ForwardTransformIterative(quotient, rootTable, &newQuotient);
            newQuotient *= m_cyclotomicPolyNTTMap[modulus];

            VecType newQuotient2(m_nttDivisionDim[cycloOrder]);
            NumberTheoreticTransformNat<VecType>().InverseTransformIterative(newQuotient, rootTableInverse,
                                                                             &newQuotient2);
            newQuotient2.SetModulus(modulus);
            newQuotient2.ModEq(modulus);

            IntType mu = modulus.ComputeMu();  // Precompute the Barrett mu parameter

            for (uint32_t i = 0; i < n; i++) {
                output[i] = element[i].ModSub(newQuotient2[cycloOrder - 1 - i], modulus, mu);
            }
        }
    }
    return output;
}

template <typename VecType>
void ChineseRemainderTransformArbNat<VecType>::Reset() {
    m_cyclotomicPolyMap.clear();
    m_cyclotomicPolyReverseNTTMap.clear();
    m_cyclotomicPolyNTTMap.clear();
    m_rootOfUnityDivisionTableByModulus.clear();
    m_rootOfUnityDivisionInverseTableByModulus.clear();
    m_DivisionNTTModulus.clear();
    m_DivisionNTTRootOfUnity.clear();
    m_nttDivisionDim.clear();
    BluesteinFFTNat<VecType>().Reset();
}

// forced template instantiation
// template class ChineseRemainderTransformFTTNat<NativeVector>;
// template class ChineseRemainderTransformArbNat<NativeVector>;

}  // namespace intnat

#endif  // __TRANSFORMNAT_IMPL_H__
