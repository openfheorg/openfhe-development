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

/*
  This file contains the functionality to switch between math backends
 */

#ifndef SRC_CORE_INCLUDE_MATH_MATH_HAL_H_
#define SRC_CORE_INCLUDE_MATH_MATH_HAL_H_

// use of MS VC is not permitted because of various incompatibilities
#ifdef _MSC_VER
    #error "MSVC COMPILER IS NOT SUPPORTED"
#endif

#include "config_core.h"
#include "math/hal/bigintbackend.h"
#include "math/hal/nativeintbackend.h"
#include "math/hal/vector.h"
#include "version.h"

namespace lbcrypto {
// Promote BigInteger and BigVector to lbcrypto namespace
/// the multiprecision integer of the selected big-integer backend
using BigInteger = bigintbackend::BigInteger;
/// the vector of multiprecision integers of the selected big-integer backend
using BigVector = bigintbackend::BigVector;
}  // namespace lbcrypto

//==============================================================================================

// TODO it might be possible to remove the template argument in the concrete class for each backend - needs further investigation

/**
 * @brief Maps a vector type to the class implementing its power-of-two cyclotomic NTT
 * (Chinese Remainder Transform); the primary template has no implementation (void).
 * @tparam VecType the vector type
 */
template <typename VecType>
struct FTTTypedef {
    /// the transform class for this vector type
    typedef void type;
};

/// @brief Power-of-two NTT for NativeVector.
template <>
struct FTTTypedef<NativeVector> {
    /// the transform class for this vector type
    typedef NatChineseRemainderTransformFTT<NativeVector> type;
};

#if NATIVEINT != 32
/// @brief Power-of-two NTT for NativeVector32 (only when the default word is not 32 bits).
template <>
struct FTTTypedef<NativeVector32> {
    /// the transform class for this vector type
    typedef NatChineseRemainderTransformFTT<NativeVector32> type;
};
#endif

#ifdef WITH_BE2
/// @brief Power-of-two NTT for the fixed-size big-integer backend (BE2).
template <>
struct FTTTypedef<M2Vector> {
    /// the transform class for this vector type
    typedef bigintfxd::ChineseRemainderTransformFTTFxd<M2Vector> type;
};
#endif

#ifdef WITH_BE4
/// @brief Power-of-two NTT for the dynamic-size big-integer backend (BE4).
template <>
struct FTTTypedef<M4Vector> {
    /// the transform class for this vector type
    typedef bigintdyn::ChineseRemainderTransformFTTDyn<M4Vector> type;
};
#endif

#ifdef WITH_NTL
/// @brief Power-of-two NTT for the NTL big-integer backend (BE6).
template <>
struct FTTTypedef<M6Vector> {
    /// the transform class for this vector type
    typedef NTL::ChineseRemainderTransformFTTNtl<M6Vector> type;
};
#endif

/// the power-of-two cyclotomic NTT class for a vector type
template <typename VecType>
using ChineseRemainderTransformFTT = typename FTTTypedef<VecType>::type;

//==============================================================================================

/**
 * @brief Maps a vector type to the class implementing its arbitrary-cyclotomic NTT
 * (Chinese Remainder Transform); the primary template has no implementation (void).
 * @tparam VecType the vector type
 */
template <typename VecType>
struct ArbTypedef {
    /// the transform class for this vector type
    typedef void type;
};

/// @brief Arbitrary-cyclotomic NTT for NativeVector.
template <>
struct ArbTypedef<NativeVector> {
    /// the transform class for this vector type
    typedef NatChineseRemainderTransformArb<NativeVector> type;
};

#if NATIVEINT != 32
/// @brief Arbitrary-cyclotomic NTT for NativeVector32 (only when the default word is not 32 bits).
template <>
struct ArbTypedef<NativeVector32> {
    /// the transform class for this vector type
    typedef NatChineseRemainderTransformArb<NativeVector32> type;
};
#endif

#ifdef WITH_BE2
/// @brief Arbitrary-cyclotomic NTT for the fixed-size big-integer backend (BE2).
template <>
struct ArbTypedef<M2Vector> {
    /// the transform class for this vector type
    typedef bigintfxd::ChineseRemainderTransformArbFxd<M2Vector> type;
};
#endif

#ifdef WITH_BE4
/// @brief Arbitrary-cyclotomic NTT for the dynamic-size big-integer backend (BE4).
template <>
struct ArbTypedef<M4Vector> {
    /// the transform class for this vector type
    typedef bigintdyn::ChineseRemainderTransformArbDyn<M4Vector> type;
};
#endif

#ifdef WITH_NTL
/// @brief Arbitrary-cyclotomic NTT for the NTL big-integer backend (BE6).
template <>
struct ArbTypedef<M6Vector> {
    /// the transform class for this vector type
    typedef NTL::ChineseRemainderTransformArbNtl<M6Vector> type;
};
#endif

/// the arbitrary-cyclotomic NTT class for a vector type
template <typename VecType>
using ChineseRemainderTransformArb = typename ArbTypedef<VecType>::type;

#endif  // SRC_CORE_INCLUDE_MATH_MATH_HAL_H_
