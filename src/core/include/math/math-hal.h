//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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

#ifndef LBCRYPTO_INC_MATH_HAL_H
#define LBCRYPTO_INC_MATH_HAL_H

// use of MS VC is not permitted because of various incompatibilities
#ifdef _MSC_VER
    #error "MSVC COMPILER IS NOT SUPPORTED"
#endif

#include "config_core.h"
#include "version.h"

#include "math/hal/vector.h"
#include "math/hal/bigintbackend.h"
#include "math/hal/nativeintbackend.h"

namespace lbcrypto {
// Promote BigInteger and BigVector to lbcrypto namespace
using BigInteger = bigintbackend::BigInteger;
using BigVector  = bigintbackend::BigVector;
}  // namespace lbcrypto

//==============================================================================================
// TODO: total hack ... move this!!!!!
template <typename VecType>
using NatChineseRemainderTransformFTT = intnat::ChineseRemainderTransformFTTNat<VecType>;
template <typename VecType>
using NatChineseRemainderTransformArb = intnat::ChineseRemainderTransformArbNat<VecType>;

//==============================================================================================

// TODO it might be possible to remove the template argument in the concrete class for each backend - needs further investigation

template <typename VecType>
struct FTTTypedef {
    typedef void type;
};

template <>
struct FTTTypedef<NativeVector> {
    typedef NatChineseRemainderTransformFTT<NativeVector> type;
};

#ifdef WITH_BE2
template <>
struct FTTTypedef<M2Vector> {
    typedef bigintfxd::ChineseRemainderTransformFTTFxd<M2Vector> type;
};
#endif

#ifdef WITH_BE4
template <>
struct FTTTypedef<M4Vector> {
    typedef bigintdyn::ChineseRemainderTransformFTTDyn<M4Vector> type;
};
#endif

#ifdef WITH_NTL
template <>
struct FTTTypedef<M6Vector> {
    typedef NTL::ChineseRemainderTransformFTTNtl<M6Vector> type;
};
#endif

template <typename VecType>
using ChineseRemainderTransformFTT = typename FTTTypedef<VecType>::type;

//==============================================================================================

template <typename VecType>
struct ArbTypedef {
    typedef void type;
};

template <>
struct ArbTypedef<NativeVector> {
    typedef NatChineseRemainderTransformArb<NativeVector> type;
};

#ifdef WITH_BE2
template <>
struct ArbTypedef<M2Vector> {
    typedef bigintfxd::ChineseRemainderTransformArbFxd<M2Vector> type;
};
#endif

#ifdef WITH_BE4
template <>
struct ArbTypedef<M4Vector> {
    typedef bigintdyn::ChineseRemainderTransformArbDyn<M4Vector> type;
};
#endif

#ifdef WITH_NTL
template <>
struct ArbTypedef<M6Vector> {
    typedef NTL::ChineseRemainderTransformArbNtl<M6Vector> type;
};
#endif

template <typename VecType>
using ChineseRemainderTransformArb = typename ArbTypedef<VecType>::type;

#endif
