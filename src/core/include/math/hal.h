// @file hal.h This file contains the functionality to switch between math
// backends
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef LBCRYPTO_MATH_HAL_H
#define LBCRYPTO_MATH_HAL_H

// use of MS VC is not permitted because of various incompatibilities
#ifdef _MSC_VER
#error "MSVC COMPILER IS NOT SUPPORTED"
#endif

#include "config_core.h"
#include "version.h"

#include "math/hal/vector.h"
#include "utils/debug.h"
#include "utils/exception.h"
#include "utils/memory.h"
#include "utils/palisadebase64.h"
#include "utils/parallel.h"
#include "utils/serializable.h"

#ifdef WITH_INTEL_HEXL
#include "math/hal/intnat-hexl/backendnathexl.h"
#include "math/hal/intnat-hexl/transformnathexl.h"
#else
#include "math/hal/intnat/backendnat.h"
#include "math/hal/intnat/transformnat.h"
#endif

#include "math/hal/bigintfxd/backendfxd.h"
#include "math/hal/bigintfxd/transformfxd.h"

#include "math/hal/bigintdyn/backenddyn.h"
#include "math/hal/bigintdyn/transformdyn.h"

#include "math/hal/bigintntl/backendntl.h"
#include "math/hal/bigintntl/transformntl.h"


/*! Define the underlying default math implementation being used by defining
 * MATHBACKEND */

// Each math backend is defined in its own namespace, and can be used at any
// time by referencing the objects in its namespace

// Selecting a math backend by defining MATHBACKEND means defining which
// underlying implementation is the default BigInteger and BigVector

// note that we #define how many bits the underlying integer can store as a
// guide for users of the backends

// MATHBACKEND 2
//    Uses bigintfxd:: definition as default
//    Implemented as a vector of integers
//    Configurable maximum bit length and type of underlying integer

// MATHBACKEND 4
//     This uses bigintdyn:: definition as default
//     This backend supports arbitrary bitwidths; no memory pool is
// used; can grow up to RAM limitation
//    Configurable type of underlying integer (either 32 or 64 bit)

// passes all tests with UBINTDYN_32
// fails tests with UBINTDYN_64
// there is a bug in the way modulus is computed. do not use.

// MATHBACKEND 6
//     This uses bigintntl:: definition as default
//     GMP 6.1.2 / NTL 10.3.0 backend

// To select backend, please UNCOMMENT the appropriate line rather than changing
// the number on the uncommented line (and breaking the documentation of the
// line)

#ifndef MATHBACKEND
#define MATHBACKEND 2
// #define MATHBACKEND 4
// #define MATHBACKEND 6
#endif

#if MATHBACKEND != 2 && MATHBACKEND != 4 && MATHBACKEND != 6
#error "MATHBACKEND value is not valid"
#endif

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

#if MATHBACKEND == 2

using BigInteger = M2Integer;
using BigVector = M2Vector;

#elif MATHBACKEND == 4

#ifdef UBINT_64
#error MATHBACKEND 4 with UBINT_64 currently does not work do not use.
#endif

using BigInteger = M4Integer;
using BigVector = M4Vector;

#elif MATHBACKEND == 6

using BigInteger = M6Integer;
using BigVector = M6Vector;

#endif

}  // namespace lbcrypto


//==============================================================================================
#ifdef WITH_INTEL_HEXL
template<typename VecType>
using NatChineseRemainderTransformFTT = intnathexl::ChineseRemainderTransformFTTNat<VecType>;
template<typename VecType>
using NatChineseRemainderTransformArb = intnathexl::ChineseRemainderTransformArbNat<VecType>;
#else
template<typename VecType>
using NatChineseRemainderTransformFTT = intnat::ChineseRemainderTransformFTTNat<VecType>;
template<typename VecType>
using NatChineseRemainderTransformArb = intnat::ChineseRemainderTransformArbNat<VecType>;
#endif

//==============================================================================================

// TODO it might be possible to remove the template argument in the concrete class for each backend - needs further investigation

// A the main template, but should never be called
// Not assuming default back-end
template<typename VecType>
struct FTTTypedef
{
	typedef	void type;
};

template<>
struct FTTTypedef<NativeVector>
{
    typedef NatChineseRemainderTransformFTT<NativeVector> type;
};

template<>
struct FTTTypedef<M4Vector>
{
    typedef bigintdyn::ChineseRemainderTransformFTTDyn<M4Vector> type;
};

template<>
struct FTTTypedef<M2Vector>
{
    typedef bigintfxd::ChineseRemainderTransformFTTFxd<M2Vector> type;
};

#ifdef WITH_NTL
template<>
struct FTTTypedef<M6Vector>
{
    typedef NTL::ChineseRemainderTransformFTTNtl<M6Vector> type;
};
#endif


template<typename VecType>
using ChineseRemainderTransformFTT = typename FTTTypedef<VecType>::type;

//==============================================================================================

// A the main template, but should never be called
// Not assuming default back-end
template<typename VecType>
struct ArbTypedef
{
	typedef	void type;
};

template<>
struct ArbTypedef<NativeVector>
{
    typedef NatChineseRemainderTransformArb<NativeVector> type;
};

template<>
struct ArbTypedef<M4Vector>
{
	typedef bigintdyn::ChineseRemainderTransformArbDyn<M4Vector> type;
};

template<>
struct ArbTypedef<M2Vector>
{
	typedef bigintfxd::ChineseRemainderTransformArbFxd<M2Vector> type;
};

#ifdef WITH_NTL
template<>
struct ArbTypedef<M6Vector>
{
	typedef NTL::ChineseRemainderTransformArbNtl<M6Vector> type;
};
#endif

template<typename VecType>
using ChineseRemainderTransformArb = typename ArbTypedef<VecType>::type;

#endif
