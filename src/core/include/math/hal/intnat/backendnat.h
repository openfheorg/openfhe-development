// @file backendnat.h This file contains the definitions for the native
// math backend
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

#ifndef SRC_CORE_INCLUDE_MATH_HAL_INTNAT_BACKENDNAT_H_
#define SRC_CORE_INCLUDE_MATH_HAL_INTNAT_BACKENDNAT_H_


namespace intnat {

template <typename I>
class NativeIntegerT;

#if NATIVEINT == 128
#define MAX_MODULUS_SIZE 121
typedef NativeIntegerT<unsigned __int128> NativeInteger;
typedef NativeIntegerT<unsigned __int128> NativeInteger128;
#elif NATIVEINT == 64 && !defined(HAVE_INT128)
#define MAX_MODULUS_SIZE 58
typedef NativeIntegerT<uint64_t> NativeInteger;
typedef NativeIntegerT<uint64_t> NativeInteger64;
#elif NATIVEINT == 64 && defined(HAVE_INT128)
#define MAX_MODULUS_SIZE 60
typedef NativeIntegerT<uint64_t> NativeInteger;
typedef NativeIntegerT<uint64_t> NativeInteger64;
#elif NATIVEINT == 32  // NOLINT
#define MAX_MODULUS_SIZE 28
typedef NativeIntegerT<uint32_t> NativeInteger;
typedef NativeIntegerT<uint32_t> NativeInteger32;
#endif

} // namespace intnat

namespace lbcrypto {

#if NATIVEINT == 128
using BasicInteger = unsigned __int128;
typedef unsigned __int128 DoubleNativeInt;
typedef unsigned __int128 uint128_t;
typedef __int128 int128_t;
#elif NATIVEINT == 64 && defined(HAVE_INT128)
using BasicInteger = uint64_t;
typedef unsigned __int128 DoubleNativeInt;
typedef unsigned __int128 uint128_t;
typedef __int128 int128_t;
#elif NATIVEINT == 64 && !defined(HAVE_INT128)
using BasicInteger = uint64_t;
typedef uint64_t DoubleNativeInt;
typedef uint64_t uint128_t;
typedef int64_t int128_t;
#elif NATIVEINT == 32
using BasicInteger = uint32_t;
typedef uint64_t DoubleNativeInt;
#endif

}

#include "math/hal/intnat/mubintvecnat.h"

// TODO:: consider moving this to intnat
#if NATIVEINT == 128
typedef intnat::NativeIntegerT<unsigned __int128> NativeInteger128;
typedef intnat::NativeVector<NativeInteger128> NativeVector128;
#elif NATIVEINT == 64
typedef intnat::NativeIntegerT<uint64_t> NativeInteger64;
typedef intnat::NativeVector<NativeInteger64> NativeVector64;
#elif NATIVEINT == 32
typedef intnat::NativeIntegerT<uint32_t> NativeInteger32;
typedef intnat::NativeVector<NativeInteger32> NativeVector32;
#endif

#if NATIVEINT == 128
typedef NativeInteger128 NativeInteger;
typedef NativeVector128 NativeVector;
#elif NATIVEINT == 64
typedef NativeInteger64 NativeInteger;
typedef NativeVector64 NativeVector;
#elif NATIVEINT == 32  // NOLINT
typedef NativeInteger32 NativeInteger;
typedef NativeVector32 NativeVector;
#endif


#endif /* SRC_CORE_INCLUDE_MATH_HAL_INTNAT_BACKENDNAT_H_ */
