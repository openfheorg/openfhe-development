// @file backend.h This file contains the functionality to switch between math
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

#ifndef LBCRYPTO_MATH_BACKEND_H
#define LBCRYPTO_MATH_BACKEND_H

#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <type_traits>
#include <typeinfo>
#include <vector>

#include "config_core.h"
#include "version.h"

#include "interface.h"
#include "utils/debug.h"
#include "utils/exception.h"
#include "utils/inttypes.h"
#include "utils/memory.h"
#include "utils/palisadebase64.h"
#include "utils/parallel.h"
#include "utils/serializable.h"

// use of MS VC is not permitted because of various incompatibilities
#ifdef _MSC_VER
#error "MSVC COMPILER IS NOT SUPPORTED"
#endif

namespace bigintnat {

template <typename I>
class NativeIntegerT;

#if NATIVEINT == 128
#define MAX_MODULUS_SIZE 121
using BasicInteger = unsigned __int128;
typedef NativeIntegerT<unsigned __int128> NativeInteger;
typedef NativeIntegerT<unsigned __int128> NativeInteger128;
#elif NATIVEINT == 64 && !defined(HAVE_INT128)
#define MAX_MODULUS_SIZE 58
using BasicInteger = uint64_t;
typedef NativeIntegerT<uint64_t> NativeInteger;
typedef NativeIntegerT<uint64_t> NativeInteger64;
#elif NATIVEINT == 64 && defined(HAVE_INT128)
#define MAX_MODULUS_SIZE 60
using BasicInteger = uint64_t;
typedef NativeIntegerT<uint64_t> NativeInteger;
typedef NativeIntegerT<uint64_t> NativeInteger64;
#elif NATIVEINT == 32  // NOLINT
#define MAX_MODULUS_SIZE 28
using BasicInteger = uint32_t;
typedef NativeIntegerT<uint32_t> NativeInteger;
typedef NativeIntegerT<uint32_t> NativeInteger32;
#endif

}  // namespace bigintnat

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

////////// bigintfxd code
typedef uint32_t integral_dtype;

/** Define the mapping for BigInteger
    3500 is the maximum bit width supported by BigIntegers, large enough for
most use cases The bitwidth can be decreased to the least value still supporting
BigInteger operations for a specific application - to achieve smaller runtimes
**/
#ifndef BigIntegerBitLength
#if (NATIVEINT < 128)
#define BigIntegerBitLength 3500  // for 32-bit and 64-bit native backend
#else
#define BigIntegerBitLength 8000  // for 128-bit native backend
#endif
#endif

#if BigIntegerBitLength < 600
#error "BigIntegerBitLength is too small"
#endif

inline const std::string& GetMathBackendParameters() {
  static std::string id =
      "Backend " + std::to_string(MATHBACKEND) +
      (MATHBACKEND == 2
           ? " internal int size " +
                 std::to_string(sizeof(integral_dtype) * 8) + " BitLength " +
                 std::to_string(BigIntegerBitLength)
           : "");
  return id;
}

#include "bigintfxd/mubintvecfxd.h"
#include "bigintfxd/ubintfxd.h"
static_assert(bigintfxd::DataTypeChecker<integral_dtype>::value,
              "Data type provided is not supported in BigInteger");

////////// for bigintdyn, decide if you want 32 bit or 64 bit underlying
/// integers in the implementation
#define UBINT_32
// #define UBINT_64

#ifdef UBINT_32
#define MATH_UBBITS 32
typedef uint32_t expdtype;
#undef UBINT_64  // cant have both accidentally
#endif

#ifdef UBINT_64
#define MATH_UBBITS 64
typedef uint64_t expdtype;
#undef UBINT_32  // cant have both accidentally
#endif

#include "bigintdyn/mubintvecdyn.h"  // rings of ubints
#include "bigintdyn/ubintdyn.h"  // dynamically sized unsigned big integers or ubints

namespace bigintdyn {
/** Define the mapping for ExpBigInteger (experimental) */
typedef ubint<expdtype> xubint;

/** Define the mapping for modulo Big Integer Vector */
typedef mubintvec<xubint> xmubintvec;
}  // namespace bigintdyn

#ifdef WITH_NTL

#include "bigintntl/mubintvecntl.h"  // rings of such
#include "bigintntl/ubintntl.h"      // experimental gmp unsigned big ints

namespace bigintntl {
typedef NTL::myZZ ubint;
}

using M6Integer = NTL::myZZ;
using M6Vector = NTL::myVecP<M6Integer>;

#endif

// typedefs for the known math backends
using M2Integer = bigintfxd::BigInteger<integral_dtype, BigIntegerBitLength>;
using M2Vector = bigintfxd::BigVectorImpl<M2Integer>;
using M4Integer = bigintdyn::xubint;
using M4Vector = bigintdyn::xmubintvec;

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

#if NATIVEINT == 128
typedef unsigned __int128 DoubleNativeInt;
typedef unsigned __int128 uint128_t;
typedef __int128 int128_t;
#elif NATIVEINT == 64 && defined(HAVE_INT128)
typedef unsigned __int128 DoubleNativeInt;
typedef unsigned __int128 uint128_t;
typedef __int128 int128_t;
#elif NATIVEINT == 64 && !defined(HAVE_INT128)
typedef uint64_t DoubleNativeInt;
typedef uint64_t uint128_t;
typedef int64_t int128_t;
#elif NATIVEINT == 32
typedef uint64_t DoubleNativeInt;
#endif

#if MATHBACKEND == 2

using BigInteger = M2Integer;
using BigVector = M2Vector;

#endif

#if MATHBACKEND == 4

#ifdef UBINT_64
#error MATHBACKEND 4 with UBINT_64 currently does not work do not use.
#endif

using BigInteger = M4Integer;
using BigVector = M4Vector;

#endif

#if MATHBACKEND == 6

using BigInteger = M6Integer;
using BigVector = M6Vector;

#endif

}  // namespace lbcrypto

////////// definitions for native integer and native vector
#include <initializer_list>
#include "bigintnat/mubintvecnat.h"
#include "bigintnat/ubintnat.h"

#if NATIVEINT == 128
typedef bigintnat::NativeIntegerT<unsigned __int128> NativeInteger128;
typedef bigintnat::NativeVector<NativeInteger128> NativeVector128;
#elif NATIVEINT == 64
typedef bigintnat::NativeIntegerT<uint64_t> NativeInteger64;
typedef bigintnat::NativeVector<NativeInteger64> NativeVector64;
#elif NATIVEINT == 32
typedef bigintnat::NativeIntegerT<uint32_t> NativeInteger32;
typedef bigintnat::NativeVector<NativeInteger32> NativeVector32;
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

#endif
