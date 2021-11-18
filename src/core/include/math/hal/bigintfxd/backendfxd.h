// @file backendfxd.h This file contains the definitions for MATHBACKEND 2
// also known as the fixed multi-precision backend. This backend supports
// fixed bitwidths; Uses bigintfxd:: definition as default
// Implemented as a vector of integers
// Configurable maximum bit length and type of underlying integer
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

#ifndef SRC_CORE_INCLUDE_MATH_HAL_BIGINTFXD_BACKENDFXD_H_
#define SRC_CORE_INCLUDE_MATH_HAL_BIGINTFXD_BACKENDFXD_H_

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

#include "math/hal/bigintfxd/mubintvecfxd.h"
#include "math/hal/bigintfxd/ubintfxd.h"

static_assert(bigintfxd::DataTypeChecker<integral_dtype>::value,
              "Data type provided is not supported in BigInteger");

using M2Integer = bigintfxd::BigInteger<integral_dtype, BigIntegerBitLength>;
using M2Vector = bigintfxd::BigVectorImpl<M2Integer>;

namespace bigintfxd {

} // namespace bigintfxd


#endif /* SRC_CORE_INCLUDE_MATH_HAL_BIGINTFXD_BACKENDFXD_H_ */
