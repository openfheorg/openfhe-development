// @file backenddyn.h This file contains the definitions for MATHBACKEND 4
// also known as the dynamic multi-precision backend. This backend supports
// arbitrary bitwidths; no memory pool is used; can grow up to RAM limitation
// Configurable type of underlying integer (either 32 or 64 bit)
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

#ifndef SRC_CORE_INCLUDE_MATH_HAL_BIGINTDYN_BACKENDDYN_H_
#define SRC_CORE_INCLUDE_MATH_HAL_BIGINTDYN_BACKENDDYN_H_

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

#include "math/hal/bigintdyn/mubintvecdyn.h"  // rings of ubints
#include "math/hal/bigintdyn/ubintdyn.h"  // dynamically sized unsigned big integers or ubints

namespace bigintdyn {

/** Define the mapping for ExpBigInteger (experimental) */
typedef ubint<expdtype> xubint;

/** Define the mapping for modulo Big Integer Vector */
typedef mubintvec<xubint> xmubintvec;

} // namespace bigintdyn

using M4Integer = bigintdyn::xubint;
using M4Vector = bigintdyn::xmubintvec;

#endif /* SRC_CORE_INCLUDE_MATH_HAL_BIGINTDYN_BACKENDDYN_H_ */
