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
  This file contains the definitions for MATHBACKEND 4 also known as the dynamic multi-precision backend.
  This backend supports arbitrary bitwidths; no memory pool is used; can grow up to RAM limitation.
  Configurable type of underlying integer (either 32 or 64 bit)
 */

#include "config_core.h"
#ifdef WITH_BE4

    #ifndef SRC_CORE_INCLUDE_MATH_HAL_BIGINTDYN_BACKENDDYN_H_
        #define SRC_CORE_INCLUDE_MATH_HAL_BIGINTDYN_BACKENDDYN_H_

        #include "math/hal/bigintdyn/mubintvecdyn.h"  // rings of ubints
        #include "math/hal/bigintdyn/ubintdyn.h"      // dynamically sized unsigned big integers or ubints
        #include "math/hal/bigintdyn/transformdyn.h"  // transforms for dynamic

// Global alias for MATHBACKEND 4 Integer
using M4Integer = bigintdyn::BigInteger;

// Global alias for MATHBACKEND 4 Vector
using M4Vector = bigintdyn::BigVector;

    #endif /* SRC_CORE_INCLUDE_MATH_HAL_BIGINTDYN_BACKENDDYN_H_ */
#else
using M4Integer = void;
#endif
