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

/*
  This file contains the definitions for MATHBACKEND 6 also known as the NTL multi-precision backend.
  This backend uses bigintntl:: definition as default.
  requires GMP 6.1.2 / NTL 10.3.0 backend
 */

//==================================================================================
// This file is included only if WITH_NTL is set to ON in CMakeLists.txt
//==================================================================================
#include "config_core.h"
#ifdef WITH_NTL

    #ifndef SRC_CORE_INCLUDE_MATH_HAL_BIGINTNTL_BACKENDNTL_H_
        #define SRC_CORE_INCLUDE_MATH_HAL_BIGINTNTL_BACKENDNTL_H_

        #include "math/hal/bigintntl/ubintntl.h"      // experimental gmp unsigned big ints
        #include "math/hal/bigintntl/mubintvecntl.h"  // rings of such
        #include "math/hal/bigintntl/transformntl.h"  // transforms for NTL

// Global alias for MATHBACKEND 6 Integer
using M6Integer = NTL::BigInteger;

// Global alias for MATHBACKEND 6 Vector
using M6Vector = NTL::BigVector;

    #endif  // SRC_CORE_INCLUDE_MATH_HAL_BIGINTNTL_BACKENDNTL_H_
#else
using M6Integer = void;
#endif  // WITH_NTL
