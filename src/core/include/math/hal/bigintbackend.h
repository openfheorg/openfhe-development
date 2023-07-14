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

#ifndef __BIGINTBACKEND_H__
#define __BIGINTBACKEND_H__

#include "config_core.h"

#include "math/hal/bigintfxd/backendfxd.h"
#include "math/hal/bigintdyn/backenddyn.h"
#include "math/hal/bigintntl/backendntl.h"

/**
 * @namespace bigintbackend
 * The namespace of bigintbackend
 */
namespace bigintbackend {

/*! Define the underlying default math implementation being used by defining
 * MATHBACKEND */

// Each math backend is defined in its own namespace, and can be used at any
// time by referencing the objects in its namespace

// Selecting a math backend by defining MATHBACKEND means defining which
// underlying implementation is the default BigInteger and BigVector

#if MATHBACKEND == 2
// Uses bigintfxd:: definition as default
// Implemented as an array of integers
// Configurable maximum bit length and type of underlying integer

using BigInteger = M2Integer;
using BigVector  = M2Vector;

#elif MATHBACKEND == 4
// This uses bigintdyn:: definition as default
// This backend supports arbitrary bitwidths; no memory pool is
//     used; can grow up to RAM limitation
// Configurable type of underlying integer (either 32 or 64 bit)

using BigInteger = M4Integer;
using BigVector  = M4Vector;

#elif MATHBACKEND == 6
//     This uses bigintntl:: definition as default
//     GMP 6.1.2 / NTL 10.3.0 backend

using BigInteger = M6Integer;
using BigVector  = M6Vector;

#else

    #error "Configuration Error: MATHBACKEND value not 2, 4, or 6"

#endif

}  // namespace bigintbackend

#endif  // __BIGINTBACKEND_H__
