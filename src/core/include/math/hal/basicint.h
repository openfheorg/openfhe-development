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

#ifndef __BASICINT_H__
#define __BASICINT_H__

#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
    #define MAX_MODULUS_SIZE 121
using BasicInteger = unsigned __int128;
typedef unsigned __int128 DoubleNativeInt;
typedef unsigned __int128 uint128_t;
typedef __int128 int128_t;
#elif NATIVEINT == 64 && defined(HAVE_INT128)
    #define MAX_MODULUS_SIZE 60
using BasicInteger = uint64_t;
typedef unsigned __int128 DoubleNativeInt;
typedef unsigned __int128 uint128_t;
typedef __int128 int128_t;
#elif NATIVEINT == 64 && !defined(HAVE_INT128)
    #define MAX_MODULUS_SIZE 58
using BasicInteger = uint64_t;
typedef uint64_t DoubleNativeInt;
typedef uint64_t uint128_t;
typedef int64_t int128_t;
#elif NATIVEINT == 32
    #define MAX_MODULUS_SIZE 28
using BasicInteger = uint32_t;
typedef uint64_t DoubleNativeInt;
#endif

#endif  // __BASICINT_H__
