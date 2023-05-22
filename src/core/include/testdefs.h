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
  common unit test definitions
 */

#ifndef TESTDEFS_H_
#define TESTDEFS_H_

#include "config_core.h"

// COMMON TESTING DEFINITIONS
extern bool TestB2;
extern bool TestB4;
#ifdef WITH_NTL
extern bool TestB6;
#endif
extern bool TestNative;

// macros for unit testing
#ifdef WITH_NTL
    #define RUN_BIG_BACKENDS_INT(FUNCTION, MESSAGE) \
        {                                           \
            if (TestB2) {                           \
                using T = M2Integer;                \
                FUNCTION<T>("BE2 " MESSAGE);        \
            }                                       \
            if (TestB4) {                           \
                using T = M4Integer;                \
                FUNCTION<T>("BE4 " MESSAGE);        \
            }                                       \
            if (TestB6) {                           \
                using T = M6Integer;                \
                FUNCTION<T>("BE6 " MESSAGE);        \
            }                                       \
        }
    #define RUN_BIG_BACKENDS(FUNCTION, MESSAGE) \
        {                                       \
            if (TestB2) {                       \
                using V = M2Vector;             \
                FUNCTION<V>("BE2 " MESSAGE);    \
            }                                   \
            if (TestB4) {                       \
                using V = M4Vector;             \
                FUNCTION<V>("BE4 " MESSAGE);    \
            }                                   \
            if (TestB6) {                       \
                using V = M6Vector;             \
                FUNCTION<V>("BE6 " MESSAGE);    \
            }                                   \
        }
    #define RUN_BIG_POLYS(FUNCTION, MESSAGE)     \
        {                                        \
            if (TestB2) {                        \
                using V = M2Poly;                \
                FUNCTION<V>("BE2Poly " MESSAGE); \
            }                                    \
            if (TestB4) {                        \
                using V = M4Poly;                \
                FUNCTION<V>("BE4Poly " MESSAGE); \
            }                                    \
            if (TestB6) {                        \
                using V = M6Poly;                \
                FUNCTION<V>("BE6Poly " MESSAGE); \
            }                                    \
        }

    #define RUN_BIG_DCRTPOLYS(FUNCTION, MESSAGE)     \
        {                                            \
            if (TestB2) {                            \
                using V = M2DCRTPoly;                \
                FUNCTION<V>("BE2DCRTPoly " MESSAGE); \
            }                                        \
            if (TestB4) {                            \
                using V = M4DCRTPoly;                \
                FUNCTION<V>("BE4DCRTPoly " MESSAGE); \
            }                                        \
            if (TestB6) {                            \
                using V = M6DCRTPoly;                \
                FUNCTION<V>("BE6DCRTPoly " MESSAGE); \
            }                                        \
        }
#else
    #define RUN_BIG_BACKENDS_INT(FUNCTION, MESSAGE) \
        {                                           \
            if (TestB2) {                           \
                using T = M2Integer;                \
                FUNCTION<T>("BE2 " MESSAGE);        \
            }                                       \
            if (TestB4) {                           \
                using T = M4Integer;                \
                FUNCTION<T>("BE4 " MESSAGE);        \
            }                                       \
        }
    #define RUN_BIG_BACKENDS(FUNCTION, MESSAGE) \
        {                                       \
            if (TestB2) {                       \
                using V = M2Vector;             \
                FUNCTION<V>("BE2 " MESSAGE);    \
            }                                   \
            if (TestB4) {                       \
                using V = M4Vector;             \
                FUNCTION<V>("BE4 " MESSAGE);    \
            }                                   \
        }
    #define RUN_BIG_POLYS(FUNCTION, MESSAGE)     \
        {                                        \
            if (TestB2) {                        \
                using V = M2Poly;                \
                FUNCTION<V>("BE2Poly " MESSAGE); \
            }                                    \
            if (TestB4) {                        \
                using V = M4Poly;                \
                FUNCTION<V>("BE4Poly " MESSAGE); \
            }                                    \
        }

    #define RUN_BIG_DCRTPOLYS(FUNCTION, MESSAGE)     \
        {                                            \
            if (TestB2) {                            \
                using V = M2DCRTPoly;                \
                FUNCTION<V>("BE2DCRTPoly " MESSAGE); \
            }                                        \
            if (TestB4) {                            \
                using V = M4DCRTPoly;                \
                FUNCTION<V>("BE4DCRTPoly " MESSAGE); \
            }                                        \
        }
#endif

#define RUN_ALL_POLYS(FUNCTION, MESSAGE)    \
    {                                       \
        RUN_BIG_POLYS(FUNCTION, MESSAGE)    \
        if (TestNative) {                   \
            using V = NativePoly;           \
            FUNCTION<V>("Native " MESSAGE); \
        }                                   \
    }

#define RUN_NATIVE_BACKENDS_INT(FUNCTION, MESSAGE) \
    {                                              \
        if (TestNative) {                          \
            {                                      \
                using T = NativeInteger;           \
                FUNCTION<T>("Native " MESSAGE);    \
            }                                      \
        }                                          \
    }

#define RUN_NATIVE_BACKENDS(FUNCTION, MESSAGE)  \
    {                                           \
        if (TestNative) {                       \
            {                                   \
                using V = NativeVector;         \
                FUNCTION<V>("Native " MESSAGE); \
            }                                   \
        }                                       \
    }

#define RUN_ALL_BACKENDS(FUNCTION, MESSAGE)    \
    {                                          \
        RUN_BIG_BACKENDS(FUNCTION, MESSAGE)    \
        RUN_NATIVE_BACKENDS(FUNCTION, MESSAGE) \
    }

#define RUN_ALL_BACKENDS_INT(FUNCTION, MESSAGE)    \
    {                                              \
        RUN_BIG_BACKENDS_INT(FUNCTION, MESSAGE)    \
        RUN_NATIVE_BACKENDS_INT(FUNCTION, MESSAGE) \
    }
#endif /* TESTDEFS_H_ */
