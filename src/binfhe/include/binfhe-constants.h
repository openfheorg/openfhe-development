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

#ifndef _BINFHE_CONSTANTS_H_
#define _BINFHE_CONSTANTS_H_

#include "lattice/constants-lattice.h"

#include <cstdint>
#include <iosfwd>
#include <string>

namespace lbcrypto {

using LWEPlaintext        = int64_t;
using LWEPlaintextModulus = uint64_t;

/**
 * @brief Bootstrapping method
 */
enum BINFHE_METHOD {
    INVALID_METHOD = 0,
    AP,       // Ducas-Micciancio variant
    GINX,     // Chillotti-Gama-Georgieva-Izabachene variant
    LMKCDEY,  // Lee-Micciancio-Kim-Choi-Deryabin-Eom-Yoo variant, ia.cr/2022/198
};
std::ostream& operator<<(std::ostream& s, BINFHE_METHOD f);

/**
 * @brief Bootstrapping methods a predefined parameter set is configured for, one bit per BINFHE_METHOD
 */
enum BINFHE_METHOD_SET : uint32_t {
    FOR_AP         = 1u << AP,
    FOR_GINX       = 1u << GINX,
    FOR_LMKCDEY    = 1u << LMKCDEY,
    FOR_ANY_METHOD = FOR_GINX | FOR_LMKCDEY | FOR_AP,
};

/**
 * @brief Predefined parameter sets: name, the bootstrapping methods each may be used with, and the
 * approximate probability of failure. Sets without a method suffix are tuned for GINX but stay open to
 * every method for backward compatibility; the failure probability is stated for the tuned method only.
 * The list expands into BINFHE_PARAMSET, its name table and isMethodCompatible, so a new set is added
 * here and in the parameter table of binfhecontext.cpp only.
 */
// clang-format off
#define BINFHE_PARAMSET_LIST(X)                                                                                                            \
    /* NAME                    METHODS            DESCRIPTION                                                     : PROBABILITY OF FAILURE */ \
    X(TOY,                     FOR_ANY_METHOD) /* no security                                                     : 2^(-270) */ \
    X(MEDIUM,                  FOR_ANY_METHOD) /* 108 bits of security for classical and 100 bits for quantum     : 2^(-40) */ \
    X(STD128,                  FOR_ANY_METHOD) /* more than 128 bits of security for classical computer attacks   : 2^(-68) */ \
    X(STD128_3,                FOR_ANY_METHOD) /* STD128 for 3 binary inputs                                      : 2^(-67) */ \
    X(STD128_4,                FOR_ANY_METHOD) /* STD128 for 4 binary inputs                                      : 2^(-66) */ \
    X(STD128Q,                 FOR_ANY_METHOD) /* more than 128 bits of security for quantum attacks              : 2^(-68) */ \
    X(STD128Q_3,               FOR_ANY_METHOD) /* STD128Q for 3 binary inputs                                     : 2^(-67) */ \
    X(STD128Q_4,               FOR_ANY_METHOD) /* STD128Q for 4 binary inputs                                     : 2^(-67) */ \
    X(STD192,                  FOR_ANY_METHOD) /* more than 192 bits of security for classical computer attacks   : 2^(-67) */ \
    X(STD192_3,                FOR_ANY_METHOD) /* STD192 for 3 binary inputs                                      : 2^(-67) */ \
    X(STD192_4,                FOR_ANY_METHOD) /* STD192 for 4 binary inputs                                      : 2^(-67) */ \
    X(STD192Q,                 FOR_ANY_METHOD) /* more than 192 bits of security for quantum attacks              : 2^(-67) */ \
    X(STD192Q_3,               FOR_ANY_METHOD) /* STD192Q for 3 binary inputs                                     : 2^(-67) */ \
    X(STD192Q_4,               FOR_ANY_METHOD) /* STD192Q for 4 binary inputs                                     : 2^(-67) */ \
    X(STD256,                  FOR_ANY_METHOD) /* more than 256 bits of security for classical computer attacks   : 2^(-67) */ \
    X(STD256_3,                FOR_ANY_METHOD) /* STD256 for 3 binary inputs                                      : 2^(-67) */ \
    X(STD256_4,                FOR_ANY_METHOD) /* STD256 for 4 binary inputs                                      : 2^(-67) */ \
    X(STD256Q,                 FOR_ANY_METHOD) /* more than 256 bits of security for quantum attacks              : 2^(-67) */ \
    X(STD256Q_3,               FOR_ANY_METHOD) /* STD256Q for 3 binary inputs                                     : 2^(-67) */ \
    X(STD256Q_4,               FOR_ANY_METHOD) /* STD256Q for 4 binary inputs                                     : 2^(-67) */ \
    X(LPF_STD128,              FOR_ANY_METHOD) /* STD128 configured with lower probability of failures            : 2^(-134) */ \
    X(LPF_STD128_3,            FOR_ANY_METHOD) /* LPF_STD128 for 3 binary inputs                                  : 2^(-133) */ \
    X(LPF_STD128_4,            FOR_ANY_METHOD) /* LPF_STD128 for 4 binary inputs                                  : 2^(-134) */ \
    X(LPF_STD128Q,             FOR_ANY_METHOD) /* STD128Q configured with lower probability of failures           : 2^(-134) */ \
    X(LPF_STD128Q_3,           FOR_ANY_METHOD) /* LPF_STD128Q for 3 binary inputs                                 : 2^(-133) */ \
    X(LPF_STD128Q_4,           FOR_ANY_METHOD) /* LPF_STD128Q for 4 binary inputs                                 : 2^(-134) */ \
    X(LPF_STD192,              FOR_ANY_METHOD) /* STD192 configured with lower probability of failures            : 2^(-136) */ \
    X(LPF_STD192_3,            FOR_ANY_METHOD) /* LPF_STD192 for 3 binary inputs                                  : 2^(-135) */ \
    X(LPF_STD192_4,            FOR_ANY_METHOD) /* LPF_STD192 for 4 binary inputs                                  : 2^(-134) */ \
    X(LPF_STD192Q,             FOR_ANY_METHOD) /* STD192Q configured with lower probability of failures           : 2^(-136) */ \
    X(LPF_STD192Q_3,           FOR_ANY_METHOD) /* LPF_STD192Q for 3 binary inputs                                 : 2^(-135) */ \
    X(LPF_STD192Q_4,           FOR_ANY_METHOD) /* LPF_STD192Q for 4 binary inputs                                 : 2^(-133) */ \
    X(LPF_STD256,              FOR_ANY_METHOD) /* STD256 configured with lower probability of failures            : 2^(-136) */ \
    X(LPF_STD256_3,            FOR_ANY_METHOD) /* LPF_STD256 for 3 binary inputs                                  : 2^(-134) */ \
    X(LPF_STD256_4,            FOR_ANY_METHOD) /* LPF_STD256 for 4 binary inputs                                  : 2^(-133) */ \
    X(LPF_STD256Q,             FOR_ANY_METHOD) /* STD256Q configured with lower probability of failures           : 2^(-135) */ \
    X(LPF_STD256Q_3,           FOR_ANY_METHOD) /* LPF_STD256Q for 3 binary inputs                                 : 2^(-134) */ \
    X(STD128_LMKCDEY,          FOR_LMKCDEY)    /* STD128 optimized for LMKCDEY                                    : 2^(-70) */ \
    X(STD128_3_LMKCDEY,        FOR_LMKCDEY)    /* STD128_LMKCDEY for 3 binary inputs                              : 2^(-67) */ \
    X(STD128_4_LMKCDEY,        FOR_LMKCDEY)    /* STD128_LMKCDEY for 4 binary inputs                              : 2^(-66) */ \
    X(STD128Q_LMKCDEY,         FOR_LMKCDEY)    /* STD128Q optimized for LMKCDEY                                   : 2^(-68) */ \
    X(STD128Q_3_LMKCDEY,       FOR_LMKCDEY)    /* STD128Q_LMKCDEY for 3 binary inputs                             : 2^(-67) */ \
    X(STD128Q_4_LMKCDEY,       FOR_LMKCDEY)    /* STD128Q_LMKCDEY for 4 binary inputs                             : 2^(-68) */ \
    X(STD192_LMKCDEY,          FOR_LMKCDEY)    /* STD192 optimized for LMKCDEY (using Gaussian secrets)           : 2^(-67) */ \
    X(STD192_3_LMKCDEY,        FOR_LMKCDEY)    /* STD192_LMKCDEY for 3 binary inputs                              : 2^(-67) */ \
    X(STD192_4_LMKCDEY,        FOR_LMKCDEY)    /* STD192_LMKCDEY for 4 binary inputs                              : 2^(-67) */ \
    X(STD192Q_LMKCDEY,         FOR_LMKCDEY)    /* STD192Q optimized for LMKCDEY (using Gaussian secrets)          : 2^(-67) */ \
    X(STD192Q_3_LMKCDEY,       FOR_LMKCDEY)    /* STD192Q_LMKCDEY for 3 binary inputs                             : 2^(-67) */ \
    X(STD192Q_4_LMKCDEY,       FOR_LMKCDEY)    /* STD192Q_LMKCDEY for 4 binary inputs                             : 2^(-67) */ \
    X(STD256_LMKCDEY,          FOR_LMKCDEY)    /* STD256 optimized for LMKCDEY (using Gaussian secrets)           : 2^(-67) */ \
    X(STD256_3_LMKCDEY,        FOR_LMKCDEY)    /* STD256_LMKCDEY for 3 binary inputs                              : 2^(-67) */ \
    X(STD256_4_LMKCDEY,        FOR_LMKCDEY)    /* STD256_LMKCDEY for 4 binary inputs                              : 2^(-67) */ \
    X(STD256Q_LMKCDEY,         FOR_LMKCDEY)    /* STD256Q optimized for LMKCDEY (using Gaussian secrets)          : 2^(-66) */ \
    X(STD256Q_3_LMKCDEY,       FOR_LMKCDEY)    /* STD256Q_LMKCDEY for 3 binary inputs                             : 2^(-67) */ \
    X(STD256Q_4_LMKCDEY,       FOR_LMKCDEY)    /* STD256Q_LMKCDEY for 4 binary inputs                             : 2^(-67) */ \
    X(LPF_STD128_LMKCDEY,      FOR_LMKCDEY)    /* LPF_STD128 optimized for LMKCDEY                                : 2^(-134) */ \
    X(LPF_STD128_3_LMKCDEY,    FOR_LMKCDEY)    /* LPF_STD128_LMKCDEY for 3 binary inputs                          : 2^(-133) */ \
    X(LPF_STD128_4_LMKCDEY,    FOR_LMKCDEY)    /* LPF_STD128_LMKCDEY for 4 binary inputs                          : 2^(-135) */ \
    X(LPF_STD128Q_LMKCDEY,     FOR_LMKCDEY)    /* LPF_STD128Q optimized for LMKCDEY                               : 2^(-134) */ \
    X(LPF_STD128Q_3_LMKCDEY,   FOR_LMKCDEY)    /* LPF_STD128Q_LMKCDEY for 3 binary inputs                         : 2^(-133) */ \
    X(LPF_STD128Q_4_LMKCDEY,   FOR_LMKCDEY)    /* LPF_STD128Q_LMKCDEY for 4 binary inputs                         : 2^(-134) */ \
    X(LPF_STD192_LMKCDEY,      FOR_LMKCDEY)    /* LPF_STD192 optimized for LMKCDEY                                : 2^(-136) */ \
    X(LPF_STD192_3_LMKCDEY,    FOR_LMKCDEY)    /* LPF_STD192_LMKCDEY for 3 binary inputs                          : 2^(-135) */ \
    X(LPF_STD192_4_LMKCDEY,    FOR_LMKCDEY)    /* LPF_STD192_LMKCDEY for 4 binary inputs                          : 2^(-134) */ \
    X(LPF_STD192Q_LMKCDEY,     FOR_LMKCDEY)    /* LPF_STD192Q optimized for LMKCDEY                               : 2^(-136) */ \
    X(LPF_STD192Q_3_LMKCDEY,   FOR_LMKCDEY)    /* LPF_STD192Q_LMKCDEY for 3 binary inputs                         : 2^(-135) */ \
    X(LPF_STD192Q_4_LMKCDEY,   FOR_LMKCDEY)    /* LPF_STD192Q_LMKCDEY for 4 binary inputs                         : 2^(-133) */ \
    X(LPF_STD256_LMKCDEY,      FOR_LMKCDEY)    /* LPF_STD256 optimized for LMKCDEY                                : 2^(-135) */ \
    X(LPF_STD256_3_LMKCDEY,    FOR_LMKCDEY)    /* LPF_STD256_LMKCDEY for 3 binary inputs                          : 2^(-134) */ \
    X(LPF_STD256_4_LMKCDEY,    FOR_LMKCDEY)    /* LPF_STD256_LMKCDEY for 4 binary inputs                          : 2^(-133) */ \
    X(LPF_STD256Q_LMKCDEY,     FOR_LMKCDEY)    /* LPF_STD256Q optimized for LMKCDEY                               : 2^(-135) */ \
    X(LPF_STD256Q_3_LMKCDEY,   FOR_LMKCDEY)    /* LPF_STD256Q_LMKCDEY for 3 binary inputs                         : 2^(-134) */ \
    X(STD128_AP,               FOR_AP)         /* STD128 optimized for AP                                         : 2^(-68) */ \
    X(STD128_3_AP,             FOR_AP)         /* STD128_AP for 3 binary inputs                                   : 2^(-67) */ \
    X(STD128_4_AP,             FOR_AP)         /* STD128_AP for 4 binary inputs                                   : 2^(-66) */ \
    X(STD128Q_AP,              FOR_AP)         /* STD128Q optimized for AP                                        : 2^(-68) */ \
    X(STD128Q_3_AP,            FOR_AP)         /* STD128Q_AP for 3 binary inputs                                  : 2^(-67) */ \
    X(STD128Q_4_AP,            FOR_AP)         /* STD128Q_AP for 4 binary inputs                                  : 2^(-68) */ \
    X(STD192_AP,               FOR_AP)         /* STD192 optimized for AP                                         : 2^(-67) */ \
    X(STD192_3_AP,             FOR_AP)         /* STD192_AP for 3 binary inputs                                   : 2^(-67) */ \
    X(STD192_4_AP,             FOR_AP)         /* STD192_AP for 4 binary inputs                                   : 2^(-67) */ \
    X(STD192Q_AP,              FOR_AP)         /* STD192Q optimized for AP                                        : 2^(-67) */ \
    X(STD192Q_3_AP,            FOR_AP)         /* STD192Q_AP for 3 binary inputs                                  : 2^(-67) */ \
    X(STD192Q_4_AP,            FOR_AP)         /* STD192Q_AP for 4 binary inputs                                  : 2^(-67) */ \
    X(STD256_AP,               FOR_AP)         /* STD256 optimized for AP                                         : 2^(-66) */ \
    X(STD256_3_AP,             FOR_AP)         /* STD256_AP for 3 binary inputs                                   : 2^(-67) */ \
    X(STD256_4_AP,             FOR_AP)         /* STD256_AP for 4 binary inputs                                   : 2^(-67) */ \
    X(STD256Q_AP,              FOR_AP)         /* STD256Q optimized for AP (using Gaussian secrets)               : 2^(-66) */ \
    X(STD256Q_3_AP,            FOR_AP)         /* STD256Q_AP for 3 binary inputs                                  : 2^(-67) */ \
    X(STD256Q_4_AP,            FOR_AP)         /* STD256Q_AP for 4 binary inputs                                  : 2^(-67) */ \
    X(LPF_STD128_AP,           FOR_AP)         /* LPF_STD128 optimized for AP                                     : 2^(-134) */ \
    X(LPF_STD128_3_AP,         FOR_AP)         /* LPF_STD128_AP for 3 binary inputs                               : 2^(-133) */ \
    X(LPF_STD128_4_AP,         FOR_AP)         /* LPF_STD128_AP for 4 binary inputs                               : 2^(-134) */ \
    X(LPF_STD128Q_AP,          FOR_AP)         /* LPF_STD128Q optimized for AP                                    : 2^(-134) */ \
    X(LPF_STD128Q_3_AP,        FOR_AP)         /* LPF_STD128Q_AP for 3 binary inputs                              : 2^(-133) */ \
    X(LPF_STD128Q_4_AP,        FOR_AP)         /* LPF_STD128Q_AP for 4 binary inputs                              : 2^(-134) */ \
    X(LPF_STD192_AP,           FOR_AP)         /* LPF_STD192 optimized for AP                                     : 2^(-134) */ \
    X(LPF_STD192_3_AP,         FOR_AP)         /* LPF_STD192_AP for 3 binary inputs                               : 2^(-136) */ \
    X(LPF_STD192_4_AP,         FOR_AP)         /* LPF_STD192_AP for 4 binary inputs                               : 2^(-133) */ \
    X(LPF_STD192Q_AP,          FOR_AP)         /* LPF_STD192Q optimized for AP                                    : 2^(-135) */ \
    X(LPF_STD192Q_3_AP,        FOR_AP)         /* LPF_STD192Q_AP for 3 binary inputs                              : 2^(-134) */ \
    X(LPF_STD192Q_4_AP,        FOR_AP)         /* LPF_STD192Q_AP for 4 binary inputs                              : 2^(-133) */ \
    X(LPF_STD256_AP,           FOR_AP)         /* LPF_STD256 optimized for AP                                     : 2^(-134) */ \
    X(LPF_STD256_3_AP,         FOR_AP)         /* LPF_STD256_AP for 3 binary inputs                               : 2^(-134) */ \
    X(LPF_STD256_4_AP,         FOR_AP)         /* LPF_STD256_AP for 4 binary inputs                               : 2^(-133) */ \
    X(LPF_STD256Q_AP,          FOR_AP)         /* LPF_STD256Q optimized for AP                                    : 2^(-135) */ \
    X(LPF_STD256Q_3_AP,        FOR_AP)         /* LPF_STD256Q_AP for 3 binary inputs                              : 2^(-135) */ \
    X(SIGNED_MOD_TEST,         FOR_ANY_METHOD) /* special parameter set for confirming the signed modular reduction in the accumulator updates works correctly: 2^(-45) */ \
    X(TOY_MULTI_BASE,          FOR_ANY_METHOD) /* no security; multiple gadget bases for testing                  : not evaluated */

enum BINFHE_PARAMSET {
#define BINFHE_PARAMSET_ENUMERATOR(name, methods) name,
    BINFHE_PARAMSET_LIST(BINFHE_PARAMSET_ENUMERATOR)
#undef BINFHE_PARAMSET_ENUMERATOR
};
// clang-format on
std::ostream& operator<<(std::ostream& s, BINFHE_PARAMSET f);
BINFHE_PARAMSET convertToBINFHE_PARAMSET(const std::string& str);

/**
 * @brief Type of ciphertext generated by the Encrypt method
 */
enum BINFHE_OUTPUT {
    INVALID_OUTPUT = 0,
    FRESH,         // a fresh encryption (deprecated)
    BOOTSTRAPPED,  // a freshly encrypted ciphertext is bootstrapped (deprecated)
    LARGE_DIM,     // a fresh encryption with dimension N
    SMALL_DIM,     // a freshly encrypted ciphertext of dimension N and modulus Q switched to n and q
};
std::ostream& operator<<(std::ostream& s, BINFHE_OUTPUT f);

/**
 * @brief Type of gates supported, with two, three or four inputs
 */
enum BINGATE { OR, AND, NOR, NAND, XOR, XNOR, MAJORITY, AND3, OR3, AND4, OR4, XOR_FAST, XNOR_FAST, CMUX };
std::ostream& operator<<(std::ostream& s, BINGATE f);

/**
 * @brief Type of ciphertext generated by the Encrypt method
 */
enum KEYGEN_MODE {
    SYM_ENCRYPT = 0,  // symmetric (secret) key encryption
    PUB_ENCRYPT,      // public key encryption
};
std::ostream& operator<<(std::ostream& s, KEYGEN_MODE f);

void isMethodCompatible(BINFHE_METHOD m, BINFHE_PARAMSET p);

}  // namespace lbcrypto

#endif  // _BINFHE_CONSTANTS_H_
