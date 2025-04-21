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

namespace lbcrypto {

using LWEPlaintext        = int64_t;
using LWEPlaintextModulus = uint64_t;

/**
 * @brief Security levels for predefined parameter sets
 */
// clang-format off
enum BINFHE_PARAMSET {
//  NAME,                 // Description                                                     : Approximate Probability of Failure
    TOY,                  // no security                                                     : 2^(-360)
    MEDIUM,               // 108 bits of security for classical and 100 bits for quantum     : 2^(-70)
    STD128_AP,            // more than 128 bits of security for classical computer attacks   : 2^(-50)
    STD128,               // more than 128 bits of security for classical computer attacks   : 2^(-40)
    STD128_3,             // STD128 for 3 binary inputs                                      : 2^(-50)
    STD128_4,             // STD128 for 4 binary inputs                                      : 2^(-50)
    STD128Q,              // more than 128 bits of security for quantum attacks              : 2^(-40)
    STD128Q_3,            // STD128Q for 3 binary inputs                                     : 2^(-50)
    STD128Q_4,            // STD128Q for 4 binary inputs                                     : 2^(-50)
    STD192,               // more than 192 bits of security for classical computer attacks   : 2^(-40)
    STD192_3,             // STD192 for 3 binary inputs                                      : 2^(-60)
    STD192_4,             // STD192 for 4 binary inputs                                      : 2^(-70)
    STD192Q,              // more than 192 bits of security for quantum attacks              : 2^(-80)
    STD192Q_3,            // STD192Q for 3 binary inputs                                     : 2^(-80)
    STD192Q_4,            // STD192Q for 4 binary inputs                                     : 2^(-50)
    STD256,               // more than 256 bits of security for classical computer attacks   : 2^(-80)
    STD256_3,             // STD256 for 3 binary inputs                                      : 2^(-70)
    STD256_4,             // STD256 for 4 binary inputs                                      : 2^(-50)
    STD256Q,              // more than 256 bits of security for quantum attacks              : 2^(-60)
    STD256Q_3,            // STD256Q for 3 binary inputs                                     : 2^(-80)
    STD256Q_4,            // STD256Q for 4 binary inputs                                     : 2^(-50)
    STD128_LMKCDEY,       // STD128 optimized for LMKCDEY (using Gaussian secrets)           : 2^(-55)
    STD128_3_LMKCDEY,     // STD128_LMKCDEY for 3 binary inputs                              : 2^(-40)
    STD128_4_LMKCDEY,     // STD128_LMKCDEY for 4 binary inputs                              : 2^(-60)
    STD128Q_LMKCDEY,      // STD128Q optimized for LMKCDEY (using Gaussian secrets)          : 2^(-50)
    STD128Q_3_LMKCDEY,    // STD128Q_LMKCDEY for 3 binary inputs                             : 2^(-45)
    STD128Q_4_LMKCDEY,    // STD128Q_LMKCDEY for 4 binary inputs                             : 2^(-80)
    STD192_LMKCDEY,       // STD192 optimized for LMKCDEY (using Gaussian secrets)           : 2^(-60)
    STD192_3_LMKCDEY,     // STD192_LMKCDEY for 3 binary inputs                              : 2^(-60)
    STD192_4_LMKCDEY,     // STD192_LMKCDEY for 4 binary inputs                              : 2^(-70)
    STD192Q_LMKCDEY,      // STD192Q optimized for LMKCDEY (using Gaussian secrets)          : 2^(-70)
    STD192Q_3_LMKCDEY,    // STD192Q_LMKCDEY for 3 binary inputs                             : 2^(-55)
    STD192Q_4_LMKCDEY,    // STD192Q_LMKCDEY for 4 binary inputs                             : 2^(-70)
    STD256_LMKCDEY,       // STD256 optimized for LMKCDEY (using Gaussian secrets)           : 2^(-50)
    STD256_3_LMKCDEY,     // STD256_LMKCDEY for 3 binary inputs                              : 2^(-50)
    STD256_4_LMKCDEY,     // STD256_LMKCDEY for 4 binary inputs                              : 2^(-60)
    STD256Q_LMKCDEY,      // STD256Q optimized for LMKCDEY (using Gaussian secrets)          : 2^(-60)
    STD256Q_3_LMKCDEY,    // STD256Q_LMKCDEY for 3 binary inputs                             : 2^(-50)
    STD256Q_4_LMKCDEY,    // STD256Q_LMKCDEY for 4 binary inputs                             : 2^(-45)
    LPF_STD128,           // STD128 configured with lower probability of failures            : 2^(-220)
    LPF_STD128Q,          // STD128Q configured with lower probability of failures           : 2^(-75)
    LPF_STD128_LMKCDEY,   // LPF_STD128 optimized for LMKCDEY                                : 2^(-120)
    LPF_STD128Q_LMKCDEY,  // LPF_STD128Q optimized for LMKCDEY                               : 2^(-120)
    SIGNED_MOD_TEST       // special parameter set for confirming the signed modular         : 2^(-40)
                          // reduction in the accumulator updates works correctly
};
// clang-format on
std::ostream& operator<<(std::ostream& s, BINFHE_PARAMSET f);

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
