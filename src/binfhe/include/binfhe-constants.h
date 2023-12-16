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
enum BINFHE_PARAMSET {
    TOY,                // no security
    MEDIUM,             // 108 bits of security for classical and 100 bits for quantum
    STD128_LMKCDEY,     // Optimized for LMKCDEY (using Gaussian secrets) -
                        // more than 128 bits of security for classical computer attacks -
                        // optimize runtime by finding a non-power-of-two n
    STD128_AP,          // Optimized for AP (has higher failure probability for GINX) -
                        // more than 128 bits of security for classical computer attacks -
                        // optimize runtime by finding a non-power-of-two n
    STD128,             // more than 128 bits of security for classical computer attacks -
                        // optimize runtime by finding a non-power-of-two n
    STD192,             // more than 192 bits of security for classical computer attacks -
                        // optimize runtime by finding a non-power-of-two n
    STD256,             // more than 256 bits of security for classical computer attacks -
                        // optimize runtime by finding a non-power-of-two n
    STD128Q,            // more than 128 bits of security for quantum attacks -
                        // optimize runtime by finding a non-power-of-two n
    STD128Q_LMKCDEY,    // Optimized for LMKCDEY (using Gaussian secrets) -
                        // more than 128 bits of security for quantum attacks -
                        // optimize runtime by finding a non-power-of-two n
    STD192Q,            // more than 192 bits of security for quantum attacks -
                        // optimize runtime by finding a non-power-of-two n
    STD256Q,            // more than 256 bits of security for quantum attacks -
                        // optimize runtime by finding a non-power-of-two n
    STD128_3,           // more than 128 bits of security for classical computer attacks -
                        // optimize runtime by finding a non-power-of-two n for 3 binary inputs
    STD128_3_LMKCDEY,   // Optimized for LMKCDEY (using Gaussian secrets) -
                        // more than 128 bits of security for classical computer attacks -
                        // optimize runtime by finding a non-power-of-two n for 3 binary inputs
    STD128Q_3,          // more than 128 bits of security for quantum computer attacks -
                        // optimize runtime by finding a non-power-of-two n for 3 binary inputs
    STD128Q_3_LMKCDEY,  // Optimized for LMKCDEY (using Gaussian secrets) -
                        // more than 128 bits of security for quantum computer attacks -
                        // optimize runtime by finding a non-power-of-two n for 3 binary inputs
    STD192Q_3,          // more than 192 bits of security for quantum computer attacks -
                        // optimize runtime by finding a non-power-of-two n for 3 binary inputs
    STD256Q_3,          // more than 256 bits of security for quantum computer attacks -
                        // optimize runtime by finding a non-power-of-two n for 3 binary inputs
    STD128_4,           // more than 128 bits of security for classical computer attacks -
                        // optimize runtime by finding a non-power-of-two n for 4 binary inputs
    STD128_4_LMKCDEY,   // Optimized for LMKCDEY (using Gaussian secrets) -
                        // more than 128 bits of security for classical computer attacks -
                        // optimize runtime by finding a non-power-of-two n for 4 binary inputs
    STD128Q_4,          // more than 128 bits of security for quantum computer attacks -
                        // optimize runtime by finding a non-power-of-two n for 4 binary inputs
    STD128Q_4_LMKCDEY,  // Optimized for LMKCDEY (using Gaussian secrets) -
                        // more than 128 bits of security for quantum computer attacks -
                        // optimize runtime by finding a non-power-of-two n for 4 binary inputs
    STD192Q_4,          // more than 192 bits of security for quantum computer attacks -
                        // optimize runtime by finding a non-power-of-two n for 4 binary inputs
    STD256Q_4,          // more than 256 bits of security for quantum computer attacks -
                        // optimize runtime by finding a non-power-of-two n for 4 binary inputs
    SIGNED_MOD_TEST     // special parameter set for confirming the signed modular
                        // reduction in the accumulator updates works correctly
};
std::ostream& operator<<(std::ostream& s, BINFHE_PARAMSET f);

/**
 * @brief Type of ciphertext generated by the Encrypt method
 */
enum BINFHE_OUTPUT {
    INVALID_OUTPUT = 0,
    FRESH,         // a fresh encryption
    BOOTSTRAPPED,  // a freshly encrypted ciphertext is bootstrapped
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

}  // namespace lbcrypto

#endif  // _BINFHE_CONSTANTS_H_
