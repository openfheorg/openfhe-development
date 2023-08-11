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

#ifndef _CONSTANTS_LATTICE_H_
#define _CONSTANTS_LATTICE_H_

#include <iosfwd>
#include <string>
#include <cstdint>

namespace lbcrypto {

/**
 * @brief Lists all modes for RLWE schemes, such as BGV and BFV, and for LWE schemes, such as DM and TFHE
 */
enum SecretKeyDist {
    GAUSSIAN        = 0,
    UNIFORM_TERNARY = 1,  // Default value, all schemes support this key distribution
    SPARSE_TERNARY  = 2,
    // BINARY = 3, // Future implementation
};
SecretKeyDist convertToSecretKeyDist(const std::string& str);
SecretKeyDist convertToSecretKeyDist(uint32_t num);
std::ostream& operator<<(std::ostream& s, SecretKeyDist m);

}  // namespace lbcrypto

#endif  // _CONSTANTS_LATTICE_H_
