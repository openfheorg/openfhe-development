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

#include "lattice/constants-lattice.h"
#include "utils/exception.h"

#include <string>
#include <ostream>

namespace lbcrypto {

SecretKeyDist convertToSecretKeyDist(const std::string& str) {
    if (str == "GAUSSIAN")
        return GAUSSIAN;
    else if (str == "UNIFORM_TERNARY")
        return UNIFORM_TERNARY;
    else if (str == "SPARSE_TERNARY")
        return SPARSE_TERNARY;
    // else if (str == "BINARY")
    //     return BINARY;

    std::string errMsg(std::string("Unknown SecretKeyDist ") + str);
    OPENFHE_THROW(config_error, errMsg);
}
SecretKeyDist convertToSecretKeyDist(uint32_t num) {
    auto keyDist = static_cast<SecretKeyDist>(num);
    switch (keyDist) {
        case GAUSSIAN:
        case UNIFORM_TERNARY:
        case SPARSE_TERNARY:
            // case BINARY:
            return keyDist;
        default:
            break;
    }

    std::string errMsg(std::string("Unknown value for SecretKeyDist ") + std::to_string(num));
    OPENFHE_THROW(config_error, errMsg);
}
std::ostream& operator<<(std::ostream& s, SecretKeyDist m) {
    switch (m) {
        case GAUSSIAN:
            s << "GAUSSIAN";
            break;
        case UNIFORM_TERNARY:
            s << "UNIFORM_TERNARY";
            break;
        case SPARSE_TERNARY:
            s << "SPARSE_TERNARY";
            break;
            // case BINARY:
            //     s << "BINARY";
            break;
        default:
            s << "UNKNOWN";
            break;
    }
    return s;
}

}  // namespace lbcrypto
