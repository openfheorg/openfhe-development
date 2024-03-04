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
  Functions for scheme id enums
 */

#include "scheme/scheme-id.h"
#include "utils/exception.h"
#include <ostream>
#include <string>

namespace lbcrypto {

SCHEME convertToSCHEME(const std::string& str) {
    if (str == "CKKSRNS_SCHEME")
        return CKKSRNS_SCHEME;
    else if (str == "BFVRNS_SCHEME")
        return BFVRNS_SCHEME;
    else if (str == "BGVRNS_SCHEME")
        return BGVRNS_SCHEME;

    std::string errMsg(std::string("Unknown schemeId ") + str);
    OPENFHE_THROW(errMsg);
}

std::string convertToString(SCHEME schemeId) noexcept {
    switch (schemeId) {
        case CKKSRNS_SCHEME:
            return "CKKSRNS_SCHEME";
        case BFVRNS_SCHEME:
            return "BFVRNS_SCHEME";
        case BGVRNS_SCHEME:
            return "BGVRNS_SCHEME";
        default:
            return "INVALID_SCHEME[" + std::to_string(schemeId) + "]";
    }
}

std::ostream& operator<<(std::ostream& os, SCHEME schemeId) {
    switch (schemeId) {
        case CKKSRNS_SCHEME:
            os << "CKKSRNS";
            break;
        case BFVRNS_SCHEME:
            os << "BFVRNS";
            break;
        case BGVRNS_SCHEME:
            os << "BGVRNS";
            break;
        default:
            std::string errMsg(std::string("Unknown schemeId ") + std::to_string(schemeId));
            OPENFHE_THROW(errMsg);
    }

    return os;
}

}  // namespace lbcrypto
