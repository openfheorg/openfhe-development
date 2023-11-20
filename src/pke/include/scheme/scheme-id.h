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
  Defines scheme id enums
 */

#ifndef _SCHEME_ID_H_
#define _SCHEME_ID_H_

#include <iosfwd>
#include <string>

namespace lbcrypto {

//====================================================================================================================
enum SCHEME {
    INVALID_SCHEME = 0,
    CKKSRNS_SCHEME,
    BFVRNS_SCHEME,
    BGVRNS_SCHEME,
};
//====================================================================================================================
SCHEME convertToSCHEME(const std::string& str);
//====================================================================================================================
std::string convertToString(SCHEME schemeId) noexcept;
//====================================================================================================================
std::ostream& operator<<(std::ostream& os, SCHEME schemeId);
//====================================================================================================================
inline bool isCKKS(SCHEME schemeId) {
    return (schemeId == CKKSRNS_SCHEME);
}
inline bool isBFVRNS(SCHEME schemeId) {
    return (schemeId == BFVRNS_SCHEME);
}
inline bool isBGVRNS(SCHEME schemeId) {
    return (schemeId == BGVRNS_SCHEME);
}

}  // namespace lbcrypto

#endif  // _SCHEME_ID_H_
