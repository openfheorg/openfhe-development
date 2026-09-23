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

#ifndef SRC_PKE_INCLUDE_SCHEME_SCHEME_ID_H_
#define SRC_PKE_INCLUDE_SCHEME_SCHEME_ID_H_

#include <iosfwd>
#include <string>

namespace lbcrypto {

//====================================================================================================================
/**
 * @brief Identifiers of the homomorphic encryption schemes implemented in the PKE module
 */
enum SCHEME {
    INVALID_SCHEME = 0, /**< no scheme selected */
    CKKSRNS_SCHEME,     /**< CKKS scheme (approximate arithmetic) in the RNS representation */
    BFVRNS_SCHEME,      /**< BFV scheme (exact integer arithmetic) in the RNS representation */
    BGVRNS_SCHEME,      /**< BGV scheme (exact integer arithmetic) in the RNS representation */
};
//====================================================================================================================
/**
 * Converts the name of a SCHEME enumerator ("CKKSRNS_SCHEME", "BFVRNS_SCHEME" or "BGVRNS_SCHEME") to its value.
 *
 * @param str the enumerator name
 * @return the corresponding scheme identifier; throws an exception if the name is unknown
 */
SCHEME convertToSCHEME(const std::string& str);
//====================================================================================================================
/**
 * Converts a scheme identifier to its enumerator name.
 *
 * @param schemeId the scheme identifier
 * @return the enumerator name, or "INVALID_SCHEME[<value>]" for a value that is not a valid scheme
 */
std::string convertToString(SCHEME schemeId) noexcept;
//====================================================================================================================
/**
 * Prints the short scheme name ("CKKSRNS", "BFVRNS" or "BGVRNS").
 *
 * @param os the output stream
 * @param schemeId the scheme identifier to print; an invalid identifier causes an exception
 * @return the output stream
 */
std::ostream& operator<<(std::ostream& os, SCHEME schemeId);
//====================================================================================================================
/**
 * Checks whether a scheme identifier denotes the CKKS scheme.
 *
 * @param schemeId the scheme identifier
 * @return true if schemeId is CKKSRNS_SCHEME
 */
inline bool isCKKS(SCHEME schemeId) {
    return (schemeId == CKKSRNS_SCHEME);
}
/**
 * Checks whether a scheme identifier denotes the BFV scheme.
 *
 * @param schemeId the scheme identifier
 * @return true if schemeId is BFVRNS_SCHEME
 */
inline bool isBFVRNS(SCHEME schemeId) {
    return (schemeId == BFVRNS_SCHEME);
}
/**
 * Checks whether a scheme identifier denotes the BGV scheme.
 *
 * @param schemeId the scheme identifier
 * @return true if schemeId is BGVRNS_SCHEME
 */
inline bool isBGVRNS(SCHEME schemeId) {
    return (schemeId == BGVRNS_SCHEME);
}

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEME_SCHEME_ID_H_
