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
  Hash utilities
 */

#ifndef _SRC_LIB_UTILS_HASHUTIL_H
#define _SRC_LIB_UTILS_HASHUTIL_H

#include <utils/exception.h>
#include <string>
#include <vector>

namespace lbcrypto {

enum HashAlgorithm { SHA_256 = 0, SHA_512 = 1 };

class HashUtil {
public:
    static void Hash(std::string message, HashAlgorithm algo, std::vector<int64_t>& digest) {
        switch (algo) {
            case SHA_256:
                SHA256(message, digest);
                return;

            case SHA_512:
                // TODO SHA512 disabled, returning SHA256 instead
                SHA256(message, digest);
                return;

            default:
                OPENFHE_THROW("ERROR: Unknown Hash Algorithm");
        }
    }

    static std::string HashString(std::string message);

private:
    static void SHA256(std::string message, std::vector<int64_t>& digest);
    static void SHA512(std::string message, std::vector<int64_t>& digest);
    static const uint32_t k_256[64];
    static const uint64_t k_512[80];
};

}  // namespace lbcrypto

#endif
