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

#ifndef _LWE_KEYTRIPLE_H_
#define _LWE_KEYTRIPLE_H_

#include "lwe-privatekey.h"
#include "lwe-publickey.h"
#include "lwe-keyswitchkey.h"
#include "lwe-keypair-fwd.h"

#include "math/math-hal.h"
#include "utils/serializable.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {
/**
 * @brief Class that stores the LWE scheme secret key, public key pair; ((A, b), s)
 */
class LWEKeyPairImpl {
public:
    LWEPublicKey publicKey{nullptr};
    LWEPrivateKey secretKey{nullptr};

    LWEKeyPairImpl(LWEPublicKey Av, LWEPrivateKey s) noexcept : publicKey(std::move(Av)), secretKey(std::move(s)) {}

    bool good() {
        return publicKey && secretKey;
    }
};

}  // namespace lbcrypto

#endif  // _LWE_KEYPAIR_H_
