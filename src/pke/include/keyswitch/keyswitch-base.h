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

/**
Base class for key switching algorithms.
 */

#ifndef LBCRYPTO_CRYPTO_KEYSWITCH_BASE_H
#define LBCRYPTO_CRYPTO_KEYSWITCH_BASE_H

#include "ciphertext-fwd.h"
#include "key/publickey-fwd.h"
#include "key/privatekey-fwd.h"
#include "key/evalkey-fwd.h"
#include "utils/exception.h"
#include "schemebase/base-cryptoparameters.h"

#include <memory>
#include <string>
#include <vector>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Abstract class for LBC keyswitching
 * @tparam Element a secret key type instantiation
 */
template <class Element>
class KeySwitchBase {
    using ParmType = typename Element::Params;

public:
    KeySwitchBase(){};

    virtual ~KeySwitchBase(){};

    /**
   * Method for KeySwitchGen
   *
   * @param &originalPrivateKey Original private key used for encryption.
   * @param &newPrivateKey New private key to generate the keyswitch hint.
   * @param *KeySwitchHint is where the resulting keySwitchHint will be
   * placed.
   */
    virtual EvalKey<Element> KeySwitchGenInternal(const PrivateKey<Element> oldPrivateKey,
                                                  const PrivateKey<Element> newPrivateKey) const {
        OPENFHE_THROW(config_error, std::string(__func__) + " is not supported");
    }

    virtual EvalKey<Element> KeySwitchGenInternal(const PrivateKey<Element> oldPrivateKey,
                                                  const PrivateKey<Element> newPrivateKey,
                                                  const EvalKey<Element> evalKey) const {
        OPENFHE_THROW(config_error, std::string(__func__) + " is not supported");
    }

    virtual EvalKey<Element> KeySwitchGenInternal(const PrivateKey<Element> oldPrivateKey,
                                                  const PublicKey<Element> newPublicKey) const {
        OPENFHE_THROW(config_error, std::string(__func__) + " is not supported");
    }

    virtual Ciphertext<Element> KeySwitch(ConstCiphertext<Element> ciphertext, const EvalKey<Element> evalKey) const;

    virtual void KeySwitchInPlace(Ciphertext<Element>& ciphertext, const EvalKey<Element> evalKey) const {
        OPENFHE_THROW(config_error, "KeySwitch is not supported");
    }

    virtual Ciphertext<Element> KeySwitchExt(ConstCiphertext<Element> ciphertext, bool addFirst) const {
        OPENFHE_THROW(config_error, "KeySwitchExt is not supported");
    }

    virtual Ciphertext<Element> KeySwitchDown(ConstCiphertext<Element> ciphertext) const {
        OPENFHE_THROW(config_error, "KeySwitchDown is not supported");
    }

    virtual Element KeySwitchDownFirstElement(ConstCiphertext<Element> ciphertext) const {
        OPENFHE_THROW(config_error, "KeySwitchDownFirstElement is not supported");
    }
    /////////////////////////////////////////
    // CORE OPERATIONS
    /////////////////////////////////////////

    virtual std::shared_ptr<std::vector<Element>> KeySwitchCore(const Element& a,
                                                                const EvalKey<Element> evalKey) const {
        OPENFHE_THROW(config_error, "KeySwitchCore is not supported");
    }

    virtual std::shared_ptr<std::vector<Element>> EvalKeySwitchPrecomputeCore(
        const Element& c, std::shared_ptr<CryptoParametersBase<Element>> cryptoParamsBase) const {
        OPENFHE_THROW(config_error, "EvalKeySwitchPrecomputeCore is not supported");
    }

    virtual std::shared_ptr<std::vector<Element>> EvalFastKeySwitchCore(
        const std::shared_ptr<std::vector<Element>> digits, const EvalKey<Element> evalKey,
        const std::shared_ptr<ParmType> paramsQl) const {
        OPENFHE_THROW(config_error, "EvalFastKeySwitchCore is not supported");
    }

    virtual std::shared_ptr<std::vector<Element>> EvalFastKeySwitchCoreExt(
        const std::shared_ptr<std::vector<Element>> digits, const EvalKey<Element> evalKey,
        const std::shared_ptr<ParmType> paramsQl) const {
        OPENFHE_THROW(config_error, "EvalFastKeySwitchCoreExt is not supported");
    }
};

}  // namespace lbcrypto

#endif
