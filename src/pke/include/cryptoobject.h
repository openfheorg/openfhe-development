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

#ifndef LBCRYPTO_CRYPTO_CRYPTOOBJECT_H
#define LBCRYPTO_CRYPTO_CRYPTOOBJECT_H

#include "cryptocontext-fwd.h"
#include "encoding/encodingparams.h"
#include "schemebase/base-cryptoparameters.h"
#include "cryptocontextfactory.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

namespace lbcrypto {

/**
 * @brief CryptoObject
 *
 * A class to aid in referring to the crypto context that an object belongs to
 */
template <typename Element>
class CryptoObject {
protected:
    CryptoContext<Element> context;  // crypto context belongs to the tag used to find the evaluation key needed
                                     // for SHE/FHE operations
    std::string keyTag;

public:
    explicit CryptoObject(CryptoContext<Element> cc = nullptr, const std::string& tag = "")
        : context(cc), keyTag(tag) {}

    CryptoObject(const CryptoObject& rhs) {
        context = rhs.context;
        keyTag  = rhs.keyTag;
    }

    CryptoObject(const CryptoObject&& rhs) {
        context = std::move(rhs.context);
        keyTag  = std::move(rhs.keyTag);
    }

    virtual ~CryptoObject() {}

    const CryptoObject& operator=(const CryptoObject& rhs) {
        this->context = rhs.context;
        this->keyTag  = rhs.keyTag;
        return *this;
    }

    const CryptoObject& operator=(const CryptoObject&& rhs) {
        this->context = std::move(rhs.context);
        this->keyTag  = std::move(rhs.keyTag);
        return *this;
    }

    bool operator==(const CryptoObject& rhs) const {
        return context.get() == rhs.context.get() && keyTag == rhs.keyTag;
    }

    CryptoContext<Element> GetCryptoContext() const {
        return context;
    }

    const std::shared_ptr<CryptoParametersBase<Element>> GetCryptoParameters() const;

    const EncodingParams GetEncodingParameters() const;

    const std::string& GetKeyTag() const {
        return keyTag;
    }

    void SetKeyTag(const std::string& tag) {
        keyTag = tag;
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("cc", context));
        ar(::cereal::make_nvp("kt", keyTag));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("cc", context));
        ar(::cereal::make_nvp("kt", keyTag));

        context = CryptoContextFactory<Element>::GetFullContextByDeserializedContext(context);
    }

    std::string SerializedObjectName() const {
        return "CryptoObject";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }
};

}  // namespace lbcrypto

#endif
