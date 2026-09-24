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

#ifndef SRC_PKE_INCLUDE_CRYPTOOBJECT_H_
#define SRC_PKE_INCLUDE_CRYPTOOBJECT_H_

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "cryptocontext-fwd.h"
#include "cryptocontextfactory.h"
#include "encoding/encodingparams.h"
#include "schemebase/base-cryptoparameters.h"

namespace lbcrypto {

/**
 * @brief CryptoObject
 *
 * A class to aid in referring to the crypto context that an object belongs to.
 * Every key and ciphertext derives from it and carries the crypto context it was created in together with a
 * key tag: the identifier of the secret key the object is associated with, used to look up the evaluation keys
 * (multiplication, rotation, summation) needed for SHE/FHE operations on it.
 *
 * @tparam Element a ring element.
 */
template <typename Element>
class CryptoObject {
  protected:
    /** crypto context the object belongs to */
    CryptoContext<Element> context;  // crypto context belongs to the tag used to find the evaluation key needed
                                     // for SHE/FHE operations
    /** identifier of the secret key the object is associated with; selects the evaluation keys used on it */
    std::string keyTag;

  public:
    CryptoObject() = default;

    /**
   * Constructs an object attached to a crypto context and a key tag.
   *
   * @param cc the crypto context the object belongs to
   * @param tag the key tag identifying the associated secret key (empty by default)
   */
    explicit CryptoObject(const CryptoContext<Element>& cc, const std::string& tag = "") : context(cc), keyTag(tag) {}

    CryptoObject(const CryptoObject& rhs) = default;

    CryptoObject(CryptoObject&& rhs) noexcept = default;

    virtual ~CryptoObject() = default;

    CryptoObject& operator=(const CryptoObject& rhs) {
        context = rhs.context;
        keyTag = rhs.keyTag;
        return *this;
    }

    CryptoObject& operator=(CryptoObject&& rhs) noexcept {
        context = std::move(rhs.context);
        keyTag = std::move(rhs.keyTag);
        return *this;
    }

    /**
   * Equality: the objects refer to the same crypto context instance (pointer comparison) and have the same
   * key tag.
   *
   * @param rhs the object to compare with
   * @return true if both the context pointer and the key tag match
   */
    bool operator==(const CryptoObject& rhs) const {
        return context.get() == rhs.context.get() && keyTag == rhs.keyTag;
    }

    /**
   * Returns the crypto context the object belongs to.
   *
   * @return the crypto context (may be null for a default-constructed object)
   */
    CryptoContext<Element> GetCryptoContext() const {
        return context;
    }

    /**
   * Returns the crypto parameters of the crypto context the object belongs to.
   *
   * @return the crypto parameters of the object's context
   */
    const std::shared_ptr<CryptoParametersBase<Element>> GetCryptoParameters() const;

    /**
   * Returns the encoding parameters of the crypto context the object belongs to.
   *
   * @return the encoding parameters of the object's context
   */
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

    /**
   * Deserializes the object. The deserialized crypto context is replaced by the matching context registered in
   * CryptoContextFactory (or registered there if it is new), so that all deserialized objects share one context.
   *
   * @param ar the archive to read from
   * @param version serialized version of the object; must not exceed SerializedVersion()
   */
    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion())
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
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

#endif  // SRC_PKE_INCLUDE_CRYPTOOBJECT_H_
