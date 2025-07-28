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

#ifndef LBCRYPTO_CRYPTO_KEY_EVALKEYRELIN_H
#define LBCRYPTO_CRYPTO_KEY_EVALKEYRELIN_H

#include "key/evalkey.h"
#include "key/evalkeyrelin-fwd.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Concrete class for Relinearization keys of RLWE scheme
 * @tparam Element a ring element.
 */
template <class Element>
class EvalKeyRelinImpl : public EvalKeyImpl<Element> {
private:
    std::vector<Element> m_AKey;
    std::vector<Element> m_BKey;

public:
    /**
   * Basic constructor for setting crypto params
   *
   * @param &cryptoParams is the reference to cryptoParams
   */
    explicit EvalKeyRelinImpl(const CryptoContext<Element>& cc) : EvalKeyImpl<Element>(cc) {}

    EvalKeyRelinImpl() = default;

    virtual ~EvalKeyRelinImpl() = default;

    /**
   * Copy constructor
   *
   *@param &rhs key to copy from
   */
    EvalKeyRelinImpl(const EvalKeyRelinImpl<Element>& rhs)
        : EvalKeyImpl<Element>(rhs.context), m_AKey(rhs.m_AKey), m_BKey(rhs.m_BKey) {}

    /**
   * Move constructor
   *
   *@param &rhs key to move from
   */
    EvalKeyRelinImpl(EvalKeyRelinImpl<Element>&& rhs) noexcept
        : EvalKeyImpl<Element>(rhs.context), m_AKey(std::move(rhs.m_AKey)), m_BKey(std::move(rhs.m_BKey)) {}

    operator bool() const {
        return (this->context != nullptr) && (m_AKey.size() != 0) && (m_BKey.size() != 0);
    }

    /**
   * Assignment Operator.
   *
   * @param &rhs key to copy from
   */
    EvalKeyRelinImpl<Element>& operator=(const EvalKeyRelinImpl<Element>& rhs) {
        this->context = rhs.context;
        m_AKey        = rhs.m_AKey;
        m_BKey        = rhs.m_BKey;
        return *this;
    }

    /**
   * Move Assignment Operator.
   *
   * @param &rhs key to move from
   */
    EvalKeyRelinImpl<Element>& operator=(EvalKeyRelinImpl<Element>&& rhs) noexcept {
        this->context = std::move(rhs.context);
        m_AKey        = std::move(rhs.m_AKey);
        m_BKey        = std::move(rhs.m_BKey);
        return *this;
    }

    /**
   * Setter function to store Relinearization Element Vector A.
   * Overrides base class implementation.
   *
   * @param &a is the Element vector to be copied.
   */
    void SetAVector(const std::vector<Element>& a) override {
        m_AKey = a;
    }

    /**
   * Setter function to store Relinearization Element Vector A.
   * Overrides base class implementation.
   *
   * @param &&a is the Element vector to be moved.
   */
    void SetAVector(std::vector<Element>&& a) noexcept override {
        m_AKey = std::move(a);
    }

    /**
   * Getter function to access Relinearization Element Vector A.
   * Overrides base class implementation.
   *
   * @return Element vector A.
   */
    const std::vector<Element>& GetAVector() const override {
        return m_AKey;
    }

    /**
   * Setter function to store Relinearization Element Vector B.
   * Overrides base class implementation.
   *
   * @param &b is the Element vector to be copied.
   */
    void SetBVector(const std::vector<Element>& b) override {
        m_BKey = b;
    }

    /**
   * Setter function to store Relinearization Element Vector B.
   * Overrides base class implementation.
   *
   * @param &&b is the Element vector to be moved.
   */
    void SetBVector(std::vector<Element>&& b) noexcept override {
        m_BKey = std::move(b);
    }

    /**
   * Getter function to access Relinearization Element Vector B.
   * Overrides base class implementation.
   *
   * @return Element vector B.
   */
    const std::vector<Element>& GetBVector() const override {
        return m_BKey;
    }

    void ClearKeys() override {
        m_AKey.clear();
        m_BKey.clear();
    }

    bool key_compare(const EvalKeyImpl<Element>& rhs) const override {
        const auto& r = static_cast<const EvalKeyRelinImpl<Element>&>(rhs);
        return CryptoObject<Element>::operator==(rhs) && m_AKey == r.m_AKey && m_BKey == r.m_BKey;
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::base_class<EvalKeyImpl<Element>>(this));
        ar(::cereal::make_nvp("ak", m_AKey));
        ar(::cereal::make_nvp("bk", m_BKey));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::base_class<EvalKeyImpl<Element>>(this));
        ar(::cereal::make_nvp("ak", m_AKey));
        ar(::cereal::make_nvp("bk", m_BKey));
    }

    std::string SerializedObjectName() const override {
        return "EvalKeyRelin";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }
};

}  // namespace lbcrypto

#endif
