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

#include "key/evalkeyrelin-fwd.h"
#include "key/evalkey.h"

#include <memory>
#include <vector>
#include <string>
#include <utility>

// TODO: fix insert issue if SetBVector used before SetAVector
// TODO: fix vector growth issue if SetAVector/SetBVector called multiple times

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
public:
    /**
   * Basic constructor for setting crypto params
   *
   * @param &cryptoParams is the reference to cryptoParams
   */
    explicit EvalKeyRelinImpl(CryptoContext<Element> cc = 0) : EvalKeyImpl<Element>(cc) {}

    virtual ~EvalKeyRelinImpl() {}

    /**
   * Copy constructor
   *
   *@param &rhs key to copy from
   */
    explicit EvalKeyRelinImpl(const EvalKeyRelinImpl<Element>& rhs)
        : EvalKeyImpl<Element>(rhs.GetCryptoContext()), m_rKey(rhs.m_rKey) {}

    /**
   * Move constructor
   *
   *@param &rhs key to move from
   */
    explicit EvalKeyRelinImpl(EvalKeyRelinImpl<Element>&& rhs) noexcept
        : EvalKeyImpl<Element>(rhs.GetCryptoContext()), m_rKey(std::move(rhs.m_rKey)) {}

    operator bool() const {
        return static_cast<bool>(this->context) && m_rKey.size() != 0;
    }

    /**
   * Assignment Operator.
   *
   * @param &rhs key to copy from
   */
    EvalKeyRelinImpl<Element>& operator=(const EvalKeyRelinImpl<Element>& rhs) {
        this->context = rhs.context;
        this->m_rKey  = rhs.m_rKey;
        return *this;
    }

    /**
   * Move Assignment Operator.
   *
   * @param &rhs key to move from
   */
    EvalKeyRelinImpl<Element>& operator=(EvalKeyRelinImpl<Element>&& rhs) {
        this->context = rhs.context;
        rhs.context   = 0;
        m_rKey        = std::move(rhs.m_rKey);
        return *this;
    }

    /**
   * Setter function to store Relinearization Element Vector A.
   * Overrides base class implementation.
   *
   * @param &a is the Element vector to be copied.
   */
    virtual void SetAVector(const std::vector<Element>& a) {
        m_rKey.insert(m_rKey.begin() + 0, a);
    }

    /**
   * Setter function to store Relinearization Element Vector A.
   * Overrides base class implementation.
   *
   * @param &&a is the Element vector to be moved.
   */
    virtual void SetAVector(std::vector<Element>&& a) {
        m_rKey.insert(m_rKey.begin() + 0, std::move(a));
    }

    /**
   * Getter function to access Relinearization Element Vector A.
   * Overrides base class implementation.
   *
   * @return Element vector A.
   */
    virtual const std::vector<Element>& GetAVector() const {
        return m_rKey.at(0);
    }

    /**
   * Setter function to store Relinearization Element Vector B.
   * Overrides base class implementation.
   *
   * @param &b is the Element vector to be copied.
   */
    virtual void SetBVector(const std::vector<Element>& b) {
        m_rKey.insert(m_rKey.begin() + 1, b);
    }

    /**
   * Setter function to store Relinearization Element Vector B.
   * Overrides base class implementation.
   *
   * @param &&b is the Element vector to be moved.
   */
    virtual void SetBVector(std::vector<Element>&& b) {
        m_rKey.insert(m_rKey.begin() + 1, std::move(b));
    }

    /**
   * Getter function to access Relinearization Element Vector B.
   * Overrides base class implementation.
   *
   * @return Element vector B.
   */
    virtual const std::vector<Element>& GetBVector() const {
        return m_rKey.at(1);
    }

    /**
   * Setter function to store key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @param &a is the Element to be copied.
   */

    virtual void SetAinDCRT(const DCRTPoly& a) {
        m_dcrtKeys.insert(m_dcrtKeys.begin() + 0, a);
    }

    /**
   * Setter function to store key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @param &&a is the Element to be moved.
   */
    virtual void SetAinDCRT(DCRTPoly&& a) {
        m_dcrtKeys.insert(m_dcrtKeys.begin() + 0, std::move(a));
    }

    /**
   * Getter function to access key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @return  Element.
   */

    virtual const DCRTPoly& GetAinDCRT() const {
        return m_dcrtKeys.at(0);
    }

    /**
   * Setter function to store key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @param &b is the Element to be copied.
   */

    virtual void SetBinDCRT(const DCRTPoly& b) {
        m_dcrtKeys.insert(m_dcrtKeys.begin() + 1, b);
    }

    /**
   * Setter function to store key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @param &&b is the Element to be moved.
   */
    virtual void SetBinDCRT(DCRTPoly&& b) {
        m_dcrtKeys.insert(m_dcrtKeys.begin() + 1, std::move(b));
    }

    /**
   * Getter function to access key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @return  Element.
   */

    virtual const DCRTPoly& GetBinDCRT() const {
        return m_dcrtKeys.at(1);
    }

    virtual void ClearKeys() {
        m_rKey.clear();
        m_dcrtKeys.clear();
    }

    bool key_compare(const EvalKeyImpl<Element>& other) const {
        const auto& oth = static_cast<const EvalKeyRelinImpl<Element>&>(other);

        if (!CryptoObject<Element>::operator==(other))
            return false;

        if (this->m_rKey.size() != oth.m_rKey.size())
            return false;
        for (size_t i = 0; i < this->m_rKey.size(); i++) {
            if (this->m_rKey[i].size() != oth.m_rKey[i].size())
                return false;
            for (size_t j = 0; j < this->m_rKey[i].size(); j++) {
                if (this->m_rKey[i][j] != oth.m_rKey[i][j])
                    return false;
            }
        }
        return true;
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::base_class<EvalKeyImpl<Element>>(this));
        ar(::cereal::make_nvp("k", m_rKey));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::base_class<EvalKeyImpl<Element>>(this));
        ar(::cereal::make_nvp("k", m_rKey));
    }
    std::string SerializedObjectName() const {
        return "EvalKeyRelin";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    // private member to store vector of vector of Element.
    std::vector<std::vector<Element>> m_rKey;

    // Used for hybrid key switching
    std::vector<DCRTPoly> m_dcrtKeys;
};

}  // namespace lbcrypto

#endif
