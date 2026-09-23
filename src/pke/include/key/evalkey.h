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

#ifndef SRC_PKE_INCLUDE_KEY_EVALKEY_H_
#define SRC_PKE_INCLUDE_KEY_EVALKEY_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "key/evalkey-fwd.h"
#include "key/key.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Abstract interface for evaluation/proxy keys
 * @tparam Element a ring element.
 */
template <class Element>
class EvalKeyImpl : public Key<Element> {
    constexpr static std::string_view NOT_SUPPORTED_ERROR = "This function is not supported";

  public:
    /**
   * Default constructor
   */
    EvalKeyImpl() = default;

    /**
   * Constructs an evaluation key in the given crypto context with an empty key tag.
   *
   * @param cc the crypto context the key belongs to
   */
    explicit EvalKeyImpl(const CryptoContext<Element>& cc) : Key<Element>(cc) {}

    virtual ~EvalKeyImpl() = default;

    /**
   * Setter function to store Relinearization Element Vector A.
   * Throws exception, to be overridden by derived class.
   *
   * @param a is the Element vector to be copied.
   */

    virtual void SetAVector(const std::vector<Element>& a) {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
   * Setter function to store Relinearization Element Vector A.
   * Throws exception, to be overridden by derived class.
   *
   * @param a is the Element vector to be moved.
   */

    virtual void SetAVector(std::vector<Element>&& a) {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
   * Getter function to access Relinearization Element Vector A.
   * Throws exception, to be overridden by derived class.
   *
   * @return Element vector A.
   */

    virtual const std::vector<Element>& GetAVector() const {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
   * Setter function to store Relinearization Element Vector B.
   * Throws exception, to be overridden by derived class.
   *
   * @param b is the Element vector to be copied.
   */

    virtual void SetBVector(const std::vector<Element>& b) {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
   * Setter function to store Relinearization Element Vector B.
   * Throws exception, to be overridden by derived class.
   *
   * @param b is the Element vector to be moved.
   */

    virtual void SetBVector(std::vector<Element>&& b) {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
   * Getter function to access Relinearization Element Vector B.
   * Throws exception, to be overridden by derived class.
   *
   * @return  Element vector B.
   */

    virtual const std::vector<Element>& GetBVector() const {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
   * Releases the key material held by the evaluation key.
   * Throws exception, to be overridden by derived class.
   */
    virtual void ClearKeys() {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
   * Equality of evaluation keys, delegated to the virtual key_compare() of the left operand.
   *
   * @param a left operand
   * @param b right operand
   * @return true if a.key_compare(b) reports equality
   */
    friend bool operator==(const EvalKeyImpl& a, const EvalKeyImpl& b) {
        return a.key_compare(b);
    }

    /**
   * Inequality of evaluation keys: negation of operator==.
   *
   * @param a left operand
   * @param b right operand
   * @return true if the keys differ
   */
    friend bool operator!=(const EvalKeyImpl& a, EvalKeyImpl& b) {
        return !(a == b);
    }

    /**
   * Compares this key with another evaluation key.
   * The base implementation always reports inequality; derived classes override it.
   *
   * @param other the evaluation key to compare with
   * @return true if the keys are equal
   */
    virtual bool key_compare(const EvalKeyImpl& other) const {
        return false;
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::base_class<Key<Element>>(this));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        ar(::cereal::base_class<Key<Element>>(this));
    }

    std::string SerializedObjectName() const override {
        return "EvalKey";
    }
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_KEY_EVALKEY_H_
