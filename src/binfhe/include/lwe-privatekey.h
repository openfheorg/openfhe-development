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

#ifndef SRC_BINFHE_INCLUDE_LWE_PRIVATEKEY_H_
#define SRC_BINFHE_INCLUDE_LWE_PRIVATEKEY_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "lwe-privatekey-fwd.h"
#include "math/math-hal.h"
#include "utils/serializable.h"

namespace lbcrypto {

/**
 * @brief Class that stores the LWE scheme secret key; contains a vector
 */
class LWEPrivateKeyImpl : public Serializable {
  public:
    LWEPrivateKeyImpl() = default;

    /**
     * Constructs an LWE secret key from its vector
     *
     * @param s the secret key vector; its length is the LWE dimension and its entries (ternary or Gaussian
     * secrets) are stored as residues modulo the LWE modulus
     */
    explicit LWEPrivateKeyImpl(const NativeVector& s) : m_s(s) {}

    /**
     * Constructs an LWE secret key from its vector, moving it
     *
     * @param s the secret key vector; its length is the LWE dimension and its entries (ternary or Gaussian
     * secrets) are stored as residues modulo the LWE modulus
     */
    explicit LWEPrivateKeyImpl(NativeVector&& s) noexcept : m_s(std::move(s)) {}

    LWEPrivateKeyImpl(const LWEPrivateKeyImpl& rhs) : m_s(rhs.m_s) {}

    LWEPrivateKeyImpl(LWEPrivateKeyImpl&& rhs) noexcept : m_s(std::move(rhs.m_s)) {}

    LWEPrivateKeyImpl& operator=(const LWEPrivateKeyImpl& rhs) {
        m_s = rhs.m_s;
        return *this;
    }

    LWEPrivateKeyImpl& operator=(LWEPrivateKeyImpl&& rhs) noexcept {
        m_s = std::move(rhs.m_s);
        return *this;
    }

    const NativeVector& GetElement() const {
        return m_s;
    }

    void SetElement(const NativeVector& s) {
        m_s = s;
    }

    void SetElement(NativeVector&& s) noexcept {
        m_s = std::move(s);
    }

    /**
     * @return the LWE dimension (the length of the secret key vector)
     */
    uint32_t GetLength() const {
        return m_s.GetLength();
    }

    /**
     * @return the modulus of the secret key vector
     */
    NativeInteger GetModulus() const {
        return m_s.GetModulus();
    }

    /**
     * @param other the secret key to compare with
     * @return true if both keys have the same vector
     */
    bool operator==(const LWEPrivateKeyImpl& other) const {
        return m_s == other.m_s;
    }

    /**
     * @param other the secret key to compare with
     * @return true if the key vectors differ
     */
    bool operator!=(const LWEPrivateKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("s", m_s));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("s", m_s));
    }

    std::string SerializedObjectName() const override {
        return "LWEPrivateKey";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }

  private:
    NativeVector m_s;
};

}  // namespace lbcrypto

#endif  // SRC_BINFHE_INCLUDE_LWE_PRIVATEKEY_H_
