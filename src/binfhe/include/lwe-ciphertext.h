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

#ifndef _LWE_CIPHERTEXT_H_
#define _LWE_CIPHERTEXT_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "math/hal.h"
#include "utils/serializable.h"

namespace lbcrypto {

class LWECiphertextImpl;

using LWECiphertext = std::shared_ptr<LWECiphertextImpl>;

using ConstLWECiphertext = const std::shared_ptr<const LWECiphertextImpl>;

/**
 * @brief Class that stores a LWE scheme ciphertext; composed of a vector "a"
 * and integer "b"
 */
class LWECiphertextImpl : public Serializable {
public:
    LWECiphertextImpl() {}

    explicit LWECiphertextImpl(const NativeVector&& a, const NativeInteger& b) : m_a(std::move(a)), m_b(b) {}

    explicit LWECiphertextImpl(const NativeVector& a, const NativeInteger& b) : m_a(a), m_b(b) {}

    LWECiphertextImpl(NativeVector&& a, NativeInteger b) : m_a(std::move(a)), m_b(b) {}

    explicit LWECiphertextImpl(const LWECiphertextImpl& rhs) {
        m_a = rhs.m_a;
        m_b = rhs.m_b;
    }

    explicit LWECiphertextImpl(const LWECiphertextImpl&& rhs) {
        m_a = std::move(rhs.m_a);
        m_b = std::move(rhs.m_b);
    }

    const LWECiphertextImpl& operator=(const LWECiphertextImpl& rhs) {
        m_a = rhs.m_a;
        m_b = rhs.m_b;
        return *this;
    }

    const LWECiphertextImpl& operator=(const LWECiphertextImpl&& rhs) {
        m_a = std::move(rhs.m_a);
        m_b = std::move(rhs.m_b);
        return *this;
    }

    const NativeVector& GetA() const {
        return m_a;
    }

    NativeVector& GetA() {
        return m_a;
    }

    const NativeInteger& GetA(std::size_t i) const {
        return m_a[i];
    }

    NativeInteger& GetA(std::size_t i) {
        return m_a[i];
    }

    const NativeInteger& GetB() const {
        return m_b;
    }

    NativeInteger& GetB() {
        return m_b;
    }

    const NativeInteger& GetModulus() const {
        return m_a.GetModulus();
    }

    void SetA(const NativeVector& a) {
        m_a = a;
    }

    void SetB(const NativeInteger& b) {
        m_b = b;
    }

    bool operator==(const LWECiphertextImpl& other) const {
        return m_a == other.m_a && m_b == other.m_b;
    }

    bool operator!=(const LWECiphertextImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("a", m_a));
        ar(::cereal::make_nvp("b", m_b));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }

        ar(::cereal::make_nvp("a", m_a));
        ar(::cereal::make_nvp("b", m_b));
    }

    std::string SerializedObjectName() const {
        return "LWECiphertext";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    NativeVector m_a;
    NativeInteger m_b;
};

}  // namespace lbcrypto

#endif  // _LWE_CIPHERTEXT_H_
