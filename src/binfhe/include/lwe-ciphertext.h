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

#ifndef SRC_BINFHE_INCLUDE_LWE_CIPHERTEXT_H_
#define SRC_BINFHE_INCLUDE_LWE_CIPHERTEXT_H_

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "lwe-ciphertext-fwd.h"
#include "math/math-hal.h"
#include "utils/serializable.h"

namespace lbcrypto {

/**
 * @brief Class that stores a LWE scheme ciphertext; composed of a vector "a"
 * and integer "b"
 */
class LWECiphertextImpl : public Serializable {
  public:
    LWECiphertextImpl() = default;

    /**
     * Constructs an LWE ciphertext (a, b) from its components
     *
     * @param a the vector "a"; its modulus is the ciphertext modulus q. For a fresh encryption of m under the
     * secret key s, b = <a, s> + e + m * (q / p) mod q
     * @param b the integer "b"
     * @param p the plaintext modulus the ciphertext encodes for (4 for binary gates)
     */
    LWECiphertextImpl(const NativeVector& a, NativeInteger b, NativeInteger p = 4) : m_a(a), m_b(b), m_p(p) {}

    /**
     * Constructs an LWE ciphertext (a, b) from its components, moving the vector "a"
     *
     * @param a the vector "a"; its modulus is the ciphertext modulus q. For a fresh encryption of m under the
     * secret key s, b = <a, s> + e + m * (q / p) mod q
     * @param b the integer "b"
     * @param p the plaintext modulus the ciphertext encodes for (4 for binary gates)
     */
    LWECiphertextImpl(NativeVector&& a, NativeInteger b, NativeInteger p = 4) noexcept
        : m_a(std::move(a)), m_b(b), m_p(p) {}

    // TODO: m_p deliberately not copied, and completing this copy breaks multi-input gates.
    /**
     * Copies "a" and "b" only; the plaintext modulus of the copy is left at its default of 4
     *
     * @param rhs the ciphertext to copy
     */
    LWECiphertextImpl(const LWECiphertextImpl& rhs) : m_a(rhs.m_a), m_b(rhs.m_b) {}

    LWECiphertextImpl(LWECiphertextImpl&& rhs) noexcept : m_a(std::move(rhs.m_a)), m_b(rhs.m_b) {}

    LWECiphertextImpl& operator=(const LWECiphertextImpl& rhs) {
        m_a = rhs.m_a;
        m_b = rhs.m_b;
        return *this;
    }

    LWECiphertextImpl& operator=(LWECiphertextImpl&& rhs) noexcept {
        m_a = std::move(rhs.m_a);
        m_b = rhs.m_b;
        return *this;
    }

    const NativeVector& GetA() const {
        return m_a;
    }

    NativeVector& GetA() {
        return m_a;
    }

    NativeInteger GetB() const {
        return m_b;
    }

    /**
     * @return the ciphertext modulus q (the modulus of the vector "a")
     */
    NativeInteger GetModulus() const {
        return m_a.GetModulus();
    }

    /**
     * @return the LWE dimension (the length of the vector "a")
     */
    uint32_t GetLength() const {
        return m_a.GetLength();
    }

    NativeInteger GetptModulus() const {
        return m_p;
    }

    void SetA(const NativeVector& a) {
        m_a = a;
    }

    void SetA(NativeVector&& a) noexcept {
        m_a = std::move(a);
    }

    void SetB(NativeInteger b) {
        m_b = b;
    }

    /**
     * Sets the ciphertext modulus and reduces "a" and "b" modulo it
     *
     * @param q the new ciphertext modulus
     */
    void SetModulus(NativeInteger q) {
        m_a.SetModulus(q);
        m_a.ModReduceEq();
        m_b.ModEq(q);
    }

    void SetptModulus(NativeInteger pmod) {
        m_p = pmod;
    }

    /**
     * Compares "a", "b" and the plaintext modulus
     *
     * @param other the ciphertext to compare with
     * @return true if both ciphertexts have the same "a", "b" and plaintext modulus
     */
    bool operator==(const LWECiphertextImpl& other) const {
        return m_a == other.m_a && m_b == other.m_b && m_p == other.m_p;
    }

    /**
     * @param other the ciphertext to compare with
     * @return true if the ciphertexts differ in "a", "b" or the plaintext modulus
     */
    bool operator!=(const LWECiphertextImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("a", m_a));
        ar(::cereal::make_nvp("b", m_b));
        ar(::cereal::make_nvp("p", m_p));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("a", m_a));
        ar(::cereal::make_nvp("b", m_b));
        ar(::cereal::make_nvp("p", m_p));
    }

    std::string SerializedObjectName() const override {
        return "LWECiphertext";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }

  private:
    NativeVector m_a;      ///< the vector "a"; its modulus is the ciphertext modulus q
    NativeInteger m_b;     ///< the integer "b" = <a, s> + e + encoded message mod q
    NativeInteger m_p{4};  ///< plaintext modulus; see the copy constructor for why copies reset it
};

}  // namespace lbcrypto

#endif  // SRC_BINFHE_INCLUDE_LWE_CIPHERTEXT_H_
