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

#ifndef SRC_BINFHE_INCLUDE_LWE_KEYSWITCHKEY_H_
#define SRC_BINFHE_INCLUDE_LWE_KEYSWITCHKEY_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "lwe-keyswitchkey-fwd.h"
#include "math/math-hal.h"
#include "utils/serializable.h"

namespace lbcrypto {

/**
 * @brief Class that stores the LWE scheme switching key
 */
class LWESwitchingKeyImpl : public Serializable {
  public:
    LWESwitchingKeyImpl() = default;

    /**
     * Constructs a key-switching key from its components
     *
     * Both components are indexed [i][j - 1][k], where i is the position in the source (dimension-N) secret
     * key skN, j in [1, baseKS) is the value of a base-baseKS digit and k is the digit position. The pair
     * (keyA[i][j - 1][k], keyB[i][j - 1][k]) is an LWE encryption of skN[i] * j * baseKS^k under the target
     * (dimension-n) secret key s modulo qKS, i.e. keyB = <keyA, s> + e + skN[i] * j * baseKS^k. For digit
     * values j at or above the extent of the top digit position the innermost vectors have one entry fewer,
     * since that position is never read during key switching.
     *
     * @param keyA the vectors "a" of the key-switching LWE encryptions
     * @param keyB the integers "b" of the key-switching LWE encryptions
     */
    LWESwitchingKeyImpl(const std::vector<std::vector<std::vector<NativeVector>>>& keyA,
                        const std::vector<std::vector<std::vector<NativeInteger>>>& keyB)
        : m_keyA(keyA), m_keyB(keyB) {}

    /**
     * Constructs a key-switching key from its components, moving them
     *
     * Both components are indexed [i][j - 1][k], where i is the position in the source (dimension-N) secret
     * key skN, j in [1, baseKS) is the value of a base-baseKS digit and k is the digit position. The pair
     * (keyA[i][j - 1][k], keyB[i][j - 1][k]) is an LWE encryption of skN[i] * j * baseKS^k under the target
     * (dimension-n) secret key s modulo qKS, i.e. keyB = <keyA, s> + e + skN[i] * j * baseKS^k. For digit
     * values j at or above the extent of the top digit position the innermost vectors have one entry fewer,
     * since that position is never read during key switching.
     *
     * @param keyA the vectors "a" of the key-switching LWE encryptions
     * @param keyB the integers "b" of the key-switching LWE encryptions
     */
    LWESwitchingKeyImpl(std::vector<std::vector<std::vector<NativeVector>>>&& keyA,
                        std::vector<std::vector<std::vector<NativeInteger>>>&& keyB) noexcept
        : m_keyA(std::move(keyA)), m_keyB(std::move(keyB)) {}

    LWESwitchingKeyImpl(const LWESwitchingKeyImpl& rhs) : m_keyA(rhs.m_keyA), m_keyB(rhs.m_keyB) {}

    LWESwitchingKeyImpl(LWESwitchingKeyImpl&& rhs) noexcept
        : m_keyA(std::move(rhs.m_keyA)), m_keyB(std::move(rhs.m_keyB)) {}

    LWESwitchingKeyImpl& operator=(const LWESwitchingKeyImpl& rhs) {
        m_keyA = rhs.m_keyA;
        m_keyB = rhs.m_keyB;
        return *this;
    }

    LWESwitchingKeyImpl& operator=(LWESwitchingKeyImpl&& rhs) noexcept {
        m_keyA = std::move(rhs.m_keyA);
        m_keyB = std::move(rhs.m_keyB);
        return *this;
    }

    const std::vector<std::vector<std::vector<NativeVector>>>& GetElementsA() const {
        return m_keyA;
    }

    const std::vector<std::vector<std::vector<NativeInteger>>>& GetElementsB() const {
        return m_keyB;
    }

    void SetElementsA(const std::vector<std::vector<std::vector<NativeVector>>>& keyA) {
        m_keyA = keyA;
    }

    void SetElementsB(const std::vector<std::vector<std::vector<NativeInteger>>>& keyB) {
        m_keyB = keyB;
    }

    void SetElementsA(std::vector<std::vector<std::vector<NativeVector>>>&& keyA) noexcept {
        m_keyA = std::move(keyA);
    }

    void SetElementsB(std::vector<std::vector<std::vector<NativeInteger>>>&& keyB) noexcept {
        m_keyB = std::move(keyB);
    }

    /**
     * @param other the key-switching key to compare with
     * @return true if both keys have the same "a" vectors and "b" integers
     */
    bool operator==(const LWESwitchingKeyImpl& other) const {
        return (m_keyA == other.m_keyA && m_keyB == other.m_keyB);
    }

    /**
     * @param other the key-switching key to compare with
     * @return true if the keys differ
     */
    bool operator!=(const LWESwitchingKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("a", m_keyA));
        ar(::cereal::make_nvp("b", m_keyB));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("a", m_keyA));
        ar(::cereal::make_nvp("b", m_keyB));
    }

    std::string SerializedObjectName() const override {
        return "LWESwitchingKey";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }

  private:
    std::vector<std::vector<std::vector<NativeVector>>> m_keyA;   ///< vectors "a", indexed [i][j - 1][k]
    std::vector<std::vector<std::vector<NativeInteger>>> m_keyB;  ///< integers "b", indexed [i][j - 1][k]
};

}  // namespace lbcrypto

#endif  // SRC_BINFHE_INCLUDE_LWE_KEYSWITCHKEY_H_
