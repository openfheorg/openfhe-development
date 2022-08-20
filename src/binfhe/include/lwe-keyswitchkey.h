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

#ifndef _LWE_KEYSWITCHKEY_H_
#define _LWE_KEYSWITCHKEY_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "math/hal.h"
#include "utils/serializable.h"

namespace lbcrypto {

class LWESwitchingKeyImpl;

using LWESwitchingKey = std::shared_ptr<LWESwitchingKeyImpl>;

using ConstLWESwitchingKey = const std::shared_ptr<const LWESwitchingKeyImpl>;

/**
 * @brief Class that stores the LWE scheme switching key
 */
class LWESwitchingKeyImpl : public Serializable {
public:
    LWESwitchingKeyImpl() {}

    explicit LWESwitchingKeyImpl(const std::vector<std::vector<std::vector<LWECiphertextImpl>>>& key) : m_key(key) {}

    explicit LWESwitchingKeyImpl(const LWESwitchingKeyImpl& rhs) {
        this->m_key = rhs.m_key;
    }

    explicit LWESwitchingKeyImpl(const LWESwitchingKeyImpl&& rhs) {
        this->m_key = std::move(rhs.m_key);
    }

    const LWESwitchingKeyImpl& operator=(const LWESwitchingKeyImpl& rhs) {
        this->m_key = rhs.m_key;
        return *this;
    }

    const LWESwitchingKeyImpl& operator=(const LWESwitchingKeyImpl&& rhs) {
        this->m_key = std::move(rhs.m_key);
        return *this;
    }

    const std::vector<std::vector<std::vector<LWECiphertextImpl>>>& GetElements() const {
        return m_key;
    }

    void SetElements(const std::vector<std::vector<std::vector<LWECiphertextImpl>>>& key) {
        m_key = key;
    }

    bool operator==(const LWESwitchingKeyImpl& other) const {
        return m_key == other.m_key;
    }

    bool operator!=(const LWESwitchingKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("k", m_key));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }

        ar(::cereal::make_nvp("k", m_key));
    }

    std::string SerializedObjectName() const {
        return "LWEPrivateKey";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    std::vector<std::vector<std::vector<LWECiphertextImpl>>> m_key;
};

}  // namespace lbcrypto

#endif
