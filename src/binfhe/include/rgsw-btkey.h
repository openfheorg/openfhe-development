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

#ifndef _RGSW_BTKEY_H_
#define _RGSW_BTKEY_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <map>

#include "lattice/lat-hal.h"
#include "math/discretegaussiangenerator.h"
#include "math/nbtheory.h"
#include "utils/serializable.h"
#include "utils/utilities.h"

#include "lwe-ciphertext.h"
#include "lwe-keyswitchkey.h"
#include "lwe-privatekey.h"
#include "lwe-cryptoparameters.h"

#include "rgsw-ciphertext.h"

namespace lbcrypto {

class RingGSWBTKeyImpl;

using RingGSWBTKey = std::shared_ptr<RingGSWBTKeyImpl>;

using ConstRingGSWBTKey = const std::shared_ptr<const RingGSWBTKeyImpl>;

/**
 * @brief Class that stores the refreshing key (used in bootstrapping)
 * A three-dimensional vector of RingGSW ciphertexts
 */
class RingGSWBTKeyImpl : public Serializable {
public:
    RingGSWBTKeyImpl() {}

    explicit RingGSWBTKeyImpl(uint32_t dim1, uint32_t dim2, uint32_t dim3) {
        m_key.resize(dim1);
        for (uint32_t i = 0; i < dim1; i++) {
            m_key[i].resize(dim2);
            for (uint32_t j = 0; j < dim2; j++)
                m_key[i][j].resize(dim3);
        }
    }

    explicit RingGSWBTKeyImpl(const std::vector<std::vector<std::vector<RingGSWCiphertextImpl>>>& key) : m_key(key) {}

    explicit RingGSWBTKeyImpl(const RingGSWBTKeyImpl& rhs) {
        this->m_key = rhs.m_key;
    }

    explicit RingGSWBTKeyImpl(const RingGSWBTKeyImpl&& rhs) {
        this->m_key = std::move(rhs.m_key);
    }

    const RingGSWBTKeyImpl& operator=(const RingGSWBTKeyImpl& rhs) {
        this->m_key = rhs.m_key;
        return *this;
    }

    const RingGSWBTKeyImpl& operator=(const RingGSWBTKeyImpl&& rhs) {
        this->m_key = std::move(rhs.m_key);
        return *this;
    }

    const std::vector<std::vector<std::vector<RingGSWCiphertextImpl>>>& GetElements() const {
        return m_key;
    }

    void SetElements(const std::vector<std::vector<std::vector<RingGSWCiphertextImpl>>>& key) {
        m_key = key;
    }

    std::vector<std::vector<RingGSWCiphertextImpl>>& operator[](uint32_t i) {
        return m_key[i];
    }

    const std::vector<std::vector<RingGSWCiphertextImpl>>& operator[](usint i) const {
        return m_key[i];
    }

    bool operator==(const RingGSWBTKeyImpl& other) const {
        return m_key == other.m_key;
    }

    bool operator!=(const RingGSWBTKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("key", m_key));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(::cereal::make_nvp("key", m_key));
    }

    std::string SerializedObjectName() const {
        return "RingGSWBTKeyImpl";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    std::vector<std::vector<std::vector<RingGSWCiphertextImpl>>> m_key;
};

// The struct for storing bootstrapping keys
typedef struct {
    // refreshing key
    RingGSWBTKey BSkey;
    // switching key
    LWESwitchingKey KSkey;
} RingGSWEvalKey;

}  // namespace lbcrypto

#endif  // _RGSW_BTKEY_H_
