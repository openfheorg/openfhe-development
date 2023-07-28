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

#include "lwe-ciphertext.h"
#include "lwe-keyswitchkey.h"
#include "lwe-privatekey.h"
#include "lwe-cryptoparameters.h"
#include "rgsw-evalkey.h"

#include "lattice/lat-hal.h"
#include "math/discretegaussiangenerator.h"
#include "math/nbtheory.h"
#include "utils/serializable.h"
#include "utils/utilities.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <map>

namespace lbcrypto {

class RingGSWACCKeyImpl;
using RingGSWACCKey      = std::shared_ptr<RingGSWACCKeyImpl>;
using ConstRingGSWACCKey = const std::shared_ptr<const RingGSWACCKeyImpl>;

/**
 * @brief Class that stores the refresh key (used in bootstrapping)
 * A three-dimensional vector of RingGSW ciphertexts
 */
class RingGSWACCKeyImpl : public Serializable {
public:
    RingGSWACCKeyImpl() = default;

    RingGSWACCKeyImpl(uint32_t dim1, uint32_t dim2, uint32_t dim3) : m_key(dim1, dim2_t(dim2, dim3_t(dim3))) {}

    explicit RingGSWACCKeyImpl(const std::vector<std::vector<std::vector<RingGSWEvalKey>>>& key) : m_key(key) {}

    RingGSWACCKeyImpl(const RingGSWACCKeyImpl& rhs) : m_key(rhs.m_key) {}

    RingGSWACCKeyImpl(RingGSWACCKeyImpl&& rhs) noexcept : m_key(std::move(rhs.m_key)) {}

    RingGSWACCKeyImpl& operator=(const RingGSWACCKeyImpl& rhs) {
        this->m_key = rhs.m_key;
        return *this;
    }

    RingGSWACCKeyImpl& operator=(RingGSWACCKeyImpl&& rhs) noexcept {
        this->m_key = std::move(rhs.m_key);
        return *this;
    }

    const std::vector<std::vector<std::vector<RingGSWEvalKey>>>& GetElements() const {
        return m_key;
    }

    void SetElements(const std::vector<std::vector<std::vector<RingGSWEvalKey>>>& key) {
        m_key = key;
    }

    std::vector<std::vector<RingGSWEvalKey>>& operator[](uint32_t i) {
        return m_key[i];
    }

    const std::vector<std::vector<RingGSWEvalKey>>& operator[](uint32_t i) const {
        return m_key[i];
    }

    bool operator==(const RingGSWACCKeyImpl& other) const {
        // as RingGSWEvalKey is shared_ptr<RingGSWEvalKeyImpl>, we have to loop through all elements to compare them
        if (m_key.size() != other.m_key.size())
            return false;
        for (size_t i = 0; i < m_key.size(); ++i) {
            const auto& l1 = m_key[i];
            const auto& o1 = other.m_key[i];
            if (l1.size() != o1.size())
                return false;
            for (size_t j = 0; j < l1.size(); ++j) {
                const auto& l2 = l1[j];
                const auto& o2 = o1[j];
                if (l2.size() != o2.size())
                    return false;
                for (size_t k = 0; k < l2.size(); ++k) {
                    const auto& l3 = l2[k];
                    const auto& o3 = o2[k];
                    if (l3.get() == nullptr || o3.get() == nullptr) {
                        if (l3.get() != o3.get())
                            return false;
                    }
                    else {
                        if (*l3 != *o3)
                            return false;
                    }
                }
            }
        }
        return true;
    }

    bool operator!=(const RingGSWACCKeyImpl& other) const {
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

    std::string SerializedObjectName() const override {
        return "RingGSWACCKey";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    using dim3_t = std::vector<RingGSWEvalKey>;
    using dim2_t = std::vector<dim3_t>;
    using dim1_t = std::vector<dim2_t>;

    std::vector<std::vector<std::vector<RingGSWEvalKey>>> m_key;
};

}  // namespace lbcrypto

#endif  // _RGSW_BTKEY_H_
