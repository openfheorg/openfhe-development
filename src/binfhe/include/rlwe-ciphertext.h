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

#ifndef _RGSW_CIPHERTEXT_H_
#define _RGSW_CIPHERTEXT_H_

#include "lwe-ciphertext.h"
#include "lwe-keyswitchkey.h"
#include "lwe-privatekey.h"
#include "lwe-cryptoparameters.h"

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

class RLWECiphertextImpl;
using RLWECiphertext      = std::shared_ptr<RLWECiphertextImpl>;
using ConstRLWECiphertext = const std::shared_ptr<const RLWECiphertextImpl>;

/**
 * @brief Class that stores a RingGSW ciphertext; a two-dimensional vector of
 * ring elements
 */
class RLWECiphertextImpl : public Serializable {
public:
    RLWECiphertextImpl() = default;

    explicit RLWECiphertextImpl(const std::vector<NativePoly>& elements) : m_elements(elements) {}

    explicit RLWECiphertextImpl(std::vector<NativePoly>&& elements) noexcept : m_elements(std::move(elements)) {}

    RLWECiphertextImpl(const RLWECiphertextImpl& rhs) : m_elements(rhs.m_elements) {}

    RLWECiphertextImpl(RLWECiphertextImpl&& rhs) noexcept : m_elements(std::move(rhs.m_elements)) {}

    RLWECiphertextImpl& operator=(const RLWECiphertextImpl& rhs) {
        this->m_elements = rhs.m_elements;
        return *this;
    }

    RLWECiphertextImpl& operator=(RLWECiphertextImpl&& rhs) noexcept {
        this->m_elements = std::move(rhs.m_elements);
        return *this;
    }

    const std::vector<NativePoly>& GetElements() const {
        return m_elements;
    }

    std::vector<NativePoly>& GetElements() {
        return m_elements;
    }

    void SetFormat(const Format format) {
        for (size_t i = 0; i < m_elements.size(); ++i)
            m_elements[i].SetFormat(format);
    }

    bool operator==(const RLWECiphertextImpl& other) const {
        return m_elements == other.m_elements;
    }

    bool operator!=(const RLWECiphertextImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("elements", m_elements));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("elements", m_elements));
    }

    std::string SerializedObjectName() const override {
        return "RLWECiphertext";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    std::vector<NativePoly> m_elements;
};

}  // namespace lbcrypto

#endif  // _RGSW_CIPHERTEXT_H_
