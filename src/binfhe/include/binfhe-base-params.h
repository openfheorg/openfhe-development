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

#ifndef _BINFHE_BASE_PARAMS_H_
#define _BINFHE_BASE_PARAMS_H_

#include "lattice/lat-hal.h"
#include "math/discretegaussiangenerator.h"
#include "math/nbtheory.h"
#include "utils/serializable.h"
#include "utils/utilities.h"

#include "binfhe-constants.h"

#include "lwe-ciphertext.h"
#include "lwe-keyswitchkey.h"
#include "lwe-cryptoparameters.h"
#include "rgsw-cryptoparameters.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <map>

namespace lbcrypto {

/**
 * @brief Class that stores all parameters for the RingGSW scheme used in
 * bootstrapping
 */
class BinFHECryptoParams : public Serializable {
public:
    BinFHECryptoParams() = default;

    /**
   * Main constructor for BinFHECryptoParams
   *
   * @param lweparams a shared poiter to an instance of LWECryptoParams
   * @param rgswparams a shared poiter to an instance of RingGSWCryptoParams
   */
    BinFHECryptoParams(const std::shared_ptr<LWECryptoParams>& lweparams,
                       const std::shared_ptr<RingGSWCryptoParams>& rgswparams)
        : m_LWEParams(lweparams), m_RGSWParams(rgswparams) {}

    /**
   * Getter for LWE params
   * @return
   */
    const std::shared_ptr<LWECryptoParams>& GetLWEParams() const {
        return m_LWEParams;
    }

    /**
   * Getter for RingGSW params
   * @return
   */
    const std::shared_ptr<RingGSWCryptoParams>& GetRingGSWParams() const {
        return m_RGSWParams;
    }

    /**
   * Compare two BinFHE sets of parameters
   * @return
   */
    bool operator==(const BinFHECryptoParams& other) const {
        return *m_LWEParams == *other.m_LWEParams && *m_RGSWParams == *other.m_RGSWParams;
    }

    bool operator!=(const BinFHECryptoParams& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("lweparams", m_LWEParams));
        ar(::cereal::make_nvp("rgswparams", m_RGSWParams));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(::cereal::make_nvp("lweparams", m_LWEParams));
        ar(::cereal::make_nvp("rgswparams", m_RGSWParams));
    }

    std::string SerializedObjectName() const override {
        return "BinFHECryptoParams";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    // shared pointer to an instance of LWECryptoParams
    std::shared_ptr<LWECryptoParams> m_LWEParams{nullptr};

    // shared pointer to an instance of RGSWCryptoParams
    std::shared_ptr<RingGSWCryptoParams> m_RGSWParams{nullptr};
};

}  // namespace lbcrypto

#endif  // _BINFHE_BASE_PARAMS_H_
