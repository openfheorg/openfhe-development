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

#include "binfhe-constants.h"

#include "lwe-ciphertext.h"
#include "lwe-keyswitchkey.h"
#include "lwe-cryptoparameters.h"

namespace lbcrypto {

/**
 * @brief Class that stores all parameters for the RingGSW scheme used in
 * bootstrapping
 */
class RingGSWCryptoParams : public Serializable {
public:
    RingGSWCryptoParams() : m_baseG(0), m_digitsG(0), m_digitsG2(0), m_baseR(0), m_method(GINX) {}

    /**
   * Main constructor for RingGSWCryptoParams
   *
   * @param lweparams a shared poiter to an instance of LWECryptoParams
   * @param baseG the gadget base used in the bootstrapping
   * @param baseR the base for the refreshing key
   * @param method bootstrapping method (AP or GINX)
   */
    explicit RingGSWCryptoParams(const std::shared_ptr<LWECryptoParams> lweparams, uint32_t baseG, uint32_t baseR,
                                 BINFHEMETHOD method, bool signEval = false)
        : m_LWEParams(lweparams), m_baseG(baseG), m_baseR(baseR), m_method(method) {
        if (!IsPowerOfTwo(baseG)) {
            OPENFHE_THROW(config_error, "Gadget base should be a power of two.");
        }

        PreCompute(signEval);
    }

    /**
   * Performs precomputations based on the supplied parameters
   */
    void PreCompute(bool signEval = false);

    const std::shared_ptr<LWECryptoParams> GetLWEParams() const {
        return m_LWEParams;
    }

    uint32_t GetBaseG() const {
        return m_baseG;
    }

    uint32_t GetDigitsG() const {
        return m_digitsG;
    }

    uint32_t GetDigitsG2() const {
        return m_digitsG2;
    }

    uint32_t GetBaseR() const {
        return m_baseR;
    }

    const std::vector<NativeInteger>& GetDigitsR() const {
        return m_digitsR;
    }

    const std::shared_ptr<ILNativeParams> GetPolyParams() const {
        return m_polyParams;
    }

    const std::vector<NativeInteger>& GetGPower() const {
        return m_Gpower;
    }

    const std::map<uint32_t, std::vector<NativeInteger>>& GetGPowerMap() const {
        return m_Gpower_map;
    }

    const std::vector<NativeInteger>& GetGateConst() const {
        return m_gateConst;
    }

    const NativePoly& GetMonomial(uint32_t i) const {
        return m_monomials[i];
    }

    BINFHEMETHOD GetMethod() const {
        return m_method;
    }

    bool operator==(const RingGSWCryptoParams& other) const {
        return *m_LWEParams == *other.m_LWEParams && m_baseR == other.m_baseR && m_baseG == other.m_baseG &&
               m_method == other.m_method;
    }

    bool operator!=(const RingGSWCryptoParams& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("params", m_LWEParams));
        ar(::cereal::make_nvp("bR", m_baseR));
        ar(::cereal::make_nvp("bG", m_baseG));
        ar(::cereal::make_nvp("method", m_method));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(::cereal::make_nvp("params", m_LWEParams));
        ar(::cereal::make_nvp("bR", m_baseR));
        ar(::cereal::make_nvp("bG", m_baseG));
        ar(::cereal::make_nvp("method", m_method));

        this->PreCompute();
    }

    std::string SerializedObjectName() const {
        return "RingGSWCryptoParams";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

    void SetQ(NativeInteger q) {
        m_LWEParams->SetQ(q);
    }

    void Change_BaseG(uint32_t BaseG) {
        if (m_baseG != BaseG) {
            m_baseG  = BaseG;
            m_Gpower = m_Gpower_map[m_baseG];
            m_digitsG =
                (uint32_t)std::ceil(log(m_LWEParams->GetQ().ConvertToDouble()) / log(static_cast<double>(m_baseG)));
            m_digitsG2 = m_digitsG * 2;
        }
    }

private:
    // shared pointer to an instance of LWECryptoParams
    std::shared_ptr<LWECryptoParams> m_LWEParams;

    // gadget base used in bootstrapping
    uint32_t m_baseG;

    // number of digits in decomposing integers mod Q
    uint32_t m_digitsG;

    // twice the number of digits in decomposing integers mod Q
    uint32_t m_digitsG2;

    // base used for the refreshing key (used only for AP bootstrapping)
    uint32_t m_baseR;

    // powers of m_baseR (used only for AP bootstrapping)
    std::vector<NativeInteger> m_digitsR;

    // A vector of powers of baseG
    std::vector<NativeInteger> m_Gpower;

    // A map of vectors of powers of baseG for sign evaluation
    std::map<uint32_t, std::vector<NativeInteger>> m_Gpower_map;

    // Parameters for polynomials in RingGSW/RingLWE
    std::shared_ptr<ILNativeParams> m_polyParams;

    // Constants used in evaluating binary gates
    std::vector<NativeInteger> m_gateConst;

    // Precomputed polynomials in Format::EVALUATION representation for X^m - 1
    // (used only for GINX bootstrapping)
    std::vector<NativePoly> m_monomials;

    // Bootstrapping method (AP or GINX)
    BINFHEMETHOD m_method;
};

}  // namespace lbcrypto

#endif  // _BINFHE_BASE_PARAMS_H_
