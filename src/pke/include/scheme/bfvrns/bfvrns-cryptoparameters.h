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

#ifndef LBCRYPTO_CRYPTO_BFVRNS_CRYPTOPARAMETERS_H
#define LBCRYPTO_CRYPTO_BFVRNS_CRYPTOPARAMETERS_H

#include "schemerns/rns-cryptoparameters.h"
#include "globals.h"

#include <memory>
#include <string>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class CryptoParametersBFVRNS : public CryptoParametersRNS {
    using ParmType = typename DCRTPoly::Params;
    #define DISABLED_FOR_BFVRNS_PARAMS OPENFHE_THROW("This parameter is not available for BFVRNS.");

public:
    CryptoParametersBFVRNS() : CryptoParametersRNS() {}

    CryptoParametersBFVRNS(const CryptoParametersBFVRNS& rhs) : CryptoParametersRNS(rhs) {}

    CryptoParametersBFVRNS(std::shared_ptr<ParmType> params, const PlaintextModulus& plaintextModulus,
                           float distributionParameter, float assuranceMeasure, SecurityLevel securityLevel,
                           usint digitSize, SecretKeyDist secretKeyDist, int maxRelinSkDeg = 2,
                           KeySwitchTechnique ksTech = BV, ScalingTechnique scalTech = FIXEDMANUAL,
                           EncryptionTechnique encTech = STANDARD, MultiplicationTechnique multTech = HPS,
                           MultipartyMode multipartyMode = FIXED_NOISE_MULTIPARTY)
        : CryptoParametersRNS(params, plaintextModulus, distributionParameter, assuranceMeasure, securityLevel,
                              digitSize, secretKeyDist, maxRelinSkDeg, ksTech, scalTech, encTech, multTech,
                              multipartyMode) {}

    CryptoParametersBFVRNS(std::shared_ptr<ParmType> params, EncodingParams encodingParams, float distributionParameter,
                           float assuranceMeasure, SecurityLevel securityLevel, usint digitSize,
                           SecretKeyDist secretKeyDist, int maxRelinSkDeg = 2, KeySwitchTechnique ksTech = BV,
                           ScalingTechnique scalTech = FIXEDMANUAL, EncryptionTechnique encTech = STANDARD,
                           MultiplicationTechnique multTech = HPS, ProxyReEncryptionMode PREMode = NOT_SET,
                           MultipartyMode multipartyMode           = FIXED_NOISE_MULTIPARTY,
                           ExecutionMode executionMode             = EXEC_EVALUATION,
                           DecryptionNoiseMode decryptionNoiseMode = FIXED_NOISE_DECRYPT,
                           PlaintextModulus noiseScale = 1, uint32_t statisticalSecurity = 30,
                           uint32_t numAdversarialQueries = 1, uint32_t thresholdNumOfParties = 1)
        : CryptoParametersRNS(params, encodingParams, distributionParameter, assuranceMeasure, securityLevel, digitSize,
                              secretKeyDist, maxRelinSkDeg, ksTech, scalTech, encTech, multTech, PREMode,
                              multipartyMode, executionMode, decryptionNoiseMode, noiseScale, statisticalSecurity,
                              numAdversarialQueries, thresholdNumOfParties) {}

    virtual ~CryptoParametersBFVRNS() {}

    void PrecomputeCRTTables(KeySwitchTechnique ksTech, ScalingTechnique scalTech, EncryptionTechnique encTech,
                             MultiplicationTechnique multTech, uint32_t numPartQ, uint32_t auxBits,
                             uint32_t extraBits) override;

    uint64_t FindAuxPrimeStep() const override;

    uint32_t GetPRENumHops() const override {
        DISABLED_FOR_BFVRNS_PARAMS;
    }

    double GetNoiseEstimate() const override {
        DISABLED_FOR_BFVRNS_PARAMS;
    }

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(cereal::base_class<CryptoParametersRNS>(this));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            std::string errMsg("serialized object version " + std::to_string(version) +
                               " is from a later version of the library");
            OPENFHE_THROW(errMsg);
        }

        ar(cereal::base_class<CryptoParametersRNS>(this));

        if (PrecomputeCRTTablesAfterDeserializaton()) {
            PrecomputeCRTTables(m_ksTechnique, m_scalTechnique, m_encTechnique, m_multTechnique, m_numPartQ, m_auxBits,
                                m_extraBits);
        }
    }

    std::string SerializedObjectName() const override {
        return "CryptoParametersBFVRNS";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }
};

}  // namespace lbcrypto

#endif
