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

#ifndef LBCRYPTO_CRYPTO_CKKSRNS_CRYPTOPARAMETERS_H
#define LBCRYPTO_CRYPTO_CKKSRNS_CRYPTOPARAMETERS_H

#include "globals.h"
#include "schemerns/rns-cryptoparameters.h"

#include <memory>
#include <string>
#include <vector>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class CryptoParametersCKKSRNS : public CryptoParametersRNS {
    using ParmType = typename DCRTPoly::Params;
#define DISABLED_FOR_CKKSRNS_PARAMS OPENFHE_THROW("This parameter is not available for CKKSRNS.");

public:
    CryptoParametersCKKSRNS()                                       = default;
    CryptoParametersCKKSRNS(const CryptoParametersCKKSRNS& rhs)     = default;
    CryptoParametersCKKSRNS(CryptoParametersCKKSRNS&& rhs) noexcept = default;

    CryptoParametersCKKSRNS(std::shared_ptr<ParmType> params, const PlaintextModulus& plaintextModulus,
                            float distributionParameter, float assuranceMeasure, SecurityLevel securityLevel,
                            uint32_t digitSize, SecretKeyDist secretKeyDist, int maxRelinSkDeg = 2,
                            KeySwitchTechnique ksTech = BV, ScalingTechnique scalTech = FIXEDMANUAL,
                            EncryptionTechnique encTech = STANDARD, MultiplicationTechnique multTech = HPS,
                            MultipartyMode multipartyMode                        = FIXED_NOISE_MULTIPARTY,
                            ExecutionMode executionMode                          = EXEC_EVALUATION,
                            DecryptionNoiseMode decryptionNoiseMode              = FIXED_NOISE_DECRYPT,
                            CompressionLevel mPIntBootCiphertextCompressionLevel = CompressionLevel::SLACK)
        : CryptoParametersRNS(params, plaintextModulus, distributionParameter, assuranceMeasure, securityLevel,
                              digitSize, secretKeyDist, maxRelinSkDeg, ksTech, scalTech, encTech, multTech,
                              multipartyMode, executionMode, decryptionNoiseMode, mPIntBootCiphertextCompressionLevel) {
    }

    CryptoParametersCKKSRNS(std::shared_ptr<ParmType> params, EncodingParams encodingParams,
                            float distributionParameter, float assuranceMeasure, SecurityLevel securityLevel,
                            uint32_t digitSize, SecretKeyDist secretKeyDist, int maxRelinSkDeg = 2,
                            KeySwitchTechnique ksTech = BV, ScalingTechnique scalTech = FIXEDMANUAL,
                            EncryptionTechnique encTech = STANDARD, MultiplicationTechnique multTech = HPS,
                            ProxyReEncryptionMode PREMode           = NOT_SET,
                            MultipartyMode multipartyMode           = FIXED_NOISE_MULTIPARTY,
                            ExecutionMode executionMode             = EXEC_EVALUATION,
                            DecryptionNoiseMode decryptionNoiseMode = FIXED_NOISE_DECRYPT,
                            PlaintextModulus noiseScale = 1, uint32_t statisticalSecurity = 30,
                            uint32_t numAdversarialQueries = 1, uint32_t thresholdNumOfParties = 1,
                            CompressionLevel mPIntBootCiphertextCompressionLevel = CompressionLevel::SLACK,
                            uint32_t compositeDegree = BASE_NUM_LEVELS_TO_DROP, uint32_t registerWordSize = NATIVEINT,
                            CKKSDataType ckksDataType = REAL)
        : CryptoParametersRNS(params, encodingParams, distributionParameter, assuranceMeasure, securityLevel, digitSize,
                              secretKeyDist, maxRelinSkDeg, ksTech, scalTech, encTech, multTech, PREMode,
                              multipartyMode, executionMode, decryptionNoiseMode, noiseScale, statisticalSecurity,
                              numAdversarialQueries, thresholdNumOfParties, mPIntBootCiphertextCompressionLevel,
                              compositeDegree, registerWordSize, ckksDataType) {}

    virtual ~CryptoParametersCKKSRNS() = default;

    void PrecomputeCRTTables(KeySwitchTechnique ksTech, ScalingTechnique scalTech, EncryptionTechnique encTech,
                             MultiplicationTechnique multTech, uint32_t numPartQ, uint32_t auxBits,
                             uint32_t extraBits) override;

    uint64_t FindAuxPrimeStep() const override;

    void ConfigureCompositeDegree(uint32_t scalingModSize);

    // PlaintextModulus GetPlaintextModulus() const override {
    //     DISABLED_FOR_CKKSRNS_PARAMS;
    // }

    uint32_t GetEvalAddCount() const override {
        DISABLED_FOR_CKKSRNS_PARAMS;
    }

    uint32_t GetKeySwitchCount() const override {
        DISABLED_FOR_CKKSRNS_PARAMS;
    }

    uint32_t GetPRENumHops() const override {
        DISABLED_FOR_CKKSRNS_PARAMS;
    }

    /////////////////////////////////////
    // Composite scaling : bootstrapping modulus raise (ExtendCiphertext)
    // Tables for the exact CRT basis extension (DCRTPoly::ExpandCRTBasis) from the small
    // bottom basis Ql = {q_0, ..., q_{d-1}}, d = compositeDegree (the towers remaining in
    // the depleted ciphertext), to the full basis Q. ComplQl = {q_d, ..., q_{L-1}} denotes
    // the complement of Ql in Q (the extension moduli).
    // Only populated when compositeDegree > 1; see PrecomputeCRTTables.
    /////////////////////////////////////

    /**
   * Gets the element parameters of the extension basis ComplQl = {q_d, ..., q_{L-1}}
   *
   * @return the precomputed parameters
   */
    const std::shared_ptr<ParmType>& GetParamsModRaiseComplQl() const {
        return m_paramsModRaiseComplQl;
    }

    /**
   * Gets the precomputed table of [(Ql/q_i)^{-1}]_{q_i}, q_i in Ql
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GetModRaiseQlHatInvModq() const {
        return m_modRaiseQlHatInvModq;
    }

    /**
   * Gets the modular multiplication precomputations for [(Ql/q_i)^{-1}]_{q_i}, q_i in Ql
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GetModRaiseQlHatInvModqPrecon() const {
        return m_modRaiseQlHatInvModqPrecon;
    }

    /**
   * Gets the precomputed table of [Ql/q_i]_{q_j}, q_i in Ql, q_j in ComplQl
   *
   * @return the precomputed table
   */
    const std::vector<std::vector<NativeInteger>>& GetModRaiseQlHatModComplq() const {
        return m_modRaiseQlHatModComplq;
    }

    /**
   * Gets the precomputed table of [a*Ql]_{q_j}, 0 <= a <= d, q_j in ComplQl (the overflow
   * correction used in the exact CRT reconstruction)
   *
   * @return the precomputed table
   */
    const std::vector<std::vector<NativeInteger>>& GetModRaiseAlphaQlModComplq() const {
        return m_modRaiseAlphaQlModComplq;
    }

    /**
   * Gets the Barrett modulo reduction precomputations for q_j in ComplQl
   *
   * @return the precomputed table
   */
    const std::vector<DoubleNativeInt>& GetModRaiseModComplqBarrettMu() const {
        return m_modRaiseModComplqBarrettMu;
    }

    /**
   * Gets the precomputed table of 1./q_i for q_i in Ql
   *
   * @return the precomputed table
   */
    const std::vector<double>& GetModRaiseqInv() const {
        return m_modRaiseqInv;
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
        return "CryptoParametersCKKSRNS";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    // Composite scaling : bootstrapping modulus raise (ExtendCiphertext) precomputations
    // for the exact CRT basis extension from Ql = {q_0, ..., q_{d-1}}, d = compositeDegree,
    // to the full basis Q; ComplQl = {q_d, ..., q_{L-1}} is the complement of Ql in Q.
    // Not serialized; regenerated by PrecomputeCRTTables (including after deserialization).

    // Params for the extension basis ComplQl
    std::shared_ptr<ParmType> m_paramsModRaiseComplQl;
    // [(Ql/q_i)^{-1}]_{q_i}, q_i in Ql
    std::vector<NativeInteger> m_modRaiseQlHatInvModq;
    // modular multiplication precomputations for [(Ql/q_i)^{-1}]_{q_i}
    std::vector<NativeInteger> m_modRaiseQlHatInvModqPrecon;
    // [Ql/q_i]_{q_j}, q_i in Ql, q_j in ComplQl
    std::vector<std::vector<NativeInteger>> m_modRaiseQlHatModComplq;
    // [a*Ql]_{q_j}, 0 <= a <= d, q_j in ComplQl
    std::vector<std::vector<NativeInteger>> m_modRaiseAlphaQlModComplq;
    // Barrett modulo reduction precomputations for q_j in ComplQl
    std::vector<DoubleNativeInt> m_modRaiseModComplqBarrettMu;
    // 1./q_i for q_i in Ql
    std::vector<double> m_modRaiseqInv;
};

}  // namespace lbcrypto

#endif
