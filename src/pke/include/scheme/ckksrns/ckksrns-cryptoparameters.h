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
    // Sparse secret encapsulation (SPARSE_ENCAPSULATED): switching between the dense and
    // sparse secrets at the bootstrapping modulus raise (FHECKKSRNS::KeySwitchGenSparse /
    // KeySwitchSparse). The GHS-style switching key is generated over q0*P', where
    // P' = p'_0*...*p'_{k-1} is an auxiliary modulus of two primes of MAX_MODULUS_SIZE/2 + 3
    // bits each (33 bits, i.e., ~66 auxiliary bits, for the standard 64-bit build), generated
    // here, during parameter generation. Making P' exceed the largest possible q0 by ~6 bits,
    // instead of using a single prime of at most MAX_MODULUS_SIZE bits, makes the key switching
    // noise floor(q0*e/P') comparable to the modulus switching noise
    // (see https://github.com/openfheorg/openfhe-development/issues/1041).
    // The tables below support the exact (HPS-style) CRT basis switch used to scale the
    // key-switched ciphertext back down from q0*P' to q0.
    // Only populated when secretKeyDist == SPARSE_ENCAPSULATED; see PrecomputeCRTTables.
    /////////////////////////////////////

    /**
   * Gets the element parameters of the sparse encapsulation auxiliary basis P' = {p'_0, ..., p'_{k-1}}
   *
   * @return the precomputed parameters
   */
    const std::shared_ptr<ParmType>& GetSparseKSParamsP() const {
        return m_sparseKSParamsP;
    }

    /**
   * Gets the element parameters of the extended basis {q_0, p'_0, ..., p'_{k-1}} used for
   * the sparse encapsulation switching key
   *
   * @return the precomputed parameters
   */
    const std::shared_ptr<ParmType>& GetSparseKSParamsQP() const {
        return m_sparseKSParamsQP;
    }

    /**
   * Gets the element parameters of the single-limb basis {q_0} (the target basis of the
   * sparse encapsulation modulus switch)
   *
   * @return the precomputed parameters
   */
    const std::shared_ptr<ParmType>& GetSparseKSParamsQ() const {
        return m_sparseKSParamsQ;
    }

    /**
   * Gets the precomputed value [P']_{q_0}
   *
   * @return the precomputed value
   */
    const NativeInteger& GetSparseKSPModq() const {
        return m_sparseKSPModq;
    }

    /**
   * Gets the precomputed value [P'^{-1}]_{q_0}
   *
   * @return the precomputed value
   */
    const NativeInteger& GetSparseKSPInvModq() const {
        return m_sparseKSPInvModq;
    }

    /**
   * Gets the precomputed table of [(P'/p'_j)^{-1}]_{p'_j}
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GetSparseKSPHatInvModp() const {
        return m_sparseKSPHatInvModp;
    }

    /**
   * Gets the modular multiplication precomputations for [(P'/p'_j)^{-1}]_{p'_j}
   *
   * @return the precomputed table
   */
    const std::vector<NativeInteger>& GetSparseKSPHatInvModpPrecon() const {
        return m_sparseKSPHatInvModpPrecon;
    }

    /**
   * Gets the precomputed table of [P'/p'_j]_{q_0}, indexed as [q_i][p'_j] with a single q_0 row
   * (the orientation expected by DCRTPoly::SwitchCRTBasis)
   *
   * @return the precomputed table
   */
    const std::vector<std::vector<NativeInteger>>& GetSparseKSPHatModq() const {
        return m_sparseKSPHatModq;
    }

    /**
   * Gets the precomputed table of [a*P']_{q_0}, 0 <= a <= k (the overflow correction used
   * in the exact CRT reconstruction)
   *
   * @return the precomputed table
   */
    const std::vector<std::vector<NativeInteger>>& GetSparseKSAlphaPModq() const {
        return m_sparseKSAlphaPModq;
    }

    /**
   * Gets the Barrett modulo reduction precomputation for q_0
   *
   * @return the precomputed table
   */
    const std::vector<DoubleNativeInt>& GetSparseKSModqBarrettMu() const {
        return m_sparseKSModqBarrettMu;
    }

    /**
   * Gets the precomputed table of 1./p'_j
   *
   * @return the precomputed table
   */
    const std::vector<double>& GetSparseKSpInv() const {
        return m_sparseKSpInv;
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

    // Sparse secret encapsulation (SPARSE_ENCAPSULATED) precomputations for the key
    // switching to/from the sparse secret at the bootstrapping modulus raise: auxiliary
    // basis P' = {p'_0, ..., p'_{k-1}} (two primes of MAX_MODULUS_SIZE/2 + 3 bits each)
    // and the tables for the exact (HPS-style) CRT basis switch from P' to {q_0}.
    // Not serialized; regenerated by PrecomputeCRTTables (including after deserialization).

    // Params for the auxiliary basis P'
    std::shared_ptr<ParmType> m_sparseKSParamsP;
    // Params for the extended basis {q_0, p'_0, ..., p'_{k-1}}
    std::shared_ptr<ParmType> m_sparseKSParamsQP;
    // Params for the single-limb basis {q_0}
    std::shared_ptr<ParmType> m_sparseKSParamsQ;
    // [P']_{q_0}
    NativeInteger m_sparseKSPModq;
    // [P'^{-1}]_{q_0}
    NativeInteger m_sparseKSPInvModq;
    // [(P'/p'_j)^{-1}]_{p'_j}
    std::vector<NativeInteger> m_sparseKSPHatInvModp;
    // modular multiplication precomputations for [(P'/p'_j)^{-1}]_{p'_j}
    std::vector<NativeInteger> m_sparseKSPHatInvModpPrecon;
    // [P'/p'_j]_{q_0}, indexed as [q_i][p'_j] with a single q_0 row
    std::vector<std::vector<NativeInteger>> m_sparseKSPHatModq;
    // [a*P']_{q_0}, 0 <= a <= k
    std::vector<std::vector<NativeInteger>> m_sparseKSAlphaPModq;
    // Barrett modulo reduction precomputation for q_0
    std::vector<DoubleNativeInt> m_sparseKSModqBarrettMu;
    // 1./p'_j
    std::vector<double> m_sparseKSpInv;
};

}  // namespace lbcrypto

#endif
