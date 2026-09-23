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

#ifndef SRC_PKE_INCLUDE_SCHEME_BGVRNS_BGVRNS_CRYPTOPARAMETERS_H_
#define SRC_PKE_INCLUDE_SCHEME_BGVRNS_BGVRNS_CRYPTOPARAMETERS_H_

#include <cstdint>
#include <memory>
#include <string>

#include "globals.h"
#include "schemerns/rns-cryptoparameters.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Crypto parameters for the BGV scheme in the RNS (double-CRT) representation. Adds to
 * CryptoParametersRNS the precomputation of the BGV modulus switching tables and of the FLEXIBLEAUTO /
 * FLEXIBLEAUTOEXT scaling factors modulo the plaintext modulus.
 */
class CryptoParametersBGVRNS : public CryptoParametersRNS {
    using ParmType = typename DCRTPoly::Params;
#define DISABLED_FOR_BGVRNS_PARAMS OPENFHE_THROW("This parameter is not available for BGVRNS.");

  public:
    CryptoParametersBGVRNS() : CryptoParametersRNS() {}

    CryptoParametersBGVRNS(const CryptoParametersBGVRNS& rhs) : CryptoParametersRNS(rhs) {}

    /**
   * Constructor that initializes the BGV crypto parameters from a plaintext modulus.
   *
   * @param params element parameters (the DCRT modulus chain).
   * @param plaintextModulus plaintext modulus t.
   * @param distributionParameter standard deviation of the error distribution.
   * @param assuranceMeasure assurance measure (the number of standard deviations used for noise bounds).
   * @param securityLevel security level from the homomorphic encryption standard.
   * @param digitSize the size of the digit (relinearization window) for BV key switching.
   * @param secretKeyDist secret key distribution: GAUSSIAN, UNIFORM_TERNARY or SPARSE_TERNARY.
   * @param maxRelinSkDeg the maximum power of the secret key for which a relinearization key is generated.
   * @param ksTech key switching technique (BV or HYBRID).
   * @param scalTech scaling (modulus switching) technique.
   * @param encTech encryption technique (BFV-only; kept for a uniform interface).
   * @param multTech multiplication technique (BFV-only; kept for a uniform interface).
   * @param multipartyMode security mode for multiparty (threshold) decryption.
   */
    CryptoParametersBGVRNS(std::shared_ptr<ParmType> params, const PlaintextModulus& plaintextModulus,
                           float distributionParameter, float assuranceMeasure, SecurityLevel securityLevel,
                           uint32_t digitSize, SecretKeyDist secretKeyDist, int maxRelinSkDeg = 2,
                           KeySwitchTechnique ksTech = BV, ScalingTechnique scalTech = FIXEDMANUAL,
                           EncryptionTechnique encTech = STANDARD, MultiplicationTechnique multTech = HPS,
                           MultipartyMode multipartyMode = FIXED_NOISE_MULTIPARTY)
        : CryptoParametersRNS(params, plaintextModulus, distributionParameter, assuranceMeasure, securityLevel,
                              digitSize, secretKeyDist, maxRelinSkDeg, ksTech, scalTech, encTech, multTech,
                              multipartyMode) {}

    /**
   * Constructor that initializes the BGV crypto parameters from explicit encoding parameters.
   *
   * @param params element parameters (the DCRT modulus chain).
   * @param encodingParams encoding parameters (plaintext modulus, batch size).
   * @param distributionParameter standard deviation of the error distribution.
   * @param assuranceMeasure assurance measure (the number of standard deviations used for noise bounds).
   * @param securityLevel security level from the homomorphic encryption standard.
   * @param digitSize the size of the digit (relinearization window) for BV key switching.
   * @param secretKeyDist secret key distribution: GAUSSIAN, UNIFORM_TERNARY or SPARSE_TERNARY.
   * @param maxRelinSkDeg the maximum power of the secret key for which a relinearization key is generated.
   * @param ksTech key switching technique (BV or HYBRID).
   * @param scalTech scaling (modulus switching) technique.
   * @param encTech encryption technique (BFV-only; kept for a uniform interface).
   * @param multTech multiplication technique (BFV-only; kept for a uniform interface).
   * @param PREMode security mode for proxy re-encryption.
   * @param multipartyMode security mode for multiparty (threshold) decryption.
   * @param executionMode execution mode (CKKS-only; kept for a uniform interface).
   * @param decryptionNoiseMode decryption noise mode (CKKS-only; kept for a uniform interface).
   * @param noiseScale multiplier applied to the fresh encryption noise (the plaintext modulus t for BGV).
   * @param statisticalSecurity statistical security parameter in bits (CKKS-only).
   * @param numAdversarialQueries number of adversarial decryption queries assumed (CKKS-only).
   * @param thresholdNumOfParties number of parties in a threshold-FHE application (bounds the joint secret key).
   */
    CryptoParametersBGVRNS(std::shared_ptr<ParmType> params, EncodingParams encodingParams, float distributionParameter,
                           float assuranceMeasure, SecurityLevel securityLevel, uint32_t digitSize,
                           SecretKeyDist secretKeyDist, int maxRelinSkDeg = 2, KeySwitchTechnique ksTech = BV,
                           ScalingTechnique scalTech = FIXEDMANUAL, EncryptionTechnique encTech = STANDARD,
                           MultiplicationTechnique multTech = HPS, ProxyReEncryptionMode PREMode = NOT_SET,
                           MultipartyMode multipartyMode = FIXED_NOISE_MULTIPARTY,
                           ExecutionMode executionMode = EXEC_EVALUATION,
                           DecryptionNoiseMode decryptionNoiseMode = FIXED_NOISE_DECRYPT,
                           PlaintextModulus noiseScale = 1, uint32_t statisticalSecurity = 30,
                           uint32_t numAdversarialQueries = 1, uint32_t thresholdNumOfParties = 1)
        : CryptoParametersRNS(params, encodingParams, distributionParameter, assuranceMeasure, securityLevel, digitSize,
                              secretKeyDist, maxRelinSkDeg, ksTech, scalTech, encTech, multTech, PREMode,
                              multipartyMode, executionMode, decryptionNoiseMode, noiseScale, statisticalSecurity,
                              numAdversarialQueries, thresholdNumOfParties) {}

    virtual ~CryptoParametersBGVRNS() {}

    /**
   * Computes the RNS tables shared by all schemes (via CryptoParametersRNS::PrecomputeCRTTables) and the
   * BGV-specific tables: [t]_{q_i}, [-t^{-1}]_{q_i} and [q_l^{-1}]_{q_i} for modulus switching, t^{-1} modulo
   * the q_i and p_j for HYBRID key switching, the Barrett constants for the q_i, and, for FLEXIBLEAUTO and
   * FLEXIBLEAUTOEXT, the per-level scaling factors and [q_i]_t.
   *
   * @param ksTech the technique to use for key switching (BV or HYBRID).
   * @param scalTech the technique to use for scaling (e.g., FLEXIBLEAUTOEXT or FIXEDMANUAL).
   * @param encTech the technique to use for encryption (unused by BGV).
   * @param multTech the technique to use for homomorphic multiplication (unused by BGV).
   * @param numPartQ the number of digits (partitions of Q) for HYBRID key switching.
   * @param auxBits the number of bits in the auxiliary (special) prime moduli.
   * @param extraBits the number of extra bits reserved for the auxiliary modulus in HYBRID key switching.
   */
    void PrecomputeCRTTables(KeySwitchTechnique ksTech, ScalingTechnique scalTech, EncryptionTechnique encTech,
                             MultiplicationTechnique multTech, uint32_t numPartQ, uint32_t auxBits,
                             uint32_t extraBits) override;

    /**
   * Returns the step for the auxiliary prime search of HYBRID key switching; for BGV the auxiliary primes
   * must be 1 modulo both the cyclotomic order 2n and the plaintext modulus t, so the step is their least
   * common multiple.
   *
   * @return lcm(2n, t).
   */
    uint64_t FindAuxPrimeStep() const override;

    /**
   * CKKS noise estimate for noise flooding; not available for BGV (always throws).
   *
   * @return never returns.
   */
    double GetNoiseEstimate() const override {
        DISABLED_FOR_BGVRNS_PARAMS;
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
        return "CryptoParametersBGVRNS";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEME_BGVRNS_BGVRNS_CRYPTOPARAMETERS_H_
