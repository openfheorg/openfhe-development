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

/*
  ring-learn-with-errors functionality
 */

#ifndef LBCRYPTO_RLWE_CRYPTOPARAMETERS_H
#define LBCRYPTO_RLWE_CRYPTOPARAMETERS_H

#include <memory>
#include <string>

#include "lattice/lat-hal.h"
#include "schemebase/base-cryptoparameters.h"
#include "constants.h"

// TODO - temp include for the SecurityLevel
#include "lattice/stdlatticeparms.h"

namespace lbcrypto {

/**
 * @brief Template for crypto parameters.
 * @tparam Element a ring element.
 */
template <class Element>
class CryptoParametersRLWE : public CryptoParametersBase<Element> {
public:
    /**
   * Default Constructor
   */
    CryptoParametersRLWE() = default;

    /**
   * Copy constructor.
   */
    CryptoParametersRLWE(const CryptoParametersRLWE& rhs)
        : CryptoParametersBase<Element>(rhs.GetElementParams(), rhs.GetPlaintextModulus()) {
        m_distributionParameter         = rhs.m_distributionParameter;
        m_assuranceMeasure              = rhs.m_assuranceMeasure;
        m_noiseScale                    = rhs.m_noiseScale;
        m_digitSize                     = rhs.m_digitSize;
        m_maxRelinSkDeg                 = rhs.m_maxRelinSkDeg;
        m_secretKeyDist                 = rhs.m_secretKeyDist;
        m_stdLevel                      = rhs.m_stdLevel;
        m_floodingDistributionParameter = rhs.m_floodingDistributionParameter;
        m_dgg.SetStd(m_distributionParameter);
        m_dggFlooding.SetStd(m_floodingDistributionParameter);
        m_PREMode               = rhs.m_PREMode;
        m_multipartyMode        = rhs.m_multipartyMode;
        m_executionMode         = rhs.m_executionMode;
        m_decryptionNoiseMode   = rhs.m_decryptionNoiseMode;
        m_statisticalSecurity   = rhs.m_statisticalSecurity;
        m_numAdversarialQueries = rhs.m_numAdversarialQueries;
        m_thresholdNumOfParties = rhs.m_thresholdNumOfParties;
    }

    /**
   * Constructor that initializes values - uses HomomorphicEncryption.org
   * standard security levels
   *
   * @param &params element parameters.
   * @param &encodingParams encoding-specific parameters
   * @param distributionParameter noise distribution parameter.
   * @param assuranceMeasure assurance level.
   * @param stdLevel security level.
   * @param digitSize the size of the digit size.
   * @param maxRelinSkDeg the maximum power of secret key for which the
   * relinearization key is generated
   * @param secretKeyDist mode for secret polynomial, defaults to GAUSSIAN.
   * @param noiseScale used in HRA-secure PRE
   */
    CryptoParametersRLWE(std::shared_ptr<typename Element::Params> params, EncodingParams encodingParams,
                         float distributionParameter, float assuranceMeasure, SecurityLevel stdLevel, usint digitSize,
                         int maxRelinSkDeg = 2, SecretKeyDist secretKeyDist = GAUSSIAN,
                         ProxyReEncryptionMode PREMode = INDCPA, MultipartyMode multipartyMode = FIXED_NOISE_MULTIPARTY,
                         ExecutionMode executionMode             = EXEC_EVALUATION,
                         DecryptionNoiseMode decryptionNoiseMode = FIXED_NOISE_DECRYPT, PlaintextModulus noiseScale = 1,
                         uint32_t statisticalSecurity = 30, uint32_t numAdversarialQueries = 1,
                         uint32_t thresholdNumOfParties = 1)
        : CryptoParametersBase<Element>(params, encodingParams) {
        m_distributionParameter = distributionParameter;
        m_assuranceMeasure      = assuranceMeasure;
        m_noiseScale            = noiseScale;
        m_digitSize             = digitSize;
        m_dgg.SetStd(m_distributionParameter);
        m_maxRelinSkDeg         = maxRelinSkDeg;
        m_secretKeyDist         = secretKeyDist;
        m_stdLevel              = stdLevel;
        m_PREMode               = PREMode;
        m_multipartyMode        = multipartyMode;
        m_executionMode         = executionMode;
        m_decryptionNoiseMode   = decryptionNoiseMode;
        m_statisticalSecurity   = statisticalSecurity;
        m_numAdversarialQueries = numAdversarialQueries;
        m_thresholdNumOfParties = thresholdNumOfParties;
    }

    /**
   * Destructor
   */
    virtual ~CryptoParametersRLWE() {}

    /**
   * Returns the value of standard deviation r for discrete Gaussian
   * distribution
   *
   * @return the standard deviation r.
   */
    float GetDistributionParameter() const {
        return m_distributionParameter;
    }

    /**
   * Returns the value of standard deviation r for discrete Gaussian
   * distribution with flooding
   *
   * @return the flooding standard deviation r.
   */
    double GetFloodingDistributionParameter() const {
        return m_floodingDistributionParameter;
    }

    /**
   * Returns the values of assurance measure alpha
   *
   * @return the assurance measure.
   */
    float GetAssuranceMeasure() const {
        return m_assuranceMeasure;
    }

    /**
   * Returns the value of noise scale.
   *
   * @return the noise scale.
   */
    PlaintextModulus GetNoiseScale() const {
        return m_noiseScale;
    }

    /**
   * Returns the value of digit size.
   *
   * @return the digit size.
   */
    usint GetDigitSize() const {
        return m_digitSize;
    }

    /**
   * Returns the value of the maximum power of secret key for which the
   * relinearization key is generated
   *
   * @return maximum power of secret key
   */
    uint32_t GetMaxRelinSkDeg() const {
        return m_maxRelinSkDeg;
    }

    /**
   * Gets the secretKeyDist setting: GAUSSIAN or UNIFORM_TERNARY
   *
   * @return the secretKeyDist setting.
   */
    SecretKeyDist GetSecretKeyDist() const {
        return m_secretKeyDist;
    }

    /**
   * Gets the pre security mode setting:
   * INDCPA, FIXED_NOISE_HRA, NOISE_FLOODING_HRA or MODULUS_SWITCHING_HRA.
   *
   * @return the pre security mode setting.
   */
    ProxyReEncryptionMode GetPREMode() const {
        return m_PREMode;
    }

    /**
   * Gets the multiparty security mode setting.
   *
   * @return the multiparty security mode setting.
   */
    MultipartyMode GetMultipartyMode() const {
        return m_multipartyMode;
    }

    /**
   * Gets the execution mode setting.
   *
   * @return the execution mode setting.
   */
    ExecutionMode GetExecutionMode() const {
        return m_executionMode;
    }

    /**
   * Gets the decryption noise mode setting.
   *
   * @return the decryption noise mode setting.
   */
    DecryptionNoiseMode GetDecryptionNoiseMode() {
        return m_decryptionNoiseMode;
    }

    /**
   * Gets the standard security level
   *
   * @return the security level.
   */
    SecurityLevel GetStdLevel() const {
        return m_stdLevel;
    }

    /**
   * Returns reference to Discrete Gaussian Generator
   *
   * @return reference to Discrete Gaussian Generaror.
   */
    const typename Element::DggType& GetDiscreteGaussianGenerator() const {
        return m_dgg;
    }

    /**
   * Returns reference to Discrete Gaussian Generator with flooding for PRE
   *
   * @return reference to Discrete Gaussian Generaror with flooding for PRE.
   * The Std dev for this generator changes based on the PRE mode, so it is not const
   */
    typename Element::DggType& GetFloodingDiscreteGaussianGenerator() {
        return m_dggFlooding;
    }

    /**
   * Gets the statistical security level
   *
   * @return the statistical security level.
   */
    double GetStatisticalSecurity() const {
        return m_statisticalSecurity;
    }

    /**
   * Gets the number of adversarial queries
   *
   * @return the number of adversarial queries.
   */
    double GetNumAdversarialQueries() const {
        return m_numAdversarialQueries;
    }

    /**
   * Gets the threshold number of parties
   *
   * @return the threshold number of parties.
   */
    uint32_t GetThresholdNumOfParties() const {
        return m_thresholdNumOfParties;
    }

    // @Set Properties

    /**
   * Sets the value of standard deviation r for discrete Gaussian distribution
   * @param distributionParameter
   */
    void SetDistributionParameter(float distributionParameter) {
        m_distributionParameter = distributionParameter;
        m_dgg.SetStd(m_distributionParameter);
    }

    /**
   * Sets the value of flooding standard deviation r for discrete Gaussian distribution with flooding
   * @param distributionParameter
   */
    void SetFloodingDistributionParameter(double distributionParameter) {
        m_floodingDistributionParameter = distributionParameter;
        m_dggFlooding.SetStd(m_floodingDistributionParameter);
    }

    /**
   * Sets the values of assurance measure alpha
   * @param assuranceMeasure
   */
    void SetAssuranceMeasure(float assuranceMeasure) {
        m_assuranceMeasure = assuranceMeasure;
    }

    /**
   * Sets the standard security level
   * @param standard security level
   */
    void SetStdLevel(SecurityLevel securityLevel) {
        m_stdLevel = securityLevel;
    }

    /**
   * Sets the value of noise scale
   * @param noiseScale
   */
    void SetNoiseScale(PlaintextModulus noiseScale) {
        m_noiseScale = noiseScale;
    }

    /**
   * Sets the value of digit size
   * @param digitSize
   */
    void SetDigitSize(usint digitSize) {
        m_digitSize = digitSize;
    }

    /**
   * Sets the value of the maximum power of secret key for which the
   * relinearization key is generated
   * @param maxRelinSkDeg
   */
    void SetMaxRelinSkDeg(uint32_t maxRelinSkDeg) {
        m_maxRelinSkDeg = maxRelinSkDeg;
    }

    /**
   * Configures the secretKeyDist for generating the secret key polynomial
   * @param secretKeyDist is GAUSSIAN or UNIFORM_TERNARY
   */
    void SetSecretKeyDist(SecretKeyDist secretKeyDist) {
        m_secretKeyDist = secretKeyDist;
    }

    /**
   * Configures the security mode for pre
   * @param PREMode is INDCPA, FIXED_NOISE_HRA, NOISE_FLOODING_HRA or MODULUS_SWITCHING_HRA.
   */
    void SetPREMode(ProxyReEncryptionMode PREMode) {
        m_PREMode = PREMode;
    }

    /**
   * Configures the security mode for multiparty
   * @param multipartyMode Security mode for multiparty decryption.
   */
    void SetMultipartyMode(MultipartyMode multipartyMode) {
        m_multipartyMode = multipartyMode;
    }

    /**
   * Configures the execution for CKKS noise flooding
   * @param executionMode Execution mode.
   */
    void SetExecutionMode(ExecutionMode executionMode) {
        m_executionMode = executionMode;
    }

    /**
   * Configures the decryption noise mode for CKKS noise flooding
   * @param decryptionNoiseMode Decryption noise mode.
   */
    void SetDecryptionNoiseMode(DecryptionNoiseMode decryptionNoiseMode) {
        m_decryptionNoiseMode = decryptionNoiseMode;
    }

    /**
   * Configures the decryption noise mode for CKKS noise flooding and PRE
   * @param statisticalSecurity.
   */
    void SetStatisticalSecurity(uint32_t statisticalSecurity) {
        m_statisticalSecurity = statisticalSecurity;
    }

    /**
   * Configures the decryption noise mode for CKKS noise flooding and PRE
   * @param numAdversarialQueries.
   */
    void SetNumAdversarialQueries(uint32_t numAdversarialQueries) {
        m_numAdversarialQueries = numAdversarialQueries;
    }

    /**
   * Configures the number of parties in thresholdFHE
   * @param thresholdNumOfParties.
   */
    void SetThresholdNumOfParties(uint32_t thresholdNumOfParties) {
        m_thresholdNumOfParties = thresholdNumOfParties;
    }

    /**
   * == operator to compare to this instance of CryptoParametersRLWE object.
   *
   * @param &rhs CryptoParameters to check equality against.
   */
    bool operator==(const CryptoParametersBase<Element>& rhs) const {
        const auto* el = dynamic_cast<const CryptoParametersRLWE<Element>*>(&rhs);

        if (el == nullptr)
            return false;

        return CryptoParametersBase<Element>::operator==(*el) &&
               this->GetPlaintextModulus() == el->GetPlaintextModulus() &&
               *this->GetElementParams() == *el->GetElementParams() &&
               *this->GetEncodingParams() == *el->GetEncodingParams() &&
               m_distributionParameter == el->GetDistributionParameter() &&
               m_assuranceMeasure == el->GetAssuranceMeasure() && m_noiseScale == el->GetNoiseScale() &&
               m_digitSize == el->GetDigitSize() && m_secretKeyDist == el->GetSecretKeyDist() &&
               m_stdLevel == el->GetStdLevel() && m_maxRelinSkDeg == el->GetMaxRelinSkDeg() &&
               m_PREMode == el->GetPREMode() && m_multipartyMode == el->GetMultipartyMode() &&
               m_executionMode == el->GetExecutionMode() &&
               m_floodingDistributionParameter == el->GetFloodingDistributionParameter() &&
               m_statisticalSecurity == el->GetStatisticalSecurity() &&
               m_numAdversarialQueries == el->GetNumAdversarialQueries() &&
               m_thresholdNumOfParties == el->GetThresholdNumOfParties();
    }

    void PrintParameters(std::ostream& os) const {
        CryptoParametersBase<Element>::PrintParameters(os);

        os << "Distrib parm " << GetDistributionParameter() << ", Assurance measure " << GetAssuranceMeasure()
           << ", Noise scale " << GetNoiseScale() << ", Digit Size " << GetDigitSize() << ", SecretKeyDist "
           << GetSecretKeyDist() << ", Standard security level " << GetStdLevel() << std::endl;
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::base_class<CryptoParametersBase<Element>>(this));
        ar(::cereal::make_nvp("dp", m_distributionParameter));
        ar(::cereal::make_nvp("am", m_assuranceMeasure));
        ar(::cereal::make_nvp("ns", m_noiseScale));
        ar(::cereal::make_nvp("rw", m_digitSize));
        ar(::cereal::make_nvp("md", m_maxRelinSkDeg));
        ar(::cereal::make_nvp("mo", m_secretKeyDist));
        ar(::cereal::make_nvp("pmo", m_PREMode));
        ar(::cereal::make_nvp("mmo", m_multipartyMode));
        ar(::cereal::make_nvp("exm", m_executionMode));
        ar(::cereal::make_nvp("dnm", m_decryptionNoiseMode));
        ar(::cereal::make_nvp("slv", m_stdLevel));
        ar(::cereal::make_nvp("fdp", m_floodingDistributionParameter));
        ar(::cereal::make_nvp("ss", m_statisticalSecurity));
        ar(::cereal::make_nvp("aq", m_numAdversarialQueries));
        ar(::cereal::make_nvp("tp", m_thresholdNumOfParties));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        ar(::cereal::base_class<CryptoParametersBase<Element>>(this));
        ar(::cereal::make_nvp("dp", m_distributionParameter));
        ar(::cereal::make_nvp("am", m_assuranceMeasure));
        ar(::cereal::make_nvp("ns", m_noiseScale));
        ar(::cereal::make_nvp("rw", m_digitSize));
        ar(::cereal::make_nvp("md", m_maxRelinSkDeg));
        ar(::cereal::make_nvp("mo", m_secretKeyDist));
        ar(::cereal::make_nvp("pmo", m_PREMode));
        ar(::cereal::make_nvp("mmo", m_multipartyMode));
        ar(::cereal::make_nvp("exm", m_executionMode));
        ar(::cereal::make_nvp("dnm", m_decryptionNoiseMode));
        ar(::cereal::make_nvp("slv", m_stdLevel));
        ar(::cereal::make_nvp("fdp", m_floodingDistributionParameter));
        ar(::cereal::make_nvp("ss", m_statisticalSecurity));
        ar(::cereal::make_nvp("aq", m_numAdversarialQueries));
        ar(::cereal::make_nvp("tp", m_thresholdNumOfParties));

        m_dgg.SetStd(m_distributionParameter);
        m_dggFlooding.SetStd(m_floodingDistributionParameter);
    }

    std::string SerializedObjectName() const {
        return "CryptoParametersRLWE";
    }

protected:
    // standard deviation in Discrete Gaussian Distribution
    float m_distributionParameter = 0;
    // standard deviation in Discrete Gaussian Distribution with Flooding
    double m_floodingDistributionParameter = 0;
    // assurance measure alpha
    float m_assuranceMeasure = 0;
    // noise scale
    PlaintextModulus m_noiseScale = 1;
    // digit size
    usint m_digitSize = 1;
    // the highest power of secret key for which relinearization key is generated
    uint32_t m_maxRelinSkDeg = 2;
    // specifies whether the secret polynomials are generated from discrete
    // Gaussian distribution or ternary distribution with the norm of unity
    SecretKeyDist m_secretKeyDist = GAUSSIAN;
    // Security level according in the HomomorphicEncryption.org standard
    SecurityLevel m_stdLevel = HEStd_NotSet;

    // m_dgg gets the same default value as m_distributionParameter does
    typename Element::DggType m_dgg = typename Element::DggType(0);
    // m_dggFlooding gets the same default value as m_floodingDistributionParameter does
    typename Element::DggType m_dggFlooding = typename Element::DggType(0);

    // specifies the security mode used for PRE
    ProxyReEncryptionMode m_PREMode = NOT_SET;

    // specifies the security mode used for multiparty decryption
    MultipartyMode m_multipartyMode = FIXED_NOISE_MULTIPARTY;

    // specifies the execution mode used for NOISE_FLOODING_DECRYPT mode in CKKS
    ExecutionMode m_executionMode = EXEC_EVALUATION;

    // specifies the noise mode used for decryption in CKKS
    DecryptionNoiseMode m_decryptionNoiseMode = FIXED_NOISE_DECRYPT;

    // Statistical security of CKKS in NOISE_FLOODING_DECRYPT mode. This is the bound on the probability of success
    // that any adversary can have. Specifically, they a probability of success of at most 2^(-statisticalSecurity).
    double m_statisticalSecurity = 30;

    // This is the number of adversarial queries a user is expecting for their application, which we use to ensure
    // security of CKKS in NOISE_FLOODING_DECRYPT mode.
    double m_numAdversarialQueries = 1;

    usint m_thresholdNumOfParties = 1;
};

}  // namespace lbcrypto

#endif
