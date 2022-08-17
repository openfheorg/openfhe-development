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

// noise flooding distribution parameter
// for distributed decryption in
// threshold FHE
const double MP_SD = 1048576;

// noise flooding distribution parameter
// for fixed 20 bits noise multihop PRE
const double MPRE_SD = 1048576;

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
    CryptoParametersRLWE() : CryptoParametersBase<Element>() {
        m_distributionParameter = 0.0f;
        m_assuranceMeasure      = 0.0f;
        m_noiseScale            = 1;
        m_digitSize             = 1;
        m_dgg.SetStd(m_distributionParameter);
        m_maxRelinSkDeg = 2;
        m_secretKeyDist = GAUSSIAN;
        m_stdLevel      = HEStd_NotSet;
    }

    /**
   * Copy constructor.
   *
   */
    CryptoParametersRLWE(const CryptoParametersRLWE& rhs)
        : CryptoParametersBase<Element>(rhs.GetElementParams(), rhs.GetPlaintextModulus()) {
        m_distributionParameter = rhs.m_distributionParameter;
        m_assuranceMeasure      = rhs.m_assuranceMeasure;
        m_noiseScale            = rhs.m_noiseScale;
        m_digitSize             = rhs.m_digitSize;
        m_dgg.SetStd(m_distributionParameter);
        m_maxRelinSkDeg = rhs.m_maxRelinSkDeg;
        m_secretKeyDist = rhs.m_secretKeyDist;
        m_stdLevel      = rhs.m_stdLevel;
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
                         int maxRelinSkDeg = 2, SecretKeyDist secretKeyDist = GAUSSIAN, PlaintextModulus noiseScale = 1)
        : CryptoParametersBase<Element>(params, encodingParams) {
        m_distributionParameter = distributionParameter;
        m_assuranceMeasure      = assuranceMeasure;
        m_noiseScale            = noiseScale;
        m_digitSize             = digitSize;
        m_dgg.SetStd(m_distributionParameter);
        m_maxRelinSkDeg = maxRelinSkDeg;
        m_secretKeyDist = secretKeyDist;
        m_stdLevel      = stdLevel;
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
   * Returns the maximum homomorphic multiplication depth before performing
   * relinearization
   *
   * @return the computation depth supported d.
   */
    size_t GetMaxRelinSkDeg() const {
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
   * @param depth
   */
    void SetMaxRelinSkDeg(size_t maxRelinSkDeg) {
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
               m_stdLevel == el->GetStdLevel();
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
        ar(::cereal::make_nvp("slv", m_stdLevel));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        ar(::cereal::base_class<CryptoParametersBase<Element>>(this));
        ar(::cereal::make_nvp("dp", m_distributionParameter));
        m_dgg.SetStd(m_distributionParameter);
        ar(::cereal::make_nvp("am", m_assuranceMeasure));
        ar(::cereal::make_nvp("ns", m_noiseScale));
        ar(::cereal::make_nvp("rw", m_digitSize));
        ar(::cereal::make_nvp("md", m_maxRelinSkDeg));
        ar(::cereal::make_nvp("mo", m_secretKeyDist));
        ar(::cereal::make_nvp("slv", m_stdLevel));
    }

    std::string SerializedObjectName() const {
        return "CryptoParametersRLWE";
    }

protected:
    // standard deviation in Discrete Gaussian Distribution
    float m_distributionParameter;
    // assurance measure alpha
    float m_assuranceMeasure;
    // noise scale
    PlaintextModulus m_noiseScale;
    // digit size
    usint m_digitSize;
    // maximum depth support of a ciphertext without keyswitching
    // corresponds to the highest power of secret key for which evaluation keys are genererated
    uint32_t m_maxRelinSkDeg;
    // specifies whether the secret polynomials are generated from discrete
    // Gaussian distribution or ternary distribution with the norm of unity
    SecretKeyDist m_secretKeyDist;
    // Security level according in the HomomorphicEncryption.org standard
    SecurityLevel m_stdLevel;

    typename Element::DggType m_dgg;
};

}  // namespace lbcrypto

#endif
