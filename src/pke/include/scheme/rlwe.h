// @file rlwe.h -- PALISADE ring-learn-with-errors functionality.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef LBCRYPTO_CRYPTO_RLWE_H
#define LBCRYPTO_CRYPTO_RLWE_H

#include <memory>
#include <string>

#include "lattice/dcrtpoly.h"
#include "lattice/poly.h"
#include "lattice/stdlatticeparms.h"
#include "utils/serializable.h"

namespace lbcrypto {

// noise flooding distribution parameter
// for distributed decryption in
// threshold FHE
const double MP_SD = 1048576;

/**
 * @brief Template for crypto parameters.
 * @tparam Element a ring element.
 */
template <class Element>
class LPCryptoParametersRLWE : public LPCryptoParameters<Element> {
 public:
  /**
   * Default Constructor
   */
  LPCryptoParametersRLWE() : LPCryptoParameters<Element>() {
    m_distributionParameter = 0.0f;
    m_assuranceMeasure = 0.0f;
    m_securityLevel = 0.0f;
    m_relinWindow = 1;
    m_dgg.SetStd(m_distributionParameter);
    m_depth = 0;
    m_maxDepth = 2;
    m_mode = RLWE;
    m_stdLevel = HEStd_NotSet;
  }

  /**
   * Copy constructor.
   *
   */
  LPCryptoParametersRLWE(const LPCryptoParametersRLWE &rhs)
      : LPCryptoParameters<Element>(rhs.GetElementParams(),
                                    rhs.GetPlaintextModulus()) {
    m_distributionParameter = rhs.m_distributionParameter;
    m_assuranceMeasure = rhs.m_assuranceMeasure;
    m_securityLevel = rhs.m_securityLevel;
    m_relinWindow = rhs.m_relinWindow;
    m_dgg.SetStd(m_distributionParameter);
    m_depth = rhs.m_depth;
    m_maxDepth = rhs.m_maxDepth;
    m_mode = rhs.m_mode;
    m_stdLevel = rhs.m_stdLevel;
  }

  /**
   * Constructor that initializes values.
   *
   * @param &params element parameters.
   * @param &encodingParams encoding-specific parameters
   * @param distributionParameter noise distribution parameter.
   * @param assuranceMeasure assurance level.
   * @param securityLevel security level.
   * @param relinWindow the size of the relinearization window.
   * @param depth is the depth of computation circuit supported for these
   * parameters (not used now; for future use).
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   * @param mode mode for secret polynomial, defaults to RLWE.
   */
  LPCryptoParametersRLWE(shared_ptr<typename Element::Params> params,
                         EncodingParams encodingParams,
                         float distributionParameter, float assuranceMeasure,
                         float securityLevel, usint relinWindow, int depth = 1,
                         int maxDepth = 2, MODE mode = RLWE)
      : LPCryptoParameters<Element>(params, encodingParams) {
    m_distributionParameter = distributionParameter;
    m_assuranceMeasure = assuranceMeasure;
    m_securityLevel = securityLevel;
    m_relinWindow = relinWindow;
    m_dgg.SetStd(m_distributionParameter);
    m_depth = depth;
    m_maxDepth = maxDepth;
    m_mode = mode;
    m_stdLevel = HEStd_NotSet;
  }

  /**
   * Constructor that initializes values - uses HomomorphicEncryption.org
   * standard security levels
   *
   * @param &params element parameters.
   * @param &encodingParams encoding-specific parameters
   * @param distributionParameter noise distribution parameter.
   * @param assuranceMeasure assurance level.
   * @param securityLevel security level.
   * @param relinWindow the size of the relinearization window.
   * @param depth is the depth of computation circuit supported for these
   * parameters (not used now; for future use).
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   * @param mode mode for secret polynomial, defaults to RLWE.
   */
  LPCryptoParametersRLWE(shared_ptr<typename Element::Params> params,
                         EncodingParams encodingParams,
                         float distributionParameter, float assuranceMeasure,
                         SecurityLevel stdLevel, usint relinWindow,
                         int depth = 1, int maxDepth = 2, MODE mode = RLWE)
      : LPCryptoParameters<Element>(params, encodingParams) {
    m_distributionParameter = distributionParameter;
    m_assuranceMeasure = assuranceMeasure;
    m_securityLevel = 0;
    m_relinWindow = relinWindow;
    m_dgg.SetStd(m_distributionParameter);
    m_depth = depth;
    m_maxDepth = maxDepth;
    m_mode = mode;
    m_stdLevel = stdLevel;
  }

  /**
   * Destructor
   */
  virtual ~LPCryptoParametersRLWE() {}

  /**
   * Returns the value of standard deviation r for discrete Gaussian
   * distribution
   *
   * @return the standard deviation r.
   */
  float GetDistributionParameter() const { return m_distributionParameter; }

  /**
   * Returns the values of assurance measure alpha
   *
   * @return the assurance measure.
   */
  float GetAssuranceMeasure() const { return m_assuranceMeasure; }

  /**
   * Returns the value of root Hermite factor security level /delta.
   *
   * @return the root Hermite factor /delta.
   */
  float GetSecurityLevel() const { return m_securityLevel; }

  /**
   * Returns the value of relinearization window.
   *
   * @return the relinearization window.
   */
  usint GetRelinWindow() const { return m_relinWindow; }

  /**
   * Returns the depth of computation circuit supported for these parameters
   * (not used now; for future use).
   *
   * @return the computation depth supported d.
   */
  int GetDepth() const { return m_depth; }

  /**
   * Returns the maximum homomorphic multiplication depth before performing
   * relinearization
   *
   * @return the computation depth supported d.
   */
  size_t GetMaxDepth() const { return m_maxDepth; }

  /**
   * Gets the mode setting: RLWE or OPTIMIZED.
   *
   * @return the mode setting.
   */
  MODE GetMode() const { return m_mode; }

  /**
   * Gets the standard security level
   *
   * @return the security level.
   */
  SecurityLevel GetStdLevel() const { return m_stdLevel; }

  /**
   * Returns reference to Discrete Gaussian Generator
   *
   * @return reference to Discrete Gaussian Generaror.
   */
  const typename Element::DggType &GetDiscreteGaussianGenerator() const {
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
   * Sets the value of security level /delta
   * @param securityLevel
   */
  void SetSecurityLevel(float securityLevel) {
    m_securityLevel = securityLevel;
  }

  /**
   * Sets the standard security level
   * @param standard security level
   */
  void SetStdLevel(SecurityLevel securityLevel) { m_stdLevel = securityLevel; }

  /**
   * Sets the value of relinearization window
   * @param relinWindow
   */
  void SetRelinWindow(usint relinWindow) { m_relinWindow = relinWindow; }

  /**
   * Sets the depth of computation circuit supported for these parameters (not
   * used now; for future use).
   * @param depth
   */
  void SetDepth(int depth) { m_depth = depth; }

  /**
   * Sets the value of the maximum power of secret key for which the
   * relinearization key is generated
   * @param depth
   */
  void SetMaxDepth(size_t maxDepth) { m_maxDepth = maxDepth; }

  /**
   * Configures the mode for generating the secret key polynomial
   * @param mode is RLWE or OPTIMIZED.
   */
  void SetMode(MODE mode) { m_mode = mode; }

  /**
   * == operator to compare to this instance of LPCryptoParametersRLWE object.
   *
   * @param &rhs LPCryptoParameters to check equality against.
   */
  bool operator==(const LPCryptoParameters<Element> &rhs) const {
    const auto *el =
        dynamic_cast<const LPCryptoParametersRLWE<Element> *>(&rhs);

    if (el == nullptr) return false;

    return this->GetPlaintextModulus() == el->GetPlaintextModulus() &&
           *this->GetElementParams() == *el->GetElementParams() &&
           *this->GetEncodingParams() == *el->GetEncodingParams() &&
           m_distributionParameter == el->GetDistributionParameter() &&
           m_assuranceMeasure == el->GetAssuranceMeasure() &&
           m_securityLevel == el->GetSecurityLevel() &&
           m_relinWindow == el->GetRelinWindow() && m_mode == el->GetMode() &&
           m_stdLevel == el->GetStdLevel();
  }

  void PrintParameters(std::ostream &os) const {
    LPCryptoParameters<Element>::PrintParameters(os);

    os << "Distrib parm " << GetDistributionParameter()
       << ", Assurance measure " << GetAssuranceMeasure() << ", Security level "
       << GetSecurityLevel() << ", Relin window " << GetRelinWindow()
       << ", Depth " << GetDepth() << ", Mode " << GetMode()
       << ", Standard security level " << GetStdLevel() << std::endl;
  }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::base_class<LPCryptoParameters<Element>>(this));
    ar(::cereal::make_nvp("dp", m_distributionParameter));
    ar(::cereal::make_nvp("am", m_assuranceMeasure));
    ar(::cereal::make_nvp("sl", m_securityLevel));
    ar(::cereal::make_nvp("rw", m_relinWindow));
    ar(::cereal::make_nvp("d", m_depth));
    ar(::cereal::make_nvp("md", m_maxDepth));
    ar(::cereal::make_nvp("mo", m_mode));
    ar(::cereal::make_nvp("slv", m_stdLevel));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    ar(::cereal::base_class<LPCryptoParameters<Element>>(this));
    ar(::cereal::make_nvp("dp", m_distributionParameter));
    m_dgg.SetStd(m_distributionParameter);
    ar(::cereal::make_nvp("am", m_assuranceMeasure));
    ar(::cereal::make_nvp("sl", m_securityLevel));
    ar(::cereal::make_nvp("rw", m_relinWindow));
    ar(::cereal::make_nvp("d", m_depth));
    ar(::cereal::make_nvp("md", m_maxDepth));
    ar(::cereal::make_nvp("mo", m_mode));
    ar(::cereal::make_nvp("slv", m_stdLevel));
  }

  std::string SerializedObjectName() const { return "RLWESchemeParameters"; }

 protected:
  // standard deviation in Discrete Gaussian Distribution
  float m_distributionParameter;
  // assurance measure alpha
  float m_assuranceMeasure;
  // root Hermite value /delta
  float m_securityLevel;
  // relinearization window
  usint m_relinWindow;
  // depth of computations; used for FHE
  int m_depth;
  // maximum depth support of a ciphertext without keyswitching
  // corresponds to the highest power of secret key for which evaluation keys
  // are genererated
  size_t m_maxDepth;
  // specifies whether the secret polynomials are generated from discrete
  // Gaussian distribution or ternary distribution with the norm of unity
  MODE m_mode;
  // Security level according in the HomomorphicEncryption.org standard
  SecurityLevel m_stdLevel;

  typename Element::DggType m_dgg;
};
}  // namespace lbcrypto

#endif
