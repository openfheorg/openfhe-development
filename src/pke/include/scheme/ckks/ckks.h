// @file ckks.h -- Operations for the CKKS cryptoscheme.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, Duality Technologies Inc.
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

/*
 * This code implements the CKKS homomorphic encryption scheme.
 */

#ifndef LBCRYPTO_CRYPTO_CKKS_H
#define LBCRYPTO_CRYPTO_CKKS_H

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "math/dftransfrm.h"
#include "palisade.h"
#include "utils/caller_info.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Crypto parameters class for RLWE-based  schemes.
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPCryptoParametersCKKS : public LPCryptoParametersRLWE<Element> {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;
  using DugType = typename Element::DugType;
  using DggType = typename Element::DggType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default Constructor.
   */
  LPCryptoParametersCKKS()
      : LPCryptoParametersRLWE<Element>(),
        m_ksTechnique(BV),
        m_rsTechnique(APPROXRESCALE),
        m_numPartQ(0),
        m_numPerPartQ(0),
        m_approxSF(0) {}

  /**
   * Copy constructor.
   *
   * @param rhs - source
   */
  LPCryptoParametersCKKS(const LPCryptoParametersCKKS &rhs)
      : LPCryptoParametersRLWE<Element>(rhs),
        m_ksTechnique(BV),
        m_rsTechnique(APPROXRESCALE),
        m_numPartQ(0),
        m_numPerPartQ(0),
        m_approxSF(0) {}

  /**
   * Constructor that initializes values.  Note that it is possible to set
   * parameters in a way that is overall infeasible for actual use. There are
   * fewer degrees of freedom than parameters provided.  Typically one chooses
   * the basic noise, assurance and security parameters as the typical
   * community-accepted values, then chooses the plaintext modulus and depth
   * as needed.  The element parameters should then be choosen to provide
   * correctness and security.  In some cases we would need to operate over
   * already encrypted/provided ciphertext and the depth needs to be
   * pre-computed for initial settings.
   *
   * @param params element parameters.
   * @param &plaintextModulus plaintext modulus.
   * @param distributionParameter noise distribution parameter.
   * @param assuranceMeasure assurance level.
   * @param securityLevel security level.
   * @param relinWindow the size of the relinearization window.
   * @param mode sets the mode of operation: RLWE or OPTIMIZED
   * @param depth depth which is set to 1.
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   * @param ksTech key switching method
   * @param rsTech rescaling method
   */
  LPCryptoParametersCKKS(shared_ptr<ParmType> params,
                         const PlaintextModulus &plaintextModulus,
                         float distributionParameter, float assuranceMeasure,
                         float securityLevel, usint relinWindow, MODE mode,
                         int depth = 1, int maxDepth = 2,
                         KeySwitchTechnique ksTech = BV,
                         RescalingTechnique rsTech = APPROXRESCALE)
      : LPCryptoParametersRLWE<Element>(
            params,
            EncodingParams(
                std::make_shared<EncodingParamsImpl>(plaintextModulus)),
            distributionParameter, assuranceMeasure, securityLevel, relinWindow,
            depth, maxDepth, mode) {
    m_ksTechnique = ksTech;
    m_rsTechnique = rsTech;
    m_numPartQ = 0;
    m_numPerPartQ = 0;
    m_approxSF = 0;
  }

  /**
   * Constructor that initializes values.
   *
   * @param params element parameters.
   * @param encodingParams plaintext space parameters.
   * @param distributionParameter noise distribution parameter.
   * @param assuranceMeasure assurance level.
   * @param securityLevel security level.
   * @param relinWindow the size of the relinearization window.
   * @param mode sets the mode of operation: RLWE or OPTIMIZED
   * @param depth depth which is set to 1.
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   * @param ksTech key switching method
   * @param rsTech rescaling method
   */
  LPCryptoParametersCKKS(shared_ptr<ParmType> params,
                         EncodingParams encodingParams,
                         float distributionParameter, float assuranceMeasure,
                         float securityLevel, usint relinWindow, MODE mode,
                         int depth = 1, int maxDepth = 2,
                         KeySwitchTechnique ksTech = BV,
                         RescalingTechnique rsTech = APPROXRESCALE)
      : LPCryptoParametersRLWE<Element>(
            params, encodingParams, distributionParameter, assuranceMeasure,
            securityLevel, relinWindow, depth, maxDepth, mode) {
    m_ksTechnique = ksTech;
    m_rsTechnique = rsTech;
    m_numPartQ = 0;
    m_numPerPartQ = 0;
    m_approxSF = 0;
  }

  /**
   * Destructor.
   */
  virtual ~LPCryptoParametersCKKS() {}

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(cereal::base_class<LPCryptoParametersRLWE<Element>>(this));
    ar(cereal::make_nvp("ks", m_ksTechnique));
    ar(cereal::make_nvp("rs", m_rsTechnique));
    ar(cereal::make_nvp("dnum", m_numPartQ));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(cereal::base_class<LPCryptoParametersRLWE<Element>>(this));
    ar(cereal::make_nvp("ks", m_ksTechnique));
    ar(cereal::make_nvp("rs", m_rsTechnique));
    ar(cereal::make_nvp("dnum", m_numPartQ));

    if (SERIALIZE_PRECOMPUTE) {
      this->PrecomputeCRTTables(m_ksTechnique, m_rsTechnique, m_numPartQ);
    }
  }

  std::string SerializedObjectName() const { return "CKKSSchemeParameters"; }
  static uint32_t SerializedVersion() { return 1; }

  /**
   * Computes all tables needed for decryption, homomorphic multiplication,
   * and key switching
   * @param ksTech the technique to use for key switching (e.g., BV or GHS).
   * @param rsTech the technique to use for rescaling (e.g., EXACTRESCALE or
   * APPROXRESCALE).
   * @return true on success
   */
  bool PrecomputeCRTTables(KeySwitchTechnique ksTech, RescalingTechnique rsTech,
                           uint32_t numLargeDigits = 0);

  /**
   * == operator to compare to this instance of LPCryptoParametersCKKS object.
   *
   * @param &rhs LPCryptoParameters to check equality against.
   */
  bool operator==(const LPCryptoParameters<Element> &rhs) const {
    const auto *el =
        dynamic_cast<const LPCryptoParametersCKKS<Element> *>(&rhs);

    if (el == nullptr) return false;

    return LPCryptoParametersRLWE<Element>::operator==(rhs) &&
           m_rsTechnique == el->GetRescalingTechnique() &&
           m_ksTechnique == el->GetKeySwitchTechnique() &&
           m_numPartQ == el->GetNumPartQ();
  }

  void PrintParameters(std::ostream &os) const {
    LPCryptoParametersRLWE<Element>::PrintParameters(os);
  }

  /**
   * Q^(l) = \prod_{j=0}^{l-1}
   * Gets the precomputed table of [Q^(l)*[Q^(l)^{-1}]_{q_l}/q_l]_{q_i}
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger> &GetQlQlInvModqlDivqlModq(size_t i) const {
    return m_QlQlInvModqlDivqlModq[i];
  }

  /**
   * Q^(l) = \prod_{j=0}^{l-1}
   * Gets the NTL precomputions for [Q^(l)*[Q^(l)^{-1}]_{q_l}/q_l]_{q_i}
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger> &GetQlQlInvModqlDivqlModqPrecon(
      size_t i) const {
    return m_QlQlInvModqlDivqlModqPrecon[i];
  }

  /**
   * Gets the precomputed table of [q_i^{-1}]_{q_j}
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger> &GetqInvModq(size_t i) const {
    return m_qInvModq[i];
  }

  /**
   * Gets the NTL precomputions for [q_i^{-1}]_{q_j}
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger> &GetqInvModqPrecon(size_t i) const {
    return m_qInvModqPrecon[i];
  }

  /**
   * Gets the Auxiliary CRT basis {P} = {p_1,...,p_k}
   * Used in GHS key switching
   *
   * @return the parameters CRT params
   */
  const shared_ptr<ILDCRTParams<BigInteger>> GetParamsP() const {
    return m_paramsP;
  }

  /**
   * Gets product P = \prod_j p_j
   * Used in GHS key switching
   *
   * @return product \prod_j p_j
   */
  const BigInteger &GetAuxModulus() const { return m_modulusP; }

  /**
   * Gets Auxiliary expanded CRT basis
   * Q*P = {q_1,...,q_l,p_1,...,p_k}
   * Used in GHS key switching
   *
   * @return the precomputed CRT params
   */
  const shared_ptr<ILDCRTParams<BigInteger>> GetParamsQP() const {
    return m_paramsQP;
  }

  /**
   * Gets the precomputed table of [P^{-1}]_{q_i}
   * Used in GHS key switching
   *
   * See more in "A full RNS variant of approximate homomorphic
   * encryption" by Cheon, et. al. Section 4.
   *
   * @return the precomputed table
   */
  const vector<NativeInteger> &GetPInvModq() const { return m_PInvModq; }

  /**
   * Gets the NTL precomputions for [P^{-1}]_{q_i}
   * Used for speeding up GHS key switching.
   *
   * @return the precomputed table
   */
  const vector<NativeInteger> &GetPInvModqPrecon() const {
    return m_PInvModqPrecon;
  }

  /**
   * Get the precomputed table of [(P/p_j)^{-1}]_{p_j}
   * Used in GHS key switching.
   *
   * See more in "A full RNS variant of approximate homomorphic
   * encryption" by Cheon, et. al. Section 4.
   *
   * @return the precomputed table
   */
  const vector<NativeInteger> &GetPHatInvModp() const { return m_PHatInvModp; }

  /**
   * Get the NTL precomputions for [(P/p_j)^{-1}]_{p_j}
   *
   * @return the precomputed table
   */
  const vector<NativeInteger> &GetPHatInvModpPrecon() const {
    return m_PHatInvModpPrecon;
  }

  /**
   * Gets the leveled precomputed table of [(Q^(l)/q_i)^{-1}]_{q_i}
   * Used in GHS key switching.
   *
   * See more in "A full RNS variant of approximate homomorphic
   * encryption" by Cheon, et. al. Section 4.
   *
   * @return the precomputed table
   */
  const vector<NativeInteger> &GetQlHatInvModq(uint32_t l) const {
    return m_LvlQHatInvModq[l];
  }

  /**
   * Get the NTL precomputions for [(Q^(l)/q_i)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
  const vector<NativeInteger> &GetQlHatInvModqPrecon(uint32_t l) const {
    return m_LvlQHatInvModqPrecon[l];
  }

  /**
   * Gets the precomputed table of [P/p_j]_{q_i}
   * Used in GHS key switching.
   *
   * See more in "A full RNS variant of approximate homomorphic
   * encryption" by Cheon, et. al. Section 4.
   *
   * @return the precomputed table
   */
  const vector<vector<NativeInteger>> &GetPHatModq() const {
    return m_PHatModq;
  }

  /**
   * Gets the leveled precomputed table of [Q^(l)/q_i]_{p_j}
   * Used in GHS key switching.
   *
   * See more in "A full RNS variant of approximate homomorphic
   * encryption" by Cheon, et. al. Section 4.
   *
   * @return the precomputed table
   */
  const vector<vector<NativeInteger>> &GetQlHatModp(uint32_t l) const {
    return m_LvlQHatModp[l];
  }

  /**
   * Gets the precomputed table of [P]_{q_i}
   * Used in GHS key switching.
   *
   * See more in "A full RNS variant of approximate homomorphic
   * encryption" by Cheon, et. al. Section 4.
   *
   * @return the precomputed table
   */
  const vector<NativeInteger> &GetPModq() const { return m_PModq; }

  /**
   * Gets the Barrett modulo reduction precomputation for q_i
   *
   * @return the precomputed table
   */
  const vector<DoubleNativeInt> &GetModqBarrettMu() const {
    return m_modqBarrettMu;
  }

  /**
   * Gets the Barrett modulo reduction precomputation for p_j
   *
   * @return the precomputed table
   */
  const vector<DoubleNativeInt> &GetModpBarrettMu() const {
    return m_modpBarrettMu;
  }

  /**
   * Method to retrieve the technique to be used for key switching.
   *
   * @return the key switching technique.
   */
  enum KeySwitchTechnique GetKeySwitchTechnique() const {
    return m_ksTechnique;
  }

  /**
   * Method to retrieve the technique to be used for rescaling.
   *
   * @return the rescaling technique.
   */
  enum RescalingTechnique GetRescalingTechnique() const {
    return m_rsTechnique;
  }

  /**
   * Method to retrieve the scaling factor of level l.
   * For APPROXRESCALE rescaling technique method always returns 2^p,
   * where p corresponds to plaintext modulus
   * @param l For EXACTRESCALE rescaling technique the level whose scaling
   * factor we want to learn. Levels start from 0 (no rescaling done - all
   * towers) and go up to K-1, where K is the number of towers supported.
   * @return the scaling factor.
   */
  double GetScalingFactorOfLevel(uint32_t l = 0) const {
    if (m_rsTechnique == EXACTRESCALE) {
      if (l >= m_scalingFactors.size()) {
        PALISADE_THROW(
            math_error,
            "LPCryptoParametersCKKS::GetScalingFactorOfLevel - Cannot "
            "return scaling factor of level " +
                std::to_string(l) + ". Current settings have up to " +
                std::to_string(m_scalingFactors.size()) +
                " levels, starting from 0.");
      }

      return m_scalingFactors[l];
    }

    return m_approxSF;
  }

  /**
   * Method to retrieve the modulus to be dropped of level l.
   * For APPROXRESCALE rescaling technique method always returns 2^p,
   * where p corresponds to plaintext modulus
   * @param l index of modulus to be dropped for EXACTRESCALE rescaling
   * technique
   *
   * @return the precomputed table
   */
  double GetModReduceFactor(uint32_t l = 0) const {
    if (m_rsTechnique == EXACTRESCALE) {
      return m_dmoduliQ[l];
    }

    return m_approxSF;
  }

  /**
   * Get the precomputed table of [Q/Q_j]_{q_i}
   * Used in HYBRID key switching.
   *
   * @return the precomputed table
   */
  const vector<vector<NativeInteger>> &GetPartQHatModq() const {
    return m_PartQHatModq;
  }

  /**
   * Method that returns the element parameters corresponding to
   * partitions {Q_j} of Q.
   *
   * @param j is the number of the digit we want to get the list of towers for.
   * @return the pre-computed values.
   */
  const shared_ptr<ILDCRTParams<BigInteger>> &GetParamsPartQ(
      uint32_t part) const {
    return m_paramsPartQ[part];
  }

  /*
   * Method that returns the element parameters corresponding to the
   * complementary basis of a single digit j, i.e., the basis consisting of
   * all other digits plus the special primes. Note that numTowers should be
   * up to l (where l is the number of towers).
   *
   * @param numTowers is the total number of towers there are in the
   * ciphertext.
   * @param digit is the index of the digit we want to get the complementary
   * partition from.
   * @return the partitions.
   */
  const shared_ptr<ILDCRTParams<BigInteger>> &GetParamsComplPartQ(
      uint32_t numTowers, uint32_t digit) const {
    return m_paramsComplPartQ[numTowers][digit];
  }

  /*
   * Method that returns the number of partitions.
   *
   * @return the number of partitions.
   */
  uint32_t GetNumberOfQPartitions() const { return m_paramsPartQ.size(); }

  /**
   * Method that returns the precomputed values for QHat^-1 mod qj, used in
   * HYBRID.
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger> &GetPartQHatInvModq(uint32_t part) const {
    return m_PartQHatInvModq[part];
  }

  /**
   * Method that returns the actual number of digits.
   *
   * @return the number of digits.
   */
  uint32_t GetNumPartQ() const { return m_numPartQ; }

  /**
   * Method that returns the number of towers within every digit.
   * This is the alpha parameter from the paper (see documentation
   * for KeySwitchHHybrid).
   *
   * @return the number of towers per digit.
   */
  uint32_t GetNumPerPartQ() const { return m_numPerPartQ; }

  /**
   * Method that returns the precomputed values for QHat^-1 mod qj within a
   * partition of towers, used in HYBRID.
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger> &GetPartQlHatInvModq(uint32_t part,
                                                   uint32_t sublvl) const {
    if (part < m_LvlPartQHatInvModq.size() &&
        sublvl < m_LvlPartQHatInvModq[part].size())
      return m_LvlPartQHatInvModq[part][sublvl];

    PALISADE_THROW(math_error,
                   "LPCryptoParametersCKKS::GetPartitionQHatInvModQTable - "
                   "index out of bounds.");
  }

  /**
   * Barrett multiplication precomputations getter.
   *
   * @param index The number of towers in the ciphertext.
   * @return the pre-computed values.
   */
  const vector<NativeInteger> &GetPartQlHatInvModqPrecon(
      uint32_t part, uint32_t sublvl) const {
    if (part < m_LvlPartQHatInvModqPrecon.size() &&
        sublvl < m_LvlPartQHatInvModqPrecon[part].size())
      return m_LvlPartQHatInvModqPrecon[part][sublvl];

    PALISADE_THROW(math_error,
                   "LPCryptoParametersCKKS::"
                   "GetPartitionQHatInvModQPreconTable - index "
                   "out of bounds.");
  }

  /**
   * Barrett multiplication precomputations getter.
   *
   * @param index The table containing [PartQHat]_{p_j}
   * @return the pre-computed values.
   */
  const vector<vector<NativeInteger>> &GetPartQlHatModp(uint32_t lvl,
                                                        uint32_t part) const {
    if (lvl < m_LvlPartQHatModp.size() && part < m_LvlPartQHatModp[lvl].size())
      return m_LvlPartQHatModp[lvl][part];

    PALISADE_THROW(math_error,
                   "LPCryptoParametersCKKS::GetPartitionQHatModPTable - "
                   "index out of bounds.");
  }

  /**
   * Barrett multiplication precomputations getter.
   *
   * @param index The number of towers in the ciphertext.
   * @return the pre-computed values.
   */
  const vector<DoubleNativeInt> &GetmodComplPartqBarrettMu(
      uint32_t lvl, uint32_t part) const {
    if (lvl < m_modComplPartqBarrettMu.size() &&
        part < m_modComplPartqBarrettMu[lvl].size())
      return m_modComplPartqBarrettMu[lvl][part];

    PALISADE_THROW(math_error,
                   "LPCryptoParametersCKKS::GetPartitionPrecon - index out "
                   "of bounds.");
  }

 private:
  // Stores the technique to use for key switching
  enum KeySwitchTechnique m_ksTechnique;

  // Stores the technique to use for rescaling
  enum RescalingTechnique m_rsTechnique;

  // Stores the partition size {PartQ} = {Q_1,...,Q_l}
  // where each Q_i is the product of q_j
  uint32_t m_numPartQ;

  // Stores the number of towers per Q_i
  uint32_t m_numPerPartQ;

  // Stores the composite moduli Q_i
  vector<BigInteger> m_moduliPartQ;

  // Stores the partition of the moduli that correspond to digit j
  vector<shared_ptr<ILDCRTParams<BigInteger>>> m_paramsPartQ;

  // Stores the complementary partition of each digit, which is
  // used in HYBRID key switching
  vector<vector<shared_ptr<ILDCRTParams<BigInteger>>>> m_paramsComplPartQ;

  // Stores the Barrett multiplication precomputation
  vector<vector<vector<DoubleNativeInt>>> m_modComplPartqBarrettMu;

  // Stores [Q/Q_j] for HYBRID
  vector<BigInteger> m_PartQHat;

  // Stores [Q/Q_j]_{q_i} for HYBRID
  vector<vector<NativeInteger>> m_PartQHatModq;

  // Stores [{Q/Q_j}^{-1}]_{q_i} for HYBRID
  vector<vector<NativeInteger>> m_PartQHatInvModq;

  // Stores [{(Q_k)^(l)/q_i}^{-1}]_{q_i} for HYBRID
  vector<vector<vector<NativeInteger>>> m_LvlPartQHatInvModq;

  // Stores NTL precomputations for [{(Q_k)^(l)/q_i}^{-1}]_{q_i}
  vector<vector<vector<NativeInteger>>> m_LvlPartQHatInvModqPrecon;

  // Stores [QHat_i]_{p_j}
  vector<vector<vector<vector<NativeInteger>>>> m_LvlPartQHatModp;

  // Q^(l) = \prod_{j=0}^{l-1}
  // Stores [Q^(l)*[Q^(l)^{-1}]_{q_l}/q_l]_{q_i}
  std::vector<std::vector<NativeInteger>> m_QlQlInvModqlDivqlModq;

  // Q^(l) = \prod_{j=0}^{l-1}
  // Stores NTL precomputations for [Q^(l)*[Q^(l)^{-1}]_{q_l}/q_l]_{q_i}
  std::vector<std::vector<NativeInteger>> m_QlQlInvModqlDivqlModqPrecon;

  // Stores [q_i]_{q_j}
  std::vector<std::vector<NativeInteger>> m_qInvModq;

  // Stores NTL precomputations for [q_i]_{q_j}
  std::vector<std::vector<NativeInteger>> m_qInvModqPrecon;

  // Params for Auxiliary CRT basis {P} = {p_1,...,p_k}
  // used in GHS key switching
  shared_ptr<ILDCRTParams<BigInteger>> m_paramsP;

  // Params for Extended CRT basis {QP} = {q_1...q_l,p_1,...,p_k}
  // used in GHS key switching
  shared_ptr<ILDCRTParams<BigInteger>> m_paramsQP;

  // Moduli product P (P=p1*p2*..pk) of the auxiliary CRT basis for GHS key
  // switching
  BigInteger m_modulusP;

  // Stores [P]_{q_i}, used in GHS key switching
  vector<NativeInteger> m_PModq;

  // Stores [P^{-1}]_{q_i}, required for GHS key switching
  vector<NativeInteger> m_PInvModq;

  // Stores NTL precomputations for [P^{-1}]_{q_i}
  vector<NativeInteger> m_PInvModqPrecon;

  // Stores [(P/p_j)^{-1}]_{p_j}, required for GHS key switching
  vector<NativeInteger> m_PHatInvModp;

  // Stores NTL precomputations for [(P/p_j)^{-1}]_{p_j}
  vector<NativeInteger> m_PHatInvModpPrecon;

  // Stores [(Q/q_i)^{-1}]_{q_i}
  // required for GHS key switching
  vector<vector<NativeInteger>> m_LvlQHatInvModq;

  // Stores NTL precomputations for [(Q/q_i)^{-1}]_{q_i}
  vector<vector<NativeInteger>> m_LvlQHatInvModqPrecon;

  // Stores [P/p_j]_{q_i}, required for GHS key switching
  vector<vector<NativeInteger>> m_PHatModq;

  // Stores [Q^(l)/q_i]_{p_j}, required for GHS key switching
  vector<vector<vector<NativeInteger>>> m_LvlQHatModp;

  // Stores the Barrett multiplication precomputation for p_j
  vector<DoubleNativeInt> m_modpBarrettMu;

  // Stores the Barrett multiplication precomputation for q_i
  vector<DoubleNativeInt> m_modqBarrettMu;

  // A vector holding the doubles that correspond to the exact
  // scaling factor of each level, when EXACTRESCALE is used.
  vector<double> m_scalingFactors;

  // Stores q_i as doubles
  vector<double> m_dmoduliQ;

  // Stores 2^ptm where ptm - plaintext modulus
  double m_approxSF;
};

/**
 * @brief Parameter generation for CKKS.
 */
template <class Element>
class LPAlgorithmParamsGenCKKS
    : public LPParameterGenerationAlgorithm<Element> {
 public:
  /**
   * Default constructor
   */
  LPAlgorithmParamsGenCKKS() {}

  /**
   * Method for computing all derived parameters based on chosen primitive
   * parameters. This method isfor BFV-family of schemes.
   *
   * @param cryptoParams the crypto parameters object to be populated with
   * parameters.
   * @param evalAddCount number of EvalAdds assuming no EvalMult and KeySwitch
   * operations are performed.
   * @param evalMultCount number of EvalMults assuming no EvalAdd and
   * KeySwitch operations are performed.
   * @param keySwitchCount number of KeySwitch operations assuming no EvalAdd
   * and EvalMult operations are performed.
   * @param dcrtBits number of bits in each CRT modulus
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   */
  bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams,
                 int32_t evalAddCount = 0, int32_t evalMultCount = 0,
                 int32_t keySwitchCount = 0, size_t dcrtBits = 0,
                 uint32_t n = 0) const {
    std::string errMsg = "This ParamsGen method is not implemented for CKKS.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Method for computing all derived parameters based on chosen primitive
   * parameters.
   *
   * @param *cryptoParams the crypto parameters object to be populated with
   * parameters.
   * @param cyclOrder the cyclotomic order.
   * @param numPrimes number of modulus towers to support.
   * @param scaleExp the bit-width for plaintexts and DCRTPoly's.
   * @param relinWindow the relinearization window
   * @param mode
   * @param ksTech the key switching technique used (e.g., BV or GHS)
   * @param firstModSize the bit-size of the first modulus
   * @param rsTech the rescaling technique used (e.g., APPROXRESCALE or
   * EXACTRESCALE)
   */
  bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams,
                 usint cyclOrder, usint numPrimes, usint scaleExp,
                 usint relinWindow, MODE mode, KeySwitchTechnique ksTech = BV,
                 usint firstModSize = 60, RescalingTechnique = APPROXRESCALE,
                 uint32_t numLargeDigits = 4) const;

  ~LPAlgorithmParamsGenCKKS() {}

  template <class Archive>
  void save(Archive &ar) const {
    ar(cereal::base_class<LPParameterGenerationAlgorithm<Element>>(this));
  }

  template <class Archive>
  void load(Archive &ar) {
    ar(cereal::base_class<LPParameterGenerationAlgorithm<Element>>(this));
  }

  std::string SerializedObjectName() const { return "CKKSParamsGen"; }
};

/**
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPAlgorithmCKKS : public LPEncryptionAlgorithm<Element> {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;
  using DugType = typename Element::DugType;
  using DggType = typename Element::DggType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmCKKS() {}

  /**
   * Method for encrypting plaintext using CKKS Scheme
   *
   * @param publicKey is the public key used for encryption.
   * @param plaintext the plaintext input.
   * @param doEncryption encrypts if true, embeds (encodes) the plaintext into
   * cryptocontext if false
   * @return ciphertext which results from encryption.
   */
  Ciphertext<Element> Encrypt(const LPPublicKey<Element> publicKey,
                              Element plaintext) const;

  /**
   * Method for encrypting plaintext using CKKS Scheme
   *
   * @param privateKey is the private key used for encryption.
   * @param plaintext the plaintext input.
   * @param doEncryption encrypts if true, embeds (encodes) the plaintext into
   * cryptocontext if false
   * @return ciphertext which results from encryption.
   */
  Ciphertext<Element> Encrypt(const LPPrivateKey<Element> privateKey,
                              Element plaintext) const;

  /**
   * Method for decrypting plaintext using CKKS
   *
   * @param &privateKey private key used for decryption.
   * @param &ciphertext ciphertext id decrypted.
   * @param *plaintext the plaintext output.
   * @return the success/fail result
   */
  DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
                        ConstCiphertext<Element> ciphertext,
                        NativePoly *plaintext) const;

  /**
   * Method for decrypting plaintext using CKKS
   *
   * @param &privateKey private key used for decryption.
   * @param &ciphertext ciphertext id decrypted.
   * @param *plaintext the plaintext output.
   * @return the success/fail result
   */
  DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
                        ConstCiphertext<Element> ciphertext,
                        Poly *plaintext) const;

  /**
   * Function to generate public and private keys
   *
   * @param cc is the cryptoContext which encapsulates the crypto paramaters.
   * @param makeSparse is a boolean flag that species if the key is
   * sparse(interleaved zeroes) or not.
   * @return KeyPair containting private key and public key.
   */
  LPKeyPair<Element> KeyGen(CryptoContext<Element> cc, bool makeSparse = false);

  template <class Archive>
  void save(Archive &ar) const {
    ar(cereal::base_class<LPEncryptionAlgorithm<Element>>(this));
  }

  template <class Archive>
  void load(Archive &ar) {
    ar(cereal::base_class<LPEncryptionAlgorithm<Element>>(this));
  }

  std::string SerializedObjectName() const { return "CKKSEncryption"; }
};

/**
 * Class for evaluation of somewhat homomorphic operations.
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPAlgorithmSHECKKS : public LPSHEAlgorithm<Element> {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;
  using DugType = typename Element::DugType;
  using DggType = typename Element::DggType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmSHECKKS() {}

  /**
   * Destructor
   */
  virtual ~LPAlgorithmSHECKKS() {}

  /**
   * Function for in-place homomorphic addition of ciphertexts.
   *
   * @param ciphertext1 first input/output ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @details \p ciphertext1 stores the result of \p ciphertext1 + \p
   * ciphertext2
   */
  void EvalAddInPlace(Ciphertext<Element> &ciphertext1,
                      ConstCiphertext<Element> ciphertext2) const override;

  /**
   * Function for homomorphic addition of ciphertexts.
   * Mutable version - input ciphertexts may get rescaled/level-reduced.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return result of homomorphic addition of input ciphertexts.
   */
  Ciphertext<Element> EvalAddMutable(
      Ciphertext<Element> &ciphertext1,
      Ciphertext<Element> &ciphertext2) const override {
    std::string errMsg =
        "LPAlgorithmSHECKKS::EvalAddMutable is only supported for DCRTPoly.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Function for homomorphic addition of ciphertexts.
   *
   * @param ciphertext input ciphertext.
   * @param plaintext input plaintext.
   * @return result of homomorphic addition of input ciphertexts.
   */
  Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext,
                              ConstPlaintext plaintext) const override;

  /**
   * Function for homomorphic addition of ciphertexts.
   * Mutable version - input ciphertexts may get rescaled/level-reduced.
   *
   * @param ciphertext input ciphertext.
   * @param plaintext input plaintext.
   * @return result of homomorphic addition of input ciphertexts.
   */
  Ciphertext<Element> EvalAddMutable(Ciphertext<Element> &ciphertext,
                                     Plaintext plaintext) const override {
    std::string errMsg =
        "LPAlgorithmSHECKKS::EvalAddMutable is only supported for DCRTPoly.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Function for adding a constant to a ciphertext.
   *
   * @param ciphertext input ciphertext.
   * @param constant input constant.
   * @return encrypted result of addition.
   */
  Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext,
                              double constant) const override;

  /**
   * Function for adding a constant to a ciphertext.
   * Mutable version - input ciphertexts may get rescaled/level-reduced.
   *
   * @param ciphertext input ciphertext.
   * @param constant input constant.
   * @return encrypted result of addition.
   */
  virtual Ciphertext<Element> EvalAddMutable(Ciphertext<Element> &ciphertext,
                                             double constant) const {
    std::string errMsg =
        "LPAlgorithmSHECKKS::EvalAddMutable is only supported for DCRTPoly.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Function for computing the linear weighted sum of a
   * vector of ciphertexts. It is implemented as a wrapper to
   * EvalLinearWSumMutable.
   *
   * @param ciphertexts vector of input ciphertexts.
   * @param constants vector containing double weights.
   * @return A ciphertext containing the linear weighted sum.
   */
  Ciphertext<Element> EvalLinearWSum(vector<Ciphertext<Element>> ciphertexts,
                                     vector<double> constants) const override {
    std::string errMsg =
        "LPAlgorithmSHECKKS::EvalLinearWSum is only supported for DCRTPoly.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Function for computing the linear weighted sum of a
   * vector of ciphertexts. This is a mutable method,
   * meaning that the level/depth of input ciphertexts may change.
   *
   * @param ciphertexts vector of input ciphertexts.
   * @param constants vector containing double weights.
   * @return A ciphertext containing the linear weighted sum.
   */
  Ciphertext<Element> EvalLinearWSumMutable(
      vector<Ciphertext<Element>> ciphertexts,
      vector<double> constants) const override {
    std::string errMsg =
        "LPAlgorithmSHECKKS::EvalLinearWSumMutable is only supported for "
        "DCRTPoly.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Function for homomorphic subtraction of ciphertexts.
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return result of homomorphic subtraction of input ciphertexts.
   */
  Ciphertext<Element> EvalSub(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2) const override;

  /**
   * Function for homomorphic subtraction of ciphertexts.
   * Mutable version - input ciphertexts may get rescaled/level-reduced.
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return result of homomorphic subtraction of input ciphertexts.
   */
  Ciphertext<Element> EvalSubMutable(
      Ciphertext<Element> &ciphertext1,
      Ciphertext<Element> &ciphertext2) const override {
    std::string errMsg =
        "LPAlgorithmSHECKKS::EvalSubMutable is only supported for DCRTPoly.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Function for homomorphic subtraction of ciphertexts.
   *
   * @param ciphertext1 the input ciphertext.
   * @param plaintext the input plaintext.
   * @return result of homomorphic subtraction of input ciphertexts.
   */
  Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext1,
                              ConstPlaintext plaintext) const override;

  /**
   * Function for homomorphic subtraction of ciphertexts.
   * Mutable version - input ciphertexts may get rescaled/level-reduced.
   *
   * @param ciphertext1 the input ciphertext.
   * @param plaintext the input plaintext.
   * @return result of homomorphic subtraction of input ciphertexts.
   */
  Ciphertext<Element> EvalSubMutable(Ciphertext<Element> &ciphertext1,
                                     Plaintext plaintext) const override {
    std::string errMsg =
        "LPAlgorithmSHECKKS::EvalSubMutable is only supported for DCRTPoly.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Function for subtracting a constant from a ciphertext.
   *
   * @param ciphertext input ciphertext.
   * @param constant input constant.
   * @return encrypted result of substraction.
   */
  Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext,
                              double constant) const override;

  /**
   * Function for subtracting a constant from a ciphertext.
   * Mutable version - input ciphertexts may get rescaled/level-reduced.
   *
   * @param ciphertext input ciphertext.
   * @param constant input constant.
   * @return encrypted result of substraction.
   */
  virtual Ciphertext<Element> EvalSubMutable(Ciphertext<Element> &ciphertext,
                                             double constant) const {
    std::string errMsg =
        "LPAlgorithmSHECKKS::EvalSubMutable is only supported for DCRTPoly.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Function for homomorphic multiplication of ciphertexts without key
   * switching. Currently it assumes that the input arguments are fresh
   * ciphertexts (of depth 1). Support for the input ciphertexts of higher
   * depths will be added later.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return result of homomorphic multiplication of input ciphertexts.
   */
  Ciphertext<Element> EvalMult(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2) const override;

  /**
   * Function for homomorphic multiplication of ciphertexts without key
   * switching. Mutable version - input ciphertexts may get
   * rescaled/level-reduced.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return result of homomorphic multiplication of input ciphertexts.
   */
  Ciphertext<Element> EvalMultMutable(
      Ciphertext<Element> &ciphertext1,
      Ciphertext<Element> &ciphertext2) const override {
    std::string errMsg =
        "LPAlgorithmSHECKKS::EvalMultMutable is only supported for DCRTPoly.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Function for multiplying ciphertext by plaintext.
   *
   * @param ciphertext input ciphertext.
   * @param plaintext input plaintext embedded in the cryptocontext.
   * @return result of the multiplication.
   */
  Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext,
                               ConstPlaintext plaintext) const override;

  /**
   * Function for multiplying ciphertext by plaintext.
   * Mutable version - input ciphertexts may get rescaled/level-reduced.
   *
   * @param ciphertext input ciphertext.
   * @param plaintext input plaintext embedded in the cryptocontext.
   * @return result of the multiplication.
   */
  Ciphertext<Element> EvalMultMutable(Ciphertext<Element> &ciphertext,
                                      Plaintext plaintext) const override {
    std::string errMsg =
        "LPAlgorithmSHECKKS::EvalMultMutable is only supported for DCRTPoly.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Function for multiplying a ciphertext by a constant.
   *
   * @param ciphertext input ciphertext.
   * @param constant input constant.
   * @return encrypted result of multiplication.
   */
  Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext,
                               double constant) const override;

  /**
   * Function for multiplying a ciphertext by a constant.
   * Mutable version - input ciphertexts may get rescaled/level-reduced.
   *
   * @param ciphertext input ciphertext.
   * @param constant input constant.
   * @return encrypted result of multiplication.
   */
  Ciphertext<Element> EvalMultMutable(Ciphertext<Element> &ciphertext,
                                      double constant) const override {
    std::string errMsg =
        "LPAlgorithmSHECKKS::EvalMultMutable is only supported for DCRTPoly.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Function for homomorphic multiplication of ciphertexts followed by key
   * switching operation. Currently it assumes that the input arguments are
   * fresh ciphertexts (of depth 1). Support for the input ciphertexts of
   * higher depths will be added later.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @param ek is the evaluation key to make the newCiphertext decryptable by
   * the same secret key as that of ciphertext1 and ciphertext2.
   * @return result of homomorphic multiplication of input ciphertexts.
   */
  Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1,
                               ConstCiphertext<Element> ciphertext2,
                               const LPEvalKey<Element> ek) const override;

  /**
   * Function for homomorphic multiplication of ciphertexts followed by key
   * switching operation. Mutable version - input ciphertexts may get
   * rescaled/level-reduced.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @param ek is the evaluation key to make the newCiphertext decryptable by
   * the same secret key as that of ciphertext1 and ciphertext2.
   * @return result of homomorphic multiplication of input ciphertexts.
   */
  Ciphertext<Element> EvalMultMutable(
      Ciphertext<Element> &ciphertext1, Ciphertext<Element> &ciphertext2,
      const LPEvalKey<Element> ek) const override;

  /**
   * Unimplemented function to support  a multiplication with depth larger
   * than 2 for the CKKS scheme.
   *
   * @param ciphertext1 The first input ciphertext.
   * @param ciphertext2 The second input ciphertext.
   * @param ek The evaluation key input.
   * @return A shared pointer to the ciphertext which is the EvalMult of the
   * two inputs.
   */
  Ciphertext<Element> EvalMultAndRelinearize(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2,
      const vector<LPEvalKey<Element>> &ek) const override {
    std::string errMsg =
        "LPAlgorithmSHECKKS::EvalMultAndRelinearize is not implemented for "
        "the "
        "CKKS Scheme.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /*
   * Relinearize a ciphertext.
   *
   * @param ciphertext input ciphertext to be relinearized
   * @param ek The evaluation key input.
   * @return the relinearized ciphertext
   */
  Ciphertext<Element> Relinearize(
      ConstCiphertext<Element> ciphertext,
      const vector<LPEvalKey<Element>> &ek) const override {
    std::string errMsg =
        "LPAlgorithmSHECKKS::Relinearize is not implemented for the non "
        "Double-CRT variant of the CKKS Scheme.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /*
   * Relinearize a ciphertext in place.
   *
   * @param ciphertext input ciphertext to be relinearized
   * @param ek The evaluation key input.
   * @return the relinearized ciphertext
   */
  void RelinearizeInPlace(
      Ciphertext<Element> &ciphertext,
      const vector<LPEvalKey<Element>> &ek) const override {
    std::string errMsg =
        "LPAlgorithmSHECKKS::RelinearizeInPlace is not implemented for the non "
        "Double-CRT variant of the CKKS Scheme.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Function for homomorphic negation of ciphertexts.
   *
   * @param ct first input ciphertext.
   * @return new ciphertext.
   */
  Ciphertext<Element> EvalNegate(ConstCiphertext<Element> ct) const override;

  /**
   * Method for generating a key switch matrix for HYBRID key switching.
   * HYBRID key switching is described in Section 3 of Han, et. al.,
   * "Better bootstrapping for approximate homomorphic encryption".
   *
   * @param oldKey Original private key used for encryption.
   * @param newKey New private key to generate the keyswitch hint.
   * @param ek The evaluation key input.
   * @return resulting keySwitchHint.
   */
  LPEvalKey<Element> KeySwitchHybridGen(
      const LPPrivateKey<Element> oldKey, const LPPrivateKey<Element> newKey,
      const LPEvalKey<DCRTPoly> ek = nullptr) const {
    std::string errMsg =
        "LPAlgorithmSHECKKS::KeySwitchHybridGen is not implemented for the "
        "non "
        "Double-CRT variant of the CKKS Scheme.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Method for in-place key switching using the HYBRID method. HYBRID key
   * switching is described in Section 3 of Han, et. al., "Better bootstrapping
   * for approximate homomorphic encryption".
   * @param keySwitchHint Hint required to perform the ciphertext switching.
   * @param ciphertext Original ciphertext to perform in-place key switching on.
   */
  void KeySwitchHybridInPlace(const LPEvalKey<Element> keySwitchHint,
                              Ciphertext<Element> &ciphertext) const {
    std::string errMsg =
        "LPAlgorithmSHECKKS::KeySwitchHybridInPlace is not implemented for the "
        "non Double-CRT variant of the CKKS Scheme.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Method for generating a key switch matrix for GHS key switching.
   * GHS key switching was introduced in Gentry, et. al., "Homomorphic
   * evaluation of the AES circuit (Updated implementation)". Here, we
   * follow the notation of Section 3.2 of "A full RNS variant of
   * approximate homomorphic encryption" (RNS CKKS paper).
   *
   * @param oldKey Original private key used for encryption.
   * @param newKey New private key to generate the keyswitch hint.
   * @param ek The evaluation key input.
   * @return resulting keySwitchHint.
   */
  LPEvalKey<Element> KeySwitchGHSGen(
      const LPPrivateKey<DCRTPoly> oldKey, const LPPrivateKey<DCRTPoly> newKey,
      const LPEvalKey<DCRTPoly> ek = nullptr) const;

  /**
   * Method for in-place key switching using the GHS method introduced in
   * Gentry, et. al., "Homomorphic evaluation of the AES circuit (Updated
   * implementation)". Here, we follow the notation of Section 3.2 of
   * "A full RNS variant of approximate homomorphic encryption" (RNS
   * CKKS paper).
   *
   * @param keySwitchHint Hint required to perform the ciphertext switching.
   * @param ciphertext Original ciphertext to perform switching on.
   */
  void KeySwitchGHSInPlace(const LPEvalKey<Element> keySwitchHint,
                           Ciphertext<Element> &ciphertext) const;

  /**
   * Method for generating a key switch matrix for BV key switching.
   * BV key switching was introduced in Brakerski, et. al., "Efficient
   * full homomorphic encryption from (standard) LWE". Here, we follow
   * Section 3.2 of "(Leveled) fully homomorphic encryption without
   * bootstrapping" (BGV paper).
   *
   * @param oldKey Original private key used for encryption.
   * @param newKey New private key to generate the keyswitch hint.
   * @param ek The evaluation key input.
   * @return resulting keySwitchHint.
   */
  LPEvalKey<Element> KeySwitchBVGen(
      const LPPrivateKey<Element> oldKey, const LPPrivateKey<Element> newKey,
      const LPEvalKey<DCRTPoly> ek = nullptr) const;

  /**
   * Method for in-place key switching using the BV method introduced in
   * Brakerski, et. al., "Efficient full homomorphic encryption from (standard)
   * LWE". Here, we follow Section 3.2 of "(Leveled) fully homomorphic
   * encryption without bootstrapping" (BGV paper).
   *
   * @param keySwitchHint Hint required to perform the ciphertext switching.
   * @param ciphertext Original ciphertext to perform in-place key switching on.
   */
  void KeySwitchBVInPlace(const LPEvalKey<Element> keySwitchHint,
                          Ciphertext<Element> &ciphertext) const;

  /**
   * Method for generating a KeySwitchHint using RLWE relinearization
   *
   * @param oldKey Original private key used for encryption.
   * @param newKey New private key to generate the keyswitch hint.
   * @return resulting keySwitchHint.
   */
  LPEvalKey<Element> KeySwitchGen(
      const LPPrivateKey<Element> oldKey,
      const LPPrivateKey<Element> newKey) const override;

  /**
   * Method for KeySwitching based on a KeySwitchHint - uses the RLWE
   * relinearization
   *
   * @param keySwitchHint Hint required to perform the ciphertext switching.
   * @param ciphertext Original ciphertext to perform switching on.
   */
  void KeySwitchInPlace(const LPEvalKey<Element> keySwitchHint,
                        Ciphertext<Element> &ciphertext) const override;

  /**
   * Function to generate key switch hint on a ciphertext for depth 2.
   *
   * @param privateKey is the original private key used for generating
   * ciphertext.
   * @return keySwitchHint generated to switch the ciphertext.
   */
  LPEvalKey<Element> EvalMultKeyGen(
      const LPPrivateKey<Element> privateKey) const override;

  /**
   * Function to generate key switch hint on a ciphertext for depth more
   * than 2. Currently this method is not supported for CKKS.
   *
   * @param privateKey is the original private key used for generating
   * ciphertext.
   * @return keySwitchHint generated to switch the ciphertext.
   */
  vector<LPEvalKey<Element>> EvalMultKeysGen(
      const LPPrivateKey<Element> privateKey) const override;

  /**
   * Function for evaluating automorphism of ciphertext at index i
   *
   * @param ciphertext the input ciphertext.
   * @param i automorphism index
   * @param &evalKeys - reference to the map of evaluation keys generated by
   * EvalAutomorphismKeyGen.
   * @return resulting ciphertext
   */
  Ciphertext<Element> EvalAutomorphism(
      ConstCiphertext<Element> ciphertext, usint i,
      const std::map<usint, LPEvalKey<Element>> &evalKeys,
      CALLER_INFO_ARGS_HDR) const override;

  /**
   * Generate automophism keys for a given private key; Uses the private key
   * for encryption
   *
   * @param privateKey private key.
   * @param indexList list of automorphism indices to be computed
   * @return returns the evaluation keys
   */
  shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(
      const LPPrivateKey<Element> privateKey,
      const std::vector<usint> &indexList) const override;

  /**
   * Generate automophism keys for a given private key; Uses the public key
   * for encryption
   *
   * @param publicKey public key.
   * @param privateKey private key.
   * @param indexList list of automorphism indices to be computed
   * @return returns the evaluation keys
   */
  shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(
      const LPPublicKey<Element> publicKey,
      const LPPrivateKey<Element> privateKey,
      const std::vector<usint> &indexList) const override {
    std::string errMsg =
        "LPAlgorithmSHECKKS::EvalAutomorphismKeyGen is not implemented for "
        "CKKS SHE Scheme.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * EvalFastRotationPrecompute is a wrapper for the hoisted automorphism
   * pre-computation step, in schemes BV, GHS, and Hybrid.
   *
   * @param ciphertext the input ciphertext on which to do the precomputation
   * (digit decomposition)
   */
  shared_ptr<vector<Element>> EvalFastRotationPrecompute(
      ConstCiphertext<Element> ciphertext) const override;

  /**
   * EvalFastRotation is a wrapper for hoisted automorphism.
   * It decides what version of EvalFastRotation to perform, based on the
   * key switching technique currently used (e.g., BV or GHS key switching).
   *
   * @param ciphertext the input ciphertext to perform the automorphism on
   * @param index the index of the rotation. Positive indices correspond to
   * left rotations and negative indices correspond to right rotations.
   * @param m is the cyclotomic order
   * @param precomp In BV, this is the digit decomposition created by
   * 		  EvalFastRotationPrecomputeBV. In GHS, this is the expanded
   * part of the ciphertext.
   */
  Ciphertext<Element> EvalFastRotation(
      ConstCiphertext<Element> ciphertext, const usint index, const usint m,
      const shared_ptr<vector<Element>> precomp) const override;

  /**
   * Function used in EXACTRESCALE to change the level of a ciphertext, while
   * at the same time adjusting the scaling factor of the target level.
   * AdjustLevelWithRescale assumes input is of depth 1 and output of depth 1
   * too. It performs a rescale (ModReduce) operation to bring the output to
   * the desired depth.
   *
   * A description of how the EXACTRESCALE version of CKKS works:
   *
   * Each ciphertext/plaintext is at a given level and depth. Levels
   * correspond to the number of rescaling operations previously performed
   * on the ciphertext (i.e., fresh ciphertexts are of level 0, after one
   * rescale they become level 1 and so on). Plaintexts can be created at
   * any chosen valid level, and ciphertexts inherit the level and depth of
   * the plaintexts they were created with. Depth corresponds to the number
   * of multiplications without rescaling that have been performed. E.g., the
   * product of two ciphertexts of depth 1 is of depth 2, and it becomes depth
   * 1 after we apply a rescaling (mod reduce) operation.
   *
   * One can think of rescaling in CKKS as dropping a tower and dividing with
   * the modulus corresponding to that tower. For that reason, the rescaling
   * operation slightly changes the scaling factor with which the plaintext is
   * scaled to support real number arithmetic. There are two ways to deal with
   * this: (1) ignore the change in scaling factor and incur an approximation
   * error in the value of the ciphertext, or (2) adjust the value of the
   * scaling factor by performing an EvalMult operation with a double operand.
   * Solution (1) is implemented in the APPROXRESCALE variant of CKKS, and
   * approach (2) in EXACTRESCALE.
   *
   * In EXACTRESCALE, each level has a particular scaling factor SF_i:
   * Level 0: SF_0 = q_L
   * Level 1: SF_1 = SF_0^2 / q_L = 2^2p / q_L
   * Level 2: SF_2 = SF_1^2 / q_{L-1} = 2^4p / q_L^2 * q_{L-1}
   * ...
   * The scaling factor of level i at depth j is (SF_i)^j.
   *
   * The selection of scaling factors follows the natural way scaling factors
   * are changed with every multiplication and rescale operation (squared
   * scaling factor divided by tower modulus). However, this is true only if
   * we always multiply ciphertexts that are of depth 1, otherwise we may get
   * scaling factors that do not exactly match the chosen values above. Since
   * this is a good practice anyway, we decided to make this the default
   * behavior in EXACTRESCALE, and therefore we do not allow the user to
   * manually perform rescaling - it is automatically performed whenever the
   * user tries to multiply ciphertexts that are not of depth 1. A side effect
   * of this is that all ciphertexts in CKKS/EXACTRESCALE will be depth 1 or
   * 2 only.
   *
   * Since levels have different scaling factors, we need to make sure that
   * ciphertexts/plaintexts are adjusted to the correct scaling factor
   * whenever we have an operation between ciphertexts of different levels.
   * This is in general achieved with a multiplication by a double value
   * called an adjustment factor. There are many cases that need to be covered
   * - EvalAdd/Sub/Mult for all possible combinations of valid ciphertexts in
   * the CKKS scheme (i.e., fresh L:i/D:1, or L:i/D:2). This logic is
   * implemented in EvalAdd/Sub/MultMutable and the AdjustLevelWithRescale and
   * AdjustLevelWithoutRescale methods.
   *
   * @param ciphertext input ciphertext.
   * @param targetLevel The number of the level we want to take this
   * ciphertext to. Levels are numbered from 0 (all towers) to
   * GetNumberOfTowers()-1 (one remaining tower).
   * @return A ciphertext containing the same value as c1, but at level
   * targetLevel.
   */
  Ciphertext<Element> AdjustLevelWithRescale(
      Ciphertext<Element> &ciphertext, uint32_t targetLevel) const override {
    std::string errMsg =
        "LPAlgorithmSHECKKS::AdjustLevelWithoutRescale is not implemented "
        "for "
        "the non Double-CRT variant of the CKKS Scheme.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Function used in EXACTRESCALE to change the level of a ciphertext, while
   * at the same time adjusting the scaling factor of the target level.
   * AdjustLevelWithoutRescale assumes input is of depth 1 and output of depth
   * 2. It performs a rescaling (ModReduce) operation, and is used in
   * addition/subtraction in EXACTRESCALE.
   *
   * Please refer to the AdjustLevelWithRescale documentation to see how
   * EXACTRESCALE works in CKKS.
   *
   * @param ciphertext input ciphertext.
   * @param targetLevel The number of the level we want to take this
   * ciphertext to. Levels are numbered from 0 (all towers) to
   * GetNumberOfTowers()-1 (one remaining tower).
   * @return A ciphertext containing the same value as c1, but at level
   * targetLevel.
   */
  Ciphertext<Element> AdjustLevelWithoutRescale(Ciphertext<Element> &ciphertext,
                                                uint32_t targetLevel) const {
    std::string errMsg =
        "LPAlgorithmSHECKKS::AdjustLevelWithoutRescale is not implemented "
        "for "
        "the non Double-CRT variant of the CKKS Scheme.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

 protected:
  /**
   * Internal function for multiplying a ciphertext by a plaintext
   * in the APPROXRESCALE variant.
   *
   * @param ciphertext input ciphertext.
   * @param constant input constant.
   * @return encrypted result of multiplication.
   */
  virtual Ciphertext<DCRTPoly> EvalMultApprox(
      ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
    std::string errMsg =
        "LPAlgorithmSHECKKS::EvalMultApprox with plaintext is only supported "
        "for DCRTPoly.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Internal function for homomorphic addition of ciphertext
   * and plaintext. This method does not check whether input
   * ciphertexts are at the same level.
   *
   * @param ciphertext input ciphertext.
   * @param ptElement the Element corresponding to the input plaintext.
   * @param ptDepth the scaling factor (depth) of the input plaintext.
   * @return result of homomorphic addition of inputs.
   */
  Ciphertext<Element> EvalAddCorePlaintext(ConstCiphertext<Element> ciphertext,
                                           Element ptElement,
                                           usint ptDepth) const;

  /**
   * Internal function for homomorphic subtraction of ciphertext
   * and plaintext. This method does not check whether input
   * ciphertexts are at the same level.
   *
   * @param ciphertext input ciphertext.
   * @param ptElement the Element corresponding to the input plaintext.
   * @param ptDepth the scaling factor (depth) of the input plaintext.
   * @return result of homomorphic subtraction of inputs.
   */
  Ciphertext<Element> EvalSubCorePlaintext(ConstCiphertext<Element> ciphertext,
                                           Element ptElement,
                                           usint ptDepth) const;

  /**
   * Internal function to automatically level-reduce a ciphertext and a
   * plaintext.
   *
   * @param ciphertext1 input ciphertext.
   * @param plaintext input plaintext.
   * @return a vector containing two ciphertexts of the same level.
   */
  std::pair<shared_ptr<ConstCiphertext<Element>>, Element> AutomaticLevelReduce(
      ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const;

  /**
   * EvalFastRotationPrecomputeBV implements the precomputation step of
   * hoisted automorphisms for the BV key switching scheme.
   *
   * Please refer to Section 5 of Halevi and Shoup, "Faster Homomorphic
   * linear transformations in HELib." for more details, link:
   * https://eprint.iacr.org/2018/244.
   *
   * Generally, automorphisms are performed with three steps: (1) the
   * automorphism is applied on the ciphertext, (2) the automorphed values are
   * decomposed into digits, and (3) key switching is applied to make it
   * possible to further compute on the ciphertext.
   *
   * Hoisted automorphisms is a technique that performs the digit
   * decomposition for the original ciphertext first, and then performs the
   * automorphism and the key switching on the decomposed digits. The benefit
   * of this is that the digit decomposition is independent of the
   * automorphism rotation index, so it can be reused for multiple different
   * indices. This can greatly improve performance when we have to compute
   * many automorphisms on the same ciphertext. This routinely happens when we
   * do permutations (EvalPermute).
   *
   * EvalFastRotationPrecompute implements the digit decomposition step of
   * hoisted automorphisms.
   *
   * @param ciphertext the input ciphertext on which to do the precomputation
   * (digit decomposition)
   */
  shared_ptr<vector<Element>> EvalFastRotationPrecomputeBV(
      ConstCiphertext<Element> ciphertext) const;

  /**
   * EvalFastRotationBV implements the automorphism and key switching step of
   * hoisted automorphisms in the BV key switching scheme.
   *
   * Please refer to Section 5 of Halevi and Shoup, "Faster Homomorphic
   * linear transformations in HELib." for more details, link:
   * https://eprint.iacr.org/2018/244.
   *
   * Generally, automorphisms are performed with three steps: (1) the
   * automorphism is applied on the ciphertext, (2) the automorphed values are
   * decomposed into digits, and (3) key switching is applied to make it
   * possible to further compute on the ciphertext.
   *
   * Hoisted automorphisms is a technique that performs the digit
   * decomposition for the original ciphertext first, and then performs the
   * automorphism and the key switching on the decomposed digits. The benefit
   * of this is that the digit decomposition is independent of the
   * automorphism rotation index, so it can be reused for multiple different
   * indices. This can greatly improve performance when we have to compute
   * many automorphisms on the same ciphertext. This routinely happens when we
   * do permutations (EvalPermute).
   *
   * EvalFastRotation implements the automorphism and key swithcing step of
   * hoisted automorphisms.
   *
   * This method assumes that all required rotation keys exist. This may not
   * be true if we are using baby-step/giant-step key switching. Please refer
   * to Section 5.1 of the above reference and EvalPermuteBGStepHoisted to see
   * how to deal with this issue.
   *
   * @param ciphertext the input ciphertext to perform the automorphism on
   * @param index the index of the rotation. Positive indices correspond to
   * left rotations and negative indices correspond to right rotations.
   * @param m is the cyclotomic order
   * @param digits the digit decomposition created by
   * EvalFastRotationPrecompute at the precomputation step.
   * @param evalKey is the rotation key that corresponds to the index
   * (computed in wrapper EvalFastRotation)
   */
  Ciphertext<Element> EvalFastRotationBV(
      ConstCiphertext<Element> ciphertext, const usint index, const usint m,
      const shared_ptr<vector<Element>> digits,
      LPEvalKey<DCRTPoly> evalKey) const;

  /**
   * EvalFastRotationPrecomputeGHS implements the precomputation step of
   * hoisted automorphisms for the GHS key switching scheme.
   *
   * You can find more information about the GHS key switching technique
   * in "Homomorphic evaluation of the AES circuit (Updated
   * implementation)" and in "A full RNS variant of approximate
   * homomorphic encryption" (RNS CKKS paper).
   *
   * Here, we hoist the first part of key switching (ModUp), and only
   * repeat the remaining steps (multiplication with eval key and
   * ModDown's) for subsequent automorphisms.
   *
   * @param ciphertext the input ciphertext on which to do the precomputation
   */
  shared_ptr<vector<Element>> EvalFastRotationPrecomputeGHS(
      ConstCiphertext<Element> ciphertext) const;

  /**
   * EvalFastRotationGHS implements the automorphism and key switching step of
   * hoisted automorphisms in the GHS key switching scheme.
   *
   * You can find more information about the GHS key switching technique
   * in "Homomorphic evaluation of the AES circuit (Updated
   * implementation)" and in "A full RNS variant of approximate
   * homomorphic encryption" (RNS CKKS paper).
   *
   * @param ciphertext the input ciphertext to perform the automorphism on
   * @param index the index of the rotation. Positive indices correspond to
   * left rotations and negative indices correspond to right rotations.
   * @param m is the cyclotomic order
   * @param expandedCiphertext the result of ModUp on one of the ciphertext
   * parts, which is generated by EvalFastRotationPrecomputeGHS at the
   * precomputation step.
   * @param evalKey is the rotation key that corresponds to the index
   * (computed in wrapper EvalFastRotation)
   */
  Ciphertext<Element> EvalFastRotationGHS(
      ConstCiphertext<Element> ciphertext, const usint index, const usint m,
      const shared_ptr<vector<Element>> expandedCiphertext,
      LPEvalKey<DCRTPoly> evalKey) const;

  /**
   * EvalFastRotationPrecomputeHybrid implements the precomputation step of
   * hoisted automorphisms for the HYBRID key switching scheme.
   *
   * You can find more information about the HYBRID key switching technique
   * in "Better bootstrapping for approximate homomorphic encryption".
   *
   * Here, we hoist the first part of key switching (ModUp), and the RNS
   * digit decomposition. We repeat the remaining steps for subsequent
   * automorphisms.
   *
   * @param ciphertext the input ciphertext on which to do the precomputation
   */
  shared_ptr<vector<Element>> EvalFastRotationPrecomputeHybrid(
      ConstCiphertext<Element> ciphertext) const;

  /**
   * EvalFastRotationHybrid implements the automorphism and key switching step
   * of hoisted automorphisms in the HYBRID key switching scheme.
   *
   * You can find more information about the HYBRID key switching technique
   * in "Better bootstrapping for approximate homomorphic encryption".
   *
   * @param ciphertext the input ciphertext to perform the automorphism on
   * @param index the index of the rotation. Positive indices correspond to
   * left rotations and negative indices correspond to right rotations.
   * @param m is the cyclotomic order
   * @param expandedCiphertext the result of ModUp and RNS digit decomposition
   * on one of the ciphertext parts, which is generated by
   * EvalFastRotationPrecomputeHybrid at the precomputation step.
   * @param evalKey is the rotation key that corresponds to the index
   * (computed in wrapper EvalFastRotation)
   */
  Ciphertext<Element> EvalFastRotationHybrid(
      ConstCiphertext<Element> ciphertext, const usint index, const usint m,
      const shared_ptr<vector<Element>> expandedCiphertext,
      LPEvalKey<DCRTPoly> evalKey) const;

 private:
  /**
   * Internal function for homomorphic addition of ciphertexts.
   * This method does not check whether input ciphertexts are
   * at the same level.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return result of homomorphic addition of input ciphertexts.
   */
  Ciphertext<Element> EvalAddCore(ConstCiphertext<Element> ciphertext1,
                                  ConstCiphertext<Element> ciphertext2) const;

  /**
   * Internal function for in-place homomorphic addition of ciphertexts.
   * This method does not check whether input ciphertexts are
   * at the same level.
   *
   * @param ciphertext1 first input/output ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return \p ciphertext1 contains the result of the homomorphic addition of
   * input ciphertexts.
   */
  void EvalAddCoreInPlace(Ciphertext<Element> &ciphertext1,
                          ConstCiphertext<Element> ciphertext2) const;

  /**
   * Internal function for homomorphic addition of ciphertexts
   * in the APPROXRESCALE variant.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return result of homomorphic addition of input ciphertexts.
   */
  virtual Ciphertext<Element> EvalAddApprox(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2) const {
    std::string errMsg =
        "LPAlgorithmSHECKKS::EvalAddApprox is only supported for DCRTPoly.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Internal function for in-place homomorphic addition of ciphertexts
   * in the APPROXRESCALE variant.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return result of homomorphic addition of input ciphertexts.
   */
  virtual void EvalAddApproxInPlace(
      Ciphertext<Element> &ciphertext1,
      ConstCiphertext<Element> ciphertext2) const {
    std::string errMsg =
        "LPAlgorithmSHECKKS::EvalAddApproxInPlace is only supported for "
        "DCRTPoly.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Internal function for homomorphic subtraction of ciphertexts.
   * This method does not check whether input ciphertexts are
   * at the same level.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return result of homomorphic subtraction of input ciphertexts.
   */
  Ciphertext<Element> EvalSubCore(ConstCiphertext<Element> ciphertext1,
                                  ConstCiphertext<Element> ciphertext2) const;

  /**
   * Internal function for homomorphic subtraction of ciphertexts
   * in the APPROXRESCALE variant.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return result of homomorphic subtraction of input ciphertexts.
   */
  Ciphertext<Element> EvalSubApprox(ConstCiphertext<Element> ciphertext1,
                                    ConstCiphertext<Element> ciphertext2) const;

  /**
   * Internal function for homomorphic multiplication of ciphertexts.
   * This method does not check whether input ciphertexts are
   * at the same level.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return result of homomorphic multiplication of input ciphertexts.
   */
  Ciphertext<Element> EvalMultCore(ConstCiphertext<Element> ciphertext1,
                                   ConstCiphertext<Element> ciphertext2) const;

  /**
   * Internal function for homomorphic multiplication of ciphertexts
   * in the APPROXRESCALE variant.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return result of homomorphic multiplication of input ciphertexts.
   */
  virtual Ciphertext<Element> EvalMultApprox(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2) const {
    std::string errMsg =
        "LPAlgorithmSHECKKS::EvalMultApprox is only supported for DCRTPoly.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Internal function for multiplying a ciphertext by a constant
   * in the APPROXRESCALE variant.
   *
   * @param ciphertext input ciphertext.
   * @param constant input constant.
   * @return encrypted result of multiplication.
   */
  virtual Ciphertext<Element> EvalMultApprox(
      ConstCiphertext<Element> ciphertext, double constant) const;

  /**
   * Internal function to automatically level-reduce a pair of ciphertexts.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return a vector containing two ciphertexts of the same level.
   */
  vector<shared_ptr<ConstCiphertext<Element>>> AutomaticLevelReduce(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2) const;

  /**
   * Internal function to automatically level-reduce a ciphertext in-place.
   *
   * @param ciphertext1 first input/output ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @details \p ciphertext1 will have level less than or equal to that of \p
   * ciphertext2
   */
  void AutomaticLevelReduceInPlace(Ciphertext<Element> &ciphertext1,
                                   ConstCiphertext<Element> ciphertext2) const;

  /**
   * Internal function used in computing the linear weighted sum of a
   * vector of ciphertexts. This is a mutable method, meaning that the
   * level/depth of input ciphertexts may change.
   *
   * @param ciphertexts vector of input ciphertexts.
   * @param constants vector containing double weights.
   * @return A ciphertext containing the linear weighted sum.
   */
  Ciphertext<DCRTPoly> EvalLinearWSumInternalMutable(
      vector<Ciphertext<DCRTPoly>> ciphertexts, vector<double> constants) const;

  /**
   * Internal function used in adding/substracting a constant.
   *
   * @param ciphertext input ciphertext.
   * @param constant a double-precision constant.
   * @return A ciphertext corresponding to the addition/subtraction.
   */
  std::vector<DCRTPoly::Integer> GetElementForEvalAddOrSub(
      ConstCiphertext<DCRTPoly> ciphertext, double constant) const;

 public:
  template <class Archive>
  void save(Archive &ar) const {
    ar(cereal::base_class<LPSHEAlgorithm<Element>>(this));
  }

  template <class Archive>
  void load(Archive &ar) {
    ar(cereal::base_class<LPSHEAlgorithm<Element>>(this));
  }

  std::string SerializedObjectName() const { return "CKKSSHE"; }
};

/**
 * @brief PRE scheme based on CKKS.
 * The basic scheme is described here:
 *   -  Brakerski Z., Vaikuntanathan V. (2011) Fully Homomorphic Encryption
 * from Ring-LWE and Security for Key Dependent Messages. In: Rogaway P. (eds)
 * Advances in Cryptology – CRYPTO 2011. CRYPTO 2011. Lecture Notes in
 * Computer Science, vol 6841. Springer, Berlin, Heidelberg
 *      (http://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf) or
 * alternative Internet source:
 * (http://dx.doi.org/10.1007/978-3-642-22792-9_29).
 *
 * We use advances from the CKKS scheme for leveled homomorphic capabilities
 * from here:
 *   - Brakerski Z., Gentry C., Halevi S. (2013) Packed Ciphertexts in
 * LWE-Based Homomorphic Encryption. In: Kurosawa K., Hanaoka G. (eds)
 * Public-Key Cryptography – PKC 2013. Lecture Notes in Computer Science, vol
 * 7778. Springer, Berlin, Heidelberg (https://eprint.iacr.org/2011/277.pdf).
 *
 * Our PRE design and algorithms are informed by the design here:
 *   - Polyakov, Yuriy, Kurt Rohloff, Gyana Sahu and Vinod Vaikuntanathan.
 * Fast Proxy Re-Encryption for Publish/Subscribe Systems. Under Review in ACM
 * Transactions on Privacy and Security (ACM TOPS).
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPAlgorithmPRECKKS : public LPPREAlgorithm<Element> {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;
  using DugType = typename Element::DugType;
  using DggType = typename Element::DggType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmPRECKKS() {}

  /**
   * Function to generate a re-encryption key as 1..log(q) encryptions for
   * each bit of the original private key Variant that uses the new secret key
   * directly.
   *
   * @param newKey new private key for the new ciphertext.
   * @param oldKey original private key used for decryption.
   * @return evalKey the evaluation key for switching the ciphertext to be
   * decryptable by new private key.
   */
  LPEvalKey<Element> ReKeyGen(const LPPrivateKey<Element> newKey,
                              const LPPrivateKey<Element> oldKey) const;

  /**
   * The generation of re-encryption keys is based on the BG-PRE scheme
   * described in Polyakov, et. al., "Fast proxy re-encryption for
   * publish/subscribe systems".
   *
   * The above scheme was found to have a weakness in Cohen, "What about Bob?
   * The inadequacy of CPA Security for proxy re-encryption". Section 5.1
   * shows an attack where given an original ciphertext c=(c0,c1) and a
   * re-encrypted ciphertext c'=(c'0, c'1), the subscriber (Bob) can compute
   * the secret key of the publisher (Alice).
   *
   * We fix this vulnerability by making re-encryption keys be encryptions of
   * the s*(2^{i*r}) terms, instead of simple addition as previously defined.
   * This makes retrieving the secret key using the above attack as hard as
   * breaking the RLWE assumption.
   *
   * Our modification makes the scheme CPA-secure, but does not achieve
   * HRA-security as it was defined in the Cohen paper above. Please look at
   * the ReEncrypt method for an explanation of the two security definitions
   * and how to achieve each in Palisade.
   *
   * @param newKey public key for the new private key.
   * @param oldKey original private key used for decryption.
   * @return evalKey the evaluation key for switching the ciphertext to be
   * decryptable by new private key.
   */
  LPEvalKey<Element> ReKeyGen(const LPPublicKey<Element> newKey,
                              const LPPrivateKey<Element> oldKey) const;

  /**
   * This method implements re-encryption using the evaluation key generated
   * by ReKeyGen.
   *
   * The PRE scheme used can achieve two different levels of security, based
   * on the value supplied in the publicKey argument:
   *
   * If publicKey is nullptr, the PRE scheme is CPA-secure. If the publicKey
   * of the recipient of the re-encrypted ciphertext is supplied, then the
   * scheme is HRA- secure. Please refer to Cohen, "What about Bob? The
   * inadequacy of CPA Security for proxy re-encryption", for more information
   * on HRA security.
   *
   * The tradeoff of going for HRA is twofold: (1) performance is a little
   * worst because we add one additional encryption and homomorphic addition
   * to the result, and (2) more noise is added to the result because of the
   * additional operations - in particular, the extra encryption draws noise
   * from a distribution whose standard deviation is scaled by K, the number
   * of digits in the PRE decomposition.
   *
   * @param evalKey the evaluation key.
   * @param ciphertext the input ciphertext.
   * @param publicKey the public key of the recipient of the re-encrypted
   * ciphertext.
   * @return resulting ciphertext after the re-encryption operation.
   */
  Ciphertext<Element> ReEncrypt(
      const LPEvalKey<Element> EK, ConstCiphertext<Element> ciphertext,
      const LPPublicKey<Element> publicKey = nullptr) const;

 private:
  /**
   * The generation of re-encryption keys is based on the BG-PRE scheme
   * described in Polyakov, et. al., "Fast proxy re-encryption for
   * publish/subscribe systems".
   *
   * This is the version of ReKeyGen that works with BV key switching (digit
   * decomposition).
   *
   * @param newKey public key for the new private key.
   * @param oldKey original private key used for decryption.
   * @return evalKey the evaluation key for switching the ciphertext to be
   * decryptable by new private key.
   */
  LPEvalKey<Element> ReKeyGenBV(const LPPublicKey<Element> newKey,
                                const LPPrivateKey<Element> oldKey) const;

  /**
   * The generation of re-encryption keys is based on the BG-PRE scheme
   * described in Polyakov, et. al., "Fast proxy re-encryption for
   * publish/subscribe systems".
   *
   * This is the version of ReKeyGen that works with GHS key switching
   * (approx. mod. switching).
   *
   * @param newKey public key for the new private key.
   * @param oldKey original private key used for decryption.
   * @return evalKey the evaluation key for switching the ciphertext to be
   * decryptable by new private key.
   */
  LPEvalKey<Element> ReKeyGenGHS(const LPPublicKey<Element> newKey,
                                 const LPPrivateKey<Element> oldKey) const;

 public:
  template <class Archive>
  void save(Archive &ar) const {
    ar(cereal::base_class<LPPREAlgorithm<Element>>(this));
  }

  template <class Archive>
  void load(Archive &ar) {
    ar(cereal::base_class<LPPREAlgorithm<Element>>(this));
  }

  std::string SerializedObjectName() const { return "CKKSPRE"; }
};

/**
 * @brief The multiparty homomorphic encryption capability for the CKKS
 * scheme. A version of this multiparty scheme built on the CKKS scheme is
 * seen here:
 *   - Asharov G., Jain A., López-Alt A., Tromer E., Vaikuntanathan V., Wichs
 * D. (2012) Multiparty Computation with Low Communication, Computation and
 * Interaction via Threshold FHE. In: Pointcheval D., Johansson T. (eds)
 * Advances in Cryptology – EUROCRYPT 2012. EUROCRYPT 2012. Lecture Notes in
 * Computer Science, vol 7237. Springer, Berlin, Heidelberg
 *
 * During offline key generation, this multiparty scheme relies on the clients
 * coordinating their public key generation.  To do this, a single client
 * generates a public-secret key pair. This public key is shared with other
 * keys which use an element in the public key to generate their own public
 * keys. The clients generate a shared key pair using a scheme-specific
 * approach, then generate re-encryption keys.  Re-encryption keys are
 * uploaded to the server. Clients encrypt data with their public keys and
 * send the encrypted data server. The data is re-encrypted.  Computations are
 * then run on the data. The result is sent to each of the clients. One client
 * runs a "Leader" multiparty decryption operation with its own secret key.
 * All other clients run a regular "Main" multiparty decryption with their own
 * secret key. The resulting partially decrypted ciphertext are then fully
 * decrypted with the decryption fusion algorithms.
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPAlgorithmMultipartyCKKS : public LPMultipartyAlgorithm<Element> {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;
  using DugType = typename Element::DugType;
  using DggType = typename Element::DggType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmMultipartyCKKS() {}

  /**
   * Threshold FHE: Generation of a public key derived
   * from a previous joined public key (for prior secret shares) and the secret
   * key share of the current party.
   *
   * @param cc cryptocontext for the keys to be generated.
   * @param pk1 joined public key from prior parties.
   * @param makeSparse set to true if ring reduce by a factor of 2 is to be
   * used. NOT SUPPORTED BY ANY SCHEME ANYMORE.
   * @param fresh set to true if proxy re-encryption is used in the multi-party
   * protocol or star topology is used
   * @return key pair including the secret share for the current party and
   * joined public key
   */
  LPKeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
                                      const LPPublicKey<Element> pk1,
                                      bool makeSparse = false,
                                      bool fresh = false);

  /**
   * Threshold FHE: Generates a public key from a vector of secret shares.
   * ONLY FOR DEBUGGING PURPOSES. SHOULD NOT BE USED IN PRODUCTION.
   *
   * @param cc cryptocontext for the keys to be generated.
   * @param secretkeys secrete key sahres.
   * @param makeSparse set to true if ring reduce by a factor of 2 is to be
   * used. NOT SUPPORTED BY ANY SCHEME ANYMORE.
   * @return key pair including the private for the current party and joined
   * public key
   */
  LPKeyPair<Element> MultipartyKeyGen(
      CryptoContext<Element> cc,
      const vector<LPPrivateKey<Element>> &secretKeys, bool makeSparse = false);

  /**
   * Threshold FHE: "Partial" decryption computed by all parties except for the
   * lead one
   *
   * @param privateKey secret key share used for decryption.
   * @param ciphertext ciphertext that is being decrypted.
   */
  Ciphertext<Element> MultipartyDecryptMain(
      const LPPrivateKey<Element> privateKey,
      ConstCiphertext<Element> ciphertext) const;

  /**
   * Threshold FHE: Method for decryption operation run by the lead decryption
   * client
   *
   * @param privateKey secret key share used for decryption.
   * @param ciphertext ciphertext id decrypted.
   */
  Ciphertext<Element> MultipartyDecryptLead(
      const LPPrivateKey<Element> privateKey,
      ConstCiphertext<Element> ciphertext) const;

  /**
   * Threshold FHE: Method for combining the partially decrypted ciphertexts
   * and getting the final decryption in the clear as a NativePoly.
   *
   * @param &ciphertextVec vector of "partial" decryptions.
   * @param *plaintext the plaintext output as a NativePoly.
   * @return the decoding result.
   */
  DecryptResult MultipartyDecryptFusion(
      const vector<Ciphertext<Element>> &ciphertextVec,
      NativePoly *plaintext) const;

  /**
   * Threshold FHE: Method for combining the partially decrypted ciphertexts
   * and getting the final decryption in the clear as a Poly.
   *
   * @param &ciphertextVec vector of "partial" decryptions.
   * @param *plaintext the plaintext output as a Poly.
   * @return the decoding result.
   */
  DecryptResult MultipartyDecryptFusion(
      const vector<Ciphertext<Element>> &ciphertextVec, Poly *plaintext) const;

  /**
   * Threshold FHE: Generates a joined evaluation key
   * from the current secret share and a prior joined
   * evaluation key
   *
   * @param originalPrivateKey secret key transformed from.
   * @param newPrivateKey secret key transformed to.
   * @param ek the prior joined evaluation key.
   * @return the new joined evaluation key.
   */
  LPEvalKey<Element> MultiKeySwitchGen(
      const LPPrivateKey<Element> originalPrivateKey,
      const LPPrivateKey<Element> newPrivateKey,
      const LPEvalKey<Element> ek) const;

  /**
   * Threshold FHE: Generates joined automorphism keys
   * from the current secret share and prior joined
   * automorphism keys
   *
   * @param privateKey secret key share.
   * @param eAuto a dictionary with prior joined automorphism keys.
   * @param &indexList a vector of automorphism indices.
   * @return a dictionary with new joined automorphism keys.
   */
  shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiEvalAutomorphismKeyGen(
      const LPPrivateKey<Element> privateKey,
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> eAuto,
      const std::vector<usint> &indexList) const;

  /**
   * Threshold FHE: Generates joined summation evaluation keys
   * from the current secret share and prior joined
   * summation keys
   *
   * @param privateKey secret key share.
   * @param eSum a dictionary with prior joined summation keys.
   * @return new joined summation keys.
   */
  shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiEvalSumKeyGen(
      const LPPrivateKey<Element> privateKey,
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> eSum) const;

  /**
   * Threshold FHE: Generates a partial evaluation key for homomorphic
   * multiplication based on the current secret share and an existing partial
   * evaluation key
   *
   * @param evalKey prior evaluation key.
   * @param sk current secret share.
   * @return the new joined key.
   */
  LPEvalKey<Element> MultiMultEvalKey(LPEvalKey<Element> evalKey,
                                      LPPrivateKey<Element> sk) const;

  template <class Archive>
  void save(Archive &ar) const {
    ar(cereal::base_class<LPMultipartyAlgorithm<Element>>(this));
  }

  template <class Archive>
  void load(Archive &ar) {
    ar(cereal::base_class<LPMultipartyAlgorithm<Element>>(this));
  }

  std::string SerializedObjectName() const { return "CKKSMultiparty"; }
};

/**
 * @brief Concrete feature class for Leveled SHECKKS operations. This class
 * adds leveled (CKKS scheme) features to the CKKS scheme.
 *
 * We use advances from the CKKS scheme for levelled homomorphic capabilities
 * from here:
 *   - Brakerski Z., Gentry C., Halevi S. (2013) Packed Ciphertexts in
 * LWE-Based Homomorphic Encryption. In: Kurosawa K., Hanaoka G. (eds)
 * Public-Key Cryptography – PKC 2013. Lecture Notes in Computer Science, vol
 * 7778. Springer, Berlin, Heidelberg (https://eprint.iacr.org/2011/277.pdf).
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPLeveledSHEAlgorithmCKKS : public LPLeveledSHEAlgorithm<Element> {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;
  using DugType = typename Element::DugType;
  using DggType = typename Element::DggType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPLeveledSHEAlgorithmCKKS() {}

  virtual ~LPLeveledSHEAlgorithmCKKS() {}

  /**
   * Wrapper method for rescaling. If APPROXRESCALE is used, then it
   * directly calls the ModReduceInternalInPlace method, that corresponds to
   * the original rescaling operation in the CKKS scheme.
   *
   * If EXACTRESCALE is used, rescaling is done automatically, and
   * therefore calling ModReduceInPlace does nothing and returns the original
   * ciphertext. This behavior was chosen to allow running applications
   * written for APPROXRESCALE in the exact scheme.
   *
   * @param ciphertext is the ciphertext to perform modreduce on.
   * @return ciphertext after the modulus reduction performed.
   */
  void ModReduceInPlace(Ciphertext<Element> &ciphertext,
                        size_t levels = 1) const override;

  /**
   * Method for rescaling.
   *
   * @param ciphertext is the ciphertext to perform modreduce on.
   * @return ciphertext after the modulus reduction performed.
   */
  Ciphertext<Element> ModReduceInternal(ConstCiphertext<Element> ciphertext,
                                        size_t levels = 1) const override;

  void ModReduceInternalInPlace(Ciphertext<Element> &ciphertext,
                                size_t levels = 1) const override;

  /**
   * Method for compressing the ciphertext before decryption.
   *
   * @param ciphertext is the ciphertext to perform compress on.
   * @param towersLeft is the number of towers after compression
   * @return ciphertext after the compression performed.
   */
  Ciphertext<Element> Compress(ConstCiphertext<Element> ciphertext,
                               size_t towersLeft = 1) const override;

  /**
   * Method for Composed EvalMult, which includes homomorphic multiplication,
   * key switching, and modulo reduction. Not implemented for the CKKS/CKKS
   * scheme.
   *
   * @param cipherText1 ciphertext1, first input ciphertext to perform
   * multiplication on.
   * @param cipherText2 cipherText2, second input ciphertext to perform
   * multiplication on.
   * @param quadKeySwitchHint is used for EvalMult operation.
   * @return resulting ciphertext.
   */
  Ciphertext<Element> ComposedEvalMult(
      ConstCiphertext<Element> cipherText1,
      ConstCiphertext<Element> cipherText2,
      const LPEvalKey<Element> quadKeySwitchHint) const override {
    std::string errMsg =
        "LPLeveledSHEAlgorithmCKKS::ComposedEvalMult is not currently "
        "implemented "
        "for "
        "the CKKS/CKKS Scheme.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Wrapper method for level reduce in CKKS.
   * If APPROXRESCALE is used, then the method directly calls
   * LevelReduceInternal. If EXACTRESCALE is used, the method does nothing and
   * returns the origin ciphertext.
   *
   * @param ciphertext is the original ciphertext to be level reduced.
   * @param linearKeySwitchHint not used in the CKKS scheme.
   * @param levels the number of towers to drop.
   * @return resulting ciphertext.
   */
  Ciphertext<Element> LevelReduce(ConstCiphertext<Element> ciphertext,
                                  const LPEvalKey<Element> linearKeySwitchHint,
                                  size_t levels) const override;

  /**
   * Method for Level Reduction in the CKKS scheme. It just drops "levels"
   * number of the towers of the ciphertext without changing the underlying
   * plaintext.
   *
   * @param ciphertext is the original ciphertext to be level reduced.
   * @param linearKeySwitchHint not used in the CKKS scheme.
   * @param levels the number of towers to drop.
   * @return resulting ciphertext.
   */
  Ciphertext<Element> LevelReduceInternal(
      ConstCiphertext<Element> ciphertext,
      const LPEvalKey<Element> linearKeySwitchHint,
      size_t levels) const override;

  /**
   * Method for In-place Level Reduction in the CKKS scheme. It just drops
   * "levels" number of the towers of the ciphertext without changing the
   * underlying plaintext.
   *
   * @param ciphertext is the original ciphertext to be level reduced.
   * @param linearKeySwitchHint not used in the CKKS scheme.
   * @param levels the number of towers to drop.
   * @return \p ciphertext Contains the level-reduced cipheretext
   */
  void LevelReduceInternalInPlace(Ciphertext<Element> &ciphertext,
                                  const LPEvalKey<Element> linearKeySwitchHint,
                                  size_t levels) const override;

  /**
   * Method for polynomial evaluation for polynomials represented as power
   * series.
   *
   * @param &cipherText input ciphertext
   * @param &coefficients is the vector of coefficients in the polynomial; the
   * size of the vector is the degree of the polynomial + 1
   * @return the result of polynomial evaluation.
   */
  Ciphertext<Element> EvalPoly(
      ConstCiphertext<Element> cipherText,
      const std::vector<double> &coefficients) const override {
    std::string errMsg =
        "LPLeveledSHEAlgorithmCKKS::EvalPoly is only supported for DCRTPoly.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  template <class Archive>
  void save(Archive &ar) const {
    ar(cereal::base_class<LPLeveledSHEAlgorithm<Element>>(this));
  }

  template <class Archive>
  void load(Archive &ar) {
    ar(cereal::base_class<LPLeveledSHEAlgorithm<Element>>(this));
  }

  std::string SerializedObjectName() const { return "CKKSLeveledSHE"; }
};

/**
 * @brief Main public key encryption scheme for the CKKS/CKKS implementation
 * @tparam Element a ring element.
 */
template <class Element>
class LPPublicKeyEncryptionSchemeCKKS
    : public LPPublicKeyEncryptionScheme<Element> {
 public:
  LPPublicKeyEncryptionSchemeCKKS() : LPPublicKeyEncryptionScheme<Element>() {
    this->m_algorithmParamsGen =
        std::make_shared<LPAlgorithmParamsGenCKKS<Element>>();
  }

  bool operator==(const LPPublicKeyEncryptionScheme<Element> &sch) const {
    return dynamic_cast<const LPPublicKeyEncryptionSchemeCKKS<Element> *>(
               &sch) != nullptr;
  }

  void Enable(PKESchemeFeature feature);

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(cereal::base_class<LPPublicKeyEncryptionScheme<Element>>(this));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    ar(cereal::base_class<LPPublicKeyEncryptionScheme<Element>>(this));
  }

  std::string SerializedObjectName() const { return "CKKSScheme"; }
};

}  // namespace lbcrypto
#endif
