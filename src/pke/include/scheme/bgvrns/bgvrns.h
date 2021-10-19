// @file bgvrns.h -- Operations for the BGVrns cryptoscheme.
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

/*
 * This code implements the BGVrns homomorphic encryption scheme.
 */

#ifndef LBCRYPTO_CRYPTO_BGVRNS_H
#define LBCRYPTO_CRYPTO_BGVRNS_H

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "math/dftransfrm.h"
#include "palisade.h"
#include "utils/caller_info.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

#define ONLYDCRTPOLY                          \
  PALISADE_THROW(not_implemented_error,       \
                 "BGVrns only supported for " \
                 "DCRTPoly.");

#define NOIMPL \
  PALISADE_THROW(not_implemented_error, "Not implemented for BGVrns.");

/**
 * @brief Crypto parameters class for RLWE-based schemes.
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPCryptoParametersBGVrns : public LPCryptoParametersRLWE<Element> {
  using IntType = typename Element::Integer;
  using ParmType = typename Element::Params;
  using DggType = typename Element::DggType;
  using DugType = typename Element::DugType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default Constructor.
   */
  LPCryptoParametersBGVrns()
      : LPCryptoParametersRLWE<Element>(),
        m_ksTechnique(BV),
        m_msMethod(MANUAL),
        m_numPartQ(0),
        m_numPerPartQ(0) {}

  /**
   * Copy constructor.
   *
   * @param rhs - source
   */
  LPCryptoParametersBGVrns(const LPCryptoParametersBGVrns& rhs)
      : LPCryptoParametersRLWE<Element>(rhs),
        m_ksTechnique(BV),
        m_msMethod(MANUAL),
        m_numPartQ(0),
        m_numPerPartQ(0) {}

  /**
   * Constructor that initializes values.  Note that it is possible to set
   * parameters in a way that is overall infeasible for actual use.  There are
   * fewer degrees of freedom than parameters provided.  Typically one chooses
   * the basic noise, assurance and security parameters as the typical
   * community-accepted values, then chooses the plaintext modulus and depth as
   * needed.  The element parameters should then be choosen to provide
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
   * @param msMethod mod switch method
   */
  LPCryptoParametersBGVrns(shared_ptr<ParmType> params,
                           const PlaintextModulus& plaintextModulus,
                           float distributionParameter, float assuranceMeasure,
                           float securityLevel, usint relinWindow, MODE mode,
                           int depth = 1, int maxDepth = 2,
                           KeySwitchTechnique ksTech = BV,
                           ModSwitchMethod msMethod = MANUAL)
      : LPCryptoParametersRLWE<Element>(
            params,
            EncodingParams(
                std::make_shared<EncodingParamsImpl>(plaintextModulus)),
            distributionParameter, assuranceMeasure, securityLevel, relinWindow,
            depth, maxDepth, mode) {
    m_ksTechnique = ksTech;
    m_msMethod = msMethod;
    m_numPartQ = 0;
    m_numPerPartQ = 0;
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
   * @param msMethod mod switch method
   */
  LPCryptoParametersBGVrns(shared_ptr<ParmType> params,
                           EncodingParams encodingParams,
                           float distributionParameter, float assuranceMeasure,
                           float securityLevel, usint relinWindow, MODE mode,
                           int depth = 1, int maxDepth = 2,
                           KeySwitchTechnique ksTech = BV,
                           ModSwitchMethod msMethod = MANUAL)
      : LPCryptoParametersRLWE<Element>(
            params, encodingParams, distributionParameter, assuranceMeasure,
            securityLevel, relinWindow, depth, maxDepth, mode) {
    m_ksTechnique = ksTech;
    m_msMethod = msMethod;
    m_numPartQ = 0;
    m_numPerPartQ = 0;
  }

  /**
   * Destructor.
   */
  virtual ~LPCryptoParametersBGVrns() {}

  template <class Archive>
  void save(Archive& ar, std::uint32_t const version) const {
    ar(cereal::base_class<LPCryptoParametersRLWE<Element>>(this));
    ar(cereal::make_nvp("ks", m_ksTechnique));
    ar(cereal::make_nvp("ms", m_msMethod));
    ar(cereal::make_nvp("dnum", m_numPartQ));
  }

  template <class Archive>
  void load(Archive& ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(cereal::base_class<LPCryptoParametersRLWE<Element>>(this));
    ar(cereal::make_nvp("ks", m_ksTechnique));
    ar(cereal::make_nvp("ms", m_msMethod));
    ar(cereal::make_nvp("dnum", m_numPartQ));
    PrecomputeCRTTables(m_ksTechnique, m_numPartQ);
  }

  std::string SerializedObjectName() const { return "BGVrnsSchemeParameters"; }
  static uint32_t SerializedVersion() { return 1; }

  /**
   * Computes all tables needed for decryption, homomorphic multiplication, and
   * key switching
   * @param ksTech the technique to use for key switching (e.g., BV or GHS).
   * @param numPartQ number of Large digits
   * @return true on success
   */
  bool PrecomputeCRTTables(KeySwitchTechnique ksTech, uint32_t numPartQ = 0);

  /**
   * == operator to compare to this instance of LPCryptoParametersBGVrns object.
   *
   * @param &rhs LPCryptoParameters to check equality against.
   */
  bool operator==(const LPCryptoParameters<Element>& rhs) const {
    const auto* el =
        dynamic_cast<const LPCryptoParametersBGVrns<Element>*>(&rhs);

    if (el == nullptr) return false;

    return LPCryptoParametersRLWE<Element>::operator==(rhs) &&
           m_ksTechnique == el->GetKeySwitchTechnique() &&
           m_numPartQ == el->GetNumPartQ() &&
           m_msMethod == el->GetModSwitchMethod();
  }

  void PrintParameters(std::ostream& os) const {
    LPCryptoParametersRLWE<Element>::PrintParameters(os);
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
  const BigInteger& GetAuxModulus() const { return m_modulusP; }

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
  const vector<NativeInteger>& GetPInvModq() const { return m_PInvModq; }

  /**
   * Gets the NTL precomputions for [P^{-1}]_{q_i}
   * Used for speeding up GHS key switching.
   *
   * @return the precomputed table
   */
  const vector<NativeInteger>& GetPInvModqPrecon() const {
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
  const vector<NativeInteger>& GetPHatInvModp() const { return m_PHatInvModp; }

  /**
   * Get the NTL precomputions for [(P/p_j)^{-1}]_{p_j}
   *
   * @return the precomputed table
   */
  const vector<NativeInteger>& GetPHatInvModpPrecon() const {
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
  const vector<NativeInteger>& GetQlHatInvModq(uint32_t l) const {
    return m_LvlQHatInvModq[l];
  }

  /**
   * Get the NTL precomputions for [(Q^(l)/q_i)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
  const vector<NativeInteger>& GetQlHatInvModqPrecon(uint32_t l) const {
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
  const vector<vector<NativeInteger>>& GetPHatModq() const {
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
  const vector<vector<NativeInteger>>& GetQlHatModp(uint32_t l) const {
    return m_LvlQHatModp[l];
  }

  /**
   * Gets the precomputed table of [P]_{q_i}
   * Used in GHS key switching.
   *
   * See more in "A full RNS variant of approximate homomorphic
   * encryption" by Cheon, et. al. Section 4.
   *
   * @return a vector holding (P mod q_j) for every j.
   */
  const vector<NativeInteger>& GetPModq() const { return m_PModq; }

  /**
   * Gets the Barrett modulo reduction precomputation for q_i
   *
   * @return the precomputed table
   */
  const vector<DoubleNativeInt>& GetModqBarrettMu() const {
    return m_modqBarrettMu;
  }

  /**
   * Gets the Barrett modulo reduction precomputation for p_j
   *
   * @return the precomputed table
   */
  const vector<DoubleNativeInt>& GetModpBarrettMu() const {
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
   * Method to retrieve the technique to be used for key switching.
   *
   * @return the mod switching method.
   */
  enum ModSwitchMethod GetModSwitchMethod() const { return m_msMethod; }

  /**
   * Get the precomputed table of [Q/Q_j]_{q_i}
   * Used in HYBRID key switching.
   *
   * @return the precomputed table
   */
  const vector<vector<NativeInteger>>& GetPartQHatModq() const {
    return m_PartQHatModq;
  }

  /**
   * Method that returns the element parameters corresponding to
   * partitions {Q_j} of Q.
   *
   * @param j is the number of the digit we want to get the list of towers for.
   * @return the pre-computed values.
   */
  const shared_ptr<ILDCRTParams<BigInteger>>& GetParamsPartQ(uint32_t j) const {
    return m_paramsPartQ[j];
  }

  /*
   * Method that returns the element parameters corresponding to the
   * complementary basis of a single digit j, i.e., the basis consisting of
   * all other digits plus the special primes. Note that numTowers should be
   * up to l (where l is the number of towers).
   *
   * @param numTowers is the total number of towers there are in the ciphertext.
   * @param digit is the index of the digit we want to get the complementary
   * partition from.
   * @return the partitions.
   */
  const shared_ptr<ILDCRTParams<BigInteger>>& GetParamsComplPartQ(
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
   * Get the precomputed table of [{Q/Q_j}^{-1}]_{q_i}
   * Used in HYBRID key switching.
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger>& GetPartQHatInvModq(uint32_t part) const {
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
  const vector<NativeInteger>& GetPartQlHatInvModq(uint32_t part,
                                                   uint32_t sublvl) const {
    if (part < m_LvlPartQHatInvModq.size() &&
        sublvl < m_LvlPartQHatInvModq[part].size())
      return m_LvlPartQHatInvModq[part][sublvl];

    PALISADE_THROW(math_error,
                   "LPCryptoParametersBGVrns::GetPartitionQHatInvModQTable - "
                   "index out of bounds.");
  }

  /**
   * Barret multiplication precomputations getter.
   *
   * @param index The number of towers in the ciphertext.
   * @return the pre-computed values.
   */
  const vector<NativeInteger>& GetPartQlHatInvModqPrecon(
      uint32_t part, uint32_t sublvl) const {
    if (part < m_LvlPartQHatInvModqPrecon.size() &&
        sublvl < m_LvlPartQHatInvModqPrecon[part].size())
      return m_LvlPartQHatInvModqPrecon[part][sublvl];

    PALISADE_THROW(
        math_error,
        "LPCryptoParametersBGVrns::GetPartitionQHatInvModQPreconTable - "
        "index out of bounds.");
  }

  /**
   * Barret multiplication precomputations getter.
   *
   * @param index The table containing QHat mod pi.
   * @return the pre-computed values.
   */
  const vector<vector<NativeInteger>>& GetPartQlHatModp(uint32_t lvl,
                                                        uint32_t part) const {
    if (lvl < m_LvlPartQHatModp.size() && part < m_LvlPartQHatModp[lvl].size())
      return m_LvlPartQHatModp[lvl][part];

    PALISADE_THROW(math_error,
                   "LPCryptoParametersBGVrns::GetPartitionQHatModPTable - "
                   "index out of bounds.");
  }

  /**
   * Barret multiplication precomputations getter.
   *
   * @param index The number of towers in the ciphertext.
   * @return the pre-computed values.
   */
  const vector<DoubleNativeInt>& GetmodComplPartqBarrettMu(
      uint32_t lvl, uint32_t part) const {
    if (lvl < m_modComplPartqBarrettMu.size() &&
        part < m_modComplPartqBarrettMu[lvl].size())
      return m_modComplPartqBarrettMu[lvl][part];

    PALISADE_THROW(math_error,
                   "LPCryptoParametersBGVrns::GetPartitionPrecon - index out "
                   "of bounds.");
  }

  /**
   * Method that returns the precomputed values for [t^(-1)]_{q_i}
   * Used in ModulusSwitching.
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger>& GettInvModq() const { return m_tInvModq; }

  /**
   * Method that returns the NTL precomputions for [t]_{q_i}
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger>& GettModqPrecon() const { return m_tModqPrecon; }

  /**
   * Method that returns the NTL precomputions for [t^{-1}]_{q_i}
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger>& GettInvModqPrecon() const {
    return m_tInvModqPrecon;
  }

  /**
   * Method that returns the precomputed values for [t^(-1)]_{p_j}
   * Used in KeySwitching.
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger>& GettInvModp() const { return m_tInvModp; }

  /**
   * Method that returns the NTL precomputions for [t]_{p_j}
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger>& GettModpPrecon() const { return m_tModpPrecon; }

  /**
   * Method that returns the NTL precomputions for [t^{-1}]_{p_j}
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger>& GettInvModpPrecon() const {
    return m_tInvModpPrecon;
  }

  /**
   * Get the precomputed table of [-t^{-1}]_{q_i}
   *
   * @return the pre-computed values.
   */
  const NativeInteger& GetNegtInvModq(usint l) const {
    return m_negtInvModq[l];
  }

  /**
   * Method that returns the NTL precomputions for [-t^{-1}]_{q_i}
   *
   * @return the pre-computed values.
   */
  const NativeInteger& GetNegtInvModqPrecon(usint l) const {
    return m_negtInvModqPrecon[l];
  }

  /**
   * Get the precomputed table of [q_l^{-1}]_{q_i}
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger>& GetqlInvModq(usint l) const {
    return m_qInvModq[l];
  }

  /**
   * Method that returns the NTL precomputions for [q_l^{-1}]_{q_i}
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger>& GetqlInvModqPrecon(usint l) const {
    return m_qInvModqPrecon[l];
  }

 private:
  // Stores the technique to use for key switching
  enum KeySwitchTechnique m_ksTechnique;

  // Stores the method to use for mod switching
  enum ModSwitchMethod m_msMethod;

  // HYBRID

  // Stores the partition size {PartQ} = {Q_1,...,Q_l}
  // where each Q_i is the product of q_j
  uint32_t m_numPartQ;

  // Stores the number of towers per Q_i
  uint32_t m_numPerPartQ;

  // Stores the composite moduli Q_i
  vector<BigInteger> m_moduliPartQ;

  // Stores the parameters for moduli Q_i
  vector<shared_ptr<ILDCRTParams<BigInteger>>> m_paramsPartQ;

  // Stores the parameters for complementary {\bar{Q_i},P}
  vector<vector<shared_ptr<ILDCRTParams<BigInteger>>>> m_paramsComplPartQ;

  // Stores the Barrett mu for CompQBar_i
  vector<vector<vector<DoubleNativeInt>>> m_modComplPartqBarrettMu;

  // Stores [Q/Q_j] for HYBRID
  vector<BigInteger> m_PartQHat;

  // Stores [Q/Q_j]_{q_i} for HYBRID
  vector<vector<NativeInteger>> m_PartQHatModq;

  // Stores [{Q/Q_j}^{-1}]_{q_i} for HYBRID
  vector<vector<NativeInteger>> m_PartQHatInvModq;

  // Stores [{(Q_k)^(l)/q_i}^{-1}]_{q_i} for HYBRID
  vector<vector<vector<NativeInteger>>> m_LvlPartQHatInvModq;

  // Stores NTL precomputations for
  // [{(Q_k)^(l)/q_i}^{-1}]_{q_i} for HYBRID
  vector<vector<vector<NativeInteger>>> m_LvlPartQHatInvModqPrecon;

  // Stores [QHat_i]_{p_j}
  vector<vector<vector<vector<NativeInteger>>>> m_LvlPartQHatModp;

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

  // Stores [(Q^(l)/q_i)^{-1}]_{q_i}, required for GHS key switching
  vector<vector<NativeInteger>> m_LvlQHatInvModq;

  // Stores NTL precomputations for [(Q^(l)/q_i)^{-1}]_{q_i}
  vector<vector<NativeInteger>> m_LvlQHatInvModqPrecon;

  // Stores [P/p_j]_{q_i}, required for GHS key switching
  vector<vector<NativeInteger>> m_PHatModq;

  // Stores [Q^(l)/q_i]_{p_j}, required for GHS key switching
  vector<vector<vector<NativeInteger>>> m_LvlQHatModp;

  // Stores the BarrettUint128ModUint64 precomputations for p_i
  vector<DoubleNativeInt> m_modpBarrettMu;

  // Stores the BarrettUint128ModUint64 precomputations for q_j
  vector<DoubleNativeInt> m_modqBarrettMu;

  // Stores NTL precomputations for [t]_{q_i}
  vector<NativeInteger> m_tModqPrecon;

  // Stores NTL precomputations for [t]_{p_j}
  vector<NativeInteger> m_tModpPrecon;

  // Stores [t^{-1}]_{q_i}
  vector<NativeInteger> m_tInvModq;

  // Stores NTL precomputations for [t^{-1}]_{q_i}
  vector<NativeInteger> m_tInvModqPrecon;

  // Stores [t^{-1}]_{p_j}
  vector<NativeInteger> m_tInvModp;

  // Stores NTL precomputations for [t^{-1}]_{p_j}
  vector<NativeInteger> m_tInvModpPrecon;

  // Stores [-t^{-1}]_{q_i}
  vector<NativeInteger> m_negtInvModq;

  // Stores NTL precomputations for [-t^{-1}]_{q_i}
  vector<NativeInteger> m_negtInvModqPrecon;

  // Stores [q_l^{-1}]_{q_i}
  vector<vector<NativeInteger>> m_qInvModq;

  // Stores NTL precomputations for [q_l^{-1}]_{q_i}
  vector<vector<NativeInteger>> m_qInvModqPrecon;
};

/**
 * @brief Parameter generation for BGVrns.
 */
template <class Element>
class LPAlgorithmParamsGenBGVrns
    : public LPParameterGenerationAlgorithm<Element> {
  using IntType = typename Element::Integer;
  using ParmType = typename Element::Params;
  using DggType = typename Element::DggType;
  using DugType = typename Element::DugType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmParamsGenBGVrns() {}

  /**
   * Method for computing all derived parameters based on chosen primitive
   * parameters.
   * @param cryptoParams the crypto parameters object to be populated with
   * parameters.
   * @param evalAddCount number of EvalAdds assuming no EvalMult and KeySwitch
   * operations are performed.
   * @param evalMultCount number of EvalMults assuming no EvalAdd and KeySwitch
   * operations are performed.
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
    NOIMPL
  }

  /**
   * Method for computing all derived parameters based on chosen primitive
   * parameters.
   *
   * @param cryptoParams the crypto parameters object to be populated with
   * parameters.
   * @param cyclOrder the cyclotomic order.
   * @param ptm the plaintext modulus
   * @param numPrimes number of modulus towers to support.
   * @param relinWindow the relinearization window
   * @param mode the distribution of the secret (RLWE, OPTIMIZED or SPARSE)
   * @param ksTech the key switching technique used (e.g., BV or GHS)
   * @param firstModSize the bit-size of the first modulus
   * @param dcrtBits the bit-width for tower's moduli.
   * @param numLargeDigits the number of digits for hybrid key-switching.
   */
  bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams,
                 usint cyclOrder, usint ptm, usint numPrimes, usint relinWindow,
                 MODE mode, KeySwitchTechnique ksTech = BV,
                 usint firstModSize = 0, usint dcrtBits = 0,
                 uint32_t numLargeDigits = 4) const;

  ~LPAlgorithmParamsGenBGVrns() {}

  template <class Archive>
  void save(Archive& ar) const {
    ar(cereal::base_class<LPParameterGenerationAlgorithm<Element>>(this));
  }

  template <class Archive>
  void load(Archive& ar) {
    ar(cereal::base_class<LPParameterGenerationAlgorithm<Element>>(this));
  }

  std::string SerializedObjectName() const { return "BGVrnsParamsGen"; }
};

/**
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPAlgorithmBGVrns : public LPEncryptionAlgorithm<Element> {
  using IntType = typename Element::Integer;
  using ParmType = typename Element::Params;
  using DggType = typename Element::DggType;
  using DugType = typename Element::DugType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmBGVrns() {}

  /**
   * Method for encrypting plaintext using BGVrns Scheme
   *
   * @param publicKey is the public key used for encryption.
   * @param plaintext the plaintext input.
   * @return ciphertext which results from encryption.
   */
  Ciphertext<Element> Encrypt(const LPPublicKey<Element> publicKey,
                              Element plaintext) const override;

  /**
   * Method for encrypting plaintext using BGVrns Scheme
   *
   * @param privateKey is the private key used for encryption.
   * @param plaintext the plaintext input.
   * @return ciphertext which results from encryption.
   */
  Ciphertext<Element> Encrypt(const LPPrivateKey<Element> privateKey,
                              Element plaintext) const override;

  /**
   * Method for decrypting plaintext using BGVrns
   *
   * @param privateKey private key used for decryption.
   * @param ciphertext ciphertext id decrypted.
   * @param *plaintext the plaintext output.
   * @return the success/fail result
   */
  DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
                        ConstCiphertext<Element> ciphertext,
                        NativePoly* plaintext) const override;

  /**
   * Method for decrypting plaintext using BGVrns
   *
   * @param privateKey private key used for decryption.
   * @param ciphertext ciphertext id decrypted.
   * @param *plaintext the plaintext output.
   * @return the success/fail result
   */
  DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
                        ConstCiphertext<Element> ciphertext,
                        Poly* plaintext) const override;

  /**
   * Function to generate public and private keys
   *
   * @param cc is the cryptoContext which encapsulates the crypto paramaters.
   * @param makeSparse is a boolean flag that species if the key is
   * sparse(interleaved zeroes) or not.
   * @return KeyPair containting private key and public key.
   */
  LPKeyPair<Element> KeyGen(CryptoContext<Element> cc,
                            bool makeSparse = false) override;

  template <class Archive>
  void save(Archive& ar) const {
    ar(cereal::base_class<LPEncryptionAlgorithm<Element>>(this));
  }

  template <class Archive>
  void load(Archive& ar) {
    ar(cereal::base_class<LPEncryptionAlgorithm<Element>>(this));
  }

  std::string SerializedObjectName() const { return "BGVrnsEncryption"; }
};

/**
 * Class for evaluation of somewhat homomorphic operations.
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPAlgorithmSHEBGVrns : public LPSHEAlgorithm<Element> {
  using IntType = typename Element::Integer;
  using ParmType = typename Element::Params;
  using DggType = typename Element::DggType;
  using DugType = typename Element::DugType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmSHEBGVrns() {}

  /**
   * Destructor
   */
  virtual ~LPAlgorithmSHEBGVrns() {}

  /**
   * Internal function to automatically level-reduce a pair of ciphertexts.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return a vector containing two ciphertexts of the same level.
   */
  vector<shared_ptr<ConstCiphertext<Element>>> AdjustLevels(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2) const;

  /**
   * Internal function to automatically level-reduce a pair of ciphertexts.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   */
  void AdjustLevelsEq(Ciphertext<Element>& ciphertext1,
                      Ciphertext<Element>& ciphertext2) const;

  /**
   * Internal function to automatically level-reduce a ciphertext and a
   * plaintext.
   *
   * @param ciphertext1 input ciphertext.
   * @param plaintext input plaintext.
   * @return a vector containing two ciphertexts of the same level.
   */
  std::pair<shared_ptr<ConstCiphertext<Element>>, Element> AdjustLevels(
      ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const;

  /**
   * Internal function to automatically level-reduce a ciphertext and a
   * plaintext.
   *
   * @param ciphertext1 input ciphertext.
   * @param plaintext input plaintext.
   * @return a vector containing two ciphertexts of the same level.
   */
  void AdjustLevelsEq(Ciphertext<Element>& ciphertext,
                      Plaintext plaintext) const;

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
   * @details \p ciphertext1 stores the result of \p ciphertext1 + \p ciphertext2
   */
  void EvalAddCoreInPlace(Ciphertext<Element>& ciphertext1,
                          ConstCiphertext<Element> ciphertext2) const;

  /**
   * Function for homomorphic addition of ciphertexts.
   * Mutable version - input ciphertexts may get rescaled/level-reduced.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return result of homomorphic addition of input ciphertexts.
   */
  virtual Ciphertext<Element> EvalAddMutable(
      Ciphertext<Element>& ciphertext1,
      Ciphertext<Element>& ciphertext2) const override {ONLYDCRTPOLY}

  /**
   * Function for in-place homomorphic addition of ciphertexts.
   *
   * @param ct1 first input/output ciphertext.
   * @param ct2 second input ciphertext.
   * @details \p ct1 stores the result of \p ct1 + \p ct2
   */
  void EvalAddInPlace(Ciphertext<Element>& ciphertext1,
                      ConstCiphertext<Element> ciphertext2) const override;

  /**
   * Internal function for homomorphic addition of ciphertext
   * and plaintext. This method does not check whether input
   * ciphertexts are at the same level.
   *
   * @param ciphertext input ciphertext.
   * @param ptElement the Element corresponding to the input plaintext.
   * @return result of homomorphic addition of inputs.
   */
  Ciphertext<Element> EvalAddCore(ConstCiphertext<Element> ciphertext,
                                  Element ptElement) const;

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
  virtual Ciphertext<Element> EvalAddMutable(Ciphertext<Element>& ciphertext,
                                             Plaintext plaintext) const override {
    ONLYDCRTPOLY
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
  virtual Ciphertext<Element> EvalLinearWSum(
      vector<Ciphertext<Element>> ciphertexts, vector<double> constants) const override {
    NOIMPL
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
  virtual Ciphertext<Element> EvalLinearWSumMutable(
      vector<Ciphertext<Element>> ciphertexts,
      vector<double> constants) const override {NOIMPL}

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
   * Function for homomorphic subtraction of ciphertexts.
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return result of homomorphic subtraction of input ciphertexts.
   */
  Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext1,
                              ConstCiphertext<Element> ciphertext2) const override;

  /**
   * Function for homomorphic subtraction of ciphertexts.
   * Mutable version - input ciphertexts may get rescaled/level-reduced.
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return result of homomorphic subtraction of input ciphertexts.
   */
  virtual Ciphertext<Element> EvalSubMutable(
      Ciphertext<Element>& ciphertext1,
      Ciphertext<Element>& ciphertext2) const override {ONLYDCRTPOLY}

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
  Ciphertext<Element> EvalSubCore(ConstCiphertext<Element> ciphertext,
                                  Element ptElement) const;

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
  virtual Ciphertext<Element> EvalSubMutable(Ciphertext<Element>& ciphertext1,
                                             Plaintext plaintext) const override {
      ONLYDCRTPOLY}

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
   * Function for homomorphic multiplication of ciphertexts without key
   * switching. Currently it assumes that the input arguments are fresh
   * ciphertexts (of depth 1). Support for the input ciphertexts of higher
   * depths will be added later.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return result of homomorphic multiplication of input ciphertexts.
   */
  Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1,
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
  virtual Ciphertext<Element> EvalMultMutable(
      Ciphertext<Element>& ciphertext1,
      Ciphertext<Element>& ciphertext2) const override {ONLYDCRTPOLY}

  /**
   * Internal function for homomorphic multiplication of ciphertext
   * and plaintext. This method does not check whether input
   * ciphertexts are at the same level.
   *
   * @param ciphertext input ciphertext.
   * @param ptxt the Element corresponding to the input plaintext.
   * @return result of homomorphic subtraction of inputs.
   */
  Ciphertext<Element> EvalMultCore(ConstCiphertext<Element> ciphertext,
                                   Element ptxt) const;

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
   * The ciphertext can be changed
   *
   * @param &ciphertext input ciphertext.
   * @param plaintext input plaintext embedded in the cryptocontext.
   */
  virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ciphertext,
                                              Plaintext plaintext) const override {
      ONLYDCRTPOLY}

  /**
   * Function for homomorphic multiplication of ciphertexts followed by key
   * switching operation. Currently it assumes that the input arguments are
   * fresh ciphertexts (of depth 1). Support for the input ciphertexts of higher
   * depths will be added later.
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
  Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ciphertext1,
                                      Ciphertext<Element>& ciphertext2,
                                      const LPEvalKey<Element> ek) const override;

  /**
   * Unimplemented function to support  a multiplication with depth larger than
   * 2 for the BGVrns scheme.
   *
   * @param ciphertext1 The first input ciphertext.
   * @param ciphertext2 The second input ciphertext.
   * @param ek The evaluation key input.
   * @return A shared pointer to the ciphertext which is the EvalMult of the two
   * inputs.
   */
  Ciphertext<Element> EvalMultAndRelinearize(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2,
      const vector<LPEvalKey<Element>>& ek) const override;

  /*
   * Relinearize a ciphertext.
   *
   * @param ciphertext input ciphertext to be relinearized
   * @param ek The evaluation key input.
   * @return the relinearized ciphertext
   */
  Ciphertext<Element> Relinearize(ConstCiphertext<Element> ciphertext,
                                  const vector<LPEvalKey<Element>>& ek) const override;

  /*
   * Relinearize a ciphertext in place.
   *
   * @param ciphertext input ciphertext to be relinearized
   * @param ek The evaluation key input.
   */
  void RelinearizeInPlace(Ciphertext<Element> &ciphertext,
                                  const vector<LPEvalKey<Element>>& ek) const override {
    std::string errMsg =
        "LPAlgorithmSHEBGVrns::RelinearizeInPlace is not implemented for the non "
        "Double-CRT variant of the BGV Scheme.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Function for homomorphic negation of ciphertexts.
   *
   * @param ct input ciphertext.
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
      const LPEvalKey<DCRTPoly> ek = nullptr) const;

  /*
   * Method for in-place key switching using the GHS method
   *
   * @param keySwitchHint Hint required to perform the ciphertext switching.
   * @param ciphertext Original ciphertext to perform switching on.
   */
  void KeySwitchHybridInPlace(const LPEvalKey<Element> keySwitchHint,
                              Ciphertext<Element>& ciphertext) const;

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
   * Method for in-place key switching using the GHS method introduced in Gentry,
   * et. al., "Homomorphic evaluation of the AES circuit (Updated
   * implementation)". Here, we follow the notation of Section 3.2 of
   * "A full RNS variant of approximate homomorphic encryption" (RNS
   * CKKS paper).
   *
   * @param keySwitchHint Hint required to perform the ciphertext switching.
   * @param ciphertext Original ciphertext to perform switching on.
   */
  void KeySwitchGHSInPlace(const LPEvalKey<Element> keySwitchHint,
                           Ciphertext<Element>& ciphertext) const;

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
                          Ciphertext<Element>& ciphertext) const;

  /**
   * Method for generating a KeySwitchHint using RLWE relinearization
   *
   * @param oldKey Original private key used for encryption.
   * @param newKey New private key to generate the keyswitch hint.
   * @return resulting keySwitchHint.
   */
  virtual LPEvalKey<Element> KeySwitchGen(
      const LPPrivateKey<Element> oldKey,
      const LPPrivateKey<Element> newKey) const override;

  /**
   * Method for in-place KeySwitching based on a KeySwitchHint - uses the RLWE
   * relinearization
   *
   * @param keySwitchHint Hint required to perform the ciphertext switching.
   */
  void KeySwitchInPlace(const LPEvalKey<Element> keySwitchHint,
                              Ciphertext<Element>& ciphertext) const override;

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
   * Function to generate key switch hint on a ciphertext for depth more than 2.
   * Currently this method is not supported for BGVrns.
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
      const std::map<usint, LPEvalKey<Element>>& evalKeys,
      CALLER_INFO_ARGS_HDR) const override;

  /**
   * Generate automophism keys for a given private key; Uses the private key for
   * encryption
   *
   * @param privateKey private key.
   * @param indexList list of automorphism indices to be computed
   * @return returns the evaluation keys
   */
  shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(
      const LPPrivateKey<Element> privateKey,
      const std::vector<usint>& indexList) const override;

  /**
   * Generate automophism keys for a given private key; Uses the public key for
   * encryption
   *
   * @param publicKey public key.
   * @param privateKey private key.
   * @param indexList list of automorphism indices to be computed
   * @return returns the evaluation keys
   */
  shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(
      const LPPublicKey<Element> publicKey,
      const LPPrivateKey<Element> privateKey,
      const std::vector<usint>& indexList) const override {
    std::string errMsg =
        "LPAlgorithmSHEBGVrns::EvalAutomorphismKeyGen is not implemented for "
        "BGVrns SHE Scheme.";
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
   * @param index the index of the rotation. Positive indices correspond to left
   * rotations and negative indices correspond to right rotations.
   * @param m is the cyclotomic order
   * @param precomp In BV, this is the digit decomposition created by
   * 		  EvalFastRotationPrecomputeBV. In GHS, this is the expanded
   * part of the ciphertext.
   */
  Ciphertext<Element> EvalFastRotation(
      ConstCiphertext<Element> ciphertext, const usint index, const usint m,
      const shared_ptr<vector<Element>> precomp) const override;

 private:
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
   * Hoisted automorphisms is a technique that performs the digit decomposition
   * for the original ciphertext first, and then performs the automorphism and
   * the key switching on the decomposed digits. The benefit of this is that the
   * digit decomposition is independent of the automorphism rotation index, so
   * it can be reused for multiple different indices. This can greatly improve
   * performance when we have to compute many automorphisms on the same
   * ciphertext. This routinely happens when we do permutations (EvalPermute).
   *
   * EvalFastRotationPrecompute implements the digit decomposition step of
   * hoisted automorphisms.
   *
   * @param ct the input ciphertext on which to do the precomputation (digit
   * decomposition)
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
   * Hoisted automorphisms is a technique that performs the digit decomposition
   * for the original ciphertext first, and then performs the automorphism and
   * the key switching on the decomposed digits. The benefit of this is that the
   * digit decomposition is independent of the automorphism rotation index, so
   * it can be reused for multiple different indices. This can greatly improve
   * performance when we have to compute many automorphisms on the same
   * ciphertext. This routinely happens when we do permutations (EvalPermute).
   *
   * EvalFastRotation implements the automorphism and key swithcing step of
   * hoisted automorphisms.
   *
   * This method assumes that all required rotation keys exist. This may not be
   * true if we are using baby-step/giant-step key switching. Please refer to
   * Section 5.1 of the above reference and EvalPermuteBGStepHoisted to see how
   * to deal with this issue.
   *
   * @param ct the input ciphertext to perform the automorphism on
   * @param index the index of the rotation. Positive indices correspond to left
   * rotations and negative indices correspond to right rotations.
   * @param m is the cyclotomic order
   * @param digits the digit decomposition created by EvalFastRotationPrecompute
   * at the precomputation step.
   * @param evalKey is the rotation key that corresponds to the index (computed
   * in wrapper EvalFastRotation)
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
   * @param index the index of the rotation. Positive indices correspond to left
   * rotations and negative indices correspond to right rotations.
   * @param m is the cyclotomic order
   * @param expandedCiphertext the result of ModUp on one of the ciphertext
   * parts, which is generated by EvalFastRotationPrecomputeGHS at the
   * precomputation step.
   * @param evalKey is the rotation key that corresponds to the index (computed
   * in wrapper EvalFastRotation)
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
   * @param index the index of the rotation. Positive indices correspond to left
   * rotations and negative indices correspond to right rotations.
   * @param m is the cyclotomic order
   * @param expandedCiphertext the result of ModUp and RNS digit decomposition
   * on one of the ciphertext parts, which is generated by
   * EvalFastRotationPrecomputeHybrid at the precomputation step.
   * @param evalKey is the rotation key that corresponds to the index (computed
   * in wrapper EvalFastRotation)
   */
  Ciphertext<Element> EvalFastRotationHybrid(
      ConstCiphertext<Element> ciphertext, const usint index, const usint m,
      const shared_ptr<vector<Element>> expandedCiphertext,
      LPEvalKey<DCRTPoly> evalKey) const;

  /**
   * Function for evaluating multiplication on ciphertext followed by
   * relinearization operation. It computes the multiplication in a binary tree
   * manner. Also, it reduces the number of elements in the ciphertext to two
   * after each multiplication and then ModSwitch. Currently it assumes that the
   * consecutive two input arguments have total depth smaller than the supported
   * depth. Otherwise, it throws an error.
   *
   * @param ciphertextList  is the ciphertext list.
   * @param evalKeys is the evaluation key to make the newCiphertext
   *  decryptable by the same secret key as that of ciphertext list.
   * @return new ciphertext.
   */
  Ciphertext<Element> EvalMultMany(
      const vector<Ciphertext<Element>>& ciphertextList,
      const vector<LPEvalKey<Element>>& evalKeys) const override {
    std::string errMsg =                                             \
        "BGVrns supports only DCRTPoly."; \
    PALISADE_THROW(not_implemented_error, errMsg);
  }

 public:
  template <class Archive>
  void save(Archive& ar) const {
    ar(cereal::base_class<LPSHEAlgorithm<Element>>(this));
  }

  template <class Archive>
  void load(Archive& ar) {
    ar(cereal::base_class<LPSHEAlgorithm<Element>>(this));
  }

  std::string SerializedObjectName() const { return "BGVrnsSHE"; }
};

/**
 * @brief PRE scheme based on BGVrns.
 * The basic scheme is described here:
 *   -  Brakerski Z., Vaikuntanathan V. (2011) Fully Homomorphic Encryption from
 * Ring-LWE and Security for Key Dependent Messages. In: Rogaway P. (eds)
 * Advances in Cryptology � CRYPTO 2011. CRYPTO 2011. Lecture Notes in
 * Computer Science, vol 6841. Springer, Berlin, Heidelberg
 *      (http://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf) or
 * alternative Internet source:
 * (http://dx.doi.org/10.1007/978-3-642-22792-9_29).
 *
 * We use advances from the BGVrns scheme for leveled homomorphic capabilities
 * from here:
 *   - Brakerski Z., Gentry C., Halevi S. (2013) Packed Ciphertexts in LWE-Based
 * Homomorphic Encryption. In: Kurosawa K., Hanaoka G. (eds) Public-Key
 * Cryptography � PKC 2013. Lecture Notes in Computer Science, vol 7778.
 * Springer, Berlin, Heidelberg (https://eprint.iacr.org/2011/277.pdf).
 *
 * Our PRE design and algorithms are informed by the design here:
 *   - Polyakov, Yuriy, Kurt Rohloff, Gyana Sahu and Vinod Vaikuntanathan. Fast
 * Proxy Re-Encryption for Publish/Subscribe Systems. Under Review in ACM
 * Transactions on Privacy and Security (ACM TOPS).
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPAlgorithmPREBGVrns : public LPPREAlgorithm<Element> {
  using IntType = typename Element::Integer;
  using ParmType = typename Element::Params;
  using DggType = typename Element::DggType;
  using DugType = typename Element::DugType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmPREBGVrns() {}

  /**
   * Function to generate a re-encryption key as 1..log(q) encryptions for each
   * bit of the original private key Variant that uses the new secret key
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
   * The inadequacy of CPA Security for proxy re-encryption". Section 5.1 shows
   * an attack where given an original ciphertext c=(c0,c1) and a re-encrypted
   * ciphertext c'=(c'0, c'1), the subscriber (Bob) can compute the secret key
   * of the publisher (Alice).
   *
   * We fix this vulnerability by making re-encryption keys be encryptions of
   * the s*(2^{i*r}) terms, instead of simple addition as previously defined.
   * This makes retrieving the secret key using the above attack as hard as
   * breaking the RLWE assumption.
   *
   * Our modification makes the scheme CPA-secure, but does not achieve
   * HRA-security as it was defined in the Cohen paper above. Please look at the
   * ReEncrypt method for an explanation of the two security definitions and how
   * to achieve each in Palisade.
   *
   * @param newKey public key for the new private key.
   * @param oldKey original private key used for decryption.
   * @return evalKey the evaluation key for switching the ciphertext to be
   * decryptable by new private key.
   */
  LPEvalKey<Element> ReKeyGen(
      const LPPublicKey<Element> newKey,
      const LPPrivateKey<Element> oldKey) const override;

  /**
   * This method implements re-encryption using the evaluation key generated by
   * ReKeyGen.
   *
   * The PRE scheme used can achieve two different levels of security, based on
   * the value supplied in the publicKey argument:
   *
   * If publicKey is nullptr, the PRE scheme is CPA-secure. If the publicKey of
   * the recipient of the re-encrypted ciphertext is supplied, then the scheme
   * is HRA- secure. Please refer to Cohen, "What about Bob? The inadequacy of
   * CPA Security for proxy re-encryption", for more information on HRA
   * security.
   *
   * The tradeoff of going for HRA is twofold: (1) performance is a little worst
   * because we add one additional encryption and homomorphic addition to the
   * result, and (2) more noise is added to the result because of the additional
   * operations.
   *
   * @param evalKey the evaluation key.
   * @param ciphertext the input ciphertext.
   * @param publicKey the original public key.
   * @return resulting ciphertext after the re-encryption operation.
   */
  Ciphertext<Element> ReEncrypt(
      const LPEvalKey<Element> EK, ConstCiphertext<Element> ciphertext,
      const LPPublicKey<Element> publicKey = nullptr) const override;

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
   * This is the version of ReKeyGen that works with GHS key switching (approx.
   * mod. switching).
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
  void save(Archive& ar) const {
    ar(cereal::base_class<LPPREAlgorithm<Element>>(this));
  }

  template <class Archive>
  void load(Archive& ar) {
    ar(cereal::base_class<LPPREAlgorithm<Element>>(this));
  }

  std::string SerializedObjectName() const { return "BGVrnsPRE"; }
};

/**
 * @brief The multiparty homomorphic encryption capability for the BGVrns
 * scheme. A version of this multiparty scheme built on the BGVrns scheme is
 * seen here:
 *   - Asharov G., Jain A., L�pez-Alt A., Tromer E., Vaikuntanathan V., Wichs
 * D. (2012) Multiparty Computation with Low Communication, Computation and
 * Interaction via Threshold FHE. In: Pointcheval D., Johansson T. (eds)
 * Advances in Cryptology � EUROCRYPT 2012. EUROCRYPT 2012. Lecture Notes in
 * Computer Science, vol 7237. Springer, Berlin, Heidelberg
 *
 * During offline key generation, this multiparty scheme relies on the clients
 * coordinating their public key generation.  To do this, a single client
 * generates a public-secret key pair. This public key is shared with other keys
 * which use an element in the public key to generate their own public keys. The
 * clients generate a shared key pair using a scheme-specific approach, then
 * generate re-encryption keys.  Re-encryption keys are uploaded to the server.
 * Clients encrypt data with their public keys and send the encrypted data
 * server. The data is re-encrypted.  Computations are then run on the data. The
 * result is sent to each of the clients. One client runs a "Leader" multiparty
 * decryption operation with its own secret key.  All other clients run a
 * regular "Main" multiparty decryption with their own secret key. The resulting
 * partially decrypted ciphertext are then fully decrypted with the decryption
 * fusion algorithms.
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPAlgorithmMultipartyBGVrns : public LPMultipartyAlgorithm<Element> {
  using IntType = typename Element::Integer;
  using ParmType = typename Element::Params;
  using DggType = typename Element::DggType;
  using DugType = typename Element::DugType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmMultipartyBGVrns() {}

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
                                      bool fresh = false) override;

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
      const vector<LPPrivateKey<Element>>& secretKeys,
      bool makeSparse = false) override;

  /**
   * Threshold FHE: "Partial" decryption computed by all parties except for the
   * lead one
   *
   * @param privateKey secret key share used for decryption.
   * @param ciphertext ciphertext that is being decrypted.
   */
  Ciphertext<Element> MultipartyDecryptMain(
      const LPPrivateKey<Element> privateKey,
      ConstCiphertext<Element> ciphertext) const override;

  /**
   * Threshold FHE: Method for decryption operation run by the lead decryption
   * client
   *
   * @param privateKey secret key share used for decryption.
   * @param ciphertext ciphertext id decrypted.
   */
  Ciphertext<Element> MultipartyDecryptLead(
      const LPPrivateKey<Element> privateKey,
      ConstCiphertext<Element> ciphertext) const override;

  /**
   * Threshold FHE: Method for combining the partially decrypted ciphertexts
   * and getting the final decryption in the clear as a NativePoly.
   *
   * @param &ciphertextVec vector of "partial" decryptions.
   * @param *plaintext the plaintext output as a NativePoly.
   * @return the decoding result.
   */
  DecryptResult MultipartyDecryptFusion(
      const vector<Ciphertext<Element>>& ciphertextVec,
      NativePoly* plaintext) const override;

  /**
   * Threshold FHE: Method for combining the partially decrypted ciphertexts
   * and getting the final decryption in the clear as a Poly.
   *
   * @param &ciphertextVec vector of "partial" decryptions.
   * @param *plaintext the plaintext output as a Poly.
   * @return the decoding result.
   */
  DecryptResult MultipartyDecryptFusion(
      const vector<Ciphertext<Element>>& ciphertextVec,
      Poly* plaintext) const override;

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
      const LPEvalKey<Element> ek) const override;

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
      const std::vector<usint>& indexList) const override;

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
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> eSum)
      const override;

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
                                      LPPrivateKey<Element> sk) const override;

  template <class Archive>
  void save(Archive& ar) const {
    ar(cereal::base_class<LPMultipartyAlgorithm<Element>>(this));
  }

  template <class Archive>
  void load(Archive& ar) {
    ar(cereal::base_class<LPMultipartyAlgorithm<Element>>(this));
  }

  std::string SerializedObjectName() const { return "BGVrnsMultiparty"; }
};

/**
 * @brief Concrete feature class for Leveled SHEBGVrns operations. This class
 * adds leveled (BGVrns scheme) features to the BGVrns scheme.
 *
 * We use advances from the BGVrns scheme for levelled homomorphic capabilities
 * from here:
 *   - Brakerski Z., Gentry C., Halevi S. (2013) Packed Ciphertexts in LWE-Based
 * Homomorphic Encryption. In: Kurosawa K., Hanaoka G. (eds) Public-Key
 * Cryptography � PKC 2013. Lecture Notes in Computer Science, vol 7778.
 * Springer, Berlin, Heidelberg (https://eprint.iacr.org/2011/277.pdf).
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPLeveledSHEAlgorithmBGVrns : public LPLeveledSHEAlgorithm<Element> {
  using IntType = typename Element::Integer;
  using ParmType = typename Element::Params;
  using DggType = typename Element::DggType;
  using DugType = typename Element::DugType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPLeveledSHEAlgorithmBGVrns() {}

  virtual ~LPLeveledSHEAlgorithmBGVrns() {}

  /**
   * Method for rescaling.
   *
   * @param ciphertext is the ciphertext to perform modreduce on.
   * @return ciphertext after the modulus reduction performed.
   */
  Ciphertext<Element> ModReduceInternal(ConstCiphertext<Element> ciphertext,
                                        size_t levels = 1) const override;

  /**
   * Method for rescaling in-place
   *
   * @param ciphertext is the ciphertext to perform modreduce on in-place
   */
  void ModReduceInternalInPlace(Ciphertext<Element>& ciphertext,
                                size_t levels = 1) const override;

  /**
   * Method for rescaling in-place.
   *
   * @param ciphertext is the ciphertext to perform modreduce on in-place
   */
  void ModReduceInPlace(Ciphertext<Element>& ciphertext,
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
   * key switching, and modulo reduction.
   *
   * @param ciphertext1 ciphertext1, first input ciphertext to perform
   * multiplication on.
   * @param ciphertext2 cipherText2, second input ciphertext to perform
   * multiplication on.
   * @param quadKeySwitchHint is used for EvalMult operation.
   * @return resulting ciphertext.
   */
  Ciphertext<Element> ComposedEvalMult(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2,
      const LPEvalKey<Element> quadKeySwitchHint) const override;
  /**
   * Wrapper method for level reduce in BGVrns.
   *
   * @param cipherText1 is the original ciphertext to be level reduced.
   * @param linearKeySwitchHint not used in the BGVrns scheme.
   * @param levels the number of towers to drop.
   * @return resulting ciphertext.
   */
  Ciphertext<Element> LevelReduce(ConstCiphertext<Element> cipherText,
                                  const LPEvalKey<Element> linearKeySwitchHint,
                                  size_t levels) const override;
  /**
   * Method for Level Reduction in the BGVrns scheme. It just drops "levels"
   * number of the towers of the ciphertext without changing the underlying
   * plaintext.
   *
   * @param ciphertext is the original ciphertext to be level reduced.
   * @param linearKeySwitchHint not used in the BGVrns scheme.
   * @param levels the number of towers to drop.
   * @return resulting ciphertext.
   */
  Ciphertext<Element> LevelReduceInternal(
      ConstCiphertext<Element> ciphertext,
      const LPEvalKey<Element> linearKeySwitchHint,
      size_t levels) const override;

  template <class Archive>
  void save(Archive& ar) const {
    ar(cereal::base_class<LPLeveledSHEAlgorithm<Element>>(this));
  }

  template <class Archive>
  void load(Archive& ar) {
    ar(cereal::base_class<LPLeveledSHEAlgorithm<Element>>(this));
  }

  std::string SerializedObjectName() const { return "BGVrnsLeveledSHE"; }
};

/**
 * @brief Main public key encryption scheme for the BGVrns/BGVrns implementation
 * @tparam Element a ring element.
 */
template <class Element>
class LPPublicKeyEncryptionSchemeBGVrns
    : public LPPublicKeyEncryptionScheme<Element> {
  using IntType = typename Element::Integer;
  using ParmType = typename Element::Params;
  using DggType = typename Element::DggType;
  using DugType = typename Element::DugType;
  using TugType = typename Element::TugType;

 public:
  LPPublicKeyEncryptionSchemeBGVrns() : LPPublicKeyEncryptionScheme<Element>() {
    this->m_algorithmParamsGen =
        std::make_shared<LPAlgorithmParamsGenBGVrns<Element>>();
  }

  bool operator==(
      const LPPublicKeyEncryptionScheme<Element>& sch) const override {
    return dynamic_cast<const LPPublicKeyEncryptionSchemeBGVrns<Element>*>(
               &sch) != nullptr;
  }

  void Enable(PKESchemeFeature feature) override;

  template <class Archive>
  void save(Archive& ar, std::uint32_t const version) const {
    ar(cereal::base_class<LPPublicKeyEncryptionScheme<Element>>(this));
  }

  template <class Archive>
  void load(Archive& ar, std::uint32_t const version) {
    ar(cereal::base_class<LPPublicKeyEncryptionScheme<Element>>(this));
  }

  std::string SerializedObjectName() const override { return "BGVrnsScheme"; }
};

}  // namespace lbcrypto
#endif
