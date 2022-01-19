// @file pre-base.h -- Public key type for lattice crypto operations.
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

#ifndef LBCRYPTO_CRYPTO_RNS_CRYPTOPARAMETERS_H
#define LBCRYPTO_CRYPTO_RNS_CRYPTOPARAMETERS_H

#include "lattice/backend.h"

#include "schemebase/rlwe-cryptoparameters.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief main implementation class to capture essential cryptoparameters of
 * any LBC system
 * @tparam Element a ring element.
 */
class CryptoParametersRNS : public CryptoParametersRLWE<DCRTPoly> {
  using ParmType = typename DCRTPoly::Params;

public:

  CryptoParametersRNS()
      : CryptoParametersRLWE<DCRTPoly>(),
        m_ksTechnique(BV),
        m_rsTechnique(FIXEDMANUAL),
        m_encTechnique(STANDARD),
        m_multTechnique(HPS) {}

  CryptoParametersRNS(const CryptoParametersRNS &rhs)
      : CryptoParametersRLWE<DCRTPoly>(rhs),
        m_ksTechnique(rhs.m_ksTechnique),
        m_rsTechnique(rhs.m_rsTechnique),
        m_encTechnique(rhs.m_encTechnique),
        m_multTechnique(rhs.m_multTechnique) {}

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
  CryptoParametersRNS(shared_ptr<ParmType> params,
                       const PlaintextModulus &plaintextModulus,
                       float distributionParameter, float assuranceMeasure,
                       float securityLevel, usint relinWindow, MODE mode,
                       int depth = 1, int maxDepth = 2,
                       KeySwitchTechnique ksTech = BV,
                       RescalingTechnique rsTech = FIXEDMANUAL,
                       EncryptionTechnique encTech = STANDARD,
                       MultiplicationTechnique multTech = HPS)
      : CryptoParametersRLWE<DCRTPoly>(
            params,
            EncodingParams(
                std::make_shared<EncodingParamsImpl>(plaintextModulus)),
            distributionParameter, assuranceMeasure, securityLevel, relinWindow,
            depth, maxDepth, mode) {
    m_ksTechnique = ksTech;
    m_rsTechnique = rsTech;
    m_encTechnique = encTech;
    m_multTechnique = multTech;
  }

  CryptoParametersRNS(shared_ptr<ParmType> params,
                       EncodingParams encodingParams,
                       float distributionParameter, float assuranceMeasure,
                       float securityLevel, usint relinWindow, MODE mode,
                       int depth = 1, int maxDepth = 2,
                       KeySwitchTechnique ksTech = BV,
                       RescalingTechnique rsTech = FIXEDMANUAL,
                       EncryptionTechnique encTech = STANDARD,
                       MultiplicationTechnique multTech = HPS)
      : CryptoParametersRLWE<DCRTPoly>(
            params, encodingParams, distributionParameter, assuranceMeasure,
            securityLevel, relinWindow, depth, maxDepth, mode) {
    m_ksTechnique = ksTech;
    m_rsTechnique = rsTech;
    m_encTechnique = encTech;
    m_multTechnique = multTech;
  }


  virtual ~CryptoParametersRNS() {}

  /**
   * Computes all tables needed for decryption, homomorphic multiplication,
   * and key switching
   * @param ksTech the technique to use for key switching (e.g., BV or GHS).
   * @param rsTech the technique to use for rescaling (e.g., FLEXIBLEAUTO or
   * FIXEDMANUAL).
   */
  virtual void PrecomputeCRTTables(KeySwitchTechnique ksTech = BV,
                                   RescalingTechnique rsTech = FIXEDMANUAL,
                                   EncryptionTechnique encTech = STANDARD,
                                   MultiplicationTechnique multTech = HPS,
                                   uint32_t numPartQ = 0,
                                   uint32_t auxBits = 0,
                                   uint32_t extraBits = 0);

  virtual uint64_t FindAuxPrimeStep() const;

  /**
   * == operator to compare to this instance of CryptoParametersBase object.
   *
   * @param &rhs CryptoParameters to check equality against.
   */
  bool operator==(const CryptoParametersBase<DCRTPoly> &rhs) const override {
    const auto *el = dynamic_cast<const CryptoParametersRNS *>(&rhs);

    if (el == nullptr) return false;

    return CryptoParametersBase<DCRTPoly>::operator==(rhs) &&
           m_rsTechnique == el->GetRescalingTechnique() &&
           m_ksTechnique == el->GetKeySwitchTechnique() &&
           m_multTechnique == el->GetMultiplicationTechnique() &&
           m_encTechnique == el->GetEncryptionTechnique() &&
           m_numPartQ == el->GetNumPartQ() &&
           m_auxBits == el->GetAuxBits() &&
           m_extraBits == el->GetExtraBits();
  }

  void PrintParameters(std::ostream &os) const override {
    CryptoParametersBase<DCRTPoly>::PrintParameters(os);
  }

  /////////////////////////////////////
  // PrecomputeCRTTables
  /////////////////////////////////////

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
   * Method to retrieve the technique to be used for rescaling.
   *
   * @return the rescaling technique.
   */
  enum EncryptionTechnique GetEncryptionTechnique() const {
    return m_encTechnique;
  }

  /**
   * Method to retrieve the technique to be used for rescaling.
   *
   * @return the rescaling technique.
   */
  enum MultiplicationTechnique GetMultiplicationTechnique() const {
    return m_multTechnique;
  }

  uint32_t GetAuxBits() const { return m_auxBits; }

  uint32_t GetExtraBits() const { return m_extraBits; }

  /////////////////////////////////////
  // BGVrns : ModReduce
  /////////////////////////////////////

  /**
   * Method that returns the NTL precomputions for [t]_{q_i}
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger> &GettModqPrecon() const { return m_tModqPrecon; }

  /**
   * Get the precomputed table of [-t^{-1}]_{q_i}
   *
   * @return the pre-computed values.
   */
  const NativeInteger &GetNegtInvModq(usint l) const {
    return m_negtInvModq[l];
  }

  /**
   * Method that returns the NTL precomputions for [-t^{-1}]_{q_i}
   *
   * @return the pre-computed values.
   */
  const NativeInteger &GetNegtInvModqPrecon(usint l) const {
    return m_negtInvModqPrecon[l];
  }

  /////////////////////////////////////
  // CKKSrns : DropLastElementAndScale
  /////////////////////////////////////

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
  const std::vector<NativeInteger> &GetqlInvModq(size_t i) const {
    return m_qlInvModq[i];
  }

  /**
   * Gets the NTL precomputions for [q_i^{-1}]_{q_j}
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger> &GetqlInvModqPrecon(size_t i) const {
    return m_qlInvModqPrecon[i];
  }

  /////////////////////////////////////
  // KeySwitchHybrid : KeyGen
  /////////////////////////////////////

  /**
   * Gets Q*P CRT basis
   * Q*P = {q_1,...,q_l,p_1,...,p_k}
   * Used in Hybrid key switch generation
   *
   * @return the precomputed CRT params
   */
  const shared_ptr<ILDCRTParams<BigInteger>> GetParamsQP() const {
    return m_paramsQP;
  }

  /**
   * Method that returns the number of digits.
   * Used in Hybrid key switch generation
   * @return the number of digits.
   */
  uint32_t GetNumPartQ() const { return m_numPartQ; }

  /**
   * Gets the precomputed table of [P]_{q_i}
   * Used in Hybrid key switch generation.
   * @return the precomputed table
   */
  const vector<NativeInteger> &GetPModq() const { return m_PModq; }

  /**
   * Get the precomputed table of [Q/Q_j]_{q_i}
   * Used in HYBRID key switch generation.
   *
   * @return the precomputed table
   */
  const vector<vector<NativeInteger>> &GetPartQHatModq() const {
    return m_PartQHatModq;
  }

  /////////////////////////////////////
  // KeySwitchHybrid : KeySwitch
  /////////////////////////////////////

  /**
   * Gets the Auxiliary CRT basis {P} = {p_1,...,p_k}
   * Used in Hybrid key switching
   *
   * @return the parameters CRT params
   */
  const shared_ptr<ILDCRTParams<BigInteger>> GetParamsP() const {
    return m_paramsP;
  }

  /**
   * Method that returns the number of towers within every digit.
   * This is the alpha parameter from the paper (see documentation
   * for KeySwitchHHybrid).
   * Used in Hybrid key switching
   *
   * @return the number of towers per digit.
   */
  uint32_t GetNumPerPartQ() const { return m_numPerPartQ; }

  /*
   * Method that returns the number of partitions.
   * Used in Hybrid key switching
   *
   * @return the number of partitions.
   */
  uint32_t GetNumberOfQPartitions() const { return m_paramsPartQ.size(); }

  /**
   * Method that returns the element parameters corresponding to
   * partitions {Q_j} of Q.
   * Used in Hybrid key switching
   *
   * @return the pre-computed values.
   */
  const shared_ptr<ILDCRTParams<BigInteger>> &GetParamsPartQ(
      uint32_t part) const {
    return m_paramsPartQ[part];
  }

  /**
   * Method that returns the precomputed values for QHat^-1 mod qj
   * Used in Hybrid key switching
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger> &GetPartQHatInvModq(uint32_t part) const {
    return m_PartQHatInvModq[part];
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

  /**
   * Method that returns the precomputed values for QHat^-1 mod qj within a
   * partition of towers, used in HYBRID.
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger> &GetPartQlHatInvModq(uint32_t part,
                                                   uint32_t sublvl) const {
    if (part < m_PartQlHatInvModq.size() &&
        sublvl < m_PartQlHatInvModq[part].size())
      return m_PartQlHatInvModq[part][sublvl];

    PALISADE_THROW(math_error,
                   "CryptoParametersCKKS::GetPartitionQHatInvModQTable - "
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
    if (part < m_PartQlHatInvModqPrecon.size() &&
        sublvl < m_PartQlHatInvModqPrecon[part].size())
      return m_PartQlHatInvModqPrecon[part][sublvl];

    PALISADE_THROW(math_error,
                   "CryptoParametersCKKS::"
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
    if (lvl < m_PartQlHatModp.size() && part < m_PartQlHatModp[lvl].size())
      return m_PartQlHatModp[lvl][part];

    PALISADE_THROW(math_error,
                   "CryptoParametersCKKS::GetPartitionQHatModPTable - "
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
                   "CryptoParametersCKKS::GetPartitionPrecon - index out "
                   "of bounds.");
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
   * Gets the Barrett modulo reduction precomputation for q_i
   *
   * @return the precomputed table
   */
  const vector<DoubleNativeInt> &GetModqBarrettMu() const {
    return m_modqBarrettMu;
  }

  /**
   * Method that returns the precomputed values for [t^(-1)]_{q_i}
   * Used in ModulusSwitching.
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger> &GettInvModq() const { return m_tInvModq; }

  /**
   * Method that returns the NTL precomputions for [t^{-1}]_{q_i}
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger> &GettInvModqPrecon() const {
    return m_tInvModqPrecon;
  }

  /**
   * Method that returns the precomputed values for [t^(-1)]_{p_j}
   * Used in KeySwitching.
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger> &GettInvModp() const { return m_tInvModp; }

  /**
   * Method that returns the NTL precomputions for [t^{-1}]_{p_j}
   *
   * @return the pre-computed values.
   */
  const vector<NativeInteger> &GettInvModpPrecon() const {
    return m_tInvModpPrecon;
  }

  /////////////////////////////////////
  // CKKSrns Scaling Factor
  /////////////////////////////////////

  /**
   * Method to retrieve the scaling factor of level l.
   * For FIXEDMANUAL rescaling technique method always returns 2^p,
   * where p corresponds to plaintext modulus
   * @param l For FLEXIBLEAUTO rescaling technique the level whose scaling
   * factor we want to learn. Levels start from 0 (no rescaling done - all
   * towers) and go up to K-1, where K is the number of towers supported.
   * @return the scaling factor.
   */
  double GetScalingFactorReal(uint32_t l = 0) const {
    if (m_rsTechnique == FLEXIBLEAUTO) {
      if (l >= m_scalingFactorsReal.size()) {
        PALISADE_THROW(math_error,
                       "CryptoParametersCKKS::GetScalingFactorOfLevel - Cannot "
                       "return scaling factor of level " +
                           std::to_string(l) +
                           ". Current settings have up to " +
                           std::to_string(m_scalingFactorsReal.size()) +
                           " levels, starting from 0.");
      }

      return m_scalingFactorsReal[l];
    }

    return m_approxSF;
  }

  double GetScalingFactorRealBig(uint32_t l = 0) const {
    return m_scalingFactorsRealBig[l];
  }

  /**
   * Method to retrieve the modulus to be dropped of level l.
   * For FIXEDMANUAL rescaling technique method always returns 2^p,
   * where p corresponds to plaintext modulus
   * @param l index of modulus to be dropped for FLEXIBLEAUTO rescaling
   * technique
   *
   * @return the precomputed table
   */
  double GetModReduceFactor(uint32_t l = 0) const {
    if (m_rsTechnique == FLEXIBLEAUTO) {
      return m_dmoduliQ[l];
    }

    return m_approxSF;
  }

  /////////////////////////////////////
  // BFVrns : Mult : ExpandCRTBasis
  /////////////////////////////////////

  /**
   * Gets the Auxiliary CRT basis {R} = {r_1,...,r_k}
   * used in homomorphic multiplication
   *
   * @return the precomputed CRT params
   */
  const shared_ptr<ILDCRTParams<BigInteger>> GetParamsRl(usint l) const {
    return m_paramsRl[l];
  }

  /**
   * Gets the Auxiliary expanded CRT basis {S} = {Q*R} =
   * {{q_i},{r_k}} used in homomorphic multiplication
   *
   * @return the precomputed CRT params
   */
  const shared_ptr<ILDCRTParams<BigInteger>> GetParamsQlRl(usint l) const {
    return m_paramsQlRl[l];
  }

  /**
   * Gets the precomputed table of [(Q/q_i)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger> &GetQlHatInvModq(usint l) const {
    return m_QlHatInvModq[l];
  }

  /**
   * Gets the NTL precomputations for [(Q/q_i)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger> &GetQlHatInvModqPrecon(usint l) const {
    return m_QlHatInvModqPrecon[l];
  }

  /**
   * Gets the precomputed table of [Q/q_i]_{r_k}
   *
   * @return the precomputed table
   */
  const std::vector<std::vector<NativeInteger>> &GetQlHatModr(usint l) const {
    return m_QlHatModr[l];
  }

  /**
   * Gets the precomputed table of [\alpha*Q]_{r_k}
   *
   * @return the precomputed table
   */
  const std::vector<std::vector<NativeInteger>> &GetalphaQlModr(usint l) const {
    return m_alphaQlModr[l];
  }

  /**
   * Gets the Barrett modulo reduction precomputations for r_k
   *
   * @return the precomputed table
   */
  std::vector<DoubleNativeInt> const &GetModrBarrettMu() const {
    return m_modrBarrettMu;
  }

  /**
   * Gets the precomputed table of 1./q_i
   *
   * @return the precomputed table
   */
  std::vector<double> const &GetqInv() const { return m_qInv; }

  /////////////////////////////////////
  // BFVrns : Mult : ScaleAndRound
  /////////////////////////////////////

  /**
   * For S = QR
   * Gets the precomputed table of \frac{[t*R*(S/s_m)^{-1}]_{s_m}/s_m}
   *
   * @return the precomputed table
   */
  const std::vector<double> &GettRSHatInvModsDivsFrac() const {
    return m_tRSHatInvModsDivsFrac;
  }

  /**
   * For S = QR
   * Gets the precomputed table of [\floor{t*R*(S/s_m)^{-1}/s_m}]_{r_k}
   *
   * @return the precomputed table
   */
  const std::vector<std::vector<NativeInteger>> &GettRSHatInvModsDivsModr()
      const {
    return m_tRSHatInvModsDivsModr;
  }

  /////////////////////////////////////
  // BFVrns : Mult : SwitchCRTBasis
  /////////////////////////////////////

  /**
   * Gets the precomputed table of [(R/r_k)^{-1}]_{r_k}
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger> &GetRlHatInvModr(usint l) const {
    return m_RlHatInvModr[l];
  }

  /**
   * Gets the NTL precomputation for [(R/r_k)^{-1}]_{r_k}
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger> &GetRlHatInvModrPrecon(usint l) const {
    return m_RlHatInvModrPrecon[l];
  }

  /**
   * Gets the precomputed table of [R/r_k]_{q_i}
   *
   * @return the precomputed table
   */
  const std::vector<std::vector<NativeInteger>> &GetRlHatModq(usint l) const {
    return m_RlHatModq[l];
  }

  /**
   * Gets the precomputed table of [\alpha*P]_{q_i}
   *
   * @return the precomputed table
   */
  const std::vector<std::vector<NativeInteger>> &GetalphaRlModq(usint l) const {
    return m_alphaRlModq[l];
  }

  /**
   * Gets the precomputed table of 1./p_j
   *
   * @return the precomputed table
   */
  std::vector<double> const &GetrInv() const { return m_rInv; }

  /////////////////////////////////////
  // BFVrns : Decrypt : ScaleAndRound
  /////////////////////////////////////

  /**
   * Gets the precomputed table of \frac{t*{Q/q_i}^{-1}/q_i}
   *
   * @return the precomputed table
   */
  const std::vector<double> &GettQHatInvModqDivqFrac() const {
    return m_tQHatInvModqDivqFrac;
  }

  /**
   * When log2(q_i) >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
   * Gets the precomputed table of \frac{t*{Q/q_i}^{-1}*B/q_i}
   *
   * @return the precomputed table
   */
  const std::vector<double> &GettQHatInvModqBDivqFrac() const {
    return m_tQHatInvModqBDivqFrac;
  }

  /**
   * Gets the precomputed table of [\floor{t*{Q/q_i}^{-1}/q_i}]_t
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger> &GettQHatInvModqDivqModt() const {
    return m_tQHatInvModqDivqModt;
  }

  /**
   * Gets the NTL precomputations for [\floor{t*{Q/q_i}^{-1}/q_i}]_t
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger> &GettQHatInvModqDivqModtPrecon() const {
    return m_tQHatInvModqDivqModtPrecon;
  }

  /**
   * When log2(q_i) >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
   * Gets the precomputed table of [\floor{t*{Q/q_i}^{-1}*B/q_i}]_t
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger> &GettQHatInvModqBDivqModt() const {
    return m_tQHatInvModqBDivqModt;
  }

  /**
   * When log2(q_i) >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
   * Gets the NTL precomputations for [\floor{t*{Q/q_i}^{-1}*B/q_i}]_t
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger> &GettQHatInvModqBDivqModtPrecon() const {
    return m_tQHatInvModqBDivqModtPrecon;
  }

  const NativeInteger &GetScalingFactorInt(usint l) const {
    if (m_rsTechnique == FLEXIBLEAUTO) {
      return m_scalingFactorsInt[l];
    }
    return m_fixedSF;
  }

  const NativeInteger &GetScalingFactorIntBig(usint l) const { return m_scalingFactorsIntBig[l]; }

  const NativeInteger &GetModReduceFactorInt(uint32_t l = 0) const {
    if (m_rsTechnique == FLEXIBLEAUTO) {
      return m_qModt[l];
    }
    return m_fixedSF;
  }

  /////////////////////////////////////
  // BFVrns : Encrypt
  /////////////////////////////////////

  /**
   * Gets the precomputed table of [\floor{Q/t}]_{q_i}
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger> &GetQDivtModq() const { return m_QDivtModq; }

  /////////////////////////////////////
  // BFVrnsB
  /////////////////////////////////////

  /**
   * Gets the Auxiliary CRT basis {Bsk} = {B U msk}
   * used in homomorphic multiplication
   *
   * @return the precomputed CRT params
   */
  const shared_ptr<ILDCRTParams<BigInteger>> GetParamsBsk() const {
    return m_paramsBsk;
  }

  /**
   * Gets the precomputed table of q_i
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GetModuliQ() const { return m_moduliQ; }

  /**
   * Gets the precomputed table of bsk_j
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GetModuliBsk() const { return m_moduliBsk; }

  /**
   * Gets the Barrett modulo reduction precomputation for bsk_j
   *
   * @return the precomputed table
   */
  std::vector<DoubleNativeInt> const &GetModbskBarrettMu() const {
    return m_modbskBarrettMu;
  }

  /**
   * Gets the precomputed table of [mtilde*(Q/q_i)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GetmtildeQHatInvModq() const {
    return m_mtildeQHatInvModq;
  }

  /**
   * Gets the NTL precomputations for [mtilde*(Q/q_i)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GetmtildeQHatInvModqPrecon() const {
    return m_mtildeQHatInvModqPrecon;
  }

  /**
   * Gets the precomputed table of [Q/q_i]_{bsk_j}
   *
   * @return the precomputed table
   */
  std::vector<std::vector<NativeInteger>> const &GetQHatModbsk() const {
    return m_QHatModbsk;
  }

  /**
   * Gets the precomputed table of [(q_i)^{-1}]_{bsk_j}
   *
   * @return the precomputed table
   */
  std::vector<std::vector<NativeInteger>> const &GetqInvModbsk() const {
    return m_qInvModbsk;
  }

  /**
   * Gets the precomputed table of [Q/q_i]_{mtilde}
   *
   * @return the precomputed table
   */
  std::vector<uint16_t> const &GetQHatModmtilde() const {
    return m_QHatModmtilde;
  }

  /**
   * Gets the precomputed table of [Q]_{bsk_j}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GetQModbsk() const { return m_QModbsk; }

  /**
   * Gets the NTL precomputations for [Q]_{bsk_j}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GetQModbskPrecon() const {
    return m_QModbskPrecon;
  }

  /**
   * Gets the precomputed [-Q^{-1}]_{mtilde}
   *
   * @return the precomputed value
   */
  uint16_t const &GetNegQInvModmtilde() const { return m_negQInvModmtilde; }

  /**
   * Gets the precomputed table of [mtilde^{-1}]_{bsk_j}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GetmtildeInvModbsk() const {
    return m_mtildeInvModbsk;
  }

  /**
   * Gets the NTL precomputations for [mtilde^{-1}]_{bsk_j}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GetmtildeInvModbskPrecon() const {
    return m_mtildeInvModbskPrecon;
  }

  /**
   * Gets the precomputed table of [t*(Q/q_i)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GettQHatInvModq() const {
    return m_tQHatInvModq;
  }

  /**
   * Gets the NTL precomputations for [t*(Q/q_i)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GettQHatInvModqPrecon() const {
    return m_tQHatInvModqPrecon;
  }

  /**
   * Gets the precomputed table of [t*gamma*(Q/q_i)^(-1)]_{q_i}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GettgammaQHatInvModq() const {
    return m_tgammaQHatInvModq;
  }

  /**
   * Gets the NTL precomputations for [t*gamma*(Q/q_i)^(-1)]_{q_i}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GettgammaQHatInvModqPrecon() const {
    return m_tgammaQHatInvModqPrecon;
  }

  /**
   * Gets the precomputed table of [t/Q]_{bsk_j}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GettQInvModbsk() const {
    return m_tQInvModbsk;
  }

  /**
   * Gets the NTL precomputations for [t/Q]_{bsk_j}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GettQInvModbskPrecon() const {
    return m_tQInvModbskPrecon;
  }

  /**
   * Gets the precomputed table of [(B/b_j)^{-1}]_{b_j}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GetBHatInvModb() const {
    return m_BHatInvModb;
  }

  /**
   * Gets the NTL precomputations for [(B/b_j)^{-1}]_{b_j}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GetBHatInvModbPrecon() const {
    return m_BHatInvModbPrecon;
  }

  /**
   * Gets the precomputed table of [B/b_j]_{msk}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GetBHatModmsk() const {
    return m_BHatModmsk;
  }

  /**
   * Gets the precomputed [B^{-1}]_msk
   *
   * @return the precomputed value
   */
  NativeInteger const &GetBInvModmsk() const { return m_BInvModmsk; }

  /**
   * Gets the NTL precomputions for [B^{-1}]_msk
   *
   * @return the precomputed value
   */
  NativeInteger const &GetBInvModmskPrecon() const {
    return m_BInvModmskPrecon;
  }

  /**
   * Gets the precomputed table of [B/b_j]_{q_i}
   *
   * @return the precomputed table
   */
  std::vector<std::vector<NativeInteger>> const &GetBHatModq() const {
    return m_BHatModq;
  }

  /**
   * Gets the precomputed table of [B]_{q_i}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GetBModq() const { return m_BModq; }

  /**
   * Gets the NTL precomputions for [B]_{q_i}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GetBModqPrecon() const {
    return m_BModqPrecon;
  }

  /**
   * Gets auxiliary modulus gamma
   *
   * @return gamma
   */
  uint32_t const &Getgamma() const { return m_gamma; }

  // TODO: use 64 bit words in case NativeInteger uses smaller word size
  /**
   * Gets t*gamma where t - plaintext modulus, gamma - auxiliary modulus
   *
   * @return t*gamma
   */
  NativeInteger const &Gettgamma() const { return m_tgamma; }

  /**
   * Gets the precomputed table of [-(q_i)^{-1}]_{t*gamma}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GetNegInvqModtgamma() const {
    return m_negInvqModtgamma;
  }

  /**
   * Gets the NTL precomputions for [-(q_i)^{-1}]_{t*gamma}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GetNegInvqModtgammaPrecon() const {
    return m_negInvqModtgammaPrecon;
  }

 protected:
  /////////////////////////////////////
  // PrecomputeCRTTables
  /////////////////////////////////////

  // Stores the technique to use for key switching
  enum KeySwitchTechnique m_ksTechnique;

  enum RescalingTechnique m_rsTechnique;

  enum EncryptionTechnique m_encTechnique;

  enum MultiplicationTechnique m_multTechnique;

  uint32_t m_auxBits = 0;

  uint32_t m_extraBits = 0;

  /////////////////////////////////////
  // BGVrns ModReduce
  /////////////////////////////////////

  // Stores NTL precomputations for [t]_{q_i}
  vector<NativeInteger> m_tModqPrecon;

  // Stores [-t^{-1}]_{q_i}
  vector<NativeInteger> m_negtInvModq;

  // Stores NTL precomputations for [-t^{-1}]_{q_i}
  vector<NativeInteger> m_negtInvModqPrecon;

  /////////////////////////////////////
  // CKKSrns/BFVrns DropLastElementAndScale
  /////////////////////////////////////

  // Q^(l) = \prod_{j=0}^{l-1}
  // Stores [Q^(l)*[Q^(l)^{-1}]_{q_l}/q_l]_{q_i}
  std::vector<std::vector<NativeInteger>> m_QlQlInvModqlDivqlModq;

  // Q^(l) = \prod_{j=0}^{l-1}
  // Stores NTL precomputations for [Q^(l)*[Q^(l)^{-1}]_{q_l}/q_l]_{q_i}
  std::vector<std::vector<NativeInteger>> m_QlQlInvModqlDivqlModqPrecon;

  // Stores [q_l^{-1}]_{q_i}
  vector<vector<NativeInteger>> m_qlInvModq;

  // Stores NTL precomputations for [q_l^{-1}]_{q_i}
  vector<vector<NativeInteger>> m_qlInvModqPrecon;

  /////////////////////////////////////
  // KeySwitchHybrid KeyGen
  /////////////////////////////////////

  // Params for Extended CRT basis {QP} = {q_1...q_l,p_1,...,p_k}
  // used in GHS key switching
  shared_ptr<ILDCRTParams<BigInteger>> m_paramsQP;

  // Stores the partition size {PartQ} = {Q_1,...,Q_l}
  // where each Q_i is the product of q_j
  uint32_t m_numPartQ = 0;

  // Stores [P]_{q_i}, used in GHS key switching
  vector<NativeInteger> m_PModq;

  // Stores [Q/Q_j]_{q_i} for HYBRID
  vector<vector<NativeInteger>> m_PartQHatModq;

  /////////////////////////////////////
  // KeySwitchHybrid KeySwitch
  /////////////////////////////////////

  // Params for Auxiliary CRT basis {P} = {p_1,...,p_k}
  // used in GHS key switching
  shared_ptr<ILDCRTParams<BigInteger>> m_paramsP;

  // Stores the number of towers per Q_i
  uint32_t m_numPerPartQ = 0;

  // Stores the parameters for moduli Q_i
  vector<shared_ptr<ILDCRTParams<BigInteger>>> m_paramsPartQ;

  // Stores [{Q/Q_j}^{-1}]_{q_i} for HYBRID
  vector<vector<NativeInteger>> m_PartQHatInvModq;

  // Stores the parameters for complementary {\bar{Q_i},P}
  vector<vector<shared_ptr<ILDCRTParams<BigInteger>>>> m_paramsComplPartQ;

  // Stores [{(Q_k)^(l)/q_i}^{-1}]_{q_i} for HYBRID
  vector<vector<vector<NativeInteger>>> m_PartQlHatInvModq;

  // Stores NTL precomputations for
  // [{(Q_k)^(l)/q_i}^{-1}]_{q_i} for HYBRID
  vector<vector<vector<NativeInteger>>> m_PartQlHatInvModqPrecon;

  // Stores [QHat_i]_{p_j}
  vector<vector<vector<vector<NativeInteger>>>> m_PartQlHatModp;

  // Stores the Barrett mu for CompQBar_i
  vector<vector<vector<DoubleNativeInt>>> m_modComplPartqBarrettMu;

  // Stores [P^{-1}]_{q_i}, required for GHS key switching
  vector<NativeInteger> m_PInvModq;

  // Stores NTL precomputations for [P^{-1}]_{q_i}
  vector<NativeInteger> m_PInvModqPrecon;

  // Stores [(P/p_j)^{-1}]_{p_j}, required for GHS key switching
  vector<NativeInteger> m_PHatInvModp;

  // Stores NTL precomputations for [(P/p_j)^{-1}]_{p_j}
  vector<NativeInteger> m_PHatInvModpPrecon;

  // Stores [P/p_j]_{q_i}, required for GHS key switching
  vector<vector<NativeInteger>> m_PHatModq;

  // Stores the BarrettUint128ModUint64 precomputations for q_j
  vector<DoubleNativeInt> m_modqBarrettMu;

  // Stores [t^{-1}]_{p_j}
  vector<NativeInteger> m_tInvModp;

  // Stores NTL precomputations for [t^{-1}]_{p_j}
  vector<NativeInteger> m_tInvModpPrecon;

  /////////////////////////////////////
  // CKKS Scaling Factor
  /////////////////////////////////////

  // A vector holding the doubles that correspond to the exact
  // scaling factor of each level, when FLEXIBLEAUTO is used.
  vector<double> m_scalingFactorsReal;

  vector<double> m_scalingFactorsRealBig;

  // Stores q_i as doubles
  vector<double> m_dmoduliQ;

  // Stores 2^ptm where ptm - plaintext modulus
  double m_approxSF = 0;

  /////////////////////////////////////
  // BFVrns : Encrypt
  /////////////////////////////////////

  // Stores [\floor{Q/t}]_{q_i}
  std::vector<NativeInteger> m_QDivtModq;

  vector<NativeInteger> m_scalingFactorsInt;

  vector<NativeInteger> m_scalingFactorsIntBig;

  vector<NativeInteger> m_qModt;

  NativeInteger m_fixedSF = NativeInteger(1);

  /////////////////////////////////////
  // BFVrns : Encrypt
  /////////////////////////////////////

  NativeInteger m_negQModt;
  NativeInteger m_negQModtPrecon;
  vector<NativeInteger> m_tInvModq;
  vector<NativeInteger> m_tInvModqPrecon;

  /////////////////////////////////////
  // BFVrns : Encrypt
  /////////////////////////////////////

  shared_ptr<ILDCRTParams<BigInteger>> m_paramsQr;
  NativeInteger m_negQrModt;
  NativeInteger m_negQrModtPrecon;
  std::vector<NativeInteger> m_rInvModq;
  std::vector<NativeInteger> m_rInvModqPrecon;

  /////////////////////////////////////
  // BFVrns : Decrypt : ScaleAndRound
  /////////////////////////////////////

  // Stores \frac{t*{Q/q_i}^{-1}/q_i}
  std::vector<double> m_tQHatInvModqDivqFrac;

  // when log2(q_i) >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
  // Stores \frac{t*{Q/q_i}^{-1}*B/q_i}
  std::vector<double> m_tQHatInvModqBDivqFrac;

  // Stores [\floor{t*{Q/q_i}^{-1}/q_i}]_t
  std::vector<NativeInteger> m_tQHatInvModqDivqModt;

  // Stores NTL precomputations for [\floor{t*{Q/q_i}^{-1}/q_i}]_t
  std::vector<NativeInteger> m_tQHatInvModqDivqModtPrecon;

  // when log2(q_i) >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
  // Stores [\floor{t*{Q/q_i}^{-1}*B/q_i}]_t
  std::vector<NativeInteger> m_tQHatInvModqBDivqModt;

  // when log2 q_i >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
  // Stores NTL precomputations for [\floor{t*{Q/q_i}^{-1}*B/q_i}]_t
  std::vector<NativeInteger> m_tQHatInvModqBDivqModtPrecon;

  /////////////////////////////////////
  // BFVrns : Mult : ExpandCRTBasis
  /////////////////////////////////////

  // Auxiliary CRT basis {Ql} = {q_i}
  // used in homomorphic multiplication
  std::vector<shared_ptr<ILDCRTParams<BigInteger>>> m_paramsQl;

  // Auxiliary CRT basis {Rl} = {r_k}
  // used in homomorphic multiplication
  std::vector<shared_ptr<ILDCRTParams<BigInteger>>> m_paramsRl;

  // Auxiliary expanded CRT basis Ql*Rl = {s_m}
  // used in homomorphic multiplication
  std::vector<shared_ptr<ILDCRTParams<BigInteger>>> m_paramsQlRl;

  // Stores [(Ql/q_i)^{-1}]_{q_i}
  std::vector<std::vector<NativeInteger>> m_QlHatInvModq;

  // Stores NTL precomputations for [(Ql/q_i)^{-1}]_{q_i}
  std::vector<std::vector<NativeInteger>> m_QlHatInvModqPrecon;

  // Stores [Q/q_i]_{r_k}
  std::vector<std::vector<std::vector<NativeInteger>>> m_QlHatModr;

  // Stores [\alpha*Ql]_{r_k} for 0 <= alpha <= sizeQl
  std::vector<std::vector<std::vector<NativeInteger>>> m_alphaQlModr;

  // Barrett modulo reduction precomputation for r_k
  std::vector<DoubleNativeInt> m_modrBarrettMu;

  // Stores \frac{1/q_i}
  std::vector<double> m_qInv;

  /////////////////////////////////////
  // BFVrns : Mult : ScaleAndRound
  /////////////////////////////////////

  // S = QR
  // Stores \frac{[t*R*(S/s_m)^{-1}]_{s_m}/s_m}
  std::vector<double> m_tRSHatInvModsDivsFrac;

  // S = QR
  // Stores [\floor{t*R*(S/s_m)^{-1}/s_m}]_{r_k}
  std::vector<std::vector<NativeInteger>> m_tRSHatInvModsDivsModr;

  /////////////////////////////////////
  // BFVrns : Mult : SwitchCRTBasis
  /////////////////////////////////////

  // Stores [(Rl/r_k)^{-1}]_{r_k}
  std::vector<std::vector<NativeInteger>> m_RlHatInvModr;

  // Stores NTL precomputations for [(Rl/r_k)^{-1}]_{r_k}
  std::vector<std::vector<NativeInteger>> m_RlHatInvModrPrecon;

  // Stores [Rl/r_k]_{q_i}
  std::vector<std::vector<std::vector<NativeInteger>>> m_RlHatModq;

  // Stores [\alpha*Rl]_{q_i} for 0 <= alpha <= sizeR
  std::vector<std::vector<std::vector<NativeInteger>>> m_alphaRlModq;

  // Stores \frac{1/r_k}
  std::vector<double> m_rInv;

  /////////////////////////////////////
  // BFVrns : Mult : FastExpandCRTBasisPloverQ
  /////////////////////////////////////

  std::vector<vector<NativeInteger>> m_negRlQHatInvModq;

  std::vector<vector<NativeInteger>> m_negRlQHatInvModqPrecon;

  std::vector<std::vector<NativeInteger>> m_qInvModr;

  /////////////////////////////////////
  // BFVrns : Mult : ExpandCRTBasisQlHat
  /////////////////////////////////////

  std::vector<std::vector<NativeInteger>> m_QlHatModq;

  std::vector<std::vector<NativeInteger>> m_QlHatModqPrecon;

  /////////////////////////////////////
  // BFVrns : Mult : ScaleAndRoundP
  /////////////////////////////////////

  std::vector<std::vector<double>> m_tQlSlHatInvModsDivsFrac;

  std::vector<std::vector<std::vector<NativeInteger>>>
      m_tQlSlHatInvModsDivsModq;

  /////////////////////////////////////
  // BFVrnsB
  /////////////////////////////////////

  // Auxiliary CRT basis {Bsk} = {B U msk} = {{b_j} U msk}
  shared_ptr<ILDCRTParams<BigInteger>> m_paramsBsk;

  // number of moduli in the base {Q}
  uint32_t m_numq = 0;

  // number of moduli in the auxilliary base {B}
  uint32_t m_numb = 0;

  // mtilde = 2^16
  NativeInteger m_mtilde = NativeInteger((uint64_t)1 << 16);

  // Auxiliary modulus msk
  NativeInteger m_msk;

  // Stores q_i
  std::vector<NativeInteger> m_moduliQ;

  // Stores auxilliary base moduli b_j
  std::vector<NativeInteger> m_moduliB;

  // Stores the roots of unity modulo bsk_j
  std::vector<NativeInteger> m_rootsBsk;

  // Stores moduli {bsk_i} = {{b_j} U msk}
  std::vector<NativeInteger> m_moduliBsk;

  // Barrett modulo reduction precomputation for bsk_j
  std::vector<DoubleNativeInt> m_modbskBarrettMu;

  // Stores [mtilde*(Q/q_i)^{-1}]_{q_i}
  std::vector<NativeInteger> m_mtildeQHatInvModq;

  // Stores NTL precomputations for [mtilde*(Q/q_i)^{-1}]_{q_i}
  std::vector<NativeInteger> m_mtildeQHatInvModqPrecon;

  // Stores [Q/q_i]_{bsk_j}
  std::vector<std::vector<NativeInteger>> m_QHatModbsk;

  // Stores [(q_i)^{-1}]_{bsk_j}
  std::vector<std::vector<NativeInteger>> m_qInvModbsk;

  // Stores [Q/q_i]_{mtilde}
  std::vector<uint16_t> m_QHatModmtilde;

  // Stores [Q]_{bsk_j}
  std::vector<NativeInteger> m_QModbsk;
  // Stores NTL precomputations for [Q]_{bsk_j}
  std::vector<NativeInteger> m_QModbskPrecon;

  // Stores [-Q^{-1}]_{mtilde}
  uint16_t m_negQInvModmtilde = 0;

  // Stores [mtilde^{-1}]_{bsk_j}
  std::vector<NativeInteger> m_mtildeInvModbsk;
  // Stores NTL precomputations for [mtilde^{-1}]_{bsk_j}
  std::vector<NativeInteger> m_mtildeInvModbskPrecon;

  // Stores [t*(Q/q_i)^{-1}]_{q_i}
  std::vector<NativeInteger> m_tQHatInvModq;

  // Stores NTL precomputations for [t*(Q/q_i)^{-1}]_{q_i}
  std::vector<NativeInteger> m_tQHatInvModqPrecon;

  // Stores [t*gamma*(Q/q_i)^(-1)]_{q_i}
  std::vector<NativeInteger> m_tgammaQHatInvModq;
  // Stores NTL precomputations for [t*gamma*(Q/q_i)^(-1)]_{q_i}
  std::vector<NativeInteger> m_tgammaQHatInvModqPrecon;

  // Stores [t/Q]_{bsk_j}
  std::vector<NativeInteger> m_tQInvModbsk;
  // Stores NTL precomputations for [t/Q]_{bsk_j}
  std::vector<NativeInteger> m_tQInvModbskPrecon;

  // Stores [(B/b_j)^{-1}]_{b_j}
  std::vector<NativeInteger> m_BHatInvModb;

  // Stores NTL precomputations for [(B/b_j)^{-1}]_{b_j}
  std::vector<NativeInteger> m_BHatInvModbPrecon;

  // stores [B/b_j]_{msk}
  std::vector<NativeInteger> m_BHatModmsk;

  // Stores [B^{-1}]_msk
  NativeInteger m_BInvModmsk;
  // Stores NTL precomputations for [B^{-1}]_msk
  NativeInteger m_BInvModmskPrecon;

  // Stores [B/b_j]_{q_i}
  std::vector<std::vector<NativeInteger>> m_BHatModq;

  // Stores [B]_{q_i}
  std::vector<NativeInteger> m_BModq;
  // Stores NTL precomputations for [B]_{q_i}
  std::vector<NativeInteger> m_BModqPrecon;

  // Stores gamma = 2^26;
  uint32_t m_gamma = 1 << 26;

  // TODO: use 64 bit words in case NativeInteger uses smaller word size
  // Stores t*gamma on a uint64_t word
  NativeInteger m_tgamma;

  // Stores [-(q_i)^{-1}]_{t*gamma}
  std::vector<NativeInteger> m_negInvqModtgamma;
  // Stores NTL precomputations for [-(q_i)^{-1}]_{t*gamma}
  std::vector<NativeInteger> m_negInvqModtgammaPrecon;

 public:
  /////////////////////////////////////
  // SERIALIZATION
  /////////////////////////////////////

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(cereal::base_class<CryptoParametersRLWE<DCRTPoly>>(this));
    ar(cereal::make_nvp("ks", m_ksTechnique));
    ar(cereal::make_nvp("rs", m_rsTechnique));
    ar(cereal::make_nvp("encs", m_encTechnique));
    ar(cereal::make_nvp("muls", m_multTechnique));
    ar(cereal::make_nvp("dnum", m_numPartQ));
    ar(cereal::make_nvp("ab", m_auxBits));
    ar(cereal::make_nvp("eb", m_extraBits));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(cereal::base_class<CryptoParametersRLWE<DCRTPoly>>(this));
    ar(cereal::make_nvp("ks", m_ksTechnique));
    ar(cereal::make_nvp("rs", m_rsTechnique));
    ar(cereal::make_nvp("encs", m_encTechnique));
    ar(cereal::make_nvp("muls", m_multTechnique));
    ar(cereal::make_nvp("dnum", m_numPartQ));
    ar(cereal::make_nvp("ab", m_auxBits));
    ar(cereal::make_nvp("eb", m_extraBits));

    PrecomputeCRTTables(m_ksTechnique, m_rsTechnique, m_encTechnique, m_multTechnique,
                        m_numPartQ, m_auxBits, m_extraBits);
  }

  virtual std::string SerializedObjectName() const override { return "SchemeParametersRNS"; }
  static uint32_t SerializedVersion() { return 1; }
};

}  // namespace lbcrypto

#endif
