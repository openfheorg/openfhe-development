// @file bfvrnsB.h -- Operations for the BEHZ variant of BFV.
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
 *
 * This code implements the BEHZ variant of the Brakerski-Fan-Vercauteren (BFV)
 *homomorphic encryption scheme.  This scheme is also referred to as the FV
 *scheme.
 *
 * The BFV scheme is introduced in the following papers:
 *   - Zvika Brakerski (2012). Fully Homomorphic Encryption without Modulus
 *Switching from Classical GapSVP. Cryptology ePrint Archive, Report 2012/078.
 *(https://eprint.iacr.org/2012/078)
 *   - Junfeng Fan and Frederik Vercauteren (2012). Somewhat Practical Fully
 *Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144.
 *(https://eprint.iacr.org/2012/144.pdf)
 *
 * Our implementation builds from the designs here:
 *   - Jean-Claude Bajard and Julien Eynard and Anwar Hasan and Vincent
 *Zucca (2016). A Full RNS Variant of FV like Somewhat Homomorphic Encryption
 *Schemes. Cryptology ePrint Archive, Report 2016/510.
 *(https://eprint.iacr.org/2016/510)
 *   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption
 *Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in
 *Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer
 *Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
 *   - Ahmad Al Badawi and Yuriy Polyakov and Khin Mi Mi Aung and Bharadwaj
 *Veeravalli and Kurt Rohloff (2018). Implementation and Performance Evaluation
 *of RNS Variants of the BFV Homomorphic Encryption Scheme. Cryptology ePrint
 *Archive, Report 2018/589. {https://eprint.iacr.org/2018/589}
 *
 */

#ifndef LBCRYPTO_CRYPTO_BFVRNS_B_H
#define LBCRYPTO_CRYPTO_BFVRNS_B_H

#include <memory>
#include <string>
#include <vector>

#include "palisade.h"

namespace lbcrypto {

/**
 * @brief This is the parameters class for the BFVrnsB encryption scheme. This
 * scheme is also referred to as the FVrns scheme.
 *
 * @tparam Element a ring element type.
 */
template <class Element>
class LPCryptoParametersBFVrnsB : public LPCryptoParametersRLWE<Element> {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;
  using DugType = typename Element::DugType;
  using DggType = typename Element::DggType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor.
   */
  LPCryptoParametersBFVrnsB();

  /**
   * Copy constructor.
   * @param rhs - source
   */
  LPCryptoParametersBFVrnsB(const LPCryptoParametersBFVrnsB &rhs);
  /**
   * Constructor that initializes values.  Note that it is possible to set
   * parameters in a way that is overall infeasible for actual use.  There are
   * fewer degrees of freedom than parameters provided.  Typically one chooses
   * the basic noise, assurance and security parameters as the typical
   * community-accepted values, then chooses the plaintext modulus and depth
   * as needed.  The element parameters should then be choosen to provide
   * correctness and security.  In some cases we would need to operate over
   * already encrypted/provided ciphertext and the depth needs to be
   * pre-computed for initial settings.
   *
   * @param &params Element parameters.  This will depend on the specific
   * class of element being used.
   * @param &plaintextModulus Plaintext modulus, typically denoted as p in
   * most publications.
   * @param distributionParameter Noise distribution parameter, typically
   * denoted as /sigma in most publications.  Community standards typically
   * call for a value of 3 to 6. Lower values provide more room for
   * computation while larger values provide more security.
   * @param assuranceMeasure Assurance level, typically denoted as w in most
   * applications.  This is oftern perceived as a fudge factor in the
   * literature, with a typical value of 9.
   * @param securityLevel Security level as Root Hermite Factor.  We use the
   * Root Hermite Factor representation of the security level to better
   * conform with US ITAR and EAR export regulations.  This is typically
   * represented as /delta in the literature.  Typically a Root Hermite Factor
   * of 1.006 or less provides reasonable security for RLWE crypto schemes.
   * @param relinWindow The size of the relinearization window.  This is
   * relevant when using this scheme for proxy re-encryption, and the value is
   * denoted as r in the literature.
   * @param mode optimization setting (RLWE vs OPTIMIZED)
   * @param depth is the depth of computation circuit supported for these
   * parameters (not used now; for future use).
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   */
  LPCryptoParametersBFVrnsB(shared_ptr<typename Element::Params> params,
                            const PlaintextModulus &plaintextModulus,
                            float distributionParameter, float assuranceMeasure,
                            float securityLevel, usint relinWindow,
                            MODE mode = RLWE, int depth = 1, int maxDepth = 2);

  /**
   * Constructor that initializes values.
   *
   * @param params element parameters.
   * @param encodingParams plaintext space parameters.
   * @param distributionParameter noise distribution parameter.
   * @param assuranceMeasure assurance level. = BigInteger::ZERO
   * @param securityLevel security level (root Hermite factor).
   * @param relinWindow the size of the relinearization window.
   * @param mode optimization setting (RLWE vs OPTIMIZED)
   * @param depth is the depth of computation circuit supported for these
   * parameters (not used now; for future use).
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   */
  LPCryptoParametersBFVrnsB(shared_ptr<typename Element::Params> params,
                            EncodingParams encodingParams,
                            float distributionParameter, float assuranceMeasure,
                            float securityLevel, usint relinWindow,
                            MODE mode = RLWE, int depth = 1, int maxDepth = 2);

  /**
   * Constructor that initializes values.
   *
   * @param params element parameters.
   * @param encodingParams plaintext space parameters.
   * @param distributionParameter noise distribution parameter.
   * @param assuranceMeasure assurance level. = BigInteger::ZERO
   * @param securityLevel standard security level
   * @param relinWindow the size of the relinearization window.
   * @param mode optimization setting (RLWE vs OPTIMIZED)
   * @param depth is the depth of computation circuit supported for these
   * parameters (not used now; for future use).
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   */
  LPCryptoParametersBFVrnsB(shared_ptr<typename Element::Params> params,
                            EncodingParams encodingParams,
                            float distributionParameter, float assuranceMeasure,
                            SecurityLevel securityLevel, usint relinWindow,
                            MODE mode = RLWE, int depth = 1, int maxDepth = 2);

  /**
   * Destructor
   */
  virtual ~LPCryptoParametersBFVrnsB() {}

  /**
   * Computes all tables needed for decryption, homomorphic multiplication,
   * and key switching
   * @return true on success
   */
  bool PrecomputeCRTTables();

  /**
   * == operator to compare to this instance of LPCryptoParametersBFVrnsB
   * object.
   *
   * @param &rhs LPCryptoParameters to check equality against.
   */
  bool operator==(const LPCryptoParameters<Element> &rhs) const {
    const auto *el =
        dynamic_cast<const LPCryptoParametersBFVrnsB<Element> *>(&rhs);

    if (el == nullptr) return false;

    return LPCryptoParametersRLWE<Element>::operator==(rhs);
  }

  void PrintParameters(std::ostream &os) const {
    LPCryptoParametersRLWE<Element>::PrintParameters(os);
  }

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
   * Gets the Barrett modulo reduction precomputation for q_i
   *
   * @return the precomputed table
   */
  std::vector<DoubleNativeInt> const &GetModqBarrettMu() const {
    return m_modqBarrettMu;
  }

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
   * Gets the precomputed table of [\floor{Q/t}]_{q_i}
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger> &GetDelta() const { return m_QDivtModq; }

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
   * Gets the precomputed table of [(Q/q_i)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
  std::vector<NativeInteger> const &GetQHatInvModq() const {
    return m_QHatInvModq;
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

  // NOTE that we do not serialize any of the members declared in this class.
  // they are all cached computations, and get recomputed in any
  // implementation that does a deserialization
  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::base_class<LPCryptoParametersRLWE<Element>>(this));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::base_class<LPCryptoParametersRLWE<Element>>(this));
  }

  std::string SerializedObjectName() const { return "BFVrnsBSchemeParameters"; }
  static uint32_t SerializedVersion() { return 1; }

 private:
  // Stores a precomputed table of [\floor{Q/t}]_{q_i}
  std::vector<NativeInteger> m_QDivtModq;

  // Auxiliary CRT basis {Bsk} = {B U msk} = {{b_j} U msk}
  shared_ptr<ILDCRTParams<BigInteger>> m_paramsBsk;

  // number of moduli in the base {Q}
  uint32_t m_numq;

  // number of moduli in the auxilliary base {B}
  uint32_t m_numb;

  // mtilde = 2^16
  NativeInteger m_mtilde = NativeInteger((uint64_t)1 << 16);

  // Auxiliary modulus msk
  NativeInteger m_msk;

  // Stores q_i
  std::vector<NativeInteger> m_moduliQ;

  // Barrett modulo reduction precomputation for q_i
  std::vector<DoubleNativeInt> m_modqBarrettMu;

  // Stores auxilliary base moduli b_j
  std::vector<NativeInteger> m_moduliB;

  // Stores the roots of unity modulo bsk_j
  std::vector<NativeInteger> m_rootsBsk;

  // Stores moduli {bsk_i} = {{b_j} U msk}
  std::vector<NativeInteger> m_moduliBsk;

  // Barrett modulo reduction precomputation for bsk_j
  std::vector<DoubleNativeInt> m_modbskBarrettMu;

  // Stores [(Q/q_i)^{-1}]_{q_i}
  std::vector<NativeInteger> m_QHatInvModq;

  // Stores [t*(Q/q_i)^{-1}]_{q_i}
  std::vector<NativeInteger> m_tQHatInvModq;

  // Stores NTL precomputations for [t*(Q/q_i)^{-1}]_{q_i}
  std::vector<NativeInteger> m_tQHatInvModqPrecon;

  // Stores [Q/q_i]_{bsk_j}
  std::vector<std::vector<NativeInteger>> m_QHatModbsk;

  // Stores [(q_i)^{-1}]_{bsk_j}
  std::vector<std::vector<NativeInteger>> m_qInvModbsk;

  // Stores [Q/q_i]_{mtilde}
  std::vector<uint16_t> m_QHatModmtilde;

  // Stores [mtilde*(Q/q_i)^{-1}]_{q_i}
  std::vector<NativeInteger> m_mtildeQHatInvModq;

  // Stores NTL precomputations for [mtilde*(Q/q_i)^{-1}]_{q_i}
  std::vector<NativeInteger> m_mtildeQHatInvModqPrecon;

  // Stores [-Q^{-1}]_{mtilde}
  uint16_t m_negQInvModmtilde;

  // Stores [Q]_{bsk_j}
  std::vector<NativeInteger> m_QModbsk;
  // Stores NTL precomputations for [Q]_{bsk_j}
  std::vector<NativeInteger> m_QModbskPrecon;

  // Stores [mtilde^{-1}]_{bsk_j}
  std::vector<NativeInteger> m_mtildeInvModbsk;
  // Stores NTL precomputations for [mtilde^{-1}]_{bsk_j}
  std::vector<NativeInteger> m_mtildeInvModbskPrecon;

  // Stores [t/Q]_{bsk_j}
  std::vector<NativeInteger> m_tQInvModbsk;
  // Stores NTL precomputations for [t/Q]_{bsk_j}
  std::vector<NativeInteger> m_tQInvModbskPrecon;

  // Stores [(B/b_j)^{-1}]_{b_j}
  std::vector<NativeInteger> m_BHatInvModb;
  // Stores NTL precomputations for [(B/b_j)^{-1}]_{b_j}
  std::vector<NativeInteger> m_BHatInvModbPrecon;

  // Stores [B/b_j]_{q_i}
  std::vector<std::vector<NativeInteger>> m_BHatModq;

  // stores [B/b_j]_{msk}
  std::vector<NativeInteger> m_BHatModmsk;

  // Stores [B^{-1}]_msk
  NativeInteger m_BInvModmsk;
  // Stores NTL precomputations for [B^{-1}]_msk
  NativeInteger m_BInvModmskPrecon;

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

  // Stores [t*gamma*(Q/q_i)^(-1)]_{q_i}
  std::vector<NativeInteger> m_tgammaQHatInvModq;
  // Stores NTL precomputations for [t*gamma*(Q/q_i)^(-1)]_{q_i}
  std::vector<NativeInteger> m_tgammaQHatInvModqPrecon;
};

/**
 * @brief Parameter generation for BFVrnsB.  This scheme is also referred to
 * as the FV scheme.
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPAlgorithmParamsGenBFVrnsB : public LPAlgorithmParamsGenBFV<Element> {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;
  using DugType = typename Element::DugType;
  using DggType = typename Element::DggType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmParamsGenBFVrnsB() {}

  /**
   * Method for computing all derived parameters based on chosen primitive
   * parameters
   *
   * @param cryptoParams the crypto parameters object to be populated with
   * parameters.
   * @param evalAddCount number of EvalAdds assuming no EvalMult and KeySwitch
   * operations are performed.
   * @param evalMultCount number of EvalMults assuming no EvalAdd and
   * KeySwitch operations are performed.
   * @param keySwitchCount number of KeySwitch operations assuming no EvalAdd
   * and EvalMult operations are performed.
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   */
  bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams,
                 int32_t evalAddCount = 0, int32_t evalMultCount = 0,
                 int32_t keySwitchCount = 0, size_t dcrBits = 60,
                 uint32_t n = 0) const override;
};

/**
 * @brief Encryption algorithm implementation for BFVrnsB for the basic public
 * key encrypt, decrypt and key generation methods for the BFVrnsB encryption
 * scheme.
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPAlgorithmBFVrnsB : public LPAlgorithmBFV<Element> {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;
  using DugType = typename Element::DugType;
  using DggType = typename Element::DggType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmBFVrnsB() {}

  /**
   * Method for encrypting plaintext using BFVrnsB.
   *
   * @param publicKey public key used for encryption.
   * @param plaintext the plaintext input.
   * @return ciphertext which results from encryption.
   */
  Ciphertext<Element> Encrypt(const LPPublicKey<Element> publicKey,
                              Element plaintext) const override;

  /**
   * Method for encrypting plaintext with private key using BFVrnsB.
   *
   * @param privateKey private key used for encryption.
   * @param plaintext the plaintext input.
   * @return ciphertext which results from encryption.
   */
  Ciphertext<Element> Encrypt(const LPPrivateKey<Element> privateKey,
                              Element plaintext) const override;

  /**
   * Method for decrypting using BFVrnsB. See the class description for
   * citations on where the algorithms were taken from.
   *
   * @param privateKey private key used for decryption.
   * @param ciphertext ciphertext to be decrypted.
   * @param *plaintext the plaintext output.
   * @return the decrypted plaintext returned.
   */
  DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
                        ConstCiphertext<Element> ciphertext,
                        NativePoly *plaintext) const override;
};

/**
 * @brief SHE algorithms implementation for BFVrnsB.
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPAlgorithmSHEBFVrnsB : public LPAlgorithmSHEBFV<Element> {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;
  using DugType = typename Element::DugType;
  using DggType = typename Element::DggType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmSHEBFVrnsB() {}

  /**
   * Function for homomorphic addition of ciphertext and plaintext.
   *
   * @param ct input ciphertext.
   * @param pt input plaintext.
   * @return new ciphertext.
   */
  Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ct,
                              ConstPlaintext pt) const override;

  /**
   * Function for homomorphic subtraction of ciphertext ans plaintext.
   *
   * @param ct input ciphertext.
   * @param pt input plaintext.
   * @return new ciphertext.
   */
  Ciphertext<Element> EvalSub(ConstCiphertext<Element> ct,
                              ConstPlaintext pt) const override;

  /**
   * Function for homomorphic evaluation of ciphertexts.
   * The multiplication is supported for a fixed level without keyswitching
   * requirement (default level=2). If the total depth of the ciphertexts
   * exceeds the supported level, it throws an error.
   *
   * @param ct1 first input ciphertext.
   * @param ct2 second input ciphertext.
   * @return resulting EvalMult ciphertext.
   */
  Ciphertext<Element> EvalMult(ConstCiphertext<Element> ct1,
                               ConstCiphertext<Element> ct2) const override;

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
   * Method for in-place key switching based on a KeySwitchHint using RLWE
   * relinearization
   *
   * @param keySwitchHint Hint required to perform the ciphertext switching.
   * @param &cipherText Original ciphertext to perform in-place key switching
   * on.
   */
  void KeySwitchInPlace(const LPEvalKey<Element> keySwitchHint,
                        Ciphertext<Element>& ciphertext) const override;

  /**
   * Function for evaluating multiplication on ciphertext followed by
   * relinearization operation. Currently it assumes that the input arguments
   * have total depth smaller than the supported depth. Otherwise, it throws
   * an error.
   *
   * @param ct1 first input ciphertext.
   * @param ct2 second input ciphertext.
   * @param &ek is the evaluation key to make the newCiphertext
   *  decryptable by the same secret key as that of ciphertext1 and
   * ciphertext2.
   * @return new ciphertext
   */
  Ciphertext<Element> EvalMultAndRelinearize(
      ConstCiphertext<Element> ct1, ConstCiphertext<Element> ct2,
      const vector<LPEvalKey<Element>> &ek) const override;
};

/**
 * @brief PRE algorithms implementation for BFVrnsB.
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPAlgorithmPREBFVrnsB : public LPAlgorithmPREBFV<Element> {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;
  using DugType = typename Element::DugType;
  using DggType = typename Element::DggType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmPREBFVrnsB() {}

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
  LPEvalKey<Element> ReKeyGen(
      const LPPublicKey<Element> newKey,
      const LPPrivateKey<Element> oldKey) const override;

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
   * @param ek the evaluation key.
   * @param ciphertext the input ciphertext.
   * @param publicKey the public key of the recipient of the re-encrypted
   * ciphertext.
   * @return resulting ciphertext after the re-encryption operation.
   */
  Ciphertext<Element> ReEncrypt(
      const LPEvalKey<Element> ek, ConstCiphertext<Element> ciphertext,
      const LPPublicKey<Element> publicKey = nullptr) const override;
};

/**
 * @brief Concrete class for the FHE Multiparty algorithms on BFVrnsB.    This
 * scheme is also referred to as the FV scheme.  A version of this multiparty
 * scheme built on the BGV scheme is seen here:
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
class LPAlgorithmMultipartyBFVrnsB : public LPAlgorithmMultipartyBFV<Element> {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;
  using DugType = typename Element::DugType;
  using DggType = typename Element::DggType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmMultipartyBFVrnsB() {}

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
      NativePoly *plaintext) const override;

  /**
   * Threshold FHE: Generates a joined evaluation key
   * from the current secret share and a prior joined
   * evaluation key
   *
   * @param oldKey secret key transformed from.
   * @param newKey secret key transformed to.
   * @param ek the prior joined evaluation key.
   * @return the new joined evaluation key.
   */
  LPEvalKey<Element> MultiKeySwitchGen(
      const LPPrivateKey<Element> oldKey, const LPPrivateKey<Element> newKey,
      const LPEvalKey<Element> ek) const override;

  template <class Archive>
  void save(Archive &ar) const {
    ar(cereal::base_class<LPAlgorithmMultipartyBFV<Element>>(this));
  }

  template <class Archive>
  void load(Archive &ar) {
    ar(cereal::base_class<LPAlgorithmMultipartyBFV<Element>>(this));
  }

  std::string SerializedObjectName() const { return "BFVrnsBMultiparty"; }
};

/**
 * @brief Main public key encryption scheme for BFVrnsB implementation,
 * @tparam Element a ring element.
 */
template <class Element>
class LPPublicKeyEncryptionSchemeBFVrnsB
    : public LPPublicKeyEncryptionScheme<Element> {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;
  using DugType = typename Element::DugType;
  using DggType = typename Element::DggType;
  using TugType = typename Element::TugType;

 public:
  LPPublicKeyEncryptionSchemeBFVrnsB();

  bool operator==(
      const LPPublicKeyEncryptionScheme<Element> &sch) const override {
    return dynamic_cast<const LPPublicKeyEncryptionSchemeBFVrnsB<Element> *>(
               &sch) != nullptr;
  }

  void Enable(PKESchemeFeature feature) override;

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::base_class<LPPublicKeyEncryptionScheme<Element>>(this));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    ar(::cereal::base_class<LPPublicKeyEncryptionScheme<Element>>(this));
  }

  std::string SerializedObjectName() const override { return "BFVrnsScheme"; }
};

}  // namespace lbcrypto

#endif
