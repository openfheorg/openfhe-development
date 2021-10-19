// @file bfvrns.h -- Operations for the HPS RNS variant of the BFV cryptoscheme.
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
 * This code implements a RNS variant of the Brakerski-Fan-Vercauteren (BFV)
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
 *   - Halevi S., Polyakov Y., and Shoup V. An Improved RNS Variant of the BFV
 *Homomorphic Encryption Scheme. Cryptology ePrint Archive, Report 2018/117.
 *(https://eprint.iacr.org/2018/117)
 *   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption
 *Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in
 *Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer
 *Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
 *   - Jean-Claude Bajard and Julien Eynard and Anwar Hasan and Vincent
 *Zucca (2016). A Full RNS Variant of FV like Somewhat Homomorphic Encryption
 *Schemes. Cryptology ePrint Archive, Report 2016/510.
 *(https://eprint.iacr.org/2016/510)
 *   - Ahmad Al Badawi and Yuriy Polyakov and Khin Mi Mi Aung and Bharadwaj
 *Veeravalli and Kurt Rohloff (2018). Implementation and Performance Evaluation
 *of RNS Variants of the BFV Homomorphic Encryption Scheme. Cryptology ePrint
 *Archive, Report 2018/589. {https://eprint.iacr.org/2018/589}
 */

#ifndef LBCRYPTO_CRYPTO_BFVRNS_H
#define LBCRYPTO_CRYPTO_BFVRNS_H

#include <memory>
#include <string>
#include <vector>

#include "palisade.h"

namespace lbcrypto {

/**
 * @brief This is the parameters class for the BFVrns encryption scheme.  This
 * scheme is also referred to as the FVrns scheme.
 *
 * @tparam Element a ring element type.
 */
template <class Element>
class LPCryptoParametersBFVrns : public LPCryptoParametersRLWE<Element> {
  using IntType = typename Element::Integer;
  using ParmType = typename Element::Params;
  using DggType = typename Element::DggType;
  using DugType = typename Element::DugType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor.
   */
  LPCryptoParametersBFVrns();

  /**
   * Copy constructor.
   * @param rhs - source
   */
  LPCryptoParametersBFVrns(const LPCryptoParametersBFVrns& rhs);
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
   * @param &params Element parameters.  This will depend on the specific class
   * of element being used.
   * @param &plaintextModulus Plaintext modulus, typically denoted as p in most
   * publications.
   * @param distributionParameter Noise distribution parameter, typically
   * denoted as /sigma in most publications.  Community standards typically call
   * for a value of 3 to 6. Lower values provide more room for computation while
   * larger values provide more security.
   * @param assuranceMeasure Assurance level, typically denoted as w in most
   * applications.  This is oftern perceived as a fudge factor in the
   * literature, with a typical value of 9.
   * @param securityLevel Security level as Root Hermite Factor.  We use the
   * Root Hermite Factor representation of the security level to better conform
   * with US ITAR and EAR export regulations.  This is typically represented as
   * /delta in the literature.  Typically a Root Hermite Factor of 1.006 or less
   * provides reasonable security for RLWE crypto schemes.
   * @param relinWindow The size of the relinearization window.  This is
   * relevant when using this scheme for proxy re-encryption, and the value is
   * denoted as r in the literature.
   * @param mode optimization setting (RLWE vs OPTIMIZED)
   * @param depth is the depth of computation circuit supported for these
   * parameters (not used now; for future use).
   * @param maxDepth is the maximum homomorphic multiplication depth before
   * performing relinearization
   */
  LPCryptoParametersBFVrns(shared_ptr<ParmType> params,
                           const PlaintextModulus& plaintextModulus,
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
   * @param maxDepth is the maximum homomorphic multiplication depth before
   * performing relinearization
   */
  LPCryptoParametersBFVrns(shared_ptr<ParmType> params,
                           EncodingParams encodingParams,
                           float distributionParameter, float assuranceMeasure,
                           float securityLevel, usint relinWindow,
                           MODE mode = RLWE, int depth = 1, int maxDepth = 2);

  /**
   * Constructor that initializes values.
   *
   * @param &params element parameters.
   * @param &encodingParams plaintext space parameters.
   * @param distributionParameter noise distribution parameter.
   * @param assuranceMeasure assurance level. = BigInteger::ZERO
   * @param securityLevel standard security level
   * @param relinWindow the size of the relinearization window.
   * @param mode optimization setting (RLWE vs OPTIMIZED)
   * @param depth is the depth of computation circuit supported for these
   * parameters (not used now; for future use).
   * @param maxDepth is the maximum homomorphic multiplication depth before
   * performing relinearization
   */
  LPCryptoParametersBFVrns(shared_ptr<ParmType> params,
                           EncodingParams encodingParams,
                           float distributionParameter, float assuranceMeasure,
                           SecurityLevel securityLevel, usint relinWindow,
                           MODE mode = RLWE, int depth = 1, int maxDepth = 2);

  /**
   * Destructor
   */
  virtual ~LPCryptoParametersBFVrns() {}

  /**
   * Computes all tables needed for decryption, homomorphic multiplication, and
   * key switching
   * @return true on success
   */
  bool PrecomputeCRTTables();

  /**
   * Gets the Auxiliary CRT basis {P} = {p_1,...,p_k}
   * used in homomorphic multiplication
   *
   * @return the precomputed CRT params
   */
  const shared_ptr<ILDCRTParams<BigInteger>> GetParamsP() const {
    return m_paramsP;
  }

  /**
   * Gets the Auxiliary expanded CRT basis {S} = {Q*P} =
   * {q_1,...,q_l,p_1,...,p_k} used in homomorphic multiplication
   *
   * @return the precomputed CRT params
   */
  const shared_ptr<ILDCRTParams<BigInteger>> GetParamsQP() const {
    return m_paramsQP;
  }

  /**
   * Gets the precomputed table of 1./q_i
   *
   * @return the precomputed table
   */
  std::vector<double> const& GetqInv() const { return m_qInv; }

  /**
   * Gets the precomputed table of 1./p_j
   *
   * @return the precomputed table
   */
  std::vector<double> const& GetpInv() const { return m_pInv; }

  /**
   * Gets the Barrett modulo reduction precomputation for q_i
   *
   * @return the precomputed table
   */
  std::vector<DoubleNativeInt> const& GetModqBarrettMu() const {
    return m_modqBarrettMu;
  }

  /**
   * Gets the Barrett modulo reduction precomputations for p_j
   *
   * @return the precomputed table
   */
  std::vector<DoubleNativeInt> const& GetModpBarrettMu() const {
    return m_modpBarrettMu;
  }

  /**
   * Gets the precomputed table of \frac{t*{Q/q_i}^{-1}/q_i}
   *
   * @return the precomputed table
   */
  const std::vector<double>& GettQHatInvModqDivqFrac() const {
    return m_tQHatInvModqDivqFrac;
  }

  /**
   * When log2(q_i) >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
   * Gets the precomputed table of \frac{t*{Q/q_i}^{-1}*B/q_i}
   *
   * @return the precomputed table
   */
  const std::vector<double>& GettQHatInvModqBDivqFrac() const {
    return m_tQHatInvModqBDivqFrac;
  }

  /**
   * Gets the precomputed table of [\floor{t*{Q/q_i}^{-1}/q_i}]_t
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger>& GettQHatInvModqDivqModt() const {
    return m_tQHatInvModqDivqModt;
  }

  /**
   * Gets the NTL precomputations for [\floor{t*{Q/q_i}^{-1}/q_i}]_t
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger>& GettQHatInvModqDivqModtPrecon() const {
    return m_tQHatInvModqDivqModtPrecon;
  }

  /**
   * When log2(q_i) >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
   * Gets the precomputed table of [\floor{t*{Q/q_i}^{-1}*B/q_i}]_t
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger>& GettQHatInvModqBDivqModt() const {
    return m_tQHatInvModqBDivqModt;
  }

  /**
   * When log2(q_i) >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
   * Gets the NTL precomputations for [\floor{t*{Q/q_i}^{-1}*B/q_i}]_t
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger>& GettQHatInvModqBDivqModtPrecon() const {
    return m_tQHatInvModqBDivqModtPrecon;
  }

  /**
   * Gets the precomputed table of [\floor{Q/t}]_{q_i}
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger>& GetDelta() const { return m_QDivtModq; }

  /**
   * Gets the precomputed table of [(Q/q_i)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger>& GetQHatInvModq() const {
    return m_QHatInvModq;
  }

  /**
   * Gets the NTL precomputations for [(Q/q_i)^{-1}]_{q_i}
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger>& GetQHatInvModqPrecon() const {
    return m_QHatInvModqPrecon;
  }

  /**
   * Gets the precomputed table of [Q/q_i]_{p_j}
   *
   * @return the precomputed table
   */
  const std::vector<std::vector<NativeInteger>>& GetQHatModp() const {
    return m_QHatModp;
  }

  /**
   * Gets the precomputed table of [\alpha*Q]_{p_j}
   *
   * @return the precomputed table
   */
  const std::vector<std::vector<NativeInteger>>& GetalphaQModp() const {
    return m_alphaQModp;
  }

  /**
   * For S = QP
   * Gets the precomputed table of \frac{[t*P*(S/s_k)^{-1}]_{s_k}/s_k}
   *
   * @return the precomputed table
   */
  const std::vector<double>& GettPSHatInvModsDivsFrac() const {
    return m_tPSHatInvModsDivsFrac;
  }

  /**
   * For S = QP
   * Gets the precomputed table of [\floor{t*P*(S/s_k)^{-1}/s_k}]_{p_j}
   *
   * @return the precomputed table
   */
  const std::vector<std::vector<NativeInteger>>& GettPSHatInvModsDivsModp()
      const {
    return m_tPSHatInvModsDivsModp;
  }

  /**
   * Gets the precomputed table of [(P/p_j)^{-1}]_{p_j}
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger>& GetPHatInvModp() const {
    return m_PHatInvModp;
  }

  /**
   * Gets the NTL precomputation for [(P/p_j)^{-1}]_{p_j}
   *
   * @return the precomputed table
   */
  const std::vector<NativeInteger>& GetPHatInvModpPrecon() const {
    return m_PHatInvModpPrecon;
  }

  /**
   * Gets the precomputed table of [P/p_j]_{q_i}
   *
   * @return the precomputed table
   */
  const std::vector<std::vector<NativeInteger>>& GetPHatModq() const {
    return m_PHatModq;
  }

  /**
   * Gets the precomputed table of [\alpha*P]_{q_i}
   *
   * @return the precomputed table
   */
  const std::vector<std::vector<NativeInteger>>& GetalphaPModq() const {
    return m_alphaPModq;
  }

  /**
   * == operator to compare to this instance of LPCryptoParametersBFVrns object.
   *
   * @param &rhs LPCryptoParameters to check equality against.
   */
  bool operator==(const LPCryptoParameters<Element>& rhs) const {
    const auto* el =
        dynamic_cast<const LPCryptoParametersBFVrns<Element>*>(&rhs);

    if (el == nullptr) return false;

    return LPCryptoParametersRLWE<Element>::operator==(rhs);
  }

  void PrintParameters(std::ostream& os) const {
    LPCryptoParametersRLWE<Element>::PrintParameters(os);
  }

  // NOTE that we do not serialize any of the members declared in this class.
  // they are all cached computations, and get recomputed in any implementation
  // that does a deserialization
  template <class Archive>
  void save(Archive& ar, std::uint32_t const version) const {
    ar(::cereal::base_class<LPCryptoParametersRLWE<Element>>(this));
  }

  template <class Archive>
  void load(Archive& ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::base_class<LPCryptoParametersRLWE<Element>>(this));

    PrecomputeCRTTables();
  }

  std::string SerializedObjectName() const { return "BFVrnsSchemeParameters"; }
  static uint32_t SerializedVersion() { return 1; }

 private:
  // Auxiliary CRT basis {P} = {p_j}
  // used in homomorphic multiplication
  shared_ptr<ILDCRTParams<BigInteger>> m_paramsP;

  // Auxiliary expanded CRT basis Q*P = {s_k}
  // used in homomorphic multiplication
  shared_ptr<ILDCRTParams<BigInteger>> m_paramsQP;

  // Stores \frac{1/q_i}
  std::vector<double> m_qInv;

  // Stores \frac{1/p_j}
  std::vector<double> m_pInv;

  // Barrett modulo reduction precomputation for q_i
  std::vector<DoubleNativeInt> m_modqBarrettMu;

  // Barrett modulo reduction precomputation for p_j
  std::vector<DoubleNativeInt> m_modpBarrettMu;

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

  // Stores [\floor{Q/t}]_{q_i}
  std::vector<NativeInteger> m_QDivtModq;

  // Stores [(Q/q_i)^{-1}]_{q_i}
  std::vector<NativeInteger> m_QHatInvModq;
  // Stores NTL precomputations for [(Q/q_i)^{-1}]_{q_i}
  std::vector<NativeInteger> m_QHatInvModqPrecon;

  // Stores [Q/q_i]_{p_j}
  std::vector<std::vector<NativeInteger>> m_QHatModp;

  // Stores [\alpha*Q]_{p_j} for 0 <= alpha <= sizeQ
  std::vector<std::vector<NativeInteger>> m_alphaQModp;

  // S = QP
  // Stores [\floor{t*P*(S/s_k)^{-1}/s_k}]_{p_j}
  std::vector<std::vector<NativeInteger>> m_tPSHatInvModsDivsModp;

  // S = QP
  // Stores \frac{[t*P*(S/s_k)^{-1}]_{s_k}/s_k}
  std::vector<double> m_tPSHatInvModsDivsFrac;

  // Stores [(P/p_j)^{-1}]_{p_j}
  std::vector<NativeInteger> m_PHatInvModp;
  // Stores NTL precomputations for [(P/p_j)^{-1}]_{p_j}
  std::vector<NativeInteger> m_PHatInvModpPrecon;

  // Stores [P/p_j]_{q_i}
  std::vector<std::vector<NativeInteger>> m_PHatModq;

  // Stores [\alpha*P]_{q_i} for 0 <= alpha <= sizeP
  std::vector<std::vector<NativeInteger>> m_alphaPModq;
};

/**
 * @brief Parameter generation for BFVrns.  This scheme is also referred to as
 * the FV scheme.
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPAlgorithmParamsGenBFVrns : public LPAlgorithmParamsGenBFV<Element> {
  using IntType = typename Element::Integer;
  using ParmType = typename Element::Params;
  using DggType = typename Element::DggType;
  using DugType = typename Element::DugType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmParamsGenBFVrns() {}

  /**
   * Method for computing all derived parameters based on chosen primitive
   * parameters
   *
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
                 int32_t keySwitchCount = 0, size_t dcrBits = 60,
                 uint32_t n = 0) const;
};

/**
 * @brief Encryption algorithm implementation for BFVrns for the basic public
 * key encrypt, decrypt and key generation methods for the BFVrns encryption
 * scheme.
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPAlgorithmBFVrns : public LPAlgorithmBFV<Element> {
  using IntType = typename Element::Integer;
  using ParmType = typename Element::Params;
  using DggType = typename Element::DggType;
  using DugType = typename Element::DugType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmBFVrns() {}

  /**
   * Method for encrypting plaintext using BFVrns.
   *
   * @param publicKey public key used for encryption.
   * @param plaintext the plaintext input.
   * @return ciphertext which results from encryption.
   */
  Ciphertext<Element> Encrypt(const LPPublicKey<Element> publicKey,
                              Element plaintext) const;

  /**
   * Method for encrypting plaintext with private key using BFVrns.
   *
   * @param privateKey private key used for encryption.
   * @param plaintext the plaintext input.
   * @return ciphertext which results from encryption.
   */
  Ciphertext<Element> Encrypt(const LPPrivateKey<Element> privateKey,
                              Element plaintext) const;

  /**
   * Method for decrypting using BFVrns. See the class description for citations
   * on where the algorithms were taken from.
   *
   * @param privateKey private key used for decryption.
   * @param ciphertext ciphertext to be decrypted.
   * @param *plaintext the plaintext output.
   * @return the decrypted plaintext returned.
   */
  DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
                        ConstCiphertext<Element> ciphertext,
                        NativePoly* plaintext) const;
};

/**
 * @brief SHE algorithms implementation for BFVrns.
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPAlgorithmSHEBFVrns : public LPAlgorithmSHEBFV<Element> {
  using IntType = typename Element::Integer;
  using ParmType = typename Element::Params;
  using DggType = typename Element::DggType;
  using DugType = typename Element::DugType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmSHEBFVrns() {}

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
  Ciphertext<Element> EvalSub(ConstCiphertext<Element> ct1,
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
   * have total depth smaller than the supported depth. Otherwise, it throws an
   * error.
   *
   * @param ct1 first input ciphertext.
   * @param ct2 second input ciphertext.
   * @param &ek is the evaluation key to make the newCiphertext
   *  decryptable by the same secret key as that of ciphertext1 and ciphertext2.
   * @return new ciphertext
   */
  Ciphertext<Element> EvalMultAndRelinearize(
      ConstCiphertext<Element> ct1, ConstCiphertext<Element> ct2,
      const vector<LPEvalKey<Element>>& ek) const override;
};

/**
 * @brief PRE algorithms implementation for BFVrns.
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPAlgorithmPREBFVrns : public LPAlgorithmPREBFV<Element> {
  using IntType = typename Element::Integer;
  using ParmType = typename Element::Params;
  using DggType = typename Element::DggType;
  using DugType = typename Element::DugType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmPREBFVrns() {}

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
  LPEvalKey<Element> ReKeyGen(const LPPublicKey<Element> newKey,
                              const LPPrivateKey<Element> oldKey) const;

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
   * operations - in particular, the extra encryption draws noise from a
   * distribution whose standard deviation is scaled by K, the number of digits
   * in the PRE decomposition.
   *
   * @param ek the evaluation key.
   * @param ciphertext the input ciphertext.
   * @param publicKey the public key of the recipient of the re-encrypted
   * ciphertext.
   * @return resulting ciphertext after the re-encryption operation.
   */
  Ciphertext<Element> ReEncrypt(
      const LPEvalKey<Element> ek, ConstCiphertext<Element> ciphertext,
      const LPPublicKey<Element> publicKey = nullptr) const;
};

/**
 * @brief Concrete class for the FHE Multiparty algorithms on BFVrns.    This
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
class LPAlgorithmMultipartyBFVrns : public LPAlgorithmMultipartyBFV<Element> {
  using IntType = typename Element::Integer;
  using ParmType = typename Element::Params;
  using DggType = typename Element::DggType;
  using DugType = typename Element::DugType;
  using TugType = typename Element::TugType;

 public:
  /**
   * Default constructor
   */
  LPAlgorithmMultipartyBFVrns() {}

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

  template <class Archive>
  void save(Archive& ar) const {
    ar(cereal::base_class<LPAlgorithmMultipartyBFV<Element>>(this));
  }

  template <class Archive>
  void load(Archive& ar) {
    ar(cereal::base_class<LPAlgorithmMultipartyBFV<Element>>(this));
  }

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

  std::string SerializedObjectName() const { return "BFVrnsMultiparty"; }
};

/**
 * @brief Main public key encryption scheme for BFVrns implementation,
 * @tparam Element a ring element.
 */
template <class Element>
class LPPublicKeyEncryptionSchemeBFVrns
    : public LPPublicKeyEncryptionScheme<Element> {
  using IntType = typename Element::Integer;
  using ParmType = typename Element::Params;
  using DggType = typename Element::DggType;
  using DugType = typename Element::DugType;
  using TugType = typename Element::TugType;

 public:
  LPPublicKeyEncryptionSchemeBFVrns();

  bool operator==(
      const LPPublicKeyEncryptionScheme<Element>& sch) const override {
    return dynamic_cast<const LPPublicKeyEncryptionSchemeBFVrns<Element>*>(
               &sch) != nullptr;
  }

  void Enable(PKESchemeFeature feature) override;

  template <class Archive>
  void save(Archive& ar, std::uint32_t const version) const {
    ar(::cereal::base_class<LPPublicKeyEncryptionScheme<Element>>(this));
  }

  template <class Archive>
  void load(Archive& ar, std::uint32_t const version) {
    ar(::cereal::base_class<LPPublicKeyEncryptionScheme<Element>>(this));
  }

  std::string SerializedObjectName() const override { return "BFVrnsScheme"; }
};
}  // namespace lbcrypto

#endif
