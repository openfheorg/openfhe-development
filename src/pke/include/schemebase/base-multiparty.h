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

#ifndef LBCRYPTO_CRYPTO_BASE_MULTIPARTY_H
#define LBCRYPTO_CRYPTO_BASE_MULTIPARTY_H

#include "key/privatekey-fwd.h"
#include "key/publickey-fwd.h"
#include "key/evalkey-fwd.h"
#include "cryptocontext-fwd.h"
#include "ciphertext-fwd.h"
#include "decrypt-result.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"

#include <vector>
#include <memory>
#include <map>
#include <string>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {
template <class Element>
class KeyPair;
/**
 * @brief Abstract interface class for LBC Multiparty algorithms based on
 * threshold FHE.  A version of this multiparty scheme built on the BGV scheme
 * is seen here:
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
class MultipartyBase {
    using ParmType = typename Element::Params;
    using IntType  = typename Element::Integer;
    using DugType  = typename Element::DugType;
    using DggType  = typename Element::DggType;
    using TugType  = typename Element::TugType;

public:
    virtual ~MultipartyBase() {}

    /**
   * Threshold FHE: Generates a public key from a vector of secret shares.
   * ONLY FOR DEBUGGIN PURPOSES. SHOULD NOT BE USED IN PRODUCTION.
   *
   * @param cc cryptocontext for the keys to be generated.
   * @param secretkeys secrete key shares.
   * @param makeSparse set to true if ring reduce by a factor of 2 is to be
   * used. NOT SUPPORTED BY ANY SCHEME ANYMORE.
   * @return key pair including the private for the current party and joined
   * public key
   */
    virtual KeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
                                              const std::vector<PrivateKey<Element>>& privateKeyVec, bool makeSparse);

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
    virtual KeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc, const PublicKey<Element> publicKey,
                                              bool makeSparse, bool fresh);

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
    virtual EvalKey<Element> MultiKeySwitchGen(const PrivateKey<Element> oldPrivateKey,
                                               const PrivateKey<Element> newPrivateKey,
                                               const EvalKey<Element> evalKey) const;

    /**
   * Threshold FHE: Generates joined automorphism keys
   * from the current secret share and prior joined
   * automorphism keys
   *
   * @param privateKey secret key share.
   * @param evalKeyMap a dictionary with prior joined automorphism keys.
   * @param &indexVec a vector of automorphism indices.
   * @return a dictionary with new joined automorphism keys.
   */
    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiEvalAutomorphismKeyGen(
        const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap,
        const std::vector<usint>& indexVec) const;

    /**
   * Threshold FHE: Generates evaluation keys for a list of indices for a
   * multi-party setting Currently works only for power-of-two and cyclic-group
   * cyclotomics
   *
   * @param privateKey secret share
   * @param evalKeyMap evaluation key set from other party (parties)
   * @param indexVec list of indices to be computed
   * @return returns the joined evaluation keys
   */
    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiEvalAtIndexKeyGen(
        const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap,
        const std::vector<int32_t>& indexVec) const;

    /**
   * Threshold FHE: Generates joined summation evaluation keys
   * from the current secret share and prior joined
   * summation keys
   *
   * @param privateKey secret key share.
   * @param evalKeyMap a dictionary with prior joined summation keys.
   * @return new joined summation keys.
   */
    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiEvalSumKeyGen(
        const PrivateKey<Element> privateKey,
        const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap) const;

    // MULTIPARTY PKE

    /**
   * Threshold FHE: "Partial" decryption computed by all parties except for the
   * lead one
   *
   * @param ciphertext ciphertext that is being decrypted.
   * @param privateKey secret key share used for decryption.
   */
    virtual Ciphertext<Element> MultipartyDecryptMain(ConstCiphertext<Element> ciphertext,
                                                      const PrivateKey<Element> privateKey) const;

    /**
   * Threshold FHE: Method for decryption operation run by the lead decryption
   * client
   *
   * @param ciphertext ciphertext id decrypted.
   * @param privateKey secret key share used for decryption.
   */
    virtual Ciphertext<Element> MultipartyDecryptLead(ConstCiphertext<Element> ciphertext,
                                                      const PrivateKey<Element> privateKey) const;

    /**
   * Threshold FHE: Method for combining the partially decrypted ciphertexts
   * and getting the final decryption in the clear as a NativePoly.
   *
   * @param &ciphertextVec vector of "partial" decryptions.
   * @param *plaintext the plaintext output as a NativePoly.
   * @return the decoding result.
   */
    virtual DecryptResult MultipartyDecryptFusion(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                                  NativePoly* plaintext) const;

    /**
   * Threshold FHE: Method for combining the partially decrypted ciphertexts
   * and getting the final decryption in the clear as a Poly.
   *
   * @param &ciphertextVec vector of "partial" decryptions.
   * @param *plaintext the plaintext output as a Poly.
   * @return the decoding result.
   */
    virtual DecryptResult MultipartyDecryptFusion(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                                  Poly* plaintext) const {
        OPENFHE_THROW(config_error, "Decryption to Poly is not supported");
    }

    /**
   * Threshold FHE: Adds two prior public keys
   *
   * @param evalKey1 first public key.
   * @param evalKey2 second public key.
   * @return the new joined key.
   */
    virtual PublicKey<Element> MultiAddPubKeys(PublicKey<Element> publicKey1, PublicKey<Element> publicKey2) const;

    /**
   * Threshold FHE: Adds two prior evaluation keys
   *
   * @param evalKey1 first evaluation key.
   * @param evalKey2 second evaluation key.
   * @return the new joined key.
   */
    virtual EvalKey<Element> MultiAddEvalKeys(EvalKey<Element> evalKey1, EvalKey<Element> evalKey2) const;

    /**
   * Threshold FHE: Adds two partial evaluation keys for multiplication
   *
   * @param evalKey1 first evaluation key.
   * @param evalKey2 second evaluation key.
   * @return the new joined key.
   */
    virtual EvalKey<Element> MultiAddEvalMultKeys(EvalKey<Element> evalKey1, EvalKey<Element> evalKey2) const;

    /**
    * Threshold FHE: Generates a partial evaluation key for homomorphic
    * multiplication based on the current secret share and an existing partial
    * evaluation key
    *
    * @param privateKey current secret share.
    * @param evalKey prior evaluation key.
    * @return the new joined key.
    */
    virtual EvalKey<Element> MultiMultEvalKey(PrivateKey<Element> privateKey, EvalKey<Element> evalKey) const;
    /**
    *
    * Threshold FHE: Adds two prior evaluation key sets for automorphisms
    *
    * @param evalKeyMap1 first automorphism key set.
    * @param evalKeyMap2 second automorphism key set.
    * @return the new joined key set for summation.
    */
    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiAddEvalAutomorphismKeys(
        const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap1,
        const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap2) const;

    /**
    * Threshold FHE: Adds two prior evaluation key sets for summation
    *
    * @param evalKeyMap1 first summation key set.
    * @param evalKeyMap2 second summation key set.
    * @return the new joined key set for summation.
    */
    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiAddEvalSumKeys(
        const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap1,
        const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap2) const;

    /**
    * Threshold FHE: Prepare a ciphertext for Multi-Party Interactive Bootstrapping
    *
    * @param ciphertext: Input Ciphertext
    * @return: Resulting Ciphertext
    */
    virtual Ciphertext<Element> IntMPBootAdjustScale(ConstCiphertext<Element> ciphertext) const;

    /**
    * Threshold FHE: Generate a common random polynomial for Multi-Party Interactive Bootstrapping
    *
    * @param publicKey: the scheme public key (you can also provide the lead party's public-key)
    * @return: Resulting ring element
    */
    virtual Ciphertext<Element> IntMPBootRandomElementGen(std::shared_ptr<CryptoParametersCKKSRNS> params,
                                                          const PublicKey<Element> publicKey) const;

    /**
    * Threshold FHE: Does masked decryption as part of Multi-Party Interactive Bootstrapping.
    * Each party calls this function as part of the protocol
    *
    * @param privateKey: secret key share for party i
    * @param ciphertext: input ciphertext
    * @param a: input common random polynomial
    * @return: Resulting masked decryption
    */
    virtual std::vector<Ciphertext<Element>> IntMPBootDecrypt(const PrivateKey<Element> privateKey,
                                                              ConstCiphertext<Element> ciphertext,
                                                              ConstCiphertext<Element> a) const;

    /**
    * Threshold FHE: Aggregates a vector of masked decryptions and re-encryotion shares,
    * which is the second step of the interactive multiparty bootstrapping procedure.
    *
    * @param sharesPairVec: vector of pair of ciphertexts, each element of this vector contains
    * (h_0i, h_1i) - the masked-decryption and encryption shares ofparty i
    * @return: aggregated pair of shares ((h_0, h_1)
    */
    virtual std::vector<Ciphertext<Element>> IntMPBootAdd(
        std::vector<std::vector<Ciphertext<Element>>>& sharesPairVec) const;

    /**
    *  Threshold FHE: Does public key encryption of lead party's masked decryption
    * as part of interactive multi-party bootstrapping, which increases
    * the ciphertext modulus and enables future computations.
    * This operation is done by the lead party as the final step
    * of interactive multi-party bootstrapping.
    *
    * @param publicKey: the lead party's public key
    * @param sharesPair: aggregated decryption and re-encryption shares
    * @param a: common random ring element
    * @param ciphertext: input ciphertext
    * @return: Resulting encryption
    */
    virtual Ciphertext<Element> IntMPBootEncrypt(const PublicKey<Element> publicKey,
                                                 const std::vector<Ciphertext<Element>>& sharesPair,
                                                 ConstCiphertext<Element> a, ConstCiphertext<Element> ciphertext) const;

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {}

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {}

    std::string SerializedObjectName() const {
        return "MultiPartyBase";
    }
};

}  // namespace lbcrypto

#endif
