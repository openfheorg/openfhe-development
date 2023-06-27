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
  Header file for BinFHEContext class, which is used for Boolean circuit FHE schemes
 */

#ifndef BINFHE_BINFHECONTEXT_H
#define BINFHE_BINFHECONTEXT_H

#include "binfhe-base-scheme.h"

#include "utils/serializable.h"
#include "lattice/stdlatticeparms.h"

#include <memory>
#include <string>
#include <vector>
#include <map>

namespace lbcrypto {

/**
 * @brief BinFHEContext
 *
 * The wrapper class for Boolean circuit FHE
 */
class BinFHEContext : public Serializable {
public:
    BinFHEContext() = default;

    /**
   * Creates a crypto context using custom parameters.
   * Should be used with care (only for advanced users familiar with LWE
   * parameter selection).
   *
   * @param n lattice parameter for additive LWE scheme
   * @param N ring dimension for RingGSW/RLWE used in bootstrapping
   * @param &q modulus for additive LWE
   * @param &Q modulus for RingGSW/RLWE used in bootstrapping
   * @param std standard deviation
   * @param baseKS the base used for key switching
   * @param baseG the gadget base used in bootstrapping
   * @param baseR the base used for refreshing
   * @param method the bootstrapping method (DM or CGGI or LMKCDEY)
   * @return creates the cryptocontext
   */
    void GenerateBinFHEContext(uint32_t n, uint32_t N, const NativeInteger& q, const NativeInteger& Q, double std,
                               uint32_t baseKS, uint32_t baseG, uint32_t baseR, BINFHE_METHOD method = GINX);

    /**
   * Creates a crypto context using custom parameters.
   * Should be used with care (only for advanced users familiar with LWE
   * parameter selection).
   *
   * @param sl the parameter set: TOY, MEDIUM, STD128, STD192, STD256
   * @param arbFunc whether need to evaluate an arbitrary function using functional bootstrapping
   * @param logQ log(input ciphertext modulus)
   * @param N ring dimension for RingGSW/RLWE used in bootstrapping
   * @param method the bootstrapping method (DM or CGGI or LMKCDEY)
   * @param timeOptimization whether to use dynamic bootstrapping technique
   * @return creates the cryptocontext
   */
    void GenerateBinFHEContext(BINFHE_PARAMSET set, bool arbFunc, uint32_t logQ = 11, int64_t N = 0,
                               BINFHE_METHOD method = GINX, bool timeOptimization = false);

    /**
   * Creates a crypto context using predefined parameters sets. Recommended for
   * most users.
   *
   * @param set the parameter set: TOY, MEDIUM, STD128, STD192, STD256
   * @param method the bootstrapping method (DM or CGGI or LMKCDEY)
   * @return create the cryptocontext
   */
    void GenerateBinFHEContext(BINFHE_PARAMSET set, BINFHE_METHOD method = GINX);

    /**
   * Gets the refreshing key (used for serialization).
   *
   * @return a shared pointer to the refreshing key
   */
    const RingGSWACCKey GetRefreshKey() const {
        return m_BTKey.BSkey;
    }

    /**
   * Gets the switching key (used for serialization).
   *
   * @return a shared pointer to the switching key
   */
    const LWESwitchingKey GetSwitchKey() const {
        return m_BTKey.KSkey;
    }

    /**
   * Gets the public key (used for serialization).
   *
   * @return a shared pointer to the switching key
   */
    const LWEPublicKey GetPublicKey() const {
        return m_BTKey.Pkey;
    }

    /**
    * Gets the bootstrapping key map (used for serialization).
    *
    * @return a shared pointer to the bootstrapping key map
    */
    const std::shared_ptr<std::map<uint32_t, RingGSWBTKey>> GetBTKeyMap() const {
        return std::make_shared<std::map<uint32_t, RingGSWBTKey>>(m_BTKey_map);
    }

    /**
   * Generates a secret key for the main LWE scheme
   *
   * @param DiffQ Keygen according to DiffQ instead of m_q if DiffQ != 0
   * @return a shared pointer to the secret key
   */
    LWEPrivateKey KeyGen() const;

    /**
   * Generates a public key, secret key pair for the main LWE scheme
   *
   * @return a shared pointer to the public key, secret key pair
   */

    LWEKeyPair KeyGenPair() const;

    /**
   * Generates a public key for a secret key for the main LWE scheme
   *
   * @return a shared pointer to the public key
   */

    LWEPublicKey PubKeyGen(ConstLWEPrivateKey sk) const;

    /**
   * Generates a secret key used in bootstrapping
   * @return a shared pointer to the secret key
   */
    LWEPrivateKey KeyGenN() const;

    /**
   * Encrypts a bit using a secret key (symmetric key encryption)
   *
   * @param sk - the secret key
   * @param &m - the plaintext
   * @param output - FRESH to generate fresh ciphertext, BOOTSTRAPPED to
   * generate a refreshed ciphertext (default)
   * @param p - plaintext modulus
   * @param mod Encrypt according to mod instead of m_q if mod != 0
   * @return a shared pointer to the ciphertext
   */
    LWECiphertext Encrypt(ConstLWEPrivateKey sk, LWEPlaintext m, BINFHE_OUTPUT output = BOOTSTRAPPED,
                          LWEPlaintextModulus p = 4, const NativeInteger& mod = 0) const;

    /**
   * Encrypts a bit using a public key (public key encryption)
   *
   * @param pk - the public key
   * @param &m - the plaintext
   * @param p - plaintext modulus
   * @param mod Encrypt according to mod instead of m_q if mod != 0
   * @param output - SMALL_DIM to generate ciphertext with dimension n (default). LARGE_DIM to generate ciphertext with dimension N
   * @return a shared pointer to the ciphertext
   */
    LWECiphertext Encrypt(ConstLWEPublicKey pk, LWEPlaintext m, BINFHE_OUTPUT output = SMALL_DIM,
                          LWEPlaintextModulus p = 4, const NativeInteger& mod = 0) const;

    /**
   * Converts a ciphertext (public key encryption) with modulus Q and dimension N to ciphertext with q and n
   *
   * @param ksk - the key switching key from secret key of dimension N to secret key of dimension n
   * @return a shared pointer to the ciphertext
   */
    LWECiphertext SwitchCTtoqn(ConstLWESwitchingKey ksk, ConstLWECiphertext ct) const;

    /**
   * Decrypts a ciphertext using a secret key
   *
   * @param sk the secret key
   * @param ct the ciphertext
   * @param *result plaintext result
   * @param p - plaintext modulus
   * @param DiffQ Decrypt according to DiffQ instead of m_q if DiffQ != 0
   */
    void Decrypt(ConstLWEPrivateKey sk, ConstLWECiphertext ct, LWEPlaintext* result, LWEPlaintextModulus p = 4) const;

    /**
   * Generates a switching key to go from a secret key with (Q,N) to a secret
   * key with (q,n)
   *
   * @param sk new secret key
   * @param skN old secret key
   * @return a shared pointer to the switching key
   */
    LWESwitchingKey KeySwitchGen(ConstLWEPrivateKey sk, ConstLWEPrivateKey skN) const;

    /**
   * Generates boostrapping keys
   *
   * @param sk secret key
   * @param DiffQ BTKeyGen according to DiffQ instead of m_q if DiffQ != 0
   */
    void BTKeyGen(ConstLWEPrivateKey sk, KEYGEN_MODE keygenMode = SYM_ENCRYPT);

    /**
   * Loads bootstrapping keys in the context (typically after deserializing)
   *
   * @param key struct with the bootstrapping keys
   */
    void BTKeyLoad(const RingGSWBTKey& key) {
        m_BTKey = key;
    }

    /**
   * Loads a bootstrapping key map element in the context (typically after deserializing)
   *
   * @param baseG baseG corresponding to the given key
   * @param key struct with the bootstrapping keys
   */
    void BTKeyMapLoadSingleElement(uint32_t baseG, const RingGSWBTKey& key) {
        m_BTKey_map[baseG] = key;
    }

    /**
   * Clear the bootstrapping keys in the current context
   */
    void ClearBTKeys() {
        m_BTKey.BSkey.reset();
        m_BTKey.KSkey.reset();
        m_BTKey.Pkey.reset();
        m_BTKey_map.clear();
    }

    /**
   * Evaluates a binary gate (calls bootstrapping as a subroutine)
   *
   * @param gate the gate; can be AND, OR, NAND, NOR, XOR, or XNOR
   * @param ct1 first ciphertext
   * @param ct2 second ciphertext
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalBinGate(BINGATE gate, ConstLWECiphertext ct1, ConstLWECiphertext ct2) const;

    /**
   * Bootstraps a ciphertext (without peforming any operation)
   *
   * @param ct1 ciphertext to be bootstrapped
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext Bootstrap(ConstLWECiphertext ct) const;

    /**
   * Evaluate an arbitrary function
   *
   * @param ct1 ciphertext to be bootstrapped
   * @param LUT the look-up table of the to-be-evaluated function
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFunc(ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT) const;

    /**
   * Generate the LUT for the to-be-evaluated function
   *
   * @param f the to-be-evaluated function
   * @param p plaintext modulus
   * @return a shared pointer to the resulting ciphertext
   */
    std::vector<NativeInteger> GenerateLUTviaFunction(NativeInteger (*f)(NativeInteger m, NativeInteger p),
                                                      NativeInteger p);

    /**
   * Evaluate a round down function
   *
   * @param ct1 ciphertext to be bootstrapped
   * @param roundbits number of bits to be rounded
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFloor(ConstLWECiphertext ct, uint32_t roundbits = 0) const;

    /**
   * Evaluate a sign function over large precisions
   *
   * @param ct1 ciphertext to be bootstrapped
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalSign(ConstLWECiphertext ct);

    /**
   * Evaluate ciphertext decomposition
   *
   * @param ct1 ciphertext to be bootstrapped
   * @return a vector of shared pointers to the resulting ciphertexts
   */
    std::vector<LWECiphertext> EvalDecomp(ConstLWECiphertext ct);

    /**
   * Evaluates NOT gate
   *
   * @param ct1 the input ciphertext
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalNOT(ConstLWECiphertext ct) const;

    /**
   * Evaluates constant gate
   *
   * @param value the Boolean value to output
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalConstant(bool value) const;

    const std::shared_ptr<BinFHECryptoParams> GetParams() {
        return m_params;
    }

    const std::shared_ptr<LWEEncryptionScheme> GetLWEScheme() {
        return m_LWEscheme;
    }

    const std::shared_ptr<BinFHEScheme> GetBinFHEScheme() {
        return m_binfhescheme;
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("params", m_params));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(::cereal::make_nvp("params", m_params));
        m_binfhescheme = std::make_shared<BinFHEScheme>(m_params->GetRingGSWParams()->GetMethod());
    }

    std::string SerializedObjectName() const {
        return "BinFHEContext";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

    NativeInteger GetMaxPlaintextSpace() const {
        // Under our parameter choices, beta = 128 is enough, and therefore plaintext = q/2beta
        return m_params->GetLWEParams()->Getq() / this->GetBeta() / 2;
    }

    NativeInteger GetBeta() const {
        return 128;
    }

private:
    // Shared pointer to Ring GSW + LWE parameters
    std::shared_ptr<BinFHECryptoParams> m_params = nullptr;

    // Shared pointer to the underlying additive LWE scheme
    std::shared_ptr<LWEEncryptionScheme> m_LWEscheme = nullptr;

    // Shared pointer to the underlying RingGSW/RLWE scheme
    std::shared_ptr<BinFHEScheme> m_binfhescheme = nullptr;

    // Struct containing the bootstrapping keys
    RingGSWBTKey m_BTKey = {0};

    // Struct containing the bootstrapping keys
    std::map<uint32_t, RingGSWBTKey> m_BTKey_map;

    // Whether to optimize time for sign eval
    bool m_timeOptimization = false;
};

}  // namespace lbcrypto

#endif
