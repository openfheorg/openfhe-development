// @file cryptocontext.h -- Control for encryption operations.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT))
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

#ifndef SRC_PKE_CRYPTOCONTEXT_H_
#define SRC_PKE_CRYPTOCONTEXT_H_

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "palisade.h"
#include "scheme/allscheme.h"

#include "cryptocontexthelper.h"

#include "utils/caller_info.h"
#include "utils/serial.h"

namespace lbcrypto {

// Backend-specific settings for CKKS
#if NATIVEINT == 128
const size_t FIRSTMODSIZE = 105;
const enum RescalingTechnique DEFAULTRSTECH = APPROXAUTO;
#else
const size_t FIRSTMODSIZE = 60;
const enum RescalingTechnique DEFAULTRSTECH = EXACTRESCALE;
#endif

template <typename Element>
class CryptoContextFactory;

template <typename Element>
class CryptoContextImpl;

template <typename Element>
using CryptoContext = shared_ptr<CryptoContextImpl<Element>>;

/**
 * @brief CryptoContextImpl
 *
 * A CryptoContextImpl is the object used to access the PALISADE library
 *
 * All PALISADE functionality is accessed by way of an instance of a
 * CryptoContextImpl; we say that various objects are "created in" a context,
 * and can only be used in the context in which they were created
 *
 * All PALISADE methods are accessed through CryptoContextImpl methods. Guards
 * are implemented to make certain that only valid objects that have been
 * created in the context are used
 *
 * Contexts are created using the CryptoContextFactory, and can be serialized
 * and recovered from a serialization
 */
template <typename Element>
class CryptoContextImpl : public Serializable {
  using IntType = typename Element::Integer;
  using ParmType = typename Element::Params;

  friend class CryptoContextFactory<Element>;

 protected:
  // crypto parameters used for this context
  shared_ptr<LPCryptoParameters<Element>> params;
  // algorithm used; accesses all crypto methods
  shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme;

  static std::map<string, std::vector<LPEvalKey<Element>>>& evalMultKeyMap() {
    // cached evalmult keys, by secret key UID
    static std::map<string, std::vector<LPEvalKey<Element>>> s_evalMultKeyMap;
    return s_evalMultKeyMap;
  }

  static std::map<string, shared_ptr<std::map<usint, LPEvalKey<Element>>>>&
  evalSumKeyMap() {
    // cached evalsum keys, by secret key UID
    static std::map<string, shared_ptr<std::map<usint, LPEvalKey<Element>>>>
        s_evalSumKeyMap;
    return s_evalSumKeyMap;
  }

  static std::map<string, shared_ptr<std::map<usint, LPEvalKey<Element>>>>&
  evalAutomorphismKeyMap() {
    // cached evalautomorphism keys, by secret key UID
    static std::map<string, shared_ptr<std::map<usint, LPEvalKey<Element>>>>
        s_evalAutomorphismKeyMap;
    return s_evalAutomorphismKeyMap;
  }

  string m_schemeId;

  size_t m_keyGenLevel;

  /**
   * TypeCheck makes sure that an operation between two ciphertexts is permitted
   * @param a
   * @param b
   */
  void TypeCheck(ConstCiphertext<Element> a, ConstCiphertext<Element> b,
                 CALLER_INFO_ARGS_HDR) const {
    if (a == nullptr || b == nullptr) {
      std::string errorMsg(std::string("Null Ciphertext") + CALLER_INFO);
      PALISADE_THROW(type_error, errorMsg);
    }
    if (a->GetCryptoContext().get() != this) {
      std::string errorMsg(
          std::string("Ciphertext was not created in this CryptoContext") +
          CALLER_INFO);
      PALISADE_THROW(type_error, errorMsg);
    }
    if (a->GetCryptoContext() != b->GetCryptoContext()) {
      std::string errorMsg(
          std::string(
              "Ciphertexts were not created in the same CryptoContext") +
          CALLER_INFO);
      PALISADE_THROW(type_error, errorMsg);
    }
    if (a->GetKeyTag() != b->GetKeyTag()) {
      std::string errorMsg(
          std::string("Ciphertexts were not encrypted with same keys") +
          CALLER_INFO);
      PALISADE_THROW(type_error, errorMsg);
    }
    if (a->GetEncodingType() != b->GetEncodingType()) {
      std::stringstream ss;
      ss << "Ciphertext encoding types " << a->GetEncodingType();
      ss << " and " << b->GetEncodingType();
      ss << " do not match";
      ss << CALLER_INFO;
      PALISADE_THROW(type_error, ss.str());
    }
  }

  /**
   * TypeCheck makes sure that an operation between two ciphertexts is permitted
   * This is intended for mutable methods, hence inputs are Ciphretext instead
   * of ConstCiphertext.
   *
   * @param a
   * @param b
   */
  /*
 void TypeCheck(Ciphertext<Element> a,
                Ciphertext<Element> b,
                CALLER_INFO_ARGS_HDR) const {
   if (a == nullptr || b == nullptr) {
     std::string errorMsg(std::string("Null Ciphertext") + CALLER_INFO);
     PALISADE_THROW(type_error, errorMsg);
   }
   if (a->GetCryptoContext().get() != this) {
     std::string errorMsg(
       std::string("Ciphertext was not created in this CryptoContext") +
       CALLER_INFO);
     PALISADE_THROW(type_error, errorMsg);
   }
   if (a->GetCryptoContext() != b->GetCryptoContext()) {
     std::string errorMsg(
       std::string("Ciphertexts were not created in the same CryptoContext") +
       CALLER_INFO);
     PALISADE_THROW(type_error, errorMsg);
   }
   if (a->GetKeyTag() != b->GetKeyTag()) {
     std::string errorMsg(
       std::string("Ciphertexts were not encrypted with same keys") +
       CALLER_INFO);
     PALISADE_THROW(type_error, errorMsg);
   }
   if (a->GetEncodingType() != b->GetEncodingType()) {
     std::stringstream ss;
     ss << "Ciphertext encoding types " << a->GetEncodingType();
     ss << " and " << b->GetEncodingType();
     ss << " do not match";
     ss << CALLER_INFO;
     PALISADE_THROW(type_error, ss.str());
   }
 }
 */

  /**
   * TypeCheck makes sure that an operation between a ciphertext and a plaintext
   * is permitted
   * @param a
   * @param b
   */
  void TypeCheck(ConstCiphertext<Element> a, ConstPlaintext b,
                 CALLER_INFO_ARGS_HDR) const {
    if (a == nullptr) {
      std::string errorMsg(std::string("Null Ciphertext") + CALLER_INFO);
      PALISADE_THROW(type_error, errorMsg);
    }
    if (b == nullptr) {
      std::string errorMsg(std::string("Null Plaintext") + CALLER_INFO);
      PALISADE_THROW(type_error, errorMsg);
    }
    if (a->GetCryptoContext().get() != this) {
      std::string errorMsg(
          std::string("Ciphertext was not created in this CryptoContext") +
          CALLER_INFO);
      PALISADE_THROW(type_error, errorMsg);
    }
    if (a->GetEncodingType() != b->GetEncodingType()) {
      std::stringstream ss;
      ss << "Ciphertext encoding type " << a->GetEncodingType();
      ss << " and Plaintext encoding type " << b->GetEncodingType();
      ss << " do not match";
      ss << CALLER_INFO;
      PALISADE_THROW(type_error, ss.str());
    }
  }

  bool Mismatched(const CryptoContext<Element> a) const {
    if (a.get() != this) {
      return true;
    }
    return false;
  }

 public:
  LPPrivateKey<Element> privateKey;

  /**
   * This stores the private key in the crypto context.
   * This is only intended for debugging and should not be
   * used in production systems. Please define DEBUG_KEY in
   * palisade.h to enable this.
   *
   * If used, one can create a key pair and store the secret
   * key in th crypto context like this:
   *
   * auto keys = cc->KeyGen();
   * cc->SetPrivateKey(keys.secretKey);
   *
   * After that, anyone in the code, one can access the
   * secret key by getting the crypto context and doing the
   * following:
   *
   * auto sk = cc->GetPrivateKey();
   *
   * This key can be used for decrypting any intermediate
   * ciphertexts for debugging purposes.
   *
   * @param sk the secret key
   *
   */
  void SetPrivateKey(const LPPrivateKey<Element> sk) {
#ifdef DEBUG_KEY
    cerr << "Warning - SetPrivateKey is only intended to be used for debugging "
            "purposes - not for production systems."
         << endl;
    this->privateKey = sk;
#else
    PALISADE_THROW(
        not_available_error,
        "SetPrivateKey is only allowed if DEBUG_KEY is set in palisade.h");
#endif
  }

  /**
   * This gets the private key from the crypto context.
   * This is only intended for debugging and should not be
   * used in production systems. Please define DEBUG_KEY in
   * palisade.h to enable this.
   *
   * If used, one can create a key pair and store the secret
   * key in th crypto context like this:
   *
   * auto keys = cc->KeyGen();
   * cc->SetPrivateKey(keys.secretKey);
   *
   * After that, anyone in the code, one can access the
   * secret key by getting the crypto context and doing the
   * following:
   *
   * auto sk = cc->GetPrivateKey();
   *
   * This key can be used for decrypting any intermediate
   * ciphertexts for debugging purposes.
   *
   * @return the secret key
   *
   */
  const LPPrivateKey<Element> GetPrivateKey() {
#ifdef DEBUG_KEY
    return this->privateKey;
#else
    PALISADE_THROW(
        not_available_error,
        "GetPrivateKey is only allowed if DEBUG_KEY is set in palisade.h");
#endif
  }

  void setSchemeId(string schemeTag) { this->m_schemeId = schemeTag; }

  string getSchemeId() const { return this->m_schemeId; }

  /**
   * CryptoContextImpl constructor from pointers to parameters and scheme
   * @param params - pointer to CryptoParameters
   * @param scheme - pointer to Crypto Scheme
   */
  CryptoContextImpl(LPCryptoParameters<Element>* params = nullptr,
                    LPPublicKeyEncryptionScheme<Element>* scheme = nullptr,
                    const string& schemeId = "Not") {
    this->params.reset(params);
    this->scheme.reset(scheme);
    this->m_keyGenLevel = 0;
    this->m_schemeId = schemeId;
  }

  /**
   * CryptoContextImpl constructor from shared pointers to parameters and scheme
   * @param params - shared pointer to CryptoParameters
   * @param scheme - sharedpointer to Crypto Scheme
   */
  CryptoContextImpl(shared_ptr<LPCryptoParameters<Element>> params,
                    shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme,
                    const string& schemeId = "Not") {
    this->params = params;
    this->scheme = scheme;
    this->m_keyGenLevel = 0;
    this->m_schemeId = schemeId;
  }

  /**
   * Copy constructor
   * @param c - source
   */
  CryptoContextImpl(const CryptoContextImpl<Element>& c) {
    params = c.params;
    scheme = c.scheme;
    this->m_keyGenLevel = 0;
    this->m_schemeId = c.m_schemeId;
  }

  /**
   * Assignment
   * @param rhs - assigning from
   * @return this
   */
  CryptoContextImpl<Element>& operator=(const CryptoContextImpl<Element>& rhs) {
    params = rhs.params;
    scheme = rhs.scheme;
    m_keyGenLevel = rhs.m_keyGenLevel;
    m_schemeId = rhs.m_schemeId;
    return *this;
  }

  /**
   * A CryptoContextImpl is only valid if the shared pointers are both valid
   */
  operator bool() const { return params && scheme; }

  /**
   * Private methods to compare two contexts; this is only used internally and
   * is not generally available
   * @param a - operand 1
   * @param b - operand 2
   * @return true if the implementations have identical parms and scheme
   */
  friend bool operator==(const CryptoContextImpl<Element>& a,
                         const CryptoContextImpl<Element>& b) {
    // Identical if the parameters and the schemes are identical... the exact
    // same object, OR the same type and the same values
    if (a.params.get() == b.params.get()) {
      return true;
    } else {
      if (typeid(*a.params.get()) != typeid(*b.params.get())) {
        return false;
      }
      if (*a.params.get() != *b.params.get()) return false;
    }

    if (a.scheme.get() == b.scheme.get()) {
      return true;
    } else {
      if (typeid(*a.scheme.get()) != typeid(*b.scheme.get())) {
        return false;
      }
      if (*a.scheme.get() != *b.scheme.get()) return false;
    }

    return true;
  }

  friend bool operator!=(const CryptoContextImpl<Element>& a,
                         const CryptoContextImpl<Element>& b) {
    return !(a == b);
  }

  /**
   * SerializeEvalMultKey for a single EvalMult key or all EvalMult keys
   *
   * @param ser - stream to serialize to
   * @param sertype - type of serialization
   * @param id for key to serialize - if empty string, serialize them all
   * @return true on success
   */
  template <typename ST>
  static bool SerializeEvalMultKey(std::ostream& ser, const ST& sertype,
                                   string id = "");

  /**
   * SerializeEvalMultKey for all EvalMultKeys made in a given context
   *
   * @param cc whose keys should be serialized
   * @param ser - stream to serialize to
   * @param sertype - type of serialization
   * @return true on success (false on failure or no keys found)
   */
  template <typename ST>
  static bool SerializeEvalMultKey(std::ostream& ser, const ST& sertype,
                                   const CryptoContext<Element> cc) {
    std::map<string, std::vector<LPEvalKey<Element>>> omap;
    for (const auto& k : GetAllEvalMultKeys()) {
      if (k.second[0]->GetCryptoContext() == cc) {
        omap[k.first] = k.second;
      }
    }

    if (omap.size() == 0) return false;

    Serial::Serialize(omap, ser, sertype);
    return true;
  }

  /**
   * DeserializeEvalMultKey deserialize all keys in the serialization
   * deserialized keys silently replace any existing matching keys
   * deserialization will create CryptoContextImpl if necessary
   *
   * @param serObj - stream with a serialization
   * @return true on success
   */
  template <typename ST>
  static bool DeserializeEvalMultKey(std::istream& ser, const ST& sertype) {
    std::map<string, std::vector<LPEvalKey<Element>>> evalMultKeys;

    Serial::Deserialize(GetAllEvalMultKeys(), ser, sertype);

    // The deserialize call created any contexts that needed to be created....
    // so all we need to do is put the keys into the maps for their context

    for (auto k : GetAllEvalMultKeys()) {
      GetAllEvalMultKeys()[k.first] = k.second;
    }

    return true;
  }

  /**
   * ClearEvalMultKeys - flush EvalMultKey cache
   */
  static void ClearEvalMultKeys();

  /**
   * ClearEvalMultKeys - flush EvalMultKey cache for a given id
   * @param id
   */
  static void ClearEvalMultKeys(const string& id);

  /**
   * ClearEvalMultKeys - flush EvalMultKey cache for a given context
   * @param cc
   */
  static void ClearEvalMultKeys(const CryptoContext<Element> cc);

  /**
   * InsertEvalMultKey - add the given vector of keys to the map, replacing the
   * existing vector if there
   * @param vectorToInsert
   */
  static void InsertEvalMultKey(
      const std::vector<LPEvalKey<Element>>& vectorToInsert);

  /**
   * SerializeEvalSumKey for a single EvalSum key or all of the EvalSum keys
   *
   * @param ser - stream to serialize to
   * @param sertype - type of serialization
   * @param id - key to serialize; empty string means all keys
   * @return true on success
   */
  template <typename ST>
  static bool SerializeEvalSumKey(std::ostream& ser, const ST& sertype,
                                  string id = "") {
    std::map<string, shared_ptr<std::map<usint, LPEvalKey<Element>>>>* smap;
    std::map<string, shared_ptr<std::map<usint, LPEvalKey<Element>>>> omap;

    if (id.length() == 0) {
      smap = &GetAllEvalSumKeys();
    } else {
      auto k = GetAllEvalSumKeys().find(id);

      if (k == GetAllEvalSumKeys().end()) return false;  // no such id

      smap = &omap;
      omap[k->first] = k->second;
    }
    Serial::Serialize(*smap, ser, sertype);
    return true;
  }

  /**
   * SerializeEvalSumKey for all of the EvalSum keys for a context
   *
   * @param ser - stream to serialize to
   * @param sertype - type of serialization
   * @param cc - context
   * @return true on success
   */
  template <typename ST>
  static bool SerializeEvalSumKey(std::ostream& ser, const ST& sertype,
                                  const CryptoContext<Element> cc) {
    std::map<string, shared_ptr<std::map<usint, LPEvalKey<Element>>>> omap;
    for (const auto& k : GetAllEvalSumKeys()) {
      if (k.second->begin()->second->GetCryptoContext() == cc) {
        omap[k.first] = k.second;
      }
    }

    if (omap.size() == 0) return false;

    Serial::Serialize(omap, ser, sertype);

    return true;
  }

  /**
   * DeserializeEvalSumKey deserialize all keys in the serialization
   * deserialized keys silently replace any existing matching keys
   * deserialization will create CryptoContextImpl if necessary
   *
   * @param ser - stream to serialize from
   * @param sertype - type of serialization
   * @return true on success
   */
  template <typename ST>
  static bool DeserializeEvalSumKey(std::istream& ser, const ST& sertype) {
    std::map<string, shared_ptr<std::map<usint, LPEvalKey<Element>>>>
        evalSumKeys;

    Serial::Deserialize(evalSumKeys, ser, sertype);

    // The deserialize call created any contexts that needed to be created....
    // so all we need to do is put the keys into the maps for their context

    for (auto k : evalSumKeys) {
      GetAllEvalSumKeys()[k.first] = k.second;
    }

    return true;
  }

  /**
   * ClearEvalSumKeys - flush EvalSumKey cache
   */
  static void ClearEvalSumKeys();

  /**
   * ClearEvalSumKeys - flush EvalSumKey cache for a given id
   * @param id
   */
  static void ClearEvalSumKeys(const string& id);

  /**
   * ClearEvalSumKeys - flush EvalSumKey cache for a given context
   * @param cc
   */
  static void ClearEvalSumKeys(const CryptoContext<Element> cc);

  /**
   * InsertEvalSumKey - add the given map of keys to the map, replacing the
   * existing map if there
   * @param mapToInsert
   */
  static void InsertEvalSumKey(
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> mapToInsert);

  /**
   * SerializeEvalAutomorphismKey for a single EvalAuto key or all of the
   * EvalAuto keys
   *
   * @param ser - stream to serialize to
   * @param sertype - type of serialization
   * @param id - key to serialize; empty string means all keys
   * @return true on success
   */
  template <typename ST>
  static bool SerializeEvalAutomorphismKey(std::ostream& ser, const ST& sertype,
                                           string id = "") {
    std::map<string, shared_ptr<std::map<usint, LPEvalKey<Element>>>>* smap;
    std::map<string, shared_ptr<std::map<usint, LPEvalKey<Element>>>> omap;
    if (id.length() == 0) {
      smap = &GetAllEvalAutomorphismKeys();
    } else {
      auto k = GetAllEvalAutomorphismKeys().find(id);

      if (k == GetAllEvalAutomorphismKeys().end()) return false;  // no such id

      smap = &omap;
      omap[k->first] = k->second;
    }
    Serial::Serialize(*smap, ser, sertype);
    return true;
  }

  /**
   * SerializeEvalAutomorphismKey for all of the EvalAuto keys for a context
   *
   * @param ser - stream to serialize to
   * @param sertype - type of serialization
   * @param cc - context
   * @return true on success
   */
  template <typename ST>
  static bool SerializeEvalAutomorphismKey(std::ostream& ser, const ST& sertype,
                                           const CryptoContext<Element> cc) {
    std::map<string, shared_ptr<std::map<usint, LPEvalKey<Element>>>> omap;
    for (const auto& k : GetAllEvalAutomorphismKeys()) {
      if (k.second->begin()->second->GetCryptoContext() == cc) {
        omap[k.first] = k.second;
      }
    }

    if (omap.size() == 0) return false;

    Serial::Serialize(omap, ser, sertype);
    return true;
  }

  /**
   * DeserializeEvalAutomorphismKey deserialize all keys in the serialization
   * deserialized keys silently replace any existing matching keys
   * deserialization will create CryptoContextImpl if necessary
   *
   * @param ser - stream to serialize from
   * @param sertype - type of serialization
   * @return true on success
   */
  template <typename ST>
  static bool DeserializeEvalAutomorphismKey(std::istream& ser,
                                             const ST& sertype) {
    std::map<string, shared_ptr<std::map<usint, LPEvalKey<Element>>>>
        evalSumKeys;

    Serial::Deserialize(evalSumKeys, ser, sertype);

    // The deserialize call created any contexts that needed to be created....
    // so all we need to do is put the keys into the maps for their context

    for (auto k : evalSumKeys) {
      GetAllEvalAutomorphismKeys()[k.first] = k.second;
    }

    return true;
  }

  /**
   * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache
   */
  static void ClearEvalAutomorphismKeys();

  /**
   * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given id
   * @param id
   */
  static void ClearEvalAutomorphismKeys(const string& id);

  /**
   * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given
   * context
   * @param cc
   */
  static void ClearEvalAutomorphismKeys(const CryptoContext<Element> cc);

  /**
   * InsertEvalAutomorphismKey - add the given map of keys to the map, replacing
   * the existing map if there
   * @param mapToInsert
   */
  static void InsertEvalAutomorphismKey(
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> mapToInsert);

  // TURN FEATURES ON
  /**
   * Enable a particular feature for use with this CryptoContextImpl
   * @param feature - the feature that should be enabled
   */
  void Enable(PKESchemeFeature feature) { scheme->Enable(feature); }

  /**
   * Enable several features at once
   * @param featureMask - bitwise or of several PKESchemeFeatures
   */
  void Enable(usint featureMask) { scheme->Enable(featureMask); }

  // GETTERS
  /**
   * Getter for Scheme
   * @return scheme
   */
  const shared_ptr<LPPublicKeyEncryptionScheme<Element>>
  GetEncryptionAlgorithm() const {
    return scheme;
  }

  /**
   * Getter for CryptoParams
   * @return params
   */
  const shared_ptr<LPCryptoParameters<Element>> GetCryptoParameters() const {
    return params;
  }

  size_t GetKeyGenLevel() const { return m_keyGenLevel; }

  void SetKeyGenLevel(size_t level) { m_keyGenLevel = level; }

  /**
   * Getter for element params
   * @return
   */
  const shared_ptr<ParmType> GetElementParams() const {
    return params->GetElementParams();
  }

  /**
   * Getter for encoding params
   * @return
   */
  const EncodingParams GetEncodingParams() const {
    return params->GetEncodingParams();
  }

  /**
   * Get the cyclotomic order used for this context
   *
   * @return
   */
  usint GetCyclotomicOrder() const {
    return params->GetElementParams()->GetCyclotomicOrder();
  }

  /**
   * Get the ring dimension used for this context
   *
   * @return
   */
  usint GetRingDimension() const {
    return params->GetElementParams()->GetRingDimension();
  }

  /**
   * Get the ciphertext modulus used for this context
   *
   * @return
   */
  const IntType& GetModulus() const {
    return params->GetElementParams()->GetModulus();
  }

  /**
   * Get the ciphertext modulus used for this context
   *
   * @return
   */
  const IntType& GetRootOfUnity() const {
    return params->GetElementParams()->GetRootOfUnity();
  }

  /**
   * KeyGen generates a key pair using this algorithm's KeyGen method
   * @return a public/secret key pair
   */
  LPKeyPair<Element> KeyGen() {
    auto r = GetEncryptionAlgorithm()->KeyGen(
        CryptoContextFactory<Element>::GetContextForPointer(this), false);
    return r;
  }

  /**
   * Threshold FHE: Generation of a public key derived
   * from a previous joined public key (for prior secret shares) and the secret
   * key share of the current party.
   *
   * @param pk joined public key from prior parties.
   * @param makeSparse set to true if ring reduce by a factor of 2 is to be
   * used. NOT SUPPORTED BY ANY SCHEME ANYMORE.
   * @param fresh set to true if proxy re-encryption is used in the multi-party
   * protocol or star topology is used
   * @return key pair including the secret share for the current party and
   * joined public key
   */
  LPKeyPair<Element> MultipartyKeyGen(const LPPublicKey<Element> pk,
                                      bool makeSparse = false,
                                      bool fresh = false) {
    if (!pk) PALISADE_THROW(config_error, "Input public key is empty");
    auto r = GetEncryptionAlgorithm()->MultipartyKeyGen(
        CryptoContextFactory<Element>::GetContextForPointer(this), pk,
        makeSparse, fresh);
    return r;
  }

  /**
   * Threshold FHE: Generates a public key from a vector of secret shares.
   * ONLY FOR DEBUGGIN PURPOSES. SHOULD NOT BE USED IN PRODUCTION.
   *
   * @param secretkeys secrete key shares.
   * @return key pair including the private for the current party and joined
   * public key
   */
  LPKeyPair<Element> MultipartyKeyGen(
      const vector<LPPrivateKey<Element>>& secretKeys) {
    if (!secretKeys.size())
      PALISADE_THROW(config_error, "Input private key vector is empty");
    auto r = GetEncryptionAlgorithm()->MultipartyKeyGen(
        CryptoContextFactory<Element>::GetContextForPointer(this), secretKeys,
        false);
    return r;
  }

  /**
   * Threshold FHE: Method for decryption operation run by the lead decryption
   * client
   *
   * @param privateKey secret key share used for decryption.
   * @param ciphertext ciphertext id decrypted.
   */
  vector<Ciphertext<Element>> MultipartyDecryptLead(
      const LPPrivateKey<Element> privateKey,
      const vector<Ciphertext<Element>>& ciphertext) const {
    if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext()))
      PALISADE_THROW(config_error,
                     "Information passed to MultipartyDecryptLead was not "
                     "generated with this crypto context");

    vector<Ciphertext<Element>> newCiphertext;

    for (size_t i = 0; i < ciphertext.size(); i++) {
      if (ciphertext[i] == nullptr ||
          Mismatched(ciphertext[i]->GetCryptoContext()))
        PALISADE_THROW(config_error,
                       "A ciphertext passed to MultipartyDecryptLead was not "
                       "generated with this crypto context");

      newCiphertext.push_back(GetEncryptionAlgorithm()->MultipartyDecryptLead(
          privateKey, ciphertext[i]));
    }

    return newCiphertext;
  }

  /**
   * Threshold FHE: "Partial" decryption computed by all parties except for the
   * lead one
   *
   * @param privateKey secret key share used for decryption.
   * @param ciphertext ciphertext that is being decrypted.
   */
  vector<Ciphertext<Element>> MultipartyDecryptMain(
      const LPPrivateKey<Element> privateKey,
      const vector<Ciphertext<Element>>& ciphertext) const {
    if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext()))
      PALISADE_THROW(config_error,
                     "Information passed to MultipartyDecryptMain was not "
                     "generated with this crypto context");

    vector<Ciphertext<Element>> newCiphertext;

    for (size_t i = 0; i < ciphertext.size(); i++) {
      if (ciphertext[i] == nullptr ||
          Mismatched(ciphertext[i]->GetCryptoContext()))
        PALISADE_THROW(config_error,
                       "A ciphertext passed to MultipartyDecryptMain was not "
                       "generated with this crypto context");

      newCiphertext.push_back(GetEncryptionAlgorithm()->MultipartyDecryptMain(
          privateKey, ciphertext[i]));
    }

    return newCiphertext;
  }

  /**
   * Threshold FHE: Method for combining the partially decrypted ciphertexts
   * and getting the final decryption in the clear.
   *
   * @param &partialCiphertextVec vector of "partial" decryptions.
   * @param *plaintext the plaintext output.
   * @return the decoding result.
   */
  DecryptResult MultipartyDecryptFusion(
      const vector<Ciphertext<Element>>& partialCiphertextVec,
      Plaintext* plaintext) const;

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
      const LPEvalKey<Element> ek) const {
    if (!originalPrivateKey)
      PALISADE_THROW(config_error, "Input first private key is nullptr");
    if (!newPrivateKey)
      PALISADE_THROW(config_error, "Input second private key is nullptr");
    if (!ek) PALISADE_THROW(config_error, "Input evaluation key is nullptr");
    auto r = GetEncryptionAlgorithm()->MultiKeySwitchGen(originalPrivateKey,
                                                         newPrivateKey, ek);
    return r;
  }

  /**
   * Threshold FHE: Generates joined automorphism keys
   * from the current secret share and prior joined
   * automorphism keys
   *
   * @param privateKey secret key share.
   * @param eAuto a dictionary with prior joined automorphism keys.
   * @param &indexList a vector of automorphism indices.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return a dictionary with new joined automorphism keys.
   */
  shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiEvalAutomorphismKeyGen(
      const LPPrivateKey<Element> privateKey,
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> eAuto,
      const std::vector<usint>& indexList, const std::string& keyId = "") {
    if (!privateKey)
      PALISADE_THROW(config_error, "Input private key is nullptr");
    if (!eAuto)
      PALISADE_THROW(config_error, "Input evaluation key map is nullptr");
    if (!indexList.size())
      PALISADE_THROW(config_error, "Input index vector is empty");
    auto r = GetEncryptionAlgorithm()->MultiEvalAutomorphismKeyGen(
        privateKey, eAuto, indexList, keyId);
    return r;
  }

  /**
   * Threshold FHE: Generates joined rotation keys
   * from the current secret share and prior joined
   * rotation keys
   *
   * @param privateKey secret key share.
   * @param eAuto a dictionary with prior joined rotation keys.
   * @param &indexList a vector of rotation indices.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return a dictionary with new joined rotation keys.
   */
  shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiEvalAtIndexKeyGen(
      const LPPrivateKey<Element> privateKey,
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> eAuto,
      const std::vector<int32_t>& indexList, const std::string& keyId = "") {
    if (!privateKey)
      PALISADE_THROW(config_error, "Input private key is nullptr");
    if (!eAuto)
      PALISADE_THROW(config_error, "Input evaluation key map is nullptr");
    if (!indexList.size())
      PALISADE_THROW(config_error, "Input index vector is empty");
    auto r = GetEncryptionAlgorithm()->MultiEvalAtIndexKeyGen(privateKey, eAuto,
                                                              indexList, keyId);
    return r;
  }

  /**
   * Threshold FHE: Generates joined summation evaluation keys
   * from the current secret share and prior joined
   * summation keys
   *
   * @param privateKey secret key share.
   * @param eSum a dictionary with prior joined summation keys.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return new joined summation keys.
   */
  shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiEvalSumKeyGen(
      const LPPrivateKey<Element> privateKey,
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> eSum,
      const std::string& keyId = "") {
    if (!privateKey)
      PALISADE_THROW(config_error, "Input private key is nullptr");
    if (!eSum)
      PALISADE_THROW(config_error, "Input evaluation key map is nullptr");
    auto r =
        GetEncryptionAlgorithm()->MultiEvalSumKeyGen(privateKey, eSum, keyId);
    return r;
  }

  /**
   * Threshold FHE: Adds two prior evaluation keys
   *
   * @param a first evaluation key.
   * @param b second evaluation key.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return the new joined key.
   */
  LPEvalKey<Element> MultiAddEvalKeys(LPEvalKey<Element> a,
                                      LPEvalKey<Element> b,
                                      const std::string& keyId = "") {
    if (!a)
      PALISADE_THROW(config_error, "Input first evaluation key is nullptr");
    if (!b)
      PALISADE_THROW(config_error, "Input second evaluation key is nullptr");
    auto r = GetEncryptionAlgorithm()->MultiAddEvalKeys(a, b, keyId);
    return r;
  }

  /**
   * Threshold FHE: Generates a partial evaluation key for homomorphic
   * multiplication based on the current secret share and an existing partial
   * evaluation key
   *
   * @param evalKey prior evaluation key.
   * @param sk current secret share.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return the new joined key.
   */
  LPEvalKey<Element> MultiMultEvalKey(LPEvalKey<Element> evalKey,
                                      LPPrivateKey<Element> sk,
                                      const std::string& keyId = "") {
    if (!evalKey)
      PALISADE_THROW(config_error, "Input evaluation key is nullptr");
    if (!sk) PALISADE_THROW(config_error, "Input private key is nullptr");
    auto r = GetEncryptionAlgorithm()->MultiMultEvalKey(evalKey, sk, keyId);
    return r;
  }

  /**
   * Threshold FHE: Adds two prior evaluation key sets for summation
   *
   * @param es1 first summation key set.
   * @param es2 second summation key set.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return the new joined key set for summation.
   */
  shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiAddEvalSumKeys(
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> es1,
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> es2,
      const std::string& keyId = "") {
    if (!es1)
      PALISADE_THROW(config_error, "Input first evaluation key map is nullptr");
    if (!es2)
      PALISADE_THROW(config_error,
                     "Input second evaluation key map is nullptr");
    auto r = GetEncryptionAlgorithm()->MultiAddEvalSumKeys(es1, es2, keyId);
    return r;
  }

  /**
   * Threshold FHE: Adds two prior evaluation key sets for automorphisms
   *
   * @param es1 first automorphism key set.
   * @param es2 second automorphism key set.
   * @param keyId - new key identifier used for the resulting evaluation key.
   * @return the new joined key set for summation.
   */
  shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiAddEvalAutomorphismKeys(
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> es1,
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> es2,
      const std::string& keyId = "") {
    if (!es1)
      PALISADE_THROW(config_error, "Input first evaluation key map is nullptr");
    if (!es2)
      PALISADE_THROW(config_error,
                     "Input second evaluation key map is nullptr");
    auto r =
        GetEncryptionAlgorithm()->MultiAddEvalAutomorphismKeys(es1, es2, keyId);
    return r;
  }

  /**
   * Threshold FHE: Adds two  partial public keys
   *
   * @param pubKey1 first public key.
   * @param pubKey2 second public key.
   * @param keyId - new key identifier used for the resulting evaluation key.
   * @return the new joined key.
   */
  LPPublicKey<Element> MultiAddPubKeys(LPPublicKey<Element> pubKey1,
                                       LPPublicKey<Element> pubKey2,
                                       const std::string& keyId = "") {
    if (!pubKey1)
      PALISADE_THROW(config_error, "Input first public key is nullptr");
    if (!pubKey2)
      PALISADE_THROW(config_error, "Input second public key is nullptr");

    auto r = GetEncryptionAlgorithm()->MultiAddPubKeys(pubKey1, pubKey2, keyId);
    return r;
  }

  /**
   * Threshold FHE: Adds two  partial evaluation keys for multiplication
   *
   * @param evalKey1 first evaluation key.
   * @param evalKey2 second evaluation key.
   * @param keyId - new key identifier used for the resulting evaluation key.
   * @return the new joined key.
   */
  LPEvalKey<Element> MultiAddEvalMultKeys(LPEvalKey<Element> evalKey1,
                                          LPEvalKey<Element> evalKey2,
                                          const std::string& keyId = "") {
    if (!evalKey1)
      PALISADE_THROW(config_error, "Input first evaluation key is nullptr");
    if (!evalKey2)
      PALISADE_THROW(config_error, "Input second evaluation key is nullptr");
    auto r = GetEncryptionAlgorithm()->MultiAddEvalMultKeys(evalKey1, evalKey2,
                                                            keyId);
    return r;
  }

  /**
   * SparseKeyGen generates a key pair with special structure, and without full
   * entropy, for use in special cases like Ring Reduction
   * @return a public/secret key pair
   */
  LPKeyPair<Element> SparseKeyGen() {
    auto r = GetEncryptionAlgorithm()->KeyGen(
        CryptoContextFactory<Element>::GetContextForPointer(this), true);
    return r;
  }

  /**
   * ReKeyGen produces an Eval Key that PALISADE can use for Proxy Re Encryption
   * @param newKey (public)
   * @param oldKey (private)
   * @return new evaluation key
   */
  LPEvalKey<Element> ReKeyGen(const LPPublicKey<Element> newKey,
                              const LPPrivateKey<Element> oldKey) const {
    if (newKey == nullptr || oldKey == nullptr ||
        Mismatched(newKey->GetCryptoContext()) ||
        Mismatched(oldKey->GetCryptoContext()))
      PALISADE_THROW(config_error,
                     "Keys passed to ReKeyGen were not generated with this "
                     "crypto context");

    auto r = GetEncryptionAlgorithm()->ReKeyGen(newKey, oldKey);
    return r;
  }

  /**
   * ReKeyGen produces an Eval Key that PALISADE can use for Proxy Re Encryption
   * NOTE this functionality has been completely removed from PALISADE
   * @param newKey (private)
   * @param oldKey (private)
   * @return new evaluation key
   */
  LPEvalKey<Element> ReKeyGen(const LPPrivateKey<Element> newKey,
                              const LPPrivateKey<Element> oldKey) const
      __attribute__((deprecated("functionality removed from PALISADE")));

  /**
   * EvalMultKeyGen creates a key that can be used with the PALISADE EvalMult
   * operator
   * the new evaluation key is stored in cryptocontext
   * @param key
   */
  void EvalMultKeyGen(const LPPrivateKey<Element> key);

  /**
   * EvalMultsKeyGen creates a vector evalmult keys that can be used with the
   * PALISADE EvalMult operator 1st key (for s^2) is used for multiplication of
   * ciphertexts of depth 1 2nd key (for s^3) is used for multiplication of
   * ciphertexts of depth 2, etc.
   * a vector of new evaluation keys is stored in crytpocontext
   *
   * @param key
   */
  void EvalMultKeysGen(const LPPrivateKey<Element> key);

  /**
   * GetEvalMultKeyVector fetches the eval mult keys for a given KeyID
   * @param keyID
   * @return key vector from ID
   */
  static const vector<LPEvalKey<Element>>& GetEvalMultKeyVector(
      const string& keyID);

  /**
   * GetEvalMultKeys
   * @return map of all the keys
   */
  static std::map<string, std::vector<LPEvalKey<Element>>>&
  GetAllEvalMultKeys();

  /**
   * KeySwitchGen creates a key that can be used with the PALISADE KeySwitch
   * operation
   * @param key1
   * @param key2
   * @return new evaluation key
   */
  LPEvalKey<Element> KeySwitchGen(const LPPrivateKey<Element> key1,
                                  const LPPrivateKey<Element> key2) const {
    if (key1 == nullptr || key2 == nullptr ||
        Mismatched(key1->GetCryptoContext()) ||
        Mismatched(key2->GetCryptoContext()))
      PALISADE_THROW(config_error,
                     "Keys passed to KeySwitchGen were not generated with this "
                     "crypto context");

    auto r = GetEncryptionAlgorithm()->KeySwitchGen(key1, key2);
    return r;
  }

  /**
   * Encrypt a plaintext using a given public key
   * @param publicKey
   * @param plaintext
   * @return ciphertext (or null on failure)
   */
  Ciphertext<Element> Encrypt(const LPPublicKey<Element> publicKey,
                              Plaintext plaintext) {
    if (publicKey == nullptr)
      PALISADE_THROW(type_error, "null key passed to Encrypt");

    if (plaintext == nullptr)
      PALISADE_THROW(type_error, "Input plaintext is nullptr");

    if (Mismatched(publicKey->GetCryptoContext()))
      PALISADE_THROW(
          config_error,
          "key passed to Encrypt was not generated with this crypto context");

    Ciphertext<Element> ciphertext = GetEncryptionAlgorithm()->Encrypt(
        publicKey, plaintext->GetElement<Element>());

    if (ciphertext) {
      ciphertext->SetEncodingType(plaintext->GetEncodingType());
      ciphertext->SetScalingFactor(plaintext->GetScalingFactor());
      ciphertext->SetDepth(plaintext->GetDepth());
      ciphertext->SetLevel(plaintext->GetLevel());
    }

    return ciphertext;
  }

  /**
   * Encrypt a plaintext using a given private key
   * @param privateKey
   * @param plaintext
   * @return ciphertext (or null on failure)
   */
  Ciphertext<Element> Encrypt(const LPPrivateKey<Element> privateKey,
                              Plaintext plaintext) const {
    if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext()))
      PALISADE_THROW(
          config_error,
          "key passed to Encrypt was not generated with this crypto context");
    if (plaintext == nullptr)
      PALISADE_THROW(type_error, "Input plaintext is nullptr");

    Ciphertext<Element> ciphertext = GetEncryptionAlgorithm()->Encrypt(
        privateKey, plaintext->GetElement<Element>());

    if (ciphertext) {
      ciphertext->SetEncodingType(plaintext->GetEncodingType());
      ciphertext->SetScalingFactor(plaintext->GetScalingFactor());
      ciphertext->SetDepth(plaintext->GetDepth());
      ciphertext->SetLevel(plaintext->GetLevel());
    }

    return ciphertext;
  }

  // PLAINTEXT FACTORY METHODS
  // TODO to be deprecated in 2.0
  /**
   * MakeStringPlaintext constructs a StringEncoding in this context
   * @param str
   * @return plaintext
   */
  Plaintext MakeStringPlaintext(const string& str) const {
    auto p = PlaintextFactory::MakePlaintext(String, this->GetElementParams(),
                                             this->GetEncodingParams(), str);
    return p;
  }

  /**
   * MakeCoefPackedPlaintext constructs a CoefPackedEncoding in this context
   * @param value
   * @return plaintext
   */
  Plaintext MakeCoefPackedPlaintext(const vector<int64_t>& value) const {
    auto p = PlaintextFactory::MakePlaintext(
        CoefPacked, this->GetElementParams(), this->GetEncodingParams(), value);
    return p;
  }

  /**
   * MakePackedPlaintext constructs a PackedEncoding in this context
   * @param value
   * @return plaintext
   */
  Plaintext MakePackedPlaintext(const vector<int64_t>& value) const {
    auto p = PlaintextFactory::MakePlaintext(Packed, this->GetElementParams(),
                                             this->GetEncodingParams(), value);
    return p;
  }

  /**
   * MakePlaintext static that takes a cc and calls the Plaintext Factory
   * @param encoding
   * @param cc
   * @param value
   * @return
   */
  template <typename Value1>
  static Plaintext MakePlaintext(PlaintextEncodings encoding,
                                 CryptoContext<Element> cc,
                                 const Value1& value) {
    return PlaintextFactory::MakePlaintext(encoding, cc->GetElementParams(),
                                           cc->GetEncodingParams(), value);
  }

  template <typename Value1, typename Value2>
  static Plaintext MakePlaintext(PlaintextEncodings encoding,
                                 CryptoContext<Element> cc, const Value1& value,
                                 const Value2& value2) {
    return PlaintextFactory::MakePlaintext(encoding, cc->GetElementParams(),
                                           cc->GetEncodingParams(), value,
                                           value2);
  }

  /**
   * COMPLEX ARITHMETIC IS NOT AVAILABLE STARTING WITH 1.10.6,
   * AND THIS METHOD BE DEPRECATED. USE THE REAL-NUMBER METHOD INSTEAD.
   * MakeCKKSPackedPlaintext constructs a CKKSPackedEncoding in this context
   * from a vector of complex numbers
   * @param value - input vector
   * @paran depth - depth used to encode the vector
   * @param level - level at each the vector will get encrypted
   * @param params - parameters to be usef for the ciphertext
   * @return plaintext
   */
  virtual Plaintext MakeCKKSPackedPlaintext(
      const std::vector<std::complex<double>>& value, size_t depth = 1,
      uint32_t level = 0, const shared_ptr<ParmType> params = nullptr) const {
    Plaintext p;
    const auto cryptoParamsCKKS =
        std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
            this->GetCryptoParameters());

    double scFact = cryptoParamsCKKS->GetScalingFactorOfLevel(level);

    if (params == nullptr) {
      shared_ptr<ILDCRTParams<DCRTPoly::Integer>> elemParamsPtr;
      if (level != 0) {
        ILDCRTParams<DCRTPoly::Integer> elemParams =
            *(cryptoParamsCKKS->GetElementParams());
        for (uint32_t i = 0; i < level; i++) {
          elemParams.PopLastParam();
        }
        elemParamsPtr =
            std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(elemParams);
      } else {
        elemParamsPtr = cryptoParamsCKKS->GetElementParams();
      }

      p = Plaintext(std::make_shared<CKKSPackedEncoding>(
          elemParamsPtr, this->GetEncodingParams(), value, depth, level,
          scFact));
    } else {
      p = Plaintext(std::make_shared<CKKSPackedEncoding>(
          params, this->GetEncodingParams(), value, depth, level, scFact));
    }

    p->Encode();
    return p;
  }

  /**
   * MakeCKKSPackedPlaintext constructs a CKKSPackedEncoding in this context
   * from a vector of real numbers
   * @param value - input vector
   * @paran depth - depth used to encode the vector
   * @param level - level at each the vector will get encrypted
   * @param params - parameters to be usef for the ciphertext
   * @return plaintext
   */
  virtual Plaintext MakeCKKSPackedPlaintext(
      const std::vector<double>& value, size_t depth = 1, uint32_t level = 0,
      const shared_ptr<ParmType> params = nullptr) const {
    std::vector<std::complex<double>> complexValue(value.size());
    std::transform(value.begin(), value.end(), complexValue.begin(),
                   [](double da) { return std::complex<double>(da); });

    return MakeCKKSPackedPlaintext(complexValue, depth, level, params);
  }

  /**
   * GetPlaintextForDecrypt returns a new Plaintext to be used in decryption.
   *
   * @param pte Type of plaintext we want to return
   * @param evp Element parameters
   * @param ep Encoding parameters
   * @return plaintext
   */
  static Plaintext GetPlaintextForDecrypt(PlaintextEncodings pte,
                                          shared_ptr<ParmType> evp,
                                          EncodingParams ep);

 public:
  /**
   * Decrypt a single ciphertext into the appropriate plaintext
   *
   * @param privateKey - decryption key
   * @param ciphertext - ciphertext to decrypt
   * @param plaintext - resulting plaintext object pointer is here
   * @return
   */
  DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
                        ConstCiphertext<Element> ciphertext,
                        Plaintext* plaintext);

  /**
   * ReEncrypt - Proxy Re Encryption mechanism for PALISADE
   * @param evalKey - evaluation key from the PRE keygen method
   * @param ciphertext - vector of shared pointers to encrypted Ciphertext
   * @param publicKey the public key of the recipient of the re-encrypted
   * ciphertext.
   * @return vector of shared pointers to re-encrypted ciphertexts
   */
  Ciphertext<Element> ReEncrypt(
      LPEvalKey<Element> evalKey, ConstCiphertext<Element> ciphertext,
      const LPPublicKey<Element> publicKey = nullptr) const {
    if (evalKey == nullptr || Mismatched(evalKey->GetCryptoContext()))
      PALISADE_THROW(config_error,
                     "Information passed to ReEncrypt was not generated with "
                     "this crypto context");

    if (ciphertext == nullptr || Mismatched(ciphertext->GetCryptoContext()))
      PALISADE_THROW(config_error,
                     "The ciphertext passed to ReEncrypt was not generated "
                     "with this crypto context");

    Ciphertext<Element> newCiphertext =
        GetEncryptionAlgorithm()->ReEncrypt(evalKey, ciphertext, publicKey);

    return newCiphertext;
  }

  /**
   * EvalAdd - PALISADE EvalAdd method for a pair of ciphertexts
   * @param ct1
   * @param ct2
   * @return new ciphertext for ct1 + ct2
   */
  Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ct1,
                              ConstCiphertext<Element> ct2) const {
    TypeCheck(ct1, ct2);

    auto rv = GetEncryptionAlgorithm()->EvalAdd(ct1, ct2);
    return rv;
  }

  /**
   * EvalAdd - PALISADE EvalAddInPlace method for a pair of ciphertexts
   * @param ct1 Input/output ciphertext
   * @param ct2 Input cipherext
   * @return \p ct1 contains \p ct1 + \p ct2
   */
  void EvalAddInPlace(Ciphertext<Element>& ct1,
                      ConstCiphertext<Element> ct2) const {
    TypeCheck(ct1, ct2);

    GetEncryptionAlgorithm()->EvalAddInPlace(ct1, ct2);
  }

  /**
   * EvalAdd - PALISADE EvalAddMutable method for a pair of ciphertexts.
   * This is a mutable version - input ciphertexts may get automatically
   * rescaled, or level-reduced.
   *
   * @param ct1
   * @param ct2
   * @return new ciphertext for ct1 + ct2
   */
  Ciphertext<Element> EvalAddMutable(Ciphertext<Element>& ct1,
                                     Ciphertext<Element>& ct2) const {
    TypeCheck(ct1, ct2);

    auto rv = GetEncryptionAlgorithm()->EvalAddMutable(ct1, ct2);
    return rv;
  }

  /**
   * EvalSub - PALISADE EvalSub method for a pair of ciphertexts
   * @param ct1
   * @param ct2
   * @return new ciphertext for ct1 - ct2
   */
  Ciphertext<Element> EvalSub(ConstCiphertext<Element> ct1,
                              ConstCiphertext<Element> ct2) const {
    TypeCheck(ct1, ct2);

    auto rv = GetEncryptionAlgorithm()->EvalSub(ct1, ct2);
    return rv;
  }

  /**
   * EvalSub - PALISADE EvalSubMutable method for a pair of ciphertexts
   * This is a mutable version - input ciphertexts may get automatically
   * rescaled, or level-reduced.
   *
   * @param ct1
   * @param ct2
   * @return new ciphertext for ct1 - ct2
   */
  Ciphertext<Element> EvalSubMutable(Ciphertext<Element>& ct1,
                                     Ciphertext<Element>& ct2) const {
    TypeCheck(ct1, ct2);

    auto rv = GetEncryptionAlgorithm()->EvalSubMutable(ct1, ct2);
    return rv;
  }

  /**
   * EvalAdd - PALISADE EvalAdd method for a ciphertext and plaintext
   * @param ciphertext
   * @param plaintext
   * @return new ciphertext for ciphertext + plaintext
   */
  Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext,
                              ConstPlaintext plaintext) const {
    TypeCheck(ciphertext, plaintext);

    plaintext->SetFormat(EVALUATION);

    auto rv = GetEncryptionAlgorithm()->EvalAdd(ciphertext, plaintext);
    return rv;
  }

  /**
   * EvalAdd - PALISADE EvalAddMutable method for a ciphertext and plaintext
   * This is a mutable version - input ciphertexts may get automatically
   * rescaled, or level-reduced.
   *
   * @param ciphertext
   * @param plaintext
   * @return new ciphertext for ciphertext + plaintext
   */
  Ciphertext<Element> EvalAddMutable(Ciphertext<Element>& ciphertext,
                                     Plaintext plaintext) const {
    TypeCheck((ConstCiphertext<Element>)ciphertext, (ConstPlaintext)plaintext);

    plaintext->SetFormat(EVALUATION);

    auto rv = GetEncryptionAlgorithm()->EvalAddMutable(ciphertext, plaintext);
    return rv;
  }

  /**
   * EvalAdd - PALISADE EvalAdd method for a ciphertext and constant
   * @param ciphertext
   * @param constant
   * @return new ciphertext for ciphertext + constant
   */
  Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext,
                              double constant) const {
    Ciphertext<Element> rv;

    if (constant >= 0) {
      rv = GetEncryptionAlgorithm()->EvalAdd(ciphertext, constant);
    } else {
      rv = GetEncryptionAlgorithm()->EvalSub(ciphertext, -constant);
    }

    return rv;
  }

  /**
   * EvalLinearWSum - PALISADE EvalLinearWSum method to compute a linear
   * weighted sum
   *
   * @param ciphertexts a list of ciphertexts
   * @param constants a list of weights
   * @return new ciphertext containing the weighted sum
   */
  Ciphertext<Element> EvalLinearWSum(vector<Ciphertext<Element>> ciphertexts,
                                     vector<double> constants) const {
    auto rv = GetEncryptionAlgorithm()->EvalLinearWSum(ciphertexts, constants);
    return rv;
  }

  /**
   * EvalLinearWSum - method to compute a linear weighted sum.
   * This is a mutable version, meaning the level/depth of input
   * ciphertexts may change in the process.
   *
   * @param ciphertexts a list of ciphertexts
   * @param constants a list of weights
   * @return new ciphertext containing the weighted sum
   */
  Ciphertext<Element> EvalLinearWSumMutable(
      vector<Ciphertext<Element>> ciphertexts, vector<double> constants) const {
    auto rv =
        GetEncryptionAlgorithm()->EvalLinearWSumMutable(ciphertexts, constants);
    return rv;
  }

  inline Ciphertext<Element> EvalLinearWSum(
      vector<double> constants, vector<Ciphertext<Element>> ciphertexts) const {
    return EvalLinearWSum(ciphertexts, constants);
  }

  inline Ciphertext<Element> EvalLinearWSumMutable(
      vector<double> constants, vector<Ciphertext<Element>> ciphertexts) const {
    return EvalLinearWSumMutable(ciphertexts, constants);
  }

  inline Ciphertext<Element> EvalAdd(
      ConstPlaintext plaintext, ConstCiphertext<Element> ciphertext) const {
    return EvalAdd(ciphertext, plaintext);
  }

  inline Ciphertext<Element> EvalAddMutable(
      Plaintext plaintext, Ciphertext<Element>& ciphertext) const {
    return EvalAddMutable(ciphertext, plaintext);
  }

  inline Ciphertext<Element> EvalAdd(
      double constant, ConstCiphertext<Element> ciphertext) const {
    return EvalAdd(ciphertext, constant);
  }

  /**
   * EvalSubPlain - PALISADE EvalSub method for a ciphertext and plaintext
   * @param ciphertext
   * @param plaintext
   * @return new ciphertext for ciphertext - plaintext
   */
  Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext,
                              ConstPlaintext plaintext) const {
    TypeCheck(ciphertext, plaintext);

    auto rv = GetEncryptionAlgorithm()->EvalSub(ciphertext, plaintext);
    return rv;
  }

  /**
   * EvalSubPlain - PALISADE EvalSubMutable method for a ciphertext and
   * plaintext This is a mutable version - input ciphertexts may get
   * automatically rescaled, or level-reduced.
   *
   * @param ciphertext
   * @param plaintext
   * @return new ciphertext for ciphertext - plaintext
   */
  Ciphertext<Element> EvalSubMutable(Ciphertext<Element>& ciphertext,
                                     Plaintext plaintext) const {
    TypeCheck((ConstCiphertext<Element>)ciphertext, (ConstPlaintext)plaintext);

    auto rv = GetEncryptionAlgorithm()->EvalSubMutable(ciphertext, plaintext);
    return rv;
  }

  /**
   * EvalSub - PALISADE EvalSub method for a ciphertext and constant
   * @param ciphertext
   * @param constant
   * @return new ciphertext for ciphertext - constant
   */
  Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext,
                              double constant) const {
    Ciphertext<Element> rv;

    if (constant >= 0) {
      rv = GetEncryptionAlgorithm()->EvalSub(ciphertext, constant);
    } else {
      rv = GetEncryptionAlgorithm()->EvalAdd(ciphertext, -constant);
    }

    return rv;
  }

  inline Ciphertext<Element> EvalSub(
      ConstPlaintext plaintext, ConstCiphertext<Element> ciphertext) const {
    return EvalAdd(EvalNegate(ciphertext), plaintext);
  }

  inline Ciphertext<Element> EvalSubMutable(
      Plaintext plaintext, Ciphertext<Element>& ciphertext) const {
    Ciphertext<Element> negated = EvalNegate(ciphertext);
    Ciphertext<Element> result = EvalAddMutable(negated, plaintext);
    ciphertext = EvalNegate(negated);
    return result;
  }

  inline Ciphertext<Element> EvalSub(
      double constant, ConstCiphertext<Element> ciphertext) const {
    return EvalAdd(EvalNegate(ciphertext), constant);
  }

  /**
   * EvalMult - PALISADE EvalMult method for a pair of ciphertexts - with key
   * switching
   * @param ct1
   * @param ct2
   * @return new ciphertext for ct1 * ct2
   */
  Ciphertext<Element> EvalMult(ConstCiphertext<Element> ct1,
                               ConstCiphertext<Element> ct2) const {
    TypeCheck(ct1, ct2);

    auto ek = GetEvalMultKeyVector(ct1->GetKeyTag());
    if (!ek.size()) {
      PALISADE_THROW(type_error,
                     "Evaluation key has not been generated for EvalMult");
    }

    auto rv = GetEncryptionAlgorithm()->EvalMult(ct1, ct2, ek[0]);
    return rv;
  }

  /**
   * EvalMult - PALISADE EvalMult method for a pair of ciphertexts - with key
   * switching This is a mutable version - input ciphertexts may get
   * automatically rescaled, or level-reduced.
   *
   * @param ct1
   * @param ct2
   * @return new ciphertext for ct1 * ct2
   */
  Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ct1,
                                      Ciphertext<Element>& ct2) const {
    TypeCheck(ct1, ct2);

    auto ek = GetEvalMultKeyVector(ct1->GetKeyTag());
    if (!ek.size()) {
      PALISADE_THROW(type_error,
                     "Evaluation key has not been generated for EvalMult");
    }

    auto rv = GetEncryptionAlgorithm()->EvalMultMutable(ct1, ct2, ek[0]);
    return rv;
  }

  /**
   * EvalMult - PALISADE EvalMult method for a pair of ciphertexts - no key
   * switching (relinearization)
   * @param ct1
   * @param ct2
   * @return new ciphertext for ct1 * ct2
   */
  Ciphertext<Element> EvalMultNoRelin(ConstCiphertext<Element> ct1,
                                      ConstCiphertext<Element> ct2) const {
    TypeCheck(ct1, ct2);

    auto rv = GetEncryptionAlgorithm()->EvalMult(ct1, ct2);
    return rv;
  }

  /**
   * EvalMultMany - PALISADE function for evaluating multiplication on
   * ciphertext followed by relinearization operation (at the end). It computes
   * the multiplication in a binary tree manner. Also, it reduces the number of
   * elements in the ciphertext to two after each multiplication.
   * Currently it assumes that the consecutive two input arguments have
   * total depth smaller than the supported depth. Otherwise, it throws an
   * error.
   *
   * @param cipherTextList  is the ciphertext list.
   *
   * @return new ciphertext.
   */
  Ciphertext<Element> EvalMultMany(
      const vector<Ciphertext<Element>>& ct) const {
    // input parameter check
    if (!ct.size()) PALISADE_THROW(type_error, "Empty input ciphertext vector");

    const auto ek = GetEvalMultKeyVector(ct[0]->GetKeyTag());
    if (ek.size() < (ct[0]->GetElements().size() - 2)) {
      PALISADE_THROW(type_error,
                     "Insufficient value was used for maxDepth to generate "
                     "keys for EvalMult");
    }

    auto rv = GetEncryptionAlgorithm()->EvalMultMany(ct, ek);
    return rv;
  }

  /**
   * EvalAddMany - Evaluate addition on a vector of ciphertexts.
   * It computes the addition in a binary tree manner.
   *
   * @param ctList is the list of ciphertexts.
   *
   * @return new ciphertext.
   */
  Ciphertext<Element> EvalAddMany(
      const vector<Ciphertext<Element>>& ctList) const {
    // input parameter check
    if (!ctList.size())
      PALISADE_THROW(type_error, "Empty input ciphertext vector");

    auto rv = GetEncryptionAlgorithm()->EvalAddMany(ctList);
    return rv;
  }

  /**
   * EvalAddManyInPlace - Evaluate addition on a vector of ciphertexts.
   * Addition is computed in a binary tree manner. Difference with EvalAddMany
   * is that EvalAddManyInPlace uses the input ciphertext vector to store
   * intermediate results, to avoid the overhead of using extra tepmorary
   * space.
   *
   * @param ctList is the list of ciphertexts.
   *
   * @return new ciphertext.
   */
  Ciphertext<Element> EvalAddManyInPlace(
      vector<Ciphertext<Element>>& ctList) const {
    // input parameter check
    if (!ctList.size())
      PALISADE_THROW(type_error, "Empty input ciphertext vector");

    auto rv = GetEncryptionAlgorithm()->EvalAddManyInPlace(ctList);
    return rv;
  }

  /**
   * Function for evaluating multiplication on ciphertext followed by
   * relinearization operation. Currently it assumes that the input arguments
   * have total depth smaller than the supported depth. Otherwise, it throws an
   * error.
   *
   * @param ct1 first input ciphertext.
   * @param ct2 second input ciphertext.
   *
   * @return new ciphertext
   */
  Ciphertext<Element> EvalMultAndRelinearize(
      ConstCiphertext<Element> ct1, ConstCiphertext<Element> ct2) const {
    // input parameter check
    if (!ct1 || !ct2) PALISADE_THROW(type_error, "Input ciphertext is nullptr");

    const auto ek = GetEvalMultKeyVector(ct1->GetKeyTag());
    if (ek.size() <
        (ct1->GetElements().size() + ct2->GetElements().size() - 3)) {
      PALISADE_THROW(type_error,
                     "Insufficient value was used for maxDepth to generate "
                     "keys for EvalMult");
    }

    auto rv = GetEncryptionAlgorithm()->EvalMultAndRelinearize(ct1, ct2, ek);
    return rv;
  }

  /**
   * Function for relinearization of a ciphertext.
   *
   * @param ct input ciphertext.
   *
   * @return relinearized ciphertext
   */
  Ciphertext<Element> Relinearize(ConstCiphertext<Element> ct) const {
    // input parameter check
    if (!ct) PALISADE_THROW(type_error, "Input ciphertext is nullptr");

    const auto ek = GetEvalMultKeyVector(ct->GetKeyTag());

    if (ek.size() < (ct->GetElements().size() - 2)) {
      PALISADE_THROW(type_error,
                     "Insufficient value was used for maxDepth to generate "
                     "keys for EvalMult");
    }

    auto rv = GetEncryptionAlgorithm()->Relinearize(ct, ek);
    return rv;
  }

  /**
   * Function for relinearization of a ciphertext.
   *
   * @param ct input ciphertext.
   *
   * @return relinearized ciphertext
   */
   void RelinearizeInPlace(Ciphertext<Element> &ct) const {
    // input parameter check
    if (!ct)
      PALISADE_THROW(type_error, "Input ciphertext is nullptr");

    const auto ek = GetEvalMultKeyVector(ct->GetKeyTag());
    if (ek.size() < (ct->GetElements().size() - 2)) {
      PALISADE_THROW(type_error,
                     "Insufficient value was used for maxDepth to generate "
                     "keys for EvalMult");
    }

    GetEncryptionAlgorithm()->RelinearizeInPlace(ct, ek);
   }

  /**
   * EvalMult - PALISADE EvalMult method for plaintext * ciphertext
   * @param pt2
   * @param ct1
   * @return new ciphertext for ct1 * pt2
   */
  inline Ciphertext<Element> EvalMult(ConstPlaintext pt2,
                                      ConstCiphertext<Element> ct1) const {
    return EvalMult(ct1, pt2);
  }

  /**
   * EvalMult - PALISADE EvalMultMutable method for plaintext * ciphertext
   * @param pt2
   * @param ct1
   * @return new ciphertext for ct1 * pt2
   */
  inline Ciphertext<Element> EvalMultMutable(Plaintext pt2,
                                             Ciphertext<Element>& ct1) const {
    return EvalMultMutable(ct1, pt2);
  }

  /**
   * EvalMult - PALISADE EvalMult method for constant * ciphertext
   * @param constant
   * @param ct1
   * @return new ciphertext for ct1 * constant
   */
  inline Ciphertext<Element> EvalMult(double constant,
                                      ConstCiphertext<Element> ct1) const {
    return EvalMult(ct1, constant);
  }

  inline Ciphertext<Element> EvalMultMutable(double constant,
                                             Ciphertext<Element>& ct1) const {
    return EvalMultMutable(ct1, constant);
  }

  /**
   * EvalMult - PALISADE EvalMult method for plaintext * ciphertext
   * @param ct1
   * @param pt2
   * @return new ciphertext for ct1 * pt2
   */
  Ciphertext<Element> EvalMult(ConstCiphertext<Element> ct1,
                               ConstPlaintext pt2) const {
    TypeCheck(ct1, pt2);

    auto rv = GetEncryptionAlgorithm()->EvalMult(ct1, pt2);
    return rv;
  }

  /**
   * EvalMult - PALISADE EvalMultMutable method for plaintext * ciphertext
   * This is a mutable version - input ciphertexts may get automatically
   * rescaled, or level-reduced.
   *
   * @param ct1
   * @param pt2
   * @return new ciphertext for ct1 * pt2
   */
  Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ct1,
                                      Plaintext pt2) const {
    TypeCheck(ct1, pt2);

    auto rv = GetEncryptionAlgorithm()->EvalMultMutable(ct1, pt2);
    return rv;
  }

  /**
   * EvalMult - PALISADE EvalSub method for a ciphertext and constant
   * @param ciphertext
   * @param constant
   * @return new ciphertext for ciphertext - constant
   */
  Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext,
                               double constant) const {
    // input parameter check
    if (!ciphertext) {
      PALISADE_THROW(type_error, "Input ciphertext is nullptr");
    }

    auto rv = GetEncryptionAlgorithm()->EvalMult(ciphertext, constant);
    return rv;
  }

  /**
   * EvalMult - PALISADE EvalSub method for a ciphertext and constant
   * This is a mutable version - input ciphertexts may get automatically
   * rescaled, or level-reduced.
   *
   * @param ciphertext
   * @param constant
   * @return new ciphertext for ciphertext - constant
   */
  Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ciphertext,
                                      double constant) const {
    // input parameter check
    if (!ciphertext) {
      PALISADE_THROW(type_error, "Input ciphertext is nullptr");
    }

    auto rv = GetEncryptionAlgorithm()->EvalMultMutable(ciphertext, constant);
    return rv;
  }

  /**
   * EvalSub - PALISADE Negate method for a ciphertext
   * @param ct
   * @return new ciphertext -ct
   */
  Ciphertext<Element> EvalNegate(ConstCiphertext<Element> ct) const {
    if (ct == nullptr || Mismatched(ct->GetCryptoContext()))
      PALISADE_THROW(config_error,
                     "Information passed to EvalNegate was not generated with "
                     "this crypto context");

    auto rv = GetEncryptionAlgorithm()->EvalNegate(ct);
    return rv;
  }

  /**
   * Generate automophism keys for a given private key
   *
   * @param publicKey original public key.
   * @param origPrivateKey original private key.
   * @param indexList list of automorphism indices to be computed
   * @return returns the evaluation keys; index 0 of the vector corresponds to
   * plaintext index 2, index 1 to plaintex index 3, etc.
   */
  shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAutomorphismKeyGen(
      const LPPublicKey<Element> publicKey,
      const LPPrivateKey<Element> origPrivateKey,
      const std::vector<usint>& indexList) const {
    if (publicKey == nullptr || origPrivateKey == nullptr)
      PALISADE_THROW(type_error, "Null Keys");
    if (!indexList.size())
      PALISADE_THROW(config_error, "Input index vector is empty");
    if (publicKey->GetCryptoContext().get() != this)
      PALISADE_THROW(type_error,
                     "Key was not created in this CryptoContextImpl");
    if (publicKey->GetCryptoContext() != origPrivateKey->GetCryptoContext())
      PALISADE_THROW(type_error,
                     "Keys were not created in the same CryptoContextImpl");

    auto rv = GetEncryptionAlgorithm()->EvalAutomorphismKeyGen(
        publicKey, origPrivateKey, indexList);
    return rv;
  }

  /**
   * Function for evaluating automorphism of ciphertext at index i
   *
   * @param ciphertext the input ciphertext.
   * @param i automorphism index
   * @param &evalKeys - reference to the vector of evaluation keys generated by
   * EvalAutomorphismKeyGen.
   * @return resulting ciphertext
   */
  Ciphertext<Element> EvalAutomorphism(
      ConstCiphertext<Element> ciphertext, usint i,
      const std::map<usint, LPEvalKey<Element>>& evalKeys,
      CALLER_INFO_ARGS_HDR) const {
    if (nullptr == ciphertext) {
      std::string errorMsg(std::string("Input ciphertext is nullptr") +
                           CALLER_INFO);
      PALISADE_THROW(type_error, errorMsg);
    }

    if (evalKeys.empty()) {
      std::string errorMsg(std::string("Empty input key map") + CALLER_INFO);
      PALISADE_THROW(type_error, errorMsg);
    }
    auto tk = evalKeys.begin()->second;
    if (nullptr == tk) {
      std::string errorMsg(std::string("Invalid evalKey") + CALLER_INFO);
      PALISADE_THROW(type_error, errorMsg);
    }

    if (ciphertext->GetCryptoContext().get() != this) {
      std::string errorMsg(
          std::string("Ciphertext was not created in this CryptoContextImpl") +
          CALLER_INFO);
      PALISADE_THROW(type_error, errorMsg);
    }

    if (ciphertext->GetCryptoContext() != tk->GetCryptoContext()) {
      std::string errorMsg(
          std::string("Items were not created in the same CryptoContextImpl") +
          CALLER_INFO);
      PALISADE_THROW(type_error, errorMsg);
    }

    if (ciphertext->GetKeyTag() != tk->GetKeyTag()) {
      std::string errorMsg(
          std::string("Items were not encrypted with same keys") + CALLER_INFO);
      PALISADE_THROW(type_error, errorMsg);
    }

    auto rv =
        GetEncryptionAlgorithm()->EvalAutomorphism(ciphertext, i, evalKeys);
    return rv;
  }

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
      const std::vector<usint>& indexList) const {
    if (privateKey == nullptr) PALISADE_THROW(type_error, "Null input");
    if (!indexList.size())
      PALISADE_THROW(config_error, "Input index vector is empty");
    if (privateKey->GetCryptoContext().get() != this)
      PALISADE_THROW(type_error,
                     "Key was not created in this CryptoContextImpl");

    auto rv =
        GetEncryptionAlgorithm()->EvalAutomorphismKeyGen(privateKey, indexList);
    return rv;
  }

  /**
   * EvalSumKeyGen Generates the key map to be used by evalsum
   *
   * @param privateKey private key.
   * @param publicKey public key (used in NTRU schemes).
   */
  void EvalSumKeyGen(const LPPrivateKey<Element> privateKey,
                     const LPPublicKey<Element> publicKey = nullptr);

  shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumRowsKeyGen(
      const LPPrivateKey<Element> privateKey,
      const LPPublicKey<Element> publicKey = nullptr, usint rowSize = 0,
      usint subringDim = 0);

  shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumColsKeyGen(
      const LPPrivateKey<Element> privateKey,
      const LPPublicKey<Element> publicKey = nullptr);

  /**
   * GetEvalSumKey  returns the map
   *
   * @return the EvalSum key map
   */
  static const std::map<usint, LPEvalKey<Element>>& GetEvalSumKeyMap(
      const string& id);

  static std::map<string, shared_ptr<std::map<usint, LPEvalKey<Element>>>>&
  GetAllEvalSumKeys();

  /**
   * Function for evaluating a sum of all components
   *
   * @param ciphertext the input ciphertext.
   * @param batchSize size of the batch
   * @return resulting ciphertext
   */
  Ciphertext<Element> EvalSum(ConstCiphertext<Element> ciphertext,
                              usint batchSize) const;

  Ciphertext<Element> EvalSumRows(
      ConstCiphertext<Element> ciphertext, usint rowSize,
      const std::map<usint, LPEvalKey<Element>>& evalKeys,
      usint subringDim = 0) const;

  Ciphertext<Element> EvalSumCols(
      ConstCiphertext<Element> ciphertext, usint rowSize,
      const std::map<usint, LPEvalKey<Element>>& evalKeys) const;

  /**
   * EvalAtIndexKeyGen generates evaluation keys for a list of indices
   *
   * @param privateKey private key.
   * @param indexList list of indices.
   * @param publicKey public key (used in NTRU schemes).
   */
  void EvalAtIndexKeyGen(const LPPrivateKey<Element> privateKey,
                         const std::vector<int32_t>& indexList,
                         const LPPublicKey<Element> publicKey = nullptr);

  /**
   * EvalFastRotationPrecompute implements the precomputation step of
   * hoisted automorphisms.
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
  shared_ptr<vector<Element>> EvalFastRotationPrecompute(
      ConstCiphertext<Element> ct) const {
    auto rv = GetEncryptionAlgorithm()->EvalFastRotationPrecompute(ct);
    return rv;
  }

  /**
   * EvalFastRotation implements the automorphism and key switching step of
   * hoisted automorphisms.
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
   */
  Ciphertext<Element> EvalFastRotation(
      ConstCiphertext<Element> ct, const usint index, const usint m,
      const shared_ptr<vector<Element>> digits) const {
    auto rv = GetEncryptionAlgorithm()->EvalFastRotation(ct, index, m, digits);
    return rv;
  }

  /**
   * Merges multiple ciphertexts with encrypted results in slot 0 into a single
   * ciphertext The slot assignment is done based on the order of ciphertexts in
   * the vector
   *
   * @param ciphertextVector vector of ciphertexts to be merged.
   * @param &evalKeys - reference to the map of evaluation keys generated by
   * EvalAutomorphismKeyGen.
   * @return resulting ciphertext
   */
  Ciphertext<Element> EvalMerge(
      const vector<Ciphertext<Element>>& ciphertextVector) const;

  /**
   * GetEvalAutomorphismKey  returns the map
   *
   * @return the EvalAutomorphism key map
   */
  static const std::map<usint, LPEvalKey<Element>>& GetEvalAutomorphismKeyMap(
      const string& id);

  static std::map<string, shared_ptr<std::map<usint, LPEvalKey<Element>>>>&
  GetAllEvalAutomorphismKeys();

  /**
   * Moves i-th slot to slot 0
   *
   * @param ciphertext.
   * @param i the index.
   * @return resulting ciphertext
   */
  Ciphertext<Element> EvalAtIndex(ConstCiphertext<Element> ciphertext,
                                  int32_t index) const;

  /**
   * Evaluates inner product in batched encoding
   *
   * @param ciphertext1 first vector.
   * @param ciphertext2 second vector.
   * @param batchSize size of the batch to be summed up
   * @return resulting ciphertext
   */
  Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element> ciphertext1,
                                       ConstCiphertext<Element> ciphertext2,
                                       usint batchSize) const;

  /**
   * Evaluates inner product in batched encoding
   *
   * @param ciphertext1 first vector - ciphertext.
   * @param plaintext second vector - plaintext.
   * @param batchSize size of the batch to be summed up
   * @return resulting ciphertext
   */
  Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element> ciphertext1,
                                       ConstPlaintext plaintext,
                                       usint batchSize) const;

  /**
   * Method for polynomial evaluation for polynomials represented as power
   * series.
   *
   * @param &cipherText input ciphertext
   * @param &coefficients is the vector of coefficients in the polynomial; the
   * size of the vector is the degree of the polynomial + 1
   * @return the result of polynomial evaluation.
   */
  virtual Ciphertext<Element> EvalPoly(
      ConstCiphertext<Element> ciphertext,
      const std::vector<double>& coefficients) const {
    if (ciphertext == nullptr ||
        this->Mismatched(ciphertext->GetCryptoContext()))
      throw std::logic_error(
          "Information passed to EvalPoly was not generated with this crypto "
          "context");

    auto rv = std::static_pointer_cast<LPPublicKeyEncryptionScheme<Element>>(
                  this->GetEncryptionAlgorithm())
                  ->EvalPoly(ciphertext, coefficients);
    return rv;
  }

  /**
   * KeySwitch - PALISADE KeySwitch method
   * @param keySwitchHint - reference to KeySwitchHint
   * @param ciphertext - ciphertext
   * @return new CiphertextImpl after applying key switch
   */
  Ciphertext<Element> KeySwitch(const LPEvalKey<Element> keySwitchHint,
                                ConstCiphertext<Element> ciphertext) const {
    if (keySwitchHint == nullptr ||
        Mismatched(keySwitchHint->GetCryptoContext()))
      PALISADE_THROW(
          config_error,
          "Key passed to KeySwitch was not generated with this crypto context");

    if (ciphertext == nullptr || Mismatched(ciphertext->GetCryptoContext()))
      PALISADE_THROW(config_error,
                     "Ciphertext passed to KeySwitch was not generated with "
                     "this crypto context");

    auto rv = GetEncryptionAlgorithm()->KeySwitch(keySwitchHint, ciphertext);
    return rv;
  }

  /**
   * KeySwitch - PALISADE KeySwitchInPlace method
   * @param keySwitchHint - reference to KeySwitchHint
   * @param ciphertext - ciphertext on which to perform in-place key switching
   */
  void KeySwitchInPlace(const LPEvalKey<Element> keySwitchHint,
                        Ciphertext<Element>& ciphertext) const {
    if (keySwitchHint == nullptr ||
        Mismatched(keySwitchHint->GetCryptoContext()))
      PALISADE_THROW(config_error,
                     "Key passed to KeySwitchInPlace was not generated with "
                     "this crypto context");

    if (ciphertext == nullptr || Mismatched(ciphertext->GetCryptoContext()))
      PALISADE_THROW(
          config_error,
          "Ciphertext passed to KeySwitchInPlace was not generated with "
          "this crypto context");

    GetEncryptionAlgorithm()->KeySwitchInPlace(keySwitchHint, ciphertext);
  }

  /**
   * Rescale - An alias for PALISADE ModReduce method.
   * This is because ModReduce is called Rescale in CKKS.
   *
   * @param ciphertext - ciphertext
   * @return mod reduced ciphertext
   */
  Ciphertext<Element> Rescale(ConstCiphertext<Element> ciphertext) const {
    if (ciphertext == nullptr || Mismatched(ciphertext->GetCryptoContext()))
      PALISADE_THROW(config_error,
                     "Information passed to Rescale was not generated with "
                     "this crypto context");

    auto rv = GetEncryptionAlgorithm()->ModReduce(ciphertext);
    return rv;
  }

  /**
   * Rescale - An alias for PALISADE ModReduceInPlace method.
   * This is because ModReduceInPlace is called RescaleInPlace in CKKS.
   *
   * @param ciphertext - ciphertext to be mod-reduced in-place
   */
  void RescaleInPlace(Ciphertext<Element>& ciphertext) const {
    if (ciphertext == nullptr || Mismatched(ciphertext->GetCryptoContext()))
      PALISADE_THROW(
          config_error,
          "Information passed to RescaleInPlace was not generated with "
          "this crypto context");

    GetEncryptionAlgorithm()->ModReduceInPlace(ciphertext);
  }

  /**
   * ModReduce - PALISADE ModReduce method used only for BGVrns
   * @param ciphertext - ciphertext
   * @return mod reduced ciphertext
   */
  Ciphertext<Element> ModReduce(ConstCiphertext<Element> ciphertext) const {
    if (ciphertext == nullptr || Mismatched(ciphertext->GetCryptoContext()))
      PALISADE_THROW(
          not_available_error,
          "Information passed to ModReduce was not generated with this crypto "
          "context");

    auto rv = GetEncryptionAlgorithm()->ModReduce(ciphertext);
    return rv;
  }

  /**
   * ModReduce - PALISADE ModReduceInPlace method used only for BGVrns
   * @param ciphertext - ciphertext to be mod-reduced in-place
   */
  void ModReduceInPlace(Ciphertext<Element>& ciphertext) const {
    if (ciphertext == nullptr || Mismatched(ciphertext->GetCryptoContext()))
      PALISADE_THROW(
          not_available_error,
          "Information passed to ModReduce was not generated with this crypto "
          "context");

    GetEncryptionAlgorithm()->ModReduceInPlace(ciphertext);
  }

  /**
   * LevelReduce - PALISADE LevelReduce method
   * @param cipherText1
   * @param linearKeySwitchHint
   * @return vector of level reduced ciphertext
   */
  Ciphertext<Element> LevelReduce(ConstCiphertext<Element> cipherText1,
                                  const LPEvalKey<Element> linearKeySwitchHint,
                                  size_t levels = 1) const {
    const auto cryptoParams =
        std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
            cipherText1->GetCryptoParameters());

    if (cipherText1 == nullptr || Mismatched(cipherText1->GetCryptoContext())) {
      PALISADE_THROW(config_error,
                     "Information passed to LevelReduce was not generated with "
                     "this crypto context");
    }

    auto rv = GetEncryptionAlgorithm()->LevelReduce(
        cipherText1, linearKeySwitchHint, levels);
    return rv;
  }

  /**
   * ComposedEvalMult - PALISADE composed evalmult
   * @param ciphertext1 - vector for first cipher text
   * @param ciphertext2 - vector for second cipher text
   * @param quadKeySwitchHint - is the quadratic key switch hint from original
   * private key to the quadratic key return vector of resulting ciphertext
   */
  Ciphertext<Element> ComposedEvalMult(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2) const {
    if (ciphertext1 == nullptr || ciphertext2 == nullptr ||
        ciphertext1->GetKeyTag() != ciphertext2->GetKeyTag() ||
        Mismatched(ciphertext1->GetCryptoContext()))
      PALISADE_THROW(config_error,
                     "Ciphertexts passed to ComposedEvalMult were not "
                     "generated with this crypto context");

    auto ek = GetEvalMultKeyVector(ciphertext1->GetKeyTag());
    if (!ek.size()) {
      PALISADE_THROW(type_error,
                     "Evaluation key has not been generated for EvalMult");
    }

    auto rv = GetEncryptionAlgorithm()->ComposedEvalMult(ciphertext1,
                                                         ciphertext2, ek[0]);
    return rv;
  }

  /**
   * Compress - Reduces the size of ciphertext modulus to minimize the
   * communication cost before sending the encrypted result for decryption
   * @param ciphertext1 - input ciphertext
   * @param numTowers - number of CRT limbs after compressing (default is 1)
   * @return compressed ciphertext
   */
  Ciphertext<Element> Compress(ConstCiphertext<Element> ciphertext1,
                               uint32_t numTowers = 1) const {
    if (ciphertext1 == nullptr)
      PALISADE_THROW(config_error, "input ciphertext is invalid (has no data)");

    auto ct = GetEncryptionAlgorithm()->Compress(ciphertext1, numTowers);
    return ct;
  }

  template <class Archive>
  void save(Archive& ar, std::uint32_t const version) const {
    ar(cereal::make_nvp("cc", params));
    ar(cereal::make_nvp("kt", scheme));
    ar(cereal::make_nvp("si", m_schemeId));
  }

  template <class Archive>
  void load(Archive& ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(cereal::make_nvp("cc", params));
    ar(cereal::make_nvp("kt", scheme));
    ar(cereal::make_nvp("si", m_schemeId));

    // NOTE: a pointer to this object will be wrapped in a shared_ptr, and is a
    // "CryptoContext". PALISADE relies on the notion that identical
    // CryptoContextImpls are not duplicated in memory Once we deserialize this
    // object, we must check to see if there is a matching object for this
    // object that's already existing in memory if it DOES exist, use it. If it
    // does NOT exist, add this to the cache of all contexts
  }

  virtual std::string SerializedObjectName() const { return "CryptoContext"; }
  static uint32_t SerializedVersion() { return 1; }
};

/**
 * @brief CryptoObject
 *
 * A class to aid in referring to the crypto context that an object belongs to
 */
template <typename Element>
class CryptoObject {
 protected:
  CryptoContext<Element> context;  // crypto context this object belongs to
                                   // tag used to find the evaluation key needed
                                   // for SHE/FHE operations
  string keyTag;

 public:
  explicit CryptoObject(CryptoContext<Element> cc = nullptr,
                        const string& tag = "")
      : context(cc), keyTag(tag) {}

  CryptoObject(const CryptoObject& rhs) {
    context = rhs.context;
    keyTag = rhs.keyTag;
  }

  CryptoObject(const CryptoObject&& rhs) {
    context = std::move(rhs.context);
    keyTag = std::move(rhs.keyTag);
  }

  virtual ~CryptoObject() {}

  const CryptoObject& operator=(const CryptoObject& rhs) {
    this->context = rhs.context;
    this->keyTag = rhs.keyTag;
    return *this;
  }

  const CryptoObject& operator=(const CryptoObject&& rhs) {
    this->context = std::move(rhs.context);
    this->keyTag = std::move(rhs.keyTag);
    return *this;
  }

  bool operator==(const CryptoObject& rhs) const {
    return context.get() == rhs.context.get() && keyTag == rhs.keyTag;
  }

  CryptoContext<Element> GetCryptoContext() const { return context; }

  const shared_ptr<LPCryptoParameters<Element>> GetCryptoParameters() const {
    return context->GetCryptoParameters();
  }

  const EncodingParams GetEncodingParameters() const {
    return context->GetCryptoParameters()->GetEncodingParams();
  }

  const string GetKeyTag() const { return keyTag; }

  void SetKeyTag(const string& tag) { keyTag = tag; }

  template <class Archive>
  void save(Archive& ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("cc", context));
    ar(::cereal::make_nvp("kt", keyTag));
  }

  template <class Archive>
  void load(Archive& ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::make_nvp("cc", context));
    ar(::cereal::make_nvp("kt", keyTag));

    context = CryptoContextFactory<Element>::GetContext(
        context->GetCryptoParameters(), context->GetEncryptionAlgorithm());
  }

  std::string SerializedObjectName() const { return "CryptoObject"; }
  static uint32_t SerializedVersion() { return 1; }
};

/**
 * @brief CryptoContextFactory
 *
 * A class that contains static methods to generate new crypto contexts from
 * user parameters
 *
 */
template <typename Element>
class CryptoContextFactory {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;

 protected:
  static vector<CryptoContext<Element>> AllContexts;

 public:
  static void ReleaseAllContexts();

  static int GetContextCount();

  static CryptoContext<Element> GetSingleContext();

  static CryptoContext<Element> GetContext(
      shared_ptr<LPCryptoParameters<Element>> params,
      shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme,
      const string& schemeId = "Not");

  static CryptoContext<Element> GetContextForPointer(
      CryptoContextImpl<Element>* cc);

  static const vector<CryptoContext<Element>>& GetAllContexts();

  /**
   * construct a PALISADE CryptoContextImpl for the BFV Scheme
   * @param params ring parameters
   * @param plaintextModulus plaintext modulus
   * @param relinWindow bits in the base of digits in key
   * switching/relinearization
   * @param stdDev sigma - distribution parameter for error distribution
   * @param delta - the plaintext scaling parameter floor(q/t) in BFV
   * @param mode - mode for generating secret keys (RLWE vs OPTIMIZED)
   * @param bigmodulus - large modulus used in tensoring of homomorphic
   * multiplication
   * @param bigrootofunity - root of unity for bigmodulus
   * @param depth of supported computation circuit (not used; for future use)
   * @param assuranceMeasure alpha - effective bound for gaussians: -
   * sqrt{alpha}*sigma..sqrt{alpha}*sigma
   * @param security level - root Hermite factor
   * @param bigmodulusarb - additional large modulus for bigmoduls for the case
   * of general (non-power-of-two) cyclotomics
   * @param bigrootofunityarb - root of unity for bigmodulusarb
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFV(
      shared_ptr<ParmType> params, const PlaintextModulus plaintextmodulus,
      usint relinWindow, float stDev, const std::string& delta,
      MODE mode = RLWE, const std::string& bigmodulus = "0",
      const std::string& bigrootofunity = "0", int depth = 0,
      int assuranceMeasure = 0, float securityLevel = 0,
      const std::string& bigmodulusarb = "0",
      const std::string& bigrootofunityarb = "0", int maxDepth = 2);

  /**
   * construct a PALISADE CryptoContextImpl for the BFV Scheme
   * @param params ring parameters
   * @param encodingParams plaintext encoding parameters
   * @param relinWindow bits in the base of digits in key
   * switching/relinearization
   * @param stdDev sigma - distribution parameter for error distribution
   * @param delta - the plaintext scaling parameter floor(q/t) in BFV
   * @param mode - mode for generating secret keys (RLWE vs OPTIMIZED)
   * @param bigmodulus - large modulus used in tensoring of homomorphic
   * multiplication
   * @param bigrootofunity - root of unity for bigmodulus
   * @param depth of supported computation circuit (not used; for future use)
   * @param assuranceMeasure alpha - effective bound for gaussians: -
   * sqrt{alpha}*sigma..sqrt{alpha}*sigma
   * @param security level - root Hermite factor
   * @param bigmodulusarb - additional large modulus for bigmoduls for the case
   * of general (non-power-of-two) cyclotomics
   * @param bigrootofunityarb - root of unity for bigmodulusarb
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFV(
      shared_ptr<ParmType> params, EncodingParams encodingParams,
      usint relinWindow, float stDev, const std::string& delta,
      MODE mode = RLWE, const std::string& bigmodulus = "0",
      const std::string& bigrootofunity = "0", int depth = 0,
      int assuranceMeasure = 0, float securityLevel = 0,
      const std::string& bigmodulusarb = "0",
      const std::string& bigrootofunityarb = "0", int maxDepth = 2);

  /**
   * construct a PALISADE CryptoContextImpl for the BFV Scheme using the
   * scheme's ParamsGen methods
   * @param plaintextModulus plaintext modulus
   * @param securityLevel root Hermite factor (lattice security parameter)
   * @param relinWindow bits in the base of digits in key
   * switching/relinearization
   * @param dist distribution parameter for Gaussian noise generation
   * @param numAdds additive depth for homomorphic computations (assumes
   * numMults and numKeySwitches are set to zero)
   * @param numMults multiplicative depth for homomorphic computations (assumes
   * numAdds and numKeySwitches are set to zero)
   * @param numKeyswitches  key-switching depth for homomorphic computations
   * (assumes numAdds and numMults are set to zero)
   * @param mode secret key distribution mode (RLWE [Gaussian noise] or
   * OPTIMIZED [ternary uniform distribution])
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFV(
      const PlaintextModulus plaintextModulus, float securityLevel,
      usint relinWindow, float dist, unsigned int numAdds,
      unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED,
      int maxDepth = 2, uint32_t n = 0);

  /**
   * construct a PALISADE CryptoContextImpl for the BFV Scheme using the
   * scheme's ParamsGen methods
   * @param plaintextModulus plaintext modulus
   * @param securityLevel standard security level
   * @param relinWindow bits in the base of digits in key
   * switching/relinearization
   * @param dist distribution parameter for Gaussian noise generation
   * @param numAdds additive depth for homomorphic computations (assumes
   * numMults and numKeySwitches are set to zero)
   * @param numMults multiplicative depth for homomorphic computations (assumes
   * numAdds and numKeySwitches are set to zero)
   * @param numKeyswitches  key-switching depth for homomorphic computations
   * (assumes numAdds and numMults are set to zero)
   * @param mode secret key distribution mode (RLWE [Gaussian noise] or
   * OPTIMIZED [ternary uniform distribution])
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFV(
      const PlaintextModulus plaintextModulus, SecurityLevel securityLevel,
      usint relinWindow, float dist, unsigned int numAdds,
      unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED,
      int maxDepth = 2, uint32_t n = 0);

  /**
   * construct a PALISADE CryptoContextImpl for the BFV Scheme using the
   * scheme's ParamsGen methods
   * @param encodingParams plaintext encoding parameters
   * @param securityLevel root Hermite factor (lattice security parameter)
   * @param distribution parameter for Gaussian noise generation
   * @param numAdds additive depth for homomorphic computations (assumes
   * numMults and numKeySwitches are set to zero)
   * @param numMults multiplicative depth for homomorphic computations (assumes
   * numAdds and numKeySwitches are set to zero)
   * @param numKeyswitches  key-switching depth for homomorphic computations
   * (assumes numAdds and numMults are set to zero)
   * @param mode secret key distribution mode (RLWE [Gaussian noise] or
   * OPTIMIZED [ternary uniform distribution])
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFV(
      EncodingParams encodingParams, float securityLevel, usint relinWindow,
      float dist, unsigned int numAdds, unsigned int numMults,
      unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2,
      uint32_t n = 0);

  /**
   * construct a PALISADE CryptoContextImpl for the BFV Scheme using the
   * scheme's ParamsGen methods
   * @param encodingParams plaintext encoding parameters
   * @param securityLevel standard security level
   * @param distribution parameter for Gaussian noise generation
   * @param numAdds additive depth for homomorphic computations (assumes
   * numMults and numKeySwitches are set to zero)
   * @param numMults multiplicative depth for homomorphic computations (assumes
   * numAdds and numKeySwitches are set to zero)
   * @param numKeyswitches  key-switching depth for homomorphic computations
   * (assumes numAdds and numMults are set to zero)
   * @param mode secret key distribution mode (RLWE [Gaussian noise] or
   * OPTIMIZED [ternary uniform distribution])
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFV(
      EncodingParams encodingParams, SecurityLevel securityLevel,
      usint relinWindow, float dist, unsigned int numAdds,
      unsigned int numMults, unsigned int numKeyswitches, MODE mode = OPTIMIZED,
      int maxDepth = 2, uint32_t n = 0);

  /**
   * construct a PALISADE CryptoContextImpl for the BFVrns Scheme using the
   * scheme's ParamsGen methods
   * @param plaintextModulus plaintext modulus
   * @param securityLevel root Hermite factor (lattice security parameter)
   * @param dist distribution parameter for Gaussian noise generation
   * @param numAdds additive depth for homomorphic computations (assumes
   * numMults and numKeySwitches are set to zero)
   * @param numMults multiplicative depth for homomorphic computations (assumes
   * numAdds and numKeySwitches are set to zero)
   * @param numKeyswitches  key-switching depth for homomorphic computations
   * (assumes numAdds and numMults are set to zero)
   * @param mode secret key distribution mode (RLWE [Gaussian noise] or
   * OPTIMIZED [ternary uniform distribution])
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @param relinWindow the key switching window (bits in the base for digits)
   * used for digit decomposition (0 - means to use only CRT decomposition)
   * @param dcrtBits size of "small" CRT moduli
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFVrns(
      const PlaintextModulus plaintextModulus, float securityLevel, float dist,
      unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
      MODE mode = OPTIMIZED, int maxDepth = 2, uint32_t relinWindow = 0,
      size_t dcrtBits = 60, uint32_t n = 0);

  /**
   * construct a PALISADE CryptoContextImpl for the BFVrns Scheme using the
   * scheme's ParamsGen methods
   * @param plaintextModulus plaintext modulus
   * @param securityLevel standard secuirity level
   * @param dist distribution parameter for Gaussian noise generation
   * @param numAdds additive depth for homomorphic computations (assumes
   * numMults and numKeySwitches are set to zero)
   * @param numMults multiplicative depth for homomorphic computations (assumes
   * numAdds and numKeySwitches are set to zero)
   * @param numKeyswitches  key-switching depth for homomorphic computations
   * (assumes numAdds and numMults are set to zero)
   * @param mode secret key distribution mode (RLWE [Gaussian noise] or
   * OPTIMIZED [ternary uniform distribution])
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @param relinWindow the key switching window (bits in the base for digits)
   * used for digit decomposition (0 - means to use only CRT decomposition)
   * @param dcrtBits size of "small" CRT moduli
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFVrns(
      const PlaintextModulus plaintextModulus, SecurityLevel securityLevel,
      float dist, unsigned int numAdds, unsigned int numMults,
      unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2,
      uint32_t relinWindow = 0, size_t dcrtBits = 60, uint32_t n = 0);

  /**
   * construct a PALISADE CryptoContextImpl for the BFVrns Scheme using the
   * scheme's ParamsGen methods
   * @param encodingParams plaintext encoding parameters
   * @param securityLevel root Hermite factor (lattice security parameter)
   * @param dist distribution parameter for Gaussian noise generation
   * @param numAdds additive depth for homomorphic computations (assumes
   * numMults and numKeySwitches are set to zero)
   * @param numMults multiplicative depth for homomorphic computations (assumes
   * numAdds and numKeySwitches are set to zero)
   * @param numKeyswitches  key-switching depth for homomorphic computations
   * (assumes numAdds and numMults are set to zero)
   * @param mode secret key distribution mode (RLWE [Gaussian noise] or
   * OPTIMIZED [ternary uniform distribution])
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @param relinWindow  the key switching window used for digit decomposition
   * (0 - means to use only CRT decomposition)
   * @param dcrtBits size of "small" CRT moduli
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFVrns(
      EncodingParams encodingParams, float securityLevel, float dist,
      unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
      MODE mode = OPTIMIZED, int maxDepth = 2, uint32_t relinWindow = 0,
      size_t dcrtBits = 60, uint32_t n = 0);

  /**
   * construct a PALISADE CryptoContextImpl for the BFVrns Scheme using the
   * scheme's ParamsGen methods
   * @param encodingParams plaintext encoding parameters
   * @param securityLevel standard security level
   * @param dist distribution parameter for Gaussian noise generation
   * @param numAdds additive depth for homomorphic computations (assumes
   * numMults and numKeySwitches are set to zero)
   * @param numMults multiplicative depth for homomorphic computations (assumes
   * numAdds and numKeySwitches are set to zero)
   * @param numKeyswitches  key-switching depth for homomorphic computations
   * (assumes numAdds and numMults are set to zero)
   * @param mode secret key distribution mode (RLWE [Gaussian noise] or
   * OPTIMIZED [ternary uniform distribution])
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @param relinWindow  the key switching window used for digit decomposition
   * (0 - means to use only CRT decomposition)
   * @param dcrtBits size of "small" CRT moduli
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFVrns(
      EncodingParams encodingParams, SecurityLevel securityLevel, float dist,
      unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
      MODE mode = OPTIMIZED, int maxDepth = 2, uint32_t relinWindow = 0,
      size_t dcrtBits = 60, uint32_t n = 0);

  /**
   * construct a PALISADE CryptoContextImpl for the BFVrnsB Scheme using the
   * scheme's ParamsGen methods
   * @param plaintextModulus plaintext modulus
   * @param securityLevel root Hermite factor (lattice security parameter)
   * @param dist distribution parameter for Gaussian noise generation
   * @param numAdds additive depth for homomorphic computations (assumes
   * numMults and numKeySwitches are set to zero)
   * @param numMults multiplicative depth for homomorphic computations (assumes
   * numAdds and numKeySwitches are set to zero)
   * @param numKeyswitches  key-switching depth for homomorphic computations
   * (assumes numAdds and numMults are set to zero)
   * @param mode secret key distribution mode (RLWE [Gaussian noise] or
   * OPTIMIZED [ternary uniform distribution])
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @param relinWindow  the key switching window used for digit decomposition
   * (0 - means to use only CRT decomposition)
   * @param dcrtBits size of "small" CRT moduli
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFVrnsB(
      const PlaintextModulus plaintextModulus, float securityLevel, float dist,
      unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
      MODE mode = OPTIMIZED, int maxDepth = 2, uint32_t relinWindow = 0,
      size_t dcrtBits = 60, uint32_t n = 0);

  /**
   * construct a PALISADE CryptoContextImpl for the BFVrnsB Scheme using the
   * scheme's ParamsGen methods
   * @param plaintextModulus plaintext modulus
   * @param securityLevel standard security level
   * @param dist distribution parameter for Gaussian noise generation
   * @param numAdds additive depth for homomorphic computations (assumes
   * numMults and numKeySwitches are set to zero)
   * @param numMults multiplicative depth for homomorphic computations (assumes
   * numAdds and numKeySwitches are set to zero)
   * @param numKeyswitches  key-switching depth for homomorphic computations
   * (assumes numAdds and numMults are set to zero)
   * @param mode secret key distribution mode (RLWE [Gaussian noise] or
   * OPTIMIZED [ternary uniform distribution])
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @param relinWindow  the key switching window used for digit decomposition
   * (0 - means to use only CRT decomposition)
   * @param dcrtBits size of "small" CRT moduli
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFVrnsB(
      const PlaintextModulus plaintextModulus, SecurityLevel securityLevel,
      float dist, unsigned int numAdds, unsigned int numMults,
      unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2,
      uint32_t relinWindow = 0, size_t dcrtBits = 60, uint32_t = 0);

  /**
   * construct a PALISADE CryptoContextImpl for the BFVrnsB Scheme using the
   * scheme's ParamsGen methods
   * @param encodingParams plaintext encoding parameters
   * @param securityLevel root Hermite factor (lattice security parameter)
   * @param dist distribution parameter for Gaussian noise generation
   * @param numAdds additive depth for homomorphic computations (assumes
   * numMults and numKeySwitches are set to zero)
   * @param numMults multiplicative depth for homomorphic computations (assumes
   * numAdds and numKeySwitches are set to zero)
   * @param numKeyswitches  key-switching depth for homomorphic computations
   * (assumes numAdds and numMults are set to zero)
   * @param mode secret key distribution mode (RLWE [Gaussian noise] or
   * OPTIMIZED [ternary uniform distribution])
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @param relinWindow  the key switching window used for digit decomposition
   * (0 - means to use only CRT decomposition)
   * @param dcrtBits size of "small" CRT moduli
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFVrnsB(
      EncodingParams encodingParams, float securityLevel, float dist,
      unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
      MODE mode = OPTIMIZED, int maxDepth = 2, uint32_t relinWindow = 0,
      size_t dcrtBits = 60, uint32_t n = 0);

  /**
   * construct a PALISADE CryptoContextImpl for the BFVrnsB Scheme using the
   * scheme's ParamsGen methods
   * @param encodingParams plaintext encoding parameters
   * @param securityLevel standard security level
   * @param dist distribution parameter for Gaussian noise generation
   * @param numAdds additive depth for homomorphic computations (assumes
   * numMults and numKeySwitches are set to zero)
   * @param numMults multiplicative depth for homomorphic computations (assumes
   * numAdds and numKeySwitches are set to zero)
   * @param numKeyswitches  key-switching depth for homomorphic computations
   * (assumes numAdds and numMults are set to zero)
   * @param mode secret key distribution mode (RLWE [Gaussian noise] or
   * OPTIMIZED [ternary uniform distribution])
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @param relinWindow  the key switching window used for digit decomposition
   * (0 - means to use only CRT decomposition)
   * @param dcrtBits size of "small" CRT moduli
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFVrnsB(
      EncodingParams encodingParams, SecurityLevel securityLevel, float dist,
      unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
      MODE mode = OPTIMIZED, int maxDepth = 2, uint32_t relinWindow = 0,
      size_t dcrtBits = 60, uint32_t n = 0);

  /**
   * construct a PALISADE CryptoContextImpl for the CKKS Scheme
   * @param plaintextmodulus
   * @param ringdim
   * @param modulus
   * @param rootOfUnity
   * @param relinWindow
   * @param stDev
   * @param mode
   * @param depth
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   * @param ksTech key switching technique to use (e.g., GHS or BV)
   * @param rsTech rescaling technique to use (e.g., APPROXRESCALE or
   * EXACTRESCALE)
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextCKKS(
      shared_ptr<ParmType> params, const PlaintextModulus plaintextmodulus,
      usint relinWindow, float stDev, MODE mode = RLWE, int depth = 1,
      int maxDepth = 2, KeySwitchTechnique ksTech = BV,
      RescalingTechnique rsTech = APPROXRESCALE);

  /**
   * construct a PALISADE CryptoContextImpl for the CKKS Scheme
   * @param encodingParams
   * @param ringdim
   * @param modulus
   * @param rootOfUnity
   * @param relinWindow
   * @param stDev
   * @param mode
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   * @param ksTech key switching technique to use (e.g., GHS or BV)
   * @param rsTech rescaling technique to use (e.g., APPROXRESCALE or
   * EXACTRESCALE)
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextCKKS(
      shared_ptr<ParmType> params, EncodingParams encodingParams,
      usint relinWindow, float stDev, MODE mode = RLWE, int depth = 1,
      int maxDepth = 2, enum KeySwitchTechnique ksTech = BV,
      RescalingTechnique rsTech = APPROXRESCALE);

  /**
   * Automatically generate the moduli chain and construct a PALISADE
   * CryptoContextImpl for the CKKS Scheme with it.
   *
   * @param cyclOrder the cyclotomic order M
   * @param numPrimes the number of towers/primes to use when building the
   * moduli chain
   * @param scaleExp the plaintext scaling factor, which is equal to dcrtBits in
   * our implementation of CKKS
   * @param batchSize the batch size of the ciphertext
   * @param mode RLWE or OPTIMIZED
   * @param depth
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   * @param firstModSize the bit-length of the first modulus
   * @param ksTech key switching technique to use (e.g., GHS or BV)
   * @param rsTech rescaling technique to use (e.g., APPROXRESCALE or
   * EXACTRESCALE)
   * @param numLargeDigits the number of big digits to use in HYBRID key
   * switching
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextCKKSWithParamsGen(
      usint cyclOrder, usint numPrimes, usint scaleExp, usint relinWindow,
      usint batchSize, MODE mode, int depth = 1, int maxDepth = 2,
      usint firstModSize = FIRSTMODSIZE, enum KeySwitchTechnique ksTech = BV,
      enum RescalingTechnique rsTech = APPROXRESCALE,
      uint32_t numLargeDigits = 4);

  /**
   * Construct a PALISADE CryptoContextImpl for the CKKS Scheme.
   *
   * @param multiplicativeDepth the depth of multiplications supported by the
   * scheme (equal to number of towers - 1)
   * @param scalingFactorBits the size of the scaling factor in bits
   * @param batchSize the number of slots being used in the ciphertext
   * @param stdLevel the standard security level we want the scheme to satisfy
   * @param ringDim the ring dimension (if not specified selected automatically
   * based on stdLevel)
   * @param ksTech key switching technique to use (e.g., HYBRID, GHS or BV)
   * @param rsTech rescaling technique to use (e.g., APPROXRESCALE or
   * EXACTRESCALE)
   * @param numLargeDigits the number of big digits to use in HYBRID key
   * switching
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   * @param firstModSize the bit-length of the first modulus
   * @param relinWindow the relinearization windows (used in BV key switching,
   * use 0 for RNS decomposition)
   * @param mode RLWE (gaussian distribution) or OPTIMIZED (ternary
   * distribution)
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextCKKS(
      usint multiplicativeDepth, usint scalingFactorBits, usint batchSize,
      SecurityLevel stdLevel = HEStd_128_classic, usint ringDim = 0,
      enum RescalingTechnique rsTech = DEFAULTRSTECH,
      enum KeySwitchTechnique ksTech = HYBRID, uint32_t numLargeDigits = 0,
      int maxDepth = 2, usint firstModSize = FIRSTMODSIZE,
      usint relinWindow = 0, MODE mode = OPTIMIZED);

  /**
   * construct a PALISADE CryptoContextImpl for the BGVrns Scheme
   * @param plaintextmodulus
   * @param ringdim
   * @param modulus
   * @param rootOfUnity
   * @param relinWindow
   * @param stDev
   * @param mode
   * @param depth
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   * @param ksTech key switching technique to use (e.g., GHS or BV)
   * @param msMethod mod switch method
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBGVrns(
      shared_ptr<ParmType> params, const PlaintextModulus plaintextmodulus,
      usint relinWindow, float stDev, MODE mode = RLWE, int depth = 1,
      int maxDepth = 2, KeySwitchTechnique ksTech = BV,
      enum ModSwitchMethod msMethod = MANUAL);

  /**
   * construct a PALISADE CryptoContextImpl for the BGVrns Scheme
   * @param encodingParams
   * @param ringdim
   * @param modulus
   * @param rootOfUnity
   * @param relinWindow
   * @param stDev
   * @param mode
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   * @param ksTech key switching technique to use (e.g., GHS or BV)
   * @param msMethod mod switch method
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBGVrns(
      shared_ptr<ParmType> params, EncodingParams encodingParams,
      usint relinWindow, float stDev, MODE mode = RLWE, int depth = 1,
      int maxDepth = 2, enum KeySwitchTechnique ksTech = BV,
      enum ModSwitchMethod msMethod = MANUAL);

  /**
   * Automatically generate the moduli chain and construct a PALISADE
   * CryptoContextImpl for the BGVrns Scheme with it.
   *
   * @param cyclOrder the cyclotomic order M
   * @param numPrimes the number of towers/primes to use when building the
   * moduli chain
   * @param ptm the plaintext modulus
   * @param mode RLWE or OPTIMIZED
   * @param depth
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   * @param firstModSize the bit-length of the first modulus
   * @param dcrtrBits the size of the moduli in bits
   * @param ksTech key switching technique to use (e.g., GHS or BV)
   * @param numLargeDigits the number of big digits to use in HYBRID key
   * switching
   * @param batchSize the number of slots being used in the ciphertext
   * @param msMethod mod switch method
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBGVrnsWithParamsGen(
      usint cyclOrder, usint numPrimes, usint ptm, usint relinWindow, MODE mode,
      int depth = 1, int maxDepth = 2, enum KeySwitchTechnique ksTech = BV,
      usint firstModSize = 0, usint dcrtBits = 0, uint32_t numLargeDigits = 4,
      usint batchSize = 0, enum ModSwitchMethod msMethod = MANUAL);

  /**
   * Construct a PALISADE CryptoContextImpl for the BGVrns Scheme.
   *
   * @param multiplicativeDepth the depth of multiplications supported by the
   * scheme (equal to number of towers - 1)
   * @param ptm the plaintext modulus
   * @param stdLevel the standard security level we want the scheme to satisfy
   * @param stdDev sigma - distribution parameter for error distribution
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   * @param mode RLWE (gaussian distribution) or OPTIMIZED (ternary
   * distribution)
   * @param ksTech key switching technique to use (e.g., HYBRID, GHS or BV)
   * @param ringDim the ring dimension (if not specified selected automatically
   * based on stdLevel)
   * @param numLargeDigits the number of big digits to use in HYBRID key
   * switching
   * @param firstModSize the bit-length of the first modulus
   * @param dcrtrBits the size of the moduli in bits
   * @param relinWindow the relinearization windows (used in BV key switching,
   * use 0 for RNS decomposition)
   * @param batchSize the number of slots being used in the ciphertext
   * @param msMethod mod switch method
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBGVrns(
      usint multiplicativeDepth, usint ptm,
      SecurityLevel stdLevel = HEStd_128_classic, float stdDev = 3.19,
      int maxDepth = 2, MODE mode = OPTIMIZED,
      enum KeySwitchTechnique ksTech = HYBRID, usint ringDim = 0,
      uint32_t numLargeDigits = 0, usint firstModSize = 0, usint dcrtBits = 0,
      usint relinWindow = 0, usint batchSize = 0,
      enum ModSwitchMethod msMethod = AUTO);

  /**
   * construct a PALISADE CryptoContextImpl for the Null Scheme
   * @param m cyclotomic order (ring dimension n = m/2 for power-of-two
   * cyclotomics)
   * @param plaintextModulus plaintext modulus
   * @return
   */
  static CryptoContext<Element> genCryptoContextNull(
      unsigned int m, const PlaintextModulus ptModulus);

  /**
   * construct a PALISADE CryptoContextImpl for the Null Scheme
   * @param m cyclotomic order (ring dimension n = m/2 for power-of-two
   * cyclotomics)
   * @param encodingParams plaintext encoding parameters
   * @return
   */
  static CryptoContext<Element> genCryptoContextNull(
      unsigned int m, EncodingParams encodingParams);

};

}  // namespace lbcrypto

#endif /* SRC_PKE_CRYPTOCONTEXT_H_ */
