// @file pubkeylp.h -- Public key type for lattice crypto operations.
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

#ifndef LBCRYPTO_CRYPTO_PUBKEYLP_H
#define LBCRYPTO_CRYPTO_PUBKEYLP_H

#include <iomanip>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "lattice/elemparams.h"
#include "lattice/ilparams.h"

#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "utils/caller_info.h"
#include "utils/hashutil.h"
#include "utils/inttypes.h"

#include "math/distrgen.h"

#include "encoding/encodingparams.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/* This struct holds the different options for
 * key switching algorithms that are supported
 * by the library.
 *
 */
enum KeySwitchTechnique { BV, GHS, HYBRID };

/* This struct holds the different options for
 * mod switching algorithms that are supported
 * by the library.
 *
 */
enum ModSwitchMethod { MANUAL, AUTO };

// forward declarations, used to resolve circular header dependencies
template <typename Element>
class CiphertextImpl;

template <typename Element>
class LPCryptoParameters;

template <typename Element>
class LPCryptoParametersBFV;

template <typename Element>
class CryptoObject;

struct EncryptResult {
  EncryptResult() : isValid(false), numBytesEncrypted(0) {}

  explicit EncryptResult(size_t len) : isValid(true), numBytesEncrypted(len) {}

  bool isValid;  // whether the encryption was successful
  // count of the number of plaintext bytes that were encrypted
  usint numBytesEncrypted;
};

/**
 * @brief Decryption result.  This represents whether the decryption of a
 * cipheretext was performed correctly.
 *
 * This is intended to eventually incorporate information about the amount of
 * padding in a decoded ciphertext, to ensure that the correct amount of
 * padding is stripped away. It is intended to provided a very simple kind of
 * checksum eventually. This notion of a decoding output is inherited from the
 * crypto++ library. It is also intended to be used in a recover and restart
 * robust functionality if not all ciphertext is recieved over a lossy
 * channel, so that if all information is eventually recieved,
 * decoding/decryption can be performed eventually. This is intended to be
 * returned with the output of a decryption operation.
 */
struct DecryptResult {
  /**
   * Constructor that initializes all message lengths to 0.
   */
  DecryptResult() : isValid(false), messageLength(0) {}

  /**
   * Constructor that initializes all message lengths.
   * @param len the new length.
   */
  explicit DecryptResult(size_t len) : isValid(true), messageLength(len) {}

  bool isValid;        /**< whether the decryption was successful */
  usint messageLength; /**< the length of the decrypted plaintext message */
};

/**
 * @brief Abstract interface class for LP Keys
 *
 * @tparam Element a ring element.
 */
template <class Element>
class LPKey : public CryptoObject<Element>, public Serializable {
 public:
  explicit LPKey(CryptoContext<Element> cc, const string &id = "")
      : CryptoObject<Element>(cc, id) {}

  explicit LPKey(shared_ptr<CryptoObject<Element>> co)
      : CryptoObject<Element>(co) {}

  virtual ~LPKey() {}

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::base_class<CryptoObject<Element>>(this));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    ar(::cereal::base_class<CryptoObject<Element>>(this));
  }
};

template <typename Element>
class LPPublicKeyImpl;

template <typename Element>
using LPPublicKey = shared_ptr<LPPublicKeyImpl<Element>>;

/**
 * @brief Class for LP public keys
 * @tparam Element a ring element.
 */
template <typename Element>
class LPPublicKeyImpl : public LPKey<Element> {
 public:
  /**
   * Basic constructor
   *
   * @param cc - CryptoContext
   * @param id - key identifier
   */
  explicit LPPublicKeyImpl(CryptoContext<Element> cc = 0, const string &id = "")
      : LPKey<Element>(cc, id) {}

  /**
   * Copy constructor
   *
   *@param &rhs LPPublicKeyImpl to copy from
   */
  explicit LPPublicKeyImpl(const LPPublicKeyImpl<Element> &rhs)
      : LPKey<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
    m_h = rhs.m_h;
  }

  /**
   * Move constructor
   *
   *@param &rhs LPPublicKeyImpl to move from
   */
  explicit LPPublicKeyImpl(LPPublicKeyImpl<Element> &&rhs)
      : LPKey<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
    m_h = std::move(rhs.m_h);
  }

  operator bool() const {
    return static_cast<bool>(this->context) && m_h.size() != 0;
  }

  /**
   * Assignment Operator.
   *
   * @param &rhs LPPublicKeyImpl to copy from
   */
  const LPPublicKeyImpl<Element> &operator=(
      const LPPublicKeyImpl<Element> &rhs) {
    CryptoObject<Element>::operator=(rhs);
    this->m_h = rhs.m_h;
    return *this;
  }

  /**
   * Move Assignment Operator.
   *
   * @param &rhs LPPublicKeyImpl to copy from
   */
  const LPPublicKeyImpl<Element> &operator=(LPPublicKeyImpl<Element> &&rhs) {
    CryptoObject<Element>::operator=(rhs);
    m_h = std::move(rhs.m_h);
    return *this;
  }

  // @Get Properties

  /**
   * Gets the computed public key
   * @return the public key element.
   */
  const std::vector<Element> &GetPublicElements() const { return this->m_h; }

  // @Set Properties

  /**
   * Sets the public key vector of Element.
   * @param &element is the public key Element vector to be copied.
   */
  void SetPublicElements(const std::vector<Element> &element) { m_h = element; }

  /**
   * Sets the public key vector of Element.
   * @param &&element is the public key Element vector to be moved.
   */
  void SetPublicElements(std::vector<Element> &&element) {
    m_h = std::move(element);
  }

  /**
   * Sets the public key Element at index idx.
   * @param &element is the public key Element to be copied.
   */
  void SetPublicElementAtIndex(usint idx, const Element &element) {
    m_h.insert(m_h.begin() + idx, element);
  }

  /**
   * Sets the public key Element at index idx.
   * @param &&element is the public key Element to be moved.
   */
  void SetPublicElementAtIndex(usint idx, Element &&element) {
    m_h.insert(m_h.begin() + idx, std::move(element));
  }

  bool operator==(const LPPublicKeyImpl &other) const {
    if (!CryptoObject<Element>::operator==(other)) {
      return false;
    }

    if (m_h.size() != other.m_h.size()) {
      return false;
    }

    for (size_t i = 0; i < m_h.size(); i++) {
      if (m_h[i] != other.m_h[i]) {
        return false;
      }
    }

    return true;
  }

  bool operator!=(const LPPublicKeyImpl &other) const {
    return !(*this == other);
  }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::base_class<LPKey<Element>>(this));
    ar(::cereal::make_nvp("h", m_h));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::base_class<LPKey<Element>>(this));
    ar(::cereal::make_nvp("h", m_h));
  }

  std::string SerializedObjectName() const { return "PublicKey"; }
  static uint32_t SerializedVersion() { return 1; }

 private:
  std::vector<Element> m_h;
};

template <typename Element>
class LPEvalKeyImpl;

template <typename Element>
using LPEvalKey = shared_ptr<LPEvalKeyImpl<Element>>;

/**
 * @brief Abstract interface for LP evaluation/proxy keys
 * @tparam Element a ring element.
 */
template <class Element>
class LPEvalKeyImpl : public LPKey<Element> {
 public:
  /**
   * Basic constructor for setting crypto params
   *
   * @param &cryptoParams is the reference to cryptoParams
   */

  explicit LPEvalKeyImpl(CryptoContext<Element> cc = 0) : LPKey<Element>(cc) {}

  virtual ~LPEvalKeyImpl() {}

  /**
   * Setter function to store Relinearization Element Vector A.
   * Throws exception, to be overridden by derived class.
   *
   * @param &a is the Element vector to be copied.
   */

  virtual void SetAVector(const std::vector<Element> &a) {
    PALISADE_THROW(not_implemented_error,
                   "SetAVector copy operation not supported");
  }

  /**
   * Setter function to store Relinearization Element Vector A.
   * Throws exception, to be overridden by derived class.
   *
   * @param &&a is the Element vector to be moved.
   */

  virtual void SetAVector(std::vector<Element> &&a) {
    PALISADE_THROW(not_implemented_error,
                   "SetAVector move operation not supported");
  }

  /**
   * Getter function to access Relinearization Element Vector A.
   * Throws exception, to be overridden by derived class.
   *
   * @return Element vector A.
   */

  virtual const std::vector<Element> &GetAVector() const {
    PALISADE_THROW(not_implemented_error, "GetAVector operation not supported");
  }

  /**
   * Setter function to store Relinearization Element Vector B.
   * Throws exception, to be overridden by derived class.
   *
   * @param &b is the Element vector to be copied.
   */

  virtual void SetBVector(const std::vector<Element> &b) {
    PALISADE_THROW(not_implemented_error,
                   "SetBVector copy operation not supported");
  }

  /**
   * Setter function to store Relinearization Element Vector B.
   * Throws exception, to be overridden by derived class.
   *
   * @param &&b is the Element vector to be moved.
   */

  virtual void SetBVector(std::vector<Element> &&b) {
    PALISADE_THROW(not_implemented_error,
                   "SetBVector move operation not supported");
  }

  /**
   * Getter function to access Relinearization Element Vector B.
   * Throws exception, to be overridden by derived class.
   *
   * @return  Element vector B.
   */

  virtual const std::vector<Element> &GetBVector() const {
    PALISADE_THROW(not_implemented_error, "GetBVector operation not supported");
  }

  /**
   * Setter function to store key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @param &a is the Element to be copied.
   */

  virtual void SetA(const Element &a) {
    PALISADE_THROW(not_implemented_error, "SetA copy operation not supported");
  }

  /**
   * Setter function to store key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @param &&a is the Element to be moved.
   */
  virtual void SetA(Element &&a) {
    PALISADE_THROW(not_implemented_error, "SetA move operation not supported");
  }

  /**
   * Getter function to access key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @return  Element.
   */

  virtual const Element &GetA() const {
    PALISADE_THROW(not_implemented_error, "GetA operation not supported");
  }

  /**
   * Setter function to store key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @param &a is the Element to be copied.
   */

  virtual void SetAinDCRT(const DCRTPoly &a) {
    PALISADE_THROW(not_implemented_error,
                   "SetAinDCRT copy operation not supported");
  }

  /**
   * Setter function to store key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @param &&a is the Element to be moved.
   */
  virtual void SetAinDCRT(DCRTPoly &&a) {
    PALISADE_THROW(not_implemented_error,
                   "SetAinDCRT move operation not supported");
  }

  /**
   * Getter function to access key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @return  Element.
   */

  virtual const DCRTPoly &GetAinDCRT() const {
    PALISADE_THROW(not_implemented_error, "GetAinDCRT operation not supported");
  }

  /**
   * Setter function to store key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @param &b is the Element to be copied.
   */

  virtual void SetBinDCRT(const DCRTPoly &b) {
    PALISADE_THROW(not_implemented_error,
                   "SetAinDCRT copy operation not supported");
  }

  /**
   * Setter function to store key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @param &&b is the Element to be moved.
   */
  virtual void SetBinDCRT(DCRTPoly &&b) {
    PALISADE_THROW(not_implemented_error,
                   "SetAinDCRT move operation not supported");
  }

  /**
   * Getter function to access key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @return  Element.
   */

  virtual const DCRTPoly &GetBinDCRT() const {
    PALISADE_THROW(not_implemented_error, "GetAinDCRT operation not supported");
  }

  virtual void ClearKeys() {
    PALISADE_THROW(not_implemented_error,
                   "ClearKeys operation is not supported");
  }

  friend bool operator==(const LPEvalKeyImpl &a, const LPEvalKeyImpl &b) {
    return a.key_compare(b);
  }

  friend bool operator!=(const LPEvalKeyImpl &a, LPEvalKeyImpl &b) {
    return !(a == b);
  }

  virtual bool key_compare(const LPEvalKeyImpl &other) const { return false; }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::base_class<LPKey<Element>>(this));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    ar(::cereal::base_class<LPKey<Element>>(this));
  }
  std::string SerializedObjectName() const { return "EvalKey"; }
};

template <typename Element>
class LPEvalKeyRelinImpl;

template <typename Element>
using LPEvalKeyRelin = shared_ptr<LPEvalKeyRelinImpl<Element>>;

/**
 * @brief Concrete class for Relinearization keys of RLWE scheme
 * @tparam Element a ring element.
 */
template <class Element>
class LPEvalKeyRelinImpl : public LPEvalKeyImpl<Element> {
 public:
  /**
   * Basic constructor for setting crypto params
   *
   * @param &cryptoParams is the reference to cryptoParams
   */
  explicit LPEvalKeyRelinImpl(CryptoContext<Element> cc = 0)
      : LPEvalKeyImpl<Element>(cc) {}

  virtual ~LPEvalKeyRelinImpl() {}

  /**
   * Copy constructor
   *
   *@param &rhs key to copy from
   */
  explicit LPEvalKeyRelinImpl(const LPEvalKeyRelinImpl<Element> &rhs)
      : LPEvalKeyImpl<Element>(rhs.GetCryptoContext()) {
    m_rKey = rhs.m_rKey;
  }

  /**
   * Move constructor
   *
   *@param &rhs key to move from
   */
  explicit LPEvalKeyRelinImpl(LPEvalKeyRelinImpl<Element> &&rhs)
      : LPEvalKeyImpl<Element>(rhs.GetCryptoContext()) {
    m_rKey = std::move(rhs.m_rKey);
  }

  operator bool() const {
    return static_cast<bool>(this->context) && m_rKey.size() != 0;
  }

  /**
   * Assignment Operator.
   *
   * @param &rhs key to copy from
   */
  const LPEvalKeyRelinImpl<Element> &operator=(
      const LPEvalKeyRelinImpl<Element> &rhs) {
    this->context = rhs.context;
    this->m_rKey = rhs.m_rKey;
    return *this;
  }

  /**
   * Move Assignment Operator.
   *
   * @param &rhs key to move from
   */
  const LPEvalKeyRelinImpl<Element> &operator=(
      LPEvalKeyRelinImpl<Element> &&rhs) {
    this->context = rhs.context;
    rhs.context = 0;
    m_rKey = std::move(rhs.m_rKey);
    return *this;
  }

  /**
   * Setter function to store Relinearization Element Vector A.
   * Overrides base class implementation.
   *
   * @param &a is the Element vector to be copied.
   */
  virtual void SetAVector(const std::vector<Element> &a) {
    m_rKey.insert(m_rKey.begin() + 0, a);
  }

  /**
   * Setter function to store Relinearization Element Vector A.
   * Overrides base class implementation.
   *
   * @param &&a is the Element vector to be moved.
   */
  virtual void SetAVector(std::vector<Element> &&a) {
    m_rKey.insert(m_rKey.begin() + 0, std::move(a));
  }

  /**
   * Getter function to access Relinearization Element Vector A.
   * Overrides base class implementation.
   *
   * @return Element vector A.
   */
  virtual const std::vector<Element> &GetAVector() const {
    return m_rKey.at(0);
  }

  /**
   * Setter function to store Relinearization Element Vector B.
   * Overrides base class implementation.
   *
   * @param &b is the Element vector to be copied.
   */
  virtual void SetBVector(const std::vector<Element> &b) {
    m_rKey.insert(m_rKey.begin() + 1, b);
  }

  /**
   * Setter function to store Relinearization Element Vector B.
   * Overrides base class implementation.
   *
   * @param &&b is the Element vector to be moved.
   */
  virtual void SetBVector(std::vector<Element> &&b) {
    m_rKey.insert(m_rKey.begin() + 1, std::move(b));
  }

  /**
   * Getter function to access Relinearization Element Vector B.
   * Overrides base class implementation.
   *
   * @return Element vector B.
   */
  virtual const std::vector<Element> &GetBVector() const {
    return m_rKey.at(1);
  }

  /**
   * Setter function to store key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @param &a is the Element to be copied.
   */

  virtual void SetAinDCRT(const DCRTPoly &a) {
    m_dcrtKeys.insert(m_dcrtKeys.begin() + 0, a);
  }

  /**
   * Setter function to store key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @param &&a is the Element to be moved.
   */
  virtual void SetAinDCRT(DCRTPoly &&a) {
    m_dcrtKeys.insert(m_dcrtKeys.begin() + 0, std::move(a));
  }

  /**
   * Getter function to access key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @return  Element.
   */

  virtual const DCRTPoly &GetAinDCRT() const { return m_dcrtKeys.at(0); }

  /**
   * Setter function to store key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @param &b is the Element to be copied.
   */

  virtual void SetBinDCRT(const DCRTPoly &b) {
    m_dcrtKeys.insert(m_dcrtKeys.begin() + 1, b);
  }

  /**
   * Setter function to store key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @param &&b is the Element to be moved.
   */
  virtual void SetBinDCRT(DCRTPoly &&b) {
    m_dcrtKeys.insert(m_dcrtKeys.begin() + 1, std::move(b));
  }

  /**
   * Getter function to access key switch Element.
   * Throws exception, to be overridden by derived class.
   *
   * @return  Element.
   */

  virtual const DCRTPoly &GetBinDCRT() const { return m_dcrtKeys.at(1); }

  virtual void ClearKeys() {
    m_rKey.clear();
    m_dcrtKeys.clear();
  }


  bool key_compare(const LPEvalKeyImpl<Element> &other) const {
    const auto &oth = static_cast<const LPEvalKeyRelinImpl<Element> &>(other);

    if (!CryptoObject<Element>::operator==(other)) return false;

    if (this->m_rKey.size() != oth.m_rKey.size()) return false;
    for (size_t i = 0; i < this->m_rKey.size(); i++) {
      if (this->m_rKey[i].size() != oth.m_rKey[i].size()) return false;
      for (size_t j = 0; j < this->m_rKey[i].size(); j++) {
        if (this->m_rKey[i][j] != oth.m_rKey[i][j]) return false;
      }
    }
    return true;
  }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::base_class<LPEvalKeyImpl<Element>>(this));
    ar(::cereal::make_nvp("k", m_rKey));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::base_class<LPEvalKeyImpl<Element>>(this));
    ar(::cereal::make_nvp("k", m_rKey));
  }
  std::string SerializedObjectName() const { return "EvalKeyRelin"; }
  static uint32_t SerializedVersion() { return 1; }

 private:
  // private member to store vector of vector of Element.
  std::vector<std::vector<Element>> m_rKey;

  // Used for GHS key switching
  std::vector<DCRTPoly> m_dcrtKeys;
};

template <typename Element>
class LPPrivateKeyImpl;

template <typename Element>
using LPPrivateKey = shared_ptr<LPPrivateKeyImpl<Element>>;

/**
 * @brief Class fpr LP Private keys
 * @tparam Element a ring element.
 */
template <class Element>
class LPPrivateKeyImpl : public LPKey<Element> {
 public:
  /**
   * Construct in context
   */

  explicit LPPrivateKeyImpl(CryptoContext<Element> cc = 0)
      : LPKey<Element>(cc, GenerateUniqueKeyID()) {}

  /**
   * Copy constructor
   *@param &rhs the LPPrivateKeyImpl to copy from
   */
  explicit LPPrivateKeyImpl(const LPPrivateKeyImpl<Element> &rhs)
      : LPKey<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
    this->m_sk = rhs.m_sk;
  }

  /**
   * Move constructor
   *@param &rhs the LPPrivateKeyImpl to move from
   */
  explicit LPPrivateKeyImpl(LPPrivateKeyImpl<Element> &&rhs)
      : LPKey<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
    this->m_sk = std::move(rhs.m_sk);
  }

  operator bool() const { return static_cast<bool>(this->context); }

  /**
   * Assignment Operator.
   *
   * @param &rhs LPPrivateKeyto assign from.
   * @return the resulting LPPrivateKeyImpl
   */
  const LPPrivateKeyImpl<Element> &operator=(
      const LPPrivateKeyImpl<Element> &rhs) {
    CryptoObject<Element>::operator=(rhs);
    this->m_sk = rhs.m_sk;
    return *this;
  }

  /**
   * Move Assignment Operator.
   *
   * @param &rhs LPPrivateKeyImpl to assign from.
   * @return the resulting LPPrivateKeyImpl
   */
  const LPPrivateKeyImpl<Element> &operator=(LPPrivateKeyImpl<Element> &&rhs) {
    CryptoObject<Element>::operator=(rhs);
    this->m_sk = std::move(rhs.m_sk);
    return *this;
  }

  /**
   * Implementation of the Get accessor for private element.
   * @return the private element.
   */
  const Element &GetPrivateElement() const { return m_sk; }

  /**
   * Set accessor for private element.
   * @private &x private element to set to.
   */
  void SetPrivateElement(const Element &x) { m_sk = x; }

  /**
   * Set accessor for private element.
   * @private &x private element to set to.
   */
  void SetPrivateElement(Element &&x) { m_sk = std::move(x); }

  bool operator==(const LPPrivateKeyImpl &other) const {
    return CryptoObject<Element>::operator==(other) && m_sk == other.m_sk;
  }

  bool operator!=(const LPPrivateKeyImpl &other) const {
    return !(*this == other);
  }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::base_class<LPKey<Element>>(this));
    ar(::cereal::make_nvp("s", m_sk));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::base_class<LPKey<Element>>(this));
    ar(::cereal::make_nvp("s", m_sk));
  }

  std::string SerializedObjectName() const { return "PrivateKey"; }
  static uint32_t SerializedVersion() { return 1; }

 private:
  Element m_sk;
};

template <class Element>
class LPKeyPair {
 public:
  LPPublicKey<Element> publicKey;
  LPPrivateKey<Element> secretKey;

  LPKeyPair(LPPublicKey<Element> a, LPPrivateKey<Element> b)
      : publicKey(a), secretKey(b) {}

  LPKeyPair(LPPublicKeyImpl<Element> *a = nullptr,
            LPPrivateKeyImpl<Element> *b = nullptr)
      : publicKey(a), secretKey(b) {}

  bool good() { return publicKey && secretKey; }
};

/**
 * @brief Abstract interface for parameter generation algorithm
 * @tparam Element a ring element.
 */
template <class Element>
class LPParameterGenerationAlgorithm {
 public:
  virtual ~LPParameterGenerationAlgorithm() {}

  /**
   * Method for computing all derived parameters based on chosen primitive
   * parameters
   *
   * @param *cryptoParams the crypto parameters object to be populated with
   * parameters.
   * @param evalAddCount number of EvalAdds assuming no EvalMult and KeySwitch
   * operations are performed.
   * @param evalMultCount number of EvalMults assuming no EvalAdd and
   * KeySwitch operations are performed.
   * @param keySwitchCount number of KeySwitch operations assuming no EvalAdd
   * and EvalMult operations are performed.
   * @param dcrtBits number of bits in each CRT modulus*
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   */
  virtual bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams,
                         int32_t evalAddCount = 0, int32_t evalMultCount = 0,
                         int32_t keySwitchCount = 0, size_t dcrtBits = 0,
                         uint32_t n = 0) const = 0;

  /**
   * Method for computing all derived parameters based on chosen primitive
   * parameters. This is intended for CKKS and DCRTPoly.
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
  virtual bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams,
                         usint cyclOrder, usint numPrimes, usint scaleExp,
                         usint relinWindow, MODE mode,
                         KeySwitchTechnique ksTech, usint firstModSize,
                         RescalingTechnique rsTech) const {
    PALISADE_THROW(
        config_error,
        "This signature for ParamsGen is not supported for this scheme.");
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
  virtual bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams,
                         usint cyclOrder, usint numPrimes, usint scaleExp,
                         usint relinWindow, MODE mode,
                         KeySwitchTechnique ksTech = BV,
                         usint firstModSize = 60,
                         RescalingTechnique = APPROXRESCALE,
                         uint32_t numLargeDigits = 4) const {
    PALISADE_THROW(
        config_error,
        "This signature for ParamsGen is not supported for this scheme.");
  }

  /**
   * Method for computing all derived parameters based on chosen primitive
   * parameters. This is intended for BGVrns
   * @param *cryptoParams the crypto parameters object to be populated with
   * parameters.
   * @param cyclOrder the cyclotomic order.
   * @param numPrimes number of modulus towers to support.
   * @param relinWindow the relinearization window
   * @param mode
   * @param ksTech the key switching technique used (e.g., BV or GHS)
   * @param firstModSize the bit-size of the first modulus
   * @param dcrtBits the bit-width of moduli.
   */
  virtual bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams,
                         usint cyclOrder, usint ptm, usint numPrimes,
                         usint relinWindow, MODE mode,
                         KeySwitchTechnique ksTech = BV,
                         usint firstModSize = 60, usint dcrtBits = 60,
                         uint32_t numLargeDigits = 4) const {
    PALISADE_THROW(
        not_implemented_error,
        "This signature for ParamsGen is not supported for this scheme.");
  }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {}

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {}

  std::string SerializedObjectName() const { return "ParamsGen"; }
};

/**
 * @brief Abstract interface for encryption algorithm
 * @tparam Element a ring element.
 */
template <class Element>
class LPEncryptionAlgorithm {
 public:
  virtual ~LPEncryptionAlgorithm() {}

  /**
   * Method for encrypting plaintext using LBC
   *
   * @param&publicKey public key used for encryption.
   * @param plaintext copy of the plaintext element. NOTE a copy is passed!
   * That is NOT an error!
   * @param doEncryption encrypts if true, embeds (encodes) the plaintext into
   * cryptocontext if false
   * @param *ciphertext ciphertext which results from encryption.
   */
  virtual Ciphertext<Element> Encrypt(const LPPublicKey<Element> publicKey,
                                      Element plaintext) const = 0;

  /**
   * Method for encrypting plaintex using LBC
   *
   * @param privateKey private key used for encryption.
   * @param plaintext copy of the plaintext input. NOTE a copy is passed! That
   * is NOT an error!
   * @param doEncryption encrypts if true, embeds (encodes) the plaintext into
   * cryptocontext if false
   * @param *ciphertext ciphertext which results from encryption.
   */
  virtual Ciphertext<Element> Encrypt(const LPPrivateKey<Element> privateKey,
                                      Element plaintext) const = 0;

  /**
   * Method for decrypting plaintext using LBC
   *
   * @param &privateKey private key used for decryption.
   * @param &ciphertext ciphertext id decrypted.
   * @param *plaintext the plaintext output.
   * @return the decoding result.
   */
  virtual DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
                                ConstCiphertext<Element> ciphertext,
                                NativePoly *plaintext) const = 0;

  /**
   * Method for decrypting plaintext using LBC
   *
   * @param &privateKey private key used for decryption.
   * @param &ciphertext ciphertext id decrypted.
   * @param *plaintext the plaintext output.
   * @return the decoding result.
   */
  virtual DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
                                ConstCiphertext<Element> ciphertext,
                                Poly *plaintext) const {
    PALISADE_THROW(config_error, "Decryption to Poly is not supported");
  }

  /**
   * Function to generate public and private keys
   *
   * @param &publicKey private key used for decryption.
   * @param &privateKey private key used for decryption.
   * @return function ran correctly.
   */
  virtual LPKeyPair<Element> KeyGen(CryptoContext<Element> cc,
                                    bool makeSparse = false) = 0;
};

/**
 * @brief Abstract interface for Leveled SHE operations
 * @tparam Element a ring element.
 */
template <class Element>
class LPLeveledSHEAlgorithm {
 public:
  virtual ~LPLeveledSHEAlgorithm() {}

  /**
   * Method for In-place Modulus Reduction.
   *
   * @param &cipherText Ciphertext to perform mod reduce on.
   * @param levels the number of towers to drop.
   */
  virtual void ModReduceInPlace(Ciphertext<Element> &ciphertext,
                                size_t levels = 1) const = 0;

  /**
   * Method for Modulus Reduction.
   *
   * @param &cipherText Ciphertext to perform mod reduce on.
   * @param levels the number of towers to drop.
   */
  virtual Ciphertext<Element> ModReduce(ConstCiphertext<Element> ciphertext,
                                        size_t levels = 1) const {
    auto rv = ciphertext->Clone();
    ModReduceInPlace(rv, levels);
    return rv;
  }

  /**
   * Method for rescaling.
   *
   * @param cipherText is the ciphertext to perform modreduce on.
   * @param levels the number of towers to drop.
   * @return ciphertext after the modulus reduction performed.
   */
  virtual Ciphertext<Element> ModReduceInternal(
      ConstCiphertext<Element> ciphertext, size_t levels = 1) const {
    PALISADE_THROW(config_error,
                   "ModReduceInternal is not supported for this scheme");
  }

  /**
   * Method for rescaling in-place.
   *
   * @param cipherText is the ciphertext to perform modreduce on.
   * @param levels the number of towers to drop.
   * @details \p cipherText will have modulus reduction performed in-place.
   */
  virtual void ModReduceInternalInPlace(Ciphertext<Element> &ciphertext,
                                        size_t levels = 1) const {
    PALISADE_THROW(config_error,
                   "ModReduceInternalInPlace is not supported for this scheme");
  }

  virtual Ciphertext<Element> Compress(ConstCiphertext<Element> ciphertext,
                                       size_t towersLeft = 1) const {
    PALISADE_THROW(config_error, "Compress is not supported for this scheme");
  }

  /**
   * Method for Composed EvalMult
   *
   * @param &cipherText1 ciphertext1, first input ciphertext to perform
   * multiplication on.
   * @param &cipherText2 cipherText2, second input ciphertext to perform
   * multiplication on.
   * @param &quadKeySwitchHint is for resultant quadratic secret key after
   * multiplication to the secret key of the particular level.
   * @param &cipherTextResult is the resulting ciphertext that can be
   * decrypted with the secret key of the particular level.
   */
  virtual Ciphertext<Element> ComposedEvalMult(
      ConstCiphertext<Element> cipherText1,
      ConstCiphertext<Element> cipherText2,
      const LPEvalKey<Element> quadKeySwitchHint) const = 0;

  /**
   * Method for Level Reduction from sk -> sk1. This method peforms a
   * keyswitch on the ciphertext and then performs a modulus reduction.
   *
   * @param &cipherText1 is the original ciphertext to be key switched and mod
   * reduced.
   * @param &linearKeySwitchHint is the linear key switch hint to perform the
   * key switch operation.
   * @param &cipherTextResult is the resulting ciphertext.
   */
  virtual Ciphertext<Element> LevelReduce(
      ConstCiphertext<Element> cipherText1,
      const LPEvalKey<Element> linearKeySwitchHint, size_t levels) const = 0;

  /**
   * Method for Level Reduction in the CKKS scheme. It just drops "levels"
   * number of the towers of the ciphertext without changing the underlying
   * plaintext.
   *
   * @param cipherText1 is the original ciphertext to be level reduced.
   * @param linearKeySwitchHint not used in the CKKS scheme.
   * @param levels the number of towers to drop.
   * @return resulting ciphertext.
   */
  virtual Ciphertext<Element> LevelReduceInternal(
      ConstCiphertext<Element> cipherText1,
      const LPEvalKey<Element> linearKeySwitchHint, size_t levels) const {
    PALISADE_THROW(config_error,
                   "LevelReduceInternal is not supported for this scheme");
  }

  /**
   * Method for in-place Level Reduction in the CKKS scheme. It just drops
   * "levels" number of the towers of the ciphertext without changing the
   * underlying plaintext.
   *
   * @param cipherText1 is the ciphertext to be level reduced in-place
   * @param linearKeySwitchHint not used in the CKKS scheme.
   * @param levels the number of towers to drop.
   */
  virtual void LevelReduceInternalInPlace(
      Ciphertext<Element> &cipherText1,
      const LPEvalKey<Element> linearKeySwitchHint, size_t levels) const {
    PALISADE_THROW(
        config_error,
        "LevelReduceInternalInPlace is not supported for this scheme");
  }

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
      ConstCiphertext<Element> cipherText,
      const std::vector<double> &coefficients) const {
    PALISADE_THROW(config_error, "EvalPoly is not supported for the scheme.");
  }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {}

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {}

  std::string SerializedObjectName() const { return "LeveledSHE"; }
};

/**
 * @brief Abstract interface class for LBC PRE algorithms
 * @tparam Element a ring element.
 */
template <class Element>
class LPPREAlgorithm {
 public:
  virtual ~LPPREAlgorithm() {}

  /**
   * Virtual function to generate 1..log(q) encryptions for each bit of the
   * original private key Variant that uses the public key for the new secret
   * key.
   *
   * @param &newKey public key for the new secret key.
   * @param &origPrivateKey original private key used for decryption.
   * @param *evalKey the evaluation key.
   * @return the re-encryption key.
   */
  virtual LPEvalKey<Element> ReKeyGen(
      const LPPublicKey<Element> newKey,
      const LPPrivateKey<Element> origPrivateKey) const = 0;

  /**
   * Virtual function to define the interface for re-encypting ciphertext
   * using the array generated by ProxyGen
   *
   * @param &evalKey proxy re-encryption key.
   * @param &ciphertext the input ciphertext.
   * @param publicKey the public key of the recipient of the re-encrypted
   * ciphertext.
   * @param *newCiphertext the new ciphertext.
   */
  virtual Ciphertext<Element> ReEncrypt(
      const LPEvalKey<Element> evalKey, ConstCiphertext<Element> ciphertext,
      const LPPublicKey<Element> publicKey = nullptr) const = 0;
};

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
class LPMultipartyAlgorithm {
 public:
  virtual ~LPMultipartyAlgorithm() {}

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
  virtual LPKeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
                                              const LPPublicKey<Element> pk1,
                                              bool makeSparse = false,
                                              bool fresh = false) = 0;

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
  virtual LPKeyPair<Element> MultipartyKeyGen(
      CryptoContext<Element> cc,
      const vector<LPPrivateKey<Element>> &secretKeys,
      bool makeSparse = false) = 0;

  /**
   * Threshold FHE: "Partial" decryption computed by all parties except for the
   * lead one
   *
   * @param privateKey secret key share used for decryption.
   * @param ciphertext ciphertext that is being decrypted.
   */
  virtual Ciphertext<Element> MultipartyDecryptMain(
      const LPPrivateKey<Element> privateKey,
      ConstCiphertext<Element> ciphertext) const = 0;

  /**
   * Threshold FHE: Method for decryption operation run by the lead decryption
   * client
   *
   * @param privateKey secret key share used for decryption.
   * @param ciphertext ciphertext id decrypted.
   */
  virtual Ciphertext<Element> MultipartyDecryptLead(
      const LPPrivateKey<Element> privateKey,
      ConstCiphertext<Element> ciphertext) const = 0;

  /**
   * Threshold FHE: Method for combining the partially decrypted ciphertexts
   * and getting the final decryption in the clear as a NativePoly.
   *
   * @param &ciphertextVec vector of "partial" decryptions.
   * @param *plaintext the plaintext output as a NativePoly.
   * @return the decoding result.
   */
  virtual DecryptResult MultipartyDecryptFusion(
      const vector<Ciphertext<Element>> &ciphertextVec,
      NativePoly *plaintext) const = 0;

  /**
   * Threshold FHE: Method for combining the partially decrypted ciphertexts
   * and getting the final decryption in the clear as a Poly.
   *
   * @param &ciphertextVec vector of "partial" decryptions.
   * @param *plaintext the plaintext output as a Poly.
   * @return the decoding result.
   */
  virtual DecryptResult MultipartyDecryptFusion(
      const vector<Ciphertext<Element>> &ciphertextVec, Poly *plaintext) const {
    PALISADE_THROW(config_error, "Decryption to Poly is not supported");
  }

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
  virtual LPEvalKey<Element> MultiKeySwitchGen(
      const LPPrivateKey<Element> originalPrivateKey,
      const LPPrivateKey<Element> newPrivateKey,
      const LPEvalKey<Element> ek) const {
    PALISADE_THROW(not_implemented_error,
                   "MultiKeySwitchGen multi-party capability is not supported "
                   "for this scheme");
  }

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
  virtual std::shared_ptr<std::map<usint, LPEvalKey<Element>>>
  MultiEvalAutomorphismKeyGen(
      const LPPrivateKey<Element> privateKey,
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> eAuto,
      const std::vector<usint> &indexList) const {
    PALISADE_THROW(not_implemented_error,
                   "MultiEvalAutomorphismKeyGen multi-party capability is not "
                   "supported for this scheme");
  }

  /**
   * Threshold FHE: Generates joined summation evaluation keys
   * from the current secret share and prior joined
   * summation keys
   *
   * @param privateKey secret key share.
   * @param eSum a dictionary with prior joined summation keys.
   * @return new joined summation keys.
   */
  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiEvalSumKeyGen(
      const LPPrivateKey<Element> privateKey,
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> eSum) const {
    PALISADE_THROW(not_implemented_error,
                   "MultiEvalSumKeyGen multi-party capability is not supported "
                   "for this scheme");
  }

  /**
   * Threshold FHE: Adds two prior public keys
   *
   * @param evalKey1 first public key.
   * @param evalKey2 second public key.
   * @return the new joined key.
   */
  virtual LPPublicKey<Element> MultiAddPubKeys(
      LPPublicKey<Element> pubKey1, LPPublicKey<Element> pubKey2) const {
    if (!pubKey1)
      PALISADE_THROW(config_error, "Input first public key is nullptr");
    if (!pubKey2)
      PALISADE_THROW(config_error, "Input second public key is nullptr");

    LPPublicKey<Element> pubKey(
        new LPPublicKeyImpl<Element>(pubKey1->GetCryptoContext()));

    if (pubKey1->GetPublicElements()[1] != pubKey2->GetPublicElements()[1])
      PALISADE_THROW(type_error,
                     "MultiAddPubKeys: public keys are not compatible");

    const Element &a = pubKey1->GetPublicElements()[1];

    const Element &b1 = pubKey1->GetPublicElements()[0];
    const Element &b2 = pubKey2->GetPublicElements()[0];

    pubKey->SetPublicElementAtIndex(0, std::move(b1 + b2));
    pubKey->SetPublicElementAtIndex(1, a);

    return pubKey;
  }

  /**
   * Threshold FHE: Adds two prior evaluation keys
   *
   * @param evalKey1 first evaluation key.
   * @param evalKey2 second evaluation key.
   * @return the new joined key.
   */
  virtual LPEvalKey<Element> MultiAddEvalKeys(
      LPEvalKey<Element> evalKey1, LPEvalKey<Element> evalKey2) const {
    if (!evalKey1)
      PALISADE_THROW(config_error, "Input first evaluation key is nullptr");
    if (!evalKey2)
      PALISADE_THROW(config_error, "Input second evaluation key is nullptr");

    LPEvalKey<Element> evalKeySum(
        new LPEvalKeyRelinImpl<Element>(evalKey1->GetCryptoContext()));

    const std::vector<Element> &a = evalKey1->GetAVector();

    const std::vector<Element> &b1 = evalKey1->GetBVector();
    const std::vector<Element> &b2 = evalKey2->GetBVector();

    std::vector<Element> b;

    for (usint i = 0; i < a.size(); i++) {
      b.push_back(b1[i] + b2[i]);
    }

    evalKeySum->SetAVector(a);
    evalKeySum->SetBVector(std::move(b));

    return evalKeySum;
  }

  /**
   * Threshold FHE: Generates a partial evaluation key for homomorphic
   * multiplication based on the current secret share and an existing partial
   * evaluation key
   *
   * @param evalKey prior evaluation key.
   * @param sk current secret share.
   * @return the new joined key.
   */
  virtual LPEvalKey<Element> MultiMultEvalKey(LPEvalKey<Element> evalKey,
                                              LPPrivateKey<Element> sk) const {
    PALISADE_THROW(not_implemented_error,
                   "MultiMultEvalKey multi-party capability is not supported "
                   "for this scheme");
  }

  /**
   * Threshold FHE: Adds two prior evaluation key sets for summation
   *
   * @param es1 first summation key set.
   * @param es2 second summation key set.
   * @return the new joined key set for summation.
   */
  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiAddEvalSumKeys(
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> es1,
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> es2) const {
    if (!es1)
      PALISADE_THROW(config_error, "Input first evaluation key map is nullptr");
    if (!es2)
      PALISADE_THROW(config_error,
                     "Input second evaluation key map is nullptr");

    auto evalSumKeys = std::make_shared<std::map<usint, LPEvalKey<Element>>>();

    for (auto it = es1->begin(); it != es1->end(); ++it) {
      auto it2 = es2->find(it->first);
      if (it2 != es2->end())
        (*evalSumKeys)[it->first] = MultiAddEvalKeys(it->second, it2->second);
    }

    return evalSumKeys;
  }

  /**
   * Threshold FHE: Adds two prior evaluation key sets for automorphisms
   *
   * @param es1 first automorphism key set.
   * @param es2 second automorphism key set.
   * @return the new joined key set for summation.
   */
  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>>
  MultiAddEvalAutomorphismKeys(
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> es1,
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> es2) const {
    if (!es1)
      PALISADE_THROW(config_error, "Input first evaluation key map is nullptr");
    if (!es2)
      PALISADE_THROW(config_error,
                     "Input second evaluation key map is nullptr");

    auto evalAutomorphismKeys =
        std::make_shared<std::map<usint, LPEvalKey<Element>>>();

    for (auto it = es1->begin(); it != es1->end(); ++it) {
      auto it2 = es2->find(it->first);
      if (it2 != es2->end())
        (*evalAutomorphismKeys)[it->first] =
            MultiAddEvalKeys(it->second, it2->second);
    }

    return evalAutomorphismKeys;
  }

  /**
   * Threshold FHE: Adds two  partial evaluation keys for multiplication
   *
   * @param evalKey1 first evaluation key.
   * @param evalKey2 second evaluation key.
   * @return the new joined key.
   */
  virtual LPEvalKey<Element> MultiAddEvalMultKeys(
      LPEvalKey<Element> evalKey1, LPEvalKey<Element> evalKey2) const {
    if (!evalKey1)
      PALISADE_THROW(config_error, "Input first evaluation key is nullptr");
    if (!evalKey2)
      PALISADE_THROW(config_error, "Input second evaluation key is nullptr");

    LPEvalKey<Element> evalKeySum(
        new LPEvalKeyRelinImpl<Element>(evalKey1->GetCryptoContext()));

    const std::vector<Element> &a1 = evalKey1->GetAVector();
    const std::vector<Element> &a2 = evalKey2->GetAVector();

    const std::vector<Element> &b1 = evalKey1->GetBVector();
    const std::vector<Element> &b2 = evalKey2->GetBVector();

    std::vector<Element> a;
    std::vector<Element> b;

    for (usint i = 0; i < a1.size(); i++) {
      a.push_back(a1[i] + a2[i]);
      b.push_back(b1[i] + b2[i]);
    }

    evalKeySum->SetAVector(std::move(a));

    evalKeySum->SetBVector(std::move(b));

    return evalKeySum;
  }

  /**
   * Threshold FHE: Generates evaluation keys for a list of indices for a
   * multi-party setting Currently works only for power-of-two and cyclic-group
   * cyclotomics
   *
   * @param secretShare secret share
   * @param partial evaluation key set from other party (parties)
   * @param indexList list of indices to be computed
   * @return returns the joined evaluation keys
   */
  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>>
  MultiEvalAtIndexKeyGen(
      const LPPrivateKey<Element> secretShare,
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> eAuto,
      const std::vector<int32_t> &indexList) const {
    if (!secretShare)
      PALISADE_THROW(config_error, "Input private key is nullptr");
    if (!eAuto)
      PALISADE_THROW(config_error, "Input evaluation key map is nullptr");
    if (!indexList.size())
      PALISADE_THROW(config_error, "Input index vector is empty");
    const auto cryptoParams = secretShare->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();
    const auto elementParams = cryptoParams->GetElementParams();
    uint32_t m = elementParams->GetCyclotomicOrder();

    std::vector<uint32_t> autoIndices(indexList.size());

    if (IsPowerOfTwo(m)) {  // power-of-two cyclotomics
      for (size_t i = 0; i < indexList.size(); i++) {
        auto ccInst = secretShare->GetCryptoContext();
        // CKKS Packing
        if (ccInst->getSchemeId() == "CKKS")
          autoIndices[i] = FindAutomorphismIndex2nComplex(indexList[i], m);
        else
          autoIndices[i] = FindAutomorphismIndex2n(indexList[i], m);
      }

    } else {  // cyclic groups
      for (size_t i = 0; i < indexList.size(); i++)
        autoIndices[i] = FindAutomorphismIndexCyclic(
            indexList[i], m, encodingParams->GetPlaintextGenerator());
    }

    return MultiEvalAutomorphismKeyGen(secretShare, eAuto, autoIndices);
  }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {}

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {}

  std::string SerializedObjectName() const { return "MultiParty"; }
};

/**
 * @brief Abstract interface class for LBC SHE algorithms
 * @tparam Element a ring element.
 */
template <class Element>
class LPSHEAlgorithm {
 public:
  virtual ~LPSHEAlgorithm() {}

  /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts.
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalAdd(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2) const {
    auto rv = ciphertext1->Clone();
    EvalAddInPlace(rv, ciphertext2);
    return rv;
  }

  /**
   * Virtual function to define the interface for in-place homomorphic addition
   * of ciphertexts.
   *
   * @param ciphertext1 the input/output ciphertext.
   * @param ciphertext2 the input ciphertext.
   */
  virtual void EvalAddInPlace(Ciphertext<Element> &ciphertext1,
                              ConstCiphertext<Element> ciphertext2) const = 0;

  /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts. This is the mutable version - input ciphertexts may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalAddMutable(
      Ciphertext<Element> &ciphertext1,
      Ciphertext<Element> &ciphertext2) const {
    PALISADE_THROW(not_implemented_error,
                   "EvalAddMutable is not implemented for this scheme");
  }

  /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts.
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext,
                                      ConstPlaintext plaintext) const = 0;

  /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalAddMutable(Ciphertext<Element> &ciphertext,
                                             Plaintext plaintext) const {
    PALISADE_THROW(not_implemented_error,
                   "EvalAddMutable is not implemented for this scheme");
  }

  /**
   * Virtual function to define the adding of a scalar to a ciphertext
   *
   * @param ciphertext the input ciphertext.
   * @param constant the input constant.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext,
                                      double constant) const {
    PALISADE_THROW(not_implemented_error,
                   "Scalar addition is not implemented for this scheme");
  }

  /**
   * Virtual function for computing the linear weighted sum of a
   * vector of ciphertexts.
   *
   * @param ciphertexts vector of input ciphertexts.
   * @param constants vector containing double weights.
   * @return A ciphertext containing the linear weighted sum.
   */
  virtual Ciphertext<Element> EvalLinearWSum(
      vector<Ciphertext<Element>> ciphertexts, vector<double> constants) const {
    std::string errMsg = "EvalLinearWSum is not implemented for this scheme.";
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
  virtual Ciphertext<Element> EvalLinearWSumMutable(
      vector<Ciphertext<Element>> ciphertexts, vector<double> constants) const {
    std::string errMsg =
        "EvalLinearWSumMutable is not implemented for this scheme.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Virtual function to define the interface for homomorphic subtraction of
   * ciphertexts.
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalSub(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2) const = 0;

  /**
   * Virtual function to define the interface for homomorphic subtraction of
   * ciphertexts. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalSubMutable(
      Ciphertext<Element> &ciphertext1,
      Ciphertext<Element> &ciphertext2) const {
    PALISADE_THROW(not_implemented_error,
                   "EvalSubMutable is not implemented for this scheme");
  }

  /**
   * Virtual function to define the interface for homomorphic subtraction of
   * ciphertexts.
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext,
                                      ConstPlaintext plaintext) const = 0;

  /**
   * Virtual function to define the interface for homomorphic subtraction of
   * ciphertexts. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalSubMutable(Ciphertext<Element> &ciphertext,
                                             Plaintext plaintext) const {
    PALISADE_THROW(not_implemented_error,
                   "EvalSubMutable is not implemented for this scheme");
  }

  /**
   * Virtual function to define the subtraction of a scalar from a ciphertext
   *
   * @param ciphertext the input ciphertext.
   * @param constant the input constant.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext,
                                      double constant) const {
    PALISADE_THROW(not_implemented_error,
                   "Scalar subtraction is not implemented for this scheme");
  }

  /**
   * Virtual function to define the interface for multiplicative homomorphic
   * evaluation of ciphertext.
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalMult(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2) const = 0;

  /**
   * Virtual function to define the interface for multiplicative homomorphic
   * evaluation of ciphertext. This is the mutable version - input ciphertexts
   * may change (automatically rescaled, or towers dropped).
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalMultMutable(
      Ciphertext<Element> &ciphertext1,
      Ciphertext<Element> &ciphertext2) const {
    PALISADE_THROW(not_implemented_error,
                   "EvalMultMutable is not implemented for this scheme");
  }

  /**
   * Virtual function to define the interface for multiplication of ciphertext
   * by plaintext.
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext,
                                       ConstPlaintext plaintext) const = 0;

  /**
   * Virtual function to define the interface for multiplication of ciphertext
   * by plaintext. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element> &ciphertext,
                                              Plaintext plaintext) const {
    PALISADE_THROW(not_implemented_error,
                   "EvalMultMutable is not implemented for this scheme");
  }

  /**
   * Virtual function to define the multiplication of a ciphertext by a
   * constant
   *
   * @param ciphertext the input ciphertext.
   * @param constant the input constant.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext,
                                       double constant) const {
    PALISADE_THROW(not_implemented_error,
                   "Scalar multiplication is not implemented for this scheme");
  }

  /**
   * Virtual function to define the multiplication of a ciphertext by a
   * constant. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext the input ciphertext.
   * @param constant the input constant.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element> &ciphertext,
                                              double constant) const {
    PALISADE_THROW(not_implemented_error,
                   "EvalMultMutable is not implemented for this scheme");
  }

  /**
   * Virtual function to define the interface for multiplicative homomorphic
   * evaluation of ciphertext using the evaluation key.
   *
   * @param &ciphertext1 first input ciphertext.
   * @param &ciphertext2 second input ciphertext.
   * @param &ek is the evaluation key to make the newCiphertext decryptable by
   * the same secret key as that of ciphertext1 and ciphertext2.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1,
                                       ConstCiphertext<Element> ciphertext2,
                                       const LPEvalKey<Element> ek) const = 0;

  /**
   * Virtual function to define the interface for multiplicative homomorphic
   * evaluation of ciphertext using the evaluation key. This is the mutable
   * version - input ciphertext may change (automatically rescaled, or towers
   * dropped).
   *
   * @param &ciphertext1 first input ciphertext.
   * @param &ciphertext2 second input ciphertext.
   * @param &ek is the evaluation key to make the newCiphertext decryptable by
   * the same secret key as that of ciphertext1 and ciphertext2.
   * @return the new ciphertext.
   */
  virtual Ciphertext<Element> EvalMultMutable(
      Ciphertext<Element> &ciphertext1, Ciphertext<Element> &ciphertext2,
      const LPEvalKey<Element> ek) const {
    PALISADE_THROW(not_implemented_error,
                   "EvalMultMutable is not implemented for this scheme");
  }

  /**
   * Virtual function for evaluating multiplication of a ciphertext list which
   * each multiplication is followed by relinearization operation.
   *
   * @param cipherTextList  is the ciphertext list.
   * @param evalKeys is the evaluation key to make the newCiphertext
   *  decryptable by the same secret key as that of ciphertext list.
   * @param *newCiphertext the new resulting ciphertext.
   */
  virtual Ciphertext<Element> EvalMultMany(
      const vector<Ciphertext<Element>> &cipherTextList,
      const vector<LPEvalKey<Element>> &evalKeys) const {
    // default implementation if you don't have one in your scheme
    // TODO: seems that we can simply call EvalAddMany() here.
    // TODO: see EvalAddMany() below
    if (cipherTextList.size() < 1)
      PALISADE_THROW(config_error,
                     "Input ciphertext vector size should be 1 or more");

    const size_t inSize = cipherTextList.size();
    const size_t lim = inSize * 2 - 2;
    vector<Ciphertext<Element>> cipherTextResults;
    cipherTextResults.resize(inSize - 1);
    size_t ctrIndex = 0;

    for (size_t i = 0; i < lim; i = i + 2) {
      cipherTextResults[ctrIndex++] = this->EvalMult(
          i < inSize ? cipherTextList[i] : cipherTextResults[i - inSize],
          i + 1 < inSize ? cipherTextList[i + 1]
                         : cipherTextResults[i + 1 - inSize]);
    }

    return cipherTextResults.back();
  }

  /**
   * Virtual function for evaluating addition of a list of ciphertexts.
   *
   * @param ctList  is the ciphertext list.
   * @param *newCiphertext the new resulting ciphertext.
   */
  virtual Ciphertext<Element> EvalAddMany(
      const vector<Ciphertext<Element>> &ctList) const {
    // default implementation if you don't have one in your scheme
    if (ctList.size() < 1)
      PALISADE_THROW(config_error,
                     "Input ciphertext vector size should be 1 or more");

    const size_t inSize = ctList.size();
    const size_t lim = inSize * 2 - 2;
    vector<Ciphertext<Element>> cipherTextResults;
    cipherTextResults.resize(inSize - 1);
    size_t ctrIndex = 0;

    for (size_t i = 0; i < lim; i = i + 2) {
      cipherTextResults[ctrIndex++] = this->EvalAdd(
          i < inSize ? ctList[i] : cipherTextResults[i - inSize],
          i + 1 < inSize ? ctList[i + 1] : cipherTextResults[i + 1 - inSize]);
    }

    return cipherTextResults.back();
  }

  /**
   * Virtual function for evaluating addition of a list of ciphertexts.
   * This version uses no additional space, other than the vector provided.
   *
   * @param ctList  is the ciphertext list.
   * @param *newCiphertext the new resulting ciphertext.
   */
  virtual Ciphertext<Element> EvalAddManyInPlace(
      vector<Ciphertext<Element>> &ctList) const {
    // default implementation if you don't have one in your scheme
    if (ctList.size() < 1)
      PALISADE_THROW(config_error,
                     "Input ciphertext vector size should be 1 or more");

    for (size_t j = 1; j < ctList.size(); j = j * 2) {
      for (size_t i = 0; i < ctList.size(); i = i + 2 * j) {
        if ((i + j) < ctList.size()) {
          if (ctList[i] != nullptr && ctList[i + j] != nullptr) {
            ctList[i] = EvalAdd(ctList[i], ctList[i + j]);
          } else if (ctList[i] == nullptr && ctList[i + j] != nullptr) {
            ctList[i] = ctList[i + j];
          }  // In all remaining cases (ctList[i+j]), ctList[i] needs to
             // remain unchanged.
        }
      }
    }

    Ciphertext<Element> result(
        std::make_shared<CiphertextImpl<Element>>(*(ctList[0])));

    return result;
  }

  /**
   * Virtual function to define the interface for multiplicative homomorphic
   * evaluation of ciphertext using the evaluation key.
   *
   * @param ct1 first input ciphertext.
   * @param ct2 second input ciphertext.
   * @param ek is the evaluation key to make the newCiphertext
   *  decryptable by the same secret key as that of ciphertext1 and
   * ciphertext2.
   * @param *newCiphertext the new resulting ciphertext.
   */
  virtual Ciphertext<Element> EvalMultAndRelinearize(
      ConstCiphertext<Element> ct1, ConstCiphertext<Element> ct2,
      const vector<LPEvalKey<Element>> &ek) const = 0;

  /**
   * Virtual function to do relinearization
   *
   * @param ciphertext input ciphertext.
   * @param ek are the evaluation keys to make the newCiphertext
   *  decryptable by the same secret key as that of ciphertext1 and
   * ciphertext2.
   * @return the new resulting ciphertext.
   */
  virtual Ciphertext<Element> Relinearize(
      ConstCiphertext<Element> ciphertext,
      const vector<LPEvalKey<Element>> &ek) const {
    PALISADE_THROW(config_error, "Relinearize operation not supported");
  }

  /**
   * Virtual function to do in-place relinearization
   *
   * @param &ciphertext input ciphertext.
   * @param ek are the evaluation keys
   * @return the new resulting ciphertext.
   */
  virtual void RelinearizeInPlace(
      Ciphertext<Element> &ciphertext,
      const vector<LPEvalKey<Element>> &ek) const {
    PALISADE_THROW(config_error, "RelinearizeInPlace operation not supported");
  }

  /**
   * Virtual function to define the interface for homomorphic negation of
   * ciphertext.
   *
   * @param &ciphertext the input ciphertext.
   * @param *newCiphertext the new ciphertext.
   */
  virtual Ciphertext<Element> EvalNegate(
      ConstCiphertext<Element> ciphertext) const = 0;

  /**
   * Function to add random noise to all plaintext slots except for the first
   * one; used in EvalInnerProduct
   *
   * @param &ciphertext the input ciphertext.
   * @return modified ciphertext
   */
  virtual Ciphertext<Element> AddRandomNoise(
      ConstCiphertext<Element> ciphertext) const {
    if (!ciphertext)
      PALISADE_THROW(config_error, "Input ciphertext is nullptr");

    std::uniform_real_distribution<double> distribution(0.0, 1.0);

    string kID = ciphertext->GetKeyTag();
    const auto cryptoParams = ciphertext->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();
    const auto elementParams = cryptoParams->GetElementParams();

    usint n = elementParams->GetRingDimension();

    auto cc = ciphertext->GetCryptoContext();

    Plaintext plaintext;

    if (ciphertext->GetEncodingType() == CKKSPacked) {
      std::vector<std::complex<double>> randomIntVector(n);

      // first plaintext slot does not need to change
      randomIntVector[0].real(0);

      for (usint i = 0; i < n - 1; i++) {
        randomIntVector[i + 1].real(
            distribution(PseudoRandomNumberGenerator::GetPRNG()));
      }

      plaintext =
          cc->MakeCKKSPackedPlaintext(randomIntVector, ciphertext->GetDepth());

    } else {
      DiscreteUniformGenerator dug;
      dug.SetModulus(encodingParams->GetPlaintextModulus());
      BigVector randomVector = dug.GenerateVector(n - 1);

      std::vector<int64_t> randomIntVector(n);

      // first plaintext slot does not need to change
      randomIntVector[0] = 0;

      for (usint i = 0; i < n - 1; i++) {
        randomIntVector[i + 1] = randomVector[i].ConvertToInt();
      }

      plaintext = cc->MakePackedPlaintext(randomIntVector);
    }

    plaintext->Encode();
    plaintext->GetElement<Element>().SetFormat(EVALUATION);

    auto ans = EvalAdd(ciphertext, plaintext);

    return ans;
  }

  /**
   * Method for KeySwitchGen
   *
   * @param &originalPrivateKey Original private key used for encryption.
   * @param &newPrivateKey New private key to generate the keyswitch hint.
   * @param *KeySwitchHint is where the resulting keySwitchHint will be
   * placed.
   */
  virtual LPEvalKey<Element> KeySwitchGen(
      const LPPrivateKey<Element> originalPrivateKey,
      const LPPrivateKey<Element> newPrivateKey) const = 0;

  /**
   * Method for KeySwitch
   *
   * @param &keySwitchHint Hint required to perform the ciphertext switching.
   * @param &cipherText Original ciphertext to perform switching on.
   */

  virtual void KeySwitchInPlace(const LPEvalKey<Element> keySwitchHint,
                                Ciphertext<Element> &cipherText) const = 0;

  virtual Ciphertext<Element> KeySwitch(
      const LPEvalKey<Element> keySwitchHint,
      ConstCiphertext<Element> cipherText) const {
    auto ret = cipherText->Clone();
    KeySwitchInPlace(keySwitchHint, ret);
    return ret;
  }

  /**
   * Virtual function to define the interface for generating a evaluation key
   * which is used after each multiplication.
   *
   * @param &ciphertext1 first input ciphertext.
   * @param &ciphertext2 second input ciphertext.
   * @param &ek is the evaluation key to make the newCiphertext decryptable by
   * the same secret key as that of ciphertext1 and ciphertext2.
   * @param *newCiphertext the new resulting ciphertext.
   */
  virtual LPEvalKey<Element> EvalMultKeyGen(
      const LPPrivateKey<Element> originalPrivateKey) const = 0;

  /**
   * Virtual function to define the interface for generating a evaluation key
   * which is used after each multiplication for depth more than 2.
   *
   * @param &originalPrivateKey Original private key used for encryption.
   * @param *evalMultKeys the resulting evalution key vector list.
   */
  virtual vector<LPEvalKey<Element>> EvalMultKeysGen(
      const LPPrivateKey<Element> originalPrivateKey) const = 0;

  /**
   * Virtual function to generate all isomorphism keys for a given private key
   *
   * @param publicKey encryption key for the new ciphertext.
   * @param origPrivateKey original private key used for decryption.
   * @param indexList list of automorphism indices to be computed
   * @return returns the evaluation keys
   */
  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>>
  EvalAutomorphismKeyGen(const LPPublicKey<Element> publicKey,
                         const LPPrivateKey<Element> origPrivateKey,
                         const std::vector<usint> &indexList) const = 0;

  /**
   * Virtual function for the precomputation step of hoisted
   * automorphisms.
   *
   * @param ct the input ciphertext on which to do the precomputation (digit
   * decomposition)
   */
  virtual shared_ptr<vector<Element>> EvalFastRotationPrecompute(
      ConstCiphertext<Element> cipherText) const {
    std::string errMsg =
        "LPSHEAlgorithm::EvalFastRotationPrecompute is not implemented for "
        "this Scheme.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Virtual function for the automorphism and key switching step of
   * hoisted automorphisms.
   *
   * @param ct the input ciphertext to perform the automorphism on
   * @param index the index of the rotation. Positive indices correspond to
   * left rotations and negative indices correspond to right rotations.
   * @param m is the cyclotomic order
   * @param digits the digit decomposition created by
   * EvalFastRotationPrecompute at the precomputation step.
   */
  virtual Ciphertext<Element> EvalFastRotation(
      ConstCiphertext<Element> cipherText, const usint index, const usint m,
      const shared_ptr<vector<Element>> digits) const {
    std::string errMsg =
        "LPSHEAlgorithm::EvalFastRotation is not implemented for this "
        "Scheme.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  /**
   * Generates evaluation keys for a list of indices
   * Currently works only for power-of-two and cyclic-group cyclotomics
   *
   * @param publicKey encryption key for the new ciphertext.
   * @param origPrivateKey original private key used for decryption.
   * @param indexList list of indices to be computed
   * @return returns the evaluation keys
   */
  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAtIndexKeyGen(
      const LPPublicKey<Element> publicKey,
      const LPPrivateKey<Element> origPrivateKey,
      const std::vector<int32_t> &indexList) const {
    /*
     * we don't validate publicKey as it is needed by NTRU-based scheme only
     * NTRU-based scheme only and it is checked for null later.
     */
    if (!origPrivateKey)
      PALISADE_THROW(config_error, "Input private key is nullptr");
    const auto cryptoParams = origPrivateKey->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();
    const auto elementParams = cryptoParams->GetElementParams();
    uint32_t m = elementParams->GetCyclotomicOrder();

    std::vector<uint32_t> autoIndices(indexList.size());

    if (IsPowerOfTwo(m)) {  // power-of-two cyclotomics
      for (size_t i = 0; i < indexList.size(); i++) {
        auto ccInst = origPrivateKey->GetCryptoContext();
        // CKKS Packing
        if (ccInst->getSchemeId() == "CKKS")
          autoIndices[i] = FindAutomorphismIndex2nComplex(indexList[i], m);
        else
          autoIndices[i] = FindAutomorphismIndex2n(indexList[i], m);
      }

    } else {  // cyclic groups
      for (size_t i = 0; i < indexList.size(); i++)
        autoIndices[i] = FindAutomorphismIndexCyclic(
            indexList[i], m, encodingParams->GetPlaintextGenerator());
    }

    if (publicKey)
      // NTRU-based scheme
      return EvalAutomorphismKeyGen(publicKey, origPrivateKey, autoIndices);
    else
      // RLWE-based scheme
      return EvalAutomorphismKeyGen(origPrivateKey, autoIndices);
  }

  /**
   * Virtual function for evaluating automorphism of ciphertext at index i
   *
   * @param ciphertext the input ciphertext.
   * @param i automorphism index
   * @param &evalKeys - reference to the vector of evaluation keys generated
   * by EvalAutomorphismKeyGen.
   * @return resulting ciphertext
   */
  virtual Ciphertext<Element> EvalAutomorphism(
      ConstCiphertext<Element> ciphertext, usint i,
      const std::map<usint, LPEvalKey<Element>> &evalKeys,
      CALLER_INFO_ARGS_HDR) const = 0;

  /**
   * Moves i-th slot to slot 0
   *
   * @param ciphertext.
   * @param i the index.
   * @param &evalAtIndexKeys - reference to the map of evaluation keys
   * generated by EvalAtIndexKeyGen.
   * @return resulting ciphertext
   */
  virtual Ciphertext<Element> EvalAtIndex(
      ConstCiphertext<Element> ciphertext, int32_t index,
      const std::map<usint, LPEvalKey<Element>> &evalAtIndexKeys) const {
    if (!ciphertext)
      PALISADE_THROW(config_error, "Input ciphertext is nullptr");
    if (!evalAtIndexKeys.size())
      PALISADE_THROW(config_error, "Input index map is empty");
    const auto cryptoParams = ciphertext->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();
    const auto elementParams = cryptoParams->GetElementParams();
    uint32_t m = elementParams->GetCyclotomicOrder();

    uint32_t autoIndex;

    // power-of-two cyclotomics
    if (IsPowerOfTwo(m)) {
      if (ciphertext->GetEncodingType() == CKKSPacked)
        autoIndex = FindAutomorphismIndex2nComplex(index, m);
      else
        autoIndex = FindAutomorphismIndex2n(index, m);
    } else {  // cyclic-group cyclotomics
      autoIndex = FindAutomorphismIndexCyclic(
          index, m, encodingParams->GetPlaintextGenerator());
    }

    return EvalAutomorphism(ciphertext, autoIndex, evalAtIndexKeys);
  }

  /**
   * Virtual function to generate automophism keys for a given private key;
   * Uses the private key for encryption
   *
   * @param privateKey private key.
   * @param indexList list of automorphism indices to be computed
   * @return returns the evaluation keys
   */
  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>>
  EvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
                         const std::vector<usint> &indexList) const = 0;

  /**
   * Virtual function to generate the automorphism keys for EvalSum; works
   * only for packed encoding
   *
   * @param privateKey private key.
   * @return returns the evaluation keys
   */
  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumKeyGen(
      const LPPrivateKey<Element> privateKey,
      const LPPublicKey<Element> publicKey) const {
    if (!privateKey)
      PALISADE_THROW(config_error, "Input private key is nullptr");
    /*
     * we don't validate publicKey as it is needed by NTRU-based scheme only
     * NTRU-based scheme only and it is checked for null later.
     */
    const auto cryptoParams = privateKey->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();
    const auto elementParams = cryptoParams->GetElementParams();

    usint batchSize = encodingParams->GetBatchSize();
    usint m = elementParams->GetCyclotomicOrder();

    // stores automorphism indices needed for EvalSum
    std::vector<usint> indices;

    if (IsPowerOfTwo(m)) {
      auto ccInst = privateKey->GetCryptoContext();
      // CKKS Packing
      if (ccInst->getSchemeId() == "CKKS")
        indices = GenerateIndices2nComplex(batchSize, m);
      else
        indices = GenerateIndices_2n(batchSize, m);
    } else {  // Arbitrary cyclotomics
      usint g = encodingParams->GetPlaintextGenerator();
      for (int i = 0; i < floor(log2(batchSize)); i++) {
        indices.push_back(g);
        g = (g * g) % m;
      }
    }

    if (publicKey)  // NTRU-based scheme
      return EvalAutomorphismKeyGen(publicKey, privateKey, indices);

    // Regular RLWE scheme
    return EvalAutomorphismKeyGen(privateKey, indices);
  }

  /**
   * Virtual function to generate the automorphism keys for EvalSumRows; works
   * only for packed encoding
   *
   * @param privateKey private key.
   * @param publicKey public key.
   * @param rowSize size of rows in the matrix
   * @param subringDim subring dimension (set to cyclotomic order if set to 0)
   * @return returns the evaluation keys
   */
  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumRowsKeyGen(
      const LPPrivateKey<Element> privateKey,
      const LPPublicKey<Element> publicKey, usint rowSize,
      usint subringDim = 0) const {
    if (!privateKey)
      PALISADE_THROW(config_error, "Input private key is nullptr");
    const auto cryptoParams = privateKey->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();
    const auto elementParams = cryptoParams->GetElementParams();

    usint m =
        (subringDim == 0) ? elementParams->GetCyclotomicOrder() : subringDim;

    // stores automorphism indices needed for EvalSum
    std::vector<usint> indices;

    if (IsPowerOfTwo(m)) {
      auto ccInst = privateKey->GetCryptoContext();
      // CKKS Packing
      if (ccInst->getSchemeId() == "CKKS")
        indices = GenerateIndices2nComplexRows(rowSize, m);
      else
        PALISADE_THROW(config_error,
                       "Matrix summation of row-vectors is only supported for "
                       "CKKSPackedEncoding.");

    } else {  // Arbitrary cyclotomics
      PALISADE_THROW(config_error,
                     "Matrix summation of row-vectors is not supported for "
                     "arbitrary cyclotomics.");
    }

    if (publicKey)
      // NTRU-based scheme
      return EvalAutomorphismKeyGen(publicKey, privateKey, indices);
    else
      // Regular RLWE scheme
      return EvalAutomorphismKeyGen(privateKey, indices);
  }

  /**
   * Virtual function to generate the automorphism keys for EvalSumCols; works
   * only for packed encoding
   *
   * @param privateKey private key.
   * @param publicKey public key.
   * @param rowSize size of rows in the matrix
   * @param colSize size of columns in the matrix
   * @return returns the evaluation keys
   */
  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumColsKeyGen(
      const LPPrivateKey<Element> privateKey,
      const LPPublicKey<Element> publicKey) const {
    if (!privateKey)
      PALISADE_THROW(config_error, "Input private key is nullptr");
    const auto cryptoParams = privateKey->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();
    const auto elementParams = cryptoParams->GetElementParams();

    usint batchSize = encodingParams->GetBatchSize();
    usint m = elementParams->GetCyclotomicOrder();

    auto ccInst = privateKey->GetCryptoContext();
    // CKKS Packing
    if (ccInst->getSchemeId() == "CKKS") {
      // stores automorphism indices needed for EvalSum
      std::vector<usint> indices;

      if (IsPowerOfTwo(m)) {
        indices = GenerateIndices2nComplexCols(batchSize, m);
      } else {  // Arbitrary cyclotomics
        PALISADE_THROW(config_error,
                       "Matrix summation of column-vectors is not supported "
                       "for arbitrary cyclotomics.");
      }

      if (publicKey)
        // NTRU-based scheme
        return EvalAutomorphismKeyGen(publicKey, privateKey, indices);
      else
        // Regular RLWE scheme
        return EvalAutomorphismKeyGen(privateKey, indices);
    } else {
      PALISADE_THROW(config_error,
                     "Matrix summation of column-vectors is only supported for "
                     "CKKSPackedEncoding.");
    }
  }

  /**
   * Sums all elements in log (batch size) time - works only with packed
   * encoding
   *
   * @param ciphertext the input ciphertext.
   * @param batchSize size of the batch to be summed up
   * @param &evalKeys - reference to the map of evaluation keys generated by
   * EvalAutomorphismKeyGen.
   * @return resulting ciphertext
   */
  virtual Ciphertext<Element> EvalSum(
      ConstCiphertext<Element> ciphertext, usint batchSize,
      const std::map<usint, LPEvalKey<Element>> &evalKeys) const {
    if (!ciphertext)
      PALISADE_THROW(config_error, "Input ciphertext is nullptr");
    if (!evalKeys.size())
      PALISADE_THROW(config_error, "Input index map is empty");
    const shared_ptr<LPCryptoParameters<Element>> cryptoParams =
        ciphertext->GetCryptoParameters();
    Ciphertext<Element> newCiphertext(
        std::make_shared<CiphertextImpl<Element>>(*ciphertext));

    const auto encodingParams = cryptoParams->GetEncodingParams();
    const auto elementParams = cryptoParams->GetElementParams();

    usint m = elementParams->GetCyclotomicOrder();

    if ((encodingParams->GetBatchSize() == 0)) {
      PALISADE_THROW(
          config_error,
          "EvalSum: Packed encoding parameters 'batch size' is not set; "
          "Please "
          "check the EncodingParams passed to the crypto context.");
    } else {
      if (IsPowerOfTwo(m)) {
        if (ciphertext->GetEncodingType() == CKKSPacked)
          newCiphertext =
              EvalSum2nComplex(batchSize, m, evalKeys, newCiphertext);
        else
          newCiphertext = EvalSum_2n(batchSize, m, evalKeys, newCiphertext);

      } else {  // Arbitrary cyclotomics
        if (encodingParams->GetPlaintextGenerator() == 0) {
          PALISADE_THROW(config_error,
                         "EvalSum: Packed encoding parameters 'plaintext "
                         "generator' is not set; Please check the "
                         "EncodingParams passed to the crypto context.");
        } else {
          usint g = encodingParams->GetPlaintextGenerator();
          for (int i = 0; i < floor(log2(batchSize)); i++) {
            auto ea = EvalAutomorphism(newCiphertext, g, evalKeys);
            newCiphertext = EvalAdd(newCiphertext, ea);
            g = (g * g) % m;
          }
        }
      }
    }

    return newCiphertext;
  }

  /**
   * Sums all elements over row-vectors in a matrix - works only with packed
   * encoding
   *
   * @param ciphertext the input ciphertext.
   * @param rowSize size of rows in the matrix
   * @param &evalKeys - reference to the map of evaluation keys generated by
   * @param subringDim the current cyclotomic order/subring dimension. If set to
   * 0, we use the full cyclotomic order. EvalAutomorphismKeyGen.
   * @return resulting ciphertext
   */
  virtual Ciphertext<Element> EvalSumRows(
      ConstCiphertext<Element> ciphertext, usint rowSize,
      const std::map<usint, LPEvalKey<Element>> &evalKeys,
      usint subringDim = 0) const {
    if (!ciphertext)
      PALISADE_THROW(config_error, "Input ciphertext is nullptr");
    if (!evalKeys.size())
      PALISADE_THROW(config_error, "Input index map is empty");
    const shared_ptr<LPCryptoParameters<Element>> cryptoParams =
        ciphertext->GetCryptoParameters();
    Ciphertext<Element> newCiphertext(
        std::make_shared<CiphertextImpl<Element>>(*ciphertext));

    const auto encodingParams = cryptoParams->GetEncodingParams();
    const auto elementParams = cryptoParams->GetElementParams();

    usint m =
        (subringDim == 0) ? elementParams->GetCyclotomicOrder() : subringDim;

    if ((encodingParams->GetBatchSize() == 0)) {
      PALISADE_THROW(
          config_error,
          "EvalSum: Packed encoding parameters 'batch size' is not set; "
          "Please "
          "check the EncodingParams passed to the crypto context.");
    } else {
      if (IsPowerOfTwo(m)) {
        if (ciphertext->GetEncodingType() == CKKSPacked)
          newCiphertext =
              EvalSum2nComplexRows(rowSize, m, evalKeys, newCiphertext);
        else
          PALISADE_THROW(config_error,
                         "Matrix summation of row-vectors is only supported "
                         "for CKKS packed encoding.");

      } else {  // Arbitrary cyclotomics
        PALISADE_THROW(config_error,
                       "Matrix summation of row-vectors is not supported for "
                       "arbitrary cyclotomics.");
      }
    }

    return newCiphertext;
  }

  /**
   * Sums all elements over column-vectors in a matrix - works only with
   * packed encoding
   *
   * @param ciphertext the input ciphertext.
   * @param rowSize size of rows in the matrixs
   * @param &evalKeys - reference to the map of evaluation keys generated by
   * EvalAutomorphismKeyGen.
   * @return resulting ciphertext
   */
  virtual Ciphertext<Element> EvalSumCols(
      ConstCiphertext<Element> ciphertext, usint batchSize,
      const std::map<usint, LPEvalKey<Element>> &evalKeys,
      const std::map<usint, LPEvalKey<Element>> &rightEvalKeys) const {
    if (!ciphertext)
      PALISADE_THROW(config_error, "Input ciphertext is nullptr");
    if (!evalKeys.size())
      PALISADE_THROW(config_error, "Input evalKeys map is empty");
    if (!rightEvalKeys.size())
      PALISADE_THROW(config_error, "Input rightEvalKeys map is empty");
    const shared_ptr<LPCryptoParameters<Element>> cryptoParams =
        ciphertext->GetCryptoParameters();
    Ciphertext<Element> newCiphertext(
        std::make_shared<CiphertextImpl<Element>>(*ciphertext));

    const auto encodingParams = cryptoParams->GetEncodingParams();
    const auto elementParams = cryptoParams->GetElementParams();

    usint m = elementParams->GetCyclotomicOrder();

    if ((encodingParams->GetBatchSize() == 0)) {
      PALISADE_THROW(
          config_error,
          "EvalSumCols: Packed encoding parameters 'batch size' is not set; "
          "Please check the EncodingParams passed to the crypto context.");
    } else {
      if (ciphertext->GetEncodingType() == CKKSPacked) {
        if (IsPowerOfTwo(m)) {
          newCiphertext =
              EvalSum2nComplex(batchSize, m, evalKeys, newCiphertext);

          std::vector<std::complex<double>> mask(m / 4);
          for (size_t i = 0; i < mask.size(); i++) {
            if (i % batchSize == 0)
              mask[i] = 1;
            else
              mask[i] = 0;
          }

          auto cc = ciphertext->GetCryptoContext();

          Plaintext plaintext = cc->MakeCKKSPackedPlaintext(mask, 1);

          newCiphertext = EvalMult(newCiphertext, plaintext);

          newCiphertext =
              EvalSum2nComplexCols(batchSize, m, rightEvalKeys, newCiphertext);

        } else {  // Arbitrary cyclotomics
          PALISADE_THROW(config_error,
                         "Matrix summation of column-vectors is not supported "
                         "for arbitrary cyclotomics.");
        }
      } else {
        PALISADE_THROW(config_error,
                       "Matrix summation of column-vectors is only supported "
                       "for CKKS packed encoding.");
      }
    }

    return newCiphertext;
  }

  /**
   * Evaluates inner product in batched encoding
   *
   * @param ciphertext1 first vector.
   * @param ciphertext2 second vector.
   * @param batchSize size of the batch to be summed up
   * @param &evalSumKeys - reference to the map of evaluation keys generated
   * by EvalAutomorphismKeyGen.
   * @param &evalMultKey - reference to the evaluation key generated by
   * EvalMultKeyGen.
   * @return resulting ciphertext
   */
  virtual Ciphertext<Element> EvalInnerProduct(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2, usint batchSize,
      const std::map<usint, LPEvalKey<Element>> &evalSumKeys,
      const LPEvalKey<Element> evalMultKey) const {
    Ciphertext<Element> result =
        EvalMult(ciphertext1, ciphertext2, evalMultKey);

    result = EvalSum(result, batchSize, evalSumKeys);

    // add a random number to all slots except for the first one so that no
    // information is leaked
    // if (ciphertext1->GetEncodingType() != CKKSPacked)
    //   result = AddRandomNoise(result);
    return result;
  }

  /**
   * Evaluates inner product in batched encoding
   *
   * @param ciphertext1 first vector.
   * @param plaintext plaintext.
   * @param batchSize size of the batch to be summed up
   * @param &evalSumKeys - reference to the map of evaluation keys generated
   * by EvalAutomorphismKeyGen.
   * @param &evalMultKey - reference to the evaluation key generated by
   * EvalMultKeyGen.
   * @return resulting ciphertext
   */
  virtual Ciphertext<Element> EvalInnerProduct(
      ConstCiphertext<Element> ciphertext1, ConstPlaintext plaintext,
      usint batchSize,
      const std::map<usint, LPEvalKey<Element>> &evalSumKeys) const {
    Ciphertext<Element> result = EvalMult(ciphertext1, plaintext);

    result = EvalSum(result, batchSize, evalSumKeys);

    // add a random number to all slots except for the first one so that no
    // information is leaked
    // if (ciphertext1->GetEncodingType() != CKKSPacked)
    //   result = AddRandomNoise(result);
    return result;
  }

  /**
   * Merges multiple ciphertexts with encrypted results in slot 0 into a
   * single ciphertext The slot assignment is done based on the order of
   * ciphertexts in the vector
   *
   * @param ciphertextVector vector of ciphertexts to be merged.
   * @param &evalKeys - reference to the map of evaluation keys generated by
   * EvalAutomorphismKeyGen.
   * @return resulting ciphertext
   */
  virtual Ciphertext<Element> EvalMerge(
      const vector<Ciphertext<Element>> &ciphertextVector,
      const std::map<usint, LPEvalKey<Element>> &evalKeys) const {
    if (ciphertextVector.size() == 0)
      PALISADE_THROW(math_error,
                     "EvalMerge: the vector of ciphertexts to be merged "
                     "cannot be empty");

    const shared_ptr<LPCryptoParameters<Element>> cryptoParams =
        ciphertextVector[0]->GetCryptoParameters();
    Ciphertext<Element> newCiphertext(
        std::make_shared<CiphertextImpl<Element>>(*(ciphertextVector[0])));

    auto cc = ciphertextVector[0]->GetCryptoContext();

    Plaintext plaintext;
    if (ciphertextVector[0]->GetEncodingType() == CKKSPacked) {
      std::vector<std::complex<double>> plaintextVector({{1, 0}, {0, 0}});
      plaintext = cc->MakeCKKSPackedPlaintext(plaintextVector);
    } else {
      std::vector<int64_t> plaintextVector = {1, 0};
      plaintext = cc->MakePackedPlaintext(plaintextVector);
    }

    newCiphertext = EvalMult(newCiphertext, plaintext);

    for (size_t i = 1; i < ciphertextVector.size(); i++) {
      newCiphertext = EvalAdd(
          newCiphertext, EvalAtIndex(EvalMult(ciphertextVector[i], plaintext),
                                     -(int32_t)i, evalKeys));
    }

    return newCiphertext;
  }

  /* Maintenance procedure used in the exact RNS variant of CKKS
   * @param c1 input ciphertext.
   * @param targetLevel The number of the level we want to take this
   * ciphertext to. Levels are numbered from 0 (all towers) to
   * GetNumberOfTowers()-1 (one remaining tower).
   * @return A ciphertext containing the same value as c1, but at level
   * targetLevel.
   */
  virtual Ciphertext<Element> AdjustLevelWithRescale(
      Ciphertext<Element> &c1, uint32_t targetLevel) const {
    std::string errMsg =
        "AdjustLevelWithoutRescale is not implemented for this scheme.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

 private:
  std::vector<usint> GenerateIndices_2n(usint batchSize, usint m) const {
    // stores automorphism indices needed for EvalSum
    std::vector<usint> indices;

    if (batchSize > 1) {
      usint g = 5;
      for (int i = 0; i < ceil(log2(batchSize)) - 1; i++) {
        indices.push_back(g);
        g = (g * g) % m;
      }
      if (2 * batchSize < m)
        indices.push_back(g);
      else
        indices.push_back(m - 1);
    }

    return indices;
  }

  std::vector<usint> GenerateIndices2nComplex(usint batchSize, usint m) const {
    // stores automorphism indices needed for EvalSum
    std::vector<usint> indices;

    // generator
    int32_t g = 5;
    usint gFinal = g;

    for (size_t j = 0; j < ceil(log2(batchSize)); j++) {
      indices.push_back(gFinal);
      g = (g * g) % m;

      gFinal = g;
    }

    return indices;
  }

  std::vector<usint> GenerateIndices2nComplexRows(usint rowSize,
                                                  usint m) const {
    // stores automorphism indices needed for EvalSum
    std::vector<usint> indices;

    usint colSize = m / (4 * rowSize);

    // generator
    int32_t g0 = 5;
    usint g = 0;

    int32_t f = (NativeInteger(g0).ModExp(rowSize, m)).ConvertToInt();

    for (size_t j = 0; j < ceil(log2(colSize)); j++) {
      g = f;

      indices.push_back(g);

      f = (f * f) % m;
    }

    return indices;
  }

  std::vector<usint> GenerateIndices2nComplexCols(usint batchSize,
                                                  usint m) const {
    // stores automorphism indices needed for EvalSum
    std::vector<usint> indices;

    // generator
    int32_t g = NativeInteger(5).ModInverse(m).ConvertToInt();
    usint gFinal = g;

    for (size_t j = 0; j < ceil(log2(batchSize)); j++) {
      indices.push_back(gFinal);
      g = (g * g) % m;

      gFinal = g;
    }

    return indices;
  }

  Ciphertext<Element> EvalSum_2n(
      usint batchSize, usint m,
      const std::map<usint, LPEvalKey<Element>> &evalKeys,
      ConstCiphertext<Element> ciphertext) const {
    Ciphertext<Element> newCiphertext(
        std::make_shared<CiphertextImpl<Element>>(*ciphertext));

    if (batchSize > 1) {
      usint g = 5;
      for (int i = 0; i < ceil(log2(batchSize)) - 1; i++) {
        newCiphertext = EvalAdd(newCiphertext,
                                EvalAutomorphism(newCiphertext, g, evalKeys));
        g = (g * g) % m;
      }
      if (2 * batchSize < m)
        newCiphertext = EvalAdd(newCiphertext,
                                EvalAutomorphism(newCiphertext, g, evalKeys));
      else
        newCiphertext = EvalAdd(
            newCiphertext, EvalAutomorphism(newCiphertext, m - 1, evalKeys));
    }

    return newCiphertext;
  }

  Ciphertext<Element> EvalSum2nComplex(
      usint batchSize, usint m,
      const std::map<usint, LPEvalKey<Element>> &evalKeys,
      ConstCiphertext<Element> ciphertext) const {
    Ciphertext<Element> newCiphertext(
        std::make_shared<CiphertextImpl<Element>>(*ciphertext));

    // generator
    int32_t g = 5;
    usint gFinal = g;

    for (int i = 0; i < ceil(log2(batchSize)); i++) {
      newCiphertext = EvalAdd(
          newCiphertext, EvalAutomorphism(newCiphertext, gFinal, evalKeys));
      g = (g * g) % m;

      gFinal = g;
    }

    return newCiphertext;
  }

  Ciphertext<Element> EvalSum2nComplexRows(
      usint rowSize, usint m,
      const std::map<usint, LPEvalKey<Element>> &evalKeys,
      ConstCiphertext<Element> ciphertext) const {
    Ciphertext<Element> newCiphertext(
        std::make_shared<CiphertextImpl<Element>>(*ciphertext));

    usint colSize = m / (4 * rowSize);

    // generator
    int32_t g0 = 5;
    usint g = 0;
    int32_t f = (NativeInteger(g0).ModExp(rowSize, m)).ConvertToInt();

    for (size_t j = 0; j < ceil(log2(colSize)); j++) {
      g = f;

      newCiphertext =
          EvalAdd(newCiphertext, EvalAutomorphism(newCiphertext, g, evalKeys));

      f = (f * f) % m;
    }

    return newCiphertext;
  }

  Ciphertext<Element> EvalSum2nComplexCols(
      usint batchSize, usint m,
      const std::map<usint, LPEvalKey<Element>> &evalKeys,
      ConstCiphertext<Element> ciphertext) const {
    Ciphertext<Element> newCiphertext(
        std::make_shared<CiphertextImpl<Element>>(*ciphertext));

    // generator
    int32_t g = NativeInteger(5).ModInverse(m).ConvertToInt();
    usint gFinal = g;

    for (int i = 0; i < ceil(log2(batchSize)); i++) {
      newCiphertext = EvalAdd(
          newCiphertext, EvalAutomorphism(newCiphertext, gFinal, evalKeys));
      g = (g * g) % m;

      gFinal = g;
    }

    return newCiphertext;
  }
};

/**
 * @brief main implementation class to capture essential cryptoparameters of
 * any LBC system
 * @tparam Element a ring element.
 */
template <typename Element>
class LPCryptoParameters : public Serializable {
 public:
  LPCryptoParameters() {}

  virtual ~LPCryptoParameters() {}

  /**
   * Returns the value of plaintext modulus p
   *
   * @return the plaintext modulus.
   */
  virtual const PlaintextModulus &GetPlaintextModulus() const {
    return m_encodingParams->GetPlaintextModulus();
  }

  /**
   * Returns the reference to IL params
   *
   * @return the ring element parameters.
   */
  virtual const shared_ptr<typename Element::Params> GetElementParams() const {
    return m_params;
  }

  /**
   * Returns the reference to encoding params
   *
   * @return the encoding parameters.
   */
  virtual const EncodingParams GetEncodingParams() const {
    return m_encodingParams;
  }

  /**
   * Sets the value of plaintext modulus p
   */
  virtual void SetPlaintextModulus(const PlaintextModulus &plaintextModulus) {
    m_encodingParams->SetPlaintextModulus(plaintextModulus);
  }

  virtual bool operator==(const LPCryptoParameters<Element> &cmp) const = 0;
  virtual bool operator!=(const LPCryptoParameters<Element> &cmp) const {
    return !(*this == cmp);
  }

  /**
   * Overload to allow printing of parameters to an iostream
   * NOTE that the implementation relies on calling the virtual
   * PrintParameters method
   * @param out - the stream to print to
   * @param item - reference to the item to print
   * @return the stream
   */
  friend std::ostream &operator<<(std::ostream &out,
                                  const LPCryptoParameters &item) {
    item.PrintParameters(out);
    return out;
  }

  virtual usint GetRelinWindow() const { return 0; }

  virtual int GetDepth() const { return 0; }
  virtual size_t GetMaxDepth() const { return 0; }

  virtual const typename Element::DggType &GetDiscreteGaussianGenerator()
      const {
    PALISADE_THROW(config_error, "No DGG Available for this parameter set");
  }

  /**
   * Sets the reference to element params
   */
  virtual void SetElementParams(shared_ptr<typename Element::Params> params) {
    m_params = params;
  }

  /**
   * Sets the reference to encoding params
   */
  virtual void SetEncodingParams(EncodingParams encodingParams) {
    m_encodingParams = encodingParams;
  }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("elp", m_params));
    ar(::cereal::make_nvp("enp", m_encodingParams));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::make_nvp("elp", m_params));
    ar(::cereal::make_nvp("enp", m_encodingParams));
  }

  std::string SerializedObjectName() const { return "CryptoParameters"; }
  static uint32_t SerializedVersion() { return 1; }

 protected:
  explicit LPCryptoParameters(const PlaintextModulus &plaintextModulus) {
    m_encodingParams = std::make_shared<EncodingParamsImpl>(plaintextModulus);
  }

  LPCryptoParameters(shared_ptr<typename Element::Params> params,
                     const PlaintextModulus &plaintextModulus) {
    m_params = params;
    m_encodingParams = std::make_shared<EncodingParamsImpl>(plaintextModulus);
  }

  LPCryptoParameters(shared_ptr<typename Element::Params> params,
                     EncodingParams encodingParams) {
    m_params = params;
    m_encodingParams = encodingParams;
  }

  LPCryptoParameters(LPCryptoParameters<Element> *from,
                     shared_ptr<typename Element::Params> newElemParms) {
    *this = *from;
    m_params = newElemParms;
  }

  virtual void PrintParameters(std::ostream &out) const {
    out << "Element Parameters: " << *m_params << std::endl;
    out << "Encoding Parameters: " << *m_encodingParams << std::endl;
  }

 private:
  // element-specific parameters
  shared_ptr<typename Element::Params> m_params;

  // encoding-specific parameters
  EncodingParams m_encodingParams;
};

// forward decl so SchemeIdentifier works
template <typename Element>
class LPPublicKeyEncryptionScheme;

template <typename Element>
class PalisadeSchemeIdentifier {
  string schemeName;
  LPPublicKeyEncryptionScheme<Element> *(*schemeMaker)();

 public:
  PalisadeSchemeIdentifier(string n,
                           LPPublicKeyEncryptionScheme<Element> (*f)())
      : schemeName(n), schemeMaker(f) {}

  const string &GetName() const { return schemeName; }
  LPPublicKeyEncryptionScheme<Element> *GetScheme() const {
    return (*schemeMaker)();
  }
};

/**
 * @brief Abstract interface for public key encryption schemes
 * @tparam Element a ring element.
 */
template <typename Element>
class LPPublicKeyEncryptionScheme {
 private:
  inline void CheckMultipartyDecryptCompatibility(
      ConstCiphertext<Element> &ciphertext, CALLER_INFO_ARGS_HDR) const {
    if (ciphertext->GetElements().size() > 2) {
      std::string errorMsg(std::string("ciphertext's number of elements is [") +
                           std::to_string(ciphertext->GetElements().size()) +
                           "]. Must be 2 or less for Multiparty Decryption." +
                           CALLER_INFO);
      PALISADE_THROW(palisade_error, errorMsg);
    }
  }

 public:
  LPPublicKeyEncryptionScheme() {}

  virtual ~LPPublicKeyEncryptionScheme() {}

  virtual bool operator==(const LPPublicKeyEncryptionScheme &sch) const = 0;

  virtual bool operator!=(const LPPublicKeyEncryptionScheme &sch) const {
    return !(*this == sch);
  }

  /**
   * Enable features with a bit mast of PKESchemeFeature codes
   * @param mask
   */
  virtual void Enable(usint mask) {
    if (mask & ENCRYPTION) Enable(ENCRYPTION);

    if (mask & PRE) Enable(PRE);

    if (mask & SHE) Enable(SHE);

    if (mask & LEVELEDSHE) Enable(LEVELEDSHE);

    if (mask & MULTIPARTY) Enable(MULTIPARTY);
  }

  virtual usint GetEnabled() const {
    usint flag = 0;

    if (m_algorithmEncryption != nullptr) flag |= ENCRYPTION;
    if (m_algorithmPRE != nullptr) flag |= PRE;
    if (m_algorithmSHE != nullptr) flag |= SHE;
    if (m_algorithmLeveledSHE != nullptr) flag |= LEVELEDSHE;
    if (m_algorithmMultiparty != nullptr) flag |= MULTIPARTY;

    return flag;
  }

  // instantiated in the scheme implementation class
  virtual void Enable(PKESchemeFeature feature) = 0;

  /////////////////////////////////////////
  // wrapper for LPParameterSelectionAlgorithm
  //

  virtual bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams,
                         int32_t evalAddCount = 0, int32_t evalMultCount = 0,
                         int32_t keySwitchCount = 0, size_t dcrtBits = 0,
                         uint32_t n = 0) const {
    if (m_algorithmParamsGen) {
      return m_algorithmParamsGen->ParamsGen(cryptoParams, evalAddCount,
                                             evalMultCount, keySwitchCount,
                                             dcrtBits, n);
    }
    PALISADE_THROW(not_implemented_error,
                   "Parameter generation operation has not been implemented");
  }

  /////////////////////////////////////////
  // the three functions below are wrappers for things in
  // LPEncryptionAlgorithm (ENCRYPT)
  //

  virtual Ciphertext<Element> Encrypt(const LPPublicKey<Element> publicKey,
                                      const Element &plaintext) const {
    if (m_algorithmEncryption) {
      return m_algorithmEncryption->Encrypt(publicKey, plaintext);
    } else {
      PALISADE_THROW(config_error, "Encrypt operation has not been enabled");
    }
  }

  virtual Ciphertext<Element> Encrypt(const LPPrivateKey<Element> privateKey,
                                      const Element &plaintext) const {
    if (m_algorithmEncryption) {
      return m_algorithmEncryption->Encrypt(privateKey, plaintext);
    }
    PALISADE_THROW(config_error, "Encrypt operation has not been enabled");
  }

  virtual DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
                                ConstCiphertext<Element> ciphertext,
                                NativePoly *plaintext) const {
    if (m_algorithmEncryption) {
      return m_algorithmEncryption->Decrypt(privateKey, ciphertext, plaintext);
    }
    PALISADE_THROW(config_error, "Decrypt operation has not been enabled");
  }

  virtual DecryptResult Decrypt(const LPPrivateKey<Element> privateKey,
                                ConstCiphertext<Element> ciphertext,
                                Poly *plaintext) const {
    if (m_algorithmEncryption) {
      return m_algorithmEncryption->Decrypt(privateKey, ciphertext, plaintext);
    }
    PALISADE_THROW(config_error, "Decrypt operation has not been enabled");
  }

  virtual LPKeyPair<Element> KeyGen(CryptoContext<Element> cc,
                                    bool makeSparse) {
    if (m_algorithmEncryption) {
      auto kp = m_algorithmEncryption->KeyGen(cc, makeSparse);
      kp.publicKey->SetKeyTag(kp.secretKey->GetKeyTag());
      return kp;
    }
    PALISADE_THROW(config_error, "KeyGen operation has not been enabled");
  }

  /////////////////////////////////////////
  // the three functions below are wrappers for things in LPPREAlgorithm (PRE)
  //

  virtual LPEvalKey<Element> ReKeyGen(
      const LPPublicKey<Element> newKey,
      const LPPrivateKey<Element> origPrivateKey) const {
    if (m_algorithmPRE) {
      auto rk = m_algorithmPRE->ReKeyGen(newKey, origPrivateKey);
      rk->SetKeyTag(newKey->GetKeyTag());
      return rk;
    }
    PALISADE_THROW(config_error, "ReKeyGen operation has not been enabled");
  }

  virtual Ciphertext<Element> ReEncrypt(
      const LPEvalKey<Element> evalKey, ConstCiphertext<Element> ciphertext,
      const LPPublicKey<Element> publicKey) const {
    if (m_algorithmPRE) {
      auto ct = m_algorithmPRE->ReEncrypt(evalKey, ciphertext, publicKey);
      ct->SetKeyTag(evalKey->GetKeyTag());
      return ct;
    }
    PALISADE_THROW(config_error, "ReEncrypt operation has not been enabled");
  }

  /////////////////////////////////////////
  // the three functions below are wrappers for things in
  // LPMultipartyAlgorithm (Multiparty)
  //

  // Wrapper for Multiparty Key Gen
  virtual LPKeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
                                              const LPPublicKey<Element> pk1,
                                              bool makeSparse, bool PRE) {
    if (m_algorithmMultiparty) {
      if (!cc) PALISADE_THROW(config_error, "Input crypto context is nullptr");
      if (!pk1) PALISADE_THROW(config_error, "Input public key is empty");
      auto k =
          m_algorithmMultiparty->MultipartyKeyGen(cc, pk1, makeSparse, PRE);
      k.publicKey->SetKeyTag(k.secretKey->GetKeyTag());
      return k;
    }
    PALISADE_THROW(config_error,
                   "MultipartyKeyGen operation has not been enabled");
  }

  // Wrapper for Multiparty Key Gen
  virtual LPKeyPair<Element> MultipartyKeyGen(
      CryptoContext<Element> cc,
      const vector<LPPrivateKey<Element>> &secretKeys, bool makeSparse) {
    if (m_algorithmMultiparty) {
      if (!cc) PALISADE_THROW(config_error, "Input crypto context is nullptr");
      if (!secretKeys.size())
        PALISADE_THROW(config_error, "Input private key vector is empty");
      auto k =
          m_algorithmMultiparty->MultipartyKeyGen(cc, secretKeys, makeSparse);
      k.publicKey->SetKeyTag(k.secretKey->GetKeyTag());
      return k;
    }
    PALISADE_THROW(config_error,
                   "MultipartyKeyGen operation has not been enabled");
  }

  virtual Ciphertext<Element> MultipartyDecryptMain(
      const LPPrivateKey<Element> privateKey,
      ConstCiphertext<Element> ciphertext) const {
    if (m_algorithmMultiparty) {
      CheckMultipartyDecryptCompatibility(ciphertext);
      auto ct =
          m_algorithmMultiparty->MultipartyDecryptMain(privateKey, ciphertext);
      ct->SetKeyTag(privateKey->GetKeyTag());
      return ct;
    }
    PALISADE_THROW(config_error,
                   "MultipartyDecryptMain operation has not been enabled");
  }

  virtual Ciphertext<Element> MultipartyDecryptLead(
      const LPPrivateKey<Element> privateKey,
      ConstCiphertext<Element> ciphertext) const {
    if (m_algorithmMultiparty) {
      CheckMultipartyDecryptCompatibility(ciphertext);
      auto ct =
          m_algorithmMultiparty->MultipartyDecryptLead(privateKey, ciphertext);
      ct->SetKeyTag(privateKey->GetKeyTag());
      return ct;
    }
    PALISADE_THROW(config_error,
                   "MultipartyDecryptLead operation has not been enabled");
  }

  virtual DecryptResult MultipartyDecryptFusion(
      const vector<Ciphertext<Element>> &ciphertextVec,
      NativePoly *plaintext) const {
    if (m_algorithmMultiparty) {
      return m_algorithmMultiparty->MultipartyDecryptFusion(ciphertextVec,
                                                            plaintext);
    }
    PALISADE_THROW(config_error,
                   "MultipartyDecrypt operation has not been enabled");
  }

  virtual DecryptResult MultipartyDecryptFusion(
      const vector<Ciphertext<Element>> &ciphertextVec, Poly *plaintext) const {
    if (m_algorithmMultiparty) {
      return m_algorithmMultiparty->MultipartyDecryptFusion(ciphertextVec,
                                                            plaintext);
    }
    PALISADE_THROW(config_error,
                   "MultipartyDecrypt operation has not been enabled");
  }

  virtual LPEvalKey<Element> MultiKeySwitchGen(
      const LPPrivateKey<Element> originalPrivateKey,
      const LPPrivateKey<Element> newPrivateKey,
      const LPEvalKey<Element> ek) const {
    if (m_algorithmMultiparty) {
      if (!originalPrivateKey)
        PALISADE_THROW(config_error, "Input first private key is nullptr");
      if (!newPrivateKey)
        PALISADE_THROW(config_error, "Input second private key is nullptr");
      if (!ek) PALISADE_THROW(config_error, "Input evaluation key is nullptr");
      auto k = m_algorithmMultiparty->MultiKeySwitchGen(originalPrivateKey,
                                                        newPrivateKey, ek);
      k->SetKeyTag(newPrivateKey->GetKeyTag());
      return k;
    }
    PALISADE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>>
  MultiEvalAutomorphismKeyGen(
      const LPPrivateKey<Element> privateKey,
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> eAuto,
      const std::vector<usint> &indexList, const std::string &keyId = "") {
    if (m_algorithmMultiparty) {
      if (!privateKey)
        PALISADE_THROW(config_error, "Input private key is nullptr");
      if (!eAuto)
        PALISADE_THROW(config_error, "Input evaluation key map is nullptr");
      if (!indexList.size())
        PALISADE_THROW(config_error, "Input index vector is empty");
      auto keys = m_algorithmMultiparty->MultiEvalAutomorphismKeyGen(
          privateKey, eAuto, indexList);
      for (auto it = keys->begin(); it != keys->end(); ++it) {
        if (it->second) {
          it->second->SetKeyTag(keyId);
        }
      }
      return keys;
    }
    PALISADE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>>
  MultiEvalAtIndexKeyGen(
      const LPPrivateKey<Element> privateKey,
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> eAuto,
      const std::vector<int32_t> &indexList, const std::string &keyId = "") {
    if (m_algorithmMultiparty) {
      if (!privateKey)
        PALISADE_THROW(config_error, "Input private key is nullptr");
      if (!eAuto)
        PALISADE_THROW(config_error, "Input evaluation key map is nullptr");
      if (!indexList.size())
        PALISADE_THROW(config_error, "Input index vector is empty");
      auto keys = m_algorithmMultiparty->MultiEvalAtIndexKeyGen(
          privateKey, eAuto, indexList);
      for (auto it = keys->begin(); it != keys->end(); ++it) {
        if (it->second) {
          it->second->SetKeyTag(keyId);
        }
      }
      return keys;
    }
    PALISADE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiEvalSumKeyGen(
      const LPPrivateKey<Element> privateKey,
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> eSum,
      const std::string &keyId = "") {
    if (m_algorithmMultiparty) {
      if (!privateKey)
        PALISADE_THROW(config_error, "Input private key is nullptr");
      if (!eSum)
        PALISADE_THROW(config_error, "Input evaluation key map is nullptr");
      auto keys = m_algorithmMultiparty->MultiEvalSumKeyGen(privateKey, eSum);
      for (auto it = keys->begin(); it != keys->end(); ++it) {
        if (it->second) {
          it->second->SetKeyTag(keyId);
        }
      }
      return keys;
    }
    PALISADE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual LPEvalKey<Element> MultiAddEvalKeys(LPEvalKey<Element> a,
                                              LPEvalKey<Element> b,
                                              const std::string &keyId = "") {
    if (m_algorithmMultiparty) {
      if (!a)
        PALISADE_THROW(config_error, "Input first evaluation key is nullptr");
      if (!b)
        PALISADE_THROW(config_error, "Input second evaluation key is nullptr");

      auto key = m_algorithmMultiparty->MultiAddEvalKeys(a, b);
      key->SetKeyTag(keyId);
      return key;
    }
    PALISADE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual LPEvalKey<Element> MultiMultEvalKey(LPEvalKey<Element> evalKey,
                                              LPPrivateKey<Element> sk,
                                              const std::string &keyId = "") {
    if (m_algorithmMultiparty) {
      if (!evalKey)
        PALISADE_THROW(config_error, "Input evaluation key is nullptr");
      if (!sk) PALISADE_THROW(config_error, "Input private key is nullptr");

      auto key = m_algorithmMultiparty->MultiMultEvalKey(evalKey, sk);
      key->SetKeyTag(keyId);
      return key;
    }
    PALISADE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiAddEvalSumKeys(
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> es1,
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> es2,
      const std::string &keyId = "") {
    if (m_algorithmMultiparty) {
      if (!es1)
        PALISADE_THROW(config_error,
                       "Input first evaluation key map is nullptr");
      if (!es2)
        PALISADE_THROW(config_error,
                       "Input second evaluation key map is nullptr");
      auto keys = m_algorithmMultiparty->MultiAddEvalSumKeys(es1, es2);
      for (auto it = keys->begin(); it != keys->end(); ++it) {
        if (it->second) {
          it->second->SetKeyTag(keyId);
        }
      }
      return keys;
    }
    PALISADE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>>
  MultiAddEvalAutomorphismKeys(
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> es1,
      const shared_ptr<std::map<usint, LPEvalKey<Element>>> es2,
      const std::string &keyId = "") {
    if (m_algorithmMultiparty) {
      if (!es1)
        PALISADE_THROW(config_error,
                       "Input first evaluation key map is nullptr");
      if (!es2)
        PALISADE_THROW(config_error,
                       "Input second evaluation key map is nullptr");

      auto keys = m_algorithmMultiparty->MultiAddEvalAutomorphismKeys(es1, es2);
      for (auto it = keys->begin(); it != keys->end(); ++it) {
        if (it->second) {
          it->second->SetKeyTag(keyId);
        }
      }
      return keys;
    }
    PALISADE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual LPPublicKey<Element> MultiAddPubKeys(LPPublicKey<Element> pubKey1,
                                               LPPublicKey<Element> pubKey2,
                                               const std::string &keyId = "") {
    if (m_algorithmMultiparty) {
      if (!pubKey1)
        PALISADE_THROW(config_error, "Input first public key is nullptr");
      if (!pubKey2)
        PALISADE_THROW(config_error, "Input second public key is nullptr");

      auto key = m_algorithmMultiparty->MultiAddPubKeys(pubKey1, pubKey2);
      key->SetKeyTag(keyId);
      return key;
    }
    PALISADE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual LPEvalKey<Element> MultiAddEvalMultKeys(
      LPEvalKey<Element> evalKey1, LPEvalKey<Element> evalKey2,
      const std::string &keyId = "") {
    if (m_algorithmMultiparty) {
      if (!evalKey1)
        PALISADE_THROW(config_error, "Input first evaluation key is nullptr");
      if (!evalKey2)
        PALISADE_THROW(config_error, "Input second evaluation key is nullptr");
      auto key =
          m_algorithmMultiparty->MultiAddEvalMultKeys(evalKey1, evalKey2);
      key->SetKeyTag(keyId);
      return key;
    }
    PALISADE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  /////////////////////////////////////////
  // the three functions below are wrappers for things in LPSHEAlgorithm (SHE)
  //

  virtual Ciphertext<Element> AddRandomNoise(
      ConstCiphertext<Element> ciphertext) const {
    if (m_algorithmSHE) {
      if (!ciphertext)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      return m_algorithmSHE->AddRandomNoise(ciphertext);
    }
    PALISADE_THROW(config_error,
                   "AddRandomNoise operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalAdd(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        PALISADE_THROW(config_error, "Input second ciphertext is nullptr");
      return m_algorithmSHE->EvalAdd(ciphertext1, ciphertext2);
    }
    PALISADE_THROW(config_error, "EvalAdd operation has not been enabled");
  }

  virtual void EvalAddInPlace(Ciphertext<Element> &ciphertext1,
                              ConstCiphertext<Element> ciphertext2) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        PALISADE_THROW(config_error, "Input second ciphertext is nullptr");
      m_algorithmSHE->EvalAddInPlace(ciphertext1, ciphertext2);
      return;
    }
    PALISADE_THROW(config_error,
                   "EvalAddInPlace operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalAddMutable(
      Ciphertext<Element> &ciphertext1,
      Ciphertext<Element> &ciphertext2) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        PALISADE_THROW(config_error, "Input second ciphertext is nullptr");
      return m_algorithmSHE->EvalAddMutable(ciphertext1, ciphertext2);
    }
    PALISADE_THROW(config_error, "EvalAdd operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext1,
                                      ConstPlaintext plaintext) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      if (!plaintext)
        PALISADE_THROW(config_error, "Input plaintext is nullptr");
      return m_algorithmSHE->EvalAdd(ciphertext1, plaintext);
    }
    PALISADE_THROW(config_error, "EvalAdd operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalAddMutable(Ciphertext<Element> &ciphertext1,
                                             Plaintext plaintext) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      if (!plaintext)
        PALISADE_THROW(config_error, "Input plaintext is nullptr");
      return m_algorithmSHE->EvalAddMutable(ciphertext1, plaintext);
    }
    PALISADE_THROW(config_error, "EvalAdd operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext1,
                                      double constant) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      return m_algorithmSHE->EvalAdd(ciphertext1, constant);
    }
    PALISADE_THROW(config_error, "EvalAdd operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalLinearWSum(
      vector<Ciphertext<Element>> ciphertexts, vector<double> constants) const {
    if (m_algorithmSHE) {
      if (!ciphertexts.size())
        PALISADE_THROW(config_error, "Input ciphertext vector is empty");
      return m_algorithmSHE->EvalLinearWSum(ciphertexts, constants);
    }
    PALISADE_THROW(config_error,
                   "EvalLinearWSum operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalLinearWSumMutable(
      vector<Ciphertext<Element>> ciphertexts, vector<double> constants) const {
    if (m_algorithmSHE) {
      if (!ciphertexts.size())
        PALISADE_THROW(config_error, "Input ciphertext vector is empty");
      return m_algorithmSHE->EvalLinearWSumMutable(ciphertexts, constants);
    }
    PALISADE_THROW(config_error,
                   "EvalLinearWSum operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalSub(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        PALISADE_THROW(config_error, "Input second ciphertext is nullptr");
      return m_algorithmSHE->EvalSub(ciphertext1, ciphertext2);
    }
    PALISADE_THROW(config_error, "EvalSub operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalSubMutable(
      Ciphertext<Element> &ciphertext1,
      Ciphertext<Element> &ciphertext2) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        PALISADE_THROW(config_error, "Input second ciphertext is nullptr");
      return m_algorithmSHE->EvalSubMutable(ciphertext1, ciphertext2);
    }
    PALISADE_THROW(config_error, "EvalSub operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext1,
                                      ConstPlaintext plaintext) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      if (!plaintext)
        PALISADE_THROW(config_error, "Input plaintext is nullptr");
      return m_algorithmSHE->EvalSub(ciphertext1, plaintext);
    }
    PALISADE_THROW(config_error, "EvalSub operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalSubMutable(Ciphertext<Element> &ciphertext1,
                                             Plaintext plaintext) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      if (!plaintext)
        PALISADE_THROW(config_error, "Input plaintext is nullptr");
      return m_algorithmSHE->EvalSubMutable(ciphertext1, plaintext);
    }
    PALISADE_THROW(config_error, "EvalSub operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext1,
                                      double constant) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      return m_algorithmSHE->EvalSub(ciphertext1, constant);
    }
    PALISADE_THROW(config_error, "EvalSub operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMult(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        PALISADE_THROW(config_error, "Input second ciphertext is nullptr");
      return m_algorithmSHE->EvalMult(ciphertext1, ciphertext2);
    }
    PALISADE_THROW(config_error, "EvalMult operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMultMutable(
      Ciphertext<Element> &ciphertext1,
      Ciphertext<Element> &ciphertext2) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        PALISADE_THROW(config_error, "Input second ciphertext is nullptr");
      return m_algorithmSHE->EvalMultMutable(ciphertext1, ciphertext2);
    }
    PALISADE_THROW(config_error, "EvalMult operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext,
                                       ConstPlaintext plaintext) const {
    if (m_algorithmSHE) {
      if (!ciphertext)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      if (!plaintext)
        PALISADE_THROW(config_error, "Input plaintext is nullptr");
      return m_algorithmSHE->EvalMult(ciphertext, plaintext);
    }
    PALISADE_THROW(config_error, "EvalMult operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element> &ciphertext,
                                              Plaintext plaintext) const {
    if (m_algorithmSHE) {
      if (!ciphertext)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      if (!plaintext)
        PALISADE_THROW(config_error, "Input plaintext is nullptr");
      return m_algorithmSHE->EvalMultMutable(ciphertext, plaintext);
    }
    PALISADE_THROW(config_error, "EvalMult operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1,
                                       double constant) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      return m_algorithmSHE->EvalMult(ciphertext1, constant);
    }
    PALISADE_THROW(config_error, "EvalMult operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element> &ciphertext1,
                                              double constant) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      return m_algorithmSHE->EvalMultMutable(ciphertext1, constant);
    }
    PALISADE_THROW(config_error, "EvalMult operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1,
                                       ConstCiphertext<Element> ciphertext2,
                                       const LPEvalKey<Element> evalKey) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        PALISADE_THROW(config_error, "Input second ciphertext is nullptr");
      if (!evalKey)
        PALISADE_THROW(config_error, "Input evaluation key is nullptr");
      return m_algorithmSHE->EvalMult(ciphertext1, ciphertext2, evalKey);
    }
    PALISADE_THROW(config_error, "EvalMult operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMultMutable(
      Ciphertext<Element> &ciphertext1, Ciphertext<Element> &ciphertext2,
      const LPEvalKey<Element> evalKey) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        PALISADE_THROW(config_error, "Input second ciphertext is nullptr");
      if (!evalKey)
        PALISADE_THROW(config_error, "Input evaluation key is nullptr");
      auto ct =
          m_algorithmSHE->EvalMultMutable(ciphertext1, ciphertext2, evalKey);
      return ct;
    }
    PALISADE_THROW(config_error, "EvalMult operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMultMany(
      const vector<Ciphertext<Element>> &ciphertext,
      const vector<LPEvalKey<Element>> &evalKeys) const {
    if (m_algorithmSHE) {
      if (!ciphertext.size())
        PALISADE_THROW(config_error, "Input ciphertext vector is empty");
      if (!evalKeys.size())
        PALISADE_THROW(config_error, "Input evaluation key vector is empty");
      return m_algorithmSHE->EvalMultMany(ciphertext, evalKeys);
    }
    PALISADE_THROW(config_error, "EvalMultMany operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalAddMany(
      const vector<Ciphertext<Element>> &ciphertexts) const {
    if (m_algorithmSHE) {
      if (!ciphertexts.size())
        PALISADE_THROW(config_error, "Input ciphertext vector is empty");
      return m_algorithmSHE->EvalAddMany(ciphertexts);
    }
    PALISADE_THROW(config_error, "EvalAddMany operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalAddManyInPlace(
      vector<Ciphertext<Element>> &ciphertexts) const {
    if (m_algorithmSHE) {
      if (!ciphertexts.size())
        PALISADE_THROW(config_error, "Input ciphertext vector is empty");
      return m_algorithmSHE->EvalAddManyInPlace(ciphertexts);
    }
    PALISADE_THROW(config_error,
                   "EvalAddManyInPlace operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalNegate(
      ConstCiphertext<Element> ciphertext) const {
    if (m_algorithmSHE) {
      if (!ciphertext)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      auto ct = m_algorithmSHE->EvalNegate(ciphertext);
      return ct;
    }
    PALISADE_THROW(config_error, "EvalNegate operation has not been enabled");
  }

  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>>
  EvalAutomorphismKeyGen(const LPPublicKey<Element> publicKey,
                         const LPPrivateKey<Element> origPrivateKey,
                         const std::vector<usint> &indexList) const {
    if (m_algorithmSHE) {
      if (!publicKey)
        PALISADE_THROW(config_error, "Input public key is nullptr");
      if (!origPrivateKey)
        PALISADE_THROW(config_error, "Input private key is nullptr");
      auto km = m_algorithmSHE->EvalAutomorphismKeyGen(
          publicKey, origPrivateKey, indexList);
      for (auto &k : *km) k.second->SetKeyTag(origPrivateKey->GetKeyTag());
      return km;
    }
    PALISADE_THROW(config_error,
                   "EvalAutomorphismKeyGen operation has not been enabled");
  }

  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalAtIndexKeyGen(
      const LPPublicKey<Element> publicKey,
      const LPPrivateKey<Element> origPrivateKey,
      const std::vector<int32_t> &indexList) const {
    if (m_algorithmSHE) {
      if (!origPrivateKey)
        PALISADE_THROW(config_error, "Input private key is nullptr");
      auto km = m_algorithmSHE->EvalAtIndexKeyGen(publicKey, origPrivateKey,
                                                  indexList);
      for (auto &k : *km) k.second->SetKeyTag(origPrivateKey->GetKeyTag());
      return km;
    }
    PALISADE_THROW(config_error,
                   "EvalAtIndexKeyGen operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalAutomorphism(
      ConstCiphertext<Element> ciphertext, usint i,
      const std::map<usint, LPEvalKey<Element>> &evalKeys,
      CALLER_INFO_ARGS_HDR) const {
    if (m_algorithmSHE) {
      if (!ciphertext)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      if (!evalKeys.size())
        PALISADE_THROW(config_error, "Input evaluation key map is empty");
      auto ct = m_algorithmSHE->EvalAutomorphism(ciphertext, i, evalKeys);
      return ct;
    }
    std::string errorMsg(
        std::string("EvalAutomorphism operation has not been enabled") +
        CALLER_INFO);
    PALISADE_THROW(config_error, errorMsg);
  }

  virtual Ciphertext<Element> EvalAtIndex(
      ConstCiphertext<Element> ciphertext, usint i,
      const std::map<usint, LPEvalKey<Element>> &evalKeys) const {
    if (m_algorithmSHE) {
      if (!ciphertext)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      if (!evalKeys.size())
        PALISADE_THROW(config_error, "Input evaluation key map is empty");
      auto ct = m_algorithmSHE->EvalAtIndex(ciphertext, i, evalKeys);
      return ct;
    }
    PALISADE_THROW(config_error, "EvalAtIndex operation has not been enabled");
  }

  virtual shared_ptr<vector<Element>> EvalFastRotationPrecompute(
      ConstCiphertext<Element> ciphertext) const {
    if (m_algorithmSHE) {
      if (!ciphertext)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      auto ct = m_algorithmSHE->EvalFastRotationPrecompute(ciphertext);
      return ct;
    }
    PALISADE_THROW(config_error,
                   "EvalFastRotationPrecompute operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalFastRotation(
      ConstCiphertext<Element> ciphertext, const usint index, const usint m,
      const shared_ptr<vector<Element>> digits) const {
    if (m_algorithmSHE) {
      if (!ciphertext)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      auto ct = m_algorithmSHE->EvalFastRotation(ciphertext, index, m, digits);
      return ct;
    }
    PALISADE_THROW(config_error,
                   "EvalFastRotation operation has not been enabled");
  }

  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>>
  EvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
                         const std::vector<usint> &indexList) const {
    if (m_algorithmSHE) {
      if (!privateKey)
        PALISADE_THROW(config_error, "Input private key is nullptr");
      auto km = m_algorithmSHE->EvalAutomorphismKeyGen(privateKey, indexList);
      for (auto &k : *km) k.second->SetKeyTag(privateKey->GetKeyTag());
      return km;
    }
    PALISADE_THROW(config_error,
                   "EvalAutomorphismKeyGen operation has not been enabled");
  }

  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumKeyGen(
      const LPPrivateKey<Element> privateKey,
      const LPPublicKey<Element> publicKey) const {
    if (m_algorithmSHE) {
      if (!privateKey)
        PALISADE_THROW(config_error, "Input private key is nullptr");
      auto km = m_algorithmSHE->EvalSumKeyGen(privateKey, publicKey);
      for (auto &k : *km) {
        k.second->SetKeyTag(privateKey->GetKeyTag());
      }
      return km;
    }
    PALISADE_THROW(config_error,
                   "EvalSumKeyGen operation has not been enabled");
  }

  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumRowsKeyGen(
      const LPPrivateKey<Element> privateKey,
      const LPPublicKey<Element> publicKey, usint rowSize,
      usint subringDim = 0) const {
    if (m_algorithmSHE) {
      if (!privateKey)
        PALISADE_THROW(config_error, "Input private key is nullptr");
      auto km = m_algorithmSHE->EvalSumRowsKeyGen(privateKey, publicKey,
                                                  rowSize, subringDim);
      for (auto &k : *km) {
        k.second->SetKeyTag(privateKey->GetKeyTag());
      }
      return km;
    }
    PALISADE_THROW(config_error,
                   "EvalSumRowsKeyGen operation has not been enabled");
  }

  virtual shared_ptr<std::map<usint, LPEvalKey<Element>>> EvalSumColsKeyGen(
      const LPPrivateKey<Element> privateKey,
      const LPPublicKey<Element> publicKey) const {
    if (m_algorithmSHE) {
      if (!privateKey)
        PALISADE_THROW(config_error, "Input private key is nullptr");
      auto km = m_algorithmSHE->EvalSumColsKeyGen(privateKey, publicKey);
      for (auto &k : *km) {
        k.second->SetKeyTag(privateKey->GetKeyTag());
      }
      return km;
    }
    PALISADE_THROW(config_error,
                   "EvalSumColsKeyGen operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalSum(
      ConstCiphertext<Element> ciphertext, usint batchSize,
      const std::map<usint, LPEvalKey<Element>> &evalKeys) const {
    if (m_algorithmSHE) {
      if (!ciphertext)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      if (!evalKeys.size())
        PALISADE_THROW(config_error, "Input evaluation key map is empty");
      auto ct = m_algorithmSHE->EvalSum(ciphertext, batchSize, evalKeys);
      return ct;
    }
    PALISADE_THROW(config_error, "EvalSum operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalSumRows(
      ConstCiphertext<Element> ciphertext, usint rowSize,
      const std::map<usint, LPEvalKey<Element>> &evalKeys,
      usint subringDim = 0) const {
    if (m_algorithmSHE) {
      if (!ciphertext)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      if (!evalKeys.size())
        PALISADE_THROW(config_error, "Input evaluation key map is empty");
      auto ct = m_algorithmSHE->EvalSumRows(ciphertext, rowSize, evalKeys,
                                            subringDim);
      return ct;
    }
    PALISADE_THROW(config_error, "EvalSumRow operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalSumCols(
      ConstCiphertext<Element> ciphertext, usint batchSize,
      const std::map<usint, LPEvalKey<Element>> &evalKeys,
      const std::map<usint, LPEvalKey<Element>> &rightEvalKeys) const {
    if (m_algorithmSHE) {
      if (!evalKeys.size())
        PALISADE_THROW(config_error, "Input first evaluation key map is empty");
      if (!rightEvalKeys.size())
        PALISADE_THROW(config_error,
                       "Input second evaluation key map is empty");
      auto ct = m_algorithmSHE->EvalSumCols(ciphertext, batchSize, evalKeys,
                                            rightEvalKeys);
      return ct;
    }
    PALISADE_THROW(config_error, "EvalSumCols operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalInnerProduct(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2, usint batchSize,
      const std::map<usint, LPEvalKey<Element>> &evalSumKeys,
      const LPEvalKey<Element> evalMultKey) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        PALISADE_THROW(config_error, "Input second ciphertext is nullptr");
      if (!evalSumKeys.size())
        PALISADE_THROW(config_error, "Input evaluation key map is empty");
      if (!evalMultKey)
        PALISADE_THROW(config_error, "Input evaluation key is nullptr");
      auto ct = m_algorithmSHE->EvalInnerProduct(
          ciphertext1, ciphertext2, batchSize, evalSumKeys, evalMultKey);
      ct->SetKeyTag(evalSumKeys.begin()->second->GetKeyTag());
      return ct;
    }
    PALISADE_THROW(config_error,
                   "EvalInnerProduct operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMerge(
      const vector<Ciphertext<Element>> &ciphertextVector,
      const std::map<usint, LPEvalKey<Element>> &evalKeys) const {
    if (m_algorithmSHE) {
      if (!ciphertextVector.size())
        PALISADE_THROW(config_error, "Input ciphertext vector is empty");
      if (!evalKeys.size())
        PALISADE_THROW(config_error, "Input evaluation key map is empty");
      return m_algorithmSHE->EvalMerge(ciphertextVector, evalKeys);
    }
    PALISADE_THROW(config_error, "EvalMerge operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalInnerProduct(
      ConstCiphertext<Element> ciphertext1, ConstPlaintext plaintext,
      usint batchSize,
      const std::map<usint, LPEvalKey<Element>> &evalSumKeys) const {
    if (m_algorithmSHE) {
      if (!ciphertext1)
        PALISADE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!plaintext)
        PALISADE_THROW(config_error, "Input plaintext is nullptr");
      if (!evalSumKeys.size())
        PALISADE_THROW(config_error, "Input evaluation key map is empty");
      return m_algorithmSHE->EvalInnerProduct(ciphertext1, plaintext, batchSize,
                                              evalSumKeys);
    }
    PALISADE_THROW(config_error,
                   "EvalInnerProduct operation has not been enabled");
  }

  virtual LPEvalKey<Element> KeySwitchGen(
      const LPPrivateKey<Element> originalPrivateKey,
      const LPPrivateKey<Element> newPrivateKey) const {
    if (m_algorithmSHE) {
      if (!originalPrivateKey)
        PALISADE_THROW(config_error, "Input first private key is nullptr");
      if (!newPrivateKey)
        PALISADE_THROW(config_error, "Input second private key is nullptr");
      auto kp = m_algorithmSHE->KeySwitchGen(originalPrivateKey, newPrivateKey);
      kp->SetKeyTag(newPrivateKey->GetKeyTag());
      return kp;
    }
    PALISADE_THROW(config_error, "KeySwitchGen operation has not been enabled");
  }

  virtual Ciphertext<Element> KeySwitch(
      const LPEvalKey<Element> keySwitchHint,
      ConstCiphertext<Element> cipherText) const {
    if (m_algorithmSHE) {
      if (!keySwitchHint)
        PALISADE_THROW(config_error, "Input evaluation key is nullptr");
      if (!cipherText)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      auto ct = m_algorithmSHE->KeySwitch(keySwitchHint, cipherText);
      return ct;
    }
    PALISADE_THROW(config_error, "KeySwitch operation has not been enabled");
  }

  virtual void KeySwitchInPlace(const LPEvalKey<Element> keySwitchHint,
                                Ciphertext<Element> &cipherText) const {
    if (m_algorithmSHE) {
      if (!keySwitchHint)
        PALISADE_THROW(config_error, "Input evaluation key is nullptr");
      if (!cipherText)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      m_algorithmSHE->KeySwitchInPlace(keySwitchHint, cipherText);
      return;
    }
    PALISADE_THROW(config_error,
                   "KeySwitchInPlace operation has not been enabled");
  }

  virtual LPEvalKey<Element> EvalMultKeyGen(
      const LPPrivateKey<Element> originalPrivateKey) const {
    if (m_algorithmSHE) {
      if (!originalPrivateKey)
        PALISADE_THROW(config_error, "Input private key is nullptr");
      auto ek = m_algorithmSHE->EvalMultKeyGen(originalPrivateKey);
      ek->SetKeyTag(originalPrivateKey->GetKeyTag());
      return ek;
    }
    PALISADE_THROW(config_error,
                   "EvalMultKeyGen operation has not been enabled");
  }

  virtual vector<LPEvalKey<Element>> EvalMultKeysGen(
      const LPPrivateKey<Element> originalPrivateKey) const {
    if (m_algorithmSHE) {
      if (!originalPrivateKey)
        PALISADE_THROW(config_error, "Input private key is nullptr");
      auto ek = m_algorithmSHE->EvalMultKeysGen(originalPrivateKey);
      for (size_t i = 0; i < ek.size(); i++)
        ek[i]->SetKeyTag(originalPrivateKey->GetKeyTag());
      return ek;
    }
    PALISADE_THROW(config_error,
                   "EvalMultKeysGen operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMultAndRelinearize(
      ConstCiphertext<Element> ct1, ConstCiphertext<Element> ct2,
      const vector<LPEvalKey<Element>> &ek) const {
    if (m_algorithmSHE) {
      if (!ct1)
        PALISADE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ct2)
        PALISADE_THROW(config_error, "Input second ciphertext is nullptr");
      if (!ek.size())
        PALISADE_THROW(config_error, "Input evaluation key vector is empty");
      return m_algorithmSHE->EvalMultAndRelinearize(ct1, ct2, ek);
    }
    PALISADE_THROW(config_error,
                   "EvalMultAndRelinearize operation has not been enabled");
  }

  virtual Ciphertext<Element> Relinearize(
      ConstCiphertext<Element> ciphertext,
      const vector<LPEvalKey<Element>> &ek) const {
    if (m_algorithmSHE) {
      if (!ciphertext)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      if (!ek.size())
        PALISADE_THROW(config_error, "Input evaluation key vector is empty");
      return m_algorithmSHE->Relinearize(ciphertext, ek);
    }
    PALISADE_THROW(config_error, "Relinearize operation has not been enabled");
  }

  virtual void RelinearizeInPlace(
      Ciphertext<Element> &ciphertext,
      const vector<LPEvalKey<Element>> &ek) const {
    if (m_algorithmSHE) {
      if (!ciphertext)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      if (!ek.size())
        PALISADE_THROW(config_error, "Input evaluation key vector is empty");
      return m_algorithmSHE->RelinearizeInPlace(ciphertext, ek);
    }
    PALISADE_THROW(config_error, "RelinearizeInPlace operation has not been enabled");
  }

  /////////////////////////////////////////
  // the functions below are wrappers for things in LPFHEAlgorithm (FHE)
  //
  // TODO: Add Bootstrap and any other FHE methods

  /////////////////////////////////////////
  // the functions below are wrappers for things in LPSHEAlgorithm (SHE)
  //

  virtual Ciphertext<Element> ModReduce(ConstCiphertext<Element> cipherText,
                                        size_t levels = 1) const {
    if (m_algorithmLeveledSHE) {
      if (!cipherText)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      auto ct = m_algorithmLeveledSHE->ModReduce(cipherText, levels);
      ct->SetKeyTag(cipherText->GetKeyTag());
      return ct;
    }
    PALISADE_THROW(config_error, "ModReduce operation has not been enabled");
  }

  virtual void ModReduceInPlace(Ciphertext<Element> &cipherText,
                                size_t levels = 1) const {
    if (m_algorithmLeveledSHE) {
      if (!cipherText)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      m_algorithmLeveledSHE->ModReduceInPlace(cipherText, levels);
      return;
    }
    PALISADE_THROW(config_error, "ModReduce operation has not been enabled");
  }

  virtual Ciphertext<Element> ComposedEvalMult(
      ConstCiphertext<Element> cipherText1,
      ConstCiphertext<Element> cipherText2,
      const LPEvalKey<Element> quadKeySwitchHint) const {
    if (m_algorithmLeveledSHE) {
      if (!cipherText1)
        PALISADE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!cipherText2)
        PALISADE_THROW(config_error, "Input second ciphertext is nullptr");
      if (!quadKeySwitchHint)
        PALISADE_THROW(config_error, "Input evaluation key is nullptr");
      auto ct = m_algorithmLeveledSHE->ComposedEvalMult(
          cipherText1, cipherText2, quadKeySwitchHint);
      ct->SetKeyTag(quadKeySwitchHint->GetKeyTag());
      return ct;
    }
    PALISADE_THROW(config_error,
                   "ComposedEvalMult operation has not been enabled");
  }

  virtual Ciphertext<Element> LevelReduce(
      ConstCiphertext<Element> cipherText1,
      const LPEvalKey<Element> linearKeySwitchHint, size_t levels = 1) const {
    if (m_algorithmLeveledSHE) {
      if (!cipherText1)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      // if (!linearKeySwitchHint)
      //    PALISADE_THROW(config_error, "Input evaluation key is nullptr");
      auto ct = m_algorithmLeveledSHE->LevelReduce(cipherText1,
                                                   linearKeySwitchHint, levels);
      ct->SetKeyTag(cipherText1->GetKeyTag());
      return ct;
    }
    PALISADE_THROW(config_error, "LevelReduce operation has not been enabled");
  }

  /**
   * Method for polynomial evaluation for polynomials represented as power
   * series.
   *
   * @param &cipherText input ciphertext
   * @param &coefficients is the vector of coefficients in the polynomial; the
   * size of the vector is the degree of the polynomial + 1
   * @return the result of polynomial evaluation.
   */
  Ciphertext<Element> EvalPoly(ConstCiphertext<Element> ciphertext,
                               const std::vector<double> &coefficients) const {
    if (this->m_algorithmLeveledSHE) {
      if (!ciphertext)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      auto ctm =
          this->m_algorithmLeveledSHE->EvalPoly(ciphertext, coefficients);
      return ctm;
    } else {
      PALISADE_THROW(config_error, "EvalPoly operation has not been enabled");
    }
  }

  /*
   * This exposes CKKS's own ParamsGen through the
   * LPPublicKeyEncryptionSchemeCKKS API. See
   * LPAlgorithmParamsGenCKKS::ParamsGen for a description of the arguments.
   *
   */
  virtual bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams,
                         usint cyclOrder, usint numPrimes, usint scaleExp,
                         usint relinWindow, MODE mode,
                         enum KeySwitchTechnique ksTech, usint firstModSize,
                         RescalingTechnique rsTech,
                         uint32_t numLargeDigits) const {
    if (m_algorithmParamsGen) {
      return m_algorithmParamsGen->ParamsGen(
          cryptoParams, cyclOrder, numPrimes, scaleExp, relinWindow, mode,
          ksTech, firstModSize, rsTech, numLargeDigits);
    }
    PALISADE_THROW(not_implemented_error,
                   "Parameter generation operation has not been implemented "
                   "for this scheme.");
  }

  /*
   * This exposes BGVrns own ParamsGen through the
   * LPPublicKeyEncryptionSchemeBGVrns API. See
   * LPAlgorithmParamsGenBGVrns::ParamsGen for a description of the arguments.
   *
   */
  virtual bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams,
                         usint cyclOrder, usint ptm, usint numPrimes,
                         usint relinWindow, MODE mode,
                         enum KeySwitchTechnique ksTech, usint firstModSize,
                         usint dcrtBits, uint32_t numLargeDigits) const {
    if (m_algorithmParamsGen) {
      return m_algorithmParamsGen->ParamsGen(
          cryptoParams, cyclOrder, ptm, numPrimes, relinWindow, mode, ksTech,
          firstModSize, dcrtBits, numLargeDigits);
    }
    PALISADE_THROW(
        not_implemented_error,
        "Parameter generation operation has not been implemented for this "
        "scheme.");
  }

  /*
   * Internal method performing level reduce (drop towers).
   * It's exposed here so methods in LPAlgorithmSHECKKS can access methods
   * from LPLeveledSHEAlgorithmCKKS (so that automatic rescaling can work
   * in EXACTRESCALE).
   *
   * @param cipherText1 input ciphertext
   * @param linearKeySwitchHint not used in the CKKS scheme.
   * @param levels the number of towers to drop from the input ciphertext
   * @return a ciphertext of the same plaintext value as that of the input,
   *         but with fewer towers.
   *
   */
  virtual Ciphertext<Element> LevelReduceInternal(
      ConstCiphertext<Element> cipherText1,
      const LPEvalKey<Element> linearKeySwitchHint, size_t levels) const {
    if (m_algorithmLeveledSHE) {
      if (!cipherText1)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      return m_algorithmLeveledSHE->LevelReduceInternal(
          cipherText1, linearKeySwitchHint, levels);
    }
    PALISADE_THROW(not_implemented_error,
                   "LevelReduceInternal has not been enabled for this scheme.");
  }

  /*
   * Internal method performing in-place level reduce (drop towers).
   * It's exposed here so methods in LPAlgorithmSHECKKS can access methods
   * from LPLeveledSHEAlgorithmCKKS (so that automatic rescaling can work
   * in EXACTRESCALE).
   *
   * @param cipherText1 input/output ciphertext
   * @param linearKeySwitchHint not used in the CKKS scheme.
   * @param levels the number of towers to drop from the input ciphertext
   * @return a ciphertext of the same plaintext value as that of the input,
   *         but with fewer towers.
   *
   */
  virtual void LevelReduceInternalInPlace(
      Ciphertext<Element> &cipherText1,
      const LPEvalKey<Element> linearKeySwitchHint, size_t levels) const {
    if (m_algorithmLeveledSHE) {
      if (!cipherText1)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      m_algorithmLeveledSHE->LevelReduceInternalInPlace(
          cipherText1, linearKeySwitchHint, levels);
      return;
    }
    PALISADE_THROW(
        not_implemented_error,
        "LevelReduceInternalInPlace has not been enabled for this scheme.");
  }

  /*
   * Internal method performing mod reduce (rescaling).
   * It's exposed here so methods in LPAlgorithmSHECKKS can access the method
   * from LPLeveledSHEAlgorithmCKKS (so that automatic rescaling can work
   * in EXACTRESCALE).
   *
   * @param cipherText1 input ciphertext
   * @return the rescaled ciphertext.
   *
   */
  virtual Ciphertext<Element> ModReduceInternal(
      ConstCiphertext<Element> cipherText, size_t levels = 1) const {
    if (m_algorithmLeveledSHE) {
      if (!cipherText)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      return m_algorithmLeveledSHE->ModReduceInternal(cipherText, levels);
    }
    PALISADE_THROW(config_error,
                   "ModReduceInternal has not been enabled for this scheme.");
  }

  virtual void ModReduceInternalInPlace(Ciphertext<Element> &cipherText,
                                        size_t levels = 1) const {
    if (m_algorithmLeveledSHE) {
      if (!cipherText)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      m_algorithmLeveledSHE->ModReduceInternalInPlace(cipherText, levels);
      return;
    }
    PALISADE_THROW(
        config_error,
        "ModReduceInternalInPlace has not been enabled for this scheme.");
  }

  virtual Ciphertext<Element> Compress(ConstCiphertext<Element> cipherText,
                                       size_t towersLeft = 1) const {
    if (m_algorithmLeveledSHE) {
      if (!cipherText)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      return m_algorithmLeveledSHE->Compress(cipherText, towersLeft);
    }
    PALISADE_THROW(config_error,
                   "Compress has not been enabled for this scheme.");
  }

  virtual Ciphertext<Element> AdjustLevelWithRescale(
      Ciphertext<Element> cipherText, uint32_t targetLevel) const {
    if (m_algorithmSHE) {
      if (!cipherText)
        PALISADE_THROW(config_error, "Input ciphertext is nullptr");
      return m_algorithmSHE->AdjustLevelWithRescale(cipherText, targetLevel);
    }
    PALISADE_THROW(
        config_error,
        "AdjustLevelWithRescale has not been enabled for this scheme.");
  }

  const std::shared_ptr<LPEncryptionAlgorithm<Element>> getAlgorithm() const {
    return m_algorithmEncryption;
  }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("enabled", GetEnabled()));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }

    usint enabled;
    ar(::cereal::make_nvp("enabled", enabled));
    this->Enable(enabled);
  }

  virtual std::string SerializedObjectName() const { return "Scheme"; }
  static uint32_t SerializedVersion() { return 1; }

  friend std::ostream &operator<<(
      std::ostream &out, const LPPublicKeyEncryptionScheme<Element> &s) {
    out << typeid(s).name() << ":";
    out << " ParameterGeneration "
        << (s.m_algorithmParamsGen == 0
                ? "none"
                : typeid(*s.m_algorithmParamsGen).name());
    out << ", Encryption "
        << (s.m_algorithmEncryption == 0
                ? "none"
                : typeid(*s.m_algorithmEncryption).name());
    out << ", PRE "
        << (s.m_algorithmPRE == 0 ? "none" : typeid(*s.m_algorithmPRE).name());
    out << ", Multiparty "
        << (s.m_algorithmMultiparty == 0
                ? "none"
                : typeid(*s.m_algorithmMultiparty).name());
    out << ", SHE "
        << (s.m_algorithmSHE == 0 ? "none" : typeid(*s.m_algorithmSHE).name());
    out << ", LeveledSHE "
        << (s.m_algorithmLeveledSHE == 0
                ? "none"
                : typeid(*s.m_algorithmLeveledSHE).name());
    return out;
  }

 protected:
  std::shared_ptr<LPParameterGenerationAlgorithm<Element>> m_algorithmParamsGen;
  std::shared_ptr<LPEncryptionAlgorithm<Element>> m_algorithmEncryption;
  std::shared_ptr<LPPREAlgorithm<Element>> m_algorithmPRE;
  std::shared_ptr<LPMultipartyAlgorithm<Element>> m_algorithmMultiparty;
  std::shared_ptr<LPSHEAlgorithm<Element>> m_algorithmSHE;
  std::shared_ptr<LPLeveledSHEAlgorithm<Element>> m_algorithmLeveledSHE;
};

}  // namespace lbcrypto

#endif
