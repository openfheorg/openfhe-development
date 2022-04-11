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

#ifndef LBCRYPTO_CRYPTO_KEY_EVALKEY_H
#define LBCRYPTO_CRYPTO_KEY_EVALKEY_H

#include "key/key.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

template <typename Element>
class EvalKeyImpl;

template <typename Element>
using EvalKey = std::shared_ptr<EvalKeyImpl<Element>>;

/**
 * @brief Abstract interface for evaluation/proxy keys
 * @tparam Element a ring element.
 */
template <class Element>
class EvalKeyImpl : public Key<Element> {
 public:
  /**
   * Basic constructor for setting crypto params
   *
   * @param &cryptoParams is the reference to cryptoParams
   */

  explicit EvalKeyImpl(CryptoContext<Element> cc = 0) : Key<Element>(cc) {}

  virtual ~EvalKeyImpl() {}

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

  friend bool operator==(const EvalKeyImpl &a, const EvalKeyImpl &b) {
    return a.key_compare(b);
  }

  friend bool operator!=(const EvalKeyImpl &a, EvalKeyImpl &b) {
    return !(a == b);
  }

  virtual bool key_compare(const EvalKeyImpl &other) const { return false; }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::base_class<Key<Element>>(this));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    ar(::cereal::base_class<Key<Element>>(this));
  }
  std::string SerializedObjectName() const { return "EvalKey"; }
};

}  // namespace lbcrypto

#endif
