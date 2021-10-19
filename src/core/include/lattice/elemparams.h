// @file elemparams.h base class for parameters for a lattice element
// @author TPOC: contact@palisade-crypto.org
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

#ifndef LBCRYPTO_LATTICE_ELEMPARAMS_H
#define LBCRYPTO_LATTICE_ELEMPARAMS_H

#include <iostream>
#include <string>
#include <utility>

#include "math/backend.h"
#include "math/nbtheory.h"
#include "utils/inttypes.h"
#include "utils/serializable.h"

namespace lbcrypto {

/**
 * @class ElemParams
 * @file elemparams.h
 * @brief Wrapper class to hold the parameters for Element types and their
 * inheritors.
 */
template <typename IntegerType>
class ElemParams : public Serializable {
 public:
  /**
   * @brief Simple constructor method that takes as input root of unity, big
   * root of unity, cyclotomic order and the ciphertext modulus and big
   * ciphertext Modulus.  This is used for bit-packing operations.
   * @param order the cyclotomic order wrapped by the parameter set.
   * @param ctModulus the ciphertext modulus wrapped by the parameter set.
   * @param rUnity the root of unity.
   * @param bigCtModulus the big ciphertext modulus used for bit packing
   * operations.
   * @param bigRUnity the big root of unity used for bit packing operations.
   */
  ElemParams(usint order, const IntegerType& ctModulus,
             const IntegerType& rUnity = IntegerType(0),
             const IntegerType& bigCtModulus = IntegerType(0),
             const IntegerType& bigRUnity = IntegerType(0)) {
    cyclotomicOrder = order;
    ringDimension = GetTotient(order);
    isPowerOfTwo = ringDimension == cyclotomicOrder / 2;
    ciphertextModulus = ctModulus;
    rootOfUnity = rUnity;
    bigCiphertextModulus = bigCtModulus;
    bigRootOfUnity = bigRUnity;
  }

  /**
   * @brief Copy constructor using assignment to copy wrapped elements.
   * @param rhs the input ElemParams copied.
   * @return the resulting parameter set with parameters copied.
   */
  ElemParams(const ElemParams& rhs) {
    cyclotomicOrder = rhs.cyclotomicOrder;
    ringDimension = rhs.ringDimension;
    isPowerOfTwo = rhs.isPowerOfTwo;
    ciphertextModulus = rhs.ciphertextModulus;
    rootOfUnity = rhs.rootOfUnity;
    bigCiphertextModulus = rhs.bigCiphertextModulus;
    bigRootOfUnity = rhs.bigRootOfUnity;
  }

  /**
   * @brief Copy constructor using move semnantics to copy wrapped elements.
   * @param rhs the input ElemParams copied.
   * @return the resulting copy of the parameter set.
   */
  ElemParams(const ElemParams&& rhs) {
    cyclotomicOrder = rhs.cyclotomicOrder;
    ringDimension = rhs.ringDimension;
    isPowerOfTwo = rhs.isPowerOfTwo;
    ciphertextModulus = std::move(rhs.ciphertextModulus);
    rootOfUnity = std::move(rhs.rootOfUnity);
    bigCiphertextModulus = std::move(rhs.bigCiphertextModulus);
    bigRootOfUnity = std::move(rhs.bigRootOfUnity);
  }

  /**
   * @brief Assignment operator using assignment operations of wrapped elements.
   * @param rhs the ElemParams instance to copy.
   */
  const ElemParams& operator=(const ElemParams& rhs) {
    cyclotomicOrder = rhs.cyclotomicOrder;
    ringDimension = rhs.ringDimension;
    isPowerOfTwo = rhs.isPowerOfTwo;
    ciphertextModulus = rhs.ciphertextModulus;
    rootOfUnity = rhs.rootOfUnity;
    bigCiphertextModulus = rhs.bigCiphertextModulus;
    bigRootOfUnity = rhs.bigRootOfUnity;
    return *this;
  }

  /**
   * @brief Simple destructor method.
   * @return
   */
  virtual ~ElemParams() {}

  /**
   * @brief Simple getter method for cyclotomic order.
   * @return The cyclotomic order.
   */
  usint GetCyclotomicOrder() const { return cyclotomicOrder; }

  /**
   * @brief Simple ring dimension getter method.  The ring dimension is the
   * evaluation of the totient function of the cyclotomic order.
   * @return the ring dimension.
   */
  usint GetRingDimension() const { return ringDimension; }

  /**
   * @brief Returns True if the cyclotomic order or ring dimension is a power
   * of 2.
   * @return True if the cyclotomic order or ring dimension is a power of 2.
   * False otherwise.
   */
  bool OrderIsPowerOfTwo() const { return isPowerOfTwo; }

  /**
   * @brief Simple getter method for the ciphertext modulus, not the big
   * ciphertext modulus.
   * @return The ciphertext modulus, not the big ciphertext modulus.
   */
  const IntegerType& GetModulus() const { return ciphertextModulus; }

  /**
   * @brief Simpler getter method for the big ciphertext modulus.
   * This is not relevant for all applications.
   * @return The big ciphertext modulus.
   */
  const IntegerType& GetBigModulus() const { return bigCiphertextModulus; }

  /**
   * @brief Simple getter method for the root of unity, not the big root of
   * unity.
   * @return The root of unity, not the big root of unity.
   */
  const IntegerType& GetRootOfUnity() const { return rootOfUnity; }

  /**
   * @brief Simple getter method for the big root of unity.
   * @return The the big root of unity.
   */
  const IntegerType& GetBigRootOfUnity() const { return bigRootOfUnity; }

  /**
   * @brief Output strem operator.
   * @param out the preceding output stream.
   * @param item what to add to the output stream.
   * @return the appended output stream.
   */
  friend std::ostream& operator<<(std::ostream& out, const ElemParams& item) {
    return item.doprint(out);
  }

  /**
   * @brief Equality operator that tests the equality of all wrapped values.
   * @param other the other ElemenParams to compare to.
   * @return True if all elements are equal, and False otherwise.
   */
  virtual bool operator==(const ElemParams<IntegerType>& other) const {
    return cyclotomicOrder == other.cyclotomicOrder &&
           ringDimension == other.ringDimension &&
           ciphertextModulus == other.ciphertextModulus &&
           rootOfUnity == other.rootOfUnity &&
           bigCiphertextModulus == other.bigCiphertextModulus &&
           bigRootOfUnity == other.bigRootOfUnity;
  }

  /**
   * @brief Inequality operator that tests the equality of all wrapped values.
   * @param other the other ElemenParams to compare to.
   * @return False if all elements are equal, and True otherwise.
   */
  bool operator!=(const ElemParams<IntegerType>& other) const {
    return !(*this == other);
  }

  template <class Archive>
  void save(Archive& ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("co", cyclotomicOrder));
    ar(::cereal::make_nvp("rd", ringDimension));
    ar(::cereal::make_nvp("2n", isPowerOfTwo));
    ar(::cereal::make_nvp("cm", ciphertextModulus));
    ar(::cereal::make_nvp("ru", rootOfUnity));
    ar(::cereal::make_nvp("bm", bigCiphertextModulus));
    ar(::cereal::make_nvp("br", bigRootOfUnity));
  }

  template <class Archive>
  void load(Archive& ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::make_nvp("co", cyclotomicOrder));
    ar(::cereal::make_nvp("rd", ringDimension));
    ar(::cereal::make_nvp("2n", isPowerOfTwo));
    ar(::cereal::make_nvp("cm", ciphertextModulus));
    ar(::cereal::make_nvp("ru", rootOfUnity));
    ar(::cereal::make_nvp("bm", bigCiphertextModulus));
    ar(::cereal::make_nvp("br", bigRootOfUnity));
  }

  std::string SerializedObjectName() const { return "ElemParams"; }
  static uint32_t SerializedVersion() { return 1; }

 protected:
  usint cyclotomicOrder;
  usint ringDimension;  // True iff the Ring Dimension is a power of 2.

  bool isPowerOfTwo;
  IntegerType ciphertextModulus;
  IntegerType rootOfUnity;
  IntegerType bigCiphertextModulus;  // Used for only some applications.
  IntegerType bigRootOfUnity;        // Used for only some applications.

  /**
   * @brief Pretty print operator for the ElemParams type.
   * @param out the ElemParams to output
   * @return the resulting output stream.
   */
  virtual std::ostream& doprint(std::ostream& out) const {
    out << "[m=" << cyclotomicOrder << (isPowerOfTwo ? "* " : " ")
        << "n=" << ringDimension << " q=" << ciphertextModulus
        << " ru=" << rootOfUnity << " bigq=" << bigCiphertextModulus
        << " bigru=" << bigRootOfUnity << "]";
    return out;
  }
};

}  // namespace lbcrypto

#endif
