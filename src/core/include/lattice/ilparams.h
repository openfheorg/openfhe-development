// @file ilparams.h Wraps parameters for integer lattice operations.  Inherits
// from ElemParams.
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

#ifndef LBCRYPTO_LATTICE_ILPARAMS_H
#define LBCRYPTO_LATTICE_ILPARAMS_H

#include <string>

#include "lattice/elemparams.h"
#include "math/backend.h"
#include "math/nbtheory.h"
#include "utils/inttypes.h"

namespace lbcrypto {

/**
 * @class ILParamsImpl
 * @file ilparams.h
 * @brief Wrapper class to hold the parameters for integer lattice operations
 * and their inheritors.
 */
template <typename IntType>
class ILParamsImpl : public ElemParams<IntType> {
 public:
  typedef IntType Integer;

  /**
   * Constructor that initializes nothing.
   * All of the private members will be initialized to zero.
   */
  ILParamsImpl() : ElemParams<IntType>(0, 0) {}

  /**
   * @brief Constructor for the case of partially pre-computed parameters.
   *
   * @param &order the order of the ciphertext.
   * @param &modulus the ciphertext modulus.
   * @param &rootOfUnity the root of unity used in the ciphertext.
   * @param bigModulus the big ciphertext modulus.
   * @param bigRootOfUnity the big ciphertext modulus used for bit packing
   * operations.
   * @return
   */
  ILParamsImpl(const usint order, const IntType &modulus,
               const IntType &rootOfUnity, const IntType &bigModulus = 0,
               const IntType &bigRootOfUnity = 0)
      : ElemParams<IntType>(order, modulus, rootOfUnity, bigModulus,
                            bigRootOfUnity) {}

  /**
   * @brief Constructor for the case of partially pre-computed parameters.
   *
   * @param &order the order of the ciphertext.
   * @param &modulus the ciphertext modulus.
   */
  ILParamsImpl(const usint order, const IntType &modulus)
      : ElemParams<IntType>(order, modulus) {
    this->rootOfUnity = RootOfUnity<IntType>(order, modulus);
  }

  /**
   * @brief Copy constructor.
   *
   * @param &rhs the input set of parameters which is copied.
   */
  ILParamsImpl(const ILParamsImpl &rhs) : ElemParams<IntType>(rhs) {}

  /**
   * @brief Assignment Operator.
   *
   * @param &rhs the params to be copied.
   * @return this object
   */
  const ILParamsImpl &operator=(const ILParamsImpl &rhs) {
    ElemParams<IntType>::operator=(rhs);
    return *this;
  }

  /**
   * @brief Move constructor.
   *
   * @param &rhs the input set of parameters which is copied.
   */
  ILParamsImpl(const ILParamsImpl &&rhs) : ElemParams<IntType>(rhs) {}

  /**
   * @brief Standard Destructor method.
   */
  ~ILParamsImpl() {}

  /**
   * @brief Equality operator compares ElemParams (which will be dynamic casted)
   *
   * @param &rhs is the specified Poly to be compared with this Poly.
   * @return True if this Poly represents the same values as the specified
   * DCRTPoly, False otherwise
   */
  bool operator==(const ElemParams<IntType> &rhs) const {
    if (dynamic_cast<const ILParamsImpl<IntType> *>(&rhs) == nullptr)
      return false;

    return ElemParams<IntType>::operator==(rhs);
  }

 private:
  std::ostream &doprint(std::ostream &out) const {
    out << "ILParams ";
    ElemParams<IntType>::doprint(out);
    out << std::endl;
    return out;
  }

 public:
  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::base_class<ElemParams<IntType>>(this));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::base_class<ElemParams<IntType>>(this));
  }

  std::string SerializedObjectName() const { return "ILParms"; }
  static uint32_t SerializedVersion() { return 1; }
};

}  // namespace lbcrypto

#endif
