// @file This file contains mubintvecdyn, a <vector> of buintdyn, with
// associated modulus and modulo math operators.
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

#ifndef LBCRYPTO_MATH_BIGINTDYN_MUBINTVECDYN_H
#define LBCRYPTO_MATH_BIGINTDYN_MUBINTVECDYN_H

#include <initializer_list>
#include <iostream>
#include <string>
#include <vector>

#include "math/bigintfxd/mubintvecfxd.h"
#include "utils/inttypes.h"
#include "utils/serializable.h"

/**
 * @namespace bigintdyn
 * The namespace of bigintdyn
 */
namespace bigintdyn {
/**
 * @brief The class for representing vectors of ubint with associated modulo
 * math
 */

template <class ubint_el_t>
class mubintvec
    : public lbcrypto::BigVectorInterface<mubintvec<ubint_el_t>, ubint_el_t>,
      public lbcrypto::Serializable {
 public:
  // CONSTRUCTORS

  /**
   * Basic constructor.
   */
  mubintvec();

  static mubintvec Single(const ubint_el_t &val, const ubint_el_t &modulus) {
    mubintvec vec(1);
    vec.m_data[0] = val;
    vec.SetModulus(modulus);
    return vec;
  }

  /**
   * Basic constructor for specifying the length of the vector.
   *
   * @param length initial size in terms of the number of entries.
   */
  explicit mubintvec(usint length);

  /**
   * Basic constructor for specifying the length and modulus of the vector.
   *
   * @param length initial size in terms of the number of entries.
   * @param modulus usint associated with entries in the vector.
   */
  explicit mubintvec(const usint length, const usint &modulus);

  /**
   * Basic constructor for specifying the length of the vector with modulus
   *
   * @param length initial size in terms of the number of entries.
   * @param modulus ubint associated with entries in the vector.
   */
  explicit mubintvec(const usint length, const ubint_el_t &modulus);

  /**
   * Basic constructor for specifying the length and modulus of the vector.
   *
   * @param length initial size in terms of the number of entries.
   * @param modulus string associated with entries in the vector.
   */
  explicit mubintvec(const usint length, const std::string &modulus);

  /**
   * Copy constructor for copying a vector
   *
   * @param rhs is the mubintvec to be copied.
   */
  explicit mubintvec(const mubintvec &rhs);

  /**
   * Move constructor for moving a vector
   *
   * @param &&rhs is the mubintvec to be moved.
   */
  mubintvec(mubintvec &&rhs);

  /**
   * Basic constructor for specifying the length of the vector with
   * modulus with initializer lists
   *
   * @param length initial size in terms of the number of entries.
   * @param modulus ubint associated with entries in the vector.
   * @param rhs initialier list of strings
   */
  explicit mubintvec(const usint length, const ubint_el_t &modulus,
                     std::initializer_list<std::string> rhs);

  /**
   * Basic constructor for specifying the length of the vector with
   * modulus with initializer lists
   *
   * @param length initial size in terms of the number of entries.
   * @param modulus ubint associated with entries in the vector.
   * @param rhs initialier list of usints
   */
  explicit mubintvec(const usint length, const ubint_el_t &modulus,
                     std::initializer_list<uint64_t> rhs);

  // constructor specifying the mubintvec as a vector of strings and modulus
  explicit mubintvec(const std::vector<std::string> &s,
                     const ubint_el_t &modulus);

  // constructor specifying the mubintvec as a vector of strings and modulus
  explicit mubintvec(const std::vector<std::string> &s,
                     const std::string &modulus);

  /**
   * Destructor.
   */
  virtual ~mubintvec();

  // ASSIGNMENT OPERATORS

  /**
   * Assignment operator
   *
   * @param &rhs is the mubintvec to be assigned from.
   * @return assigned mubintvec ref.
   */
  const mubintvec &operator=(const mubintvec &rhs);

  /**
   * move assignment contructor
   *
   * @param &rhs is the mubintvec to move
   * @return the return value.
   */
  const mubintvec &operator=(mubintvec &&rhs);

  /**
   * Initializer list for mubintvec.
   *
   * @param &&rhs is the list of strings to be assigned to the mubintvec.
   * @return mubintvec object
   * note if  modulus is set then mod(input) is stored
   * note modulus remains unchanged.
   */
  const mubintvec &operator=(std::initializer_list<std::string> rhs);

  /**
   * Initializer list for mubintvec.
   *
   * @param &&rhs is the list of usints to be assigned to the mubintvec.
   * @return mubintvec object
   * note if  modulus is set then mod(input) is stored
   * note modulus remains unchanged.
   */
  const mubintvec &operator=(std::initializer_list<uint64_t> rhs);

  /**
   * @param &&rhs is the usint value to assign to the zeroth entry
   * @return resulting mubintvec
   * note that modulus remains untouched.
   */
  const mubintvec &operator=(uint64_t val) {
    this->m_data[0] = val;
    for (size_t i = 1; i < GetLength(); ++i) {
      this->m_data[i] = 0;
    }
    return *this;
  }

  /**
   * @param &&rhs is the ubint value to assign to the zeroth entry
   * @return resulting mubintvec
   */
  const mubintvec &operator=(const ubint_el_t &val) {
    this->m_data[0] = val;
    for (size_t i = 1; i < this->m_data.size(); ++i) {
      this->m_data[i] = 0;
    }
    return *this;
  }

  size_t GetLength() const { return m_data.size(); }

  // ACCESSORS

  /**
   * Sets/gets a value at an index.
   * This method is slower than operator[] as it checks if index out of range
   *
   * @param index is the index to set a value at.
   */
  ubint_el_t &at(size_t i) {
    if (!this->IndexCheck(i)) {
      PALISADE_THROW(lbcrypto::math_error, "index out of range");
    }
    return this->m_data[i];
  }

  const ubint_el_t &at(size_t i) const {
    if (!this->IndexCheck(i)) {
      PALISADE_THROW(lbcrypto::math_error, "index out of range");
    }
    return this->m_data[i];
  }

  ubint_el_t &operator[](size_t i) { return this->m_data[i]; }

  const ubint_el_t &operator[](size_t i) const { return this->m_data[i]; }

  /**
   * checks the vector modulus state.
   * always returns true
   */
  bool isModulusSet(void) const { return true; }

  /**
   * Sets the vector modulus.
   *
   * @param value is the value to set.
   */
  void SetModulus(const usint &value);

  /**
   * Sets the vector modulus.
   *
   * @param value is the value to set.
   */
  void SetModulus(const ubint_el_t &value);

  /**
   * Sets the vector modulus.
   *
   * @param value is the value to set.
   */
  void SetModulus(const std::string &value);

  /**
   * Sets the vector modulus to the same as another mubintvec
   *
   * @param value is the vector whose modulus to use.
   */
  void SetModulus(const mubintvec &value);

  /**
   * Sets the vector modulus and changes the values to match the new modulus.
   *
   * @param value is the value to set.
   */
  void SwitchModulus(const ubint_el_t &value);

  /**
   * Gets the vector modulus.
   *
   * @return the vector modulus.
   */
  const ubint_el_t &GetModulus() const;

  // MODULUS ARITHMETIC OPERATIONS

  /**
   * Vector modulus operator.
   * Side effect it resets the vector modulus to modulus
   *
   * @param &modulus is the modulus to perform on the current vector entries.
   * @return is the result of the modulus operation on current vector.
   */
  mubintvec Mod(const ubint_el_t &modulus) const;

  /**
   * Vector modulus operator. In-place variant.
   * Side effect it resets the vector modulus to modulus
   *
   * @param &modulus is the modulus to perform on the current vector entries.
   * @return is the result of the modulus operation on current vector.
   */
  const mubintvec &ModEq(const ubint_el_t &modulus);

  /**
   * Scalar-to-vector modulus addition operation.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus addition operation.
   */
  mubintvec ModAdd(const ubint_el_t &b) const;

  /**
   * Scalar-to-vector modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus addition operation.
   */
  const mubintvec &ModAddEq(const ubint_el_t &b);

  /**
   * Scalar modulus addition at a particular index.
   *
   * @param i is the index of the entry to add.
   * @param &b is the scalar to add.
   * @return is the result of the modulus addition operation.
   */
  mubintvec ModAddAtIndex(usint i, const ubint_el_t &b) const;

  /**
   * Scalar modulus addition at a particular index. In-place variant.
   *
   * @param i is the index of the entry to add.
   * @param &b is the scalar to add.
   * @return is the result of the modulus addition operation.
   */
  const mubintvec &ModAddAtIndexEq(usint i, const ubint_el_t &b);

  /**
   * Vector component wise modulus addition.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus addition operation.
   */
  mubintvec ModAdd(const mubintvec &b) const;

  /**
   * Vector component wise modulus addition. In-place variant.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus addition operation.
   */
  const mubintvec &ModAddEq(const mubintvec &b);

  /**
   * Scalar-from-vector modulus subtraction operation.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus subtraction operation.
   */
  mubintvec ModSub(const ubint_el_t &b) const;

  /**
   * Scalar-from-vector modulus subtraction operation. In-place variant.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus subtraction operation.
   */
  const mubintvec &ModSubEq(const ubint_el_t &b);

  /**
   * Vector component wise modulus subtraction.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus subtraction operation.
   */
  mubintvec ModSub(const mubintvec &b) const;

  /**
   * Vector component wise modulus subtraction. In-place variant.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus subtraction operation.
   */
  const mubintvec &ModSubEq(const mubintvec &b);

  /**
   * Scalar-to-vector modulus multiplication operation.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus multiplication operation.
   */
  mubintvec ModMul(const ubint_el_t &b) const;

  /**
   * Scalar-to-vector modulus multiplication operation. In-place variant.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus multiplication operation.
   */
  const mubintvec &ModMulEq(const ubint_el_t &b);

  /**
   * Vector component wise modulus multiplication.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus multiplication
   * operation.
   */
  mubintvec ModMul(const mubintvec &b) const;

  /**
   * Vector component wise modulus multiplication. In-place variant.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus multiplication
   * operation.
   */
  const mubintvec &ModMulEq(const mubintvec &b);

  /**
   * Scalar modulus exponentiation operation.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus exponentiation operation.
   */
  mubintvec ModExp(const ubint_el_t &b) const;

  /**
   * Scalar modulus exponentiation operation. In-place variant.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus exponentiation operation.
   */
  const mubintvec &ModExpEq(const ubint_el_t &b);

  /**
   * Modulus inverse operation.
   *
   * @return is the result of the component wise modulus inverse operation.
   */
  mubintvec ModInverse() const;

  /**
   * Modulus inverse operation. In-place variant.
   *
   * @return is the result of the component wise modulus inverse operation.
   */
  const mubintvec &ModInverseEq();

  /**
   * Modulus 2 operation, also a least significant bit.
   *
   * @return is the result of the component wise modulus 2 operation, also a
   * least significant bit.
   */
  mubintvec ModByTwo() const;

  /**
   * Modulus 2 operation, also a least significant bit. In-place variant.
   *
   * @return is the result of the component wise modulus 2 operation, also a
   * least significant bit.
   */
  const mubintvec &ModByTwoEq();

  /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
  mubintvec MultiplyAndRound(const ubint_el_t &p, const ubint_el_t &q) const;

  /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
  const mubintvec &MultiplyAndRoundEq(const ubint_el_t &p, const ubint_el_t &q);

  /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
  mubintvec DivideAndRound(const ubint_el_t &q) const;

  /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
  const mubintvec &DivideAndRoundEq(const ubint_el_t &q);

  // OTHER FUNCTIONS

  /**
   * Digit vector at a specific index for all entries for a given number base.
   * Warning: only power-of-2 bases are currently supported.
   * Example: for vector (83, 1, 45), index 2 and base 4 we have:
   *
   *                           index:0,1,2,3
   * |83|                           |3,0,1,1|                 |1|
   * |1 | --base 4 decomposition--> |1,0,0,0| --at index 2--> |0|
   * |45|                           |1,3,2,0|                 |2|
   *
   * The return vector is (1,0,2)
   *
   * @param index is the index to return the digit from in all entries.
   * @param base is the base to use for the operation.
   * @return is the digit at a specific index for all entries for a given number
   * base
   */
  mubintvec GetDigitAtIndexForBase(usint index, usint base) const;

  // STRINGS & STREAMS

  /**
   * ostream output << operator.
   *
   * @param os is the std ostream object.
   * @param ptr_obj is mubintvec to be printed.
   * @return is the ostream object.
   */
  friend std::ostream &operator<<(std::ostream &os, const mubintvec &ptr_obj) {
#if 0  // old way
    os << std::endl;
    for (usint i = 0; i < ptr_obj.m_data.size(); i++) {
      os << ptr_obj.m_data[i] << std::endl;
    }
    os << "modulus: " << ptr_obj.m_modulus;
    os << std::endl;
#else
    auto len = ptr_obj.m_data.size();
    os << "[";
    for (usint i = 0; i < len; i++) {
      os << ptr_obj.m_data[i];
      os << ((i == (len - 1)) ? "]" : " ");
    }
    os << " modulus: " << ptr_obj.m_modulus;
#endif
    return os;
  }

  // SERIALIZATION

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("d", m_data));
    ar(::cereal::make_nvp("m", m_modulus));
    ar(::cereal::make_nvp("ms", m_modulus_state));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(lbcrypto::deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::make_nvp("d", m_data));
    ar(::cereal::make_nvp("m", m_modulus));
    ar(::cereal::make_nvp("ms", m_modulus_state));
  }

  std::string SerializedObjectName() const { return "ExpVector"; }

  static uint32_t SerializedVersion() { return 1; }

 private:
  ubint_el_t m_modulus;

  enum State { INITIALIZED, GARBAGE };

  // enum to store the state of the
  State m_modulus_state;

  std::vector<ubint_el_t> m_data;

  bool IndexCheck(size_t length) const {
    if (length > m_data.size()) {
      return false;
    }
    return true;
  }
};
}  // namespace bigintdyn

#endif  // LBCRYPTO_MATH_BIGINTDYN_MUBINTVECDYN_H
