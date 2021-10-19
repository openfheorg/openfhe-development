// @file poly.h Represents integer lattice elements
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

#ifndef LBCRYPTO_LATTICE_POLY_H
#define LBCRYPTO_LATTICE_POLY_H

#include <functional>
#include <string>
#include <utility>
#include <vector>
using std::function;
#include <memory>
using std::shared_ptr;

#include "encoding/encodingparams.h"
#include "lattice/backend.h"
#include "lattice/elemparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "lattice/ilparams.h"
#include "math/backend.h"
#include "math/distrgen.h"
#include "math/nbtheory.h"
#include "math/transfrm.h"
#include "utils/inttypes.h"
#include "utils/memory.h"

namespace lbcrypto {

/**
 * @class PolyImpl
 * @file poly.h
 * @brief Ideal lattice using a vector representation
 */
template <typename VecType>
class PolyImpl : public ILElement<PolyImpl<VecType>, VecType> {
 public:
  using Integer = typename VecType::Integer;
  using Params = ILParamsImpl<Integer>;

  typedef VecType Vector;
  typedef PolyImpl<VecType> PolyType;
  typedef DiscreteGaussianGeneratorImpl<VecType> DggType;
  typedef DiscreteUniformGeneratorImpl<VecType> DugType;
  typedef TernaryUniformGeneratorImpl<VecType> TugType;
  typedef BinaryUniformGeneratorImpl<VecType> BugType;
  typedef PolyImpl<NativeVector> PolyNative;
  typedef PolyImpl<VecType> PolyLargeType;

  /**
   * @brief Return the element name.
   * @return This method returns "PolyImpl".
   */
  static const std::string GetElementName() { return "PolyImpl"; }

  /**
   * @brief Default constructor
   */
  PolyImpl();

  /**
   * @brief Construct given parameters and format
   * @param params - element parameters
   * @param format - Format::EVALUATION or COEFFICIENT
   * @param initializeElementToZero - if true, allocates  an empty vector set to
   * all 0s
   */
  PolyImpl(const shared_ptr<Params> params, Format format = Format::EVALUATION,
           bool initializeElementToZero = false);

  PolyImpl(const shared_ptr<ILDCRTParams<Integer>> params,
           Format format = Format::EVALUATION,
           bool initializeElementToZero = false);

  /**
   * @brief Construct given parameters and format
   * @param initializeElementToMax - if true, initializes entries in the vector
   * to the maximum value
   * @param params - element parameters
   * @param format - Format::EVALUATION or COEFFICIENT
   */
  PolyImpl(bool initializeElementToMax, const shared_ptr<Params> params,
           Format format);

  /**
   * @brief Construct with a vector from a given generator
   *
   * @param &dgg the input discrete Gaussian Generator.
   * @param &params the input params.
   * @param format - Format::EVALUATION or COEFFICIENT
   */
  PolyImpl(const DggType &dgg, const shared_ptr<Params> params,
           Format format = Format::EVALUATION);

  /**
   * @brief Construct with a vector from a given generator
   *
   * @param &bug the input Binary Uniform Generator.
   * @param &params the input params.
   * @param format - Format::EVALUATION or COEFFICIENT
   */
  PolyImpl(const BugType &bug, const shared_ptr<Params> params,
           Format format = Format::EVALUATION);

  /**
   * @brief Construct with a vector from a given generator
   *
   * @param &tug the input Ternary Uniform Generator.
   * @param &params the input params.
   * @param format - Format::EVALUATION or COEFFICIENT
   * @param h - Hamming weight for sparse ternary distribution (by default, when
   * h = 0, the distribution is NOT sparse)
   */
  PolyImpl(const TugType &tug, const shared_ptr<Params> params,
           Format format = Format::EVALUATION, uint32_t h = 0);

  /**
   * @brief Construct with a vector from a given generator
   *
   * @param &dug the input discrete Uniform Generator.
   * @param &params the input params.
   * @param format - Format::EVALUATION or COEFFICIENT
   */
  PolyImpl(DugType &dug, const shared_ptr<Params> params,
           Format format = Format::EVALUATION);

  /**
   * @brief Create lambda that allocates a zeroed element for the case when it
   * is called from a templated class
   * @param params the params to use.
   * @param format - Format::EVALUATION or COEFFICIENT
   */
  inline static function<PolyType()> Allocator(const shared_ptr<Params> params,
                                               Format format) {
    return [=]() { return PolyType(params, format, true); };
  }

  /**
   * @brief Allocator for discrete uniform distribution.
   *
   * @param params ILParams instance that is is passed.
   * @param resultFormat resultFormat for the polynomials generated.
   * @param stddev standard deviation for the discrete gaussian generator.
   * @return the resulting vector.
   */
  inline static function<PolyType()> MakeDiscreteGaussianCoefficientAllocator(
      shared_ptr<Params> params, Format resultFormat, double stddev) {
    return [=]() {
      DiscreteGaussianGeneratorImpl<VecType> dgg(stddev);
      PolyType ilvec(dgg, params, Format::COEFFICIENT);
      ilvec.SetFormat(resultFormat);
      return ilvec;
    };
  }

  /**
   * @brief Allocator for discrete uniform distribution.
   *
   * @param params ILParams instance that is is passed.
   * @param format format for the polynomials generated.
   * @return the resulting vector.
   */
  inline static function<PolyType()> MakeDiscreteUniformAllocator(
      shared_ptr<Params> params, Format format) {
    return [=]() {
      DiscreteUniformGeneratorImpl<VecType> dug;
      dug.SetModulus(params->GetModulus());
      return PolyType(dug, params, format);
    };
  }

  /**
   * @brief Copy constructor.
   *
   * @param &element the copied element.
   * @param parms ILParams instance that is is passed.
   */
  PolyImpl(const PolyType &element, shared_ptr<Params> parms = 0);

  /**
   * @brief Copy constructor from a Poly of native integers.
   *
   * @param &element the copied element.
   * @param &format sets the format for the new Poly object
   */
  PolyImpl(const PolyNative &element, Format format);

  /**
   * @brief Move constructor.
   *
   * @param &&element the copied element.
   * @param parms ILParams instance that is is passed.
   */
  PolyImpl(PolyType &&element, shared_ptr<Params> parms = 0);

  /**
   * @brief Clone the object by making a copy of it and returning the copy
   * @return new Element
   */
  PolyType Clone() const { return PolyImpl(*this); }

  /**
   * @brief Clone the object, but have it contain nothing
   * @return new Element
   */
  PolyType CloneEmpty() const { return PolyImpl(); }

  /**
   * @brief Clone method that creates a new PolyImpl and clones only the params.
   *  The tower values are empty. The tower values can be filled by another
   * process/function or initializer list.
   * @return new Element
   */
  PolyType CloneParametersOnly() const;

  /**
   * @brief Clone method with noise.
   * Creates a new PolyImpl and clones the params. The tower values will be
   * filled up with noise based on the discrete gaussian.
   *
   * @param &dgg the input discrete Gaussian generator. The dgg will be the seed
   * to populate the towers of the PolyImpl with random numbers.
   * @return new Element
   */
  PolyType CloneWithNoise(const DiscreteGaussianGeneratorImpl<VecType> &dgg,
                          Format format) const;

  /**
   * Destructor
   */
  ~PolyImpl();

  /**
   * @brief Assignment Operator.
   *
   * @param &rhs the PolyImpl to be copied.
   * @return the resulting PolyImpl.
   */
  const PolyType &operator=(const PolyType &rhs);

  /**
   * @brief Move Assignment.
   *
   * @param &rhs the PolyImpl to be copied.
   * @return the resulting PolyImpl.
   */
  const PolyType &operator=(PolyType &&rhs);

  /**
   * @brief Initalizer list
   *
   * @param &rhs the list to set the PolyImpl to.
   * @return the resulting PolyImpl.
   */
  const PolyType &operator=(std::initializer_list<uint64_t> rhs);

  /**
   * @brief Creates a Poly from a vector of signed integers (used for trapdoor
   * sampling)
   *
   * @param &rhs the vector to set the PolyImpl to.
   * @return the resulting PolyImpl.
   */
  const PolyType &operator=(std::vector<int64_t> rhs);

  /**
   * @brief Creates a Poly from a vector of signed integers (used for trapdoor
   * sampling)
   *
   * @param &rhs the vector to set the PolyImpl to.
   * @return the resulting PolyImpl.
   */
  const PolyType &operator=(std::vector<int32_t> rhs);

  /**
   * @brief Initalizer list
   *
   * @param &rhs the list to set the PolyImpl to.
   * @return the resulting PolyImpl.
   */
  const PolyType &operator=(std::initializer_list<std::string> rhs);

  /**
   * @brief Assignment Operator. The usint val will be set at index zero and all
   * other indices will be set to zero.
   *
   * @param val is the usint to assign to index zero.
   * @return the resulting vector.
   */
  const PolyType &operator=(uint64_t val);

  // GETTERS
  /**
   * @brief Get method to get ILParams for the current vector.
   *
   * @return the ring element params.
   */
  const shared_ptr<Params> GetParams() const { return m_params; }

  /**
   * @brief Get format of the element
   *
   * @return COEFFICIENT or Format::EVALUATION
   */
  Format GetFormat() const;

  /**
   * @brief Get the length of the element.
   *
   * @return length
   */
  usint GetLength() const;

  /**
   * @brief Get modulus of the element
   *
   * @return the modulus.
   */
  const Integer &GetModulus() const { return m_params->GetModulus(); }

  /**
   * @brief Get the values for the element
   *
   * @return the vector.
   */
  const VecType &GetValues() const;

  /**
   * @brief Get the cyclotomic order
   *
   * @return order
   */
  usint GetCyclotomicOrder() const { return m_params->GetCyclotomicOrder(); }

  /**
   * @brief Get the ring dimension.
   *
   * @return the ring dimension
   */
  usint GetRingDimension() const { return m_params->GetRingDimension(); }

  /**
   * @brief Get the root of unity.
   *
   * @return the root of unity.
   */
  const Integer &GetRootOfUnity() const { return m_params->GetRootOfUnity(); }

  /**
   * @brief Get value of element at index i.
   *
   * @return value at index i.
   */
  Integer &at(usint i);
  const Integer &at(usint i) const;

  /**
   * @brief Get value of element at index i.
   *
   * @return value at index i.
   */
  Integer &operator[](usint i);
  const Integer &operator[](usint i) const;

  // SETTERS
  /**
   *  @brief Set VecType value to val
   *
   * @param index is the index at which the value is to be set.
   * @param val is the value to be set.
   */
  // SCALAR OPERATIONS

  /**
   * @brief Set method of the values.
   *
   * @param values is the set of values of the vector.
   * @param format is the format, either COEFFICIENT or EVALUATION.
   */
  void SetValues(const VecType &values, Format format);

  /**
   * @brief Set method of the values.
   *
   * @param values is the set of values of the vector.
   * @param format is the format, either COEFFICIENT or EVALUATION.
   */
  void SetValues(VecType &&values, Format format);

  /**
   * @brief Sets all values of element to zero.
   */
  void SetValuesToZero();

  /**
   * @brief Sets all values of element to maximum.
   */
  void SetValuesToMax();

  /**
   * @brief Scalar addition - add an element to the first index only.
   * This operation is only allowed in COEFFICIENT format.
   *
   * @param &element is the element to add entry-wise.
   * @return is the return of the addition operation.
   */
  PolyImpl Plus(const Integer &element) const;

  /**
   * @brief Scalar subtraction - subtract an element to all entries.
   *
   * @param &element is the element to subtract entry-wise.
   * @return is the return value of the minus operation.
   */
  PolyImpl Minus(const Integer &element) const;

  /**
   * @brief Scalar multiplication - multiply all entries.
   *
   * @param &element is the element to multiply entry-wise.
   * @return is the return value of the times operation.
   */
  PolyImpl Times(const Integer &element) const;

#if NATIVEINT != 64
  /**
   * @brief Scalar multiplication - by a signed integer.
   *
   * @param &element is the element to multiply entry-wise.
   * @return is the return value of the times operation.
   */
  PolyImpl Times(int64_t element) const {
    return Times((bigintnat::NativeInteger::SignedNativeInt)element);
  }
#endif

  /**
   * @brief Scalar multiplication - by a signed integer.
   *
   * @param &element is the element to multiply entry-wise.
   * @return is the return value of the times operation.
   */
  PolyImpl Times(bigintnat::NativeInteger::SignedNativeInt element) const;

  // VECTOR OPERATIONS

  /**
   * @brief Unary minus on a lattice element.
   * @return negation of the lattice element.
   */
  PolyImpl operator-() const {
    PolyImpl all0(this->GetParams(), this->GetFormat(), true);
    return all0 - *this;
  }
  /**
   * @brief Performs an addition operation and returns the result.
   *
   * @param &element is the element to add with.
   * @return is the result of the addition.
   */
  PolyImpl Plus(const PolyImpl &element) const;

  /**
   * @brief Performs a subtraction operation and returns the result.
   *
   * @param &element is the element to subtract with.
   * @return is the result of the subtraction.
   */
  PolyImpl Minus(const PolyImpl &element) const;

  /**
   * @brief Performs a multiplication operation and returns the result.
   *
   * @param &element is the element to multiply with.
   * @return is the result of the multiplication.
   */
  PolyImpl Times(const PolyImpl &element) const;

  /**
   * @brief Performs += operation with a Integer and returns the result.
   *
   * @param &element is the element to add
   * @return is the result of the addition.
   */
  const PolyImpl &operator+=(const Integer &element) {
    return *this = this->Plus(element);
  }

  /**
   * @brief Performs -= operation with a Integer and returns the result.
   *
   * @param &element is the element to subtract
   * @return is the result of the subtraction.
   */
  const PolyImpl &operator-=(const Integer &element) {
    m_values->ModSubEq(element);
    return *this;
  }

  /**
   * @brief Performs *= operation with a Integer and returns the result.
   *
   * @param &element is the element to multiply by
   * @return is the result of the multiplication.
   */
  const PolyImpl &operator*=(const Integer &element) {
    m_values->ModMulEq(element);
    return *this;
  }

  /**
   * @brief Performs an addition operation and returns the result.
   *
   * @param &element is the element to add
   * @return is the result of the addition.
   */
  const PolyImpl &operator+=(const PolyImpl &element);

  /**
   * @brief Performs an subtraction operation and returns the result.
   *
   * @param &element is the element to subtract
   * @return is the result of the subtract.
   */
  const PolyImpl &operator-=(const PolyImpl &element);

  /**
   * @brief Performs an multiplication operation and returns the result.
   *
   * @param &element is the element to multiply by
   * @return is the result of the multiplication.
   */
  const PolyImpl &operator*=(const PolyImpl &element);

  /**
   * @brief Equality operator compares this element to the input element.
   *
   * @param &rhs is the specified PolyImpl to be compared with this element.
   * @return true if this PolyImpl represents the same values as the specified
   * element, false otherwise
   */
  inline bool operator==(const PolyImpl &rhs) const {
    if (this->GetFormat() != rhs.GetFormat()) {
      return false;
    }
    if (m_params->GetRootOfUnity() != rhs.GetRootOfUnity()) {
      return false;
    }
    if (this->GetValues() != rhs.GetValues()) {
      return false;
    }
    return true;
  }

  /**
   * @brief Scalar multiplication followed by division and rounding operation -
   * operation on all entries.
   *
   * @param &p is the integer muliplicand.
   * @param &q is the integer divisor.
   * @return is the return value of the multiply, divide and followed by
   * rounding operation.
   */
  PolyImpl MultiplyAndRound(const Integer &p, const Integer &q) const;

  /**
   * @brief Scalar division followed by rounding operation - operation on all
   * entries.
   *
   * @param &q is the element to divide entry-wise.
   * @return is the return value of the divide, followed by rounding operation.
   */
  PolyImpl DivideAndRound(const Integer &q) const;

  /**
   * @brief Performs a negation operation and returns the result.
   *
   * @return is the result of the negation.
   */
  PolyImpl Negate() const;

  // OTHER METHODS

  /**
   * @brief Adds one to every entry of the PolyImpl.
   */
  void AddILElementOne();

  /**
   * @brief Performs an automorphism transform operation and returns the result.
   *
   * @param &i is the element to perform the automorphism transform with.
   * @return is the result of the automorphism transform.
   */
  PolyImpl AutomorphismTransform(const usint &k) const;

  /**
   * @brief Performs an automorphism transform operation using precomputed bit
   * reversal indices.
   *
   * @param &i is the element to perform the automorphism transform with.
   * @param &map a vector with precomputed indices
   * @return is the result of the automorphism transform.
   */
  PolyImpl AutomorphismTransform(usint i, const std::vector<usint> &map) const;

  /**
   * @brief Interpolates based on the Chinese Remainder Transform Interpolation.
   * Does nothing for PolyImpl. Needed to support the linear CRT interpolation
   * in DCRTPoly.
   *
   * @return the original ring element.
   */
  PolyImpl CRTInterpolate() const { return *this; }

  PolyNative DecryptionCRTInterpolate(PlaintextModulus ptm) const;

  PolyNative ToNativePoly() const;

  PolyNative ToNativePolyCloneParams() const;

  /**
   * @brief Transpose the ring element using the automorphism operation
   *
   * @return is the result of the transposition.
   */
  PolyImpl Transpose() const;

  /**
   * @brief Performs a multiplicative inverse operation and returns the result.
   *
   * @return is the result of the multiplicative inverse.
   */
  PolyImpl MultiplicativeInverse() const;

  /**
   * @brief Perform a modulus by 2 operation.  Returns the least significant
   * bit.
   *
   * @return is the return value of the modulus by 2, also the least significant
   * bit.
   */
  PolyImpl ModByTwo() const;

  /**
   * @brief Modulus - perform a modulus operation. Does proper mapping of
   * [-modulus/2, modulus/2) to [0, modulus)
   *
   * @param modulus is the modulus to use.
   * @return is the return value of the modulus.
   */
  PolyImpl Mod(const Integer &modulus) const;

  /**
   * @brief Switch modulus and adjust the values
   *
   * @param &modulus is the modulus to be set.
   * @param &rootOfUnity is the corresponding root of unity for the modulus
   * @param &modulusArb is the modulus used for arbitrary cyclotomics CRT
   * @param &rootOfUnityArb is the corresponding root of unity for the modulus
   * ASSUMPTION: This method assumes that the caller provides the correct
   * rootOfUnity for the modulus.
   */
  void SwitchModulus(const Integer &modulus, const Integer &rootOfUnity,
                     const Integer &modulusArb = Integer(0),
                     const Integer &rootOfUnityArb = Integer(0));

  /**
   * @brief Convert from Coefficient to Format::EVALUATION or vice versa; calls
   * FFT and inverse FFT.
   */
  void SwitchFormat();

  /**
   * @brief Make the element values sparse. Sets every index not equal to zero
   * mod the wFactor to zero.
   *
   * @param &wFactor ratio between the original ring dimension and the new ring
   * dimension.
   */
  void MakeSparse(const uint32_t &wFactor);

  /**
   * @brief Returns true if the vector is empty/ m_values==nullptr
   */
  bool IsEmpty() const;

  /**
   * @brief Determines if inverse exists
   *
   * @return is the Boolean representation of the existence of multiplicative
   * inverse.
   */
  bool InverseExists() const;

  /**
   * @brief Returns the infinity norm, basically the largest value in the ring
   * element.
   *
   * @return is the largest value in the ring element.
   */
  double Norm() const;

  /**
   * @brief Rounds the polynomial to an input integer.
   *
   * @param x is integer to round to.
   * @return is the result of the rounding operation.
   */
  PolyImpl Round(const Integer &x) const;

  /**
   * @brief Write the element as \f$ \sum\limits{i=0}^{\lfloor {\log q/base}
   * \rfloor} {(base^i u_i)} \f$ and return the vector of \f$ \left\{u_0,
   * u_1,...,u_{\lfloor {\log q/base} \rfloor} \right\} \in R_{{base}^{\lceil
   * {\log q/base} \rceil}} \f$; This is used as a subroutine in the
   * relinearization procedure.
   *
   * @param baseBits is the number of bits in the base, i.e., \f$ base =
   * 2^{baseBits} \f$.
   * @return is the pointer where the base decomposition vector is stored
   */
  std::vector<PolyImpl> BaseDecompose(usint baseBits,
                                      bool evalModeAnswer = true) const;

  /**
   * @brief Generate a vector of PolyImpl's as \f$ \left\{x, {base}*x,
   * {base}^2*x, ..., {base}^{\lfloor {\log q/{base}} \rfloor} \right\}*x \f$,
   * where \f$ x \f$ is the current PolyImpl object;
   * used as a subroutine in the relinearization procedure to get powers of a
   * certain "base" for the secret key element
   *
   * @param baseBits is the number of bits in the base, i.e., \f$ base =
   * 2^{baseBits} \f$.
   * @return is the pointer where the base decomposition vector is stored
   */
  std::vector<PolyImpl> PowersOfBase(usint baseBits) const;

  /**
   * @brief Shift entries in the vector left a specific number of entries.
   *
   * @param n the number of entries to shift left.
   * @return is the resulting vector from shifting left.
   */
  PolyImpl ShiftLeft(unsigned int n) const;

  /**
   * @brief Shift entries in the vector right a specific number of entries.
   *
   * @param n the number of entries to shift right.
   * @return is the resulting vector from shifting right.
   */
  PolyImpl ShiftRight(unsigned int n) const;

  /**
   * @brief ostream operator
   * @param os the input preceding output stream
   * @param vec the element to add to the output stream.
   * @return a resulting concatenated output stream
   */
  friend inline std::ostream &operator<<(std::ostream &os,
                                         const PolyImpl &vec) {
    os << (vec.m_format == Format::EVALUATION ? "EVAL: " : "COEF: ")
       << vec.GetValues();
    return os;
  }

  /**
   * @brief Element-element addition operator.
   * @param a first element to add.
   * @param b second element to add.
   * @return the result of the addition operation.
   */
  friend inline PolyImpl operator+(const PolyImpl &a, const PolyImpl &b) {
    return a.Plus(b);
  }

  /**
   * @brief Element-integer addition operator.
   * @param a first element to add.
   * @param b integer to add.
   * @return the result of the addition operation.
   */
  friend inline PolyImpl operator+(const PolyImpl &a, const Integer &b) {
    return a.Plus(b);
  }

  /**
   * @brief Integer-element addition operator.
   * @param a integer to add.
   * @param b element to add.
   * @return the result of the addition operation.
   */
  friend inline PolyImpl operator+(const Integer &a, const PolyImpl &b) {
    return b.Plus(a);
  }

  /**
   * @brief Element-element subtraction operator.
   * @param a element to subtract from.
   * @param b element to subtract.
   * @return the result of the subtraction operation.
   */
  friend inline PolyImpl operator-(const PolyImpl &a, const PolyImpl &b) {
    return a.Minus(b);
  }

  /**
   * @brief Element-integer subtraction operator.
   * @param a element to subtract from.
   * @param b integer to subtract.
   * @return the result of the subtraction operation.
   */
  friend inline PolyImpl operator-(const PolyImpl &a, const Integer &b) {
    return a.Minus(b);
  }

  /**
   * @brief Element-element multiplication operator.
   * @param a element to multiply.
   * @param b element to multiply.
   * @return the result of the multiplication operation.
   */
  friend inline PolyImpl operator*(const PolyImpl &a, const PolyImpl &b) {
    return a.Times(b);
  }

  /**
   * @brief Element-integer multiplication operator.
   * @param a element to multiply.
   * @param b integer to multiply.
   * @return the result of the multiplication operation.
   */
  friend inline PolyImpl operator*(const PolyImpl &a, const Integer &b) {
    return a.Times(b);
  }

  /**
   * @brief Integer-element multiplication operator.
   * @param a integer to multiply.
   * @param b element to multiply.
   * @return the result of the multiplication operation.
   */
  friend inline PolyImpl operator*(const Integer &a, const PolyImpl &b) {
    return b.Times(a);
  }

  /**
   * @brief Element-signed-integer multiplication operator.
   * @param a element to multiply.
   * @param b integer to multiply.
   * @return the result of the multiplication operation.
   */
  friend inline PolyImpl operator*(const PolyImpl &a, int64_t b) {
    return a.Times((bigintnat::NativeInteger::SignedNativeInt)b);
  }

  /**
   * @brief signed-integer-element multiplication operator.
   * @param a integer to multiply.
   * @param b element to multiply.
   * @return the result of the multiplication operation.
   */
  friend inline PolyImpl operator*(int64_t a, const PolyImpl &b) {
    return b.Times((bigintnat::NativeInteger::SignedNativeInt)a);
  }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("v", m_values));
    ar(::cereal::make_nvp("f", m_format));
    ar(::cereal::make_nvp("p", m_params));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::make_nvp("v", m_values));
    ar(::cereal::make_nvp("f", m_format));
    ar(::cereal::make_nvp("p", m_params));
  }

  std::string SerializedObjectName() const { return "Poly"; }
  static uint32_t SerializedVersion() { return 1; }

 private:
  // stores either coefficient or Format::EVALUATION representation
  unique_ptr<VecType> m_values;

  // 1 for coefficient and 0 for Format::EVALUATION format
  Format m_format;

  // parameters for ideal lattices
  shared_ptr<Params> m_params;

  void ArbitrarySwitchFormat();
};

template <>
inline PolyImpl<NativeVector> PolyImpl<NativeVector>::DecryptionCRTInterpolate(
    PlaintextModulus ptm) const {
  return this->Mod(ptm);
}

// biginteger version
template <>
inline PolyImpl<NativeVector> PolyImpl<BigVector>::ToNativePolyCloneParams()
    const {
  PolyImpl<NativeVector> interp(
      std::make_shared<ILParamsImpl<NativeInteger>>(
          this->GetCyclotomicOrder(), this->GetModulus().ConvertToInt(),
          this->GetRootOfUnity().ConvertToInt()),
      this->GetFormat(), true);

  for (usint i = 0; i < this->GetLength(); i++) {
    interp[i] = (*this)[i].ConvertToInt();
  }

  return interp;
}

// native poly version
template <>
inline PolyImpl<NativeVector> PolyImpl<NativeVector>::ToNativePolyCloneParams()
    const {
  return *this;
}

}  // namespace lbcrypto

#endif
