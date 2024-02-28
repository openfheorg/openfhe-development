//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
  Defines an interface that any DCRT Polynomial implmentation must implement in order to work in OpenFHE.
 */

#ifndef LBCRYPTO_INC_LATTICE_HAL_POLYINTERFACE_H
#define LBCRYPTO_INC_LATTICE_HAL_POLYINTERFACE_H

#include "lattice/ilelement.h"
#include "lattice/hal/default/ilparams.h"

#include "math/math-hal.h"
#include "math/distrgen.h"
#include "math/nbtheory.h"

#include "utils/inttypes.h"
#include "utils/exception.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

template <typename DerivedType, typename VecType, template <typename LVT> typename ContainerType>
class PolyInterface : public ILElement<DerivedType, VecType> {
public:
    using Vector     = VecType;
    using Integer    = typename VecType::Integer;
    using Params     = ILParamsImpl<Integer>;
    using PolyNative = ContainerType<NativeVector>;
    using DggType    = DiscreteGaussianGeneratorImpl<VecType>;
    using DugType    = DiscreteUniformGeneratorImpl<VecType>;
    using TugType    = TernaryUniformGeneratorImpl<VecType>;
    using BugType    = BinaryUniformGeneratorImpl<VecType>;

    /**
   * @brief Get the Derived object, this is apart of the CRTP software design pattern
   * it allows the base class (this one) to implement methods that call the derived
   * objects implementation.
   *
   * @ref Chapter 21.2 "C++ Templates The Complete Guide" by David Vandevoorde and Nicolai M. Josuttis
   * http://www.informit.com/articles/article.asp?p=31473
   *
   * @return DerivedType&
   */
    DerivedType& GetDerived() {
        return static_cast<DerivedType&>(*this);
    }

    const DerivedType& GetDerived() const {
        return static_cast<DerivedType const&>(*this);
    }

    /**
   * @brief Create lambda that allocates a zeroed element for the case when it
   * is called from a templated class
   * @param params the params to use.
   * @param format - EVALUATION or COEFFICIENT
   */
    inline static std::function<DerivedType()> Allocator(const std::shared_ptr<Params>& params, Format format) {
        return [=]() {
            return DerivedType(params, format, true);
        };
    }

    /**
   * @brief Allocator for discrete uniform distribution.
   *
   * @param params Params instance that is is passed.
   * @param resultFormat resultFormat for the polynomials generated.
   * @param stddev standard deviation for the discrete gaussian generator.
   * @return the resulting vector.
   */
    inline static std::function<DerivedType()> MakeDiscreteGaussianCoefficientAllocator(
        const std::shared_ptr<Params>& params, Format resultFormat, double stddev) {
        return [=]() {
            DggType dgg(stddev);
            return DerivedType(dgg, params, resultFormat);
        };
    }

    /**
   * @brief Allocator for discrete uniform distribution.
   *
   * @param params Params instance that is is passed.
   * @param format format for the polynomials generated.
   * @return the resulting vector.
   */
    inline static std::function<DerivedType()> MakeDiscreteUniformAllocator(const std::shared_ptr<Params>& params,
                                                                            Format format) {
        return [=]() {
            DugType dug;
            return DerivedType(dug, params, format);
        };
    }

    DerivedType& operator=(const DerivedType& rhs) override = 0;
    DerivedType& operator=(DerivedType&& rhs) override      = 0;
    DerivedType& operator=(const std::vector<int32_t>& rhs) {
        return this->GetDerived().operator=(rhs);
    }
    DerivedType& operator=(const std::vector<int64_t>& rhs) {
        return this->GetDerived().operator=(rhs);
    }
    DerivedType& operator=(std::initializer_list<uint64_t> rhs) override = 0;
    DerivedType& operator=(std::initializer_list<std::string> rhs) {
        return this->GetDerived().operator=(rhs);
    }
    DerivedType& operator=(uint64_t rhs) {
        return this->GetDerived().operator=(rhs);
    }

    /**
   * @brief Get method of the format.
   *
   * @return the format, either COEFFICIENT or EVALUATION
   */
    Format GetFormat() const override {
        return this->GetDerived().GetFormat();
    }

    /**
   * @brief returns the parameters of the element.
   * @return the element parameter set.
   */
    const std::shared_ptr<Params>& GetParams() const {
        return this->GetDerived().GetParams();
    }

    /**
   * @brief returns the element's ring dimension
   * @return returns the ring dimension of the element.
   */
    usint GetRingDimension() const {
        return this->GetDerived().GetParams()->GetRingDimension();
    }

    /**
   * @brief returns the element's root of unity.
   * @return the element's root of unity.
   */
    const Integer& GetRootOfUnity() const {
        return this->GetDerived().GetParams()->GetRootOfUnity();
    }

    /**
   * @brief returns the element's modulus
   * @return returns the modulus of the element.
   */
    const Integer& GetModulus() const final {
        return this->GetDerived().GetParams()->GetModulus();
    }

    /**
   * @brief returns the element's cyclotomic order
   * @return returns the cyclotomic order of the element.
   */
    usint GetCyclotomicOrder() const final {
        return this->GetDerived().GetParams()->GetCyclotomicOrder();
    }

    /**
   * @brief Get method for length of each component element.
   * NOTE assumes all components are the same size. (Ring Dimension)
   *
   * @return length of the component element
   */
    usint GetLength() const final {
        //        if (this->GetDerived().IsEmpty())
        //            OPENFHE_THROW("No values in PolyImpl");
        return this->GetDerived().GetValues().GetLength();
    }

    /**
   * @brief Get method that should not be used
   *
   * @return will throw an error.
   *
   * @warning Doesn't make sense for DCRT
   */
    const VecType& GetValues() const override = 0;

    /**
   * @brief Get interpolated value of elements at all tower index i.
   * Note this operation is computationally intense. Does bound checking
   * @return interpolated value at index i.
   */
    Integer& at(usint i) override             = 0;
    const Integer& at(usint i) const override = 0;

    /**
   * @brief Get interpolated value of element at index i.
   * Note this operation is computationally intense. No bound checking
   * @return interpolated value at index i.
   */
    Integer& operator[](usint i) override {
        return this->GetDerived()[i];
    }

    const Integer& operator[](usint i) const override {
        return this->GetDerived()[i];
    }

    /**
   * @brief Performs an addition operation and returns the result.
   *
   * @param &element is the element to add with.
   * @return is the result of the addition.
   */
    DerivedType Plus(const DerivedType& rhs) const override {
        return this->GetDerived().Plus(rhs);
    }

    /**
   * @brief Performs a subtraction operation and returns the result.
   *
   * @param &element is the element to subtract from.
   * @return is the result of the subtraction.
   */
    DerivedType Minus(const DerivedType& element) const override = 0;

    /**
   * @brief Performs a modular multiplication operation for Poly's in
   * EVALUATION format and returns the result. Performs runtime checks
   * for operand compatibility.
   *
   * @param &element is the element to multiply with.
   * @return is the result of the multiplication.
   */
    DerivedType Times(const DerivedType& element) const override = 0;

    /**
   * @brief Performs a modular multiplication operation for Poly's in
   * any format and returns the result. Performs no runtime checks.
   *
   * @param &element is the element to multiply with.
   * @return is the result of the multiplication.
   */
    DerivedType TimesNoCheck(const DerivedType& rhs) const {
        return this->GetDerived().Times(rhs);
    }
    /**
   * @brief Scalar addition - add an element to the first index of each tower.
   *
   * @param &element is the element to add entry-wise.
   * @return is the result of the addition operation.
   */
    DerivedType Plus(const Integer& element) const override = 0;

    /**
   * @brief Scalar subtraction - subtract an element to all entries.
   *
   * @param &element is the element to subtract entry-wise.
   * @return is the return value of the minus operation.
   */
    DerivedType Minus(const Integer& element) const override = 0;

    /**
   * @brief Scalar multiplication - multiply all entries.
   *
   * @param &element is the element to multiply entry-wise.
   * @return is the return value of the times operation.
   */
    DerivedType Times(const Integer& element) const override = 0;

    /**
   * @brief Scalar multiplication - multiply by a signed integer
   *
   * @param &element is the element to multiply entry-wise.
   * @return is the return value of the times operation.
   */
    DerivedType Times(NativeInteger::SignedNativeInt element) const override = 0;

#if NATIVEINT != 64
    /**
   * @brief Scalar multiplication - multiply by a signed integer
   *
   * @param &element is the element to multiply entry-wise.
   * @return is the return value of the times operation.
   *
   * @note this is need for 128-bit so that the 64-bit inputs can be used.
   */
    DerivedType Times(int64_t rhs) const {
        return this->GetDerived().Times(rhs);
    }
#endif

    /**
   * @brief Scalar multiplication followed by division and rounding operation -
   * operation on all entries.
   *
   * @param &p is the element to multiply entry-wise.
   * @param &q is the element to divide entry-wise.
   * @return is the return value of the multiply, divide and followed by
   * rounding operation.
   *
   * @warning Will remove, this is only inplace because of BFV
   */
    DerivedType MultiplyAndRound(const Integer& p, const Integer& q) const override = 0;

    /**
   * @brief Scalar division followed by rounding operation - operation on all
   * entries.
   *
   * @param &q is the element to divide entry-wise.
   * @return is the return value of the divide, followed by rounding operation.
   *
   * @warning Will remove, this is only inplace because of BFV
   */
    DerivedType DivideAndRound(const Integer& q) const override = 0;

    /**
   * @brief Performs a negation operation and returns the result.
   *
   * @return is the result of the negation.
   */
    virtual DerivedType Negate() const = 0;

    /**
   * @brief Unary minus on a element.
   * @return additive inverse of the an element.
   */
    DerivedType operator-() const override = 0;

    DerivedType& operator+=(const Integer& element) override = 0;

    /**
   * @brief Performs a subtraction operation and returns the result.
   *
   * @param &element is the element to subtract from.
   * @return is the result of the subtraction.
   */
    DerivedType& operator-=(const Integer& element) override = 0;

    /**
   * @brief Performs a multiplication operation and returns the result.
   *
   * @param &element is the element to multiply by.
   * @return is the result of the multiplication.
   */
    DerivedType& operator*=(const Integer& element) override = 0;

    /**
   * @brief Performs an entry-wise addition over all elements of each tower with
   * the towers of the element on the right hand side.
   *
   * @param &rhs is the element to add with.
   * @return is the result of the addition.
   */
    DerivedType& operator+=(const DerivedType& rhs) override = 0;

    /**
   * @brief Performs an entry-wise subtraction over all elements of each tower
   * with the towers of the element on the right hand side.
   *
   * @param &rhs is the element to subtract from.
   * @return is the result of the addition.
   */
    DerivedType& operator-=(const DerivedType& rhs) override = 0;

    /**
   * @brief Performs an multiplication operation and returns the result.
   *
   * @param &element is the element to multiply with.
   * @return is the result of the multiplication.
   */
    DerivedType& operator*=(const DerivedType& element) override = 0;

    /**
   * @brief Equality operator.
   *
   * @param &rhs is the specified element to be compared with this element.
   * @return true if this element represents the same values as the specified
   * element, false otherwise
   */
    bool operator==(const DerivedType& rhs) const override = 0;

    /**
   * @brief Adds "1" to every entry in every tower.
   */
    void AddILElementOne() override = 0;

    /**
   * @brief Permutes coefficients in a polynomial. Moves the ith index to the
   * first one, it only supports odd indices.
   *
   * @param &i is the element to perform the automorphism transform with.
   * @return is the result of the automorphism transform.
   */
    DerivedType AutomorphismTransform(uint32_t i) const override = 0;

    /**
   * @brief Performs an automorphism transform operation using precomputed bit
   * reversal indices.
   *
   * @param &i is the element to perform the automorphism transform with.
   * @param &vec a vector with precomputed indices
   * @return is the result of the automorphism transform.
   */
    DerivedType AutomorphismTransform(uint32_t i, const std::vector<uint32_t>& vec) const override = 0;

    /**
   * @brief Transpose the ring element using the automorphism operation
   *
   * @return is the result of the transposition.
   */
    inline DerivedType Transpose() const final {
        if (this->GetDerived().GetFormat() == Format::COEFFICIENT) {
            OPENFHE_THROW(
                "PolyInterface element transposition is currently "
                "implemented only in the Evaluation representation.");
        }
        return this->GetDerived().AutomorphismTransform(this->GetDerived().GetCyclotomicOrder() - 1);
    }

    /**
   * @brief Performs a multiplicative inverse operation and returns the result.
   *
   * @return is the result of the multiplicative inverse.
   */
    DerivedType MultiplicativeInverse() const override = 0;

    /**
   * @brief Perform a modulus by 2 operation.  Returns the least significant
   * bit.
   *
   * @return is the resulting value.
   */
    DerivedType ModByTwo() const override = 0;

    /**
   * @brief Modulus - perform a modulus operation. Does proper mapping of
   * [-modulus/2, modulus/2) to [0, modulus)
   *
   * @param modulus is the modulus to use.
   * @return is the return value of the modulus.
   */
    DerivedType Mod(const Integer& modulus) const override = 0;

    /**
   * @brief Switch modulus and adjust the values
   *
   * @param &modulus is the modulus to be set
   * @param &rootOfUnity is the corresponding root of unity for the modulus
   * @param &modulusArb is the modulus used for arbitrary cyclotomics CRT
   * @param &rootOfUnityArb is the corresponding root of unity for the modulus
   * ASSUMPTION: This method assumes that the caller provides the correct
   * rootOfUnity for the modulus
   */
    void SwitchModulus(const Integer& modulus, const Integer& rootOfUnity, const Integer& modulusArb,
                       const Integer& rootOfUnityArb) override = 0;

    /**
   * @brief Convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT
   *
   * @warning use @see SetFormat(format) instead
   */
    void SwitchFormat() override = 0;

    /**
   * @brief Sets format to value without calling FFT. Only use if you know what you're doing.
   *
   */
    virtual void OverrideFormat(const Format f) = 0;

    /**
   * @brief Make DCRTPoly Sparse. Sets every index of each tower not equal to
   * zero mod the wFactor to zero.
   *
   * @param &wFactor ratio between the sparse and none-sparse values.
   *
   * @warning Only used by RingSwitching, which is no longer supported. Will be removed in future.
   */
    void MakeSparse(uint32_t wFactor) override = 0;

    /**
   * @brief Returns true if ALL the tower(s) are empty.
   * @return true if all towers are empty
   */
    bool IsEmpty() const override = 0;

    /**
   * @brief Determines if inverse exists
   *
   * @return is the Boolean representation of the existence of multiplicative
   * inverse.
   */
    bool InverseExists() const override = 0;

    /**
   * @brief Returns the infinity norm, basically the largest value in the ring
   * element.
   *
   * @return is the largest value in the ring element.
   */
    double Norm() const override = 0;

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
   *
   * @warning not efficient and  not fast, uses multiprecision arithmetic and
   *          will be removed in future. Use @see DCRTPolyInterface::CRTDecompose instead.
   */

    std::vector<DerivedType> BaseDecompose(usint baseBits, bool evalModeAnswer) const override = 0;

    /**
   * @brief Generate a vector of PolyImpl's as \f$ \left\{x, {base}*x,
   * {base}^2*x, ..., {base}^{\lfloor {\log q/{base}} \rfloor} \right\}*x \f$,
   * where \f$ x \f$ is the current PolyImpl object;
   * used as a subroutine in the relinearization procedure to get powers of a
   * certain "base" for the secret key element.
   *
   * @param baseBits is the number of bits in the base, i.e., \f$ base =
   * 2^{baseBits} \f$.
   * @return is the pointer where the base decomposition vector is stored
   *
   * @warning not efficient and  not fast, uses multiprecision arithmetic and
   *          will be removed in future. Use @see DCRTPolyInterface::CRTDecompose instead.
   */
    std::vector<DerivedType> PowersOfBase(usint baseBits) const override = 0;

    /**
   * @brief Set method that should not be used, will throw an error.
   *
   * @param &values
   * @param format
   */
    virtual void SetValues(const VecType& values, Format format) = 0;
    virtual void SetValues(VecType&& values, Format format)      = 0;

    /**
   * @brief Sets all values of element to zero.
   */
    virtual void SetValuesToZero() = 0;
    virtual void SetValuesToMax()  = 0;

    /**
   * @brief Interpolates the DCRTPoly to an Poly based on the Chinese Remainder
   * Transform Interpolation. and then returns a Poly with that single element
   *
   * @return the interpolated ring element as a Poly object.
   */
    DerivedType CRTInterpolate() const {
        return this->GetDerived();
    }

    virtual PolyNative DecryptionCRTInterpolate(PlaintextModulus ptm) const = 0;

    /**
   * @brief If the values are small enough this is used for efficiency
   *
   * @return NativePoly
   *
   * @warning This will be replaced with a non-member utility function.
   */
    virtual PolyNative ToNativePoly() const = 0;

    DerivedType Clone() const final {
        return DerivedType(this->GetDerived());
    }

    DerivedType CloneEmpty() const final {
        return DerivedType();
    }

    DerivedType CloneParametersOnly() const final {
        return DerivedType(this->GetDerived().GetParams(), this->GetDerived().GetFormat());
    }

    DerivedType CloneWithNoise(const DggType& dgg, Format format) const final {
        return DerivedType(dgg, this->GetDerived().GetParams(), this->GetDerived().GetFormat());
    }

    const std::string GetElementName() const {
        return this->GetDerived().GetElementName();
    }

protected:
    /**
   * @brief ostream operator
   * @param os the input preceding output stream
   * @param vec the element to add to the output stream.
   * @return a resulting concatenated output stream
   */
    friend inline std::ostream& operator<<(std::ostream& os, const DerivedType& vec) {
        os << (vec.GetFormat() == Format::EVALUATION ? "EVAL: " : "COEF: ") << vec.GetValues();
        return os;
    }

    /**
   * @brief Element-element addition operator.
   * @param a first element to add.
   * @param b second element to add.
   * @return the result of the addition operation.
   */
    friend inline DerivedType operator+(const DerivedType& a, const DerivedType& b) {
        return a.Plus(b);
    }
    /**
   * @brief Element-integer addition operator.
   * @param a first element to add.
   * @param b integer to add.
   * @return the result of the addition operation.
   */
    friend inline DerivedType operator+(const DerivedType& a, const Integer& b) {
        return a.Plus(b);
    }

    /**
   * @brief Integer-element addition operator.
   * @param a integer to add.
   * @param b element to add.
   * @return the result of the addition operation.
   */
    friend inline DerivedType operator+(const Integer& a, const DerivedType& b) {
        return b.Plus(a);
    }

    /**
   * @brief Element-element subtraction operator.
   * @param a element to subtract from.
   * @param b element to subtract.
   * @return the result of the subtraction operation.
   */
    friend inline DerivedType operator-(const DerivedType& a, const DerivedType& b) {
        return a.Minus(b);
    }

    /**
   * @brief Element-integer subtraction operator.
   * @param a element to subtract from.
   * @param b integer to subtract.
   * @return the result of the subtraction operation.
   */
    friend inline DerivedType operator-(const DerivedType& a, const Integer& b) {
        return a.Minus(b);
    }

    /**
   * @brief Element-element multiplication operator.
   * @param a element to multiply.
   * @param b element to multiply.
   * @return the result of the multiplication operation.
   */
    friend inline DerivedType operator*(const DerivedType& a, const DerivedType& b) {
        return a.Times(b);
    }

    /**
   * @brief Element-integer multiplication operator.
   * @param a element to multiply.
   * @param b integer to multiply.
   * @return the result of the multiplication operation.
   */
    friend inline DerivedType operator*(const DerivedType& a, const Integer& b) {
        return a.Times(b);
    }

    /**
   * @brief Integer-element multiplication operator.
   * @param a integer to multiply.
   * @param b element to multiply.
   * @return the result of the multiplication operation.
   */
    friend inline DerivedType operator*(const Integer& a, const DerivedType& b) {
        return b.Times(a);
    }

    /**
   * @brief Element-signed-integer multiplication operator.
   * @param a element to multiply.
   * @param b integer to multiply.
   * @return the result of the multiplication operation.
   */
    friend inline DerivedType operator*(const DerivedType& a, int64_t b) {
        return a.Times((NativeInteger::SignedNativeInt)b);
    }

    /**
   * @brief signed-Integer-element multiplication operator.
   * @param a integer to multiply.
   * @param b element to multiply.
   * @return the result of the multiplication operation.
   */
    friend inline DerivedType operator*(int64_t a, const DerivedType& b) {
        return b.Times((NativeInteger::SignedNativeInt)a);
    }
};

}  // namespace lbcrypto

#endif
