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

#ifndef LBCRYPTO_INC_LATTICE_HAL_DCRTPOLYINTERFACE_H
#define LBCRYPTO_INC_LATTICE_HAL_DCRTPOLYINTERFACE_H

#include "lattice/hal/default/ildcrtparams.h"
#include "lattice/ilelement.h"

#include "math/math-hal.h"
#include "math/distrgen.h"

#include "utils/inttypes.h"
#include "utils/exception.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

/**
 * @brief Ideal lattice for the double-CRT interface representation.
 * The interface contains a methods required for computations on lattices
 * The double-CRT representation of polynomials is a common optimization for
 * lattice encryption operations. Basically, it allows large-modulus polynomials
 * to be represented as multiple smaller-modulus polynomials.  The double-CRT
 * representations are discussed theoretically here:
 *   - Gentry C., Halevi S., Smart N.P. (2012) Homomorphic Evaluation of the AES
 * Circuit. In: Safavi-Naini R., Canetti R. (eds) Advances in Cryptology –
 * CRYPTO 2012. Lecture Notes in Computer Science, vol 7417. Springer, Berlin,
 * Heidelberg
 *
 *
 * @tparam DerivedType Curiously-Recurring-Template-Pattern
 * @tparam BigVecType The Vector type before decomposing the polynomial into CRT
 * @tparam LilVecType The underlaying RNS data structure, a vectors type structure, that will compose the CRT data
 * @tparam RNSContainer The container of LilVecType, a lbcrypto::PolyImpl or vector typically
 *
 * example for the default DerivedType the template types would be...
 *    DerivedType       - DCRTPolyImpl<BigVector>
 *    BigVecType        - BigVector
 *    LilVecType        - NativeVector
 *    RNSContainer<LVT> - PolyImpl
 */

// TODO: CRTP with ILElement to remove virtual overhead

template <typename DerivedType, typename BigVecType, typename LilVecType,
          template <typename LVT> typename RNSContainerType>
class DCRTPolyInterface : public ILElement<DerivedType, BigVecType> {
public:
    using BigIntType    = typename BigVecType::Integer;
    using Params        = ILDCRTParams<BigIntType>;
    using LilIntType    = typename LilVecType::Integer;
    using TowerType     = RNSContainerType<LilVecType>;
    using PolyLargeType = RNSContainerType<BigVecType>;
    using DggType       = DiscreteGaussianGeneratorImpl<LilVecType>;
    using DugType       = DiscreteUniformGeneratorImpl<LilVecType>;
    using TugType       = TernaryUniformGeneratorImpl<LilVecType>;
    using BugType       = BinaryUniformGeneratorImpl<LilVecType>;

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
   *
   * @param params the params to use.
   * @param format - EVALUATION or COEFFICIENT
   */
    static std::function<DerivedType()> Allocator(const std::shared_ptr<Params>& params, Format format) {
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
    static std::function<DerivedType()> MakeDiscreteGaussianCoefficientAllocator(const std::shared_ptr<Params>& params,
                                                                                 Format resultFormat, double stddev) {
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
    static std::function<DerivedType()> MakeDiscreteUniformAllocator(const std::shared_ptr<Params>& params,
                                                                     Format format) {
        return [=]() {
            DugType dug;
            return DerivedType(dug, params, format);
        };
    }

    /**
   * @brief Makes a copy of the DCRTPoly, but it includes only a sequential
   * subset of the towers that the original holds.
   *
   * @param startTower The index number of the first tower to clone
   * @param endTower The index number of the last tower to clone
   * @return new Element
   */
    DerivedType CloneTowers(uint32_t startTower, uint32_t endTower) {
        return this->GetDerived().CloneTowers(startTower, endTower);
    }

    DerivedType Clone() const final {
        return DerivedType(this->GetDerived());
    }

    DerivedType CloneEmpty() const final {
        return DerivedType();
    }

    DerivedType CloneParametersOnly() const final {
        return DerivedType(this->GetDerived().GetParams(), this->GetDerived().GetFormat());
    }

    /**
   * @brief Clone with noise.  This method creates a new DCRTPoly and clones the
   * params. The tower values will be filled up with noise based on the discrete
   * gaussian.
   *
   * @param &dgg the input discrete Gaussian generator. The dgg will be the seed
   * to populate the towers of the DCRTPoly with random numbers.
   * @param format the input format fixed to EVALUATION. Format is a enum type
   * that indicates if the polynomial is in Evaluation representation or
   * Coefficient representation. It is defined in inttypes.h.
   */
    DerivedType CloneWithNoise(const DiscreteGaussianGeneratorImpl<BigVecType>& dgg, Format format) const override = 0;

    /**
   * @brief Get method of the format.
   *
   * @return the format, either COEFFICIENT or EVALUATION
   */
    Format GetFormat() const override = 0;
    //    return this->GetDerived().GetFormat();

    /**
   * @brief returns the parameters of the element.
   * @return the element parameter set.
   */
    const std::shared_ptr<Params>& GetParams() const {
        return this->GetDerived().GetParams();
    }

    /**
   * @brief returns the element's cyclotomic order
   * @return returns the cyclotomic order of the element.
   */
    usint GetCyclotomicOrder() const final {
        return this->GetDerived().GetParams()->GetCyclotomicOrder();
    }

    /**
   * @brief returns the element's ring dimension
   * @return returns the ring dimension of the element.
   */
    usint GetRingDimension() const {
        return this->GetDerived().GetParams()->GetRingDimension();
    }

    /**
   * @brief returns the element's modulus
   * @return returns the modulus of the element.
   */
    const BigIntType& GetModulus() const final {
        return this->GetDerived().GetParams()->GetModulus();
    }

    /**
   * @brief returns the element's root of unity.
   * @return the element's root of unity.
   */
    // TODO: this doesn't look right
    const BigIntType GetRootOfUnity() const {
        //        return BigIntType(0);
        return this->GetDerived().GetParams()->GetRootOfUnity();
    }

    /**
   * @brief Get method for length of each component element.
   * NOTE assumes all components are the same size. (Ring Dimension)
   *
   * @return length of the component element
   */
    usint GetLength() const final {
        return this->GetDerived().GetParams()->GetRingDimension();
    }

    /**
   * @brief Get interpolated value of elements at all tower index i.
   * Note this operation is computationally intense. Does bound checking
   * @return interpolated value at index i.
   */
    BigIntType& at(usint i) final {
        OPENFHE_THROW("at() not implemented for DCRTPoly");
    }
    const BigIntType& at(usint i) const final {
        OPENFHE_THROW("const at() not implemented for DCRTPoly");
    }

    /**
   * @brief Get interpolated value of element at index i.
   * Note this operation is computationally intense. No bound checking
   * @return interpolated value at index i.
   */
    BigIntType& operator[](usint i) final {
        OPENFHE_THROW("operator[] not implemented for DCRTPoly");
    }
    const BigIntType& operator[](usint i) const final {
        OPENFHE_THROW("const operator[] not implemented for DCRTPoly");
    }

    /**
   * @brief Get method that returns a vector of all component elements.
   *
   * @returns a vector of the component elements.
   */
    const std::vector<TowerType>& GetAllElements() const {
        return this->GetDerived().GetAllElements();
    }
    std::vector<TowerType>& GetAllElements() {
        return this->GetDerived().GetAllElements();
    }

    /**
   * @brief Get method of the number of component elements, also known as the
   * number of towers.
   *
   * @return the number of component elements.
   */
    usint GetNumOfElements() const {
        return this->GetDerived().GetAllElements().size();
    }

    /**
   * @brief Get method of individual tower of elements.
   * Note this behavior is different than poly
   * @param i index of tower to be returned.
   * @returns a reference to the returned tower
   */
    const TowerType& GetElementAtIndex(usint i) const {
        return this->GetDerived().GetAllElements()[i];
    }

    /**
   * @brief Sets element at index
   *
   * @param index where the element should be set
   * @param element The element to store
   */
    void SetElementAtIndex(usint index, const TowerType& element) {
        return this->GetDerived().SetElementAtIndex(index, element);
    }

    /**
   * @brief Sets element at index
   *
   * @param index where the element should be set
   * @param element The element to store
   */
    void SetElementAtIndex(usint index, TowerType&& element) {
        return this->GetDerived().SetElementAtIndex(index, std::move(element));
    }

    /***********************************************************************
   * Yuriy and I stopped here!
   **********************************************************************/

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
   * CRT basis decomposition of c as [c qi/q]_qi
   *
   * @param &baseBits bits in the base for additional digit decomposition if
   * base > 0
   * @return is the pointer where the resulting vector is stored
   */
    std::vector<DerivedType> CRTDecompose(uint32_t baseBits) const {
        return this->GetDerived().CRTDecompose(baseBits);
    }

    DerivedType& operator=(const TowerType& rhs) {
        return this->GetDerived().operator=(rhs);
    }

    /**
   * @brief Assignment Operator.
   *
   * @param &rhs the copied element.
   * @return the resulting element.
   */
    DerivedType& operator=(const DerivedType& rhs) override = 0;

    /**
   * @brief Move Assignment Operator.
   *
   * @param &rhs the copied element.
   * @return the resulting element.
   */
    DerivedType& operator=(DerivedType&& rhs) override = 0;

    /**
   * @brief Initalizer list
   *
   * @param &rhs the list to initalized the element.
   * @return the resulting element.
   */
    DerivedType& operator=(std::initializer_list<uint64_t> rhs) override = 0;

    /**
   * @brief Assignment Operator. The usint val will be set at index zero and all
   * other indices will be set to zero.
   *
   * @param val is the usint to assign to index zero.
   * @return the resulting vector.
   */
    DerivedType& operator=(uint64_t val) {
        return this->GetDerived().operator=(val);
    }

    /**
   * @brief Creates a Poly from a vector of signed integers (used for trapdoor
   * sampling)
   *
   * @param &rhs the vector to set the PolyImpl to.
   * @return the resulting PolyImpl.
    */
    DerivedType& operator=(const std::vector<int64_t>& rhs) {
        return this->GetDerived().operator=(rhs);
    }

    /**
   * @brief Creates a Poly from a vector of signed integers (used for trapdoor
   * sampling)
   *
   * @param &rhs the vector to set the PolyImpl to.
   * @return the resulting PolyImpl.
   */
    DerivedType& operator=(const std::vector<int32_t>& rhs) {
        return this->GetDerived().operator=(rhs);
    }

    /**
   * @brief Initalizer list
   *
   * @param &rhs the list to set the PolyImpl to.
   * @return the resulting PolyImpl.
   */
    DerivedType& operator=(std::initializer_list<std::string> rhs) {
        return this->GetDerived().operator=(rhs);
    }

    /**
   * @brief Unary minus on a element.
   * @return additive inverse of the an element.
   */
    DerivedType operator-() const override = 0;

    /**
   * @brief Equality operator.
   *
   * @param &rhs is the specified element to be compared with this element.
   * @return true if this element represents the same values as the specified
   * element, false otherwise.
   */
    bool operator==(const DerivedType& rhs) const override = 0;

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
    DerivedType Transpose() const final {
        if (this->GetDerived().GetFormat() == Format::COEFFICIENT)
            OPENFHE_THROW(
                "DCRTPolyInterface element transposition is currently "
                "implemented only in the Evaluation representation.");
        return this->GetDerived().AutomorphismTransform(this->GetDerived().GetCyclotomicOrder() - 1);
    }

    /**
   * @brief Performs an addition operation and returns the result.
   *
   * @param &element is the element to add with.
   * @return is the result of the addition.
   */
    DerivedType Plus(const DerivedType& rhs) const override = 0;
    //    return this->GetDerived().Plus(rhs);

    /**
   * @brief Performs a multiplication operation and returns the result.
   *
   * @param &element is the element to multiply with.
   * @return is the result of the multiplication.
   */
    DerivedType Times(const DerivedType& rhs) const override = 0;
    //    return this->GetDerived().Times(rhs);

    /**
   * @brief Performs a subtraction operation and returns the result.
   *
   * @param &element is the element to subtract from.
   * @return is the result of the subtraction.
   */
    DerivedType Minus(const DerivedType& rhs) const override = 0;

    /**
   * @brief Scalar addition - add an element to the first index of each tower.
   *
   * @param &element is the element to add entry-wise.
   * @return is the result of the addition operation.
   */
    DerivedType Plus(const BigIntType& rhs) const override = 0;

    /**
   * @brief Scalar addition for elements in CRT format.
   * CRT elements are represented as vector of integer elements which
   * correspond to the represented number modulo the primes in the
   * tower chain (in same order).
   *
   * @param &element is the element to add entry-wise.
   * @return is the result of the addition operation.
   */
    DerivedType Plus(const std::vector<BigIntType>& rhs) const {
        return this->GetDerived().Plus(rhs);
    }

    /**
   * @brief Scalar subtraction - subtract an element to all entries.
   *
   * @param &element is the element to subtract entry-wise.
   * @return is the return value of the minus operation.
   */
    DerivedType Minus(const BigIntType& rhs) const override = 0;

    /**
   * @brief Scalar subtraction for elements in CRT format.
   * CRT elements are represented as vector of integer elements which
   * correspond to the represented number modulo the primes in the
   * tower chain (in same order).
   *
   * @param &element is the element to subtract entry-wise.
   * @return is the result of the subtraction operation.
   */
    DerivedType Minus(const std::vector<BigIntType>& rhs) const {
        return this->GetDerived().Minus(rhs);
    }

    /**
   * @brief Scalar multiplication - multiply all entries.
   *
   * @param &element is the element to multiply entry-wise.
   * @return is the return value of the times operation.
   */
    DerivedType Times(const BigIntType& rhs) const override = 0;

    /**
   * @brief Scalar multiplication - multiply by a signed integer
   *
   * @param &element is the element to multiply entry-wise.
   * @return is the return value of the times operation.
   */
    DerivedType Times(NativeInteger::SignedNativeInt rhs) const override = 0;

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
   * @brief Scalar multiplication by an integer represented in CRT Basis.
   *
   * @param &element is the element to multiply entry-wise.
   * @return is the return value of the times operation.
   */
    DerivedType Times(const std::vector<NativeInteger>& rhs) const {
        return this->GetDerived().Times(rhs);
    }

    /**
   * @brief Performs a multiplication operation even when the multiplicands
   * have a different number of towers.
   *
   * @param &element is the element to multiply with.
   * @return is the result of the multiplication.
   */
    DerivedType TimesNoCheck(const std::vector<NativeInteger>& rhs) const {
        return this->GetDerived().TimesNoCheck(rhs);
    }

    /**
   * @brief Scalar modular multiplication by an integer represented in CRT
   * Basis.
   *
   * @param &element is the element to multiply entry-wise.
   * @return is the return value of the times operation.
   *
   * @warning Should remove this, data is truncated to native-word size.
   */
    DerivedType Times(const std::vector<BigIntType>& rhs) const {
        return this->GetDerived().Times(rhs);
    }

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
    DerivedType MultiplyAndRound(const BigIntType& p, const BigIntType& q) const final {
        OPENFHE_THROW("MultiplyAndRound not implemented for DCRTPoly");
    }

    /**
   * @brief Scalar division followed by rounding operation - operation on all
   * entries.
   *
   * @param &q is the element to divide entry-wise.
   * @return is the return value of the divide, followed by rounding operation.
   *
   * @warning Will remove, this is only inplace because of BFV
   */
    DerivedType DivideAndRound(const BigIntType& q) const final {
        OPENFHE_THROW("DivideAndRound not implemented for DCRTPoly");
    }

    /**
   * @brief Performs a negation operation and returns the result.
   *
   * @return is the result of the negation.
   */
    virtual DerivedType Negate() const = 0;

    DerivedType& operator+=(const BigIntType& rhs) override = 0;
    virtual DerivedType& operator+=(const LilIntType& rhs)  = 0;

    /**
   * @brief Performs a subtraction operation and returns the result.
   *
   * @param &element is the element to subtract from.
   * @return is the result of the subtraction.
   */
    DerivedType& operator-=(const BigIntType& rhs) override = 0;
    virtual DerivedType& operator-=(const LilIntType& rhs)  = 0;

    /**
   * @brief Performs a multiplication operation and returns the result.
   *
   * @param &element is the element to multiply by.
   * @return is the result of the multiplication.
   */
    DerivedType& operator*=(const BigIntType& rhs) override = 0;
    virtual DerivedType& operator*=(const LilIntType& rhs)  = 0;

    /**
   * @brief Performs a multiplication operation and returns the result.
   *
   * @param &element is the element to multiply with.
   * @return is the result of the multiplication.
   */
    DerivedType& operator*=(const DerivedType& rhs) override = 0;

    // multiplicative inverse operation
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
   *
   * @warning Doesn't make sense for DCRT
   */
    DerivedType ModByTwo() const final {
        OPENFHE_THROW("Mod of a BigIntType not implemented for DCRTPoly");
    }

    /**
   * @brief Modulus - perform a modulus operation. Does proper mapping of
   * [-modulus/2, modulus/2) to [0, modulus)
   *
   * @param modulus is the modulus to use.
   * @return is the return value of the modulus.
   *
   * @warning Doesn't make sense for DCRT
   */
    DerivedType Mod(const BigIntType& modulus) const final {
        OPENFHE_THROW("Mod of a BigIntType not implemented for DCRTPoly");
    }

    /**
   * @brief Get method that should not be used
   *
   * @return will throw an error.
   *
   * @warning Doesn't make sense for DCRT
   */
    const BigVecType& GetValues() const final {
        OPENFHE_THROW("GetValues not implemented for DCRTPoly");
    }

    /**
   * @brief Set method that should not be used, will throw an error.
   *
   * @param &values
   * @param format
   *
   * @warning Doesn't make sense for DCRT
   */
    void SetValues(const BigVecType& values, Format format) {
        OPENFHE_THROW("SetValues not implemented for DCRTPoly");
    }

    /**
   * @brief Sets all values of element to zero.
   */
    virtual void SetValuesToZero() = 0;

    /**
   * @brief Sets values with a different modulus
   */
    virtual void SetValuesModSwitch(const DerivedType& element, const NativeInteger& modulus) = 0;

    /**
   * @brief Adds "1" to every entry in every tower.
   */
    void AddILElementOne() override = 0;

    /**
   * @brief Add uniformly random values to all components except for the first
   * one
   *
   * @warning Doesn't make sense for DCRT
   */
    DerivedType AddRandomNoise(const BigIntType& modulus) const {
        OPENFHE_THROW("AddRandomNoise is not currently implemented for DCRTPoly");
    }

    /**
   * @brief Make DCRTPoly Sparse. Sets every index of each tower not equal to
   * zero mod the wFactor to zero.
   *
   * @param &wFactor ratio between the sparse and none-sparse values.
   *
   * @warning Only used by RingSwitching, which is no longer supported. Will be removed in future.
   */
    void MakeSparse(uint32_t wFactor) final {
        OPENFHE_THROW("MakeSparse is not currently implemented for DCRTPoly");
    }

    /**
   * @brief Returns true if ALL the tower(s) are empty.
   * @return true if all towers are empty
   */
    bool IsEmpty() const override = 0;

    /**
   * @brief Drops the last element in the double-CRT representation. The
   * resulting DCRTPoly element will have one less tower.
   */
    virtual void DropLastElement() = 0;

    /**
   * @brief Drops the last i elements in the double-CRT representation.
   */
    virtual void DropLastElements(size_t i) = 0;

    /**
   * @brief Drops the last element in the double-CRT representation and scales
   * down by the last CRT modulus. The resulting DCRTPoly element will have one
   * less tower.
   * @param &QlQlInvModqlDivqlModq precomputed values for
   * [Q^(l)*[Q^(l)^{-1}]_{q_l}/q_l]_{q_i}
   * @param &QlQlInvModqlDivqlModqPrecon NTL-specific precomputations
   * @param &qlInvModq precomputed values for [q_l^{-1}]_{q_i}
   * @param &qlInvModqPrecon NTL-specific precomputations
   */
    virtual void DropLastElementAndScale(const std::vector<NativeInteger>& QlQlInvModqlDivqlModq,
                                         const std::vector<NativeInteger>& qlInvModq) = 0;

    /**
   * @brief ModReduces reduces the DCRTPoly element's composite modulus by
   * dropping the last modulus from the chain of moduli as well as dropping the
   * last tower.
   *
   * @param &t is the plaintextModulus used for the DCRTPoly
   * @param &tModqPrecon NTL-specific precomputations for [t]_{q_i}
   * @param &negtInvModq precomputed values for [-t^{-1}]_{q_i}
   * @param &negtInvModqPrecon NTL-specific precomputations for [-t^{-1}]_{q_i}
   * @param &qlInvModq precomputed values for [q_{l}^{-1}]_{q_i}
   * @param &qlInvModqPrecon NTL-specific precomputations for [q_{l}^{-1}]_{q_i}
   */
    virtual void ModReduce(const NativeInteger& t, const std::vector<NativeInteger>& tModqPrecon,
                           const NativeInteger& negtInvModq, const NativeInteger& negtInvModqPrecon,
                           const std::vector<NativeInteger>& qlInvModq,
                           const std::vector<NativeInteger>& qlInvModqPrecon) = 0;

    /**
   * @brief Interpolates the DCRTPoly to a Poly based on the Chinese Remainder
   * Transform Interpolation. and then returns a Poly with that single element
   *
   * @return the interpolated ring element as a Poly object.
   */
    virtual PolyLargeType CRTInterpolate() const = 0;

    virtual TowerType DecryptionCRTInterpolate(PlaintextModulus ptm) const = 0;

    /**
   * @brief If the values are small enough this is used for efficiency
   *
   * @return NativePoly
   *
   * @warning This will be replaced with a non-member utility function.
   */
    virtual TowerType ToNativePoly() const = 0;

    /**
   * @brief Interpolates the DCRTPoly to a Poly based on the Chinese Remainder
   * Transform Interpolation, only at element index i, all other elements are
   * zero. and then returns a Poly with that single element
   *
   * @return the interpolated ring element as a Poly object.
   */
    virtual PolyLargeType CRTInterpolateIndex(usint i) const = 0;

    /**
   * @brief Computes and returns the product of primes in the current moduli
   * chain. Compared to GetModulus, which always returns the product of all
   * primes in the crypto parameters, this method will return a different
   * modulus, based on the towers/moduli that are currently in the chain (some
   * towers are dropped along the way).
   *
   * @return the product of moduli in the current towers.
   */
    virtual BigIntType GetWorkingModulus() const = 0;

    /**
   * @brief Returns the element parameters for DCRTPoly elements in an extended
   * CRT basis, which is the concatenation of the towers currently in "this"
   * DCRTPoly, and the moduli in ParamsP.
   *
   * @return element parameters of the extended basis.
   */
    virtual std::shared_ptr<Params> GetExtendedCRTBasis(const std::shared_ptr<Params>& paramsP) const = 0;

    virtual void TimesQovert(const std::shared_ptr<Params>& paramsQ, const std::vector<NativeInteger>& tInvModq,
                             const NativeInteger& t, const NativeInteger& NegQModt,
                             const NativeInteger& NegQModtPrecon) = 0;

    /**
   * @brief Performs approximate CRT basis switching:
   * {X}_{Q} -> {X'}_{P}
   * X' = X + alpha*Q for small alpha
   * {Q} = {q_1,...,q_l}
   * {P} = {p_1,...,p_k}
   *
   * Brief algorithm:
   * [X']_{p_j} = [\sum_i([x_i*(Q/q_i)^{-1}]_{q_i}*(Q/q_i)]_{p_j}
   *
   * Source: "A full RNS variant of approximate homomorphic encryption" by
   * Cheon, et. al.
   *
   * @param &paramsQ parameters for the CRT basis {q_1,...,q_l}
   * @param &paramsP parameters for the CRT basis {p_1,...,p_k}
   * @param &QHatinvModq precomputed values for [(Q/q_i)^{-1}]_{q_i}
   * @param &QHatinvModqPrecon NTL-specific precomputations
   * @param &QHatModp precomputed values for [Q/q_i]_{p_j}
   * @param &modpBarrettMu 128-bit Barrett reduction precomputed values
   * @return the representation of {X + alpha*Q} in basis {P}.
   */
    virtual DerivedType ApproxSwitchCRTBasis(const std::shared_ptr<Params>& paramsQ,
                                             const std::shared_ptr<Params>& paramsP,
                                             const std::vector<NativeInteger>& QHatInvModq,
                                             const std::vector<NativeInteger>& QHatInvModqPrecon,
                                             const std::vector<std::vector<NativeInteger>>& QHatModp,
                                             const std::vector<DoubleNativeInt>& modpBarrettMu) const = 0;

    /**
   * @brief Performs approximate modulus raising:
   * {X}_{Q} -> {X'}_{Q,P}.
   * X' = X + alpha*Q for small alpha
   * {Q} = {q_1,...,q_l}
   * {P} = {p_1,...,p_k}
   *
   * Brief algorithm:
   * {X}_{Q} -> {X'}_Q : trivial
   * {X}_{Q} -> {X'}_P : use DCRTPoly::ApproxSwitchCRTBasis
   *
   * Source: "A full RNS variant of approximate homomorphic encryption" by
   * Cheon, et. al.
   *
   * @param &paramsQ parameters for the CRT basis {q_1,...,q_l}
   * @param &paramsP parameters for the CRT basis {p_1,...,p_k}
   * @param &QHatInvModq precomputed values for [(Q/q_i)^{-1}]_{q_i}
   * @param &QHatInvModqPrecon NTL-specific precomputations
   * @param &QHatModp precomputed values for [Q/q_i]_{p_j}
   * @param &modpBarrettMu 128-bit Barrett reduction precomputed values for
   * p_j
   * @return the representation of {X + alpha*Q} in basis {Q,P}.
   */
    virtual void ApproxModUp(const std::shared_ptr<Params>& paramsQ, const std::shared_ptr<Params>& paramsP,
                             const std::shared_ptr<Params>& paramsQP, const std::vector<NativeInteger>& QHatInvModq,
                             const std::vector<NativeInteger>& QHatInvModqPrecon,
                             const std::vector<std::vector<NativeInteger>>& QHatModp,
                             const std::vector<DoubleNativeInt>& modpBarrettMu) = 0;

    /**
   * @brief Performs approximate modulus reduction:
   * {X}_{Q,P} -> {\approx(X/P)}_{Q}.
   * {Q} = {q_1,...,q_l}
   * {P} = {p_1,...,p_k}
   *
   * Brief algorithm:
   * 1) use DCRTPoly::ApproxSwitchCRTBasis : {X}_{P} -> {X'}_{Q}
   * 2) compute : {(X-X') * P^{-1}}_{Q}
   *
   * Source: "A full RNS variant of approximate homomorphic encryption" by
   * Cheon, et. al.
   *
   * @param &paramsQ parameters for the CRT basis {q_1,...,q_l}
   * @param &paramsP parameters for the CRT basis {p_1,...,p_k}
   * @param &PInvModq precomputed values for (P^{-1} mod q_j)
   * @param &PInvModqPrecon NTL-specific precomputations
   * @param &PHatInvModp precomputed values for [(P/p_j)^{-1}]_{p_j}
   * @param &PHatInvModpPrecon NTL-specific precomputations
   * @param &PHatModq precomputed values for [P/p_j]_{q_i}
   * @param &modqBarrettMu 128-bit Barrett reduction precomputed values for
   * q_i
   * @param &tInvModp precomputed values for [t^{-1}]_{p_j}
   * used in BGVrns
   * @param t often corresponds to the plaintext modulus
   * used in BGVrns
   * @return the representation of {\approx(X/P)}_{Q}
   */
    virtual DerivedType ApproxModDown(
        const std::shared_ptr<Params>& paramsQ, const std::shared_ptr<Params>& paramsP,
        const std::vector<NativeInteger>& PInvModq, const std::vector<NativeInteger>& PInvModqPrecon,
        const std::vector<NativeInteger>& PHatInvModp, const std::vector<NativeInteger>& PHatInvModpPrecon,
        const std::vector<std::vector<NativeInteger>>& PHatModq, const std::vector<DoubleNativeInt>& modqBarrettMu,
        const std::vector<NativeInteger>& tInvModp, const std::vector<NativeInteger>& tInvModpPrecon,
        const NativeInteger& t, const std::vector<NativeInteger>& tModqPrecon) const = 0;

    /**
   * @brief Performs CRT basis switching:
   * {X}_{Q} -> {X}_{P}
   * {Q} = {q_1,...,q_l}
   * {P} = {p_1,...,p_k}
   *
   * Brief algorithm:
   * 1) X=\sum_i[x_i*(Q/q_i)^{-1}]_{q_i}*(Q/q_i)-alpha*Q
   * 2) compute round[[x_i*(Q/q_i)^{-1}]_{q_i} / q_i] to find alpha
   * 3) [X]_{p_j}=[\sum_i[x_i*(Q/q_i)^{-1}]_{q_i}*(Q/q_i)]_{p_j}-[alpha*Q]_{p_j}
   *
   * Source: Halevi S., Polyakov Y., and Shoup V. An Improved RNS Variant of the
   * BFV Homomorphic Encryption Scheme. Cryptology ePrint Archive, Report
   * 2018/117. (https://eprint.iacr.org/2018/117)
   *
   * @param &paramsP parameters for the CRT basis {p_1,...,p_k}
   * @param &QHatInvModq precomputed values for [(Q/q_i)^{-1}]_{q_i}
   * @param &QHatInvModqPrecon NTL-specific precomputations
   * @param &QHatModp precomputed values for [Q/q_i]_{p_j}
   * @param &alphaQModp precomputed values for [alpha*Q]_{p_j}
   * @param &modpBarrettMu 128-bit Barrett reduction precomputed values for
   * p_j
   * @params &qInv precomputed values for 1/q_i
   * @return the representation of {X}_{P}
   */
    virtual DerivedType SwitchCRTBasis(const std::shared_ptr<Params>& paramsP,
                                       const std::vector<NativeInteger>& QHatInvModq,
                                       const std::vector<NativeInteger>& QHatInvModqPrecon,
                                       const std::vector<std::vector<NativeInteger>>& QHatModp,
                                       const std::vector<std::vector<NativeInteger>>& alphaQModp,
                                       const std::vector<DoubleNativeInt>& modpBarrettMu,
                                       const std::vector<double>& qInv) const = 0;

    /**
   * @brief Performs modulus raising:
   * {X}_{Q} -> {X}_{Q,P}
   * {Q} = {q_1,...,q_l}
   * {P} = {p_1,...,p_k}
   *
   * Brief algorithm:
   * {X}_{Q} -> {X}_P : use DCRTPoly::SwitchCRTBasis
   * combine {X}_{Q} and {X}_{P}
   * Outputs the resulting polynomial in CRT/RNS
   *
   * Source: Halevi S., Polyakov Y., and Shoup V. An Improved RNS Variant of the
   * BFV Homomorphic Encryption Scheme. Cryptology ePrint Archive, Report
   * 2018/117. (https://eprint.iacr.org/2018/117)
   *
   * @param &paramsQP parameters for the CRT basis {q_1,...,q_l,p_1,...,p_k}
   * @param &paramsP parameters for the CRT basis {p_1,...,p_k}
   * @param &QHatInvModq precomputed values for [QInv_i]_{q_i}
   * @param &QHatInvModqPrecon NTL-specific precomputations
   * @param &QHatModp precomputed values for [QHat_i]_{p_j}
   * @param &alphaQModp precomputed values for [alpha*Q]_{p_j}
   * @param &modpBarrettMu 128-bit Barrett reduction precomputed values for
   * p_j
   * @params &qInv precomputed values for 1/q_i
   * @param resultFormat Specifies the format we want the result to be in
   *
   */
    virtual void ExpandCRTBasis(const std::shared_ptr<Params>& paramsQP, const std::shared_ptr<Params>& paramsP,
                                const std::vector<NativeInteger>& QHatInvModq,
                                const std::vector<NativeInteger>& QHatInvModqPrecon,
                                const std::vector<std::vector<NativeInteger>>& QHatModp,
                                const std::vector<std::vector<NativeInteger>>& alphaQModp,
                                const std::vector<DoubleNativeInt>& modpBarrettMu, const std::vector<double>& qInv,
                                Format resultFormat) = 0;

    /**
   * @brief Performs modulus raising in reverse order:
   * {X}_{Q} -> {X}_{P,Q}
   */
    virtual void ExpandCRTBasisReverseOrder(const std::shared_ptr<Params>& paramsQP,
                                            const std::shared_ptr<Params>& paramsP,
                                            const std::vector<NativeInteger>& QHatInvModq,
                                            const std::vector<NativeInteger>& QHatInvModqPrecon,
                                            const std::vector<std::vector<NativeInteger>>& QHatModp,
                                            const std::vector<std::vector<NativeInteger>>& alphaQModp,
                                            const std::vector<DoubleNativeInt>& modpBarrettMu,
                                            const std::vector<double>& qInv, Format resultFormat) = 0;

    struct CRTBasisExtensionPrecomputations {
        // TODO (dsuponit) and (pascoec): make the data members private to enforce their constantness and add getters.
        std::shared_ptr<Params> paramsQlPl;
        std::shared_ptr<Params> paramsPl;
        std::shared_ptr<Params> paramsQl;
        std::vector<NativeInteger> mPlQHatInvModq;
        std::vector<NativeInteger> mPlQHatInvModqPrecon;
        std::vector<std::vector<NativeInteger>> qInvModp;
        std::vector<DoubleNativeInt> modpBarrettMu;
        std::vector<NativeInteger> PlHatInvModp;
        std::vector<NativeInteger> PlHatInvModpPrecon;
        std::vector<std::vector<NativeInteger>> PlHatModq;
        std::vector<std::vector<NativeInteger>> alphaPlModq;
        std::vector<DoubleNativeInt> modqBarrettMu;
        std::vector<double> pInv;

        // clang-format off
        CRTBasisExtensionPrecomputations(
            const std::shared_ptr<Params>& paramsQlPl0,
            const std::shared_ptr<Params>& paramsPl0,
            const std::shared_ptr<Params>& paramsQl0,
            const std::vector<NativeInteger>& mPlQHatInvModq0,
            const std::vector<NativeInteger>& mPlQHatInvModqPrecon0,
            const std::vector<std::vector<NativeInteger>>& qInvModp0,
            const std::vector<DoubleNativeInt>& modpBarrettMu0,
            const std::vector<NativeInteger>& PlHatInvModp0,
            const std::vector<NativeInteger>& PlHatInvModpPrecon0,
            const std::vector<std::vector<NativeInteger>>& PlHatModq0,
            const std::vector<std::vector<NativeInteger>>& alphaPlModq0,
            const std::vector<DoubleNativeInt>& modqBarrettMu0,
            const std::vector<double>& pInv0)
            : paramsQlPl(paramsQlPl0),
              paramsPl(paramsPl0),
              paramsQl(paramsQl0),
              mPlQHatInvModq(mPlQHatInvModq0),
              mPlQHatInvModqPrecon(mPlQHatInvModqPrecon0),
              qInvModp(qInvModp0),
              modpBarrettMu(modpBarrettMu0),
              PlHatInvModp(PlHatInvModp0),
              PlHatInvModpPrecon(PlHatInvModpPrecon0),
              PlHatModq(PlHatModq0),
              alphaPlModq(alphaPlModq0),
              modqBarrettMu(modqBarrettMu0),
              pInv(pInv0) {}
        // clang-format on
    };
    typedef struct CRTBasisExtensionPrecomputations CRTBasisExtensionPrecomputations;

    virtual void FastExpandCRTBasisPloverQ(const CRTBasisExtensionPrecomputations& precomputed) = 0;

    virtual void ExpandCRTBasisQlHat(const std::shared_ptr<Params>& paramsQ,
                                     const std::vector<NativeInteger>& QlHatModq,
                                     const std::vector<NativeInteger>& QlHatModqPrecon, const usint sizeQ) = 0;

    /**
   * @brief Performs scale and round:
   * {X}_{Q} -> {\round(t/Q*X)}_t
   * {Q} = {q_1,...,q_l}
   * {P} = {p_1,...,p_k}
   *
   * Brief algorithm:
   * [\sum_i x_i*[t*QHatInv_i/q_i]_t + Round(\sum_i x_i*{t*QHatInv_i/q_i})]_t
   *
   * Source: Halevi S., Polyakov Y., and Shoup V. An Improved RNS Variant of the
   * BFV Homomorphic Encryption Scheme. Cryptology ePrint Archive, Report
   * 2018/117. (https://eprint.iacr.org/2018/117)
   *
   * @param &t often corresponds to the plaintext modulus
   * @param &tQHatInvModqDivqModt precomputed values for
   * [Floor{t*QHatInv_i/q_i}]_t
   * @param &tQHatInvModqDivqModtPrecon NTL-specific precomputations
   * @param &tQHatInvModqBDivqModt precomputed values for
   * [Floor{t*QHatInv_i*B/q_i}]_t used when CRT moduli are 45..60 bits long
   * @param &tQHatInvBDivqModtPrecon NTL-specific precomputations
   * used when CRT moduli are 45..60 bits long
   * @param &tQHatInvModqDivqFrac precomputed values for Frac{t*QHatInv_i/q_i}
   * @param &tQHatInvBDivqFrac precomputed values for Frac{t*QHatInv_i*B/q_i}
   * used when CRT moduli are 45..60 bits long
   * @return the result of computation as a polynomial with native 64-bit
   * coefficients
   */
    virtual TowerType ScaleAndRound(const NativeInteger& t, const std::vector<NativeInteger>& tQHatInvModqDivqModt,
                                    const std::vector<NativeInteger>& tQHatInvModqDivqModtPrecon,
                                    const std::vector<NativeInteger>& tQHatInvModqBDivqModt,
                                    const std::vector<NativeInteger>& tQHatInvModqBDivqModtPrecon,
                                    const std::vector<double>& tQHatInvModqDivqFrac,
                                    const std::vector<double>& tQHatInvModqBDivqFrac) const = 0;

    /**
   * @brief Computes approximate scale and round:
   * {X}_{Q,P} -> {\approx{t/Q * X}}_{P}
   * {Q} = {q_1,...,q_l}
   * {P} = {p_1,...,p_k}
   *
   * Brief algorithm:
   * Let S = {Q,P}
   * 1) [\sum_k x_k * alpha_k]_{p_j}
   * 2) alpha_k = [Floor[t*P*[[SHatInv_k]_{s_k}/s_k]]_{p_j}
   *
   * Source: Halevi S., Polyakov Y., and Shoup V. An Improved RNS Variant of the
   * BFV Homomorphic Encryption Scheme. Cryptology ePrint Archive, Report
   * 2018/117. (https://eprint.iacr.org/2018/117)
   *
   * @param &paramsP parameters for the CRT basis {p_1,...,p_k}
   * @param &tPSHatInvModsDivsModp precomputed values for
   * [\floor[t*P*[[SHatInv_k]_{s_k}/s_k]]_{p_j}
   * @param &modpBarretMu 128-bit Barrett reduction precomputed values for
   * p_j
   * @return the result {\approx{t/Q * X}}_{P}
   */
    virtual DerivedType ApproxScaleAndRound(const std::shared_ptr<Params>& paramsP,
                                            const std::vector<std::vector<NativeInteger>>& tPSHatInvModsDivsModp,
                                            const std::vector<DoubleNativeInt>& modpBarretMu) const = 0;

    /**
   * @brief Computes scale and round:
   * {X}_{I,O} -> {t/I * X}_{O}
   * {I} = {i_1,...,i_l}
   * {O} = {o_1,...,o_k}
   * O, the output modulus can be either P or Q, and I is the other one.
   *
   * Brief algorithm:
   * Let S = {I,O}
   * 1) [\sum_k x_k * alpha_k + Round(\sum_k beta_k * x_k)]_{o_j}
   * 2) alpha_k = [Floor[t*O*[[SHatInv_k]_{s_k}/s_k]]_{o_j}
   * 3) beta_k = {t*O*[[SHatInv_k]_{s_k}/s_k}
   *
   * Source: Halevi S., Polyakov Y., and Shoup V. An Improved RNS Variant of the
   * BFV Homomorphic Encryption Scheme. Cryptology ePrint Archive, Report
   * 2018/117. (https://eprint.iacr.org/2018/117)
   *
   * @param &paramsOutput parameters for the CRT basis {o_1,...,o_k}.
   * @param &tOSHatInvModsDivsModo precomputed values for
   * [\floor[t*O*[[SHatInv_k]_{s_k}/s_k]]_{o_j}
   * @param &tPSHatInvModsDivsFrac precomputed values for
   * {t*O*[[SHatInv_k]_{s_k}/s_k}
   * @param &modoBarretMu 128-bit Barrett reduction precomputed values for
   * o_j
   * @return the result {t/I * X}_{O}
   */
    virtual DerivedType ScaleAndRound(const std::shared_ptr<Params>& paramsOutput,
                                      const std::vector<std::vector<NativeInteger>>& tOSHatInvModsDivsModo,
                                      const std::vector<double>& tOSHatInvModsDivsFrac,
                                      const std::vector<DoubleNativeInt>& modoBarretMu) const = 0;

    /**
   * @brief Computes scale and round for fast rounding:
   * {X}_{Q} -> {\round(t/Q * X)}_t
   * {Q} = {q_1,...,q_l}
   *
   * Brief algorithm:
   *
   * Source: Jean-Claude Bajard and Julien Eynard and Anwar Hasan and Vincent
   * Zucca. A Full RNS Variant of FV like Somewhat Homomorphic Encryption
   * Schemes. Cryptology ePrint Archive: Report 2016/510.
   * (https://eprint.iacr.org/2016/510)
   *
   * @param &moduliQ moduli {q_1,...,q_l}
   * @param &t often corresponds to the plaintext modulus
   * @param &tgamma t * gamma : t * 2^26 reduction
   * @param &tgammaQHatModq [t*gamma*(Q/q_i)]_{q_i}
   * @param &tgammaQHatModqPrecon NTL-specific precomputations
   * @param &negInvqModtgamma [-q^{-1}]_{t*gamma}
   * @param &negInvqModtgammaPrecon NTL-specific precomputations
   * @return
   */
    virtual TowerType ScaleAndRound(const std::vector<NativeInteger>& moduliQ, const NativeInteger& t,
                                    const NativeInteger& tgamma, const std::vector<NativeInteger>& tgammaQHatModq,
                                    const std::vector<NativeInteger>& tgammaQHatModqPrecon,
                                    const std::vector<NativeInteger>& negInvqModtgamma,
                                    const std::vector<NativeInteger>& negInvqModtgammaPrecon) const = 0;

    /**
   * @brief Computes scale and round for BFV encryption mode EXTENDED:
   * {X}_{Qp} -> {\round(1/p * X)}_Q
   * {Q} = {q_1,...,q_l}
   *
   * Source: Andrey Kim and Yuriy Polyakov and Vincent Zucca. Revisiting Homomorphic Encryption
   * Schemes for Finite Fields. Cryptology ePrint Archive: Report 2021/204.
   * (https://eprint.iacr.org/2021/204.pdf)
   *
   * @param &paramsQ Parameters for moduli {q_1,...,q_l}
   * @param &pInvModq p^{-1}_{q_i}
   * @return
   */
    virtual void ScaleAndRoundPOverQ(const std::shared_ptr<Params>& paramsQ,
                                     const std::vector<NativeInteger>& pInvModq) = 0;

    /**
   * @brief Expands basis:
   * {X}_{Q} -> {X}_{Q,Bsk,mtilde}
   * mtilde is a redundant modulus used to remove q overflows generated from
   * fast conversion. Outputs the resulting polynomial in CRT/RNS
   * {Q} = {q_1,...,q_l}
   * {Bsk} = {bsk_1,...,bsk_k}
   *
   *
   * Source: Jean-Claude Bajard and Julien Eynard and Anwar Hasan and Vincent
   * Zucca. A Full RNS Variant of FV like Somewhat Homomorphic Encryption
   * Schemes. Cryptology ePrint Archive: Report 2016/510.
   * (https://eprint.iacr.org/2016/510)
   *
   * @param paramsQBsk: container of QBsk moduli and roots on unity
   * @param &moduliQ: basis {Q} = {q_1,q_2,...,q_l}
   * @param &moduliBsk: basis {Bsk U mtilde} ...
   * @param &modbskBarrettMu: 128-bit Barrett reduction precomputed values for
   * bsk_j
   * @param &mtildeQHatInvModq: [mtilde*(Q/q_i)^{-1}]_{q_i}
   * @param &mtildeQHatInvModqPrecon NTL-specific precomputations
   * @param &QHatModbsk: [Q/q_i]_{bsk_j}
   * @param &QHatModmtilde: [Q/q_i]_{mtilde}
   * @param &QModbsk: [Q]_{bsk_j}
   * @param &QModbskPrecon NTL-specific precomputations
   * @param &negQInvModmtilde: [-Q^{-1}]_{mtilde}
   * @param &mtildeInvModbsk: [mtilde^{-1}]_{bsk_j}
   * @param &mtildeInvModbskPrecon NTL-specific precomputations
   */
    virtual void FastBaseConvqToBskMontgomery(
        const std::shared_ptr<Params>& paramsQBsk, const std::vector<NativeInteger>& moduliQ,
        const std::vector<NativeInteger>& moduliBsk, const std::vector<DoubleNativeInt>& modbskBarrettMu,
        const std::vector<NativeInteger>& mtildeQHatInvModq, const std::vector<NativeInteger>& mtildeQHatInvModqPrecon,
        const std::vector<std::vector<NativeInteger>>& QHatModbsk, const std::vector<uint64_t>& QHatModmtilde,
        const std::vector<NativeInteger>& QModbsk, const std::vector<NativeInteger>& QModbskPrecon,
        const uint64_t& negQInvModmtilde, const std::vector<NativeInteger>& mtildeInvModbsk,
        const std::vector<NativeInteger>& mtildeInvModbskPrecon) = 0;

    /**
   * @brief Computes scale and floor:
   * {X}_{Q,Bsk} -> {\floor{t/Q * X}}_{Bsk}
   * {Q} = {q_1,...,q_l}
   * {Bsk} = {bsk_1,...,bsk_k}
   * Outputs the resulting polynomial in CRT/RNS
   *
   * Source: Jean-Claude Bajard and Julien Eynard and Anwar Hasan and Vincent
   * Zucca. A Full RNS Variant of FV like Somewhat Homomorphic Encryption
   * Schemes. Cryptology ePrint Archive: Report 2016/510.
   * (https://eprint.iacr.org/2016/510)
   *
   * @param &t: plaintext modulus
   * @param &moduliQ: {Q} = {q_1,...,q_l}
   * @param &moduliBsk: {Bsk} = {bsk_1,...,bsk_k}
   * @param &modbskBarrettMu: 128-bit Barrett reduction precomputed values for
   * bsk_j
   * @param &tQHatInvModq: [(Q/q_i)^{-1}]_{q_i}
   * @param &tQHatInvModqPrecon: NTL-specific precomputations
   * @param &QHatModbsk: [Q/q_i]_{bsk_i}
   * @param &qInvModbsk: [(q_i)^{-1}]_{bsk_j}
   * @param &tQInvModbsk: [t*Q^{-1}]_{bsk_j}
   * @param &tQInvModbskPrecon: NTL-specific precomputations
   */
    virtual void FastRNSFloorq(
        const NativeInteger& t, const std::vector<NativeInteger>& moduliQ, const std::vector<NativeInteger>& moduliBsk,
        const std::vector<DoubleNativeInt>& modbskBarrettMu, const std::vector<NativeInteger>& tQHatInvModq,
        const std::vector<NativeInteger>& tQHatInvModqPrecon, const std::vector<std::vector<NativeInteger>>& QHatModbsk,
        const std::vector<std::vector<NativeInteger>>& qInvModbsk, const std::vector<NativeInteger>& tQInvModbsk,
        const std::vector<NativeInteger>& tQInvModbskPrecon) = 0;

    /**
   * @brief @brief Converts basis:
   * {X}_{Q,Bsk} -> {X}_{Bsk}
   * {Q} = {q_1,...,q_l}
   * {Bsk} = {bsk_1,...,bsk_k}
   * using Shenoy Kumaresan method.
   * Outputs the resulting polynomial in CRT/RNS
   *
   * Source: Jean-Claude Bajard and Julien Eynard and Anwar Hasan and Vincent
   * Zucca. A Full RNS Variant of FV like Somewhat Homomorphic Encryption
   * Schemes. Cryptology ePrint Archive: Report 2016/510.
   * (https://eprint.iacr.org/2016/510)
   *
   * Note in the source paper, B is referred to by M.
   *
   * @param &paramsQ: Params for Q
   * @param &modqBarrettMu precomputed Barrett Mu for q_i
   * @param &moduliBsk: basis {Bsk} = {bsk_1,...,bsk_k}
   * @param &modbskBarrettMu: precomputed Barrett Mu for bsk_j
   * @param &BHatInvModb: [(B/b_j)^{-1}]_{b_j}
   * @param &BHatInvModbPrecon NTL precomptations for [(B/b_j)^{-1}]_{b_j}
   * @param &BHatModmsk: [B/b_j]_{msk}
   * @param &BInvModmsk: [B^{-1}]_{msk}
   * @param &BInvModmskPrecon NTL precomptation for [B^{-1}]_{msk}
   * @param &BHatModq: [B/b_j]_{q_i}
   * @param &BModq: [B]_{q_i}
   * @param &BModqPrecon NTL precomptations for [B]_{q_i}
   */
    virtual void FastBaseConvSK(
        const std::shared_ptr<Params>& paramsQ, const std::vector<DoubleNativeInt>& modqBarrettMu,
        const std::vector<NativeInteger>& moduliBsk, const std::vector<DoubleNativeInt>& modbskBarrettMu,
        const std::vector<NativeInteger>& BHatInvModb, const std::vector<NativeInteger>& BHatInvModbPrecon,
        const std::vector<NativeInteger>& BHatModmsk, const NativeInteger& BInvModmsk,
        const NativeInteger& BInvModmskPrecon, const std::vector<std::vector<NativeInteger>>& BHatModq,
        const std::vector<NativeInteger>& BModq, const std::vector<NativeInteger>& BModqPrecon) = 0;

    /**
   * @brief Convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT.
   *
   * @warning use @see SetFormat(format) instead
   */
    void SwitchFormat() override = 0;

    /**
   * @brief Sets format to value without performing NTT. Only use if you know what you're doing.
   *
   */
    virtual void OverrideFormat(const Format f) = 0;

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
    void SwitchModulus(const BigIntType& modulus, const BigIntType& rootOfUnity, const BigIntType& modulusArb,
                       const BigIntType& rootOfUnityArb) final {
        OPENFHE_THROW("SwitchModulus not implemented for DCRTPoly");
    }

    /**
   * @brief Switch modulus at tower i and adjust the values
   *
   * @param index is the index for the tower
   * @param &modulus is the modulus to be set
   * @param &rootOfUnity is the corresponding root of unity for the modulus
   * ASSUMPTION: This method assumes that the caller provides the correct
   * rootOfUnity for the modulus
   */
    virtual void SwitchModulusAtIndex(size_t index, const BigIntType& modulus, const BigIntType& rootOfUnity) = 0;

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
    //    virtual double Norm() const override = 0;
    double Norm() const final {
        return PolyLargeType(this->GetDerived().CRTInterpolate()).Norm();
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
        // os << (vec.m_format == EVALUATION ? "EVAL: " : "COEF: ");
        for (usint i = 0; i < vec.GetAllElements().size(); i++) {
            if (i != 0)
                os << std::endl;
            os << i << ": ";
            os << vec.GetAllElements()[i];
        }
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
    friend inline DerivedType operator+(const DerivedType& a, const BigIntType& b) {
        return a.Plus(b);
    }

    /**
   * @brief BigIntType-element addition operator.
   * @param a integer to add.
   * @param b element to add.
   * @return the result of the addition operation.
   */
    friend inline DerivedType operator+(const BigIntType& a, const DerivedType& b) {
        return b.Plus(a);
    }

    /**
   * @brief Element-integer addition operator with CRT integer.
   * @param a first element to add.
   * @param b integer to add.
   * @return the result of the addition operation.
   */
    friend inline DerivedType operator+(const DerivedType& a, const std::vector<BigIntType>& b) {
        return a.Plus(b);
    }

    /**
   * @brief BigIntType-element addition operator with CRT integer.
   * @param a integer to add.
   * @param b element to add.
   * @return the result of the addition operation.
   */
    friend inline DerivedType operator+(const std::vector<BigIntType>& a, const DerivedType& b) {
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
   * @brief Element-integer subtraction operator with CRT integer.
   * @param a first element to subtract.
   * @param b integer to subtract.
   * @return the result of the subtraction operation.
   */
    friend inline DerivedType operator-(const DerivedType& a, const std::vector<BigIntType>& b) {
        return a.Minus(b);
    }

    /**
   * @brief BigIntType-element subtraction operator with CRT integer.
   * @param a integer to subtract.
   * @param b element to subtract.
   * @return the result of the subtraction operation.
   */
    friend inline DerivedType operator-(const std::vector<BigIntType>& a, const DerivedType& b) {
        return b.Minus(a);
    }

    /**
   * @brief Element-integer subtraction operator.
   * @param a element to subtract from.
   * @param b integer to subtract.
   * @return the result of the subtraction operation.
   */
    friend inline DerivedType operator-(const DerivedType& a, const BigIntType& b) {
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
    friend inline DerivedType operator*(const DerivedType& a, const BigIntType& b) {
        return a.Times(b);
    }

    /**
   * @brief Element-CRT number multiplication operator.
   * @param a element to multiply.
   * @param b integer to multiply, in CRT format.
   * @return the result of the multiplication operation.
   */
    friend inline DerivedType operator*(const DerivedType& a, const std::vector<BigIntType>& b) {
        return a.Times(b);
    }

    /**
   * @brief BigIntType-element multiplication operator.
   * @param a integer to multiply.
   * @param b element to multiply.
   * @return the result of the multiplication operation.
   */
    friend inline DerivedType operator*(const BigIntType& a, const DerivedType& b) {
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
   * @brief signed-BigIntType-element multiplication operator.
   * @param a integer to multiply.
   * @param b element to multiply.
   * @return the result of the multiplication operation.
   */
    friend inline DerivedType operator*(int64_t a, const DerivedType& b) {
        return b.Times((NativeInteger::SignedNativeInt)a);
    }
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_LATTICE_HAL_DCRTPOLYINTERFACE_H
