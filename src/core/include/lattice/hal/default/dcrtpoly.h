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
  Represents integer lattice elements with double-CRT
 */

#ifndef LBCRYPTO_LATTICE_DCRTPOLY_H
#define LBCRYPTO_LATTICE_DCRTPOLY_H

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "math/hal.h"

#include "utils/inttypes.h"
#include "utils/exception.h"

#include "lattice/ildcrtparams.h"
#include "lattice/hal/dcrtpoly-interface.h"
#include "math/distrgen.h"

namespace lbcrypto {

/**
 * @brief Ideal lattice for the double-CRT representation.
 * The implementation contains a vector of underlying native-integer lattices
 * The double-CRT representation of polynomials is a common optimization for
 * lattice encryption operations. Basically, it allows large-modulus polynomials
 * to be represented as multiple smaller-modulus polynomials.  The double-CRT
 * representations are discussed theoretically here:
 *   - Gentry C., Halevi S., Smart N.P. (2012) Homomorphic Evaluation of the AES
 * Circuit. In: Safavi-Naini R., Canetti R. (eds) Advances in Cryptology –
 * CRYPTO 2012. Lecture Notes in Computer Science, vol 7417. Springer, Berlin,
 * Heidelberg
 */
template <typename VecType>
class DCRTPolyImpl : public DCRTPolyInterface<DCRTPolyImpl<VecType>, VecType, NativeVector, PolyImpl> {
public:
    using Integer = typename VecType::Integer;
    using Params  = ILDCRTParams<Integer>;

    typedef VecType Vector;

    typedef DCRTPolyImpl<VecType> DCRTPolyType;

    // Shorthand for the templated base class
    using DCRTPolyInterfaceType = DCRTPolyInterface<DCRTPolyImpl<VecType>, VecType, NativeVector, PolyImpl>;

    using DggType = typename DCRTPolyInterfaceType::DggType;
    using DugType = typename DCRTPolyInterfaceType::DugType;
    using TugType = typename DCRTPolyInterfaceType::TugType;
    using BugType = typename DCRTPolyInterfaceType::BugType;

    // this class contains an array of these, aka NativePoly
    // warning, this has been removed before but lattice/backend.h can't be included
    // as this creates a circular dependency. PolyType can be thought of as a
    // forward declaration of the NativePoly type.
    using PolyType = PolyImpl<NativeVector>;

    // the composed polynomial type
    typedef PolyImpl<VecType> PolyLargeType;

    static const std::string GetElementName() {
        return "DCRTPolyImpl";
    }

    // CONSTRUCTORS

    /**
   * @brief Constructor that initialized m_format to EVALUATION and calls
   * m_params to nothing
   */
    DCRTPolyImpl();

    /**
   * Constructor that initializes parameters.
   *
   *@param params parameter set required for DCRTPoly.
   *@param format the input format fixed to EVALUATION. Format is a enum type
   *that indicates if the polynomial is in Evaluation representation or
   *Coefficient representation. It is defined in inttypes.h.
   *@param initializeElementToZero
   */
    DCRTPolyImpl(const std::shared_ptr<Params> params, Format format = EVALUATION,
                 bool initializeElementToZero = false);

    const DCRTPolyType& operator=(const PolyLargeType& element);

    const DCRTPolyType& operator=(const PolyType& element) override;

    /**
   * @brief Constructor based on discrete Gaussian generator.
   *
   * @param &dgg the input discrete Gaussian generator. The dgg will be the seed
   * to populate the towers of the DCRTPoly with random numbers.
   * @param params parameter set required for DCRTPoly.
   * @param format the input format fixed to EVALUATION. Format is a enum type
   * that indicates if the polynomial is in Evaluation representation or
   * Coefficient representation. It is defined in inttypes.h.
   */
    DCRTPolyImpl(const DggType& dgg, const std::shared_ptr<Params> params, Format format = EVALUATION);

    /**
   * @brief Constructor based on binary distribution generator. This is not
   * implemented. Will throw an error.
   *
   * @param &bug the input binary uniform generator. The bug will be the seed to
   * populate the towers of the DCRTPoly with random numbers.
   * @param params parameter set required for DCRTPoly.
   * @param format the input format fixed to EVALUATION. Format is a enum type
   * that indicates if the polynomial is in Evaluation representation or
   * Coefficient representation. It is defined in inttypes.h.
   */
    DCRTPolyImpl(const BugType& bug, const std::shared_ptr<Params> params, Format format = EVALUATION);

    /**
   * @brief Constructor based on ternary distribution generator.
   *
   * @param &tug the input ternary uniform generator. The bug will be the seed
   * to populate the towers of the DCRTPoly with random numbers.
   * @param params parameter set required for DCRTPoly.
   * @param format the input format fixed to EVALUATION. Format is a enum type
   * that indicates if the polynomial is in Evaluation representation or
   * Coefficient representation. It is defined in inttypes.h.
   * @param h - Hamming weight for sparse ternary distribution (by default, when
   * h = 0, the distribution is NOT sparse)
   */
    DCRTPolyImpl(const TugType& tug, const std::shared_ptr<Params> params, Format format = EVALUATION, uint32_t h = 0);

    /**
   * @brief Constructor based on discrete uniform generator.
   *
   * @param &dug the input discrete Uniform Generator.
   * @param params the input params.
   * @param &format the input format fixed to EVALUATION. Format is a enum type
   * that indicates if the polynomial is in Evaluation representation or
   * Coefficient representation. It is defined in inttypes.h.
   */
    DCRTPolyImpl(DugType& dug, const std::shared_ptr<Params> params, Format format = EVALUATION);

    /**
   * @brief Construct using a single Poly. The Poly is copied into every tower.
   * Each tower will be reduced to it's corresponding modulus  via GetModuli(at
   * tower index). The format is derived from the passed in Poly.
   *
   * @param &element Poly to build other towers from.
   * @param params parameter set required for DCRTPoly.
   */
    DCRTPolyImpl(const PolyLargeType& element, const std::shared_ptr<Params> params);

    /**
   * @brief Construct using a single PolyType. The PolyType is copied into
   * every tower. Each tower will be reduced to it's corresponding modulus  via
   * GetModuli(at tower index). The format is derived from the passed in
   * PolyType.
   *
   * @param &element Poly to build other towers from.
   * @param params parameter set required for DCRTPoly.
   */
    DCRTPolyImpl(const PolyType& element, const std::shared_ptr<Params> params);

    /**
   * @brief Construct using an tower of ILVectro2ns. The params and format for
   * the DCRTPoly will be derived from the towers.
   *
   * @param &towers vector of Polys which correspond to each tower of DCRTPoly.
   */
    explicit DCRTPolyImpl(const std::vector<PolyType>& elements);

    /**
   * @brief Copy constructor.
   *
   * @param &element DCRTPoly to copy from
   */
    DCRTPolyImpl(const DCRTPolyType& element);  // NOLINT

    /**
   * @brief Move constructor.
   *
   * @param &&element DCRTPoly to move from
   */
    explicit DCRTPolyImpl(const DCRTPolyType&& element);

    // CLONE OPERATIONS
    /**
   * @brief Clone the object by making a copy of it and returning the copy
   * @return new Element
   */
    DCRTPolyType Clone() const override {
        return DCRTPolyImpl(*this);
    }

    /**
   * @brief Makes a copy of the DCRTPoly, but it includes only a sequential
   * subset of the towers that the original holds.
   *
   * @param startTower The index number of the first tower to clone
   * @param endTower The index number of the last tower to clone
   * @return new Element
   */
    DCRTPolyType CloneTowers(uint32_t startTower, uint32_t endTower) const override {
        std::vector<NativeInteger> moduli(endTower - startTower + 1);
        std::vector<NativeInteger> roots(endTower - startTower + 1);

        for (uint32_t i = startTower; i <= endTower; i++) {
            moduli[i - startTower] = this->GetParams()->GetParams()[i]->GetModulus();
            roots[i - startTower]  = this->GetParams()->GetParams()[i]->GetRootOfUnity();
        }

        auto params = DCRTPolyImpl::Params(this->GetCyclotomicOrder(), moduli, roots, {}, {}, 0);

        auto res = DCRTPolyImpl(std::make_shared<typename DCRTPolyImpl::Params>(params), EVALUATION, false);

        for (uint32_t i = startTower; i <= endTower; i++) {
            res.SetElementAtIndex(i - startTower, this->GetElementAtIndex(i));
        }

        return res;
    }

    /**
   * @brief Clone the object, but have it contain nothing
   * @return new Element
   */
    DCRTPolyType CloneEmpty() const override {
        return DCRTPolyImpl();
    }

    /**
   * @brief Clone method creates a new DCRTPoly and clones only the params. The
   * tower values are empty. The tower values can be filled by another
   * process/function or initializer list.
   */
    DCRTPolyType CloneParametersOnly() const override;

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
    DCRTPolyType CloneWithNoise(const DiscreteGaussianGeneratorImpl<VecType>& dgg, Format format) const override;

    /**
   * @brief Destructor.
   */
    ~DCRTPolyImpl();

    // GETTERS

    /**
   * @brief Get interpolated value of elements at all tower index i.
   * Note this operation is computationally intense.
   * @return interpolated value at index i.
   */
    Integer& at(usint i) override;
    const Integer& at(usint i) const override;

    /**
   * @brief Get interpolated value of element at index i.
   * Note this operation is computationally intense.
   * @return interpolated value at index i.
   */
    Integer& operator[](usint i) override;
    const Integer& operator[](usint i) const override;

    /**
   * @brief Get method of individual tower of elements.
   * Note this behavior is different than poly
   * @param i index of tower to be returned.
   * @returns a reference to the returned tower
   */
    const PolyType& GetElementAtIndex(usint i) const override;

    /**
   * @brief Get method of the number of component elements, also known as the
   * number of towers.
   *
   * @return the number of component elements.
   */
    usint GetNumOfElements() const override;

    /**
   * @brief Get method that returns a vector of all component elements.
   *
   * @returns a vector of the component elements.
   */
    const std::vector<PolyType>& GetAllElements() const override;

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
    std::vector<DCRTPolyType> BaseDecompose(usint baseBits, bool evalModeAnswer) const override;

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
   */
    std::vector<DCRTPolyType> PowersOfBase(usint baseBits) const override;

    /**
   * CRT basis decomposition of c as [c qi/q]_qi
   *
   * @param &baseBits bits in the base for additional digit decomposition if
   * base > 0
   * @return is the pointer where the resulting vector is stored
   */
    std::vector<DCRTPolyType> CRTDecompose(uint32_t baseBits) const override;

    // VECTOR OPERATIONS

    /**
   * @brief Assignment Operator.
   *
   * @param &rhs the copied element.
   * @return the resulting element.
   */
    const DCRTPolyType& operator=(const DCRTPolyType& rhs) override;

    /**
   * @brief Move Assignment Operator.
   *
   * @param &rhs the copied element.
   * @return the resulting element.
   */
    const DCRTPolyType& operator=(DCRTPolyType&& rhs) override;

    /**
   * @brief Initalizer list
   *
   * @param &rhs the list to initalized the element.
   * @return the resulting element.
   */
    DCRTPolyType& operator=(std::initializer_list<uint64_t> rhs) override;

    /**
   * @brief Assignment Operator. The usint val will be set at index zero and all
   * other indices will be set to zero.
   *
   * @param val is the usint to assign to index zero.
   * @return the resulting vector.
   */
    DCRTPolyType& operator=(uint64_t val) override;

    /**
   * @brief Creates a Poly from a vector of signed integers (used for trapdoor
   * sampling)
   *
   * @param &rhs the vector to set the PolyImpl to.
   * @return the resulting PolyImpl.
   */
    DCRTPolyType& operator=(const std::vector<int64_t>& rhs) override;

    /**
   * @brief Creates a Poly from a vector of signed integers (used for trapdoor
   * sampling)
   *
   * @param &rhs the vector to set the PolyImpl to.
   * @return the resulting PolyImpl.
   */
    DCRTPolyType& operator=(const std::vector<int32_t>& rhs) override;

    /**
   * @brief Initalizer list
   *
   * @param &rhs the list to set the PolyImpl to.
   * @return the resulting PolyImpl.
   */

    DCRTPolyType& operator=(std::initializer_list<std::string> rhs) override;

    /**
   * @brief Unary minus on a element.
   * @return additive inverse of the an element.
   */
    DCRTPolyType operator-() const override {
        DCRTPolyType all0(this->GetParams(), this->GetFormat(), true);
        return all0 - *this;
    }

    /**
   * @brief Equality operator.
   *
   * @param &rhs is the specified element to be compared with this element.
   * @return true if this element represents the same values as the specified
   * element, false otherwise
   */
    bool operator==(const DCRTPolyType& rhs) const override;

    /**
   * @brief Performs an entry-wise addition over all elements of each tower with
   * the towers of the element on the right hand side.
   *
   * @param &rhs is the element to add with.
   * @return is the result of the addition.
   */
    const DCRTPolyType& operator+=(const DCRTPolyType& rhs) override;

    /**
   * @brief Performs an entry-wise subtraction over all elements of each tower
   * with the towers of the element on the right hand side.
   *
   * @param &rhs is the element to subtract from.
   * @return is the result of the addition.
   */
    const DCRTPolyType& operator-=(const DCRTPolyType& rhs) override;

    /**
   * @brief Permutes coefficients in a polynomial. Moves the ith index to the
   * first one, it only supports odd indices.
   *
   * @param &i is the element to perform the automorphism transform with.
   * @return is the result of the automorphism transform.
   */
    DCRTPolyType AutomorphismTransform(const usint& i) const override {
        DCRTPolyType result(*this);
        for (usint k = 0; k < m_vectors.size(); k++) {
            result.m_vectors[k] = m_vectors[k].AutomorphismTransform(i);
        }
        return result;
    }

    /**
   * @brief Performs an automorphism transform operation using precomputed bit
   * reversal indices.
   *
   * @param &i is the element to perform the automorphism transform with.
   * @param &vec a vector with precomputed indices
   * @return is the result of the automorphism transform.
   */
    DCRTPolyType AutomorphismTransform(usint i, const std::vector<usint>& vec) const override {
        DCRTPolyType result(*this);
        for (usint k = 0; k < m_vectors.size(); k++) {
            result.m_vectors[k] = m_vectors[k].AutomorphismTransform(i, vec);
        }
        return result;
    }

    /**
   * @brief Transpose the ring element using the automorphism operation
   *
   * @return is the result of the transposition.
   */
    DCRTPolyType Transpose() const override {
        if (this->GetFormat() == COEFFICIENT) {
            OPENFHE_THROW(not_implemented_error,
                          "DCRTPolyImpl element transposition is currently "
                          "implemented only in the Evaluation representation.");
        }
        else {
            usint m = this->GetCyclotomicOrder();
            return AutomorphismTransform(m - 1);
        }
    }

    /**
   * @brief Performs an addition operation and returns the result.
   *
   * @param &element is the element to add with.
   * @return is the result of the addition.
   */
    DCRTPolyType Plus(const DCRTPolyType& element) const override;

    /**
   * @brief Performs a multiplication operation and returns the result.
   *
   * @param &element is the element to multiply with.
   * @return is the result of the multiplication.
   */
    DCRTPolyType Times(const DCRTPolyType& element) const override;

    /**
   * @brief Performs a subtraction operation and returns the result.
   *
   * @param &element is the element to subtract from.
   * @return is the result of the subtraction.
   */
    DCRTPolyType Minus(const DCRTPolyType& element) const override;

    // SCALAR OPERATIONS

    /**
   * @brief Scalar addition - add an element to the first index of each tower.
   *
   * @param &element is the element to add entry-wise.
   * @return is the result of the addition operation.
   */
    DCRTPolyType Plus(const Integer& element) const override;

    /**
   * @brief Scalar addition for elements in CRT format.
   * CRT elements are represented as vector of integer elements which
   * correspond to the represented number modulo the primes in the
   * tower chain (in same order).
   *
   * @param &element is the element to add entry-wise.
   * @return is the result of the addition operation.
   */
    DCRTPolyType Plus(const std::vector<Integer>& element) const override;

    /**
   * @brief Scalar subtraction - subtract an element to all entries.
   *
   * @param &element is the element to subtract entry-wise.
   * @return is the return value of the minus operation.
   */
    DCRTPolyType Minus(const Integer& element) const override;

    /**
   * @brief Scalar subtraction for elements in CRT format.
   * CRT elements are represented as vector of integer elements which
   * correspond to the represented number modulo the primes in the
   * tower chain (in same order).
   *
   * @param &element is the element to subtract entry-wise.
   * @return is the result of the subtraction operation.
   */
    DCRTPolyType Minus(const std::vector<Integer>& element) const override;

    /**
   * @brief Scalar multiplication - multiply all entries.
   *
   * @param &element is the element to multiply entry-wise.
   * @return is the return value of the times operation.
   */
    DCRTPolyType Times(const Integer& element) const override;

    /**
   * @brief Scalar multiplication - multiply by a signed integer
   *
   * @param &element is the element to multiply entry-wise.
   * @return is the return value of the times operation.
   */
    DCRTPolyType Times(NativeInteger::SignedNativeInt element) const override;

#if NATIVEINT != 64
    /**
   * @brief Scalar multiplication - multiply by a signed integer
   *
   * @param &element is the element to multiply entry-wise.
   * @return is the return value of the times operation.
   */
    DCRTPolyType Times(int64_t element) const override {
        return Times((NativeInteger::SignedNativeInt)element);
    }
#endif

    /**
   * @brief Scalar multiplication by an integer represented in CRT Basis.
   *
   * @param &element is the element to multiply entry-wise.
   * @return is the return value of the times operation.
   */
    DCRTPolyType Times(const std::vector<NativeInteger>& element) const override;

    /**
   * @brief Performs a multiplication operation even when the multiplicands
   * have a different number of towers.
   *
   * @param &element is the element to multiply with.
   * @return is the result of the multiplication.
   */
    DCRTPolyType TimesNoCheck(const std::vector<NativeInteger>& element) const override;

    /**
   * @brief Scalar modular multiplication by an integer represented in CRT
   * Basis.
   *
   * @param &element is the element to multiply entry-wise.
   * @return is the return value of the times operation.
   */
    DCRTPolyType Times(const std::vector<Integer>& element) const override;

    /**
   * @brief Performs a negation operation and returns the result.
   *
   * @return is the result of the negation.
   */
    DCRTPolyType Negate() const override;

    const DCRTPolyType& operator+=(const Integer& element) override {
        for (usint i = 0; i < this->GetNumOfElements(); i++) {
            this->m_vectors[i] += (element.Mod(this->m_vectors[i].GetModulus())).ConvertToInt();
        }
        return *this;
    }

    /**
   * @brief Performs a subtraction operation and returns the result.
   *
   * @param &element is the element to subtract from.
   * @return is the result of the subtraction.
   */
    const DCRTPolyType& operator-=(const Integer& element) override {
        for (usint i = 0; i < this->GetNumOfElements(); i++) {
            this->m_vectors[i] -= (element.Mod(this->m_vectors[i].GetModulus())).ConvertToInt();
        }
        return *this;
    }

    /**
   * @brief Performs a multiplication operation and returns the result.
   *
   * @param &element is the element to multiply by.
   * @return is the result of the multiplication.
   */
    const DCRTPolyType& operator*=(const Integer& element) override;

    /**
   * @brief Performs an multiplication operation and returns the result.
   *
   * @param &element is the element to multiply with.
   * @return is the result of the multiplication.
   */
    const DCRTPolyType& operator*=(const DCRTPolyType& element) override;

    /**
   * @brief Get value of element at index i.
   *
   * @return value at index i.
   */
    PolyType& ElementAtIndex(usint i) override;

    // multiplicative inverse operation
    /**
   * @brief Performs a multiplicative inverse operation and returns the result.
   *
   * @return is the result of the multiplicative inverse.
   */
    DCRTPolyType MultiplicativeInverse() const override;

    // OTHER FUNCTIONS AND UTILITIES

    /**
   * @brief Sets element at index
   *
   * @param index where the element should be set
   * @param element The element to store
   */
    void SetElementAtIndex(usint index, const PolyType& element) override {
        m_vectors[index] = element;
    }

    /**
   * @brief Sets element at index
   *
   * @param index where the element should be set
   * @param element The element to store
   */
    void SetElementAtIndex(usint index, PolyType&& element) override {
        m_vectors[index] = std::move(element);
    }

    /**
   * @brief Sets all values of element to zero.
   */
    void SetValuesToZero() override;

    /**
   * @brief Adds "1" to every entry in every tower.
   */
    void AddILElementOne() override;

    /**
   * @brief Add uniformly random values to all components except for the first
   * one
   */
    DCRTPolyType AddRandomNoise(const Integer& modulus) const override {
        OPENFHE_THROW(not_implemented_error, "AddRandomNoise is not currently implemented for DCRTPoly");
    }

    /**
   * @brief Make DCRTPoly Sparse. Sets every index of each tower not equal to
   * zero mod the wFactor to zero.
   *
   * @param &wFactor ratio between the sparse and none-sparse values.
   */
    void MakeSparse(const uint32_t& wFactor) override;

    /**
   * @brief Returns true if ALL the tower(s) are empty.
   * @return true if all towers are empty
   */
    bool IsEmpty() const override;

    /**
   * @brief Drops the last element in the double-CRT representation. The
   * resulting DCRTPoly element will have one less tower.
   */
    void DropLastElement() override;

    /**
   * @brief Drops the last i elements in the double-CRT representation.
   */
    void DropLastElements(size_t i) override;

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
    void DropLastElementAndScale(const std::vector<NativeInteger>& QlQlInvModqlDivqlModq,
                                 const std::vector<NativeInteger>& QlQlInvModqlDivqlModqPrecon,
                                 const std::vector<NativeInteger>& qlInvModq,
                                 const std::vector<NativeInteger>& qlInvModqPrecon) override;

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
    void ModReduce(const NativeInteger& t, const std::vector<NativeInteger>& tModqPrecon,
                   const NativeInteger& negtInvModq, const NativeInteger& negtInvModqPrecon,
                   const std::vector<NativeInteger>& qlInvModq,
                   const std::vector<NativeInteger>& qlInvModqPrecon) override;

    /**
   * @brief Interpolates the DCRTPoly to an Poly based on the Chinese Remainder
   * Transform Interpolation. and then returns a Poly with that single element
   *
   * @return the interpolated ring element as a Poly object.
   */
    PolyLargeType CRTInterpolate() const override;

    PolyType DecryptionCRTInterpolate(PlaintextModulus ptm) const override;

    PolyType ToNativePoly() const override;

    /**
   * @brief Interpolates the DCRTPoly to an Poly based on the Chinese Remainder
   * Transform Interpolation, only at element index i, all other elements are
   * zero. and then returns a Poly with that single element
   *
   * @return the interpolated ring element as a Poly object.
   */
    PolyLargeType CRTInterpolateIndex(usint i) const override;

    /**
   * @brief Computes and returns the product of primes in the current moduli
   * chain. Compared to GetModulus, which always returns the product of all
   * primes in the crypto parameters, this method will return a different
   * modulus, based on the towers/moduli that are currently in the chain (some
   * towers are dropped along the way).
   *
   * @return the product of moduli in the current towers.
   */
    Integer GetWorkingModulus() const override;

    /**
   * @brief Returns the element parameters for DCRTPoly elements in an extended
   * CRT basis, which is the concatenation of the towers currently in "this"
   * DCRTPoly, and the moduli in ParamsP.
   *
   * @return element parameters of the extended basis.
   */
    std::shared_ptr<Params> GetExtendedCRTBasis(std::shared_ptr<Params> paramsP) const override;

    void TimesQovert(const std::shared_ptr<Params> paramsQ, const std::vector<NativeInteger>& tInvModq,
                     const NativeInteger& t, const NativeInteger& NegQModt,
                     const NativeInteger& NegQModtPrecon) override;

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
    DCRTPolyType ApproxSwitchCRTBasis(const std::shared_ptr<Params> paramsQ, const std::shared_ptr<Params> paramsP,
                                      const std::vector<NativeInteger>& QHatInvModq,
                                      const std::vector<NativeInteger>& QHatInvModqPrecon,
                                      const std::vector<std::vector<NativeInteger>>& QHatModp,
                                      const std::vector<DoubleNativeInt>& modpBarrettMu) const override;

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
    void ApproxModUp(const std::shared_ptr<Params> paramsQ, const std::shared_ptr<Params> paramsP,
                     const std::shared_ptr<Params> paramsQP, const std::vector<NativeInteger>& QHatInvModq,
                     const std::vector<NativeInteger>& QHatInvModqPrecon,
                     const std::vector<std::vector<NativeInteger>>& QHatModp,
                     const std::vector<DoubleNativeInt>& modpBarrettMu) override;

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
    DCRTPolyType ApproxModDown(
        const std::shared_ptr<Params> paramsQ, const std::shared_ptr<Params> paramsP,
        const std::vector<NativeInteger>& PInvModq, const std::vector<NativeInteger>& PInvModqPrecon,
        const std::vector<NativeInteger>& PHatInvModp, const std::vector<NativeInteger>& PHatInvModpPrecon,
        const std::vector<std::vector<NativeInteger>>& PHatModq, const std::vector<DoubleNativeInt>& modqBarrettMu,
        const std::vector<NativeInteger>& tInvModp, const std::vector<NativeInteger>& tInvModpPrecon,
        const NativeInteger& t, const std::vector<NativeInteger>& tModqPrecon) const override;

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
    DCRTPolyType SwitchCRTBasis(const std::shared_ptr<Params> paramsP, const std::vector<NativeInteger>& QHatInvModq,
                                const std::vector<NativeInteger>& QHatInvModqPrecon,
                                const std::vector<std::vector<NativeInteger>>& QHatModp,
                                const std::vector<std::vector<NativeInteger>>& alphaQModp,
                                const std::vector<DoubleNativeInt>& modpBarrettMu,
                                const std::vector<double>& qInv) const override;

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
    void ExpandCRTBasis(const std::shared_ptr<Params> paramsQP, const std::shared_ptr<Params> paramsP,
                        const std::vector<NativeInteger>& QHatInvModq,
                        const std::vector<NativeInteger>& QHatInvModqPrecon,
                        const std::vector<std::vector<NativeInteger>>& QHatModp,
                        const std::vector<std::vector<NativeInteger>>& alphaQModp,
                        const std::vector<DoubleNativeInt>& modpBarrettMu, const std::vector<double>& qInv,
                        Format resultFormat) override;

    /**
   * @brief Performs modulus raising in reverse order:
   * {X}_{Q} -> {X}_{P,Q}
   */
    void ExpandCRTBasisReverseOrder(const std::shared_ptr<Params> paramsQP, const std::shared_ptr<Params> paramsP,
                                    const std::vector<NativeInteger>& QHatInvModq,
                                    const std::vector<NativeInteger>& QHatInvModqPrecon,
                                    const std::vector<std::vector<NativeInteger>>& QHatModp,
                                    const std::vector<std::vector<NativeInteger>>& alphaQModp,
                                    const std::vector<DoubleNativeInt>& modpBarrettMu, const std::vector<double>& qInv,
                                    Format resultFormat) override;

    struct CRTBasisExtensionPrecomputations {
        const std::shared_ptr<DCRTPolyImpl::Params> paramsQlPl;
        const std::shared_ptr<DCRTPolyImpl::Params> paramsPl;
        const std::shared_ptr<DCRTPolyImpl::Params> paramsQl;
        const std::vector<NativeInteger> mPlQHatInvModq;
        const std::vector<NativeInteger> mPlQHatInvModqPrecon;
        const std::vector<std::vector<NativeInteger>> qInvModp;
        const std::vector<DoubleNativeInt> modpBarrettMu;
        const std::vector<NativeInteger> PlHatInvModp;
        const std::vector<NativeInteger> PlHatInvModpPrecon;
        const std::vector<std::vector<NativeInteger>> PlHatModq;
        const std::vector<std::vector<NativeInteger>> alphaPlModq;
        const std::vector<DoubleNativeInt> modqBarrettMu;
        const std::vector<double> pInv;

        // clang-format off
        CRTBasisExtensionPrecomputations(
            const std::shared_ptr<DCRTPolyImpl::Params> paramsQlPl0,
            const std::shared_ptr<DCRTPolyImpl::Params> paramsPl0,
            const std::shared_ptr<DCRTPolyImpl::Params> paramsQl0,
            const std::vector<NativeInteger> mPlQHatInvModq0,
            const std::vector<NativeInteger> mPlQHatInvModqPrecon0,
            const std::vector<std::vector<NativeInteger>> qInvModp0,
            const std::vector<DoubleNativeInt> modpBarrettMu0,
            const std::vector<NativeInteger> PlHatInvModp0,
            const std::vector<NativeInteger> PlHatInvModpPrecon0,
            const std::vector<std::vector<NativeInteger>> PlHatModq0,
            const std::vector<std::vector<NativeInteger>> alphaPlModq0,
            const std::vector<DoubleNativeInt> modqBarrettMu0,
            const std::vector<double> pInv0)
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
    void FastExpandCRTBasisPloverQ(const CRTBasisExtensionPrecomputations precomputed);

    void ExpandCRTBasisQlHat(const std::shared_ptr<DCRTPolyImpl::Params> paramsQ,
                             const std::vector<NativeInteger>& QlHatModq,
                             const std::vector<NativeInteger>& QlHatModqPrecon, const usint sizeQ);

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
    PolyType ScaleAndRound(const NativeInteger& t, const std::vector<NativeInteger>& tQHatInvModqDivqModt,
                           const std::vector<NativeInteger>& tQHatInvModqDivqModtPrecon,
                           const std::vector<NativeInteger>& tQHatInvModqBDivqModt,
                           const std::vector<NativeInteger>& tQHatInvModqBDivqModtPrecon,
                           const std::vector<double>& tQHatInvModqDivqFrac,
                           const std::vector<double>& tQHatInvModqBDivqFrac) const override;

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
   * @param &modoBarretMu 128-bit Barrett reduction precomputed values for
   * p_j
   * @return the result {\approx{t/Q * X}}_{P}
   */
    DCRTPolyType ApproxScaleAndRound(const std::shared_ptr<Params> paramsP,
                                     const std::vector<std::vector<NativeInteger>>& tPSHatInvModsDivsModp,
                                     const std::vector<DoubleNativeInt>& modpBarretMu) const override;

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
    DCRTPolyType ScaleAndRound(const std::shared_ptr<Params> paramsOutput,
                               const std::vector<std::vector<NativeInteger>>& tOSHatInvModsDivsModo,
                               const std::vector<double>& tOSHatInvModsDivsFrac,
                               const std::vector<DoubleNativeInt>& modoBarretMu) const override;

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
    PolyType ScaleAndRound(const std::vector<NativeInteger>& moduliQ, const NativeInteger& t,
                           const NativeInteger& tgamma, const std::vector<NativeInteger>& tgammaQHatModq,
                           const std::vector<NativeInteger>& tgammaQHatModqPrecon,
                           const std::vector<NativeInteger>& negInvqModtgamma,
                           const std::vector<NativeInteger>& negInvqModtgammaPrecon) const override;

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
    void ScaleAndRoundPOverQ(const std::shared_ptr<DCRTPolyImpl::Params> paramsQ,
                             const std::vector<NativeInteger>& pInvModq) override;

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
   * @param paramsBsk: container of Bsk moduli and roots on unity
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
    void FastBaseConvqToBskMontgomery(
        const std::shared_ptr<Params> paramsBsk, const std::vector<NativeInteger>& moduliQ,
        const std::vector<NativeInteger>& moduliBsk, const std::vector<DoubleNativeInt>& modbskBarrettMu,
        const std::vector<NativeInteger>& mtildeQHatInvModq, const std::vector<NativeInteger>& mtildeQHatInvModqPrecon,
        const std::vector<std::vector<NativeInteger>>& QHatModbsk, const std::vector<uint16_t>& QHatModmtilde,
        const std::vector<NativeInteger>& QModbsk, const std::vector<NativeInteger>& QModbskPrecon,
        const uint16_t& negQInvModmtilde, const std::vector<NativeInteger>& mtildeInvModbsk,
        const std::vector<NativeInteger>& mtildeInvModbskPrecon) override;

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
    void FastRNSFloorq(const NativeInteger& t, const std::vector<NativeInteger>& moduliQ,
                       const std::vector<NativeInteger>& moduliBsk, const std::vector<DoubleNativeInt>& modbskBarrettMu,
                       const std::vector<NativeInteger>& tQHatInvModq,
                       const std::vector<NativeInteger>& tQHatInvModqPrecon,
                       const std::vector<std::vector<NativeInteger>>& QHatModbsk,
                       const std::vector<std::vector<NativeInteger>>& qInvModbsk,
                       const std::vector<NativeInteger>& tQInvModbsk,
                       const std::vector<NativeInteger>& tQInvModbskPrecon) override;

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
    void FastBaseConvSK(const std::shared_ptr<Params> paramsQ, const std::vector<DoubleNativeInt>& modqBarrettMu,
                        const std::vector<NativeInteger>& moduliBsk,
                        const std::vector<DoubleNativeInt>& modbskBarrettMu,
                        const std::vector<NativeInteger>& BHatInvModb,
                        const std::vector<NativeInteger>& BHatInvModbPrecon,
                        const std::vector<NativeInteger>& BHatModmsk, const NativeInteger& BInvModmsk,
                        const NativeInteger& BInvModmskPrecon, const std::vector<std::vector<NativeInteger>>& BHatModq,
                        const std::vector<NativeInteger>& BModq,
                        const std::vector<NativeInteger>& BModqPrecon) override;

    /**
   * @brief Convert from Coefficient to CRT or vice versa; calls FFT and inverse
   * FFT.
   */
    void SwitchFormat() override;

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
                       const Integer& rootOfUnityArb) override {
        OPENFHE_THROW(not_implemented_error, "SwitchModulus not implemented on DCRTPoly");
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
    void SwitchModulusAtIndex(usint index, const Integer& modulus, const Integer& rootOfUnity) override;

    /**
   * @brief Determines if inverse exists
   *
   * @return is the Boolean representation of the existence of multiplicative
   * inverse.
   */
    bool InverseExists() const override;

    /**
   * @brief Returns the infinity norm, basically the largest value in the ring
   * element.
   *
   * @return is the largest value in the ring element.
   */
    double Norm() const override;

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("v", m_vectors));
        ar(::cereal::make_nvp("f", this->m_format));
        ar(::cereal::make_nvp("p", this->m_params));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(::cereal::make_nvp("v", m_vectors));
        ar(::cereal::make_nvp("f", this->m_format));
        ar(::cereal::make_nvp("p", this->m_params));
    }

    std::string SerializedObjectName() const override {
        return "DCRTPoly";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

protected:
    // array of vectors used for double-CRT presentation
    std::vector<PolyType> m_vectors;
};

}  // namespace lbcrypto

#endif
