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
  Represents and defines integer lattice element objects in OpenFHE
 */

#ifndef LBCRYPTO_INC_LATTICE_ILELEMENT_H
#define LBCRYPTO_INC_LATTICE_ILELEMENT_H

#include "math/discretegaussiangenerator.h"
#include "math/nbtheory.h"

#include "utils/exception.h"
#include "utils/inttypes.h"
#include "utils/serializable.h"

#include <vector>

namespace lbcrypto {

/**
 * @brief Interface for ideal lattices
 *
 * Every lattice must implement these pure virtuals in order to properly
 * interoperate with OpenFHE PKE. Element is the return type for all of these
 * virtual functions. There is no constructor here in the base class; it
 * contains no data to construct.
 */
template <typename Element, typename VecType>
class ILElement : public Serializable {
    using IntType = typename VecType::Integer;

public:
    /**
   * @brief Clone the object by making a copy of it and returning the copy
   * @return new Element
   */
    virtual Element Clone() const = 0;

    /**
   * @brief Clone the object, but have it contain nothing
   * @return new Element
   */
    virtual Element CloneEmpty() const = 0;

    /**
   * @brief Clones the element's parameters, leaves vector initialized to 0
   * @return new Element
   */
    virtual Element CloneParametersOnly() const = 0;

    /**
   * @brief Clones the element with parameters and with noise for the vector
   * @param dgg
   * @param format
   * @return new Element
   */
    virtual Element CloneWithNoise(const DiscreteGaussianGeneratorImpl<VecType>& dgg, Format format) const = 0;

    /**
   * @brief Standard destructor
   */
    virtual ~ILElement() = default;

    // Assignment operators
    /**
   * @brief Assignment operator that copies elements.
   * @param rhs
   */
    virtual const Element& operator=(const Element& rhs) = 0;
    /**
   * @brief Assignment operator that copies elements.
   * @param rhs
   */
    virtual const Element& operator=(Element&& rhs) = 0;
    /**
   * @brief Assignment operator that copies elements.
   * @param rhs
   */
    virtual const Element& operator=(std::initializer_list<uint64_t> rhs) = 0;

    // GETTERS
    /**
   * @brief Get format of the element
   *
   * @return Format is either COEFFICIENT or EVALUATION
   */
    virtual Format GetFormat() const = 0;

    /**
   * @brief Get the length of the element.
   *
   * @return length
   */
    virtual usint GetLength() const = 0;

    /**
   * @brief Get modulus of the element
   *
   * @return the modulus.
   */
    virtual const IntType& GetModulus() const = 0;

    /**
   * @brief Get the values for the element
   *
   * @return the vector.
   */
    virtual const VecType& GetValues() const = 0;

    /**
   * @brief Get the cyclotomic order
   *
   * @return order
   */
    virtual usint GetCyclotomicOrder() const = 0;

    /**
   * @brief Gets the Value in the Element that is At Index and returns it.
   * This is only implemented for some derived classes, so the default
   * implementation throws an exception
   *
   * @param i is the index.
   * @return will throw an error.
   */
    virtual IntType& at(usint i) {
        OPENFHE_THROW(not_implemented_error, "at not implemented");
    }
    virtual const IntType& at(usint i) const {
        OPENFHE_THROW(not_implemented_error, "const at not implemented");
    }
    virtual IntType& operator[](usint i) {
        OPENFHE_THROW(not_implemented_error, "[] not implemented");
    }
    virtual const IntType& operator[](usint i) const {
        OPENFHE_THROW(not_implemented_error, "const [] not implemented");
    }

    //  virtual NativePoly DecryptionCRTInterpolate(PlaintextModulus ptm) const
    //= 0;

    // OPERATORS
    /**
   * @brief Unary negation on a lattice
   * @return -lattice
   */
    virtual Element operator-() const = 0;

    /**
   * @brief Scalar addition - add an element to the first index only.
   * This operation is only allowed in COEFFICIENT format.
   *
   * @param &element is the element to add entry-wise.
   * @return is the return of the addition operation.
   */
    virtual Element Plus(const IntType& element) const = 0;

    /**
   * @brief Scalar subtraction - subtract an element frp, all entries.
   *
   * @param &element is the element to subtract entry-wise.
   * @return is the return value of the minus operation.
   */
    virtual Element Minus(const IntType& element) const = 0;

    /**
   * @brief Scalar multiplication - multiply all entries.
   *
   * @param &element is the element to multiply entry-wise.
   * @return is the return value of the times operation.
   */
    virtual Element Times(const IntType& element) const = 0;

    /**
   * @brief Scalar multiplication - mulltiply by a signed integer
   *
   * @param &element is the element to multiply entry-wise.
   * @return is the return value of the times operation.
   */
    virtual Element Times(NativeInteger::SignedNativeInt element) const = 0;

    /**
   * @brief Performs an addition operation and returns the result.
   *
   * @param &element is the element to add with.
   * @return is the result of the addition.
   */
    virtual Element Plus(const Element& element) const = 0;

    /**
   * @brief Performs a subtraction operation and returns the result.
   *
   * @param &element is the element to subtract with.
   * @return is the result of the subtraction.
   */
    virtual Element Minus(const Element& element) const = 0;

    /**
   * @brief Performs a multiplication operation and returns the result.
   *
   * @param &element is the element to multiply with.
   * @return is the result of the multiplication.
   */
    virtual Element Times(const Element& element) const = 0;

    // overloaded op= operators
    /**
   * @brief Performs += operation with a BigInteger and returns the result.
   *
   * @param &element is the element to add
   * @return is the result of the addition.
   */
    virtual const Element& operator+=(const IntType& element) = 0;

    /**
   * @brief Performs -= operation with a BigInteger and returns the result.
   *
   * @param &element is the element to subtract
   * @return is the result of the addition.
   */
    virtual const Element& operator-=(const IntType& element) = 0;

    /**
   * @brief Performs *= operation with a BigInteger and returns the result.
   *
   * @param &element is the element to multiply by
   * @return is the result of the multiplication.
   */
    virtual const Element& operator*=(const IntType& element) = 0;

    /**
   * @brief Performs an addition operation and returns the result.
   *
   * @param &element is the element to add
   * @return is the result of the addition.
   */
    virtual const Element& operator+=(const Element& element) = 0;

    /**
   * @brief Performs an subtraction operation and returns the result.
   *
   * @param &element is the element to subtract
   * @return is the result of the addition.
   */
    virtual const Element& operator-=(const Element& element) = 0;

    /**
   * @brief Performs an multiplication operation and returns the result.
   *
   * @param &element is the element to multiply by
   * @return is the result of the multiplication.
   */
    virtual const Element& operator*=(const Element& element) = 0;

    /**
   * @brief Equality operator.  Compares values of element to be compared to.
   * @param element the element to compare to.
   */
    virtual bool operator==(const Element& element) const = 0;

    /**
   * @brief Inequality operator.  Compares values of element to be compared to.
   * @param element the element to compare to.
   */
    inline bool operator!=(const Element& element) const {
        return !(*this == element);
    }

    /**
   * @brief Adds one to every entry of the Element, in place
   */
    virtual void AddILElementOne() = 0;

    /**
   * @brief Performs an automorphism transform operation and returns the result.
   *
   * @param &i is the element to perform the automorphism transform with.
   * @return is the result of the automorphism transform.
   */
    virtual Element AutomorphismTransform(uint32_t i) const = 0;

    /**
   * @brief Performs an automorphism transform operation using precomputed bit
   * reversal indices.
   *
   * @param &i is the element to perform the automorphism transform with.
   * @param &vec a vector with precomputed indices
   * @return is the result of the automorphism transform.
   */
    virtual Element AutomorphismTransform(uint32_t i, const std::vector<uint32_t>& vec) const = 0;

    /**
   * @brief Transpose the ring element using the automorphism operation
   *
   * @return is the result of the transposition.
   */
    virtual Element Transpose() const = 0;

    /**
   * @brief Write the element as \f$ \sum\limits{i=0}^{\lfloor {\log q/base}
   * \rfloor} {(base^i u_i)} \f$ and return the vector of \f$ \left\{u_0,
   * u_1,...,u_{\lfloor {\log q/base} \rfloor} \right\} \in R_{{base}^{\lceil
   * {\log q/base} \rceil}} \f$; This is used as a subroutine in the
   * relinearization procedure.
   *
   * @param baseBits is the number of bits in the base, i.e., base = 2^baseBits
   * @param evalModeAnswer - if true, convert the resultant polynomials to
   * evaluation mode
   * @result is the pointer where the base decomposition vector is stored
   */
    virtual std::vector<Element> BaseDecompose(usint baseBits, bool evalModeAnswer) const = 0;

    /**
   * @brief Scalar division followed by rounding operation - operation on all
   * entries.
   *
   * @param &q is the element to divide entry-wise.
   * @return is the return value of the divide, followed by rounding operation.
   */
    virtual Element DivideAndRound(const IntType& q) const = 0;

    /**
   * @brief Determines if inverse exists
   *
   * @return true if there exists a multiplicative inverse.
   */
    virtual bool InverseExists() const = 0;

    /**
   * @brief Returns the infinity norm, basically the largest value in the ring
   * element.
   *
   * @return the largest value in the ring element.
   */
    virtual double Norm() const = 0;

    /**
   * @brief Returns true if the vector is empty/ m_values==nullptr
   *
   * @return true if the vector is empty and all values nullptr.  false
   * otherwise.
   */
    virtual bool IsEmpty() const = 0;

    /**
   * @brief Make the element Sparse for SHE KeyGen operations.
   * Sets every index not equal to zero mod the wFactor to zero.
   *
   * @param &wFactor ratio between the original element's ring dimension and the
   * new ring dimension.
   */
    virtual void MakeSparse(uint32_t wFactor) = 0;

    /**
   * @brief Calculate Element mod 2
   *
   * @return result of performing a mod-2 operation on the element.
   */
    virtual Element ModByTwo() const = 0;

    /**
   * @brief Calculate and return the Multiplicative Inverse of the element
   * @return the multiplicative inverse of the element, if it exists.
   */
    virtual Element MultiplicativeInverse() const = 0;

    /**
   * @brief Scalar multiplication followed by division and rounding operation -
   * operation on all entries.
   *
   * @param &p is the integer muliplicand.
   * @param &q is the integer divisor.
   * @return is the return value of the multiply, divide and followed by
   * rounding operation.
   */
    virtual Element MultiplyAndRound(const IntType& p, const IntType& q) const = 0;

    /**
   * @brief Calculate a vector of elements by raising the base element to
   * successive powers
   *
   * @param baseBits
   * @return
   */
    virtual std::vector<Element> PowersOfBase(usint baseBits) const = 0;

    /**
   * @brief Mod - perform a modulus operation.
   * Does proper mapping of [-modulus/2, modulus/2) to [0, modulus).
   *
   * @param modulus is the modulus to use.
   * @return is the return value of the modulus.
   */
    virtual Element Mod(const IntType& modulus) const = 0;

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
    virtual void SwitchModulus(const IntType& modulus, const IntType& rootOfUnity, const IntType& modulusArb,
                               const IntType& rootOfUnityArb) = 0;

    /**
   * @brief onvert from Coefficient to CRT or vice versa; calls FFT and inverse FFT.
   */
    virtual void SwitchFormat() = 0;

    /**
   * @brief Sets the format/representation of the element.
   * @param format the format/representation to set.
   */
    inline void SetFormat(const Format format) {
        if (this->GetFormat() != format) {
            this->SwitchFormat();
        }
    }
};

}  // namespace lbcrypto

#endif
