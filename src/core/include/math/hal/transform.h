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
  This file contains the interface for the transforms in each math backend
 */

#ifndef LBCRYPTO_MATH_TRANSFORM_H
#define LBCRYPTO_MATH_TRANSFORM_H

#include "utils/inttypes.h"

#include <complex>
#include <map>
#include <utility>
#include <vector>

#ifndef M_PI
    #define M_PI 3.14159265358979323846
#endif

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Golden Chinese Remainder Transform FFT implementation.
 */
template <typename VecType>
class ChineseRemainderTransformFTTInterface {
    using IntType = typename VecType::Integer;

public:
    /**
   * Copies \p element into \p result and calls NumberTheoreticTransform::ForwardTransformToBitReverseInPlace()
   *
   * Forward Transform in the ring Z_q[X]/(X^n+1) with prime q and power-of-two
   * n s.t. 2n|q-1. Bit reversing indexes.
   *
   * @param[in] &element is the input to the transform of type VecType and length n.
   * @param &rootOfUnity is the 2n-th root of unity in Z_q. Used to precompute
   * the root of unity tables if needed. If rootOfUnity == 0 or 1, then the
   * result == input.
   * @param CycloOrder is 2n, should be a power-of-two or a throw if an error
   * occurs.
   * @param[out] *result is the result of the transform, a VecType should be of the same
   * size as input or a throw of error occurs.
   * @see NumberTheoreticTransform::ForwardTransformToBitReverseInPlace()
   */
    virtual void ForwardTransformToBitReverse(const VecType& element, const IntType& rootOfUnity,
                                              const usint CycloOrder, VecType* result) = 0;

    /**
   * In-place Forward Transform in the ring Z_q[X]/(X^n+1) with prime q and
   * power-of-two n s.t. 2n|q-1. Bit reversing indexes.
   *
   * @param &rootOfUnity is the 2n-th root of unity in Z_q. Used to precompute
   * the root of unity tables if needed. If rootOfUnity == 0 or 1, then the
   * result == input.
   * @param CycloOrder is 2n, should be a power-of-two or a throw if an error
   * occurs.
   * @param[in,out] &element is the input to the transform of type VecType and length n.
   * @return none
   * @see NumberTheoreticTransform::ForwardTransformToBitReverseInPlace()
   */
    virtual void ForwardTransformToBitReverseInPlace(const IntType& rootOfUnity, const usint CycloOrder,
                                                     VecType* element) = 0;

    /**
   * Copies \p element into \p result and calls NumberTheoreticTransform::InverseTransformFromBitReverseInPlace()
   *
   * Inverse Transform in the ring Z_q[X]/(X^n+1) with prime q and power-of-two
   * n s.t. 2n|q-1. Bit reversing indexes.
   *
   * @param &element[in] is the input to the transform of type VecType and length n.
   * @param &rootOfUnity is the 2n-th root of unity in Z_q. Used to precompute
   * the root of unity tables if needed. If rootOfUnity == 0 or 1, then the
   * result == input.
   * @param CycloOrder is 2n, should be a power-of-two or a throw if an error
   * occurs.
   * @param[out] *result is the result of the transform, a VecType should be of the same
   * size as input or a throw if an error occurs.
   * @return none
   * @see NumberTheoreticTransform::InverseTransformFromBitReverseInPlace()
   */
    virtual void InverseTransformFromBitReverse(const VecType& element, const IntType& rootOfUnity,
                                                const usint CycloOrder, VecType* result) = 0;

    /**
   * In-place Inverse Transform in the ring Z_q[X]/(X^n+1) with prime q and
   * power-of-two n s.t. 2n|q-1. Bit reversing indexes.
   *
   * @param &rootOfUnity is the 2n-th root of unity in Z_q. Used to precompute
   * the root of unity tables if needed. If rootOfUnity == 0 or 1, then the
   * result == input.
   * @param CycloOrder is 2n, should be a power-of-two or a throw if an error
   * occurs.
   * @param[in,out] &element is the input/output of the transform of type VecType and length n.
   * @return none
   * @see NumberTheoreticTransform::InverseTransformFromBitReverseInPlace()
   */
    virtual void InverseTransformFromBitReverseInPlace(const IntType& rootOfUnity, const usint CycloOrder,
                                                       VecType* element) = 0;

    /**
   * Precomputation of root of unity tables for transforms in the ring
   * Z_q[X]/(X^n+1)
   *
   * @param &rootOfUnity is the 2n-th root of unity in Z_q. Used to precompute
   * the root of unity tables if needed. If rootOfUnity == 0 or 1, then the
   * result == input.
   * @param CycloOrder is a power-of-two, equal to 2n.
   * @param modulus is q, the prime modulus
   */
    virtual void PreCompute(const IntType& rootOfUnity, const usint CycloOrder, const IntType& modulus) = 0;

    /**
   * Precomputation of root of unity tables for transforms in the ring
   * Z_q[X]/(X^n+1)
   *
   * @param &rootOfUnity is the 2n-th root of unity in Z_q. Used to precompute
   * the root of unity tables if needed. If rootOfUnity == 0 or 1, then the
   * result == input.
   * @param CycloOrder is a power-of-two, equal to 2n.
   * @param &moduliChain is the vector of prime moduli qi such that 2n|qi-1
   */
    virtual void PreCompute(std::vector<IntType>& rootOfUnity, const usint CycloOrder,
                            std::vector<IntType>& moduliChain) = 0;

    /**
   * Reset cached values for the root of unity tables to empty.
   */
    virtual void Reset() = 0;
};

/**
 * @brief Chinese Remainder Transform for arbitrary cyclotomics.
 */
template <typename VecType>
class ChineseRemainderTransformArbInterface {
    using IntType = typename VecType::Integer;

public:
    /**
   * Sets the cyclotomic polynomial.
   *
   */
    virtual void SetCylotomicPolynomial(const VecType& poly, const IntType& mod) = 0;

    /**
   * Forward transform.
   *
   * @param element is the element to perform the transform on.
   * @param root is the 2mth root of unity w.r.t the ring modulus.
   * @param cycloOrder is the cyclotomic order of the ring element.
   * @param bigMod is the addtional modulus needed for NTT operation.
   * @param bigRoot is the addtional root of unity w.r.t bigMod needed for NTT
   * operation.
   * @return is the output result of the transform.
   */
    virtual VecType ForwardTransform(const VecType& element, const IntType& root, const IntType& bigMod,
                                     const IntType& bigRoot, const usint cycloOrder) = 0;

    /**
   * Inverse transform.
   *
   * @param element is the element to perform the transform on.
   * @param root is the 2mth root of unity w.r.t the ring modulus.
   * @param cycloOrder is the cyclotomic order of the ring element.
   * @param bigMod is the addtional modulus needed for NTT operation.
   * @param bigRoot is the addtional root of unity w.r.t bigMod needed for NTT
   * operation.
   * @return is the output result of the transform.
   */
    virtual VecType InverseTransform(const VecType& element, const IntType& root, const IntType& bigMod,
                                     const IntType& bigRoot, const usint cycloOrder) = 0;

    /**
   * Reset cached values for the transform to empty.
   */
    virtual void Reset() = 0;

    /**
   * @brief Precomputes the root of unity and modulus needed for NTT operation
   * in forward Bluestein transform.
   * @param cycloOrder is the cyclotomic order of the polynomial ring.
   * @param modulus is the modulus of the polynomial ring.
   */
    virtual void PreCompute(const usint cyclotoOrder, const IntType& modulus) = 0;

    /**
   * @brief Sets the precomputed root of unity and modulus needed for NTT
   * operation in forward Bluestein transform.
   * @param cycloOrder is the cyclotomic order of the polynomial ring.
   * @param modulus is the modulus of the polynomial ring.
   * @param nttMod is the modulus needed for the NTT operation in forward
   * Bluestein transform.
   * @param nttRoot is the root of unity needed for the NTT operation in forward
   * Bluestein transform.
   */
    virtual void SetPreComputedNTTModulus(usint cyclotoOrder, const IntType& modulus, const IntType& nttMod,
                                          const IntType& nttRoot) = 0;

    /**
   * @brief Sets the precomputed root of unity and modulus needed for NTT
   * operation and computes m_cyclotomicPolyReveseNTTMap,m_cyclotomicPolyNTTMap.
   * Always called after setting the cyclotomic polynomial.
   * @param cycloOrder is the cyclotomic order of the polynomial ring.
   * @param modulus is the modulus of the polynomial ring.
   * @param nttMod is the modulus needed for the NTT operation in forward
   * Bluestein transform.
   * @param nttRoot is the root of unity needed for the NTT operation in forward
   * Bluestein transform.
   */
    virtual void SetPreComputedNTTDivisionModulus(usint cyclotoOrder, const IntType& modulus, const IntType& nttMod,
                                                  const IntType& nttRoot) = 0;

    /**
   * @brief Computes the inverse of the cyclotomic polynomial using
   * Newton-Iteration method.
   * @param cycloPoly is the cyclotomic polynomial.
   * @param modulus is the modulus of the polynomial ring.
   * @return inverse polynomial.
   */
    virtual VecType InversePolyMod(const VecType& cycloPoly, const IntType& modulus, usint power) = 0;

private:
    /**
   * @brief Padding zeroes to a vector
   * @param &element is the input of type VecType to be padded with zeros.
   * @param cycloOrder is the cyclotomic order of the ring
   * @param forward is a flag for forward/inverse transform padding.
   * @return is result vector with &element values with padded zeros to it
   */
    virtual VecType Pad(const VecType& element, const usint cycloOrder, bool forward) = 0;

    /**
   * @brief Dropping elements from a vector
   * @param &element is the input of type VecType.
   * @param cycloOrder is the cyclotomic order of the ring
   * @param forward is a flag for forward/inverse transform dropping.
   * @param &bigMod is a modulus used to precompute the root of unity tables if
   * needed. The tables are used in the inverse dropping computations
   * @param &bigRoot is a root of unity used to precompute the root of unity
   * tables if needed. The tables are used in the inverse dropping computations
   * @return is result vector with &element values with dropped elements from it
   */
    virtual VecType Drop(const VecType& element, const usint cycloOrder, bool forward, const IntType& bigMod,
                         const IntType& bigRoot) = 0;
};
}  // namespace lbcrypto

#endif
