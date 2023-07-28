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
  This file contains the linear transform interface functionality for the fixed math backend
 */

#include "config_core.h"
#ifdef WITH_BE2

    #ifndef LBCRYPTO_MATH_HAL_BIGINTFXD_TRANSFORMFXD_H
        #define LBCRYPTO_MATH_HAL_BIGINTFXD_TRANSFORMFXD_H

        #include <map>
        #include <unordered_map>
        #include <mutex>
        #include <vector>
        #include <utility>

        #include "math/hal/transform.h"
        #include "math/hal/bigintfxd/ubintfxd.h"
        #include "math/hal/bigintfxd/mubintvecfxd.h"

/**
 * @namespace bigintfxd
 * The namespace of bigintfxd
 */

namespace bigintfxd {

/**
 * @brief Number Theoretic Transform implementation
 */
template <typename VecType>
class NumberTheoreticTransformFxd {
    using IntType = typename VecType::Integer;

public:
    /**
   * Forward transform in the ring Z_q[X]/(X^n-1).
   *
   * @param &element is the input to the transform of type VecType and length n
   * s.t. n|q-1.
   * @param &rootOfUnityTable is the table with the root of unity powers.
   * @return is the result of the transform, a VecType should be of the same
   * size as input or a throw if an error occurs.
   */
    void ForwardTransformIterative(const VecType& element, const VecType& rootOfUnityTable, VecType* result);

    /**
   * Inverse transform in the ring Z_q[X]/(X^n-1) with prime q and power-of-two
   * n s.t. n|q-1.
   *
   * @param[in,out] &element is the input and output to the transform of type VecType and length n.
   * @param &rootOfUnityTable is the table with the inverse n-th root of unity
   * powers.
   * @return is the result of the transform, a VecType should be of the same
   * size as input or a throw if an error occurs.
   */
    void InverseTransformIterative(const VecType& element, const VecType& rootOfUnityInverseTable, VecType* result);

    /**
   * Copies \p element into \p result and calls ForwardTransformToBitReverseInPlace()
   *
   * Forward transform in the ring Z_q[X]/(X^n+1) with prime q and power-of-two
   * n s.t. 2n|q-1. Bit reversing indexes. [Algorithm 1 in
   * https://eprint.iacr.org/2016/504.pdf]
   *
   * @param[in] &element is the input to the transform of type VecType and length n.
   * @param &rootOfUnityTable is the table with the n-th root of unity powers in
   * bit reverse order.
   * @param[out] *result is the result of the transform, a VecType should be of the same
   * size as input or a throw if an error occurs.
   * @see ForwardTransformToBitReverseInPlace()
   */
    void ForwardTransformToBitReverse(const VecType& element, const VecType& rootOfUnityTable, VecType* result);
    /**
   * In-place forward transform in the ring Z_q[X]/(X^n+1) with prime q and
   * power-of-two n s.t. 2n|q-1. Bit reversing indexes. [Algorithm 1 in
   * https://eprint.iacr.org/2016/504.pdf]
   *
   * @param &rootOfUnityTable is the table with the n-th root of unity powers in
   * bit reverse order.
   * @param &element[in,out] is the input/output of the transform of type VecType and length n.
   * @return none
   */
    void ForwardTransformToBitReverseInPlace(const VecType& rootOfUnityTable, VecType* element);

    /**
   * Copies \p element into \p result and calls ForwardTransformToBitReverseInPlace()
   *
   * Forward transform in the ring Z_q[X]/(X^n+1) with prime q and power-of-two
   * n s.t. 2n|q-1. Bit reversing indexes. The method works for the
   * NativeInteger case based on NTL's modular multiplication. [Algorithm 1 in
   * https://eprint.iacr.org/2016/504.pdf]
   *
   * @param &element is the input to the transform of type VecType and length n.
   * @param &rootOfUnityTable is the table with the root of unity powers in bit
   * reverse order.
   * @param &preconRootOfUnityTable is NTL-specific precomputations for
   * optimized NativeInteger modulo multiplications.
   * @param[out] *result is the result of the transform, a VecType should be of the same
   * size as input or a throw if an error occurs.
   * @return none
   * @see ForwardTransformToBitReverseInPlace()
   */
    void ForwardTransformToBitReverse(const VecType& element, const VecType& rootOfUnityTable,
                                      const VecType& preconRootOfUnityTable, VecType* result);

    /**
   * In-place forward transform in the ring Z_q[X]/(X^n+1) with prime q and
   * power-of-two n s.t. 2n|q-1. Bit reversing indexes. The method works for the
   * NativeInteger case based on NTL's modular multiplication. [Algorithm 1 in
   * https://eprint.iacr.org/2016/504.pdf]
   *
   * @param &rootOfUnityTable is the table with the root of unity powers in bit
   * reverse order.
   * @param &preconRootOfUnityTable is NTL-specific precomputations for
   * optimized NativeInteger modulo multiplications.
   * @param[in,out] &element is the input/output of the transform of type VecType and length n.
   * @return none
   */
    void ForwardTransformToBitReverseInPlace(const VecType& rootOfUnityTable, const VecType& preconRootOfUnityTable,
                                             VecType* element);

    /**
   * Copies \p element into \p result and calls InverseTransformFromBitReverseInPlace()
   *
   * Inverse transform in the ring Z_q[X]/(X^n+1) with prime q and power-of-two
   * n s.t. 2n|q-1. Bit reversing indexes. [Algorithm 2 in
   * https://eprint.iacr.org/2016/504.pdf]
   *
   * @param &element is the input to the transform of type VecType and length n.
   * @param &rootOfUnityInverseTable is the table with the inverse 2n-th root of
   * unity powers in bit reverse order.
   * @param &cycloOrderInv is inverse of n modulo q
   * @param[out] *result is the result of the transform, a VecType should be of the same
   * size as input or a throw if an error occurs.
   * @return none
   * @see InverseTransformFromBitReverseInPlace()
   */
    void InverseTransformFromBitReverse(const VecType& element, const VecType& rootOfUnityInverseTable,
                                        const IntType& cycloOrderInv, VecType* result);

    /**
   * In-place inverse transform in the ring Z_q[X]/(X^n+1) with prime q and
   * power-of-two n s.t. 2n|q-1. Bit reversing indexes. [Algorithm 2 in
   * https://eprint.iacr.org/2016/504.pdf]
   *
   * @param &rootOfUnityInverseTable is the table with the inverse 2n-th root of
   * unity powers in bit reverse order.
   * @param &cycloOrderInv is inverse of n modulo q
   * @param[in,out] &element is the input/output of the transform of type VecType and length n.
   * @return none
   */
    void InverseTransformFromBitReverseInPlace(const VecType& rootOfUnityInverseTable, const IntType& cycloOrderInv,
                                               VecType* element);

    /**
   * Copies \p element into \p result and calls InverseTransformFromBitReverseInPlace()
   *
   * Inverse transform in the ring Z_q[X]/(X^n+1) with prime q and power-of-two
   * n s.t. 2n|q-1. Bit reversing indexes. The method works for the
   * NativeInteger case based on NTL's modular multiplication. [Algorithm 2 in
   * https://eprint.iacr.org/2016/504.pdf]
   *
   * @param &element is the input to the transform of type VecType and length n.
   * @param &rootOfUnityInverseTable is the table with the inverse 2n-th root of
   * unity powers in bit reverse order.
   * @param &preconRootOfUnityInverseTable is NTL-specific precomputations for
   * optimized NativeInteger modulo multiplications.
   * @param &cycloOrderInv is inverse of n modulo q
   * @param &preconCycloOrderInv is NTL-specific precomputations for optimized
   * NativeInteger modulo multiplications.
   * @param *result is the result of the transform, a VecType should be of the same
   * size as input or a throw if an error occurs.
   * @return none.
   * @see InverseTransformFromBitReverseInPlace()
   */
    void InverseTransformFromBitReverse(const VecType& element, const VecType& rootOfUnityInverseTable,
                                        const VecType& preconRootOfUnityInverseTable, const IntType& cycloOrderInv,
                                        const IntType& preconCycloOrderInv, VecType* result);

    /**
   * In-place Inverse transform in the ring Z_q[X]/(X^n+1) with prime q and
   * power-of-two n s.t. 2n|q-1. Bit reversing indexes. The method works for the
   * NativeInteger case based on NTL's modular multiplication. [Algorithm 2 in
   * https://eprint.iacr.org/2016/504.pdf]
   *
   * @param &rootOfUnityInverseTable is the table with the inverse 2n-th root of
   * unity powers in bit reverse order.
   * @param &preconRootOfUnityInverseTable is NTL-specific precomputations for
   * optimized NativeInteger modulo multiplications.
   * @param &cycloOrderInv is inverse of n modulo q
   * @param &preconCycloOrderInv is NTL-specific precomputations for optimized
   * NativeInteger modulo multiplications.
   * @param &element[in,out] is the input/output of the transform of type VecType and length n.
   * @return none
   */
    void InverseTransformFromBitReverseInPlace(const VecType& rootOfUnityInverseTable,
                                               const VecType& preconRootOfUnityInverseTable,
                                               const IntType& cycloOrderInv, const IntType& preconCycloOrderInv,
                                               VecType* element);
};

/**
 * @brief Golden Chinese Remainder Transform FFT implementation.
 */
template <typename VecType>
class ChineseRemainderTransformFTTFxd : public lbcrypto::ChineseRemainderTransformFTTInterface<VecType> {
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
    void ForwardTransformToBitReverse(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder,
                                      VecType* result);

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
    void ForwardTransformToBitReverseInPlace(const IntType& rootOfUnity, const usint CycloOrder, VecType* element);

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
    void InverseTransformFromBitReverse(const VecType& element, const IntType& rootOfUnity, const usint CycloOrder,
                                        VecType* result);

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
    void InverseTransformFromBitReverseInPlace(const IntType& rootOfUnity, const usint CycloOrder, VecType* element);

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
    void PreCompute(const IntType& rootOfUnity, const usint CycloOrder, const IntType& modulus);

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
    void PreCompute(std::vector<IntType>& rootOfUnity, const usint CycloOrder, std::vector<IntType>& moduliChain);

    /**
   * Reset cached values for the root of unity tables to empty.
   */
    void Reset();

    /// map to store the cyclo order inverse with modulus as a key
    /// For inverse FTT, we also need #m_cycloOrderInversePreconTableByModulus (this is to use an N-size NTT for FTT instead of 2N-size NTT).
    static std::map<IntType, VecType> m_cycloOrderInverseTableByModulus;

    /// map to store the cyclo order inverse preconditioned with modulus as a key
    /// Shoup's precomputation of above #m_cycloOrderInverseTableByModulus
    static std::map<IntType, VecType> m_cycloOrderInversePreconTableByModulus;

    /// map to store the forward roots of Unity for NTT, with bits reversed, with modulus as a key (aka twiddle factors)
    static std::map<IntType, VecType> m_rootOfUnityReverseTableByModulus;

    /// map to store inverse roots of unity for iNTT, with bits reversed, with modulus as a key (aka inverse twiddle factors)
    static std::map<IntType, VecType> m_rootOfUnityInverseReverseTableByModulus;

    /// map to store Shoup's precomputations of forward roots of unity for NTT, with bits reversed, with modulus as a key
    static std::map<IntType, VecType> m_rootOfUnityPreconReverseTableByModulus;

    /// map to store Shoup's precomputations of inverse rou for iNTT, with bits reversed, with modulus as a key
    static std::map<IntType, VecType> m_rootOfUnityInversePreconReverseTableByModulus;
};

// struct used as a key in BlueStein transform
template <typename IntType>
using ModulusRoot = std::pair<IntType, IntType>;

template <typename IntType>
using ModulusRootPair = std::pair<ModulusRoot<IntType>, ModulusRoot<IntType>>;

/**
 * @brief Bluestein Fast Fourier Transform implementation
 */
template <typename VecType>
class BluesteinFFTFxd {
    using IntType = typename VecType::Integer;

public:
    /**
   * Forward transform.
   *
   * @param element is the element to perform the transform on.
   * @param rootOfUnityTable the root of unity table.
   * @param cycloOrder is the cyclotomic order.
   * @return is the output result of the transform.
   */
    VecType ForwardTransform(const VecType& element, const IntType& root, const usint cycloOrder);
    VecType ForwardTransform(const VecType& element, const IntType& root, const usint cycloOrder,
                             const ModulusRoot<IntType>& nttModulusRoot);

    /**
   *
   * @param a is the input vector to be padded with zeros.
   * @param finalSize is the length of the output vector.
   * @return output vector padded with (finalSize - initial size)additional
   * zeros.
   */
    VecType PadZeros(const VecType& a, const usint finalSize);

    /**
   *
   * @param a is the input vector to be resized.
   * @param lo is lower coefficient index.
   * @param hi is higher coefficient index.
   * @return output vector s.t output vector = a[lo]...a[hi].
   */
    VecType Resize(const VecType& a, usint lo, usint hi);

    // void PreComputeNTTModulus(usint cycloOrder, const std::vector<IntType>
    // &modulii);

    /**
   * @brief Precomputes the modulus needed for NTT operation in forward
   * Bluestein transform.
   * @param cycloOrder is the cyclotomic order of the polynomial.
   * @param modulus is the modulus of the polynomial.
   */
    void PreComputeDefaultNTTModulusRoot(usint cycloOrder, const IntType& modulus);

    /**
   * @brief Precomputes the root of unity table needed for NTT operation in
   * forward Bluestein transform.
   * @param cycloOrder is the cyclotomic order of the polynomial ring.
   * @param modulus is the modulus of the polynomial.
   */
    void PreComputeRootTableForNTT(usint cycloOrder, const ModulusRoot<IntType>& nttModulusRoot);

    /**
   * @brief precomputes the powers of root used in forward Bluestein transform.
   * @param cycloOrder is the cyclotomic order of the polynomial ring.
   * @param modulus is the modulus of the polynomial ring.
   * @param root is the root of unity s.t. root^2m = 1.
   */
    void PreComputePowers(usint cycloOrder, const ModulusRoot<IntType>& modulusRoot);

    /**
   * @brief precomputes the NTT transform of the power of root of unity used in
   * the Bluestein transform.
   * @param cycloOrder is the cyclotomic order of the polynomial ring.
   * @param modulus is the modulus of the polynomial ring.
   * @param root is the root of unity s.t. root^2m = 1.
   * @param bigMod is the modulus required for the NTT transform.
   * @param bigRoot is the root of unity required for the NTT transform.
   */
    void PreComputeRBTable(usint cycloOrder, const ModulusRootPair<IntType>& modulusRootPair);

    /**
   * Reset cached values for the transform to empty.
   */
    void Reset();

    // map to store the root of unity table with modulus as key.
    static std::map<ModulusRoot<IntType>, VecType> m_rootOfUnityTableByModulusRoot;

    // map to store the root of unity inverse table with modulus as key.
    static std::map<ModulusRoot<IntType>, VecType> m_rootOfUnityInverseTableByModulusRoot;

    // map to store the power of roots as a table with modulus + root of unity as
    // key.
    static std::map<ModulusRoot<IntType>, VecType> m_powersTableByModulusRoot;

    // map to store the forward transform of power table with modulus + root of
    // unity as key.
    static std::map<ModulusRootPair<IntType>, VecType> m_RBTableByModulusRootPair;

private:
    // map to store the precomputed NTT modulus with modulus as key.
    static std::map<IntType, ModulusRoot<IntType>> m_defaultNTTModulusRoot;
};

/**
 * @brief Chinese Remainder Transform for arbitrary cyclotomics.
 */
template <typename VecType>
class ChineseRemainderTransformArbFxd : public lbcrypto::ChineseRemainderTransformArbInterface<VecType> {
    using IntType = typename VecType::Integer;

public:
    /**
   * Sets the cyclotomic polynomial.
   *
   */
    void SetCylotomicPolynomial(const VecType& poly, const IntType& mod);

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
    VecType ForwardTransform(const VecType& element, const IntType& root, const IntType& bigMod, const IntType& bigRoot,
                             const usint cycloOrder);

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
    VecType InverseTransform(const VecType& element, const IntType& root, const IntType& bigMod, const IntType& bigRoot,
                             const usint cycloOrder);

    /**
   * Reset cached values for the transform to empty.
   */
    void Reset();

    /**
   * @brief Precomputes the root of unity and modulus needed for NTT operation
   * in forward Bluestein transform.
   * @param cycloOrder is the cyclotomic order of the polynomial ring.
   * @param modulus is the modulus of the polynomial ring.
   */
    void PreCompute(const usint cyclotoOrder, const IntType& modulus);

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
    void SetPreComputedNTTModulus(usint cyclotoOrder, const IntType& modulus, const IntType& nttMod,
                                  const IntType& nttRoot);

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
    void SetPreComputedNTTDivisionModulus(usint cyclotoOrder, const IntType& modulus, const IntType& nttMod,
                                          const IntType& nttRoot);

    /**
   * @brief Computes the inverse of the cyclotomic polynomial using
   * Newton-Iteration method.
   * @param cycloPoly is the cyclotomic polynomial.
   * @param modulus is the modulus of the polynomial ring.
   * @return inverse polynomial.
   */
    VecType InversePolyMod(const VecType& cycloPoly, const IntType& modulus, usint power);

private:
    /**
   * @brief Padding zeroes to a vector
   * @param &element is the input of type VecType to be padded with zeros.
   * @param cycloOrder is the cyclotomic order of the ring
   * @param forward is a flag for forward/inverse transform padding.
   * @return is result vector with &element values with padded zeros to it
   */
    VecType Pad(const VecType& element, const usint cycloOrder, bool forward);

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
    VecType Drop(const VecType& element, const usint cycloOrder, bool forward, const IntType& bigMod,
                 const IntType& bigRoot);

    // map to store the cyclotomic polynomial with polynomial ring's modulus as
    // key.
    static std::map<IntType, VecType> m_cyclotomicPolyMap;

    // map to store the forward NTT transform of the inverse of cyclotomic
    // polynomial with polynomial ring's modulus as key.
    static std::map<IntType, VecType> m_cyclotomicPolyReverseNTTMap;

    // map to store the forward NTT transform of the cyclotomic polynomial with
    // polynomial ring's modulus as key.
    static std::map<IntType, VecType> m_cyclotomicPolyNTTMap;

    // map to store the root of unity table used in NTT based polynomial division.
    static std::map<IntType, VecType> m_rootOfUnityDivisionTableByModulus;

    // map to store the root of unity table for computing forward NTT of inverse
    // cyclotomic polynomial used in NTT based polynomial division.
    static std::map<IntType, VecType> m_rootOfUnityDivisionInverseTableByModulus;

    // modulus used in NTT based polynomial division.
    static std::map<IntType, IntType> m_DivisionNTTModulus;

    // root of unity used in NTT based polynomial division.
    static std::map<IntType, IntType> m_DivisionNTTRootOfUnity;

    // dimension of the NTT transform in NTT based polynomial division.
    static std::map<usint, usint> m_nttDivisionDim;
};

}  // namespace bigintfxd

        #include "math/hal/bigintfxd/transformfxd-impl.h"

    #endif

#endif
