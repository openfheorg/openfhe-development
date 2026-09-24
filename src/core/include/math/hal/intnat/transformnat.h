//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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
 This file contains the linear transform interface functionality for the native math backend
*/

#ifndef SRC_CORE_INCLUDE_MATH_HAL_INTNAT_TRANSFORMNAT_H_
#define SRC_CORE_INCLUDE_MATH_HAL_INTNAT_TRANSFORMNAT_H_

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <utility>
#include <vector>

#include "math/hal/intnat/mubintvecnat.h"
#include "math/hal/transform.h"
#include "utils/inttypes.h"

/**
 * @namespace intnat
 * The namespace of intnat
 */
namespace intnat {

/**
 * @brief Hash functor for std::pair keys, used by the unordered maps of the transforms.
 */
struct HashPair {
    /**
     * Hashes a pair by combining the std::hash values of its two members.
     *
     * @param p is the pair to hash.
     * @return the combined hash.
     */
    template <class T1, class T2>
    size_t operator()(const std::pair<T1, T2>& p) const {
        auto hash1 = std::hash<T1>{}(std::get<0>(p));
        auto hash2 = std::hash<T2>{}(std::get<1>(p));
        return HashCombine(hash1, hash2);
    }

    /**
     * Combines two hash values (boost::hash_combine formula).
     *
     * @param lhs is the first hash.
     * @param rhs is the second hash.
     * @return the combined hash.
     */
    static size_t HashCombine(size_t lhs, size_t rhs) {
        lhs ^= rhs + 0x9e3779b9 + (lhs << 6) + (lhs >> 2);
        return lhs;
    }
};

/**
 * @brief Number Theoretic Transform implementation
 */
template <typename VecType>
class NumberTheoreticTransformNat {
    using IntType = typename VecType::Integer;

  public:
    /**
     * Forward transform in the ring Z_q[X]/(X^n-1).
     *
     * @param[in] element is the input to the transform of type VecType and length n
     * s.t. n|q-1.
     * @param rootOfUnityTable is the table with the root of unity powers.
     * @param[out] result is the result of the transform, a VecType should be of the same
     * size as input or a throw if an error occurs.
     */
    void ForwardTransformIterative(const VecType& element, const VecType& rootOfUnityTable, VecType* result);

    /**
     * Inverse transform in the ring Z_q[X]/(X^n-1) with prime q and power-of-two
     * n s.t. n|q-1.
     *
     * @param[in] element is the input to the transform of type VecType and length n.
     * @param rootOfUnityInverseTable is the table with the inverse n-th root of unity
     * powers.
     * @param[out] result is the result of the transform, a VecType should be of the same
     * size as input or a throw if an error occurs.
     */
    void InverseTransformIterative(const VecType& element, const VecType& rootOfUnityInverseTable, VecType* result);

    /**
     * Forward transform in the ring Z_q[X]/(X^n-1) taking the Shoup precomputations for the
     * root table; the output is bit-identical to the two-table form.
     *
     * @param[in] element is the input to the transform of type VecType and length n.
     * @param rootOfUnityTable is the table with the root of unity powers.
     * @param preconRootOfUnityTable is the table of Shoup precomputations for rootOfUnityTable.
     * @param[out] result is the result of the transform, a VecType should be of the same
     * size as input or a throw if an error occurs.
     */
    void ForwardTransformIterative(const VecType& element, const VecType& rootOfUnityTable,
                                   const VecType& preconRootOfUnityTable, VecType* result);

    /**
     * Inverse transform in the ring Z_q[X]/(X^n-1) taking the Shoup precomputations for the
     * inverse root table; the output is bit-identical to the two-table form.
     *
     * @param[in] element is the input to the transform of type VecType and length n.
     * @param rootOfUnityInverseTable is the table with the inverse n-th root of unity powers.
     * @param preconRootOfUnityInverseTable is the table of Shoup precomputations for
     * rootOfUnityInverseTable.
     * @param[out] result is the result of the transform, a VecType should be of the same
     * size as input or a throw if an error occurs.
     */
    void InverseTransformIterative(const VecType& element, const VecType& rootOfUnityInverseTable,
                                   const VecType& preconRootOfUnityInverseTable, VecType* result);

    /**
     * Copies \p element into \p result and calls ForwardTransformToBitReverseInPlace()
     *
     * Forward transform in the ring Z_q[X]/(X^n+1) with prime q and power-of-two
     * n s.t. 2n|q-1. Bit reversing indexes. [Algorithm 1 in
     * https://eprint.iacr.org/2016/504.pdf]
     *
     * @param[in] element is the input to the transform of type VecType and length n.
     * @param rootOfUnityTable is the table with the n-th root of unity powers in
     * bit reverse order.
     * @param[out] result is the result of the transform, a VecType should be of the same
     * size as input or a throw if an error occurs.
     * @see ForwardTransformToBitReverseInPlace()
     */
    void ForwardTransformToBitReverse(const VecType& element, const VecType& rootOfUnityTable, VecType* result);
    /**
     * In-place forward transform in the ring Z_q[X]/(X^n+1) with prime q and
     * power-of-two n s.t. 2n|q-1. Bit reversing indexes. [Algorithm 1 in
     * https://eprint.iacr.org/2016/504.pdf]
     *
     * Every coefficient of \p element must already be reduced to [0, modulus). The deferred
     * reduction schedule lets values grow by twice the modulus per stage and folds them back in
     * the peeled final stage, so an unreduced input exceeds the bound that schedule is derived
     * from and the transform returns a wrong result.
     *
     * @param rootOfUnityTable is the table with the n-th root of unity powers in
     * bit reverse order.
     * @param[in,out] element is the input/output of the transform of type VecType and length n.
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
     * @param element is the input to the transform of type VecType and length n.
     * @param rootOfUnityTable is the table with the root of unity powers in bit
     * reverse order.
     * @param preconRootOfUnityTable is NTL-specific precomputations for
     * optimized NativeInteger modulo multiplications.
     * @param[out] result is the result of the transform, a VecType should be of the same
     * size as input or a throw if an error occurs.
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
     * Every coefficient of \p element must already be reduced to [0, modulus), for the reason
     * given on the two-argument overload above.
     *
     * @param rootOfUnityTable is the table with the root of unity powers in bit
     * reverse order.
     * @param preconRootOfUnityTable is NTL-specific precomputations for
     * optimized NativeInteger modulo multiplications.
     * @param[in,out] element is the input/output of the transform of type VecType and length n.
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
     * @param element is the input to the transform of type VecType and length n.
     * @param rootOfUnityInverseTable is the table with the inverse 2n-th root of
     * unity powers in bit reverse order.
     * @param cycloOrderInv is inverse of n modulo q
     * @param[out] result is the result of the transform, a VecType should be of the same
     * size as input or a throw if an error occurs.
     * @see InverseTransformFromBitReverseInPlace()
     */
    void InverseTransformFromBitReverse(const VecType& element, const VecType& rootOfUnityInverseTable,
                                        const IntType& cycloOrderInv, VecType* result);

    /**
     * In-place inverse transform in the ring Z_q[X]/(X^n+1) with prime q and
     * power-of-two n s.t. 2n|q-1. Bit reversing indexes. [Algorithm 2 in
     * https://eprint.iacr.org/2016/504.pdf]
     *
     * @param rootOfUnityInverseTable is the table with the inverse 2n-th root of
     * unity powers in bit reverse order.
     * @param cycloOrderInv is inverse of n modulo q
     * @param[in,out] element is the input/output of the transform of type VecType and length n.
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
     * @param element is the input to the transform of type VecType and length n.
     * @param rootOfUnityInverseTable is the table with the inverse 2n-th root of
     * unity powers in bit reverse order.
     * @param preconRootOfUnityInverseTable is NTL-specific precomputations for
     * optimized NativeInteger modulo multiplications.
     * @param cycloOrderInv is inverse of n modulo q
     * @param preconCycloOrderInv is NTL-specific precomputations for optimized
     * NativeInteger modulo multiplications.
     * @param[out] result is the result of the transform, a VecType should be of the same
     * size as input or a throw if an error occurs.
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
     * @param rootOfUnityInverseTable is the table with the inverse 2n-th root of
     * unity powers in bit reverse order.
     * @param preconRootOfUnityInverseTable is NTL-specific precomputations for
     * optimized NativeInteger modulo multiplications.
     * @param cycloOrderInv is inverse of n modulo q
     * @param preconCycloOrderInv is NTL-specific precomputations for optimized
     * NativeInteger modulo multiplications.
     * @param[in,out] element is the input/output of the transform of type VecType and length n.
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
class ChineseRemainderTransformFTTNat final : public lbcrypto::ChineseRemainderTransformFTTInterface<VecType> {
    using IntType = typename VecType::Integer;

  public:
    /**
     * Copies \p element into \p result and calls NumberTheoreticTransform::ForwardTransformToBitReverseInPlace()
     *
     * Forward Transform in the ring Z_q[X]/(X^n+1) with prime q and power-of-two
     * n s.t. 2n|q-1. Bit reversing indexes.
     *
     * @param[in] element is the input to the transform of type VecType and length n.
     * @param rootOfUnity is the 2n-th root of unity in Z_q. Used to precompute
     * the root of unity tables if needed. If rootOfUnity == 0 or 1, then the
     * result == input.
     * @param CycloOrder is 2n, should be a power-of-two or a throw if an error
     * occurs.
     * @param[out] result is the result of the transform, a VecType should be of the same
     * size as input or a throw of error occurs.
     * @see NumberTheoreticTransform::ForwardTransformToBitReverseInPlace()
     */
    void ForwardTransformToBitReverse(const VecType& element, const IntType& rootOfUnity, const uint32_t CycloOrder,
                                      VecType* result);

    /**
     * In-place Forward Transform in the ring Z_q[X]/(X^n+1) with prime q and
     * power-of-two n s.t. 2n|q-1. Bit reversing indexes.
     *
     * @param rootOfUnity is the 2n-th root of unity in Z_q. Used to precompute
     * the root of unity tables if needed. If rootOfUnity == 0 or 1, then the
     * result == input.
     * @param CycloOrder is 2n, should be a power-of-two or a throw if an error
     * occurs.
     * @param[in,out] element is the input to the transform of type VecType and length n.
     * @see NumberTheoreticTransform::ForwardTransformToBitReverseInPlace()
     */
    void ForwardTransformToBitReverseInPlace(const IntType& rootOfUnity, const uint32_t CycloOrder, VecType* element);

    /**
     * Copies \p element into \p result and calls NumberTheoreticTransform::InverseTransformFromBitReverseInPlace()
     *
     * Inverse Transform in the ring Z_q[X]/(X^n+1) with prime q and power-of-two
     * n s.t. 2n|q-1. Bit reversing indexes.
     *
     * @param[in] element is the input to the transform of type VecType and length n.
     * @param rootOfUnity is the 2n-th root of unity in Z_q. Used to precompute
     * the root of unity tables if needed. If rootOfUnity == 0 or 1, then the
     * result == input.
     * @param CycloOrder is 2n, should be a power-of-two or a throw if an error
     * occurs.
     * @param[out] result is the result of the transform, a VecType should be of the same
     * size as input or a throw if an error occurs.
     * @see NumberTheoreticTransform::InverseTransformFromBitReverseInPlace()
     */
    void InverseTransformFromBitReverse(const VecType& element, const IntType& rootOfUnity, const uint32_t CycloOrder,
                                        VecType* result);

    /**
     * In-place Inverse Transform in the ring Z_q[X]/(X^n+1) with prime q and
     * power-of-two n s.t. 2n|q-1. Bit reversing indexes.
     *
     * @param rootOfUnity is the 2n-th root of unity in Z_q. Used to precompute
     * the root of unity tables if needed. If rootOfUnity == 0 or 1, then the
     * result == input.
     * @param CycloOrder is 2n, should be a power-of-two or a throw if an error
     * occurs.
     * @param[in,out] element is the input/output of the transform of type VecType and length n.
     * @see NumberTheoreticTransform::InverseTransformFromBitReverseInPlace()
     */
    void InverseTransformFromBitReverseInPlace(const IntType& rootOfUnity, const uint32_t CycloOrder, VecType* element);

    /**
     * Precomputation of root of unity tables for transforms in the ring
     * Z_q[X]/(X^n+1)
     *
     * @param rootOfUnity is the 2n-th root of unity in Z_q used to precompute
     * the root of unity tables.
     * @param CycloOrder is a power-of-two, equal to 2n.
     * @param modulus is q, the prime modulus
     */
    void PreCompute(const IntType& rootOfUnity, const uint32_t CycloOrder, const IntType& modulus);

    /**
     * Precomputation of root of unity tables for transforms in the ring
     * Z_q[X]/(X^n+1)
     *
     * @param rootOfUnity is the vector of 2n-th roots of unity, one per modulus
     * in moduliChain, used to precompute the root of unity tables.
     * @param CycloOrder is a power-of-two, equal to 2n.
     * @param moduliChain is the vector of prime moduli qi such that 2n|qi-1
     */
    void PreCompute(std::vector<IntType>& rootOfUnity, const uint32_t CycloOrder, std::vector<IntType>& moduliChain);

    /**
     * Reset cached values for the root of unity tables to empty.
     */
    void Reset();

    /**
     * All precomputed tables for one modulus: the forward/inverse roots of unity in
     * bit-reversed order with their Shoup precomputations, and the cyclotomic-order
     * inverses (indexed by log2 of the transform size) with theirs. Published
     * immutably through a shared_ptr so a transform running on one bundle is
     * unaffected by a concurrent rebuild for the same modulus.
     */
    struct Tables {
        /// forward roots of unity in bit-reversed order
        VecType rootReverse;
        /// Shoup precomputations for rootReverse
        VecType preconRootReverse;
        /// inverse roots of unity in bit-reversed order
        VecType rootInverseReverse;
        /// Shoup precomputations for rootInverseReverse
        VecType preconRootInverseReverse;
        /// inverses of the transform sizes, indexed by log2 of the size
        VecType cycloOrderInverse;
        /// Shoup precomputations for cycloOrderInverse
        VecType preconCycloOrderInverse;
    };

    /**
     * Single lookup-or-build entry for the tables of one modulus: one map traversal
     * per transform instead of one per table, with reads and fills synchronized. The cached
     * bundle is reused when its size matches cycloOrder/2 and rebuilt otherwise.
     *
     * @param rootOfUnity is the 2n-th root of unity modulo modulus used to build the tables.
     * @param CycloOrder is the cyclotomic order (twice the transform size).
     * @param modulus is the modulus the tables are keyed on.
     * @return the immutable table bundle for the modulus.
     */
    static std::shared_ptr<const Tables> GetTables(const IntType& rootOfUnity, uint32_t CycloOrder,
                                                   const IntType& modulus);

  private:
    static std::map<IntType, std::shared_ptr<const Tables>> m_tablesByModulus;

    static std::shared_mutex& TablesMutex() {
        static std::shared_mutex m;
        return m;
    }
};

/// (modulus, root of unity) pair used as a key in the Bluestein transform caches
template <typename IntType>
using ModulusRoot = std::pair<IntType, IntType>;

/// ((modulus, root), (NTT modulus, NTT root)) pair used as a key in the Bluestein transform caches
template <typename IntType>
using ModulusRootPair = std::pair<ModulusRoot<IntType>, ModulusRoot<IntType>>;

/**
 * @brief Bluestein Fast Fourier Transform implementation
 */
template <typename VecType>
class BluesteinFFTNat {
    using IntType = typename VecType::Integer;

  public:
    /**
     * Forward transform.
     *
     * @param element is the element to perform the transform on.
     * @param root is the root of unity w.r.t. the modulus of element used to compute the power table.
     * @param cycloOrder is the cyclotomic order.
     * @return is the output result of the transform.
     */
    VecType ForwardTransform(const VecType& element, const IntType& root, const uint32_t cycloOrder);

    /**
     * Forward transform with an explicit NTT modulus and root; all tables for (modulus of
     * element, root), nttModulusRoot and their pair must have been precomputed by the
     * PreCompute* methods.
     *
     * @param element is the element to perform the transform on; its length must equal cycloOrder.
     * @param root is the root of unity w.r.t. the modulus of element used to compute the power table.
     * @param cycloOrder is the cyclotomic order.
     * @param nttModulusRoot is the (modulus, root of unity) pair of the NTT used internally.
     * @return is the output result of the transform.
     */
    VecType ForwardTransform(const VecType& element, const IntType& root, const uint32_t cycloOrder,
                             const ModulusRoot<IntType>& nttModulusRoot);

    /**
     *
     * @param a is the input vector to be padded with zeros.
     * @param finalSize is the length of the output vector.
     * @return output vector padded with (finalSize - initial size)additional
     * zeros.
     */
    VecType PadZeros(const VecType& a, const uint32_t finalSize);

    /**
     *
     * @param a is the input vector to be resized.
     * @param lo is lower coefficient index.
     * @param hi is higher coefficient index.
     * @return output vector s.t output vector = a[lo]...a[hi].
     */
    VecType Resize(const VecType& a, uint32_t lo, uint32_t hi);

    /**
     * @brief Precomputes the modulus needed for NTT operation in forward
     * Bluestein transform.
     * @param cycloOrder is the cyclotomic order of the polynomial.
     * @param modulus is the modulus of the polynomial.
     */
    void PreComputeDefaultNTTModulusRoot(uint32_t cycloOrder, const IntType& modulus);

    /**
     * @brief Precomputes the root of unity table needed for NTT operation in
     * forward Bluestein transform.
     * @param cycloOrder is the cyclotomic order of the polynomial ring.
     * @param nttModulusRoot is the (modulus, root of unity) pair used for the NTT operation.
     */
    void PreComputeRootTableForNTT(uint32_t cycloOrder, const ModulusRoot<IntType>& nttModulusRoot);

    /**
     * @brief precomputes the powers of root used in forward Bluestein transform.
     * @param cycloOrder is the cyclotomic order of the polynomial ring.
     * @param modulusRoot is the pair (modulus, root) of the polynomial ring's modulus
     * and a root of unity s.t. root^2m = 1.
     */
    void PreComputePowers(uint32_t cycloOrder, const ModulusRoot<IntType>& modulusRoot);

    /**
     * @brief precomputes the NTT transform of the power of root of unity used in
     * the Bluestein transform.
     * @param cycloOrder is the cyclotomic order of the polynomial ring.
     * @param modulusRootPair is the pair ((modulus, root), (bigMod, bigRoot)), where
     * modulus is the modulus of the polynomial ring, root is the root of unity s.t.
     * root^2m = 1, and bigMod and bigRoot are the modulus and root of unity required
     * for the NTT transform.
     */
    void PreComputeRBTable(uint32_t cycloOrder, const ModulusRootPair<IntType>& modulusRootPair);

    /**
     * Reset cached values for the transform to empty.
     */
    void Reset();

    /// map to store the root of unity table with modulus as key.
    static std::map<ModulusRoot<IntType>, VecType> m_rootOfUnityTableByModulusRoot;

    /// map to store the root of unity inverse table with modulus as key.
    static std::map<ModulusRoot<IntType>, VecType> m_rootOfUnityInverseTableByModulusRoot;

    /// map to store the power of roots as a table with modulus + root of unity as
    /// key.
    static std::map<ModulusRoot<IntType>, VecType> m_powersTableByModulusRoot;

    /// map to store the forward transform of power table with modulus + root of
    /// unity as key.
    static std::map<ModulusRootPair<IntType>, VecType> m_RBTableByModulusRootPair;

    /// Shoup precomputations matching m_rootOfUnityTableByModulusRoot.
    static std::map<ModulusRoot<IntType>, VecType> m_preconRootOfUnityTableByModulusRoot;
    /// Shoup precomputations matching m_rootOfUnityInverseTableByModulusRoot.
    static std::map<ModulusRoot<IntType>, VecType> m_preconRootOfUnityInverseTableByModulusRoot;

    /**
     * Mutex guarding every Bluestein/arbitrary-cyclotomic static cache: fills are lazy and the
     * tower loops run in parallel, so lookups must lock as well (references into a std::map
     * stay valid after the lock is released; the map structure does not).
     *
     * @return the shared recursive mutex.
     */
    static std::recursive_mutex& CacheMutex() {
        static std::recursive_mutex m;
        return m;
    }

  private:
    // map to store the precomputed NTT modulus with modulus as key.
    static std::map<IntType, ModulusRoot<IntType>> m_defaultNTTModulusRoot;
};

/**
 * @brief Chinese Remainder Transform for arbitrary cyclotomics.
 */
template <typename VecType>
class ChineseRemainderTransformArbNat final : public lbcrypto::ChineseRemainderTransformArbInterface<VecType> {
    using IntType = typename VecType::Integer;

  public:
    /**
     * Sets the cyclotomic polynomial.
     *
     * @param poly is the cyclotomic polynomial.
     * @param mod is the modulus of the polynomial ring.
     */
    void SetCylotomicPolynomial(const VecType& poly, const IntType& mod);

    /**
     * Forward transform.
     *
     * @param element is the element to perform the transform on.
     * @param root is the 2mth root of unity w.r.t the ring modulus.
     * @param bigMod is the additional modulus needed for NTT operation.
     * @param bigRoot is the additional root of unity w.r.t bigMod needed for NTT
     * operation.
     * @param cycloOrder is the cyclotomic order of the ring element.
     * @return is the output result of the transform.
     */
    VecType ForwardTransform(const VecType& element, const IntType& root, const IntType& bigMod, const IntType& bigRoot,
                             const uint32_t cycloOrder);

    /**
     * Inverse transform.
     *
     * @param element is the element to perform the transform on.
     * @param root is the 2mth root of unity w.r.t the ring modulus.
     * @param bigMod is the additional modulus needed for NTT operation.
     * @param bigRoot is the additional root of unity w.r.t bigMod needed for NTT
     * operation.
     * @param cycloOrder is the cyclotomic order of the ring element.
     * @return is the output result of the transform.
     */
    VecType InverseTransform(const VecType& element, const IntType& root, const IntType& bigMod, const IntType& bigRoot,
                             const uint32_t cycloOrder);

    /**
     * Reset cached values for the transform to empty.
     */
    void Reset();

    /**
     * @brief Precomputes the root of unity and modulus needed for NTT operation
     * in forward Bluestein transform.
     * @param cyclotoOrder is the cyclotomic order of the polynomial ring.
     * @param modulus is the modulus of the polynomial ring.
     */
    void PreCompute(const uint32_t cyclotoOrder, const IntType& modulus);

    /**
     * @brief Sets the precomputed root of unity and modulus needed for NTT
     * operation in forward Bluestein transform.
     * @param cyclotoOrder is the cyclotomic order of the polynomial ring.
     * @param modulus is the modulus of the polynomial ring.
     * @param nttMod is the modulus needed for the NTT operation in forward
     * Bluestein transform.
     * @param nttRoot is the root of unity needed for the NTT operation in forward
     * Bluestein transform.
     */
    void SetPreComputedNTTModulus(uint32_t cyclotoOrder, const IntType& modulus, const IntType& nttMod,
                                  const IntType& nttRoot);

    /**
     * @brief Sets the precomputed root of unity and modulus needed for NTT
     * operation and computes m_cyclotomicPolyReveseNTTMap,m_cyclotomicPolyNTTMap.
     * Always called after setting the cyclotomic polynomial.
     * @param cyclotoOrder is the cyclotomic order of the polynomial ring.
     * @param modulus is the modulus of the polynomial ring.
     * @param nttMod is the modulus needed for the NTT operation in forward
     * Bluestein transform.
     * @param nttRoot is the root of unity needed for the NTT operation in forward
     * Bluestein transform.
     */
    void SetPreComputedNTTDivisionModulus(uint32_t cyclotoOrder, const IntType& modulus, const IntType& nttMod,
                                          const IntType& nttRoot);

    /**
     * @brief Computes the inverse of the cyclotomic polynomial using
     * Newton-Iteration method.
     * @param cycloPoly is the cyclotomic polynomial.
     * @param modulus is the modulus of the polynomial ring.
     * @param power is the number of coefficients of the result; the inverse is computed modulo x^power.
     * @return inverse polynomial.
     */
    VecType InversePolyMod(const VecType& cycloPoly, const IntType& modulus, uint32_t power);

  private:
    /**
     * @brief Padding zeroes to a vector
     * @param element is the input of type VecType to be padded with zeros.
     * @param cycloOrder is the cyclotomic order of the ring
     * @param forward is a flag for forward/inverse transform padding.
     * @return is result vector with &element values with padded zeros to it
     */
    VecType Pad(const VecType& element, const uint32_t cycloOrder, bool forward);

    /**
     * @brief Dropping elements from a vector
     * @param element is the input of type VecType.
     * @param cycloOrder is the cyclotomic order of the ring
     * @param forward is a flag for forward/inverse transform dropping.
     * @param bigMod is a modulus used to precompute the root of unity tables if
     * needed. The tables are used in the inverse dropping computations
     * @param bigRoot is a root of unity used to precompute the root of unity
     * tables if needed. The tables are used in the inverse dropping computations
     * @return is result vector with &element values with dropped elements from it
     */
    VecType Drop(const VecType& element, const uint32_t cycloOrder, bool forward, const IntType& bigMod,
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

    // Shoup precomputations matching the two division tables above.
    static std::map<IntType, VecType> m_rootOfUnityDivisionPreconTableByModulus;
    static std::map<IntType, VecType> m_rootOfUnityDivisionInversePreconTableByModulus;

    // modulus used in NTT based polynomial division.
    static std::map<IntType, IntType> m_DivisionNTTModulus;

    // root of unity used in NTT based polynomial division.
    static std::map<IntType, IntType> m_DivisionNTTRootOfUnity;

    // dimension of the NTT transform in NTT based polynomial division.
    static std::map<uint32_t, uint32_t> m_nttDivisionDim;
};

}  // namespace intnat

#define TRANSFORM_IMPLEMENTATION "math/hal/intnat/transformnat-impl.h"

#define MAKE_TRANSFORM_TYPES                                                      \
    template class intnat::NumberTheoreticTransformNat<intnat::NativeVector>;     \
    template class intnat::ChineseRemainderTransformFTTNat<intnat::NativeVector>; \
    template class intnat::BluesteinFFTNat<intnat::NativeVector>;                 \
    template class intnat::ChineseRemainderTransformArbNat<intnat::NativeVector>;

#define EXTERN_TRANSFORM_TYPES                                                           \
    extern template class intnat::NumberTheoreticTransformNat<intnat::NativeVector>;     \
    extern template class intnat::ChineseRemainderTransformFTTNat<intnat::NativeVector>; \
    extern template class intnat::BluesteinFFTNat<intnat::NativeVector>;                 \
    extern template class intnat::ChineseRemainderTransformArbNat<intnat::NativeVector>;

// Same set at 32-bit width, for use alongside the native width in a 64-bit build.
#define MAKE_TRANSFORM_TYPES32                                                      \
    template class intnat::NumberTheoreticTransformNat<intnat::NativeVector32>;     \
    template class intnat::ChineseRemainderTransformFTTNat<intnat::NativeVector32>; \
    template class intnat::BluesteinFFTNat<intnat::NativeVector32>;                 \
    template class intnat::ChineseRemainderTransformArbNat<intnat::NativeVector32>;

#define EXTERN_TRANSFORM_TYPES32                                                           \
    extern template class intnat::NumberTheoreticTransformNat<intnat::NativeVector32>;     \
    extern template class intnat::ChineseRemainderTransformFTTNat<intnat::NativeVector32>; \
    extern template class intnat::BluesteinFFTNat<intnat::NativeVector32>;                 \
    extern template class intnat::ChineseRemainderTransformArbNat<intnat::NativeVector32>;

EXTERN_TRANSFORM_TYPES
#if NATIVEINT != 32
EXTERN_TRANSFORM_TYPES32
#endif

#endif  // SRC_CORE_INCLUDE_MATH_HAL_INTNAT_TRANSFORMNAT_H_
