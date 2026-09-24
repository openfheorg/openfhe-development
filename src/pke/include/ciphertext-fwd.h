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
 * It is a lightweight file to be included where we need the declaration of Ciphertext only
 */
#ifndef SRC_PKE_INCLUDE_CIPHERTEXT_FWD_H_
#define SRC_PKE_INCLUDE_CIPHERTEXT_FWD_H_

#include <cstdint>
#include <memory>
#include <vector>

namespace lbcrypto {

template <typename Element>
class CiphertextImpl;

/**
 * @brief Shared pointer to a mutable ciphertext; this is the type the public API passes around
 * @tparam Element a ring element.
 */
template <typename Element>
using Ciphertext = std::shared_ptr<CiphertextImpl<Element>>;

/**
 * @brief Const shared pointer to a read-only ciphertext, used for input arguments that must not be modified
 * @tparam Element a ring element.
 */
template <typename Element>
using ConstCiphertext = const std::shared_ptr<const CiphertextImpl<Element>>;

/**
 * @brief Non-const shared pointer to a read-only ciphertext; unlike ConstCiphertext it can be stored in std::vector
 * @tparam Element a ring element.
 */
// reqiured for std::vector
template <typename Element>
using ReadOnlyCiphertext = std::shared_ptr<const CiphertextImpl<Element>>;

/**
 * @brief Precomputed encrypted powers (or Chebyshev polynomials) of a ciphertext, reused across several
 * polynomial or Chebyshev-series evaluations of the same input
 *
 * Filled by EvalPowers/EvalChebyPolys and consumed by EvalPolyWithPrecomp/EvalChebyshevSeriesWithPrecomp.
 * For the linear (power-basis) algorithm only powersRe holds x, x^2, ..., x^k. For the Paterson-Stockmeyer
 * algorithm powersRe holds the powers up to degree k, powers2Re holds x^k, x^{2k}, x^{4k}, ..., x^{2^{m-1}k}
 * and power2km1Re holds x^{k(2m-1)}; the Chebyshev variants store T_i(x) in place of x^i. The *Im members hold
 * the same data for the imaginary part of a complex input and are empty otherwise.
 *
 * @tparam Element a ring element.
 */
template <typename Element>
struct seriesPowers {
    /** powers (or Chebyshev polynomials) of degree 1..k of the real part */
    std::vector<Ciphertext<Element>> powersRe;
    /** powers of degree k*2^i, i = 0..m-1, of the real part (Paterson-Stockmeyer only) */
    std::vector<Ciphertext<Element>> powers2Re;
    /** power of degree k*(2m-1) of the real part (Paterson-Stockmeyer only) */
    Ciphertext<Element> power2km1Re;
    /** Paterson-Stockmeyer baby-step degree k */
    uint32_t k;
    /** Paterson-Stockmeyer giant-step count m */
    uint32_t m;
    /** powers (or Chebyshev polynomials) of degree 1..k of the imaginary part; empty for real inputs */
    std::vector<Ciphertext<Element>> powersIm;
    /** powers of degree k*2^i, i = 0..m-1, of the imaginary part (Paterson-Stockmeyer only) */
    std::vector<Ciphertext<Element>> powers2Im;
    /** power of degree k*(2m-1) of the imaginary part (Paterson-Stockmeyer only) */
    Ciphertext<Element> power2km1Im;

    seriesPowers() = default;

    ~seriesPowers() = default;

    /**
     * Constructs the precomputation for the linear algorithm on a real input.
     *
     * @param powers0 powers of degree 1..k
     */
    explicit seriesPowers(const std::vector<Ciphertext<Element>>& powers0) : powersRe(powers0) {}

    /**
     * Constructs the precomputation for the linear algorithm on a complex input.
     *
     * @param powers0 powers of degree 1..k of the real part
     * @param powers1 powers of degree 1..k of the imaginary part
     */
    seriesPowers(const std::vector<Ciphertext<Element>>& powers0, const std::vector<Ciphertext<Element>>& powers1)
        : powersRe(powers0), powersIm(powers1) {}

    /**
     * Constructs the precomputation for the Paterson-Stockmeyer algorithm on a real input.
     *
     * @param powers0 powers of degree 1..k
     * @param powers20 powers of degree k*2^i, i = 0..m-1
     * @param power2km10 power of degree k*(2m-1)
     * @param k0 baby-step degree k
     * @param m0 giant-step count m
     */
    seriesPowers(const std::vector<Ciphertext<Element>>& powers0, const std::vector<Ciphertext<Element>>& powers20,
                 const Ciphertext<Element>& power2km10, uint32_t k0, uint32_t m0)
        : powersRe(powers0), powers2Re(powers20), power2km1Re(power2km10), k(k0), m(m0) {}

    /**
     * Constructs the precomputation for the Paterson-Stockmeyer algorithm on a complex input.
     *
     * @param powers0 powers of degree 1..k of the real part
     * @param powers20 powers of degree k*2^i, i = 0..m-1, of the real part
     * @param power2km10 power of degree k*(2m-1) of the real part
     * @param k0 baby-step degree k
     * @param m0 giant-step count m
     * @param powers1 powers of degree 1..k of the imaginary part
     * @param powers21 powers of degree k*2^i, i = 0..m-1, of the imaginary part
     * @param power2km11 power of degree k*(2m-1) of the imaginary part
     */
    seriesPowers(const std::vector<Ciphertext<Element>>& powers0, const std::vector<Ciphertext<Element>>& powers20,
                 const Ciphertext<Element>& power2km10, uint32_t k0, uint32_t m0,
                 const std::vector<Ciphertext<Element>>& powers1, const std::vector<Ciphertext<Element>>& powers21,
                 const Ciphertext<Element>& power2km11)
        : powersRe(powers0),
          powers2Re(powers20),
          power2km1Re(power2km10),
          k(k0),
          m(m0),
          powersIm(powers1),
          powers2Im(powers21),
          power2km1Im(power2km11) {}
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_CIPHERTEXT_FWD_H_
