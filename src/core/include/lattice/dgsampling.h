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
  Provides detailed algorithms for G-sampling and perturbation sampling as described in https://eprint.iacr.org/2017/844.pdf,
  https://eprint.iacr.org/2018/946, and "Implementing Token-Based Obfuscation under (Ring) LWE" (not publicly available yet)
 */

#ifndef LBCRYPTO_INC_LATTICE_DGSAMPLING_H
#define LBCRYPTO_INC_LATTICE_DGSAMPLING_H

#include "lattice/field2n.h"

#include "math/matrix.h"
#include "math/nbtheory.h"

#include <memory>
#include <vector>

namespace lbcrypto {

// Statistical error in Gaussian sampling
// corresponds to statistical error of 2^(-80)
const double DG_ERROR = 8.27181e-25;

// Maximum ring dimension to be supported - up to 560 bits in the modulus
const int32_t N_MAX = 16384;

// Smoothing parameter also used as a "standard deviation" for generating error
// polynomials
const double SIGMA = std::sqrt(std::log(2 * N_MAX / DG_ERROR) / M_PI);

// Spectral norm for preimage samples
const double SPECTRAL_CONSTANT = 1.8;
const auto SPECTRAL_BOUND      = [](uint64_t n, uint64_t k, uint64_t base) -> double {
    return SPECTRAL_CONSTANT * (base + 1) * SIGMA * SIGMA * (std::sqrt(n * k) + std::sqrt(2 * n) + 4.7);
};

// Spectral norm for preimage samples - for the case of matrices of ring
// elements
const auto SPECTRAL_BOUND_D = [](uint64_t n, uint64_t k, uint64_t base, uint64_t d) -> double {
    return SPECTRAL_CONSTANT * (base + 1) * SIGMA * SIGMA * (std::sqrt(d * n * k) + std::sqrt(2 * n) + 4.7);
};

/**
 * @brief Utility class containing operations needed for lattice sampling;
 * Sources: https://eprint.iacr.org/2017/844.pdf and
 * https://eprint.iacr.org/2017/308.pdf This construction is based on the
 * hardness of Ring-LWE problem
 */
template <class Element>
class LatticeGaussSampUtility {
public:
    /**
   * Gaussian sampling from lattice for gagdet matrix G, syndrome u, and
   * arbitrary modulus q Discrete sampling variant As described in Figure 2 of
   * https://eprint.iacr.org/2017/308.pdf
   *
   * @param u syndrome (a polynomial)
   * @param sttdev standard deviation
   * @param k number of components in the gadget vector
   * @param q integer modulus
   * @param base base of gadget matrix
   * @param dgg discrete Gaussian generator
   * @param *z a set of k sampled polynomials corresponding to the gadget matrix
   * G; represented as Z^(k x n)
   */
    static void GaussSampGq(const Element& u, double stddev, size_t k, const typename Element::Integer& q, int64_t base,
                            typename Element::DggType& dgg, Matrix<int64_t>* z);

    /**
   * Gaussian sampling from lattice for gagdet matrix G, syndrome u, and
   * arbitrary modulus q Continuous sampling variant As described in Algorithm 3
   * of https://eprint.iacr.org/2017/844.pdf
   *
   * @param u syndrome (a polynomial)
   * @param sttdev standard deviation
   * @param k number of components in the gadget vector
   * @param q integer modulus
   * @param base base of gadget matrix
   * @param dgg discrete Gaussian generator
   * @param *z a set of k sampled polynomials corresponding to the gadget matrix
   * G; represented as Z^(k x n)
   */
    static void GaussSampGqArbBase(const Element& u, double stddev, size_t k, const typename Element::Integer& q,
                                   int64_t base, typename Element::DggType& dgg, Matrix<int64_t>* z);

    /**
   * Subroutine used by ZSampleSigmaP as described Algorithm 4 in
   * https://eprint.iacr.org/2017/844.pdf
   *
   * @param a field element in DFT format
   * @param b field element in DFT format
   * @param d field element in DFT format
   * @param c a vector of field elements in Coefficient format
   * @param dgg discrete Gaussian generator
   * @param p non-spherical perturbation vector; output of the function
   */
    static void ZSampleSigma2x2(const Field2n& a, const Field2n& b, const Field2n& d, const Matrix<Field2n>& c,
                                const typename Element::DggType& dgg, std::shared_ptr<Matrix<int64_t>> p);

    /**
   * Subroutine used by SamplePertSquareMat as described in "Implementing
   * Token-Based Obfuscation under (Ring) LWE"
   *
   * @param A a matrix of field elements in DFT format
   * @param B a matrix of field elements in DFT format
   * @param D a matrix of field elements in DFT format
   * @param C a matrix of field elements in Coefficient format
   * @param dgg discrete Gaussian generator
   * @param *p non-spherical perturbation matrix; output of the function
   */
    static void SampleMat(const Matrix<Field2n>& A, const Matrix<Field2n>& B, const Matrix<Field2n>& D,
                          const Matrix<Field2n>& C, const typename Element::DggType& dgg,
                          std::shared_ptr<Matrix<int64_t>> p);

    /**
   * Subroutine used by ZSampleSigma2x2 as described Algorithm 4 in
   * https://eprint.iacr.org/2017/844.pdf
   *
   * @param f field element in Coefficient format
   * @param c field element in Coefficient format
   * @param dgg discrete Gaussian generator
   * @param n ring dimension used for rejection sampling
   */
    static std::shared_ptr<Matrix<int64_t>> ZSampleF(const Field2n& f, const Field2n& c,
                                                     const typename Element::DggType& dgg, size_t n);

private:
    // subroutine used by GaussSampGq
    // Discrete sampling variant
    // As described in Figure 2 of https://eprint.iacr.org/2017/308.pdf
    static void Perturb(double sigma, size_t k, size_t n, const std::vector<double>& l, const std::vector<double>& h,
                        int64_t base, typename Element::DggType& dgg, std::vector<int64_t>* p);

    // subroutine used by GaussSampGqArbBase
    // Continuous sampling variant
    // As described in Algorithm 3 of https://eprint.iacr.org/2017/844.pdf
    static void PerturbFloat(double sigma, size_t k, size_t n, const std::vector<double>& l,
                             const std::vector<double>& h, int64_t base, typename Element::DggType& dgg,
                             std::vector<double>* p);

    // subroutine used by GaussSampGq
    // As described in Algorithm 3 of https://eprint.iacr.org/2017/844.pdf
    static void SampleC(const Matrix<double>& c, size_t k, size_t n, double sigma, typename Element::DggType& dgg,
                        Matrix<double>* a, std::vector<int64_t>* z);

    // subroutine earlier used by ZSampleF
    // Algorithm utilizes the same permutation algorithm as discussed in
    // https://eprint.iacr.org/2017/844.pdf
    static Matrix<int32_t> Permute(Matrix<int32_t>* p);

    // subroutine used by ZSampleF
    // Algorithm utilizes the same inverse permutation algorithm as discussed in
    // https://eprint.iacr.org/2017/844.pdf
    static void InversePermute(std::shared_ptr<Matrix<int64_t>> p);
};

}  // namespace lbcrypto

#endif
