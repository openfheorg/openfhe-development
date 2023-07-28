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
  Provides the utility for sampling trapdoor lattices as described in https://eprint.iacr.org/2017/844.pdf,
  https://eprint.iacr.org/2018/946, and "Implementing Token-Based Obfuscation under (Ring) LWE" as described in
  https://eprint.iacr.org/2018/1222.pdf.
 */

#include "lattice/dgsampling-impl.h"
#include "lattice/lat-hal.h"
#include "lattice/trapdoor-impl.h"

#include "math/matrix-impl.h"

#include "utils/debug.h"

namespace lbcrypto {

// Trapdoor generation method as described in Algorithm 1 of
// https://eprint.iacr.org/2017/844.pdf and
// "Implementing Token-Based Obfuscation under (Ring) LWE"
template <>
std::pair<Matrix<DCRTPoly>, RLWETrapdoorPair<DCRTPoly>> RLWETrapdoorUtility<DCRTPoly>::TrapdoorGen(
    std::shared_ptr<ParmType> params, double stddev, int64_t base, bool bal) {
    auto zero_alloc     = DCRTPoly::Allocator(params, Format::EVALUATION);
    auto gaussian_alloc = DCRTPoly::MakeDiscreteGaussianCoefficientAllocator(params, Format::COEFFICIENT, stddev);
    auto uniform_alloc  = DCRTPoly::MakeDiscreteUniformAllocator(params, Format::EVALUATION);

    NativeInteger q = params->GetParams()[0]->GetModulus();

    size_t digitCount = static_cast<size_t>(ceil(log2(q.ConvertToDouble()) / log2(base)));

    size_t k = params->GetParams().size() * digitCount;

    if (bal == true) {
        k++;  // for a balanced digit representation, there is an extra digit
              // required
    }

    auto a = uniform_alloc();

    Matrix<DCRTPoly> r(zero_alloc, 1, k, gaussian_alloc);
    Matrix<DCRTPoly> e(zero_alloc, 1, k, gaussian_alloc);

    // Converts discrete gaussians to Evaluation representation
    r.SetFormat(Format::EVALUATION);
    e.SetFormat(Format::EVALUATION);

    Matrix<DCRTPoly> g = Matrix<DCRTPoly>(zero_alloc, 1, k).GadgetVector(base);

    Matrix<DCRTPoly> A(zero_alloc, 1, k + 2);
    A(0, 0) = 1;
    A(0, 1) = a;

    for (size_t i = 0; i < k; ++i) {
        A(0, i + 2) = g(0, i) - (a * r(0, i) + e(0, i));
    }

    return std::pair<Matrix<DCRTPoly>, RLWETrapdoorPair<DCRTPoly>>(A, RLWETrapdoorPair<DCRTPoly>(r, e));
}

template <>
std::pair<Matrix<DCRTPoly>, RLWETrapdoorPair<DCRTPoly>> RLWETrapdoorUtility<DCRTPoly>::TrapdoorGenSquareMat(
    std::shared_ptr<ParmType> params, double stddev, size_t d, int64_t base, bool bal) {
    auto zero_alloc     = DCRTPoly::Allocator(params, Format::EVALUATION);
    auto gaussian_alloc = DCRTPoly::MakeDiscreteGaussianCoefficientAllocator(params, Format::COEFFICIENT, stddev);
    auto uniform_alloc  = DCRTPoly::MakeDiscreteUniformAllocator(params, Format::EVALUATION);

    NativeInteger q = params->GetParams()[0]->GetModulus();

    size_t digitCount = static_cast<size_t>(ceil(log2(q.ConvertToDouble()) / log2(base)));

    size_t k = params->GetParams().size() * digitCount;

    if (bal == true) {
        k++;  // for a balanced digit representation, there is an extra digit
              // required
    }

    Matrix<DCRTPoly> R(zero_alloc, d, d * k, gaussian_alloc);
    Matrix<DCRTPoly> E(zero_alloc, d, d * k, gaussian_alloc);

    Matrix<DCRTPoly> Abar(zero_alloc, d, d, uniform_alloc);

    // Converts discrete gaussians to Evaluation representation
    R.SetFormat(Format::EVALUATION);
    E.SetFormat(Format::EVALUATION);

    Matrix<DCRTPoly> G = Matrix<DCRTPoly>(zero_alloc, d, d * k).GadgetVector(base);

    Matrix<DCRTPoly> A(zero_alloc, d, d * 2);

    for (size_t i = 0; i < d; i++) {
        for (size_t j = 0; j < d; j++) {
            A(i, j) = Abar(i, j);
            if (i == j)
                A(i, j + d) = 1;
            else
                A(i, j + d) = 0;
        }
    }

    Matrix<DCRTPoly> A1 = G - (Abar * R + E);

    A.HStack(A1);

    return std::pair<Matrix<DCRTPoly>, RLWETrapdoorPair<DCRTPoly>>(A, RLWETrapdoorPair<DCRTPoly>(R, E));
}

// Gaussian sampling as described in Alogorithm 2 of
// https://eprint.iacr.org/2017/844.pdf

template <>
Matrix<DCRTPoly> RLWETrapdoorUtility<DCRTPoly>::GaussSamp(size_t n, size_t k, const Matrix<DCRTPoly>& A,
                                                          const RLWETrapdoorPair<DCRTPoly>& T, const DCRTPoly& u,
                                                          DggType& dgg, DggType& dggLargeSigma, int64_t base) {
    OPENFHE_DEBUG_FLAG(false);
    TimeVar t1, t1_tot, t2, t2_tot;
    TIC(t1);
    TIC(t1_tot);
    const std::shared_ptr<ParmType> params = u.GetParams();
    auto zero_alloc                        = DCRTPoly::Allocator(params, Format::EVALUATION);

    double c = (base + 1) * SIGMA;

    // spectral bound s
    double s = SPECTRAL_BOUND(n, k, base);

    OPENFHE_DEBUG("c " << c << " s " << s);

    // perturbation vector in evaluation representation
    auto pHat = std::make_shared<Matrix<DCRTPoly>>(zero_alloc, k + 2, 1);
    OPENFHE_DEBUG("t1a: " << TOC(t1));
    TIC(t1);
    ZSampleSigmaP(n, s, c, T, dgg, dggLargeSigma, pHat);
    OPENFHE_DEBUG("t1b: " << TOC(t1));  // this takes the most time 61
    TIC(t1);
    // It is assumed that A has dimension 1 x (k + 2) and pHat has the dimension
    // of (k + 2) x 1 perturbedSyndrome is in the evaluation representation
    DCRTPoly perturbedSyndrome = u - (A.Mult(*pHat))(0, 0);

    OPENFHE_DEBUG("t1c: " << TOC(t1));  // takes 2
    TIC(t1);
    OPENFHE_DEBUG("t1d: " << TOC(t1));  // takes 0
    Matrix<int64_t> zHatBBI([]() { return 0; }, k, n);
    OPENFHE_DEBUG("t1: " << TOC(t1_tot));  // takes 64
    TIC(t2);
    TIC(t2_tot);
    perturbedSyndrome.SetFormat(Format::COEFFICIENT);
    OPENFHE_DEBUG("t2a: " << TOC(t2));  // takes 1
    TIC(t2);

    size_t size = perturbedSyndrome.GetNumOfElements();

    for (size_t u = 0; u < size; u++) {
        uint32_t kRes = k / size;

        NativeInteger qu = params->GetParams()[u]->GetModulus();

        Matrix<int64_t> digits([]() { return 0; }, kRes, n);
        LatticeGaussSampUtility<NativePoly>::GaussSampGqArbBase(perturbedSyndrome.GetElementAtIndex(u), c, kRes, qu,
                                                                base, dgg, &digits);
        for (size_t p = 0; p < kRes; p++) {
            for (size_t j = 0; j < n; j++) {
                zHatBBI(p + u * kRes, j) = digits(p, j);
            }
        }
    }

    OPENFHE_DEBUG("t2b: " << TOC(t2));  // takes 36
    TIC(t2);
    // Convert zHat from a matrix of BBI to a vector of Element ring elements
    // zHat is in the coefficient representation
    Matrix<DCRTPoly> zHat = SplitInt64AltIntoElements<DCRTPoly>(zHatBBI, n, params);

    OPENFHE_DEBUG("t2c: " << TOC(t2));  // takes 0
    // Now converting it to the evaluation representation before multiplication
    zHat.SetFormat(Format::EVALUATION);
    OPENFHE_DEBUG("t2d: " << TOC(t2));  // takes 17
    OPENFHE_DEBUG("t2: " << TOC(t2_tot));

    Matrix<DCRTPoly> zHatPrime(zero_alloc, k + 2, 1);

    zHatPrime(0, 0) = (*pHat)(0, 0) + T.m_e.Mult(zHat)(0, 0);
    zHatPrime(1, 0) = (*pHat)(1, 0) + T.m_r.Mult(zHat)(0, 0);

    for (size_t row = 2; row < k + 2; ++row)
        zHatPrime(row, 0) = (*pHat)(row, 0) + zHat(row - 2, 0);

    return zHatPrime;
}

// Gaussian sampling as described in "Implementing Token-Based Obfuscation under
// Ring (LWE)"

template <>
Matrix<DCRTPoly> RLWETrapdoorUtility<DCRTPoly>::GaussSampSquareMat(size_t n, size_t k, const Matrix<DCRTPoly>& A,
                                                                   const RLWETrapdoorPair<DCRTPoly>& T,
                                                                   const Matrix<DCRTPoly>& U, DggType& dgg,
                                                                   DggType& dggLargeSigma, int64_t base) {
    const std::shared_ptr<ParmType> params = U(0, 0).GetParams();
    auto zero_alloc                        = DCRTPoly::Allocator(params, Format::EVALUATION);

    double c = (base + 1) * SIGMA;

    size_t d = T.m_r.GetRows();

    // spectral bound s
    double s = SPECTRAL_BOUND_D(n, k, base, d);

    // perturbation vector in evaluation representation
    auto pHat = std::make_shared<Matrix<DCRTPoly>>(zero_alloc, d * (k + 2), d);

    SamplePertSquareMat(n, s, c, T, dgg, dggLargeSigma, pHat);

    // It is assumed that A has dimension d x d*(k + 2) and pHat has the dimension
    // of d*(k + 2) x d perturbedSyndrome is in the evaluation representation
    Matrix<DCRTPoly> perturbedSyndrome = U - (A.Mult(*pHat));

    perturbedSyndrome.SetFormat(Format::COEFFICIENT);

    size_t size = perturbedSyndrome(0, 0).GetNumOfElements();

    Matrix<DCRTPoly> zHatMat(zero_alloc, d * k, d);

    for (size_t i = 0; i < d; i++) {
        for (size_t j = 0; j < d; j++) {
            Matrix<int64_t> zHatBBI([]() { return 0; }, k, n);

            for (size_t u = 0; u < size; u++) {
                uint32_t kRes = k / size;

                NativeInteger qu = params->GetParams()[u]->GetModulus();

                Matrix<int64_t> digits([]() { return 0; }, kRes, n);

                LatticeGaussSampUtility<NativePoly>::GaussSampGqArbBase(perturbedSyndrome(i, j).GetElementAtIndex(u), c,
                                                                        kRes, qu, base, dgg, &digits);

                for (size_t p = 0; p < kRes; p++) {
                    for (size_t jj = 0; jj < n; jj++) {
                        zHatBBI(p + u * kRes, jj) = digits(p, jj);
                    }
                }
            }

            // Convert zHat from a matrix of BBI to a vector of DCRTPoly ring elements
            // zHat is in the coefficient representation
            Matrix<DCRTPoly> zHat = SplitInt64AltIntoElements<DCRTPoly>(zHatBBI, n, params);

            // Now converting it to the evaluation representation before
            // multiplication
            zHat.SetFormat(Format::EVALUATION);

            for (size_t p = 0; p < k; p++)
                zHatMat(i * k + p, j) = zHat(p, 0);
        }
    }

    Matrix<DCRTPoly> zHatPrime(zero_alloc, d * (k + 2), d);

    Matrix<DCRTPoly> rZhat = T.m_r.Mult(zHatMat);  // d x d
    Matrix<DCRTPoly> eZhat = T.m_e.Mult(zHatMat);  // d x d

    for (size_t j = 0; j < d; j++) {  // columns
        for (size_t i = 0; i < d; i++) {
            zHatPrime(i, j)     = (*pHat)(i, j) + rZhat(i, j);
            zHatPrime(i + d, j) = (*pHat)(i + d, j) + eZhat(i, j);

            for (size_t p = 0; p < k; p++) {
                zHatPrime(i * k + p + 2 * d, j) = (*pHat)(i * k + p + 2 * d, j) + zHatMat(i * k + p, j);
            }
        }
    }

    return zHatPrime;
}

template class LatticeGaussSampUtility<DCRTPoly>;
template class RLWETrapdoorPair<DCRTPoly>;
template class RLWETrapdoorUtility<DCRTPoly>;

}  // namespace lbcrypto
