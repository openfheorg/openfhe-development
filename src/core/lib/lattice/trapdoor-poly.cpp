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

template <>
std::pair<Matrix<Poly>, RLWETrapdoorPair<Poly>> RLWETrapdoorUtility<Poly>::TrapdoorGen(
    std::shared_ptr<typename Poly::Params> params, double stddev, int64_t base, bool bal) {
    auto zero_alloc     = Poly::Allocator(params, EVALUATION);
    auto gaussian_alloc = Poly::MakeDiscreteGaussianCoefficientAllocator(params, COEFFICIENT, stddev);
    auto uniform_alloc  = Poly::MakeDiscreteUniformAllocator(params, EVALUATION);

    double val   = params->GetModulus().ConvertToDouble();
    double nBits = floor(log2(val - 1.0) + 1.0);

    size_t k = std::ceil(nBits / log2(base)); /* (+1) is for balanced representation */

    if (bal == true) {
        k++;  // for a balanced digit representation, there is an extra digit
              // required
    }

    auto a = uniform_alloc();

    Matrix<Poly> r(zero_alloc, 1, k, gaussian_alloc);
    Matrix<Poly> e(zero_alloc, 1, k, gaussian_alloc);

    // Converts discrete gaussians to Evaluation representation
    r.SetFormat(Format::EVALUATION);
    e.SetFormat(Format::EVALUATION);

    Matrix<Poly> g = Matrix<Poly>(zero_alloc, 1, k).GadgetVector(base);

    Matrix<Poly> A(zero_alloc, 1, k + 2);
    A(0, 0) = 1;
    A(0, 1) = a;

    for (size_t i = 0; i < k; ++i) {
        A(0, i + 2) = g(0, i) - (a * r(0, i) + e(0, i));
    }

    return std::pair<Matrix<Poly>, RLWETrapdoorPair<Poly>>(A, RLWETrapdoorPair<Poly>(r, e));
}

template <>
std::pair<Matrix<NativePoly>, RLWETrapdoorPair<NativePoly>> RLWETrapdoorUtility<NativePoly>::TrapdoorGen(
    std::shared_ptr<typename NativePoly::Params> params, double stddev, int64_t base, bool bal) {
    auto zero_alloc     = NativePoly::Allocator(params, EVALUATION);
    auto gaussian_alloc = NativePoly::MakeDiscreteGaussianCoefficientAllocator(params, COEFFICIENT, stddev);
    auto uniform_alloc  = NativePoly::MakeDiscreteUniformAllocator(params, EVALUATION);

    double val   = params->GetModulus().ConvertToDouble();
    double nBits = floor(log2(val - 1.0) + 1.0);

    size_t k = std::ceil(nBits / log2(base)); /* (+1) is for balanced representation */

    if (bal == true) {
        k++;  // for a balanced digit representation, there is an extra digit
              // required
    }

    auto a = uniform_alloc();

    Matrix<NativePoly> r(zero_alloc, 1, k, gaussian_alloc);
    Matrix<NativePoly> e(zero_alloc, 1, k, gaussian_alloc);

    // Converts discrete gaussians to Evaluation representation
    r.SetFormat(Format::EVALUATION);
    e.SetFormat(Format::EVALUATION);

    Matrix<NativePoly> g = Matrix<NativePoly>(zero_alloc, 1, k).GadgetVector(base);

    Matrix<NativePoly> A(zero_alloc, 1, k + 2);
    A(0, 0) = 1;
    A(0, 1) = a;

    for (size_t i = 0; i < k; ++i) {
        A(0, i + 2) = g(0, i) - (a * r(0, i) + e(0, i));
    }

    return std::pair<Matrix<NativePoly>, RLWETrapdoorPair<NativePoly>>(A, RLWETrapdoorPair<NativePoly>(r, e));
}

template <>
std::pair<Matrix<Poly>, RLWETrapdoorPair<Poly>> RLWETrapdoorUtility<Poly>::TrapdoorGenSquareMat(
    std::shared_ptr<typename Poly::Params> params, double stddev, size_t d, int64_t base, bool bal) {
    auto zero_alloc     = Poly::Allocator(params, EVALUATION);
    auto gaussian_alloc = Poly::MakeDiscreteGaussianCoefficientAllocator(params, COEFFICIENT, stddev);
    auto uniform_alloc  = Poly::MakeDiscreteUniformAllocator(params, EVALUATION);

    double val   = params->GetModulus().ConvertToDouble();
    double nBits = ceil(log2(val));

    size_t k = std::ceil(nBits / log2(base)); /* (+1) is for balanced representation */

    if (bal == true) {
        k++;  // for a balanced digit representation, there is an extra digit
              // required
    }

    Matrix<Poly> R(zero_alloc, d, d * k, gaussian_alloc);
    Matrix<Poly> E(zero_alloc, d, d * k, gaussian_alloc);

    Matrix<Poly> Abar(zero_alloc, d, d, uniform_alloc);

    // Converts discrete gaussians to Evaluation representation
    R.SetFormat(Format::EVALUATION);
    E.SetFormat(Format::EVALUATION);

    Matrix<Poly> G = Matrix<Poly>(zero_alloc, d, d * k).GadgetVector(base);

    Matrix<Poly> A(zero_alloc, d, d * 2);

    for (size_t i = 0; i < d; i++) {
        for (size_t j = 0; j < d; j++) {
            A(i, j) = Abar(i, j);
            if (i == j)
                A(i, j + d) = 1;
            else
                A(i, j + d) = 0;
        }
    }

    Matrix<Poly> A1 = G - (Abar * R + E);

    A.HStack(A1);

    return std::pair<Matrix<Poly>, RLWETrapdoorPair<Poly>>(A, RLWETrapdoorPair<Poly>(R, E));
}

template <>
std::pair<Matrix<NativePoly>, RLWETrapdoorPair<NativePoly>> RLWETrapdoorUtility<NativePoly>::TrapdoorGenSquareMat(
    std::shared_ptr<typename NativePoly::Params> params, double stddev, size_t d, int64_t base, bool bal) {
    auto zero_alloc     = NativePoly::Allocator(params, EVALUATION);
    auto gaussian_alloc = NativePoly::MakeDiscreteGaussianCoefficientAllocator(params, COEFFICIENT, stddev);
    auto uniform_alloc  = NativePoly::MakeDiscreteUniformAllocator(params, EVALUATION);

    double val   = params->GetModulus().ConvertToDouble();
    double nBits = ceil(log2(val));

    size_t k = std::ceil(nBits / log2(base)); /* (+1) is for balanced representation */

    if (bal == true) {
        k++;  // for a balanced digit representation, there is an extra digit
              // required
    }

    Matrix<NativePoly> R(zero_alloc, d, d * k, gaussian_alloc);
    Matrix<NativePoly> E(zero_alloc, d, d * k, gaussian_alloc);

    Matrix<NativePoly> Abar(zero_alloc, d, d, uniform_alloc);

    // Converts discrete gaussians to Evaluation representation
    R.SetFormat(Format::EVALUATION);
    E.SetFormat(Format::EVALUATION);

    Matrix<NativePoly> G = Matrix<NativePoly>(zero_alloc, d, d * k).GadgetVector(base);

    Matrix<NativePoly> A(zero_alloc, d, d * 2);

    for (size_t i = 0; i < d; i++) {
        for (size_t j = 0; j < d; j++) {
            A(i, j) = Abar(i, j);
            if (i == j)
                A(i, j + d) = 1;
            else
                A(i, j + d) = 0;
        }
    }

    Matrix<NativePoly> A1 = G - (Abar * R + E);

    A.HStack(A1);

    return std::pair<Matrix<NativePoly>, RLWETrapdoorPair<NativePoly>>(A, RLWETrapdoorPair<NativePoly>(R, E));
}

// Gaussian sampling as described in Alogorithm 2 of
// https://eprint.iacr.org/2017/844.pdf

template <>
Matrix<Poly> RLWETrapdoorUtility<Poly>::GaussSamp(size_t n, size_t k, const Matrix<Poly>& A,
                                                  const RLWETrapdoorPair<Poly>& T, const Poly& u,
                                                  typename Poly::DggType& dgg, typename Poly::DggType& dggLargeSigma,
                                                  int64_t base) {
    OPENFHE_DEBUG_FLAG(false);
    TimeVar t1, t1_tot, t2, t2_tot;
    TIC(t1);
    TIC(t1_tot);
    const std::shared_ptr<typename Poly::Params> params = u.GetParams();
    auto zero_alloc                                     = Poly::Allocator(params, EVALUATION);

    double c = (base + 1) * SIGMA;

    const typename Poly::Integer& modulus = A(0, 0).GetModulus();

    // spectral bound s
    double s = SPECTRAL_BOUND(n, k, base);

    OPENFHE_DEBUG("c " << c << " s " << s);

    // perturbation vector in evaluation representation
    auto pHat = std::make_shared<Matrix<Poly>>(zero_alloc, k + 2, 1);
    OPENFHE_DEBUG("t1a: " << TOC(t1));
    TIC(t1);
    ZSampleSigmaP(n, s, c, T, dgg, dggLargeSigma, pHat);
    OPENFHE_DEBUG("t1b: " << TOC(t1));  // this takes the most time 61
    TIC(t1);
    // It is assumed that A has dimension 1 x (k + 2) and pHat has the dimension
    // of (k + 2) x 1 perturbedSyndrome is in the evaluation representation
    Poly perturbedSyndrome = u - (A.Mult(*pHat))(0, 0);

    OPENFHE_DEBUG("t1c: " << TOC(t1));  // takes 2
    TIC(t1);
    Matrix<int64_t> zHatBBI([]() { return 0; }, k, n);
    OPENFHE_DEBUG("t1d: " << TOC(t1));     // takes 0
    OPENFHE_DEBUG("t1: " << TOC(t1_tot));  // takes 64
    TIC(t2);
    TIC(t2_tot);
    perturbedSyndrome.SetFormat(Format::COEFFICIENT);
    OPENFHE_DEBUG("t2a: " << TOC(t2));  // takes 1
    TIC(t2);
    LatticeGaussSampUtility<Poly>::GaussSampGqArbBase(perturbedSyndrome, c, k, modulus, base, dgg, &zHatBBI);
    OPENFHE_DEBUG("t2b: " << TOC(t2));  // takes 36
    TIC(t2);
    // Convert zHat from a matrix of BBI to a vector of Element ring elements
    // zHat is in the coefficient representation
    Matrix<Poly> zHat = SplitInt64AltIntoElements<Poly>(zHatBBI, n, params);

    OPENFHE_DEBUG("t2c: " << TOC(t2));  // takes 0
    // Now converting it to the evaluation representation before multiplication
    zHat.SetFormat(Format::EVALUATION);
    OPENFHE_DEBUG("t2d: " << TOC(t2));  // takes 17
    OPENFHE_DEBUG("t2: " << TOC(t2_tot));
    // TIC(t3); seems trivial
    Matrix<Poly> zHatPrime(zero_alloc, k + 2, 1);

    zHatPrime(0, 0) = (*pHat)(0, 0) + T.m_e.Mult(zHat)(0, 0);
    zHatPrime(1, 0) = (*pHat)(1, 0) + T.m_r.Mult(zHat)(0, 0);

    for (size_t row = 2; row < k + 2; ++row)
        zHatPrime(row, 0) = (*pHat)(row, 0) + zHat(row - 2, 0);

    return zHatPrime;
}

// Gaussian sampling as described in Alogorithm 2 of
// https://eprint.iacr.org/2017/844.pdf

template <>
Matrix<NativePoly> RLWETrapdoorUtility<NativePoly>::GaussSamp(size_t n, size_t k, const Matrix<NativePoly>& A,
                                                              const RLWETrapdoorPair<NativePoly>& T,
                                                              const NativePoly& u, typename NativePoly::DggType& dgg,
                                                              typename NativePoly::DggType& dggLargeSigma,
                                                              int64_t base) {
    OPENFHE_DEBUG_FLAG(false);
    TimeVar t1, t1_tot, t2, t2_tot;
    TIC(t1);
    TIC(t1_tot);
    const std::shared_ptr<typename NativePoly::Params> params = u.GetParams();
    auto zero_alloc                                           = NativePoly::Allocator(params, EVALUATION);

    double c = (base + 1) * SIGMA;

    const typename NativePoly::Integer& modulus = A(0, 0).GetModulus();

    // spectral bound s
    double s = SPECTRAL_BOUND(n, k, base);

    OPENFHE_DEBUG("c " << c << " s " << s);

    // perturbation vector in evaluation representation
    auto pHat = std::make_shared<Matrix<NativePoly>>(zero_alloc, k + 2, 1);
    OPENFHE_DEBUG("t1a: " << TOC(t1));
    TIC(t1);
    ZSampleSigmaP(n, s, c, T, dgg, dggLargeSigma, pHat);
    OPENFHE_DEBUG("t1b: " << TOC(t1));  // this takes the most time 61
    TIC(t1);
    // It is assumed that A has dimension 1 x (k + 2) and pHat has the dimension
    // of (k + 2) x 1 perturbedSyndrome is in the evaluation representation
    NativePoly perturbedSyndrome = u - (A.Mult(*pHat))(0, 0);

    OPENFHE_DEBUG("t1c: " << TOC(t1));  // takes 2
    TIC(t1);
    Matrix<int64_t> zHatBBI([]() { return 0; }, k, n);
    OPENFHE_DEBUG("t1d: " << TOC(t1));     // takes 0
    OPENFHE_DEBUG("t1: " << TOC(t1_tot));  // takes 64
    TIC(t2);
    TIC(t2_tot);
    perturbedSyndrome.SetFormat(Format::COEFFICIENT);
    OPENFHE_DEBUG("t2a: " << TOC(t2));  // takes 1
    TIC(t2);
    LatticeGaussSampUtility<NativePoly>::GaussSampGqArbBase(perturbedSyndrome, c, k, modulus, base, dgg, &zHatBBI);
    OPENFHE_DEBUG("t2b: " << TOC(t2));  // takes 36
    TIC(t2);
    // Convert zHat from a matrix of BBI to a vector of Element ring elements
    // zHat is in the coefficient representation
    Matrix<NativePoly> zHat = SplitInt64AltIntoElements<NativePoly>(zHatBBI, n, params);

    OPENFHE_DEBUG("t2c: " << TOC(t2));  // takes 0
    // Now converting it to the evaluation representation before multiplication
    zHat.SetFormat(Format::EVALUATION);
    OPENFHE_DEBUG("t2d: " << TOC(t2));  // takes 17
    OPENFHE_DEBUG("t2: " << TOC(t2_tot));
    // TIC(t3); seems trivial
    Matrix<NativePoly> zHatPrime(zero_alloc, k + 2, 1);

    zHatPrime(0, 0) = (*pHat)(0, 0) + T.m_e.Mult(zHat)(0, 0);
    zHatPrime(1, 0) = (*pHat)(1, 0) + T.m_r.Mult(zHat)(0, 0);

    for (size_t row = 2; row < k + 2; ++row)
        zHatPrime(row, 0) = (*pHat)(row, 0) + zHat(row - 2, 0);

    return zHatPrime;
}

// Gaussian sampling as described in "Implementing Token-Based Obfuscation under
// Ring (LWE)"

template <>
Matrix<Poly> RLWETrapdoorUtility<Poly>::GaussSampSquareMat(size_t n, size_t k, const Matrix<Poly>& A,
                                                           const RLWETrapdoorPair<Poly>& T, const Matrix<Poly>& U,
                                                           typename Poly::DggType& dgg,
                                                           typename Poly::DggType& dggLargeSigma, int64_t base) {
    const std::shared_ptr<typename Poly::Params> params = U(0, 0).GetParams();
    auto zero_alloc                                     = Poly::Allocator(params, EVALUATION);

    double c = (base + 1) * SIGMA;

    const typename Poly::Integer& modulus = A(0, 0).GetModulus();

    size_t d = T.m_r.GetRows();

    // spectral bound s
    double s = SPECTRAL_BOUND_D(n, k, base, d);

    // perturbation vector in evaluation representation
    auto pHat = std::make_shared<Matrix<Poly>>(zero_alloc, d * (k + 2), d);

    SamplePertSquareMat(n, s, c, T, dgg, dggLargeSigma, pHat);

    // It is assumed that A has dimension d x d*(k + 2) and pHat has the dimension
    // of d*(k + 2) x d perturbedSyndrome is in the evaluation representation
    Matrix<Poly> perturbedSyndrome = U - (A.Mult(*pHat));

    perturbedSyndrome.SetFormat(Format::COEFFICIENT);

    Matrix<Poly> zHatMat(zero_alloc, d * k, d);

    for (size_t i = 0; i < d; i++) {
        for (size_t j = 0; j < d; j++) {
            Matrix<int64_t> zHatBBI([]() { return 0; }, k, n);

            LatticeGaussSampUtility<Poly>::GaussSampGqArbBase(perturbedSyndrome(i, j), c, k, modulus, base, dgg,
                                                              &zHatBBI);

            // Convert zHat from a matrix of BBI to a vector of Poly ring elements
            // zHat is in the coefficient representation
            Matrix<Poly> zHat = SplitInt64AltIntoElements<Poly>(zHatBBI, n, params);

            // Now converting it to the evaluation representation before
            // multiplication
            zHat.SetFormat(Format::EVALUATION);

            for (size_t p = 0; p < k; p++)
                zHatMat(i * k + p, j) = zHat(p, 0);
        }
    }

    Matrix<Poly> zHatPrime(zero_alloc, d * (k + 2), d);

    Matrix<Poly> rZhat = T.m_r.Mult(zHatMat);  // d x d
    Matrix<Poly> eZhat = T.m_e.Mult(zHatMat);  // d x d

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

template <>
Matrix<NativePoly> RLWETrapdoorUtility<NativePoly>::GaussSampSquareMat(
    size_t n, size_t k, const Matrix<NativePoly>& A, const RLWETrapdoorPair<NativePoly>& T, const Matrix<NativePoly>& U,
    typename NativePoly::DggType& dgg, typename NativePoly::DggType& dggLargeSigma, int64_t base) {
    const std::shared_ptr<typename NativePoly::Params> params = U(0, 0).GetParams();
    auto zero_alloc                                           = NativePoly::Allocator(params, EVALUATION);

    double c = (base + 1) * SIGMA;

    const typename NativePoly::Integer& modulus = A(0, 0).GetModulus();

    size_t d = T.m_r.GetRows();

    // spectral bound s
    double s = SPECTRAL_BOUND_D(n, k, base, d);

    // perturbation vector in evaluation representation
    auto pHat = std::make_shared<Matrix<NativePoly>>(zero_alloc, d * (k + 2), d);

    SamplePertSquareMat(n, s, c, T, dgg, dggLargeSigma, pHat);

    // It is assumed that A has dimension d x d*(k + 2) and pHat has the dimension
    // of d*(k + 2) x d perturbedSyndrome is in the evaluation representation
    Matrix<NativePoly> perturbedSyndrome = U - (A.Mult(*pHat));

    perturbedSyndrome.SetFormat(Format::COEFFICIENT);

    Matrix<NativePoly> zHatMat(zero_alloc, d * k, d);

    for (size_t i = 0; i < d; i++) {
        for (size_t j = 0; j < d; j++) {
            Matrix<int64_t> zHatBBI([]() { return 0; }, k, n);

            LatticeGaussSampUtility<NativePoly>::GaussSampGqArbBase(perturbedSyndrome(i, j), c, k, modulus, base, dgg,
                                                                    &zHatBBI);

            // Convert zHat from a matrix of BBI to a vector of NativePoly ring
            // elements zHat is in the coefficient representation
            Matrix<NativePoly> zHat = SplitInt64AltIntoElements<NativePoly>(zHatBBI, n, params);

            // Now converting it to the evaluation representation before
            // multiplication
            zHat.SetFormat(Format::EVALUATION);

            for (size_t p = 0; p < k; p++)
                zHatMat(i * k + p, j) = zHat(p, 0);
        }
    }

    Matrix<NativePoly> zHatPrime(zero_alloc, d * (k + 2), d);

    Matrix<NativePoly> rZhat = T.m_r.Mult(zHatMat);  // d x d
    Matrix<NativePoly> eZhat = T.m_e.Mult(zHatMat);  // d x d

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

template class LatticeGaussSampUtility<Poly>;
template class RLWETrapdoorPair<Poly>;
template class RLWETrapdoorUtility<Poly>;

template class LatticeGaussSampUtility<NativePoly>;
template class RLWETrapdoorPair<NativePoly>;
template class RLWETrapdoorUtility<NativePoly>;

}  // namespace lbcrypto
