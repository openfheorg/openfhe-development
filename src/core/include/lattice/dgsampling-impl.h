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
  Provides detailed algorithms for G-sampling and perturbation sampling as described in https://eprint.iacr.org/2017/844.pdf,
  https://eprint.iacr.org/2018/946, and "Implementing Token-Based Obfuscation under (Ring) LWE" as described in
  https://eprint.iacr.org/2018/1222.pdf
 */

#ifndef LBCRYPTO_INC_LATTICE_DGSAMPLING_IMPL_H
#define LBCRYPTO_INC_LATTICE_DGSAMPLING_IMPL_H

#include "lattice/dgsampling.h"

#include "utils/inttypes.h"
#include "utils/parallel.h"

#include <memory>
#include <vector>

namespace lbcrypto {

// Gaussian sampling from lattice for gagdet matrix G, syndrome u, and arbitrary
// modulus q Discrete sampling variant As described in Figure 2 of
// https://eprint.iacr.org/2017/308.pdf

template <class Element>
void LatticeGaussSampUtility<Element>::GaussSampGq(const Element& syndrome, double stddev, size_t k,
                                                   const typename Element::Integer& q, int64_t base,
                                                   typename Element::DggType& dgg, Matrix<int64_t>* z) {
    // If DCRT is used, the polynomial is first converted from DCRT to large
    // polynomial (in COEFFICIENT representation)
    typename Element::PolyLargeType u = syndrome.CRTInterpolate();

    const typename Poly::Integer& modulus = u.GetParams()->GetModulus();
    double sigma                          = stddev / (base + 1);

    std::vector<int64_t> m_digits = *(GetDigits(modulus, base, k));

    // main diagonal of matrix L
    std::vector<double> l(k);
    // upper diagonal of matrix L
    std::vector<double> h(k);

    // Matrix<double> a([]() { return 0.0; }, k, 1);
    Matrix<double> c([]() { return 0.0; }, k, 1);

    //  set the values of matrix L
    // (double) is added to avoid integer division
    l[0] = sqrt(base * (1 + 1 / k) + 1);
    for (size_t i = 1; i < k; i++)
        l[i] = sqrt(base * (1 + 1 / static_cast<double>(k - i)));

    h[0] = 0;
    // (double) is added to avoid integer division
    for (size_t i = 1; i < k; i++)
        h[i] = sqrt(base * (1 - 1 / static_cast<double>(k - (i - 1))));

    // c can be pre-computed as it only depends on the modulus
    // (double) is added to avoid integer division
    c(0, 0) = m_digits[0] / static_cast<double>(base);

    for (size_t i = 1; i < k; i++)
        c(i, 0) = (c(i - 1, 0) + m_digits[i]) / base;

#pragma omp parallel for
    for (size_t j = 0; j < u.GetLength(); j++) {
        typename Element::Integer v(u.at(j));

        std::vector<int64_t> p(k);

        LatticeGaussSampUtility<Element>::Perturb(sigma, k, u.GetLength(), l, h, base, dgg, &p);

        Matrix<double> a([]() { return 0.0; }, k, 1);

        std::vector<int64_t> v_digits = *(GetDigits(v, base, k));

        // int64_t cast is needed here as GetDigitAtIndexForBase returns an unsigned
        // int when the result is negative, a(0,0) gets values close to 2^64 if the
        // cast is not used (double) is added to avoid integer division
        a(0, 0) = ((int64_t)(v_digits[0]) - p[0]) / static_cast<double>(base);

        for (size_t t = 1; t < k; t++) {
            a(t, 0) = (a(t - 1, 0) + (int64_t)(v_digits[t]) - p[t]) / base;
        }
        std::vector<int64_t> zj(k);

        LatticeGaussSampUtility<Element>::SampleC(c, k, u.GetLength(), sigma, dgg, &a, &zj);

        (*z)(0, j) = base * zj[0] + (int64_t)(m_digits[0]) * zj[k - 1] + (int64_t)(v_digits[0]);

        for (size_t t = 1; t < k - 1; t++) {
            (*z)(t, j) = base * zj[t] - zj[t - 1] + (int64_t)(m_digits[t]) * zj[k - 1] + (int64_t)(v_digits[t]);
        }
        (*z)(k - 1, j) = (int64_t)(m_digits[k - 1]) * zj[k - 1] - zj[k - 2] + (int64_t)(v_digits[k - 1]);
    }
}

// Gaussian sampling from lattice for gagdet matrix G, syndrome u, and arbitrary
// modulus q Continuous sampling variant As described in Algorithm 3 of
// https://eprint.iacr.org/2017/844.pdf

template <class Element>
void LatticeGaussSampUtility<Element>::GaussSampGqArbBase(const Element& syndrome, double stddev, size_t k,
                                                          const typename Element::Integer& q, int64_t base,
                                                          typename Element::DggType& dgg, Matrix<int64_t>* z) {
    // If DCRT is used, the polynomial is first converted from DCRT to large
    // polynomial (in Format::COEFFICIENT representation)
    typename Element::PolyLargeType u = syndrome.CRTInterpolate();

    const typename Poly::Integer& modulus = u.GetParams()->GetModulus();
    double sigma                          = stddev / (base + 1);

    std::vector<int64_t> m_digits = *(GetDigits(modulus, base, k));

    // main diagonal of matrix L
    std::vector<double> l(k);
    // upper diagonal of matrix L
    std::vector<double> h(k);

    // Matrix<double> a([]() { return 0.0; }, k, 1);
    Matrix<double> c([]() { return 0.0; }, k, 1);

    //  set the values of matrix L
    // (double) is added to avoid integer division
    l[0] = sqrt(base * (1 + 1 / k) + 1);
    for (size_t i = 1; i < k; i++)
        l[i] = sqrt(base * (1 + 1 / static_cast<double>(k - i)));

    h[0] = 0;
    // (double) is added to avoid integer division
    for (size_t i = 1; i < k; i++)
        h[i] = sqrt(base * (1 - 1 / static_cast<double>(k - (i - 1))));

    // c can be pre-computed as it only depends on the modulus
    // (double) is added to avoid integer division
    c(0, 0) = ((int64_t)m_digits[0]) / static_cast<double>(base);

    for (size_t i = 1; i < k; i++)
        c(i, 0) = (c(i - 1, 0) + (int64_t)m_digits[i]) / static_cast<double>(base);

#pragma omp parallel for
    for (size_t j = 0; j < u.GetLength(); j++) {
        typename Element::Integer v(u.at(j));

        std::vector<int64_t> v_digits = *(GetDigits(v, base, k));

        std::vector<double> p(k);

        LatticeGaussSampUtility<Element>::PerturbFloat(sigma, k, u.GetLength(), l, h, base, dgg, &p);

        Matrix<double> a([]() { return 0.0; }, k, 1);

        // int64_t cast is needed here as GetDigitAtIndexForBase returns an unsigned
        // int when the result is negative, a(0,0) gets values close to 2^64 if the
        // cast is not used (double) is added to avoid integer division
        a(0, 0) = ((int64_t)(v_digits[0]) - p[0]) / static_cast<double>(base);

        for (size_t t = 1; t < k; t++) {
            a(t, 0) = (a(t - 1, 0) + (int64_t)(v_digits[t]) - p[t]) / static_cast<double>(base);
        }
        std::vector<int64_t> zj(k);

        LatticeGaussSampUtility<Element>::SampleC(c, k, u.GetLength(), sigma, dgg, &a, &zj);

        (*z)(0, j) = base * zj[0] + (int64_t)(m_digits[0]) * zj[k - 1] + (int64_t)(v_digits[0]);

        for (size_t t = 1; t < k - 1; t++) {
            (*z)(t, j) = base * zj[t] - zj[t - 1] + (int64_t)(m_digits[t]) * zj[k - 1] + (int64_t)(v_digits[t]);
        }
        (*z)(k - 1, j) = (int64_t)(m_digits[k - 1]) * zj[k - 1] - zj[k - 2] + (int64_t)(v_digits[k - 1]);
    }
}

// subroutine used by GaussSampGq
// Discrete sampling variant
// As described in Figure 2 of https://eprint.iacr.org/2017/308.pdf

template <class Element>
void LatticeGaussSampUtility<Element>::Perturb(double sigma, size_t k, size_t n, const std::vector<double>& l,
                                               const std::vector<double>& h, int64_t base,
                                               typename Element::DggType& dgg, std::vector<int64_t>* p) {
    std::vector<int32_t> z(k);
    double d = 0;

    for (size_t i = 0; i < k; i++) {
        z[i] = dgg.GenerateIntegerKarney(d / l[i], sigma / l[i]);
        d    = -z[i] * h[i];
    }

    (*p)[0] = (2 * base + 1) * z[0] + base * z[1];
    for (size_t i = 1; i < k - 1; i++)
        (*p)[i] = base * (z[i - 1] + 2 * z[i] + z[i + 1]);
    (*p)[k - 1] = base * (z[k - 2] + 2 * z[k - 1]);
}

// subroutine used by GaussSampGqArbBase
// Continuous sampling variant
// As described in Algorithm 3 of https://eprint.iacr.org/2017/844.pdf

template <class Element>
void LatticeGaussSampUtility<Element>::PerturbFloat(double sigma, size_t k, size_t n, const std::vector<double>& l,
                                                    const std::vector<double>& h, int64_t base,
                                                    typename Element::DggType& dgg, std::vector<double>* p) {
    std::normal_distribution<> d(0, sigma);

    PRNG& g = PseudoRandomNumberGenerator::GetPRNG();

    std::vector<double> z(k);

    // Generate a vector using continuous Gaussian distribution
    for (size_t i = 0; i < k; i++)
        z[i] = d(g);

    // Compute matrix-vector product Lz (apply linear transformation)
    for (size_t i = 0; i < k - 1; i++) {
        p->at(i) = l[i] * z[i] + h[i + 1] * z[i + 1];
    }

    p->at(k - 1) = h[k - 1] * z[k - 1];
}

// subroutine used by GaussSampGq
// As described in Algorithm 3 of https://eprint.iacr.org/2017/844.pdf

template <class Element>
void LatticeGaussSampUtility<Element>::SampleC(const Matrix<double>& c, size_t k, size_t n, double sigma,
                                               typename Element::DggType& dgg, Matrix<double>* a,
                                               std::vector<int64_t>* z) {
    (*z)[k - 1] = dgg.GenerateIntegerKarney(-(*a)(k - 1, 0) / c(k - 1, 0), sigma / c(k - 1, 0));
    *a          = *a + (static_cast<double>((*z)[k - 1])) * c;

    for (size_t i = 0; i < k - 1; i++) {
        (*z)[i] = dgg.GenerateIntegerKarney(-(*a)(i, 0), sigma);
    }
}

// Subroutine used by ZSampleSigmaP as described Algorithm 4 in
// https://eprint.iacr.org/2017/844.pdf a - field element in DFT format b -
// field element in DFT format d - field element in DFT format c - vector of
// field elements in Format::COEFFICIENT format
template <class Element>
void LatticeGaussSampUtility<Element>::ZSampleSigma2x2(const Field2n& a, const Field2n& b, const Field2n& d,
                                                       const Matrix<Field2n>& c, const typename Element::DggType& dgg,
                                                       std::shared_ptr<Matrix<int64_t>> q) {
    // size of the the lattice
    size_t n = a.Size();

    Field2n dCoeff = d;
    dCoeff.SetFormat(Format::COEFFICIENT);

    std::shared_ptr<Matrix<int64_t>> q2Int = ZSampleF(dCoeff, c(1, 0), dgg, n);
    Field2n q2(*q2Int);

    Field2n q2Minusc2 = q2 - c(1, 0);
    // Convert to DFT representation prior to multiplication
    q2Minusc2.SwitchFormat();

    Field2n product = b * d.Inverse() * q2Minusc2;
    product.SetFormat(Format::COEFFICIENT);

    // Computes c1 in Format::COEFFICIENT format
    Field2n c1 = c(0, 0) + product;

    Field2n f = a - b * d.Inverse() * b.Transpose();
    f.SetFormat(Format::COEFFICIENT);

    std::shared_ptr<Matrix<int64_t>> q1Int = ZSampleF(f, c1, dgg, n);

    for (size_t i = 0; i < q1Int->GetRows(); i++) {
        (*q)(i, 0) = (*q1Int)(i, 0);
    }

    for (size_t i = 0; i < q2Int->GetRows(); i++) {
        (*q)(i + q1Int->GetRows(), 0) = (*q2Int)(i, 0);
    }
}

// Subroutine used by SamplePertSquareMat as described in "Implementing
// Token-Based Obfuscation under (Ring) LWE"

template <class Element>
void LatticeGaussSampUtility<Element>::SampleMat(const Matrix<Field2n>& A, const Matrix<Field2n>& B,
                                                 const Matrix<Field2n>& D, const Matrix<Field2n>& C,
                                                 const typename Element::DggType& dgg,
                                                 std::shared_ptr<Matrix<int64_t>> p) {
    size_t d = C.GetRows();

    if (d == 2) {
        ZSampleSigma2x2(A(0, 0), B(0, 0), D(0, 0), C, dgg, p);
        return;
    }

    size_t n = D(0, 0).Size();

    size_t dimA = A.GetRows();
    size_t dimD = D.GetRows();

    auto q1 = std::make_shared<Matrix<int64_t>>([]() { return 0; }, n * dimD, 1);
    Matrix<Field2n> c0([]() { return Field2n(Format::COEFFICIENT); }, dimA, 1);
    Matrix<Field2n> c1([]() { return Field2n(Format::COEFFICIENT); }, dimD, 1);
    Matrix<Field2n> qF1([]() { return Field2n(Format::COEFFICIENT); }, dimD, 1);

    Matrix<Field2n> Dinverse([]() { return Field2n(Format::EVALUATION); }, dimD, dimD);

    if (dimD == 1) {
        Field2n dEval = D(0, 0);
        dEval.SetFormat(Format::COEFFICIENT);
        c1(0, 0) = C(d - 1, 0);
        c0       = C.ExtractRows(0, d - 2);

        q1 = ZSampleF(dEval, c1(0, 0), dgg, dEval.Size());

        Dinverse(0, 0) = D(0, 0).Inverse();

        qF1(0, 0) = Field2n(*q1);
    }
    else if (dimD == 2) {  // dimD == 2
        c1 = C.ExtractRows(dimA, d - 1);
        c0 = C.ExtractRows(0, dimA - 1);

        ZSampleSigma2x2(D(0, 0), D(0, 1), D(1, 1), c1, dgg, q1);

        for (size_t i = 0; i < dimD; i++)
            qF1(i, 0) = Field2n(q1->ExtractRows(i * n, i * n + n - 1));

        Field2n det        = D(0, 0) * D(1, 1) - D(0, 1) * D(1, 0);
        Field2n detInverse = det.Inverse();

        Dinverse(0, 0) = D(1, 1) * detInverse;
        Dinverse(0, 1) = -D(0, 1) * detInverse;
        Dinverse(1, 0) = -D(1, 0) * detInverse;
        Dinverse(1, 1) = D(0, 0) * detInverse;
    }
    else {  // dimD > 2
        c1 = C.ExtractRows(dimA, d - 1);
        c0 = C.ExtractRows(0, dimA - 1);

        size_t newDimA = static_cast<size_t>(std::ceil(static_cast<double>(dimD) / 2));
        size_t newDimD = static_cast<size_t>(std::floor(static_cast<double>(dimD) / 2));

        Matrix<Field2n> newA([&]() { return Field2n(n, Format::EVALUATION, true); }, newDimA, newDimA);
        Matrix<Field2n> newB([&]() { return Field2n(n, Format::EVALUATION, true); }, newDimA, newDimD);
        Matrix<Field2n> newD([&]() { return Field2n(n, Format::EVALUATION, true); }, newDimD, newDimD);

        for (size_t i = 0; i < newDimA; i++)
            for (size_t j = 0; j < newDimA; j++)
                newA(i, j) = D(i, j);

        for (size_t i = 0; i < newDimA; i++)
            for (size_t j = 0; j < newDimD; j++)
                newB(i, j) = D(i, j + newDimA);

        for (size_t i = 0; i < newDimD; i++)
            for (size_t j = 0; j < newDimD; j++)
                newD(i, j) = D(i + newDimA, j + newDimA);

        SampleMat(newA, newB, newD, c1, dgg, q1);

        for (size_t i = 0; i < dimD; i++)
            qF1(i, 0) = Field2n(q1->ExtractRows(i * n, i * n + n - 1));

        Field2n det(n, Format::EVALUATION, true);
        D.Determinant(&det);

        Field2n detInverse = det.Inverse();

        Dinverse = (D.CofactorMatrix()).Transpose() * detInverse;
    }

    Matrix<Field2n> sigma = A - B * Dinverse * (B.Transpose());

    Matrix<Field2n> diff = qF1 - c1;
    diff.SetFormat(Format::EVALUATION);
    c0.SetFormat(Format::EVALUATION);

    Matrix<Field2n> cNew = c0 + B * Dinverse * diff;

    cNew.SetFormat(Format::COEFFICIENT);

    size_t newDimA = static_cast<size_t>(std::ceil(static_cast<double>(dimA) / 2));
    size_t newDimD = static_cast<size_t>(std::floor(static_cast<double>(dimA) / 2));

    Matrix<Field2n> newA([&]() { return Field2n(n, Format::EVALUATION, true); }, newDimA, newDimA);
    Matrix<Field2n> newB([&]() { return Field2n(n, Format::EVALUATION, true); }, newDimA, newDimD);
    Matrix<Field2n> newD([&]() { return Field2n(n, Format::EVALUATION, true); }, newDimD, newDimD);

    for (size_t i = 0; i < newDimA; i++)
        for (size_t j = 0; j < newDimA; j++)
            newA(i, j) = sigma(i, j);

    for (size_t i = 0; i < newDimA; i++)
        for (size_t j = 0; j < newDimD; j++)
            newB(i, j) = sigma(i, j + newDimA);

    for (size_t i = 0; i < newDimD; i++)
        for (size_t j = 0; j < newDimD; j++)
            newD(i, j) = sigma(i + newDimA, j + newDimA);

    auto q0 = std::make_shared<Matrix<int64_t>>([]() { return 0; }, n * dimA, 1);

    SampleMat(newA, newB, newD, cNew, dgg, q0);

    *p = *q0;

    p->VStack(*q1);

    return;
}

// Subroutine used by ZSampleSigma2x2 as described Algorithm 4 in
// https://eprint.iacr.org/2017/844.pdf f is in Format::COEFFICIENT
// representation c is in Format::COEFFICIENT representation
template <class Element>
std::shared_ptr<Matrix<int64_t>> LatticeGaussSampUtility<Element>::ZSampleF(const Field2n& f, const Field2n& c,
                                                                            const typename Element::DggType& dgg,
                                                                            size_t n) {
    if (f.Size() == 1) {
        auto p     = std::make_shared<Matrix<int64_t>>([]() { return 0; }, 1, 1);
        (*p)(0, 0) = dgg.GenerateIntegerKarney(c[0].real(), sqrt(f[0].real()));
        return p;
    }

    Field2n f0 = f.ExtractEven();
    Field2n f1 = f.ExtractOdd();

    f0.SetFormat(Format::EVALUATION);
    f1.SetFormat(Format::EVALUATION);

    usint f0_size = f0.Size();

    auto qZVector = std::make_shared<Matrix<int64_t>>([]() { return 0; }, f0_size * 2, 1);

    Matrix<Field2n> cPermuted([]() { return Field2n(); }, 2, 1);

    cPermuted(0, 0) = c.ExtractEven();
    cPermuted(1, 0) = c.ExtractOdd();
    LatticeGaussSampUtility<Element>::ZSampleSigma2x2(f0, f1, f0, cPermuted, dgg, qZVector);
    InversePermute(qZVector);

    return qZVector;
}

// subroutine earlier used by ZSampleF
// Algorithm utilizes the same permutation algorithm as discussed in
// https://eprint.iacr.org/2017/844.pdf
template <class Element>
Matrix<int32_t> LatticeGaussSampUtility<Element>::Permute(Matrix<int32_t>* p) {
    int evenPtr = 0;
    int oddPtr  = p->GetRows() / 2;
    Matrix<int32_t> permuted([]() { return 0; }, p->GetRows(), 1);
    for (usint i = 0; i < p->GetRows(); i++) {
        if (i % 2 == 0) {
            permuted(evenPtr, 0) = (*p)(i, 0);
            evenPtr++;
        }
        else {
            permuted(oddPtr, 0) = (*p)(i, 0);
            oddPtr++;
        }
    }
    return permuted;
}

// subroutine used by ZSampleF
// Algorithm utilizes the same permutation algorithm as discussed in
// https://eprint.iacr.org/2017/844.pdf
template <class Element>
void LatticeGaussSampUtility<Element>::InversePermute(std::shared_ptr<Matrix<int64_t>> p) {
    // a vector of int64_t is used for intermediate storage because it is faster
    // than a Matrix of unique pointers to int64_t

    std::vector<int64_t> vectorPermuted(p->GetRows());

    size_t evenPtr = 0;
    size_t oddPtr  = vectorPermuted.size() / 2;
    for (size_t i = 0; evenPtr < vectorPermuted.size() / 2; i += 2) {
        vectorPermuted[i]     = (*p)(evenPtr, 0);
        vectorPermuted[i + 1] = (*p)(oddPtr, 0);
        evenPtr++;
        oddPtr++;
    }

    for (size_t i = 0; i < vectorPermuted.size(); i++) {
        (*p)(i, 0) = vectorPermuted[i];
    }
}

}  // namespace lbcrypto

#endif
