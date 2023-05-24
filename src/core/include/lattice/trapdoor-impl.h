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

#ifndef LBCRYPTO_INC_LATTICE_TRAPDOOR_IMPL_H
#define LBCRYPTO_INC_LATTICE_TRAPDOOR_IMPL_H

#include "lattice/lat-hal.h"
#include "lattice/trapdoor.h"

#include "math/matrix-impl.h"

#include "utils/debug.h"

#include <memory>

namespace lbcrypto {

// On-line stage of pre-image sampling (includes only G-sampling)

template <class Element>
Matrix<Element> RLWETrapdoorUtility<Element>::GaussSampOnline(size_t n, size_t k, const Matrix<Element>& A,
                                                              const RLWETrapdoorPair<Element>& T, const Element& u,
                                                              DggType& dgg, const std::shared_ptr<Matrix<Element>> pHat,
                                                              int64_t base) {
    const std::shared_ptr<ParmType> params = u.GetParams();
    auto zero_alloc                        = Element::Allocator(params, Format::EVALUATION);

    double c = (base + 1) * SIGMA;

    const IntType& modulus = A(0, 0).GetModulus();

    // It is assumed that A has dimension 1 x (k + 2) and pHat has the dimension
    // of (k + 2) x 1 perturbedSyndrome is in the Format::EVALUATION
    // representation
    Element perturbedSyndrome = u - (A.Mult(*pHat))(0, 0);

    Matrix<int64_t> zHatBBI([]() { return 0; }, k, n);

    perturbedSyndrome.SetFormat(Format::COEFFICIENT);

    LatticeGaussSampUtility<Element>::GaussSampGqArbBase(perturbedSyndrome, c, k, modulus, base, dgg, &zHatBBI);

    // Convert zHat from a matrix of integers to a vector of Element ring elements
    // zHat is in the coefficient representation
    Matrix<Element> zHat = SplitInt64AltIntoElements<Element>(zHatBBI, n, params);
    // Now converting it to the Format::EVALUATION representation before
    // multiplication
    zHat.SetFormat(Format::EVALUATION);

    Matrix<Element> zHatPrime(zero_alloc, k + 2, 1);

    zHatPrime(0, 0) = (*pHat)(0, 0) + T.m_e.Mult(zHat)(0, 0);
    zHatPrime(1, 0) = (*pHat)(1, 0) + T.m_r.Mult(zHat)(0, 0);

    for (size_t row = 2; row < k + 2; ++row)
        zHatPrime(row, 0) = (*pHat)(row, 0) + zHat(row - 2, 0);

    return zHatPrime;
}

// Offline stage of pre-image sampling (perturbation sampling)

template <class Element>
std::shared_ptr<Matrix<Element>> RLWETrapdoorUtility<Element>::GaussSampOffline(size_t n, size_t k,
                                                                                const RLWETrapdoorPair<Element>& T,
                                                                                DggType& dgg, DggType& dggLargeSigma,
                                                                                int64_t base) {
    const std::shared_ptr<ParmType> params = T.m_e(0, 0).GetParams();
    auto zero_alloc                        = Element::Allocator(params, Format::EVALUATION);

    double c = (base + 1) * SIGMA;

    // spectral bound s
    double s = SPECTRAL_BOUND(n, k, base);

    // perturbation vector in evaluation representation
    auto result = std::make_shared<Matrix<Element>>(zero_alloc, k + 2, 1);
    ZSampleSigmaP(n, s, c, T, dgg, dggLargeSigma, result);

    return result;
}

template <>
inline void RLWETrapdoorUtility<DCRTPoly>::ZSampleSigmaP(size_t n, double s, double sigma,
                                                         const RLWETrapdoorPair<DCRTPoly>& Tprime,
                                                         const DCRTPoly::DggType& dgg,
                                                         const DCRTPoly::DggType& dggLargeSigma,
                                                         std::shared_ptr<Matrix<DCRTPoly>> perturbationVector) {
    OPENFHE_DEBUG_FLAG(false);
    TimeVar t1, t1_tot;

    TIC(t1);
    TIC(t1_tot);
    Matrix<DCRTPoly> Tprime0 = Tprime.m_e;
    Matrix<DCRTPoly> Tprime1 = Tprime.m_r;
    // k is the bit length
    size_t k = Tprime0.GetCols();

    const std::shared_ptr<DCRTPoly::Params> params = Tprime0(0, 0).GetParams();

    OPENFHE_DEBUG("z1a: " << TOC(t1));  // 0
    TIC(t1);
    // all three Polynomials are initialized with "0" coefficients
    NativePoly va((*params)[0], Format::EVALUATION, 1);
    NativePoly vb((*params)[0], Format::EVALUATION, 1);
    NativePoly vd((*params)[0], Format::EVALUATION, 1);

    for (size_t i = 0; i < k; i++) {
        va += (NativePoly)Tprime0(0, i).GetElementAtIndex(0) * Tprime0(0, i).Transpose().GetElementAtIndex(0);
        vb += (NativePoly)Tprime1(0, i).GetElementAtIndex(0) * Tprime0(0, i).Transpose().GetElementAtIndex(0);
        vd += (NativePoly)Tprime1(0, i).GetElementAtIndex(0) * Tprime1(0, i).Transpose().GetElementAtIndex(0);
    }
    OPENFHE_DEBUG("z1b: " << TOC(t1));  // 9
    TIC(t1);

    // Switch the ring elements (Polynomials) to coefficient representation
    va.SetFormat(Format::COEFFICIENT);
    vb.SetFormat(Format::COEFFICIENT);
    vd.SetFormat(Format::COEFFICIENT);

    OPENFHE_DEBUG("z1c: " << TOC(t1));  // 5
    TIC(t1);

    // Create field elements from ring elements
    Field2n a(va), b(vb), d(vd);

    double scalarFactor = -s * s * sigma * sigma / (s * s - sigma * sigma);

    a = a.ScalarMult(scalarFactor);
    b = b.ScalarMult(scalarFactor);
    d = d.ScalarMult(scalarFactor);

    a = a + s * s;
    d = d + s * s;
    OPENFHE_DEBUG("z1d: " << TOC(t1));  // 0
    TIC(t1);

    // converts the field elements to DFT representation
    a.SetFormat(Format::EVALUATION);
    b.SetFormat(Format::EVALUATION);
    d.SetFormat(Format::EVALUATION);
    OPENFHE_DEBUG("z1e: " << TOC(t1));  // 0
    TIC(t1);

    Matrix<int64_t> p2ZVector([]() { return 0; }, n * k, 1);

    double sigmaLarge = sqrt(s * s - sigma * sigma);

    // for distribution parameters up to KARNEY_THRESHOLD (experimentally found
    // threshold) use the Peikert's inversion method otherwise, use Karney's
    // method
    if (sigmaLarge > KARNEY_THRESHOLD) {
        // Karney rejection sampling method
        for (size_t i = 0; i < n * k; i++) {
            p2ZVector(i, 0) = dgg.GenerateIntegerKarney(0, sigmaLarge);
        }
    }
    else {
        // Peikert's inversion sampling method
        std::shared_ptr<int64_t> dggVector = dggLargeSigma.GenerateIntVector(n * k);

        for (size_t i = 0; i < n * k; i++) {
            p2ZVector(i, 0) = (dggVector.get())[i];
        }
    }
    OPENFHE_DEBUG("z1f1: " << TOC(t1));
    TIC(t1);

    // create k ring elements in coefficient representation
    Matrix<DCRTPoly> p2 = SplitInt64IntoElements<DCRTPoly>(p2ZVector, n, params);
    OPENFHE_DEBUG("z1f2: " << TOC(t1));
    TIC(t1);

    // now converting to Format::EVALUATION representation before multiplication
    p2.SetFormat(Format::EVALUATION);

    OPENFHE_DEBUG("z1g: " << TOC(t1));  // 17

    TIC(t1);

    auto zero_alloc = NativePoly::Allocator((*params)[0], Format::EVALUATION);
    Matrix<NativePoly> Tp2(zero_alloc, 2, 1);
    for (unsigned int i = 0; i < k; i++) {
        Tp2(0, 0) += Tprime0(0, i).GetElementAtIndex(0) * (NativePoly)p2(i, 0).GetElementAtIndex(0);
        Tp2(1, 0) += Tprime1(0, i).GetElementAtIndex(0) * (NativePoly)p2(i, 0).GetElementAtIndex(0);
    }

    OPENFHE_DEBUG("z1h2: " << TOC(t1));
    TIC(t1);
    // change to coefficient representation before converting to field elements
    Tp2.SetFormat(Format::COEFFICIENT);
    OPENFHE_DEBUG("z1h3: " << TOC(t1));
    TIC(t1);

    Matrix<Field2n> c([]() { return Field2n(); }, 2, 1);

    c(0, 0) = Field2n(Tp2(0, 0)).ScalarMult(-sigma * sigma / (s * s - sigma * sigma));
    c(1, 0) = Field2n(Tp2(1, 0)).ScalarMult(-sigma * sigma / (s * s - sigma * sigma));

    auto p1ZVector = std::make_shared<Matrix<int64_t>>([]() { return 0; }, n * 2, 1);
    OPENFHE_DEBUG("z1i: " << TOC(t1));
    TIC(t1);

    LatticeGaussSampUtility<DCRTPoly>::ZSampleSigma2x2(a, b, d, c, dgg, p1ZVector);
    OPENFHE_DEBUG("z1j1: " << TOC(t1));  // 14
    TIC(t1);

    // create 2 ring elements in coefficient representation
    Matrix<DCRTPoly> p1 = SplitInt64IntoElements<DCRTPoly>(*p1ZVector, n, params);
    OPENFHE_DEBUG("z1j2: " << TOC(t1));
    TIC(t1);

    p1.SetFormat(Format::EVALUATION);
    OPENFHE_DEBUG("z1j3: " << TOC(t1));
    TIC(t1);

    *perturbationVector = p1.VStack(p2);
    OPENFHE_DEBUG("z1j4: " << TOC(t1));
    TIC(t1);
    OPENFHE_DEBUG("z1tot: " << TOC(t1_tot));
}

}  // namespace lbcrypto

#endif
