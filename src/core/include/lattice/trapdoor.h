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
  Provides the utility for sampling trapdoor lattices as described in https://eprint.iacr.org/2017/844.pdf
  https://eprint.iacr.org/2018/946, and "Implementing Token-Based Obfuscation under (Ring) LWE" as described in
  https://eprint.iacr.org/2018/1222.pdf.
 */

#ifndef LBCRYPTO_INC_LATTICE_TRAPDOOR_H
#define LBCRYPTO_INC_LATTICE_TRAPDOOR_H

#include "lattice/dgsampling.h"
#include "lattice/field2n.h"

#include "math/matrix.h"

#include <memory>
#include <utility>

#include "utils/debug.h"

namespace lbcrypto {

/**
 * @brief Class to store a lattice trapdoor pair generated using construction 1
 * in section 3.2 of https://eprint.iacr.org/2013/297.pdf This construction is
 * based on the hardness of Ring-LWE problem
 */
template <class Element>
class RLWETrapdoorPair {
public:
    // matrix of noise polynomials
    Matrix<Element> m_r;
    // matrix
    Matrix<Element> m_e;
    // CTOR with empty trapdoor pair for deserialization
    RLWETrapdoorPair()
        : m_r(Matrix<Element>([]() { return Element(); }, 0, 0)),
          m_e(Matrix<Element>([]() { return Element(); }, 0, 0)) {}

    RLWETrapdoorPair(const Matrix<Element>& r, const Matrix<Element>& e) : m_r(r), m_e(e) {}

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(CEREAL_NVP(m_r));
        ar(CEREAL_NVP(m_e));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        ar(CEREAL_NVP(m_r));
        ar(CEREAL_NVP(m_e));
    }
};

/**
 * @brief Static class implementing lattice trapdoor construction in Algorithm 1
 * of https://eprint.iacr.org/2017/844.pdf
 */
template <class Element>
class RLWETrapdoorUtility {
    using ParmType = typename Element::Params;
    using DggType  = typename Element::DggType;
    using IntType  = typename Element::Integer;

public:
    /**
   * Trapdoor generation method as described in Algorithm 1 of
   * https://eprint.iacr.org/2017/844.pdf
   *
   * @param params ring element parameters
   * @param sttdev distribution parameter used in sampling noise polynomials
   * of the trapdoor
   * @param base base of gadget matrix
   * @param bal flag for balanced (true) versus not-balanced (false) digit
   * representation
   * @return the trapdoor pair including the public key (matrix of rings)
   * and trapdoor itself
   */
    static std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> TrapdoorGen(std::shared_ptr<ParmType> params,
                                                                             double stddev, int64_t base = 2,
                                                                             bool bal = false);

    /**
   * Generalized trapdoor generation method (described in "Implementing
   * Token-Based Obfuscation under (Ring) LWE")
   *
   * @param params ring element parameters
   * @param sttdev distribution parameter used in sampling noise polynomials of
   * the trapdoor
   * @param dimension of square matrix
   * @param base base of gadget matrix
   * @param bal flag for balanced (true) versus not-balanced (false) digit
   * representation
   * @return the trapdoor pair including the public key (matrix of rings) and
   * trapdoor itself
   */
    static std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> TrapdoorGenSquareMat(std::shared_ptr<ParmType> params,
                                                                                      double stddev, size_t dimension,
                                                                                      int64_t base = 2,
                                                                                      bool bal     = false);

    /**
   * Gaussian sampling as described in Alogorithm 2 of
   * https://eprint.iacr.org/2017/844.pdf
   *
   * @param n ring dimension
   * @param k matrix sample dimension; k = log2(q)/log2(base) + 2
   * @param &A public key of the trapdoor pair
   * @param &T trapdoor itself
   * @param &u syndrome vector where gaussian that Gaussian sampling is centered
   * around
   * @param &dgg discrete Gaussian generator for integers
   * @param &dggLargeSigma discrete Gaussian generator for perturbation vector
   * sampling (only used in Peikert's method)
   * @param base base of gadget matrix
   * @return the sampled vector (matrix)
   */
    static Matrix<Element> GaussSamp(size_t n, size_t k, const Matrix<Element>& A, const RLWETrapdoorPair<Element>& T,
                                     const Element& u, DggType& dgg, DggType& dggLargeSigma, int64_t base = 2);

    /**
   * Gaussian sampling (described in "Implementing Token-Based Obfuscation under
   * (Ring) LWE")
   *
   * @param n ring dimension
   * @param k matrix sample dimension; k = log2(q)/log2(base) + 2
   * @param &A public key of the trapdoor pair
   * @param &T trapdoor itself
   * @param &U syndrome matrix that Gaussian sampling is centered around
   * @param &dgg discrete Gaussian generator for integers
   * @param &dggLargeSigma discrete Gaussian generator for perturbation vector
   * sampling (only used in Peikert's method)
   * @param base base of gadget matrix
   * @return the sampled vector (matrix)
   */
    static Matrix<Element> GaussSampSquareMat(size_t n, size_t k, const Matrix<Element>& A,
                                              const RLWETrapdoorPair<Element>& T, const Matrix<Element>& U,
                                              DggType& dgg, DggType& dggLargeSigma, int64_t base = 2);

    /**
   * On-line stage of pre-image sampling (includes only G-sampling)
   *
   * @param n ring dimension
   * @param k matrix sample dimension; k = log2(q)/log2(base) + 2
   * @param &A public key of the trapdoor pair
   * @param &T trapdoor itself
   * @param &u syndrome vector where gaussian that Gaussian sampling is centered
   * around
   * @param &dgg discrete Gaussian generator for integers
   * @param &perturbationVector perturbation vector generated during the offline
   * stage
   * @param &base base for G-lattice
   * @return the sampled vector (matrix)
   */
    static Matrix<Element> GaussSampOnline(size_t n, size_t k, const Matrix<Element>& A,
                                           const RLWETrapdoorPair<Element>& T, const Element& u, DggType& dgg,
                                           const std::shared_ptr<Matrix<Element>> perturbationVector, int64_t base = 2);

    /**
   * Offline stage of pre-image sampling (perturbation sampling)
   *
   * @param n ring dimension
   * @param k matrix sample dimension; k = logq + 2
   * @param &T trapdoor itself
   * @param &dgg discrete Gaussian generator for integers
   * @param &dggLargeSigma discrete Gaussian generator for perturbation vector
   * sampling
   * @param &base base for G-lattice
   * @return the sampled vector (matrix)
   */
    static std::shared_ptr<Matrix<Element>> GaussSampOffline(size_t n, size_t k, const RLWETrapdoorPair<Element>& T,
                                                             DggType& dgg, DggType& dggLargeSigma, int64_t base = 2);

    /**
   * Method for perturbation generation as described in Algorithm 4 of
   *https://eprint.iacr.org/2017/844.pdf
   *
   *@param n ring dimension
   *@param s parameter Gaussian distribution
   *@param sigma standard deviation
   *@param &Tprime compact trapdoor matrix
   *@param &dgg discrete Gaussian generator for error sampling
   *@param &dggLargeSigma discrete Gaussian generator for perturbation vector
   *sampling
   *@param *perturbationVector perturbation vector;output of the function
   */
    static void ZSampleSigmaP(size_t n, double s, double sigma, const RLWETrapdoorPair<Element>& Tprime,
                              const DggType& dgg, const DggType& dggLargeSigma,
                              std::shared_ptr<Matrix<Element>> perturbationVector) {
        OPENFHE_DEBUG_FLAG(false);
        TimeVar t1, t1_tot;

        TIC(t1);
        TIC(t1_tot);
        Matrix<Element> Tprime0 = Tprime.m_e;
        Matrix<Element> Tprime1 = Tprime.m_r;

        // k is the bit length
        size_t k = Tprime0.GetCols();

        const std::shared_ptr<ParmType> params = Tprime0(0, 0).GetParams();
        OPENFHE_DEBUG("z1a: " << TOC(t1));  // 0
        TIC(t1);
        // all three Polynomials are initialized with "0" coefficients
        Element va(params, Format::EVALUATION, 1);
        Element vb(params, Format::EVALUATION, 1);
        Element vd(params, Format::EVALUATION, 1);

        for (size_t i = 0; i < k; i++) {
            va += Tprime0(0, i) * Tprime0(0, i).Transpose();
            vb += Tprime1(0, i) * Tprime0(0, i).Transpose();
            vd += Tprime1(0, i) * Tprime1(0, i).Transpose();
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

        // for distribution parameters up to 3e5 (experimentally found threshold)
        // use the Peikert's inversion method otherwise, use Karney's method

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
        Matrix<Element> p2 = SplitInt64IntoElements<Element>(p2ZVector, n, va.GetParams());
        OPENFHE_DEBUG("z1f2: " << TOC(t1));
        TIC(t1);

        // now converting to Format::EVALUATION representation before multiplication
        p2.SetFormat(Format::EVALUATION);

        OPENFHE_DEBUG("z1g: " << TOC(t1));  // 17

        TIC(t1);

        // the dimension is 2x1 - a vector of 2 ring elements
        auto zero_alloc = Element::Allocator(params, Format::EVALUATION);
        Matrix<Element> Tp2(zero_alloc, 2, 1);
        Tp2(0, 0) = (Tprime0 * p2)(0, 0);
        Tp2(1, 0) = (Tprime1 * p2)(0, 0);

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
        LatticeGaussSampUtility<Element>::ZSampleSigma2x2(a, b, d, c, dgg, p1ZVector);
        OPENFHE_DEBUG("z1j1: " << TOC(t1));  // 14
        TIC(t1);

        // create 2 ring elements in coefficient representation
        Matrix<Element> p1 = SplitInt64IntoElements<Element>(*p1ZVector, n, va.GetParams());
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

    /**
   * Method for perturbation generation as described in "Implementing
   *Token-Based Obfuscation under (Ring) LWE"
   *
   *@param n ring dimension
   *@param s spectral norm
   *@param sigma standard deviation
   *@param &Tprime compact trapdoor matrix
   *@param &dgg discrete Gaussian generator for error sampling
   *@param &dggLargeSigma discrete Gaussian generator for perturbation vector
   *sampling
   *@param *perturbationVector perturbation vector;output of the function
   */
    static void SamplePertSquareMat(size_t n, double s, double sigma, const RLWETrapdoorPair<Element>& Tprime,
                                    const DggType& dgg, const DggType& dggLargeSigma,
                                    std::shared_ptr<Matrix<Element>> perturbationVector) {
        Matrix<Element> R = Tprime.m_r;
        Matrix<Element> E = Tprime.m_e;

        const std::shared_ptr<ParmType> params = R(0, 0).GetParams();

        // k is the bit length
        size_t k = R.GetCols();
        size_t d = R.GetRows();

        Matrix<int64_t> p2ZVector([]() { return 0; }, n * k, d);

        double sigmaLarge = sqrt(s * s - sigma * sigma);

        // for distribution parameters up to the experimentally found threshold, use
        // the Peikert's inversion method otherwise, use Karney's method
        if (sigmaLarge > KARNEY_THRESHOLD) {
            // Karney rejection sampling method
            for (size_t i = 0; i < n * k; i++) {
                for (size_t j = 0; j < d; j++) {
                    p2ZVector(i, j) = dgg.GenerateIntegerKarney(0, sigmaLarge);
                }
            }
        }
        else {
            // Peikert's inversion sampling method
            std::shared_ptr<int64_t> dggVector = dggLargeSigma.GenerateIntVector(n * k * d);

            for (size_t i = 0; i < n * k; i++) {
                for (size_t j = 0; j < d; j++) {
                    p2ZVector(i, j) = (dggVector.get())[i * d + j];
                }
            }
        }

        // create a matrix of d*k x d ring elements in coefficient representation
        Matrix<Element> p2 = SplitInt64IntoElements<Element>(p2ZVector.ExtractCol(0), n, params);
        for (size_t i = 1; i < d; i++) {
            p2.HStack(SplitInt64IntoElements<Element>(p2ZVector.ExtractCol(i), n, params));
        }

        // now converting to Format::EVALUATION representation before multiplication
        p2.SetFormat(Format::EVALUATION);

        auto zero_alloc = Element::Allocator(params, Format::EVALUATION);

        Matrix<Element> A = R * (R.Transpose());  // d x d
        Matrix<Element> B = R * (E.Transpose());  // d x d
        Matrix<Element> D = E * (E.Transpose());  // d x d

        // Switch the ring elements (Polynomials) to coefficient representation
        A.SetFormat(Format::COEFFICIENT);
        B.SetFormat(Format::COEFFICIENT);
        D.SetFormat(Format::COEFFICIENT);

        Matrix<Field2n> AF([&]() { return Field2n(n, Format::EVALUATION, true); }, d, d);
        Matrix<Field2n> BF([&]() { return Field2n(n, Format::EVALUATION, true); }, d, d);
        Matrix<Field2n> DF([&]() { return Field2n(n, Format::EVALUATION, true); }, d, d);

        double scalarFactor = -sigma * sigma;

        for (size_t i = 0; i < d; i++) {
            for (size_t j = 0; j < d; j++) {
                AF(i, j) = Field2n(A(i, j));
                AF(i, j) = AF(i, j).ScalarMult(scalarFactor);
                BF(i, j) = Field2n(B(i, j));
                BF(i, j) = BF(i, j).ScalarMult(scalarFactor);
                DF(i, j) = Field2n(D(i, j));
                DF(i, j) = DF(i, j).ScalarMult(scalarFactor);
                if (i == j) {
                    AF(i, j) = AF(i, j) + s * s;
                    DF(i, j) = DF(i, j) + s * s;
                }
            }
        }

        // converts the field elements to DFT representation
        AF.SetFormat(Format::EVALUATION);
        BF.SetFormat(Format::EVALUATION);
        DF.SetFormat(Format::EVALUATION);

        // the dimension is 2d x d
        Matrix<Element> Tp2 = (R.VStack(E)) * p2;

        // change to coefficient representation before converting to field elements
        Tp2.SetFormat(Format::COEFFICIENT);

        Matrix<Element> p1(zero_alloc, 1, 1);

        for (size_t j = 0; j < d; j++) {
            Matrix<Field2n> c([&]() { return Field2n(n, Format::COEFFICIENT); }, 2 * d, 1);

            for (size_t i = 0; i < d; i++) {
                c(i, 0)     = Field2n(Tp2(i, j)).ScalarMult(-sigma * sigma / (s * s - sigma * sigma));
                c(i + d, 0) = Field2n(Tp2(i + d, j)).ScalarMult(-sigma * sigma / (s * s - sigma * sigma));
            }

            auto p1ZVector = std::make_shared<Matrix<int64_t>>([]() { return 0; }, n * 2 * d, 1);

            LatticeGaussSampUtility<Element>::SampleMat(AF, BF, DF, c, dgg, p1ZVector);

            if (j == 0)
                p1 = SplitInt64IntoElements<Element>(*p1ZVector, n, params);
            else
                p1.HStack(SplitInt64IntoElements<Element>(*p1ZVector, n, params));
        }

        p1.SetFormat(Format::EVALUATION);

        *perturbationVector = p1.VStack(p2);

        p1.SetFormat(Format::COEFFICIENT);
    }
};

}  // namespace lbcrypto

#endif
