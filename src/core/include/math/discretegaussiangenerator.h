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
  This code provides generation of gaussian distributions of discrete values. Discrete uniform generator
  relies on the built-in C++ generator for 32-bit unsigned integers defined in <random>
 */

/**
 * This is the header file for DiscreteGaussianGenerator class, which contains 3
 * different sampling methods.
 *
 * First sampling method implemented is the rejection sampling defined in
 * section 4.1 of https://eprint.iacr.org/2007/432.pdf. It is usable for
 * arbitrary centers and standard deviations, and does not require any form of
 * precomputation. However, it has high rejection rates and is prone to timing
 * attacks. It is not used anywhere in the library at the moment and is here for
 * historical reasons.
 *
 * Second sampling method implemented is Karney's method defined in Algorithm D
 * from https://arxiv.org/pdf/1303.6257.pdf, which is an improved method based
 * on rejection sampling. It also works for arbitrary centers and standard
 * deviations without any precomputation. Its rejection rate is smaller than in
 * the rejection sampling method but it may still be vulnerable to timing
 * attacks.
 *
 *
 * Final sampling method defined in this class is the Peikert's inversion method
 * discussed in section 4.1 of https://eprint.iacr.org/2010/088.pdf and
 * summarized in section 3.2.2 of
 * https://link.springer.com/content/pdf/10.1007%2Fs00200-014-0218-3.pdf. It
 * requires CDF tables of probabilities centered around single center to be
 * kept, which are precalculated in constructor. The method is not prone to
 * timing attacks but it is usable for single center, single deviation only.
 * It should be also noted that the memory requirement grows with the standard
 * deviation, therefore it is advised to use it with smaller deviations.   */

#ifndef LBCRYPTO_INC_MATH_DISCRETEGAUSSIANGENERATOR_H_
#define LBCRYPTO_INC_MATH_DISCRETEGAUSSIANGENERATOR_H_

#define _USE_MATH_DEFINES  // added for Visual Studio support

#include "math/distributiongenerator.h"

#include <memory>
#include <random>
#include <vector>

namespace lbcrypto {

constexpr double KARNEY_THRESHOLD = 300.0;

/**
 * @brief The class for Discrete Gaussion Distribution generator.
 */
template <typename VecType>
class DiscreteGaussianGeneratorImpl {
public:
    /**
   * @brief         Basic constructor for specifying distribution parameter and
   * modulus.
   * @param modulus The modulus to use to generate discrete values.
   * @param std     The standard deviation for this Gaussian Distribution.
   */
    explicit DiscreteGaussianGeneratorImpl(double std = 1.0);

    /**
   * @brief Destructor
   */
    ~DiscreteGaussianGeneratorImpl() = default;

    /**
     * @brief Check if the gaussian generator has been initialized with a standard deviation
     */
    bool IsInitialized() const;

    /**
   * @brief Initializes the generator.
   */
    void Initialize();

    /**
   * @brief  Returns the standard deviation of the generator.
   * @return The analytically obtained standard deviation of the generator.
   */
    double GetStd() const;

    /**
   * @brief     Sets the standard deviation of the generator.
   * @param std The analytic standard deviation of the generator.
   */
    void SetStd(double std);

    /**
   * @brief      Returns a generated signed integer. Uses Peikert's Inversion
   * Method
   * @return     a value generated with the distribution.
   */
    int32_t GenerateInt() const;

    /**
   * @brief      Returns a generated integer vector. Uses Peikert's inversion
   * method.
   * @param size The number of values to return.
   * @return     A pointer to an array of integer values generated with the
   * distribution.
   */
    std::shared_ptr<int64_t> GenerateIntVector(uint32_t size) const;

    /**
   * @brief  Returns a generated integer. Uses Peikert's inversion method.
   * @return A random value within this Discrete Gaussian Distribution.
   */
    typename VecType::Integer GenerateInteger(const typename VecType::Integer& modulus) const;

    /**
   * @brief           Generates a vector of random values within this Discrete
   * Gaussian Distribution. Uses Peikert's inversion method.
   *
   * @param  size     The number of values to return.
   * @param  modulus  modulus of the polynomial ring.
   * @return          The vector of values within this Discrete Gaussian
   * Distribution.
   */
    VecType GenerateVector(uint32_t size, const typename VecType::Integer& modulus) const;

    /**
   * @brief  Returns a generated integer. Uses rejection method.
   * @param mean center of discrete Gaussian distribution.
   * @param stddev standard deviatin of discrete Gaussian distribution.
   * @param n is ring dimension
   * param modulus modulus
   * @return A random value within this Discrete Gaussian Distribution.
   */
    typename VecType::Integer GenerateInteger(double mean, double stddev, size_t n,
                                              const typename VecType::Integer& modulus) const;

    /**
   * @brief  Returns a generated integer. Uses rejection method.
   * @param mean center of discrete Gaussian distribution.
   * @param stddev standard deviatin of discrete Gaussian distribution.
   * @param n is ring dimension
   * @return A random value within this Discrete Gaussian Distribution.
   */
    int32_t GenerateInteger(double mean, double stddev, size_t n) const;

    /**
   * @brief  Returns a generated integer (int32_t). Uses rejection method.
   * @param mean center of discrecte Gaussian distribution.
   * @param stddev standard deviatin of discrete Gaussian distribution.
   * @return A random value within this Discrete Gaussian Distribution.
   */
    // int32_t GenerateInt32 (double mean, double stddev);
    // will be defined later

    /**
   * @brief Returns a generated integer. Uses Karney's method defined as
   * Algorithm D in https://arxiv.org/pdf/1303.6257.pdf
   * @param mean center of discrecte Gaussian distribution.
   * @param stddev standard deviation of discrete Gaussian distribution.
   * @return A random value within this Discrete Gaussian Distribution.
   */
    static int64_t GenerateIntegerKarney(double mean, double stddev);

private:
    // Gyana to add precomputation methods and data members
    // all parameters are set as int because it is assumed that they are used for
    // generating "small" polynomials only
    double m_std{1.0};
    double m_a{0.0};
    std::vector<double> m_vals;
    bool peikert{false};

    uint32_t FindInVector(const std::vector<double>& S, double search) const;

    static double UnnormalizedGaussianPDF(const double& mean, const double& sigma, int32_t x) {
        return pow(M_E, -pow(x - mean, 2) / (2. * sigma * sigma));
    }

    static double UnnormalizedGaussianPDFOptimized(const double& mean, const double& sigmaFactor, int32_t x) {
        return pow(M_E, sigmaFactor * (x - mean) * (x - mean));
    }

    /**
   * @brief Subroutine used by Karney's Method to accept an integer with
   * probability exp(-n/2).
   * @param g Mersenne Twister Engine used for deviates
   * @param n Number to test with exp(-n/2) probability
   * @return Accept/Reject result
   */
    static bool AlgorithmP(PRNG& g, int32_t n);
    /**
   * @brief Subroutine used by Karney's Method to generate an integer with
   * probability exp(-k/2)(1 - exp(-1/2)).
   * @param g Mersenne Twister Engine used for deviates
   * @return Random number k
   */
    static int32_t AlgorithmG(PRNG& g);
    /**
   * @brief Generates a Bernoulli random value H which is true with probability
   * exp(-1/2).
   * @param g Mersenne Twister Engine used for uniform deviates
   * @return Bernoulli random value H
   */
    static bool AlgorithmH(PRNG& g);
    /**
   * @brief Generates a Bernoulli random value H which is true with probability
   * exp(-1/2). Uses double precision.
   * @param g Mersenne Twister Engine used for uniform deviates
   * @return Bernoulli random value H
   */
    static bool AlgorithmHDouble(PRNG& g);
    /**
   * @brief Bernoulli trial with probability exp(-x(2k + x)/(2k + 2)).
   * @param g Mersenne Twister Engine used for uniform deviates
   * @param k Deviate k used for calculations
   * @param x Deviate x used for calculations
   * @return Whether the number of runs are even or not
   */
    static bool AlgorithmB(PRNG& g, int32_t k, double x);
    /**
   * @brief Bernoulli trial with probability exp(-x(2k + x)/(2k + 2)). Uses
   * double precision.
   * @param g Mersenne Twister Engine used for uniform deviates
   * @param k Deviate k used for calculations
   * @param x Deviate x used for calculations
   * @return Whether the number of runs are even or not
   */
    static bool AlgorithmBDouble(PRNG& g, int32_t k, double x);
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATOR_H_
