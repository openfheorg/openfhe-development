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

/*This is the header file for the Generic Sampler used for various Discrete
 * Gaussian Sampling applications. This class implements the generic sampler by
 * UCSD discussed in the https://eprint.iacr.org/2017/259.pdf and it is heavily
 * based on Michael Walter's original code. Along the sides of the
 * implementation there are also two different "base samplers", which are used
 * for the generic sampler or can be used on their own depending on the
 * requirements of needed application.
 *
 * The first base sampler uses Peikert's inversion method, discussed in
 * section 4.1 of https://eprint.iacr.org/2010/088.pdf and summarized in
 * section 3.2.2 of
 * https://link.springer.com/content/pdf/10.1007%2Fs00200-014-0218-3.pdf.
 * Peikert's method requires precomputation of CDF tables around a specific
 * center and the table must be kept during the sampling process. Hence,
 * Peikert's method works best if the DESIRED STANDARD DEVIATION IS SMALL and
 * THE MEAN OF THE DISTRIBUTION IS FIXED, as each new center will require a new
 * set of precomputations.
 *
 * Second base sampler is  the Knuth-Yao Sampler discussed in section 5 of
 * https://link.springer.com/content/pdf/10.1007%2Fs00200-014-0218-3.pdf .
 * Similar to Peikert's, Knuth-Yao precomputes the PDF's of the numbers based on
 * standard deviation and the center, which is used during the sampling process.
 * Therefore like Peikert's method,  Knuth-Yao works best method works best if
 * the DESIRED STANDARD DEVIATION IS SMALL and THE MEAN OF THE DISTRIBUTION IS
 * FIXED, as each new center will require a new set of precomputations, just
 * like Peikert's inversion method.
 *
 * The "generic sampler" on the other hand, works independent from standard
 * deviation of the distribution. It combines an array of previously discussed
 * base samplers centered around 0 to (2^b-1) / 2^b through convolution. The
 * tables of base samplers however, must be precomputed beforehand; but they do
 * not need to be recalculated at any time of the sampling process. It is USABLE
 * FOR ANY STANDARD DEVIATION AND MEAN, just like Karney's method defined in
 * discretegaussiangenerator.h, needs only one single precomputation and is not
 * prone to timing attacks unlike Karney. Karney's method, however, is faster
 * than the generic sampler.
 *
 * PARAMETER SELECTION FOR GENERIC SAMPLER
 *
 * The selection of parameters change the run time/memory usage/precision of the
 * generic sampler. The triple trade off between these parameters are defined in
 * the equation k = (PRECISION - FLIPS) / LOG_BASE. k denotes the level of
 * precision of the generic sampler. Higher the k is, higher the precision of
 * the generic sampler but higher the run time. PRECISION denotes the number of
 * decimal bits in the center of the distribution. Since we are using 'double'
 * for mean, it is fixed to 53 by definition. FLIPS denote the number of
 * Bernoulli flips used to approximate the bits used in combination of base
 * sampler. Higher the number of flips, larger the number of bits approximated
 * rather than calculated which means smaller run times. Generic sampler
 * requires a set of base samplers centered around 0/2^b to (2^b-1)/2^b;
 * LOG_BASE denotes b in this equation. Higher the LOG_BASE is, more base
 * samplers required which requires additional memory; but at the same time
 * smaller run times.
 *
 * The base samplers used in generic sampler requires varying centers between
 * 0/2^b and (2^b-1)/(2^b) with the same standard deviation. The standard
 * deviation required for base samplers must satisfy SIGMA>=4*SQRT(2)*N, where
 * sigma is the standard deviation of the base sampler and N is the smoothing
 * parameter
 *
 * */

#ifndef LBCRYPTO_INC_MATH_DISCRETEGAUSSIANGENERATORGENERIC_H_
#define LBCRYPTO_INC_MATH_DISCRETEGAUSSIANGENERATORGENERIC_H_

#define MAX_LEVELS 4

#include "math/distributiongenerator.h"

#include <cmath>
#include <memory>
#include <random>
#include <vector>

namespace lbcrypto {

enum BaseSamplerType { KNUTH_YAO = 0, PEIKERT = 1 };

class DiscreteGaussianGeneratorGeneric;
class BaseSampler;
class SamplerCombiner;
class BitGenerator;

/*
 * @brief Class implementation to generate random bit. This is created for
 * centralizing the random bit pools by the samplers.
 */
class BitGenerator {
public:
    BitGenerator()  = default;
    ~BitGenerator() = default;
    /*
   * @brief Method for generating a random bit
   * @return A random bit
   */
    short Generate() {  // NOLINT
        if (m_counter == 0) {
            m_sequence = (PseudoRandomNumberGenerator::GetPRNG())();
            m_counter  = 32;
        }
        return static_cast<short>((m_sequence >> (--m_counter)) & 0x1);  // NOLINT
    }

private:
    uint32_t m_sequence{0};
    uint32_t m_counter{0};
};
/*
 * @brief Class definiton for base samplers with precomputation that is used for
 * UCSD generic sampler
 */
class BaseSampler {
public:
    /*
   * @brief Constructor
   * @param mean Mean of the distribution
   * @param std Standard deviation of the distribution
   * @param generator Pointer to the bit generator that the sampler will use the
   * random bits from
   * @param bType Type of the base sampler
   */
    BaseSampler(double mean, double std, BitGenerator* generator, BaseSamplerType bType);
    BaseSampler() = default;
    /*
   * @brief Method for generating integer from the base sampler
   * @return A random integer from the distribution
   */
    virtual int64_t GenerateInteger();
    /*
   * @brief Destroyer for the base sampler
   */
    virtual ~BaseSampler() = default;
    /*
   * @brief Method for generating a random bit from the bit generator within
   * @return A random bit
   */
    short RandomBit() {  // NOLINT
        return bg->Generate();
    }

private:
    // all parameters are set as int because it is assumed that they are used for
    // generating "small" polynomials only
    double b_a;

    /**
   *Mean of the distribution used
   */
    int64_t b_mean;

    /**
   * The standard deviation of the distribution.
   */
    float b_std;

    /**
   * Generator used for creating random bits through sampling
   */
    BitGenerator* bg;
    /**
   * Type of the base sampler (Knuth Yao or Peikert's Inversion)
   */
    BaseSamplerType b_type;

    int fin;

    std::vector<std::vector<short>> DDGTree;  // NOLINT

    // short *DDGColumn = nullptr;

    /**
   *Array that stores the Hamming Weights of the probability matrix used in
   *Knuth-Yao sampling
   */
    std::vector<uint32_t> hammingWeights;
    /**
   *Size of probability matrix used in Knuth-Yao
   */
    int32_t b_matrixSize;

    /**
   *Index of first bit with non zero Hamming weight in the probability table
   */
    int32_t firstNonZero;

    int32_t endIndex;

    std::vector<double> m_vals;
    /**
   * @brief Sub-procedure called by Peikert's inversion sampling
   * @param S Vector containing the CDF values
   * @param search Searched probability value
   * @return Index that is the smallest bigger value than search
   */
    uint32_t FindInVector(const std::vector<double>& S, double search) const;
    /**
   * @brief Generates DDG tree used through the sampling in Knuth-Yao
   * @param probMatrix The probability matrix used for filling the DDG tree
   */
    void GenerateDDGTree(const std::vector<uint64_t>& probMatrix);
    /**
   * @brief Initializes the generator used for Peikert's Inversion method.
   * @param mean Mean of the distribution that the sampler will be using
   *
   */
    void Initialize(double mean);

    /**
   * @brief Generates the probability matrix of given distribution, which is
   * used in Knuth-Yao method
   * @param sttdev standard deviation of Discrete Gaussian Distribution
   * @param mean Center of the distribution
   * @param tableCount Number of probability tables to be generated
   */
    void GenerateProbMatrix(double stddev, double mean);
    /**
   * @ brief Returns a generated integer. Uses Naive Knuth-Yao method
   * @ return A random value within the Discrete Gaussian Distribution
   */
    int64_t GenerateIntegerKnuthYao();
    /**
   * @brief Returns a generated integer. Uses Peikert's inversion method.
   */
    int64_t GenerateIntegerPeikert() const;
};
/*
 * @brief Class for combining samples from two base samplers, which is used for
 * UCSD generic sampling
 */
class SamplerCombiner final : public BaseSampler {
public:
    /**
   * @brief Constructor
   * @param s1 Pointer to the first sampler to be combined
   * @param s2 Pointer to the second sampler to be combined
   * @param z1 Coefficient for the first sampler
   * @param z2 Coefficient for the second sampler
   */
    SamplerCombiner(BaseSampler* s1, BaseSampler* s2, int64_t z1, int64_t z2)
        : sampler1(s1), sampler2(s1), x1(z1), x2(z2) {}
    /**
   * @brief Return the combined value for two samplers with given coefficients
   * @return Combined value of the samplers with given coefficents
   */
    int64_t GenerateInteger() override {
        return x1 * sampler1->GenerateInteger() + x2 * sampler2->GenerateInteger();
    }
    /**
   * @brief Destructor
   */
    ~SamplerCombiner() = default;

private:
    // Samplers to be combined
    BaseSampler *sampler1, *sampler2;
    // Coefficients that are used for combining
    int64_t x1, x2;
};

/**
 * @brief The class for Generic Discrete Gaussion Distribution generator.
 */
class DiscreteGaussianGeneratorGeneric {
public:
    /**
   * @brief Basic constructor which does the precomputations.
   * @param samplers Array containing the base samplers
   * @param std Standard deviation of the base samplers
   * @param base Log of number of centers that are used for calculating base
   * samplers (Recall that base samplers are centered from 0 to (2^b-1)/2^b)
   * @param N smoothing parameter
   */
    DiscreteGaussianGeneratorGeneric(BaseSampler** samplers, const double std, const int b, double N);

    /**
   * @ brief Returns a generated integer. Uses generic algorithm in UCSD paper,
   * based on Sample Z
   * @ param mean Mean of the distribution
   * @ param variance Variance of the desired distribution
   * @ return A random value within the Discrete Gaussian Distribution
   */
    int64_t GenerateInteger(double mean, double std);
    int64_t GenerateInteger() {
        return base_samplers[0]->GenerateInteger();
    }
    /**
   * @brief Destructor
   */
    ~DiscreteGaussianGeneratorGeneric();

private:
    /**
   * @brief Subroutine used by Sample C
   * @param center Center of the distribution
   */
    int64_t flipAndRound(double center);
    /**
   * @brief Sample C defined in the paper
   * @param center Center of the distribution
   */
    int64_t SampleC(int64_t center);

    BaseSampler* wide_sampler;
    BaseSampler** base_samplers;
    BaseSampler* combiners[MAX_LEVELS];
    long double wide_variance, sampler_variance;
    double x, c, ci;
    int k, log_base;
    uint64_t mask;
    /**
   * @ brief Method to return the nth bit of a number
   * @ param number The number that the bit of desired
   * @ param n Desired bit number
   * @ return The nth bit of the number starting from 0 being the LSB
   */
    short extractBit(int64_t number, int n) {  // NOLINT
        return (number >> n) & 0x1;
    }
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_INC_MATH_DISCRETEGAUSSIANGENERATORGENERIC_H_
