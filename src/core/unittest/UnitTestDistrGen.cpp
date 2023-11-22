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
  This code exercises the random number distribution generator libraries of the OpenFHE lattice encryption library.
 */

#include <iostream>
#include <thread>

#include "gtest/gtest.h"

#include "lattice/lat-hal.h"
#include "math/distrgen.h"
#include "math/nbtheory.h"
#include "utils/debug.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

#include "testdefs.h"

using namespace lbcrypto;

//////////////////////////////////////////////////////////////////
// Testing Methods of BigInteger DiscreteUniformGenerator
//////////////////////////////////////////////////////////////////

// helper functions defined later
template <typename V>
void testDiscreteUniformGenerator(typename V::Integer& modulus, std::string test_name);

template <typename V>
void testParallelDiscreteUniformGenerator(typename V::Integer& modulus, std::string test_name);

template <typename V>
void DiscreteUniformGenerator_LONG(const std::string& msg) {
    // TEST CASE TO GENERATE A UNIFORM BIG BINARY INTEGER WITH SMALL MODULUS
    {
        typename V::Integer modulus("10403");
        auto dug = DiscreteUniformGeneratorImpl<V>();
        dug.SetModulus(modulus);
        typename V::Integer uniRandNum = dug.GenerateInteger();

        EXPECT_LT(uniRandNum, modulus) << msg << " Failure testing with_in_small_modulus_integer_small_modulus";
    }

    // TEST CASE TO GENERATE A UNIFORM BIG BINARY INTEGER WITH LARGE MODULUS
    {
        typename V::Integer modulus("10402635286389262637365363");
        auto dug = DiscreteUniformGeneratorImpl<V>();
        dug.SetModulus(modulus);
        typename V::Integer uniRandNum = dug.GenerateInteger();

        EXPECT_LT(uniRandNum, modulus) << msg << " Failure testing with_in_large_modulus_integer_large_modulus";
    }

    // TEST CASE TO GENERATE A UNIFORM BIG BINARY VECTOR WITH SMALL MODULUS
    {
        typename V::Integer modulus("10403");
        auto dug = DiscreteUniformGeneratorImpl<V>();

        usint size      = 10;
        V uniRandVector = dug.GenerateVector(size, modulus);
        // test length
        EXPECT_EQ(uniRandVector.GetLength(), size)
            << msg << " Failure testing vector_uniform_vector_small_modulus wrong length";
        // test content
        for (size_t i = 0; i < size; i++) {
            EXPECT_LT(uniRandVector.at(i), modulus) << msg
                                                    << " Failure testing vector_uniform_vector_small_modulus value "
                                                       "greater than modulus at index "
                                                    << i;
        }
    }

    // TEST CASE TO GENERATE A UNIFORM BIG BINARY VECTOR WITH LARGE MODULUS

    {
        typename V::Integer modulus("10402635286389262637365363");
        auto dug = DiscreteUniformGeneratorImpl<V>();

        usint size      = 100;
        V uniRandVector = dug.GenerateVector(size, modulus);
        // test length
        EXPECT_EQ(uniRandVector.GetLength(), size) << "Failure testing vector_uniform_vector_large_modulus";
        // test content
        for (size_t i = 0; i < size; i++) {
            EXPECT_LT(uniRandVector.at(i), modulus) << msg
                                                    << " Failure testing vector_uniform_vector_large_modulus value "
                                                       "greater than modulus at index "
                                                    << i;
        }
    }

    {
        // TEST CASE ON FIRST AND SECOND CENTRAL MOMENTS SMALL MODULUS
        typename V::Integer small_modulus("7919");
        testDiscreteUniformGenerator<V>(small_modulus, msg + " small_modulus");
    }
    {
        // TEST CASE ON FIRST AND SECOND CENTRAL MOMENTS LARGE MODULUS
        typename V::Integer large_modulus("100019");
        testDiscreteUniformGenerator<V>(large_modulus, msg + " large_modulus");
    }

    {
        // TEST CASE ON FIRST AND SECOND CENTRAL MOMENTS HUGE MODULUS
        typename V::Integer huge_modulus("10402635286389262637365363");
        testDiscreteUniformGenerator<V>(huge_modulus, msg + " huge_modulus");
    }

    // TEST CASE TO RECREATE OVERFLOW ISSUE CAUSED WHEN CALCULATING MEAN OF BBI's
    {
        int caught_error = 0;
        try {
            typename V::Integer modulus("10402635286389262637365363");  // 10402635286389262637365363
            auto dug = DiscreteUniformGeneratorImpl<V>();

            usint eachIterationSize = 1000, noOfIterations = 100;
            typename V::Integer sum, mean, N(eachIterationSize);

            V uniRandVector = dug.GenerateVector(eachIterationSize * noOfIterations, modulus);

            for (usint i = 0; i < noOfIterations; i++) {
                sum = mean = typename V::Integer(0);
                for (size_t j = i * eachIterationSize; j < (i + 1) * eachIterationSize; j++) {
                    sum += uniRandVector.at(j);
                }
                mean = sum.DividedBy(N);
            }
        }
        catch (...) {
            caught_error = 1;
        }
        EXPECT_EQ(caught_error, 0) << msg << " Failure recreate_overflow_issue threw an error";
    }
}

TEST(UTDistrGen, DiscreteUniformGenerator_LONG) {
    RUN_BIG_BACKENDS(DiscreteUniformGenerator_LONG, "DiscreteUniformGenerator_LONG")
}

//
// helper function to test first and second central moment of discrete uniform
// generator single thread case
template <typename V>
void testDiscreteUniformGenerator(typename V::Integer& modulus, std::string test_name) {
    // TEST CASE ON FIRST CENTRAL MOMENT

    double modulusInDouble      = modulus.ConvertToDouble();
    double expectedMeanInDouble = modulusInDouble / 2.0;

    auto distrUniGen = DiscreteUniformGeneratorImpl<V>();
    distrUniGen.SetModulus(modulus);

    usint size      = 50000;
    V randBigVector = distrUniGen.GenerateVector(size);

    double sum = 0;
    typename V::Integer length(std::to_string(randBigVector.GetLength()));

    for (usint index = 0; index < size; index++) {
        sum += (randBigVector.at(index)).ConvertToDouble();
    }

    double computedMeanInDouble = sum / size;
    double diffInMeans          = abs(computedMeanInDouble - expectedMeanInDouble);

    // within 1% of expected mean
    EXPECT_LT(diffInMeans, 0.01 * modulusInDouble) << "Failure testing first_moment_test_convertToDouble " << test_name;

    // TEST CASE ON SECOND CENTRAL MOMENT
    double expectedVarianceInDouble = ((modulusInDouble - 1.0) * (modulusInDouble - 1.0)) / 12.0;
    double expectedStdDevInDouble   = sqrt(expectedVarianceInDouble);

    sum = 0;
    double temp;
    for (usint index = 0; index < size; index++) {
        temp = (randBigVector.at(index)).ConvertToDouble() - expectedMeanInDouble;
        temp *= temp;
        sum += temp;
    }

    double computedVariance = (sum / size);
    double computedStdDev   = sqrt(computedVariance);
    double diffInStdDev     = abs(computedStdDev - expectedStdDevInDouble);

    EXPECT_LT(diffInStdDev, 0.01 * expectedStdDevInDouble)
        << "Failure testing second_moment_test_convertToDouble " << test_name;
}

#ifdef PARALLEL
template <typename V>
void ParallelDiscreteUniformGenerator_LONG(const std::string& msg) {
    // BUILD SEVERAL VECTORS OF BBI IN PARALLEL, CONCATENATE THEM TO ONE LARGE
    // VECTOR AND TEST THE RESULT OF THE FIRST AND SECOND CENTRAL MOMENTS

    typename V::Integer small_modulus("7919");  // test small modulus
    testParallelDiscreteUniformGenerator<V>(small_modulus, msg + " small_modulus");

    typename V::Integer large_modulus("100019");  // test large modulus
    testParallelDiscreteUniformGenerator<V>(large_modulus, msg + " large_modulus");

    typename V::Integer huge_modulus("10402635286389262637365363");
    testParallelDiscreteUniformGenerator<V>(huge_modulus, msg + " huge_modulus");
}

TEST(UTDistrGen, ParallelDiscreteUniformGenerator_LONG) {
    RUN_BIG_BACKENDS(ParallelDiscreteUniformGenerator_LONG, "ParallelDiscreteUniformGenerator_LONG")
}

//
// helper function to test first and second central moment of discrete uniform
// generator multi thread case
template <typename V>
void testParallelDiscreteUniformGenerator(typename V::Integer& modulus, std::string test_name) {
    double modulusInDouble = modulus.ConvertToDouble();
    // we expect the mean to be modulus/2 (the mid range of the min-max data);
    double expectedMeanInDouble = modulusInDouble / 2.0;
    usint size                  = 50000;
    // usint size = omp_get_max_threads() * 4;

    OPENFHE_DEBUG_FLAG(false);
    std::vector<typename V::Integer> randBigVector;
    #pragma omp parallel  // this is executed in parallel
    {
        // private copies of our vector
        std::vector<typename V::Integer> randBigVectorPvt;
        auto distrUniGen = DiscreteUniformGeneratorImpl<V>();

        distrUniGen.SetModulus(modulus);
        // build the vectors in parallel
    #pragma omp for nowait schedule(static)
        for (usint i = 0; i < size; i++) {
            // build private copies in parallel
            randBigVectorPvt.push_back(distrUniGen.GenerateInteger());
        }

    #pragma omp for schedule(static) ordered
        // now stitch them back together sequentially to preserve order of i
        for (int i = 0; i < omp_get_num_threads(); i++) {
    #pragma omp ordered
            {
                OPENFHE_DEBUG("thread #" << omp_get_thread_num() << " moving " << (int)randBigVectorPvt.size()
                                         << " to starting point " << (int)randBigVector.size());
                randBigVector.insert(randBigVector.end(), randBigVectorPvt.begin(), randBigVectorPvt.end());
                OPENFHE_DEBUG("thread #" << omp_get_thread_num() << " moved");
            }
        }
    }

    // now compute the sum over the entire vector
    double sum = 0;
    typename V::Integer length(std::to_string(randBigVector.size()));

    for (usint index = 0; index < size; index++) {
        sum += (randBigVector[index]).ConvertToDouble();
    }
    // divide by the size (i.e. take mean)
    double computedMeanInDouble = sum / size;
    // compute the difference between the expected and actual
    double diffInMeans = abs(computedMeanInDouble - expectedMeanInDouble);

    // within 1% of expected mean
    EXPECT_LT(diffInMeans, 0.01 * modulusInDouble)
        << "Failure testing parallel_first_central_moment_test " << test_name;

    // TEST CASE ON SECOND CENTRAL MOMENT SMALL MODULUS
    double expectedVarianceInDouble =
        ((modulusInDouble - 1.0) * (modulusInDouble - 1.0)) / 12.0;  // var = ((b-a)^2) /12
    double expectedStdDevInDouble = sqrt(expectedVarianceInDouble);

    sum = 0;
    double temp;
    for (usint index = 0; index < size; index++) {
        temp = (randBigVector[index]).ConvertToDouble() - expectedMeanInDouble;
        temp *= temp;
        sum += temp;
    }

    double computedVariance = (sum / size);
    double computedStdDev   = sqrt(computedVariance);

    double diffInStdDev = abs(computedStdDev - expectedStdDevInDouble);

    // within 1% of expected std dev
    EXPECT_LT(diffInStdDev, 0.1 * expectedStdDevInDouble) << "Failure testing second_central_moment_test " << test_name;
}
#endif

// TEST(UTDistrGen, DiscreteUniformGeneratorSeed ) {
//   typename V::Integer modulus("7919"); // test small modulus
//   double sum1=0;
//   usint size = 10;
//   {
//     DiscreteUniformGenerator distrUniGen =
//     lbcrypto::DiscreteUniformGenerator(modulus, 12345);

//     V randBigVector1 = distrUniGen.GenerateVector(size);

//     for(usint index=0; index<size; index++) {
//       sum1 += (randBigVector1.at(index)).ConvertToDouble();
//     }
//   }
//   DiscreteUniformGenerator distrUniGen =
//   lbcrypto::DiscreteUniformGenerator(modulus, 12345); V randBigVector2 =
//   distrUniGen.GenerateVector(size); double sum2=0;

//   for(usint index=0; index<size; index++) {
//     sum2 += (randBigVector2.at(index)).ConvertToDouble();
//   }

//   EXPECT_EQ(sum1, sum2) << "Failure, summs are different";

// }

////////////////////////////////////////////////
// Testing Methods of BigInteger BinaryUniformGenerator
////////////////////////////////////////////////

template <typename V>
void BinaryUniformGeneratorTest(const std::string& msg) {
    // fail if less than 0
    {
        auto binaryUniGen  = BinaryUniformGeneratorImpl<V>();
        auto binUniRandNum = binaryUniGen.GenerateInteger();
        EXPECT_GE(binUniRandNum.ConvertToInt(), 0ULL) << msg << " Failure less than 0";
    }

    // fail if gt 1
    {
        auto binaryUniGen  = BinaryUniformGeneratorImpl<V>();
        auto binUniRandNum = binaryUniGen.GenerateInteger();
        EXPECT_LE(binUniRandNum.ConvertToInt(), 1ULL) << msg << " Failure greater than 1";
    }

    // mean test
    {
        auto binaryUniGen = BinaryUniformGeneratorImpl<V>();

        usint length       = 100000;
        auto modulus       = typename V::Integer("1041");
        auto randBigVector = binaryUniGen.GenerateVector(length, modulus);

        usint sum = 0;

        for (usint index = 0; index < randBigVector.GetLength(); index++) {
            sum += randBigVector.at(index).ConvertToInt();
        }

        float computedMean = static_cast<float>(sum) / static_cast<float>(length);
        float expectedMean = 0.5;
        float dif          = abs(computedMean - expectedMean);

        EXPECT_LT(dif, 0.01) << msg << " Failure Mean is incorrect";
        // a large sample. Max of them should be less than q
    }
}

TEST(UTDistrGen, BinaryUniformGenerator) {
    RUN_ALL_BACKENDS(BinaryUniformGeneratorTest, "BinaryUniformGeneratorTest")
}

// mean test
template <typename V>
void TernaryUniformGeneratorTest(const std::string& msg) {
    auto ternaryUniGen = TernaryUniformGeneratorImpl<V>();

    usint length    = 100000;
    auto modulus    = typename V::Integer("1041");
    V randBigVector = ternaryUniGen.GenerateVector(length, modulus);

    int32_t sum = 0;

    for (usint index = 0; index < randBigVector.GetLength(); index++) {
        if (randBigVector[index] == modulus - typename V::Integer(1))
            sum -= 1;
        else
            sum += randBigVector[index].ConvertToInt();
    }

    float computedMean = static_cast<double>(sum) / static_cast<double>(length);

    float expectedMean = 0;
    float dif          = abs(computedMean - expectedMean);

    EXPECT_LT(dif, 0.01) << msg << " Ternary Uniform Distribution Failure Mean is incorrect";
    // a large sample. Max of them should be less than q
}

TEST(UTDistrGen, TernaryUniformGenerator) {
    RUN_ALL_BACKENDS(TernaryUniformGeneratorTest, "TernaryUniformGeneratorTest")
}

////////////////////////////////////////////////
// Testing Methods of BigInteger DiscreteGaussianGenerator
////////////////////////////////////////////////

template <typename V>
void DiscreteGaussianGeneratorTest(const std::string& msg) {
    // mean test

    {
        int stdev  = 5;
        usint size = 100000;
        typename V::Integer modulus("10403");
        auto dgg                               = DiscreteGaussianGeneratorImpl<V>(stdev);
        std::shared_ptr<int64_t> dggCharVector = dgg.GenerateIntVector(size);

        double mean = 0;
        for (usint i = 0; i < size; i++) {
            mean += static_cast<double>((dggCharVector.get())[i]);
        }
        mean /= size;

        EXPECT_LE(mean, 0.1) << msg << " Failure generate_char_vector_mean_test mean > 0.1";
        EXPECT_GE(mean, -0.1) << msg << " Failure generate_char_vector_mean_test mean < -0.1";
    }

    // generate_vector_mean_test
    {
        int stdev  = 5;
        usint size = 100000;
        typename V::Integer modulus("10403");
        typename V::Integer modulusByTwo(modulus.DividedBy(2));
        const auto dgg = DiscreteGaussianGeneratorImpl<V>(stdev);
        V dggBigVector = dgg.GenerateVector(size, modulus);

        usint countOfZero = 0;
        double mean = 0, current = 0;

        for (usint i = 0; i < size; i++) {
            current = std::stod(dggBigVector.at(i).ToString());
            if (current == 0)
                countOfZero++;
            mean += current;
        }

        mean /= (size - countOfZero);

        double modulusByTwoInDouble = std::stod(modulusByTwo.ToString());

        double diff = abs(modulusByTwoInDouble - mean);
        EXPECT_LT(diff, 104) << msg << " Failure generate_vector_mean_test";
    }
}

TEST(UTDistrGen, DiscreteGaussianGenerator) {
    RUN_ALL_BACKENDS(DiscreteGaussianGeneratorTest, "DiscreteGaussianGeneratorTest")
}

#ifdef PARALLEL
template <typename V>
void ParallelDiscreteGaussianGenerator_VERY_LONG(const std::string& msg) {
    // mean test
    OPENFHE_DEBUG_FLAG(false);

    {
        int stdev  = 5;
        usint size = 10000;
        typename V::Integer modulus("10403");

        std::vector<int32_t> dggCharVector;

    #pragma omp parallel  // this is executed in parallel
        {
            // private copies of our vector
            std::vector<int32_t> dggCharVectorPvt;
            auto dgg = DiscreteGaussianGeneratorImpl<V>(stdev);

            // build the vectors in parallel
    #pragma omp for nowait schedule(static)
            for (usint i = 0; i < size; i++) {
                // build private copies in parallel
                dggCharVectorPvt.push_back(dgg.GenerateInt());
            }

    #pragma omp for schedule(static) ordered
            // now stitch them back together sequentially to preserve order of i
            for (int i = 0; i < omp_get_num_threads(); i++) {
    #pragma omp ordered
                {
                    OPENFHE_DEBUG("thread #" << omp_get_thread_num() << " "
                                             << "moving " << (int)dggCharVectorPvt.size() << " to starting point"
                                             << (int)dggCharVector.size());
                    dggCharVector.insert(dggCharVector.end(), dggCharVectorPvt.begin(), dggCharVectorPvt.end());
                }
            }
        }

        double mean = 0;
        for (usint i = 0; i < size; i++) {
            mean += static_cast<double>(dggCharVector[i]);
        }
        mean /= size;

        EXPECT_LE(mean, 0.1) << msg << " Failure parallel generate_char_vector_mean_test mean > 0.1";
        EXPECT_GE(mean, -0.1) << msg << " Failure parallel generate_char_vector_mean_test mean < -0.1";
    }

    // generate_vector_mean_test
    {
        int stdev  = 5;
        usint size = 100000;
        typename V::Integer modulus("10403");
        typename V::Integer modulusByTwo(modulus.DividedBy(2));

        std::vector<typename V::Integer> dggBigVector;
    #pragma omp parallel  // this is executed in parallel
        {
            // private copies of our vector
            std::vector<typename V::Integer> dggBigVectorPvt;
            auto dgg = DiscreteGaussianGeneratorImpl<V>(stdev);

            // build the vectors in parallel
    #pragma omp for nowait schedule(static)
            for (usint i = 0; i < size; i++) {
                // build private copies in parallel
                dggBigVectorPvt.push_back(dgg.GenerateInteger(modulus));
            }

    #pragma omp for schedule(static) ordered
            // now stitch them back together sequentially to preserve order of i
            for (int i = 0; i < omp_get_num_threads(); i++) {
    #pragma omp ordered
                {
                    OPENFHE_DEBUG("thread #" << omp_get_thread_num() << " "
                                             << "moving " << (int)dggBigVectorPvt.size() << " to starting point"
                                             << (int)dggBigVector.size());
                    dggBigVector.insert(dggBigVector.end(), dggBigVectorPvt.begin(), dggBigVectorPvt.end());
                }
            }
        }

        usint countOfZero = 0;
        double mean = 0, current = 0;

        for (usint i = 0; i < size; i++) {
            current = std::stod(dggBigVector[i].ToString());
            if (current == 0)
                countOfZero++;
            mean += current;
        }

        mean /= (size - countOfZero);

        double modulusByTwoInDouble = std::stod(modulusByTwo.ToString());

        double diff = abs(modulusByTwoInDouble - mean);
        EXPECT_LT(diff, 104) << msg << " Failure generate_vector_mean_test";
    }
}

TEST(UTDistrGen, ParallelDiscreteGaussianGenerator_VERY_LONG) {
    RUN_ALL_BACKENDS(ParallelDiscreteGaussianGenerator_VERY_LONG, "ParallelDiscreteGaussianGenerator_VERY_LONG")
}
#endif  // PARALLEL

// Mean test for Karney sampling
template <typename V>
void Karney_Mean(const std::string& msg) {
    int stdev     = 10;
    usint size    = 10000;
    double mean   = 0;
    double center = 10;
    auto dgg      = DiscreteGaussianGeneratorImpl<V>(stdev);
    for (unsigned int i = 0; i < size; i++) {
        mean += dgg.GenerateIntegerKarney(center, stdev);
    }
    mean /= size;
    double difference = std::abs(mean - center);
    difference /= center;
    EXPECT_LE(difference, 0.1) << msg << " Failure to create mean with difference  < 10%";
}

TEST(UTDistrGen, Karney_Mean) {
    RUN_ALL_BACKENDS(Karney_Mean, "Karney_Mean")
}

// Variance test for Karney sampling
template <typename V>
void Karney_Variance(const std::string& msg) {
    int stdev       = 10;
    usint size      = 10000;
    double mean     = 0;
    double variance = 0;
    auto dgg        = DiscreteGaussianGeneratorImpl<V>(stdev);
    int numbers[10000];

    for (unsigned int i = 0; i < size; i++) {
        numbers[i] = dgg.GenerateIntegerKarney(0, stdev);
        mean += numbers[i];
    }
    mean /= size;
    for (unsigned int i = 0; i < size; i++) {
        variance += (numbers[i] - mean) * (numbers[i] - mean);
    }
    variance /= (size - 1);
    double difference = std::abs(variance - stdev * stdev) / (stdev * stdev);
    EXPECT_LE(difference, 0.1) << msg << " Failure to create variance with difference  < 10%";
}

TEST(UTDistrGen, Karney_Variance) {
    RUN_ALL_BACKENDS(Karney_Variance, "Karney_Variance")
}

#ifdef PARALLEL
void ThreadSafetyTestHelper() {
    PRNG& engine = PseudoRandomNumberGenerator::GetPRNG();
    engine();
}

template <typename V>
void ThreadSafetyInGetPRNG(const std::string& msg) {
    std::thread t1(ThreadSafetyTestHelper);
    t1.join();

    ThreadSafetyTestHelper();
}

TEST(UTDistrGen, ThreadSafetyInGetPRNG) {
    RUN_ALL_BACKENDS(ThreadSafetyInGetPRNG, "Thread safety in getPRNG")
}
#endif
