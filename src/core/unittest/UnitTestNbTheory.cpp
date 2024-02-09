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
  This code exercises the math libraries of the OpenFHE lattice encryption library
 */

#include <iostream>
#include "gtest/gtest.h"

#include "lattice/lat-hal.h"
#include "lattice/ilelement.h"
#include "math/math-hal.h"
#include "math/distrgen.h"
#include "math/nbtheory.h"
#include "testdefs.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

using namespace lbcrypto;

// ---------------  TESTING METHODS OF NBTHEORY ---------------

template <typename T>
void method_greatest_common_divisor(const std::string& msg) {
    {
        // TEST CASE TO FIND GREATEST COMMON DIVISOR OF TWO SMALL NUMBERS
        T a("10403"), b("103");
        T c = GreatestCommonDivisor(a, b);

        uint64_t expectedResult = 103;

        EXPECT_EQ(expectedResult, c.ConvertToInt()) << msg << " Failure equals_small_numbers";
    }
    {
        // TEST CASE TO FIND GREATEST COMMON DIVISOR OF TWO POWERS OF 2 NUMBERS

        T a("1048576"), b("4096");
        T c(GreatestCommonDivisor(a, b));

        T expectedResult(b);

        EXPECT_EQ(expectedResult, c) << msg << " Failure equals_powers_of_two_numbers";
    }
    {
        // test that failed in Issue #409
        T a("883035439563027"), b("3042269397984931");
        T c(GreatestCommonDivisor(a, b));
        T expectedResult("1");
        EXPECT_EQ(expectedResult, c) << msg << " Failure Issue 409";
    }
}

TEST(UTNbTheory, method_greatest_common_divisor) {
    RUN_ALL_BACKENDS_INT(method_greatest_common_divisor, "method_greatest_common_divisor")
}

template <typename T>
void method_miller_rabin_primality(const std::string& msg) {
    {
        // TEST CASE FOR MILLER RABIN PRIMALITY TEST FOR SMALL PRIME
        T prime("24469");
        EXPECT_TRUE(MillerRabinPrimalityTest(prime)) << msg << " Failure is_prime_small_prime";
    }
    {
        // TEST CASE FOR MILLER RABIN PRIMALITY TEST FOR BIG PRIME

        T prime("952229140957");

        EXPECT_TRUE(MillerRabinPrimalityTest(prime)) << msg << " Failure is_prime_big_prime";
    }
    {
        // TEST CASE FOR MILLER RABIN PRIMALITY TEST FOR SMALL COMPOSITE NUMBER

        T isNotPrime("10403");

        EXPECT_FALSE(MillerRabinPrimalityTest(isNotPrime)) << msg << " Failure is_not_prime_small_composite_number";
    }
    {
        // TEST CASE FOR MILLER RABIN PRIMALITY TEST FOR BIG COMPOSITE NUMBER

        T isNotPrime("952229140959");

        EXPECT_FALSE(MillerRabinPrimalityTest(isNotPrime)) << msg << " Failure is_not_prime_big_composite_number";
    }
}

TEST(UTNbTheory, method_miller_rabin_primality) {
    RUN_ALL_BACKENDS_INT(method_miller_rabin_primality, "method_miller_rabin_primality")
}

// TEST CASE FOR FACTORIZATION

template <typename Element>
::testing::AssertionResult isMemberOf(Element val, const std::vector<Element>& values) {
    if (std::find(values.begin(), values.end(), val) != values.end())
        return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure();
}

template <typename T>
void method_factorize_returns_factors(const std::string& msg) {
    T comp("53093040");
    std::set<T> factors;
    std::vector<T> answers({2, 3, 5, 7, 11, 13, 15, 17});

    PrimeFactorize(comp, factors);

    for (auto it = factors.begin(); it != factors.end(); ++it) {
        EXPECT_TRUE(isMemberOf(*it, answers)) << msg;
    }
}

// NOLINTNEXTLINE
TEST(UTNbTheory, method_factorize_returns_factors){
    RUN_ALL_BACKENDS_INT(method_factorize_returns_factors, "method_factorize_returns_factors")}

TEST(UTNbTheory, first_prime_overflow) {
    // Failure case check
    usint m     = 512;
    usint nBits = NATIVEINT;

    EXPECT_THROW(FirstPrime<NativeInteger>(nBits, m), OpenFHEException)
        << "did not detect overflow and throw exception for Native";
    EXPECT_THROW(LastPrime<NativeInteger>(nBits, m), OpenFHEException)
        << "did not detect overflow and throw exception for Native";

#ifdef WITH_BE2
    nBits = BigIntegerBitLength + 10;

    EXPECT_THROW(FirstPrime<M2Integer>(nBits, m), OpenFHEException)
        << "did not detect overflow and throw exception for BE2";
#endif
}

template <typename T>
void method_prime_modulus(const std::string& msg) {
    usint m, nBits;
    {
        // TEST CASE TO FIND PRIME MODULUS
        m     = 2048;
        nBits = 30;

        T expectedResult("1073707009");

        EXPECT_EQ(expectedResult, LastPrime<T>(nBits, m)) << msg << " Failure foundPrimeModulus";
    }
    {
        // TEST CASE TO FIND PRIME MODULUS FOR A HIGHER BIT LENGTH
        m     = 4096;
        nBits = 49;

        T expectedResult("562949953392641");
        EXPECT_EQ(expectedResult, LastPrime<T>(nBits, m)) << msg << " Failure returns_higher_bit_length";
    }
}

TEST(UTNbTheory, method_prime_modulus) {
    RUN_ALL_BACKENDS_INT(method_prime_modulus, "method_prime_modulus")
}

template <typename T>
void method_primitive_root_of_unity_VERY_LONG(const std::string& msg) {
    {
        // TEST CASE TO ENSURE THE ROOT OF UNITY THAT IS FOUND IS A PRIMITIVE ROOT
        // OF UNTIY
        usint m     = 4096;
        usint nBits = 33;

        T primeModulus         = LastPrime<T>(nBits, m);
        T primitiveRootOfUnity = RootOfUnity<T>(m, primeModulus);

        T M(std::to_string(m)), MbyTwo(M.DividedBy(2));

        T wpowerm = primitiveRootOfUnity.ModExp(M, primeModulus);
        EXPECT_EQ(wpowerm, T(1)) << msg << " Failure single equal_m";

        T wpowermbytwo = primitiveRootOfUnity.ModExp(MbyTwo, primeModulus);
        EXPECT_NE(wpowermbytwo, T(1)) << msg << " Failure single not_equal_mbytwo";
    }
    {
        // TEST CASE TO ENSURE THE ROOTS OF UNITY THAT ARE FOUND ARE
        // CONSISTENTLY THE PRIMITIVE ROOTS OF UNTIY
        const usint n        = 256;
        const usint m        = 2 * n;
        const usint nBits    = 43;
        const int ITERATIONS = m * 2;

        T M(std::to_string(m)), MbyTwo(M.DividedBy(2)), MbyFour(MbyTwo.DividedBy(2));

        T primeModulus = LastPrime<T>(nBits, m);

        for (int i = 0; i < ITERATIONS; i++) {
            T primitiveRootOfUnity = RootOfUnity<T>(m, primeModulus);
            T wpowerm              = primitiveRootOfUnity.ModExp(M, primeModulus);
            EXPECT_EQ(wpowerm, T(1)) << msg << " Failure single input iteration " << i << " equal_m";
            T wpowermbytwo = primitiveRootOfUnity.ModExp(MbyTwo, primeModulus);
            EXPECT_NE(wpowermbytwo, T(1)) << msg << " Failure single input  iteration " << i << " not_equal_mbytwo";
            T wpowermbyfour = primitiveRootOfUnity.ModExp(MbyFour, primeModulus);
            EXPECT_NE(wpowermbyfour, T(1)) << msg << " Failure single input iteration " << i << "not_equal_mbyfour";
        }
    }
    {
        // TEST CASE TO ENSURE THE ROOTS OF UNITY FOUND FOR MULTIPLE
        // CYCLOTOMIC NUMBERS ARE ALL PRIMITIVE ROOTS OF UNTIY

        // ofstream fout;
        // fout.open ("primitiveRootsBug.log");
        usint nqBitsArray[] = {
            1,
            1,
            2,
            4,
            8,
            20,
            1024,
            30,
            2048,
            31,
            2048,
            33,
            2048,
            40,
            2048,
            41
            // const usint BIT_LENGTH = 200 and const usint FRAGMENTATION_FACTOR =
            // 27 ,2048, 51
            ,
            4096,
            32,
            4096,
            43
            // ,4096, 53
            ,
            8192,
            33,
            8192,
            44
            // ,8192, 55
            ,
            16384,
            34,
            16384,
            46
            // ,16384, 57
            ,
            32768,
            35,
            32768,
            47
            // ,32768, 59
        };
        int length = sizeof(nqBitsArray) / sizeof(nqBitsArray[0]);
        // double diff, start, finish;
        usint n, qBits, m;
        // T M(std::to_string(m)), MbyTwo(M.DividedBy(2)),
        // MbyFour(MbyTwo.DividedBy(2));

        for (int i = 2; i < length; i += 2) {
            // fout <<
            // "----------------------------------------------------------------------------------------------------------------------------------"
            // << endl; fout << "i = " << i << endl;
            n     = nqBitsArray[i];
            qBits = nqBitsArray[i + 1];
            m     = 2 * n;

            T M(std::to_string(m)), MbyTwo(M.DividedBy(2)), MbyFour(MbyTwo.DividedBy(2));

            // start = currentDateTime();
            // fout << "m=" << m << ", qBits=" << qBits << ", M=" << M << ", MbyTwo="
            // << MbyTwo << endl;
            T primeModulus = LastPrime<T>(qBits, m);
            // fout << "Prime modulus for n = " << n << " and qbits = " << qBits << "
            // is " << primeModulus << endl;

            T primitiveRootOfUnity(RootOfUnity<T>(m, primeModulus));

            // fout << "The primitiveRootOfUnity is " << primitiveRootOfUnity << endl;

            // std::set<T> rootsOfUnity = testRootsOfUnity(m, primeModulus);

            // fout << "Roots of unity for prime modulus " << primeModulus << " are: "
            // << endl; for(auto it = rootsOfUnity.begin(); it != rootsOfUnity.end();
            // ++it) {   fout << (*it) << ", ";
            // }
            // fout << endl;
            // finish = currentDateTime();
            // diff = finish - start;
            // fout << "Computation time: " << "\t" << diff << " ms" << endl;
            // fout <<
            // "----------------------------------------------------------------------------------------------------------------------------------"
            // << endl;

            T wpowerm = primitiveRootOfUnity.ModExp(M, primeModulus);
            // fout << "w^m = " << wpowerm << endl;
            EXPECT_EQ(wpowerm, T(1)) << msg << " Failure multi input iteration " << i << " equal_m";

            T wpowermbytwo = primitiveRootOfUnity.ModExp(MbyTwo, primeModulus);
            // fout << "w^(m/2) = " << wpowermbytwo << endl;
            EXPECT_NE(wpowermbytwo, T(1)) << msg << " Failure multi input  iteration " << i << " not_equal_mbytwo";

            T wpowermbyfour = primitiveRootOfUnity.ModExp(MbyFour, primeModulus);
            // fout << "w^(m/4) = " << wpowermbyfour << endl;
            EXPECT_NE(wpowermbyfour, T(1)) << msg << " Failure multi input  iteration " << i << " not_equal_mbyfour";
            // fout <<
            // "----------------------------------------------------------------------------------------------------------------------------------"
            // << endl; fout << endl;
        }
        // fout << "End of Computation" << endl;
        // fout.close();
    }

    // Exception handling
    {
        OPENFHE_DEBUG_FLAG(false);
        int m = 32;
        T modulus1("67108913"), modulus2("17729"), modulus3("2097169"), modulus4("8353"), modulus5("8369");

        // note this example shows two ways of testing for an exception throw
        T primitiveRootOfUnity1;

        // the first way is to catch the error and expect the result.
        int caught_error = 0;
        try {
            primitiveRootOfUnity1 = RootOfUnity<T>(m, modulus1);
        }
        catch (...) {
            caught_error = 1;
        }
        EXPECT_EQ(caught_error, 1) << msg << " RootOfUnity did not throw an error and should have";

        // the second way is to directly expect the throw.
        EXPECT_ANY_THROW(  // this call should throw
            primitiveRootOfUnity1 = RootOfUnity<T>(m, modulus1);)
            << msg << " RootOfUnity did not throw an error and should have";

        T primitiveRootOfUnity2;
        EXPECT_NO_THROW(  // this call should NOT throw
            primitiveRootOfUnity2 = RootOfUnity<T>(m, modulus2);)
            << msg << " RootOfUnity threw an error and should not have";

        OPENFHE_DEBUG("RootOfUnity for " << modulus1 << " is " << primitiveRootOfUnity1);
        OPENFHE_DEBUG("RootOfUnity for " << modulus2 << " is " << primitiveRootOfUnity2);
    }
}

TEST(UTNbTheory, method_primitive_root_of_unity_VERY_LONG) {
    RUN_ALL_BACKENDS_INT(method_primitive_root_of_unity_VERY_LONG, "method_primitive_root_of_unity_VERY_LONG")
}

template <typename T>
void test_nextQ(const std::string& msg) {
    usint m    = 2048;
    usint bits = 22;

    std::vector<T> moduliBBV = {T("4208641"), T("4263937"), T("4270081"), T("4274177"), T("4294657"),
                                T("4300801"), T("4304897"), T("4319233"), T("4323329"), T("4360193")};

    auto q = FirstPrime<T>(bits, m);
    for (usint i = 0; i < 10; i++) {
        q = NextPrime(q, m);
        EXPECT_EQ(q, moduliBBV[i]) << msg;
    }
}

TEST(UTNbTheory, test_nextQ) {
    RUN_ALL_BACKENDS_INT(test_nextQ, "test_nextQ")
}
