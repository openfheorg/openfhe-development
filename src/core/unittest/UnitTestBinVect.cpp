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
  This code exercises the math libraries of the OpenFHE lattice encryption library.
 */

#include <iostream>
#include "gtest/gtest.h"

#include "lattice/lat-hal.h"
#include "lattice/ilelement.h"
#include "testdefs.h"
#include "utils/debug.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

using namespace lbcrypto;

// --------------- TESTING INTEGER OPERATIONS ON VECTOR  ---------------
/*
   at() operates on Big Vector, retrieves the value at the given index of a
   vector The functions returns BigInteger, which is passed to ConvertToInt() to
   convert to integer One dimensional integer array expectedResult is created
   Indivdual expected result for each index of the vector is store in array
   EXPECT_EQ is given the above integer from at, and the value of the
   expectedResult at the corresponding index
*/

// --------------- TESTING METHOD MODULUS FOR ALL CONDITIONS ---------------
/*   The method "Mod" operates on Big Vector m, BigInteger q
     Returns:  m mod q, and the result is stored in Big Vector
   calculatedResult.
*/
template <typename V>
void AtAndSetModulusTest(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);
    usint len = 10;
    V m(len);

    // note at() does not set modulus
    m.at(0) = typename V::Integer("987968");
    m.at(1) = typename V::Integer("587679");
    m.at(2) = typename V::Integer("456454");
    m.at(3) = typename V::Integer("234343");
    m.at(4) = typename V::Integer("769789");
    m.at(5) = typename V::Integer("465654");
    m.at(6) = typename V::Integer("79");
    m.at(7) = typename V::Integer("346346");
    m.at(8) = typename V::Integer("325328");
    m.at(9) = typename V::Integer("7698798");

    typename V::Integer q("233");

    m.SetModulus(q);

    OPENFHE_DEBUG("m" << m);
    V calculatedResult = m.Mod(q);
    OPENFHE_DEBUG("calculated result" << m);
    uint64_t expectedResult[] = {48, 53, 7, 178, 190, 120, 79, 108, 60, 12};
    for (usint i = 0; i < len; i++) {
        EXPECT_EQ(expectedResult[i], calculatedResult[i].ConvertToInt()) << msg << " Mod failed";
    }

    V n(len, q);

    n.at(0) = typename V::Integer("987968");  // note at() does not take modulus
    n.at(1) = typename V::Integer("587679");
    n.at(2) = typename V::Integer("456454");
    n.at(3) = typename V::Integer("234343");
    n.at(4) = typename V::Integer("769789");
    n.at(5) = typename V::Integer("465654");
    n.at(6) = typename V::Integer("79");
    n.at(7) = typename V::Integer("346346");
    n.at(8) = typename V::Integer("325328");
    n.at(9) = typename V::Integer("7698798");

    OPENFHE_DEBUG("n" << n);
    for (usint i = 0; i < len; i++) {
        if (i != 6) {  // value at 6 is < q
            EXPECT_NE(expectedResult[i], n[i].ConvertToInt()) << msg << " at no mod failed";
        }
        else {
            EXPECT_EQ(expectedResult[i], n[i].ConvertToInt()) << msg << " at no mod failed";
        }
    }

    V l(len, q);
    // note list assignment does take modulus
    l = {"987968", "587679", "456454", "234343", "769789", "465654", "79", "346346", "325328", "7698798"};
    OPENFHE_DEBUG("l" << l);
    for (usint i = 0; i < len; i++) {
        EXPECT_EQ(expectedResult[i], l[i].ConvertToInt()) << msg << " Mod on list assignment failed";
    }
}

TEST(UTBinVect, AtAndSetModulusTest) {
    RUN_BIG_BACKENDS(AtAndSetModulusTest, "AtAndSetModulusTest")
}

template <typename V>
void CTOR_Test(const std::string& msg) {
    typename V::Integer q("233");
    usint expectedResult[10] = {48, 53, 7, 178, 190, 120, 79, 108, 60, 12};
    const usint len          = sizeof(expectedResult) / sizeof(expectedResult[0]);

    {
        V m(len, q, {"987968", "587679", "456454", "234343", "769789", "465654", "79", "346346", "325328", "7698798"});

        V calculatedResult = m.Mod(q);

        for (usint i = 0; i < len; i++) {
            EXPECT_EQ(expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
        }
    }

    {
        V m(len, q, {48, 53, 7, 178, 190, 120, 79, 108, 60, 12});

        for (usint i = 0; i < len; i++) {
            EXPECT_EQ(expectedResult[i], m.at(i).ConvertToInt()) << msg;
        }
    }
}

TEST(UTBinVect, CTOR_Test) {
    RUN_BIG_BACKENDS(CTOR_Test, "CTOR_Test")
}

// --------------- TESTING METHOD MODADD FOR ALLCONDITIONS ---------------

/*   The method "Mod Add" operates on Big Vector m, BigIntegers n,q
        Returns:  (m+n)mod q, and the result is stored in Big Vector
   calculatedResult.
*/

// TEST CASE WHEN NUMBERS AFTER ADDITION ARE SMALLER THAN MODULUS

template <typename V>
void ModAddBigModulus(const std::string& msg) {
    typename V::Integer q("3435435");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    typename V::Integer n("3");

    // at() is ok since q is bigger than values
    m.at(0) = typename V::Integer("9868");
    m.at(1) = typename V::Integer("5879");
    m.at(2) = typename V::Integer("4554");
    m.at(3) = typename V::Integer("2343");
    m.at(4) = typename V::Integer("9789");

    V calculatedResult = m.ModAdd(n);

    uint64_t expectedResult[5] = {9871, 5882, 4557, 2346, 9792};

    for (usint i = 0; i < 5; i++) {
        EXPECT_EQ(expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
    }
}

TEST(UTBinVect, ModAddBigModulus) {
    RUN_BIG_BACKENDS(ModAddBigModulus, "ModAddBigModulus")
}

// TEST CASE WHEN NUMBERS AFTER ADDITION ARE GREATER THAN MODULUS

template <typename V>
void ModAddSmallerModulus(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);

    typename V::Integer q("3534");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    typename V::Integer n("34365");

    OPENFHE_DEBUG("m " << m);
    OPENFHE_DEBUG("m's modulus " << m.GetModulus());

    m.at(0) = typename V::Integer("9868");
    m.at(1) = typename V::Integer("5879");
    m.at(2) = typename V::Integer("4554");
    m.at(3) = typename V::Integer("2343");
    m.at(4) = typename V::Integer("9789");

    // at() does not apply mod so m is currently ill-formed for input to ModAdd
    // n is okay
    m.ModEq(q);

    V calculatedResult = m.ModAdd(n);

    OPENFHE_DEBUG("m " << m);
    OPENFHE_DEBUG("calculated result  " << calculatedResult);
    uint64_t expectedResult[5] = {1825, 1370, 45, 1368, 1746};

    for (usint i = 0; i < 5; i++) {
        EXPECT_EQ(expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
    }
}

TEST(UTBinVect, ModAddSmallerModulus) {
    RUN_BIG_BACKENDS(ModAddSmallerModulus, "ModAddSmallerModulus")
}

// --------------- TESTING METHOD MODUSUB FOR ALL CONDITIONS ---------------
/*   The method "Mod Sub" operates on Big Vector m, BigIntegers n,q
        Returns:
                when m>n, (m-n)mod q
                when m=n, 0
                when m<n, {(m mod q)+q-(n mod q)} mod q
        and the result is stored in Big Vector calculatedResult.
*/

// TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER

template <typename V>
void modsub_first_less_than_second(const std::string& msg) {
    typename V::Integer q("3534");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    typename V::Integer n("34365");

    m.at(0) = typename V::Integer("9868");
    m.at(1) = typename V::Integer("5879");
    m.at(2) = typename V::Integer("4554");
    m.at(3) = typename V::Integer("2343");
    m.at(4) = typename V::Integer("9789");

    // at() does not apply mod so m is currently ill-formed for input to ModSub
    // n is okay
    m.ModEq(q);

    V calculatedResult = m.ModSub(n);

    uint64_t expectedResult[5] = {241, 3320, 1995, 3318, 162};

    for (usint i = 0; i < 5; i++) {
        EXPECT_EQ(expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
    }
}

TEST(UTBinVect, modsub_first_less_than_second) {
    RUN_BIG_BACKENDS(modsub_first_less_than_second, "modsub_first_less_than_second")
}

// TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER

template <typename V>
void modsub_first_greater_than_second(const std::string& msg) {
    typename V::Integer q("35");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    typename V::Integer n("765");

    m.at(0) = typename V::Integer("9868");
    m.at(1) = typename V::Integer("5879");
    m.at(2) = typename V::Integer("4554");
    m.at(3) = typename V::Integer("2343");
    m.at(4) = typename V::Integer("9789");

    // at() does not apply mod so m is currently ill-formed for input to ModSub
    // n is okay
    m.ModEq(q);

    V calculatedResult = m.ModSub(n);

    uint64_t expectedResult[5] = {3, 4, 9, 3, 29};

    for (usint i = 0; i < 5; i++) {
        EXPECT_EQ(expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
    }
}

TEST(UTBinVect, modsub_first_greater_than_second) {
    RUN_BIG_BACKENDS(modsub_first_greater_than_second, "modsub_first_greater_than_second")
}

// --------------- TESTING METHOD MODUMUL FOR ALL CONDITIONS ---------------

/*   The method "Mod Mul" operates on Big Vector m, BigIntegers n,q
        Returns:  (m*n)mod q
        and the result is stored in Big Vector calculatedResult.
*/
template <typename V>
void ModMulTest(const std::string& msg) {
    typename V::Integer q("3534");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    typename V::Integer n("46");

    m.at(0) = typename V::Integer("9868");
    m.at(1) = typename V::Integer("5879");
    m.at(2) = typename V::Integer("4554");
    m.at(3) = typename V::Integer("2343");
    m.at(4) = typename V::Integer("9789");

    V calculatedResult = m.ModMul(n);

    uint64_t expectedResult[5] = {1576, 1850, 978, 1758, 1476};

    for (usint i = 0; i < 5; i++) {
        EXPECT_EQ(expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
    }
}

TEST(UTBinVect, ModMulTest) {
    RUN_BIG_BACKENDS(ModMulTest, "ModMulTest")
}

// --------------- TESTING METHOD MODEXP FOR ALL CONDITIONS  ---------------
/*   The method "Mod Exp" operates on Big Vector m, BigIntegers n,q
        Returns:  (m^n)mod q
        and the result is stored in Big Vector calculatedResult.
*/
template <typename V>
void ModExpTest(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);
    typename V::Integer q("3534");  // constructor calling to set mod value

    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    typename V::Integer n("3");

    m.at(0) = typename V::Integer("968");
    m.at(1) = typename V::Integer("579");
    m.at(2) = typename V::Integer("4");
    m.at(3) = typename V::Integer("2343");
    m.at(4) = typename V::Integer("97");
    OPENFHE_DEBUG("m's modulus " << m.GetModulus());

    V calculatedResult = m.ModExp(n);

    uint64_t expectedResult[5] = {2792, 3123, 64, 159, 901};

    for (usint i = 0; i < 5; i++) {
        EXPECT_EQ(expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
    }
}

TEST(UTBinVect, ModExpTest) {
    RUN_BIG_BACKENDS(ModExpTest, "ModExpTest")
}

// --------------- TESTING METHOD MODINVERSE FOR ALL CONDITIONS ---------------

/*   The method "Mod ModInverse" operates on Big Vector m, BigInteger q
        Returns:  (m^(-1))mod q
                when m and q are co-prime (i,e GCD of m and q is 1)
                and is calculated using extended Eucleadian Algorithm
        and the result is stored in Big Vector calculatedResult.
*/
template <typename V>
void test_modinv(const std::string& msg) {
    typename V::Integer q("35");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);

    m.at(0) = typename V::Integer("968");
    m.at(1) = typename V::Integer("579");
    m.at(2) = typename V::Integer("4");
    m.at(3) = typename V::Integer("2343");
    m.at(4) = typename V::Integer("97");

    V calculatedResult = m.ModInverse();

    uint64_t expectedResult[5] = {32, 24, 9, 17, 13};

    for (usint i = 0; i < 5; i++) {
        EXPECT_EQ(expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
    }
}

TEST(UTBinVect, test_modinv) {
    RUN_BIG_BACKENDS(test_modinv, "test_modinv")
}

// --------------- TESTING METHOD MODADD FOR ALL CONDITIONS ---------------

/*   The method "Mod Add" operates on Big Vectors m,n BigInteger q
        Returns:  (m+n)mod q, and the result is stored in Big Vector
   calculatedResult.
*/

// TEST CASE WHEN NUMBERS AFTER ADDITION ARE SMALLER THAN MODULUS

template <typename V>
void modadd_vector_result_smaller_modulus(const std::string& msg) {
    typename V::Integer q("878870");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    V n(5, q);

    m.at(0) = typename V::Integer("9868");
    m.at(1) = typename V::Integer("5879");
    m.at(2) = typename V::Integer("4554");
    m.at(3) = typename V::Integer("2343");
    m.at(4) = typename V::Integer("9789");

    n.at(0) = typename V::Integer("4533");
    n.at(1) = typename V::Integer("4549");
    n.at(2) = typename V::Integer("6756");
    n.at(3) = typename V::Integer("1233");
    n.at(4) = typename V::Integer("7897");

    V calculatedResult = m.ModAdd(n);

    uint64_t expectedResult[5] = {14401, 10428, 11310, 3576, 17686};

    for (usint i = 0; i < 5; i++) {
        EXPECT_EQ(expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
    }
}

TEST(UTBinVect, modadd_vector_result_smaller_modulus) {
    RUN_BIG_BACKENDS(modadd_vector_result_smaller_modulus, "modadd_vector_result_smaller_modulus")
}

// TEST CASE WHEN NUMBERS AFTER ADDITION ARE GREATER THAN MODULUS

template <typename V>
void modadd_vector_result_greater_modulus(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);
    typename V::Integer q("657");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    V n(5, q);

    m = {"9868", "5879", "4554", "2343", "9789"};

    n = {"4533", "4549", "6756", "1233", "7897"};

    OPENFHE_DEBUG("m " << m);
    OPENFHE_DEBUG("m mod" << m.GetModulus());
    OPENFHE_DEBUG("n " << n);
    OPENFHE_DEBUG("n mod " << n.GetModulus());

    V calculatedResult = m.ModAdd(n);

    OPENFHE_DEBUG("result mod " << calculatedResult.GetModulus());
    uint64_t expectedResult[5] = {604, 573, 141, 291, 604};

    for (usint i = 0; i < 5; i++) {
        EXPECT_EQ(expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
    }
}

TEST(UTBinVect, modadd_vector_result_greater_modulus) {
    RUN_BIG_BACKENDS(modadd_vector_result_greater_modulus, "modadd_vector_result_greater_modulus")
}

// --------------- TESTING METHOD ADD EQUALS FOR ALL CONDITIONS ---------------
/*   The operator "Add Equals" operates on Big Vectors m,n BigInteger q
        Returns:  (m+n)mod q, and the result is stored in Big Vector a.
*/
template <typename V>
void method_add_equals_vector_operation(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);
    typename V::Integer q("657");
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    V n(5, q);

    m = {"9868", "5879", "4554", "2343", "9789"};

    // note at does not allow uses of modulus.
    n.at(0) = typename V::Integer("4");
    n.at(1) = typename V::Integer("9");
    n.at(2) = typename V::Integer("66");
    n.at(3) = typename V::Integer("33");
    n.at(4) = typename V::Integer("7");

    OPENFHE_DEBUG("m " << m);
    OPENFHE_DEBUG("n " << n);

    m += n;
    OPENFHE_DEBUG("m" << m);
    uint64_t expectedResult[5] = {17, 632, 21, 405, 598};

    for (usint i = 0; i < 5; i++) {
        EXPECT_EQ(expectedResult[i], (m.at(i)).ConvertToInt()) << msg;
    }
}

TEST(UTBinVect, method_add_equals_vector_operation) {
    RUN_BIG_BACKENDS(method_add_equals_vector_operation, "method_add_equals_vector_operation")
}

// --------------- TESTING METHOD MODMUL FOR ALL CONDITIONS ---------------

/*   The operator "Mod Mul" operates on Big Vectors m,n BigInteger q
        Returns:  (m*n)mod q, and the result is stored in Big Vector a.
*/

template <typename V>
void modmul_vector(const std::string& msg) {
    typename V::Integer q("657");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    V n(5, q);

    m.at(0) = typename V::Integer("9868");
    m.at(1) = typename V::Integer("5879");
    m.at(2) = typename V::Integer("4554");
    m.at(3) = typename V::Integer("2343");
    m.at(4) = typename V::Integer("9789");

    n.at(0) = typename V::Integer("4");
    n.at(1) = typename V::Integer("9");
    n.at(2) = typename V::Integer("66");
    n.at(3) = typename V::Integer("33");
    n.at(4) = typename V::Integer("7");

    V calculatedResult = m.ModMul(n);

    uint64_t expectedResult[5] = {52, 351, 315, 450, 195};

    for (usint i = 0; i < 5; i++) {
        EXPECT_EQ(expectedResult[i], (calculatedResult.at(i)).ConvertToInt()) << msg;
    }
}

TEST(UTBinVect, modmul_vector) {
    RUN_BIG_BACKENDS(modmul_vector, "modmul_vector")
}
