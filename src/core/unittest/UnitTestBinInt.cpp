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
  This code tests the binary integers in the math libraries of the OpenFHE lattice encryption library.
 */

#include "config_core.h"
#include "gtest/gtest.h"
#include "lattice/lat-hal.h"
#include "lattice/ilelement.h"
#include "math/math-hal.h"
#include "math/distrgen.h"
#include "math/nbtheory.h"
#include "testdefs.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

#include <iostream>

#define PROFILE

using namespace lbcrypto;

extern bool TestB2;
extern bool TestB4;
extern bool TestB6;
extern bool TestNative;

/************************************************/
/* TESTING METHODS OF ALL THE INTEGER CLASSES   */
/************************************************/

class UTBinInt : public ::testing::Test {
protected:
};

template <typename T>
void assign_test(const std::string& msg) {
    T v;
    std::vector<uint64_t> vals({
        27,
        uint64_t(1) << 10,
        uint64_t(1) << 25,
        uint64_t(1) << 35,
        uint64_t(1) << 55,
    });

    for (auto tv : vals) {
        v = uint64_t(tv);
        EXPECT_EQ(v.ConvertToInt(), tv) << msg;
    }
}

TEST_F(UTBinInt, assign) {
    RUN_ALL_BACKENDS_INT(assign_test, "assign")
}

template <typename T>
void identity_test(const std::string& msg) {
    // Function to produce a failure message
    auto f = [](T& a, const std::string& m) {
        T ZERO(0);
        T ONE(1);

        EXPECT_EQ(a, a + ZERO) << m << " Failure testing a + 0";
        EXPECT_EQ(a, a += ZERO) << m << " Failure testing a += 0";
        EXPECT_EQ(a, a * ONE) << m << " Failure testing a * 1";
        EXPECT_EQ(a, a *= ONE) << m << " Failure testing a *= 1";

        EXPECT_EQ(a, ZERO + a) << m << " Failure testing 0 + a";
        EXPECT_EQ(a, ZERO += a) << m << " Failure testing 0 += a";
        EXPECT_EQ(a, ONE * a) << m << " Failure testing 1 * a";
        EXPECT_EQ(a, ONE *= a) << m << " Failure testing 1 *= a";

        EXPECT_EQ(a * a, ONE *= a) << m << " Failure on 1 *= a, twice";
    };

    T sm("3279");
    f(sm, msg + " small");
    T lg("1234567898765432");
    f(lg, msg + " small");
}

TEST_F(UTBinInt, identity) {
    RUN_BIG_BACKENDS_INT(identity_test, "identity")
}

/************************************************/
/* TESTING BASIC MATH METHODS AND OPERATORS     */
/************************************************/
template <typename T>
void basic_math_test(const std::string& msg) {
    /************************************************/
    /* TESTING METHOD ADD FOR ALL CONDITIONS       */
    /************************************************/
    // The method "Add" does addition on two Ts a,b
    // Returns a+b, which is stored in another T
    // calculatedResult ConvertToInt converts T
    // calculatedResult to integer

    T calculatedResult;
    uint64_t expectedResult;
    // TEST_F CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER AND MSB
    // HAS NO OVERFLOW
    {
        T a("203450");
        T b("2034");

        calculatedResult = a.Add(b);
        expectedResult   = 205484;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing add_a_greater_than_b";
    }
    // TEST_F CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER AND MSB
    // HAS NO OVERFLOW
    {
        T a("2034");
        T b("203450");

        calculatedResult = a.Add(b);
        expectedResult   = 205484;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing add_a_less_than_b";
    }
    // TEST_F CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW TO THE NEXT
    // BYTE
    {
        T a("768900");
        T b("16523408");

        calculatedResult = a.Add(b);
        expectedResult   = 17292308;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing overflow_to_next_byte";
    }
    // TEST_F CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW IN THE SAME
    // BYTE
    {
        T a("35");
        T b("1015");

        calculatedResult = a.Add(b);
        expectedResult   = 1050;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing add_no_overflow_to_next_byte";
    }

    /************************************************/
    /* TESTING OPERATOR += FOR ALL CONDITIONS       */
    /************************************************/

    // The operator "+=(Add Equals)" does addition of two Big
    // Integers a,b Calculates a+b, and stores result in a ConvertToInt
    // converts T a to integer

    // TEST_F CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER AND MSB
    // HAS NO OVERFLOW
    {
        T a("2034");
        T b("203");

        a += b;
        expectedResult = 2237;

        EXPECT_EQ(expectedResult, a.ConvertToInt()) << " Failure testing add_equals_a_greater_than_b";
    }
    // TEST_F CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER AND MSB
    // HAS NO OVERFLOW
    {
        T a("2034");
        T b("203450");

        a += b;
        expectedResult = 205484;

        EXPECT_EQ(expectedResult, a.ConvertToInt()) << msg << " Failure testing add_equals_a_less_than_b";
    }
    // TEST_F CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW TO THE NEXT
    // BYTE
    {
        T a("768900");
        T b("16523408");

        a += b;
        expectedResult = 17292308;

        EXPECT_EQ(expectedResult, a.ConvertToInt()) << msg << " Failure testing add_equals_overflow_to_next_byte";
    }
    // TEST_F CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW IN THE SAME
    // BYTE
    {
        T a("35");
        T b("1015");

        a += b;
        expectedResult = 1050;

        EXPECT_EQ(expectedResult, a.ConvertToInt()) << msg << " Failure testing add_equals_no_overflow_to_next_byte";
    }
    /************************************************/
    /* TESTING METHOD SUB FOR ALL CONDITIONS      */
    /************************************************/

    // The method "Sub" does subtraction on two Ts a,b
    // Returns a-b, which is stored in another T
    // calculatedResult When a<b, the result is 0, since there is no
    // support for negative numbers as of now ConvertToInt converts
    // T calculatedResult to integer

    //  {
    //    // TEST_F CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER
    //
    //    T a("20489");
    //    T b("2034455");
    //
    //    calculatedResult = a.Sub(b);
    //    expectedResult = 0;
    //
    //    //SINCE THERE IS NO CONCEPT OF NEGATIVE NUMEBR RESULT SHOULD BE
    //    //ZERO
    //    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
    //      << msg << " Failure testing sub_a_less_than_b";
    //  }
    // TEST_F CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
    {
        T a("2048956567");
        T b("2048956567");

        calculatedResult = a.Sub(b);
        expectedResult   = 0;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing sub_a_equal_to_b";
    }
    // TEST_F CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
    {
        T a("2048956567");
        T b("2034455");

        calculatedResult = a.Sub(b);
        expectedResult   = 2046922112;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing sub_a_greater_than_b";
    }
    // TEST_F CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE
    {
        T a("196737");
        T b("65406");

        calculatedResult = a.Sub(b);
        expectedResult   = 131331;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing sub_borrow_from_next_byte";
    }

    /************************************************/
    /* TESTING OPERATOR -= FOR ALL CONDITIONS       */
    /************************************************/

    // The operator "-=(Sub Equals)" does subtraction of two Big
    // Integers a,b Calculates a-b, and stores result in a Results to 0,
    // when a<b, since there is no concept of negative number as of now
    // ConvertToInt converts T a to integer
    //  {
    //    // TEST_F CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER
    //
    //    T a("20489");
    //    T b("2034455");
    //
    //    a-=b;
    //    expectedResult = 0;
    //
    //    //SINCE THERE IS NO CONCEPT OF NEGATIVE NUMBER RESULT SHOULD BE ZERO
    //    EXPECT_EQ(expectedResult, a.ConvertToInt())
    //      << msg << " Failure testing sub_equals_a_less_than_b";
    //  }
    // TEST_F CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
    {
        T a("2048956567");
        T b("2048956567");

        a -= b;
        expectedResult = 0;

        EXPECT_EQ(expectedResult, a.ConvertToInt()) << msg << " Failure testing sub_equals_a_equal_to_b";
    }
    // TEST_F CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
    {
        T a("2048956567");
        T b("2034455");

        a -= b;
        expectedResult = 2046922112;

        EXPECT_EQ(expectedResult, a.ConvertToInt()) << msg << " Failure testing sub_equals_a_greater_than_b";
    }
    // TEST_F CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE
    {
        T a("196737");
        T b("65406");

        a -= b;
        expectedResult = 131331;

        EXPECT_EQ(expectedResult, a.ConvertToInt()) << msg << " Failure testing sub_equals_borrow_from_next_byte";
    }

    /************************************************/
    /* TESTING METHOD MUL FOR ALL CONDITIONS      */
    /************************************************/

    // The method "Mul" does multiplication on two Ts
    // a,b Returns a*b, which is stored in another T
    // calculatedResult ConvertToInt converts T
    // calculatedResult to integer
    {
        // ask about the branching if (b.m_MSB==0 or 1)
        T a("1967");
        T b("654");

        calculatedResult = a * b;
        expectedResult   = 1286418;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing mul_test";
    }

    /************************************************/
    /* TESTING METHOD DIVIDED_BY FOR ALL CONDITIONS */
    /************************************************/

    // The method "Divided By" does division of T a by
    // another T b Returns a/b, which is stored in another
    // T calculatedResult ConvertToInt converts
    // T calculatedResult to integer When b=0, throws
    // error, since division by Zero is not allowed When a<b, returns 0,
    // since decimal value is not returned

    // TEST_F CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER
    {
        T a("2048");
        T b("2034455");

        calculatedResult = a.DividedBy(b);
        expectedResult   = 0;

        // RESULT SHOULD BE ZERO
        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing divided_by_a_less_than_b";
    }

    // TEST_F CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
    {
        T a("2048956567");
        T b("2048956567");

        calculatedResult = a.DividedBy(b);
        expectedResult   = 1;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing divided_by_a_equals_b";
    }

    // TEST_F CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
    {
        T a("2048956567");
        T b("2034455");

        calculatedResult = a.DividedBy(b);
        expectedResult   = 1007;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing divided_by_a_greater_than_b";
    }

    {
        T a("8096");
        T b("4049");

        calculatedResult = a.Mod(b);
        expectedResult   = 4047;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing Mod";
    }

    // TEST_F CASE FOR VERIFICATION OF ROUNDING OPERATION.

    {
        T a("8096");
        T b("4049");

        calculatedResult = a.DivideAndRound(b);
        expectedResult   = 2;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing divided_and_rounding_by_a_greater_than_b";
    }

    /*{
    T a("204");
    T b("210");

    calculatedResult = a.DivideAndRound(b);
    expectedResult = 1;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << msg << " Failure testing divided_and_rounding_by_a_greater_than_b";
  }

  // TEST_F CASE FOR VERIFICATION OF ROUNDING OPERATION.
  {
          T a("100");
          T b("210");

          calculatedResult = a.DivideAndRound(b);
          expectedResult = 0;

          EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
                  << msg << " Failure testing
  divided_and_rounding_by_a_greater_than_b";
  }*/

    // TEST_F CASE FOR VERIFICATION OF ROUNDING OPERATION.
    /*{
    T a("4048");
    T b("4049");
    T c("2");

    calculatedResult = a.MultiplyAndRound(c, b);
    expectedResult = 2;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << msg << " Failure testing divided_and_rounding_by_a_greater_than_b";
  }*/
}

TEST_F(UTBinInt, basic_math) {
    RUN_ALL_BACKENDS_INT(basic_math_test, "basic math")
}

template <typename T>
void basic_compare_test(const std::string& msg) {
    /************************************************/
    /* TESTING BASIC COMPARATOR METHODS AND OPERATORS */
    /**************************************************/

    /************************************************/
    /* TESTING METHOD COMPARE FOR ALL CONDITIONS    */
    /************************************************/

    // The method "Compare" compares two Ts a,b
    // Returns:
    //    1, when a>b
    //    0, when a=b
    //   -1, when a<b
    //
    // Result is stored in signed integer, and then the result is
    // typecasted to int as EXPECT_EQ takes integer

    int c;
    int expectedResult;

    // TEST_F CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER
    {
        T a("112504");
        T b("46968");

        c              = a.Compare(b);
        expectedResult = 1;

        EXPECT_EQ(expectedResult, (int)c) << msg << " Failure testing compare_a_greater_than_b";
    }
    // TEST_F CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER
    {
        T a("12504");
        T b("46968");

        c              = a.Compare(b);
        expectedResult = -1;

        EXPECT_EQ(expectedResult, (int)c) << msg << " Failure testing compare_a_less_than_b";
    }
    // TEST_F CASE WHEN FIRST NUMBER IS EQUAL TO SECOND NUMBER
    {
        T a("34512504");
        T b("34512504");

        c              = a.Compare(b);
        expectedResult = 0;

        EXPECT_EQ(expectedResult, (int)c) << msg << " Failure testing compare_a_equals_b";
    }
}

TEST_F(UTBinInt, basic_compare) {
    RUN_ALL_BACKENDS_INT(basic_compare_test, "basic compare")
}

template <typename T>
void mod_test(const std::string& msg) {
    /************************************************/
    /* TESTING METHOD MOD FOR ALL CONDITIONS        */
    /************************************************/

    // The method "Mod" does modulus operation on two Ts
    // m,p Returns (m mod p), which is stored in another T
    // calculatedResult ConvertToInt converts T r to
    // integer

    T calculatedResult;
    uint64_t expectedResult;
    // TEST_F CASE WHEN THE NUMBER IS LESS THAN MOD
    {
        T m("27");
        T p("240");

        calculatedResult = m.Mod(p);
        expectedResult   = 27;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing number_less_than_modulus";
    }
    // TEST_F CASE WHEN THE NUMBER IS GREATER THAN MOD
    {
        T m("93409673");
        T p("406");

        calculatedResult = m.Mod(p);
        expectedResult   = 35;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing number_greater_than_modulus";
    }
    // TEST_F CASE WHEN THE NUMBER IS DIVISIBLE BY MOD
    {
        T m("32768");
        T p("16");

        calculatedResult = m.Mod(p);
        expectedResult   = 0;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing number_dividible_by_modulus";
    }

    // TEST_F CASE WHEN THE NUMBER IS EQUAL TO MOD
    {
        T m("67108913");
        T p("67108913");

        calculatedResult = m.Mod(p);
        expectedResult   = 0;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing number_equal_to_modulus";
    }

#ifdef OUT
    /************************************************/
    /* TESTING METHOD MOD BARRETT FOR ALL CONDITIONS */
    /************************************************/

    /*   The method "Divided By" does division of T m by another T p
        Function takes b as argument and operates on a
        Returns a/b, which is stored in another T calculatedResult
        ConvertToInt converts BigInteger calculatedResult to integer
        When b=0, throws error, since division by Zero is not allowed
        When a<b, returns 0, since decimal value is not returned
  */

    // TEST_F CASE WHEN THE NUMBER IS LESS THAN MOD      //NOT
    // GIVING PROPER OUTPUT AS OF NOW

    TEST_F(UTBinInt_METHOD_MOD_BARRETT, NUMBER_LESS_THAN_MOD) {
        T a("9587");
        T b("3591");
        T c("177");

        T calculatedResult = a.Mod(b, c);
        int expectedResult = 205484;

        std::cout << "\n" << d.ConvertToInt() << "\n";  // for testing purpose

        // EXPECT_EQ(27,calculatedResult.ConvertToInt());
    }
#endif
}

TEST_F(UTBinInt, mod_operations) {
    RUN_ALL_BACKENDS_INT(mod_test, "mod")
}

template <typename T>
void mod_inverse(const std::string& msg) {
    /*************************************************/
    /* TESTING METHOD MOD INVERSE FOR ALL CONDITIONS */
    /*************************************************/
    // The method "Mod Inverse" operates on Ts m,p
    // Returns {(m)^(-1)}mod p
    //    which is multiplicative inverse of m with respect to p, and is
    //    uses extended Euclidean algorithm m and p are co-primes (i,e GCD
    //    of m and p is 1)
    // If m and p are not co-prime, the method throws an error
    // ConvertToInt converts T calculatedResult to integer

    T calculatedResult;
    uint64_t expectedResult;

    // TEST_F CASE WHEN THE NUMBER IS GREATER THAN MOD
    {
        T m("5");
        T p("108");

        calculatedResult = m.ModInverse(p);
        expectedResult   = 65;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing number_less_than_modulus";
    }
    // TEST_F CASE WHEN THE NUMBER AND MOD ARE NOT CO-PRIME
    {
        T m("3017");
        T p("108");

        calculatedResult = m.ModInverse(p);
        expectedResult   = 77;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing number_greater_than_modulus";
    }

    // TESTCASE

    // testcase that failed during testing.
    {
        T first("4974113608263");
        T second("486376675628");
        std::string modcorrect("110346851983");
        T modresult;

        modresult = first.Mod(second);

        EXPECT_EQ(modcorrect, modresult.ToString()) << msg << " Failure ModInverse() Mod regression test";

        T input("405107564542978792");
        T modulus("1152921504606847009");
        std::string modIcorrect("844019068664266609");
        T modIresult;

        bool thrown = false;
        try {
            modIresult = input.ModInverse(modulus);
        }
        catch (...) {
            thrown = true;
        }

        EXPECT_FALSE(thrown) << msg << " Failure testing ModInverse() non co-prime arguments";
        EXPECT_EQ(modIcorrect, modIresult.ToString()) << msg << " Failure ModInverse() regression test";
    }

#ifdef OUT
    {
        // BBI just hangs, do not run this test.
        T first("4974113608263");
        T second("0");
        std::string modcorrect("4974113608263");
        T modresult;

        modresult = first.Mod(second);

        EXPECT_EQ(modcorrect, modresult.ToString()) << msg << " Failure ModInverse() Mod(0)";
    }
#endif
}

TEST_F(UTBinInt, mod_inverse) {
    RUN_ALL_BACKENDS_INT(mod_inverse, "modinv")
}

template <typename T>
void mod_arithmetic(const std::string& msg) {
    T calculatedResult;
    uint64_t expectedResult;
    /************************************************/
    /* TESTING METHOD MODADD FOR ALL CONDITIONS     */
    /************************************************/
    // The method "Mod Add" operates on Ts m,n,q
    //   Returns:
    //     (m+n)mod q
    //      = {(m mod q) + (n mod q)}mod q
    //   ConvertToInt converts T calculatedResult to integer

    // TEST_F CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
    {
        T m("58059595");
        T n("3768");
        T q("4067");

        calculatedResult = m.ModAdd(n, q);
        expectedResult   = 2871;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing first_number_greater_than_modulus";
    }
    // TEST_F CASE WHEN THE SECOND NUMBER IS GREATER THAN MOD
    {
        T m("595");
        T n("376988");
        T q("4067");

        calculatedResult = m.ModAdd(n, q);
        expectedResult   = 3419;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing second_number_greater_than_modulus";
    }
    // TEST_F CASE WHEN THE BOTH NUMBERS ARE LESS THAN MOD
    {
        T m("595");
        T n("376");
        T q("4067");

        calculatedResult = m.ModAdd(n, q);
        expectedResult   = 971;
        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing both_numbers_less_than_modulus";
    }
    // TEST_F CASE WHEN THE BOTH NUMBERS ARE GREATER THAN MOD
    {
        T m("59509095449");
        T n("37654969960");
        T q("4067");

        calculatedResult = m.ModAdd(n, q);
        expectedResult   = 2861;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing both_numbers_greater_than_modulus";
    }

    /************************************************/
    /* TESTING METHOD MODSUB FOR ALL CONDITIONS -*/
    /************************************************/

    // The method "Mod Sub" operates on Ts m,n,q
    //   Returns:
    //    (m-n)mod q
    //    = {(m mod q) - (n mod q)}mod q  when m>n
    //    = 0 when m=n
    //    = {(m mod q)+q-(n mod q)}mod q when m<n

    //   ConvertToInt converts T calculatedResult to integer

    // TEST_F CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
    {
        T m("595");
        T n("399");
        T q("406");

        calculatedResult = m.ModSub(n, q);
        expectedResult   = 196;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing first_number_greater_than_modulus";
    }
    // TEST_F CASE WHEN THE FIRST NUMBER LESS THAN SECOND NUMBER AND MOD
    {
        T m("39960");
        T n("595090959");
        T q("406756");

        calculatedResult = m.ModSub(n, q);
        expectedResult   = 33029;

        // [{(a mod c)+ c} - (b mod c)] since a < b
        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing first_number_less_than_modulus";
    }
    // TEST_F CASE WHEN THE FIRST NUMBER EQUAL TO SECOND NUMBER
    {
        T m("595090959");
        T n("595090959");
        T q("406756");

        calculatedResult = m.ModSub(n, q);
        expectedResult   = 0;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing first_number_equals_second_number";
    }

    /************************************************/
    /* TESTING METHOD MODMUL FOR ALL CONDITIONS     */
    /************************************************/

    // The method "Mod Mul" operates on Ts m,n,q
    //   Returns:  (m*n)mod q
    //              = {(m mod q)*(n mod q)}mod q
    // ConvertToInt converts T calculatedResult to integer

    // FIRST > MOD
    {
        T m("38");
        T n("4");
        T q("32");

        calculatedResult = m.ModMul(n, q);
        expectedResult   = 24;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing ModMul first > mod";
    }

    // FIRST == MOD
    {
        T m("32");
        T n("4");
        T q("32");

        calculatedResult = m.ModMul(n, q);
        expectedResult   = 0;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing ModMul first == mod";
    }

    // SECOND > MOD
    {
        T m("3");
        T n("37");
        T q("32");

        calculatedResult = m.ModMul(n, q);
        expectedResult   = 15;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing ModMul second > mod";
    }

    // SECOND == MOD
    {
        T m("3");
        T n("32");
        T q("32");

        calculatedResult = m.ModMul(n, q);
        expectedResult   = 0;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing ModMul second == mod";
    }

    // BOTH > MOD
    {
        T m("36");
        T n("37");
        T q("32");

        calculatedResult = m.ModMul(n, q);
        expectedResult   = 20;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing ModMul both > mod";
    }

    // BOTH == MOD
    {
        T m("32");
        T n("32");
        T q("32");

        calculatedResult = m.ModMul(n, q);
        expectedResult   = 0;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing ModMul both == mod";
    }

    // PRODUCT > MOD
    {
        T m("39");
        T n("37");
        T q("32");

        calculatedResult = m.ModMul(n, q);
        expectedResult   = 3;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing ModMul product > mod";
    }

    // PRODUCT == MOD
    {
        T m("8");
        T n("4");
        T q("32");

        calculatedResult = m.ModMul(n, q);
        expectedResult   = 0;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing ModMul product == mod";
    }

    /************************************************/
    /* TESTING METHOD MODEXP FOR ALL CONDITIONS     */
    /************************************************/

    // The method "Mod Exp" operates on Ts m,n,q
    // Returns:  (m^n)mod q
    //   = {(m mod q)^(n mod q)}mod q
    // ConvertToInt converts T calculatedResult to integer

    {
        T m("39960");
        T n("9");
        T q("406756");

        calculatedResult = m.ModExp(n, q);
        expectedResult   = 96776;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt()) << msg << " Failure testing mod_exp_test";
    }
}

TEST_F(UTBinInt, mod_arithmetic) {
    RUN_ALL_BACKENDS_INT(mod_arithmetic, "mod_arithmetic")
}

template <typename T>
void big_modexp(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);
    TimeVar t;

    TIC(t);
    T m("150802716267100577727763462252");
    T n("507060240091291760598681282151");
    T q("1014120480182583521197362564303");

    T calculatedResult = m.ModExp(n, q);
    T expectedResult("187237443793760596004690725849");

    EXPECT_EQ(expectedResult, calculatedResult) << msg << " Failure testing very big mod_exp_test";

    OPENFHE_DEBUG("big_modexp time ns " << TOC_NS(t));
}

TEST_F(UTBinInt, big_modexp) {
    RUN_BIG_BACKENDS_INT(big_modexp, "big_modexp")
}

template <typename T>
void power_2_modexp(const std::string& msg) {
    T m("2");
    T n("50");
    T q("16");

    T calculatedResult = m.ModExp(n, q);
    T expectedResult(0);

    EXPECT_EQ(expectedResult, calculatedResult) << msg << " Failure testing TWO.ModExp(50,16)";
}

TEST_F(UTBinInt, power_2_modexp) {
    RUN_ALL_BACKENDS_INT(power_2_modexp, "power_2_modexp")
}

template <typename T>
void shift(const std::string& msg) {
    /****************************/
    /* TESTING SHIFT OPERATORS  */
    /****************************/

    /*******************************************************/
    /* TESTING OPERATOR LEFT SHIFT (<<) FOR ALL CONDITIONS */
    /*******************************************************/

    // The operator 'Left Shift' operates on T a, and it
    // is shifted by a number

    // Returns: a<<(num), and the result is stored in Terger
    // calculatedResult 'a' is left shifted by 'num' number of bits, and
    // filled up by 0s from right which is equivalent to a * (2^num)
    //
    //        example:
    //            4<<3 => (100)<<3 => (100000) => 32
    //           this is equivalent to: 4* (2^3) => 4*8 =32
    // ConvertToInt converts T calculatedResult to integer

    // TEST_F CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
    {
        T a("39960");
        usshort shift = 3;

        T calculatedResult      = a << (shift);
        uint64_t expectedResult = 319680;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing shift_less_than_max_shift";
    }
    // TEST_F CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
    {
        T a("39960");
        usshort shift = 6;

        T calculatedResult      = a << (shift);
        uint64_t expectedResult = 2557440;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing shift_greater_than_max_shift";
    }

    /************************************************/
    /* TESTING OPERATOR LEFT SHIFT EQUALS (<<=) FOR ALL CONDITIONS -*/
    /************************************************/

    // The operator 'Left Shift Equals' operates on T a,
    // and it is shifted by a number
    // Returns:
    // a<<(num), and the result is stored in 'a'
    // 'a' is left shifted by 'num' number of bits, and filled up by 0s
    // from right which is equivalent to a * (2^num)
    // example :4<<3 => (100)<<3 => (100000) => 32
    // this is equivalent to: 4* (2^3) => 4*8 =32
    // ConvertToInt converts T a to integer

    // TEST_F CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
    {
        T a("39960");
        usshort num = 3;

        a <<= (num);
        uint64_t expectedResult = 319680;

        EXPECT_EQ(expectedResult, a.ConvertToInt()) << msg << " Failure testing shift_less_than_max_shift";
    }
    // TEST_F CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
    {
        T a("39960");
        usshort num = 6;

        a <<= (num);
        uint64_t expectedResult = 2557440;

        EXPECT_EQ(expectedResult, a.ConvertToInt()) << msg << " Failure testing shift_greater_than_max_shift";
    }

    /********************************************************/
    /* TESTING OPERATOR RIGHT SHIFT (>>) FOR ALL CONDITIONS */
    /********************************************************/
    // The operator 'Right Shift' operates on T a, and it
    // is shifted by a number

    // Returns: a>>(num), and the result is stored in T
    // calculated. Result 'a' is right shifted by 'num' number of bits,
    // and filled up by 0s from left which is equivalent to a / (2^num)

    //  ex:4>>3 => (100000)>>3 => (000100) => 4

    // this is equivalent to: 32*(2^3) => 32/8 = 4
    // ConvertToInt converts T calculatedResult to integer

    // TEST_F CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
    {
        T a("39965675");
        usshort shift = 3;

        T calculatedResult      = a >> (shift);
        uint64_t expectedResult = 4995709;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing shift_less_than_max_shift";
    }
    // TEST_F CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
    {
        T a("39965675");
        usshort shift = 6;

        T calculatedResult      = a >> (shift);
        uint64_t expectedResult = 624463;

        EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
            << msg << " Failure testing shift_greater_than_max_shift";
    }

    /***************************************************************/
    /* TESTING OPERATOR RIGHT SHIFT EQUALS(>>=) FOR ALL CONDITIONS */
    /***************************************************************/

    // The operator 'Right Shift Equals' operates on T a,
    // and it is shifted by a number

    // Returns: a>>=(num), and the result is stored in a 'a' is right
    // shifted by 'num' number of bits, and filled up by 0s from left
    // which is equivalent to a / (2^num)

    //   ex:4>>3 => (100000)>>3 => (000100) => 4

    //   this is equivalent to: 32*(2^3) => 32/8 = 4
    //   ConvertToInt converts T calculatedResult to integer

    // TEST_F CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
    {
        T a("39965675");
        usshort shift = 3;

        a >>= (shift);
        uint64_t expectedResult = 4995709;

        EXPECT_EQ(expectedResult, a.ConvertToInt()) << msg << " Failure testing shift_less_than_max_shift";
    }
    // TEST_F CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
    {
        T a("39965675");
        usshort shift = 6;

        a >>= (shift);
        uint64_t expectedResult = 624463;

        EXPECT_EQ(expectedResult, a.ConvertToInt()) << msg << " Failure testing shift_greater_than_max_shift";
    }
}

TEST_F(UTBinInt, shift) {
    RUN_ALL_BACKENDS_INT(shift, "shift")
}

/****************************************/
/* TESTING METHOD  FromBinaryString */
/****************************************/

template <typename T>
void binString(const std::string& msg) {
    // TEST_F CASE FOR STATIC METHOD FromBinaryString in BigInteger

    std::string binaryString = "1011101101110001111010111011000000011";
    T b                      = T::FromBinaryString(binaryString);

    T expectedResult("100633769475");
    EXPECT_EQ(expectedResult, b) << msg << " Failure testing FromBinaryString";
}

TEST_F(UTBinInt, binString) {
    RUN_ALL_BACKENDS_INT(binString, "binString")
}

template <typename T>
void expNoMod(const std::string& msg) {
    T x("56");
    T result = x.Exp(10);

    T expectedResult("303305489096114176");
    EXPECT_EQ(expectedResult, result) << msg << " Failure testing exp";
}

TEST_F(UTBinInt, expNoMod) {
    RUN_ALL_BACKENDS_INT(expNoMod, "expNoMod")
}

template <typename T>
void convToDouble(const std::string& msg) {
    T x("104037585658683680");
    double xInDouble = 104037585658683680;

    EXPECT_EQ(xInDouble, x.ConvertToDouble()) << msg;
}

TEST_F(UTBinInt, convToDouble) {
    RUN_ALL_BACKENDS_INT(convToDouble, "convToDouble")
}

template <typename T>
void getDigitAtIndex(const std::string& msg) {
    T x(0xa);

    EXPECT_EQ(x.GetDigitAtIndexForBase(1, 2), 0ULL) << msg;
    EXPECT_EQ(x.GetDigitAtIndexForBase(2, 2), 1ULL) << msg;
    EXPECT_EQ(x.GetDigitAtIndexForBase(3, 2), 0ULL) << msg;
    EXPECT_EQ(x.GetDigitAtIndexForBase(4, 2), 1ULL) << msg;
}

TEST_F(UTBinInt, getDigitAtIndex) {
    RUN_ALL_BACKENDS_INT(getDigitAtIndex, "getDigitAtIndex")
}

template <typename T>
void GetBitAtIndex(const std::string& msg) {
    T x(1);

    x <<= 55;  // x has one bit at 55

    x += T(2);  // x has one bit at 2

    // index is 1 for lsb!
    EXPECT_EQ(x.GetBitAtIndex(1), 0) << msg;
    EXPECT_EQ(x.GetBitAtIndex(2), 1) << msg;

    for (auto idx = 3; idx < 55; idx++) {
        EXPECT_EQ(x.GetBitAtIndex(idx), 0) << msg;
    }
    EXPECT_EQ(x.GetBitAtIndex(56), 1) << msg;
}

TEST_F(UTBinInt, GetBitAtIndex) {
    RUN_ALL_BACKENDS_INT(GetBitAtIndex, "GetBitAtIndex")
}

template <typename T>
void GetInternalRepresentation(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);
    T x(1);

    x <<= 100;  // x has one bit at 101
    x += T(2);  // x has one bit at 2

    auto x_limbs = x.GetInternalRepresentation();

#if !defined(NDEBUG)
    if (dbg_flag) {
        OPENFHE_DEBUG(x_limbs);
        OPENFHE_DEBUG("x_limbs " << x_limbs);
        OPENFHE_DEBUG("x " << x);
    }
#endif

    // define what is correct based on math backend selected
    std::string correct("2 0 0 16");

// TODO: clean this up
#ifdef WITH_BE4
    #if (NATIVEINT >= 64 && defined(HAVE_INT128))
    correct = "2 68719476736";
    #endif
#endif

#ifdef WITH_NTL
    if (typeid(T) == typeid(M6Integer))
        correct = "2 68719476736";
#endif

    EXPECT_EQ(correct, x_limbs) << msg;
}

TEST_F(UTBinInt, GetInternalRepresentation) {
    RUN_BIG_BACKENDS_INT(GetInternalRepresentation, "GetInternalRepresentation")
}
