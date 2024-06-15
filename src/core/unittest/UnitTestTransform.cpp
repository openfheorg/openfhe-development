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
  This code tests the transform feature of the OpenFHE lattice encryption library
 */

#include <iostream>
#include "gtest/gtest.h"

#include "lattice/lat-hal.h"
#include "lattice/ilelement.h"
#include "math/math-hal.h"
#include "math/distrgen.h"
#include "math/nbtheory.h"
#include "random"
#include "testdefs.h"
#include "utils/debug.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

using namespace lbcrypto;

// ---------------  TESTING METHODS OF TRANSFORM ---------------

// TEST CASE TO TEST POLYNOMIAL MULTIPLICATION USING CHINESE REMAINDER THEOREM

template <typename V>
void CRT_polynomial_mult(const std::string& msg) {
    typename V::Integer primeModulus("113");  // 65537
    usint cycloOrder = 8;
    usint n          = cycloOrder / 2;

    typename V::Integer primitiveRootOfUnity = lbcrypto::RootOfUnity(cycloOrder, primeModulus);

    ChineseRemainderTransformFTT<V>().PreCompute(primitiveRootOfUnity, cycloOrder, primeModulus);

    V a(n, primeModulus);
    a.at(0) = typename V::Integer("1");
    a.at(1) = typename V::Integer("2");
    a.at(2) = typename V::Integer("4");
    a.at(3) = typename V::Integer("1");
    V b(a);

    V A(cycloOrder / 2);
    ChineseRemainderTransformFTT<V>().ForwardTransformToBitReverse(a, primitiveRootOfUnity, cycloOrder, &A);
    V B(cycloOrder / 2);
    ChineseRemainderTransformFTT<V>().ForwardTransformToBitReverse(b, primitiveRootOfUnity, cycloOrder, &B);

    V AB = A * B;

    V InverseFFTAB(cycloOrder / 2);
    ChineseRemainderTransformFTT<V>().InverseTransformFromBitReverse(AB, primitiveRootOfUnity, cycloOrder,
                                                                     &InverseFFTAB);

    V expectedResult(n, primeModulus);
    expectedResult.at(0) = typename V::Integer("94");
    expectedResult.at(1) = typename V::Integer("109");
    expectedResult.at(2) = typename V::Integer("11");
    expectedResult.at(3) = typename V::Integer("18");

    EXPECT_EQ(expectedResult, InverseFFTAB) << msg << "inverse transform";
}

TEST(UTTransform, CRT_polynomial_mult) {
    RUN_ALL_BACKENDS(CRT_polynomial_mult, "CRT_polynomial_mult")
}

// TEST CASE TO TEST POLYNOMIAL MULTIPLICATION IN ARBITRARY CYCLOTOMIC FILED
// USING CHINESE REMAINDER THEOREM

template <typename V>
void CRT_polynomial_mult_small(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);

    usint m = 22;
    typename V::Integer squareRootOfRoot(3750);
    typename V::Integer modulus(4621);
    typename V::Integer bigModulus("32043581647489");
    typename V::Integer bigRoot("31971887649898");
    usint n = GetTotient(m);

    OPENFHE_DEBUG("m is " << m << " and n is " << n);
    auto cycloPoly = GetCyclotomicPolynomial<V>(m, modulus);
    OPENFHE_DEBUG("2 " << cycloPoly);

    // ChineseRemainderTransformArb<V>::PreCompute(m, modulus);
    ChineseRemainderTransformArb<V>().SetCylotomicPolynomial(cycloPoly, modulus);
    OPENFHE_DEBUG("3");

    V a(n, modulus);
    a      = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    auto A = ChineseRemainderTransformArb<V>().ForwardTransform(a, squareRootOfRoot, bigModulus, bigRoot, m);
    OPENFHE_DEBUG("4 " << A);

    V b(n, modulus);
    b      = {5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
    auto B = ChineseRemainderTransformArb<V>().ForwardTransform(b, squareRootOfRoot, bigModulus, bigRoot, m);
    OPENFHE_DEBUG("5 " << B);
    auto C = A * B;
    OPENFHE_DEBUG("6 " << C);

    auto c = ChineseRemainderTransformArb<V>().InverseTransform(C, squareRootOfRoot, bigModulus, bigRoot, m);

    OPENFHE_DEBUG("7 " << c);
    auto cCheck = PolynomialMultiplication(a, b);

    OPENFHE_DEBUG("8");
    cCheck = PolyMod(cCheck, cycloPoly, modulus);

    for (usint i = 0; i < n; i++) {
        EXPECT_EQ(cCheck.at(i), c.at(i)) << msg;
    }
}

TEST(UTTransform, CRT_polynomial_mult_small) {
    RUN_ALL_BACKENDS(CRT_polynomial_mult_small, "CRT_polynomial_mult_small")
}

// TEST CASE TO TEST POLYNOMIAL MULTIPLICATION IN ARBITRARY CYCLOTOMIC FILED
// USING CHINESE REMAINDER THEOREM

template <typename V>
void CRT_polynomial_mult_big_ring(const std::string& msg) {
    usint m = 1800;

    typename V::Integer modulus(14401);
    typename V::Integer bigModulus("1045889179649");
    typename V::Integer bigRoot("864331722621");
    typename V::Integer squareRootOfRoot("972");
    usint n        = GetTotient(m);
    auto cycloPoly = GetCyclotomicPolynomial<V>(m, modulus);

    ChineseRemainderTransformArb<V>().PreCompute(m, modulus);
    ChineseRemainderTransformArb<V>().SetCylotomicPolynomial(cycloPoly, modulus);

    V a(n, modulus);
    a      = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    auto A = ChineseRemainderTransformArb<V>().ForwardTransform(a, squareRootOfRoot, bigModulus, bigRoot, m);

    V b(n, modulus);
    b      = {5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
    auto B = ChineseRemainderTransformArb<V>().ForwardTransform(b, squareRootOfRoot, bigModulus, bigRoot, m);

    auto C = A * B;

    auto c = ChineseRemainderTransformArb<V>().InverseTransform(C, squareRootOfRoot, bigModulus, bigRoot, m);

    auto cCheck = PolynomialMultiplication(a, b);

    cCheck = PolyMod(cCheck, cycloPoly, modulus);
    for (usint i = 0; i < n; i++) {
        EXPECT_EQ(cCheck.at(i), c.at(i)) << msg;
    }
}

TEST(UTTransform, CRT_polynomial_mult_big_ring) {
    RUN_ALL_BACKENDS(CRT_polynomial_mult_big_ring, "CRT_polynomial_mult_big_ring")
}

template <typename V>
void CRT_polynomial_mult_big_ring_prime_cyclotomics(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);

    usint m = 1733;

    typename V::Integer modulus("1152921504606909071");
    typename V::Integer bigModulus("10889035741470030830827987437816582848513");
    typename V::Integer bigRoot("5879632101734955395039618227388702592012");
    typename V::Integer squareRootOfRoot("44343872016735288");
    usint n        = GetTotient(m);
    auto cycloPoly = GetCyclotomicPolynomial<V>(m, modulus);

    ChineseRemainderTransformArb<V>().PreCompute(m, modulus);
    ChineseRemainderTransformArb<V>().SetCylotomicPolynomial(cycloPoly, modulus);

    V a(n, modulus);
    a = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    auto A = ChineseRemainderTransformArb<V>().ForwardTransform(a, squareRootOfRoot, bigModulus, bigRoot, m);

    V b(n, modulus);
    b      = {5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
    auto B = ChineseRemainderTransformArb<V>().ForwardTransform(b, squareRootOfRoot, bigModulus, bigRoot, m);

    auto C = A * B;

    auto c = ChineseRemainderTransformArb<V>().InverseTransform(C, squareRootOfRoot, bigModulus, bigRoot, m);

    auto cCheck = PolynomialMultiplication(a, b);

    cCheck = PolyMod(cCheck, cycloPoly, modulus);
    OPENFHE_DEBUG("c " << c);
    OPENFHE_DEBUG("cCheck " << cCheck);
    EXPECT_EQ(cCheck, c) << msg;
}

TEST(UTTransform, CRT_polynomial_mult_big_ring_prime_cyclotomics) {
    RUN_BIG_BACKENDS(CRT_polynomial_mult_big_ring_prime_cyclotomics, "CRT_polynomial_mult_big_ring_prime_cyclotomics")
}

// TEST CASE TO TEST FORWARD AND INVERSE TRANSFORM IN ARBITRARY CYCLOTOMIC
// FILED.
// CHECKING IF INVERSET-TRANSFORM(FORWARD-TRANSFORM(A)) = A.

template <typename V>
void CRT_CHECK_small_ring(const std::string& msg) {
    usint m = 22;
    typename V::Integer squareRootOfRoot(3750);
    typename V::Integer modulus(4621);
    typename V::Integer bigModulus("32043581647489");
    typename V::Integer bigRoot("31971887649898");
    usint n = GetTotient(m);

    auto cycloPoly = GetCyclotomicPolynomial<V>(m, modulus);

    // ChineseRemainderTransformArb<V>::PreCompute(m, modulus);
    ChineseRemainderTransformArb<V>().SetCylotomicPolynomial(cycloPoly, modulus);

    V input(n, modulus);
    input      = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    auto INPUT = ChineseRemainderTransformArb<V>().ForwardTransform(input, squareRootOfRoot, bigModulus, bigRoot, m);

    auto inputCheck =
        ChineseRemainderTransformArb<V>().InverseTransform(INPUT, squareRootOfRoot, bigModulus, bigRoot, m);

    for (usint i = 0; i < n; i++) {
        EXPECT_EQ(input.at(i), inputCheck.at(i)) << msg;
    }
}

TEST(UTTransform, CRT_CHECK_small_ring) {
    RUN_ALL_BACKENDS(CRT_CHECK_small_ring, "CRT_CHECK_small_ring")
}

// TEST CASE TO TEST FORWARD AND INVERSE TRANSFORM IN ARBITRARY CYCLOTOMIC
// FILED.
// CHECKING IF INVERSET-TRANSFORM(FORWARD-TRANSFORM(A)) = A.

template <typename V>
void CRT_CHECK_big_ring(const std::string& msg) {
    usint m = 1800;

    typename V::Integer modulus(14401);
    typename V::Integer squareRootOfRoot("972");
    typename V::Integer bigModulus("1045889179649");
    typename V::Integer bigRoot("864331722621");
    usint n        = GetTotient(m);
    auto cycloPoly = GetCyclotomicPolynomial<V>(m, modulus);

    // ChineseRemainderTransformArb<V>::PreCompute(m, modulus);
    ChineseRemainderTransformArb<V>().SetCylotomicPolynomial(cycloPoly, modulus);

    V input(n, modulus);
    PRNG gen(1);

    std::uniform_int_distribution<> dis(0, 100);  // generates a number in [0,100]
    for (usint i = 0; i < n; i++) {
        input.at(i) = typename V::Integer(dis(gen));
    }

    auto output = ChineseRemainderTransformArb<V>().ForwardTransform(input, squareRootOfRoot, bigModulus, bigRoot, m);

    auto recOut = ChineseRemainderTransformArb<V>().InverseTransform(output, squareRootOfRoot, bigModulus, bigRoot, m);

    for (usint i = 0; i < n; i++) {
        EXPECT_EQ(input.at(i), recOut.at(i)) << msg;
    }
}

TEST(UTTransform, CRT_CHECK_big_ring) {
    RUN_ALL_BACKENDS(CRT_CHECK_big_ring, "CRT_CHECK_big_ring")
}

template <typename V>
void CRT_CHECK_small_ring_precomputed(const std::string& msg) {
    usint m = 22;
    typename V::Integer squareRootOfRoot(3750);
    typename V::Integer modulus(4621);
    usint n = GetTotient(m);

    auto cycloPoly = GetCyclotomicPolynomial<V>(m, modulus);
    typename V::Integer nttmodulus("32043581647489");
    typename V::Integer nttroot("31971887649898");

    // ChineseRemainderTransformArb<V>::PreCompute(m, modulus);
    // ChineseRemainderTransformArb<V>::SetPreComputedNTTModulus(m, modulus,
    // nttmodulus, nttroot);
    ChineseRemainderTransformArb<V>().SetCylotomicPolynomial(cycloPoly, modulus);

    V input(n, modulus);
    input = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    auto INPUT = ChineseRemainderTransformArb<V>().ForwardTransform(input, squareRootOfRoot, nttmodulus, nttroot, m);

    auto inputCheck =
        ChineseRemainderTransformArb<V>().InverseTransform(INPUT, squareRootOfRoot, nttmodulus, nttroot, m);

    for (usint i = 0; i < n; i++) {
        EXPECT_EQ(input.at(i), inputCheck.at(i)) << msg;
    }
}

TEST(UTTransform, CRT_CHECK_small_ring_precomputed) {
    RUN_ALL_BACKENDS(CRT_CHECK_small_ring_precomputed, "CRT_CHECK_small_ring_precomputed")
}

template <typename V>
void CRT_CHECK_very_big_ring_precomputed(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);
    usint m = 8422;
    OPENFHE_DEBUG("1");
    // find a modulus that has 2*8422 root of unity and is 120 bit long
    typename V::Integer modulus("619578785044668429129510602549015713");
    typename V::Integer squareRootOfRoot("204851043665385327685783246012876507");
    usint n = GetTotient(m);
    OPENFHE_DEBUG("UT GetTotient(" << m << ")= " << n);

    auto cycloPoly = GetCyclotomicPolynomial<V>(m, modulus);
    typename V::Integer nttmodulus(
        "185267342779705912677713576013900652565231975465024902463132134412661007"
        "6631041");
    typename V::Integer nttroot(
        "101185740842230903903955690719590885956153523464987081415401983436274640"
        "8101010");

    // ChineseRemainderTransformArb<V>::PreCompute(m, modulus);
    // ChineseRemainderTransformArb<V>::SetPreComputedNTTModulus(m, modulus,
    // nttmodulus, nttroot);

    OPENFHE_DEBUG("2");
    ChineseRemainderTransformArb<V>().SetCylotomicPolynomial(cycloPoly, modulus);
    OPENFHE_DEBUG("3");
    V input(n, modulus);
    input = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    OPENFHE_DEBUG("4");
    auto INPUT = ChineseRemainderTransformArb<V>().ForwardTransform(input, squareRootOfRoot, nttmodulus, nttroot, m);
    OPENFHE_DEBUG("5");
    auto inputCheck =
        ChineseRemainderTransformArb<V>().InverseTransform(INPUT, squareRootOfRoot, nttmodulus, nttroot, m);
    OPENFHE_DEBUG("6");
    for (usint i = 0; i < n; i++) {
        EXPECT_EQ(input.at(i), inputCheck.at(i)) << msg;
    }
}

TEST(UTTransform, CRT_CHECK_very_big_ring_precomputed) {
    RUN_BIG_BACKENDS(CRT_CHECK_very_big_ring_precomputed, "CRT_CHECK_very_big_ring_precomputed")
}
