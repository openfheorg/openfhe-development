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
  This code exercises the Field2n methods of the OpenFHE lattice encryption library.
 */

#include "gtest/gtest.h"
#include "lattice/field2n.h"
#include "math/dftransform.h"
#include "utils/debug.h"

using namespace lbcrypto;

// ---------------  TESTING METHODS OF FIELD2N ---------------

// TEST FOR GETTER FOR FORMAT
TEST(UTField2n, get_format) {
    OPENFHE_DEBUG_FLAG(false);

    OPENFHE_DEBUG("Step 1");
    Field2n test(2, Format::COEFFICIENT, true);
    OPENFHE_DEBUG("Step 2");
    EXPECT_EQ(Format::COEFFICIENT, test.GetFormat()) << "Failed getter" << std::endl;
}

// TEST FOR INVERSE OF FIELD ELEMENT
TEST(UTField2n, inverse) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("Step 1");
    Field2n test(2, Format::EVALUATION, true);
    test.at(0) = std::complex<double>(2, 1);
    test.at(1) = std::complex<double>(-4, -2);
    OPENFHE_DEBUG("Step 2");
    Field2n inverse(2, Format::EVALUATION, true);
    inverse.at(0) = std::complex<double>(0.4, -0.2);
    inverse.at(1) = std::complex<double>(-0.2, 0.1);
    OPENFHE_DEBUG("Step 3");
    EXPECT_EQ(inverse, test.Inverse());
}

// TEST FOR ADDITION OPERATION
TEST(UTField2n, plus) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("Step 1");
    Field2n a(2, Format::EVALUATION, true);
    a.at(0) = std::complex<double>(2, 1);
    a.at(1) = std::complex<double>(-4, 2);
    OPENFHE_DEBUG("Step 2");
    Field2n b(2, Format::EVALUATION, true);
    b.at(0) = std::complex<double>(3, -0.1);
    b.at(1) = std::complex<double>(-4, 3.2);
    OPENFHE_DEBUG("Step 3");
    Field2n c(2, Format::EVALUATION, true);
    c.at(0) = std::complex<double>(5, 0.9);
    c.at(1) = std::complex<double>(-8, 5.2);
    EXPECT_EQ(c, a.Plus(b));
}

// TEST FOR SCALAR ADDITION
TEST(UTField2n, scalar_plus) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("Step 1");
    Field2n a(2, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(2, 0);
    a.at(1) = std::complex<double>(-4, 0);
    OPENFHE_DEBUG("Step 2");
    double b = 3.2;
    OPENFHE_DEBUG("Step 3");
    Field2n c(2, Format::COEFFICIENT, true);
    c.at(0) = std::complex<double>(5.2, 0);
    c.at(1) = std::complex<double>(-4, 0);
    EXPECT_EQ(c, a.Plus(b));
}

// TEST FOR SUBSTRACTION OPERATION
TEST(UTField2n, minus) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("Step 1");
    Field2n a(2, Format::EVALUATION, true);
    a.at(0) = std::complex<double>(2, 1);
    a.at(1) = std::complex<double>(-4, 2);
    OPENFHE_DEBUG("Step 2");
    Field2n b(2, Format::EVALUATION, true);
    b.at(0) = std::complex<double>(3, -0.1);
    b.at(1) = std::complex<double>(-4, 3.2);
    OPENFHE_DEBUG("Step 3");
    Field2n c(2, Format::EVALUATION, true);
    c.at(0) = std::complex<double>(-1, 1.1);
    c.at(1) = std::complex<double>(0, -1.2);

    Field2n d = a.Minus(b);
    for (int i = 0; i < 2; i++) {
        EXPECT_LE(fabs(d.at(i).real() - c.at(i).real()), fabs(c.at(i).real()) * 0.00001);
        EXPECT_LE(fabs(d.at(i).imag() - c.at(i).imag()), fabs(c.at(i).imag()) * 0.00001);
    }
}

// TEST FOR MULTIPLICATION OPERATION
TEST(UTField2n, times) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("Step 1");
    Field2n a(2, Format::EVALUATION, true);
    a.at(0) = std::complex<double>(4, 3);
    a.at(1) = std::complex<double>(6, -3);
    OPENFHE_DEBUG("Step 2");
    Field2n b(2, Format::EVALUATION, true);
    b.at(0) = std::complex<double>(4, -3);
    b.at(1) = std::complex<double>(4, -2.8);
    OPENFHE_DEBUG("Step 3");
    Field2n c(2, Format::EVALUATION, true);
    c.at(0) = std::complex<double>(25, 0);
    c.at(1) = std::complex<double>(15.6, -28.8);
    OPENFHE_DEBUG("Step 4");
    Field2n d = a.Times(b);
    for (int i = 0; i < 2; i++) {
        EXPECT_LE(fabs(d.at(i).real() - c.at(i).real()), fabs(c.at(i).real()) * 0.00001);
        EXPECT_LE(fabs(d.at(i).imag() - c.at(i).imag()), fabs(c.at(i).imag()) * 0.00001);
    }
}

// TEST FOR MULTIPLICATION OPERATION WITH SWITCH FORMAT
TEST(UTField2n, times_with_switch) {
    DiscreteFourierTransform::PreComputeTable(8);
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(1, 0);
    a.at(1) = std::complex<double>(1, 0);
    a.at(2) = std::complex<double>(1, 0);
    a.at(3) = std::complex<double>(1, 0);
    OPENFHE_DEBUG("Step 2");
    Field2n b(4, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(1, 0);
    b.at(1) = std::complex<double>(0, 0);
    b.at(2) = std::complex<double>(1, 0);
    b.at(3) = std::complex<double>(0, 0);
    OPENFHE_DEBUG("Step 3");
    Field2n c(4, Format::COEFFICIENT, true);
    c.at(0) = std::complex<double>(0, 0);
    c.at(1) = std::complex<double>(0, 0);
    c.at(2) = std::complex<double>(2, 0);
    c.at(3) = std::complex<double>(2, 0);
    OPENFHE_DEBUG("Step 4");
    a.SwitchFormat();
    b.SwitchFormat();
    Field2n d = a.Times(b);
    d.SwitchFormat();
    for (int i = 0; i < 4; i++) {
        EXPECT_LE(fabs(d.at(i).real() - c.at(i).real()), pow(10, -12));
    }
    DiscreteFourierTransform::Reset();
}

// TEST FOR SHIFT RIGHT OPERATION
TEST(UTField2n, shift_right) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(4, 0);
    a.at(1) = std::complex<double>(3, 0);
    a.at(2) = std::complex<double>(2, 0);
    a.at(3) = std::complex<double>(1, 0);
    OPENFHE_DEBUG("Step 2");
    Field2n b(4, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(-1, 0);
    b.at(1) = std::complex<double>(4, 0);
    b.at(2) = std::complex<double>(3, 0);
    b.at(3) = std::complex<double>(2, 0);
    OPENFHE_DEBUG("Step 3");
    EXPECT_EQ(b, a.ShiftRight());
}

// TEST FOR TRANSPOSE OPERATION
TEST(UTField2n, transpose) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(4, 0);
    a.at(1) = std::complex<double>(3, 0);
    a.at(2) = std::complex<double>(2, 0);
    a.at(3) = std::complex<double>(1, 0);
    OPENFHE_DEBUG("Step 2");
    Field2n b(4, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(4, 0);
    b.at(1) = std::complex<double>(-1, 0);
    b.at(2) = std::complex<double>(-2, 0);
    b.at(3) = std::complex<double>(-3, 0);
    OPENFHE_DEBUG("Step 3");
    EXPECT_EQ(b, a.Transpose());
}

// TEST FOR TRANSPOSE OPERATION
TEST(UTField2n, transpose_eval) {
    DiscreteFourierTransform::PreComputeTable(8);
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(4, 0);
    a.at(1) = std::complex<double>(3, 0);
    a.at(2) = std::complex<double>(2, 0);
    a.at(3) = std::complex<double>(1, 0);
    // Convert to Format::EVALUATION format
    a.SwitchFormat();
    a = a.Transpose();
    // back to Format::COEFFICIENT representation
    a.SwitchFormat();
    OPENFHE_DEBUG("Step 2");
    Field2n b(4, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(4, 0);
    b.at(1) = std::complex<double>(-1, 0);
    b.at(2) = std::complex<double>(-2, 0);
    b.at(3) = std::complex<double>(-3, 0);
    OPENFHE_DEBUG("Step 3");
    for (int i = 0; i < 4; i++) {
        EXPECT_LE(fabs(b.at(i).real() - a.at(i).real()), fabs(b.at(i).real()) * 0.0001);
    }
    DiscreteFourierTransform::Reset();
}

// TEST FOR AUTOMORPHISM OPERATION
TEST(UTField2n, automorphism) {
    DiscreteFourierTransform::PreComputeTable(8);
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(1, 0);
    a.at(1) = std::complex<double>(2, 0);
    a.at(2) = std::complex<double>(3, 0);
    a.at(3) = std::complex<double>(4, 0);
    a.SwitchFormat();
    a = a.AutomorphismTransform(3);
    a.SwitchFormat();
    OPENFHE_DEBUG("Step 2");
    Field2n b(4, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(1, 0);
    b.at(1) = std::complex<double>(4, 0);
    b.at(2) = std::complex<double>(-3, 0);
    b.at(3) = std::complex<double>(2, 0);
    OPENFHE_DEBUG("Step 3");
    for (int i = 0; i < 4; i++) {
        EXPECT_LE(fabs(b.at(i).real() - a.at(i).real()), fabs(b.at(i).real()) * 0.0001);
    }
    DiscreteFourierTransform::Reset();
}

// TEST FOR EXTRACT ODD OPERATION
TEST(UTField2n, extract_odd) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(4, 0);
    a.at(1) = std::complex<double>(3, 0);
    a.at(2) = std::complex<double>(2, 0);
    a.at(3) = std::complex<double>(1, 0);
    OPENFHE_DEBUG("Step 2");
    Field2n b(2, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(3, 0);
    b.at(1) = std::complex<double>(1, 0);
    OPENFHE_DEBUG("Step 3");
    EXPECT_EQ(b, a.ExtractOdd());
}

// TEST FOR EXTRACT EVEN OPERATION
TEST(UTField2n, extract_even) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(4, 0);
    a.at(1) = std::complex<double>(3, 0);
    a.at(2) = std::complex<double>(2, 0);
    a.at(3) = std::complex<double>(1, 0);
    OPENFHE_DEBUG("Step 2");
    Field2n b(2, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(4, 0);
    b.at(1) = std::complex<double>(2, 0);
    OPENFHE_DEBUG("Step 3");
    EXPECT_EQ(b, a.ExtractEven());
}

// TEST FOR PERMUTE OPERATION
TEST(UTField2n, permute) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(1, 0);
    a.at(1) = std::complex<double>(2, 0);
    a.at(2) = std::complex<double>(3, 0);
    a.at(3) = std::complex<double>(4, 0);
    OPENFHE_DEBUG("Step 2");
    Field2n b(4, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(1, 0);
    b.at(1) = std::complex<double>(3, 0);
    b.at(2) = std::complex<double>(2, 0);
    b.at(3) = std::complex<double>(4, 0);
    OPENFHE_DEBUG("Step 3");
    EXPECT_EQ(b, a.Permute());
}

// TEST FOR INVERSE PERMUTE OPERATION
TEST(UTField2n, inverse_permute) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(1, 0);
    a.at(1) = std::complex<double>(3, 0);
    a.at(2) = std::complex<double>(2, 0);
    a.at(3) = std::complex<double>(4, 0);
    OPENFHE_DEBUG("Step 2");
    Field2n b(4, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(1, 0);
    b.at(1) = std::complex<double>(2, 0);
    b.at(2) = std::complex<double>(3, 0);
    b.at(3) = std::complex<double>(4, 0);
    OPENFHE_DEBUG("Step 3");
    EXPECT_EQ(b, a.InversePermute());
}

// TEST FOR SCALAR MULT OPERATION
TEST(UTField2n, scalar_mult) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("Step 1");
    Field2n a(4, Format::EVALUATION, true);
    a.at(0) = std::complex<double>(1, -1);
    a.at(1) = std::complex<double>(3, -2);
    a.at(2) = std::complex<double>(2, -3);
    a.at(3) = std::complex<double>(4, -4);
    OPENFHE_DEBUG("Step 2");
    Field2n b(4, Format::EVALUATION, true);
    b.at(0) = std::complex<double>(3, -3);
    b.at(1) = std::complex<double>(9, -6);
    b.at(2) = std::complex<double>(6, -9);
    b.at(3) = std::complex<double>(12, -12);
    OPENFHE_DEBUG("Step 3");
    EXPECT_EQ(b, a.ScalarMult(3));
}

// TEST FOR Format::COEFFICIENT TO Format::EVALUATION FORMAT CHANGE
TEST(UTField2n, COEFFICIENT_EVALUATION) {
    DiscreteFourierTransform::PreComputeTable(16);
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("Step 1");
    Field2n a(8, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(4, 0);
    a.at(1) = std::complex<double>(5, 0);
    a.at(2) = std::complex<double>(5, 0);
    a.at(3) = std::complex<double>(4.2, 0);
    a.at(4) = std::complex<double>(5, 0);
    a.at(5) = std::complex<double>(7.1, 0);
    a.at(6) = std::complex<double>(6, 0);
    a.at(7) = std::complex<double>(3, 0);
    OPENFHE_DEBUG("Step 2");
    Field2n b(8, Format::EVALUATION, true);
    b.at(0) = std::complex<double>(4.03087, 26.2795);
    b.at(1) = std::complex<double>(8.15172, 5.84489);
    b.at(2) = std::complex<double>(1.26249, 0.288539);
    b.at(3) = std::complex<double>(2.55492, 0.723132);
    b.at(4) = std::complex<double>(2.55492, -0.723132);
    b.at(5) = std::complex<double>(1.26249, -0.288539);
    b.at(6) = std::complex<double>(8.15172, -5.84489);
    b.at(7) = std::complex<double>(4.03087, -26.2795);
    OPENFHE_DEBUG("Step 3");
    a.SwitchFormat();
    for (int i = 0; i < 8; i++) {
        EXPECT_LE(fabs(a.at(i).real() - b.at(i).real()), fabs(b.at(i).real()) * 0.0001);
        EXPECT_LE(fabs(a.at(i).imag() - b.at(i).imag()), fabs(b.at(i).imag()) * 0.0001);
    }
    DiscreteFourierTransform::Reset();
}

// TEST FOR Format::EVALUATION TO Format::COEFFICIENT FORMAT CHANGE
TEST(UTField2n, EVALUATION_COEFFICIENT) {
    DiscreteFourierTransform::PreComputeTable(16);
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("Step 1");
    Field2n b(8, Format::EVALUATION, true);
    b.at(0) = std::complex<double>(4.03087, 26.2795);
    b.at(1) = std::complex<double>(8.15172, 5.84489);
    b.at(2) = std::complex<double>(1.26249, 0.288539);
    b.at(3) = std::complex<double>(2.55492, 0.723132);
    b.at(4) = std::complex<double>(2.55492, -0.723132);
    b.at(5) = std::complex<double>(1.26249, -0.288539);
    b.at(6) = std::complex<double>(8.15172, -5.84489);
    b.at(7) = std::complex<double>(4.03087, -26.2795);
    OPENFHE_DEBUG("Step 2");
    Field2n a(8, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(4, 0);
    a.at(1) = std::complex<double>(5, 0);
    a.at(2) = std::complex<double>(5, 0);
    a.at(3) = std::complex<double>(4.2, 0);
    a.at(4) = std::complex<double>(5, 0);
    a.at(5) = std::complex<double>(7.1, 0);
    a.at(6) = std::complex<double>(6, 0);
    a.at(7) = std::complex<double>(3, 0);

    OPENFHE_DEBUG("Step 3");
    b.SwitchFormat();
    for (int i = 0; i < 8; i++) {
        EXPECT_LE(fabs(a.at(i).real() - b.at(i).real()), fabs(a.at(i).real()) * 0.0001);
    }
    DiscreteFourierTransform::Reset();
}
