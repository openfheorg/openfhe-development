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
#include "math/distrgen.h"
#include "math/nbtheory.h"
#include "testdefs.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

#include "math/matrix.h"
#include "math/matrixstrassen-impl.h"

using namespace lbcrypto;

template <typename Element>
static std::function<Element()> secureIL2nAlloc() {
    usint m = 2048;
    typename Element::Integer secureModulus("8590983169");
    typename Element::Integer secureRootOfUnity("4810681236");
    return Element::Allocator(std::make_shared<typename Element::Params>(m, secureModulus, secureRootOfUnity),
                              Format::EVALUATION);
}

template <typename Element>
static std::function<Element()> fastIL2nAlloc() {
    usint m = 16;
    typename Element::Integer modulus("67108913");
    typename Element::Integer rootOfUnity("61564");
    return Element::Allocator(std::make_shared<typename Element::Params>(m, modulus, rootOfUnity), Format::EVALUATION);
}

template <typename Element>
static std::function<Element()> fastUniformIL2nAlloc() {
    usint m = 16;
    typename Element::Integer modulus("67108913");
    typename Element::Integer rootOfUnity("61564");
    return Element::MakeDiscreteUniformAllocator(std::make_shared<typename Element::Params>(m, modulus, rootOfUnity),
                                                 Format::EVALUATION);
}

TEST(UTMatrix, serializer) {
    Matrix<int32_t> m([]() { return 0; }, 3, 5);
}

template <typename Element>
void basic_il2n_math(const std::string& msg) {
    Matrix<Element> z(secureIL2nAlloc<Element>(), 2, 2);
    Matrix<Element> n = Matrix<Element>(secureIL2nAlloc<Element>(), 2, 2).Ones();
    Matrix<Element> I = Matrix<Element>(secureIL2nAlloc<Element>(), 2, 2).Identity();
    I.SetFormat(Format::COEFFICIENT);
    I.SetFormat(Format::EVALUATION);
    EXPECT_EQ(n, I * n) << msg;

    n = n - n;
    EXPECT_EQ(n, z) << msg;
}

TEST(UTMatrix, basic_il2n_math) {
    RUN_ALL_POLYS(basic_il2n_math, "basic_il2n_math")
}

template <typename T>
void basic_int_math(const std::string& msg) {
    Matrix<T> z(T::Allocator, 2, 2);
    Matrix<T> n = Matrix<T>(T::Allocator, 2, 2).Ones();
    Matrix<T> I = Matrix<T>(T::Allocator, 2, 2).Identity();
    EXPECT_EQ(n, I * n) << msg;
    n = n - n;
    EXPECT_EQ(n, z) << msg;
}

TEST(UTMatrix, basic_int_math) {
    RUN_ALL_BACKENDS_INT(basic_int_math, "basic_int_math")
}

template <typename V>
void basic_intvec_math(const std::string& msg) {
    OPENFHE_DEBUG_FLAG(false);

    typename V::Integer modulus("67108913");
    OPENFHE_DEBUG("1");
    auto singleAlloc = [=]() {
        return V(1, modulus);
    };
    OPENFHE_DEBUG("2");
    Matrix<V> z(singleAlloc, 2, 2);
    OPENFHE_DEBUG("3");
    Matrix<V> n = Matrix<V>(singleAlloc, 2, 2).Ones();
    OPENFHE_DEBUG("4");
    Matrix<V> I = Matrix<V>(singleAlloc, 2, 2).Identity();
    OPENFHE_DEBUG("5");
    OPENFHE_DEBUG("z mod 00 " << z(0, 0).GetModulus().ToString());
    OPENFHE_DEBUG("z mod 01 " << z(0, 1).GetModulus().ToString());
    OPENFHE_DEBUG("z mod 10 " << z(1, 0).GetModulus().ToString());
    OPENFHE_DEBUG("z mod 1 1 " << z(1, 1).GetModulus().ToString());
    OPENFHE_DEBUG("n mod " << n(0, 0).GetModulus().ToString());
    OPENFHE_DEBUG("I mod " << I(0, 0).GetModulus().ToString());
    EXPECT_EQ(n, I * n) << msg;
    OPENFHE_DEBUG("6");
    n = n - n;
    OPENFHE_DEBUG("7");
    EXPECT_EQ(n, z) << msg;
    OPENFHE_DEBUG("8");
}

TEST(UTMatrix, basic_intvec_math) {
    RUN_ALL_BACKENDS(basic_intvec_math, "basic_intvec_math")
}

template <typename Element>
void transpose(const std::string& msg) {
    Matrix<Element> n  = Matrix<Element>(secureIL2nAlloc<Element>(), 4, 2).Ones();
    Matrix<Element> nT = Matrix<Element>(n).Transpose();
    Matrix<Element> I  = Matrix<Element>(secureIL2nAlloc<Element>(), 2, 2).Identity();
    EXPECT_EQ(nT, I * nT) << msg;
}

TEST(UTMatrix, transpose) {
    RUN_ALL_POLYS(transpose, "transpose")
}

template <typename Element>
void scalar_mult(const std::string& msg) {
    Matrix<Element> n = Matrix<Element>(secureIL2nAlloc<Element>(), 4, 2).Ones();
    auto one          = secureIL2nAlloc<Element>()();
    one               = 1;
    EXPECT_EQ(n, one * n) << msg;
    EXPECT_EQ(n, n * one) << msg;
}

TEST(UTMatrix, scalar_mult) {
    RUN_ALL_POLYS(scalar_mult, "scalar_mult")
}

template <typename Element>
void Poly_mult_square_matrix(const std::string& msg) {
    int32_t dimension = 8;

    Matrix<Element> A =
        Matrix<Element>(fastIL2nAlloc<Element>(), dimension, dimension, fastUniformIL2nAlloc<Element>());
    Matrix<Element> B =
        Matrix<Element>(fastIL2nAlloc<Element>(), dimension, dimension, fastUniformIL2nAlloc<Element>());
    Matrix<Element> C =
        Matrix<Element>(fastIL2nAlloc<Element>(), dimension, dimension, fastUniformIL2nAlloc<Element>());
    Matrix<Element> I = Matrix<Element>(fastIL2nAlloc<Element>(), dimension, dimension).Identity();

    EXPECT_EQ(A, A * I) << msg << " Matrix multiplication of two Poly2Ns: A = AI - failed.\n";
    EXPECT_EQ(A, I * A) << msg << " Matrix multiplication of two Poly2Ns: A = IA - failed.\n";

    EXPECT_EQ((A * B).Transpose(), B.Transpose() * A.Transpose())
        << "Matrix multiplication of two Poly2Ns: (A*B)^T = B^T*A^T - failed.\n";

    EXPECT_EQ(A * B * C, A * (B * C)) << msg << " Matrix multiplication of two Poly2Ns: A*B*C = A*(B*C) - failed.\n";
    EXPECT_EQ(A * B * C, (A * B) * C) << msg << " Matrix multiplication of two Poly2Ns: A*B*C = (A*B)*C - failed.\n";
}

TEST(UTMatrix, Poly_mult_square_matrix) {
    RUN_ALL_POLYS(Poly_mult_square_matrix, "Poly_mult_square_matrix")
}

template <typename Element>
void Poly_mult_square_matrix_caps(const std::string& msg) {
    int32_t dimension = 16;

    MatrixStrassen<Element> A =
        MatrixStrassen<Element>(fastIL2nAlloc<Element>(), dimension, dimension, fastUniformIL2nAlloc<Element>());
    MatrixStrassen<Element> B =
        MatrixStrassen<Element>(fastIL2nAlloc<Element>(), dimension, dimension, fastUniformIL2nAlloc<Element>());
    MatrixStrassen<Element> C =
        MatrixStrassen<Element>(fastIL2nAlloc<Element>(), dimension, dimension, fastUniformIL2nAlloc<Element>());
    MatrixStrassen<Element> I = MatrixStrassen<Element>(fastIL2nAlloc<Element>(), dimension, dimension).Identity();

    // EXPECT_EQ((A.Mult(B))(0, 0), (A.MultiplyCAPS(B, 2))(0, 0)) << "CAPS matrix
    // multiplication of two Poly2Ns doesn't agree with Mult: A.Mult(B),
    // A.MultiplyCAPS(B,2) - failed.\n";
    EXPECT_EQ(A, A.Mult(I, 2)) << msg << " CAPS matrix multiplication of two Poly2Ns: A = AI - failed.\n";
    EXPECT_EQ(A, I.Mult(A, 2)) << msg << " Matrix multiplication of two Poly2Ns: A = IA - failed.\n";

    EXPECT_EQ((A.Mult(B, 2)).Transpose(), B.Transpose().Mult(A.Transpose(), 2))
        << msg
        << " Matrix multiplication of two Poly2Ns: "
           "(A.MultiplyCAPS(B,2)).Transpose(), "
           "B.Transpose().MultiplyCAPS(A.Transpose(),2) - failed.\n";

    EXPECT_EQ(A.Mult(B, 2).Mult(C, 2), A.Mult((B.Mult(C, 2)), 2))
        << msg
        << " Matrix multiplication of two Poly2Ns: "
           "A.MultiplyCAPS(B,2).MultiplyCAPS(C,2), "
           "A.MultiplyCAPS((B.MultiplyCAPS(C,2)),2) - failed.\n";
    EXPECT_EQ(A.Mult(B, 2).Mult(C, 2), (A.Mult(B, 2)).Mult(C, 2))
        << msg
        << " Matrix multiplication of two Poly2Ns: "
           "A.MultiplyCAPS(B,2).MultiplyCAPS(C,2), "
           "(A.MultiplyCAPS(B,2)).MultiplyCAPS(C,2) - failed.\n";
}

TEST(UTMatrix, Poly_mult_square_matrix_caps) {
    RUN_ALL_POLYS(Poly_mult_square_matrix_caps, "Poly_mult_square_matrix_caps")
}

inline void expect_close(double a, double b) {
    EXPECT_LE(fabs(a - b), 10e-8);
}

TEST(UTMatrix, cholesky) {
    OPENFHE_DEBUG_FLAG(false);
    Matrix<int32_t> m([]() { return 0; }, 2, 2);
    m(0, 0) = 20;
    m(0, 1) = 4;
    m(1, 0) = 4;
    m(1, 1) = 10;

    auto c = Cholesky(m);
    OPENFHE_DEBUGEXP(c);
    EXPECT_LE(fabs(4.47213595 - c(0, 0)), 1e-8);
    EXPECT_LE(fabs(0 - c(0, 1)), 1e-8);
    EXPECT_LE(fabs(.89442719 - c(1, 0)), 1e-8);
    EXPECT_LE(fabs(3.03315018 - c(1, 1)), 1e-8);
    auto cc = c * c.Transpose();
    EXPECT_LE(fabs(m(0, 0) - cc(0, 0)), 1e-8);
    EXPECT_LE(fabs(m(0, 1) - cc(0, 1)), 1e-8);
    EXPECT_LE(fabs(m(1, 0) - cc(1, 0)), 1e-8);
    EXPECT_LE(fabs(m(1, 1) - cc(1, 1)), 1e-8);
    OPENFHE_DEBUGEXP(cc);
}

template <typename Element>
void gadget_vector(const std::string& msg) {
    Matrix<Element> n = Matrix<Element>(secureIL2nAlloc<Element>(), 1, 4).GadgetVector();
    auto v            = secureIL2nAlloc<Element>()();
    v                 = 1;
    EXPECT_EQ(v, n(0, 0)) << msg;
    v = 2;
    EXPECT_EQ(v, n(0, 1)) << msg;
    v = 4;
    EXPECT_EQ(v, n(0, 2)) << msg;
    v = 8;
    EXPECT_EQ(v, n(0, 3)) << msg;
}

TEST(UTMatrix, gadget_vector) {
    RUN_ALL_POLYS(gadget_vector, "gadget_vector")
}

template <typename Element>
void rotate_vec_result(const std::string& msg) {
    Matrix<Element> n                        = Matrix<Element>(fastIL2nAlloc<Element>(), 1, 2).Ones();
    const typename Element::Integer& modulus = n(0, 0).GetModulus();
    n.SetFormat(Format::COEFFICIENT);
    n(0, 0).at(2)                      = 1;
    Matrix<typename Element::Vector> R = RotateVecResult(n);
    EXPECT_EQ(8U, R.GetRows()) << msg;
    EXPECT_EQ(16U, R.GetCols()) << msg;
    EXPECT_EQ(Element::Vector::Single(1, modulus), R(0, 0)) << msg;

    typename Element::Integer negOne   = n(0, 0).GetModulus() - typename Element::Integer(1);
    typename Element::Vector negOneVec = Element::Vector::Single(negOne, modulus);
    EXPECT_EQ(negOneVec, R(0, 6)) << msg;
    EXPECT_EQ(negOneVec, R(1, 7)) << msg;

    auto singleAlloc = [=]() {
        return typename Element::Vector(1, modulus);
    };
    EXPECT_EQ(singleAlloc(), R(0, 6 + 8)) << msg;
    EXPECT_EQ(singleAlloc(), R(1, 7 + 8)) << msg;
}

TEST(UTMatrix, rotate_vec_result) {
    RUN_ALL_POLYS(rotate_vec_result, "rotate_vec_result")
}

template <typename Element>
void rotate(const std::string& msg) {
    Matrix<Element> n = Matrix<Element>(fastIL2nAlloc<Element>(), 1, 2).Ones();

    n.SetFormat(Format::COEFFICIENT);
    n(0, 0).at(2)                       = 1;
    Matrix<typename Element::Integer> R = Rotate(n);
    EXPECT_EQ(8U, R.GetRows()) << msg;
    EXPECT_EQ(16U, R.GetCols()) << msg;
    EXPECT_EQ(typename Element::Integer(1), R(0, 0)) << msg;

    typename Element::Integer negOne = n(0, 0).GetModulus() - typename Element::Integer(1);
    EXPECT_EQ(negOne, R(0, 6)) << msg;
    EXPECT_EQ(negOne, R(1, 7)) << msg;

    EXPECT_EQ(typename Element::Integer(0), R(0, 6 + 8)) << msg;
    EXPECT_EQ(typename Element::Integer(0), R(1, 7 + 8)) << msg;
}

TEST(UTMatrix, rotate) {
    RUN_ALL_POLYS(rotate, "rotate")
}

template <typename Element>
void vstack(const std::string& msg) {
    Matrix<Element> n = Matrix<Element>(secureIL2nAlloc<Element>(), 4, 2).Ones();
    Matrix<Element> m = Matrix<Element>(secureIL2nAlloc<Element>(), 8, 2).Ones();
    EXPECT_EQ(m, n.VStack(n)) << msg;
}

TEST(UTMatrix, vstack) {
    RUN_ALL_POLYS(vstack, "vstack")
}

template <typename Element>
void hstack(const std::string& msg) {
    Matrix<Element> n = Matrix<Element>(secureIL2nAlloc<Element>(), 2, 2).Ones();
    Matrix<Element> m = Matrix<Element>(secureIL2nAlloc<Element>(), 2, 4).Ones();
    EXPECT_EQ(m, n.HStack(n)) << msg;
}

TEST(UTMatrix, hstack) {
    RUN_ALL_POLYS(hstack, "hstack")
}

template <typename Element>
void norm(const std::string& msg) {
    Matrix<Element> n = Matrix<Element>(secureIL2nAlloc<Element>(), 2, 2).Ones();
    EXPECT_EQ(1.0, n.Norm());
    Matrix<Element> m = Matrix<Element>(secureIL2nAlloc<Element>(), 2, 2).Identity();
    EXPECT_EQ(1.0, m.Norm()) << msg;
}

// NOLINTNEXTLINE
TEST(UTMatrix, norm){RUN_ALL_POLYS(norm, "norm")}

// Checks the implementantation of determinant based on a 3x3 matrix
TEST(UTMatrix, determinant) {
    Matrix<int32_t> m([]() { return 0; }, 3, 3);
    m(0, 0) = 1;
    m(0, 1) = 2;
    m(0, 2) = 1;
    m(1, 0) = -1;
    m(1, 1) = 1;
    m(1, 2) = 1;
    m(2, 0) = 1;
    m(2, 1) = 2;
    m(2, 2) = 3;

    // int32_t determinant = m.Determinant();
    int32_t determinant = 0;
    m.Determinant(&determinant);
    EXPECT_EQ(6, determinant);
}

// Checks the implementantation of cofactor matrix based on a 3x3 matrix
TEST(UTMatrix, cofactorMatrix) {
    Matrix<int32_t> m([]() { return 0; }, 3, 3);
    m(0, 0) = 1;
    m(0, 1) = 2;
    m(0, 2) = 0;
    m(1, 0) = -1;
    m(1, 1) = 1;
    m(1, 2) = 1;
    m(2, 0) = 1;
    m(2, 1) = 2;
    m(2, 2) = 3;

    Matrix<int32_t> r([]() { return 0; }, 3, 3);
    r(0, 0) = 1;
    r(0, 1) = 4;
    r(0, 2) = -3;
    r(1, 0) = -6;
    r(1, 1) = 3;
    r(1, 2) = 0;
    r(2, 0) = 2;
    r(2, 1) = -1;
    r(2, 2) = 3;

    EXPECT_EQ(r, m.CofactorMatrix());
}
