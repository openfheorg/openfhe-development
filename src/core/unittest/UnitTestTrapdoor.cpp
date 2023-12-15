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

#include <iostream>
#include "gtest/gtest.h"

#include "lattice/lat-hal.h"
#include "math/distrgen.h"
#include "math/nbtheory.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"
#include "lattice/trapdoor.h"

using namespace lbcrypto;

class UnitTestTrapdoor : public ::testing::Test {
protected:
    virtual void SetUp() {}

    virtual void TearDown() {
        // Code here will be called immediately after each test
        // (right before the destructor).
    }
};

/************************************************/
/*  TESTING METHODS OF TRAPDOOR CLASS    */
/************************************************/

/************************************************/
/* TESTING BASIC MATH METHODS AND OPERATORS     */
/************************************************/

TEST(UTTrapdoor, randomized_round) {
    //  It compiles! ...
    // RandomizeRound(0, 4.3, 1024);
}

TEST(UTTrapdoor, sizes) {
    usint m = 16;
    BigInteger modulus("67108913");
    BigInteger rootOfUnity("61564");
    float stddev = 4;

    double val = modulus.ConvertToDouble();  // TODO get the next few lines
                                             // working in a single instance.
    double logTwo = log(val - 1.0) / log(2) + 1.0;
    usint k       = (usint)floor(logTwo);  // = this->m_cryptoParameters.GetModulus();

    auto fastParams = std::make_shared<ILParams>(m, modulus, rootOfUnity);
    std::pair<Matrix<Poly>, RLWETrapdoorPair<Poly>> trapPair =
        RLWETrapdoorUtility<Poly>::TrapdoorGen(fastParams, stddev);

    EXPECT_EQ(1U, trapPair.first.GetRows()) << "Failure testing number of rows";
    EXPECT_EQ(k + 2, trapPair.first.GetCols()) << "Failure testing number of colums";

    EXPECT_EQ(1U, trapPair.second.m_r.GetRows()) << "Failure testing number of rows";
    EXPECT_EQ(k, trapPair.second.m_r.GetCols()) << "Failure testing number of colums";

    EXPECT_EQ(1U, trapPair.second.m_e.GetRows()) << "Failure testing number of rows";
    EXPECT_EQ(k, trapPair.second.m_e.GetCols()) << "Failure testing number of colums";
}

TEST(UTTrapdoor, TrapDoorPairTest) {
    usint m = 16;
    BigInteger modulus("67108913");
    BigInteger rootOfUnity("61564");
    float stddev = 4;

    double val = modulus.ConvertToDouble();  // TODO get the next few lines
                                             // working in a single instance.
    double logTwo = log(val - 1.0) / log(2) + 1.0;
    usint k       = (usint)floor(logTwo);  // = this->m_cryptoParameters.GetModulus();

    auto params     = std::make_shared<ILParams>(m, modulus, rootOfUnity);
    auto zero_alloc = Poly::Allocator(params, Format::EVALUATION);

    std::pair<Matrix<Poly>, RLWETrapdoorPair<Poly>> trapPair = RLWETrapdoorUtility<Poly>::TrapdoorGen(params, stddev);

    Matrix<Poly> eHat  = trapPair.second.m_e;
    Matrix<Poly> rHat  = trapPair.second.m_r;
    Matrix<Poly> eyeKK = Matrix<Poly>(zero_alloc, k, k).Identity();

    // std::cout << eHat <<std::endl;
    // std::cout << rHat <<std::endl;
    // std::cout << eyeKK <<std::endl;

    Matrix<Poly> stackedTrap1 = eHat.VStack(rHat);
    // std::cout << stackedTrap2 <<std::endl;

    EXPECT_EQ(2U, stackedTrap1.GetRows()) << "Failure testing number of rows";
    EXPECT_EQ(k, stackedTrap1.GetCols()) << "Failure testing number of colums";

    Matrix<Poly> stackedTrap2 = stackedTrap1.VStack(eyeKK);

    EXPECT_EQ(k + 2, stackedTrap2.GetRows()) << "Failure testing number of rows";
    EXPECT_EQ(k, stackedTrap2.GetCols()) << "Failure testing number of colums";

    // Matrix<Poly> g = Matrix<Poly>(zero_alloc, 1, k).GadgetVector();
}

TEST(UTTrapdoor, TrapDoorPairTestSquareMat) {
    usint m = 16;
    BigInteger modulus("67108913");
    BigInteger rootOfUnity("61564");
    float stddev = 4;

    double val = modulus.ConvertToDouble();  // TODO get the next few lines
                                             // working in a single instance.
    double logTwo = ceil(log2(val));
    usint k       = (usint)floor(logTwo);  // = this->m_cryptoParameters.GetModulus();

    auto params     = std::make_shared<ILParams>(m, modulus, rootOfUnity);
    auto zero_alloc = Poly::Allocator(params, Format::EVALUATION);

    size_t d = 5;

    std::pair<Matrix<Poly>, RLWETrapdoorPair<Poly>> trapPair =
        RLWETrapdoorUtility<Poly>::TrapdoorGenSquareMat(params, stddev, d);

    Matrix<Poly> eHat  = trapPair.second.m_e;
    Matrix<Poly> rHat  = trapPair.second.m_r;
    Matrix<Poly> eyeKK = Matrix<Poly>(zero_alloc, d * k, d * k).Identity();

    Matrix<Poly> stackedTrap1 = rHat.VStack(eHat);
    // std::cout << stackedTrap2 <<std::endl;

    EXPECT_EQ(2 * d, stackedTrap1.GetRows()) << "Failure testing number of rows";
    EXPECT_EQ(d * k, stackedTrap1.GetCols()) << "Failure testing number of colums";

    Matrix<Poly> stackedTrap2 = stackedTrap1.VStack(eyeKK);

    EXPECT_EQ(d * (k + 2), stackedTrap2.GetRows()) << "Failure testing number of rows";
    EXPECT_EQ(d * k, stackedTrap2.GetCols()) << "Failure testing number of colums";

    // Matrix<Poly> g = Matrix<Poly>(zero_alloc, 1, k).GadgetVector();
}

TEST(UTTrapdoor, GadgetTest) {
    usint m = 16;
    BigInteger modulus("67108913");
    BigInteger rootOfUnity("61564");

    double val = modulus.ConvertToDouble();  // TODO get the next few lines
                                             // working in a single instance.
    double logTwo = log(val - 1.0) / log(2) + 1.0;
    usint k       = (usint)floor(logTwo);  // = this->m_cryptoParameters.GetModulus();

    auto params     = std::make_shared<ILParams>(m, modulus, rootOfUnity);
    auto zero_alloc = Poly::Allocator(params, Format::EVALUATION);

    Matrix<Poly> g = Matrix<Poly>(zero_alloc, 1, k).GadgetVector();

    EXPECT_EQ(1U, g.GetRows()) << "Failure testing number of rows";
    EXPECT_EQ(k, g.GetCols()) << "Failure testing number of colums";
}

TEST(UTTrapdoor, TrapDoorMultTest) {
    usint m = 16;
    BigInteger modulus("67108913");
    BigInteger rootOfUnity("61564");
    float stddev = 4;

    double val = modulus.ConvertToDouble();  // TODO get the next few lines
                                             // working in a single instance.
    double logTwo = log(val - 1.0) / log(2) + 1.0;
    usint k       = (usint)floor(logTwo);  // = this->m_cryptoParameters.GetModulus();

    auto params     = std::make_shared<ILParams>(m, modulus, rootOfUnity);
    auto zero_alloc = Poly::Allocator(params, Format::EVALUATION);

    std::pair<Matrix<Poly>, RLWETrapdoorPair<Poly>> trapPair = RLWETrapdoorUtility<Poly>::TrapdoorGen(params, stddev);

    Matrix<Poly> eHat  = trapPair.second.m_e;
    Matrix<Poly> rHat  = trapPair.second.m_r;
    Matrix<Poly> eyeKK = Matrix<Poly>(zero_alloc, k, k).Identity();

    // std::cout << eHat <<std::endl;
    // std::cout << rHat <<std::endl;
    // std::cout << eyeKK <<std::endl;

    Matrix<Poly> stackedTrap1 = eHat.VStack(rHat);
    Matrix<Poly> stackedTrap2 = stackedTrap1.VStack(eyeKK);

    Matrix<Poly> trapMult = (trapPair.first) * (stackedTrap2);
    EXPECT_EQ(1U, trapMult.GetRows()) << "Failure testing number of rows";
    EXPECT_EQ(k, trapMult.GetCols()) << "Failure testing number of colums";

    Matrix<Poly> g = Matrix<Poly>(zero_alloc, 1, k).GadgetVector();
    EXPECT_EQ(g, trapMult);
}

TEST(UTTrapdoor, TrapDoorMultTestSquareMat) {
    usint m = 16;
    BigInteger modulus("67108913");
    BigInteger rootOfUnity("61564");
    float stddev = 4;

    double val = modulus.ConvertToDouble();  // TODO get the next few lines
                                             // working in a single instance.
    double logTwo = ceil(log2(val));
    usint k       = (usint)floor(logTwo);  // = this->m_cryptoParameters.GetModulus();

    size_t d = 5;

    auto params     = std::make_shared<ILParams>(m, modulus, rootOfUnity);
    auto zero_alloc = Poly::Allocator(params, Format::EVALUATION);

    std::pair<Matrix<Poly>, RLWETrapdoorPair<Poly>> trapPair =
        RLWETrapdoorUtility<Poly>::TrapdoorGenSquareMat(params, stddev, d);

    Matrix<Poly> eHat  = trapPair.second.m_e;
    Matrix<Poly> rHat  = trapPair.second.m_r;
    Matrix<Poly> eyeKK = Matrix<Poly>(zero_alloc, d * k, d * k).Identity();

    Matrix<Poly> stackedTrap1 = rHat.VStack(eHat);
    Matrix<Poly> stackedTrap2 = stackedTrap1.VStack(eyeKK);

    Matrix<Poly> trapMult = (trapPair.first) * (stackedTrap2);
    EXPECT_EQ(d, trapMult.GetRows()) << "Failure testing number of rows";
    EXPECT_EQ(d * k, trapMult.GetCols()) << "Failure testing number of colums";

    Matrix<Poly> G = Matrix<Poly>(zero_alloc, d, d * k).GadgetVector();

    // std::cerr << G << std::endl;

    EXPECT_EQ(G, trapMult);
}

TEST(UTTrapdoor, TrapDoorGaussGqSampTest) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("start tests");
    usint m = 16;
    usint n = m / 2;
    BigInteger modulus("67108913");
    BigInteger rootOfUnity("61564");
    // BigInteger modulus("134218081");
    // BigInteger rootOfUnity("19091337");
    // BigInteger modulus("1048609");
    // BigInteger rootOfUnity("389832");
    auto params     = std::make_shared<ILParams>(m, modulus, rootOfUnity);
    auto zero_alloc = Poly::Allocator(params, Format::EVALUATION);

    uint64_t base = 2;
    double sigma  = (base + 1) * SIGMA;

    Poly::DggType dgg(sigma);
    Poly::DugType dug;

    OPENFHE_DEBUG("1");
    Poly u(dug, params, Format::COEFFICIENT);
    OPENFHE_DEBUG("2");
    double val = modulus.ConvertToDouble();  // TODO get the next few lines
                                             // working in a single instance.
    // YSP check logTwo computation
    double logTwo = log(val - 1.0) / log(2) + 1.0;
    usint k       = (usint)floor(logTwo);

    Matrix<int64_t> zHatBBI([]() { return 0; }, k, m / 2);

    OPENFHE_DEBUG("3");
    OPENFHE_DEBUG("u " << u);
    OPENFHE_DEBUG("sigma " << sigma);
    OPENFHE_DEBUG("k " << k);
    OPENFHE_DEBUG("modulus " << modulus);

    LatticeGaussSampUtility<Poly>::GaussSampGq(u, sigma, k, modulus, base, dgg, &zHatBBI);

    EXPECT_EQ(k, zHatBBI.GetRows()) << "Failure testing number of rows";
    EXPECT_EQ(u.GetLength(), zHatBBI.GetCols()) << "Failure testing number of colums";
    OPENFHE_DEBUG("4");
    Matrix<Poly> z = SplitInt64AltIntoElements<Poly>(zHatBBI, n, params);
    z.SwitchFormat();

    Poly uEst;
    uEst = (Matrix<Poly>(zero_alloc, 1, k).GadgetVector() * z)(0, 0);
    uEst.SwitchFormat();

    EXPECT_EQ(u, uEst);
    OPENFHE_DEBUG("end tests");
}

// this test does not work correctly in the web assembly configuration
// it is not needed for the functionality exposed through the web assembly
#if !defined(__EMSCRIPTEN__) && !defined(__CYGWIN__)
TEST(UTTrapdoor, TrapDoorGaussSampTestDCRT) {
    usint n      = 16;  // cyclotomic order
    size_t kRes  = 51;
    size_t base  = 8;
    size_t size  = 4;
    double sigma = SIGMA;

    auto params        = std::make_shared<ILDCRTParams<BigInteger>>(2 * n, size, kRes);
    int64_t digitCount = static_cast<int64_t>(ceil(log2((*params)[0]->GetModulus().ConvertToDouble()) / log2(base)));

    std::pair<Matrix<DCRTPoly>, RLWETrapdoorPair<DCRTPoly>> trapPair =
        RLWETrapdoorUtility<DCRTPoly>::TrapdoorGen(params, sigma, base);

    Matrix<DCRTPoly> eHat = trapPair.second.m_e;
    Matrix<DCRTPoly> rHat = trapPair.second.m_r;

    DCRTPoly::DggType dgg(sigma);
    DCRTPoly::DugType dug;
    DCRTPoly u(dug, params, Format::COEFFICIENT);

    usint k = size * digitCount;

    double c = (base + 1) * SIGMA;
    double s = SPECTRAL_BOUND(n, k, base);
    DCRTPoly::DggType dggLargeSigma(sqrt(s * s - c * c));

    u.SwitchFormat();

    Matrix<DCRTPoly> z =
        RLWETrapdoorUtility<DCRTPoly>::GaussSamp(n, k, trapPair.first, trapPair.second, u, dgg, dggLargeSigma, base);

    // Matrix<Poly> uEst = trapPair.first * z;

    EXPECT_EQ(trapPair.first.GetCols(), z.GetRows()) << "Failure testing number of rows";
    EXPECT_EQ(n, z(0, 0).GetLength()) << "Failure testing ring dimension for the first ring element";

    DCRTPoly uEst = (trapPair.first * z)(0, 0);

    uEst.SwitchFormat();
    u.SwitchFormat();

    EXPECT_EQ(u, uEst);
}
#endif

TEST(UTTrapdoor, TrapDoorGaussGqSampTestBase1024) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("start tests");

    usint m = 1024;
    usint n = m / 2;
    BigInteger modulus("8399873");
    BigInteger rootOfUnity("824894");
    // BigInteger modulus("134218081");
    // BigInteger rootOfUnity("19091337");
    // BigInteger modulus("1048609");
    // BigInteger rootOfUnity("389832");
    auto params     = std::make_shared<ILParams>(m, modulus, rootOfUnity);
    auto zero_alloc = Poly::Allocator(params, Format::EVALUATION);

    uint64_t base = 1 << 10;
    double sigma  = (base + 1) * SIGMA;

    Poly::DggType dgg(SIGMA);
    Poly::DugType dug;

    OPENFHE_DEBUG("1");
    Poly u(dug, params, Format::COEFFICIENT);
    OPENFHE_DEBUG("2");
    // double val = modulus.ConvertToDouble(); //TODO get the next few lines
    // working in a single instance. YSP check logTwo computation

    usint nBits = floor(log2(modulus.ConvertToDouble() - 1.0) + 1.0);
    usint k     = ceil(nBits / log2(base));

    // double logTwo = log(val - 1.0) / log(2) + 1.0;
    // usint k = (usint)floor(logTwo);

    Matrix<int64_t> zHatBBI([]() { return 0; }, k, m / 2);

    OPENFHE_DEBUG("3");
    OPENFHE_DEBUG("u " << u);
    OPENFHE_DEBUG("sigma " << sigma);
    OPENFHE_DEBUG("k " << k);
    OPENFHE_DEBUG("modulus " << modulus);
    OPENFHE_DEBUG("base = " << base);

    LatticeGaussSampUtility<Poly>::GaussSampGq(u, sigma, k, modulus, base, dgg, &zHatBBI);

    EXPECT_EQ(k, zHatBBI.GetRows()) << "Failure testing number of rows";
    EXPECT_EQ(u.GetLength(), zHatBBI.GetCols()) << "Failure testing number of colums";
    OPENFHE_DEBUG("4");

    // int32_t maxValue = 0;

    // for (size_t i = 0; i < zHatBBI.GetRows(); i++)
    //  for (size_t j = 0; j < zHatBBI.GetCols(); j++)
    //    if (std::abs(zHatBBI(i, j)) > maxValue)
    //      maxValue = std::abs(zHatBBI(i, j));
    //
    // std::cout << maxValue << std::endl;

    Matrix<Poly> z = SplitInt64AltIntoElements<Poly>(zHatBBI, n, params);
    OPENFHE_DEBUG("4.5");
    // TODO for some reason I must do this before calling switchformat (which
    // uses omp for parallel execution)
    // TODO my guess is there is a race in the calculation/caching of factors
    // underneath, though the critical
    // TODO region *should* address that...
    auto mmm = z.GetData()[0][0];
    mmm.SwitchFormat();

    z.SwitchFormat();

    OPENFHE_DEBUG("5");
    Poly uEst;
    uEst = (Matrix<Poly>(zero_alloc, 1, k).GadgetVector(base) * z)(0, 0);
    uEst.SwitchFormat();

    // std::cout << u - uEst << std::endl;

    EXPECT_EQ(u, uEst);
    OPENFHE_DEBUG("end tests");
}

// Test of Gaussian Sampling using the UCSD integer perturbation sampling
// algorithm
TEST(UTTrapdoor, TrapDoorGaussSampTest) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("in test");
    usint m = 16;
    usint n = m / 2;

    BigInteger modulus("67108913");
    BigInteger rootOfUnity("61564");
    double sigma = SIGMA;

    double val = modulus.ConvertToDouble();  // TODO get the next few lines
                                             // working in a single instance.
    double logTwo = log(val - 1.0) / log(2) + 1.0;
    usint k       = (usint)floor(logTwo);  // = this->m_cryptoParameters.GetModulus();

    OPENFHE_DEBUG("k = " << k);
    OPENFHE_DEBUG("sigma = " << sigma);
    OPENFHE_DEBUG("m = " << m);
    OPENFHE_DEBUG("modulus = " << modulus);
    OPENFHE_DEBUG("root = " << rootOfUnity);

    auto params = std::make_shared<ILParams>(m, modulus, rootOfUnity);

    std::pair<Matrix<Poly>, RLWETrapdoorPair<Poly>> trapPair = RLWETrapdoorUtility<Poly>::TrapdoorGen(params, sigma);

    Matrix<Poly> eHat = trapPair.second.m_e;
    Matrix<Poly> rHat = trapPair.second.m_r;
    // auto uniform_alloc = Poly::MakeDiscreteUniformAllocator(params,
    // Format::EVALUATION);

    Poly::DggType dgg(sigma);
    Poly::DugType dug;

    uint32_t base = 2;
    double c      = (base + 1) * SIGMA;
    double s      = SPECTRAL_BOUND(n, k, base);
    Poly::DggType dggLargeSigma(sqrt(s * s - c * c));

    Poly u(dug, params, Format::COEFFICIENT);

    OPENFHE_DEBUG("u " << u);
    u.SwitchFormat();
    OPENFHE_DEBUG("u " << u);

    Matrix<Poly> z =
        RLWETrapdoorUtility<Poly>::GaussSamp(m / 2, k, trapPair.first, trapPair.second, u, dgg, dggLargeSigma);

    // Matrix<Poly> uEst = trapPair.first * z;

    EXPECT_EQ(trapPair.first.GetCols(), z.GetRows()) << "Failure testing number of rows";
    EXPECT_EQ(m / 2, z(0, 0).GetLength()) << "Failure testing ring dimension for the first ring element";

    Poly uEst = (trapPair.first * z)(0, 0);

    OPENFHE_DEBUG("uEst " << uEst);
    OPENFHE_DEBUG("u " << u);

    OPENFHE_DEBUG("uEst.GetModulus() " << uEst.GetModulus());
    OPENFHE_DEBUG("u.GetModulus() " << u.GetModulus());

    uEst.SwitchFormat();
    u.SwitchFormat();

    EXPECT_EQ(u, uEst);

    // std::cout << z << std::endl;
}

// Test of Gaussian Sampling for matrices from 2x2 to 5x5
TEST(UTTrapdoor, TrapDoorGaussSampTestSquareMatrices) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("in test");
    usint m = 16;
    usint n = m / 2;

    BigInteger modulus("67108913");
    BigInteger rootOfUnity("61564");
    double sigma = SIGMA;

    double val = modulus.ConvertToDouble();  // TODO get the next few lines
                                             // working in a single instance.
    double logTwo = std::ceil(log2(val));
    usint k       = (usint)(logTwo);

    auto params = std::make_shared<ILParams>(m, modulus, rootOfUnity);

    auto zero_alloc    = Poly::Allocator(params, Format::EVALUATION);
    auto uniform_alloc = Poly::MakeDiscreteUniformAllocator(params, Format::EVALUATION);

    for (size_t d = 2; d < 6; d++) {
        std::pair<Matrix<Poly>, RLWETrapdoorPair<Poly>> trapPair =
            RLWETrapdoorUtility<Poly>::TrapdoorGenSquareMat(params, sigma, d);

        Matrix<Poly> R = trapPair.second.m_r;
        Matrix<Poly> E = trapPair.second.m_e;

        Poly::DggType dgg(sigma);

        uint32_t base = 2;
        double c      = (base + 1) * SIGMA;
        double s      = SPECTRAL_BOUND_D(n, k, base, d);
        Poly::DggType dggLargeSigma(sqrt(s * s - c * c));

        Matrix<Poly> U(zero_alloc, d, d, uniform_alloc);

        Matrix<Poly> z = RLWETrapdoorUtility<Poly>::GaussSampSquareMat(m / 2, k, trapPair.first, trapPair.second, U,
                                                                       dgg, dggLargeSigma);

        EXPECT_EQ(trapPair.first.GetCols(), z.GetRows()) << "Failure testing number of rows";
        EXPECT_EQ(m / 2, z(0, 0).GetLength()) << "Failure testing ring dimension for the first ring element";

        Matrix<Poly> UEst = trapPair.first * z;

        UEst.SwitchFormat();
        U.SwitchFormat();

        EXPECT_EQ(U, UEst) << "Failure trapdoor sampling test for " << d << "x" << d << " matrices";
    }
}

// this test does not work correctly in the web assembly configuration
// it is not needed for the functionality exposed through the web assembly
#if !defined(__EMSCRIPTEN__) && !defined(__CYGWIN__)
// Test of Gaussian Sampling for matrices from 2x2 to 5x5
TEST(UTTrapdoor, TrapDoorGaussSampTestSquareMatricesDCRT) {
    usint m         = 16;
    usint n         = m / 2;
    size_t dcrtBits = 57;
    size_t size     = 3;
    double sigma    = SIGMA;

    auto params = std::make_shared<ILDCRTParams<BigInteger>>(2 * n, size, dcrtBits);

    double val    = params->GetModulus().ConvertToDouble();
    double logTwo = std::ceil(log2(val));
    usint k       = (usint)(logTwo);

    auto zero_alloc    = DCRTPoly::Allocator(params, Format::EVALUATION);
    auto uniform_alloc = DCRTPoly::MakeDiscreteUniformAllocator(params, Format::EVALUATION);

    for (size_t d = 2; d < 6; d++) {
        std::pair<Matrix<DCRTPoly>, RLWETrapdoorPair<DCRTPoly>> trapPair =
            RLWETrapdoorUtility<DCRTPoly>::TrapdoorGenSquareMat(params, sigma, d);

        Matrix<DCRTPoly> R = trapPair.second.m_r;
        Matrix<DCRTPoly> E = trapPair.second.m_e;

        DCRTPoly::DggType dgg(sigma);

        uint32_t base = 2;
        double c      = (base + 1) * SIGMA;
        double s      = SPECTRAL_BOUND_D(n, k, base, d);
        DCRTPoly::DggType dggLargeSigma(sqrt(s * s - c * c));

        Matrix<DCRTPoly> U(zero_alloc, d, d, uniform_alloc);

        Matrix<DCRTPoly> z = RLWETrapdoorUtility<DCRTPoly>::GaussSampSquareMat(m / 2, k, trapPair.first,
                                                                               trapPair.second, U, dgg, dggLargeSigma);

        EXPECT_EQ(trapPair.first.GetCols(), z.GetRows()) << "Failure testing number of rows";
        EXPECT_EQ(m / 2, z(0, 0).GetLength()) << "Failure testing ring dimension for the first ring element";

        Matrix<DCRTPoly> UEst = trapPair.first * z;

        UEst.SwitchFormat();
        U.SwitchFormat();

        EXPECT_EQ(U, UEst) << "Failure trapdoor sampling test for " << d << "x" << d << " matrices";
    }
}
#endif

// Test  UCSD integer perturbation sampling algorithm
// So far the test simply runs 100 instances of ZSampleSigmaP
// and makes sure no exceptions are encountered - this validates that
// covariance matrices at all steps are positive definite
TEST(UTTrapdoor, TrapDoorPerturbationSamplingTest) {
    // usint m = 2048;
    usint m = 16;
    // usint m = 8192;
    usint n = m / 2;

    // for m = 16
    BigInteger modulus("67108913");
    BigInteger rootOfUnity("61564");

    // for m = 2048
    // BigInteger modulus("134246401");
    // BigInteger rootOfUnity("34044212");

    // for m = 2^13
    // BigInteger modulus("268460033");
    // BigInteger rootOfUnity("154905983");

    // BigInteger modulus("1237940039285380274899136513");
    // BigInteger rootOfUnity("977145384161930579732228319");

    double val = modulus.ConvertToDouble();  // TODO get the next few lines
                                             // working in a single instance.
    double logTwo = log(val - 1.0) / log(2) + 1.0;
    usint k       = (usint)floor(logTwo);  // = this->m_cryptoParameters.GetModulus();

    // smoothing parameter
    // double c(2 * sqrt(log(2 * n*(1 + 1 / DG_ERROR)) / M_PI));
    uint32_t base = 2;
    double c      = (base + 1) * SIGMA;

    // spectral bound s
    double s = SPECTRAL_BOUND(n, k, base);

    // std::cout << "sigma = " << SIGMA << std::endl;
    // std::cout << "s = " << s << std::endl;

    // Generate the trapdoor pair
    auto params = std::make_shared<ILParams>(m, modulus, rootOfUnity);

    double sigma = SIGMA;

    // std::cout << 50 / (c*sigma) << std::endl;

    std::pair<Matrix<Poly>, RLWETrapdoorPair<Poly>> trapPair = RLWETrapdoorUtility<Poly>::TrapdoorGen(params, sigma);

    Matrix<Poly> eHat = trapPair.second.m_e;
    Matrix<Poly> rHat = trapPair.second.m_r;

    Poly::DggType dgg(sigma);
    Poly::DggType dggLargeSigma(sqrt(s * s - c * c));

    auto zero_alloc = Poly::Allocator(params, Format::EVALUATION);

    // Do perturbation sampling
    auto pHat = std::make_shared<Matrix<Poly>>(zero_alloc, k + 2, 1);

    Matrix<int32_t> p([]() { return 0; }, (2 + k) * n, 1);

    Matrix<int32_t> pCovarianceMatrix([]() { return 0; }, 2 * n, 2 * n);

    // std::vector<Matrix<int32_t>> pTrapdoors;

    Matrix<int32_t> pTrapdoor([]() { return 0; }, 2 * n, 1);

    Matrix<BigInteger> bbiTrapdoor(BigInteger::Allocator, 2 * n, 1);

    Matrix<int32_t> pTrapdoorAverage([]() { return 0; }, 2 * n, 1);

    size_t count = 100;

    for (size_t i = 0; i < count; i++) {
        RLWETrapdoorUtility<Poly>::ZSampleSigmaP(n, s, c, trapPair.second, dgg, dggLargeSigma, pHat);

        // convert to Format::COEFFICIENT representation
        pHat->SwitchFormat();

        for (size_t j = 0; j < n; j++) {
            bbiTrapdoor(j, 0)     = (*pHat)(0, 0).GetValues().at(j);
            bbiTrapdoor(j + n, 0) = (*pHat)(1, 0).GetValues().at(j);
        }

        pTrapdoor = ConvertToInt32(bbiTrapdoor, modulus);

        for (size_t j = 0; j < 2 * n; j++) {
            pTrapdoorAverage(j, 0) = pTrapdoorAverage(j, 0) + pTrapdoor(j, 0);
        }
        // pTrapdoors.push_back(pTrapdoor);

        pCovarianceMatrix = pCovarianceMatrix + pTrapdoor * pTrapdoor.Transpose();
    }

    Matrix<Poly> Tprime0 = eHat;
    Matrix<Poly> Tprime1 = rHat;

    // all three polynomials are initialized with "0" coefficients
    Poly va(params, Format::EVALUATION, 1);
    Poly vb(params, Format::EVALUATION, 1);
    Poly vd(params, Format::EVALUATION, 1);

    for (size_t i = 0; i < k; i++) {
        va = va + Tprime0(0, i) * Tprime0(0, i).Transpose();
        vb = vb + Tprime1(0, i) * Tprime0(0, i).Transpose();
        vd = vd + Tprime1(0, i) * Tprime1(0, i).Transpose();
    }

    // Switch the ring elements (polynomials) to Format::COEFFICIENT
    // representation
    va.SwitchFormat();
    vb.SwitchFormat();
    vd.SwitchFormat();

    // Create field elements from ring elements
    Field2n a(va), b(vb), d(vd);

    double scalarFactor = -s * s * c * c / (s * s - c * c);

    a = a.ScalarMult(scalarFactor);
    b = b.ScalarMult(scalarFactor);
    d = d.ScalarMult(scalarFactor);

    a = a + s * s;
    d = d + s * s;

    // for (size_t j = 0; j < 2 * n; j++) {
    //  pTrapdoorAverage(j, 0) = pTrapdoorAverage(j, 0) / count;
    //}

    // std::cout << a << std::endl;

    Matrix<int32_t> meanMatrix = pTrapdoorAverage * pTrapdoorAverage.Transpose();

    // std::cout << (double(pCovarianceMatrix(0, 0)) - meanMatrix(0, 0))/ count <<
    // std::endl; std::cout << (double(pCovarianceMatrix(1, 0)) - meanMatrix(1,
    // 0)) / count << std::endl; std::cout << (double(pCovarianceMatrix(2, 0)) -
    // meanMatrix(2, 0)) / count << std::endl; std::cout <<
    // (double(pCovarianceMatrix(3, 0)) - meanMatrix(3, 0)) / count << std::endl;
}
