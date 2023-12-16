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

#include "cryptocontext.h"
#include "encoding/encodings.h"
#include "gtest/gtest.h"
#include "gen-cryptocontext.h"
#include "scheme/bfvrns/gen-cryptocontext-bfvrns.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"
#include "UnitTestUtils.h"
#include "utils/debug.h"

#include <iostream>
#include <vector>

using namespace lbcrypto;

class UTBFVRNS_CRT : public ::testing::Test {
protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

public:
};

void BFVrns_TestMultiplicativeDepthLimitation(MultiplicationTechnique multiplicationTechnique,
                                              usint multiplicativeDepth) {
    CCParams<CryptoContextBFVRNS> parameters;
    const uint64_t ptm = 786433;

    parameters.SetPlaintextModulus(ptm);
    parameters.SetMultiplicativeDepth(multiplicativeDepth);

    parameters.SetMultiplicationTechnique(multiplicationTechnique);

    // For speed
    parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    parameters.SetRingDim(32);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key

    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    // First plaintext vector is encoded
    std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    // Second plaintext vector is encoded
    std::vector<int64_t> vectorOfInts2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext2               = cryptoContext->MakePackedPlaintext(vectorOfInts2);

    size_t expectedResultSize =
        (vectorOfInts1.size() < vectorOfInts2.size()) ? vectorOfInts1.size() : vectorOfInts2.size();
    std::vector<int64_t> expectedResult(expectedResultSize);
    for (size_t i = 0; i < expectedResultSize; ++i) {
        expectedResult[i] = vectorOfInts1[i] * vectorOfInts2[i];
    }
    Plaintext expectedPlaintext = cryptoContext->MakePackedPlaintext(expectedResult);

    // The encoded vectors are encrypted
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

    // Homomorphic multiplications
    auto ciphertextMul12 = cryptoContext->EvalMult(ciphertext1, ciphertext2);

    // Decrypt the result of multiplications
    Plaintext plaintextMultResult;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12, &plaintextMultResult);
    plaintextMultResult->SetLength(expectedResultSize);
    std::vector<int64_t> decvec = plaintextMultResult->GetPackedValue();
    Plaintext dRes              = cryptoContext->MakePackedPlaintext(decvec);

    EXPECT_EQ(plaintextMultResult, expectedPlaintext);
}
TEST_F(UTBFVRNS_CRT, BFVrns_TestMultiplicativeDepthLimitation_BEHZ) {
    BFVrns_TestMultiplicativeDepthLimitation(BEHZ, 32);
    BFVrns_TestMultiplicativeDepthLimitation(BEHZ, 33);
    BFVrns_TestMultiplicativeDepthLimitation(BEHZ, 34);

    if (MATHBACKEND != 2) {
        BFVrns_TestMultiplicativeDepthLimitation(BEHZ, 65);
        BFVrns_TestMultiplicativeDepthLimitation(BEHZ, 66);
        BFVrns_TestMultiplicativeDepthLimitation(BEHZ, 67);
        BFVrns_TestMultiplicativeDepthLimitation(BEHZ, 68);
        BFVrns_TestMultiplicativeDepthLimitation(BEHZ, 99);
        BFVrns_TestMultiplicativeDepthLimitation(BEHZ, 100);
        BFVrns_TestMultiplicativeDepthLimitation(BEHZ, 101);
        BFVrns_TestMultiplicativeDepthLimitation(BEHZ, 102);
        BFVrns_TestMultiplicativeDepthLimitation(BEHZ, 132);
        BFVrns_TestMultiplicativeDepthLimitation(BEHZ, 133);
        BFVrns_TestMultiplicativeDepthLimitation(BEHZ, 134);
        BFVrns_TestMultiplicativeDepthLimitation(BEHZ, 135);
    }
}
TEST_F(UTBFVRNS_CRT, BFVrns_TestMultiplicativeDepthLimitation_HPS) {
    BFVrns_TestMultiplicativeDepthLimitation(HPS, 33);
    BFVrns_TestMultiplicativeDepthLimitation(HPS, 32);
    BFVrns_TestMultiplicativeDepthLimitation(HPS, 34);

    if (MATHBACKEND != 2) {
        BFVrns_TestMultiplicativeDepthLimitation(HPS, 65);
        BFVrns_TestMultiplicativeDepthLimitation(HPS, 66);
        BFVrns_TestMultiplicativeDepthLimitation(HPS, 67);
        BFVrns_TestMultiplicativeDepthLimitation(HPS, 68);
        BFVrns_TestMultiplicativeDepthLimitation(HPS, 99);
        BFVrns_TestMultiplicativeDepthLimitation(HPS, 100);
        BFVrns_TestMultiplicativeDepthLimitation(HPS, 101);
        BFVrns_TestMultiplicativeDepthLimitation(HPS, 102);
        BFVrns_TestMultiplicativeDepthLimitation(HPS, 132);
        BFVrns_TestMultiplicativeDepthLimitation(HPS, 133);
        BFVrns_TestMultiplicativeDepthLimitation(HPS, 134);
        BFVrns_TestMultiplicativeDepthLimitation(HPS, 135);
    }
}
TEST_F(UTBFVRNS_CRT, BFVrns_TestMultiplicativeDepthLimitation_HPSPOVERQ) {
    BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQ, 32);
    BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQ, 33);
    BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQ, 34);

    if (MATHBACKEND != 2) {
        BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQ, 65);
        BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQ, 66);
        BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQ, 67);
        BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQ, 68);
        BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQ, 99);
        BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQ, 100);
        BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQ, 134);
        BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQ, 135);
    }
}
TEST_F(UTBFVRNS_CRT, BFVrns_TestMultiplicativeDepthLimitation_HPSPOVERQLEVELED) {
    BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQLEVELED, 32);
    BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQLEVELED, 33);
    BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQLEVELED, 34);

    if (MATHBACKEND != 2) {
        BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQLEVELED, 65);
        BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQLEVELED, 66);
        BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQLEVELED, 67);
        BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQLEVELED, 68);
        BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQLEVELED, 99);
        BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQLEVELED, 100);
        BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQLEVELED, 134);
        BFVrns_TestMultiplicativeDepthLimitation(HPSPOVERQLEVELED, 135);
    }
}

TEST_F(UTBFVRNS_CRT, BFVrns_FastBaseConvqToBskMontgomery) {
    UnitTestCCParams parameters;
    parameters.schemeId                = BFVRNS_SCHEME;
    parameters.plaintextModulus        = 65537;
    parameters.standardDeviation       = 3.19;
    parameters.maxRelinSkDeg           = 2;
    parameters.scalTech                = NORESCALE;
    parameters.numLargeDigits          = 0;
    parameters.multiplicativeDepth     = 2;
    parameters.scalingModSize          = 60;
    parameters.ksTech                  = BV;
    parameters.digitSize               = 20;
    parameters.securityLevel           = HEStd_NotSet;
    parameters.ringDimension           = 8;
    parameters.firstModSize            = 60;
    parameters.batchSize               = 8;
    parameters.secretKeyDist           = UNIFORM_TERNARY;
    parameters.multiplicationTechnique = BEHZ;

    CryptoContext<Element> cc(UnitTestGenerateContext(parameters));

    const std::shared_ptr<ILDCRTParams<BigInteger>> params = cc->GetCryptoParameters()->GetElementParams();

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cc->GetCryptoParameters());

    // Generate the element "a" of the public key
    DCRTPoly a(params, Format::EVALUATION);

    usint m1               = 16;
    NativeInteger modulus0 = 1152921504606846577;
    NativeInteger modulus1 = 1152921504606846097;
    NativeInteger rootOfUnity0(RootOfUnity(m1, modulus0));
    NativeInteger rootOfUnity1(RootOfUnity(m1, modulus1));

    ILNativeParams polyParams0(m1, modulus0, rootOfUnity0);
    ILNativeParams polyParams1(m1, modulus1, rootOfUnity1);
    auto x0p = std::make_shared<ILNativeParams>(polyParams0);
    auto x1p = std::make_shared<ILNativeParams>(polyParams1);

    NativePoly poly0(x0p, Format::EVALUATION);
    NativePoly poly1(x1p, Format::EVALUATION);
    poly0 = {611651427055975783, 739811248882229946, 790810915716521716, 536363726228107588,
             647651536262422014, 322042217691169971, 138609670727909932, 793736138075446811};
    poly1 = {846754661443099927,  602279558317502186, 342175723088143584, 904036735987820179,
             1124341799555345257, 885339199454111253, 417243638107713607, 548811148460128084};

    a.SetElementAtIndex(0, poly0);
    a.SetElementAtIndex(1, poly1);

    a.FastBaseConvqToBskMontgomery(
        cryptoParams->GetParamsQBsk(), cryptoParams->GetModuliQ(), cryptoParams->GetModuliBsk(),
        cryptoParams->GetModbskBarrettMu(), cryptoParams->GetmtildeQHatInvModq(),
        cryptoParams->GetmtildeQHatInvModqPrecon(), cryptoParams->GetQHatModbsk(), cryptoParams->GetQHatModmtilde(),
        cryptoParams->GetQModbsk(), cryptoParams->GetQModbskPrecon(), cryptoParams->GetNegQInvModmtilde(),
        cryptoParams->GetmtildeInvModbsk(), cryptoParams->GetmtildeInvModbskPrecon());

    NativeInteger modulus2 = 1152921504606845777;
    NativeInteger modulus3 = 1152921504606845473;
    NativeInteger modulus4 = 1152921504606844913;
    NativeInteger rootOfUnity2(RootOfUnity(m1, modulus2));
    NativeInteger rootOfUnity3(RootOfUnity(m1, modulus3));
    NativeInteger rootOfUnity4(RootOfUnity(m1, modulus4));

    ILNativeParams polyParams2(m1, modulus2, rootOfUnity2);
    ILNativeParams polyParams3(m1, modulus3, rootOfUnity3);
    ILNativeParams polyParams4(m1, modulus4, rootOfUnity4);
    auto x2p = std::make_shared<ILNativeParams>(polyParams2);
    auto x3p = std::make_shared<ILNativeParams>(polyParams3);
    auto x4p = std::make_shared<ILNativeParams>(polyParams4);
    NativePoly ans0(x0p, Format::EVALUATION);
    NativePoly ans1(x1p, Format::EVALUATION);
    NativePoly ans2(x2p, Format::EVALUATION);
    NativePoly ans3(x3p, Format::EVALUATION);
    NativePoly ans4(x4p, Format::EVALUATION);
    ans0 = {611651427055975783, 739811248882229946, 790810915716521716, 536363726228107588,
            647651536262422014, 322042217691169971, 138609670727909932, 793736138075446811};
    ans1 = {846754661443099927,  602279558317502186, 342175723088143584, 904036735987820179,
            1124341799555345257, 885339199454111253, 417243638107713607, 548811148460128084};
    ans2 = {524228833460429474, 692928367413813885, 465662343623521646, 107498520099165490,
            81602760285107383,  482417615916109741, 249076385001962496, 719980682178715834};
    ans3 = {474506930637362424, 723790960760608304, 7991172453764409,   738286918217632692,
            933904287195446155, 98490114749039532,  293617451261147895, 1050780276990075548};
    ans4 = {612459830520599999, 273948808875966259, 276211279884817131,  805184382328000673,
            605603488049806384, 756318612975583592, 1014214483788531002, 480836070509458175};

    EXPECT_EQ(a.GetElementAtIndex(0), ans0);
    EXPECT_EQ(a.GetElementAtIndex(1), ans1);
    EXPECT_EQ(a.GetElementAtIndex(2), ans2);
    EXPECT_EQ(a.GetElementAtIndex(3), ans3);
    EXPECT_EQ(a.GetElementAtIndex(4), ans4);
}

// TODO (dsuponit): review and fix multiple errors in this file
TEST_F(UTBFVRNS_CRT, BFVrns_FastExpandCRTBasisPloverQ) {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetRingDim(8);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetDigitSize(20);
    parameters.SetBatchSize(8);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetMultiplicationTechnique(HPSPOVERQ);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    const std::shared_ptr<ILDCRTParams<BigInteger>> params = cc->GetCryptoParameters()->GetElementParams();

    const auto cryptoParamsBFVrns = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cc->GetCryptoParameters());

    size_t sizeQ = 2;

    // Generate the element "a" of the public key
    DCRTPoly a(params, Format::COEFFICIENT);

    usint m1               = 16;
    NativeInteger modulus0 = NativeInteger("1152921504606846577");
    NativeInteger modulus1 = NativeInteger("1152921504606846097");
    NativeInteger rootOfUnity0(RootOfUnity(m1, modulus0));
    NativeInteger rootOfUnity1(RootOfUnity(m1, modulus1));

    ILNativeParams polyParams0(m1, modulus0, rootOfUnity0);
    ILNativeParams polyParams1(m1, modulus1, rootOfUnity1);
    auto x0p = std::make_shared<ILNativeParams>(polyParams0);
    auto x1p = std::make_shared<ILNativeParams>(polyParams1);

    NativePoly poly0(x0p, Format::COEFFICIENT);
    NativePoly poly1(x1p, Format::COEFFICIENT);
    poly0 = {242947838436205858, 458804958636264704, 813208723994158017, 738376275125875131,
             269337450701982501, 633721177525656427, 406635995163024073, 763204304316606329};
    poly1 = {1024863409567898083, 845721255474383902,  537504300724180111, 1018489837930110795,
             112800627588840746,  1119710169440476902, 77894506676832730,  34149187620514595};

    a.SetElementAtIndex(0, poly0);
    a.SetElementAtIndex(1, poly1);

    auto param1  = cryptoParamsBFVrns->GetParamsQlRl(sizeQ - 1);
    auto param2  = cryptoParamsBFVrns->GetParamsRl(sizeQ - 1);
    auto param3  = cryptoParamsBFVrns->GetParamsQl(sizeQ - 1);
    auto param4  = cryptoParamsBFVrns->GetmNegRlQHatInvModq(sizeQ - 1);
    auto param5  = cryptoParamsBFVrns->GetmNegRlQHatInvModqPrecon(sizeQ - 1);
    auto param6  = cryptoParamsBFVrns->GetqInvModr();
    auto param7  = cryptoParamsBFVrns->GetModrBarrettMu();
    auto param8  = cryptoParamsBFVrns->GetRlHatInvModr(sizeQ - 1);
    auto param9  = cryptoParamsBFVrns->GetRlHatInvModrPrecon(sizeQ - 1);
    auto param10 = cryptoParamsBFVrns->GetRlHatModq(sizeQ - 1);
    auto param11 = cryptoParamsBFVrns->GetalphaRlModq(sizeQ - 1);
    auto param12 = cryptoParamsBFVrns->GetModqBarrettMu();
    auto param13 = cryptoParamsBFVrns->GetrInv();
    DCRTPoly::CRTBasisExtensionPrecomputations basisPQ(param1, param2, param3, param4, param5, param6, param7, param8,
                                                       param9, param10, param11, param12, param13);

    a.FastExpandCRTBasisPloverQ(basisPQ);

    NativeInteger modulus2 = NativeInteger("1152921504606845777");
    NativeInteger modulus3 = NativeInteger("1152921504606845473");
    NativeInteger rootOfUnity2(RootOfUnity(m1, modulus2));
    NativeInteger rootOfUnity3(RootOfUnity(m1, modulus3));

    ILNativeParams polyParams2(m1, modulus2, rootOfUnity2);
    ILNativeParams polyParams3(m1, modulus3, rootOfUnity3);
    auto x2p = std::make_shared<ILNativeParams>(polyParams2);
    auto x3p = std::make_shared<ILNativeParams>(polyParams3);
    NativePoly ans0(x0p, Format::COEFFICIENT);
    NativePoly ans1(x1p, Format::COEFFICIENT);
    NativePoly ans2(x2p, Format::COEFFICIENT);
    NativePoly ans3(x3p, Format::COEFFICIENT);
    ans0 = {805568738929329616, 1078766251747424582, 785656076316475932, 599125608237504784,
            541576441836927290, 152721755350883626,  574857357780891061, 1081393409810468825};
    ans1 = {434562805454153184, 312761043978375123, 509951653046700586, 879239171041671808,
            385039618723450975, 638710747265582661, 246115869294473638, 352338293114574371};
    ans2 = {955839852875274614,  186398073668078476, 710455872402389881, 1065981546244475424,
            1049296073052489283, 578396240339812092, 26954876970280156,  1019223053257416912};
    ans3 = {874592295621923164, 585167928946466637, 612704504638527027, 551633899923050545,
            758002500979691774, 694035684451390662, 625796987487151016, 96319544173820807};

    EXPECT_EQ(a.GetElementAtIndex(0), ans0);
    EXPECT_EQ(a.GetElementAtIndex(1), ans1);
    EXPECT_EQ(a.GetElementAtIndex(2), ans2);
    EXPECT_EQ(a.GetElementAtIndex(3), ans3);
}

TEST_F(UTBFVRNS_CRT, BFVrns_SwitchCRTBasis) {
    CCParams<CryptoContextBFVRNS> parameters;
    usint ptm = 1 << 31;
    parameters.SetPlaintextModulus(ptm);
    parameters.SetMultiplicativeDepth(7);
    parameters.SetMaxRelinSkDeg(8);
    parameters.SetScalingModSize(60);
    parameters.SetMultiplicationTechnique(HPS);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    const std::shared_ptr<ILDCRTParams<BigInteger>> params = cryptoContext->GetCryptoParameters()->GetElementParams();

    const auto cryptoParamsBFVrns =
        std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cryptoContext->GetCryptoParameters());

    const std::shared_ptr<ILDCRTParams<BigInteger>> paramsR = cryptoParamsBFVrns->GetParamsRl();

    typename DCRTPoly::DugType dug;

    // Generate the element "a" of the public key
    const DCRTPoly a(dug, params, Format::COEFFICIENT);

    Poly resultA = a.CRTInterpolate();

    const DCRTPoly b =
        a.SwitchCRTBasis(paramsR, cryptoParamsBFVrns->GetQlHatInvModq(), cryptoParamsBFVrns->GetQlHatInvModqPrecon(),
                         cryptoParamsBFVrns->GetQlHatModr(), cryptoParamsBFVrns->GetalphaQlModr(),
                         cryptoParamsBFVrns->GetModrBarrettMu(), cryptoParamsBFVrns->GetqInv());

    Poly resultB = b.CRTInterpolate();

    BigInteger A0 = resultA.at(0);

    if (A0 > (params->GetModulus() >> 1))
        A0 = params->GetModulus() - A0;

    BigInteger B0 = resultB.at(0);

    if (B0 > (paramsR->GetModulus() >> 1))
        B0 = paramsR->GetModulus() - B0;

    EXPECT_EQ(A0, B0) << "SwitchCRTBasis produced incorrect results";
}

// TESTING POLYNOMIAL MULTIPLICATION - ONE TERM IS CONSTANT POLYNOMIAL
TEST_F(UTBFVRNS_CRT, BFVrns_Mult_by_Constant) {
    CCParams<CryptoContextBFVRNS> parameters;
    usint ptm = 1 << 15;
    parameters.SetPlaintextModulus(ptm);
    parameters.SetScalingModSize(60);
    parameters.SetMultiplicationTechnique(HPS);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    const std::shared_ptr<ILDCRTParams<BigInteger>> paramsQ = cryptoContext->GetCryptoParameters()->GetElementParams();

    const auto cryptoParamsBFVrns =
        std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cryptoContext->GetCryptoParameters());

    const std::shared_ptr<ILDCRTParams<BigInteger>> paramsR = cryptoParamsBFVrns->GetParamsRl();

    const std::shared_ptr<ILDCRTParams<BigInteger>> paramsQR = cryptoParamsBFVrns->GetParamsQlRl();

    typename DCRTPoly::DugType dug;

    // Generate uninform element
    DCRTPoly a(dug, paramsQ, Format::COEFFICIENT);

    // Generate constant element
    DCRTPoly b(paramsQ, Format::COEFFICIENT, true);
    b = b + (uint64_t)1976860313128;
    b = b.Negate();

    Poly aPoly = a.CRTInterpolate();

    Poly bPoly = b.CRTInterpolate();

    a.ExpandCRTBasis(paramsQR, paramsR, cryptoParamsBFVrns->GetQlHatInvModq(),
                     cryptoParamsBFVrns->GetQlHatInvModqPrecon(), cryptoParamsBFVrns->GetQlHatModr(),
                     cryptoParamsBFVrns->GetalphaQlModr(), cryptoParamsBFVrns->GetModrBarrettMu(),
                     cryptoParamsBFVrns->GetqInv(), Format::EVALUATION);

    b.ExpandCRTBasis(paramsQR, paramsR, cryptoParamsBFVrns->GetQlHatInvModq(),
                     cryptoParamsBFVrns->GetQlHatInvModqPrecon(), cryptoParamsBFVrns->GetQlHatModr(),
                     cryptoParamsBFVrns->GetalphaQlModr(), cryptoParamsBFVrns->GetModrBarrettMu(),
                     cryptoParamsBFVrns->GetqInv(), Format::EVALUATION);

    Poly resultExpandedB = b.CRTInterpolate();

    BigInteger A0 = bPoly.at(0);

    if (A0 > (bPoly.GetModulus() >> 1))
        A0 = bPoly.GetModulus() - A0;

    BigInteger B0 = resultExpandedB.at(0);

    if (B0 > (resultExpandedB.GetModulus() >> 1))
        B0 = resultExpandedB.GetModulus() - B0;

    EXPECT_EQ(A0, B0) << "CRT expansion of polynomial b worked incorrectly";

    // a and b are already in evaluation representation after ExpandCRTBasis

    // Polynomial multiplication in Q*S CRT basis
    DCRTPoly c = a * b;

    c.SetFormat(Format::COEFFICIENT);

    Poly resultC = c.CRTInterpolate();

    // Starting multiprecision polynomial multiplication

    BigInteger modulus("1606938044258990275541962092341162602522202993782792836833281");
    BigInteger root("859703842628303907691187858658134128225754111718143879712783");
    usint m = 8192;

    auto paramsPoly = std::make_shared<ILParams>(m, modulus, root);

    aPoly.SwitchModulus(modulus, root, 0, 0);
    bPoly.SwitchModulus(modulus, root, 0, 0);

    aPoly.SetFormat(Format::EVALUATION);
    bPoly.SetFormat(Format::EVALUATION);

    // Polynomial multiplication in Q*S CRT basis
    Poly cPoly = aPoly * bPoly;

    cPoly.SetFormat(Format::COEFFICIENT);

    // Ended multiprecision multiplication

    A0 = cPoly.at(0);

    if (A0 > (cPoly.GetModulus() >> 1))
        A0 = cPoly.GetModulus() - A0;

    B0 = resultC.at(0);

    if (B0 > (resultC.GetModulus() >> 1))
        B0 = resultC.GetModulus() - B0;

    EXPECT_EQ(A0, B0) << "Results of multiprecision and CRT multiplication do not match";

    DCRTPoly rounded =
        c.ScaleAndRound(paramsR, cryptoParamsBFVrns->GettRSHatInvModsDivsModr(),
                        cryptoParamsBFVrns->GettRSHatInvModsDivsFrac(), cryptoParamsBFVrns->GetModrBarrettMu());

    DCRTPoly roundedQ = rounded.SwitchCRTBasis(paramsQ, cryptoParamsBFVrns->GetRlHatInvModr(),
                                               cryptoParamsBFVrns->GetRlHatInvModrPrecon(),
                                               cryptoParamsBFVrns->GetRlHatModq(), cryptoParamsBFVrns->GetalphaRlModq(),
                                               cryptoParamsBFVrns->GetModqBarrettMu(), cryptoParamsBFVrns->GetrInv());

    Poly resultRoundedQ = roundedQ.CRTInterpolate();

    Poly roundedMP = cPoly.MultiplyAndRound(BigInteger(ptm), roundedQ.GetModulus());

    A0 = roundedMP.at(0);

    if (A0 > (roundedMP.GetModulus() >> 1))
        A0 = roundedMP.GetModulus() - A0;

    B0 = resultRoundedQ.at(0);

    if (B0 > (resultRoundedQ.GetModulus() >> 1))
        B0 = resultRoundedQ.GetModulus() - B0;

    // uint64_t result = (A0 + BigInteger(2) - B0).ConvertToInt();

    // EXPECT_TRUE((result >= 1) && (result <= 3)) << "Results of multiprecision
    // and CRT multiplication after scaling + rounding do not match";
}

// TESTING POLYNOMIAL MULTIPLICATION - UNIFORM AND GAUSSIAN RANDOM POLYNOMIALS
TEST_F(UTBFVRNS_CRT, BFVrns_Mult_by_Gaussian) {
    CCParams<CryptoContextBFVRNS> parameters;
    usint ptm = 1 << 15;
    parameters.SetPlaintextModulus(ptm);
    parameters.SetScalingModSize(60);
    parameters.SetMultiplicationTechnique(HPS);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    const std::shared_ptr<ILDCRTParams<BigInteger>> paramsQ = cryptoContext->GetCryptoParameters()->GetElementParams();

    const auto cryptoParamsBFVrns =
        std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cryptoContext->GetCryptoParameters());

    const std::shared_ptr<ILDCRTParams<BigInteger>> paramsR = cryptoParamsBFVrns->GetParamsRl();

    const std::shared_ptr<ILDCRTParams<BigInteger>> paramsQR = cryptoParamsBFVrns->GetParamsQlRl();

    typename DCRTPoly::DugType dug;

    // Generate uninform element
    DCRTPoly a(dug, paramsQ, Format::COEFFICIENT);

    // dgg with distribution parameter 400000
    typename DCRTPoly::DggType dgg(400000);

    // Generate Discrete Gaussian element
    DCRTPoly b(dgg, paramsQ, Format::COEFFICIENT);

    Poly aPoly = a.CRTInterpolate();

    Poly bPoly = b.CRTInterpolate();

    a.ExpandCRTBasis(paramsQR, paramsR, cryptoParamsBFVrns->GetQlHatInvModq(),
                     cryptoParamsBFVrns->GetQlHatInvModqPrecon(), cryptoParamsBFVrns->GetQlHatModr(),
                     cryptoParamsBFVrns->GetalphaQlModr(), cryptoParamsBFVrns->GetModrBarrettMu(),
                     cryptoParamsBFVrns->GetqInv(), Format::EVALUATION);

    b.ExpandCRTBasis(paramsQR, paramsR, cryptoParamsBFVrns->GetQlHatInvModq(),
                     cryptoParamsBFVrns->GetQlHatInvModqPrecon(), cryptoParamsBFVrns->GetQlHatModr(),
                     cryptoParamsBFVrns->GetalphaQlModr(), cryptoParamsBFVrns->GetModrBarrettMu(),
                     cryptoParamsBFVrns->GetqInv(), Format::EVALUATION);

    Poly resultExpandedB = b.CRTInterpolate();

    BigInteger A0 = bPoly.at(0);

    if (A0 > (bPoly.GetModulus() >> 1))
        A0 = bPoly.GetModulus() - A0;

    BigInteger B0 = resultExpandedB.at(0);

    if (B0 > (resultExpandedB.GetModulus() >> 1))
        B0 = resultExpandedB.GetModulus() - B0;

    EXPECT_EQ(A0, B0) << "CRT expansion of polynomial b worked incorrectly";

    // a and b are already in evaluation representation after ExpandCRTBasis

    // Polynomial multiplication in Q*S CRT basis
    DCRTPoly c = a * b;

    c.SetFormat(Format::COEFFICIENT);

    Poly resultC = c.CRTInterpolate();

    // Starting multiprecision polynomial multiplication

    BigInteger modulus("1606938044258990275541962092341162602522202993782792836833281");
    BigInteger root("859703842628303907691187858658134128225754111718143879712783");
    usint m = 8192;

    auto paramsPoly = std::make_shared<ILParams>(m, modulus, root);

    aPoly.SwitchModulus(modulus, root, 0, 0);
    bPoly.SwitchModulus(modulus, root, 0, 0);

    aPoly.SetFormat(Format::EVALUATION);
    bPoly.SetFormat(Format::EVALUATION);

    // Polynomial multiplication in Q*S CRT basis
    Poly cPoly = aPoly * bPoly;

    cPoly.SetFormat(Format::COEFFICIENT);

    // Ended multiprecision multiplication

    A0 = cPoly.at(0);

    if (A0 > (cPoly.GetModulus() >> 1))
        A0 = cPoly.GetModulus() - A0;

    B0 = resultC.at(0);

    if (B0 > (resultC.GetModulus() >> 1))
        B0 = resultC.GetModulus() - B0;

    // TODO (andrey) fix this part of the test
    //  EXPECT_EQ(A0, B0)
    //      << "Results of multiprecision and CRT multiplication do not match";

    DCRTPoly rounded =
        c.ScaleAndRound(paramsR, cryptoParamsBFVrns->GettRSHatInvModsDivsModr(),
                        cryptoParamsBFVrns->GettRSHatInvModsDivsFrac(), cryptoParamsBFVrns->GetModrBarrettMu());

    DCRTPoly roundedQ = rounded.SwitchCRTBasis(paramsQ, cryptoParamsBFVrns->GetRlHatInvModr(),
                                               cryptoParamsBFVrns->GetRlHatInvModrPrecon(),
                                               cryptoParamsBFVrns->GetRlHatModq(), cryptoParamsBFVrns->GetalphaRlModq(),
                                               cryptoParamsBFVrns->GetModqBarrettMu(), cryptoParamsBFVrns->GetrInv());

    Poly resultRoundedQ = roundedQ.CRTInterpolate();

    Poly roundedMP = cPoly.MultiplyAndRound(BigInteger(ptm), roundedQ.GetModulus());

    A0 = roundedMP.at(0);

    if (A0 > (roundedMP.GetModulus() >> 1))
        A0 = roundedMP.GetModulus() - A0;

    B0 = resultRoundedQ.at(0);

    if (B0 > (resultRoundedQ.GetModulus() >> 1))
        B0 = resultRoundedQ.GetModulus() - B0;

    // uint64_t result = (A0 + BigInteger(2) - B0).ConvertToInt();

    // EXPECT_TRUE((result >= 1) && (result <= 3)) <<  "Results of multiprecision
    // and CRT multiplication after scaling + rounding do not match";
}
