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

//#include "scheme/bfvrns/bfvrns.h"
#include "scheme/bfvrns/cryptocontext-bfvrns.h"
#include "gen-cryptocontext.h"

#include <iostream>
#include <vector>
#include "gtest/gtest.h"

#include "cryptocontext.h"

#include "encoding/encodings.h"

#include "utils/debug.h"
#include "utils/parmfactory.h"

using namespace lbcrypto;

class UTBFVRNS_CRT : public ::testing::Test {
 protected:
  void SetUp() {}

  void TearDown() {
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
  }

 public:
};
// TODO (dsuponit): review and fix multiple errors in this file
TEST_F(UTBFVRNS_CRT, BFVrns_SwitchCRTBasis) {

    CCParams<CryptoContextBFVRNS> parameters;
    usint ptm = 1 << 31;
    parameters.SetPlaintextModulus(ptm);
    parameters.SetRootHermiteFactor(1.006);
    parameters.SetEvalMultCount(7);
    parameters.SetMaxDepth(8);
    parameters.SetScalingFactorBits(60);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    const std::shared_ptr<ILDCRTParams<BigInteger>> params =
        cryptoContext->GetCryptoParameters()->GetElementParams();

    const auto cryptoParamsBFVrns =
        std::static_pointer_cast<CryptoParametersBFVRNS>(
            cryptoContext->GetCryptoParameters());

    const std::shared_ptr<ILDCRTParams<BigInteger>> paramsR =
        cryptoParamsBFVrns->GetParamsRl();

  typename DCRTPoly::DugType dug;

  // Generate the element "a" of the public key
  const DCRTPoly a(dug, params, Format::COEFFICIENT);

  Poly resultA = a.CRTInterpolate();

    const DCRTPoly b = a.SwitchCRTBasis(
        paramsR, cryptoParamsBFVrns->GetQlHatInvModq(),
        cryptoParamsBFVrns->GetQlHatInvModqPrecon(),
        cryptoParamsBFVrns->GetQlHatModr(), cryptoParamsBFVrns->GetalphaQlModr(),
        cryptoParamsBFVrns->GetModrBarrettMu(), cryptoParamsBFVrns->GetqInv());

    Poly resultB = b.CRTInterpolate();

  BigInteger A0 = resultA.at(0);

    if (A0 > (params->GetModulus() >> 1)) A0 = params->GetModulus() - A0;

  BigInteger B0 = resultB.at(0);

    if (B0 > (paramsR->GetModulus() >> 1)) B0 = paramsR->GetModulus() - B0;

    EXPECT_EQ(A0, B0) << "SwitchCRTBasis produced incorrect results";
}

// TESTING POLYNOMIAL MULTIPLICATION - ONE TERM IS CONSTANT POLYNOMIAL
TEST_F(UTBFVRNS_CRT, BFVrns_Mult_by_Constant) {

    CCParams<CryptoContextBFVRNS> parameters;
    usint ptm = 1 << 15;
    parameters.SetPlaintextModulus(ptm);
    parameters.SetRootHermiteFactor(1.006);
    parameters.SetEvalMultCount(1);
    parameters.SetScalingFactorBits(60);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    const std::shared_ptr<ILDCRTParams<BigInteger>> paramsQ =
      cryptoContext->GetCryptoParameters()->GetElementParams();

  const auto cryptoParamsBFVrns =
      std::static_pointer_cast<CryptoParametersBFVRNS>(
          cryptoContext->GetCryptoParameters());

  const std::shared_ptr<ILDCRTParams<BigInteger>> paramsR =
      cryptoParamsBFVrns->GetParamsRl();

  const std::shared_ptr<ILDCRTParams<BigInteger>> paramsQR =
      cryptoParamsBFVrns->GetParamsQlRl();

  typename DCRTPoly::DugType dug;

  // Generate uninform element
  DCRTPoly a(dug, paramsQ, Format::COEFFICIENT);

  // Generate constant element
  DCRTPoly b(paramsQ, Format::COEFFICIENT, true);
  b = b + (uint64_t)1976860313128;
  b = b.Negate();

  Poly aPoly = a.CRTInterpolate();

  Poly bPoly = b.CRTInterpolate();

  a.ExpandCRTBasis(
      paramsQR, paramsR, cryptoParamsBFVrns->GetQlHatInvModq(),
      cryptoParamsBFVrns->GetQlHatInvModqPrecon(),
      cryptoParamsBFVrns->GetQlHatModr(), cryptoParamsBFVrns->GetalphaQlModr(),
      cryptoParamsBFVrns->GetModrBarrettMu(), cryptoParamsBFVrns->GetqInv());

  b.ExpandCRTBasis(
      paramsQR, paramsR, cryptoParamsBFVrns->GetQlHatInvModq(),
      cryptoParamsBFVrns->GetQlHatInvModqPrecon(),
      cryptoParamsBFVrns->GetQlHatModr(), cryptoParamsBFVrns->GetalphaQlModr(),
      cryptoParamsBFVrns->GetModrBarrettMu(), cryptoParamsBFVrns->GetqInv());

  Poly resultExpandedB = b.CRTInterpolate();

  BigInteger A0 = bPoly.at(0);

  if (A0 > (bPoly.GetModulus() >> 1)) A0 = bPoly.GetModulus() - A0;

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

  BigInteger modulus(
      "1606938044258990275541962092341162602522202993782792836833281");
  BigInteger root(
      "859703842628303907691187858658134128225754111718143879712783");
  usint m = 8192;

  auto paramsPoly = std::make_shared<ILParams>(m, modulus, root);

  aPoly.SwitchModulus(modulus, root);
  bPoly.SwitchModulus(modulus, root);

  aPoly.SetFormat(Format::EVALUATION);
  bPoly.SetFormat(Format::EVALUATION);

  // Polynomial multiplication in Q*S CRT basis
  Poly cPoly = aPoly * bPoly;

  cPoly.SetFormat(Format::COEFFICIENT);

  // Ended multiprecision multiplication

  A0 = cPoly.at(0);

  if (A0 > (cPoly.GetModulus() >> 1)) A0 = cPoly.GetModulus() - A0;

  B0 = resultC.at(0);

  if (B0 > (resultC.GetModulus() >> 1)) B0 = resultC.GetModulus() - B0;

  EXPECT_EQ(A0, B0)
      << "Results of multiprecision and CRT multiplication do not match";

  DCRTPoly rounded =
      c.ScaleAndRound(paramsR, cryptoParamsBFVrns->GettRSHatInvModsDivsModr(),
          cryptoParamsBFVrns->GettRSHatInvModsDivsFrac(),
          cryptoParamsBFVrns->GetModrBarrettMu());

  DCRTPoly roundedQ = rounded.SwitchCRTBasis(
      paramsQ, cryptoParamsBFVrns->GetRlHatInvModr(),
      cryptoParamsBFVrns->GetRlHatInvModrPrecon(),
      cryptoParamsBFVrns->GetRlHatModq(), cryptoParamsBFVrns->GetalphaRlModq(),
      cryptoParamsBFVrns->GetModqBarrettMu(), cryptoParamsBFVrns->GetrInv());

  Poly resultRoundedQ = roundedQ.CRTInterpolate();

  Poly roundedMP =
      cPoly.MultiplyAndRound(BigInteger(ptm), roundedQ.GetModulus());

  A0 = roundedMP.at(0);

  if (A0 > (roundedMP.GetModulus() >> 1)) A0 = roundedMP.GetModulus() - A0;

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
    parameters.SetRootHermiteFactor(1.006);
    parameters.SetEvalMultCount(1);
    parameters.SetScalingFactorBits(60);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

  const std::shared_ptr<ILDCRTParams<BigInteger>> paramsQ =
      cryptoContext->GetCryptoParameters()->GetElementParams();

  const auto cryptoParamsBFVrns =
      std::static_pointer_cast<CryptoParametersBFVRNS>(
          cryptoContext->GetCryptoParameters());

  const std::shared_ptr<ILDCRTParams<BigInteger>> paramsR =
      cryptoParamsBFVrns->GetParamsRl();

  const std::shared_ptr<ILDCRTParams<BigInteger>> paramsQR =
      cryptoParamsBFVrns->GetParamsQlRl();

  typename DCRTPoly::DugType dug;

  // Generate uninform element
  DCRTPoly a(dug, paramsQ, Format::COEFFICIENT);

  // dgg with distribution parameter 400000
  typename DCRTPoly::DggType dgg(400000);

  // Generate Discrete Gaussian element
  DCRTPoly b(dgg, paramsQ, Format::COEFFICIENT);

  Poly aPoly = a.CRTInterpolate();

  Poly bPoly = b.CRTInterpolate();

  a.ExpandCRTBasis(
      paramsQR, paramsR, cryptoParamsBFVrns->GetQlHatInvModq(),
      cryptoParamsBFVrns->GetQlHatInvModqPrecon(),
      cryptoParamsBFVrns->GetQlHatModr(), cryptoParamsBFVrns->GetalphaQlModr(),
      cryptoParamsBFVrns->GetModrBarrettMu(), cryptoParamsBFVrns->GetqInv());

  b.ExpandCRTBasis(
      paramsQR, paramsR, cryptoParamsBFVrns->GetQlHatInvModq(),
      cryptoParamsBFVrns->GetQlHatInvModqPrecon(),
      cryptoParamsBFVrns->GetQlHatModr(), cryptoParamsBFVrns->GetalphaQlModr(),
      cryptoParamsBFVrns->GetModrBarrettMu(), cryptoParamsBFVrns->GetqInv());

  Poly resultExpandedB = b.CRTInterpolate();

  BigInteger A0 = bPoly.at(0);

  if (A0 > (bPoly.GetModulus() >> 1)) A0 = bPoly.GetModulus() - A0;

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

  BigInteger modulus(
      "1606938044258990275541962092341162602522202993782792836833281");
  BigInteger root(
      "859703842628303907691187858658134128225754111718143879712783");
  usint m = 8192;

  auto paramsPoly = std::make_shared<ILParams>(m, modulus, root);

  aPoly.SwitchModulus(modulus, root);
  bPoly.SwitchModulus(modulus, root);

  aPoly.SetFormat(Format::EVALUATION);
  bPoly.SetFormat(Format::EVALUATION);

  // Polynomial multiplication in Q*S CRT basis
  Poly cPoly = aPoly * bPoly;

  cPoly.SetFormat(Format::COEFFICIENT);

  // Ended multiprecision multiplication

  A0 = cPoly.at(0);

  if (A0 > (cPoly.GetModulus() >> 1)) A0 = cPoly.GetModulus() - A0;

  B0 = resultC.at(0);

  if (B0 > (resultC.GetModulus() >> 1)) B0 = resultC.GetModulus() - B0;

  //TODO (andrey) fix this part of the test
//  EXPECT_EQ(A0, B0)
//      << "Results of multiprecision and CRT multiplication do not match";

  DCRTPoly rounded =
      c.ScaleAndRound(paramsR, cryptoParamsBFVrns->GettRSHatInvModsDivsModr(),
          cryptoParamsBFVrns->GettRSHatInvModsDivsFrac(),
          cryptoParamsBFVrns->GetModrBarrettMu());

  DCRTPoly roundedQ = rounded.SwitchCRTBasis(
      paramsQ, cryptoParamsBFVrns->GetRlHatInvModr(),
      cryptoParamsBFVrns->GetRlHatInvModrPrecon(),
      cryptoParamsBFVrns->GetRlHatModq(), cryptoParamsBFVrns->GetalphaRlModq(),
      cryptoParamsBFVrns->GetModqBarrettMu(), cryptoParamsBFVrns->GetrInv());

  Poly resultRoundedQ = roundedQ.CRTInterpolate();

  Poly roundedMP =
      cPoly.MultiplyAndRound(BigInteger(ptm), roundedQ.GetModulus());

  A0 = roundedMP.at(0);

  if (A0 > (roundedMP.GetModulus() >> 1)) A0 = roundedMP.GetModulus() - A0;

  B0 = resultRoundedQ.at(0);

  if (B0 > (resultRoundedQ.GetModulus() >> 1))
    B0 = resultRoundedQ.GetModulus() - B0;

  // uint64_t result = (A0 + BigInteger(2) - B0).ConvertToInt();

  // EXPECT_TRUE((result >= 1) && (result <= 3)) <<  "Results of multiprecision
  // and CRT multiplication after scaling + rounding do not match";
}
