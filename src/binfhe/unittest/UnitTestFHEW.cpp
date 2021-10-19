// @file UnitTestFHEW.cpp This code runs unit tests for the FHEW methods of the
// PALISADE lattice encryption library.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, Duality Technologies Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "binfhecontext.h"
#include "gtest/gtest.h"

using namespace lbcrypto;

// ---------------  TESTING METHODS OF FHEW ---------------

// Checks the key switching operation
TEST(UnitTestFHEWAP, KeySwitch) {
  auto cc = BinFHEContext();

  cc.GenerateBinFHEContext(TOY, AP);

  NativeInteger Q = cc.GetParams()->GetLWEParams()->GetQ();

  auto sk = cc.KeyGen();
  auto skN = cc.KeyGenN();

  auto ctQN1 = cc.Encrypt(skN, 1, FRESH);
  auto ctQN0 = cc.Encrypt(skN, 0, FRESH);

  NativeVector newSK = sk->GetElement();
  newSK.SwitchModulus(Q);
  auto skQ = std::make_shared<LWEPrivateKeyImpl>(newSK);

  auto keySwitchHint = cc.KeySwitchGen(sk, skN);

  std::shared_ptr<LWECiphertextImpl> eQ1 = cc.GetLWEScheme()->KeySwitch(
      cc.GetParams()->GetLWEParams(), keySwitchHint, ctQN1);
  std::shared_ptr<LWECiphertextImpl> eQ0 = cc.GetLWEScheme()->KeySwitch(
      cc.GetParams()->GetLWEParams(), keySwitchHint, ctQN0);

  LWEPlaintext resultAfterKeySwitch1;
  cc.Decrypt(skQ, eQ1, &resultAfterKeySwitch1);

  LWEPlaintext resultAfterKeySwitch0;
  cc.Decrypt(skQ, eQ0, &resultAfterKeySwitch0);

  EXPECT_EQ(1, resultAfterKeySwitch1) << "Failed key switching test";

  EXPECT_EQ(0, resultAfterKeySwitch0) << "Failed key switching test";
}

// Checks the key switching operation
TEST(UnitTestFHEWGINX, KeySwitch) {
  auto cc = BinFHEContext();

  cc.GenerateBinFHEContext(TOY, GINX);

  NativeInteger Q = cc.GetParams()->GetLWEParams()->GetQ();

  auto sk = cc.KeyGen();
  auto skN = cc.KeyGenN();

  auto ctQN1 = cc.Encrypt(skN, 1, FRESH);
  auto ctQN0 = cc.Encrypt(skN, 0, FRESH);

  NativeVector newSK = sk->GetElement();
  newSK.SwitchModulus(Q);
  auto skQ = std::make_shared<LWEPrivateKeyImpl>(newSK);

  auto keySwitchHint = cc.KeySwitchGen(sk, skN);

  std::shared_ptr<LWECiphertextImpl> eQ1 = cc.GetLWEScheme()->KeySwitch(
      cc.GetParams()->GetLWEParams(), keySwitchHint, ctQN1);
  std::shared_ptr<LWECiphertextImpl> eQ0 = cc.GetLWEScheme()->KeySwitch(
      cc.GetParams()->GetLWEParams(), keySwitchHint, ctQN0);

  LWEPlaintext resultAfterKeySwitch1;
  cc.Decrypt(skQ, eQ1, &resultAfterKeySwitch1);

  LWEPlaintext resultAfterKeySwitch0;
  cc.Decrypt(skQ, eQ0, &resultAfterKeySwitch0);

  EXPECT_EQ(1, resultAfterKeySwitch1) << "Failed key switching test";

  EXPECT_EQ(0, resultAfterKeySwitch0) << "Failed key switching test";
}

// Checks the mod switching operation
TEST(UnitTestFHEWAP, ModSwitch) {
  auto cc = BinFHEContext();

  cc.GenerateBinFHEContext(TOY, AP);

  NativeInteger Q = cc.GetParams()->GetLWEParams()->GetQ();

  auto sk = cc.KeyGen();

  // switch secret key to Q
  NativeVector newSK = sk->GetElement();
  newSK.SwitchModulus(Q);
  auto skQ = std::make_shared<LWEPrivateKeyImpl>(newSK);

  auto ctQ1 = cc.Encrypt(skQ, 1, FRESH);
  auto ctQ0 = cc.Encrypt(skQ, 0, FRESH);

  // switches the modulus from Q to q
  auto ct1 = cc.GetLWEScheme()->ModSwitch(cc.GetParams()->GetLWEParams(), ctQ1);
  auto ct0 = cc.GetLWEScheme()->ModSwitch(cc.GetParams()->GetLWEParams(), ctQ0);

  LWEPlaintext resultAfterModSwitch1;
  cc.Decrypt(sk, ct1, &resultAfterModSwitch1);

  LWEPlaintext resultAfterModSwitch0;
  cc.Decrypt(sk, ct0, &resultAfterModSwitch0);

  EXPECT_EQ(1, resultAfterModSwitch1) << "Failed mod switching test";

  EXPECT_EQ(0, resultAfterModSwitch0) << "Failed mod switching test";
}

// Checks the mod switching operation
TEST(UnitTestFHEWGINX, ModSwitch) {
  auto cc = BinFHEContext();

  cc.GenerateBinFHEContext(TOY, GINX);

  NativeInteger Q = cc.GetParams()->GetLWEParams()->GetQ();

  auto sk = cc.KeyGen();

  // switch secret key to Q
  NativeVector newSK = sk->GetElement();
  newSK.SwitchModulus(Q);
  auto skQ = std::make_shared<LWEPrivateKeyImpl>(newSK);

  auto ctQ1 = cc.Encrypt(skQ, 1, FRESH);
  auto ctQ0 = cc.Encrypt(skQ, 0, FRESH);

  // switches the modulus from Q to q
  auto ct1 = cc.GetLWEScheme()->ModSwitch(cc.GetParams()->GetLWEParams(), ctQ1);
  auto ct0 = cc.GetLWEScheme()->ModSwitch(cc.GetParams()->GetLWEParams(), ctQ0);

  LWEPlaintext resultAfterModSwitch1;
  cc.Decrypt(sk, ct1, &resultAfterModSwitch1);

  LWEPlaintext resultAfterModSwitch0;
  cc.Decrypt(sk, ct0, &resultAfterModSwitch0);

  EXPECT_EQ(1, resultAfterModSwitch1) << "Failed mod switching test";

  EXPECT_EQ(0, resultAfterModSwitch0) << "Failed mod switching test";
}

// Checks the truth table for NOT
TEST(UnitTestFHEWAP, NOT) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, AP);

  auto sk = cc.KeyGen();

  auto ct1 = cc.Encrypt(sk, 1, FRESH);
  auto ct0 = cc.Encrypt(sk, 0, FRESH);

  auto ct1Not = cc.EvalNOT(ct1);
  auto ct0Not = cc.EvalNOT(ct0);

  LWEPlaintext result1;
  cc.Decrypt(sk, ct1Not, &result1);

  LWEPlaintext result0;
  cc.Decrypt(sk, ct0Not, &result0);

  EXPECT_EQ(0, result1) << "NOT failed";

  EXPECT_EQ(1, result0) << "NOT failed";
}

// Checks the truth table for NOT
TEST(UnitTestFHEWGINX, NOT) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, GINX);

  auto sk = cc.KeyGen();

  auto ct1 = cc.Encrypt(sk, 1, FRESH);
  auto ct0 = cc.Encrypt(sk, 0, FRESH);

  auto ct1Not = cc.EvalNOT(ct1);
  auto ct0Not = cc.EvalNOT(ct0);

  LWEPlaintext result1;
  cc.Decrypt(sk, ct1Not, &result1);

  LWEPlaintext result0;
  cc.Decrypt(sk, ct0Not, &result0);

  EXPECT_EQ(0, result1) << "NOT failed";

  EXPECT_EQ(1, result0) << "NOT failed";
}

// Checks the truth table for AND
TEST(UnitTestFHEWAP, Bootstrap) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, AP);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);

  auto ct11 = cc.Bootstrap(ct1);
  auto ct01 = cc.Bootstrap(ct0);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);

  std::string failed = "Bootstrapping failed";

  EXPECT_EQ(1, result11) << failed;
  EXPECT_EQ(0, result01) << failed;
}

// Checks the truth table for AND
TEST(UnitTestFHEWGINX, Bootstrap) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, GINX);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);

  auto ct11 = cc.Bootstrap(ct1);
  auto ct01 = cc.Bootstrap(ct0);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);

  std::string failed = "Bootstrapping failed";

  EXPECT_EQ(1, result11) << failed;
  EXPECT_EQ(0, result01) << failed;
}

// Checks the truth table for AND
TEST(UnitTestFHEWAP, AND) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, AP);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);
  auto ct1Alt = cc.Encrypt(sk, 1);
  auto ct0Alt = cc.Encrypt(sk, 0);

  auto ct11 = cc.EvalBinGate(AND, ct1, ct1Alt);
  auto ct01 = cc.EvalBinGate(AND, ct0, ct1);
  auto ct10 = cc.EvalBinGate(AND, ct1, ct0);
  auto ct00 = cc.EvalBinGate(AND, ct0, ct0Alt);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);
  LWEPlaintext result10;
  cc.Decrypt(sk, ct10, &result10);
  LWEPlaintext result00;
  cc.Decrypt(sk, ct00, &result00);

  std::string failed = "AND failed";

  EXPECT_EQ(1, result11) << failed;
  EXPECT_EQ(0, result01) << failed;
  EXPECT_EQ(0, result10) << failed;
  EXPECT_EQ(0, result00) << failed;
}

// Checks the truth table for AND
TEST(UnitTestFHEWGINX, AND) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, GINX);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);
  auto ct1Alt = cc.Encrypt(sk, 1);
  auto ct0Alt = cc.Encrypt(sk, 0);

  auto ct11 = cc.EvalBinGate(AND, ct1, ct1Alt);
  auto ct01 = cc.EvalBinGate(AND, ct0, ct1);
  auto ct10 = cc.EvalBinGate(AND, ct1, ct0);
  auto ct00 = cc.EvalBinGate(AND, ct0, ct0Alt);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);
  LWEPlaintext result10;
  cc.Decrypt(sk, ct10, &result10);
  LWEPlaintext result00;
  cc.Decrypt(sk, ct00, &result00);

  std::string failed = "AND failed";

  EXPECT_EQ(1, result11) << failed;
  EXPECT_EQ(0, result01) << failed;
  EXPECT_EQ(0, result10) << failed;
  EXPECT_EQ(0, result00) << failed;
}

// Checks GINX for the parameter set
// that exercises the signed modular reduction
// implementation in SignedDigitDecompose
TEST(UnitTestFHEWGINX, SIGNED_MOD) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(SIGNED_MOD_TEST, GINX);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);
  auto ct1Alt = cc.Encrypt(sk, 1);
  auto ct0Alt = cc.Encrypt(sk, 0);

  auto ct11 = cc.EvalBinGate(AND, ct1, ct1Alt);
  auto ct01 = cc.EvalBinGate(AND, ct0, ct1);
  auto ct10 = cc.EvalBinGate(AND, ct1, ct0);
  auto ct00 = cc.EvalBinGate(AND, ct0, ct0Alt);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);
  LWEPlaintext result10;
  cc.Decrypt(sk, ct10, &result10);
  LWEPlaintext result00;
  cc.Decrypt(sk, ct00, &result00);

  std::string failed = "AND failed for SIGNED_MOD_TEST";

  EXPECT_EQ(1, result11) << failed;
  EXPECT_EQ(0, result01) << failed;
  EXPECT_EQ(0, result10) << failed;
  EXPECT_EQ(0, result00) << failed;
}

// Checks the truth table for OR
TEST(UnitTestFHEWAP, OR) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, AP);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);
  auto ct1Alt = cc.Encrypt(sk, 1);
  auto ct0Alt = cc.Encrypt(sk, 0);

  auto ct11 = cc.EvalBinGate(OR, ct1, ct1Alt);
  auto ct01 = cc.EvalBinGate(OR, ct0, ct1);
  auto ct10 = cc.EvalBinGate(OR, ct1, ct0);
  auto ct00 = cc.EvalBinGate(OR, ct0, ct0Alt);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);
  LWEPlaintext result10;
  cc.Decrypt(sk, ct10, &result10);
  LWEPlaintext result00;
  cc.Decrypt(sk, ct00, &result00);

  std::string failed = "OR failed";

  EXPECT_EQ(1, result11) << failed;
  EXPECT_EQ(1, result01) << failed;
  EXPECT_EQ(1, result10) << failed;
  EXPECT_EQ(0, result00) << failed;
}

// Checks the truth table for OR
TEST(UnitTestFHEWGINX, OR) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, GINX);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);
  auto ct1Alt = cc.Encrypt(sk, 1);
  auto ct0Alt = cc.Encrypt(sk, 0);

  auto ct11 = cc.EvalBinGate(OR, ct1, ct1Alt);
  auto ct01 = cc.EvalBinGate(OR, ct0, ct1);
  auto ct10 = cc.EvalBinGate(OR, ct1, ct0);
  auto ct00 = cc.EvalBinGate(OR, ct0, ct0Alt);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);
  LWEPlaintext result10;
  cc.Decrypt(sk, ct10, &result10);
  LWEPlaintext result00;
  cc.Decrypt(sk, ct00, &result00);

  std::string failed = "OR failed";

  EXPECT_EQ(1, result11) << failed;
  EXPECT_EQ(1, result01) << failed;
  EXPECT_EQ(1, result10) << failed;
  EXPECT_EQ(0, result00) << failed;
}

// Checks the truth table for AND
TEST(UnitTestFHEWAP, NAND) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, AP);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);
  auto ct1Alt = cc.Encrypt(sk, 1);
  auto ct0Alt = cc.Encrypt(sk, 0);

  auto ct11 = cc.EvalBinGate(NAND, ct1, ct1Alt);
  auto ct01 = cc.EvalBinGate(NAND, ct0, ct1);
  auto ct10 = cc.EvalBinGate(NAND, ct1, ct0);
  auto ct00 = cc.EvalBinGate(NAND, ct0, ct0Alt);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);
  LWEPlaintext result10;
  cc.Decrypt(sk, ct10, &result10);
  LWEPlaintext result00;
  cc.Decrypt(sk, ct00, &result00);

  std::string failed = "NAND failed";

  EXPECT_EQ(0, result11) << failed;
  EXPECT_EQ(1, result01) << failed;
  EXPECT_EQ(1, result10) << failed;
  EXPECT_EQ(1, result00) << failed;
}

// Checks the truth table for AND
TEST(UnitTestFHEWGINX, NAND) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, GINX);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);
  auto ct1Alt = cc.Encrypt(sk, 1);
  auto ct0Alt = cc.Encrypt(sk, 0);

  auto ct11 = cc.EvalBinGate(NAND, ct1, ct1Alt);
  auto ct01 = cc.EvalBinGate(NAND, ct0, ct1);
  auto ct10 = cc.EvalBinGate(NAND, ct1, ct0);
  auto ct00 = cc.EvalBinGate(NAND, ct0, ct0Alt);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);
  LWEPlaintext result10;
  cc.Decrypt(sk, ct10, &result10);
  LWEPlaintext result00;
  cc.Decrypt(sk, ct00, &result00);

  std::string failed = "NAND failed";

  EXPECT_EQ(0, result11) << failed;
  EXPECT_EQ(1, result01) << failed;
  EXPECT_EQ(1, result10) << failed;
  EXPECT_EQ(1, result00) << failed;
}

// Checks the truth table for AND
TEST(UnitTestFHEWAP, NOR) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, AP);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);
  auto ct1Alt = cc.Encrypt(sk, 1);
  auto ct0Alt = cc.Encrypt(sk, 0);

  auto ct11 = cc.EvalBinGate(NOR, ct1, ct1Alt);
  auto ct01 = cc.EvalBinGate(NOR, ct0, ct1);
  auto ct10 = cc.EvalBinGate(NOR, ct1, ct0);
  auto ct00 = cc.EvalBinGate(NOR, ct0, ct0Alt);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);
  LWEPlaintext result10;
  cc.Decrypt(sk, ct10, &result10);
  LWEPlaintext result00;
  cc.Decrypt(sk, ct00, &result00);

  std::string failed = "NOR failed";

  EXPECT_EQ(0, result11) << failed;
  EXPECT_EQ(0, result01) << failed;
  EXPECT_EQ(0, result10) << failed;
  EXPECT_EQ(1, result00) << failed;
}

// Checks the truth table for AND
TEST(UnitTestFHEWGINX, NOR) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, GINX);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);
  auto ct1Alt = cc.Encrypt(sk, 1);
  auto ct0Alt = cc.Encrypt(sk, 0);

  auto ct11 = cc.EvalBinGate(NOR, ct1, ct1Alt);
  auto ct01 = cc.EvalBinGate(NOR, ct0, ct1);
  auto ct10 = cc.EvalBinGate(NOR, ct1, ct0);
  auto ct00 = cc.EvalBinGate(NOR, ct0, ct0Alt);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);
  LWEPlaintext result10;
  cc.Decrypt(sk, ct10, &result10);
  LWEPlaintext result00;
  cc.Decrypt(sk, ct00, &result00);

  std::string failed = "NOR failed";

  EXPECT_EQ(0, result11) << failed;
  EXPECT_EQ(0, result01) << failed;
  EXPECT_EQ(0, result10) << failed;
  EXPECT_EQ(1, result00) << failed;
}

// Checks the truth table for XOR
TEST(UnitTestFHEWAP, XOR) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, AP);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);
  auto ct1Alt = cc.Encrypt(sk, 1);
  auto ct0Alt = cc.Encrypt(sk, 0);

  auto ct11 = cc.EvalBinGate(XOR, ct1, ct1Alt);
  auto ct01 = cc.EvalBinGate(XOR, ct0, ct1);
  auto ct10 = cc.EvalBinGate(XOR, ct1, ct0);
  auto ct00 = cc.EvalBinGate(XOR, ct0, ct0Alt);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);
  LWEPlaintext result10;
  cc.Decrypt(sk, ct10, &result10);
  LWEPlaintext result00;
  cc.Decrypt(sk, ct00, &result00);

  std::string failed = "XOR failed";

  EXPECT_EQ(0, result11) << failed;
  EXPECT_EQ(1, result01) << failed;
  EXPECT_EQ(1, result10) << failed;
  EXPECT_EQ(0, result00) << failed;
}

// Checks the truth table for XOR
TEST(UnitTestFHEWGINX, XOR) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, GINX);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);
  auto ct1Alt = cc.Encrypt(sk, 1);
  auto ct0Alt = cc.Encrypt(sk, 0);

  auto ct11 = cc.EvalBinGate(XOR, ct1, ct1Alt);
  auto ct01 = cc.EvalBinGate(XOR, ct0, ct1);
  auto ct10 = cc.EvalBinGate(XOR, ct1, ct0);
  auto ct00 = cc.EvalBinGate(XOR, ct0, ct0Alt);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);
  LWEPlaintext result10;
  cc.Decrypt(sk, ct10, &result10);
  LWEPlaintext result00;
  cc.Decrypt(sk, ct00, &result00);

  std::string failed = "XOR failed";

  EXPECT_EQ(0, result11) << failed;
  EXPECT_EQ(1, result01) << failed;
  EXPECT_EQ(1, result10) << failed;
  EXPECT_EQ(0, result00) << failed;
}

// Checks the truth table for XOR
TEST(UnitTestFHEWAP, XNOR) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, AP);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);
  auto ct1Alt = cc.Encrypt(sk, 1);
  auto ct0Alt = cc.Encrypt(sk, 0);

  auto ct11 = cc.EvalBinGate(XNOR, ct1, ct1Alt);
  auto ct01 = cc.EvalBinGate(XNOR, ct0, ct1);
  auto ct10 = cc.EvalBinGate(XNOR, ct1, ct0);
  auto ct00 = cc.EvalBinGate(XNOR, ct0, ct0Alt);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);
  LWEPlaintext result10;
  cc.Decrypt(sk, ct10, &result10);
  LWEPlaintext result00;
  cc.Decrypt(sk, ct00, &result00);

  std::string failed = "XNOR failed";

  EXPECT_EQ(1, result11) << failed;
  EXPECT_EQ(0, result01) << failed;
  EXPECT_EQ(0, result10) << failed;
  EXPECT_EQ(1, result00) << failed;
}

// Checks the truth table for XOR
TEST(UnitTestFHEWGINX, XNOR) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, GINX);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);
  auto ct1Alt = cc.Encrypt(sk, 1);
  auto ct0Alt = cc.Encrypt(sk, 0);

  auto ct11 = cc.EvalBinGate(XNOR, ct1, ct1Alt);
  auto ct01 = cc.EvalBinGate(XNOR, ct0, ct1);
  auto ct10 = cc.EvalBinGate(XNOR, ct1, ct0);
  auto ct00 = cc.EvalBinGate(XNOR, ct0, ct0Alt);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);
  LWEPlaintext result10;
  cc.Decrypt(sk, ct10, &result10);
  LWEPlaintext result00;
  cc.Decrypt(sk, ct00, &result00);

  std::string failed = "XNOR failed";

  EXPECT_EQ(1, result11) << failed;
  EXPECT_EQ(0, result01) << failed;
  EXPECT_EQ(0, result10) << failed;
  EXPECT_EQ(1, result00) << failed;
}

// Checks the truth table for XOR
TEST(UnitTestFHEWAP, XOR_FAST) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, AP);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);
  auto ct1Alt = cc.Encrypt(sk, 1);
  auto ct0Alt = cc.Encrypt(sk, 0);

  auto ct11 = cc.EvalBinGate(XOR_FAST, ct1, ct1Alt);
  auto ct01 = cc.EvalBinGate(XOR_FAST, ct0, ct1);
  auto ct10 = cc.EvalBinGate(XOR_FAST, ct1, ct0);
  auto ct00 = cc.EvalBinGate(XOR_FAST, ct0, ct0Alt);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);
  LWEPlaintext result10;
  cc.Decrypt(sk, ct10, &result10);
  LWEPlaintext result00;
  cc.Decrypt(sk, ct00, &result00);

  std::string failed = "XOR_FAST failed";

  EXPECT_EQ(0, result11) << failed;
  EXPECT_EQ(1, result01) << failed;
  EXPECT_EQ(1, result10) << failed;
  EXPECT_EQ(0, result00) << failed;
}

// Checks the truth table for XOR
TEST(UnitTestFHEWGINX, XOR_FAST) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, GINX);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);
  auto ct1Alt = cc.Encrypt(sk, 1);
  auto ct0Alt = cc.Encrypt(sk, 0);

  auto ct11 = cc.EvalBinGate(XOR_FAST, ct1, ct1Alt);
  auto ct01 = cc.EvalBinGate(XOR_FAST, ct0, ct1);
  auto ct10 = cc.EvalBinGate(XOR_FAST, ct1, ct0);
  auto ct00 = cc.EvalBinGate(XOR_FAST, ct0, ct0Alt);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);
  LWEPlaintext result10;
  cc.Decrypt(sk, ct10, &result10);
  LWEPlaintext result00;
  cc.Decrypt(sk, ct00, &result00);

  std::string failed = "XOR_FAST failed";

  EXPECT_EQ(0, result11) << failed;
  EXPECT_EQ(1, result01) << failed;
  EXPECT_EQ(1, result10) << failed;
  EXPECT_EQ(0, result00) << failed;
}

// Checks the truth table for XOR
TEST(UnitTestFHEWAP, XNOR_FAST) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, AP);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);
  auto ct1Alt = cc.Encrypt(sk, 1);
  auto ct0Alt = cc.Encrypt(sk, 0);

  auto ct11 = cc.EvalBinGate(XNOR_FAST, ct1, ct1Alt);
  auto ct01 = cc.EvalBinGate(XNOR_FAST, ct0, ct1);
  auto ct10 = cc.EvalBinGate(XNOR_FAST, ct1, ct0);
  auto ct00 = cc.EvalBinGate(XNOR_FAST, ct0, ct0Alt);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);
  LWEPlaintext result10;
  cc.Decrypt(sk, ct10, &result10);
  LWEPlaintext result00;
  cc.Decrypt(sk, ct00, &result00);

  std::string failed = "XNOR_FAST failed";

  EXPECT_EQ(1, result11) << failed;
  EXPECT_EQ(0, result01) << failed;
  EXPECT_EQ(0, result10) << failed;
  EXPECT_EQ(1, result00) << failed;
}

// Checks the truth table for XOR
TEST(UnitTestFHEWGINX, XNOR_FAST) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(TOY, GINX);

  auto sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  auto ct1 = cc.Encrypt(sk, 1);
  auto ct0 = cc.Encrypt(sk, 0);
  auto ct1Alt = cc.Encrypt(sk, 1);
  auto ct0Alt = cc.Encrypt(sk, 0);

  auto ct11 = cc.EvalBinGate(XNOR_FAST, ct1, ct1Alt);
  auto ct01 = cc.EvalBinGate(XNOR_FAST, ct0, ct1);
  auto ct10 = cc.EvalBinGate(XNOR_FAST, ct1, ct0);
  auto ct00 = cc.EvalBinGate(XNOR_FAST, ct0, ct0Alt);

  LWEPlaintext result11;
  cc.Decrypt(sk, ct11, &result11);
  LWEPlaintext result01;
  cc.Decrypt(sk, ct01, &result01);
  LWEPlaintext result10;
  cc.Decrypt(sk, ct10, &result10);
  LWEPlaintext result00;
  cc.Decrypt(sk, ct00, &result00);

  std::string failed = "XNOR_FAST failed";

  EXPECT_EQ(1, result11) << failed;
  EXPECT_EQ(0, result01) << failed;
  EXPECT_EQ(0, result10) << failed;
  EXPECT_EQ(1, result00) << failed;
}
