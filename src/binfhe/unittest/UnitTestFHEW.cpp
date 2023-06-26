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
  This code runs unit tests for the FHEW methods of the OpenFHE lattice encryption library
 */

#include "binfhecontext.h"
#include "gtest/gtest.h"

using namespace lbcrypto;

// ---------------  TESTING METHODS OF FHEW ---------------
// Checks the key switching operation
void UTGENERAL_FHEW_KeySwitch(BINFHE_METHOD variant) {

    auto cc = BinFHEContext();

    cc.GenerateBinFHEContext(TOY, variant);

    NativeInteger Q = cc.GetParams()->GetLWEParams()->GetQ();

    auto sk  = cc.KeyGen();
    auto skN = cc.KeyGenN();

    auto ctQN1 = cc.Encrypt(skN, 1, FRESH, 4, Q);
    auto ctQN0 = cc.Encrypt(skN, 0, FRESH, 4, Q);

    NativeVector newSK = sk->GetElement();
    newSK.SwitchModulus(Q);
    auto skQ = std::make_shared<LWEPrivateKeyImpl>(newSK);

    auto keySwitchHint = cc.KeySwitchGen(sk, skN);

    LWECiphertext eQ1 = cc.GetLWEScheme()->KeySwitch(cc.GetParams()->GetLWEParams(), keySwitchHint, ctQN1);
    LWECiphertext eQ0 = cc.GetLWEScheme()->KeySwitch(cc.GetParams()->GetLWEParams(), keySwitchHint, ctQN0);

    LWEPlaintext resultAfterKeySwitch1;
    cc.Decrypt(skQ, eQ1, &resultAfterKeySwitch1);

    LWEPlaintext resultAfterKeySwitch0;
    cc.Decrypt(skQ, eQ0, &resultAfterKeySwitch0);

    EXPECT_EQ(1, resultAfterKeySwitch1) << "Failed key switching test";

    EXPECT_EQ(0, resultAfterKeySwitch0) << "Failed key switching test";
}


// Checks the mod switching operation
void UTGENERAL_FHEW_ModSwitch(BINFHE_METHOD variant) {

    auto cc = BinFHEContext();

    cc.GenerateBinFHEContext(TOY, variant);

    NativeInteger Q = cc.GetParams()->GetLWEParams()->GetQ();

    auto sk = cc.KeyGen();

    // switch secret key to Q
    NativeVector newSK = sk->GetElement();
    newSK.SwitchModulus(Q);
    auto skQ = std::make_shared<LWEPrivateKeyImpl>(newSK);

    auto ctQ1 = cc.Encrypt(skQ, 1, FRESH, 4, Q);
    auto ctQ0 = cc.Encrypt(skQ, 0, FRESH, 4, Q);

    // switches the modulus from Q to q
    auto ct1 = cc.GetLWEScheme()->ModSwitch(cc.GetParams()->GetLWEParams()->Getq(), ctQ1);
    auto ct0 = cc.GetLWEScheme()->ModSwitch(cc.GetParams()->GetLWEParams()->Getq(), ctQ0);

    LWEPlaintext resultAfterModSwitch1;
    cc.Decrypt(sk, ct1, &resultAfterModSwitch1);

    LWEPlaintext resultAfterModSwitch0;
    cc.Decrypt(sk, ct0, &resultAfterModSwitch0);

    EXPECT_EQ(1, resultAfterModSwitch1) << "Failed mod switching test";

    EXPECT_EQ(0, resultAfterModSwitch0) << "Failed mod switching test";
}

// Checks the truth table for NOT
void UTGENERAL_FHEW_NOT(BINFHE_METHOD variant) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, variant);

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
void UTGENERAL_FHEW_Bootstrap(BINFHE_METHOD variant) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, variant);

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
void UTGENERAL_FHEW_AND(BINFHE_METHOD variant) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, variant);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk);

    auto ct1    = cc.Encrypt(sk, 1);
    auto ct0    = cc.Encrypt(sk, 0);
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

// Checks the truth table for OR
void UTGENERAL_FHEW_OR(BINFHE_METHOD variant) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, variant);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk);

    auto ct1    = cc.Encrypt(sk, 1);
    auto ct0    = cc.Encrypt(sk, 0);
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
void UTGENERAL_FHEW_NAND(BINFHE_METHOD variant) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, variant);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk);

    auto ct1    = cc.Encrypt(sk, 1);
    auto ct0    = cc.Encrypt(sk, 0);
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
void UTGENERAL_FHEW_NOR(BINFHE_METHOD variant) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, variant);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk);

    auto ct1    = cc.Encrypt(sk, 1);
    auto ct0    = cc.Encrypt(sk, 0);
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
void UTGENERAL_FHEW_XOR(BINFHE_METHOD variant) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, variant);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk);

    auto ct1    = cc.Encrypt(sk, 1);
    auto ct0    = cc.Encrypt(sk, 0);
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
void UTGENERAL_FHEW_XNOR(BINFHE_METHOD variant) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, variant);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk);

    auto ct1    = cc.Encrypt(sk, 1);
    auto ct0    = cc.Encrypt(sk, 0);
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
void UTGENERAL_FHEW_XOR_FAST(BINFHE_METHOD variant) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, variant);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk);

    auto ct1    = cc.Encrypt(sk, 1);
    auto ct0    = cc.Encrypt(sk, 0);
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
void UTGENERAL_FHEW_XNOR_FAST(BINFHE_METHOD variant) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, variant);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk);

    auto ct1    = cc.Encrypt(sk, 1);
    auto ct0    = cc.Encrypt(sk, 0);
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

TEST(UTGENERAL_FHEW_KeySwitch, GINX) {
    UTGENERAL_FHEW_XNOR_FAST(GINX);
}
TEST(UTGENERAL_FHEW_KeySwitch, AP) {
    UTGENERAL_FHEW_XNOR_FAST(AP);
}
TEST(UTGENERAL_FHEW_KeySwitch, LMKCDEY) {
    UTGENERAL_FHEW_XNOR_FAST(LMKCDEY);
}

TEST(UTGENERAL_FHEW_ModSwitch, GINX) {
    UTGENERAL_FHEW_XNOR_FAST(GINX);
}
TEST(UTGENERAL_FHEW_ModSwitch, AP) {
    UTGENERAL_FHEW_XNOR_FAST(AP);
}
TEST(UTGENERAL_FHEW_ModSwitch, LMKCDEY) {
    UTGENERAL_FHEW_XNOR_FAST(LMKCDEY);
}

TEST(UTGENERAL_FHEW_NOT, GINX) {
    UTGENERAL_FHEW_XNOR_FAST(GINX);
}
TEST(UTGENERAL_FHEW_NOT, AP) {
    UTGENERAL_FHEW_XNOR_FAST(AP);
}
TEST(UTGENERAL_FHEW_NOT, LMKCDEY) {
    UTGENERAL_FHEW_XNOR_FAST(LMKCDEY);
}

TEST(UTGENERAL_FHEW_Bootstrap, GINX) {
    UTGENERAL_FHEW_XNOR_FAST(GINX);
}
TEST(UTGENERAL_FHEW_Bootstrap, AP) {
    UTGENERAL_FHEW_XNOR_FAST(AP);
}
TEST(UTGENERAL_FHEW_Bootstrap, LMKCDEY) {
    UTGENERAL_FHEW_XNOR_FAST(LMKCDEY);
}

TEST(UTGENERAL_FHEW_AND, GINX) {
    UTGENERAL_FHEW_XNOR_FAST(GINX);
}
TEST(UTGENERAL_FHEW_AND, AP) {
    UTGENERAL_FHEW_XNOR_FAST(AP);
}
TEST(UTGENERAL_FHEW_AND, LMKCDEY) {
    UTGENERAL_FHEW_XNOR_FAST(LMKCDEY);
}

TEST(UTGENERAL_FHEW_OR, GINX) {
    UTGENERAL_FHEW_XNOR_FAST(GINX);
}
TEST(UTGENERAL_FHEW_OR, AP) {
    UTGENERAL_FHEW_XNOR_FAST(AP);
}
TEST(UTGENERAL_FHEW_OR, LMKCDEY) {
    UTGENERAL_FHEW_XNOR_FAST(LMKCDEY);
}

TEST(UTGENERAL_FHEW_NAND, GINX) {
    UTGENERAL_FHEW_XNOR_FAST(GINX);
}
TEST(UTGENERAL_FHEW_NAND, AP) {
    UTGENERAL_FHEW_XNOR_FAST(AP);
}
TEST(UTGENERAL_FHEW_NAND, LMKCDEY) {
    UTGENERAL_FHEW_XNOR_FAST(LMKCDEY);
}

TEST(UTGENERAL_FHEW_NOR, GINX) {
    UTGENERAL_FHEW_XNOR_FAST(GINX);
}
TEST(UTGENERAL_FHEW_NOR, AP) {
    UTGENERAL_FHEW_XNOR_FAST(AP);
}
TEST(UTGENERAL_FHEW_NOR, LMKCDEY) {
    UTGENERAL_FHEW_XNOR_FAST(LMKCDEY);
}

TEST(UTGENERAL_FHEW_XOR, GINX) {
    UTGENERAL_FHEW_XNOR_FAST(GINX);
}
TEST(UTGENERAL_FHEW_XOR, AP) {
    UTGENERAL_FHEW_XNOR_FAST(AP);
}
TEST(UTGENERAL_FHEW_XOR, LMKCDEY) {
    UTGENERAL_FHEW_XNOR_FAST(LMKCDEY);
}

TEST(UTGENERAL_FHEW_XNOR, GINX) {
    UTGENERAL_FHEW_XNOR_FAST(GINX);
}
TEST(UTGENERAL_FHEW_XNOR, AP) {
    UTGENERAL_FHEW_XNOR_FAST(AP);
}
TEST(UTGENERAL_FHEW_XNOR, LMKCDEY) {
    UTGENERAL_FHEW_XNOR_FAST(LMKCDEY);
}

TEST(UTGENERAL_FHEW_XOR_FAST, GINX) {
    UTGENERAL_FHEW_XNOR_FAST(GINX);
}
TEST(UTGENERAL_FHEW_XOR_FAST, AP) {
    UTGENERAL_FHEW_XNOR_FAST(AP);
}
TEST(UTGENERAL_FHEW_XOR_FAST, LMKCDEY) {
    UTGENERAL_FHEW_XNOR_FAST(LMKCDEY);
}

TEST(UTGENERAL_FHEW_XNOR_FAST, GINX) {
    UTGENERAL_FHEW_XNOR_FAST(GINX);
}
TEST(UTGENERAL_FHEW_XNOR_FAST, AP) {
    UTGENERAL_FHEW_XNOR_FAST(AP);
}
TEST(UTGENERAL_FHEW_XNOR_FAST, LMKCDEY) {
    UTGENERAL_FHEW_XNOR_FAST(LMKCDEY);
}


// Checks GINX for the parameter set
// that exercises the signed modular reduction
// implementation in SignedDigitDecompose
TEST(UTGENERAL_FHEW, SIGNED_MOD) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(SIGNED_MOD_TEST, GINX);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk);

    auto ct1    = cc.Encrypt(sk, 1);
    auto ct0    = cc.Encrypt(sk, 0);
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

