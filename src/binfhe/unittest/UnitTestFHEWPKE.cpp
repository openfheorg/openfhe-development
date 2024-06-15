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

// Checks the truth table for NOT
TEST(UNITTestFHEWPKEAP, NOT) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, AP);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto ct1 = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0 = cc.Encrypt(cc.GetPublicKey(), 0);

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
TEST(UNITTestFHEWPKEGINX, NOT) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, GINX);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk, PUB_ENCRYPT);
    auto ct1 = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0 = cc.Encrypt(cc.GetPublicKey(), 0);

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
TEST(UNITTestFHEWPKEAP, Bootstrap) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, AP);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto ct1 = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0 = cc.Encrypt(cc.GetPublicKey(), 0);

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
TEST(UNITTestFHEWPKEGINX, Bootstrap) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, GINX);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto ct1 = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0 = cc.Encrypt(cc.GetPublicKey(), 0);

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
TEST(UNITTestFHEWPKEAP, AND) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, AP);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto ct1    = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0    = cc.Encrypt(cc.GetPublicKey(), 0);
    auto ct1Alt = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0Alt = cc.Encrypt(cc.GetPublicKey(), 0);

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
TEST(UNITTestFHEWPKEGINX, AND) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, GINX);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto ct1    = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0    = cc.Encrypt(cc.GetPublicKey(), 0);
    auto ct1Alt = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0Alt = cc.Encrypt(cc.GetPublicKey(), 0);

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
TEST(UNITTestFHEWPKEGINX, SIGNED_MOD) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(SIGNED_MOD_TEST, GINX);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto ct1    = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0    = cc.Encrypt(cc.GetPublicKey(), 0);
    auto ct1Alt = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0Alt = cc.Encrypt(cc.GetPublicKey(), 0);

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
TEST(UNITTestFHEWPKEAP, OR) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, AP);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto ct1    = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0    = cc.Encrypt(cc.GetPublicKey(), 0);
    auto ct1Alt = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0Alt = cc.Encrypt(cc.GetPublicKey(), 0);

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
TEST(UNITTestFHEWPKEGINX, OR) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, GINX);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto ct1    = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0    = cc.Encrypt(cc.GetPublicKey(), 0);
    auto ct1Alt = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0Alt = cc.Encrypt(cc.GetPublicKey(), 0);

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
TEST(UNITTestFHEWPKEAP, NAND) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, AP);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto ct1    = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0    = cc.Encrypt(cc.GetPublicKey(), 0);
    auto ct1Alt = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0Alt = cc.Encrypt(cc.GetPublicKey(), 0);

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
TEST(UNITTestFHEWPKEGINX, NAND) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, GINX);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto ct1    = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0    = cc.Encrypt(cc.GetPublicKey(), 0);
    auto ct1Alt = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0Alt = cc.Encrypt(cc.GetPublicKey(), 0);

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
TEST(UNITTestFHEWPKEAP, NOR) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, AP);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto ct1    = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0    = cc.Encrypt(cc.GetPublicKey(), 0);
    auto ct1Alt = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0Alt = cc.Encrypt(cc.GetPublicKey(), 0);

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
TEST(UNITTestFHEWPKEGINX, NOR) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, GINX);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto ct1    = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0    = cc.Encrypt(cc.GetPublicKey(), 0);
    auto ct1Alt = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0Alt = cc.Encrypt(cc.GetPublicKey(), 0);

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
TEST(UNITTestFHEWPKEAP, XOR) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, AP);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto ct1    = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0    = cc.Encrypt(cc.GetPublicKey(), 0);
    auto ct1Alt = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0Alt = cc.Encrypt(cc.GetPublicKey(), 0);

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
TEST(UNITTestFHEWPKEGINX, XOR) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, GINX);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto ct1    = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0    = cc.Encrypt(cc.GetPublicKey(), 0);
    auto ct1Alt = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0Alt = cc.Encrypt(cc.GetPublicKey(), 0);

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
TEST(UNITTestFHEWPKEAP, XNOR) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, AP);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto ct1    = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0    = cc.Encrypt(cc.GetPublicKey(), 0);
    auto ct1Alt = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0Alt = cc.Encrypt(cc.GetPublicKey(), 0);

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
TEST(UNITTestFHEWPKEGINX, XNOR) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, GINX);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto ct1    = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0    = cc.Encrypt(cc.GetPublicKey(), 0);
    auto ct1Alt = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct0Alt = cc.Encrypt(cc.GetPublicKey(), 0);

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
