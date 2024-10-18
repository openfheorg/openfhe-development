//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2024, NJIT, Duality Technologies Inc. and other contributors
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

#include "binfhecontext.h"
#include "gtest/gtest.h"

using namespace lbcrypto;

TEST(UNITTestFHEWExtended, EvalBinGate2) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, GINX);

    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto pk = cc.GetPublicKey();
    auto Q  = cc.GetParams()->GetLWEParams()->GetQ();

    auto ct_small = cc.Encrypt(pk, 1, SMALL_DIM, 4);
    EXPECT_NE(Q, ct_small->GetModulus());

    auto ct_large = cc.Encrypt(pk, 1, LARGE_DIM, 4);
    EXPECT_EQ(Q, ct_large->GetModulus());

    auto ct11 = cc.EvalBinGate(OR, ct_small, ct_large, true);
    EXPECT_EQ(Q, ct11->GetModulus());

    auto ct12 = cc.EvalBinGate(AND, ct_large, ct_small, true);
    EXPECT_EQ(Q, ct12->GetModulus());

    auto ct2  = cc.EvalBinGate(NAND, ct11, ct12, false);
    EXPECT_NE(Q, ct2->GetModulus());
    EXPECT_EQ(4, ct2->GetptModulus());

    LWEPlaintext result;
    cc.Decrypt(sk, ct2, &result);
    EXPECT_EQ(0, result);
}

TEST(UNITTestFHEWExtended, EvalBinGate3) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, GINX);

    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto pk = cc.GetPublicKey();
    auto Q  = cc.GetParams()->GetLWEParams()->GetQ();

    auto ct_small = cc.Encrypt(pk, 1, SMALL_DIM, 6);
    EXPECT_NE(Q, ct_small->GetModulus());

    auto ct_large = cc.Encrypt(pk, 1, LARGE_DIM, 6);
    EXPECT_EQ(Q, ct_large->GetModulus());

    std::vector<LWECiphertext> v{ct_small, ct_large, cc.Encrypt(pk, 0, SMALL_DIM, 6)};

    auto ct11 = cc.EvalBinGate(OR3, v, true);
    EXPECT_EQ(Q, ct11->GetModulus());
    EXPECT_EQ(6, ct11->GetptModulus());

    auto ct12 = cc.EvalBinGate(AND3, v, true);
    EXPECT_EQ(Q, ct12->GetModulus());
    EXPECT_EQ(6, ct12->GetptModulus());

    auto ct2  = cc.EvalBinGate(NAND, ct11, ct12, false);
    EXPECT_NE(Q, ct2->GetModulus());
    EXPECT_EQ(4, ct2->GetptModulus());

    LWEPlaintext result;
    cc.Decrypt(sk, ct2, &result);
    EXPECT_EQ(1, result);
}

TEST(UNITTestFHEWExtended, EvalBinGate4) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, GINX);

    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto pk = cc.GetPublicKey();
    auto Q  = cc.GetParams()->GetLWEParams()->GetQ();

    auto ct_small = cc.Encrypt(pk, 1, SMALL_DIM, 8);
    EXPECT_NE(Q, ct_small->GetModulus());

    auto ct_large = cc.Encrypt(pk, 1, LARGE_DIM, 8);
    EXPECT_EQ(Q, ct_large->GetModulus());

    std::vector<LWECiphertext> v{ct_small, ct_large, cc.Encrypt(pk, 0, SMALL_DIM, 8), cc.Encrypt(pk, 1, LARGE_DIM, 8)};

    auto ct11 = cc.EvalBinGate(OR4, v, true);
    EXPECT_EQ(Q, ct11->GetModulus());
    EXPECT_EQ(8, ct11->GetptModulus());

    auto ct12 = cc.EvalBinGate(AND4, v, true);
    EXPECT_EQ(Q, ct12->GetModulus());
    EXPECT_EQ(8, ct12->GetptModulus());

    auto ct2  = cc.EvalBinGate(NAND, ct11, ct12, false);
    EXPECT_NE(Q, ct2->GetModulus());
    EXPECT_EQ(4, ct2->GetptModulus());

    LWEPlaintext result;
    cc.Decrypt(sk, ct2, &result);
    EXPECT_EQ(1, result);
}

TEST(UNITTestFHEWExtended, BootStrap) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, GINX);

    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto pk = cc.GetPublicKey();
    auto Q  = cc.GetParams()->GetLWEParams()->GetQ();

    auto ct1 = cc.Bootstrap(cc.Encrypt(pk, 1, SMALL_DIM, 4), true);
    EXPECT_EQ(Q, ct1->GetModulus());

    auto ct0 = cc.Bootstrap(cc.Encrypt(pk, 0, LARGE_DIM, 4), true);
    EXPECT_EQ(Q, ct0->GetModulus());
}
