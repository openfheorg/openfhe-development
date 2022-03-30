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

// test very deep FHE operations
TEST(UnitTestFHEDeep, NOT_VERY_LONG) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128);

    auto sk = cc.KeyGen();
    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    unsigned int input(1);

    unsigned int nLoop(2000);

    LWECiphertext stmp = cc.Encrypt(sk, input);
    unsigned int tmp   = input;
    // not loop
    for (unsigned int ix = 0; ix < nLoop; ix++) {
        // if (ix % 100 == 0) std::cout << ix << std::endl;
        LWECiphertext a(stmp);
        auto b         = cc.EvalNOT(a);
        unsigned int c = !tmp;
        LWEPlaintext res;
        cc.Decrypt(sk, b, &res);
        std::string failed = "Failed in iteration " + std::to_string(ix);
        ASSERT_EQ(res, c) << failed;
        stmp = b;
        tmp  = c;
    }
}

// test very deep FHE operations
TEST(UnitTestFHEDeep, AND_GINX_VERY_LONG) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128, GINX);

    auto sk = cc.KeyGen();
    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    unsigned int input1(1);
    unsigned int input2(1);
    // unsigned int one(1);

    unsigned int nLoop(2000);

    LWECiphertext stmp1 = cc.Encrypt(sk, input1);
    LWECiphertext stmp2 = cc.Encrypt(sk, input2);
    auto d              = cc.EvalBinGate(AND, stmp1, stmp2);
    stmp1               = cc.Encrypt(sk, input1);
    stmp2               = cc.Encrypt(sk, input2);
    unsigned int tmp1   = input1;
    unsigned int tmp2   = input2;

    // and loop
    for (unsigned int ix = 0; ix < nLoop; ix++) {
        // if (ix % 100 == 0) std::cout << ix << std::endl;
        auto b = cc.EvalBinGate(AND, stmp1, stmp2);

        unsigned int c = tmp1 && tmp2;
        LWEPlaintext res;
        cc.Decrypt(sk, b, &res);
        std::string failed = "Failed in iteration " + std::to_string(ix);
        ASSERT_EQ(res, c) << failed;

        // we'd like to use the output to drive  both inputs on the next
        // cycle, but we can't, so lets generate a new input by anding with
        // a constant one.

        stmp1 = b;
        stmp2 = cc.EvalBinGate(AND, b, d);
        tmp1  = c;
        tmp2  = c;
    }
}

// test very deep FHE operations
TEST(UnitTestFHEDeep, AND_AP_VERY_LONG) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128, AP);

    auto sk = cc.KeyGen();
    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    unsigned int input1(1);
    unsigned int input2(1);
    // unsigned int one(1);

    unsigned int nLoop(2000);

    LWECiphertext stmp1 = cc.Encrypt(sk, input1);
    LWECiphertext stmp2 = cc.Encrypt(sk, input2);
    auto d              = cc.EvalBinGate(AND, stmp1, stmp2);
    stmp1               = cc.Encrypt(sk, input1);
    stmp2               = cc.Encrypt(sk, input2);
    // LWECiphertext eone = cc.Encrypt(sk, one);
    unsigned int tmp1 = input1;
    unsigned int tmp2 = input2;

    // not loop
    for (unsigned int ix = 0; ix < nLoop; ix++) {
        // if (ix % 100 == 0) std::cout << ix << std::endl;
        auto b = cc.EvalBinGate(AND, stmp1, stmp2);

        unsigned int c = tmp1 && tmp2;
        LWEPlaintext res;
        cc.Decrypt(sk, b, &res);
        std::string failed = "Failed in iteration " + std::to_string(ix);
        ASSERT_EQ(res, c) << failed;

        // we'd like to use the output to drive  both inputs on the next
        // cycle, but we can't, so lets generate a new input by anding with
        // a constant one.

        stmp1 = b;
        stmp2 = cc.EvalBinGate(AND, b, d);

        tmp1 = c;
        tmp2 = c;
    }
}

// test very deep FHE operations
TEST(UnitTestFHEDeep, XOR_AP_VERY_LONG) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128, AP);

    auto sk = cc.KeyGen();
    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    unsigned int input1(1);
    unsigned int input2(1);
    unsigned int one(1);

    unsigned int nLoop(2000);

    LWECiphertext stmp1 = cc.Encrypt(sk, input1);
    LWECiphertext stmp2 = cc.Encrypt(sk, input2);
    LWECiphertext eone  = cc.Encrypt(sk, one);
    unsigned int tmp1   = input1;
    unsigned int tmp2   = input2;

    // xor loop
    for (unsigned int ix = 0; ix < nLoop; ix++) {
        // if (ix % 100 == 0) std::cout << ix << std::endl;
        auto b = cc.EvalBinGate(XOR, stmp1, stmp2);

        unsigned int c = tmp1 ^ tmp2;
        LWEPlaintext res;
        cc.Decrypt(sk, b, &res);
        std::string failed = "Failed in iteration " + std::to_string(ix);
        ASSERT_EQ(res, c) << failed;

        // we'd like to use the output to drive  both inputs on the next
        // cycle, but we can't, so lets generate a new input by anding with
        // a constant one.

        stmp1 = b;
        stmp2 = cc.EvalBinGate(AND, b, eone);

        tmp1 = c;
        tmp2 = c;
    }
}
// test very deep FHE operations
TEST(UnitTestFHEDeep, XOR_GINX_VERY_LONG) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128, GINX);

    auto sk = cc.KeyGen();
    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    unsigned int input1(1);
    unsigned int input2(1);
    unsigned int one(1);

    unsigned int nLoop(2000);

    LWECiphertext stmp1 = cc.Encrypt(sk, input1);
    LWECiphertext stmp2 = cc.Encrypt(sk, input2);
    LWECiphertext eone  = cc.Encrypt(sk, one);
    unsigned int tmp1   = input1;
    unsigned int tmp2   = input2;

    // xor loop
    for (unsigned int ix = 0; ix < nLoop; ix++) {
        // if (ix % 100 == 0) std::cout << ix << std::endl;
        auto b = cc.EvalBinGate(XOR, stmp1, stmp2);

        unsigned int c = tmp1 ^ tmp2;
        LWEPlaintext res;
        cc.Decrypt(sk, b, &res);
        std::string failed = "Failed in iteration " + std::to_string(ix);
        ASSERT_EQ(res, c) << failed;

        // we'd like to use the output to drive  both inputs on the next
        // cycle, but we can't, so lets generate a new input by anding with
        // a constant one.

        stmp1 = b;
        stmp2 = cc.EvalBinGate(AND, b, eone);

        tmp1 = c;
        tmp2 = c;
    }
}

// test very deep FHE operations
TEST(UnitTestFHEDeep, OR_AP_VERY_LONG) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128, AP);

    auto sk = cc.KeyGen();
    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    unsigned int input1(1);
    unsigned int input2(1);

    unsigned int nLoop(2000);

    LWECiphertext stmp1 = cc.Encrypt(sk, input1);
    LWECiphertext stmp2 = cc.Encrypt(sk, input2);
    unsigned int tmp1   = input1;
    unsigned int tmp2   = input2;

    // or loop
    for (unsigned int ix = 0; ix < nLoop; ix++) {
        // if (ix % 100 == 0) std::cout << ix << std::endl;
        auto b = cc.EvalBinGate(OR, stmp1, stmp2);

        unsigned int c = tmp1 || tmp2;
        LWEPlaintext res;
        cc.Decrypt(sk, b, &res);
        std::string failed = "Failed in iteration " + std::to_string(ix);
        ASSERT_EQ(res, c) << failed;
        stmp1 = b;
        tmp1  = c;
    }
}

// test very deep FHE operations
TEST(UnitTestFHEDeep, OR_GINX_VERY_LONG) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128, GINX);

    auto sk = cc.KeyGen();
    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    unsigned int input1(1);
    unsigned int input2(1);

    unsigned int nLoop(2000);

    LWECiphertext stmp1 = cc.Encrypt(sk, input1);
    LWECiphertext stmp2 = cc.Encrypt(sk, input2);
    unsigned int tmp1   = input1;
    unsigned int tmp2   = input2;

    // or loop
    for (unsigned int ix = 0; ix < nLoop; ix++) {
        // if (ix % 100 == 0) std::cout << ix << std::endl;
        auto b = cc.EvalBinGate(OR, stmp1, stmp2);

        unsigned int c = tmp1 || tmp2;
        LWEPlaintext res;
        cc.Decrypt(sk, b, &res);
        std::string failed = "Failed in iteration " + std::to_string(ix);
        ASSERT_EQ(res, c) << failed;
        stmp1 = b;
        tmp1  = c;
    }
}
