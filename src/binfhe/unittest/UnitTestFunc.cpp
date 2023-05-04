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

// Checks the arbitrary function evaluation
#if NATIVEINT != 32
TEST(UnitTestFHEWGINX, EvalArbFunc) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, true, 12);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    int p   = cc.GetMaxPlaintextSpace().ConvertToInt();
    auto fp = [](NativeInteger m, NativeInteger p1) -> NativeInteger {
        if (m < p1)
            return (m * m * m) % p1;
        else
            return ((m - p1 / 2) * (m - p1 / 2) * (m - p1 / 2)) % p1;
    };
    auto lut = cc.GenerateLUTviaFunction(fp, p);

    for (int i = 0; i < p; i++) {
        auto ct1 = cc.Encrypt(sk, i % p, FRESH, p);

        auto ct_cube = cc.EvalFunc(ct1, lut);

        LWEPlaintext result;

        cc.Decrypt(sk, ct_cube, &result, p);
        //        std::cerr << "i: " << i << ", f=" << fp(i, p).ConvertToInt() << ", r=" << result << std::endl;
        std::string failed = "Arbitrary Function Evaluation failed";
        EXPECT_EQ(usint(fp(i, p).ConvertToInt()), result) << failed;
    }
}

// Checks the rounding down evaluation
TEST(UnitTestFHEWGINX, EvalFloorFunc) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, false, 12);

    auto sk = cc.KeyGen();

    cc.BTKeyGen(sk);

    int p = cc.GetMaxPlaintextSpace().ConvertToInt();  // Obtain the maximum plaintext space

    for (int i = p / 2 - 3; i < p / 2 + 5; i++) {
        auto ct1 = cc.Encrypt(sk, i % p, FRESH, p);

        // round by one bit.
        auto ctRounded = cc.EvalFloor(ct1, 1);

        LWEPlaintext result;

        cc.Decrypt(sk, ctRounded, &result, p / 2);
        //        std::cerr << "i: " << i << ", f=" << (i / 2) << ", r=" << result << std::endl;
        std::string failed = "Floor Function Evalution failed";
        EXPECT_EQ(usint(i / 2), result) << failed;
    }
}

// Checks the sign evaluation
TEST(UnitTestFHEWGINX, EvalSignFuncTime) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, false, 29, 0, GINX, true);

    uint32_t Q = 1 << 29;
    int q      = 4096;
    int factor = 1 << int(29 - log2(q));
    int p      = cc.GetMaxPlaintextSpace().ConvertToInt();
    auto sk    = cc.KeyGen();
    cc.BTKeyGen(sk);

    std::string failed = "Large Precision Sign Evalution failed";

    for (int i = 0; i < 8; i++) {
        auto ct1 = cc.Encrypt(sk, p * factor / 2 + i - 3, FRESH, p * factor, Q);
        ct1      = cc.EvalSign(ct1);
        LWEPlaintext result;
        cc.Decrypt(sk, ct1, &result, 2);
        // std::cerr << "i: " << i << ", f=" << (i >= 3) << ", r=" << result << std::endl;
        EXPECT_EQ(usint(i >= 3), result) << failed;
    }
}

// Checks the sign evaluation
TEST(UnitTestFHEWGINX, EvalSignFuncSpace) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, false, 29, 0, GINX, false);

    uint32_t Q = 1 << 29;
    int q      = 4096;
    int factor = 1 << int(29 - log2(q));
    int p      = cc.GetMaxPlaintextSpace().ConvertToInt();
    auto sk    = cc.KeyGen();
    cc.BTKeyGen(sk);

    std::string failed = "Large Precision Sign Evalution failed";

    for (int i = 0; i < 8; i++) {
        auto ct1 = cc.Encrypt(sk, p * factor / 2 + i - 3, FRESH, p * factor, Q);
        ct1      = cc.EvalSign(ct1);
        LWEPlaintext result;
        cc.Decrypt(sk, ct1, &result, 2);
        EXPECT_EQ(usint(i >= 3), result) << failed;
    }
}

// Checks the digit decomposition evaluation
TEST(UnitTestFHEWGINX, EvalDigitDecompTime) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, false, 29, 0, GINX, true);
    uint32_t Q = 1 << 29;

    int basic        = 4096;                             // q
    int factor       = 1 << int(log2(Q) - log2(basic));  // Q/q
    uint64_t p_basic = cc.GetMaxPlaintextSpace().ConvertToInt();
    uint64_t P       = p_basic * factor;
    auto st          = P / 2 - 3;
    // Generate the secret key
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    std::string failed = "Large Precision Ciphertext Decomposition failed";

    // digit decomposes values starting with st upto st + 7 and checks every digit of each decomposition
    for (uint64_t i = st; i < st + 8; i++) {
        auto ct1 = cc.Encrypt(sk, i, FRESH, p_basic * factor, Q);

        auto decomp = cc.EvalDecomp(ct1);
        EXPECT_EQ(usint(ceil(log(factor) / log(p_basic)) + 1), decomp.size()) << failed;

        auto p_basicdecrypt = p_basic;
        LWEPlaintext result;
        for (size_t j = 0; j < decomp.size(); j++) {
            ct1 = decomp[j];

            if (j == decomp.size() - 1) {
                // after every evalfloor, the least significant digit is dropped so the last modulus is computed as log p = (log P) mod (log GetMaxPlaintextSpace)
                auto logp      = GetMSB(P - 1) % GetMSB(p_basic - 1);
                p_basicdecrypt = 1 << logp;
            }
            cc.Decrypt(sk, ct1, &result, p_basicdecrypt);

            if (i < st + 3) {
                if (j == 0) {
                    EXPECT_EQ(usint(13 + i - st), result) << failed;
                }
                else if (j == decomp.size() - 1) {
                    EXPECT_EQ(usint(0), result) << failed;
                }
                else {
                    EXPECT_EQ(usint(15), result) << failed;
                }
            }
            else {
                if (j == 0) {
                    EXPECT_EQ(usint(0 + i - (st + 3)), result) << failed;
                }
                else if (j == decomp.size() - 1) {
                    EXPECT_EQ(usint(1), result) << failed;
                }
                else {
                    EXPECT_EQ(usint(0), result) << failed;
                }
            }
        }
    }
}

// Checks the sign evaluation
TEST(UnitTestFHEWGINX, EvalDigitDecompSpace) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, false, 29, 0, GINX, false);
    uint32_t Q = 1 << 29;

    int basic        = 4096;                             // q
    int factor       = 1 << int(log2(Q) - log2(basic));  // Q/q
    uint64_t p_basic = cc.GetMaxPlaintextSpace().ConvertToInt();
    uint64_t P       = p_basic * factor;
    auto st          = P / 2 - 3;
    // Generate the secret key
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    std::string failed = "Large Precision Ciphertext Decomposition failed";

    for (uint64_t i = st; i < st + 8; i++) {
        auto ct1 = cc.Encrypt(sk, i, FRESH, p_basic * factor, Q);

        auto decomp = cc.EvalDecomp(ct1);
        EXPECT_EQ(usint(ceil(log(factor) / log(p_basic)) + 1), decomp.size()) << failed;

        auto p_basicdecrypt = p_basic;
        LWEPlaintext result;
        for (size_t j = 0; j < decomp.size(); j++) {
            ct1 = decomp[j];

            if (j == decomp.size() - 1) {
                // after every evalfloor, the least significant digit is dropped so the last modulus is computed as log p = (log P) mod (log GetMaxPlaintextSpace)
                auto logp      = GetMSB(P - 1) % GetMSB(p_basic - 1);
                p_basicdecrypt = 1 << logp;
            }
            cc.Decrypt(sk, ct1, &result, p_basicdecrypt);

            if (i < st + 3) {
                if (j == 0) {
                    EXPECT_EQ(usint(13 + i - st), result) << failed;
                }
                else if (j == decomp.size() - 1) {
                    EXPECT_EQ(usint(0), result) << failed;
                }
                else {
                    EXPECT_EQ(usint(15), result) << failed;
                }
            }
            else {
                if (j == 0) {
                    EXPECT_EQ(usint(0 + i - (st + 3)), result) << failed;
                }
                else if (j == decomp.size() - 1) {
                    EXPECT_EQ(usint(1), result) << failed;
                }
                else {
                    EXPECT_EQ(usint(0), result) << failed;
                }
            }
        }
    }
}
#endif
