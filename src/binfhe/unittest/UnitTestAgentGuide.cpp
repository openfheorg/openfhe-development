//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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
  Checks the binfhe behaviour that the application guide in agents/ states as fact. When a test here fails, update
  agents/reference/binfhe.md (and this test), or fix the regression. See "Keeping agents/ current" in AGENTS.md.
 */

#include <string>
#include <vector>

#include "binfhecontext.h"
#include "gtest/gtest.h"

using namespace lbcrypto;

namespace {
const char BINFHE_MD[] = "update agents/reference/binfhe.md";
}  // namespace

TEST(UTAgentGuideBinFHE, Gates) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);

    LWEPlaintext result;
    for (LWEPlaintext x : {0, 1}) {
        for (LWEPlaintext y : {0, 1}) {
            auto a = cc.Encrypt(sk, x);
            auto b = cc.Encrypt(sk, y);
            cc.Decrypt(sk, cc.EvalBinGate(AND, a, b), &result);
            EXPECT_EQ(result, x & y) << BINFHE_MD;
            cc.Decrypt(sk, cc.EvalBinGate(XNOR, a, b), &result);
            EXPECT_EQ(result, x == y ? 1 : 0) << BINFHE_MD;
            // the output of EvalNOT can feed a gate
            cc.Decrypt(sk, cc.EvalBinGate(OR, a, cc.EvalNOT(b)), &result);
            EXPECT_EQ(result, x | (1 - y)) << BINFHE_MD;
        }
    }

    // the two inputs of a gate must be different ciphertext objects
    auto a = cc.Encrypt(sk, 1);
    std::string message;
    try {
        cc.EvalBinGate(AND, a, a);
    } catch (const std::exception& e) {
        message = e.what();
    }
    EXPECT_NE(message.find("Input ciphertexts should be independant"), std::string::npos)
            << BINFHE_MD << " and agents/reference/troubleshooting.md";
}

TEST(UTAgentGuideBinFHE, PublicKeyEncryption) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk, PUB_ENCRYPT);
    auto pk = cc.GetPublicKey();

    LWEPlaintext result;
    cc.Decrypt(sk, cc.EvalBinGate(AND, cc.Encrypt(pk, 1), cc.Encrypt(pk, 1)), &result);
    EXPECT_EQ(result, 1) << BINFHE_MD;
}

// Lookup tables and large-precision sign evaluation need a native integer wider than 32 bits.
#if NATIVEINT != 32
TEST(UTAgentGuideBinFHE, LookupTable) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128, true, 12);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);

    int p = cc.GetMaxPlaintextSpace().ConvertToInt();
    ASSERT_EQ(p, 8) << BINFHE_MD;

    auto f = [](NativeInteger m, NativeInteger p1) -> NativeInteger {
        return (m * m) % p1;
    };
    auto lut = cc.GenerateLUTviaFunction(f, p);
    for (int i = 0; i < p; ++i) {
        LWEPlaintext result;
        cc.Decrypt(sk, cc.EvalFunc(cc.Encrypt(sk, i, LARGE_DIM, p), lut), &result, p);
        EXPECT_EQ(result, (i * i) % p) << BINFHE_MD;
    }
}

TEST(UTAgentGuideBinFHE, LargePrecisionSign) {
    uint32_t logQ = 17;
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128, false, logQ, 0, GINX, false);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    uint32_t Q = 1 << logQ;
    int p = cc.GetMaxPlaintextSpace().ConvertToInt() * (1 << (logQ - 12));
    ASSERT_EQ(p, 512) << BINFHE_MD;

    LWEPlaintext result;
    cc.Decrypt(sk, cc.EvalSign(cc.Encrypt(sk, p / 2 + 5, LARGE_DIM, p, Q)), &result, 2);
    EXPECT_EQ(result, 1) << BINFHE_MD;
    cc.Decrypt(sk, cc.EvalSign(cc.Encrypt(sk, p / 2 - 5, LARGE_DIM, p, Q)), &result, 2);
    EXPECT_EQ(result, 0) << BINFHE_MD;
}
#endif  // NATIVEINT != 32
