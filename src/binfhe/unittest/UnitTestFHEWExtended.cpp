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

#include <utility>
#include <vector>

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

    auto ct2 = cc.EvalBinGate(NAND, ct11, ct12, false);
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

    auto ct2 = cc.EvalBinGate(NAND, ct11, ct12, false);
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

    auto ct2 = cc.EvalBinGate(NAND, ct11, ct12, false);
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

// BTKeyGen caches the bootstrapping key per gadget base, but its validity also depends on the
// secret key. A second BTKeyGen with a different key must regenerate, not return the first key.
TEST(UNITTestFHEWExtended, BTKeyGenRegeneratesForNewSecretKey) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128, GINX);

    for (uint32_t round = 0; round < 2; ++round) {
        auto sk = cc.KeyGen();
        cc.BTKeyGen(sk);
        for (uint32_t i = 0; i < 4; ++i) {
            uint32_t b0 = i & 0x1, b1 = (i >> 1) & 0x1;
            auto ct = cc.EvalBinGate(NAND, cc.Encrypt(sk, b0), cc.Encrypt(sk, b1));
            LWEPlaintext result;
            cc.Decrypt(sk, ct, &result);
            EXPECT_EQ(static_cast<LWEPlaintext>(1 - (b0 & b1)), result)
                << "NAND(" << b0 << "," << b1 << ") wrong for secret key " << (round + 1);
        }
    }
}

// The same, with the time-optimization path, which keeps one key per gadget base.
// Excluded at NATIVE_SIZE=32 as in UnitTestFunc.cpp: the large-precision constructor sets
// qKS = 1 << 35, which truncates to zero in a 32-bit NativeInteger.
#if NATIVEINT != 32
TEST(UNITTestFHEWExtended, BTKeyGenRegeneratesForNewSecretKeyTimeOptimization) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, false, 11, 0, GINX, true);

    for (uint32_t round = 0; round < 2; ++round) {
        auto sk = cc.KeyGen();
        cc.BTKeyGen(sk);
        for (uint32_t i = 0; i < 4; ++i) {
            uint32_t b0 = i & 0x1, b1 = (i >> 1) & 0x1;
            auto ct = cc.EvalBinGate(NAND, cc.Encrypt(sk, b0), cc.Encrypt(sk, b1));
            LWEPlaintext result;
            cc.Decrypt(sk, ct, &result);
            EXPECT_EQ(static_cast<LWEPlaintext>(1 - (b0 & b1)), result)
                << "NAND(" << b0 << "," << b1 << ") wrong for secret key " << (round + 1);
        }
    }
}
#endif

// TOY, with keyDist left free
static BinFHEContextParams ToyParams(SecretKeyDist keyDist) {
    return BinFHEContextParams{27, 1024, 64, 512, 0, 25, 512, 23, 9, keyDist, 3.19, {}};
}

TEST(UNITTestFHEWExtended, GinxRejectsGaussianSecretKeyDist) {
    auto params = ToyParams(GAUSSIAN);
    auto cc     = BinFHEContext();
    EXPECT_THROW(cc.GenerateBinFHEContext(params, GINX), OpenFHEException);
    EXPECT_NO_THROW(cc.GenerateBinFHEContext(params, AP));
    EXPECT_NO_THROW(cc.GenerateBinFHEContext(params, LMKCDEY));
}

TEST(UNITTestFHEWExtended, ManualContextPropagatesSecretKeyDist) {
    auto Q  = LastPrime<NativeInteger>(27, 1024);
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(64, 512, 512, Q, 3.19, 25, 512, 23, GAUSSIAN, LMKCDEY, 9);
    EXPECT_EQ(GAUSSIAN, cc.GetParams()->GetLWEParams()->GetKeyDist());
    EXPECT_EQ(GAUSSIAN, cc.GetParams()->GetRingGSWParams()->GetKeyDist());

    auto ccGinx = BinFHEContext();
    EXPECT_THROW(ccGinx.GenerateBinFHEContext(64, 512, 512, Q, 3.19, 25, 512, 23, GAUSSIAN, GINX, 9), OpenFHEException);
}

// Excluded at NATIVE_SIZE=32 for the reason given above: the large-precision constructor
// sets qKS = 1 << 35, which truncates to zero in a 32-bit NativeInteger.
#if NATIVEINT != 32
TEST(UNITTestFHEWExtended, ArbitraryFunctionContextUnaffected) {
    auto cc = BinFHEContext();
    EXPECT_NO_THROW(cc.GenerateBinFHEContext(TOY, false, 11, 0, GINX, false));
    EXPECT_EQ(UNIFORM_TERNARY, cc.GetParams()->GetLWEParams()->GetKeyDist());
    EXPECT_EQ(UNIFORM_TERNARY, cc.GetParams()->GetRingGSWParams()->GetKeyDist());
}
#endif

TEST(UNITTestFHEWExtended, MethodKeyDistCrossProduct) {
    const std::vector<std::pair<BINFHE_METHOD, SecretKeyDist>> supported{{GINX, UNIFORM_TERNARY},
                                                                         {AP, UNIFORM_TERNARY},
                                                                         {LMKCDEY, UNIFORM_TERNARY},
                                                                         {AP, GAUSSIAN},
                                                                         {LMKCDEY, GAUSSIAN}};

    for (const auto& [method, keyDist] : supported) {
        auto cc = BinFHEContext();
        cc.GenerateBinFHEContext(ToyParams(keyDist), method);
        auto sk = cc.KeyGen();
        cc.BTKeyGen(sk);
        for (uint32_t i = 0; i < 4; ++i) {
            uint32_t b0 = i & 0x1, b1 = (i >> 1) & 0x1;
            auto ct = cc.EvalBinGate(NAND, cc.Encrypt(sk, b0), cc.Encrypt(sk, b1));
            LWEPlaintext result;
            cc.Decrypt(sk, ct, &result);
            EXPECT_EQ(static_cast<LWEPlaintext>(1 - (b0 & b1)), result)
                << "NAND(" << b0 << "," << b1 << ") wrong for " << method << " / " << keyDist;
        }
    }
}

TEST(UNITTestFHEWExtended, GinxKeyGenRejectsNonTernarySecret) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(ToyParams(UNIFORM_TERNARY), GINX);
    auto&& lweParams = cc.GetParams()->GetLWEParams();
    auto sk          = cc.GetLWEScheme()->KeyGenGaussian(lweParams->Getn(), lweParams->GetqKS());
    EXPECT_THROW(cc.BTKeyGen(sk), OpenFHEException);
}

// Encrypt/Decrypt accumulate the inner product over the whole dimension; holding a ciphertext
// at the ring modulus Q makes dim*Q exceed a 32-bit word, which corrupts the phase while still
// decrypting correctly. Only NATIVE_SIZE=32 is close enough to the bound to trip today.
TEST(UNITTestFHEWExtended, LargeModulusCiphertextPhaseIsClean) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128, GINX);
    auto&& lweParams = cc.GetParams()->GetLWEParams();
    auto Q           = lweParams->GetQ();
    auto skN         = cc.KeyGenN();

    NativeInteger mu = Q.ComputeMu();
    for (uint32_t m = 0; m < 2; ++m) {
        auto ct       = cc.Encrypt(skN, m, LARGE_DIM, 4, Q);
        const auto& a = ct->GetA();
        const auto& s = skN->GetElement();
        NativeInteger inner(0);
        for (uint32_t i = 0; i < a.GetLength(); ++i)
            inner.ModAddFastEq(a[i].ModMulFast(s[i], Q, mu), Q);
        auto phase = ct->GetB().ModSub(inner, Q);
        phase.ModSubFastEq(NativeInteger(m) * (Q / NativeInteger(4)), Q);

        auto qi  = static_cast<int64_t>(Q.ConvertToInt());
        auto err = static_cast<int64_t>(phase.ConvertToInt());
        if (err > qi / 2)
            err -= qi;
        EXPECT_LT(err < 0 ? -err : err, 1000) << "phase error " << err << " for m=" << m;
    }
}

// binfhe generates a Gaussian secret or a uniform ternary one and nothing else, so any other
// distribution would be silently substituted rather than honoured.
TEST(UNITTestFHEWExtended, RejectsUnsupportedKeyDist) {
    for (auto dist : {SPARSE_TERNARY, SPARSE_ENCAPSULATED}) {
        for (auto method : {GINX, AP, LMKCDEY}) {
            auto cc = BinFHEContext();
            EXPECT_THROW(cc.GenerateBinFHEContext(ToyParams(dist), method), OpenFHEException)
                << "keyDist " << dist << ", method " << method;
        }
    }
}

// LMKCDEY sizes its automorphism-key vector by n and indexes it by numAutoKeys, so numAutoKeys
// == n writes one past the end -- a segfault before this was rejected.
TEST(UNITTestFHEWExtended, RejectsNumAutoKeysAtOrAboveLweDimension) {
    auto params = ToyParams(UNIFORM_TERNARY);
    ASSERT_EQ(64u, params.latticeParam);

    params.numAutoKeys = params.latticeParam - 1;
    {
        auto cc = BinFHEContext();
        EXPECT_NO_THROW(cc.GenerateBinFHEContext(params, LMKCDEY));
    }
    params.numAutoKeys = params.latticeParam;
    {
        auto cc = BinFHEContext();
        EXPECT_THROW(cc.GenerateBinFHEContext(params, LMKCDEY), OpenFHEException);
    }
    // the bound is LMKCDEY-only: GINX allocates no automorphism keys
    {
        auto cc = BinFHEContext();
        EXPECT_NO_THROW(cc.GenerateBinFHEContext(params, GINX));
    }
}
