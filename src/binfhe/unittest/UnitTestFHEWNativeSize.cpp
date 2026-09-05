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

#include "binfhecontext-ser.h"
#include "gtest/gtest.h"

#include <string>
#include <vector>

using namespace lbcrypto;

// BinFHE at the build's true native word size.
//
// The rest of the suite exercises whatever the defaults do, and since keys whose moduli fit
// 32 bits are now held and evaluated in a narrowed form by default, that is the 32-bit path
// for every parameter set those tests use. Nothing there runs at the native word size any
// more. These tests ask for it explicitly, and they check that the narrowed representation
// agrees with it rather than merely working on its own.
//
// A NATIVE_SIZE=32 build has no narrowed form to select, so the native size is what the rest
// of the suite already covers and this file is empty there.
//
// For anyone extending these: BTKeyGen defaults to internal32 = true, so a test that wants a
// native-width key must say so.

#if NATIVEINT != 32

namespace {

struct Gate {
    BINGATE gate;
    const char* name;
    int truth[4];  // indexed by (2 * a + b)
};

const std::vector<Gate> gates{{AND, "AND", {0, 0, 0, 1}}, {OR, "OR", {0, 1, 1, 1}},   {NAND, "NAND", {1, 1, 1, 0}},
                              {NOR, "NOR", {1, 0, 0, 0}}, {XOR, "XOR", {0, 1, 1, 0}}, {XNOR, "XNOR", {1, 0, 0, 1}}};

// every gate against every input pair, decrypted and compared with its truth table
void ExpectTruthTables(BinFHEContext& cc, ConstLWEPrivateKey& sk, const std::string& msg) {
    for (const auto& g : gates) {
        for (int a = 0; a < 2; ++a) {
            for (int b = 0; b < 2; ++b) {
                auto ct = cc.EvalBinGate(g.gate, cc.Encrypt(sk, a), cc.Encrypt(sk, b));
                LWEPlaintext result;
                cc.Decrypt(sk, ct, &result);
                EXPECT_EQ(g.truth[2 * a + b], static_cast<int>(result))
                    << msg << " " << g.name << "(" << a << "," << b << ")";
            }
        }
    }
}

}  // namespace

// Narrowing an existing key must not change a single ciphertext bit: same key, same inputs,
// evaluated before and after the conversion.
void UnitTestInternal32BitIdentical(BINFHE_PARAMSET set, BINFHE_METHOD method, const std::string& msg) {
    BinFHEContext cc;
    cc.GenerateBinFHEContext(set, method);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk, SYM_ENCRYPT, /*internal32=*/false);
    ASSERT_FALSE(cc.HasInternal32RefreshKey()) << msg << " expected a native-width refresh key to start from";

    // fixed inputs, so the two evaluations differ only in the key representation
    std::vector<LWECiphertext> in0, in1, before;
    for (const auto& g : gates) {
        in0.push_back(cc.Encrypt(sk, 1));
        in1.push_back(cc.Encrypt(sk, 0));
        before.push_back(cc.EvalBinGate(g.gate, in0.back(), in1.back()));
    }

    // narrow through the public route an application would use
    cc.BTKeyLoad({cc.GetRefreshKey(), cc.GetSwitchKey()}, /*internal32=*/true);
    ASSERT_TRUE(cc.HasInternal32RefreshKey()) << msg << " refresh key did not convert";
    ASSERT_TRUE(cc.HasInternal32SwitchKey()) << msg << " switching key did not convert";

    for (size_t i = 0; i < gates.size(); ++i) {
        auto after = cc.EvalBinGate(gates[i].gate, in0[i], in1[i]);
        EXPECT_EQ(*before[i], *after) << msg << " " << gates[i].name << " differs after narrowing";
    }
}

// Keys generated directly in the 32-bit form are not bit-comparable with narrowed ones, because
// they are sampled natively, so the truth tables are the oracle.
void UnitTestInternal32KeyGen(BINFHE_PARAMSET set, BINFHE_METHOD method, const std::string& msg) {
    BinFHEContext cc;
    cc.GenerateBinFHEContext(set, method);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk, SYM_ENCRYPT, /*internal32=*/true);
    EXPECT_TRUE(cc.HasInternal32RefreshKey()) << msg << " refresh key was not generated in 32-bit form";
    EXPECT_TRUE(cc.HasInternal32SwitchKey()) << msg << " switching key was not generated in 32-bit form";
    ExpectTruthTables(cc, sk, msg);
}

// The native word size, whatever the build selected. Asking for it explicitly matters twice
// over: no other test reaches it any more, and a parameter set that merely fails to qualify
// would give a mixed context rather than a native one.
void UnitTestNativeSizePath(BINFHE_PARAMSET set, BINFHE_METHOD method, const std::string& msg) {
    BinFHEContext cc;
    cc.GenerateBinFHEContext(set, method);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk, SYM_ENCRYPT, /*internal32=*/false);
    ASSERT_FALSE(cc.HasInternal32RefreshKey()) << msg << " refresh key should have stayed native width";
    ASSERT_FALSE(cc.HasInternal32SwitchKey()) << msg << " switching key should have stayed native width";
    ExpectTruthTables(cc, sk, msg);
}

TEST(UnitTestFHEWNativeSize, NativeSizePathGINX) {
    UnitTestNativeSizePath(TOY, GINX, "UnitTestFHEWNativeSize.NativeSizePathGINX:");
}
TEST(UnitTestFHEWNativeSize, NativeSizePathAP) {
    UnitTestNativeSizePath(TOY, AP, "UnitTestFHEWNativeSize.NativeSizePathAP:");
}
TEST(UnitTestFHEWNativeSize, NativeSizePathLMKCDEY) {
    UnitTestNativeSizePath(TOY, LMKCDEY, "UnitTestFHEWNativeSize.NativeSizePathLMKCDEY:");
}

TEST(UnitTestFHEWNativeSize, BitIdenticalGINX) {
    UnitTestInternal32BitIdentical(TOY, GINX, "UnitTestFHEWNativeSize.BitIdenticalGINX:");
}
TEST(UnitTestFHEWNativeSize, BitIdenticalAP) {
    UnitTestInternal32BitIdentical(TOY, AP, "UnitTestFHEWNativeSize.BitIdenticalAP:");
}
TEST(UnitTestFHEWNativeSize, BitIdenticalLMKCDEY) {
    UnitTestInternal32BitIdentical(TOY, LMKCDEY, "UnitTestFHEWNativeSize.BitIdenticalLMKCDEY:");
}

TEST(UnitTestFHEWNativeSize, Internal32KeyGenGINX) {
    UnitTestInternal32KeyGen(TOY, GINX, "UnitTestFHEWNativeSize.Internal32KeyGenGINX:");
}
TEST(UnitTestFHEWNativeSize, Internal32KeyGenLMKCDEY) {
    UnitTestInternal32KeyGen(TOY, LMKCDEY, "UnitTestFHEWNativeSize.Internal32KeyGenLMKCDEY:");
}

// Qualification is per key. STD192's modulus is too wide for a 32-bit refresh key, but its
// key-switching modulus still fits, so the context ends up mixed and must still evaluate.
TEST(UnitTestFHEWNativeSize, PartialQualification) {
    const std::string msg("UnitTestFHEWNativeSize.PartialQualification:");
    BinFHEContext cc;
    cc.GenerateBinFHEContext(STD192, GINX);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk, SYM_ENCRYPT, /*internal32=*/true);
    EXPECT_FALSE(cc.HasInternal32RefreshKey()) << msg << " a 37-bit modulus must not yield a 32-bit refresh key";
    EXPECT_TRUE(cc.HasInternal32SwitchKey()) << msg << " the key-switching modulus fits and should convert";

    LWEPlaintext result;
    cc.Decrypt(sk, cc.EvalBinGate(AND, cc.Encrypt(sk, 1), cc.Encrypt(sk, 1)), &result);
    EXPECT_EQ(1, static_cast<int>(result)) << msg << " AND(1,1) on the mixed path";
}

// Loading a 64-bit key with internal32 requested must narrow it and keep evaluating correctly.
TEST(UnitTestFHEWNativeSize, KeyLoadNarrows) {
    const std::string msg("UnitTestFHEWNativeSize.KeyLoadNarrows:");
    BinFHEContext src;
    src.GenerateBinFHEContext(TOY, GINX);
    auto sk = src.KeyGen();
    src.BTKeyGen(sk, SYM_ENCRYPT, /*internal32=*/false);

    BinFHEContext dst;
    dst.GenerateBinFHEContext(TOY, GINX);
    dst.BTKeyLoad({src.GetRefreshKey(), src.GetSwitchKey()}, /*internal32=*/true);
    EXPECT_TRUE(dst.HasInternal32RefreshKey()) << msg << " loaded refresh key did not narrow";
    EXPECT_TRUE(dst.HasInternal32SwitchKey()) << msg << " loaded switching key did not narrow";
    ExpectTruthTables(dst, sk, msg);
}

// The serialization getters widen a 32-bit key into the handle they return, without giving up
// the context's own 32-bit form, and what they return must survive a round trip.
TEST(UnitTestFHEWNativeSize, SerializationGettersWiden) {
    const std::string msg("UnitTestFHEWNativeSize.SerializationGettersWiden:");
    BinFHEContext cc;
    cc.GenerateBinFHEContext(TOY, GINX);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk, SYM_ENCRYPT, /*internal32=*/true);
    ASSERT_TRUE(cc.HasInternal32RefreshKey()) << msg << " expected a 32-bit refresh key to start from";

    std::stringstream sb, ss;
    Serial::Serialize(cc.GetRefreshKey(), sb, SerType::BINARY);
    Serial::Serialize(cc.GetSwitchKey(), ss, SerType::BINARY);

    // widening is for the caller's handle only; the context keeps its 32-bit keys
    EXPECT_TRUE(cc.HasInternal32RefreshKey()) << msg << " the context lost its 32-bit refresh key";
    EXPECT_TRUE(cc.HasInternal32SwitchKey()) << msg << " the context lost its 32-bit switching key";

    RingGSWACCKey refreshKey;
    LWESwitchingKey switchKey;
    Serial::Deserialize(refreshKey, sb, SerType::BINARY);
    Serial::Deserialize(switchKey, ss, SerType::BINARY);

    BinFHEContext loaded;
    loaded.GenerateBinFHEContext(TOY, GINX);
    loaded.BTKeyLoad({refreshKey, switchKey}, /*internal32=*/false);
    EXPECT_FALSE(loaded.HasInternal32RefreshKey()) << msg << " the wire form should load as a 64-bit key";
    ExpectTruthTables(loaded, sk, msg);
}

#endif  // NATIVEINT != 32
