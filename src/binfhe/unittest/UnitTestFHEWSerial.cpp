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

#include <sstream>
#include <string>
#include <vector>

#include "binfhecontext-ser.h"
#include "gtest/gtest.h"
#include "lwe-keyswitchkey.h"

using namespace lbcrypto;

template <typename ST, typename PS>
void UnitTestFHEWSerial(const ST& sertype, const PS& secLevel, BINFHE_METHOD variant, BINFHE_OUTPUT ctType,
                        const std::string& errMsg) {
    const LWEPlaintext val(1);
    auto cc1 = BinFHEContext();
    cc1.GenerateBinFHEContext(secLevel, variant);

    auto sk1 = cc1.KeyGen();
    cc1.BTKeyGen(sk1);

    // Encryption for a ciphertext that will be serialized
    auto ct1 = cc1.Encrypt(sk1, val, ctType);

    BinFHEContext cc2;
    {
        std::stringstream s;
        Serial::Serialize(cc1, s, sertype);
        Serial::Deserialize(cc2, s, sertype);

        EXPECT_EQ(*cc2.GetParams(), *cc1.GetParams()) << errMsg << " Context mismatch";
    }

    RingGSWBTKey btKey;
    {
        std::stringstream s;
        Serial::Serialize(cc1.GetBTKey(), s, sertype);
        Serial::Deserialize(btKey, s, sertype);
    }

    // Loading deserialized bootstrapping keys
    cc2.BTKeyLoad(btKey);

    // Check the keys after adding them to cc2, at whichever width each context holds them
    EXPECT_EQ(cc1.HasInternal32RefreshKey(), cc2.HasInternal32RefreshKey()) << errMsg << " refresh key width";
    EXPECT_EQ(cc1.HasInternal32SwitchKey(), cc2.HasInternal32SwitchKey()) << errMsg << " switching key width";
#if NATIVEINT != 32
    if (cc1.HasInternal32RefreshKey())
        EXPECT_EQ(*(cc2.GetBTKey().BSkey32), *(cc1.GetBTKey().BSkey32)) << errMsg << " refresh key";
    else
#endif
        EXPECT_EQ(*(cc2.GetRefreshKey()), *(cc1.GetRefreshKey())) << errMsg << " refresh key";
#if NATIVEINT != 32
    if (cc1.HasInternal32SwitchKey())
        EXPECT_EQ(*(cc2.GetBTKey().KSkey32), *(cc1.GetBTKey().KSkey32)) << errMsg << " switching key";
    else
#endif
        EXPECT_EQ(*(cc2.GetSwitchKey()), *(cc1.GetSwitchKey())) << errMsg << " switching key";

    LWEPrivateKey sk2;
    {
        std::stringstream s;
        Serial::Serialize(sk1, s, sertype);
        Serial::Deserialize(sk2, s, sertype);

        EXPECT_EQ(*sk1, *sk2) << errMsg << " Secret key mismatch";
    }

    LWECiphertext ct2;
    {
        std::stringstream s;
        Serial::Serialize(ct1, s, sertype);
        Serial::Deserialize(ct2, s, sertype);

        EXPECT_EQ(*ct1, *ct2) << errMsg << " Ciphertext mismatch";
    }

    auto ctNew = cc2.Encrypt(sk2, val, ctType);
    auto ctResult = cc2.EvalBinGate(AND, ct2, ctNew);
    LWEPlaintext result;
    cc2.Decrypt(sk2, ctResult, &result);

    EXPECT_EQ(val, result) << errMsg << "result = " << result << ", it is expected to be equal 1";
}

// ---------------  TESTING SERIALIZATION METHODS OF FHEW ---------------
// JSON tests were turned off as they take a very long time and require a lot of memory.
// They are left in this file for debugging purposes only.
// TEST(UnitTestFHEWSerialAP, JSON) {
//     std::string msg = "UnitTestFHEWSerialAP.JSON serialization test failed: ";
//     UnitTestFHEWSerial(SerType::JSON, TOY, AP, SMALL_DIM, msg);
// }

TEST(UnitTestFHEWSerialAP, BINARY) {
    std::string msg = "UnitTestFHEWSerialAP.BINARY serialization test failed: ";
    UnitTestFHEWSerial(SerType::BINARY, TOY, AP, SMALL_DIM, msg);
}

// TEST(UnitTestFHEWSerialGINX, JSON) {
//     std::string msg = "UnitTestFHEWSerialGINX.JSON serialization test failed: ";
//     UnitTestFHEWSerial(SerType::JSON, TOY, GINX, SMALL_DIM, msg);
// }

TEST(UnitTestFHEWSerialGINX, BINARY) {
    std::string msg = "UnitTestFHEWSerialGINX.BINARY serialization test failed: ";
    UnitTestFHEWSerial(SerType::BINARY, TOY, GINX, SMALL_DIM, msg);
}

TEST(UnitTestFHEWSerialLMKCDEY, BINARY) {
    std::string msg = "UnitTestFHEWSerialGINX.BINARY serialization test failed: ";
    UnitTestFHEWSerial(SerType::BINARY, TOY, LMKCDEY, SMALL_DIM, msg);
}

// The secret key distribution is the one context field key generation dispatches on, and every
// predefined Gaussian set is too large to serialize in a unit test, so this builds a small one.
TEST(UnitTestFHEWSerialGaussian, BINARY) {
    std::string msg = "UnitTestFHEWSerialGaussian.BINARY serialization test failed: ";
    BinFHEContextParams p{27, 1024, 64, 512, 0, 25, 512, 23, 9, GAUSSIAN, 3.19, {}};
    UnitTestFHEWSerial(SerType::BINARY, p, LMKCDEY, SMALL_DIM, msg);
}

TEST(UnitTestFHEWSerial, SwitchingKeyHasCorrectSerializedName) {
    LWESwitchingKeyImpl key;
    EXPECT_EQ("LWESwitchingKey", key.SerializedObjectName());
}

// A ciphertext has to come back from an archive with the plaintext modulus it was encrypted with, not
// the default of 4, and a multi-input gate has to give the same result on it as on the original.
template <typename ST>
void UnitTestFHEWSerialMultiInput(const ST& sertype, const std::string& errMsg) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(TOY, GINX);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);

    struct Case {
        BINGATE gate;
        std::vector<LWEPlaintext> in;
        LWEPlaintextModulus p;
        LWEPlaintext expected;
    };
    const std::vector<Case> cases = {
            {AND3, {1, 1, 0}, 6, 0},
            {OR3, {1, 1, 0}, 6, 1},
            {AND4, {1, 1, 1, 1}, 8, 1},
            {OR4, {1, 0, 0, 0}, 8, 1},
    };
    for (const auto& c : cases) {
        std::vector<LWECiphertext> in, inSer, inCopy;
        for (auto m : c.in) {
            in.push_back(cc.Encrypt(sk, m, SMALL_DIM, c.p));
            std::stringstream s;
            Serial::Serialize(in.back(), s, sertype);
            LWECiphertext ct;
            Serial::Deserialize(ct, s, sertype);
            EXPECT_EQ(NativeInteger(c.p), ct->GetptModulus()) << errMsg << " plaintext modulus lost";
            EXPECT_EQ(*in.back(), *ct) << errMsg << " ciphertext mismatch";
            inSer.push_back(ct);
            // a copy resets the plaintext modulus to 4, which the gate must not depend on either
            inCopy.push_back(std::make_shared<LWECiphertextImpl>(*in.back()));
        }
        auto out = cc.EvalBinGate(c.gate, in);
        auto outSer = cc.EvalBinGate(c.gate, inSer);
        EXPECT_EQ(*out, *outSer) << errMsg << " gate " << c.gate << " differs on deserialized inputs";
        EXPECT_EQ(*out, *cc.EvalBinGate(c.gate, inCopy)) << errMsg << " gate " << c.gate << " differs on copies";
        EXPECT_EQ(NativeInteger(c.p), out->GetptModulus()) << errMsg << " gate " << c.gate << " output modulus";
        LWEPlaintext result;
        cc.Decrypt(sk, outSer, &result, c.p);
        EXPECT_EQ(c.expected, result) << errMsg << " gate " << c.gate;
    }
}

TEST(UnitTestFHEWSerialMultiInput, BINARY) {
    UnitTestFHEWSerialMultiInput(SerType::BINARY, "UnitTestFHEWSerialMultiInput.BINARY failed:");
}

TEST(UnitTestFHEWSerialMultiInput, JSON) {
    UnitTestFHEWSerialMultiInput(SerType::JSON, "UnitTestFHEWSerialMultiInput.JSON failed:");
}
