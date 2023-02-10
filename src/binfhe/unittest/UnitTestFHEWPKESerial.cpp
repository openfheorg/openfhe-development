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

#include "gtest/gtest.h"

// these header files are needed for serialization
#include "binfhecontext-ser.h"

using namespace lbcrypto;

template <typename ST>
void UnitTestFHEWPKESerial(const ST& sertype, BINFHE_PARAMSET secLevel, BINFHE_METHOD variant,
                           const std::string& errMsg) {
    const LWEPlaintext val(1);
    auto cc1 = BinFHEContext();
    cc1.GenerateBinFHEContext(secLevel, variant);

    auto sk1 = cc1.KeyGen();
    cc1.BTKeyGen(sk1, PUB_ENCRYPT);

    LWEPublicKey pk1 = cc1.GetPublicKey();
    // Encryption for a ciphertext that will be serialized
    auto ct1 = cc1.Encrypt(pk1, val);

    BinFHEContext cc2;
    {
        std::stringstream s;
        Serial::Serialize(cc1, s, sertype);
        Serial::Deserialize(cc2, s, sertype);

        EXPECT_EQ(*cc2.GetParams(), *cc1.GetParams()) << errMsg << " Context mismatch";
    }

    RingGSWACCKey refreshKey;
    {
        std::stringstream s;
        Serial::Serialize(cc1.GetRefreshKey(), s, sertype);
        Serial::Deserialize(refreshKey, s, sertype);

        // EXPECT_EQ( *refreshKey, *cc1.GetRefreshKey()) << errMsg << "Bootstrapping key mismatch: refresh key (1)";
    }

    LWESwitchingKey switchKey;
    {
        std::stringstream s;
        Serial::Serialize(cc1.GetSwitchKey(), s, sertype);
        Serial::Deserialize(switchKey, s, sertype);

        // EXPECT_EQ( *switchKey, *cc1.GetSwitchKey()) << errMsg << "Bootstrapping key mismatch: switching key (1)";
    }

    // Loading deserialized bootstrapping keys
    cc2.BTKeyLoad({refreshKey, switchKey});

    // Check the keys after adding them to cc2
    EXPECT_EQ(*(cc2.GetRefreshKey()), *(cc1.GetRefreshKey())) << errMsg << "Bootstrapping key mismatch: refresh key";
    EXPECT_EQ(*(cc2.GetSwitchKey()), *(cc1.GetSwitchKey())) << errMsg << "Bootstrapping key mismatch: switching key";

    LWEPrivateKey sk2;
    {
        std::stringstream s;
        Serial::Serialize(sk1, s, sertype);
        Serial::Deserialize(sk2, s, sertype);

        EXPECT_EQ(*sk1, *sk2) << errMsg << " Secret key mismatch";
    }
    LWEPublicKey pk2;
    {
        std::stringstream s;
        Serial::Serialize(pk1, s, sertype);
        Serial::Deserialize(pk2, s, sertype);

        EXPECT_EQ(*pk1, *pk2) << errMsg << " Secret key mismatch";
    }

    LWECiphertext ct2;
    {
        std::stringstream s;
        Serial::Serialize(ct1, s, sertype);
        Serial::Deserialize(ct2, s, sertype);

        EXPECT_EQ(*ct1, *ct2) << errMsg << " Ciphertext mismatch";
    }

    auto ctNew    = cc2.Encrypt(pk2, val);
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
//     UnitTestFHEWSerial(SerType::JSON, TOY, AP, FRESH, msg);
// }

TEST(UnitTestFHEWPKESerialAP, BINARY) {
    std::string msg = "UnitTestFHEWSerialAP.BINARY serialization test failed: ";
    UnitTestFHEWPKESerial(SerType::BINARY, TOY, AP, msg);
}

// TEST(UnitTestFHEWSerialGINX, JSON) {
//     std::string msg = "UnitTestFHEWSerialGINX.JSON serialization test failed: ";
//     UnitTestFHEWSerial(SerType::JSON, TOY, GINX, FRESH, msg);
// }

TEST(UnitTestFHEWPKESerialGINX, BINARY) {
    std::string msg = "UnitTestFHEWSerialGINX.BINARY serialization test failed: ";
    UnitTestFHEWPKESerial(SerType::BINARY, TOY, GINX, msg);
}
