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

#include "cryptocontext.h"
#include "encoding/encodings.h"
#include "gen-cryptocontext.h"
#include "gtest/gtest.h"
#include "scheme/bfvrns/gen-cryptocontext-bfvrns.h"
#include "utils/debug.h"

#include <iostream>
#include <vector>

using namespace lbcrypto;

class UTBFVRNS_DECRYPT : public ::testing::TestWithParam<std::tuple<usint, usint>> {
protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

public:
};

/**
 * This function checks whether vectors of numbers a and b are equal.
 *
 * @param vectorSize The length of the two vectors.
 * @param failmsg Debug message to display upon failure.
 */
static void checkEquality(const std::vector<int64_t>& a, const std::vector<int64_t>& b, int vectorSize,
                          const std::string& failmsg) {
    std::vector<usint> allTrue(vectorSize);
    std::vector<usint> tmp(vectorSize);
    for (int i = 0; i < vectorSize; i++) {
        allTrue[i] = 1;
        tmp[i]     = (a[i] == b[i]);
    }
    EXPECT_TRUE(tmp == allTrue) << failmsg;
}

// static std::vector<usint> ptm_args{2, 65537, 5308417};
// static std::vector<usint> dcrtbit_args{30, 40, 50, 60};

TEST_P(UTBFVRNS_DECRYPT, BFVrns_Decrypt) {
    usint ptm      = std::get<0>(GetParam());
    usint dcrtBits = std::get<1>(GetParam());

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(ptm);
    parameters.SetScalingModSize(dcrtBits);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> kp = cc->KeyGen();

    usint vecsize = 8;
    std::vector<int64_t> vectorOfInts(8);
    for (usint i = 0; i < vecsize; ++i) {
        if (ptm == 2) {
            vectorOfInts[i] = rand() % ptm;  // NOLINT
        }
        else {
            vectorOfInts[i] = (rand() % ptm) / 2;  // NOLINT
        }
    }

    Plaintext plaintext;
    if (!(ptm & (ptm - 1)))
        plaintext = cc->MakeCoefPackedPlaintext(vectorOfInts);
    else
        plaintext = cc->MakePackedPlaintext(vectorOfInts);
    Plaintext result;
    Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(kp.publicKey, plaintext);
    cc->Decrypt(kp.secretKey, ciphertext, &result);

    if (!(ptm & (ptm - 1))) {
        auto tmp_a = plaintext->GetCoefPackedValue();
        auto tmp_b = result->GetCoefPackedValue();
        checkEquality(tmp_a, tmp_b, vecsize, "BFVrns Decrypt fails");
    }
    else {
        auto tmp_a = plaintext->GetPackedValue();
        auto tmp_b = result->GetPackedValue();
        checkEquality(tmp_a, tmp_b, vecsize, "BFVrns Decrypt fails");
    }
}

/*
 * Our tuples are (t, qMSB)
 * sizeQMSB is small (1-2 bits)
 * We test several instanses:
 * - t is a power of two
 *   - (qMSB + sizeQMSB) <  52
 *     - (qMSB + tMSB + sizeQMSB) <  63   (A)
 *     - (qMSB + tMSB + sizeQMSB) >= 63   (B)
 *   - (qMSB + sizeQMSB) >= 52
 *     - (qMSBHf + tMSB + sizeQMSB) <  62 (C)
 *     - (qMSBHf + tMSB + sizeQMSB) >= 62 (D)
 * - t it not a power of two
 *   - (qMSB + sizeQMSB) <  52
 *     - (qMSB + tMSB + sizeQMSB) <  52   (E)
 *     - (qMSB + tMSB + sizeQMSB) >= 52   (F)
 *   - (qMSB + sizeQMSB) >= 52
 *     - (qMSBHf + tMSB + sizeQMSB) <  52 (G)
 *     - (qMSBHf + tMSB + sizeQMSB) >= 52 (H)
 *
 * log2(65537) = 16.00002
 * log2(5308417) = 22.34
 * log2(3221225473) = 31.58
 */
// clang-format off
INSTANTIATE_TEST_SUITE_P(
    BFVrns_Decrypt, UTBFVRNS_DECRYPT,
    ::testing::Values(std::make_tuple(1 << 1, 30),        // A
                      std::make_tuple(1 << 15, 30),       // A
                      std::make_tuple(1 << 31, 30),       // A
                      std::make_tuple(1 << 1, 35),        // A
                      std::make_tuple(1 << 15, 35),       // A
                      std::make_tuple(1 << 31, 35),       // B
                      std::make_tuple(1 << 1, 40),        // A
                      std::make_tuple(1 << 15, 40),       // A
                      std::make_tuple(1 << 31, 40),       // B
                      std::make_tuple(1 << 1, 45),        // A
                      std::make_tuple(1 << 15, 45),       // A
                      std::make_tuple(1 << 31, 45),       // B
                      std::make_tuple(1 << 1, 50),        // A
                      std::make_tuple(1 << 15, 50),       // B
                      std::make_tuple(1 << 31, 50),       // B
                      std::make_tuple(1 << 1, 55),        // C
                      std::make_tuple(1 << 15, 55),       // C
                      std::make_tuple(1 << 31, 55),       // D
                      std::make_tuple(1 << 1, 60),        // C
                      std::make_tuple(1 << 15, 60),       // C
                      std::make_tuple(1 << 31, 60),       // D
                      std::make_tuple(65537, 30),         // E
                      std::make_tuple(5308417, 30),       // F
                      std::make_tuple(65537, 35),         // E
                      std::make_tuple(5308417, 35),       // F
                      std::make_tuple(3221225473, 35),    // F
                      std::make_tuple(65537, 40),         // F
                      std::make_tuple(5308417, 40),       // F
                      std::make_tuple(3221225473, 40),    // F
                      std::make_tuple(65537, 45),         // F
                      std::make_tuple(5308417, 45),       // F
                      std::make_tuple(3221225473, 45),    // F
                      std::make_tuple(65537, 50),         // F
                      std::make_tuple(5308417, 50),       // F
                      std::make_tuple(3221225473, 50),    // F
                      std::make_tuple(65537, 55),         // G
                      std::make_tuple(5308417, 55),       // G
                      std::make_tuple(3221225473, 55),    // H
                      std::make_tuple(65537, 60),         // G
                      std::make_tuple(5308417, 60),       // H
                      std::make_tuple(3221225473, 60)));  // H
// clang-format on
