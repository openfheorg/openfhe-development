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
  BFV decryption of ciphertexts with fewer towers than a fresh ciphertext (after Compress),
  which scales the phase down to one tower and rounds with NativePoly::MultiplyAndRound(t, q0)
 */

#include <cstdint>
#include <random>
#include <vector>

#include "cryptocontext.h"
#include "gen-cryptocontext.h"
#include "gtest/gtest.h"
#include "scheme/bfvrns/gen-cryptocontext-bfvrns.h"

using namespace lbcrypto;

class UTBFVRNS_DECRYPT_LOWLEVEL : public ::testing::TestWithParam<uint64_t> {
  protected:
    void SetUp() {
        OpenFHEParallelControls.UnitTestStart();
    }

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        OpenFHEParallelControls.UnitTestStop();
    }
};

TEST_P(UTBFVRNS_DECRYPT_LOWLEVEL, Compress) {
    const uint64_t t = GetParam();

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(t);
    parameters.SetMultiplicativeDepth(3);
    parameters.SetMultiplicationTechnique(HPSPOVERQ);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1024);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    KeyPair<DCRTPoly> kp = cc->KeyGen();

    const uint32_t n = cc->GetRingDimension();
    std::mt19937_64 rng(1);
    std::vector<int64_t> values(n);
    for (auto& v : values)
        v = static_cast<int64_t>(rng() % t) - static_cast<int64_t>(t / 2);
    Plaintext plaintext = cc->MakePackedPlaintext(values);
    auto ciphertext = cc->Encrypt(kp.publicKey, plaintext);

    // three towers -> two; Decrypt then scales the phase down to one tower
    Plaintext result;
    cc->Decrypt(kp.secretKey, cc->Compress(ciphertext, 2), &result);
    result->SetLength(n);
    EXPECT_EQ(result->GetPackedValue(), values) << "t = " << t << ": decryption after Compress";
}

// plaintext moduli = 1 mod 2^17 (packed encoding); 4503599627763713 > 2^52, 9007199255658497 > 2^53
INSTANTIATE_TEST_SUITE_P(BFVrns_DecryptLowLevel, UTBFVRNS_DECRYPT_LOWLEVEL,
                         ::testing::Values(65537, 4503599627763713ULL, 9007199255658497ULL, 36028797019488257ULL));
