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
  BFV with BEHZ: Decrypt computes modulo t * 2^26 in 64-bit integers, so t must be below 2^37
 */

#include <cstdint>
#include <random>
#include <vector>

#include "cryptocontext.h"
#include "gen-cryptocontext.h"
#include "gtest/gtest.h"
#include "scheme/bfvrns/gen-cryptocontext-bfvrns.h"

using namespace lbcrypto;

class UTBFVRNS_BEHZ_PTM : public ::testing::Test {
  protected:
    void SetUp() {
        OpenFHEParallelControls.UnitTestStart();
    }

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        OpenFHEParallelControls.UnitTestStop();
    }
};

static CCParams<CryptoContextBFVRNS> BEHZParameters(uint64_t t) {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(t);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetMultiplicationTechnique(BEHZ);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1024);
    return parameters;
}

TEST_F(UTBFVRNS_BEHZ_PTM, LargestSupported) {
    if (NativeInteger::MaxBits() != 64)
        GTEST_SKIP() << "for 64-bit native integers";
    const uint64_t t = 137438822401ULL;  // 2^37 - 2^17 + 1 (prime)
    CryptoContext<DCRTPoly> cc = GenCryptoContext(BEHZParameters(t));
    cc->Enable(PKE);
    KeyPair<DCRTPoly> kp = cc->KeyGen();

    const uint32_t n = cc->GetRingDimension();
    std::mt19937_64 rng(1);
    std::vector<int64_t> values(n);
    for (auto& v : values)
        v = static_cast<int64_t>(rng() % t) - static_cast<int64_t>(t / 2);
    Plaintext result;
    cc->Decrypt(kp.secretKey, cc->Encrypt(kp.publicKey, cc->MakePackedPlaintext(values)), &result);
    result->SetLength(n);
    EXPECT_EQ(result->GetPackedValue(), values);
}

TEST_F(UTBFVRNS_BEHZ_PTM, TooLargeRejected) {
    if (NativeInteger::MaxBits() != 64)
        GTEST_SKIP() << "for 64-bit native integers";
    // t * 2^26 >= 2^63: previously accepted, and every decryption was wrong
    for (uint64_t t : {137438953472ULL, 206158430209ULL, 274876334081ULL})
        EXPECT_THROW(GenCryptoContext(BEHZParameters(t)), OpenFHEException) << "t = " << t;
}
