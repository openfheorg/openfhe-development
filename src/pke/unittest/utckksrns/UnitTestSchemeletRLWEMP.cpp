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
  SchemeletRLWEMP::EncryptCoeff converts each signed plaintext coefficient into its residue modulo
  the ciphertext modulus. That conversion used to negate the operand as a signed value, which is
  undefined for the signed minimum, and skipped the reduction. The existing functional
  bootstrapping tests only feed non-negative coefficients, so the negative branch went untested.
*/

#include "openfhe.h"
#include "gtest/gtest.h"
#include "schemelet/rlwe-mp.h"

#include <cstdint>
#include <limits>
#include <vector>

using namespace lbcrypto;

namespace {
// Plaintext modulus; DecryptCoeff centres its output, so coefficients must stay inside
// (-PLAINTEXT_MODULUS / 2, PLAINTEXT_MODULUS / 2) to round-trip.
constexpr int64_t PLAINTEXT_MODULUS = 256;

class UTRLWEMP : public ::testing::Test {
protected:
    void TearDown() override {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }
};

// Negative coefficients must survive the round-trip unchanged. In-range values were already
// handled correctly, so this guards the branch rather than reproducing the defect; the reduction
// itself is covered below.
TEST_F(UTRLWEMP, NegativeCoefficientsRoundTrip) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1024);
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(59);
    parameters.SetFirstModSize(60);
    parameters.SetBatchSize(8);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto keys              = cc->KeyGen();
    auto elementParams     = SchemeletRLWEMP::GetElementParams(keys.secretKey, 0);
    const BigInteger Q     = BigInteger(1) << 33;
    const BigInteger p     = BigInteger(static_cast<uint64_t>(PLAINTEXT_MODULUS));
    const int64_t halfDown = PLAINTEXT_MODULUS / 2 - 1;

    const std::vector<int64_t> input{-1, -halfDown, -100, 0, 1, 100, halfDown, -42};
    auto ciphertext = SchemeletRLWEMP::EncryptCoeff(input, Q, p, keys.secretKey, elementParams);
    auto output     = SchemeletRLWEMP::DecryptCoeff(ciphertext, Q, p, keys.secretKey, elementParams, input.size());

    ASSERT_EQ(output.size(), input.size());
    for (size_t i = 0; i < input.size(); ++i)
        EXPECT_EQ(output[i], input[i]) << "coefficient " << i;
}

// A coefficient outside [0, Q) must be reduced modulo Q before it is encoded. Forming the negative
// residue as Q - |v| without reducing first underflows once |v| > Q, and the signed minimum was
// additionally negated as a signed value, which is undefined.
TEST_F(UTRLWEMP, OutOfRangeCoefficientsAreReduced) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1024);
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(59);
    parameters.SetFirstModSize(60);
    parameters.SetBatchSize(8);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto keys          = cc->KeyGen();
    auto elementParams = SchemeletRLWEMP::GetElementParams(keys.secretKey, 0);
    const BigInteger p = BigInteger(static_cast<uint64_t>(PLAINTEXT_MODULUS));

    // Q divides 2^63, so the signed minimum reduces to zero; the other coefficients sit one step
    // past a multiple of Q and must come back as that step.
    const int64_t q    = int64_t(1) << 33;
    const BigInteger Q = BigInteger(1) << 33;

    const std::vector<int64_t> input{
        std::numeric_limits<int64_t>::min(), -(q + 5), -(3 * q + 7), q + 5, 3 * q + 7, -q, q, 0};
    const std::vector<int64_t> expected{0, -5, -7, 5, 7, 0, 0, 0};

    std::vector<int64_t> output;
    ASSERT_NO_THROW(output = SchemeletRLWEMP::DecryptCoeff(
                        SchemeletRLWEMP::EncryptCoeff(input, Q, p, keys.secretKey, elementParams), Q, p, keys.secretKey,
                        elementParams, input.size()));
    ASSERT_EQ(output.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i)
        EXPECT_EQ(output[i], expected[i]) << "coefficient " << i << " (input " << input[i] << ")";
}
}  // namespace
