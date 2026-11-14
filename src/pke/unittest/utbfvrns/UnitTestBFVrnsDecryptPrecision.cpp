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
  BFV decryption (DCRTPoly::ScaleAndRound for the HPS family) on ciphertexts with a chosen
  phase close to the decryption threshold
 */

#include <cstdint>
#include <memory>
#include <random>
#include <string>
#include <tuple>
#include <vector>

#include "cryptocontext.h"
#include "gen-cryptocontext.h"
#include "gtest/gtest.h"
#include "scheme/bfvrns/gen-cryptocontext-bfvrns.h"

using namespace lbcrypto;

// (plaintext modulus, multiplicative depth, scaling mod size (0 = default), ring dimension)
using DecryptPrecisionParams = std::tuple<uint64_t, uint32_t, uint32_t, uint32_t>;

class UTBFVRNS_DECRYPT_PRECISION : public ::testing::TestWithParam<DecryptPrecisionParams> {
  protected:
    void SetUp() {
        OpenFHEParallelControls.UnitTestStart();
    }

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        OpenFHEParallelControls.UnitTestStop();
    }
};

// For every coefficient i, the phase is x_i = Floor(Q/t) * m_i +- e (mod Q), where m_i is uniform
// in [0, t) and e = Floor(ratio * B). B = Floor((Floor((Q-1)/2) - (Q mod t)(t-1)) / t) is the
// largest noise for which round(t/Q * [x]_Q) mod t returns m for every m, so decryption must
// return m_i for every ratio < 1, except within the floating-point error of ScaleAndRound of the
// threshold: at ratio r, t/Q * x is about (1 - r)/2 away from the nearest half-integer, which for
// r = 0.999 (2^{-11}) exceeds the proved error bound 25 * sizeQ * 2^{-23} for up to 160 towers.
TEST_P(UTBFVRNS_DECRYPT_PRECISION, ChosenPhase) {
    const uint64_t t = std::get<0>(GetParam());
    const uint32_t depth = std::get<1>(GetParam());
    const uint32_t modSize = std::get<2>(GetParam());
    const uint32_t ringDim = std::get<3>(GetParam());

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(t);
    parameters.SetMultiplicativeDepth(depth);
    if (modSize)
        parameters.SetScalingModSize(modSize);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(ringDim);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    KeyPair<DCRTPoly> kp = cc->KeyGen();

    const auto elementParams = cc->GetElementParams();
    const uint32_t n = cc->GetRingDimension();

    // a one-element ciphertext (c0): its phase is c0 for any secret key
    DCRTPoly zero(elementParams, Format::COEFFICIENT, true);
    Poly phase = zero.CRTInterpolate();

    const BigInteger Q = elementParams->GetModulus();
    const BigInteger T(t);
    const BigInteger delta = Q.DividedBy(T);
    const BigInteger B = (((Q - BigInteger(1)) >> 1) - Q.Mod(T) * BigInteger(t - 1)).DividedBy(T);

    std::mt19937_64 rng(1);
    for (double ratio : {0.0, 0.5, 0.9, 0.99, 0.999}) {
        const BigInteger e = (B * BigInteger(static_cast<uint64_t>(ratio * (1ULL << 40)))) >> 40;
        std::vector<uint64_t> m(n);
        for (uint32_t i = 0; i < n; ++i) {
            m[i] = rng() % t;
            BigInteger x = delta * BigInteger(m[i]);
            if (rng() & 1)
                x = (x >= e) ? x - e : x + Q - e;
            else
                x = (x + e).Mod(Q);
            phase[i] = x;
        }
        DCRTPoly c0(phase, elementParams);
        c0.SetFormat(Format::EVALUATION);
        auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(kp.publicKey);
        ct->SetElements(std::vector<DCRTPoly>{c0});

        NativePoly result;
        cc->GetScheme()->Decrypt(ct, kp.secretKey, &result);

        uint32_t wrong = 0, notReduced = 0;
        for (uint32_t i = 0; i < n; ++i) {
            const uint64_t r = result[i].ConvertToInt<uint64_t>();
            wrong += (r % t != m[i]);
            notReduced += (r >= t);
        }
        EXPECT_EQ(wrong, 0u) << "t = " << t << ", " << elementParams->GetParams().size() << " towers of at most "
                             << elementParams->GetParams().back()->GetModulus().GetMSB() << " bits, noise ratio "
                             << ratio << ": wrong coefficients";
        EXPECT_EQ(notReduced, 0u) << "t = " << t << ", noise ratio " << ratio << ": coefficients >= t";
    }
}

// clang-format off
INSTANTIATE_TEST_SUITE_P(
    BFVrns_DecryptPrecision, UTBFVRNS_DECRYPT_PRECISION,
    ::testing::Values(
        // the library defaults: three 60-bit towers
        std::make_tuple(65537, 2, 0, 1024),
        std::make_tuple(65536, 2, 0, 1024),
        // many towers of 46 bits (qMSB + sizeQMSB = 51)
        std::make_tuple(65537, 39, 46, 1024),
        std::make_tuple(65536, 39, 46, 1024),
        std::make_tuple(65537, 20, 49, 1024),
        // towers of at most 30 bits
        std::make_tuple(65537, 4, 30, 1024),
        std::make_tuple(65536, 4, 30, 1024),
        // large plaintext moduli
        std::make_tuple(1125899915231233ULL, 3, 0, 1024),   // prime ~2^50
        std::make_tuple(4503599626682369ULL, 3, 0, 1024),   // prime ~2^52
        std::make_tuple(1ULL << 50, 3, 0, 1024),
        std::make_tuple(9007199255658497ULL, 3, 0, 1024)));  // prime ~2^53
// clang-format on
