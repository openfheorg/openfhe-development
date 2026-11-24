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
  BFV with BEHZ: the scheme-level Decrypt returns a NativePoly modulo t whose coefficients must
  be in [0, t), also when the phase is just below a multiple of Q/t
 */

#include <cstdint>
#include <memory>
#include <vector>

#include "cryptocontext.h"
#include "gen-cryptocontext.h"
#include "gtest/gtest.h"
#include "scheme/bfvrns/gen-cryptocontext-bfvrns.h"

using namespace lbcrypto;

class UTBFVRNS_BEHZ_DECRYPT_RANGE : public ::testing::Test {
  protected:
    void SetUp() {
        OpenFHEParallelControls.UnitTestStart();
    }

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        OpenFHEParallelControls.UnitTestStop();
    }
};

TEST_F(UTBFVRNS_BEHZ_DECRYPT_RANGE, MessageZeroNegativeNoise) {
    const uint64_t t = 65537;
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(t);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetMultiplicationTechnique(BEHZ);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1024);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    KeyPair<DCRTPoly> kp = cc->KeyGen();

    const auto elementParams = cc->GetElementParams();
    const uint32_t n = cc->GetRingDimension();
    const BigInteger Q = elementParams->GetModulus();
    const BigInteger T(t);
    // largest noise for which textbook decryption is correct for every message
    const BigInteger B = (((Q - BigInteger(1)) >> 1) - Q.Mod(T) * BigInteger(t - 1)).DividedBy(T);

    // a one-element ciphertext (c0): its phase is c0 for any secret key. Coefficient i of c0 is
    // -e_i mod Q, an encryption of 0 with a negative noise e_i between B/1000 and B/2.
    DCRTPoly zero(elementParams, Format::COEFFICIENT, true);
    Poly phase = zero.CRTInterpolate();
    for (uint32_t i = 0; i < n; ++i)
        phase[i] = Q - (B * BigInteger(1 + (i % 500))).DividedBy(BigInteger(1000));
    DCRTPoly c0(phase, elementParams);
    c0.SetFormat(Format::EVALUATION);
    auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(kp.publicKey);
    ct->SetElements(std::vector<DCRTPoly>{c0});

    NativePoly result;
    cc->GetScheme()->Decrypt(ct, kp.secretKey, &result);
    uint32_t nonZero = 0;
    for (uint32_t i = 0; i < n; ++i)
        nonZero += (result[i] != 0);
    EXPECT_EQ(nonZero, 0u) << "coefficients other than 0 (e.g. t itself) in the decryption of 0";
}
