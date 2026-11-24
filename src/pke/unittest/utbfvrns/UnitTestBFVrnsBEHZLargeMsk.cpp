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
  BFV BEHZ multiplication when the auxiliary modulus m_sk has been enlarged beyond the ciphertext
  moduli (large plaintext modulus t relative to the RNS prime size). FastBaseConvSK has to move the
  negative Shenoy-Kumaresan correction alpha - m_sk into [0, q_j); this must also be exact when
  m_sk - alpha > q_j.
*/

#include <algorithm>
#include <cstdint>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "openfhe.h"

using namespace lbcrypto;

class UTBFVRNS_BEHZ_LARGE_MSK : public ::testing::TestWithParam<uint64_t> {
  protected:
    void SetUp() {
        OpenFHEParallelControls.UnitTestStart();
    }

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        OpenFHEParallelControls.UnitTestStop();
    }
};

static int64_t CenteredMod(__int128 x, int64_t t) {
    int64_t r = static_cast<int64_t>(x % t);
    if (r < 0)
        r += t;
    return (r > t / 2) ? r - t : r;
}

static void CheckProduct(const CryptoContext<DCRTPoly>& cc, const PrivateKey<DCRTPoly>& sk,
                         const Ciphertext<DCRTPoly>& ct, const std::vector<int64_t>& a, const std::vector<int64_t>& b,
                         int64_t t, const std::string& what) {
    Plaintext pt;
    cc->Decrypt(sk, ct, &pt);
    pt->SetLength(a.size());
    const auto& got = pt->GetPackedValue();
    size_t wrong = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        if (CenteredMod(got[i], t) != CenteredMod(static_cast<__int128>(a[i]) * b[i], t))
            ++wrong;
    }
    EXPECT_EQ(wrong, 0u) << what << ": " << wrong << " of " << a.size() << " slots wrong";
}

TEST_P(UTBFVRNS_BEHZ_LARGE_MSK, EvalMult) {
    const uint64_t t = GetParam();

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(t);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetMultiplicationTechnique(BEHZ);
    parameters.SetScalingModSize(40);
    parameters.SetRingDim(2048);
    parameters.SetSecurityLevel(HEStd_NotSet);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    // the test is only meaningful if m_sk is much larger than the ciphertext moduli
    auto cp = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cc->GetCryptoParameters());
    const auto& moduliBsk = cp->GetModuliBsk();
    uint32_t maxQBits = 0;
    for (const auto& p : cc->GetElementParams()->GetParams())
        maxQBits = std::max(maxQBits, p->GetModulus().GetMSB());
    ASSERT_GE(moduliBsk.back().GetMSB(), maxQBits + 8);

    auto kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);

    const size_t n = cc->GetRingDimension();
    const int64_t ti = static_cast<int64_t>(t);
    std::mt19937_64 rng(42);
    std::vector<int64_t> zero(n, 0), a(n), b(n);
    for (size_t i = 0; i < n; ++i) {
        a[i] = static_cast<int64_t>(rng() % t) - ti / 2;
        b[i] = static_cast<int64_t>(rng() % t) - ti / 2;
    }

    auto c0 = cc->Encrypt(kp.publicKey, cc->MakePackedPlaintext(zero));
    auto ca = cc->Encrypt(kp.publicKey, cc->MakePackedPlaintext(a));
    auto cb = cc->Encrypt(kp.publicKey, cc->MakePackedPlaintext(b));

    CheckProduct(cc, kp.secretKey, cc->EvalMultNoRelin(c0, c0), zero, zero, ti, "EvalMultNoRelin(Enc(0), Enc(0))");
    CheckProduct(cc, kp.secretKey, cc->EvalMultNoRelin(ca, cb), a, b, ti, "EvalMultNoRelin(Enc(a), Enc(b))");
    CheckProduct(cc, kp.secretKey, cc->EvalMult(ca, cb), a, b, ti, "EvalMult(Enc(a), Enc(b))");
    CheckProduct(cc, kp.secretKey, cc->EvalSquare(ca), a, a, ti, "EvalSquare(Enc(a))");
}

// primes = 1 mod 2^17 of about 2^35 and 2^36: m_sk is 9 and 10 bits longer than the 40-bit moduli
INSTANTIATE_TEST_SUITE_P(BEHZLargeMsk, UTBFVRNS_BEHZ_LARGE_MSK, ::testing::Values(34362228737ULL, 68724326401ULL));
