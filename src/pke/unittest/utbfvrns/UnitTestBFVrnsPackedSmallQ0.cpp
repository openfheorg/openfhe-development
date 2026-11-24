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
  BFV packed encoding when the plaintext modulus t is larger than half of the first RNS modulus q0
  (t - 1 > floor(q0/2)): every RNS limb of the encoded plaintext must hold the same integer.
*/

#include <cstdint>
#include <random>
#include <string>
#include <tuple>
#include <vector>

#include "gtest/gtest.h"
#include "openfhe.h"

using namespace lbcrypto;

class UTBFVRNS_PACKED_SMALL_Q0 : public ::testing::TestWithParam<std::tuple<uint64_t, uint32_t>> {
  protected:
    void SetUp() {
        OpenFHEParallelControls.UnitTestStart();
    }

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        OpenFHEParallelControls.UnitTestStop();
    }
};

static void CheckDecrypt(const CryptoContext<DCRTPoly>& cc, const PrivateKey<DCRTPoly>& sk,
                         const Ciphertext<DCRTPoly>& ct, const std::vector<int64_t>& expected, int64_t t,
                         const std::string& what) {
    Plaintext pt;
    cc->Decrypt(sk, ct, &pt);
    pt->SetLength(expected.size());
    const auto& got = pt->GetPackedValue();
    size_t wrong = 0;
    for (size_t i = 0; i < expected.size(); ++i) {
        if ((((got[i] - expected[i]) % t) + t) % t != 0)
            ++wrong;
    }
    EXPECT_EQ(wrong, 0u) << what << ": " << wrong << " of " << expected.size() << " slots wrong";
}

TEST_P(UTBFVRNS_PACKED_SMALL_Q0, EncodeEncryptDecrypt) {
    const uint64_t t = std::get<0>(GetParam());
    const uint32_t bits = std::get<1>(GetParam());

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(t);
    parameters.SetScalingModSize(bits);
    parameters.SetMultiplicativeDepth(2);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    const uint64_t q0 = cc->GetElementParams()->GetParams()[0]->GetModulus().ConvertToInt<uint64_t>();
    ASSERT_GT(t - 1, q0 / 2);  // the case under test

    auto kp = cc->KeyGen();
    const size_t n = cc->GetRingDimension();
    const int64_t ti = static_cast<int64_t>(t);
    std::mt19937_64 rng(1);
    std::vector<int64_t> a(n), b(n), sum(n), prod(n);
    for (size_t i = 0; i < n; ++i) {
        a[i] = static_cast<int64_t>(rng() % t) - ti / 2;
        b[i] = static_cast<int64_t>(rng() % t) - ti / 2;
        sum[i] = (a[i] + b[i]) % ti;
        prod[i] = static_cast<int64_t>((static_cast<__int128>(a[i]) * b[i]) % ti);
    }
    auto pa = cc->MakePackedPlaintext(a);
    auto pb = cc->MakePackedPlaintext(b);
    auto ca = cc->Encrypt(kp.publicKey, pa);
    auto cb = cc->Encrypt(kp.publicKey, pb);

    CheckDecrypt(cc, kp.secretKey, ca, a, ti, "Decrypt(Encrypt(a))");
    CheckDecrypt(cc, kp.secretKey, cc->Encrypt(kp.secretKey, pa), a, ti, "Decrypt(Encrypt(sk, a))");
    CheckDecrypt(cc, kp.secretKey, cc->EvalAdd(ca, cb), sum, ti, "EvalAdd(ct, ct)");
    CheckDecrypt(cc, kp.secretKey, cc->EvalAdd(ca, pb), sum, ti, "EvalAdd(ct, pt)");
    CheckDecrypt(cc, kp.secretKey, cc->EvalMult(ca, pb), prod, ti, "EvalMult(ct, pt)");
}

// (t, ScalingModSize): q0 = 2056193 for 21 bits and q0 = 4079617 for 22 bits (ring dimension chosen by OpenFHE)
INSTANTIATE_TEST_SUITE_P(PackedSmallQ0, UTBFVRNS_PACKED_SMALL_Q0,
                         ::testing::Values(std::make_tuple(1179649ULL, 21u), std::make_tuple(2752513ULL, 22u)));
