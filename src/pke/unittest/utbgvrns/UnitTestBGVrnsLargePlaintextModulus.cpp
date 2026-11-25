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
  BGV with a plaintext modulus t >= 2^32. With FIXEDMANUAL and FIXEDAUTO every ciphertext modulus
  must be 1 mod t (the scaling factor is kept at 1), so parameter generation must not truncate t.
*/

#include <cstdint>
#include <random>
#include <string>
#include <tuple>
#include <vector>

#include "gtest/gtest.h"
#include "openfhe.h"

using namespace lbcrypto;

class UTBGVRNS_LARGE_PTM : public ::testing::TestWithParam<std::tuple<uint64_t, ScalingTechnique>> {
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

static void CheckDecrypt(const CryptoContext<DCRTPoly>& cc, const PrivateKey<DCRTPoly>& sk,
                         const Ciphertext<DCRTPoly>& ct, const std::vector<int64_t>& expected, int64_t t,
                         const std::string& what) {
    Plaintext pt;
    cc->Decrypt(sk, ct, &pt);
    pt->SetLength(expected.size());
    const auto& got = pt->GetPackedValue();
    size_t wrong = 0;
    for (size_t i = 0; i < expected.size(); ++i) {
        if (CenteredMod(got[i], t) != CenteredMod(expected[i], t))
            ++wrong;
    }
    EXPECT_EQ(wrong, 0u) << what << ": " << wrong << " of " << expected.size() << " slots wrong";
}

TEST_P(UTBGVRNS_LARGE_PTM, EncryptMultRotate) {
    const uint64_t t = std::get<0>(GetParam());
    const ScalingTechnique scalTech = std::get<1>(GetParam());

    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(t);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingTechnique(scalTech);
    parameters.SetRingDim(4096);
    parameters.SetSecurityLevel(HEStd_NotSet);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    if (scalTech == FIXEDMANUAL || scalTech == FIXEDAUTO) {
        for (const auto& p : cc->GetElementParams()->GetParams())
            EXPECT_EQ(p->GetModulus().ConvertToInt<uint64_t>() % t, 1u) << "modulus " << p->GetModulus();
    }

    auto kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);
    cc->EvalRotateKeyGen(kp.secretKey, {1});

    const size_t n = cc->GetRingDimension();
    const size_t half = n / 2;
    const int64_t ti = static_cast<int64_t>(t);
    std::mt19937_64 rng(1);
    std::vector<int64_t> a(n), b(n), prod(n), rot(n);
    for (size_t i = 0; i < n; ++i) {
        a[i] = static_cast<int64_t>(rng() % t) - ti / 2;
        b[i] = static_cast<int64_t>(rng() % t) - ti / 2;
        prod[i] = CenteredMod(static_cast<__int128>(a[i]) * b[i], ti);
    }
    // EvalRotate by 1 rotates each of the two rows of n/2 slots
    for (size_t i = 0; i < n; ++i)
        rot[i] = a[(i / half) * half + (i % half + 1) % half];

    auto ca = cc->Encrypt(kp.publicKey, cc->MakePackedPlaintext(a));
    auto cb = cc->Encrypt(kp.publicKey, cc->MakePackedPlaintext(b));

    CheckDecrypt(cc, kp.secretKey, ca, a, ti, "Decrypt(Encrypt(a))");
    auto cab = cc->EvalMult(ca, cb);
    if (scalTech == FIXEDMANUAL)
        cc->ModReduceInPlace(cab);
    CheckDecrypt(cc, kp.secretKey, cab, prod, ti, "EvalMult(Enc(a), Enc(b))");
    CheckDecrypt(cc, kp.secretKey, cc->EvalRotate(ca, 1), rot, ti, "EvalRotate(Enc(a), 1)");
}

// primes = 1 mod 2^17: the first below 2^32 (control), the first above 2^32
INSTANTIATE_TEST_SUITE_P(BGVLargePlaintextModulus, UTBGVRNS_LARGE_PTM,
                         ::testing::Values(std::make_tuple(4293918721ULL, FIXEDMANUAL),
                                           std::make_tuple(4296540161ULL, FIXEDMANUAL),
                                           std::make_tuple(4296540161ULL, FIXEDAUTO),
                                           std::make_tuple(4296540161ULL, FLEXIBLEAUTO)));

// With FIXEDMANUAL no modulus of scalingModSize bits is 1 mod t when t has more bits than that. The prime
// search must not be started with such a step: for NATIVE_SIZE = 32 the step does not fit in NativeInteger.
TEST(UTBGVRNS_LARGE_PTM_STEP, FixedManualModulusSmallerThanStep) {
    OpenFHEParallelControls.UnitTestStart();
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(4296540161ULL);  // 33 bits
    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetScalingModSize(30);
    parameters.SetRingDim(4096);
    parameters.SetSecurityLevel(HEStd_NotSet);
    std::string msg;
    try {
        GenCryptoContext(parameters);
    } catch (const OpenFHEException& e) {
        msg = e.what();
    }
    EXPECT_NE(msg.find("The plaintext modulus is too large for FIXEDMANUAL"), std::string::npos)
            << "exception message: \"" << msg << "\"";
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    OpenFHEParallelControls.UnitTestStop();
}

// t = 2^33 is 0 modulo 2^32: parameter generation must neither reject it as zero nor loop forever
// while removing factors of 2 (HYBRID key switching also derives the step of the special primes from t)
TEST(UTBGVRNS_LARGE_PTM_POW2, ContextGeneration) {
    OpenFHEParallelControls.UnitTestStart();
    const uint64_t t = uint64_t(1) << 33;
    for (ScalingTechnique scalTech : {FIXEDMANUAL, FIXEDAUTO}) {
        CCParams<CryptoContextBGVRNS> parameters;
        parameters.SetPlaintextModulus(t);
        parameters.SetMultiplicativeDepth(2);
        parameters.SetScalingTechnique(scalTech);
        parameters.SetKeySwitchTechnique(HYBRID);
        parameters.SetRingDim(4096);
        parameters.SetSecurityLevel(HEStd_NotSet);
        CryptoContext<DCRTPoly> cc;
        ASSERT_NO_THROW(cc = GenCryptoContext(parameters));
        for (const auto& p : cc->GetElementParams()->GetParams())
            EXPECT_EQ(p->GetModulus().ConvertToInt<uint64_t>() % t, 1u) << "modulus " << p->GetModulus();
    }
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    OpenFHEParallelControls.UnitTestStop();
}
