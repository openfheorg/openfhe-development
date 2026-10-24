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
  Tests for the fused hybrid key switching + CKKS rescaling (KeySwitchAndModReduce, KeySwitchDownAndModReduce):
  the fused operations must produce the same ciphertext elements and metadata, bit for bit, as the unfused
  sequence (KeySwitchInPlace / KeySwitchDown followed by ModReduceInternalInPlace), for every scaling
  technique, including composite scaling where several towers are dropped at once.
*/

#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "UnitTestUtils.h"
#include "cryptocontext.h"
#include "gen-cryptocontext.h"
#include "gtest/gtest.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"

using namespace lbcrypto;

namespace {

struct FusedKSTestCase {
    ScalingTechnique scalTech;
    uint32_t scalingModSize;
    uint32_t firstModSize;
    uint32_t registerWordSize;  // 0 = not set (composite scaling only)
    std::string name;
};

const std::vector<FusedKSTestCase> testCases = {
        {FIXEDMANUAL, 50, 60, 0, "FIXEDMANUAL"},
        {FIXEDAUTO, 50, 60, 0, "FIXEDAUTO"},
#if NATIVEINT != 128
        {FLEXIBLEAUTO, 50, 60, 0, "FLEXIBLEAUTO"},
        {FLEXIBLEAUTOEXT, 50, 60, 0, "FLEXIBLEAUTOEXT"},
        // two and three limbs per level
        {COMPOSITESCALINGAUTO, 52, 64, 32, "COMPOSITESCALINGAUTO_deg2"},
        {COMPOSITESCALINGAUTO, 80, 96, 32, "COMPOSITESCALINGAUTO_deg3"},
#endif
};

CryptoContext<DCRTPoly> BuildContext(const FusedKSTestCase& tc) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(UNIFORM_TERNARY);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12);
    parameters.SetMultiplicativeDepth(6);
    parameters.SetScalingModSize(tc.scalingModSize);
    parameters.SetFirstModSize(tc.firstModSize);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetScalingTechnique(tc.scalTech);
    // several towers in the auxiliary basis P, so the basis extension is exercised
    parameters.SetNumLargeDigits(3);
    parameters.SetBatchSize(8);
    if (tc.registerWordSize != 0)
        parameters.SetRegisterWordSize(tc.registerWordSize);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    return cc;
}

void ExpectSameCiphertext(const Ciphertext<DCRTPoly>& fused, const Ciphertext<DCRTPoly>& ref, const std::string& msg) {
    ASSERT_EQ(fused->GetElements().size(), ref->GetElements().size()) << msg;
    for (size_t k = 0; k < ref->GetElements().size(); ++k) {
        EXPECT_EQ(fused->GetElements()[k].GetNumOfElements(), ref->GetElements()[k].GetNumOfElements()) << msg;
        EXPECT_TRUE(fused->GetElements()[k] == ref->GetElements()[k]) << msg << ": element " << k << " differs";
    }
    EXPECT_EQ(fused->GetLevel(), ref->GetLevel()) << msg;
    EXPECT_EQ(fused->GetNoiseScaleDeg(), ref->GetNoiseScaleDeg()) << msg;
    EXPECT_EQ(fused->GetScalingFactor(), ref->GetScalingFactor()) << msg;
}

void ExpectDecryptsTo(const CryptoContext<DCRTPoly>& cc, const PrivateKey<DCRTPoly>& sk, const Ciphertext<DCRTPoly>& ct,
                      const std::vector<double>& expected, const std::string& msg) {
    Plaintext result;
    cc->Decrypt(sk, ct, &result);
    result->SetLength(expected.size());
    checkEquality(result->GetRealPackedValue(), expected, 1e-4, msg);
}

}  // namespace

TEST(UTCKKSRNS_FUSED_KS_MODREDUCE, FusedEqualsUnfused) {
    for (const auto& tc : testCases) {
        SCOPED_TRACE(::testing::Message() << "scaling technique = " << tc.name);
        try {
            auto cc = BuildContext(tc);
            auto keys = cc->KeyGen();
            cc->EvalMultKeyGen(keys.secretKey);
            cc->EvalRotateKeyGen(keys.secretKey, {1});
            auto algo = cc->GetScheme();

            const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
            const uint32_t levels = cryptoParams->GetCompositeDegree();

            const std::vector<double> x = {0.25, -0.5, 1.0, 0.125, -0.75, 0.375, 0.9, -0.1};
            const std::vector<double> y = {1.5, 0.5, -0.25, 2.0, 0.6, -1.0, 0.3, 0.8};
            std::vector<double> xy(x.size()), xyRot(x.size());
            for (size_t i = 0; i < x.size(); ++i)
                xy[i] = x[i] * y[i];
            for (size_t i = 0; i < x.size(); ++i)
                xyRot[i] = xy[(i + 1) % x.size()];

            auto ctx = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(x));
            auto cty = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(y));

            // 1. three-element ciphertext: relinearization fused with the rescaling
            {
                auto prod = cc->EvalMultNoRelin(ctx, cty);
                const auto& ek = cc->GetEvalMultKeyVector(ctx->GetKeyTag())[0];

                auto ref = prod->Clone();
                algo->KeySwitchInPlace(ref, ek);
                algo->ModReduceInternalInPlace(ref, levels);

                auto fused = cc->KeySwitchAndModReduce(prod, ek, levels);
                ExpectSameCiphertext(fused, ref, "relinearization");
                ExpectDecryptsTo(cc, keys.secretKey, fused, xy, "relinearization: decryption");

                auto fusedInPlace = prod->Clone();
                cc->KeySwitchAndModReduceInPlace(fusedInPlace, ek, levels);
                ExpectSameCiphertext(fusedInPlace, ref, "relinearization in place");
            }

            // 2. two-element ciphertext: key switching to another secret key fused with the rescaling
            {
                auto keys2 = cc->KeyGen();
                auto ksKey = cc->KeySwitchGen(keys.secretKey, keys2.secretKey);
                auto ctm = cc->EvalMult(ctx, cty);

                auto ref = ctm->Clone();
                algo->KeySwitchInPlace(ref, ksKey);
                algo->ModReduceInternalInPlace(ref, levels);

                auto fused = cc->KeySwitchAndModReduce(ctm, ksKey, levels);
                ExpectSameCiphertext(fused, ref, "key switching");
                ExpectDecryptsTo(cc, keys2.secretKey, fused, xy, "key switching: decryption");
            }

            // 3. ComposedEvalMult (fused under FIXEDMANUAL) against multiplication, relinearization and the public
            //    ModReduce
            {
                auto ref = cc->EvalMult(ctx, cty);
                cc->ModReduceInPlace(ref);
                auto fused = cc->ComposedEvalMult(ctx, cty);
                ExpectSameCiphertext(fused, ref, "ComposedEvalMult");
                ExpectDecryptsTo(cc, keys.secretKey, fused, xy, "ComposedEvalMult: decryption");
            }

            // 4. hoisted rotation in the extended basis: KeySwitchDown fused with the rescaling
            {
                auto ctm = cc->EvalMult(ctx, cty);
                auto digits = cc->EvalFastRotationPrecompute(ctm);
                auto ext = cc->EvalFastRotationExt(ctm, 1, digits, true);

                auto ref = cc->KeySwitchDown(ext);
                algo->ModReduceInternalInPlace(ref, levels);

                auto fused = cc->KeySwitchDownAndModReduce(ext, levels);
                ExpectSameCiphertext(fused, ref, "KeySwitchDown");
                ExpectDecryptsTo(cc, keys.secretKey, fused, xyRot, "KeySwitchDown: decryption");
            }
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << tc.name;
        }
    }
}
