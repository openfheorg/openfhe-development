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
  Regression test for the sparse secret encapsulation key switching
  (https://github.com/openfheorg/openfhe-development/issues/1041): the noise added by
  KeySwitchSparse must stay at the modulus switching (rounding) noise level.
*/

#include "config_core.h"
#include "cryptocontext.h"
#include "gen-cryptocontext.h"
#include "gtest/gtest.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "UnitTestException.h"
#include "UnitTestUtils.h"
#include "utils/debug.h"

#include <iostream>
#include <memory>
#include <string>
#include <vector>

using namespace lbcrypto;

// Regression test for https://github.com/openfheorg/openfhe-development/issues/1041: the
// noise added by the sparse encapsulation key switching must stay at the modulus switching
// (rounding) noise level. The noise added by KeySwitchSparse decomposes as
// floor(c1*e/P') + delta_0 + delta_1*s_new, where the delta rounding terms are inherent to
// any modulus switch and are bounded by (1 + ||s_new||_1)/2 = 16.5 per coefficient for a
// Hamming weight 32 secret. With the auxiliary modulus P' of ~66 bits (two 33-bit primes)
// the key switching term is below one per coefficient, and the measured maximum is ~2^3.
// With a single ~60-bit auxiliary prime (the previous approach) the key switching term
// dominates at ~2^8, so this test fails.
TEST(UTCKKSRNS_SPARSE_KS, KeySwitchSparseAddedNoise) {
    setupSignals();
    OpenFHEParallelControls.UnitTestStart();

    const std::string failmsg("KeySwitchSparseAddedNoise");

    try {
        // scaling factor close to the first modulus: the regime where the sparse
        // encapsulation key switching noise is exposed
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(2);
        parameters.SetScalingModSize(59);
        parameters.SetFirstModSize(60);
        parameters.SetScalingTechnique(FIXEDMANUAL);
        parameters.SetSecretKeyDist(SPARSE_ENCAPSULATED);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(1 << 12);
        parameters.SetKeySwitchTechnique(HYBRID);

        auto cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
        cc->Enable(FHE);

        auto keyPair = cc->KeyGen();
        auto cryptoParams =
            std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(keyPair.secretKey->GetCryptoParameters());

        // encode at the last level so the ciphertext has a single tower (q0), as at the
        // modulus raise step of bootstrapping
        std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 0.375, 0.675, 0.125, 0.925};
        auto ptxt             = cc->MakeCKKSPackedPlaintext(x, 1, cryptoParams->GetMultiplicativeDepth());
        auto ctxt             = cc->Encrypt(keyPair.publicKey, ptxt);

        // sparse key used for the modraising step
        DCRTPoly::TugType tug;
        auto skNew = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);
        skNew->SetPrivateElement(DCRTPoly(tug, cryptoParams->GetElementParams(), Format::EVALUATION, 32));

        auto evalKey  = FHECKKSRNS::KeySwitchGenSparse(keyPair.secretKey, skNew);
        auto ctresult = FHECKKSRNS::KeySwitchSparse(ctxt, evalKey);

        // the noise added by the key switch: difference of the raw decryptions b + a*s
        // over q0 under the respective secret keys (the shared encryption noise cancels)
        const auto sOld0 = keyPair.secretKey->GetPrivateElement().GetElementAtIndex(0);
        const auto sNew0 = skNew->GetPrivateElement().GetElementAtIndex(0);
        const auto& cvo  = ctxt->GetElements();
        const auto& cvn  = ctresult->GetElements();
        auto diff        = (cvo[0].GetElementAtIndex(0) + cvo[1].GetElementAtIndex(0) * sOld0) -
                    (cvn[0].GetElementAtIndex(0) + cvn[1].GetElementAtIndex(0) * sNew0);
        diff.SetFormat(Format::COEFFICIENT);

        const NativeInteger q    = diff.GetModulus();
        const NativeInteger half = q >> 1;
        NativeInteger maxNoise(0);
        for (uint32_t i = 0; i < diff.GetLength(); ++i) {
            NativeInteger v = diff[i];
            if (v > half)
                v = q - v;
            if (v > maxNoise)
                maxNoise = v;
        }

        EXPECT_LE(maxNoise.ConvertToInt<uint64_t>(), 32u)
            << "the noise added by the sparse encapsulation key switching exceeds the modulus switching noise level";
    }
    catch (std::exception& e) {
        std::cerr << "Exception thrown from KeySwitchSparseAddedNoise: " << e.what() << std::endl;
        EXPECT_TRUE(0 == 1) << failmsg;
    }
    catch (...) {
        UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
    }

    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    OpenFHEParallelControls.UnitTestStop();
}
