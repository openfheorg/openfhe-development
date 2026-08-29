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

#include "cryptocontext.h"
#include "gen-cryptocontext.h"
#include "gtest/gtest.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "UnitTestException.h"
#include "UnitTestUtils.h"
#include "utils/debug.h"

#include <memory>
#include <vector>

using namespace lbcrypto;

TEST(UTCKKS_EXPAND_RING, EncodeThenExpandRingMatchesEagerExpansion) {
    setupSignals();
    OpenFHEParallelControls.UnitTestStart();

    const std::string failmsg("EncodeThenExpandRingMatchesEagerExpansion");

    try {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(1);
        parameters.SetScalingModSize(50);
        parameters.SetFirstModSize(60);
        parameters.SetScalingTechnique(FIXEDMANUAL);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(1 << 8);

        auto cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(LEVELEDSHE);

        const uint32_t slots = cc->GetRingDimension() / 8;

        std::vector<double> x(slots);
        for (uint32_t i = 0; i < slots; ++i)
            x[i] = static_cast<double>(i) - static_cast<double>(slots) / 2.0;

        Plaintext ptxt = cc->MakeCKKSPackedPlaintext(x, 1, 0, nullptr, slots);
        DCRTPoly big   = ptxt->GetElement<DCRTPoly>();

        const uint32_t bigDim   = big.GetRingDimension();
        const uint32_t smallDim = 2 * slots;
        const uint32_t gap      = bigDim / smallDim;

        DCRTPoly bigCoeff = big;
        bigCoeff.SetFormat(Format::COEFFICIENT);
        auto bigParams  = bigCoeff.GetParams();
        const auto& tow = bigParams->GetParams();

        std::vector<std::shared_ptr<ILNativeParams>> smallTowerParams;
        for (const auto& p : tow) {
            NativeInteger modulus   = p->GetModulus();
            NativeInteger smallRoot = p->GetRootOfUnity().ModExp(NativeInteger(gap), modulus);
            smallTowerParams.push_back(std::make_shared<ILNativeParams>(2 * smallDim, modulus, smallRoot));
        }
        auto smallParams = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(2 * smallDim, smallTowerParams);

        DCRTPoly small(smallParams, Format::COEFFICIENT, true);
        for (uint32_t t = 0; t < tow.size(); ++t) {
            NativePoly bigTower = bigCoeff.GetElementAtIndex(t);
            const NativeVector& bigVals = bigTower.GetValues();

            NativeVector smallVals(smallDim, tow[t]->GetModulus());
            for (uint32_t i = 0; i < smallDim; ++i)
                smallVals[i] = bigVals[gap * i];

            NativePoly smallTower = small.GetElementAtIndex(t);
            smallTower.SetValues(std::move(smallVals), Format::COEFFICIENT);
            small.SetElementAtIndex(t, std::move(smallTower));
        }
        small.SetFormat(Format::EVALUATION);

        DCRTPoly expanded = small.ExpandRing(bigParams);

        EXPECT_EQ(expanded, big) << failmsg;
    }
    catch (std::exception& e) {
        std::cerr << "Exception thrown from " << failmsg << ": " << e.what() << std::endl;
        EXPECT_TRUE(0 == 1) << failmsg;
    }
    catch (...) {
        UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
    }

    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    OpenFHEParallelControls.UnitTestStop();
}
