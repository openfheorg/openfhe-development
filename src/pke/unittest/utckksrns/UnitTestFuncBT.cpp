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

#include "math/hermite.h"
#include "schemelet/rlwe-mp.h"
#include "scheme/ckksrns/ckksrns-fhe.h"

#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "gen-cryptocontext.h"
#include "cryptocontext.h"

#include <vector>
#include "gtest/gtest.h"

#include "utils/debug.h"

using namespace lbcrypto;

namespace {
class UTCKKSRNS_FUNCBT_ARBLUT : public ::testing::Test {
protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }
};
}  // anonymous namespace

//================================================================================================

std::vector<int64_t> ArbitraryLUT(std::function<int64_t(int64_t)> func, const std::vector<int64_t>& x,
                                  const BigInteger& PInput, const BigInteger& POutput, const BigInteger& QBFVInit,
                                  const BigInteger& Q, const BigInteger& Bigq, double scale, size_t order,
                                  uint32_t numSlots, uint32_t levelsAvailableAfterBootstrap,
                                  uint32_t levelsAvailableBeforeBootstrap, std::tuple<uint32_t, uint32_t> levelBudget) {
    auto coefficients = GetHermiteTrigCoefficients(func, PInput.ConvertToInt(), scale);
    uint32_t dcrtBits = Bigq.GetMSB() - 1;
    uint32_t firstMod = Bigq.GetMSB() - 1;

    CCParams<CryptoContextCKKSRNS> parameters;
    SecretKeyDist secretKeyDist = SPARSE_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetFirstModSize(firstMod);
    parameters.SetNumLargeDigits(4);
    parameters.SetBatchSize(numSlots);
    parameters.SetRingDim(2 * numSlots);  // Currently not working for sparse packing

    auto& [lvlb0, lvlb1] = levelBudget;

    uint32_t depth = levelsAvailableAfterBootstrap + lvlb0 + lvlb1 + 2;

    depth += FHECKKSRNS::AdjustDepthFuncBT(coefficients, PInput, order);

    parameters.SetMultiplicativeDepth(depth);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    BigInteger QPrime = keyPair.publicKey->GetPublicElements()[0].GetParams()->GetParams()[0]->GetModulus();
    uint32_t cnt      = 1;
    auto levels       = levelsAvailableAfterBootstrap;
    while (levels > 0) {
        QPrime *= keyPair.publicKey->GetPublicElements()[0].GetParams()->GetParams()[cnt]->GetModulus();
        levels--;
        cnt++;
    }
    double scaleMod = QPrime.ConvertToLongDouble() / (Bigq.ConvertToLongDouble() * PInput.ConvertToDouble());

    cc->EvalFuncBTSetup(numSlots, PInput.GetMSB() - 1, coefficients, {0, 0}, levelBudget, scaleMod, 0, order);

    cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    auto ep = SchemeletRLWEMP::GetElementParams(keyPair.secretKey, depth - (levelsAvailableBeforeBootstrap > 0));

    auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, QBFVInit, PInput, keyPair.secretKey, ep);

    SchemeletRLWEMP::ModSwitch(ctxtBFV, Q, QBFVInit);

    auto ctxt = SchemeletRLWEMP::convert(*cc, ctxtBFV, keyPair.publicKey, Bigq, numSlots,
                                         depth - (levelsAvailableBeforeBootstrap > 0));

    auto ctxtAfterFuncBT =
        cc->EvalFuncBT(ctxt, coefficients, PInput.GetMSB() - 1, ep->GetModulus(), 1.0, 0, false, order);  // Apply LUT

    // Scalar addresses the division in Hermite Interpolation
    cc->GetScheme()->MultByIntegerInPlace(ctxtAfterFuncBT, scale);
    cc->ModReduceInPlace(ctxtAfterFuncBT);

    if (QPrime != ctxtAfterFuncBT->GetElements()[0].GetModulus())
        OPENFHE_THROW("The ciphertext modulus after bootstrapping is not as expected.");

    auto polys = SchemeletRLWEMP::convert(ctxtAfterFuncBT, Q, QPrime);

    return SchemeletRLWEMP::DecryptCoeff(polys, Q, PInput, keyPair.secretKey, ep, numSlots);
}

TEST_F(UTCKKSRNS_FUNCBT_ARBLUT, Test_CKKSrns_FuncBT_ArbLUT) {
    BigInteger QBFVInit("1152921504606846976");
    BigInteger PInput("256");
    BigInteger POutput("256");
    BigInteger Q(1UL << 47);
    BigInteger Bigq = Q;

    auto func = [PInput, POutput](int64_t x) -> int64_t {
        return (x % PInput.ConvertToInt() - PInput.ConvertToInt() / 2) % POutput.ConvertToInt();
    };

    double scale      = 32.0;
    size_t order      = 1;
    uint32_t numSlots = 32;

    uint32_t levelsAvailableAfterBootstrap  = 0;
    uint32_t levelsAvailableBeforeBootstrap = 0;

    std::tuple<uint32_t, uint32_t> levelBudget = {3, 3};

    std::vector<int64_t> x = {static_cast<int64_t>(PInput.ConvertToInt() / 2),
                              static_cast<int64_t>(PInput.ConvertToInt() / 2) + 1,
                              0,
                              3,
                              16,
                              33,
                              64,
                              static_cast<int64_t>(PInput.ConvertToInt() - 1)};
    if (x.size() < numSlots * 2)
        x = Fillint64(x, numSlots * 2);

    auto computed = ArbitraryLUT(func, x, PInput, POutput, QBFVInit, Q, Bigq, scale, order, numSlots,
                                 levelsAvailableAfterBootstrap, levelsAvailableBeforeBootstrap, levelBudget);

    auto exact(x);
    std::transform(x.begin(), x.end(), exact.begin(), [&](const int64_t& elem) {
        return (func(elem) > POutput.ConvertToDouble() / 2.) ? func(elem) - POutput.ConvertToInt() : func(elem);
    });

    std::transform(exact.begin(), exact.end(), computed.begin(), exact.begin(), std::minus<double>());
    std::transform(exact.begin(), exact.end(), exact.begin(),
                   [&](const int64_t& elem) { return (std::abs(elem)) % (PInput.ConvertToInt()); });
    auto max_error_it = std::max_element(exact.begin(), exact.end());
    // std::cerr << "\n=======Max absolute error: " << *max_error_it << std::endl << std::endl;

    EXPECT_LT((*max_error_it), 0.1);
}
