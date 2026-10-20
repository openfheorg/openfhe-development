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
  Regression tests for bootstrapping setups on modulus chains that are too short for bootstrapping.

  The setups derive the levels at which the CoeffsToSlots and SlotsToCoeffs matrices are encoded with unsigned
  arithmetic from the length of the chain. On a chain that is too short these subtractions wrapped around, and the
  plaintext encoding then dropped towers past the end of the chain (segmentation fault). At the boundary depth one
  below the required one, the SlotsToCoeffs level came out as zero, which encodes the matrices for the whole chain;
  the evaluation then threw a modulus mismatch inside an OpenMP region, which terminates the program. The setups
  now throw an OpenFHEException for both cases, and the required depth itself still works.

  The 128-bit build (NATIVE_SIZE = 128) supports bootstrapping with FIXEDMANUAL and FIXEDAUTO only and does not
  support functional or FE functional bootstrapping, so it runs the ModRaise-first and StC-first cases with the
  FIXED* techniques and its larger moduli.
 */

#include <cstdint>
#include <vector>

#include "UnitTestUtils.h"
#include "gtest/gtest.h"
#include "openfhe.h"

using namespace lbcrypto;

namespace {

constexpr uint32_t RING_DIM = 1 << 10;
constexpr uint32_t SLOTS = RING_DIM / 2;

CryptoContext<DCRTPoly> MakeContext(SecretKeyDist skd, ScalingTechnique st, uint32_t depth, bool feFBT = false) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(skd);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(RING_DIM);
    const bool composite = (st == COMPOSITESCALINGAUTO);
#if NATIVEINT == 128
    const uint32_t scalingModSize = 78;
    const uint32_t firstModSize = 89;
#else
    const uint32_t scalingModSize = composite ? 50 : 59;
    const uint32_t firstModSize = 60;
#endif
    parameters.SetScalingModSize(scalingModSize);
    // FE functional bootstrapping requires the first modulus to be twice the scaling factor
    parameters.SetFirstModSize(feFBT ? scalingModSize + 1 : firstModSize);
    if (composite)
        parameters.SetRegisterWordSize(32);
    parameters.SetScalingTechnique(st);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetMultiplicativeDepth(depth);
    if (feFBT) {
        parameters.SetCKKSDataType(COMPLEX);
        parameters.SetBatchSize(SLOTS);
    }
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    return cc;
}

#if NATIVEINT == 128
// the scaling techniques supported for bootstrapping in the 128-bit build
const std::vector<ScalingTechnique> SCALING_TECHNIQUES = {FIXEDMANUAL, FIXEDAUTO};
constexpr ScalingTechnique EVAL_SCALING_TECHNIQUE = FIXEDAUTO;
#else
const std::vector<ScalingTechnique> SCALING_TECHNIQUES = {FIXEDMANUAL, FLEXIBLEAUTO, FLEXIBLEAUTOEXT,
                                                          COMPOSITESCALINGAUTO};
constexpr ScalingTechnique EVAL_SCALING_TECHNIQUE = FLEXIBLEAUTO;
#endif
const std::vector<SecretKeyDist> SECRET_KEY_DISTS = {SPARSE_ENCAPSULATED, HYBRID_TERNARY, UNIFORM_TERNARY};
const std::vector<uint32_t> LEVEL_BUDGET = {3, 3};

}  // namespace

// ModRaise-first: the setup (and the recomputation of a setup made without precomputation) throws for every
// multiplicative depth below GetBootstrapDepth and succeeds at GetBootstrapDepth.
TEST(UTCKKSRNS_BOOT_CHAIN_LENGTH, ModRaiseFirstSetupRejectsShortChain) {
    for (auto st : SCALING_TECHNIQUES) {
        for (auto skd : SECRET_KEY_DISTS) {
            const uint32_t required = FHECKKSRNS::GetBootstrapDepth(LEVEL_BUDGET, skd);
            for (uint32_t depth = 2; depth <= required; ++depth) {
                SCOPED_TRACE(::testing::Message() << st << ", " << skd << ", depth " << depth);
                auto cc = MakeContext(skd, st, depth);
                if (depth < required) {
                    EXPECT_THROW(cc->EvalBootstrapSetup(LEVEL_BUDGET, {0, 0}, SLOTS), OpenFHEException);
                    EXPECT_NO_THROW(cc->EvalBootstrapSetup(LEVEL_BUDGET, {0, 0}, SLOTS, 0, false));
                    EXPECT_THROW(cc->EvalBootstrapPrecompute(SLOTS), OpenFHEException);
                } else {
                    EXPECT_NO_THROW(cc->EvalBootstrapSetup(LEVEL_BUDGET, {0, 0}, SLOTS));
                    EXPECT_NO_THROW(cc->EvalBootstrapPrecompute(SLOTS));
                }
                CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
            }
        }
    }
}

// A setup that throws must not leave a half-initialized precomputation registered in the bootstrapping
// precomputation map: the subsequent bootstrapping calls have to fail with the clean "precomputations not
// found" exception instead of reading the empty encoding matrices of the failed setup (segmentation fault).
TEST(UTCKKSRNS_BOOT_CHAIN_LENGTH, FailedSetupLeavesNoPrecomputation) {
    const uint32_t required = FHECKKSRNS::GetBootstrapDepth(LEVEL_BUDGET, SPARSE_ENCAPSULATED);
    auto cc = MakeContext(SPARSE_ENCAPSULATED, EVAL_SCALING_TECHNIQUE, required - 1);
    EXPECT_THROW(cc->EvalBootstrapSetup(LEVEL_BUDGET, {0, 0}, SLOTS), OpenFHEException);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    EXPECT_THROW(cc->EvalBootstrapKeyGen(keyPair.secretKey, SLOTS), OpenFHEException);

    std::vector<double> x(SLOTS, 0.5);
    auto ct = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(x, 1, 0, nullptr, SLOTS));
    EXPECT_THROW(cc->EvalBootstrap(ct), OpenFHEException);
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

// StC-first and FE functional bootstrapping evaluate SlotsToCoeffs on the input, so their setups only need the
// chain to hold the encoding of the matrices; the depth of the bootstrapping itself is checked by the
// evaluation. The setups throw on the shortest chains (which crashed before) and, wherever the setup succeeds,
// the StC-first evaluation either succeeds or throws.
TEST(UTCKKSRNS_BOOT_CHAIN_LENGTH, StCFirstAndFEFBTSetupRejectShortChain) {
    for (auto st : SCALING_TECHNIQUES) {
        SCOPED_TRACE(::testing::Message() << st);
        auto cc = MakeContext(SPARSE_ENCAPSULATED, st, 2);
        EXPECT_THROW(cc->EvalBootstrapSetup(LEVEL_BUDGET, {0, 0}, SLOTS, 0, true, true), OpenFHEException);
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

#if NATIVEINT != 128
        cc = MakeContext(SPARSE_ENCAPSULATED, st, 2, true);
        EXPECT_THROW(cc->EvalFEFuncBootstrapSetup(LEVEL_BUDGET, {0, 0}, SLOTS), OpenFHEException);
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
#endif
    }

    const uint32_t required = FHECKKSRNS::GetBootstrapDepth(LEVEL_BUDGET, SPARSE_ENCAPSULATED);
    for (uint32_t depth = 2; depth <= required; ++depth) {
        SCOPED_TRACE(::testing::Message() << "StC-first evaluation, depth " << depth);
        auto cc = MakeContext(SPARSE_ENCAPSULATED, EVAL_SCALING_TECHNIQUE, depth);
        try {
            cc->EvalBootstrapSetup(LEVEL_BUDGET, {0, 0}, SLOTS, 0, true, true);
        } catch (const OpenFHEException&) {
            CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
            continue;
        }
        auto keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
        cc->EvalBootstrapKeyGen(keyPair.secretKey, SLOTS);
        std::vector<double> x(SLOTS, 0.5);
        auto ct = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(x, 1, 0, nullptr, SLOTS));
        try {
            cc->EvalBootstrap(ct);
        } catch (const OpenFHEException&) {
        }
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }
}

#if NATIVEINT != 128
// Functional bootstrapping: the setup throws one level below GetFBTDepth, where the SlotsToCoeffs matrices were
// previously encoded for the whole chain, and succeeds at GetFBTDepth.
TEST(UTCKKSRNS_BOOT_CHAIN_LENGTH, FBTSetupRejectsBoundaryDepth) {
    const BigInteger P(2);
    const BigInteger Bigq(BigInteger(1) << 33);
    const std::vector<int64_t> coefficients = {0, 1};
    for (auto skd : SECRET_KEY_DISTS) {
        const uint32_t required = FHECKKSRNS::GetFBTDepth(LEVEL_BUDGET, coefficients, P, 1, skd);
        for (uint32_t depth : {required - 1, required}) {
            SCOPED_TRACE(::testing::Message() << skd << ", depth " << depth);
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetSecretKeyDist(skd);
            parameters.SetSecurityLevel(HEStd_NotSet);
            parameters.SetRingDim(2 * RING_DIM);
            parameters.SetScalingModSize(32);
            parameters.SetFirstModSize(32);
            parameters.SetScalingTechnique(FLEXIBLEAUTO);
            parameters.SetKeySwitchTechnique(HYBRID);
            parameters.SetBatchSize(SLOTS);
            parameters.SetMultiplicativeDepth(depth);
            auto cc = GenCryptoContext(parameters);
            cc->Enable(PKE);
            cc->Enable(KEYSWITCH);
            cc->Enable(LEVELEDSHE);
            cc->Enable(ADVANCEDSHE);
            cc->Enable(FHE);
            auto keyPair = cc->KeyGen();
            if (depth < required) {
                EXPECT_THROW(cc->EvalFBTSetup(coefficients, SLOTS, P, P, Bigq, keyPair.publicKey, {0, 0}, LEVEL_BUDGET,
                                              0, 0, 1),
                             OpenFHEException);
            } else {
                EXPECT_NO_THROW(cc->EvalFBTSetup(coefficients, SLOTS, P, P, Bigq, keyPair.publicKey, {0, 0},
                                                 LEVEL_BUDGET, 0, 0, 1));
            }
            CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        }
    }
}
#endif
