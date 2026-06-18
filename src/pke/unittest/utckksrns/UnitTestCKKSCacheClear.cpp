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

#include "binfhecontext.h"
#include "gtest/gtest.h"
#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "scheme/ckksrns/ckksrns-schemeswitching.h"
#include "scheme/scheme-swch-params.h"
#include "utils/memory.h"

#include <vector>

#if defined(__GLIBC__)
    #include <malloc.h>
#elif defined(__APPLE__)
    #include <malloc/malloc.h>
#endif

using namespace lbcrypto;

namespace {
std::size_t HeapInUseBytes() {
#if defined(__GLIBC__)
    auto info = mallinfo2();
    return info.uordblks;
#elif defined(__APPLE__)
    malloc_statistics_t s{};
    malloc_zone_statistics(malloc_default_zone(), &s);
    return s.size_in_use;
#else
    OPENFHE_THROW("heap probe unavailable on this allocator");
#endif
}

CryptoContext<DCRTPoly> MakeBootstrapCC(uint32_t ringDim = 1 << 8) {
    CCParams<CryptoContextCKKSRNS> params;
    SecretKeyDist skDist = UNIFORM_TERNARY;
    params.SetSecretKeyDist(skDist);
    params.SetSecurityLevel(HEStd_NotSet);
    params.SetRingDim(ringDim);
#if NATIVEINT == 128
    params.SetScalingModSize(78);
    params.SetFirstModSize(89);
    params.SetScalingTechnique(FIXEDAUTO);
#else
    params.SetScalingModSize(59);
    params.SetFirstModSize(60);
    params.SetScalingTechnique(FLEXIBLEAUTO);
#endif
    std::vector<uint32_t> levelBudget = {1, 1};
    uint32_t depth                    = 2 + FHECKKSRNS::GetBootstrapDepth(levelBudget, skDist);
    params.SetMultiplicativeDepth(depth);

    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    return cc;
}
CryptoContext<DCRTPoly> MakeSchemeSwitchCC() {
    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(3);
#if NATIVEINT == 128
    params.SetFirstModSize(89);
    params.SetScalingModSize(78);
    params.SetScalingTechnique(FIXEDAUTO);
#else
    params.SetFirstModSize(60);
    params.SetScalingModSize(50);
    params.SetScalingTechnique(FLEXIBLEAUTOEXT);
#endif
    params.SetSecurityLevel(HEStd_NotSet);
    params.SetRingDim(1 << 12);
    params.SetBatchSize(16);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(SCHEMESWITCH);
    return cc;
}

}  // namespace

class UTCKKSCacheClear : public ::testing::Test {
protected:
#if defined(WITH_TCM) || defined(__EMSCRIPTEN__)
    void SetUp() override {
#if defined(WITH_TCM)
        GTEST_SKIP() << "Heap usage checks are not stable with tcmalloc enabled";
#else
        GTEST_SKIP() << "Heap probe unavailable under Emscripten";
#endif
    }
#endif

    void TearDown() override {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }
};

// Full clear drops every slot-keyed entry in FHECKKSRNS::m_bootPrecomMap.
TEST_F(UTCKKSCacheClear, FullBootstrapClear) {
    auto cc           = MakeBootstrapCC();
    uint32_t numSlots = cc->GetRingDimension() / 2;

    size_t before = HeapInUseBytes();
    cc->EvalBootstrapSetup({1, 1}, {0, 0}, numSlots);
    // size_t after = HeapInUseBytes();
    cc->ClearBootstrapPrecom();
    // size_t after_cleanup = HeapInUseBytes();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    size_t final = HeapInUseBytes();

    std::string failmsg{"ClearBootstrapPrecom() may not clean all allocated memory"};
    EXPECT_TRUE(final <= before) << failmsg;

    // std::cerr << "FullBootstrapClear(): before: " << before << "; after: " << after
    //           << "; after cleanup: " << after_cleanup << "; after ReleaseAllContexts(): " << final << std::endl;
}

TEST_F(UTCKKSCacheClear, SchemeSwitchPrecomClear) {
    auto cc = MakeSchemeSwitchCC();
    auto kp = cc->KeyGen();

    SchSwchParams p;
    p.SetSecurityLevelCKKS(HEStd_NotSet);
    p.SetSecurityLevelFHEW(TOY);
    p.SetCtxtModSizeFHEWLargePrec(25);
    p.SetNumSlotsCKKS(16);
    size_t before = HeapInUseBytes();
    auto lweSk    = cc->EvalCKKStoFHEWSetup(p);
    cc->EvalCKKStoFHEWKeyGen(kp, lweSk);
    // size_t after = HeapInUseBytes();
    cc->ClearSchemeSwitchPrecom();
    cc->ClearStaticMapsAndVectors();
    // size_t after_cleanup = HeapInUseBytes();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    size_t final = HeapInUseBytes();

    std::string failmsg{"ClearSchemeSwitchPrecom() may not clean all allocated memory"};
    EXPECT_TRUE(final <= before) << failmsg;

    // std::cerr << "SchemeSwitchPrecomClear(): before: " << before << "; after: " << after
    //           << "; after cleanup: " << after_cleanup << "; after ReleaseAllContexts(): " << final << std::endl;
}
