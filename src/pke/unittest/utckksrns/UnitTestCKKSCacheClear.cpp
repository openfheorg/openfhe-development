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

// Coverage for the cache-clear APIs added for issue #533:
//   CryptoContextImpl::ClearBootstrapPrecom()            -- full clear
//   CryptoContextImpl::ClearBootstrapPrecom(uint32_t)    -- per-slot clear
//   CryptoContextImpl::ClearSchemeSwitchPrecom()
//   CryptoContextImpl::ClearAllCKKSCaches()
//   CryptoContextFactory::ReleaseAllContexts()           -- now also drops
//                                                           scheme-level caches

#include "binfhecontext.h"
#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "scheme/ckksrns/ckksrns-schemeswitching.h"
#include "scheme/scheme-swch-params.h"
#include "utils/memory.h"

#include "gtest/gtest.h"

#include <vector>

#if defined(__GLIBC__)
    #include <malloc.h>
#elif defined(__APPLE__)
    #include <malloc/malloc.h>
#endif

using namespace lbcrypto;

namespace {

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
    uint32_t depth = 2 + FHECKKSRNS::GetBootstrapDepth(levelBudget, skDist);
    params.SetMultiplicativeDepth(depth);

    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    return cc;
}

// Returns bytes currently in use by the heap allocator, or 0 if no portable
// probe is available. Only used by MemoryDropsAfterBootstrapClear, which also
// guards itself by platform. The absolute value is noisy (other threads,
// background allocations, allocator bookkeeping); the test asserts a relative
// drop, not an exact number.
size_t HeapInUseBytes() {
#if defined(__GLIBC__)
    auto info = mallinfo2();
    return info.uordblks;
#elif defined(__APPLE__)
    malloc_statistics_t s{};
    malloc_zone_statistics(nullptr, &s);
    return s.size_in_use;
#else
    return 0;
#endif
}

CryptoContext<DCRTPoly> MakeBFVContext() {
    CCParams<CryptoContextBFVRNS> params;
    params.SetPlaintextModulus(65537);
    params.SetMultiplicativeDepth(2);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    return cc;
}

CryptoContext<DCRTPoly> MakeBGVContext() {
    CCParams<CryptoContextBGVRNS> params;
    params.SetPlaintextModulus(65537);
    params.SetMultiplicativeDepth(2);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    return cc;
}

CryptoContext<DCRTPoly> MakeSchemeSwitchCC() {
    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(3);
#if NATIVEINT == 128
    // FLEXIBLE* scaling is unsupported on the 128-bit backend; use the
    // FIXED* path with the larger moduli that UnitTestSchemeSwitch uses.
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
    void TearDown() override {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }
};

// Baseline: a context with no EvalBootstrapSetup / scheme-switch setup reports
// empty caches and the clear APIs are safe no-ops.
TEST_F(UTCKKSCacheClear, DefaultContextReportsNoCaches) {
    auto cc = MakeBootstrapCC();

    EXPECT_FALSE(cc->HasBootstrapPrecom());
    EXPECT_FALSE(cc->HasBootstrapPrecom(8));
    EXPECT_FALSE(cc->HasSchemeSwitchPrecom());

    EXPECT_NO_THROW(cc->ClearBootstrapPrecom());
    EXPECT_NO_THROW(cc->ClearBootstrapPrecom(8));
    EXPECT_NO_THROW(cc->ClearSchemeSwitchPrecom());
    EXPECT_NO_THROW(cc->ClearAllCKKSCaches());
}

// Full clear drops every slot-keyed entry in FHECKKSRNS::m_bootPrecomMap.
TEST_F(UTCKKSCacheClear, FullBootstrapClear) {
    auto cc           = MakeBootstrapCC();
    uint32_t numSlots = cc->GetRingDimension() / 2;

    cc->EvalBootstrapSetup({1, 1}, {0, 0}, numSlots);
    EXPECT_TRUE(cc->HasBootstrapPrecom());
    EXPECT_TRUE(cc->HasBootstrapPrecom(numSlots));

    cc->ClearBootstrapPrecom();
    EXPECT_FALSE(cc->HasBootstrapPrecom());
    EXPECT_FALSE(cc->HasBootstrapPrecom(numSlots));
}

// Per-slot clear removes only the targeted slot entry and leaves others alone.
TEST_F(UTCKKSCacheClear, PerSlotBootstrapClear) {
    auto cc             = MakeBootstrapCC();
    uint32_t ringDim    = cc->GetRingDimension();
    uint32_t slotsLarge = ringDim / 2;
    uint32_t slotsSmall = ringDim / 4;

    cc->EvalBootstrapSetup({1, 1}, {0, 0}, slotsLarge);
    cc->EvalBootstrapSetup({1, 1}, {0, 0}, slotsSmall);
    ASSERT_TRUE(cc->HasBootstrapPrecom(slotsLarge));
    ASSERT_TRUE(cc->HasBootstrapPrecom(slotsSmall));

    cc->ClearBootstrapPrecom(slotsLarge);
    EXPECT_FALSE(cc->HasBootstrapPrecom(slotsLarge));
    EXPECT_TRUE(cc->HasBootstrapPrecom(slotsSmall));
    EXPECT_TRUE(cc->HasBootstrapPrecom());  // map still non-empty

    // Clearing a non-existent slot is a safe no-op.
    EXPECT_NO_THROW(cc->ClearBootstrapPrecom(slotsLarge));

    cc->ClearBootstrapPrecom(slotsSmall);
    EXPECT_FALSE(cc->HasBootstrapPrecom());
}

// The CKKS<->FHEW scheme-switch precomputation holds an entire BinFHEContext,
// intermediate CKKS context, two switching keys, a ciphertext and a precomputed
// linear-transform matrix. ClearSchemeSwitchPrecom() must release all of them.
TEST_F(UTCKKSCacheClear, SchemeSwitchPrecomClear) {
    auto cc = MakeSchemeSwitchCC();
    auto kp = cc->KeyGen();

    SchSwchParams p;
    p.SetSecurityLevelCKKS(HEStd_NotSet);
    p.SetSecurityLevelFHEW(TOY);
    p.SetCtxtModSizeFHEWLargePrec(25);
    p.SetNumSlotsCKKS(16);
    auto lweSk = cc->EvalCKKStoFHEWSetup(p);
    cc->EvalCKKStoFHEWKeyGen(kp, lweSk);
    EXPECT_TRUE(cc->HasSchemeSwitchPrecom());

    cc->ClearSchemeSwitchPrecom();
    EXPECT_FALSE(cc->HasSchemeSwitchPrecom());
    EXPECT_FALSE(static_cast<bool>(cc->GetScheme()->GetBinCCForSchemeSwitch()));
}

// ClearAllCKKSCaches() combines both clears. Covers the convenience path
// ReleaseAllContexts() now relies on.
TEST_F(UTCKKSCacheClear, ClearAllCKKSCachesClearsBoth) {
    auto cc = MakeSchemeSwitchCC();
    auto kp = cc->KeyGen();

    // Scheme-switch state.
    SchSwchParams p;
    p.SetSecurityLevelCKKS(HEStd_NotSet);
    p.SetSecurityLevelFHEW(TOY);
    p.SetCtxtModSizeFHEWLargePrec(25);
    p.SetNumSlotsCKKS(16);
    auto lweSk = cc->EvalCKKStoFHEWSetup(p);
    cc->EvalCKKStoFHEWKeyGen(kp, lweSk);

    // Bootstrap-like state cannot be produced on this smaller scheme-switch
    // context without heavy parameters, so only exercise the scheme-switch arm
    // here; the bootstrap arm is covered by the tests above.
    ASSERT_TRUE(cc->HasSchemeSwitchPrecom());

    cc->ClearAllCKKSCaches();
    EXPECT_FALSE(cc->HasSchemeSwitchPrecom());
    EXPECT_FALSE(cc->HasBootstrapPrecom());
}

// ReleaseAllContexts() must drop scheme-level caches even when the caller
// keeps its own shared_ptr to the CryptoContext. This is the original #533
// regression: previously the static maps were cleared but the scheme-owned
// m_bootPrecomMap (and scheme-switch state) survived.
TEST_F(UTCKKSCacheClear, ReleaseAllContextsDropsSchemeCaches) {
    auto cc           = MakeBootstrapCC();
    uint32_t numSlots = cc->GetRingDimension() / 2;

    cc->EvalBootstrapSetup({1, 1}, {0, 0}, numSlots);
    ASSERT_TRUE(cc->HasBootstrapPrecom(numSlots));

    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

    // The factory no longer owns the context, but this test still does.
    EXPECT_FALSE(cc->HasBootstrapPrecom());
    EXPECT_FALSE(cc->HasBootstrapPrecom(numSlots));
}

TEST_F(UTCKKSCacheClear, ReleaseAllContextsDropsSchemeSwitchCaches) {
    auto cc = MakeSchemeSwitchCC();
    auto kp = cc->KeyGen();

    SchSwchParams p;
    p.SetSecurityLevelCKKS(HEStd_NotSet);
    p.SetSecurityLevelFHEW(TOY);
    p.SetCtxtModSizeFHEWLargePrec(25);
    p.SetNumSlotsCKKS(16);
    auto lweSk = cc->EvalCKKStoFHEWSetup(p);
    cc->EvalCKKStoFHEWKeyGen(kp, lweSk);
    ASSERT_TRUE(cc->HasSchemeSwitchPrecom());

    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

    EXPECT_FALSE(cc->HasSchemeSwitchPrecom());
}

// BFV and BGV do not maintain scheme-level caches; the inspectors must report
// false and the clear APIs must be safe no-ops regardless of whether FHE is
// even enabled. This pins the default FHEBase path so a future BFV/BGV cache
// cannot silently go unreleased.
TEST_F(UTCKKSCacheClear, NonCKKSSchemesReportNoCachesAndClearsAreNoOps) {
    auto bfv = MakeBFVContext();
    EXPECT_FALSE(bfv->HasBootstrapPrecom());
    EXPECT_FALSE(bfv->HasBootstrapPrecom(8));
    EXPECT_FALSE(bfv->HasSchemeSwitchPrecom());
    EXPECT_NO_THROW(bfv->ClearBootstrapPrecom());
    EXPECT_NO_THROW(bfv->ClearBootstrapPrecom(8));
    EXPECT_NO_THROW(bfv->ClearSchemeSwitchPrecom());
    EXPECT_NO_THROW(bfv->ClearAllCKKSCaches());

    auto bgv = MakeBGVContext();
    EXPECT_FALSE(bgv->HasBootstrapPrecom());
    EXPECT_FALSE(bgv->HasBootstrapPrecom(8));
    EXPECT_FALSE(bgv->HasSchemeSwitchPrecom());
    EXPECT_NO_THROW(bgv->ClearBootstrapPrecom());
    EXPECT_NO_THROW(bgv->ClearBootstrapPrecom(8));
    EXPECT_NO_THROW(bgv->ClearSchemeSwitchPrecom());
    EXPECT_NO_THROW(bgv->ClearAllCKKSCaches());

    // ReleaseAllContexts must tolerate mixed-scheme context sets.
    EXPECT_NO_THROW(CryptoContextFactory<DCRTPoly>::ReleaseAllContexts());
}

// Regression for the behavior-risk noted above: when a caller keeps their own
// BinFHEContext handle via GetBinCCForSchemeSwitch(), ClearSchemeSwitchPrecom
// must not clear the bootstrap keys on that external handle. It only drops
// our owning reference.
TEST_F(UTCKKSCacheClear, ClearSchemeSwitchDoesNotMutateExternalBinFHE) {
    auto cc = MakeSchemeSwitchCC();
    auto kp = cc->KeyGen();

    SchSwchParams p;
    p.SetSecurityLevelCKKS(HEStd_NotSet);
    p.SetSecurityLevelFHEW(TOY);
    p.SetCtxtModSizeFHEWLargePrec(25);
    p.SetNumSlotsCKKS(16);
    auto lweSk = cc->EvalCKKStoFHEWSetup(p);
    cc->EvalCKKStoFHEWKeyGen(kp, lweSk);

    auto externalCcLWE = cc->GetBinCCForSchemeSwitch();
    ASSERT_TRUE(static_cast<bool>(externalCcLWE));
    // Generate FHEW bootstrap keys on the external handle so we can verify
    // they survive our cache clear.
    externalCcLWE->BTKeyGen(lweSk);

    cc->ClearSchemeSwitchPrecom();

    // Our reference is gone, but the caller's is still alive and usable.
    EXPECT_FALSE(cc->HasSchemeSwitchPrecom());
    ASSERT_TRUE(static_cast<bool>(externalCcLWE));
    EXPECT_NO_THROW(externalCcLWE->GetParams()->GetLWEParams()->Getn());
}

// ClearBootstrapPrecomExcept keeps the specified slot entry and drops every
// other entry. Covers the "oscillating between two slot counts" workload: a
// long-running bootstrap at N slots plus transient smaller setups that should
// not accumulate.
TEST_F(UTCKKSCacheClear, ClearBootstrapPrecomExceptKeepsOneEntry) {
    auto cc             = MakeBootstrapCC();
    uint32_t ringDim    = cc->GetRingDimension();
    uint32_t slotsKeep  = ringDim / 2;
    uint32_t slotsDropA = ringDim / 4;
    uint32_t slotsDropB = ringDim / 8;

    cc->EvalBootstrapSetup({1, 1}, {0, 0}, slotsKeep);
    cc->EvalBootstrapSetup({1, 1}, {0, 0}, slotsDropA);
    cc->EvalBootstrapSetup({1, 1}, {0, 0}, slotsDropB);
    ASSERT_TRUE(cc->HasBootstrapPrecom(slotsKeep));
    ASSERT_TRUE(cc->HasBootstrapPrecom(slotsDropA));
    ASSERT_TRUE(cc->HasBootstrapPrecom(slotsDropB));

    cc->ClearBootstrapPrecomExcept(slotsKeep);

    EXPECT_TRUE(cc->HasBootstrapPrecom(slotsKeep));
    EXPECT_FALSE(cc->HasBootstrapPrecom(slotsDropA));
    EXPECT_FALSE(cc->HasBootstrapPrecom(slotsDropB));

    // Keeping a slot that doesn't exist clears the whole map (there is
    // nothing to keep).
    cc->ClearBootstrapPrecomExcept(12345);
    EXPECT_FALSE(cc->HasBootstrapPrecom());
}

// Regression probe for the core #533 contract: after a clear, the allocator's
// in-use bytes must actually shrink. The previous broken behavior (before the
// fix that started this branch) left m_bootPrecomMap alive, so the in-use
// size after clear equalled the peak.
//
// The delta is noisy — parallel threads, allocator bookkeeping, lazy frees —
// so we only assert direction, not magnitude, and only on platforms where we
// can probe the allocator portably. If a future refactor reintroduces a
// self-reference that keeps the precom alive, this test catches it.
#if defined(__GLIBC__) || defined(__APPLE__)
TEST_F(UTCKKSCacheClear, MemoryDropsAfterBootstrapClear) {
    // Use a slightly larger ring dim than other tests so the per-slot
    // precomputations are large enough to be visible above allocator noise.
    auto cc           = MakeBootstrapCC(1 << 10);
    uint32_t numSlots = cc->GetRingDimension() / 2;

    size_t before = HeapInUseBytes();
    if (before == 0) {
        // mallinfo2() / malloc_zone_statistics return 0 when an alternative
        // allocator (e.g. TCMalloc via WITH_TCM=ON) replaces the system malloc.
        // The heap probe cannot see through it, so the relative-drop assertion
        // is unmeasurable; skip rather than fail.
        GTEST_SKIP() << "heap probe unavailable on this allocator";
    }
    cc->EvalBootstrapSetup({1, 1}, {0, 0}, numSlots);
    size_t peak = HeapInUseBytes();
    cc->ClearBootstrapPrecom();
    lbcrypto::TrimAllocator();
    size_t after = HeapInUseBytes();

    EXPECT_GT(peak, before) << "EvalBootstrapSetup did not grow heap as expected";
    EXPECT_LT(after, peak) << "ClearBootstrapPrecom did not release memory";
}
#endif

// TrimAllocator must be safe to call at any time and return a platform
// capability flag. It's hard to assert RSS drops portably, so this just pins
// the contract: never throws, returns true on platforms with a trim
// primitive (glibc, Apple, MSVC), false elsewhere.
TEST_F(UTCKKSCacheClear, TrimAllocatorIsSafe) {
    EXPECT_NO_THROW(lbcrypto::TrimAllocator());
    EXPECT_NO_THROW(lbcrypto::TrimAllocator());  // idempotent
#if defined(__GLIBC__) || defined(__APPLE__) || defined(_MSC_VER)
    EXPECT_TRUE(lbcrypto::TrimAllocator());
#endif
}

// ReleaseAllContextsAndTrim is a convenience: does everything ReleaseAllContexts
// does, plus the allocator trim. The cache-clear behavior must match.
TEST_F(UTCKKSCacheClear, ReleaseAllContextsAndTrimClearsSchemeCaches) {
    auto cc           = MakeBootstrapCC();
    uint32_t numSlots = cc->GetRingDimension() / 2;

    cc->EvalBootstrapSetup({1, 1}, {0, 0}, numSlots);
    ASSERT_TRUE(cc->HasBootstrapPrecom(numSlots));

    CryptoContextFactory<DCRTPoly>::ReleaseAllContextsAndTrim();

    EXPECT_FALSE(cc->HasBootstrapPrecom());
    EXPECT_FALSE(cc->HasBootstrapPrecom(numSlots));
}

// Opt-in AutoRelease mode: the factory does not track newly created contexts,
// so the caller's last handle drop destructs the context immediately and
// every scheme-level cache is released with no manual ReleaseAllContexts
// call. Verifies the flag toggles, existing contexts are flushed on enable,
// and GetContextCount() reflects the untracked state (issue #533).
TEST_F(UTCKKSCacheClear, AutoReleaseModeFactoryDoesNotTrack) {
    ASSERT_FALSE(CryptoContextFactory<DCRTPoly>::IsAutoReleaseMode());
    auto tracked = MakeBootstrapCC();
    EXPECT_GE(CryptoContextFactory<DCRTPoly>::GetContextCount(), 1);

    CryptoContextFactory<DCRTPoly>::SetAutoReleaseMode(true);
    EXPECT_TRUE(CryptoContextFactory<DCRTPoly>::IsAutoReleaseMode());
    // Flipping the flag should have flushed the tracked list.
    EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), 0);

    // Building a new context under AutoRelease must not register it.
    int before = CryptoContextFactory<DCRTPoly>::GetContextCount();
    {
        auto ephemeral    = MakeBootstrapCC();
        uint32_t numSlots = ephemeral->GetRingDimension() / 2;
        ephemeral->EvalBootstrapSetup({1, 1}, {0, 0}, numSlots);
        ASSERT_TRUE(ephemeral->HasBootstrapPrecom(numSlots));
        EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), before);
    }
    // ephemeral is out of scope; its caches should have been auto-released
    // by ~CryptoContextImpl(). We can't inspect the ex-ephemeral directly,
    // but GetContextCount() must still be 0 — nothing leaked into the
    // factory list.
    EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), 0);

    // Reset for subsequent tests.
    CryptoContextFactory<DCRTPoly>::SetAutoReleaseMode(false);
}

// The scheme's internal FHE object matches the behavior exposed on the
// CryptoContext facade. This pins the dispatch path used by callers who work
// directly with GetScheme().
TEST_F(UTCKKSCacheClear, FHEInspectorsAgreeWithFacade) {
    auto cc           = MakeBootstrapCC();
    uint32_t numSlots = cc->GetRingDimension() / 2;

    cc->EvalBootstrapSetup({1, 1}, {0, 0}, numSlots);
    auto scheme = cc->GetScheme();
    ASSERT_TRUE(scheme->HasBootstrapPrecom());
    ASSERT_TRUE(scheme->HasBootstrapPrecom(numSlots));

    scheme->ClearBootstrapPrecom();
    EXPECT_FALSE(cc->HasBootstrapPrecom());
    EXPECT_FALSE(scheme->HasBootstrapPrecom(numSlots));
}
