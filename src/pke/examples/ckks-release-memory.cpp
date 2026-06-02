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
  Example for checking CKKS bootstrap memory cleanup.

  EvalBootstrapSetup() caches precomputed data in the CKKS scheme. This example
  compares ClearBootstrapPrecom() with ReleaseAllContexts() while keeping the
  local CryptoContext handle alive.
*/

#include "openfhe.h"
#include "utils/memory.h"

#include <iostream>

using namespace lbcrypto;

#include <cstddef>
#if defined(__GLIBC__)
    #include <malloc.h>
#elif defined(__APPLE__)
    #include <malloc/malloc.h>
#endif

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

static CryptoContext<DCRTPoly> BuildBootstrapContext() {
    CCParams<CryptoContextCKKSRNS> parameters;
    SecretKeyDist skDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(skDist);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12);

    parameters.SetScalingModSize(59);
    parameters.SetFirstModSize(60);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);

    std::vector<uint32_t> levelBudget = {4, 4};
    uint32_t depth                    = 10 + FHECKKSRNS::GetBootstrapDepth(levelBudget, skDist);
    parameters.SetMultiplicativeDepth(depth);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    return cc;
}

int main() {
    auto cc           = BuildBootstrapContext();
    uint32_t ringDim  = cc->GetRingDimension();
    uint32_t numSlots = ringDim / 2;

    std::cout << "ring dim = " << ringDim << "\n";

    size_t before = HeapInUseBytes();
    cc->EvalBootstrapSetup({4, 4}, {0, 0}, numSlots);
    size_t after = HeapInUseBytes();
    cc->ClearBootstrapPrecom();
    size_t after_cleanup = HeapInUseBytes();
    std::cerr << "EvalBootstrapSetup(): before: " << before << "; after: " << after
              << "; after ClearBootstrapPrecom(): " << after_cleanup << std::endl;

    before = HeapInUseBytes();
    cc->EvalBootstrapSetup({4, 4}, {0, 0}, numSlots);
    after = HeapInUseBytes();
    cc->ClearBootstrapPrecom();
    after_cleanup = HeapInUseBytes();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    size_t final = HeapInUseBytes();
    std::cerr << "EvalBootstrapSetup(): before: " << before << "; after: " << after
              << "; after ClearBootstrapPrecom(): " << after_cleanup << "; after ReleaseAllContexts(): " << final
              << std::endl;

    return 0;
}
