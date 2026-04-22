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
  Releasing CKKS scheme-level memory without destroying the CryptoContext
  (issue #533).

  CKKS bootstrap caches (FHECKKSRNS::m_bootPrecomMap) and scheme-switch caches
  (SWITCHCKKSRNS: ccLWE, ccKS, switching keys, decoding-matrix plaintexts) are
  owned by the scheme, which lives as long as the CryptoContext. Before these
  APIs, the only way to free them was to drop every CryptoContext handle plus
  call CryptoContextFactory::ReleaseAllContexts() — if any caller kept a
  context ref alive, the caches survived.

  This example demonstrates the three common patterns:

    1. Clear one slot's bootstrap precom and reuse the context
    2. Clear all bootstrap precom except a hot slot count
    3. Full release + allocator trim at shutdown
*/

#include "openfhe.h"
#include "utils/memory.h"

#include <iostream>

using namespace lbcrypto;

static CryptoContext<DCRTPoly> BuildBootstrapContext() {
    CCParams<CryptoContextCKKSRNS> parameters;
    SecretKeyDist skDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(skDist);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12);

#if NATIVEINT == 128
    parameters.SetScalingModSize(78);
    parameters.SetFirstModSize(89);
    parameters.SetScalingTechnique(FIXEDAUTO);
#else
    parameters.SetScalingModSize(59);
    parameters.SetFirstModSize(60);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);
#endif

    std::vector<uint32_t> levelBudget = {4, 4};
    uint32_t depth = 10 + FHECKKSRNS::GetBootstrapDepth(levelBudget, skDist);
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
    uint32_t hotSlots = ringDim / 2;
    uint32_t tmpSlots = ringDim / 4;

    std::cout << "ring dim = " << ringDim << "\n";

    // Pattern 1: transient slot count, then clear just that entry.
    cc->EvalBootstrapSetup({4, 4}, {0, 0}, tmpSlots);
    std::cout << "after transient setup: "
              << "bootstrap cache present? " << std::boolalpha << cc->HasBootstrapPrecom(tmpSlots) << "\n";
    cc->ClearBootstrapPrecom(tmpSlots);
    std::cout << "after per-slot clear:   " << cc->HasBootstrapPrecom(tmpSlots) << "\n";

    // Pattern 2: hot-slot workload with occasional transient bootstraps.
    cc->EvalBootstrapSetup({4, 4}, {0, 0}, hotSlots);
    cc->EvalBootstrapSetup({4, 4}, {0, 0}, tmpSlots);
    std::cout << "with two entries, keep-except hot slots:\n";
    cc->ClearBootstrapPrecomExcept(hotSlots);
    std::cout << "  hot still present? " << cc->HasBootstrapPrecom(hotSlots) << "\n";
    std::cout << "  tmp gone?          " << !cc->HasBootstrapPrecom(tmpSlots) << "\n";

    // Pattern 3: shutdown — release everything and ask the allocator to
    // return pages to the OS. Useful right before a memory-sensitive phase
    // of the surrounding application (e.g. forking a child process).
    CryptoContextFactory<DCRTPoly>::ReleaseAllContextsAndTrim();
    // After this call, static eval-key maps are empty, every context's
    // scheme-level caches are released, and the allocator has been asked to
    // trim. `cc` is still a valid handle but its caches are gone.
    std::cout << "after ReleaseAllContextsAndTrim:\n";
    std::cout << "  cc bootstrap caches? " << cc->HasBootstrapPrecom() << "\n";

    return 0;
}
