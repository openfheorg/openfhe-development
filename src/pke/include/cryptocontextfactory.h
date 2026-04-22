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

#ifndef SRC_PKE_CRYPTOCONTEXTFACTORY_H_
#define SRC_PKE_CRYPTOCONTEXTFACTORY_H_

#include "cryptocontext-fwd.h"
#include "lattice/lat-hal.h"
#include "scheme/scheme-id.h"
#include "utils/memory.h"

#include <memory>
#include <string>
#include <vector>

namespace lbcrypto {

template <typename Element>
class SchemeBase;
template <typename Element>
class CryptoParametersBase;

/**
 * @brief CryptoContextFactory
 *
 * A class that contains all generated contexts and static methods to access/release them
 */
template <typename Element>
class CryptoContextFactory {
    static std::vector<CryptoContext<Element>> AllContexts;
    // When AutoReleaseMode is true, newly built contexts are NOT tracked in
    // AllContexts. Dropping the caller's last handle then runs the context
    // destructor immediately, which releases every scheme-level cache and
    // static eval-key ref without needing a manual ReleaseAllContexts call
    // (issue #533). Default is false to preserve pre-fix semantics.
    static bool s_autoReleaseMode;

protected:
    static CryptoContext<Element> FindContext(std::shared_ptr<CryptoParametersBase<Element>> params,
                                              std::shared_ptr<SchemeBase<Element>> scheme);
    static void AddContext(CryptoContext<Element>);

public:
    /**
     * Enable or disable AutoRelease mode. When enabled, the factory no longer
     * holds a strong reference to newly created contexts; the caller becomes
     * the sole owner and cache memory is reclaimed automatically when they
     * drop the last reference. Existing tracked contexts are released when
     * the switch is flipped so the behavior is consistent (issue #533).
     *
     * Trade-off: FindContext / GetContext deduplication only inspects the
     * tracked list, so two identical parameter sets created in AutoRelease
     * mode will produce two distinct contexts instead of aliasing. Enable
     * this only if you don't rely on factory-level deduplication.
     */
    static void SetAutoReleaseMode(bool enabled) {
        if (enabled && !AllContexts.empty()) {
            // Flush tracked contexts so the semantics are consistent: from
            // now on, no context is tracked by the factory.
            ReleaseAllContexts();
        }
        s_autoReleaseMode = enabled;
    }

    static bool IsAutoReleaseMode() noexcept {
        return s_autoReleaseMode;
    }


    static void ReleaseAllContexts() {
        // Drop scheme-level caches (bootstrap + scheme-switch) on every live
        // context before clearing the static maps. This ensures memory held
        // by FHECKKSRNS::m_bootPrecomMap and SWITCHCKKSRNS state is freed
        // even when users still hold CryptoContext shared pointers after
        // this call returns (issue #533).
        for (auto& cc : AllContexts) {
            if (cc)
                cc->ClearAllCKKSCaches();
        }
        if (AllContexts.size() > 0)
            AllContexts[0]->ClearStaticMapsAndVectors();
        AllContexts.clear();
    }

    /**
     * Release every live context's scheme-level caches, clear the static key
     * maps, and ask the C allocator to return freed pages to the OS. Behaves
     * like ReleaseAllContexts() followed by TrimAllocator() (issue #533).
     *
     * Use this when heap usage drops after clearing but RSS doesn't — the C
     * allocator is holding freed pages in its arena. On platforms without a
     * trim primitive (non-glibc Linux, FreeBSD, WASM), this degrades into the
     * plain ReleaseAllContexts() path.
     */
    static void ReleaseAllContextsAndTrim() {
        ReleaseAllContexts();
        TrimAllocator();
    }

    static int GetContextCount() {
        return AllContexts.size();
    }

    static CryptoContext<Element> GetContext(std::shared_ptr<CryptoParametersBase<Element>> params,
                                             std::shared_ptr<SchemeBase<Element>> scheme,
                                             SCHEME schemeId = SCHEME::INVALID_SCHEME);

    // GetFullContextByDeserializedContext() is to get the full cryptocontext based on partial information
    // we usually get from a de-serialized cryptocontext object. Using this function instead of GetContext()
    // allows to avoid circular dependencies in some places by including cryptocontext-fwd.h
    static CryptoContext<Element> GetFullContextByDeserializedContext(const CryptoContext<Element> context);

    static const std::vector<CryptoContext<Element>>& GetAllContexts() {
        return AllContexts;
    }
};

template <>
std::vector<CryptoContext<DCRTPoly>> CryptoContextFactory<DCRTPoly>::AllContexts;

template <>
bool CryptoContextFactory<DCRTPoly>::s_autoReleaseMode;

}  // namespace lbcrypto

#endif
