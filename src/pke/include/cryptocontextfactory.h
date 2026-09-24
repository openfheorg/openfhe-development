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

#ifndef SRC_PKE_INCLUDE_CRYPTOCONTEXTFACTORY_H_
#define SRC_PKE_INCLUDE_CRYPTOCONTEXTFACTORY_H_

#include <memory>
#include <string>
#include <vector>

#include "cryptocontext-fwd.h"
#include "lattice/lat-hal.h"
#include "scheme/scheme-id.h"
#include "utils/memory.h"

namespace lbcrypto {

template <typename Element>
class SchemeBase;
template <typename Element>
class CryptoParametersBase;

/**
 * @brief CryptoContextFactory
 *
 * A class that contains all generated contexts and static methods to access/release them.
 * Contexts are deduplicated: GetContext() returns the already registered context whose crypto parameters and
 * scheme compare equal to the requested ones, so keys and ciphertexts deserialized separately end up sharing
 * a single context instance.
 *
 * @tparam Element a ring element.
 */
template <typename Element>
class CryptoContextFactory {
    static std::vector<CryptoContext<Element>> AllContexts;

  protected:
    /**
   * Looks up a registered context with equal crypto parameters and scheme.
   * If found and the context uses packed encoding, the PackedEncoding parameters are (re)initialized for it.
   *
   * @param params crypto parameters to match (compared by value)
   * @param scheme scheme object to match (compared by value)
   * @return the matching registered context, or nullptr if there is none
   */
    static CryptoContext<Element> FindContext(std::shared_ptr<CryptoParametersBase<Element>> params,
                                              std::shared_ptr<SchemeBase<Element>> scheme);

    /**
   * Registers the given context and, if it uses packed encoding, initializes the PackedEncoding parameters
   * for it.
   */
    static void AddContext(CryptoContext<Element>);

  public:
    /**
   * Releases all registered contexts: clears their CKKS caches and the static evaluation-key maps, empties the
   * registry and returns freed memory to the system.
   */
    static void ReleaseAllContexts() {
        for (auto& cc : AllContexts) {
            if (cc)
                cc->ClearAllCKKSCaches();
        }
        if (!AllContexts.empty())
            AllContexts[0]->ClearStaticMapsAndVectors();
        AllContexts.clear();
        AllocTrim();
    }

    /**
   * Returns the number of registered contexts.
   *
   * @return the number of contexts currently held by the factory
   */
    static int GetContextCount() {
        return AllContexts.size();
    }

    /**
   * Returns the registered context with equal crypto parameters and scheme, creating and registering a new one
   * if none exists yet.
   *
   * @param params crypto parameters of the context
   * @param scheme scheme object of the context
   * @param schemeId scheme identifier stored in a newly created context (ignored if an existing one is found)
   * @return the shared context
   */
    static CryptoContext<Element> GetContext(std::shared_ptr<CryptoParametersBase<Element>> params,
                                             std::shared_ptr<SchemeBase<Element>> scheme,
                                             SCHEME schemeId = SCHEME::INVALID_SCHEME);

    /**
   * Returns the full registered context matching a (partial) context obtained by deserialization, registering
   * the deserialized context itself if no equal one exists. Callers that only include cryptocontext-fwd.h use
   * this instead of GetContext() to avoid circular dependencies.
   *
   * @param context the deserialized context
   * @return the registered context with the same crypto parameters, scheme and scheme identifier
   */
    static CryptoContext<Element> GetFullContextByDeserializedContext(const CryptoContext<Element> context);

    /**
   * Returns all registered contexts.
   *
   * @return reference to the vector of registered contexts
   */
    static const std::vector<CryptoContext<Element>>& GetAllContexts() {
        return AllContexts;
    }
};

template <>
std::vector<CryptoContext<DCRTPoly>> CryptoContextFactory<DCRTPoly>::AllContexts;

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_CRYPTOCONTEXTFACTORY_H_
