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

protected:
    static CryptoContext<Element> FindContext(std::shared_ptr<CryptoParametersBase<Element>> params,
                                              std::shared_ptr<SchemeBase<Element>> scheme);
    static void AddContext(CryptoContext<Element>);

public:
    static void ReleaseAllContexts() {
        AllContexts.clear();
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

}  // namespace lbcrypto

#endif
