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
#include "cryptocontextfactory.h"
#include "schemebase/base-scheme.h"
#include "scheme/scheme-id.h"

namespace lbcrypto {

template <>
std::vector<CryptoContext<DCRTPoly>> CryptoContextFactory<DCRTPoly>::AllContexts = {};

template <typename Element>
CryptoContext<Element> CryptoContextFactory<Element>::FindContext(std::shared_ptr<CryptoParametersBase<Element>> params,
                                                                  std::shared_ptr<SchemeBase<Element>> scheme) {
    for (CryptoContext<Element> cc : CryptoContextFactory<Element>::AllContexts) {
        if (*cc->GetScheme().get() == *scheme.get() && *cc->GetCryptoParameters().get() == *params.get()) {
            if (cc->GetEncodingParams()->GetPlaintextRootOfUnity() != 0) {
                PackedEncoding::SetParams(cc->GetCyclotomicOrder(), cc->GetEncodingParams());
            }
            return cc;
        }
    }

    return nullptr;
}

template <typename Element>
void CryptoContextFactory<Element>::AddContext(CryptoContext<Element> cc) {
    CryptoContextFactory<Element>::AllContexts.push_back(cc);

    if (cc->GetEncodingParams()->GetPlaintextRootOfUnity() != 0) {
        PackedEncoding::SetParams(cc->GetCyclotomicOrder(), cc->GetEncodingParams());
    }
}

template <typename Element>
CryptoContext<Element> CryptoContextFactory<Element>::GetContext(std::shared_ptr<CryptoParametersBase<Element>> params,
                                                                 std::shared_ptr<SchemeBase<Element>> scheme,
                                                                 SCHEME schemeId) {
    CryptoContext<Element> cc = FindContext(params, scheme);
    // if the context is not found we should create one
    if (nullptr == cc) {
        cc = std::make_shared<CryptoContextImpl<Element>>(params, scheme, schemeId);
        AddContext(cc);
    }

    return cc;
}

template <typename Element>
CryptoContext<Element> CryptoContextFactory<Element>::GetFullContextByDeserializedContext(
    const CryptoContext<Element> context) {
    return CryptoContextFactory<Element>::GetContext(context->GetCryptoParameters(), context->GetScheme(),
                                                     context->getSchemeId());
}

}  // namespace lbcrypto

// the code below is from pke/lib/cryptocontextfactory-impl.cpp
namespace lbcrypto {

template class CryptoContextFactory<DCRTPoly>;

}
