// @file cryptocontext-null.h -- API to generate NULL crypto context.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT))
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef _CRYPTOCONTEXT_NULL_H_
#define _CRYPTOCONTEXT_NULL_H_

#include "scheme/null/cryptocontextparams-null.h"
#include "cryptocontext.h"

namespace lbcrypto {

template <typename Element>
class CryptoContextNULL {
    using ParmType = typename Element::Params;
    using IntType = typename Element::Integer;

public:
    using ContextType = CryptoContext<Element>; // required by GenCryptoContext() in gen-cryptocontext.h

    static CryptoContext<Element> genCryptoContext(const CCParams<CryptoContextNULL<Element>>& parameters) {
        auto ep = std::make_shared<ParmType>(parameters.GetCyclotomicOrder(),
                                             IntType(parameters.GetPlaintextModulus()),
                                             1);
        auto params = std::make_shared<LPCryptoParametersNull<Element>>(ep, parameters.GetPlaintextModulus());
        auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeNull<Element>>();
        auto cc = CryptoContextFactory<Element>::GetContext(params, scheme);
        cc->setSchemeId("CKKSNull");  // TODO: do we need this?? (dsuponit) we could just "return CryptoContextFactory<Element>::GetContext(params, schemeCKKS);"
        return cc;
    }
};

}  // namespace lbcrypto

#endif // _CRYPTOCONTEXT_NULL_H_

