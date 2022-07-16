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
#include "schemebase/base-pke.h"
#include "schemebase/base-pre.h"

namespace lbcrypto {

template <class Element>
EvalKey<Element> PREBase<Element>::ReKeyGen(const PrivateKey<Element> oldPrivateKey,
                                            const PublicKey<Element> newPublicKey) const {
    auto algo = oldPrivateKey->GetCryptoContext()->GetScheme();
    return algo->KeySwitchGen(oldPrivateKey, newPublicKey);
}

template <class Element>
Ciphertext<Element> PREBase<Element>::ReEncrypt(ConstCiphertext<Element> ciphertext, const EvalKey<Element> evalKey,
                                                const PublicKey<Element> publicKey, usint noiseflooding) const {
    auto algo = ciphertext->GetCryptoContext()->GetScheme();

    Ciphertext<Element> result = ciphertext->Clone();
    if (publicKey != nullptr) {
        std::vector<Element>& cv                 = result->GetElements();
        std::shared_ptr<std::vector<Element>> ba = algo->EncryptZeroCore(publicKey);

        cv[0] += (*ba)[0];
        cv[1] += (*ba)[1];
    }

    algo->KeySwitchInPlace(result, evalKey);

    return result;
}

}  // namespace lbcrypto

// the code below is from base-pre-impl.cpp
namespace lbcrypto {

template class PREBase<DCRTPoly>;

}  // namespace lbcrypto
