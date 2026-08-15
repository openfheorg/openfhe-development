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
#include "key/keypair.h"
#include "key/privatekey.h"
#include "key/publickey.h"
#include "schemebase/base-pke.h"
#include "schemebase/rlwe-cryptoparameters.h"

#include <memory>
#include <utility>
#include <vector>

namespace lbcrypto {

// makeSparse is not used by this scheme
template <class Element>
KeyPair<Element> PKEBase<Element>::KeyGenInternal(CryptoContext<Element> cc, bool makeSparse) const {
    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersRLWE<Element>>(cc->GetCryptoParameters());
    const auto elementParams = cryptoParams->GetElementParams();
    const auto paramsPK      = cryptoParams->GetParamsPK();
    if (!paramsPK)
        OPENFHE_THROW("PrecomputeCRTTables() must be called before using precomputed params.");

    // Private Key Generation

    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    TugType tug;

    Element s;
    switch (cryptoParams->GetSecretKeyDist()) {
        case GAUSSIAN:
            s = Element(dgg, paramsPK, Format::EVALUATION);
            break;
        case UNIFORM_TERNARY:
            s = Element(tug, paramsPK, Format::EVALUATION);
            break;
        case SPARSE_TERNARY:
        case SPARSE_ENCAPSULATED:
            // https://github.com/openfheorg/openfhe-development/issues/311
            s = Element(tug, paramsPK, Format::EVALUATION, 192);
            break;
        default:
            OPENFHE_THROW("Unknown SecretKeyDist.");
    }

    // Public Key Generation

    DugType dug;
    Element a(dug, paramsPK, Format::EVALUATION);

    Element e(dgg, paramsPK, Format::EVALUATION);
    NativeInteger ns = cryptoParams->GetNoiseScale();

    // b = ns * e - a * s
    Element b(std::move((e *= ns) -= (a * s)));

    auto sizeQ  = elementParams->GetParams().size();
    auto sizePK = paramsPK->GetParams().size();
    if (sizePK > sizeQ)
        s.DropLastElements(sizePK - sizeQ);

    KeyPair<Element> keyPair(std::make_shared<PublicKeyImpl<Element>>(cc),
                             std::make_shared<PrivateKeyImpl<Element>>(cc));
    keyPair.secretKey->SetPrivateElement(std::move(s));
    keyPair.publicKey->SetPublicElements({std::move(b), std::move(a)});
    keyPair.publicKey->SetKeyTag(keyPair.secretKey->GetKeyTag());
    return keyPair;
}

template <class Element>
Ciphertext<Element> PKEBase<Element>::Encrypt(Element plaintext, const PrivateKey<Element> privateKey) const {
    auto ba = EncryptZeroCore(privateKey, nullptr);
    (*ba)[0] += plaintext;

    auto ctxt = std::make_shared<CiphertextImpl<Element>>(privateKey);
    ctxt->SetElements(std::move(*ba));
    ctxt->SetNoiseScaleDeg(1);
    return ctxt;
}

template <class Element>
Ciphertext<Element> PKEBase<Element>::Encrypt(Element plaintext, const PublicKey<Element> publicKey) const {
    auto ba = EncryptZeroCore(publicKey, nullptr);
    (*ba)[0] += plaintext;

    auto ctxt = std::make_shared<CiphertextImpl<Element>>(publicKey);
    ctxt->SetElements(std::move(*ba));
    ctxt->SetNoiseScaleDeg(1);
    return ctxt;
}

// makeSparse is not used by this scheme
template <class Element>
std::shared_ptr<std::vector<Element>> PKEBase<Element>::EncryptZeroCore(const PrivateKey<Element> privateKey,
                                                                        const std::shared_ptr<ParmType> params) const {
    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersRLWE<Element>>(privateKey->GetCryptoParameters());
    const auto elementParams = (params == nullptr) ? cryptoParams->GetElementParams() : params;

    DugType dug;
    Element a(dug, elementParams, Format::EVALUATION);

    Element e(cryptoParams->GetDiscreteGaussianGenerator(), elementParams, Format::EVALUATION);
    NativeInteger ns = cryptoParams->GetNoiseScale();

    // {b = ns * e - a * s, a}
    Element b(std::move((e *= ns) -= (a * privateKey->GetPrivateElement())));

    return std::make_shared<std::vector<Element>>(std::initializer_list<Element>({std::move(b), std::move(a)}));
}

// makeSparse is not used by this scheme
template <class Element>
std::shared_ptr<std::vector<Element>> PKEBase<Element>::EncryptZeroCore(const PublicKey<Element> publicKey,
                                                                        const std::shared_ptr<ParmType> params) const {
    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersRLWE<Element>>(publicKey->GetCryptoParameters());

    const auto ns      = cryptoParams->GetNoiseScale();
    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    TugType tug;

    const std::shared_ptr<ParmType> elementParams = (params == nullptr) ? cryptoParams->GetElementParams() : params;

    const std::vector<Element>& pk = publicKey->GetPublicElements();

    Element p0 = pk[0];
    Element p1 = pk[1];

    uint32_t sizeQ  = elementParams->GetParams().size();
    uint32_t sizePK = p0.GetParams()->GetParams().size();

    if (sizePK > sizeQ) {
        p0.DropLastElements(sizePK - sizeQ);
        p1.DropLastElements(sizePK - sizeQ);
    }

    Element v = cryptoParams->GetSecretKeyDist() == GAUSSIAN ? Element(dgg, elementParams, Format::EVALUATION) :
                                                               Element(tug, elementParams, Format::EVALUATION);

    // noise generation with the discrete gaussian generator dgg
    Element e0(dgg, elementParams, Format::EVALUATION);
    Element e1(dgg, elementParams, Format::EVALUATION);

    Element b(elementParams);
    Element a(elementParams);

    b = p0 * v + ns * e0;
    a = p1 * v + ns * e1;

    return std::make_shared<std::vector<Element>>(std::initializer_list<Element>({std::move(b), std::move(a)}));
}

template <class Element>
Element PKEBase<Element>::DecryptCore(const std::vector<Element>& cv, const PrivateKey<Element> privateKey) const {
    const Element& s = privateKey->GetPrivateElement();

    Element sPower = s;
    Element b      = cv[0];
    b.SetFormat(Format::EVALUATION);

    Element ci;
    for (size_t i = 1; i < cv.size(); ++i) {
        ci = cv[i];
        ci.SetFormat(Format::EVALUATION);
        b.MultAccEqNoCheck(sPower, ci);
        sPower *= s;
    }

    return b;
}

}  // namespace lbcrypto

// the code below is from base-pke-impl.cpp
namespace lbcrypto {

template class PKEBase<DCRTPoly>;

}  // namespace lbcrypto
