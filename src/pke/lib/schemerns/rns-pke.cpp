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
#include "schemerns/rns-pke.h"

#include "key/privatekey.h"
#include "key/publickey.h"
#include "cryptocontext.h"

namespace lbcrypto {

Ciphertext<DCRTPoly> PKERNS::Encrypt(DCRTPoly plaintext, const PrivateKey<DCRTPoly> privateKey) const {
    Ciphertext<DCRTPoly> ciphertext(std::make_shared<CiphertextImpl<DCRTPoly>>(privateKey));

    const std::shared_ptr<ParmType> ptxtParams = plaintext.GetParams();
    std::shared_ptr<std::vector<DCRTPoly>> ba  = EncryptZeroCore(privateKey, ptxtParams);

    plaintext.SetFormat(EVALUATION);

    (*ba)[0] += plaintext;

    ciphertext->SetElements({std::move((*ba)[0]), std::move((*ba)[1])});
    ciphertext->SetNoiseScaleDeg(1);

    return ciphertext;
}

Ciphertext<DCRTPoly> PKERNS::Encrypt(DCRTPoly plaintext, const PublicKey<DCRTPoly> publicKey) const {
    Ciphertext<DCRTPoly> ciphertext(std::make_shared<CiphertextImpl<DCRTPoly>>(publicKey));

    const std::shared_ptr<ParmType> ptxtParams = plaintext.GetParams();
    std::shared_ptr<std::vector<DCRTPoly>> ba  = EncryptZeroCore(publicKey, ptxtParams);

    plaintext.SetFormat(EVALUATION);

    (*ba)[0] += plaintext;

    ciphertext->SetElements({std::move((*ba)[0]), std::move((*ba)[1])});
    ciphertext->SetNoiseScaleDeg(1);

    return ciphertext;
}

DecryptResult PKERNS::Decrypt(ConstCiphertext<DCRTPoly> ciphertext, const PrivateKey<DCRTPoly> privateKey,
                              Poly* plaintext) const {
    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    DCRTPoly b                      = DecryptCore(cv, privateKey);

    b.SetFormat(Format::COEFFICIENT);
    size_t sizeQl = b.GetParams()->GetParams().size();

    if (sizeQl == 0)
        OPENFHE_THROW("Decryption failure: No towers left; consider increasing the depth.");

    if (sizeQl == 1) {
        *plaintext = Poly(b.GetElementAtIndex(0), Format::COEFFICIENT);
    }
    else {
        *plaintext = b.CRTInterpolate();
    }

    return DecryptResult(plaintext->GetLength());
}

DecryptResult PKERNS::Decrypt(ConstCiphertext<DCRTPoly> ciphertext, const PrivateKey<DCRTPoly> privateKey,
                              NativePoly* plaintext) const {
    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    DCRTPoly b                      = DecryptCore(cv, privateKey);

    b.SetFormat(Format::COEFFICIENT);
    const size_t sizeQl = b.GetParams()->GetParams().size();
    if (sizeQl != 1) {
        OPENFHE_THROW(
            "sizeQl " + std::to_string(sizeQl) +
            "!= 1. If sizeQl = 0, consider increasing the depth. If sizeQl > 1, check parameters (this is unsupported for NativePoly).");
    }

    *plaintext = b.GetElementAtIndex(0);

    return DecryptResult(plaintext->GetLength());
}

std::shared_ptr<std::vector<DCRTPoly>> PKERNS::EncryptZeroCore(const PrivateKey<DCRTPoly> privateKey,
                                                               const std::shared_ptr<ParmType> params) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(privateKey->GetCryptoParameters());

    const DCRTPoly& s  = privateKey->GetPrivateElement();
    const auto ns      = cryptoParams->GetNoiseScale();
    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    DugType dug;

    const std::shared_ptr<ParmType> elementParams = (params == nullptr) ? cryptoParams->GetElementParams() : params;

    DCRTPoly a(dug, elementParams, Format::EVALUATION);
    DCRTPoly e(dgg, elementParams, Format::EVALUATION);

    uint32_t sizeQ  = s.GetParams()->GetParams().size();
    uint32_t sizeQl = elementParams->GetParams().size();

    DCRTPoly c0, c1;
    if (sizeQl != sizeQ) {
        // Clone secret key because we need to drop towers.
        DCRTPoly scopy(s);

        uint32_t diffQl = sizeQ - sizeQl;
        scopy.DropLastElements(diffQl);

        c0 = a * scopy + ns * e;
        c1 = -a;
    }
    else {
        // Use secret key as is
        c0 = a * s + ns * e;
        c1 = -a;
    }

    return std::make_shared<std::vector<DCRTPoly>>(std::initializer_list<DCRTPoly>({std::move(c0), std::move(c1)}));
}

std::shared_ptr<std::vector<DCRTPoly>> PKERNS::EncryptZeroCore(const PublicKey<DCRTPoly> publicKey,
                                                               const std::shared_ptr<ParmType> params) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(publicKey->GetCryptoParameters());

    const std::vector<DCRTPoly>& pk = publicKey->GetPublicElements();
    const auto ns                   = cryptoParams->GetNoiseScale();
    const DggType& dgg              = cryptoParams->GetDiscreteGaussianGenerator();

    TugType tug;

    const std::shared_ptr<ParmType> elementParams = (params == nullptr) ? cryptoParams->GetElementParams() : params;
    // TODO (dsuponit): "tug" must be assigned with TernaryUniformGenerator. Otherwise the DCRTPoly constructor crashes.
    // check other files if "tug" is properly assigned
    // if (cryptoParams->GetSecretKeyDist() != GAUSSIAN) {
    //    OPENFHE_THROW("TugType tug must be assigned");
    //}
    DCRTPoly v = cryptoParams->GetSecretKeyDist() == GAUSSIAN ? DCRTPoly(dgg, elementParams, Format::EVALUATION) :
                                                                DCRTPoly(tug, elementParams, Format::EVALUATION);

    // noise generation with the discrete gaussian generator dgg
    DCRTPoly e0(dgg, elementParams, Format::EVALUATION);
    DCRTPoly e1(dgg, elementParams, Format::EVALUATION);

    uint32_t sizeQ  = pk[0].GetParams()->GetParams().size();
    uint32_t sizeQl = elementParams->GetParams().size();

    DCRTPoly c0, c1;
    if (sizeQl != sizeQ) {
        // Clone public keys because we need to drop towers.
        DCRTPoly p0 = pk[0].Clone();
        DCRTPoly p1 = pk[1].Clone();

        uint32_t diffQl = sizeQ - sizeQl;
        p0.DropLastElements(diffQl);
        p1.DropLastElements(diffQl);

        c0 = p0 * v + ns * e0;
        c1 = p1 * v + ns * e1;
    }
    else {
        // Use public keys as they are
        const DCRTPoly& p0 = pk[0];
        const DCRTPoly& p1 = pk[1];

        c0 = p0 * v + ns * e0;
        c1 = p1 * v + ns * e1;
    }

    return std::make_shared<std::vector<DCRTPoly>>(std::initializer_list<DCRTPoly>({std::move(c0), std::move(c1)}));
}

DCRTPoly PKERNS::DecryptCore(const std::vector<DCRTPoly>& cv, const PrivateKey<DCRTPoly> privateKey) const {
    const DCRTPoly& s = privateKey->GetPrivateElement();

    size_t sizeQ  = s.GetParams()->GetParams().size();
    size_t sizeQl = cv[0].GetParams()->GetParams().size();

    size_t diffQl = sizeQ - sizeQl;

    auto scopy(s);
    scopy.DropLastElements(diffQl);

    DCRTPoly sPower(scopy);

    DCRTPoly b(cv[0]);
    b.SetFormat(Format::EVALUATION);

    DCRTPoly ci;
    for (size_t i = 1; i < cv.size(); i++) {
        ci = cv[i];
        ci.SetFormat(Format::EVALUATION);

        b += sPower * ci;
        sPower *= scopy;
    }
    return b;
}

}  // namespace lbcrypto
