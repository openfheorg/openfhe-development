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

/*
BFV implementation. See https://eprint.iacr.org/2021/204 for details.
 */

#define PROFILE

#include "cryptocontext.h"
#include "key/privatekey.h"
#include "key/publickey.h"
#include "scheme/bfvrns/bfvrns-cryptoparameters.h"
#include "scheme/bfvrns/bfvrns-pke.h"

namespace lbcrypto {

KeyPair<DCRTPoly> PKEBFVRNS::KeyGenInternal(CryptoContext<DCRTPoly> cc, bool makeSparse) {
    KeyPair<DCRTPoly> keyPair(std::make_shared<PublicKeyImpl<DCRTPoly>>(cc),
                              std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc));

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cc->GetCryptoParameters());

    std::shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        elementParams = cryptoParams->GetParamsQr();
    }
    const std::shared_ptr<ParmType> paramsPK = cryptoParams->GetParamsPK();

    const auto ns      = cryptoParams->GetNoiseScale();
    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    DugType dug;
    TugType tug;

    // Private Key Generation

    DCRTPoly s;
    switch (cryptoParams->GetSecretKeyDist()) {
        case GAUSSIAN:
            s = DCRTPoly(dgg, paramsPK, Format::EVALUATION);
            break;
        case UNIFORM_TERNARY:
            s = DCRTPoly(tug, paramsPK, Format::EVALUATION);
            break;
        case SPARSE_TERNARY:
            s = DCRTPoly(tug, paramsPK, Format::EVALUATION, 192);
            break;
        default:
            break;
    }

    // Public Key Generation

    DCRTPoly a(dug, paramsPK, Format::EVALUATION);
    DCRTPoly e(dgg, paramsPK, Format::EVALUATION);
    DCRTPoly b(ns * e - a * s);

    usint sizeQ  = elementParams->GetParams().size();
    usint sizePK = paramsPK->GetParams().size();
    if (sizePK > sizeQ) {
        s.DropLastElements(sizePK - sizeQ);
    }

    keyPair.secretKey->SetPrivateElement(std::move(s));
    keyPair.publicKey->SetPublicElements(std::vector<DCRTPoly>{std::move(b), std::move(a)});
    keyPair.publicKey->SetKeyTag(keyPair.secretKey->GetKeyTag());

    return keyPair;
}

Ciphertext<DCRTPoly> PKEBFVRNS::Encrypt(DCRTPoly ptxt, const PrivateKey<DCRTPoly> privateKey) const {
    Ciphertext<DCRTPoly> ciphertext(std::make_shared<CiphertextImpl<DCRTPoly>>(privateKey));

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(privateKey->GetCryptoParameters());

    const auto elementParams = cryptoParams->GetElementParams();
    auto encParams           = elementParams;

    std::vector<NativeInteger> tInvModq = cryptoParams->GettInvModq();
    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        encParams = cryptoParams->GetParamsQr();
        ptxt.SetFormat(Format::COEFFICIENT);
        Poly bigPtxt = ptxt.CRTInterpolate();
        DCRTPoly plain(bigPtxt, encParams);
        ptxt     = plain;
        tInvModq = cryptoParams->GettInvModqr();
    }
    ptxt.SetFormat(Format::COEFFICIENT);

    std::shared_ptr<std::vector<DCRTPoly>> ba = EncryptZeroCore(privateKey, encParams);

    NativeInteger NegQModt       = cryptoParams->GetNegQModt();
    NativeInteger NegQModtPrecon = cryptoParams->GetNegQModtPrecon();

    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        NegQModt       = cryptoParams->GetNegQrModt();
        NegQModtPrecon = cryptoParams->GetNegQrModtPrecon();
    }

    const NativeInteger t = cryptoParams->GetPlaintextModulus();

    ptxt.TimesQovert(encParams, tInvModq, t, NegQModt, NegQModtPrecon);
    ptxt.SetFormat(Format::EVALUATION);
    (*ba)[0] += ptxt;

    (*ba)[0].SetFormat(Format::COEFFICIENT);
    (*ba)[1].SetFormat(Format::COEFFICIENT);

    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        (*ba)[0].ScaleAndRoundPOverQ(elementParams, cryptoParams->GetrInvModq());
        (*ba)[1].ScaleAndRoundPOverQ(elementParams, cryptoParams->GetrInvModq());
    }

    (*ba)[0].SetFormat(Format::EVALUATION);
    (*ba)[1].SetFormat(Format::EVALUATION);

    ciphertext->SetElements({std::move((*ba)[0]), std::move((*ba)[1])});
    ciphertext->SetNoiseScaleDeg(1);

    return ciphertext;
}

Ciphertext<DCRTPoly> PKEBFVRNS::Encrypt(DCRTPoly ptxt, const PublicKey<DCRTPoly> publicKey) const {
    Ciphertext<DCRTPoly> ciphertext(std::make_shared<CiphertextImpl<DCRTPoly>>(publicKey));

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(publicKey->GetCryptoParameters());

    const auto elementParams = cryptoParams->GetElementParams();
    auto encParams           = elementParams;

    std::vector<NativeInteger> tInvModq = cryptoParams->GettInvModq();
    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        encParams = cryptoParams->GetParamsQr();
        ptxt.SetFormat(Format::COEFFICIENT);
        Poly bigPtxt = ptxt.CRTInterpolate();
        DCRTPoly plain(bigPtxt, encParams);
        ptxt     = plain;
        tInvModq = cryptoParams->GettInvModqr();
    }
    ptxt.SetFormat(Format::COEFFICIENT);

    std::shared_ptr<std::vector<DCRTPoly>> ba = EncryptZeroCore(publicKey, encParams);

    NativeInteger NegQModt       = cryptoParams->GetNegQModt();
    NativeInteger NegQModtPrecon = cryptoParams->GetNegQModtPrecon();

    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        NegQModt       = cryptoParams->GetNegQrModt();
        NegQModtPrecon = cryptoParams->GetNegQrModtPrecon();
    }

    const NativeInteger t = cryptoParams->GetPlaintextModulus();

    ptxt.TimesQovert(encParams, tInvModq, t, NegQModt, NegQModtPrecon);
    ptxt.SetFormat(Format::EVALUATION);
    (*ba)[0] += ptxt;

    (*ba)[0].SetFormat(Format::COEFFICIENT);
    (*ba)[1].SetFormat(Format::COEFFICIENT);

    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        (*ba)[0].ScaleAndRoundPOverQ(elementParams, cryptoParams->GetrInvModq());
        (*ba)[1].ScaleAndRoundPOverQ(elementParams, cryptoParams->GetrInvModq());
    }

    (*ba)[0].SetFormat(Format::EVALUATION);
    (*ba)[1].SetFormat(Format::EVALUATION);

    ciphertext->SetElements({std::move((*ba)[0]), std::move((*ba)[1])});
    ciphertext->SetNoiseScaleDeg(1);

    return ciphertext;
}

DecryptResult PKEBFVRNS::Decrypt(ConstCiphertext<DCRTPoly> ciphertext, const PrivateKey<DCRTPoly> privateKey,
                                 NativePoly* plaintext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(privateKey->GetCryptoParameters());

    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    DCRTPoly b                      = DecryptCore(cv, privateKey);
    b.SetFormat(Format::COEFFICIENT);

    size_t sizeQl = b.GetNumOfElements();

    // use RNS procedures only if the number of RNS limbs is larger than 1
    if (sizeQl > 1) {
        if (cryptoParams->GetMultiplicationTechnique() == HPS ||
            cryptoParams->GetMultiplicationTechnique() == HPSPOVERQ ||
            cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED) {
            *plaintext =
                b.ScaleAndRound(cryptoParams->GetPlaintextModulus(), cryptoParams->GettQHatInvModqDivqModt(),
                                cryptoParams->GettQHatInvModqDivqModtPrecon(), cryptoParams->GettQHatInvModqBDivqModt(),
                                cryptoParams->GettQHatInvModqBDivqModtPrecon(), cryptoParams->GettQHatInvModqDivqFrac(),
                                cryptoParams->GettQHatInvModqBDivqFrac());
        }
        else {
            *plaintext = b.ScaleAndRound(
                cryptoParams->GetModuliQ(), cryptoParams->GetPlaintextModulus(), cryptoParams->Gettgamma(),
                cryptoParams->GettgammaQHatInvModq(), cryptoParams->GettgammaQHatInvModqPrecon(),
                cryptoParams->GetNegInvqModtgamma(), cryptoParams->GetNegInvqModtgammaPrecon());
        }
    }
    else {
        const NativeInteger t = cryptoParams->GetPlaintextModulus();
        NativePoly element    = b.GetElementAtIndex(0);
        const NativeInteger q = element.GetModulus();
        element               = element.MultiplyAndRound(t, q);

        // Setting the root of unity to ONE as the calculation is expensive
        // It is assumed that no polynomial multiplications in evaluation
        // representation are performed after this
        element.SwitchModulus(t, 1, 0, 0);

        *plaintext = element;
    }

    return DecryptResult(plaintext->GetLength());
}

}  // namespace lbcrypto
