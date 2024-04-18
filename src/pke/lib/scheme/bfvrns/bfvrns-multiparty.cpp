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

#include "scheme/bfvrns/bfvrns-multiparty.h"

#include "key/privatekey.h"
#include "key/publickey.h"
#include "scheme/bfvrns/bfvrns-cryptoparameters.h"
#include "cryptocontext.h"
#include "ciphertext.h"

namespace lbcrypto {

// makeSparse is not used by this scheme
KeyPair<DCRTPoly> MultipartyBFVRNS::MultipartyKeyGen(CryptoContext<DCRTPoly> cc,
                                                     const std::vector<PrivateKey<DCRTPoly>>& privateKeyVec,
                                                     bool makeSparse) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());

    KeyPair<DCRTPoly> keyPair(std::make_shared<PublicKeyImpl<DCRTPoly>>(cc),
                              std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc));

    auto elementParams = cryptoParams->GetElementParams();
    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        elementParams = cryptoParams->GetParamsQr();
    }
    const auto ns = cryptoParams->GetNoiseScale();

    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    DugType dug;

    // Private Key Generation

    DCRTPoly s(elementParams, Format::EVALUATION, true);

    for (auto& pk : privateKeyVec) {
        const DCRTPoly& si = pk->GetPrivateElement();
        s += si;
    }

    // Public Key Generation
    DCRTPoly a(dug, elementParams, Format::EVALUATION);
    DCRTPoly e(dgg, elementParams, Format::EVALUATION);
    DCRTPoly b(ns * e - a * s);

    keyPair.secretKey->SetPrivateElement(std::move(s));
    keyPair.publicKey->SetPublicElements(std::vector<DCRTPoly>{std::move(b), std::move(a)});

    return keyPair;
}

KeyPair<DCRTPoly> MultipartyBFVRNS::MultipartyKeyGen(CryptoContext<DCRTPoly> cc, const PublicKey<DCRTPoly> publicKey,
                                                     bool makeSparse, bool fresh) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());

    KeyPair<DCRTPoly> keyPair(std::make_shared<PublicKeyImpl<DCRTPoly>>(cc),
                              std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc));

    auto elementParams = cryptoParams->GetElementParams();
    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        elementParams = cryptoParams->GetParamsQr();
    }
    const auto paramsPK = cryptoParams->GetParamsPK();

    const auto ns = cryptoParams->GetNoiseScale();

    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    TugType tug;

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

    const std::vector<DCRTPoly>& pk = publicKey->GetPublicElements();

    DCRTPoly a = pk[1];
    DCRTPoly e(dgg, paramsPK, Format::EVALUATION);

    // When PRE is not used, a joint key is computed
    DCRTPoly b = fresh ? (ns * e - a * s) : (ns * e - a * s + pk[0]);

    usint sizeQ  = elementParams->GetParams().size();
    usint sizePK = paramsPK->GetParams().size();
    if (sizePK > sizeQ) {
        s.DropLastElements(sizePK - sizeQ);
    }

    keyPair.secretKey->SetPrivateElement(std::move(s));
    keyPair.publicKey->SetPublicElements(std::vector<DCRTPoly>{std::move(b), std::move(a)});

    return keyPair;
}

DecryptResult MultipartyBFVRNS::MultipartyDecryptFusion(const std::vector<Ciphertext<DCRTPoly>>& ciphertextVec,
                                                        NativePoly* plaintext) const {
    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ciphertextVec[0]->GetCryptoParameters());

    const std::vector<DCRTPoly>& cv0 = ciphertextVec[0]->GetElements();

    DCRTPoly b = cv0[0];
    for (size_t i = 1; i < ciphertextVec.size(); i++) {
        const std::vector<DCRTPoly>& cvi = ciphertextVec[i]->GetElements();
        b += cvi[0];
    }

    size_t sizeQl = b.GetNumOfElements();

    const auto elementParams = cryptoParams->GetElementParams();
    size_t sizeQ = elementParams->GetParams().size();

    // use RNS procedures only if the number of RNS limbs is the same as for fresh ciphertexts
    if (sizeQl == sizeQ) {
        b.SetFormat(Format::COEFFICIENT);
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
    	// for the case when compress was called, we automatically reduce the polynomial to 1 RNS limb
        size_t diffQl = sizeQ - sizeQl;
        size_t levels = sizeQl - 1;
        for (size_t l = 0; l < levels; ++l) {
			b.DropLastElementAndScale(cryptoParams->GetQlQlInvModqlDivqlModq(diffQl + l),
										  cryptoParams->GetqlInvModq(diffQl + l));
        }

        b.SetFormat(Format::COEFFICIENT);

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
