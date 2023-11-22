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

/**
 * Implements BV scheme from [Fully Homomorphic Encryption from
    Ring-LWE and Security for Key Dependent Messages (BVScheme)](
    https://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf
    )
 *  see the Appendix of https://eprint.iacr.org/2021/204 for more details
 */
#define PROFILE

#include "keyswitch/keyswitch-bv.h"

#include "key/privatekey.h"
#include "key/publickey.h"
#include "key/evalkeyrelin.h"
#include "schemerns/rns-cryptoparameters.h"
#include "cryptocontext.h"

namespace lbcrypto {

EvalKey<DCRTPoly> KeySwitchBV::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                    const PrivateKey<DCRTPoly> newKey) const {
    EvalKeyRelin<DCRTPoly> ek(std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newKey->GetCryptoContext()));

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(newKey->GetCryptoParameters());

    const DCRTPoly& sNew = newKey->GetPrivateElement();
    auto elementParams   = sNew.GetParams();
    const DCRTPoly& sOld = oldKey->GetPrivateElement();

    const auto ns      = cryptoParams->GetNoiseScale();
    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    DugType dug;

    usint digitSize = cryptoParams->GetDigitSize();

    usint sizeSOld = sOld.GetNumOfElements();
    usint nWindows = 0;
    std::vector<usint> arrWindows;
    if (digitSize > 0) {
        // creates an array of digits up to a certain tower
        for (usint i = 0; i < sizeSOld; i++) {
            usint sOldMSB    = sOld.GetElementAtIndex(i).GetModulus().GetLengthForBase(2);
            usint curWindows = sOldMSB / digitSize;
            if (sOldMSB % digitSize > 0)
                curWindows++;
            arrWindows.push_back(nWindows);
            nWindows += curWindows;
        }
    }
    else {
        nWindows = sizeSOld;
    }

    std::vector<DCRTPoly> av(nWindows);
    std::vector<DCRTPoly> bv(nWindows);

    if (digitSize > 0) {
        for (usint i = 0; i < sOld.GetNumOfElements(); i++) {
            std::vector<DCRTPoly::PolyType> sOldDecomposed = sOld.GetElementAtIndex(i).PowersOfBase(digitSize);

            for (usint k = 0; k < sOldDecomposed.size(); k++) {
                DCRTPoly filtered(elementParams, Format::EVALUATION, true);
                filtered.SetElementAtIndex(i, sOldDecomposed[k]);

                DCRTPoly a(dug, elementParams, Format::EVALUATION);
                DCRTPoly e(dgg, elementParams, Format::EVALUATION);

                av[k + arrWindows[i]] = a;
                bv[k + arrWindows[i]] = filtered - (av[k + arrWindows[i]] * sNew + ns * e);
            }
        }
    }
    else {
        for (usint i = 0; i < sOld.GetNumOfElements(); i++) {
            DCRTPoly filtered(elementParams, Format::EVALUATION, true);
            filtered.SetElementAtIndex(i, sOld.GetElementAtIndex(i));

            DCRTPoly a(dug, elementParams, Format::EVALUATION);
            DCRTPoly e(dgg, elementParams, Format::EVALUATION);

            av[i] = a;
            bv[i] = filtered - (av[i] * sNew + ns * e);
        }
    }

    ek->SetAVector(std::move(av));
    ek->SetBVector(std::move(bv));
    ek->SetKeyTag(newKey->GetKeyTag());

    return ek;
}

EvalKey<DCRTPoly> KeySwitchBV::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                    const PrivateKey<DCRTPoly> newKey,
                                                    const EvalKey<DCRTPoly> ek) const {
    EvalKeyRelin<DCRTPoly> evalKey(std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newKey->GetCryptoContext()));

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(oldKey->GetCryptoParameters());

    const DCRTPoly& sNew = newKey->GetPrivateElement();
    auto elementParams   = sNew.GetParams();
    DCRTPoly sOld        = oldKey->GetPrivateElement();
    sOld.DropLastElements(oldKey->GetCryptoContext()->GetKeyGenLevel());

    const auto ns      = cryptoParams->GetNoiseScale();
    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    DugType dug;

    usint digitSize = cryptoParams->GetDigitSize();

    usint sizeSOld = sOld.GetNumOfElements();
    usint nWindows = 0;
    std::vector<usint> arrWindows;
    if (digitSize > 0) {
        // creates an array of digits up to a certain tower
        for (usint i = 0; i < sizeSOld; i++) {
            usint sOldMSB    = sOld.GetElementAtIndex(i).GetModulus().GetLengthForBase(2);
            usint curWindows = sOldMSB / digitSize;
            if (sOldMSB % digitSize > 0)
                curWindows++;
            arrWindows.push_back(nWindows);
            nWindows += curWindows;
        }
    }
    else {
        nWindows = sizeSOld;
    }

    std::vector<DCRTPoly> av(nWindows);
    std::vector<DCRTPoly> bv(nWindows);

    if (digitSize > 0) {
        for (usint i = 0; i < sizeSOld; i++) {
            std::vector<DCRTPoly::PolyType> sOldDecomposed = sOld.GetElementAtIndex(i).PowersOfBase(digitSize);

            for (usint k = 0; k < sOldDecomposed.size(); k++) {
                DCRTPoly filtered(elementParams, Format::EVALUATION, true);
                filtered.SetElementAtIndex(i, sOldDecomposed[k]);

                if (ek == nullptr) {  // single-key HE
                    // Generate a_i vectors
                    DCRTPoly a(dug, elementParams, Format::EVALUATION);
                    av[k + arrWindows[i]] = a;
                }
                else {  // threshold HE
                    av[k + arrWindows[i]] = ek->GetAVector()[k + arrWindows[i]];
                }

                DCRTPoly e(dgg, elementParams, Format::EVALUATION);
                bv[k + arrWindows[i]] = filtered - (av[k + arrWindows[i]] * sNew + ns * e);
            }
        }
    }
    else {
        for (usint i = 0; i < sizeSOld; i++) {
            DCRTPoly filtered(elementParams, Format::EVALUATION, true);
            filtered.SetElementAtIndex(i, sOld.GetElementAtIndex(i));

            if (ek == nullptr) {  // single-key HE
                // Generate a_i vectors
                DCRTPoly a(dug, elementParams, Format::EVALUATION);
                av[i] = a;
            }
            else {  // threshold HE
                av[i] = ek->GetAVector()[i];
            }

            DCRTPoly e(dgg, elementParams, Format::EVALUATION);
            bv[i] = filtered - (av[i] * sNew + ns * e);
        }
    }

    evalKey->SetAVector(std::move(av));
    evalKey->SetBVector(std::move(bv));
    evalKey->SetKeyTag(newKey->GetKeyTag());

    return evalKey;
}

EvalKey<DCRTPoly> KeySwitchBV::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldSk,
                                                    const PublicKey<DCRTPoly> newPk) const {
    EvalKeyRelin<DCRTPoly> ek = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newPk->GetCryptoContext());

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(newPk->GetCryptoParameters());

    const auto ns                = cryptoParams->GetNoiseScale();
    const DCRTPoly::DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    DCRTPoly::TugType tug;

    const DCRTPoly& sOld = oldSk->GetPrivateElement();

    std::vector<DCRTPoly> av;
    std::vector<DCRTPoly> bv;

    uint32_t digitSize = cryptoParams->GetDigitSize();

    const DCRTPoly& newp0 = newPk->GetPublicElements().at(0);
    const DCRTPoly& newp1 = newPk->GetPublicElements().at(1);
    auto elementParams    = newp0.GetParams();

    if (digitSize > 0) {
        for (usint i = 0; i < sOld.GetNumOfElements(); i++) {
            std::vector<DCRTPoly::PolyType> sOldDecomposed = sOld.GetElementAtIndex(i).PowersOfBase(digitSize);

            for (size_t k = 0; k < sOldDecomposed.size(); k++) {
                DCRTPoly filtered(elementParams, Format::EVALUATION, true);
                filtered.SetElementAtIndex(i, sOldDecomposed[k]);

                DCRTPoly u = (cryptoParams->GetSecretKeyDist() == GAUSSIAN) ?
                                 DCRTPoly(dgg, elementParams, Format::EVALUATION) :
                                 DCRTPoly(tug, elementParams, Format::EVALUATION);

                DCRTPoly e0(dgg, elementParams, Format::EVALUATION);
                DCRTPoly e1(dgg, elementParams, Format::EVALUATION);

                DCRTPoly c0 = newp0 * u + ns * e0 + filtered;
                DCRTPoly c1 = newp1 * u + ns * e1;

                av.push_back(std::move(c1));
                bv.push_back(std::move(c0));
            }
        }
    }
    else {
        for (usint i = 0; i < sOld.GetNumOfElements(); i++) {
            DCRTPoly filtered(elementParams, Format::EVALUATION, true);
            filtered.SetElementAtIndex(i, sOld.GetElementAtIndex(i));

            DCRTPoly u = (cryptoParams->GetSecretKeyDist() == GAUSSIAN) ?
                             DCRTPoly(dgg, elementParams, Format::EVALUATION) :
                             DCRTPoly(tug, elementParams, Format::EVALUATION);

            DCRTPoly e0(dgg, elementParams, Format::EVALUATION);
            DCRTPoly e1(dgg, elementParams, Format::EVALUATION);

            DCRTPoly c0 = newp0 * u + ns * e0 + filtered;
            DCRTPoly c1 = newp1 * u + ns * e1;

            av.push_back(std::move(c1));
            bv.push_back(std::move(c0));
        }
    }

    ek->SetAVector(std::move(av));
    ek->SetBVector(std::move(bv));
    ek->SetKeyTag(newPk->GetKeyTag());

    return ek;
}

void KeySwitchBV::KeySwitchInPlace(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> ek) const {
    std::vector<DCRTPoly>& cv = ciphertext->GetElements();

    std::shared_ptr<std::vector<DCRTPoly>> ba = (cv.size() == 2) ? KeySwitchCore(cv[1], ek) : KeySwitchCore(cv[2], ek);

    cv[0].SetFormat(Format::EVALUATION);
    cv[0] += (*ba)[0];

    if (cv.size() > 2) {
        cv[1].SetFormat(Format::EVALUATION);
        cv[1] += (*ba)[1];
    }
    else {
        cv[1] = (*ba)[1];
    }

    cv.resize(2);
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchBV::KeySwitchCore(const DCRTPoly& a,
                                                                  const EvalKey<DCRTPoly> evalKey) const {
    return EvalFastKeySwitchCore(EvalKeySwitchPrecomputeCore(a, evalKey->GetCryptoParameters()), evalKey,
                                 a.GetParams());
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchBV::EvalKeySwitchPrecomputeCore(
    const DCRTPoly& c, std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParamsBase) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoParamsBase);
    return std::make_shared<std::vector<DCRTPoly>>(c.CRTDecompose(cryptoParams->GetDigitSize()));
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchBV::EvalFastKeySwitchCore(
    const std::shared_ptr<std::vector<DCRTPoly>> digits, const EvalKey<DCRTPoly> evalKey,
    const std::shared_ptr<ParmType> paramsQl) const {
    std::vector<DCRTPoly> bv(evalKey->GetBVector());
    std::vector<DCRTPoly> av(evalKey->GetAVector());

    auto sizeQ    = bv[0].GetParams()->GetParams().size();
    auto sizeQl   = paramsQl->GetParams().size();
    size_t diffQl = sizeQ - sizeQl;

    for (size_t k = 0; k < bv.size(); k++) {
        av[k].DropLastElements(diffQl);
        bv[k].DropLastElements(diffQl);
    }

    DCRTPoly ct1 = (av[0] *= (*digits)[0]);
    DCRTPoly ct0 = (bv[0] *= (*digits)[0]);

    for (usint i = 1; i < (*digits).size(); ++i) {
        ct0 += (bv[i] *= (*digits)[i]);
        ct1 += (av[i] *= (*digits)[i]);
    }

    return std::make_shared<std::vector<DCRTPoly>>(std::initializer_list<DCRTPoly>{std::move(ct0), std::move(ct1)});
}

}  // namespace lbcrypto
