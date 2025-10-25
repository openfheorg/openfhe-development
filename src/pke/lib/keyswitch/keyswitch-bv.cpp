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

#include "cryptocontext.h"
#include "key/evalkeyrelin.h"
#include "key/privatekey.h"
#include "key/publickey.h"
#include "keyswitch/keyswitch-bv.h"
#include "schemerns/rns-cryptoparameters.h"

namespace lbcrypto {

EvalKey<DCRTPoly> KeySwitchBV::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                    const PrivateKey<DCRTPoly> newKey) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(newKey->GetCryptoParameters());

    DugType dug;
    auto dgg = cryptoParams->GetDiscreteGaussianGenerator();

    const auto ns           = cryptoParams->GetNoiseScale();
    const auto& sNew        = newKey->GetPrivateElement();
    const auto& ep          = sNew.GetParams();
    const auto& sOld        = oldKey->GetPrivateElement();
    const uint32_t sizeSOld = sOld.GetNumOfElements();

    std::vector<DCRTPoly> av, bv;
    if (auto digitSize = cryptoParams->GetDigitSize(); digitSize > 0) {
        // creates an array of digits up to a certain tower
        std::vector<uint32_t> arrWindows(sizeSOld);
        uint32_t nWindows = 0;
        for (uint32_t i = 0; i < sizeSOld; ++i) {
            arrWindows[i]  = nWindows;
            double sOldMSB = sOld.GetElementAtIndex(i).GetModulus().GetMSB();
            nWindows += std::ceil(sOldMSB / digitSize);
        }

        av.resize(nWindows);
        bv.resize(nWindows);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeSOld)) private(dug, dgg)
        for (uint32_t i = 0; i < sizeSOld; ++i) {
            auto sOldDecomposed = sOld.GetElementAtIndex(i).PowersOfBase(digitSize);
            for (uint32_t j = arrWindows[i], k = 0; k < sOldDecomposed.size(); ++j, ++k) {
                av[j] = DCRTPoly(dug, ep, Format::EVALUATION);
                bv[j] = DCRTPoly(ep, Format::EVALUATION, true);
                bv[j].SetElementAtIndex(i, std::move(sOldDecomposed[k]));
                bv[j] -= (av[j] * sNew + DCRTPoly(dgg, ep, Format::EVALUATION) * ns);
            }
        }
    }
    else {
        av.resize(sizeSOld);
        bv.resize(sizeSOld);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeSOld)) private(dug, dgg)
        for (uint32_t i = 0; i < sizeSOld; ++i) {
            av[i] = DCRTPoly(dug, ep, Format::EVALUATION);
            bv[i] = DCRTPoly(ep, Format::EVALUATION, true);
            bv[i].SetElementAtIndex(i, sOld.GetElementAtIndex(i));
            bv[i] -= (av[i] * sNew + DCRTPoly(dgg, ep, Format::EVALUATION) * ns);
        }
    }

    auto ek = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newKey->GetCryptoContext());
    ek->SetAVector(std::move(av));
    ek->SetBVector(std::move(bv));
    ek->SetKeyTag(newKey->GetKeyTag());
    return ek;
}

EvalKey<DCRTPoly> KeySwitchBV::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                    const PrivateKey<DCRTPoly> newKey,
                                                    const EvalKey<DCRTPoly> ek) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(oldKey->GetCryptoParameters());

    DugType dug;
    auto dgg = cryptoParams->GetDiscreteGaussianGenerator();

    const auto ns           = cryptoParams->GetNoiseScale();
    const auto& sNew        = newKey->GetPrivateElement();
    const auto& ep          = sNew.GetParams();
    const auto& sOld        = oldKey->GetPrivateElement();
    const uint32_t sizeSOld = sOld.GetNumOfElements();

    std::vector<DCRTPoly> av, bv;
    if (auto digitSize = cryptoParams->GetDigitSize(); digitSize > 0) {
        // creates an array of digits up to a certain tower
        std::vector<uint32_t> arrWindows(sizeSOld);
        uint32_t nWindows = 0;
        for (uint32_t i = 0; i < sizeSOld; ++i) {
            arrWindows[i]  = nWindows;
            double sOldMSB = sOld.GetElementAtIndex(i).GetModulus().GetMSB();
            nWindows += std::ceil(sOldMSB / digitSize);
        }

        av.resize(nWindows);
        bv.resize(nWindows);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeSOld)) private(dug, dgg)
        for (uint32_t i = 0; i < sizeSOld; ++i) {
            auto sOldDecomposed = sOld.GetElementAtIndex(i).PowersOfBase(digitSize);
            for (uint32_t j = arrWindows[i], k = 0; k < sOldDecomposed.size(); ++j, ++k) {
                av[j] = ek ? ek->GetAVector()[j] : DCRTPoly(dug, ep, Format::EVALUATION);
                bv[j] = DCRTPoly(ep, Format::EVALUATION, true);
                bv[j].SetElementAtIndex(i, std::move(sOldDecomposed[k]));
                bv[j] -= (av[j] * sNew + DCRTPoly(dgg, ep, Format::EVALUATION) * ns);
            }
        }
    }
    else {
        av.resize(sizeSOld);
        bv.resize(sizeSOld);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeSOld)) private(dug, dgg)
        for (uint32_t i = 0; i < sizeSOld; ++i) {
            av[i] = ek ? ek->GetAVector()[i] : DCRTPoly(dug, ep, Format::EVALUATION);
            bv[i] = DCRTPoly(ep, Format::EVALUATION, true);
            bv[i].SetElementAtIndex(i, sOld.GetElementAtIndex(i));
            bv[i] -= (av[i] * sNew + DCRTPoly(dgg, ep, Format::EVALUATION) * ns);
        }
    }

    auto evalKey = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newKey->GetCryptoContext());
    evalKey->SetAVector(std::move(av));
    evalKey->SetBVector(std::move(bv));
    evalKey->SetKeyTag(newKey->GetKeyTag());
    return evalKey;
}

EvalKey<DCRTPoly> KeySwitchBV::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldSk,
                                                    const PublicKey<DCRTPoly> newPk) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(newPk->GetCryptoParameters());

    TugType tug;
    auto dgg = cryptoParams->GetDiscreteGaussianGenerator();

    const auto ns           = cryptoParams->GetNoiseScale();
    const auto& newp0       = newPk->GetPublicElements().at(0);
    const auto& newp1       = newPk->GetPublicElements().at(1);
    const auto& ep          = newp0.GetParams();
    const auto& sOld        = oldSk->GetPrivateElement();
    const uint32_t sizeSOld = sOld.GetNumOfElements();

    std::vector<DCRTPoly> av, bv;
    if (uint32_t digitSize = cryptoParams->GetDigitSize(); digitSize > 0) {
        // creates an array of digits up to a certain tower
        std::vector<uint32_t> arrWindows(sizeSOld);
        uint32_t nWindows = 0;
        for (uint32_t i = 0; i < sizeSOld; ++i) {
            arrWindows[i]  = nWindows;
            double sOldMSB = sOld.GetElementAtIndex(i).GetModulus().GetMSB();
            nWindows += std::ceil(sOldMSB / digitSize);
        }

        av.resize(nWindows);
        bv.resize(nWindows);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeSOld)) private(tug, dgg)
        for (uint32_t i = 0; i < sizeSOld; ++i) {
            auto sOldDecomposed = sOld.GetElementAtIndex(i).PowersOfBase(digitSize);
            for (uint32_t j = arrWindows[i], k = 0; k < sOldDecomposed.size(); ++j, ++k) {
                bv[j] = DCRTPoly(ep, Format::EVALUATION, true);
                bv[j].SetElementAtIndex(i, std::move(sOldDecomposed[k]));
                bv[j] += DCRTPoly(dgg, ep, Format::EVALUATION) * ns;
                DCRTPoly u = (cryptoParams->GetSecretKeyDist() == GAUSSIAN) ? DCRTPoly(dgg, ep, Format::EVALUATION) :
                                                                              DCRTPoly(tug, ep, Format::EVALUATION);
                bv[j] += newp0 * u;
                av[j] = newp1 * u;
                av[j] += DCRTPoly(dgg, ep, Format::EVALUATION) * ns;
            }
        }
    }
    else {
        av.resize(sizeSOld);
        bv.resize(sizeSOld);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeSOld)) private(tug, dgg)
        for (uint32_t i = 0; i < sizeSOld; ++i) {
            bv[i] = DCRTPoly(ep, Format::EVALUATION, true);
            bv[i].SetElementAtIndex(i, sOld.GetElementAtIndex(i));
            bv[i] += DCRTPoly(dgg, ep, Format::EVALUATION) * ns;
            DCRTPoly u = (cryptoParams->GetSecretKeyDist() == GAUSSIAN) ? DCRTPoly(dgg, ep, Format::EVALUATION) :
                                                                          DCRTPoly(tug, ep, Format::EVALUATION);
            bv[i] += newp0 * u;
            av[i] = newp1 * u;
            av[i] += DCRTPoly(dgg, ep, Format::EVALUATION) * ns;
        }
    }

    auto ek = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newPk->GetCryptoContext());
    ek->SetAVector(std::move(av));
    ek->SetBVector(std::move(bv));
    ek->SetKeyTag(newPk->GetKeyTag());
    return ek;
}

void KeySwitchBV::KeySwitchInPlace(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> ek) const {
    auto& cv = ciphertext->GetElements();
    auto ba  = KeySwitchCore(cv.back(), ek);

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
    const auto diffQl    = bv[0].GetParams()->GetParams().size() - paramsQl->GetParams().size();
    const uint32_t limit = (*digits).size();
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(limit))
    for (uint32_t i = 0; i < limit; ++i) {
        bv[i].DropLastElements(diffQl);
        bv[i] *= (*digits)[i];
        av[i].DropLastElements(diffQl);
        av[i] *= (*digits)[i];
    }

    std::vector<DCRTPoly> res{std::move(bv[0]), std::move(av[0])};
    for (uint32_t i = 1; i < limit; ++i) {
        res[0] += bv[i];
        res[1] += av[i];
    }
    return std::make_shared<std::vector<DCRTPoly>>(std::move(res));
}

}  // namespace lbcrypto
