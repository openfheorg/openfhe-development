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

#include "ciphertext.h"
#include "key/evalkeyrelin.h"
#include "key/privatekey.h"
#include "key/publickey.h"
#include "keyswitch/keyswitch-bv.h"
#include "schemerns/rns-cryptoparameters.h"

namespace lbcrypto {

EvalKey<DCRTPoly> KeySwitchBV::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                    const PrivateKey<DCRTPoly> newKey, uint32_t levels) const {
    return KeySwitchBV::KeySwitchGenInternal(oldKey, newKey, nullptr, levels);
}

EvalKey<DCRTPoly> KeySwitchBV::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                    const PrivateKey<DCRTPoly> newKey, const EvalKey<DCRTPoly> ek,
                                                    uint32_t levels) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(oldKey->GetCryptoParameters());

    DugType dug;
    auto dgg = cryptoParams->GetDiscreteGaussianGenerator();

    const auto ns        = cryptoParams->GetNoiseScale();
    const auto& sNew     = newKey->GetPrivateElement();
    const auto& sOld     = oldKey->GetPrivateElement();
    const uint32_t sizeQ = sOld.GetNumOfElements();

    if (levels >= sizeQ)
        OPENFHE_THROW("levels [" + std::to_string(levels) + "] must be smaller than the number of RNS limbs [" +
                      std::to_string(sizeQ) + "]");

    // the key is generated over the basis of Q with the last `levels` limbs dropped
    const uint32_t sizeKeyQ  = sizeQ - levels;
    const DCRTPoly sNewClone = (levels == 0) ? DCRTPoly() : sNew.CloneTowers(0, sizeKeyQ - 1);
    const DCRTPoly& sNewKey  = (levels == 0) ? sNew : sNewClone;
    const auto& ep           = sNewKey.GetParams();

    if (ek != nullptr && ek->GetAVector()[0].GetNumOfElements() != sizeKeyQ)
        OPENFHE_THROW("the number of RNS limbs in the input evaluation key does not match the requested levels");

    std::vector<DCRTPoly> av, bv;
    if (auto digitSize = cryptoParams->GetDigitSize(); digitSize > 0) {
        // creates an array of digits up to a certain tower
        std::vector<uint32_t> arrWindows(sizeKeyQ);
        uint32_t nWindows = 0;
        for (uint32_t i = 0; i < sizeKeyQ; ++i) {
            arrWindows[i]  = nWindows;
            double sOldMSB = sOld.GetElementAtIndex(i).GetModulus().GetMSB();
            nWindows += std::ceil(sOldMSB / digitSize);
        }

        av.resize(nWindows);
        bv.resize(nWindows);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeKeyQ)) private(dug, dgg)
        for (uint32_t i = 0; i < sizeKeyQ; ++i) {
            auto sOldDecomposed = sOld.GetElementAtIndex(i).PowersOfBase(digitSize);
            for (uint32_t j = arrWindows[i], k = 0; k < sOldDecomposed.size(); ++j, ++k) {
                av[j] = ek ? ek->GetAVector()[j] : DCRTPoly(dug, ep, Format::EVALUATION);
                bv[j] = DCRTPoly(ep, Format::EVALUATION, true);
                bv[j].SetElementAtIndex(i, std::move(sOldDecomposed[k]));
                bv[j] -= (av[j] * sNewKey + DCRTPoly(dgg, ep, Format::EVALUATION) * ns);
            }
        }
    }
    else {
        av.resize(sizeKeyQ);
        bv.resize(sizeKeyQ);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeKeyQ)) private(dug, dgg)
        for (uint32_t i = 0; i < sizeKeyQ; ++i) {
            av[i] = ek ? ek->GetAVector()[i] : DCRTPoly(dug, ep, Format::EVALUATION);
            bv[i] = DCRTPoly(ep, Format::EVALUATION, true);
            bv[i].SetElementAtIndex(i, sOld.GetElementAtIndex(i));
            bv[i] -= (av[i] * sNewKey + DCRTPoly(dgg, ep, Format::EVALUATION) * ns);
        }
    }

    auto evalKey = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newKey->GetCryptoContext());
    evalKey->SetAVector(std::move(av));
    evalKey->SetBVector(std::move(bv));
    evalKey->SetKeyTag(newKey->GetKeyTag());
    return evalKey;
}

EvalKey<DCRTPoly> KeySwitchBV::CompressEvalKey(const EvalKey<DCRTPoly> evalKey, uint32_t levels) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(evalKey->GetCryptoParameters());

    const auto& av       = evalKey->GetAVector();
    const auto& bv       = evalKey->GetBVector();
    const uint32_t sizeQ = av[0].GetNumOfElements();

    if (levels >= sizeQ)
        OPENFHE_THROW("levels [" + std::to_string(levels) +
                      "] must be smaller than the number of RNS limbs in the evaluation key [" +
                      std::to_string(sizeQ) + "]");
    const uint32_t sizeKeyQ = sizeQ - levels;

    // number of digits that correspond to the first sizeKeyQ towers
    uint32_t numDigits = sizeKeyQ;
    if (auto digitSize = cryptoParams->GetDigitSize(); digitSize > 0) {
        numDigits = 0;
        for (uint32_t i = 0; i < sizeKeyQ; ++i) {
            double msb = av[0].GetElementAtIndex(i).GetModulus().GetMSB();
            numDigits += std::ceil(msb / digitSize);
        }
    }

    std::vector<DCRTPoly> avNew(numDigits);
    std::vector<DCRTPoly> bvNew(numDigits);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numDigits))
    for (uint32_t j = 0; j < numDigits; ++j) {
        avNew[j] = av[j].CloneTowers(0, sizeKeyQ - 1);
        bvNew[j] = bv[j].CloneTowers(0, sizeKeyQ - 1);
    }

    auto ek = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(evalKey->GetCryptoContext());
    ek->SetAVector(std::move(avNew));
    ek->SetBVector(std::move(bvNew));
    ek->SetKeyTag(evalKey->GetKeyTag());
    return ek;
}

uint32_t KeySwitchBV::GetNumEvalKeyTowers(const std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
                                          uint32_t levels) const {
    const uint32_t sizeQ = cryptoParams->GetElementParams()->GetParams().size();
    if (levels >= sizeQ)
        OPENFHE_THROW("levels [" + std::to_string(levels) + "] must be smaller than the number of RNS limbs [" +
                      std::to_string(sizeQ) + "]");
    return sizeQ - levels;
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
    cv[0] += ba[0];
    if (cv.size() > 2) {
        cv[1].SetFormat(Format::EVALUATION);
        cv[1] += ba[1];
    }
    else {
        cv[1] = ba[1];
    }
    cv.resize(2);
}

std::vector<DCRTPoly> KeySwitchBV::KeySwitchCore(const DCRTPoly& a, const EvalKey<DCRTPoly> evalKey) const {
    return EvalFastKeySwitchCore(EvalKeySwitchPrecomputeCore(a, evalKey->GetCryptoParameters()), evalKey,
                                 a.GetParams());
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchBV::EvalKeySwitchPrecomputeCore(
    const DCRTPoly& c, std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParamsBase) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoParamsBase);
    return std::make_shared<std::vector<DCRTPoly>>(c.CRTDecompose(cryptoParams->GetDigitSize()));
}

std::vector<DCRTPoly> KeySwitchBV::EvalFastKeySwitchCore(const std::shared_ptr<std::vector<DCRTPoly>> digits,
                                                         const EvalKey<DCRTPoly> evalKey,
                                                         const std::shared_ptr<ParmType> paramsQl) const {
    const std::vector<DCRTPoly>& bref = evalKey->GetBVector();
    const std::vector<DCRTPoly>& aref = evalKey->GetAVector();
    const uint32_t sizeQl             = paramsQl->GetParams().size();
    const uint32_t lastQl             = sizeQl - 1;
    const uint32_t limit              = (*digits).size();

    // the key may have fewer towers than the cryptocontext (see the levels argument of
    // KeySwitchGen and CompressEvalKey)
    if (sizeQl > aref[0].GetNumOfElements() || limit > aref.size())
        OPENFHE_THROW("The ciphertext requires an evaluation key with at least " + std::to_string(sizeQl) +
                      " RNS limbs, but the key has only " + std::to_string(aref[0].GetNumOfElements()) +
                      "; use a key generated at a smaller level");
    std::vector<DCRTPoly> bv(limit);
    std::vector<DCRTPoly> av(limit);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(limit))
    for (uint32_t i = 0; i < limit; ++i) {
        bv[i] = bref[i].CloneTowers(0, lastQl);
        bv[i] *= (*digits)[i];
        av[i] = aref[i].CloneTowers(0, lastQl);
        av[i] *= (*digits)[i];
    }
    for (uint32_t i = 1; i < limit; ++i) {
        bv[0] += bv[i];
        av[0] += av[i];
    }
    std::vector<DCRTPoly> res;
    res.reserve(2);
    res.emplace_back(std::move(bv[0]));
    res.emplace_back(std::move(av[0]));
    return res;
}

}  // namespace lbcrypto
