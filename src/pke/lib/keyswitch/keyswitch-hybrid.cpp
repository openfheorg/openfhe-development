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
 * Hybrid key switching implementation. See
 * Appendix of https://eprint.iacr.org/2021/204 for details.
 */

#include "ciphertext.h"
#include "key/evalkeyrelin.h"
#include "key/privatekey.h"
#include "key/publickey.h"
#include "keyswitch/keyswitch-hybrid.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"

namespace lbcrypto {

EvalKey<DCRTPoly> KeySwitchHYBRID::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                        const PrivateKey<DCRTPoly> newKey, uint32_t levels) const {
    return KeySwitchHYBRID::KeySwitchGenInternal(oldKey, newKey, nullptr, levels);
}

EvalKey<DCRTPoly> KeySwitchHYBRID::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                        const PrivateKey<DCRTPoly> newKey,
                                                        const EvalKey<DCRTPoly> ekPrev, uint32_t levels) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(newKey->GetCryptoParameters());
    const auto& paramsQ     = cryptoParams->GetElementParams();
    const auto& paramsP     = cryptoParams->GetParamsP();

    const uint32_t sizeQ = paramsQ->GetParams().size();
    const uint32_t sizeP = paramsP->GetParams().size();

    if (levels >= sizeQ)
        OPENFHE_THROW("levels [" + std::to_string(levels) + "] must be smaller than the number of RNS limbs [" +
                      std::to_string(sizeQ) + "]");

    // the key is generated over the basis Q_l*P, where Q_l is Q with the last `levels` limbs dropped
    const uint32_t sizeKeyQ  = sizeQ - levels;
    const uint32_t sizeKeyQP = sizeKeyQ + sizeP;

    auto paramsQP = cryptoParams->GetParamsQP();
    if (levels > 0)
        paramsQP = std::make_shared<ParmType>(*paramsQ, sizeKeyQ, *paramsP, sizeP);
    const auto& pparamsQP = paramsQP->GetParams();

    if (ekPrev != nullptr && ekPrev->GetAVector()[0].GetNumOfElements() != sizeKeyQP)
        OPENFHE_THROW("the number of RNS limbs in the input evaluation key does not match the requested levels");

    // skNew is currently in basis Q. This extends it to basis (Q_l)P.

    DCRTPoly sNewExt(paramsQP, Format::EVALUATION, false);
    const auto& sNew = newKey->GetPrivateElement();

    auto sNew0 = sNew.GetElementAtIndex(0);
    sNew0.SetFormat(Format::COEFFICIENT);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeKeyQP))
    for (uint32_t i = 0; i < sizeKeyQP; ++i) {
        if (i < sizeKeyQ) {
            auto tmp = sNew.GetElementAtIndex(i);
            tmp.SetFormat(Format::EVALUATION);
            sNewExt.SetElementAtIndex(i, std::move(tmp));
        }
        else {
            NativePoly tmp(pparamsQP[i], Format::COEFFICIENT);
            tmp.SetValues(NativeVector(sNew0.GetValues(), pparamsQP[i]->GetModulus()), Format::COEFFICIENT);
            tmp.SetFormat(Format::EVALUATION);
            sNewExt.SetElementAtIndex(i, std::move(tmp));
        }
    }

    const auto ns = cryptoParams->GetNoiseScale();

    const uint32_t numPerPartQ = cryptoParams->GetNumPerPartQ();
    // the number of digits of a key over Q_l: same formula as for the ciphertext digits
    // in EvalKeySwitchPrecomputeCore
    uint32_t numPartQ = cryptoParams->GetNumPartQ();
    if (levels > 0) {
        numPartQ = std::ceil(static_cast<double>(sizeKeyQ) / numPerPartQ);
        if (numPartQ > cryptoParams->GetNumberOfQPartitions())
            numPartQ = cryptoParams->GetNumberOfQPartitions();
    }
    std::vector<DCRTPoly> av(numPartQ);
    std::vector<DCRTPoly> bv(numPartQ);

    DugType dug;
    auto dgg = cryptoParams->GetDiscreteGaussianGenerator();

    const auto& sOld  = oldKey->GetPrivateElement();
    const auto& PModq = cryptoParams->GetPModq();

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numPartQ)) private(dug, dgg)
    for (uint32_t part = 0; part < numPartQ; ++part) {
        auto a = (ekPrev == nullptr) ? DCRTPoly(dug, paramsQP, Format::EVALUATION) :  // single-key HE
                                       ekPrev->GetAVector()[part];                                      // threshold HE
        DCRTPoly e(dgg, paramsQP, Format::EVALUATION);
        DCRTPoly b(paramsQP, Format::EVALUATION, false);

        const uint32_t startPartIdx = numPerPartQ * part;
        const uint32_t endPartIdx =
            (sizeKeyQ > (startPartIdx + numPerPartQ)) ? (startPartIdx + numPerPartQ) : sizeKeyQ;

        for (uint32_t i = 0; i < sizeKeyQP; ++i) {
            const auto& ai  = a.GetElementAtIndex(i);
            const auto& ei  = e.GetElementAtIndex(i);
            const auto& sni = sNewExt.GetElementAtIndex(i);

            if (i < startPartIdx || i >= endPartIdx) {
                b.SetElementAtIndex(i, (-ai * sni) + (ns * ei));
            }
            else {
                const auto& soi = sOld.GetElementAtIndex(i);
                b.SetElementAtIndex(i, (-ai * sni) + (ns * ei) + (PModq[i] * soi));
            }
        }
        av[part] = std::move(a);
        bv[part] = std::move(b);
    }

    EvalKeyRelin<DCRTPoly> ek(std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newKey->GetCryptoContext()));
    ek->SetAVector(std::move(av));
    ek->SetBVector(std::move(bv));
    ek->SetKeyTag(newKey->GetKeyTag());
    return ek;
}

EvalKey<DCRTPoly> KeySwitchHYBRID::CompressEvalKey(const EvalKey<DCRTPoly> evalKey, uint32_t levels) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(evalKey->GetCryptoParameters());

    const auto& av = evalKey->GetAVector();
    const auto& bv = evalKey->GetBVector();

    const uint32_t sizeP     = cryptoParams->GetParamsP()->GetParams().size();
    const uint32_t sizeKeyQP = av[0].GetNumOfElements();
    const uint32_t sizeKeyQ  = sizeKeyQP - sizeP;

    if (levels >= sizeKeyQ)
        OPENFHE_THROW("levels [" + std::to_string(levels) +
                      "] must be smaller than the number of RNS limbs in the Q basis of the evaluation key [" +
                      std::to_string(sizeKeyQ) + "]");

    const uint32_t newSizeQ = sizeKeyQ - levels;

    // the compressed basis Q_l*P: the leading newSizeQ towers of the key's Q basis (a
    // prefix of the context's Q) followed by the full auxiliary basis P
    auto paramsQlP = std::make_shared<ParmType>(*av[0].GetParams(), newSizeQ, *cryptoParams->GetParamsP(), sizeP);

    // the number of digits needed for a key over the compressed Q basis
    const uint32_t numPerPartQ = cryptoParams->GetNumPerPartQ();
    uint32_t numPartQl         = std::ceil(static_cast<double>(newSizeQ) / numPerPartQ);
    if (numPartQl > cryptoParams->GetNumberOfQPartitions())
        numPartQl = cryptoParams->GetNumberOfQPartitions();
    if (numPartQl > av.size())
        numPartQl = static_cast<uint32_t>(av.size());

    std::vector<DCRTPoly> avNew(numPartQl);
    std::vector<DCRTPoly> bvNew(numPartQl);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numPartQl))
    for (uint32_t part = 0; part < numPartQl; ++part) {
        avNew[part] = DCRTPoly(paramsQlP, Format::EVALUATION, false);
        bvNew[part] = DCRTPoly(paramsQlP, Format::EVALUATION, false);
        for (uint32_t i = 0; i < newSizeQ; ++i) {
            avNew[part].SetElementAtIndex(i, av[part].GetElementAtIndex(i));
            bvNew[part].SetElementAtIndex(i, bv[part].GetElementAtIndex(i));
        }
        for (uint32_t i = 0; i < sizeP; ++i) {
            avNew[part].SetElementAtIndex(newSizeQ + i, av[part].GetElementAtIndex(sizeKeyQ + i));
            bvNew[part].SetElementAtIndex(newSizeQ + i, bv[part].GetElementAtIndex(sizeKeyQ + i));
        }
    }

    auto ek = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(evalKey->GetCryptoContext());
    ek->SetAVector(std::move(avNew));
    ek->SetBVector(std::move(bvNew));
    ek->SetKeyTag(evalKey->GetKeyTag());
    return ek;
}

uint32_t KeySwitchHYBRID::GetNumEvalKeyTowers(const std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
                                              uint32_t levels) const {
    const auto cryptoParamsRNS = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoParams);

    const uint32_t sizeQ = cryptoParamsRNS->GetElementParams()->GetParams().size();
    if (levels >= sizeQ)
        OPENFHE_THROW("levels [" + std::to_string(levels) + "] must be smaller than the number of RNS limbs [" +
                      std::to_string(sizeQ) + "]");
    return sizeQ - levels + cryptoParamsRNS->GetParamsP()->GetParams().size();
}

EvalKey<DCRTPoly> KeySwitchHYBRID::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                        const PublicKey<DCRTPoly> newKey) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(newKey->GetCryptoParameters());
    const auto& paramsQ     = cryptoParams->GetElementParams();
    const auto& paramsQP    = cryptoParams->GetParamsQP();

    const uint32_t sizeQ  = paramsQ->GetParams().size();
    const uint32_t sizeQP = paramsQP->GetParams().size();

    const auto ns = cryptoParams->GetNoiseScale();

    const uint32_t numPerPartQ = cryptoParams->GetNumPerPartQ();
    const uint32_t numPartQ    = cryptoParams->GetNumPartQ();
    std::vector<DCRTPoly> av(numPartQ);
    std::vector<DCRTPoly> bv(numPartQ);

    TugType tug;
    auto dgg = cryptoParams->GetDiscreteGaussianGenerator();

    const auto& sOld  = oldKey->GetPrivateElement();
    const auto& newp0 = newKey->GetPublicElements().at(0);
    const auto& newp1 = newKey->GetPublicElements().at(1);
    const auto& PModq = cryptoParams->GetPModq();

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numPartQ)) private(dgg, tug)
    for (uint32_t part = 0; part < numPartQ; ++part) {
        auto u = (cryptoParams->GetSecretKeyDist() == GAUSSIAN) ? DCRTPoly(dgg, paramsQP, Format::EVALUATION) :
                                                                  DCRTPoly(tug, paramsQP, Format::EVALUATION);
        DCRTPoly e0(dgg, paramsQP, Format::EVALUATION);
        DCRTPoly e1(dgg, paramsQP, Format::EVALUATION);
        DCRTPoly a(paramsQP, Format::EVALUATION, false);
        DCRTPoly b(paramsQP, Format::EVALUATION, false);

        // starting and ending position of current part
        const uint32_t startPartIdx = numPerPartQ * part;
        const uint32_t endPartIdx   = (sizeQ > startPartIdx + numPerPartQ) ? (startPartIdx + numPerPartQ) : sizeQ;

        for (uint32_t i = 0; i < sizeQP; ++i) {
            const auto& ui = u.GetElementAtIndex(i);

            const auto& e0i = e0.GetElementAtIndex(i);
            const auto& e1i = e1.GetElementAtIndex(i);

            const auto& newp0i = newp0.GetElementAtIndex(i);
            const auto& newp1i = newp1.GetElementAtIndex(i);

            a.SetElementAtIndex(i, newp1i * ui + ns * e1i);

            if (i < startPartIdx || i >= endPartIdx) {
                b.SetElementAtIndex(i, (newp0i * ui) + (ns * e0i));
            }
            else {
                const auto& soi = sOld.GetElementAtIndex(i);
                b.SetElementAtIndex(i, (newp0i * ui) + (ns * e0i) + (PModq[i] * soi));
            }
        }
        av[part] = std::move(a);
        bv[part] = std::move(b);
    }

    EvalKeyRelin<DCRTPoly> ek = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newKey->GetCryptoContext());
    ek->SetAVector(std::move(av));
    ek->SetBVector(std::move(bv));
    ek->SetKeyTag(newKey->GetKeyTag());
    return ek;
}

void KeySwitchHYBRID::KeySwitchInPlace(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> ek) const {
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

Ciphertext<DCRTPoly> KeySwitchHYBRID::KeySwitchExt(ConstCiphertext<DCRTPoly> ciphertext, bool addFirst) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    const auto& cv    = ciphertext->GetElements();
    const auto& PModq = cryptoParams->GetPModq();

    const auto paramsP   = cryptoParams->GetParamsP();
    const auto paramsQl  = cv[0].GetParams();
    const auto paramsQlP = cv[0].GetExtendedCRTBasis(paramsP);

    const uint32_t sizeCv = cv.size();
    const uint32_t sizeQl = paramsQl->GetParams().size();
    std::vector<DCRTPoly> elements(sizeCv);

    for (uint32_t k = 0; k < sizeCv; ++k) {
        elements[k] = DCRTPoly(paramsQlP, Format::EVALUATION, true);
        if ((addFirst) || (k > 0)) {
            auto cMult = cv[k].TimesNoCheck(PModq);
            for (uint32_t i = 0; i < sizeQl; ++i) {
                elements[k].SetElementAtIndex(i, std::move(cMult.GetElementAtIndex(i)));
            }
        }
    }

    auto result = ciphertext->CloneEmpty();
    result->SetElements(std::move(elements));
    return result;
}

Ciphertext<DCRTPoly> KeySwitchHYBRID::KeySwitchDown(ConstCiphertext<DCRTPoly> ciphertext) const {
    const auto& cv       = ciphertext->GetElements();
    const auto paramsQlP = cv[0].GetParams();

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());
    const auto paramsP      = cryptoParams->GetParamsP();

    const uint32_t sizeQl = paramsQlP->GetParams().size() - paramsP->GetParams().size();
    const auto paramsQl   = cryptoParams->GetParamsQlHybrid(sizeQl);

    const PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

    std::vector<DCRTPoly> elements;
    elements.reserve(2);
    elements.emplace_back(cv[0].ApproxModDown(paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
                                              cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                                              cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                              cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                                              cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon()));
    elements.emplace_back(cv[1].ApproxModDown(paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
                                              cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                                              cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                              cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                                              cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon()));

    auto result = ciphertext->CloneEmpty();
    result->SetElements(std::move(elements));
    return result;
}

DCRTPoly KeySwitchHYBRID::KeySwitchDownFirstElement(ConstCiphertext<DCRTPoly> ciphertext) const {
    const auto& cv       = ciphertext->GetElements()[0];
    const auto paramsQlP = cv.GetParams();

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());
    const auto paramsP      = cryptoParams->GetParamsP();

    const uint32_t sizeQl = paramsQlP->GetParams().size() - paramsP->GetParams().size();
    const auto paramsQl   = cryptoParams->GetParamsQlHybrid(sizeQl);

    const PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

    return cv.ApproxModDown(paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
                            cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                            cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                            cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                            cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());
}

std::vector<DCRTPoly> KeySwitchHYBRID::KeySwitchCore(const DCRTPoly& a, const EvalKey<DCRTPoly> evalKey) const {
    return EvalFastKeySwitchCore(EvalKeySwitchPrecomputeCore(a, evalKey->GetCryptoParameters()), evalKey,
                                 a.GetParams());
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchHYBRID::EvalKeySwitchPrecomputeCore(
    const DCRTPoly& c, std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParamsBase) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoParamsBase);

    const auto paramsQl  = c.GetParams();
    const auto paramsP   = cryptoParams->GetParamsP();
    const auto paramsQlP = c.GetExtendedCRTBasis(paramsP);

    const uint32_t sizeQl  = paramsQl->GetParams().size();
    const uint32_t sizeP   = paramsP->GetParams().size();
    const uint32_t sizeQlP = sizeQl + sizeP;
    const uint32_t alpha   = cryptoParams->GetNumPerPartQ();
    // The number of digits of the current ciphertext
    uint32_t numPartQl = std::ceil(static_cast<double>(sizeQl) / alpha);
    if (numPartQl > cryptoParams->GetNumberOfQPartitions())
        numPartQl = cryptoParams->GetNumberOfQPartitions();

    auto result = std::make_shared<std::vector<DCRTPoly>>(numPartQl);

    // Digit decomposition
    // Zero-padding and split
    for (uint32_t part = 0; part < numPartQl; ++part) {
        DCRTPoly partsCt;
        if (part == numPartQl - 1) {
            uint32_t sizePartQl = sizeQl - alpha * part;
            auto&& params       = std::make_shared<ParmType>(*cryptoParams->GetParamsPartQ(part), sizePartQl);
            partsCt             = DCRTPoly(params, Format::EVALUATION, false);
        }
        else {
            partsCt = DCRTPoly(cryptoParams->GetParamsPartQ(part), Format::EVALUATION, false);
        }

        const uint32_t sizePartQl   = partsCt.GetNumOfElements();
        const uint32_t startPartIdx = alpha * part;
        for (uint32_t i = 0, idx = startPartIdx; i < sizePartQl; ++i, ++idx)
            partsCt.SetElementAtIndex(i, c.GetElementAtIndex(idx));

        partsCt.SetFormat(Format::COEFFICIENT);
        auto partsCtCompl = partsCt.ApproxSwitchCRTBasis(cryptoParams->GetParamsPartQ(part),
                                                         cryptoParams->GetParamsComplPartQ(sizeQl - 1, part),
                                                         cryptoParams->GetPartQlHatInvModq(part, sizePartQl - 1),
                                                         cryptoParams->GetPartQlHatInvModqPrecon(part, sizePartQl - 1),
                                                         cryptoParams->GetPartQlHatModp(sizeQl - 1, part),
                                                         cryptoParams->GetmodComplPartqBarrettMu(sizeQl - 1, part));
        partsCtCompl.SetFormat(Format::EVALUATION);

        (*result)[part] = DCRTPoly(paramsQlP, Format::EVALUATION, false);

        const uint32_t endPartIdx = startPartIdx + sizePartQl;
        for (uint32_t i = 0; i < startPartIdx; ++i)
            (*result)[part].SetElementAtIndex(i, std::move(partsCtCompl.GetElementAtIndex(i)));
        for (uint32_t i = startPartIdx; i < endPartIdx; ++i)
            (*result)[part].SetElementAtIndex(i, c.GetElementAtIndex(i));
        for (uint32_t i = endPartIdx; i < sizeQlP; ++i)
            (*result)[part].SetElementAtIndex(i, std::move(partsCtCompl.GetElementAtIndex(i - sizePartQl)));
    }
    return result;
}

std::vector<DCRTPoly> KeySwitchHYBRID::EvalFastKeySwitchCore(const std::shared_ptr<std::vector<DCRTPoly>> digits,
                                                             const EvalKey<DCRTPoly> evalKey,
                                                             const std::shared_ptr<ParmType> paramsQl) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(evalKey->GetCryptoParameters());

    const PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

    auto result = EvalFastKeySwitchCoreExt(digits, evalKey, paramsQl);
    result[0]   = result[0].ApproxModDown(paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
                                          cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                                          cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                          cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                                          cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());
    result[1]   = result[1].ApproxModDown(paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
                                          cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                                          cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                          cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                                          cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());
    return result;
}

std::vector<DCRTPoly> KeySwitchHYBRID::EvalFastKeySwitchCoreExt(const std::shared_ptr<std::vector<DCRTPoly>> digits,
                                                                const EvalKey<DCRTPoly> evalKey,
                                                                const std::shared_ptr<ParmType> paramsQl) const {
    const auto paramsQlP   = (*digits)[0].GetParams();
    const uint32_t sizeQlP = paramsQlP->GetParams().size();

    const uint32_t limit  = digits->size();
    const uint32_t sizeQl = paramsQl->GetParams().size();
    auto&& cryptoParams   = std::dynamic_pointer_cast<CryptoParametersRNS>(evalKey->GetCryptoParameters());

    const auto& av = evalKey->GetAVector();
    const auto& bv = evalKey->GetBVector();

    // key may have fewer towers in its Q basis than the cryptocontext, so towers indexed relative
    // to key's own basis
    const uint32_t sizeP    = cryptoParams->GetParamsP()->GetParams().size();
    const uint32_t sizeKeyQ = av[0].GetNumOfElements() - sizeP;
    if (sizeQl > sizeKeyQ)
        OPENFHE_THROW("The ciphertext requires an evaluation key with at least " + std::to_string(sizeQl) +
                      " RNS limbs in its Q basis, but the key has only " + std::to_string(sizeKeyQ) +
                      "; use a key generated at a smaller level");
    const uint32_t delta = sizeKeyQ - sizeQl;

    std::vector<DCRTPoly> result;
    result.reserve(2);
    result.emplace_back(paramsQlP, Format::EVALUATION, true);
    result.emplace_back(paramsQlP, Format::EVALUATION, true);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQlP))
    for (uint32_t i = 0; i < sizeQlP; ++i) {
        const auto idx = (i >= sizeQl) ? i + delta : i;
        auto& r0       = result[0].GetAllElements()[i];
        auto& r1       = result[1].GetAllElements()[i];
        for (uint32_t j = 0; j < limit; ++j) {
            const auto& cji = (*digits)[j].GetElementAtIndex(i);
            r0.MultAccEqNoCheck(cji, bv[j].GetElementAtIndex(idx));
            r1.MultAccEqNoCheck(cji, av[j].GetElementAtIndex(idx));
        }
    }

    return result;
}

}  // namespace lbcrypto
