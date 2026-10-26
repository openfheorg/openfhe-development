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

#include "keyswitch/keyswitch-hybrid.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "ciphertext.h"
#include "key/evalkeyrelin.h"
#include "key/privatekey.h"
#include "key/publickey.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-leveledshe.h"
#include "utils/utilities-int.h"

namespace lbcrypto {

EvalKey<DCRTPoly> KeySwitchHYBRID::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                        const PrivateKey<DCRTPoly> newKey) const {
    return KeySwitchHYBRID::KeySwitchGenInternal(oldKey, newKey, nullptr);
}

EvalKey<DCRTPoly> KeySwitchHYBRID::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                        const PrivateKey<DCRTPoly> newKey,
                                                        const EvalKey<DCRTPoly> ekPrev) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(newKey->GetCryptoParameters());
    const auto& paramsQ = cryptoParams->GetElementParams();
    const auto& paramsQP = cryptoParams->GetParamsQP();
    const auto& pparamsQP = paramsQP->GetParams();

    // skNew is currently in basis Q. This extends it to basis QP.

    DCRTPoly sNewExt(paramsQP, Format::EVALUATION, false);
    const auto& sNew = newKey->GetPrivateElement();

    auto sNew0 = sNew.GetElementAtIndex(0);
    sNew0.SetFormat(Format::COEFFICIENT);

    const uint32_t sizeQ = paramsQ->GetParams().size();
    const uint32_t sizeQP = paramsQP->GetParams().size();

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQP))
    for (uint32_t i = 0; i < sizeQP; ++i) {
        if (i < sizeQ) {
            auto tmp = sNew.GetElementAtIndex(i);
            tmp.SetFormat(Format::EVALUATION);
            sNewExt.SetElementAtIndex(i, std::move(tmp));
        } else {
            NativePoly tmp(pparamsQP[i], Format::COEFFICIENT);
            tmp.SetValues(NativeVector(sNew0.GetValues(), pparamsQP[i]->GetModulus()), Format::COEFFICIENT);
            tmp.SetFormat(Format::EVALUATION);
            sNewExt.SetElementAtIndex(i, std::move(tmp));
        }
    }

    const auto ns = cryptoParams->GetNoiseScale();

    const uint32_t numPerPartQ = cryptoParams->GetNumPerPartQ();
    const uint32_t numPartQ = cryptoParams->GetNumPartQ();
    std::vector<DCRTPoly> av(numPartQ);
    std::vector<DCRTPoly> bv(numPartQ);

    DugType dug;
    auto dgg = cryptoParams->GetDiscreteGaussianGenerator();

    const auto& sOld = oldKey->GetPrivateElement();
    const auto& PModq = cryptoParams->GetPModq();

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numPartQ)) private(dug, dgg)
    for (uint32_t part = 0; part < numPartQ; ++part) {
        auto a = (ekPrev == nullptr) ? DCRTPoly(dug, paramsQP, Format::EVALUATION) :  // single-key HE
                                       ekPrev->GetAVector()[part];                    // threshold HE
        DCRTPoly e(dgg, paramsQP, Format::EVALUATION);
        DCRTPoly b(paramsQP, Format::EVALUATION, false);

        const uint32_t startPartIdx = numPerPartQ * part;
        const uint32_t endPartIdx = (sizeQ > (startPartIdx + numPerPartQ)) ? (startPartIdx + numPerPartQ) : sizeQ;

        for (uint32_t i = 0; i < sizeQP; ++i) {
            const auto& ai = a.GetElementAtIndex(i);
            const auto& ei = e.GetElementAtIndex(i);
            const auto& sni = sNewExt.GetElementAtIndex(i);

            if (i < startPartIdx || i >= endPartIdx) {
                b.SetElementAtIndex(i, (-ai * sni) + (ns * ei));
            } else {
                const auto& soi = sOld.GetElementAtIndex(i);
                b.SetElementAtIndex(i, (-ai * sni) + (ns * ei) + (PModq[i] * soi));
            }
        }
        av[part] = std::move(a);
        bv[part] = std::move(b);
    }

    if (cryptoParams->GetDoubleDecompDigitSize() > 0) {
        if (ekPrev != nullptr)
            OPENFHE_THROW("The double decomposition of key switching does not support threshold key generation.");
        av = DecomposeKeyDD(av, cryptoParams);
        bv = DecomposeKeyDD(bv, cryptoParams);
    }

    EvalKeyRelin<DCRTPoly> ek(std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newKey->GetCryptoContext()));
    ek->SetAVector(std::move(av));
    ek->SetBVector(std::move(bv));
    ek->SetKeyTag(newKey->GetKeyTag());
    return ek;
}

EvalKey<DCRTPoly> KeySwitchHYBRID::KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldKey,
                                                        const PublicKey<DCRTPoly> newKey) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(newKey->GetCryptoParameters());
    const auto& paramsQ = cryptoParams->GetElementParams();
    const auto& paramsQP = cryptoParams->GetParamsQP();

    const uint32_t sizeQ = paramsQ->GetParams().size();
    const uint32_t sizeQP = paramsQP->GetParams().size();

    const auto ns = cryptoParams->GetNoiseScale();

    const uint32_t numPerPartQ = cryptoParams->GetNumPerPartQ();
    const uint32_t numPartQ = cryptoParams->GetNumPartQ();
    std::vector<DCRTPoly> av(numPartQ);
    std::vector<DCRTPoly> bv(numPartQ);

    TugType tug;
    auto dgg = cryptoParams->GetDiscreteGaussianGenerator();

    const auto& sOld = oldKey->GetPrivateElement();
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
        const uint32_t endPartIdx = (sizeQ > startPartIdx + numPerPartQ) ? (startPartIdx + numPerPartQ) : sizeQ;

        for (uint32_t i = 0; i < sizeQP; ++i) {
            const auto& ui = u.GetElementAtIndex(i);

            const auto& e0i = e0.GetElementAtIndex(i);
            const auto& e1i = e1.GetElementAtIndex(i);

            const auto& newp0i = newp0.GetElementAtIndex(i);
            const auto& newp1i = newp1.GetElementAtIndex(i);

            a.SetElementAtIndex(i, newp1i * ui + ns * e1i);

            if (i < startPartIdx || i >= endPartIdx) {
                b.SetElementAtIndex(i, (newp0i * ui) + (ns * e0i));
            } else {
                const auto& soi = sOld.GetElementAtIndex(i);
                b.SetElementAtIndex(i, (newp0i * ui) + (ns * e0i) + (PModq[i] * soi));
            }
        }
        av[part] = std::move(a);
        bv[part] = std::move(b);
    }

    if (cryptoParams->GetDoubleDecompDigitSize() > 0) {
        av = DecomposeKeyDD(av, cryptoParams);
        bv = DecomposeKeyDD(bv, cryptoParams);
    }

    EvalKeyRelin<DCRTPoly> ek = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newKey->GetCryptoContext());
    ek->SetAVector(std::move(av));
    ek->SetBVector(std::move(bv));
    ek->SetKeyTag(newKey->GetKeyTag());
    return ek;
}

void KeySwitchHYBRID::KeySwitchInPlace(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> ek) const {
    auto& cv = ciphertext->GetElements();
    auto ba = KeySwitchCore(cv.back(), ek);
    cv[0].SetFormat(Format::EVALUATION);
    cv[0] += ba[0];
    if (cv.size() > 2) {
        cv[1].SetFormat(Format::EVALUATION);
        cv[1] += ba[1];
    } else {
        cv[1] = ba[1];
    }
    cv.resize(2);
}

namespace {

// Fused ModDown + modulus reduction of one element in basis QlP; see DCRTPoly::ApproxModDownAndScale.
DCRTPoly ApproxModDownAndScale(const DCRTPoly& c, uint32_t sizeQl, uint32_t levels,
                               const std::shared_ptr<CryptoParametersCKKSRNS>& cryptoParams) {
    const uint32_t sizeQ = cryptoParams->GetElementParams()->GetParams().size();
    return c.ApproxModDownAndScale(
            cryptoParams->GetParamsQlHybrid(sizeQl), cryptoParams->GetParamsQlHybrid(sizeQl - levels),
            cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(), cryptoParams->GetPModq(),
            cryptoParams->GetPHatInvModp(), cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
            cryptoParams->GetModqBarrettMu(), cryptoParams->GetqlInvModq(), sizeQ - sizeQl, levels);
}

std::shared_ptr<CryptoParametersCKKSRNS> GetCKKSParams(ConstCiphertext<DCRTPoly> ciphertext, const char* func) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());
    if (!cryptoParams)
        OPENFHE_THROW(std::string(func) + " requires parameters whose modulus reduction is DropLastElementAndScale.");
    return cryptoParams;
}

}  // namespace

void KeySwitchHYBRID::KeySwitchAndModReduceInPlace(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> ek,
                                                   uint32_t levels) const {
    const auto cryptoParams = GetCKKSParams(ciphertext, __func__);

    auto& cv = ciphertext->GetElements();
    const auto paramsQl = cv[0].GetParams();
    const uint32_t sizeQl = paramsQl->GetParams().size();
    const auto& PModq = cryptoParams->GetPModq();

    auto ba = EvalFastKeySwitchCoreExt(EvalKeySwitchPrecomputeCore(cv.back(), ek->GetCryptoParameters()), ek, paramsQl);

    // the elements not being switched (c0, and c1 for a three-element ciphertext) are raised by P and added to
    // the key switched terms in the extended basis; P * c has zero residues modulo P, so the fused ModDown of
    // the sum equals c + ModDown(ba) exactly
    const uint32_t numRaised = std::min<uint32_t>(cv.size() - 1, 2);
    for (uint32_t k = 0; k < numRaised; ++k) {
        cv[k].SetFormat(Format::EVALUATION);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQl))
        for (uint32_t i = 0; i < sizeQl; ++i)
            ba[k].GetAllElements()[i].MultAccEqNoCheck(cv[k].GetAllElements()[i], PModq[i]);
    }

    cv[0] = ApproxModDownAndScale(ba[0], sizeQl, levels, cryptoParams);
    cv[1] = ApproxModDownAndScale(ba[1], sizeQl, levels, cryptoParams);
    cv.resize(2);

    LeveledSHECKKSRNS::ModReduceMetadataInPlace(ciphertext, sizeQl, levels, cryptoParams);
}

Ciphertext<DCRTPoly> KeySwitchHYBRID::KeySwitchExt(ConstCiphertext<DCRTPoly> ciphertext, bool addFirst) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    const auto& cv = ciphertext->GetElements();
    const auto& PModq = cryptoParams->GetPModq();

    const auto paramsP = cryptoParams->GetParamsP();
    const auto paramsQl = cv[0].GetParams();
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
    const auto& cv = ciphertext->GetElements();
    const auto paramsQlP = cv[0].GetParams();

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());
    const auto paramsP = cryptoParams->GetParamsP();

    const uint32_t sizeQl = paramsQlP->GetParams().size() - paramsP->GetParams().size();
    const auto paramsQl = cryptoParams->GetParamsQlHybrid(sizeQl);

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

Ciphertext<DCRTPoly> KeySwitchHYBRID::KeySwitchDownAndModReduce(ConstCiphertext<DCRTPoly> ciphertext,
                                                                uint32_t levels) const {
    const auto cryptoParams = GetCKKSParams(ciphertext, __func__);

    const auto& cv = ciphertext->GetElements();
    const uint32_t sizeQl = cv[0].GetNumOfElements() - cryptoParams->GetParamsP()->GetParams().size();

    std::vector<DCRTPoly> elements;
    elements.reserve(2);
    elements.emplace_back(ApproxModDownAndScale(cv[0], sizeQl, levels, cryptoParams));
    elements.emplace_back(ApproxModDownAndScale(cv[1], sizeQl, levels, cryptoParams));

    auto result = ciphertext->CloneEmpty();
    result->SetElements(std::move(elements));
    LeveledSHECKKSRNS::ModReduceMetadataInPlace(result, sizeQl, levels, cryptoParams);
    return result;
}

DCRTPoly KeySwitchHYBRID::KeySwitchDownFirstElement(ConstCiphertext<DCRTPoly> ciphertext) const {
    const auto& cv = ciphertext->GetElements()[0];
    const auto paramsQlP = cv.GetParams();

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());
    const auto paramsP = cryptoParams->GetParamsP();

    const uint32_t sizeQl = paramsQlP->GetParams().size() - paramsP->GetParams().size();
    const auto paramsQl = cryptoParams->GetParamsQlHybrid(sizeQl);

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
    if (cryptoParams->GetDoubleDecompDigitSize() > 0)
        return EvalKeySwitchPrecomputeCoreDD(c, cryptoParams);

    const auto paramsQl = c.GetParams();
    const auto paramsP = cryptoParams->GetParamsP();
    const auto paramsQlP = c.GetExtendedCRTBasis(paramsP);

    const uint32_t sizeQl = paramsQl->GetParams().size();
    const uint32_t sizeP = paramsP->GetParams().size();
    const uint32_t sizeQlP = sizeQl + sizeP;
    const uint32_t ringDim = paramsQl->GetRingDimension();
    const uint32_t alpha = cryptoParams->GetNumPerPartQ();
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
            const auto& paramsPartQ = cryptoParams->GetParamsPartQ(part);

            uint32_t sizePartQl = sizeQl - alpha * part;
            std::vector<NativeInteger> moduli(sizePartQl);
            std::vector<NativeInteger> roots(sizePartQl);
            for (uint32_t i = 0; i < sizePartQl; ++i) {
                moduli[i] = paramsPartQ->GetParams()[i]->GetModulus();
                roots[i] = paramsPartQ->GetParams()[i]->GetRootOfUnity();
            }
            auto&& params = std::make_shared<ParmType>(paramsPartQ->GetCyclotomicOrder(), moduli, roots);
            partsCt = DCRTPoly(params, Format::EVALUATION, false);
        } else {
            partsCt = DCRTPoly(cryptoParams->GetParamsPartQ(part), Format::EVALUATION, false);
        }

        const uint32_t sizePartQl = partsCt.GetNumOfElements();
        const uint32_t startPartIdx = alpha * part;
        for (uint32_t i = 0, idx = startPartIdx; i < sizePartQl; ++i, ++idx)
            partsCt.SetElementAtIndex(i, c.GetElementAtIndex(idx));

        const uint32_t threads = DCRTPoly::ApproxSwitchCRTBasisThreads(ringDim, sizePartQl, sizeQlP - sizePartQl);
        partsCt.SetFormat(Format::COEFFICIENT, threads);
        auto partsCtCompl = partsCt.ApproxSwitchCRTBasis(cryptoParams->GetParamsPartQ(part),
                                                         cryptoParams->GetParamsComplPartQ(sizeQl - 1, part),
                                                         cryptoParams->GetPartQlHatInvModq(part, sizePartQl - 1),
                                                         cryptoParams->GetPartQlHatInvModqPrecon(part, sizePartQl - 1),
                                                         cryptoParams->GetPartQlHatModp(sizeQl - 1, part),
                                                         cryptoParams->GetmodComplPartqBarrettMu(sizeQl - 1, part));
        partsCtCompl.SetFormat(Format::EVALUATION, threads);

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
    if (cryptoParams->GetDoubleDecompDigitSize() > 0)
        return EvalFastKeySwitchCoreDD(digits, evalKey, paramsQl, true);

    const PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

    auto result = EvalFastKeySwitchCoreExt(digits, evalKey, paramsQl);
    result[0] = result[0].ApproxModDown(paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
                                        cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                                        cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                        cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                                        cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());
    result[1] = result[1].ApproxModDown(paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
                                        cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                                        cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                        cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                                        cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());
    return result;
}

std::vector<DCRTPoly> KeySwitchHYBRID::EvalFastKeySwitchCoreExt(const std::shared_ptr<std::vector<DCRTPoly>> digits,
                                                                const EvalKey<DCRTPoly> evalKey,
                                                                const std::shared_ptr<ParmType> paramsQl) const {
    auto&& cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(evalKey->GetCryptoParameters());
    if (cryptoParams->GetDoubleDecompDigitSize() > 0)
        return EvalFastKeySwitchCoreDD(digits, evalKey, paramsQl, false);

    const auto paramsQlP = (*digits)[0].GetParams();
    const uint32_t sizeQlP = paramsQlP->GetParams().size();

    const uint32_t limit = digits->size();
    const uint32_t sizeQl = paramsQl->GetParams().size();
    const uint32_t delta = cryptoParams->GetElementParams()->GetParams().size() - sizeQl;

    const auto& av = evalKey->GetAVector();
    const auto& bv = evalKey->GetBVector();

    std::vector<DCRTPoly> result;
    result.reserve(2);
    result.emplace_back(paramsQlP, Format::EVALUATION, true);
    result.emplace_back(paramsQlP, Format::EVALUATION, true);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQlP))
    for (uint32_t i = 0; i < sizeQlP; ++i) {
        const auto idx = (i >= sizeQl) ? i + delta : i;
        auto& r0 = result[0].GetAllElements()[i];
        auto& r1 = result[1].GetAllElements()[i];
        for (uint32_t j = 0; j < limit; ++j) {
            const auto& cji = (*digits)[j].GetElementAtIndex(i);
            r0.MultAccEqNoCheck(cji, bv[j].GetElementAtIndex(idx));
            r1.MultAccEqNoCheck(cji, av[j].GetElementAtIndex(idx));
        }
    }

    return result;
}

/////////////////////////////////////////
// DOUBLE DECOMPOSITION
/////////////////////////////////////////

namespace {

// Exact switch of centered values over B' (COEFFICIENT format, one NativePoly per prime of B') to the given limbs
// of QP, written into the limbs `out[outIdx]` of `out` (COEFFICIENT format). `limbs` lists (outIdx, qpIdx) pairs,
// qpIdx being the index of the limb in QP (Q limbs first, then P), which selects the precomputed tables.
void SwitchDDToLimbs(const std::vector<NativePoly>& acc, const std::vector<std::pair<uint32_t, uint32_t>>& limbs,
                     const std::shared_ptr<CryptoParametersRNS>& cryptoParams, DCRTPoly& out) {
    const uint32_t sizeDD = acc.size();
    const uint32_t ringDim = acc[0].GetLength();
    const auto& hatInv = cryptoParams->GetDDHatInvModDD();
    const auto& hatInvPrecon = cryptoParams->GetDDHatInvModDDPrecon();
    const auto& ddInv = cryptoParams->GetDDInv();
    const auto& hatModQP = cryptoParams->GetDDHatModQP();
    const auto& alphaModQP = cryptoParams->GetDDAlphaModQP();
    const auto& muQP = cryptoParams->GetModQPBarrettMu();
    auto& outPolys = out.GetAllElements();
    const uint32_t numLimbs = limbs.size();

    std::vector<NativeInteger> moduliDD(sizeDD);
    for (uint32_t k = 0; k < sizeDD; ++k)
        moduliDD[k] = acc[k].GetModulus();
    std::vector<NativeInteger> moduliOut(numLimbs);
    for (uint32_t l = 0; l < numLimbs; ++l)
        moduliOut[l] = outPolys[limbs[l].first].GetModulus();
#if !(defined(HAVE_INT128) && NATIVEINT == 64)
    std::vector<NativeInteger> muOut(numLimbs);
    for (uint32_t l = 0; l < numLimbs; ++l)
        muOut[l] = moduliOut[l].ComputeMu();
#endif

    std::vector<uint64_t> y(sizeDD);
#pragma omp parallel for firstprivate(y) \
        num_threads(OpenFHEParallelControls.GetThreadLimit(DCRTPoly::THREADS_CRT_BASIS_SWITCH))
    for (uint32_t ri = 0; ri < ringDim; ++ri) {
        double nu{0.5};
        for (uint32_t k = 0; k < sizeDD; ++k) {
            // [x_k (B'/p'_k)^{-1}]_{p'_k}
            y[k] = acc[k][ri]
                           .ModMulFastConst(hatInv[k], moduliDD[k], hatInvPrecon[k])
                           .template ConvertToInt<uint64_t>();
            nu += static_cast<double>(y[k]) * ddInv[k];
        }
        // the number of overflows of the (centered) reconstruction, 0 <= alpha <= sizeDD
        const uint32_t alpha = static_cast<uint32_t>(nu);
        for (uint32_t l = 0; l < numLimbs; ++l) {
            const uint32_t m = limbs[l].second;
            const auto& hatModq = hatModQP[m];
            const NativeInteger& qm = moduliOut[l];
#if defined(HAVE_INT128) && NATIVEINT == 64
            DoubleNativeInt sum = 0;
            for (uint32_t k = 0; k < sizeDD; ++k)
                sum += Mul128(y[k], hatModq[k].ConvertToInt<uint64_t>());
            const NativeInteger value(BarrettUint128ModUint64(sum, qm.ConvertToInt<uint64_t>(), muQP[m]));
#else
            NativeInteger value(0);
            for (uint32_t k = 0; k < sizeDD; ++k)
                value.ModAddFastEq(NativeInteger(y[k]).Mod(qm).ModMulFast(hatModq[k], qm, muOut[l]), qm);
#endif
            outPolys[limbs[l].first][ri] = value.ModSubFast(alphaModQP[m][alpha], qm);
        }
    }
}

}  // namespace

std::vector<DCRTPoly> KeySwitchHYBRID::DecomposeKeyDD(const std::vector<DCRTPoly>& keyQP,
                                                      const std::shared_ptr<CryptoParametersRNS>& cryptoParams) {
    const uint32_t numPartQ = keyQP.size();
    const uint32_t numDigits = cryptoParams->GetDoubleDecompNumDigits();
    const uint32_t digitSize = cryptoParams->GetDoubleDecompDigitSize();
    const auto& paramsDD = cryptoParams->GetParamsDD();
    const uint32_t numEntries = numPartQ * numDigits;

    std::vector<DCRTPoly> result(numEntries);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numEntries))
    for (uint32_t idx = 0; idx < numEntries; ++idx) {
        const uint32_t part = idx / numDigits;
        const uint32_t j = idx % numDigits;
        const auto& digitParams = cryptoParams->GetParamsDDDigit(j);
        const uint32_t sizeDigit = digitParams->GetParams().size();
        DCRTPoly digit(digitParams, Format::EVALUATION, false);
        for (uint32_t i = 0; i < sizeDigit; ++i)
            digit.SetElementAtIndex(i, keyQP[part].GetElementAtIndex(j * digitSize + i));
        digit.SetFormat(Format::COEFFICIENT);
        // the centered residue modulo the key digit, switched exactly to B'
        auto small = digit.SwitchCRTBasis(paramsDD, cryptoParams->GetDDDigitHatInvModq(j),
                                          cryptoParams->GetDDDigitHatInvModqPrecon(j),
                                          cryptoParams->GetDDDigitHatModDD(j), cryptoParams->GetDDAlphaDigitModDD(j),
                                          cryptoParams->GetModDDBarrettMu(), cryptoParams->GetDDDigitInv(j));
        small.SetFormat(Format::EVALUATION);
        result[idx] = std::move(small);
    }
    return result;
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchHYBRID::EvalKeySwitchPrecomputeCoreDD(
        const DCRTPoly& c, const std::shared_ptr<CryptoParametersRNS>& cryptoParams) const {
    const auto paramsQl = c.GetParams();
    const auto& paramsDD = cryptoParams->GetParamsDD();

    const uint32_t sizeQl = paramsQl->GetParams().size();
    const uint32_t sizeDD = paramsDD->GetParams().size();
    const uint32_t ringDim = paramsQl->GetRingDimension();
    const uint32_t alpha = cryptoParams->GetNumPerPartQ();
    // The number of digits of the current ciphertext
    uint32_t numPartQl = std::ceil(static_cast<double>(sizeQl) / alpha);
    if (numPartQl > cryptoParams->GetNumberOfQPartitions())
        numPartQl = cryptoParams->GetNumberOfQPartitions();

    auto result = std::make_shared<std::vector<DCRTPoly>>(numPartQl);

    // Digit decomposition, each digit being extended to B' (its value in [0, r Q_j) as an integer)
    for (uint32_t part = 0; part < numPartQl; ++part) {
        DCRTPoly partsCt;
        if (part == numPartQl - 1) {
            const auto& paramsPartQ = cryptoParams->GetParamsPartQ(part);

            uint32_t sizePartQl = sizeQl - alpha * part;
            std::vector<NativeInteger> moduli(sizePartQl);
            std::vector<NativeInteger> roots(sizePartQl);
            for (uint32_t i = 0; i < sizePartQl; ++i) {
                moduli[i] = paramsPartQ->GetParams()[i]->GetModulus();
                roots[i] = paramsPartQ->GetParams()[i]->GetRootOfUnity();
            }
            auto&& params = std::make_shared<ParmType>(paramsPartQ->GetCyclotomicOrder(), moduli, roots);
            partsCt = DCRTPoly(params, Format::EVALUATION, false);
        } else {
            partsCt = DCRTPoly(cryptoParams->GetParamsPartQ(part), Format::EVALUATION, false);
        }

        const uint32_t sizePartQl = partsCt.GetNumOfElements();
        const uint32_t startPartIdx = alpha * part;
        for (uint32_t i = 0, idx = startPartIdx; i < sizePartQl; ++i, ++idx)
            partsCt.SetElementAtIndex(i, c.GetElementAtIndex(idx));

        const uint32_t threads = DCRTPoly::ApproxSwitchCRTBasisThreads(ringDim, sizePartQl, sizeDD);
        partsCt.SetFormat(Format::COEFFICIENT, threads);
        auto partsCtDD = partsCt.ApproxSwitchCRTBasis(
                cryptoParams->GetParamsPartQ(part), paramsDD, cryptoParams->GetPartQlHatInvModq(part, sizePartQl - 1),
                cryptoParams->GetPartQlHatInvModqPrecon(part, sizePartQl - 1),
                cryptoParams->GetPartQlHatModDD(sizeQl - 1, part), cryptoParams->GetModDDBarrettMu());
        partsCtDD.SetFormat(Format::EVALUATION, threads);
        (*result)[part] = std::move(partsCtDD);
    }
    return result;
}

std::vector<DCRTPoly> KeySwitchHYBRID::EvalFastKeySwitchCoreDD(const std::shared_ptr<std::vector<DCRTPoly>> digits,
                                                               const EvalKey<DCRTPoly> evalKey,
                                                               const std::shared_ptr<ParmType> paramsQl,
                                                               bool modDown) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(evalKey->GetCryptoParameters());
    const auto& paramsP = cryptoParams->GetParamsP();
    const auto& paramsDD = cryptoParams->GetParamsDD();
    const auto& pparamsDD = paramsDD->GetParams();

    const uint32_t sizeQ = cryptoParams->GetElementParams()->GetParams().size();
    const uint32_t sizeP = paramsP->GetParams().size();
    const uint32_t sizeQP = sizeQ + sizeP;
    const uint32_t sizeQl = paramsQl->GetParams().size();
    const uint32_t sizeQlP = sizeQl + sizeP;
    const uint32_t delta = sizeQ - sizeQl;
    const uint32_t sizeDD = pparamsDD.size();
    const uint32_t numDigits = cryptoParams->GetDoubleDecompNumDigits();
    const uint32_t digitSize = cryptoParams->GetDoubleDecompDigitSize();
    const uint32_t limit = digits->size();

    const auto& av = evalKey->GetAVector();
    const auto& bv = evalKey->GetBVector();

    // the key digits meeting a limb of Q_l P, with the (output index, QP index) pairs of those limbs
    std::vector<uint32_t> activeDigits;
    std::vector<std::vector<std::pair<uint32_t, uint32_t>>> activeLimbs;
    for (uint32_t j = 0; j < numDigits; ++j) {
        const uint32_t start = j * digitSize;
        const uint32_t end = std::min(start + digitSize, sizeQP);
        std::vector<std::pair<uint32_t, uint32_t>> limbs;
        for (uint32_t m = start; m < end; ++m) {
            if (m < sizeQl)
                limbs.emplace_back(m, m);
            else if (m >= sizeQ)
                limbs.emplace_back(m - delta, m);
        }
        if (!limbs.empty()) {
            activeDigits.push_back(j);
            activeLimbs.push_back(std::move(limbs));
        }
    }
    const uint32_t numActive = activeDigits.size();

    // inner products over B' (NTT domain), one per key digit, then back to COEFFICIENT format
    std::vector<std::vector<NativePoly>> acc0(numActive, std::vector<NativePoly>(sizeDD));
    std::vector<std::vector<NativePoly>> acc1(numActive, std::vector<NativePoly>(sizeDD));
    const uint32_t numProducts = numActive * sizeDD;
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numProducts))
    for (uint32_t idx = 0; idx < numProducts; ++idx) {
        const uint32_t a = idx / sizeDD;
        const uint32_t k = idx % sizeDD;
        const uint32_t j = activeDigits[a];
        NativePoly r0(pparamsDD[k], Format::EVALUATION, true);
        NativePoly r1(pparamsDD[k], Format::EVALUATION, true);
        for (uint32_t part = 0; part < limit; ++part) {
            const auto& cpk = (*digits)[part].GetElementAtIndex(k);
            r0.MultAccEqNoCheck(cpk, bv[part * numDigits + j].GetElementAtIndex(k));
            r1.MultAccEqNoCheck(cpk, av[part * numDigits + j].GetElementAtIndex(k));
        }
        r0.SetFormat(Format::COEFFICIENT);
        r1.SetFormat(Format::COEFFICIENT);
        acc0[a][k] = std::move(r0);
        acc1[a][k] = std::move(r1);
    }

    // the extended basis Q_l P
    std::vector<NativeInteger> moduli, roots;
    moduli.reserve(sizeQlP);
    roots.reserve(sizeQlP);
    for (const auto& q : paramsQl->GetParams()) {
        moduli.push_back(q->GetModulus());
        roots.push_back(q->GetRootOfUnity());
    }
    for (const auto& p : paramsP->GetParams()) {
        moduli.push_back(p->GetModulus());
        roots.push_back(p->GetRootOfUnity());
    }
    auto paramsQlP = std::make_shared<ParmType>(paramsQl->GetCyclotomicOrder(), moduli, roots);

    std::vector<DCRTPoly> result;
    result.reserve(2);
    result.emplace_back(paramsQlP, Format::COEFFICIENT, true);
    result.emplace_back(paramsQlP, Format::COEFFICIENT, true);
    for (uint32_t a = 0; a < numActive; ++a) {
        SwitchDDToLimbs(acc0[a], activeLimbs[a], cryptoParams, result[0]);
        SwitchDDToLimbs(acc1[a], activeLimbs[a], cryptoParams, result[1]);
    }

    if (!modDown) {
        result[0].SetFormat(Format::EVALUATION, OpenFHEParallelControls.GetThreadLimit(sizeQlP));
        result[1].SetFormat(Format::EVALUATION, OpenFHEParallelControls.GetThreadLimit(sizeQlP));
        return result;
    }

    // division by P from the COEFFICIENT format: (x_i - [x]_P) P^{-1} mod q_i, then one NTT per limb of Q_l
    const PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();
    const auto& PInvModq = cryptoParams->GetPInvModq();
    const auto& tInvModp = cryptoParams->GettInvModp();
    for (uint32_t i = 0; i < 2; ++i) {
        auto& polys = result[i].GetAllElements();
        DCRTPoly partP(paramsP, Format::COEFFICIENT, false);
        for (uint32_t j = 0; j < sizeP; ++j) {
            NativePoly x = std::move(polys[sizeQl + j]);
            // Multiply everything by -t^(-1) mod P (BGVrns only)
            if (t > 0)
                x *= tInvModp[j];
            partP.SetElementAtIndex(j, std::move(x));
        }
        auto partQ = partP.ApproxSwitchCRTBasis(paramsP, paramsQl, cryptoParams->GetPHatInvModp(),
                                                cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                                cryptoParams->GetModqBarrettMu());
        DCRTPoly ans(paramsQl, Format::EVALUATION, false);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQl))
        for (uint32_t l = 0; l < sizeQl; ++l) {
            NativePoly x = std::move(partQ.GetAllElements()[l]);
            // Multiply everything by t mod Q (BGVrns only)
            if (t > 0)
                x *= NativeInteger(t);
            // (x_l - X'_l) * P^{-1} is computed as (X'_l - x_l) * (q_l - [P^{-1}]_{q_l})
            x -= polys[l];
            x *= (x.GetModulus() - PInvModq[l]);
            x.SetFormat(Format::EVALUATION);
            ans.SetElementAtIndex(l, std::move(x));
        }
        result[i] = std::move(ans);
    }
    return result;
}

}  // namespace lbcrypto
