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
#include "schemerns/rns-multiparty.h"

#include "key/privatekey.h"
#include "key/evalkeyrelin.h"
#include "cryptocontext.h"
#include "schemerns/rns-pke.h"

namespace lbcrypto {

Ciphertext<DCRTPoly> MultipartyRNS::MultipartyDecryptLead(ConstCiphertext<DCRTPoly> ciphertext,
                                                          const PrivateKey<DCRTPoly> privateKey) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(privateKey->GetCryptoParameters());

    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    const auto ns                   = cryptoParams->GetNoiseScale();

    auto s(privateKey->GetPrivateElement());

    size_t sizeQ  = s.GetParams()->GetParams().size();
    size_t sizeQl = cv[0].GetParams()->GetParams().size();
    size_t diffQl = sizeQ - sizeQl;

    s.DropLastElements(diffQl);

    DCRTPoly noise;
    if (cryptoParams->GetMultipartyMode() == NOISE_FLOODING_MULTIPARTY) {
        if (sizeQl < 3) {
            OPENFHE_THROW("sizeQl " + std::to_string(sizeQl) +
                          " must be at least 3 in NOISE_FLOODING_MULTIPARTY mode.");
        }
        DugType dug;
        auto params                            = cv[0].GetParams();
        auto cyclOrder                         = params->GetCyclotomicOrder();
        std::vector<NativeInteger> moduliFirst = {params->GetParams()[0]->GetModulus()};
        std::vector<NativeInteger> rootsFirst  = {params->GetParams()[0]->GetRootOfUnity()};
        auto paramsFirst = std::make_shared<ILDCRTParams<BigInteger>>(cyclOrder, moduliFirst, rootsFirst);
        std::vector<NativeInteger> moduliAllButFirst(sizeQl - 1);
        std::vector<NativeInteger> rootsAllButFirst(sizeQl - 1);
        for (size_t i = 1; i < sizeQl; i++) {
            moduliAllButFirst[i - 1] = params->GetParams()[i]->GetModulus();
            rootsAllButFirst[i - 1]  = params->GetParams()[i]->GetRootOfUnity();
        }
        auto paramsAllButFirst =
            std::make_shared<ILDCRTParams<BigInteger>>(cyclOrder, moduliAllButFirst, rootsAllButFirst);
        DCRTPoly e(dug, paramsAllButFirst, Format::EVALUATION);

        e.ExpandCRTBasisReverseOrder(params, paramsFirst, cryptoParams->GetMultipartyQHatInvModqAtIndex(sizeQl - 2),
                                     cryptoParams->GetMultipartyQHatInvModqPreconAtIndex(sizeQl - 2),
                                     cryptoParams->GetMultipartyQHatModq0AtIndex(sizeQl - 2),
                                     cryptoParams->GetMultipartyAlphaQModq0AtIndex(sizeQl - 2),
                                     cryptoParams->GetMultipartyModq0BarrettMu(), cryptoParams->GetMultipartyQInv(),
                                     Format::EVALUATION);

        noise = e;
    }
    else if (cryptoParams->GetDecryptionNoiseMode() == NOISE_FLOODING_DECRYPT &&
             cryptoParams->GetExecutionMode() == EXEC_EVALUATION) {
        auto dgg = cryptoParams->GetFloodingDiscreteGaussianGenerator();
        DCRTPoly e(dgg, cv[0].GetParams(), Format::EVALUATION);
        noise = std::move(e);
    }
    else {
        DggType dgg(NoiseFlooding::MP_SD);
        DCRTPoly e(dgg, cv[0].GetParams(), Format::EVALUATION);
        noise = std::move(e);
    }

    // e is added to do noise flooding
    DCRTPoly b = cv[0] + s * cv[1] + ns * noise;

    Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

    result->SetElements({std::move(b)});

    result->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg());
    result->SetLevel(ciphertext->GetLevel());
    result->SetScalingFactor(ciphertext->GetScalingFactor());
    result->SetScalingFactorInt(ciphertext->GetScalingFactorInt());
    result->SetSlots(ciphertext->GetSlots());

    return result;
}

Ciphertext<DCRTPoly> MultipartyRNS::MultipartyDecryptMain(ConstCiphertext<DCRTPoly> ciphertext,
                                                          const PrivateKey<DCRTPoly> privateKey) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(privateKey->GetCryptoParameters());
    const auto ns           = cryptoParams->GetNoiseScale();

    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();

    auto s(privateKey->GetPrivateElement());

    size_t sizeQ  = s.GetParams()->GetParams().size();
    size_t sizeQl = cv[0].GetParams()->GetParams().size();
    size_t diffQl = sizeQ - sizeQl;

    s.DropLastElements(diffQl);

    DCRTPoly noise;
    if (cryptoParams->GetMultipartyMode() == NOISE_FLOODING_MULTIPARTY) {
        if (sizeQl < 3) {
            OPENFHE_THROW("sizeQl " + std::to_string(sizeQl) +
                          " must be at least 3 in NOISE_FLOODING_MULTIPARTY mode.");
        }
        DugType dug;
        auto params                         = cv[0].GetParams();
        ILDCRTParams<BigInteger> paramsCopy = *params;
        paramsCopy.PopFirstParam();
        auto paramsAllButFirst = std::make_shared<ILDCRTParams<BigInteger>>(paramsCopy);
        DCRTPoly e(dug, paramsAllButFirst, Format::EVALUATION);

        auto cyclOrder                         = params->GetCyclotomicOrder();
        std::vector<NativeInteger> moduliFirst = {params->GetParams()[0]->GetModulus()};
        std::vector<NativeInteger> rootsFirst  = {params->GetParams()[0]->GetRootOfUnity()};
        auto paramsFirst = std::make_shared<ILDCRTParams<BigInteger>>(cyclOrder, moduliFirst, rootsFirst);
        e.ExpandCRTBasisReverseOrder(params, paramsFirst, cryptoParams->GetMultipartyQHatInvModqAtIndex(sizeQl - 2),
                                     cryptoParams->GetMultipartyQHatInvModqPreconAtIndex(sizeQl - 2),
                                     cryptoParams->GetMultipartyQHatModq0AtIndex(sizeQl - 2),
                                     cryptoParams->GetMultipartyAlphaQModq0AtIndex(sizeQl - 2),
                                     cryptoParams->GetMultipartyModq0BarrettMu(), cryptoParams->GetMultipartyQInv(),
                                     Format::EVALUATION);

        noise = e;
    }
    else if (cryptoParams->GetDecryptionNoiseMode() == NOISE_FLOODING_DECRYPT &&
             cryptoParams->GetExecutionMode() == EXEC_EVALUATION) {
        auto dgg = cryptoParams->GetFloodingDiscreteGaussianGenerator();
        DCRTPoly e(dgg, cv[0].GetParams(), Format::EVALUATION);
        noise = std::move(e);
    }
    else {
        DggType dgg(NoiseFlooding::MP_SD);
        DCRTPoly e(dgg, cv[0].GetParams(), Format::EVALUATION);
        noise = std::move(e);
    }

    // noise is added to do noise flooding
    DCRTPoly b = s * cv[1] + ns * noise;

    Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

    result->SetElements({std::move(b)});

    result->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg());
    result->SetLevel(ciphertext->GetLevel());
    result->SetScalingFactor(ciphertext->GetScalingFactor());
    result->SetScalingFactorInt(ciphertext->GetScalingFactorInt());
    result->SetSlots(ciphertext->GetSlots());

    return result;
}

EvalKey<DCRTPoly> MultipartyRNS::MultiMultEvalKey(PrivateKey<DCRTPoly> privateKey, EvalKey<DCRTPoly> evalKey) const {
    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersRNS>(evalKey->GetCryptoContext()->GetCryptoParameters());
    const auto ns = cryptoParams->GetNoiseScale();

    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();

    EvalKey<DCRTPoly> evalKeyResult = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(evalKey->GetCryptoContext());

    const std::vector<DCRTPoly>& a0 = evalKey->GetAVector();
    const std::vector<DCRTPoly>& b0 = evalKey->GetBVector();

    const size_t size = a0.size();

    std::vector<DCRTPoly> a;
    a.reserve(size);
    std::vector<DCRTPoly> b;
    b.reserve(size);

    if (cryptoParams->GetKeySwitchTechnique() == BV) {
        const DCRTPoly& s         = privateKey->GetPrivateElement();
        const auto& elementParams = s.GetParams();
        for (size_t i = 0; i < size; ++i) {
            a.push_back(a0[i] * s + ns * DCRTPoly(dgg, elementParams, Format::EVALUATION));
            b.push_back(b0[i] * s + ns * DCRTPoly(dgg, elementParams, Format::EVALUATION));
        }
    }
    else {
        const auto& paramsQ  = cryptoParams->GetElementParams();
        const auto& paramsQP = cryptoParams->GetParamsQP();

        usint sizeQ  = paramsQ->GetParams().size();
        usint sizeQP = paramsQP->GetParams().size();

        DCRTPoly s = privateKey->GetPrivateElement().Clone();

        s.SetFormat(Format::COEFFICIENT);
        DCRTPoly sExt(paramsQP, Format::COEFFICIENT, true);

        for (usint i = 0; i < sizeQ; i++) {
            sExt.SetElementAtIndex(i, s.GetElementAtIndex(i));
        }

        for (usint j = sizeQ; j < sizeQP; j++) {
            NativeInteger pj    = paramsQP->GetParams()[j]->GetModulus();
            NativeInteger rooti = paramsQP->GetParams()[j]->GetRootOfUnity();
            auto sNew0          = s.GetElementAtIndex(0);
            sNew0.SwitchModulus(pj, rooti, 0, 0);
            sExt.SetElementAtIndex(j, std::move(sNew0));
        }
        sExt.SetFormat(Format::EVALUATION);

        for (usint i = 0; i < size; i++) {
            a.push_back(a0[i] * sExt + ns * DCRTPoly(dgg, paramsQP, Format::EVALUATION));
            b.push_back(b0[i] * sExt + ns * DCRTPoly(dgg, paramsQP, Format::EVALUATION));
        }
    }

    evalKeyResult->SetAVector(std::move(a));
    evalKeyResult->SetBVector(std::move(b));

    return evalKeyResult;
}

}  // namespace lbcrypto
