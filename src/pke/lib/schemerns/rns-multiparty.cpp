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

#include <memory>
#include <vector>
#include <utility>
#include <string>

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

    auto result = ciphertext->CloneEmpty();
    result->SetElement(std::move(b));
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

    auto result = ciphertext->CloneEmpty();
    result->SetElement(std::move(b));
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

// Used a subroutine for interactive bootstrapping.
// Takes a polynomial with 2 two towers (RNS limbs)
// For each coefficient, applies the following logic
// If |coefficient| > q/4, then add q/2 to it
// The guarantees that rounded c_0 + c_1 < q/2,
// it prevents an overflow during interactive bootstrapping
void PolynomialRound(DCRTPoly& dcrtpoly) {
    const uint32_t NUM_TOWERS = dcrtpoly.GetNumOfElements();
    if (2 != NUM_TOWERS) {
        OPENFHE_THROW("The input polynomial has " + std::to_string(NUM_TOWERS) + " instead of 2 RNS limbs");
    }

    std::vector<NativeInteger> q(NUM_TOWERS);
    std::vector<NativePoly> poly(NUM_TOWERS);
    for (size_t i = 0; i < NUM_TOWERS; i++) {
        poly[i] = dcrtpoly.GetElementAtIndex(i);
        q[i]    = poly[i].GetModulus();
    }

    std::vector<NativeInteger> qInv(NUM_TOWERS);
    qInv[0] = q[1].ModInverse(q[0]);
    qInv[1] = q[0].ModInverse(q[1]);

    std::vector<NativeInteger> precon(NUM_TOWERS);
    for (size_t i = 0; i < NUM_TOWERS; i++) {
        precon[i] = qInv[i].PrepModMulConst(q[i]);
    }

    NativeInteger::DNativeInt Q =
        NativeInteger::DNativeInt(q[0].ConvertToInt()) * NativeInteger::DNativeInt(q[1].ConvertToInt());
    NativeInteger::DNativeInt Qhalf   = Q / 2;
    NativeInteger::DNativeInt Q1quart = Q / 4;
    NativeInteger::DNativeInt Q3quart = 3 * Q / 4;
    std::vector<NativeInteger> qHalf(NUM_TOWERS);
    for (size_t i = 0; i < NUM_TOWERS; i++) {
        qHalf[i] = Qhalf % q[i].ConvertToInt();
    }

    // to do the comparison |coefficient[k]| > q/4,
    // we compute CRT composition (interpolation) using
    // 128-bit integers
    for (size_t k = 0; k < dcrtpoly.GetRingDimension(); k++) {
        NativeInteger::DNativeInt x128 =
            (poly[0][k].ModMulFastConst(qInv[0], q[0], precon[0])).ConvertToInt() * q[1].ConvertToInt();
        x128 += (poly[1][k].ModMulFastConst(qInv[1], q[1], precon[1])).ConvertToInt() * q[0].ConvertToInt();
        if (x128 > Q)
            x128 %= Q;
        if ((x128 > Q1quart) && (x128 <= Q3quart)) {
            poly[0][k].ModAddFastEq(qHalf[0], q[0]);
            poly[1][k].ModAddFastEq(qHalf[1], q[1]);
        }
    }

    dcrtpoly.SetElementAtIndex(0, poly[0]);
    dcrtpoly.SetElementAtIndex(1, poly[1]);
}

// Used as a subroutine in interactive bootstrapping.
// Extends a DCRTPoly with 2 RNS limbs (from q) to the full
// RNS basis (to Q). The exact basis extension RNS procedure from
// https://eprint.iacr.org/2018/117 is used.
void ExtendBasis(DCRTPoly& dcrtpoly, const std::shared_ptr<DCRTPoly::Params> paramsQP) {
    if (dcrtpoly.GetNumOfElements() != 2) {
        OPENFHE_THROW(" The input polynomial should have 2 RNS limbs");
    }

    const auto paramsQ = dcrtpoly.GetParams();
    usint sizeQP       = paramsQP->GetParams().size();
    usint sizeQ        = paramsQ->GetParams().size();
    usint sizeP        = sizeQP - sizeQ;

    // Loads all moduli and roots of unity
    std::vector<NativeInteger> moduliQ(sizeQ);
    // std::vector<NativeInteger> rootsQ(sizeQ);  // TODO (dsuponit): do we need rootsQ?
    for (size_t i = 0; i < sizeQ; i++) {
        moduliQ[i] = paramsQ->GetParams()[i]->GetModulus();
        // rootsQ[i]  = paramsQ->GetParams()[i]->GetRootOfUnity();
    }

    std::vector<NativeInteger> moduliP(sizeP);
    std::vector<NativeInteger> rootsP(sizeP);
    for (size_t i = 0; i < sizeP; i++) {
        moduliP[i] = paramsQP->GetParams()[i + sizeQ]->GetModulus();
        rootsP[i]  = paramsQP->GetParams()[i + sizeQ]->GetRootOfUnity();
    }
    auto paramsP = std::make_shared<typename DCRTPoly::Params>(2 * paramsQ->GetRingDimension(), moduliP, rootsP);

    // Does all RNS precomputations
    std::vector<NativeInteger> QHatInvModq(sizeQ);
    std::vector<NativeInteger> QHatInvModqPrecon(sizeQ);
    std::vector<std::vector<NativeInteger>> QHatModp(sizeP);

    NativeInteger::DNativeInt modulusQ = dcrtpoly.GetModulus().ConvertToInt<NativeInteger::DNativeInt>();

    for (usint i = 0; i < sizeQ; i++) {
        NativeInteger::DNativeInt qi(moduliQ[i].ConvertToInt());
        NativeInteger QHati  = modulusQ / qi;
        QHatInvModq[i]       = QHati.ModInverse(moduliQ[i]).Mod(moduliQ[i]);
        QHatInvModqPrecon[i] = QHatInvModq[i].PrepModMulConst(moduliQ[i]);
        for (usint j = 0; j < sizeP; j++) {
            const NativeInteger& pj = moduliP[j];
            QHatModp[j].push_back(QHati.Mod(pj));
        }
    }

    std::vector<std::vector<NativeInteger>> alphaQModp(sizeQ + 1);
    for (usint j = 0; j < sizeP; j++) {
        NativeInteger::DNativeInt pj(moduliP[j].ConvertToInt());
        NativeInteger QModpj = modulusQ % pj;
        for (usint i = 0; i < sizeQ + 1; i++) {
            alphaQModp[i].push_back(QModpj.ModMul(NativeInteger(i), moduliP[j]));
        }
    }

    const BigInteger BarrettBase128Bit("340282366920938463463374607431768211456");  // 2^128
    const BigInteger TwoPower64("18446744073709551616");                            // 2^64

    // Precomputations for Barrett modulo reduction
    std::vector<NativeInteger::DNativeInt> modpBarrettMu(sizeP);
    for (uint32_t j = 0; j < sizeP; j++) {
        BigInteger mu = BarrettBase128Bit / BigInteger(moduliP[j]);
        uint64_t val[2];
        val[0] = (mu % TwoPower64).ConvertToInt();
        val[1] = mu.RShift(64).ConvertToInt();

        memcpy(&modpBarrettMu[j], val, sizeof(NativeInteger::DNativeInt));
    }

    std::vector<double> qInv(sizeQ);
    for (size_t i = 0; i < sizeQ; i++) {
        qInv[i] = 1. / static_cast<double>(moduliQ[i].ConvertToInt());
    }

    // Calls the exact RNS basis extension procedure
    dcrtpoly.ExpandCRTBasis(paramsQP, paramsP, QHatInvModq, QHatInvModqPrecon, QHatModp, alphaQModp, modpBarrettMu,
                            qInv, Format::COEFFICIENT);
}

Ciphertext<DCRTPoly> MultipartyRNS::IntBootDecrypt(const PrivateKey<DCRTPoly> privateKey,
                                                   ConstCiphertext<DCRTPoly> ciphertext) const {
    const size_t NUM_POLYNOMIALS = ciphertext->NumberCiphertextElements();
    if (NUM_POLYNOMIALS != 1 && NUM_POLYNOMIALS != 2) {
        std::string msg = "Ciphertext should contain either one or two polynomials. The input ciphertext has " +
                          std::to_string(NUM_POLYNOMIALS) + ".";
        OPENFHE_THROW(msg);
    }

    std::vector<DCRTPoly> c = ciphertext->GetElements();
    for (uint32_t i = 0; i < NUM_POLYNOMIALS; i++)
        c[i].SetFormat(Format::EVALUATION);
    size_t sizeQl = c[0].GetParams()->GetParams().size();

    const DCRTPoly& s = privateKey->GetPrivateElement();
    size_t sizeQ      = s.GetParams()->GetParams().size();

    size_t diffQl = sizeQ - sizeQl;

    auto scopy(s);
    scopy.DropLastElements(diffQl);

    DCRTPoly cs{(NUM_POLYNOMIALS == 1) ? (c[0] * scopy) : (c[1] * scopy + c[0])};
    cs.SetFormat(Format::COEFFICIENT);
    PolynomialRound(cs);

    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    result->SetElements({cs});

    return result;
}

Ciphertext<DCRTPoly> MultipartyRNS::IntBootEncrypt(const PublicKey<DCRTPoly> publicKey,
                                                   ConstCiphertext<DCRTPoly> ctxt) const {
    if (ctxt->GetElements().empty()) {
        OPENFHE_THROW("No polynomials found in the input ciphertext");
    }

    using DggType  = typename DCRTPoly::DggType;
    using TugType  = typename DCRTPoly::TugType;
    using ParmType = typename DCRTPoly::Params;

    const auto cryptoParams =
        std::static_pointer_cast<CryptoParametersRLWE<DCRTPoly>>(publicKey->GetCryptoParameters());

    DCRTPoly ptxt = ctxt->GetElements()[0];
    ptxt.SetFormat(Format::COEFFICIENT);

    // changes the modulus from small q (2 RNS limbs) to a large Q to support future computations
    ExtendBasis(ptxt, cryptoParams->GetElementParams());

    const std::shared_ptr<ParmType> ptxtParams = ptxt.GetParams();
    const DggType& dgg                         = cryptoParams->GetDiscreteGaussianGenerator();
    TugType tug;

    // Supports both discrete Gaussian (GAUSSIAN) and ternary uniform distribution (UNIFORM_TERNARY) cases
    DCRTPoly v = (cryptoParams->GetSecretKeyDist() == GAUSSIAN) ? DCRTPoly(dgg, ptxtParams, Format::EVALUATION) :
                                                                  DCRTPoly(tug, ptxtParams, Format::EVALUATION);

    DCRTPoly e0(dgg, ptxtParams, Format::COEFFICIENT);
    DCRTPoly e1(dgg, ptxtParams, Format::EVALUATION);

    // we add in the coefficient representation to avoid extra NTTs
    ptxt += e0;
    ptxt.SetFormat(Format::EVALUATION);

    const std::vector<DCRTPoly>& pk = publicKey->GetPublicElements();
    uint32_t sizeQl                 = ptxtParams->GetParams().size();
    uint32_t sizeQ                  = pk[0].GetParams()->GetParams().size();

    std::vector<DCRTPoly> cv;
    if (sizeQl != sizeQ) {
        // Clone public keys because we need to drop towers.
        DCRTPoly b = pk[0].Clone();
        DCRTPoly a = pk[1].Clone();

        uint32_t diffQl = sizeQ - sizeQl;
        b.DropLastElements(diffQl);
        a.DropLastElements(diffQl);

        // the error e0 was already added to ptxt
        cv.push_back(b * v + ptxt);
        cv.push_back(a * v + e1);
    }
    else {
        // Use public keys as they are
        const DCRTPoly& b = pk[0];
        const DCRTPoly& a = pk[1];

        // the error e0 was already added to ptxt
        cv.push_back(b * v + ptxt);
        cv.push_back(a * v + e1);
    }

    Ciphertext<DCRTPoly> ciphertext(std::make_shared<CiphertextImpl<DCRTPoly>>(publicKey));
    ciphertext->SetElements(std::move(cv));

    // Ciphertext depth, level, and scaling factor should be equal to that of the plaintext.
    // However, Encrypt does not take Plaintext as input (only DCRTPoly),
    // so we don't have access to these here and we copy them from the input ciphertext.
    ciphertext->SetEncodingType(ctxt->GetEncodingType());
    ciphertext->SetScalingFactor(ctxt->GetScalingFactor());
    ciphertext->SetNoiseScaleDeg(ctxt->GetNoiseScaleDeg());
    ciphertext->SetLevel(0);
    ciphertext->SetMetadataMap(ctxt->GetMetadataMap());
    ciphertext->SetSlots(ctxt->GetSlots());

    return ciphertext;
}

Ciphertext<DCRTPoly> MultipartyRNS::IntBootAdd(ConstCiphertext<DCRTPoly> ciphertext1,
                                               ConstCiphertext<DCRTPoly> ciphertext2) const {
    if (ciphertext1->GetElements().empty()) {
        OPENFHE_THROW("No polynomials found in the input ciphertext1");
    }
    if (ciphertext2->GetElements().empty()) {
        OPENFHE_THROW("No polynomials found in the input ciphertext2");
    }

    auto elements1 = ciphertext1->GetElements();
    auto elements2 = ciphertext2->GetElements();

    elements2[0].SetFormat(Format::COEFFICIENT);
    const auto cryptoParams =
        std::static_pointer_cast<CryptoParametersRLWE<DCRTPoly>>(ciphertext1->GetCryptoParameters());
    ExtendBasis(elements2[0], cryptoParams->GetElementParams());
    elements2[0].SetFormat(Format::EVALUATION);

    elements1[0] += elements2[0];

    Ciphertext<DCRTPoly> result = ciphertext1->Clone();
    result->SetElements(elements1);

    return result;
}

}  // namespace lbcrypto
