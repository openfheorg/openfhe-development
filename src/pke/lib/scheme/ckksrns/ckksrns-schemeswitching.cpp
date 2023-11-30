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
	CKKS to FHEW scheme switching implementation.
 */

#define PROFILE

#include "scheme/ckksrns/ckksrns-schemeswitching.h"

#include "cryptocontext.h"
#include "gen-cryptocontext.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"

#include "math/dftransform.h"

namespace lbcrypto {

//------------------------------------------------------------------------------
// Complex Plaintext Functions, copied from ckksrns-fhe. TODO: fix this
//------------------------------------------------------------------------------

#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
Plaintext SWITCHCKKSRNS::MakeAuxPlaintext(const CryptoContextImpl<DCRTPoly>& cc, const std::shared_ptr<ParmType> params,
                                          const std::vector<std::complex<double>>& value, size_t noiseScaleDeg,
                                          uint32_t level, usint slots) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    double scFact = cryptoParams->GetScalingFactorReal(level);

    Plaintext p = Plaintext(std::make_shared<CKKSPackedEncoding>(params, cc.GetEncodingParams(), value, noiseScaleDeg,
                                                                 level, scFact, slots));

    DCRTPoly& plainElement = p->GetElement<DCRTPoly>();

    usint N = cc.GetRingDimension();

    std::vector<std::complex<double>> inverse = value;

    inverse.resize(slots);

    DiscreteFourierTransform::FFTSpecialInv(inverse, N * 2);
    uint64_t pBits = cc.GetEncodingParams()->GetPlaintextModulus();

    double powP      = std::pow(2.0, MAX_DOUBLE_PRECISION);
    int32_t pCurrent = pBits - MAX_DOUBLE_PRECISION;

    std::vector<int128_t> temp(2 * slots);
    for (size_t i = 0; i < slots; ++i) {
        // extract the mantissa of real part and multiply it by 2^52
        int32_t n1 = 0;
        double dre = std::frexp(inverse[i].real(), &n1) * powP;
        // extract the mantissa of imaginary part and multiply it by 2^52
        int32_t n2 = 0;
        double dim = std::frexp(inverse[i].imag(), &n2) * powP;

        // Check for possible overflow
        if (is128BitOverflow(dre) || is128BitOverflow(dim)) {
            DiscreteFourierTransform::FFTSpecial(inverse, N * 2);

            double invLen = static_cast<double>(inverse.size());
            double factor = 2 * M_PI * i;

            double realMax = -1, imagMax = -1;
            uint32_t realMaxIdx = -1, imagMaxIdx = -1;

            for (uint32_t idx = 0; idx < inverse.size(); idx++) {
                // exp( j*2*pi*n*k/N )
                std::complex<double> expFactor = {cos((factor * idx) / invLen), sin((factor * idx) / invLen)};

                // X[k] * exp( j*2*pi*n*k/N )
                std::complex<double> prodFactor = inverse[idx] * expFactor;

                double realVal = prodFactor.real();
                double imagVal = prodFactor.imag();

                if (realVal > realMax) {
                    realMax    = realVal;
                    realMaxIdx = idx;
                }
                if (imagVal > imagMax) {
                    imagMax    = imagVal;
                    imagMaxIdx = idx;
                }
            }

            auto scaledInputSize = ceil(log2(dre));

            std::stringstream buffer;
            buffer << std::endl
                   << "Overflow in data encoding - scaled input is too large to fit "
                      "into a NativeInteger (60 bits). Try decreasing scaling factor."
                   << std::endl;
            buffer << "Overflow at slot number " << i << std::endl;
            buffer << "- Max real part contribution from input[" << realMaxIdx << "]: " << realMax << std::endl;
            buffer << "- Max imaginary part contribution from input[" << imagMaxIdx << "]: " << imagMax << std::endl;
            buffer << "Scaling factor is " << ceil(log2(powP)) << " bits " << std::endl;
            buffer << "Scaled input is " << scaledInputSize << " bits " << std::endl;
            OPENFHE_THROW(math_error, buffer.str());
        }

        int64_t re64       = std::llround(dre);
        int32_t pRemaining = pCurrent + n1;
        __int128 re        = 0;
        if (pRemaining < 0) {
            re = re64 >> (-pRemaining);
        }
        else {
            __int128 pPowRemaining = ((__int128)1) << pRemaining;
            re                     = pPowRemaining * re64;
        }

        int64_t im64 = std::llround(dim);
        pRemaining   = pCurrent + n2;
        __int128 im  = 0;
        if (pRemaining < 0) {
            im = im64 >> (-pRemaining);
        }
        else {
            __int128 pPowRemaining = ((int64_t)1) << pRemaining;
            im                     = pPowRemaining * im64;
        }

        temp[i]         = (re < 0) ? Max128BitValue() + re : re;
        temp[i + slots] = (im < 0) ? Max128BitValue() + im : im;

        if (is128BitOverflow(temp[i]) || is128BitOverflow(temp[i + slots])) {
            OPENFHE_THROW(math_error, "Overflow, try to decrease scaling factor");
        }
    }

    const std::shared_ptr<ILDCRTParams<BigInteger>> bigParams        = plainElement.GetParams();
    const std::vector<std::shared_ptr<ILNativeParams>>& nativeParams = bigParams->GetParams();

    for (size_t i = 0; i < nativeParams.size(); i++) {
        NativeVector nativeVec(N, nativeParams[i]->GetModulus());
        FitToNativeVector(N, temp, Max128BitValue(), &nativeVec);
        NativePoly element = plainElement.GetElementAtIndex(i);
        element.SetValues(nativeVec, Format::COEFFICIENT);
        plainElement.SetElementAtIndex(i, element);
    }

    usint numTowers = nativeParams.size();
    std::vector<DCRTPoly::Integer> moduli(numTowers);
    for (usint i = 0; i < numTowers; i++) {
        moduli[i] = nativeParams[i]->GetModulus();
    }

    DCRTPoly::Integer intPowP = NativeInteger(1) << pBits;
    std::vector<DCRTPoly::Integer> crtPowP(numTowers, intPowP);

    auto currPowP = crtPowP;

    // We want to scale temp by 2^(pd), and the loop starts from j=2
    // because temp is already scaled by 2^p in the re/im loop above,
    // and currPowP already is 2^p.
    for (size_t i = 2; i < noiseScaleDeg; i++) {
        currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
    }

    if (noiseScaleDeg > 1) {
        plainElement = plainElement.Times(currPowP);
    }

    p->SetFormat(Format::EVALUATION);
    p->SetScalingFactor(pow(p->GetScalingFactor(), noiseScaleDeg));

    return p;
}
#else
Plaintext SWITCHCKKSRNS::MakeAuxPlaintext(const CryptoContextImpl<DCRTPoly>& cc, const std::shared_ptr<ParmType> params,
                                          const std::vector<std::complex<double>>& value, size_t noiseScaleDeg,
                                          uint32_t level, usint slots) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    double scFact = cryptoParams->GetScalingFactorReal(level);

    Plaintext p = Plaintext(std::make_shared<CKKSPackedEncoding>(params, cc.GetEncodingParams(), value, noiseScaleDeg,
                                                                 level, scFact, slots));

    DCRTPoly& plainElement = p->GetElement<DCRTPoly>();

    usint N = cc.GetRingDimension();

    std::vector<std::complex<double>> inverse = value;

    inverse.resize(slots);

    DiscreteFourierTransform::FFTSpecialInv(inverse, N * 2);
    double powP = scFact;

    // Compute approxFactor, a value to scale down by, in case the value exceeds a 64-bit integer.
    constexpr int32_t MAX_BITS_IN_WORD = 61;

    int32_t logc = 0;
    for (size_t i = 0; i < slots; ++i) {
        inverse[i] *= powP;
        if (inverse[i].real() != 0) {
            int32_t logci = static_cast<int32_t>(ceil(log2(std::abs(inverse[i].real()))));
            if (logc < logci)
                logc = logci;
        }
        if (inverse[i].imag() != 0) {
            int32_t logci = static_cast<int32_t>(ceil(log2(std::abs(inverse[i].imag()))));
            if (logc < logci)
                logc = logci;
        }
    }
    if (logc < 0) {
        OPENFHE_THROW(math_error, "Too small scaling factor");
    }
    int32_t logValid    = (logc <= MAX_BITS_IN_WORD) ? logc : MAX_BITS_IN_WORD;
    int32_t logApprox   = logc - logValid;
    double approxFactor = pow(2, logApprox);

    std::vector<int64_t> temp(2 * slots);
    for (size_t i = 0; i < slots; ++i) {
        // Scale down by approxFactor in case the value exceeds a 64-bit integer.
        double dre = inverse[i].real() / approxFactor;
        double dim = inverse[i].imag() / approxFactor;

        // Check for possible overflow
        if (is64BitOverflow(dre) || is64BitOverflow(dim)) {
            DiscreteFourierTransform::FFTSpecial(inverse, N * 2);

            double invLen = static_cast<double>(inverse.size());
            double factor = 2 * M_PI * i;

            double realMax = -1, imagMax = -1;
            uint32_t realMaxIdx = -1, imagMaxIdx = -1;

            for (uint32_t idx = 0; idx < inverse.size(); idx++) {
                // exp( j*2*pi*n*k/N )
                std::complex<double> expFactor = {cos((factor * idx) / invLen), sin((factor * idx) / invLen)};

                // X[k] * exp( j*2*pi*n*k/N )
                std::complex<double> prodFactor = inverse[idx] * expFactor;

                double realVal = prodFactor.real();
                double imagVal = prodFactor.imag();

                if (realVal > realMax) {
                    realMax    = realVal;
                    realMaxIdx = idx;
                }
                if (imagVal > imagMax) {
                    imagMax    = imagVal;
                    imagMaxIdx = idx;
                }
            }

            auto scaledInputSize = ceil(log2(dre));

            std::stringstream buffer;
            buffer << std::endl
                   << "Overflow in data encoding - scaled input is too large to fit "
                      "into a NativeInteger (60 bits). Try decreasing scaling factor."
                   << std::endl;
            buffer << "Overflow at slot number " << i << std::endl;
            buffer << "- Max real part contribution from input[" << realMaxIdx << "]: " << realMax << std::endl;
            buffer << "- Max imaginary part contribution from input[" << imagMaxIdx << "]: " << imagMax << std::endl;
            buffer << "Scaling factor is " << ceil(log2(powP)) << " bits " << std::endl;
            buffer << "Scaled input is " << scaledInputSize << " bits " << std::endl;
            OPENFHE_THROW(math_error, buffer.str());
        }

        int64_t re = std::llround(dre);
        int64_t im = std::llround(dim);

        temp[i]         = (re < 0) ? Max64BitValue() + re : re;
        temp[i + slots] = (im < 0) ? Max64BitValue() + im : im;
    }

    const std::shared_ptr<ILDCRTParams<BigInteger>> bigParams        = plainElement.GetParams();
    const std::vector<std::shared_ptr<ILNativeParams>>& nativeParams = bigParams->GetParams();

    for (size_t i = 0; i < nativeParams.size(); i++) {
        NativeVector nativeVec(N, nativeParams[i]->GetModulus());
        FitToNativeVector(N, temp, Max64BitValue(), &nativeVec);
        NativePoly element = plainElement.GetElementAtIndex(i);
        element.SetValues(nativeVec, Format::COEFFICIENT);
        plainElement.SetElementAtIndex(i, element);
    }

    usint numTowers = nativeParams.size();
    std::vector<DCRTPoly::Integer> moduli(numTowers);
    for (usint i = 0; i < numTowers; i++) {
        moduli[i] = nativeParams[i]->GetModulus();
    }

    DCRTPoly::Integer intPowP = std::llround(powP);
    std::vector<DCRTPoly::Integer> crtPowP(numTowers, intPowP);

    auto currPowP = crtPowP;

    // We want to scale temp by 2^(pd), and the loop starts from j=2
    // because temp is already scaled by 2^p in the re/im loop above,
    // and currPowP already is 2^p.
    for (size_t i = 2; i < noiseScaleDeg; i++) {
        currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
    }

    if (noiseScaleDeg > 1) {
        plainElement = plainElement.Times(currPowP);
    }

    // Scale back up by the approxFactor to get the correct encoding.
    if (logApprox > 0) {
        int32_t logStep = (logApprox <= MAX_LOG_STEP) ? logApprox : MAX_LOG_STEP;
        auto intStep    = DCRTPoly::Integer(uint64_t(1) << logStep);
        std::vector<DCRTPoly::Integer> crtApprox(numTowers, intStep);
        logApprox -= logStep;

        while (logApprox > 0) {
            logStep = (logApprox <= MAX_LOG_STEP) ? logApprox : MAX_LOG_STEP;
            intStep = DCRTPoly::Integer(uint64_t(1) << logStep);
            std::vector<DCRTPoly::Integer> crtSF(numTowers, intStep);
            crtApprox = CKKSPackedEncoding::CRTMult(crtApprox, crtSF, moduli);
            logApprox -= logStep;
        }
        plainElement = plainElement.Times(crtApprox);
    }

    p->SetFormat(Format::EVALUATION);
    p->SetScalingFactor(pow(p->GetScalingFactor(), noiseScaleDeg));

    return p;
}
#endif

Ciphertext<DCRTPoly> SWITCHCKKSRNS::EvalMultExt(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    std::vector<DCRTPoly>& cv   = result->GetElements();

    DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
    pt.SetFormat(Format::EVALUATION);

    for (auto& c : cv) {
        c *= pt;
    }
    result->SetNoiseScaleDeg(result->GetNoiseScaleDeg() + plaintext->GetNoiseScaleDeg());
    result->SetScalingFactor(result->GetScalingFactor() * plaintext->GetScalingFactor());
    return result;
}

void SWITCHCKKSRNS::EvalAddExtInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) const {
    std::vector<DCRTPoly>& cv1       = ciphertext1->GetElements();
    const std::vector<DCRTPoly>& cv2 = ciphertext2->GetElements();

    for (size_t i = 0; i < cv1.size(); ++i) {
        cv1[i] += cv2[i];
    }
}

Ciphertext<DCRTPoly> SWITCHCKKSRNS::EvalAddExt(ConstCiphertext<DCRTPoly> ciphertext1,
                                               ConstCiphertext<DCRTPoly> ciphertext2) const {
    Ciphertext<DCRTPoly> result = ciphertext1->Clone();
    EvalAddExtInPlace(result, ciphertext2);
    return result;
}

EvalKey<DCRTPoly> SWITCHCKKSRNS::ConjugateKeyGen(const PrivateKey<DCRTPoly> privateKey) const {
    const auto cc = privateKey->GetCryptoContext();
    auto algo     = cc->GetScheme();

    const DCRTPoly& s = privateKey->GetPrivateElement();
    usint N           = s.GetRingDimension();

    PrivateKey<DCRTPoly> privateKeyPermuted = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);

    usint index = 2 * N - 1;
    std::vector<usint> vec(N);
    PrecomputeAutoMap(N, index, &vec);

    DCRTPoly sPermuted = s.AutomorphismTransform(index, vec);

    privateKeyPermuted->SetPrivateElement(sPermuted);
    privateKeyPermuted->SetKeyTag(privateKey->GetKeyTag());

    return algo->KeySwitchGen(privateKey, privateKeyPermuted);
}

Ciphertext<DCRTPoly> SWITCHCKKSRNS::Conjugate(ConstCiphertext<DCRTPoly> ciphertext,
                                              const std::map<usint, EvalKey<DCRTPoly>>& evalKeyMap) const {
    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    usint N                         = cv[0].GetRingDimension();

    std::vector<usint> vec(N);
    PrecomputeAutoMap(N, 2 * N - 1, &vec);

    auto algo = ciphertext->GetCryptoContext()->GetScheme();

    Ciphertext<DCRTPoly> result = ciphertext->Clone();

    algo->KeySwitchInPlace(result, evalKeyMap.at(2 * N - 1));

    std::vector<DCRTPoly>& rcv = result->GetElements();

    rcv[0] = rcv[0].AutomorphismTransform(2 * N - 1, vec);
    rcv[1] = rcv[1].AutomorphismTransform(2 * N - 1, vec);

    return result;
}

#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
void SWITCHCKKSRNS::FitToNativeVector(uint32_t ringDim, const std::vector<__int128>& vec, __int128 bigBound,
                                      NativeVector* nativeVec) const {
    if (nativeVec == nullptr)
        OPENFHE_THROW(config_error, "The passed native vector is empty.");
    NativeInteger bigValueHf((unsigned __int128)bigBound >> 1);
    NativeInteger modulus(nativeVec->GetModulus());
    NativeInteger diff = NativeInteger((unsigned __int128)bigBound) - modulus;
    uint32_t dslots    = vec.size();
    uint32_t gap       = ringDim / dslots;
    for (usint i = 0; i < vec.size(); i++) {
        NativeInteger n((unsigned __int128)vec[i]);
        if (n > bigValueHf) {
            (*nativeVec)[gap * i] = n.ModSub(diff, modulus);
        }
        else {
            (*nativeVec)[gap * i] = n.Mod(modulus);
        }
    }
}
#else  // NATIVEINT == 64
void SWITCHCKKSRNS::FitToNativeVector(uint32_t ringDim, const std::vector<int64_t>& vec, int64_t bigBound,
                                      NativeVector* nativeVec) const {
    if (nativeVec == nullptr)
        OPENFHE_THROW(config_error, "The passed native vector is empty.");
    NativeInteger bigValueHf(bigBound >> 1);
    NativeInteger modulus(nativeVec->GetModulus());
    NativeInteger diff = bigBound - modulus;
    uint32_t dslots    = vec.size();
    uint32_t gap       = ringDim / dslots;
    for (usint i = 0; i < vec.size(); i++) {
        NativeInteger n(vec[i]);
        if (n > bigValueHf) {
            (*nativeVec)[gap * i] = n.ModSub(diff, modulus);
        }
        else {
            (*nativeVec)[gap * i] = n.Mod(modulus);
        }
    }
}
#endif

//------------------------------------------------------------------------------
// Key and modulus switch and extraction methods
//------------------------------------------------------------------------------

NativeInteger RoundqQAlter(const NativeInteger& v, const NativeInteger& q, const NativeInteger& Q) {
    return NativeInteger(
               (BasicInteger)std::floor(0.5 + v.ConvertToDouble() * q.ConvertToDouble() / Q.ConvertToDouble()))
        .Mod(q);
}

NativeInteger RoundqScale(const NativeInteger& v, const NativeInteger& q, const double& Q) {
    return NativeInteger((BasicInteger)std::floor(0.5 + v.ConvertToDouble() / Q * q.ConvertToDouble())).Mod(q);
}

NativeInteger RoundqScaleAlter(const NativeInteger& v, const NativeInteger& q, const double& scFactor,
                               const NativeInteger& p) {
    return NativeInteger((BasicInteger)std::floor(0.5 + v.ConvertToDouble() / scFactor *
                                                            (q.ConvertToDouble() / p.ConvertToDouble())))
        .Mod(q);
}

EvalKey<DCRTPoly> switchingKeyGenRLWE(
    const PrivateKey<DCRTPoly>& ckksSK,
    ConstLWEPrivateKey& LWEsk) {  // This function is without the intermediate ModSwitch
    // Extract CKKS params: method which populates the first n elements of a new RLWE key with the n elements of the target LWE key
    auto skelements = ckksSK->GetPrivateElement();
    skelements.SetFormat(Format::COEFFICIENT);
    auto lweskElements = LWEsk->GetElement();
    for (size_t i = 0; i < skelements.GetNumOfElements(); i++) {
        auto skelementsPlain = skelements.GetElementAtIndex(i);
        for (size_t j = 0; j < skelementsPlain.GetLength(); j++) {
            if (j >= lweskElements.GetLength()) {
                skelementsPlain[j] = 0;
            }
            else {
                if (lweskElements[j] == 0) {
                    skelementsPlain[j] = 0;
                }
                else if (lweskElements[j].ConvertToInt() == 1) {
                    skelementsPlain[j] = 1;
                }
                else
                    skelementsPlain[j] = skelementsPlain.GetModulus() - 1;
            }
        }
        skelements.SetElementAtIndex(i, skelementsPlain);
    }

    skelements.SetFormat(Format::EVALUATION);

    auto ccCKKS    = ckksSK->GetCryptoContext();
    auto RLWELWEsk = ccCKKS->KeyGen().secretKey;
    RLWELWEsk->SetPrivateElement(std::move(skelements));

    return ccCKKS->KeySwitchGen(ckksSK, RLWELWEsk);
}

void ModSwitch(ConstCiphertext<DCRTPoly> ctxt, Ciphertext<DCRTPoly>& ctxtKS, NativeInteger modulus_CKKS_to) {
    if (ctxt->GetElements()[0].GetRingDimension() != ctxtKS->GetElements()[0].GetRingDimension()) {
        OPENFHE_THROW(not_implemented_error, "ModSwitch is implemented only for the same ring dimension.");
    }

    auto Q = ctxt->GetElements()[0].GetModulus();

    const std::vector<DCRTPoly> cv = ctxt->GetElements();

    if (cv[0].GetNumOfElements() != 1 || ctxtKS->GetElements()[0].GetNumOfElements() != 1) {
        OPENFHE_THROW(not_implemented_error, "ModSwitch is implemented only for ciphertext with one tower.");
    }

    const auto& paramsQlP = ctxtKS->GetElements()[0].GetParams();
    std::vector<DCRTPoly> resultElements(cv.size());

    for (uint32_t i = 0; i < cv.size(); i++) {
        resultElements[i] = DCRTPoly(paramsQlP, Format::COEFFICIENT, true);
        resultElements[i].SetValuesModSwitch(cv[i], modulus_CKKS_to);
        resultElements[i].SetFormat(Format::EVALUATION);
    }

    ctxtKS->SetElements(resultElements);
}

EvalKey<DCRTPoly> switchingKeyGen(const PrivateKey<DCRTPoly>& ckksSKto, const PrivateKey<DCRTPoly>& ckksSKfrom) {
    auto skElements = ckksSKto->GetPrivateElement();
    skElements.SetFormat(Format::COEFFICIENT);
    auto skElementsFrom = ckksSKfrom->GetPrivateElement();
    skElementsFrom.SetFormat(Format::COEFFICIENT);

    for (size_t i = 0; i < skElements.GetNumOfElements(); i++) {
        auto skElementsPlain     = skElements.GetElementAtIndex(i);
        auto skElementsFromPlain = skElementsFrom.GetElementAtIndex(i);
        for (size_t j = 0; j < skElementsPlain.GetLength(); j++) {
            if (skElementsFromPlain[j] == 0) {
                skElementsPlain[j] = 0;
            }
            else if (skElementsFromPlain[j] == 1) {
                skElementsPlain[j] = 1;
            }
            else
                skElementsPlain[j] = skElementsPlain.GetModulus() - 1;
        }
        skElements.SetElementAtIndex(i, skElementsPlain);
    }

    skElements.SetFormat(Format::EVALUATION);

    auto ccCKKSto        = ckksSKto->GetCryptoContext();
    auto oldTranformedSK = ccCKKSto->KeyGen().secretKey;
    oldTranformedSK->SetPrivateElement(std::move(skElements));

    return ccCKKSto->KeySwitchGen(oldTranformedSK, ckksSKto);
}

EvalKey<DCRTPoly> switchingKeyGenRLWEcc(const PrivateKey<DCRTPoly>& ckksSKto, const PrivateKey<DCRTPoly>& ckksSKfrom,
                                        ConstLWEPrivateKey& LWEsk) {
    auto skElements = ckksSKto->GetPrivateElement();
    skElements.SetFormat(Format::COEFFICIENT);
    auto skElementsFrom = ckksSKfrom->GetPrivateElement();
    skElementsFrom.SetFormat(Format::COEFFICIENT);
    auto skElements2 = ckksSKto->GetPrivateElement();
    skElements2.SetFormat(Format::COEFFICIENT);
    auto lweskElements = LWEsk->GetElement();

    for (size_t i = 0; i < skElements.GetNumOfElements(); i++) {
        auto skElementsPlain     = skElements.GetElementAtIndex(i);
        auto skElementsFromPlain = skElementsFrom.GetElementAtIndex(i);
        auto skElementsPlainLWE  = skElements2.GetElementAtIndex(i);
        for (size_t j = 0; j < skElementsPlain.GetLength(); j++) {
            if (skElementsFromPlain[j] == 0) {
                skElementsPlain[j] = 0;
            }
            else if (skElementsFromPlain[j] == 1) {
                skElementsPlain[j] = 1;
            }
            else
                skElementsPlain[j] = skElementsPlain.GetModulus() - 1;

            if (j >= lweskElements.GetLength()) {
                skElementsPlainLWE[j] = 0;
            }
            else {
                if (lweskElements[j] == 0) {
                    skElementsPlainLWE[j] = 0;
                }
                else if (lweskElements[j].ConvertToInt() == 1) {
                    skElementsPlainLWE[j] = 1;
                }
                else
                    skElementsPlainLWE[j] = skElementsPlain.GetModulus() - 1;
            }
        }
        skElements.SetElementAtIndex(i, skElementsPlain);
        skElements2.SetElementAtIndex(i, skElementsPlainLWE);
    }

    skElements.SetFormat(Format::EVALUATION);
    skElements2.SetFormat(Format::EVALUATION);

    auto ccCKKSto        = ckksSKto->GetCryptoContext();
    auto oldTranformedSK = ccCKKSto->KeyGen().secretKey;
    oldTranformedSK->SetPrivateElement(std::move(skElements));
    auto RLWELWEsk = ccCKKSto->KeyGen().secretKey;
    RLWELWEsk->SetPrivateElement(std::move(skElements2));

    return ccCKKSto->KeySwitchGen(oldTranformedSK, RLWELWEsk);
}

std::vector<std::vector<NativeInteger>> ExtractLWEpacked(const Ciphertext<DCRTPoly>& ct) {
    auto originalA{(ct->GetElements()[1]).GetElementAtIndex(0)};
    auto originalB{(ct->GetElements()[0]).GetElementAtIndex(0)};
    originalA.SetFormat(Format::COEFFICIENT);
    originalB.SetFormat(Format::COEFFICIENT);
    auto N = originalB.GetLength();

    std::vector<std::vector<NativeInteger>> extracted(2);
    extracted[0].reserve(N);
    extracted[1].reserve(N);

    auto& originalAVals = originalA.GetValues();
    auto& originalBVals = originalB.GetValues();

    extracted[1].insert(extracted[1].end(), &originalAVals[0], &originalAVals[N]);
    extracted[0].insert(extracted[0].end(), &originalBVals[0], &originalBVals[N]);

    return extracted;
}

std::shared_ptr<LWECiphertextImpl> ExtractLWECiphertext(const std::vector<std::vector<NativeInteger>>& aANDb,
                                                        NativeInteger modulus, uint32_t n, uint32_t index = 0) {
    auto N = aANDb[0].size();
    NativeVector a(n, modulus);
    NativeInteger b;

    for (size_t i = 0; i < n && i <= index; ++i) {
        a[i] = modulus - aANDb[1][index - i];
    }
    if (n > index) {
        for (size_t i = index + 1; i < n; ++i) {
            a[i] = aANDb[1][N + index - i];
        }
    }

    b           = aANDb[0][index];
    auto result = std::make_shared<LWECiphertextImpl>(std::move(a), std::move(b));
    return result;
}

//------------------------------------------------------------------------------
// Linear transformation methods.
// Currently mostly copied from ckksrns-fhe, because there an internal bootstrapping global structure is used.
// TODO: fix this.
//------------------------------------------------------------------------------

std::vector<ConstPlaintext> SWITCHCKKSRNS::EvalLTPrecomputeSwitch(
    const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A,
    const std::vector<std::vector<std::complex<double>>>& B, uint32_t dim1, uint32_t L, double scale = 1) const {
    uint32_t slots = A.size();
    uint32_t M     = cc.GetCyclotomicOrder();

    // Computing the baby-step bStep and the giant-step gStep
    uint32_t bStep = (dim1 == 0) ? getRatioBSGSLT(slots) : dim1;
    uint32_t gStep = ceil(static_cast<double>(slots) / bStep);

    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParamsCKKS->GetElementParams());
    uint32_t towersToDrop                         = 0;
    if (L != 0) {
        towersToDrop = elementParams.GetParams().size() - L - 1;
        for (uint32_t i = 0; i < towersToDrop; i++)
            elementParams.PopLastParam();
    }

    auto paramsQ = elementParams.GetParams();
    usint sizeQ  = paramsQ.size();
    auto paramsP = cryptoParamsCKKS->GetParamsP()->GetParams();
    usint sizeP  = paramsP.size();

    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);
    for (size_t i = 0; i < sizeQ; i++) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i]  = paramsQ[i]->GetRootOfUnity();
    }

    for (size_t i = 0; i < sizeP; i++) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i]  = paramsP[i]->GetRootOfUnity();
    }

    auto elementParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(M, moduli, roots);

    std::vector<std::vector<std::complex<double>>> newA(slots);
    std::vector<ConstPlaintext> result(slots);

    //  A and B are concatenated horizontally
    for (uint32_t i = 0; i < A.size(); i++) {
        auto vecA        = A[i];
        const auto& vecB = B[i];
        vecA.insert(vecA.end(), vecB.begin(), vecB.end());
        newA[i] = std::move(vecA);
    }

#pragma omp parallel for
    for (uint32_t j = 0; j < gStep; j++) {
        int32_t offset = -static_cast<int32_t>(bStep * j);
        for (uint32_t i = 0; i < bStep; i++) {
            if (bStep * j + i < slots) {
                // shifted diagonal is computed for rectangular map newA of dimension slots x 2*slots
                auto vec = ExtractShiftedDiagonal(newA, bStep * j + i);
                std::transform(vec.begin(), vec.end(), vec.begin(),
                               [&](const std::complex<double>& elem) { return elem * scale; });

                result[bStep * j + i] =
                    MakeAuxPlaintext(cc, elementParamsPtr, Rotate(Fill(vec, M / 4), offset), 1, towersToDrop, M / 4);
            }
        }
    }
    return result;
}

std::vector<ConstPlaintext> SWITCHCKKSRNS::EvalLTPrecomputeSwitch(
    const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A, uint32_t dim1,
    uint32_t L, double scale = 1) const {
    if (A[0].size() != A.size()) {
        OPENFHE_THROW(math_error, "The matrix passed to EvalLTPrecomputeSwitch is not square");
    }

    uint32_t slots = A.size();

    uint32_t M     = cc.GetCyclotomicOrder();
    uint32_t bStep = (dim1 == 0) ? getRatioBSGSLT(slots) : dim1;
    uint32_t gStep = ceil(static_cast<double>(slots) / bStep);

    // Make sure the plaintext is created only with the necessary amount of moduli
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());

    uint32_t towersToDrop = 0;
    if (L != 0) {
        towersToDrop = elementParams.GetParams().size() - L - 1;
        for (uint32_t i = 0; i < towersToDrop; i++)
            elementParams.PopLastParam();
    }

    auto paramsQ = elementParams.GetParams();
    usint sizeQ  = paramsQ.size();
    auto paramsP = cryptoParams->GetParamsP()->GetParams();
    usint sizeP  = paramsP.size();

    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);

    for (size_t i = 0; i < sizeQ; i++) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i]  = paramsQ[i]->GetRootOfUnity();
    }

    for (size_t i = 0; i < sizeP; i++) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i]  = paramsP[i]->GetRootOfUnity();
    }

    auto elementParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(M, moduli, roots);

    std::vector<ConstPlaintext> result(slots);
#pragma omp parallel for
    for (uint32_t j = 0; j < gStep; j++) {
        int32_t offset = -static_cast<int32_t>(bStep * j);
        for (uint32_t i = 0; i < bStep; i++) {
            if (bStep * j + i < slots) {
                auto diag = ExtractShiftedDiagonal(A, bStep * j + i);
                std::transform(diag.begin(), diag.end(), diag.begin(),
                               [&](const std::complex<double>& elem) { return elem * scale; });
                result[bStep * j + i] =
                    MakeAuxPlaintext(cc, elementParamsPtr, Rotate(Fill(diag, M / 4), offset), 1, towersToDrop, M / 4);
            }
        }
    }

    return result;
}

std::vector<std::vector<std::complex<double>>> EvalLTRectPrecomputeSwitch(
    const std::vector<std::vector<std::complex<double>>>& A, uint32_t dim1, double scale) {
    if ((A.size() / A[0].size()) * A[0].size() != A.size()) {
        OPENFHE_THROW(math_error, "The matrix passed to EvalLTPrecompute is not in proper rectangular shape");
    }
    uint32_t n     = A[0].size();  //
    uint32_t bStep = (dim1 == 0) ? getRatioBSGSLT(n) : dim1;
    uint32_t gStep = ceil(static_cast<double>(n) / bStep);

    auto num_slices = A.size() / A[0].size();
    std::vector<std::vector<std::vector<std::complex<double>>>> A_slices(num_slices);
    for (size_t i = 0; i < num_slices; i++) {
        A_slices[i] = std::vector<std::vector<std::complex<double>>>(A.begin() + i * A[0].size(),
                                                                     A.begin() + (i + 1) * A[0].size());
    }
    std::vector<std::vector<std::complex<double>>> diags(n);
#pragma omp parallel for
    for (uint32_t j = 0; j < gStep; j++) {
        for (uint32_t i = 0; i < bStep; i++) {
            if (bStep * j + i < n) {
                std::vector<std::complex<double>> diag(0);
                for (uint32_t k = 0; k < num_slices; k++) {
                    auto tmp = ExtractShiftedDiagonal(A_slices[k], bStep * j + i);
                    diag.insert(diag.end(), tmp.begin(), tmp.end());
                }
                std::transform(diag.begin(), diag.end(), diag.begin(),
                               [&](const std::complex<double>& elem) { return elem * scale; });
                diags[bStep * j + i] = diag;
            }
        }
    }

    return diags;
}

Ciphertext<DCRTPoly> SWITCHCKKSRNS::EvalLTWithPrecomputeSwitch(const CryptoContextImpl<DCRTPoly>& cc,
                                                               ConstCiphertext<DCRTPoly> ctxt,
                                                               const std::vector<ConstPlaintext>& A,
                                                               uint32_t dim1) const {
    uint32_t slots = A.size();

    // Computing the baby-step bStep and the giant-step gStep
    uint32_t bStep = dim1;
    uint32_t gStep = ceil(static_cast<double>(slots) / bStep);

    uint32_t M = cc.GetCyclotomicOrder();
    uint32_t N = cc.GetRingDimension();

    // Computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits = cc.EvalFastRotationPrecompute(ctxt);

    std::vector<Ciphertext<DCRTPoly>> fastRotation(bStep - 1);

    // Hoisted automorphisms
#pragma omp parallel for
    for (uint32_t j = 1; j < bStep; j++)
        fastRotation[j - 1] = cc.EvalFastRotationExt(ctxt, j, digits, true);

    Ciphertext<DCRTPoly> result;
    DCRTPoly first;

    for (uint32_t j = 0; j < gStep; j++) {
        Ciphertext<DCRTPoly> inner = EvalMultExt(cc.KeySwitchExt(ctxt, true), A[bStep * j]);

        for (uint32_t i = 1; i < bStep; i++) {
            if (bStep * j + i < slots) {
                EvalAddExtInPlace(inner, EvalMultExt(fastRotation[i - 1], A[bStep * j + i]));
            }
        }

        if (j == 0) {
            first         = cc.KeySwitchDownFirstElement(inner);
            auto elements = inner->GetElements();
            elements[0].SetValuesToZero();
            inner->SetElements(elements);
            result = inner;
        }
        else {
            inner = cc.KeySwitchDown(inner);
            // Find the automorphism index that corresponds to the rotation index.
            usint autoIndex = FindAutomorphismIndex2nComplex(bStep * j, M);
            std::vector<usint> map(N);
            PrecomputeAutoMap(N, autoIndex, &map);
            DCRTPoly firstCurrent = inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
            first += firstCurrent;

            auto innerDigits = cc.EvalFastRotationPrecompute(inner);
            EvalAddExtInPlace(result, cc.EvalFastRotationExt(inner, bStep * j, innerDigits, false));
        }
    }

    result        = cc.KeySwitchDown(result);
    auto elements = result->GetElements();
    elements[0] += first;
    result->SetElements(elements);

    return result;
}

Ciphertext<DCRTPoly> SWITCHCKKSRNS::EvalLTRectWithPrecomputeSwitch(
    const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A,
    ConstCiphertext<DCRTPoly> ct, uint32_t dim1, uint32_t L) const {
    uint32_t n = A.size();

    // Computing the baby-step bStep and the giant-step gStep
    uint32_t bStep = (dim1 == 0) ? getRatioBSGSLT(n) : dim1;
    uint32_t gStep = ceil(static_cast<double>(n) / bStep);

    uint32_t M = cc.GetCyclotomicOrder();
    uint32_t N = cc.GetRingDimension();

    // Computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits = cc.EvalFastRotationPrecompute(ct);

    std::vector<Ciphertext<DCRTPoly>> fastRotation(bStep - 1);

    // Make sure the plaintext is created only with the necessary amount of moduli
    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ct->GetCryptoParameters());

    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParamsCKKS->GetElementParams());
    uint32_t towersToDrop                         = 0;

    // For FLEXIBLEAUTOEXT we do not need extra modulus in auxiliary plaintexts
    if (L != 0) {
        towersToDrop = elementParams.GetParams().size() - L - 1;
        for (uint32_t i = 0; i < towersToDrop; i++)
            elementParams.PopLastParam();
    }
    if (cryptoParamsCKKS->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
        towersToDrop += 1;
        elementParams.PopLastParam();
    }

    auto paramsQ = elementParams.GetParams();
    usint sizeQ  = paramsQ.size();
    auto paramsP = cryptoParamsCKKS->GetParamsP()->GetParams();
    usint sizeP  = paramsP.size();

    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);

    for (size_t i = 0; i < sizeQ; i++) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i]  = paramsQ[i]->GetRootOfUnity();
    }

    for (size_t i = 0; i < sizeP; i++) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i]  = paramsP[i]->GetRootOfUnity();
    }

    auto elementParamsPtr  = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(M, moduli, roots);
    auto elementParamsPtr2 = std::dynamic_pointer_cast<typename DCRTPoly::Params>(elementParamsPtr);

// Hoisted automorphisms
#pragma omp parallel for
    for (uint32_t j = 1; j < bStep; j++) {
        fastRotation[j - 1] = cc.EvalFastRotationExt(ct, j, digits, true);
    }

    Ciphertext<DCRTPoly> result;
    DCRTPoly first;

    for (uint32_t j = 0; j < gStep; j++) {
        int32_t offset = (j == 0) ? 0 : -static_cast<int32_t>(bStep * j);
        auto temp      = cc.MakeCKKSPackedPlaintext(Rotate(Fill(A[bStep * j], N / 2), offset), 1, towersToDrop,
                                                    elementParamsPtr2, N / 2);
        Ciphertext<DCRTPoly> inner = EvalMultExt(cc.KeySwitchExt(ct, true), temp);

        for (uint32_t i = 1; i < bStep; i++) {
            if (bStep * j + i < n) {
                auto tempi = cc.MakeCKKSPackedPlaintext(Rotate(Fill(A[bStep * j + i], N / 2), offset), 1, towersToDrop,
                                                        elementParamsPtr2, N / 2);
                EvalAddExtInPlace(inner, EvalMultExt(fastRotation[i - 1], tempi));
            }
        }

        if (j == 0) {
            first         = cc.KeySwitchDownFirstElement(inner);
            auto elements = inner->GetElements();
            elements[0].SetValuesToZero();
            inner->SetElements(elements);
            result = inner;
        }
        else {
            inner = cc.KeySwitchDown(inner);
            // Find the automorphism index that corresponds to rotation index index.
            usint autoIndex = FindAutomorphismIndex2nComplex(bStep * j, M);
            std::vector<usint> map(N);
            PrecomputeAutoMap(N, autoIndex, &map);
            DCRTPoly firstCurrent = inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
            first += firstCurrent;

            auto innerDigits = cc.EvalFastRotationPrecompute(inner);
            EvalAddExtInPlace(result, cc.EvalFastRotationExt(inner, bStep * j, innerDigits, false));
        }
    }
    result        = cc.KeySwitchDown(result);
    auto elements = result->GetElements();
    elements[0] += first;
    result->SetElements(elements);

    return result;
}

Ciphertext<DCRTPoly> SWITCHCKKSRNS::EvalSlotsToCoeffsSwitch(const CryptoContextImpl<DCRTPoly>& cc,
                                                            ConstCiphertext<DCRTPoly> ctxt) const {
    uint32_t slots = m_numSlotsCKKS;
    uint32_t m     = 4 * slots;
    uint32_t M     = cc.GetCyclotomicOrder();
    bool isSparse  = (M != m) ? true : false;

    auto ctxtToDecode = ctxt->Clone();
    ctxtToDecode      = cc.Compress(ctxtToDecode, 2);

    Ciphertext<DCRTPoly> ctxtDecoded;

    if (slots != m_numSlotsCKKS || m_U0Pre.size() == 0) {
        std::string errorMsg(std::string("Precomputations for ") + std::to_string(slots) +
                             std::string(" slots were not generated") +
                             std::string(" Need to call EvalCKKSToFHEWPrecompute to proceed"));
        OPENFHE_THROW(type_error, errorMsg);
    }

    if (!isSparse) {  // fully packed
        // ctxtToDecode = cc.EvalAdd(ctxtToDecode, cc.GetScheme()->MultByMonomial(ctxtToDecode, M / 4));
        ctxtDecoded = EvalLTWithPrecomputeSwitch(cc, ctxtToDecode, m_U0Pre, m_dim1CF);
    }
    else {  // sparsely packed
        ctxtDecoded = EvalLTWithPrecomputeSwitch(cc, ctxtToDecode, m_U0Pre, m_dim1CF);
        ctxtDecoded = cc.EvalAdd(ctxtDecoded, cc.EvalAtIndex(ctxtDecoded, slots));
    }

    return ctxtDecoded;
}

Ciphertext<DCRTPoly> SWITCHCKKSRNS::EvalPartialHomDecryption(const CryptoContextImpl<DCRTPoly>& cc,
                                                             const std::vector<std::vector<std::complex<double>>>& A,
                                                             ConstCiphertext<DCRTPoly> ct, uint32_t dim1, double scale,
                                                             uint32_t L) const {
    // Ensure the # rows (# of LWE ciphertext to switch) is a multiple of # columns (the lattice parameter n)
    std::vector<std::vector<std::complex<double>>> Acopy(A);
    if ((A.size() % A[0].size()) != 0) {
        std::vector<std::vector<std::complex<double>>> padding(A[0].size() - (A.size() % A[0].size()));
        for (size_t i = 0; i < padding.size(); i++) {
            padding[i] = std::vector<std::complex<double>>(A[0].size());
        }
        Acopy.insert(Acopy.end(), padding.begin(), padding.end());
    }

    auto Apre = EvalLTRectPrecomputeSwitch(Acopy, dim1, scale);
    auto res =
        EvalLTRectWithPrecomputeSwitch(cc, Apre, ct, dim1, L);  // The result is repeated every Acopy.size() slots

    return res;
}

//------------------------------------------------------------------------------
// Scheme switching Wrapper
//------------------------------------------------------------------------------
std::pair<BinFHEContext, LWEPrivateKey> SWITCHCKKSRNS::EvalCKKStoFHEWSetup(const CryptoContextImpl<DCRTPoly>& cc,
                                                                           SecurityLevel sl, BINFHE_PARAMSET slBin,
                                                                           bool arbFunc, uint32_t logQ, bool dynamic,
                                                                           uint32_t numSlotsCKKS, uint32_t logQswitch) {
    m_ccLWE = BinFHEContext();
    if (slBin != TOY && slBin != STD128)
        OPENFHE_THROW(config_error, "Only STD128 or TOY are currently supported.");
    m_ccLWE.BinFHEContext::GenerateBinFHEContext(slBin, arbFunc, logQ, 0, GINX, dynamic);

    // For arbitrary functions, the LWE ciphertext needs to be at most the ring dimension in FHEW bootstrapping
    m_modulus_LWE = (arbFunc == false) ? 1 << logQ : m_ccLWE.GetParams()->GetLWEParams()->Getq().ConvertToInt();

    // LWE private key
    LWEPrivateKey lwesk;
    lwesk = m_ccLWE.KeyGen();

    std::pair<BinFHEContext, LWEPrivateKey> FHEWcc;
    FHEWcc.first  = m_ccLWE;
    FHEWcc.second = lwesk;

    uint32_t M = cc.GetCyclotomicOrder();
    if (numSlotsCKKS == 0 || numSlotsCKKS == M / 4)  // fully-packed
        m_numSlotsCKKS = M / 4;
    else  // sparsely-packed
        m_numSlotsCKKS = numSlotsCKKS;

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ                                  = elementParams.GetParams();
    m_modulus_CKKS_initial                        = paramsQ[0]->GetModulus().ConvertToInt();
    // Modulus to switch to in order to have secure RLWE samples with ring dimension n.
    // We can select any Qswitch less than 27 bits corresponding to 128 bits of security for lattice parameter n=1024 < 1305
    // according to https://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf
    // or any Qswitch for TOY security.
    // Ensure that Qswitch is larger than Q_FHEW and smaller than Q_CKKS.
    if (logQ >= logQswitch || logQswitch > GetMSB(m_modulus_CKKS_initial.ConvertToInt()) - 1)
        OPENFHE_THROW(config_error, "Qswitch should be larger than QFHEW and smaller than QCKKS.");

    // Intermediate cryptocontext
    uint32_t multDepth    = 0;
    uint32_t scaleModSize = cc.GetEncodingParams()->GetPlaintextModulus();

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetFirstModSize(logQswitch);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(
        FIXEDMANUAL);  // This doesn't need this to be the same scaling technique as the outer cryptocontext, since we only do a key switch
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(cc.GetRingDimension());
    parameters.SetBatchSize(cc.GetEncodingParams()->GetBatchSize());

    m_ccKS = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    m_ccKS->Enable(PKE);
    m_ccKS->Enable(KEYSWITCH);
    m_ccKS->Enable(LEVELEDSHE);
    m_ccKS->Enable(ADVANCEDSHE);
    m_ccKS->Enable(SCHEMESWITCH);
    m_ccKS->Enable(FHE);

    // Get the ciphertext modulus
    const auto cryptoParams2 = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(m_ccKS->GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams2 = *(cryptoParams2->GetElementParams());
    auto paramsQ2                                  = elementParams2.GetParams();
    m_modulus_CKKS_from                            = paramsQ2[0]->GetModulus().ConvertToInt();

    return FHEWcc;
}

std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> SWITCHCKKSRNS::EvalCKKStoFHEWKeyGen(
    const KeyPair<DCRTPoly>& keyPair, ConstLWEPrivateKey& lwesk, uint32_t dim1, uint32_t L) {
    auto privateKey = keyPair.secretKey;
    auto publicKey  = keyPair.publicKey;

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(privateKey->GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW(config_error,
                      "CKKS to FHEW scheme switching is only supported for the Hybrid key switching method.");
#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW(config_error,
                      "128-bit CKKS to FHEW scheme switching is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif

    auto ccCKKS = privateKey->GetCryptoContext();

    // Intermediate cryptocontext for CKKS to FHEW
    auto keys2 = m_ccKS->KeyGen();

    Plaintext ptxtZeroKS = m_ccKS->MakeCKKSPackedPlaintext(std::vector<double>{0.0});
    m_ctxtKS             = m_ccKS->Encrypt(keys2.publicKey, ptxtZeroKS);

    // Compute switching key between RLWE and LWE via the intermediate cryptocontext, keep it in RLWE form
    m_CKKStoFHEWswk = switchingKeyGenRLWEcc(keys2.secretKey, privateKey, lwesk);

    // Compute automorphism keys
    uint32_t M     = ccCKKS->GetCyclotomicOrder();
    uint32_t slots = m_numSlotsCKKS;
    // Computing the baby-step
    if (dim1 == 0)
        dim1 = getRatioBSGSLT(slots);
    m_dim1CF = dim1;
    m_LCF    = L;

    // Compute indices for rotations for slotToCoeff transform
    std::vector<int32_t> indexRotationS2C = FindLTRotationIndicesSwitch(m_dim1CF, M, slots);
    indexRotationS2C.emplace_back(static_cast<int32_t>(slots));

    // Remove possible duplicates
    sort(indexRotationS2C.begin(), indexRotationS2C.end());
    indexRotationS2C.erase(unique(indexRotationS2C.begin(), indexRotationS2C.end()), indexRotationS2C.end());

    auto algo     = ccCKKS->GetScheme();
    auto evalKeys = algo->EvalAtIndexKeyGen(publicKey, privateKey, indexRotationS2C);

    const DCRTPoly& s                       = privateKey->GetPrivateElement();
    usint N                                 = s.GetRingDimension();
    PrivateKey<DCRTPoly> privateKeyPermuted = std::make_shared<PrivateKeyImpl<DCRTPoly>>(ccCKKS);
    usint index                             = 2 * N - 1;
    std::vector<usint> vec(N);
    PrecomputeAutoMap(N, index, &vec);
    DCRTPoly sPermuted = s.AutomorphismTransform(index, vec);
    privateKeyPermuted->SetPrivateElement(sPermuted);
    privateKeyPermuted->SetKeyTag(privateKey->GetKeyTag());
    auto conjKey       = algo->KeySwitchGen(privateKey, privateKeyPermuted);
    (*evalKeys)[M - 1] = conjKey;

    // Compute multiplication key
    algo->EvalMultKeyGen(privateKey);

    return evalKeys;
}

void SWITCHCKKSRNS::EvalCKKStoFHEWPrecompute(const CryptoContextImpl<DCRTPoly>& cc, double scale) {
    uint32_t M     = cc.GetCyclotomicOrder();
    uint32_t slots = m_numSlotsCKKS;

    uint32_t m    = 4 * m_numSlotsCKKS;
    bool isSparse = (M != m) ? true : false;

    // Computes indices for all primitive roots of unity
    std::vector<uint32_t> rotGroup(slots);
    uint32_t fivePows = 1;
    for (uint32_t i = 0; i < slots; ++i) {
        rotGroup[i] = fivePows;
        fivePows *= 5;
        fivePows %= m;
    }
    // Computes all powers of a primitive root of unity exp(2*M_PI/m)
    std::vector<std::complex<double>> ksiPows(m + 1);
    for (uint32_t j = 0; j < m; ++j) {
        double angle = 2.0 * M_PI * j / m;
        ksiPows[j].real(cos(angle));
        ksiPows[j].imag(sin(angle));
    }
    ksiPows[m] = ksiPows[0];

    // Matrices for decoding
    std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
    std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));

    for (size_t i = 0; i < slots; i++) {
        for (size_t j = 0; j < slots; j++) {
            U0[i][j] = ksiPows[(j * rotGroup[i]) % m];
            U1[i][j] = std::complex<double>(0, 1) * U0[i][j];
        }
    }

    if (!isSparse) {  // fully packed
        m_U0Pre = EvalLTPrecomputeSwitch(cc, U0, m_dim1CF, m_LCF, scale);
    }
    else {  // sparsely packed
        m_U0Pre = EvalLTPrecomputeSwitch(cc, U0, U1, m_dim1CF, m_LCF, scale);
    }
}

std::vector<std::shared_ptr<LWECiphertextImpl>> SWITCHCKKSRNS::EvalCKKStoFHEW(ConstCiphertext<DCRTPoly> ciphertext,
                                                                              uint32_t numCtxts) {
    auto ccCKKS    = ciphertext->GetCryptoContext();
    uint32_t slots = m_numSlotsCKKS;

    // Step 1. Homomorphic decoding
    auto ctxtDecoded = EvalSlotsToCoeffsSwitch(*ccCKKS, ciphertext);
    ctxtDecoded      = ccCKKS->Compress(ctxtDecoded);

    // Step 2. Modulus switch to Q', such that CKKS is secure for (Q',n)
    auto ctxtKS = m_ctxtKS->Clone();
    ModSwitch(ctxtDecoded, ctxtKS, m_modulus_CKKS_from);

    // Step 3: Key switch from the CKKS key with the new modulus Q' to the RLWE version of the FHEW key with the new modulus Q'
    auto ctSwitched = m_ccKS->KeySwitch(ctxtKS, m_CKKStoFHEWswk);

    // Step 4. Extract LWE ciphertexts with the modulus Q'
    uint32_t n = m_ccLWE.GetParams()->GetLWEParams()->Getn();  // lattice parameter for additive LWE
    std::vector<std::shared_ptr<LWECiphertextImpl>> LWEciphertexts;
    auto AandB = ExtractLWEpacked(ctSwitched);

    if (numCtxts == 0 || numCtxts > slots) {
        numCtxts = slots;
    }

    uint32_t gap = m_ccKS->GetRingDimension() / (2 * slots);

    for (uint32_t i = 0, idx = 0; i < numCtxts; ++i, idx += gap) {
        auto temp = ExtractLWECiphertext(AandB, m_modulus_CKKS_from, n, idx);
        LWEciphertexts.emplace_back(temp);
    }

    // Step 5. Modulus switch to q in FHEW
    if (m_modulus_LWE != m_modulus_CKKS_from) {
#pragma omp parallel for
        for (uint32_t i = 0; i < numCtxts; i++) {
            auto original_a = LWEciphertexts[i]->GetA();
            auto original_b = LWEciphertexts[i]->GetB();
            // multiply by Q_LWE/Q' and round to Q_LWE
            NativeVector a_round(n, m_modulus_LWE);
            for (uint32_t j = 0; j < n; ++j) {
                a_round[j] = RoundqQAlter(original_a[j], m_modulus_LWE, m_modulus_CKKS_from);
            }
            NativeInteger b_round = RoundqQAlter(original_b, m_modulus_LWE, m_modulus_CKKS_from);
            LWEciphertexts[i]     = std::make_shared<LWECiphertextImpl>(std::move(a_round), std::move(b_round));
        }
    }

    return LWEciphertexts;
}

//------------------------------------------------------------------------------
// Scheme switching Wrapper
//------------------------------------------------------------------------------
void SWITCHCKKSRNS::EvalFHEWtoCKKSSetup(const CryptoContextImpl<DCRTPoly>& ccCKKS, const BinFHEContext& ccLWE,
                                        uint32_t numSlotsCKKS, uint32_t logQ) {
    m_ccLWE = ccLWE;

    if (m_ccLWE.GetParams()->GetLWEParams()->Getn() * 2 > ccCKKS.GetRingDimension())
        OPENFHE_THROW(config_error, "The lattice parameter in LWE cannot be larger than half the RLWE ring dimension.");

    if (numSlotsCKKS == 0) {
        if (ccCKKS.GetEncodingParams()->GetBatchSize() != 0)
            m_numSlotsCKKS = ccCKKS.GetEncodingParams()->GetBatchSize();
        else
            m_numSlotsCKKS = ccCKKS.GetRingDimension() / 2;
    }
    else {
        m_numSlotsCKKS = numSlotsCKKS;
    }

    m_modulus_LWE = (logQ != 0) ? 1 << logQ : m_ccLWE.GetParams()->GetLWEParams()->Getq().ConvertToInt();
}

std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> SWITCHCKKSRNS::EvalFHEWtoCKKSKeyGen(
    const KeyPair<DCRTPoly>& keyPair, ConstLWEPrivateKey& lwesk, uint32_t numSlots, uint32_t dim1, uint32_t L) {
    auto privateKey = keyPair.secretKey;
    auto publicKey  = keyPair.publicKey;

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(privateKey->GetCryptoParameters());
    auto ccCKKS             = privateKey->GetCryptoContext();

    uint32_t n       = lwesk->GetElement().GetLength();
    uint32_t ringDim = ccCKKS->GetRingDimension();

    // Generate FHEW to CKKS switching key, i.e., CKKS encryption of FHEW secret key
    auto skLWEElements = lwesk->GetElement();
    std::vector<std::complex<double>> skLWEDouble(n);
    for (uint32_t i = 0; i < n; i++) {
        auto tmp = skLWEElements[i].ConvertToDouble();
        if (tmp == lwesk->GetModulus().ConvertToInt() - 1)
            tmp = -1;
        skLWEDouble[i] = std::complex<double>(tmp, 0);
    }

    // Check encoding and specify the number of slots, otherwise, if batchsize is set and is smaller, it will throw an error.
    Plaintext skLWEPlainswk;
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        skLWEPlainswk = ccCKKS->MakeCKKSPackedPlaintext(Fill(skLWEDouble, ringDim / 2), 1, BASE_NUM_LEVELS_TO_DROP,
                                                        nullptr, ringDim / 2);
    else
        skLWEPlainswk = ccCKKS->MakeCKKSPackedPlaintext(Fill(skLWEDouble, ringDim / 2), 1, 0, nullptr, ringDim / 2);

    m_FHEWtoCKKSswk = ccCKKS->Encrypt(publicKey, skLWEPlainswk);

    // Compute automorphism keys for CKKS for baby-step giant-step
    uint32_t M = ccCKKS->GetCyclotomicOrder();
    if (dim1 == 0)
        dim1 = getRatioBSGSLT(n);
    m_dim1FC = dim1;
    m_LFC    = L;

    // Compute indices for rotations for homomorphic decryption in CKKS
    std::vector<int32_t> indexRotationHomDec = FindLTRotationIndicesSwitch(dim1, M, n);

    uint32_t slots = (numSlots == 0) ? m_numSlotsCKKS : numSlots;
    // Compute indices for rotations to bring back the final CKKS ciphertext encoding to slots
    if (ringDim > 2 * slots) {  // if the encoding is full, this does not execute
        indexRotationHomDec.reserve(indexRotationHomDec.size() + GetMSB(ringDim) - 2);
        for (uint32_t j = 1; j < ringDim / (2 * slots); j <<= 1) {
            indexRotationHomDec.emplace_back(j * slots);
        }
    }

    // Remove possible duplicates
    sort(indexRotationHomDec.begin(), indexRotationHomDec.end());
    indexRotationHomDec.erase(unique(indexRotationHomDec.begin(), indexRotationHomDec.end()),
                              indexRotationHomDec.end());

    auto algo     = ccCKKS->GetScheme();
    auto evalKeys = algo->EvalAtIndexKeyGen(publicKey, privateKey, indexRotationHomDec);

    // Compute multiplication key
    ccCKKS->EvalMultKeyGen(privateKey);

    return evalKeys;
}

Ciphertext<DCRTPoly> SWITCHCKKSRNS::EvalFHEWtoCKKS(std::vector<std::shared_ptr<LWECiphertextImpl>>& LWECiphertexts,
                                                   uint32_t numCtxts, uint32_t numSlots, uint32_t p, double pmin,
                                                   double pmax) const {
    if (!LWECiphertexts.size())
        OPENFHE_THROW(type_error, "Empty input FHEW ciphertext vector");
    uint32_t numLWECtxts = LWECiphertexts.size();

    uint32_t slots =
        (numSlots == 0) ? m_numSlotsCKKS : numSlots;  // This is the number of CKKS slots to use in encoding

    uint32_t numValues = (numCtxts == 0) ? numLWECtxts : std::min(numCtxts, numLWECtxts);
    numValues = std::min(numValues, slots);  // This is the number of LWE ciphertexts to pack into the CKKS ciphertext

    uint32_t n = LWECiphertexts[0]->GetA().GetLength();

    auto ccCKKS                 = m_FHEWtoCKKSswk->GetCryptoContext();
    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ccCKKS->GetCryptoParameters());

    uint32_t m    = 4 * slots;
    uint32_t M    = ccCKKS->GetCyclotomicOrder();
    uint32_t N    = ccCKKS->GetRingDimension();
    bool isSparse = (M != m) ? true : false;

    double K = 1.0;
    std::vector<double> coefficientsFHEW;  // EvalFHEWtoCKKS assumes lattice parameter n is at most 2048.
    if (n == 32) {
        K = 16.0;
        coefficientsFHEW.insert(coefficientsFHEW.end(), &g_coefficientsFHEW16[0], &g_coefficientsFHEW16[LEN_16]);
    }
    else {
        K = 128.0;  // Failure probability of 2^{-49}
        if (p <= 4) {
            coefficientsFHEW.insert(
                coefficientsFHEW.end(), &g_coefficientsFHEW128_8[0],
                &g_coefficientsFHEW128_8
                    [LEN_128_8]);  // If the output messages are bits, we could use a lower degree polynomial
        }
        else {
            coefficientsFHEW.insert(coefficientsFHEW.end(), &g_coefficientsFHEW128_9[0],
                                    &g_coefficientsFHEW128_9[LEN_128_9]);
        }
    }

    // Step 1. Form matrix A and vector b from the LWE ciphertexts, but only extract the first necessary number of them
    std::vector<std::vector<std::complex<double>>> A(numValues);

    // To have the same encoding as A*s, create b with the appropriate number of elements
    uint32_t b_size = numValues;
    if ((numValues % n) != 0) {
        b_size = numValues + n - (numValues % n);
    }
    std::vector<std::complex<double>> b(b_size);

    // Combine the scale with the division by K to consume fewer levels, but careful since the value might be too small
    double prescale = (1.0 / LWECiphertexts[0]->GetModulus().ConvertToDouble()) / K;

#pragma omp parallel for
    for (uint32_t i = 0; i < numValues; i++) {
        auto a = LWECiphertexts[i]->GetA();
        A[i]   = std::vector<std::complex<double>>(a.GetLength());
        for (uint32_t j = 0; j < a.GetLength(); j++) {
            A[i][j] = std::complex<double>(a[j].ConvertToDouble(), 0);
        }
        b[i] = std::complex<double>(LWECiphertexts[i]->GetB().ConvertToDouble(), 0);
    }

    // Step 2. Perform the homomorphic linear transformation of A*skLWE
    Ciphertext<DCRTPoly> AdotS = EvalPartialHomDecryption(*ccCKKS, A, m_FHEWtoCKKSswk, m_dim1FC, prescale, 0);

    // Step 3. Get the ciphertext of B - A*s
    for (uint32_t i = 0; i < numValues; i++) {
        b[i] *= prescale;
    }
    Plaintext BPlain = ccCKKS->MakeCKKSPackedPlaintext(b, AdotS->GetNoiseScaleDeg(), AdotS->GetLevel(), nullptr, N / 2);

    auto BminusAdotS = ccCKKS->EvalAdd(ccCKKS->EvalNegate(AdotS), BPlain);

    if (cryptoParamsCKKS->GetScalingTechnique() == FIXEDMANUAL) {
        ccCKKS->ModReduceInPlace(BminusAdotS);
    }
    else {
        if (BminusAdotS->GetNoiseScaleDeg() == 2)
            ccCKKS->GetScheme()->ModReduceInternalInPlace(BminusAdotS, BASE_NUM_LEVELS_TO_DROP);
    }

    // Step 4. Do the modulus reduction: homomorphically evaluate modular function. We do it by using sine approximation.
    auto BminusAdotS2 = BminusAdotS;  // Instead of zeroing out slots which are not of interest as done above

    double a_cheby = -1;
    double b_cheby = 1;  // The division by K was performed before

    // double a_cheby = -K; double b_cheby = K; // Alternatively, do this separately to not lose precision when scaling with everything at once
    // auto BminusAdotS2 = BminusAdotS;

    auto BminusAdotS3 = ccCKKS->EvalChebyshevSeries(BminusAdotS2, coefficientsFHEW, a_cheby, b_cheby);

    if (cryptoParamsCKKS->GetScalingTechnique() != FIXEDMANUAL) {
        ccCKKS->GetScheme()->ModReduceInternalInPlace(BminusAdotS3, BASE_NUM_LEVELS_TO_DROP);
    }

    enum { BT_ITER = 3 };
    for (int32_t j = 1; j < BT_ITER + 1; j++) {
        BminusAdotS3  = ccCKKS->EvalMult(BminusAdotS3, BminusAdotS3);
        BminusAdotS3  = ccCKKS->EvalAdd(BminusAdotS3, BminusAdotS3);
        double scalar = 1.0 / std::pow((2.0 * Pi), std::pow(2.0, j - BT_ITER));
        BminusAdotS3  = ccCKKS->EvalSub(BminusAdotS3, scalar);
        if (cryptoParamsCKKS->GetScalingTechnique() == FIXEDMANUAL) {
            ccCKKS->ModReduceInPlace(BminusAdotS3);
        }
        else {
            ccCKKS->GetScheme()->ModReduceInternalInPlace(BminusAdotS3, BASE_NUM_LEVELS_TO_DROP);
        }
    }

    /* For p <= 4 and when we only encrypt bits, we don't need sin(2pi*x)/2pi to approximate x,
     * we can directly use sin(0) for 0 and sin(pi/2) for 1.
     * Here pmax is actually the plaintext modulus, not the maximum value of the messages that we
     * consider. For plaintext modulus > 4, even if we only care about encrypting bits, 2pi is not
     * the correct post-scaling factor.
     * Moreover, we have to account for the different encoding the end ciphertext should have.
     */

    double postScale = 1.0;
    double postBias  = 0.0;
    if (p == 1 || p == 2 || p == 3 || p == 4) {
        postScale = 2 * Pi;
    }
    else {
        postScale = static_cast<double>(p);
    }

    if (pmin != 0) {
        postScale *= (pmax - pmin) / 4.0;
        postBias = (pmax - pmin) / 4.0;
    }

    // numValues are set; the rest of values up to N/2 are made zero when creating the plaintext
    std::vector<std::complex<double>> postScaleVec(numValues, std::complex<double>(postScale, 0));
    std::vector<std::complex<double>> postBiasVec(numValues, std::complex<double>(postBias, 0));

    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParamsCKKS->GetElementParams());

    uint32_t towersToDrop = BminusAdotS3->GetLevel() + BminusAdotS3->GetNoiseScaleDeg() - 1;
    for (uint32_t i = 0; i < towersToDrop; i++)
        elementParams.PopLastParam();

    auto paramsQ = elementParams.GetParams();
    usint sizeQ  = paramsQ.size();
    auto paramsP = cryptoParamsCKKS->GetParamsP()->GetParams();
    usint sizeP  = paramsP.size();

    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);
    for (size_t i = 0; i < sizeQ; i++) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i]  = paramsQ[i]->GetRootOfUnity();
    }

    for (size_t i = 0; i < sizeP; i++) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i]  = paramsP[i]->GetRootOfUnity();
    }

    auto elementParamsPtr  = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(M, moduli, roots);
    auto elementParamsPtr2 = std::dynamic_pointer_cast<typename DCRTPoly::Params>(elementParamsPtr);

    // Use full packing here to clear up the junk in the slots after numValues
    auto postScalePlain = ccCKKS->MakeCKKSPackedPlaintext(postScaleVec, 1, towersToDrop, elementParamsPtr2, N / 2);
    auto BminusAdotSres = ccCKKS->EvalMult(BminusAdotS3, postScalePlain);

    // Add the plaintext for bias at the correct level and depth
    auto postBiasPlain = ccCKKS->MakeCKKSPackedPlaintext(postBiasVec, BminusAdotSres->GetNoiseScaleDeg(),
                                                         BminusAdotSres->GetLevel(), nullptr, N / 2);

    BminusAdotSres = ccCKKS->EvalAdd(postBiasPlain, BminusAdotSres);

    // Go back to the sparse encoding if needed
    if (isSparse) {
        for (uint32_t j = 1; j < N / (2 * slots); j <<= 1) {
            auto temp = ccCKKS->EvalRotate(BminusAdotSres, j * slots);
            ccCKKS->EvalAddInPlace(BminusAdotSres, temp);
        }
        BminusAdotSres->SetSlots(slots);
    }

    if (cryptoParamsCKKS->GetScalingTechnique() == FIXEDMANUAL) {
        ccCKKS->ModReduceInPlace(BminusAdotSres);
    }

    return BminusAdotSres;
}

std::pair<BinFHEContext, LWEPrivateKey> SWITCHCKKSRNS::EvalSchemeSwitchingSetup(
    const CryptoContextImpl<DCRTPoly>& ccCKKS, SecurityLevel sl, BINFHE_PARAMSET slBin, bool arbFunc, uint32_t logQ,
    bool dynamic, uint32_t numSlotsCKKS, uint32_t logQswitch) {
    auto FHEWcc = EvalCKKStoFHEWSetup(ccCKKS, sl, slBin, arbFunc, logQ, dynamic, numSlotsCKKS, logQswitch);

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ccCKKS.GetCryptoParameters());

    // Get the last ciphertext modulus; this assumes the LWE mod switch will be performed on the ciphertext at the last level
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ                                  = elementParams.GetParams();
    m_modulus_CKKS_initial                        = paramsQ[0]->GetModulus().ConvertToInt();

    return FHEWcc;
}

std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> SWITCHCKKSRNS::EvalSchemeSwitchingKeyGen(
    const KeyPair<DCRTPoly>& keyPair, ConstLWEPrivateKey& lwesk, uint32_t numValues, bool oneHot, bool alt,
    uint32_t dim1CF, uint32_t dim1FC, uint32_t LCF, uint32_t LFC) {
    auto privateKey = keyPair.secretKey;
    auto publicKey  = keyPair.publicKey;

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(privateKey->GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW(config_error,
                      "CKKS to FHEW scheme switching is only supported for the Hybrid key switching method.");
#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW(config_error,
                      "128-bit CKKS to FHEW scheme switching is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif

    auto ccCKKS = privateKey->GetCryptoContext();

    uint32_t M       = ccCKKS->GetCyclotomicOrder();
    uint32_t slots   = m_numSlotsCKKS;
    uint32_t n       = lwesk->GetElement().GetLength();
    uint32_t ringDim = ccCKKS->GetRingDimension();

    // Intermediate cryptocontext for CKKS to FHEW
    auto keys2 = m_ccKS->KeyGen();

    Plaintext ptxtZeroKS = m_ccKS->MakeCKKSPackedPlaintext(std::vector<double>{0.0}, 1, 0, nullptr, slots);
    m_ctxtKS             = m_ccKS->Encrypt(keys2.publicKey, ptxtZeroKS);

    // Compute switching key between RLWE and LWE via the intermediate cryptocontext, keep it in RLWE form
    m_CKKStoFHEWswk = switchingKeyGenRLWEcc(keys2.secretKey, privateKey, lwesk);

    auto skLWEElements = lwesk->GetElement();
    std::vector<std::complex<double>> skLWEDouble(n);
    for (uint32_t i = 0; i < n; i++) {
        auto tmp = skLWEElements[i].ConvertToDouble();
        if (tmp == lwesk->GetModulus().ConvertToInt() - 1)
            tmp = -1;
        skLWEDouble[i] = std::complex<double>(tmp, 0);
    }

    // Check encoding and specify the number of slots, otherwise, if batchsize is set and is smaller, it will throw an error.
    Plaintext skLWEPlainswk;
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        skLWEPlainswk = ccCKKS->MakeCKKSPackedPlaintext(Fill(skLWEDouble, ringDim / 2), 1, BASE_NUM_LEVELS_TO_DROP,
                                                        nullptr, ringDim / 2);
    else
        skLWEPlainswk = ccCKKS->MakeCKKSPackedPlaintext(Fill(skLWEDouble, ringDim / 2), 1, 0, nullptr, ringDim / 2);

    m_FHEWtoCKKSswk = ccCKKS->Encrypt(publicKey, skLWEPlainswk);

    // Compute automorphism keys
    /* CKKS to FHEW */
    if (dim1CF == 0)
        dim1CF = getRatioBSGSLT(slots);
    m_dim1CF = dim1CF;
    m_LCF    = LCF;

    // Compute indices for rotations for slotToCoeff transform
    std::vector<int32_t> indexRotationS2C = FindLTRotationIndicesSwitch(m_dim1CF, M, slots);
    indexRotationS2C.emplace_back(static_cast<int32_t>(slots));

    // Compute indices for rotations for sparse packing
    if (ringDim > 2 * slots) {  // if the encoding is full, this does not execute
        indexRotationS2C.reserve(indexRotationS2C.size() + GetMSB(ringDim) - 2 + GetMSB(slots) - 1);
        for (uint32_t i = 1; i < ringDim / 2; i <<= 1) {
            indexRotationS2C.emplace_back(static_cast<int32_t>(i));
            if (i <= slots)
                indexRotationS2C.emplace_back(-static_cast<int32_t>(i));
        }
    }

    /* FHEW to CKKS */
    if (dim1FC == 0)
        dim1FC = getRatioBSGSLT(n);  // This picks the ratio for baby-step giant-step
    m_dim1FC = dim1FC;
    m_LFC    = LFC;

    // Compute indices for rotations for homomorphic decryption in CKKS
    std::vector<int32_t> indexRotationHomDec = FindLTRotationIndicesSwitch(m_dim1FC, M, n);

    // Compute indices for rotations to bring back the final CKKS ciphertext encoding to slots
    if (ringDim > 2 * slots) {  // if the encoding is full, this does not execute
        indexRotationHomDec.reserve(indexRotationHomDec.size() + GetMSB(ringDim) - 2);
        for (uint32_t j = 1; j < ringDim / (2 * slots); j <<= 1) {
            indexRotationHomDec.emplace_back(j * slots);
        }
    }

    std::vector<int32_t> indexRotationArgmin;

    /* Compute indices for Argmin if numValues != 0. Otherwise, the KeyGen is not used for Argmin*/
    if (numValues > 0) {
        indexRotationArgmin.reserve(GetMSB(numValues) - 2 + static_cast<int32_t>(!alt) * 2 * (GetMSB(numValues) - 2));
        for (uint32_t i = 1; i < numValues; i <<= 1) {
            indexRotationArgmin.emplace_back(static_cast<int32_t>(numValues / (2 * i)));
            if (!alt) {
                indexRotationArgmin.emplace_back(-static_cast<int32_t>(numValues / (2 * i)));
                if (i > 1) {
                    for (uint32_t j = numValues / i; j < numValues; j <<= 1)
                        indexRotationArgmin.emplace_back(-static_cast<int32_t>(j));
                }
            }
        }
    }

    // Combine the indices lists
    indexRotationS2C.reserve(indexRotationS2C.size() + indexRotationHomDec.size() + indexRotationArgmin.size());
    indexRotationS2C.insert(indexRotationS2C.end(), indexRotationHomDec.begin(), indexRotationHomDec.end());
    indexRotationS2C.insert(indexRotationS2C.end(), indexRotationArgmin.begin(), indexRotationArgmin.end());

    // Remove possible duplicates
    sort(indexRotationS2C.begin(), indexRotationS2C.end());
    indexRotationS2C.erase(unique(indexRotationS2C.begin(), indexRotationS2C.end()), indexRotationS2C.end());

    auto algo     = ccCKKS->GetScheme();
    auto evalKeys = algo->EvalAtIndexKeyGen(publicKey, privateKey, indexRotationS2C);

    // Compute conjugation key
    const DCRTPoly& s                       = privateKey->GetPrivateElement();
    usint N                                 = s.GetRingDimension();
    PrivateKey<DCRTPoly> privateKeyPermuted = std::make_shared<PrivateKeyImpl<DCRTPoly>>(ccCKKS);
    usint index                             = 2 * N - 1;
    std::vector<usint> vec(N);
    PrecomputeAutoMap(N, index, &vec);
    DCRTPoly sPermuted = s.AutomorphismTransform(index, vec);
    privateKeyPermuted->SetPrivateElement(sPermuted);
    privateKeyPermuted->SetKeyTag(privateKey->GetKeyTag());
    auto conjKey       = algo->KeySwitchGen(privateKey, privateKeyPermuted);
    (*evalKeys)[M - 1] = conjKey;

    // Compute multiplication key
    ccCKKS->EvalMultKeyGen(privateKey);

    // Compute automorphism keys if we don't want one hot encoding for argmin
    if (numValues != 0 && oneHot == false) {
        ccCKKS->EvalSumKeyGen(privateKey);
    }

    /* FHEW computations */
    // Generate the bootstrapping keys (refresh and switching keys)
    m_ccLWE.BTKeyGen(lwesk);

    return evalKeys;
}

void SWITCHCKKSRNS::EvalCompareSwitchPrecompute(const CryptoContextImpl<DCRTPoly>& ccCKKS, uint32_t pLWE,
                                                uint32_t initLevel, double scaleSign, bool unit) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ccCKKS.GetCryptoParameters());

    double scaleCF = 1.0;

    if (pLWE != 0) {
        double scFactor = cryptoParams->GetScalingFactorReal(initLevel);
        if (unit)  // The messages are already scaled between 0 and 1, no need to divide by pLWE
            scaleCF = m_modulus_CKKS_initial.ConvertToDouble() / scFactor;
        else
            scaleCF = m_modulus_CKKS_initial.ConvertToDouble() / (scFactor * pLWE);
    }
    // Else perform no scaling; the implicit FHEW plaintext modulus will be m_modulus_CKKS_initial / scFactor

    m_plaintextFHEW = pLWE;
    scaleCF *= scaleSign;

    EvalCKKStoFHEWPrecompute(ccCKKS, scaleCF);
}

Ciphertext<DCRTPoly> SWITCHCKKSRNS::EvalCompareSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext1,
                                                               ConstCiphertext<DCRTPoly> ciphertext2, uint32_t numCtxts,
                                                               uint32_t numSlots, uint32_t pLWE, double scaleSign,
                                                               bool unit) {
    auto ccCKKS             = ciphertext1->GetCryptoContext();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ccCKKS->GetCryptoParameters());

    auto cDiff = ccCKKS->EvalSub(ciphertext1, ciphertext2);

    if (unit) {
        if (pLWE == 0)
            OPENFHE_THROW(config_error, "To scale to the unit circle, pLWE must be non-zero.");
        else {
            cDiff = ccCKKS->EvalMult(cDiff, 1.0 / static_cast<double>(pLWE));
            cDiff = ccCKKS->Rescale(cDiff);
        }
    }

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (pLWE != 0) {
        m_scFactorOuter = cryptoParams->GetScalingFactorReal(0);
        double scFactor = cryptoParams->GetScalingFactorReal(cDiff->GetLevel());
        if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
            scFactor = cryptoParams->GetScalingFactorReal(cDiff->GetLevel() + 1);

        double scaleCF = 1.0;
        if (unit)  // The messages are already scaled between 0 and 1, no need to divide by pLWE
            scaleCF = m_modulus_CKKS_initial.ConvertToDouble() / scFactor;
        else
            scaleCF = m_modulus_CKKS_initial.ConvertToDouble() / (scFactor * pLWE);
        scaleCF *= scaleSign;
        ccCKKS->EvalCKKStoFHEWPrecompute(scaleCF);
    }

    auto LWECiphertexts = EvalCKKStoFHEW(cDiff, numCtxts);

    std::vector<LWECiphertext> cSigns(LWECiphertexts.size());
#pragma omp parallel for
    for (uint32_t i = 0; i < LWECiphertexts.size(); i++) {
        cSigns[i] = m_ccLWE.EvalSign(LWECiphertexts[i], true);
    }

    return EvalFHEWtoCKKS(cSigns, numCtxts, numSlots, 4, -1.0, 1.0);
    // return ccCKKS->EvalFHEWtoCKKS(cSigns, numCtxts, numSlots, 4, -1.0, 1.0);
}

std::vector<Ciphertext<DCRTPoly>> SWITCHCKKSRNS::EvalMinSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext,
                                                                        PublicKey<DCRTPoly> publicKey,
                                                                        uint32_t numValues, uint32_t numSlots,
                                                                        bool oneHot, uint32_t pLWE, double scaleSign) {
    auto cc                 = ciphertext->GetCryptoContext();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (pLWE != 0) {
        double scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel());
        if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
            scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel() + 1);
        double scaleCF = m_modulus_CKKS_initial.ConvertToDouble() / (scFactor * pLWE);
        scaleCF *= scaleSign;
        cc->EvalCKKStoFHEWPrecompute(scaleCF);
    }

    uint32_t towersToDrop = 12;  // How many levels are consumed in the EvalFHEWtoCKKS
    uint32_t slots        = (numSlots == 0) ? m_numSlotsCKKS : numSlots;

    Plaintext pInd;
    if (oneHot) {
        std::vector<std::complex<double>> ind(numValues, 1.0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    else {
        std::vector<std::complex<double>> ind(numValues);
        std::iota(ind.begin(), ind.end(), 0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    Ciphertext<DCRTPoly> cInd          = cc->Encrypt(publicKey, pInd);
    Ciphertext<DCRTPoly> newCiphertext = ciphertext->Clone();

    for (uint32_t M = 1; M < numValues; M <<= 1) {
        // Compute CKKS ciphertext encoding difference of the first numValues
        auto cDiff = cc->EvalSub(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));

        // Transform the ciphertext from CKKS to FHEW
        auto cTemp = cc->EvalCKKStoFHEW(cDiff, numValues / (2 * M));

        // Evaluate the sign
        // We always assume for the moment that numValues is a power of 2
        std::vector<LWECiphertext> LWESign(numValues / (2 * M));
#pragma omp parallel for
        for (uint32_t j = 0; j < numValues / (2 * M); j++) {
            LWESign[j] = m_ccLWE.EvalSign(cTemp[j], true);
        }

        // Scheme switching from FHEW to CKKS
        auto cSelect = cc->EvalFHEWtoCKKS(LWESign, numValues / (2 * M), numSlots, 4, -1.0, 1.0);

        std::vector<std::complex<double>> ones(numValues / (2 * M), 1.0);
        Plaintext ptxtOnes = cc->MakeCKKSPackedPlaintext(ones, 1, 0, nullptr, slots);
        cSelect            = cc->EvalAdd(
                       cSelect, cc->EvalAtIndex(cc->EvalSub(ptxtOnes, cSelect), -static_cast<int32_t>(numValues / (2 * M))));

        auto cExpandSelect = cSelect;
        if (M > 1) {
            for (uint32_t j = numValues / M; j < numValues; j <<= 1)
                cExpandSelect = cc->EvalAdd(cExpandSelect, cc->EvalAtIndex(cExpandSelect, -static_cast<int32_t>(j)));
        }

        // Update the ciphertext of values and the indicator
        newCiphertext = cc->EvalMult(newCiphertext, cExpandSelect);
        newCiphertext = cc->EvalAdd(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));
        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(newCiphertext);
        }

        cInd = cc->EvalMult(cInd, cExpandSelect);
        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(cInd);
        }
    }
    // After computing the minimum and argument
    if (!oneHot) {
        cInd = cc->EvalSum(cInd, numValues);
    }

    std::vector<Ciphertext<DCRTPoly>> cRes{newCiphertext, cInd};

    return cRes;
}

std::vector<Ciphertext<DCRTPoly>> SWITCHCKKSRNS::EvalMinSchemeSwitchingAlt(ConstCiphertext<DCRTPoly> ciphertext,
                                                                           PublicKey<DCRTPoly> publicKey,
                                                                           uint32_t numValues, uint32_t numSlots,
                                                                           bool oneHot, uint32_t pLWE,
                                                                           double scaleSign) {
    auto cc                 = ciphertext->GetCryptoContext();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (pLWE != 0) {
        double scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel());
        if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
            scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel() + 1);
        double scaleCF = m_modulus_CKKS_initial.ConvertToDouble() / (scFactor * pLWE);
        scaleCF *= scaleSign;
        cc->EvalCKKStoFHEWPrecompute(scaleCF);
    }

    uint32_t towersToDrop = 12;  // How many levels are consumed in the EvalFHEWtoCKKS, for binary FHEW output.
    uint32_t slots        = (numSlots == 0) ? m_numSlotsCKKS : numSlots;

    Plaintext pInd;
    if (oneHot) {
        std::vector<std::complex<double>> ind(numValues, 1.0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    else {
        std::vector<std::complex<double>> ind(numValues);
        std::iota(ind.begin(), ind.end(), 0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    Ciphertext<DCRTPoly> cInd          = cc->Encrypt(publicKey, pInd);
    Ciphertext<DCRTPoly> newCiphertext = ciphertext->Clone();

    for (uint32_t M = 1; M < numValues; M <<= 1) {
        // Compute CKKS ciphertext encoding difference of the first numValues
        auto cDiff = cc->EvalSub(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));

        // Transform the ciphertext from CKKS to FHEW
        auto cTemp = cc->EvalCKKStoFHEW(cDiff, numValues / (2 * M));

        // Evaluate the sign
        // We always assume for the moment that numValues is a power of 2
        std::vector<LWECiphertext> LWESign(numValues);
#pragma omp parallel for
        for (uint32_t j = 0; j < numValues / (2 * M); j++) {
            LWECiphertext tempSign    = m_ccLWE.EvalSign(cTemp[j], true);
            LWECiphertext negTempSign = std::make_shared<LWECiphertextImpl>(*tempSign);
            m_ccLWE.GetLWEScheme()->EvalAddConstEq(negTempSign, negTempSign->GetModulus() >> 1);  // "negated" tempSign
            for (uint32_t i = 0; i < 2 * M; i += 2) {
                LWESign[i * numValues / (2 * M) + j]       = tempSign;
                LWESign[(i + 1) * numValues / (2 * M) + j] = negTempSign;
            }
        }

        // Scheme switching from FHEW to CKKS
        auto cExpandSelect = cc->EvalFHEWtoCKKS(LWESign, numValues, numSlots, 4, -1.0, 1.0);

        // Update the ciphertext of values and the indicator
        newCiphertext = cc->EvalMult(newCiphertext, cExpandSelect);
        newCiphertext = cc->EvalAdd(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));

        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(newCiphertext);
        }

        cInd = cc->EvalMult(cInd, cExpandSelect);
        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(cInd);
        }
    }
    // After computing the minimum and argument
    if (!oneHot) {
        cInd = cc->EvalSum(cInd, numValues);
    }

    std::vector<Ciphertext<DCRTPoly>> cRes{newCiphertext, cInd};

    return cRes;
}

std::vector<Ciphertext<DCRTPoly>> SWITCHCKKSRNS::EvalMaxSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext,
                                                                        PublicKey<DCRTPoly> publicKey,
                                                                        uint32_t numValues, uint32_t numSlots,
                                                                        bool oneHot, uint32_t pLWE, double scaleSign) {
    auto cc                 = ciphertext->GetCryptoContext();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (pLWE != 0) {
        double scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel());
        if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
            scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel() + 1);
        double scaleCF = m_modulus_CKKS_initial.ConvertToDouble() / (scFactor * pLWE);
        scaleCF *= scaleSign;
        cc->EvalCKKStoFHEWPrecompute(scaleCF);
    }

    uint32_t towersToDrop = 12;  // How many levels are consumed in the EvalFHEWtoCKKS, for binary FHEW output.
    uint32_t slots        = (numSlots == 0) ? m_numSlotsCKKS : numSlots;

    Plaintext pInd;
    if (oneHot) {
        std::vector<std::complex<double>> ind(numValues, 1.0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    else {
        std::vector<std::complex<double>> ind(numValues);
        std::iota(ind.begin(), ind.end(), 0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    Ciphertext<DCRTPoly> cInd          = cc->Encrypt(publicKey, pInd);
    Ciphertext<DCRTPoly> newCiphertext = ciphertext->Clone();

    for (uint32_t M = 1; M < numValues; M <<= 1) {
        // Compute CKKS ciphertext encoding difference of the first numValues
        auto cDiff = cc->EvalSub(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));

        // Transform the ciphertext from CKKS to FHEW
        auto cTemp = cc->EvalCKKStoFHEW(cDiff, numValues / (2 * M));

        // Evaluate the sign
        // We always assume for the moment that numValues is a power of 2
        std::vector<LWECiphertext> LWESign(numValues / (2 * M));
#pragma omp parallel for
        for (uint32_t j = 0; j < numValues / (2 * M); j++) {
            LWESign[j] = m_ccLWE.EvalSign(cTemp[j], true);
        }

        // Scheme switching from FHEW to CKKS
        auto cSelect = cc->EvalFHEWtoCKKS(LWESign, numValues / (2 * M), numSlots, 4, -1.0, 1.0);

        std::vector<std::complex<double>> ones(numValues / (2 * M), 1.0);
        Plaintext ptxtOnes = cc->MakeCKKSPackedPlaintext(ones, 1, 0, nullptr, slots);
        cSelect            = cc->EvalAdd(cc->EvalSub(ptxtOnes, cSelect),
                                         cc->EvalAtIndex(cSelect, -static_cast<int32_t>(numValues / (2 * M))));

        auto cExpandSelect = cSelect;
        if (M > 1) {
            for (uint32_t j = numValues / M; j < numValues; j <<= 1)
                cExpandSelect = cc->EvalAdd(cExpandSelect, cc->EvalAtIndex(cExpandSelect, -static_cast<int32_t>(j)));
        }

        // Update the ciphertext of values and the indicator
        newCiphertext = cc->EvalMult(newCiphertext, cExpandSelect);
        newCiphertext = cc->EvalAdd(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));

        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(newCiphertext);
        }

        cInd = cc->EvalMult(cInd, cExpandSelect);
        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(cInd);
        }
    }
    // After computing the minimum and argument
    if (!oneHot) {
        cInd = cc->EvalSum(cInd, numValues);
    }

    std::vector<Ciphertext<DCRTPoly>> cRes{newCiphertext, cInd};

    return cRes;
}

std::vector<Ciphertext<DCRTPoly>> SWITCHCKKSRNS::EvalMaxSchemeSwitchingAlt(ConstCiphertext<DCRTPoly> ciphertext,
                                                                           PublicKey<DCRTPoly> publicKey,
                                                                           uint32_t numValues, uint32_t numSlots,
                                                                           bool oneHot, uint32_t pLWE,
                                                                           double scaleSign) {
    auto cc                 = ciphertext->GetCryptoContext();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (pLWE != 0) {
        double scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel());
        if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
            scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel() + 1);
        double scaleCF = m_modulus_CKKS_initial.ConvertToDouble() / (scFactor * pLWE);
        scaleCF *= scaleSign;
        cc->EvalCKKStoFHEWPrecompute(scaleCF);
    }

    uint32_t towersToDrop = 12;  // How many levels are consumed in the EvalFHEWtoCKKS, for binary FHEW output
    uint32_t slots        = (numSlots == 0) ? m_numSlotsCKKS : numSlots;

    Plaintext pInd;
    if (oneHot) {
        std::vector<std::complex<double>> ind(numValues, 1.0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    else {
        std::vector<std::complex<double>> ind(numValues);
        std::iota(ind.begin(), ind.end(), 0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    Ciphertext<DCRTPoly> cInd          = cc->Encrypt(publicKey, pInd);
    Ciphertext<DCRTPoly> newCiphertext = ciphertext->Clone();

    for (uint32_t M = 1; M < numValues; M <<= 1) {
        // Compute CKKS ciphertext encoding difference of the first numValues
        auto cDiff = cc->EvalSub(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));

        // Transform the ciphertext from CKKS to FHEW
        auto cTemp = cc->EvalCKKStoFHEW(cDiff, numValues / (2 * M));

        // Evaluate the sign
        // We always assume for the moment that numValues is a power of 2
        std::vector<LWECiphertext> LWESign(numValues);
#pragma omp parallel for
        for (uint32_t j = 0; j < numValues / (2 * M); j++) {
            LWECiphertext tempSign    = m_ccLWE.EvalSign(cTemp[j], true);
            LWECiphertext negTempSign = std::make_shared<LWECiphertextImpl>(*tempSign);
            m_ccLWE.GetLWEScheme()->EvalAddConstEq(negTempSign, negTempSign->GetModulus() >> 1);  // "negated" tempSign
            for (uint32_t i = 0; i < 2 * M; i += 2) {
                LWESign[i * numValues / (2 * M) + j]       = negTempSign;
                LWESign[(i + 1) * numValues / (2 * M) + j] = tempSign;
            }
        }

        // Scheme switching from FHEW to CKKS
        auto cExpandSelect = cc->EvalFHEWtoCKKS(LWESign, numValues, numSlots, 4, -1.0, 1.0);

        // Update the ciphertext of values and the indicator
        newCiphertext = cc->EvalMult(newCiphertext, cExpandSelect);
        newCiphertext = cc->EvalAdd(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));

        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(newCiphertext);
        }

        cInd = cc->EvalMult(cInd, cExpandSelect);
        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(cInd);
        }
    }
    // After computing the minimum and argument
    if (!oneHot) {
        cInd = cc->EvalSum(cInd, numValues);
    }

    std::vector<Ciphertext<DCRTPoly>> cRes{newCiphertext, cInd};

    return cRes;
}

}  // namespace lbcrypto
