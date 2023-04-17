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

#include "cryptocontext.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-schemeswitching.h"
#include "scheme/ckksrns/ckksrns-fhe.h"

#include "key/privatekey.h"
#include "schemebase/base-scheme.h"
#include "ciphertext.h"
#include "math/dftransform.h"

namespace lbcrypto {

//------------------------------------------------------------------------------
// Temporary for debugging
//------------------------------------------------------------------------------

std::vector<std::complex<double>> DecryptWithoutDecode(const CryptoContextImpl<DCRTPoly>& cc,
                                                       ConstCiphertext<DCRTPoly> cTemp,
                                                       const PrivateKey<DCRTPoly> privateKey, uint32_t slots,
                                                       uint32_t ringDim) {
    Plaintext decrypted = cc.GetPlaintextForDecrypt(cTemp->GetEncodingType(), cTemp->GetElements()[0].GetParams(),
                                                    cc.GetEncodingParams());
    bool isNativePoly   = true;
    DecryptResult result;

    if ((cTemp->GetEncodingType() == CKKS_PACKED_ENCODING) &&
        (cTemp->GetElements()[0].GetParams()->GetParams().size() >
         1)) {  // only one tower in DCRTPoly // Andreea: this comment is wrong, it should be the other way around
        result = cc.GetScheme()->Decrypt(cTemp, privateKey, &decrypted->GetElement<Poly>());
        //   std::cout << "Poly" << std::endl;
        isNativePoly = false;
    }
    else {
        result = cc.GetScheme()->Decrypt(cTemp, privateKey, &decrypted->GetElement<NativePoly>());
        //   std::cout << "NativePoly" << std::endl;
        isNativePoly = true;
    }

    auto elemModulus   = decrypted->GetElementModulus();
    auto noiseScaleDeg = cTemp->GetNoiseScaleDeg();
    auto scalingFactor = cTemp->GetScalingFactor();
    // std::cout << "elemModulus = "<< elemModulus << ", noiseScaleDeg = " << noiseScaleDeg << ", scalingFactor = " << scalingFactor << std::endl;

    decrypted->SetScalingFactorInt(result.scalingFactorInt);

    double p     = cc.GetEncodingParams()->GetPlaintextModulus();
    double powP  = 0.0;
    uint32_t Nh  = ringDim / 2;
    uint32_t gap = Nh / slots;
    std::vector<std::complex<double>> curValues(slots);

    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    auto scalTech = cryptoParamsCKKS->GetScalingTechnique();

    if (isNativePoly) {
        if (scalTech == FLEXIBLEAUTO || scalTech == FLEXIBLEAUTOEXT) {
            powP = pow(scalingFactor, -1);
            //   std::cout << "powP is the inverse of the scalingFactor" << std::endl;
        }
        else {
            powP = pow(2, -p);
            //   std::cout << "powP is the inverse of the 2^p" << std::endl;
        }

        //   std::cout << "powP = " << powP << std::endl;

        const NativeInteger& q = decrypted->GetElementModulus().ConvertToInt();
        NativeInteger qHalf    = q >> 1;

        for (size_t i = 0, idx = 0; i < slots; ++i, idx += gap) {
            std::complex<double> cur;

            if (decrypted->GetElement<NativePoly>()[idx] > qHalf)
                cur.real(-((q - decrypted->GetElement<NativePoly>()[idx])).ConvertToDouble());
            else
                cur.real((decrypted->GetElement<NativePoly>()[idx]).ConvertToDouble());

            if (decrypted->GetElement<NativePoly>()[idx + Nh] > qHalf)
                cur.imag(-((q - decrypted->GetElement<NativePoly>()[idx + Nh])).ConvertToDouble());
            else
                cur.imag((decrypted->GetElement<NativePoly>()[idx + Nh]).ConvertToDouble());

            curValues[i] = cur * powP;
        }
    }
    else {
        powP = pow(2, -p);

        // we will bring down the scaling factor to 2^p
        double scalingFactorPre = 0.0;
        if (scalTech == FLEXIBLEAUTO || scalTech == FLEXIBLEAUTOEXT)
            scalingFactorPre = pow(scalingFactor, -1) * pow(2, p);
        else
            scalingFactorPre = pow(2, -p * (noiseScaleDeg - 1));

        const BigInteger& q = decrypted->GetElementModulus();
        BigInteger qHalf    = q >> 1;

        for (size_t i = 0, idx = 0; i < slots; ++i, idx += gap) {
            std::complex<double> cur;

            if (decrypted->GetElement<Poly>()[idx] > qHalf)
                cur.real(-((q - decrypted->GetElement<Poly>()[idx])).ConvertToDouble() * scalingFactorPre);
            else
                cur.real((decrypted->GetElement<Poly>()[idx]).ConvertToDouble() * scalingFactorPre);

            if (decrypted->GetElement<Poly>()[idx + Nh] > qHalf)
                cur.imag(-((q - decrypted->GetElement<Poly>()[idx + Nh])).ConvertToDouble() * scalingFactorPre);
            else
                cur.imag((decrypted->GetElement<Poly>()[idx + Nh]).ConvertToDouble() * scalingFactorPre);

            curValues[i] = cur * powP;
        }
    }
    return curValues;
}

//------------------------------------------------------------------------------
// Complex Plaintext Functions, copied from ckksrns-fhe, figure out how to share them
//------------------------------------------------------------------------------

void FitToNativeVector(uint32_t ringDim, const std::vector<int64_t>& vec, int64_t bigBound, NativeVector* nativeVec) {
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

#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
void FitToNativeVector(uint32_t ringDim, const std::vector<__int128>& vec, __int128 bigBound, NativeVector* nativeVec) {
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
#endif

constexpr int64_t Max64BitValue() {
    // 2^63-2^9-1 - max value that could be rounded to int64_t
    return 9223372036854775295;
}

inline bool is64BitOverflow(double d) {
    const double EPSILON = 0.000001;

    return EPSILON < (std::abs(d) - Max64BitValue());
}

#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
Plaintext MakeAuxPlaintext(const CryptoContextImpl<DCRTPoly>& cc, const std::shared_ptr<ParmType> params,
                           const std::vector<std::complex<double>>& value, size_t noiseScaleDeg, uint32_t level,
                           usint slots) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    double scFact = cryptoParams->GetScalingFactorReal(level);

    Plaintext p = Plaintext(std::make_shared<CKKSPackedEncoding>(params, cc.GetEncodingParams(), value, noiseScaleDeg,
                                                                 level, scFact, slots));

    DCRTPoly& plainElement = p->GetElement<DCRTPoly>();

    usint N = cc.GetRingDimension();

    std::vector<std::complex<double>> inverse = value;

    inverse.resize(slots);

    DiscreteFourierTransform::FFTSpecialInv(inverse);
    uint64_t pBits     = cc.GetEncodingParams()->GetPlaintextModulus();
    uint32_t precision = 52;

    double powP      = std::pow(2, precision);
    int32_t pCurrent = pBits - precision;

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
            DiscreteFourierTransform::FFTSpecial(inverse);

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
Plaintext MakeAuxPlaintext(const CryptoContextImpl<DCRTPoly>& cc, const std::shared_ptr<DCRTPoly::Params> params,
                           const std::vector<std::complex<double>>& value, size_t noiseScaleDeg, uint32_t level,
                           usint slots) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    double scFact = cryptoParams->GetScalingFactorReal(level);

    Plaintext p = Plaintext(std::make_shared<CKKSPackedEncoding>(params, cc.GetEncodingParams(), value, noiseScaleDeg,
                                                                 level, scFact, slots));

    DCRTPoly& plainElement = p->GetElement<DCRTPoly>();

    usint N = cc.GetRingDimension();

    std::vector<std::complex<double>> inverse = value;

    inverse.resize(slots);

    DiscreteFourierTransform::FFTSpecialInv(inverse);
    double powP = scFact;

    // Compute approxFactor, a value to scale down by, in case the value exceeds a 64-bit integer.
    int32_t MAX_BITS_IN_WORD = 62;

    int32_t logc = 0;
    for (size_t i = 0; i < slots; ++i) {
        inverse[i] *= powP;
        int32_t logci = static_cast<int32_t>(ceil(log2(abs(inverse[i].real()))));
        if (logc < logci)
            logc = logci;
        logci = static_cast<int32_t>(ceil(log2(abs(inverse[i].imag()))));
        if (logc < logci)
            logc = logci;
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
            DiscreteFourierTransform::FFTSpecial(inverse);

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
    int32_t MAX_LOG_STEP = 60;
    if (logApprox > 0) {
        int32_t logStep           = (logApprox <= MAX_LOG_STEP) ? logApprox : MAX_LOG_STEP;
        DCRTPoly::Integer intStep = uint64_t(1) << logStep;
        std::vector<DCRTPoly::Integer> crtApprox(numTowers, intStep);
        logApprox -= logStep;

        while (logApprox > 0) {
            int32_t logStep           = (logApprox <= MAX_LOG_STEP) ? logApprox : MAX_LOG_STEP;
            DCRTPoly::Integer intStep = uint64_t(1) << logStep;
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

Ciphertext<DCRTPoly> EvalMultExt(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) {
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

void EvalAddExtInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) {
    std::vector<DCRTPoly>& cv1       = ciphertext1->GetElements();
    const std::vector<DCRTPoly>& cv2 = ciphertext2->GetElements();

    for (usint i = 0; i < cv1.size(); ++i) {
        cv1[i] += cv2[i];
    }
}

Ciphertext<DCRTPoly> EvalAddExt(ConstCiphertext<DCRTPoly> ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) {
    Ciphertext<DCRTPoly> result = ciphertext1->Clone();
    EvalAddExtInPlace(result, ciphertext2);
    return result;
}

EvalKey<DCRTPoly> ConjugateKeyGen(const PrivateKey<DCRTPoly> privateKey) {
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

Ciphertext<DCRTPoly> Conjugate(ConstCiphertext<DCRTPoly> ciphertext,
                               const std::map<usint, EvalKey<DCRTPoly>>& evalKeyMap) {
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

//------------------------------------------------------------------------------
// Key switch and extraction methods
//------------------------------------------------------------------------------
// EvalKey<DCRTPoly> switchingKeyGenRLWE(const PrivateKey<DCRTPoly>& ckksSK,
// const std::shared_ptr<LWEPrivateKeyImpl>& LWEsk){ // Andreea: why is this shared_ptr but the others aren't?
std::pair<EvalKey<DCRTPoly>, PrivateKey<DCRTPoly>> switchingKeyGenRLWE(
    const PrivateKey<DCRTPoly>& ckksSK,
    const std::shared_ptr<LWEPrivateKeyImpl>& LWEsk) {  // Andreea: return RLWELWEsk temporary for debugging

    // Extract CKKS params
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

    auto ccCKKS = ckksSK->GetCryptoContext();
    // PrivateKey<DCRTPoly> RLWELWEsk = std::make_shared<PrivateKeyImpl<DCRTPoly>>(ckksSK->GetCryptoContext());
    auto RLWELWEsk = ccCKKS->KeyGen().secretKey;
    RLWELWEsk->SetPrivateElement(std::move(skelements));

    // return ccCKKS->KeySwitchGen(ckksSK, RLWELWEsk);

    std::pair<EvalKey<DCRTPoly>, PrivateKey<DCRTPoly>> swPair;
    swPair.first  = ccCKKS->KeySwitchGen(ckksSK, RLWELWEsk);
    swPair.second = RLWELWEsk;
    return swPair;
}

NativeInteger RoundqQAlter(const NativeInteger& v, const NativeInteger& q, const NativeInteger& Q) {
    return NativeInteger((uint64_t)std::floor(0.5 + v.ConvertToDouble() * q.ConvertToDouble() / Q.ConvertToDouble()))
        .Mod(q);
}

std::vector<std::vector<NativeInteger>> ExtractLWEpacked(const Ciphertext<DCRTPoly>& ct) {
    auto A = ct->GetElements()[1];
    auto B = ct->GetElements()[0];
    auto N = B.GetLength();

    // std::cout << "N in ExtractLWEpacked: " << N << std::endl;

    auto originalA = A.GetElementAtIndex(0);
    auto originalB = B.GetElementAtIndex(0);
    originalA.SetFormat(Format::COEFFICIENT);
    originalB.SetFormat(Format::COEFFICIENT);

    std::vector<std::vector<NativeInteger>> extracted(2);

    for (uint32_t i = 0; i < N; i++) {
        extracted[1].push_back(originalA[i]);
        extracted[0].push_back(originalB[i]);
    }
    return extracted;
}

std::shared_ptr<LWECiphertextImpl> ExtractLWECiphertext(const std::vector<std::vector<NativeInteger>>& aANDb,
                                                        NativeInteger modulus, const BinFHEContext& ccLWE, uint32_t n,
                                                        uint32_t index = 0) {
    auto N = aANDb[0].size();
    NativeVector a(n, modulus);
    NativeInteger b;

    for (uint32_t i = 0; i < n; i += 1) {
        if (i <= index) {
            a[i] = modulus - aANDb[1][index - i];
        }
        else {
            a[i] = aANDb[1][N + index - i];
        }
    }
    b           = aANDb[0][index];
    auto result = std::make_shared<LWECiphertextImpl>(std::move(a), std::move(b));
    return result;
}

//------------------------------------------------------------------------------
// Linear transformation methods. Andreea: Mostly copied from ckksrns-fhe, because there they used an internal bootstrapping global structure
//------------------------------------------------------------------------------

// std::vector<std::vector<std::complex<double>>>
std::vector<ConstPlaintext> EvalLTPrecomputeSS(
    const CryptoContextImpl<DCRTPoly>& cc,  // Pass cc only if we return plaintexts
    const std::vector<std::vector<std::complex<double>>>& A, const std::vector<std::vector<std::complex<double>>>& B,
    uint32_t dim1 = 0, double scale = 1) {
    uint32_t slots = A.size();
    uint32_t M     = cc.GetCyclotomicOrder();

    // Computing the baby-step bStep and the giant-step gStep // Andreea: I am using the optimized ratio, unlike the LT in bootstrapping
    uint32_t bStep = (dim1 == 0) ? getRatioBSGS(static_cast<double>(slots)) : dim1;
    uint32_t gStep = ceil(static_cast<double>(slots) / bStep);

    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParamsCKKS->GetElementParams());

    uint32_t towersToDrop =
        elementParams.GetParams().size() -
        2;  // equivalent to L = 2, where L used to be an argument of how many levels the decoding consumes
    for (uint32_t i = 0; i < towersToDrop; i++)
        elementParams.PopLastParam();
    // std::cout << "towersToDrop: " << towersToDrop << std::endl;

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
        auto vecA = A[i];
        auto vecB = B[i];
        vecA.insert(vecA.end(), vecB.begin(), vecB.end());
        newA[i] = vecA;
    }
    // std::cout << "newA rows: " << newA.size() << ", newA cols: " << newA[0].size() << std::endl;

#pragma omp parallel for
    for (uint32_t j = 0; j < gStep; j++) {
        int offset = -static_cast<int>(bStep * j);
        for (uint32_t i = 0; i < bStep; i++) {
            if (bStep * j + i < slots) {
                // shifted diagonal is computed for rectangular map newA of dimension slots x 2*slots
                auto vec = ExtractShiftedDiagonal(newA, bStep * j + i);
                for (uint32_t k = 0; k < vec.size(); k++)
                    vec[k] *= scale;

                result[bStep * j + i] =
                    // MakeAuxPlaintext(cc, elementParamsPtr, Rotate(vec, offset), 1, towersToDrop, vec.size());
                    MakeAuxPlaintext(cc, elementParamsPtr, Rotate(Fill(vec, M / 4), offset), 1, towersToDrop, M / 4);
            }
        }
    }
    return result;
}

std::vector<ConstPlaintext> EvalLTPrecomputeSS(const CryptoContextImpl<DCRTPoly>& cc,
                                               const std::vector<std::vector<std::complex<double>>>& A,
                                               uint32_t dim1 = 0, double scale = 1) {
    if (A[0].size() != A.size()) {
        OPENFHE_THROW(math_error, "The matrix passed to EvalLTPrecomputeSS is not square");
    }

    uint32_t slots = A.size();

    uint32_t M     = cc.GetCyclotomicOrder();
    uint32_t bStep = (dim1 == 0) ? getRatioBSGS(static_cast<double>(slots)) : dim1;
    uint32_t gStep = ceil(static_cast<double>(slots) / bStep);

    // make sure the plaintext is created only with the necessary amount of moduli

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());

    uint32_t towersToDrop =
        elementParams.GetParams().size() -
        2;  // equivalent to L = 2, where L used to be an argument of how many levels the decoding consumes
    for (uint32_t i = 0; i < towersToDrop; i++)
        elementParams.PopLastParam();
    // std::cout << "towersToDrop: " << towersToDrop << std::endl;

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
        int offset = -static_cast<int>(bStep * j);
        for (uint32_t i = 0; i < bStep; i++) {
            if (bStep * j + i < slots) {
                auto diag = ExtractShiftedDiagonal(A, bStep * j + i);
                for (uint32_t k = 0; k < diag.size(); k++)
                    diag[k] *= scale;

                result[bStep * j + i] =
                    // MakeAuxPlaintext(cc, elementParamsPtr, Rotate(diag, offset), 1, towersToDrop, diag.size());
                    MakeAuxPlaintext(
                        cc, elementParamsPtr, Rotate(Fill(diag, M / 4), offset), 1, towersToDrop,
                        M / 4);  // Do we need to fill for wide matrices? Is the vector to multiply with repeated?
            }
        }
    }
    return result;
}

std::vector<std::vector<std::complex<double>>> EvalLTRectPrecomputeSS(
    const std::vector<std::vector<std::complex<double>>>& A, uint32_t dim1, double scale) {
    if ((A.size() / A[0].size()) * A[0].size() != A.size()) {
        OPENFHE_THROW(math_error, "The matrix passed to EvalLTPrecompute is not in proper rectangle shape");
    }

    uint32_t slots = A[0].size();
    uint32_t bStep = (dim1 == 0) ? getRatioBSGS(static_cast<double>(slots)) : dim1;
    uint32_t gStep = ceil(static_cast<double>(slots) / bStep);

    // make sure the plaintext is created only with the necessary amount of moduli

    auto num_slices = A.size() / A[0].size();
    std::vector<std::vector<std::vector<std::complex<double>>>> A_slices(num_slices);
    for (size_t i = 0; i < num_slices; i++) {
        A_slices[i] = std::vector<std::vector<std::complex<double>>>(A.begin() + i * A[0].size(),
                                                                     A.begin() + (i + 1) * A[0].size());
    }
    std::vector<std::vector<std::complex<double>>> diags(slots);
    // #pragma omp parallel for
    for (uint32_t j = 0; j < gStep; j++) {
        for (uint32_t i = 0; i < bStep; i++) {
            if (bStep * j + i < slots) {
                std::vector<std::complex<double>> diag(0);

                for (uint32_t k = 0; k < A.size() / A[0].size(); k++) {
                    auto tmp = ExtractShiftedDiagonal(A_slices[k], bStep * j + i);
                    diag.insert(diag.end(), tmp.begin(), tmp.end());
                }

                for (uint32_t k = 0; k < diag.size(); k++)
                    diag[k] *= scale;
                diags[bStep * j + i] = diag;
            }
        }
    }

    return diags;
}

Ciphertext<DCRTPoly> EvalLTWithPrecomputeSS(const CryptoContextImpl<DCRTPoly>& cc, ConstCiphertext<DCRTPoly> ctxt,
                                            const std::vector<ConstPlaintext>& A, uint32_t dim1 = 0) {
    uint32_t slots = A.size();

    // Computing the baby-step bStep and the giant-step gStep
    uint32_t bStep = (dim1 == 0) ? getRatioBSGS(static_cast<double>(slots)) :
                                   dim1;  // Andreea: I am using the optimized ratio, unlike the LT in bootstrapping
    uint32_t gStep = ceil(static_cast<double>(slots) / bStep);

    uint32_t M = cc.GetCyclotomicOrder();
    uint32_t N = cc.GetRingDimension();

    // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits = cc.EvalFastRotationPrecompute(ctxt);

    std::vector<Ciphertext<DCRTPoly>> fastRotation(bStep - 1);

    // hoisted automorphisms
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

Ciphertext<DCRTPoly> EvalLTRectWithPrecomputeSS(const CryptoContextImpl<DCRTPoly>& cc,
                                                const std::vector<std::vector<std::complex<double>>>& A,
                                                ConstCiphertext<DCRTPoly> ct, uint32_t dim1) {
    uint32_t slots = A.size();

    // Computing the baby-step bStep and the giant-step gStep
    uint32_t bStep = (dim1 == 0) ? getRatioBSGS(static_cast<double>(slots)) :
                                   dim1;  // Andreea: I am using the optimized ratio, unlike in the LT in bootstrapping
    uint32_t gStep = ceil(static_cast<double>(slots) / bStep);

    uint32_t M = cc.GetCyclotomicOrder();
    uint32_t N = cc.GetRingDimension();

    // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits = cc.EvalFastRotationPrecompute(ct);

    std::vector<Ciphertext<DCRTPoly>> fastRotation(bStep - 1);
    // make sure the plaintext is created only with the necessary amount of moduli

    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParamsCKKS->GetElementParams());
    uint32_t towersToDrop =
        elementParams.GetParams().size() -
        2;  // equivalent to L = 2, where L used to be an argument of how many levels the decoding consumes
    for (uint32_t i = 0; i < towersToDrop; i++)
        elementParams.PopLastParam();
    // std::cout << "towersToDrop: " << towersToDrop << std::endl;

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

// hoisted automorphisms
#pragma omp parallel for
    for (uint32_t j = 1; j < bStep; j++) {
        fastRotation[j - 1] = cc.EvalFastRotationExt(ct, j, digits, true);
    }

    Ciphertext<DCRTPoly> result;
    DCRTPoly first;

    for (uint32_t j = 0; j < gStep; j++) {
        int offset = (j == 0) ? 0 : -static_cast<int>(bStep * j);
        auto temp =
            cc.MakeCKKSPackedPlaintext(Rotate(Fill(A[bStep * j], M / 4), offset), 1, towersToDrop, elementParamsPtr2);
        Ciphertext<DCRTPoly> inner = cc.EvalMult(cc.KeySwitchExt(ct, true), temp);

        for (uint32_t i = 1; i < bStep; i++) {
            if (bStep * j + i < slots) {
                auto tempi = cc.MakeCKKSPackedPlaintext(Rotate(Fill(A[bStep * j + i], M / 4), offset), 1, towersToDrop,
                                                        elementParamsPtr2);
                inner      = cc.EvalAdd(inner, cc.EvalMult(tempi, fastRotation[i - 1]));
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
            result           = cc.EvalAdd(result, cc.EvalFastRotationExt(inner, bStep * j, innerDigits, false));
        }
    }

    result        = cc.KeySwitchDown(result);
    auto elements = result->GetElements();
    elements[0] += first;
    result->SetElements(elements);

    return result;
}

Ciphertext<DCRTPoly> EvalSlotsToCoeffsSS(
    const CryptoContextImpl<DCRTPoly>& cc,  // Andreea: full method, split into Precompute afterwards
    ConstCiphertext<DCRTPoly> ctxt, uint64_t slots, double scale) {
    uint32_t m    = 4 * slots;
    uint32_t M    = cc.GetCyclotomicOrder();
    bool isSparse = (M != m) ? true : false;
    std::cout << "Is sparse? " << isSparse << std::endl;

    // Computing the baby-step
    uint32_t dim1 = getRatioBSGS(static_cast<double>(slots));

    // computes indices for all primitive roots of unity
    std::vector<uint32_t> rotGroup(slots);
    uint32_t fivePows = 1;
    for (uint32_t i = 0; i < slots; ++i) {
        rotGroup[i] = fivePows;
        fivePows *= 5;
        fivePows %= m;
    }
    // computes all powers of a primitive root of unity exp(2*M_PI/m)
    std::vector<std::complex<double>> ksiPows(m + 1);
    for (uint32_t j = 0; j < m; ++j) {
        double angle = 2.0 * M_PI * j / m;
        ksiPows[j].real(cos(angle));
        ksiPows[j].imag(sin(angle));
    }
    ksiPows[m] = ksiPows[0];

    // matrices for decoding
    std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
    std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));

    for (size_t i = 0; i < slots; i++) {
        for (size_t j = 0; j < slots; j++) {
            U0[i][j] = ksiPows[(j * rotGroup[i]) % m];
            U1[i][j] = std::complex<double>(0, 1) * U0[i][j];
        }
    }

    auto ctxtToDecode = ctxt->Clone();
    ctxtToDecode->SetElements(ctxt->GetElements());
    ctxtToDecode = cc.Compress(ctxtToDecode, 2);
    // std::cout << "Ciphertext level after compression: " << ctxtToDecode->GetLevel() << std::endl;

    /* Manual debug to easily verify EvalSlotsToCoeff
    std::vector<std::complex<double>> x(slots*2, 0);
	x[0] = 0; x[1] = 1; x[2] = 0; x[3] = 0; x[4] = 0; x[5] = 0; x[6] = 0; x[7] = 0;
	x[slots] = 0; x[slots+1] = 1; x[slots+2] = 0;
	x[slots+3] = 0; x[slots+4] = 0; x[slots+5] = 0;
	x[slots+6] = 0; x[slots+7] = 0;

    if(isSparse) {
        //  U0 and U1 are concatenated horizontally
        std::vector<std::vector<std::complex<double>>> A(slots);
        for (uint32_t i = 0; i < U0.size(); i++) {
            auto vecA = U0[i];
            auto vecB = U1[i];
            vecA.insert(vecA.end(), vecB.begin(), vecB.end());
            A[i] = vecA;
        }

        std::vector<std::complex<double>> result(slots, 0);
        for (uint32_t i = 0; i < slots; i++) {
            std::complex<double> sum = 0;
            for (uint32_t j = 0; j < A[i].size(); j++) {
                sum += A[i][j]*x[j];
            }
            result[i] = sum;
        }
        std::cout << "\nMANUAL DEBUG: plain computation for x = (0,1,0,0,0,0,0,0):\n" << std::endl;
        std::cout << "result decoding [U0 | U1] * [x | x] = " << result << std::endl;

        std::vector<std::vector<std::complex<double>>> U0hatT(slots, std::vector<std::complex<double>>(slots));
        std::vector<std::vector<std::complex<double>>> U1hatT(slots, std::vector<std::complex<double>>(slots));

        for (size_t i = 0; i < slots; i++) {
            for (size_t j = 0; j < slots; j++) {
                U0hatT[j][i] = std::conj(U0[i][j]);
                U1hatT[j][i] = std::conj(U1[i][j]);
            }
        }

        //  U0hat and U1hat are concatenated vertically
        std::vector<std::vector<std::complex<double>>> B(2*slots);
        for (uint32_t i = 0; i < U0hatT.size(); i++) {
            B[i] = U0hatT[i];
        }
        for (uint32_t i = 0; i < U1hatT.size(); i++) {
            B[i+slots] = U1hatT[i];
        }

        std::vector<std::complex<double>> y(2*slots);
        std::cout << "\nMANUAL DEBUG encoding after decoding):\n" ;
        for (uint32_t i = 0; i < 2*slots; i++) {
            std::complex<double> sum = 0;
            for (uint32_t j = 0; j < B[i].size(); j++) {
                sum += B[i][j]*result[j];
            }
            y[i] = (sum + std::conj(sum))/double(2*slots);

        }

        std::cout << "should get initial input = " << y << std::endl << std::endl;

        std::cout << "Coefficients of x1: ";

        std::vector<std::complex<double>> half(slots);
        for (uint32_t i = 0; i < slots; i++) {
            std::complex<double> sum = 0;
            for (uint32_t j = 0; j < U0hatT[i].size(); j++) {
                sum += U0hatT[i][j]*x[j];
            }
            half[i] = sum/double(2*slots);
        }
        std::vector<std::complex<double>> half_enc(2*slots);
        for (uint32_t i = 0; i < slots; i++) {
            half_enc[i] = half[i] + std::conj(half[i]);
        }
        for (uint32_t i = 0; i < slots; i++) {
            std::complex<double> sum = 0;
            for (uint32_t j = 0; j < U1hatT[i].size(); j++) {
                sum += U1hatT[i][j]*x[j];
            }
            half[i] = sum/double(2*slots);
        }
        for (uint32_t i = 0; i < slots; i++) {
            half_enc[i+slots] = half[i] + std::conj(half[i]);
        }
        std::cout << half_enc << std::endl << std::endl;

    }
    else{
        //  U0
        std::vector<std::complex<double>> result(slots, 0);
        for (uint32_t i = 0; i < slots; i++) {
            std::complex<double> sum = 0;
            for (uint32_t j = 0; j < U0[i].size(); j++) {
                sum += U0[i][j]*x[j];
            }
            result[i] = sum;
        }

        std::cout << "\nDEBUG DEBUG DEBUG plain computation for x = (0,1,0,0,0,0,0,0):\nresult decoding = " << result << std::endl;

        std::vector<std::vector<std::complex<double>>> U0hatT(slots, std::vector<std::complex<double>>(slots));

        for (size_t i = 0; i < U0.size(); i++) {
            for (size_t j = 0; j < U0[0].size(); j++) {
                U0hatT[j][i] = std::conj(U0[i][j]);
            }
        }

        //  U0hat

        std::vector<std::complex<double>> y(U0hatT.size());
        std::cout << "\nDEBUG DEBUG DEBUG encoding after decoding):\n" ;
        for (uint32_t i = 0; i < U0hatT.size(); i++) {
            std::complex<double> sum = 0;
            for (uint32_t j = 0; j < U0hatT[i].size(); j++) {
                sum += U0hatT[i][j]*result[j];
            }
            y[i] = (sum + std::conj(sum))/double(2*slots);

        }
        std::cout << y << std::endl;
    }
*/

    Ciphertext<DCRTPoly> ctxtDecoded;

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    if (!isSparse) {  // fully packed
        auto U0Pre  = EvalLTPrecomputeSS(cc, U0, dim1, scale);
        ctxtDecoded = EvalLTWithPrecomputeSS(cc, ctxtToDecode, U0Pre, dim1);
    }
    else {  // sparsely packed
        auto U0Pre  = EvalLTPrecomputeSS(cc, U0, U1, dim1, scale);
        ctxtDecoded = EvalLTWithPrecomputeSS(cc, ctxtToDecode, U0Pre, dim1);
        ctxtDecoded = cc.EvalAdd(ctxtDecoded, cc.EvalAtIndex(ctxtDecoded, slots));
    }

    // auto scalingFactor = ctxtDecoded->GetScalingFactor();
    // std::cout << "scaling factor in ctxtDecoded: " << scalingFactor << std::endl << std::endl;

    return ctxtDecoded;
}

Ciphertext<DCRTPoly> EvalPartialHomDecryption(const CryptoContextImpl<DCRTPoly>& cc,
                                              const std::vector<std::vector<std::complex<double>>>& A,
                                              ConstCiphertext<DCRTPoly> ct, uint32_t dim1, double scale) {
    std::vector<std::vector<std::complex<double>>> Acopy(A);
    if ((A.size() % A[0].size()) != 0) {
        std::vector<std::vector<std::complex<double>>> padding(A[0].size() - (A.size() % A[0].size()));
        for (size_t i = 0; i < padding.size(); i++) {
            padding[i] = std::vector<std::complex<double>>(A[0].size());
        }
        Acopy.insert(Acopy.end(), padding.begin(), padding.end());
    }

    auto precomputedA = EvalLTRectPrecomputeSS(Acopy, dim1, scale);
    auto res          = EvalLTRectWithPrecomputeSS(cc, precomputedA, ct, dim1);
    precomputedA.clear();  // Andreea: is this necessary, doesn't it go out of scope?

    return res;
}

//------------------------------------------------------------------------------
// Scheme switching Wrapper
//------------------------------------------------------------------------------
std::pair<BinFHEContext, LWEPrivateKey> FHECKKSRNSSS::EvalCKKStoFHEWSetup(const CryptoContextImpl<DCRTPoly>& cc,
                                                                          bool dynamic, uint32_t logQ, SecurityLevel sl,
                                                                          uint32_t numSlotsCKKS) {
    bool arbFunc = false;  // flag for generating binfhe context for arbitrary functions, leads to larger parameters
                           // LWE cryptocontext
    m_ccLWE = BinFHEContext();
    if (sl == HEStd_128_classic)
        m_ccLWE.BinFHEContext::GenerateBinFHEContext(STD128, arbFunc, logQ, 0, GINX, dynamic);
    else
        m_ccLWE.BinFHEContext::GenerateBinFHEContext(TOY, arbFunc, logQ, 0, GINX, dynamic);

    m_modulus_LWE = 1 << logQ;  // Bear in mind this is not the same modulus as obtained from GetModulus() or as GetQ;

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

    return FHEWcc;
}

std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> FHECKKSRNSSS::EvalCKKStoFHEWKeyGen(const KeyPair<DCRTPoly>& keyPair,
                                                                                       LWEPrivateKey& lwesk) {
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

    // Compute switching key between RLWE and LWE, keep it in RLWE form
    // m_CKKStoFHEWswk = switchingKeyGenRLWE(privateKey, lwesk);

    // Andreea: only for debugging, remove later
    auto swPair     = switchingKeyGenRLWE(privateKey, lwesk);
    m_CKKStoFHEWswk = swPair.first;
    m_RLWELWEsk     = swPair.second;
    m_CKKSsk        = privateKey;

    // Compute automorphism keys
    uint32_t M     = ccCKKS->GetCyclotomicOrder();
    uint32_t slots = m_numSlotsCKKS;
    uint32_t dim1  = getRatioBSGS(static_cast<double>(slots));

    // Compute indices for rotations for slotToCoeff transform
    std::vector<int32_t> indexRotationS2C = FindLTRotationIndicesSS(dim1, M, slots);

    // Compute indices for rotations for sparse packing
    for (uint32_t i = 1; i < ccCKKS->GetRingDimension() / 2; i *= 2) {
        indexRotationS2C.push_back(static_cast<int>(i));
        if (i <= slots)
            indexRotationS2C.push_back(-static_cast<int>(i));
    }
    indexRotationS2C.push_back(static_cast<int>(slots));

    // Remove possible duplicates
    sort(indexRotationS2C.begin(), indexRotationS2C.end());
    indexRotationS2C.erase(unique(indexRotationS2C.begin(), indexRotationS2C.end()), indexRotationS2C.end());
    // std::cout << "Index rotation: " << indexRotationS2C << std::endl;

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

std::vector<std::shared_ptr<LWECiphertextImpl>> FHECKKSRNSSS::EvalCKKStoFHEW(ConstCiphertext<DCRTPoly> ciphertext,
                                                                             double scale, uint32_t numCtxts) const {
    auto ccCKKS    = ciphertext->GetCryptoContext();
    uint32_t slots = m_numSlotsCKKS;

    // Step 1. Homomorphic decoding
    auto ctxtDecoded = EvalSlotsToCoeffsSS(*ccCKKS, ciphertext, slots, scale);

    // //Hack to be able to decrypt complex numbers
    // auto evalKeyMap = ccCKKS->GetEvalAutomorphismKeyMap(ctxtDecoded->GetKeyTag());
    // auto ctxtDecodedConj = Conjugate(ctxtDecoded, evalKeyMap);
    // // // 2 * real part
    // // ccCKKS->EvalAddInPlace(ctxtDecoded, ctxtDecodedConj);
    // //2 * imag part
    // auto M = ccCKKS->GetCyclotomicOrder();
    // auto ctxtDecodedIm = ccCKKS->EvalAdd(ccCKKS->GetScheme()->MultByMonomial(ctxtDecoded, 3 * M / 4), ccCKKS->GetScheme()->MultByMonomial(ctxtDecodedConj, M / 4));

    // std::cout << "\n---Decrypted homomorphically decoded ciphertext (real or imag value)---" << std::endl;
    // Plaintext plaintextDec;
    // ccCKKS->Decrypt(m_CKKSsk, ctxtDecodedIm, &plaintextDec);
    // auto complex_vec = plaintextDec->GetRealPackedValue();
    // for (size_t j = 0; j < complex_vec.size(); j++) {
    //   std::cout << complex_vec[j]/2 << " ";
    // }
    // std::cout << std::endl << std::endl;

    // std::cout << "Ciphertext level after hom. decoding and compression: " << ctxtDecoded->GetLevel() << std::endl;

    // Step 2. Key switch
    ctxtDecoded = ccCKKS->Compress(ctxtDecoded);
    // std::cout << "Ciphertext level after more compression: " << ctxtDecoded->GetLevel() << std::endl;
    // std::cout << "scaling factor in ctxtDecoded: " << ctxtDecoded->GetScalingFactor() << std::endl << std::endl;

    // auto ctxtDecCoeff = DecryptWithoutDecode(*ccCKKS, ctxtDecoded, m_CKKSsk, slots, ccCKKS->GetRingDimension());
    // std::cout << "\nCoefficients of hom. decoded ciphertext (imaginary values can be thought as the last slot elements):\n" << ctxtDecCoeff << std::endl << std::endl;

    auto ctSwitched = ccCKKS->KeySwitch(ctxtDecoded, m_CKKStoFHEWswk);
    // std::cout << "scaling factor in ctSwitched: " << ctSwitched->GetScalingFactor() << std::endl << std::endl;

    // auto ptSwitched = DecryptWithoutDecode(*ccCKKS, ctSwitched, m_RLWELWEsk, slots, ccCKKS->GetRingDimension());
    // std::cout << "\nCoefficients of switched ciphertext (imaginary values can be thought as the last slot elements):\n" << ptSwitched << std::endl << std::endl;

    auto modulus_CKKS_from = ctSwitched->GetElements()[0].GetModulus();
    // std::cout << "current modulus in CKKS: " << modulus_CKKS_from << std::endl;
    // std::cout << "target modulus in FHEW: " << m_modulus_LWE << std::endl;

    // Step 3. Extract LWE ciphertexts
    auto const_ccLWE = BinFHEContext(
        m_ccLWE);  // Andreea: hack, otherwise I can't Getn() below with error "the object has type qualifiers that are not compatible with the member function "lbcrypto::BinFHEContext::GetParams""
    uint32_t n = const_ccLWE.GetParams()->GetLWEParams()->Getn();  // lattice parameter for additive LWE
    std::vector<std::shared_ptr<LWECiphertextImpl>> LWEciphertexts;
    auto AandB = ExtractLWEpacked(ctSwitched);

    if (numCtxts == 0) {
        numCtxts = slots;
    }

    uint32_t gap = ccCKKS->GetRingDimension() / (2 * slots);
    for (uint32_t i = 0, idx = 0; i < numCtxts; ++i, idx += gap) {
        auto temp = ExtractLWECiphertext(AandB, modulus_CKKS_from, const_ccLWE, n, idx);
        LWEciphertexts.push_back(temp);
    }

    // Step 4. Modulus switch
    if (m_modulus_LWE != modulus_CKKS_from) {
        for (uint32_t i = 0; i < numCtxts; i++) {
            auto original_a = LWEciphertexts[i]->GetA();
            auto original_b = LWEciphertexts[i]->GetB();
            // multiply by Q_LWE/Q_CKKS and round to Q_LWE
            NativeVector a_round(n, m_modulus_LWE);
            for (uint32_t j = 0; j < n; ++j)
                a_round[j] = RoundqQAlter(original_a[j], m_modulus_LWE, modulus_CKKS_from);
            NativeInteger b_round = RoundqQAlter(original_b, m_modulus_LWE, modulus_CKKS_from);
            LWEciphertexts[i]     = std::make_shared<LWECiphertextImpl>(std::move(a_round), std::move(b_round));
        }
    }

    // return ctxtDecoded;
    // return ctxtDecodedIm;
    return LWEciphertexts;
}

void FHECKKSRNSSS::EvalSchemeSwitchingSetup(const CryptoContextImpl<DCRTPoly>& cc, std::vector<uint32_t> levelBudget,
                                            std::vector<uint32_t> dim1, uint32_t numSlots, uint32_t correctionFactor) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
}

void FHECKKSRNSSS::EvalSchemeSwitchingKeyGen(const PrivateKey<DCRTPoly> privateKey, uint32_t slots) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(privateKey->GetCryptoParameters());
}

void FHECKKSRNSSS::EvalSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext, uint32_t numIterations,
                                       uint32_t precision) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());
}

}  // namespace lbcrypto
