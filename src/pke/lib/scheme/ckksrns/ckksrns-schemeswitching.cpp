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

#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns-internal.h"
#include "scheme/ckksrns/cryptocontext-ckksrns.h"
#include "scheme/ckksrns/cryptocontextparams-ckksrns.h"

#include "scheme/ckksrns/ckksrns-scheme.h"
#include "cryptocontextfactory.h"
#include "schemebase/base-scheme.h"
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
        result       = cc.GetScheme()->Decrypt(cTemp, privateKey, &decrypted->GetElement<Poly>());
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
        }
        else {
            powP = pow(2, -p);
        }

        const NativeInteger& q = decrypted->GetElementModulus().ConvertToInt();
        // NativeInteger qHalf    = q >> 1;

        for (size_t i = 0, idx = 0; i < slots; ++i, idx += gap) {
            std::complex<double> cur;

            // if (decrypted->GetElement<NativePoly>()[idx] > qHalf)
            //     cur.real(-((q - decrypted->GetElement<NativePoly>()[idx])).ConvertToDouble());
            // else
            //     cur.real((decrypted->GetElement<NativePoly>()[idx]).ConvertToDouble());

            // if (decrypted->GetElement<NativePoly>()[idx + Nh] > qHalf)
            //     cur.imag(-((q - decrypted->GetElement<NativePoly>()[idx + Nh])).ConvertToDouble());
            // else
            //     cur.imag((decrypted->GetElement<NativePoly>()[idx + Nh]).ConvertToDouble());

            cur.real((decrypted->GetElement<NativePoly>()[idx]).ConvertToDouble());
            cur.imag((decrypted->GetElement<NativePoly>()[idx + Nh]).ConvertToDouble());

            curValues[i] = cur / q.ConvertToDouble();
            // curValues[i] = cur * powP;
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
    int32_t MAX_BITS_IN_WORD = 61;

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
// Key and modulus switch and extraction methods
//------------------------------------------------------------------------------

NativeInteger RoundqQAlter(const NativeInteger& v, const NativeInteger& q, const NativeInteger& Q) {
    return NativeInteger((uint64_t)std::floor(0.5 + v.ConvertToDouble() * q.ConvertToDouble() / Q.ConvertToDouble()))
        .Mod(q);
}

NativeInteger RoundqScale(const NativeInteger& v, const NativeInteger& q, const double& Q) {
    return NativeInteger((uint64_t)std::floor(0.5 + v.ConvertToDouble() / Q * q.ConvertToDouble())).Mod(q);
}

NativeInteger RoundqScaleAlter(const NativeInteger& v, const NativeInteger& q, const double& scFactor,
                               const NativeInteger& p) {
    return NativeInteger(
               (uint64_t)std::floor(0.5 + v.ConvertToDouble() / scFactor * (q.ConvertToDouble() / p.ConvertToDouble())))
        .Mod(q);
}

// std::pair<EvalKey<DCRTPoly>, PrivateKey<DCRTPoly>>
EvalKey<DCRTPoly> switchingKeyGenRLWE(
    const PrivateKey<DCRTPoly>& ckksSK,
    ConstLWEPrivateKey& LWEsk) {  // Andreea: this function is without the intermediate ModSwitch
    // Extract CKKS params: method which populates the first n elements of a new RLWE key with the n elements of the target LWE key
    auto skelements = ckksSK->GetPrivateElement();
    skelements.SetFormat(Format::COEFFICIENT);
    auto lweskElements = LWEsk->GetElement();
    // std::cout << "lweskElements.GetLength() = " << lweskElements.GetLength() << std::endl;
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

    return ccCKKS->KeySwitchGen(ckksSK, RLWELWEsk);

    // // Andreea: only for debugging, remove later
    // std::pair<EvalKey<DCRTPoly>, PrivateKey<DCRTPoly>> swPair;
    // swPair.first  = ccCKKS->KeySwitchGen(ckksSK, RLWELWEsk);
    // swPair.second = RLWELWEsk;
    // return swPair;
}

void ModSwitch(ConstCiphertext<DCRTPoly> ctxt, Ciphertext<DCRTPoly>& ctxtKS, NativeInteger modulus_CKKS_to) {
    if (ctxt->GetElements()[0].GetRingDimension() != ctxtKS->GetElements()[0].GetRingDimension()) {
        OPENFHE_THROW(not_implemented_error, "ModSwitch is implemented only for the same ring dimension.");
    }

    auto Q = ctxt->GetElements()[0].GetModulus();

    const std::vector<DCRTPoly> cv = ctxt->GetElements();

    if (cv[0].GetNumOfElements() != 1 || ctxtKS->GetElements()[0].GetNumOfElements() != 1) {
        OPENFHE_THROW(not_implemented_error, "ModSwitch is implemented only for ciphhertext with one tower.");
    }

    std::vector<DCRTPoly> resultElements(cv.size());

    for (uint32_t i = 0; i < cv.size(); i++) {
        const auto paramsQlP = ctxtKS->GetElements()[0].GetParams();
        resultElements[i]    = DCRTPoly(paramsQlP, Format::COEFFICIENT, true);
        resultElements[i]    = resultElements[i].SetValuesModSwitch(cv[i], modulus_CKKS_to);
        resultElements[i].SetFormat(Format::EVALUATION);
    }

    ctxtKS->SetElements(resultElements);
}

// std::pair<EvalKey<DCRTPoly>, PrivateKey<DCRTPoly>>
EvalKey<DCRTPoly> switchingKeyGen(const PrivateKey<DCRTPoly>& ckksSKto, const PrivateKey<DCRTPoly>& ckksSKfrom) {
    auto skElements = ckksSKto->GetPrivateElement();
    skElements.SetFormat(Format::COEFFICIENT);
    auto skElementsFrom = ckksSKfrom->GetPrivateElement();
    skElementsFrom.SetFormat(Format::COEFFICIENT);

    // std::cout << "\nskElements.GetNumOfElements() = " << skElements.GetNumOfElements() << std::endl;
    // std::cout << "skElementsFrom.GetNumOfElements() = " << skElementsFrom.GetNumOfElements() << std::endl;
    // std::cout << "skElements.GetModulus() = " << skElements.GetModulus() << std::endl;

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

    // std::cout << "skElementsFrom = " << skElementsFrom.GetElementAtIndex(0) << std::endl;
    // std::cout << "skElements = " << skElements << std::endl;
    skElements.SetFormat(Format::EVALUATION);

    // skElementsFrom.SetFormat(Format::EVALUATION);
    // std::cout << "skElementsFrom = " << skElementsFrom.GetElementAtIndex(0) << std::endl;
    // std::cout << "skElements = " << skElements << std::endl;

    auto ccCKKSto        = ckksSKto->GetCryptoContext();
    auto oldTranformedSK = ccCKKSto->KeyGen().secretKey;
    oldTranformedSK->SetPrivateElement(std::move(skElements));

    return ccCKKSto->KeySwitchGen(oldTranformedSK, ckksSKto);

    // // Andreea: only for debugging, remove later
    // std::pair<EvalKey<DCRTPoly>, PrivateKey<DCRTPoly>> swPair;
    // swPair.first  = ccCKKSto->KeySwitchGen(oldTranformedSK, ckksSKto);
    // swPair.second = oldTranformedSK;

    // return swPair;
}

// std::pair<EvalKey<DCRTPoly>, PrivateKey<DCRTPoly>>
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

    // // Andreea: only for debugging, remove later
    // std::pair<EvalKey<DCRTPoly>, PrivateKey<DCRTPoly>> swPair;
    // swPair.first  = ccCKKSto->KeySwitchGen(oldTranformedSK, RLWELWEsk);
    // swPair.second = RLWELWEsk;

    // return swPair;
}

std::vector<std::vector<NativeInteger>> ExtractLWEpacked(const Ciphertext<DCRTPoly>& ct) {
    auto A = ct->GetElements()[1];
    auto B = ct->GetElements()[0];
    auto N = B.GetLength();

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
                                                        NativeInteger modulus, uint32_t n, uint32_t index = 0) {
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

std::vector<ConstPlaintext> FHECKKSRNSSS::EvalLTPrecomputeSS(const CryptoContextImpl<DCRTPoly>& cc,
                                                             const std::vector<std::vector<std::complex<double>>>& A,
                                                             const std::vector<std::vector<std::complex<double>>>& B,
                                                             uint32_t dim1, uint32_t L, double scale = 1) const {
    uint32_t slots = A.size();
    uint32_t M     = cc.GetCyclotomicOrder();

    // Computing the baby-step bStep and the giant-step gStep with the optimized ratio
    uint32_t bStep = (dim1 == 0) ? getRatioBSGS(static_cast<double>(slots)) : dim1;
    uint32_t gStep = ceil(static_cast<double>(slots) / bStep);

    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParamsCKKS->GetElementParams());
    uint32_t towersToDrop                         = 0;
    if (L != 0) {
        towersToDrop = elementParams.GetParams().size() - L - 1;
        for (uint32_t i = 0; i < towersToDrop; i++)
            elementParams.PopLastParam();
    }
    // std::cout << "towersToDrop EvalLTPrecomputeSS: " << towersToDrop << std::endl;

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

std::vector<ConstPlaintext> FHECKKSRNSSS::EvalLTPrecomputeSS(const CryptoContextImpl<DCRTPoly>& cc,
                                                             const std::vector<std::vector<std::complex<double>>>& A,
                                                             uint32_t dim1, uint32_t L, double scale = 1) const {
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

    uint32_t towersToDrop = 0;
    if (L != 0) {
        towersToDrop = elementParams.GetParams().size() - L - 1;
        for (uint32_t i = 0; i < towersToDrop; i++)
            elementParams.PopLastParam();
    }
    // std::cout << "towersToDrop EvalLTPrecomputeSS: " << towersToDrop << std::endl;

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
                    MakeAuxPlaintext(cc, elementParamsPtr, Rotate(Fill(diag, M / 4), offset), 1, towersToDrop, M / 4);
            }
        }
    }
    return result;
}

std::vector<std::vector<std::complex<double>>> EvalLTRectPrecomputeSS(
    const std::vector<std::vector<std::complex<double>>>& A, uint32_t dim1, double scale) {
    if ((A.size() / A[0].size()) * A[0].size() != A.size()) {
        OPENFHE_THROW(math_error, "The matrix passed to EvalLTPrecompute is not in proper rectangular shape");
    }
    // std::cout << "scale factor to scale the matrix A: " << scale << std::endl;
    uint32_t n     = A[0].size();  //
    uint32_t bStep = (dim1 == 0) ? getRatioBSGS(static_cast<double>(n)) : dim1;
    uint32_t gStep = ceil(static_cast<double>(n) / bStep);

    // std::cout << "bStep = " << bStep << ", gStep = " << gStep << std::endl;

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

                for (uint32_t k = 0; k < diag.size(); k++) {
                    diag[k] *= scale;
                }
                diags[bStep * j + i] = diag;
            }
        }
    }
    // std::cout << "diags.size() = " << diags.size() << ", diags[0].size() = " << diags[0].size() << std::endl;

    return diags;
}

Ciphertext<DCRTPoly> EvalLTWithPrecomputeSS(const CryptoContextImpl<DCRTPoly>& cc, ConstCiphertext<DCRTPoly> ctxt,
                                            const std::vector<ConstPlaintext>& A, uint32_t dim1) {
    // std::cout << "Ciphertext level and depth at start of EvalLTWithPrecomputeSS: " << ctxt->GetLevel() << ", " << ctxt->GetNoiseScaleDeg() << std::endl;

    uint32_t slots = A.size();

    // Computing the baby-step bStep and the giant-step gStep
    uint32_t bStep = dim1;
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

Ciphertext<DCRTPoly> FHECKKSRNSSS::EvalLTRectWithPrecomputeSS(const CryptoContextImpl<DCRTPoly>& cc,
                                                              const std::vector<std::vector<std::complex<double>>>& A,
                                                              ConstCiphertext<DCRTPoly> ct, uint32_t dim1,
                                                              uint32_t L) const {
    // std::cout << "Ciphertext level and depth at start of EvalLTRectWithPrecomputeSS: " << ct->GetLevel() << ", " << ct->GetNoiseScaleDeg() << std::endl;

    uint32_t n = A.size();

    // Computing the baby-step bStep and the giant-step gStep using the optimized ratio
    uint32_t bStep = (dim1 == 0) ? getRatioBSGS(static_cast<double>(n)) : dim1;
    uint32_t gStep = ceil(static_cast<double>(n) / bStep);

    // std::cout << "bStep = " << bStep << ", gStep = " << gStep << std::endl;

    uint32_t M = cc.GetCyclotomicOrder();
    uint32_t N = cc.GetRingDimension();

    // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits = cc.EvalFastRotationPrecompute(ct);

    std::vector<Ciphertext<DCRTPoly>> fastRotation(bStep - 1);

    // make sure the plaintext is created only with the necessary amount of moduli

    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ct->GetCryptoParameters());

    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParamsCKKS->GetElementParams());
    uint32_t towersToDrop                         = 0;

    // for FLEXIBLEAUTOEXT we do not need extra modulus in auxiliary plaintexts
    if (L != 0) {
        towersToDrop = elementParams.GetParams().size() - L - 1;
        for (uint32_t i = 0; i < towersToDrop; i++)
            elementParams.PopLastParam();
    }
    if (cryptoParamsCKKS->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
        towersToDrop += 1;
        elementParams.PopLastParam();
    }
    // std::cout << "towersToDrop EvalLTRectWithPrecomputeSS: " << towersToDrop << std::endl;

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
        auto temp  = cc.MakeCKKSPackedPlaintext(Rotate(Fill(A[bStep * j], N / 2), offset), 1, towersToDrop,
                                                elementParamsPtr2, N / 2);
        Ciphertext<DCRTPoly> inner = EvalMultExt(cc.KeySwitchExt(ct, true), temp);

        // std::cout << "inner level and depth: " << inner->GetLevel() << ", " << inner->GetNoiseScaleDeg() << std::endl;

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

Ciphertext<DCRTPoly> FHECKKSRNSSS::EvalSlotsToCoeffsSS(const CryptoContextImpl<DCRTPoly>& cc,
                                                       ConstCiphertext<DCRTPoly> ctxt) const {
    // std::cout << "Ciphertext level and depth at start of EvalSlotsToCoeffSS: " << ctxt->GetLevel() << ", " << ctxt->GetNoiseScaleDeg() << std::endl;

    uint32_t slots = m_numSlotsCKKS;
    uint32_t m     = 4 * slots;
    uint32_t M     = cc.GetCyclotomicOrder();
    bool isSparse  = (M != m) ? true : false;
    // std::cout << "Is sparse? " << isSparse << std::endl;

    auto ctxtToDecode = ctxt->Clone();
    ctxtToDecode->SetElements(ctxt->GetElements());
    ctxtToDecode = cc.Compress(ctxtToDecode, 2);
    // std::cout << "Ciphertext level and depth after compression EvalSlotsToCoeffSS: " << ctxtToDecode->GetLevel() << ", " << ctxtToDecode->GetNoiseScaleDeg() << std::endl;

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

    // const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    if (slots != m_numSlotsCKKS || m_U0Pre.size() == 0) {
        std::string errorMsg(std::string("Precomputations for ") + std::to_string(slots) +
                             std::string(" slots were not generated") +
                             std::string(" Need to call EvalCKKSToFHEWPrecompute to proceed"));
        OPENFHE_THROW(type_error, errorMsg);
    }

    if (!isSparse) {  // fully packed
        // ctxtToDecode = cc.EvalAdd(ctxtToDecode, cc.GetScheme()->MultByMonomial(ctxtToDecode, M / 4)); // Andreea: adding this does not seem to change the result, why?
        ctxtDecoded = EvalLTWithPrecomputeSS(cc, ctxtToDecode, m_U0Pre, m_dim1CF);
    }
    else {  // sparsely packed
        ctxtDecoded = EvalLTWithPrecomputeSS(cc, ctxtToDecode, m_U0Pre, m_dim1CF);
        ctxtDecoded = cc.EvalAdd(ctxtDecoded, cc.EvalAtIndex(ctxtDecoded, slots));
    }

    // auto scalingFactor = ctxtDecoded->GetScalingFactor();
    // std::cout << "scaling factor in ctxtDecoded: " << scalingFactor << std::endl << std::endl;

    return ctxtDecoded;
}

Ciphertext<DCRTPoly> FHECKKSRNSSS::EvalPartialHomDecryption(const CryptoContextImpl<DCRTPoly>& cc,
                                                            const std::vector<std::vector<std::complex<double>>>& A,
                                                            ConstCiphertext<DCRTPoly> ct, uint32_t dim1, double scale,
                                                            uint32_t L) const {
    // std::cout << "A.size(): " << A.size() << ", A[0].size(): " << A[0].size() << std::endl;

    // Ensure the # rows (# of LWE ciphertext to switch) is a multiple of # columns (the lattice parameter n)
    std::vector<std::vector<std::complex<double>>> Acopy(A);
    if ((A.size() % A[0].size()) != 0) {
        std::vector<std::vector<std::complex<double>>> padding(A[0].size() - (A.size() % A[0].size()));
        for (size_t i = 0; i < padding.size(); i++) {
            padding[i] = std::vector<std::complex<double>>(A[0].size());
        }
        Acopy.insert(Acopy.end(), padding.begin(), padding.end());
    }
    // std::cout << "Acopy.size(): " << Acopy.size() << ", Acopy[0].size(): " << Acopy[0].size() << std::endl;

    auto Apre = EvalLTRectPrecomputeSS(Acopy, dim1, scale);
    auto res  = EvalLTRectWithPrecomputeSS(cc, Apre, ct, dim1, L);  // The result is repeated every Acopy.size() slots

    return res;
}

//------------------------------------------------------------------------------
// Scheme switching Wrapper
//------------------------------------------------------------------------------
std::pair<BinFHEContext, LWEPrivateKey> FHECKKSRNSSS::EvalCKKStoFHEWSetup(const CryptoContextImpl<DCRTPoly>& cc,
                                                                          SecurityLevel sl, bool arbFunc, uint32_t logQ,
                                                                          bool dynamic, uint32_t numSlotsCKKS) {
    m_ccLWE = BinFHEContext();
    if (sl == HEStd_128_classic)
        m_ccLWE.BinFHEContext::GenerateBinFHEContext(STD128, arbFunc, logQ, 0, GINX, dynamic);
    else
        m_ccLWE.BinFHEContext::GenerateBinFHEContext(TOY, arbFunc, logQ, 0, GINX, dynamic);

    // For arbitrary functions, the LWE ciphertext needs to be at most the ring dimension in FHEW bootstrapping
    m_modulus_LWE = (arbFunc == false) ? 1 << logQ : m_ccLWE.GetParams()->GetLWEParams()->Getq().ConvertToInt();

    // LWE private key
    LWEPrivateKey lwesk;
    lwesk = m_ccLWE.KeyGen();
    // m_FHEWsk = lwesk;

    std::pair<BinFHEContext, LWEPrivateKey> FHEWcc;
    FHEWcc.first  = m_ccLWE;
    FHEWcc.second = lwesk;

    uint32_t M = cc.GetCyclotomicOrder();
    if (numSlotsCKKS == 0 || numSlotsCKKS == M / 4)  // fully-packed
        m_numSlotsCKKS = M / 4;
    else  // sparsely-packed
        m_numSlotsCKKS = numSlotsCKKS;

    // Modulus to switch in order to have secure RLWE samples (Q', n)
    // We can select any Q' less than 27 bits corresponding to 128 bits of security for lattice parameter n=1024 < 1305 according to https://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf
    // Ensure that Q' is larger than Q_FHEW.
    uint32_t logQswitch;
    if (logQ < 27)
        logQswitch = 27;  // logQ + 1;
    else
        OPENFHE_THROW(config_error, "The switching from CKKS to FHEW is not secure for n = 1305.");

    // Intermediate cryptocontext
    uint32_t multDepth    = 0;
    uint32_t scaleModSize = cc.GetEncodingParams()->GetPlaintextModulus();

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetFirstModSize(logQswitch);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(
        FIXEDMANUAL);  // Don't need this to be the same scaling technique as the outer cryptocontext, since no multiplication/decryption is done, and the scaling factor is already fatored out
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

    // Set the scaling factor to be able to decrypt
    const auto cryptoParams2 = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(m_ccKS->GetCryptoParameters());

    // Get the last ciphertext modulus; this assumes the LWE mod switch will be performed on the ciphertext at the last level
    ILDCRTParams<DCRTPoly::Integer> elementParams2 = *(cryptoParams2->GetElementParams());
    auto paramsQ2                                  = elementParams2.GetParams();
    m_modulus_CKKS_from                            = paramsQ2[0]->GetModulus().ConvertToInt();
    // std::cout << "Modulus to switch to in CKKS: " << m_modulus_CKKS_from <<  std::endl;

    return FHEWcc;
}

std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> FHECKKSRNSSS::EvalCKKStoFHEWKeyGen(const KeyPair<DCRTPoly>& keyPair,
                                                                                       ConstLWEPrivateKey& lwesk,
                                                                                       uint32_t dim1, uint32_t L) {
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
    // m_ctxtKS         = ccKS->Compress(m_ctxtKS, 1);

    // Compute switching key between RLWE and LWE via the intermediate cryptocontext, keep it in RLWE form
    m_CKKStoFHEWswk = switchingKeyGenRLWEcc(keys2.secretKey, privateKey, lwesk);

    // // Andreea: only for debugging, remove later
    // auto swPair     = switchingKeyGenRLWEcc(keys2.secretKey, privateKey, lwesk);
    // m_CKKStoFHEWswk = swPair.first;
    // m_RLWELWEsk     = swPair.second;
    // m_CKKSsk        = privateKey;
    // m_CKKSskKS      = keys2.secretKey;

    // // Andreea: this was without the intermediate modulus switching
    // // Compute switching key between RLWE and LWE, keep it in RLWE form
    // // m_CKKStoFHEWswk = switchingKeyGenRLWE(privateKey, lwesk);
    // // Andreea: only for debugging, remove later
    // auto swPair     = switchingKeyGenRLWE(privateKey, lwesk);
    // m_CKKStoFHEWswk = swPair.first;
    // m_RLWELWEsk     = swPair.second;
    // m_CKKSsk        = privateKey;

    // Compute automorphism keys
    uint32_t M     = ccCKKS->GetCyclotomicOrder();
    uint32_t slots = m_numSlotsCKKS;
    // Computing the baby-step
    if (dim1 == 0)
        dim1 = getRatioBSGS(static_cast<double>(slots));
    m_dim1CF = dim1;
    // std::cout << "dim1 for CKKS to FHEW: " << m_dim1CF << std::endl;
    m_LCF = L;

    // Compute indices for rotations for slotToCoeff transform
    std::vector<int32_t> indexRotationS2C = FindLTRotationIndicesSS(m_dim1CF, M, slots);
    indexRotationS2C.push_back(static_cast<int>(slots));

    // // Compute indices for rotations for sparse packing
    // for (uint32_t i = 1; i < ccCKKS->GetRingDimension() / 2; i *= 2) {
    //     indexRotationS2C.push_back(static_cast<int>(i));
    //     if (i <= slots)
    //         indexRotationS2C.push_back(-static_cast<int>(i));
    // }

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

void FHECKKSRNSSS::EvalCKKStoFHEWPrecompute(const CryptoContextImpl<DCRTPoly>& cc, double scale) {
    uint32_t M     = cc.GetCyclotomicOrder();
    uint32_t slots = m_numSlotsCKKS;

    uint32_t m    = 4 * m_numSlotsCKKS;
    bool isSparse = (M != m) ? true : false;
    // std::cout << "Is sparse? " << isSparse << std::endl;

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
    // std::cout << "dim1 for CKKS to FHEW in Precompute: " << m_dim1CF << std::endl;

    if (!isSparse) {  // fully packed
        m_U0Pre = EvalLTPrecomputeSS(cc, U0, m_dim1CF, m_LCF, scale);
    }
    else {  // sparsely packed
        m_U0Pre = EvalLTPrecomputeSS(cc, U0, U1, m_dim1CF, m_LCF, scale);
    }
}

std::vector<std::shared_ptr<LWECiphertextImpl>> FHECKKSRNSSS::EvalCKKStoFHEW(ConstCiphertext<DCRTPoly> ciphertext,
                                                                             uint32_t numCtxts) {
    auto ccCKKS    = ciphertext->GetCryptoContext();
    uint32_t slots = m_numSlotsCKKS;

    // Step 1. Homomorphic decoding
    auto ctxtDecoded = EvalSlotsToCoeffsSS(*ccCKKS, ciphertext);

    // //Hack to be able to decrypt complex numbers
    // auto evalKeyMap = ccCKKS->GetEvalAutomorphismKeyMap(ctxtDecoded->GetKeyTag());
    // auto ctxtDecodedConj = Conjugate(ctxtDecoded, evalKeyMap);
    // // 2 * real part
    // auto ctxtDecodedRe = ccCKKS->EvalAdd(ctxtDecoded, ctxtDecodedConj);
    // //2 * imag part
    // auto M = ccCKKS->GetCyclotomicOrder();
    // auto ctxtDecodedIm = ccCKKS->EvalAdd(ccCKKS->GetScheme()->MultByMonomial(ctxtDecoded, 3 * M / 4), ccCKKS->GetScheme()->MultByMonomial(ctxtDecodedConj, M / 4));

    // std::cout << "\n---Decrypted homomorphically decoded ciphertext (real or imag value)---" << std::endl;
    // Plaintext plaintextDec;
    // ccCKKS->Decrypt(m_CKKSsk, ctxtDecodedRe, &plaintextDec);
    // auto complex_vec = plaintextDec->GetRealPackedValue();
    // for (size_t j = 0; j < complex_vec.size(); j++) {
    //   std::cout << complex_vec[j]/2 << " ";
    // }
    // std::cout << std::endl;
    // ccCKKS->Decrypt(m_CKKSsk, ctxtDecodedIm, &plaintextDec);
    // complex_vec = plaintextDec->GetRealPackedValue();
    // for (size_t j = 0; j < complex_vec.size(); j++) {
    //   std::cout << complex_vec[j]/2 << " ";
    // }
    // std::cout << std::endl<< std::endl;

    // std::cout << "Ciphertext level and depth after hom. decoding and compression: " << ctxtDecoded->GetLevel() << ", " << ctxtDecoded->GetNoiseScaleDeg() << std::endl;

    // std::cout << "scaling factor in ciphertext: " << ciphertext->GetScalingFactor() << std::endl << std::endl;

    ctxtDecoded = ccCKKS->Compress(ctxtDecoded);
    // std::cout << "Ciphertext level and depth after more compression: " << ctxtDecoded->GetLevel() << ", " << ctxtDecoded->GetNoiseScaleDeg() << std::endl;
    // std::cout << "scaling factor in ctxtDecoded: " << ctxtDecoded->GetScalingFactor() << std::endl << std::endl;

    // auto ctxtDecCoeff = DecryptWithoutDecode(*ccCKKS, ctxtDecoded, m_CKKSsk, slots, ccCKKS->GetRingDimension());
    // std::cout << "\nCoefficients of hom. decoded ciphertext (imaginary values can be thought as the last slot elements):\n" << ctxtDecCoeff << std::endl << std::endl;

    // Step 2. Modulus switch to Q', such that CKKS is secure for (Q',n)
    // std::cout << "m_modulus_CKKS_from = " << m_modulus_CKKS_from << std::endl;
    // std::cout << "ctxtDecoded->GetElements()[0].GetModulus() = " << ctxtDecoded->GetElements()[0].GetModulus() << std::endl;

    auto ctxtKS = m_ctxtKS->Clone();
    ModSwitch(ctxtDecoded, ctxtKS, m_modulus_CKKS_from);

    // auto ctxtDecModCoeff = DecryptWithoutDecode(*ccCKKS, ctxtKS, m_CKKSsk, slots, ccCKKS->GetRingDimension());
    // std::cout << "\nCoefficients of mod. switched ciphertext (imaginary values can be thought as the last slot elements):\n" << ctxtDecModCoeff << std::endl << std::endl;

    // std::cout << "scaling factor in ctxtKS: " << ctxtKS->GetScalingFactor() << std::endl << std::endl;

    // Step 3: Key switch from the CKKS key with the new modulus Q' to the RLWE version of the FHEW key with the new modulus Q'
    auto ctSwitched = m_ccKS->KeySwitch(ctxtKS, m_CKKStoFHEWswk);

    // auto ptSwitched = DecryptWithoutDecode(*m_ccKS, ctxtKS, m_RLWELWEsk, slots, m_ccKS->GetRingDimension());
    // std::cout << "\nCoefficients of key switched ciphertext (imaginary values can be thought as the last slot elements):\n" << ptSwitched << std::endl << std::endl;
    // ptSwitched = DecryptWithoutDecode(*m_ccKS, ctSwitched, m_CKKSskKS, slots, m_ccKS->GetRingDimension());
    // std::cout << "\nCoefficients of key switched ciphertext (imaginary values can be thought as the last slot elements):\n" << ptSwitched << std::endl << std::endl;

    // auto ctSwitched = ccCKKS->KeySwitch(ctxtDecoded, m_CKKStoFHEWswk); // Andreea: old insecure version
    // // std::cout << "scaling factor in ctSwitched: " << ctSwitched->GetScalingFactor() << std::endl << std::endl;
    // // auto ptSwitched = DecryptWithoutDecode(*ccCKKS, ctSwitched, m_RLWELWEsk, slots, ccCKKS->GetRingDimension());
    // // std::cout << "\nCoefficients of switched ciphertext (imaginary values can be thought as the last slot elements):\n" << ptSwitched << std::endl << std::endl;

    // std::cout << "scaling factor in ctSwitched: " << ctSwitched->GetScalingFactor() << std::endl << std::endl;

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
        LWEciphertexts.push_back(temp);
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
void FHECKKSRNSSS::EvalFHEWtoCKKSSetup(const CryptoContextImpl<DCRTPoly>& ccCKKS, const BinFHEContext& ccLWE,
                                       uint32_t numSlotsCKKS, uint32_t logQ) {
    // m_ccCKKS = std::make_shared<CryptoContextImpl<DCRTPoly>>(ccCKKS);
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

std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> FHECKKSRNSSS::EvalFHEWtoCKKSKeyGen(const KeyPair<DCRTPoly>& keyPair,
                                                                                       ConstLWEPrivateKey& lwesk,
                                                                                       uint32_t numSlots, uint32_t dim1,
                                                                                       uint32_t L) {
    auto privateKey = keyPair.secretKey;
    auto publicKey  = keyPair.publicKey;

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(privateKey->GetCryptoParameters());
    auto ccCKKS             = privateKey->GetCryptoContext();

    uint32_t n       = lwesk->GetElement().GetLength();
    uint32_t ringDim = ccCKKS->GetRingDimension();

    // Generate FHEW to CKKS switching key, i.e., CKKS encryption of FHEW secret key
    auto skLWEElements = lwesk->GetElement();
    // std::vector<std::complex<double>> skLWEDouble(ringDim/2);
    std::vector<std::complex<double>> skLWEDouble(n);
    // #pragma omp parallel for
    for (uint32_t i = 0; i < n; i++) {
        auto tmp = skLWEElements[i].ConvertToDouble();
        if (tmp == lwesk->GetModulus().ConvertToInt() - 1)
            tmp = -1;
        skLWEDouble[i] = std::complex<double>(tmp, 0);
    }

    // m_FHEWtoCKKSswkDouble = skLWEDouble;

    // Check encoding and specify the number of slots, otherwise, if batchsize is set and is smaller, it will throw an error.
    Plaintext skLWEPlainswk;
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        skLWEPlainswk = ccCKKS->MakeCKKSPackedPlaintext(Fill(skLWEDouble, ringDim / 2), 1, BASE_NUM_LEVELS_TO_DROP,
                                                        nullptr, ringDim / 2);
    else
        skLWEPlainswk = ccCKKS->MakeCKKSPackedPlaintext(Fill(skLWEDouble, ringDim / 2), 1, 0, nullptr, ringDim / 2);
    // std::cout << "Encoded key: " << skLWEPlainswk << std::endl;

    // auto FHEWtoCKKSswk = ccCKKS->Encrypt(publicKey, skLWEPlainswk);
    // if(cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
    //     ccCKKS->GetScheme()->ModReduceInternalInPlace(FHEWtoCKKSswk, BASE_NUM_LEVELS_TO_DROP);
    m_FHEWtoCKKSswk = ccCKKS->Encrypt(publicKey, skLWEPlainswk);
    // std::cout << "m_swkkey level and depth: " << m_FHEWtoCKKSswk->GetLevel() << ", " << m_FHEWtoCKKSswk->GetNoiseScaleDeg() << std::endl;

    // Compute automorphism keys for CKKS for baby-step giant-step with optimized ration
    uint32_t M = ccCKKS->GetCyclotomicOrder();
    if (dim1 == 0)
        dim1 = getRatioBSGS(static_cast<double>(n));
    m_dim1FC = dim1;
    m_LFC    = L;

    // Compute indices for rotations for homomorphic decryption in CKKS
    std::vector<int32_t> indexRotationHomDec = FindLTRotationIndicesSS(dim1, M, n);

    uint32_t slots = (numSlots == 0) ? m_numSlotsCKKS : numSlots;
    // Compute indices for rotations to bring back the final CKKS ciphertext encoding to slots
    for (uint32_t j = 1; j < ringDim / (2 * slots);
         j <<= 1) {  // if the encoding is full, the for loop does not execute
        indexRotationHomDec.push_back(j * slots);
    }

    // Remove possible duplicates
    sort(indexRotationHomDec.begin(), indexRotationHomDec.end());
    indexRotationHomDec.erase(unique(indexRotationHomDec.begin(), indexRotationHomDec.end()),
                              indexRotationHomDec.end());
    // std::cout << "Index rotation: " << indexRotationHomDec << std::endl;

    auto algo     = ccCKKS->GetScheme();
    auto evalKeys = algo->EvalAtIndexKeyGen(publicKey, privateKey, indexRotationHomDec);

    // Compute multiplication key
    // algo->EvalMultKeyGen(privateKey);
    ccCKKS->EvalMultKeyGen(privateKey);

    return evalKeys;
}

Ciphertext<DCRTPoly> FHECKKSRNSSS::EvalFHEWtoCKKS(std::vector<std::shared_ptr<LWECiphertextImpl>>& LWECiphertexts,
                                                  double prescale, uint32_t numCtxts, uint32_t numSlots, uint32_t p,
                                                  double pmin, double pmax) const {
    if (!LWECiphertexts.size())
        OPENFHE_THROW(type_error, "Empty input FHEW ciphertext vector");
    uint32_t numLWECtxts = LWECiphertexts.size();

    uint32_t slots =
        (numSlots == 0) ? m_numSlotsCKKS : numSlots;  // This is the number of CKKS slots to use in encoding

    uint32_t numValues = (numCtxts == 0) ? numLWECtxts : std::min(numCtxts, numLWECtxts);
    numValues = std::min(numValues, slots);  // This is the number of LWE ciphertexts to pack into the CKKS ciphertext

    uint32_t n = LWECiphertexts[0]->GetA().GetLength();
    // std::cout << "n from LWECiphertexts: " << n << std::endl;
    // uint32_t init_level = m_FHEWtoCKKSswk->GetLevel();

    auto ccCKKS                 = m_FHEWtoCKKSswk->GetCryptoContext();
    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ccCKKS->GetCryptoParameters());

    uint32_t m    = 4 * slots;
    uint32_t M    = ccCKKS->GetCyclotomicOrder();
    uint32_t N    = ccCKKS->GetRingDimension();
    bool isSparse = (M != m) ? true : false;

    // Andreea: TODO compute formally the failure probability for n and K
    double K = 1.0;
    std::vector<double> coefficientsFHEW;
    if (n == 32) {
        K                = 16.0;
        coefficientsFHEW = g_coefficientsFHEW16;
    }
    else {
        // EvalFHEWtoCKKS assumes lattice parameter n is at most 2048.
        K = 128.0;  // Failure probability of 2^{-49}
        if (p <= 4) {
            coefficientsFHEW =
                g_coefficientsFHEW128_8;  // If the output messages are bits, we could use a lower degree polynomial
        }
        else {
            coefficientsFHEW = g_coefficientsFHEW128_9;
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

    // std::cout << "modulus from ciphertext: " << LWECiphertexts[0]->GetModulus() << std::endl;
    // std::cout << "m_modulus: " << m_modulus_LWE << std::endl;

    prescale =
        prescale /
        K;  // Combine the scale with the division by K to consume fewer levels, but careful since the value might be too small

    // std::cout << "prescale = " << prescale << std::endl;
#pragma omp parallel for
    for (uint32_t i = 0; i < numValues; i++) {
        auto a = LWECiphertexts[i]->GetA();
        A[i]   = std::vector<std::complex<double>>(a.GetLength());
        for (uint32_t j = 0; j < a.GetLength(); j++) {
            A[i][j] = std::complex<double>(a[j].ConvertToDouble(), 0);
        }
        b[i] = std::complex<double>(LWECiphertexts[i]->GetB().ConvertToDouble(), 0);
    }

    // std::vector<double> y(numValues);
    // for (uint32_t i = 0; i < numValues; i++) {
    //     std::complex<double> sum = 0;
    //     for (uint32_t j = 0; j < A[i].size(); j++) {
    //         sum += A[i][j]*m_FHEWtoCKKSswkDouble[j]*prescale;
    //     }
    //     y[i] = b[i].real()*prescale - sum.real();
    // }
    // std::cout << "---Expected result of B-A*s: " << y << "---" << std::endl;

    // Step 2. Perform the homomorphic linear transformation of A*skLWE
    Ciphertext<DCRTPoly> AdotS = EvalPartialHomDecryption(*ccCKKS, A, m_FHEWtoCKKSswk, m_dim1FC, prescale, 0);
    // std::cout << "AdotS level and depth: " << AdotS->GetLevel() << ", " << AdotS->GetNoiseScaleDeg() << std::endl;

    // Step 3. Get the ciphertext of B - A*s
    for (uint32_t i = 0; i < numValues; i++) {
        b[i] = b[i] * prescale;
    }
    // Plaintext BPlain = ccCKKS->MakeCKKSPackedPlaintext(b, 1, 0, nullptr, N / 2);
    Plaintext BPlain = ccCKKS->MakeCKKSPackedPlaintext(b, AdotS->GetNoiseScaleDeg(), AdotS->GetLevel(), nullptr, N / 2);

    // std::cout << "BPlain level and depth: " << BPlain->GetLevel() << ", " << BPlain->GetNoiseScaleDeg() << std::endl;

    auto BminusAdotS = ccCKKS->EvalAdd(ccCKKS->EvalNegate(AdotS), BPlain);

    // std::cout << "BminusAdotS level and depth: " << BminusAdotS->GetLevel() << ", " << BminusAdotS->GetNoiseScaleDeg() << std::endl;

    if (cryptoParamsCKKS->GetScalingTechnique() == FIXEDMANUAL) {
        ccCKKS->ModReduceInPlace(BminusAdotS);
        // std::cout << "BminusAdotS after compression level and depth: " << BminusAdotS->GetLevel() << ", "
        //   << BminusAdotS->GetNoiseScaleDeg() << std::endl;
    }
    else {
        if (BminusAdotS->GetNoiseScaleDeg() == 2)
            ccCKKS->GetScheme()->ModReduceInternalInPlace(BminusAdotS, BASE_NUM_LEVELS_TO_DROP);
    }

    // Step 4. Do the modulus reduction: homomorphically evaluate modular function. We do it by using sine approximation.

    // /* Andreea: this was done because there was a bug with multiplying by large values (for FHEW decryption with a large plaintext modulus), which corrupted all slots.
    //  * Hence, we zero out all irrelevant slots here. The bug was resolved, but note that multiplying by very large values does incur a potentially non-negligible error.
    // /*
    // std::vector<std::complex<double>> normFactor(N / 2, 0);
    // for (size_t i = 0; i < numValues; i++) {
    //     normFactor[i] = std::complex<double>(1.0 / K, 0.0);
    // }
    // auto normFactorPlain = ccCKKS->MakeCKKSPackedPlaintext(normFactor, 1, 0, nullptr, N / 2);
    // auto BminusAdotS2 =
    //     ccCKKS->EvalMult(BminusAdotS, normFactorPlain);  // This should zero out everything which is not of interest
    // if (cryptoParamsCKKS->GetScalingTechnique() == FIXEDMANUAL) {
    //     BminusAdotS2 = ccCKKS->Compress(BminusAdotS2, init_level - BminusAdotS2->GetLevel() - 1);
    // }
    // // else if (cryptoParamsCKKS->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
    // //     ccCKKS->GetScheme()->ModReduceInternalInPlace(BminusAdotS2, BASE_NUM_LEVELS_TO_DROP);
    // // }

    auto BminusAdotS2 = BminusAdotS;  // Instead of zeroing out slots which are not of interest as done above

    double a_cheby = -1;
    double b_cheby = 1;  // The division by K was performed before

    // double a_cheby = -K; double b_cheby = K; // Andreea: do this separately to not lose precision when scaling with everything at once
    // auto BminusAdotS2 = BminusAdotS;

    // std::cout << "BminusAdotS2 level and depth: " << BminusAdotS2->GetLevel() << ", " << BminusAdotS2->GetNoiseScaleDeg() << std::endl;

    auto BminusAdotS3 = ccCKKS->EvalChebyshevSeries(BminusAdotS2, coefficientsFHEW, a_cheby, b_cheby);

    // std::cout << "BminusAdotS3 after Cheby level and depth: " << BminusAdotS3->GetLevel() << ", " << BminusAdotS3->GetNoiseScaleDeg() << std::endl;

    // if (cryptoParamsCKKS->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
    if (cryptoParamsCKKS->GetScalingTechnique() != FIXEDMANUAL) {
        ccCKKS->GetScheme()->ModReduceInternalInPlace(BminusAdotS3, BASE_NUM_LEVELS_TO_DROP);
    }

    int32_t r = 3;
    for (int32_t j = 1; j < r + 1; j++) {
        BminusAdotS3  = ccCKKS->EvalMult(BminusAdotS3, BminusAdotS3);
        BminusAdotS3  = ccCKKS->EvalAdd(BminusAdotS3, BminusAdotS3);
        double scalar = 1.0 / std::pow((2.0 * Pi), std::pow(2.0, j - r));
        BminusAdotS3  = ccCKKS->EvalSub(BminusAdotS3, scalar);
        if (cryptoParamsCKKS->GetScalingTechnique() == FIXEDMANUAL) {
            // BminusAdotS3 = ccCKKS->Compress(BminusAdotS3, init_level - BminusAdotS3->GetLevel() - 1);
            ccCKKS->ModReduceInPlace(BminusAdotS3);
        }
        else {
            ccCKKS->GetScheme()->ModReduceInternalInPlace(BminusAdotS3, BASE_NUM_LEVELS_TO_DROP);
        }
    }

    // std::cout << "BminusAdotS3 after double angle level and depth: " << BminusAdotS3->GetLevel() << ", " << BminusAdotS3->GetNoiseScaleDeg() << std::endl;

    /* Need to be careful how to set this condition when the ciphertexts come from
     * scheme switching.
     * For p <= 4 and when we only encrypt bits, we don't need sin(2pi*x)/2pi to approximate x,
     * we can directly use sin(0) for 0 and sin(pi/2) for 1.
     * We need to be careful with the meaning of the variables. Here pmax is actually the
     * plaintext modulus, not the maximum value of the messages that we consider. For
     * plaintext modulus > 4, even if we only care about encrypting bits, 2pi is not
     * the correct post-scaling factor.
     * Moreover, we have to account for the different encoding the end ciphertext should have
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

    // if (isSparse) { // Andreea: do this if we don't rotate, but this does not fully turn into a sparse packing
    //     postScale *= N / (2*slots);
    //     postBias *= N / (2*slots);
    // }
    std::vector<std::complex<double>> postScaleVec(N / 2, 0);
    std::vector<std::complex<double>> postBiasVec(N / 2, 0);

    for (size_t i = 0; i < numValues; i++) {
        postScaleVec[i] = std::complex<double>(postScale, 0);
        postBiasVec[i]  = std::complex<double>(postBias, 0);
    }

    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParamsCKKS->GetElementParams());

    uint32_t towersToDrop = 0;
    if (cryptoParamsCKKS->GetScalingTechnique() == FIXEDMANUAL) {
        towersToDrop = BminusAdotS3->GetLevel() + BminusAdotS3->GetNoiseScaleDeg() - 1;
    }
    else {
        towersToDrop = BminusAdotS3->GetLevel() + BminusAdotS3->GetNoiseScaleDeg() - 1;
    }
    // if (cryptoParamsCKKS->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
    //     towersToDrop += 1; // Andreea: sometimes this segfaults
    // }
    for (uint32_t i = 0; i < towersToDrop; i++)
        elementParams.PopLastParam();

    // std::cout << "towers to drop for end of CKKS to FHEW = " << towersToDrop << std::endl;

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
    // std::cout << "postScalePlain level and depth: " << postScalePlain->GetLevel() << ", " << postScalePlain->GetNoiseScaleDeg() << std::endl;

    auto BminusAdotSres = ccCKKS->EvalMult(BminusAdotS3, postScalePlain);

    // std::cout << "BminusAdotSres level and depth: " << BminusAdotSres->GetLevel() << ", " << BminusAdotSres->GetNoiseScaleDeg() << std::endl;

    // Add the plaintext for bias at the correct level and depth
    auto postBiasPlain = ccCKKS->MakeCKKSPackedPlaintext(postBiasVec, BminusAdotSres->GetNoiseScaleDeg(),
                                                         BminusAdotSres->GetLevel(), nullptr, N / 2);

    // std::cout << "postBiasPlain level and depth: " << postBiasPlain->GetLevel() << ", " << postBiasPlain->GetNoiseScaleDeg() << std::endl;

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

    // std::cout << "Ciphertext at end of FHEWtoCKKS level and depth: " << BminusAdotSres->GetLevel() << ", " << BminusAdotSres->GetNoiseScaleDeg() << std::endl;

    // return BminusAdotS;
    // return BminusAdotS2;
    // return BminusAdotS3;
    return BminusAdotSres;
}

std::pair<BinFHEContext, LWEPrivateKey> FHECKKSRNSSS::EvalSchemeSwitchingSetup(
    const CryptoContextImpl<DCRTPoly>& ccCKKS, SecurityLevel sl, bool arbFunc, uint32_t logQ, bool dynamic,
    uint32_t numSlotsCKKS) {
    auto FHEWcc = EvalCKKStoFHEWSetup(ccCKKS, sl, arbFunc, logQ, dynamic, numSlotsCKKS);
    // m_ccCKKS    = std::make_shared<CryptoContextImpl<DCRTPoly>>(ccCKKS);
    // std::cout << "EvalCKKStoFHEWSetup sets modulus_LWE to be " << m_modulus_LWE << std::endl;
    // std::cout << "m_ccLWE.GetParams()->GetLWEParams()->Getq() = " << m_ccLWE.GetParams()->GetLWEParams()->Getq() << std::endl;

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ccCKKS.GetCryptoParameters());

    // Get the last ciphertext modulus; this assumes the LWE mod switch will be performed on the ciphertext at the last level
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ                                  = elementParams.GetParams();
    m_modulus_CKKS_initial                        = paramsQ[0]->GetModulus().ConvertToInt();

    return FHEWcc;
}

std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> FHECKKSRNSSS::EvalSchemeSwitchingKeyGen(
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
    // m_ctxtKS         = ccKS->Compress(m_ctxtKS, 1);

    // Compute switching key between RLWE and LWE via the intermediate cryptocontext, keep it in RLWE form
    m_CKKStoFHEWswk = switchingKeyGenRLWEcc(keys2.secretKey, privateKey, lwesk);

    // // Andreea: only for debugging, remove later
    // auto swPair = switchingKeyGenRLWEcc(keys2.secretKey, privateKey, lwesk);
    // // auto swPair     = switchingKeyGen(keys2.secretKey, privateKey); // Andreea: debugging for Q2
    // m_CKKStoFHEWswk = swPair.first;
    // m_RLWELWEsk     = swPair.second;
    // m_CKKSsk        = privateKey;
    // m_CKKSskKS      = keys2.secretKey;

    // // Andreea: old insecure version
    // // Compute switching key between RLWE and LWE, keep it in RLWE form
    // // m_CKKStoFHEWswk = switchingKeyGenRLWE(privateKey, lwesk);

    // // Andreea: only for debugging, remove later
    // auto swPair     = switchingKeyGenRLWE(privateKey, lwesk);
    // m_CKKStoFHEWswk = swPair.first;
    // m_RLWELWEsk     = swPair.second;
    // m_CKKSsk        = privateKey;

    // Generate FHEW to CKKS switching key, i.e., CKKS encryption of FHEW secret key
    /*
    // Get signal 11 when using this to create CKKS plaintext for secret key
    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ccCKKS->GetCryptoParameters());

    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParamsCKKS->GetElementParams());

    std::cout << " elementParams.GetParams().size() = " <<  elementParams.GetParams().size() << std::endl;

    auto paramsQ = elementParams.GetParams();
    usint sizeQ = paramsQ.size();
    auto paramsP = cryptoParams->GetParamsP()->GetParams();
    usint sizeP = paramsP.size();

    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);
    for (size_t i = 0; i < sizeQ; i++) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i] = paramsQ[i]->GetRootOfUnity();
    }

    for (size_t i = 0; i < sizeP; i++) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i] = paramsP[i]->GetRootOfUnity();
    }

    auto elementParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(M, moduli, roots);
    auto elementParamsPtr2 = std::dynamic_pointer_cast<typename DCRTPoly::Params>(elementParamsPtr);
*/

    auto skLWEElements = lwesk->GetElement();
    // std::vector<std::complex<double>> skLWEDouble(ringDim/2);
    std::vector<std::complex<double>> skLWEDouble(n);
    // #pragma omp parallel for
    for (uint32_t i = 0; i < n; i++) {
        auto tmp = skLWEElements[i].ConvertToDouble();
        if (tmp == lwesk->GetModulus().ConvertToInt() - 1)
            tmp = -1;
        skLWEDouble[i] = std::complex<double>(tmp, 0);
    }

    // m_FHEWtoCKKSswkDouble = skLWEDouble;

    // Check encoding and specify the number of slots, otherwise, if batchsize is set and is smaller, it will throw an error.
    // Check encoding and specify the number of slots, otherwise, if batchsize is set and is smaller, it will throw an error.
    Plaintext skLWEPlainswk;
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        skLWEPlainswk = ccCKKS->MakeCKKSPackedPlaintext(Fill(skLWEDouble, ringDim / 2), 1, BASE_NUM_LEVELS_TO_DROP,
                                                        nullptr, ringDim / 2);
    else
        skLWEPlainswk = ccCKKS->MakeCKKSPackedPlaintext(Fill(skLWEDouble, ringDim / 2), 1, 0, nullptr, ringDim / 2);
    // std::cout << "Encoded key: " << skLWEPlainswk << std::endl;

    // auto FHEWtoCKKSswk = ccCKKS->Encrypt(publicKey, skLWEPlainswk);
    // if(cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
    //     ccCKKS->GetScheme()->ModReduceInternalInPlace(FHEWtoCKKSswk, BASE_NUM_LEVELS_TO_DROP);
    m_FHEWtoCKKSswk = ccCKKS->Encrypt(publicKey, skLWEPlainswk);
    // std::cout << "m_swkkey level and depth: " << m_FHEWtoCKKSswk->GetLevel() << ", " << m_FHEWtoCKKSswk->GetNoiseScaleDeg() << std::endl;

    // Compute automorphism keys
    /* CKKS to FHEW */
    if (dim1CF == 0)
        dim1CF = getRatioBSGS(static_cast<double>(slots));
    m_dim1CF = dim1CF;
    // std::cout << "dim1 for CKKS to FHEW: " << m_dim1CF << std::endl;
    m_LCF = LCF;

    // Compute indices for rotations for slotToCoeff transform
    std::vector<int32_t> indexRotationS2C = FindLTRotationIndicesSS(m_dim1CF, M, slots);
    indexRotationS2C.push_back(static_cast<int>(slots));

    // Compute indices for rotations for sparse packing
    for (uint32_t i = 1; i < ccCKKS->GetRingDimension() / 2; i *= 2) {
        indexRotationS2C.push_back(static_cast<int>(i));
        if (i <= slots)
            indexRotationS2C.push_back(-static_cast<int>(i));
    }

    /* FHEW to CKKS */
    if (dim1FC == 0)
        dim1FC = getRatioBSGS(static_cast<double>(n));  // This picks the optimized ratio for baby-step giant-step
    m_dim1FC = dim1FC;
    // std::cout << "dim1 for FHEW to CKKS: " << m_dim1FC << std::endl;
    m_LFC = LFC;

    // Compute indices for rotations for homomorphic decryption in CKKS
    std::vector<int32_t> indexRotationHomDec = FindLTRotationIndicesSS(m_dim1FC, M, n);
    // indexRotationHomDec.push_back(static_cast<int>(n));

    // Compute indices for rotations to bring back the final CKKS ciphertext encoding to slots
    for (uint32_t j = 1; j < ringDim / (2 * slots); j <<= 1) {
        indexRotationHomDec.push_back(j * slots);
    }

    // Combine the two indices lists
    indexRotationS2C.insert(indexRotationS2C.end(), indexRotationHomDec.begin(), indexRotationHomDec.end());

    /* Compute indices for Argmin if numValues != 0*/
    if (numValues > 0) {
        for (uint32_t i = 1; i < numValues; i <<= 1) {
            indexRotationS2C.push_back(static_cast<int>(numValues / (2 * i)));
            if (!alt) {
                indexRotationS2C.push_back(-static_cast<int>(numValues / (2 * i)));
                if (i > 1) {
                    for (uint32_t j = numValues / i; j < numValues; j <<= 1)
                        indexRotationS2C.push_back(-static_cast<int>(j));
                }
            }
        }
    }

    // Remove possible duplicates
    sort(indexRotationS2C.begin(), indexRotationS2C.end());
    indexRotationS2C.erase(unique(indexRotationS2C.begin(), indexRotationS2C.end()), indexRotationS2C.end());
    // std::cout << "Index rotation: " << indexRotationS2C << std::endl;

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
    // algo->EvalMultKeyGen(privateKey); // Andreea: this is not enough for transition from FHEW to CKKS
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

void FHECKKSRNSSS::EvalCompareSSPrecompute(const CryptoContextImpl<DCRTPoly>& ccCKKS, uint32_t pLWE, uint32_t initLevel,
                                           double scaleSign, bool unit) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ccCKKS.GetCryptoParameters());

    double scaleCF = 1.0;

    if (pLWE != 0) {
        // // Get the scaling factor of the ciphertext to switch from CKKS to FHEW
        // m_scFactorOuter = cryptoParams->GetScalingFactorReal(0);
        // if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        //     m_scFactorOuter = cryptoParams->GetScalingFactorReal(1);
        // std::cout << "EvalCompareSSPrecompute: m_scFactorOuter = " << m_scFactorOuter << std::endl;

        double scFactor = cryptoParams->GetScalingFactorReal(initLevel);
        if (unit)  // The messages are already scaled between 0 and 1, no need to divide by pLWE
            scaleCF = m_modulus_CKKS_initial / scFactor;
        else
            scaleCF = m_modulus_CKKS_initial / (scFactor * pLWE);
        // std::cout << "EvalCompareSSPrecompute: scFactor = " << scFactor << std::endl;
    }
    // Else perform no scaling; the implicit FHEW plaintext modulus will be m_modulus_CKKS_initial / scFactor

    m_plaintextFHEW = pLWE;
    scaleCF *= scaleSign;

    EvalCKKStoFHEWPrecompute(ccCKKS, scaleCF);
}

Ciphertext<DCRTPoly> FHECKKSRNSSS::EvalCompareSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext1,
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
            if (cryptoParams->GetScalingTechnique() != FIXEDMANUAL)
                OPENFHE_THROW(
                    not_available_error,
                    "This scaling was not tested for other scaling modes than FIXEDMANUAL.");  // Andreea: test it later
            cDiff = ccCKKS->EvalMult(cDiff, 1.0 / static_cast<double>(pLWE));
            cDiff = ccCKKS->Rescale(cDiff);
        }
    }

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (pLWE != 0) {
        // // Get the scaling factor of the ciphertext to switch from CKKS to FHEW
        m_scFactorOuter = cryptoParams->GetScalingFactorReal(0);
        // if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        //     m_scFactorOuter = cryptoParams->GetScalingFactorReal(1);
        // std::cout << "EvalCompareSchemeSwitching: m_scFactorOuter = " << m_scFactorOuter << std::endl;

        // std::cout << cDiff->GetLevel() << std::endl;
        // std::cout << "m_modulus_CKKS_initial = " << m_modulus_CKKS_initial << std::endl;

        double scFactor = cryptoParams->GetScalingFactorReal(cDiff->GetLevel());  // Andreea: test more
        if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
            scFactor = cryptoParams->GetScalingFactorReal(cDiff->GetLevel() + 1);

        // std::cout << "EvalCompareSchemeSwitching: scFactor = " << scFactor << std::endl;
        double scaleCF = 1.0;
        if (unit)  // The messages are already scaled between 0 and 1, no need to divide by pLWE
            scaleCF = m_modulus_CKKS_initial / scFactor;
        else
            scaleCF = m_modulus_CKKS_initial / (scFactor * pLWE);
        scaleCF *= scaleSign;
        // std::cout << scaleSign << std::endl;
        ccCKKS->EvalCKKStoFHEWPrecompute(scaleCF);
    }

    auto LWECiphertexts = EvalCKKStoFHEW(cDiff, numCtxts);

    // LWEPlaintext plainLWE;
    // std::cout << "\n Inside FHEW decryption with plaintext modulus " << m_plaintextFHEW << ": ";
    // for (uint32_t i = 0; i < LWECiphertexts.size(); ++i) {
    //     m_ccLWE.Decrypt(m_FHEWsk, LWECiphertexts[i], &plainLWE, m_plaintextFHEW);
    //     std::cout << plainLWE << " ";
    // }

    std::vector<LWECiphertext> cSigns(LWECiphertexts.size());
#pragma omp parallel for
    for (uint32_t i = 0; i < LWECiphertexts.size(); i++) {
        cSigns[i] = m_ccLWE.EvalSign(LWECiphertexts[i], true);
    }

    double scaleFC = 1.0 / cSigns[0]->GetModulus().ConvertToInt();

    return EvalFHEWtoCKKS(cSigns, scaleFC, numCtxts, numSlots, 4, -1.0, 1.0);
    // return ccCKKS->EvalFHEWtoCKKS(cSigns, scaleFC, numCtxts, numSlots, 4, -1.0, 1.0);
}

std::vector<Ciphertext<DCRTPoly>> FHECKKSRNSSS::EvalMinSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext,
                                                                       PublicKey<DCRTPoly> publicKey,
                                                                       uint32_t numValues, uint32_t numSlots,
                                                                       bool oneHot, uint32_t pLWE, double scaleSign) {
    auto cc                 = ciphertext->GetCryptoContext();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (pLWE != 0) {
        // // Get the scaling factor of the ciphertext to switch from CKKS to FHEW
        // m_scFactorOuter = cryptoParams->GetScalingFactorReal(0);
        // if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        //     m_scFactorOuter = cryptoParams->GetScalingFactorReal(1);

        double scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel());  // Andreea: test more
        if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
            scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel() + 1);
        double scaleCF = m_modulus_CKKS_initial / (scFactor * pLWE);
        scaleCF *= scaleSign;
        cc->EvalCKKStoFHEWPrecompute(scaleCF);
    }

    uint32_t towersToDrop = 12;  // Andreea: how many levels are consumed in the EvalFHEWtoCKKS
    uint32_t slots        = (numSlots == 0) ? m_numSlotsCKKS : numSlots;

    Plaintext pInd;
    if (oneHot) {
        std::vector<std::complex<double>> ind(numValues, 1.0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    else {
        std::vector<std::complex<double>> ind(numValues);
        std::iota(ind.begin(), ind.end(), 1);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr, slots);
    }
    Ciphertext<DCRTPoly> cInd          = cc->Encrypt(publicKey, pInd);
    Ciphertext<DCRTPoly> newCiphertext = ciphertext->Clone();

    for (uint32_t M = 1; M < numValues; M <<= 1) {
        // std::cout << "M = " << M << std::endl;

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
        double scale = 1.0 / LWESign[0]->GetModulus().ConvertToInt();
        auto cSelect = cc->EvalFHEWtoCKKS(LWESign, scale, numValues / (2 * M), numSlots, 4, -1.0, 1.0);

        // std::cout << "Ciphertext level and depth at the end of scheme switching: " << cSelect->GetLevel() << ", " << cSelect->GetNoiseScaleDeg() << std::endl;

        std::vector<std::complex<double>> ones(numValues / (2 * M), 1.0);
        // Plaintext ptxtOnes =
        // cc->MakeCKKSPackedPlaintext(ones);  // the encoding specified when creating the cryptocontext
        Plaintext ptxtOnes = cc->MakeCKKSPackedPlaintext(ones, 1, 0, nullptr, slots);
        cSelect            = cc->EvalAdd(cSelect,
                                         cc->EvalAtIndex(cc->EvalSub(ptxtOnes, cSelect), -static_cast<int>(numValues / (2 * M))));

        auto cExpandSelect = cSelect;
        if (M > 1) {
            for (uint32_t j = numValues / M; j < numValues; j <<= 1)
                cExpandSelect = cc->EvalAdd(cExpandSelect, cc->EvalAtIndex(cExpandSelect, -static_cast<int>(j)));
        }

        // Update the ciphertext of values and the indicator // Andreea: if we lose too much precision, do the multiplication before the rotations?
        newCiphertext = cc->EvalMult(newCiphertext, cExpandSelect);
        newCiphertext = cc->EvalAdd(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));
        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(newCiphertext);
        }

        // std::cout << "Ciphertext level and depth before next iteration: " << newCiphertext->GetLevel() << ", " << newCiphertext->GetNoiseScaleDeg() << std::endl;

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

std::vector<Ciphertext<DCRTPoly>> FHECKKSRNSSS::EvalMinSchemeSwitchingAlt(ConstCiphertext<DCRTPoly> ciphertext,
                                                                          PublicKey<DCRTPoly> publicKey,
                                                                          uint32_t numValues, uint32_t numSlots,
                                                                          bool oneHot, uint32_t pLWE,
                                                                          double scaleSign) {
    auto cc                 = ciphertext->GetCryptoContext();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (pLWE != 0) {
        // // Get the scaling factor of the ciphertext to switch from CKKS to FHEW
        // m_scFactorOuter = cryptoParams->GetScalingFactorReal(0);
        // if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        //     m_scFactorOuter = cryptoParams->GetScalingFactorReal(1);

        double scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel());  // Andreea: test more
        if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
            scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel() + 1);
        double scaleCF = m_modulus_CKKS_initial / (scFactor * pLWE);
        scaleCF *= scaleSign;
        cc->EvalCKKStoFHEWPrecompute(scaleCF);
    }

    uint32_t towersToDrop =
        12;  // Andreea: How many levels are consumed in the EvalFHEWtoCKKS, for binary FHEW output. Check for FLEXIBLEAUTOEXT
    uint32_t slots = (numSlots == 0) ? m_numSlotsCKKS : numSlots;

    Plaintext pInd;
    if (oneHot) {
        std::vector<std::complex<double>> ind(numValues, 1.0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr,
                                           slots);  // the encoding specified when creating the cryptocontext
    }
    else {
        std::vector<std::complex<double>> ind(numValues);
        std::iota(ind.begin(), ind.end(), 1);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr,
                                           slots);  // the encoding specified when creating the cryptocontext
    }
    Ciphertext<DCRTPoly> cInd          = cc->Encrypt(publicKey, pInd);
    Ciphertext<DCRTPoly> newCiphertext = ciphertext->Clone();

    for (uint32_t M = 1; M < numValues; M <<= 1) {
        // std::cout << "M = " << M << std::endl;

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
        double scale       = 1.0 / LWESign[0]->GetModulus().ConvertToInt();
        auto cExpandSelect = cc->EvalFHEWtoCKKS(LWESign, scale, numValues, numSlots, 4, -1.0, 1.0);

        // std::cout << "Ciphertext level and depth at the end of scheme switching: " << cExpandSelect->GetLevel() << ", " << cExpandSelect->GetNoiseScaleDeg() << std::endl;

        // Update the ciphertext of values and the indicator // Andreea: if we lose too much precision, do the multiplication before the rotations?
        newCiphertext = cc->EvalMult(newCiphertext, cExpandSelect);
        newCiphertext = cc->EvalAdd(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));

        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(newCiphertext);
        }
        // std::cout << "Ciphertext level and depth before next iteration: " << newCiphertext->GetLevel() << ", " << newCiphertext->GetNoiseScaleDeg() << std::endl;

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

std::vector<Ciphertext<DCRTPoly>> FHECKKSRNSSS::EvalMaxSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext,
                                                                       PublicKey<DCRTPoly> publicKey,
                                                                       uint32_t numValues, uint32_t numSlots,
                                                                       bool oneHot, uint32_t pLWE, double scaleSign) {
    auto cc                 = ciphertext->GetCryptoContext();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (pLWE != 0) {
        // // Get the scaling factor of the ciphertext to switch from CKKS to FHEW
        // m_scFactorOuter = cryptoParams->GetScalingFactorReal(0);
        // if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        //     m_scFactorOuter = cryptoParams->GetScalingFactorReal(1);

        double scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel());  // Andreea: test more
        if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
            scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel() + 1);
        double scaleCF = m_modulus_CKKS_initial / (scFactor * pLWE);
        scaleCF *= scaleSign;
        cc->EvalCKKStoFHEWPrecompute(scaleCF);
    }

    uint32_t towersToDrop =
        12;  // Andreea: How many levels are consumed in the EvalFHEWtoCKKS, for binary FHEW output. Check for FLEXIBLEAUTOEXT
    uint32_t slots = (numSlots == 0) ? m_numSlotsCKKS : numSlots;

    Plaintext pInd;
    if (oneHot) {
        std::vector<std::complex<double>> ind(numValues, 1.0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr,
                                           slots);  // the encoding specified when creating the cryptocontext
    }
    else {
        std::vector<std::complex<double>> ind(numValues);
        std::iota(ind.begin(), ind.end(), 1);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr,
                                           slots);  // the encoding specified when creating the cryptocontext
    }
    Ciphertext<DCRTPoly> cInd          = cc->Encrypt(publicKey, pInd);
    Ciphertext<DCRTPoly> newCiphertext = ciphertext->Clone();

    for (uint32_t M = 1; M < numValues; M <<= 1) {
        // std::cout << "M = " << M << std::endl;

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
        double scale = 1.0 / LWESign[0]->GetModulus().ConvertToInt();
        auto cSelect = cc->EvalFHEWtoCKKS(LWESign, scale, numValues / (2 * M), numSlots, 4, -1.0, 1.0);

        // std::cout << "Ciphertext level and depth at the end of scheme switching: " << cSelect->GetLevel() << ", " << cSelect->GetNoiseScaleDeg() << std::endl;

        std::vector<std::complex<double>> ones(numValues / (2 * M), 1.0);
        // Plaintext ptxtOnes =
        // cc->MakeCKKSPackedPlaintext(ones);  // the encoding specified when creating the cryptocontext
        Plaintext ptxtOnes = cc->MakeCKKSPackedPlaintext(ones, 1, 0, nullptr, slots);
        cSelect            = cc->EvalAdd(cc->EvalSub(ptxtOnes, cSelect),
                                         cc->EvalAtIndex(cSelect, -static_cast<int>(numValues / (2 * M))));

        auto cExpandSelect = cSelect;
        if (M > 1) {
            for (uint32_t j = numValues / M; j < numValues; j <<= 1)
                cExpandSelect = cc->EvalAdd(cExpandSelect, cc->EvalAtIndex(cExpandSelect, -static_cast<int>(j)));
        }

        // Update the ciphertext of values and the indicator // Andreea: if we lose too much precision, do the multiplication before the rotations?
        newCiphertext = cc->EvalMult(newCiphertext, cExpandSelect);
        newCiphertext = cc->EvalAdd(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));

        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(newCiphertext);
        }
        // std::cout << "Ciphertext level and depth before next iteration: " << newCiphertext->GetLevel() << ", " << newCiphertext->GetNoiseScaleDeg() << std::endl;

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

std::vector<Ciphertext<DCRTPoly>> FHECKKSRNSSS::EvalMaxSchemeSwitchingAlt(ConstCiphertext<DCRTPoly> ciphertext,
                                                                          PublicKey<DCRTPoly> publicKey,
                                                                          uint32_t numValues, uint32_t numSlots,
                                                                          bool oneHot, uint32_t pLWE,
                                                                          double scaleSign) {
    auto cc                 = ciphertext->GetCryptoContext();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    // The precomputation has already been performed, but if it is scaled differently than desired, recompute it
    if (pLWE != 0) {
        // // Get the scaling factor of the ciphertext to switch from CKKS to FHEW
        // m_scFactorOuter = cryptoParams->GetScalingFactorReal(0);
        // if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        //     m_scFactorOuter = cryptoParams->GetScalingFactorReal(1);

        double scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel());  // Andreea: test more
        if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
            scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel() + 1);
        double scaleCF = m_modulus_CKKS_initial / (scFactor * pLWE);
        scaleCF *= scaleSign;
        cc->EvalCKKStoFHEWPrecompute(scaleCF);
    }

    uint32_t towersToDrop =
        12;  // Andreea: How many levels are consumed in the EvalFHEWtoCKKS, for binary FHEW output. Check for FLEXIBLEAUTOEXT
    uint32_t slots = (numSlots == 0) ? m_numSlotsCKKS : numSlots;

    Plaintext pInd;
    if (oneHot) {
        std::vector<std::complex<double>> ind(numValues, 1.0);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr,
                                           slots);  // the encoding specified when creating the cryptocontext
    }
    else {
        std::vector<std::complex<double>> ind(numValues);
        std::iota(ind.begin(), ind.end(), 1);
        pInd = cc->MakeCKKSPackedPlaintext(ind, 1, towersToDrop, nullptr,
                                           slots);  // the encoding specified when creating the cryptocontext
    }
    Ciphertext<DCRTPoly> cInd          = cc->Encrypt(publicKey, pInd);
    Ciphertext<DCRTPoly> newCiphertext = ciphertext->Clone();

    for (uint32_t M = 1; M < numValues; M <<= 1) {
        // std::cout << "M = " << M << std::endl;

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
        double scale       = 1.0 / LWESign[0]->GetModulus().ConvertToInt();
        auto cExpandSelect = cc->EvalFHEWtoCKKS(LWESign, scale, numValues, numSlots, 4, -1.0, 1.0);

        // std::cout << "Ciphertext level and depth at the end of scheme switching: " << cExpandSelect->GetLevel() << ", " << cExpandSelect->GetNoiseScaleDeg() << std::endl;

        // Update the ciphertext of values and the indicator // Andreea: if we lose too much precision, do the multiplication before the rotations?
        newCiphertext = cc->EvalMult(newCiphertext, cExpandSelect);
        newCiphertext = cc->EvalAdd(newCiphertext, cc->EvalAtIndex(newCiphertext, numValues / (2 * M)));

        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            cc->ModReduceInPlace(newCiphertext);
        }
        // std::cout << "Ciphertext level and depth before next iteration: " << newCiphertext->GetLevel() << ", " << newCiphertext->GetNoiseScaleDeg() << std::endl;

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
