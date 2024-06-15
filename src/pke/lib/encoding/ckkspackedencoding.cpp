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

#include "encoding/ckkspackedencoding.h"

#include "lattice/lat-hal.h"

#include "math/hal/basicint.h"
#include "math/dftransform.h"

#include "utils/exception.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

#include <complex>
#include <cmath>
#include <vector>

namespace lbcrypto {

std::vector<std::complex<double>> Conjugate(const std::vector<std::complex<double>>& vec) {
    uint32_t n = vec.size();
    std::vector<std::complex<double>> result(n);
    for (size_t i = 1; i < n; i++) {
        result[i] = {-vec[n - i].imag(), -vec[n - i].real()};
    }
    result[0] = {vec[0].real(), -vec[0].imag()};
    return result;
}

// Estimate standard deviation using the imaginary part of decoded vector z
// Compute m(X) - m(1/X) as a proxy for z - Conj(z) = 2*Im(z)
// vec is m(X) corresponding to z
// conjugate is m(1/X) corresponding to Conj(z)

double StdDev(const std::vector<std::complex<double>>& vec, const std::vector<std::complex<double>>& conjugate) {
    uint32_t slots = vec.size();
    if (1 == slots) {
        return vec[0].imag();
    }
    // ring dimension
    uint32_t dslots = slots * 2;

    // extract the complex part using identity z - Conj(z) == 2*Im(z)
    // here we actually compute m(X) - m(1/X) corresponding to 2*Im(z).
    // we only need first Nh/2 + 1 components of the imaginary part
    // as the remaining Nh/2 - 1 components have a symmetry
    // w.r.t. components from 1 to Nh/2 - 1
    std::vector<std::complex<double>> complexValues(slots / 2 + 1);
    for (size_t i = 0; i < slots / 2 + 1; ++i) {
        complexValues[i] = vec[i] - conjugate[i];
    }

    // Calculate the mean
    auto mean_func = [](double accumulator, const std::complex<double>& val) {
        return accumulator + (val.real() + val.imag());
    };

    // use the symmetry condition
    double mean = 2 * std::accumulate(complexValues.begin() + 1, complexValues.begin() + slots / 2, 0.0, mean_func);
    // and then add values at indices 0 and Nh/2
    mean += complexValues[0].imag();
    mean += 2 * complexValues[slots / 2].real();
    // exclude the real part at index 0 as it is always 0
    mean /= static_cast<double>(dslots) - 1.0;

    // Now calculate the variance
    auto variance_func = [&mean](double accumulator, const std::complex<double>& val) {
        return accumulator + (val.real() - mean) * (val.real() - mean) + (val.imag() - mean) * (val.imag() - mean);
    };

    // use the symmetry condition
    double variance = 2 * accumulate(complexValues.begin() + 1, complexValues.begin() + slots / 2, 0.0, variance_func);
    // and then add values at indices 0 and Nh/2
    variance += (complexValues[0].imag() - mean) * (complexValues[0].imag() - mean);
    variance += 2 * (complexValues[slots / 2].real() - mean) * (complexValues[slots / 2].real() - mean);
    // exclude the real part at index 0 as it is always 0
    variance /= static_cast<double>(dslots) - 2.0;
    // scale down by 2 as we have worked with 2*Im(z) up to this point
    double stddev = 0.5 * std::sqrt(variance);

    return stddev;
}

std::vector<DCRTPoly::Integer> CKKSPackedEncoding::CRTMult(const std::vector<DCRTPoly::Integer>& a,
                                                           const std::vector<DCRTPoly::Integer>& b,
                                                           const std::vector<DCRTPoly::Integer>& mods) {
    std::vector<DCRTPoly::Integer> result(mods.size());

    for (usint i = 0; i < a.size(); i++) {
        result[i] = a[i].ModMulFast(b[i], mods[i]);
    }

    return result;
}

#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
bool CKKSPackedEncoding::Encode() {
    if (this->isEncoded)
        return true;

    uint32_t ringDim                          = GetElementRingDimension();
    usint slots                               = this->GetSlots();
    std::vector<std::complex<double>> inverse = this->GetCKKSPackedValue();
    if (slots < inverse.size()) {
        std::string errMsg = std::string("The number of slots [") + std::to_string(slots) +
                             "] is less than the size of data [" + std::to_string(inverse.size()) + "]";
        OPENFHE_THROW(errMsg);
    }

    // clears all imaginary values as CKKS for complex numbers
    for (size_t i = 0; i < inverse.size(); i++)
        inverse[i].imag(0.0);

    inverse.resize(slots);

    if (this->typeFlag == IsDCRTPoly) {
        DiscreteFourierTransform::FFTSpecialInv(inverse, ringDim * 2);
        uint64_t pBits     = encodingParams->GetPlaintextModulus();
        uint32_t precision = 52;

        double powP      = std::pow(2, precision);
        int32_t pCurrent = pBits - precision;

        // the idea is to break down real and imaginary parts
        // expressed as input_mantissa * 2^input_exponent
        // into (input_mantissa * 2^52) * 2^(p - 52 + input_exponent)
        // to preserve 52-bit precision of doubles
        // when converting to 128-bit numbers
        std::vector<int128_t> temp(2 * slots);
        for (size_t i = 0; i < slots; ++i) {
            // Check for possible overflow in llround function
            int32_t n1 = 0;
            // extract the mantissa of real part and multiply it by 2^52
            double dre = static_cast<double>(std::frexp(inverse[i].real(), &n1) * powP);
            int32_t n2 = 0;
            // extract the mantissa of imaginary part and multiply it by 2^52
            double dim = static_cast<double>(std::frexp(inverse[i].imag(), &n2) * powP);
            if (is128BitOverflow(dre) || is128BitOverflow(dim)) {
                OPENFHE_THROW("Overflow, try to decrease scaling factor");
            }

            int64_t re64       = std::llround(dre);
            int32_t pRemaining = pCurrent + n1;
            int128_t re        = 0;
            if (pRemaining < 0) {
                re = re64 >> (-pRemaining);
            }
            else {
                int128_t pPowRemaining = ((int128_t)1) << pRemaining;
                re                     = pPowRemaining * re64;
            }

            int64_t im64 = std::llround(dim);
            pRemaining   = pCurrent + n2;
            int128_t im  = 0;
            if (pRemaining < 0) {
                im = im64 >> (-pRemaining);
            }
            else {
                int128_t pPowRemaining = ((int64_t)1) << pRemaining;
                im                     = pPowRemaining * im64;
            }

            temp[i]         = (re < 0) ? Max128BitValue() + re : re;
            temp[i + slots] = (im < 0) ? Max128BitValue() + im : im;

            if (is128BitOverflow(temp[i]) || is128BitOverflow(temp[i + slots])) {
                OPENFHE_THROW("Overflow, try to decrease scaling factor");
            }
        }

        const std::shared_ptr<ILDCRTParams<BigInteger>> params           = this->encodedVectorDCRT.GetParams();
        const std::vector<std::shared_ptr<ILNativeParams>>& nativeParams = params->GetParams();

        for (size_t i = 0; i < nativeParams.size(); i++) {
            NativeVector nativeVec(ringDim, nativeParams[i]->GetModulus());
            FitToNativeVector(temp, Max128BitValue(), &nativeVec);
            NativePoly element = this->GetElement<DCRTPoly>().GetElementAtIndex(i);
            element.SetValues(nativeVec, Format::COEFFICIENT);  // output was in coefficient format
            this->encodedVectorDCRT.SetElementAtIndex(i, element);
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
            this->encodedVectorDCRT = this->encodedVectorDCRT.Times(currPowP);
        }

        this->GetElement<DCRTPoly>().SetFormat(Format::EVALUATION);

        scalingFactor = pow(scalingFactor, noiseScaleDeg);
    }
    else {
        OPENFHE_THROW("Only DCRTPoly is supported for CKKS.");
    }

    this->isEncoded = true;
    return true;
}
#else  // NATIVEINT == 64
bool CKKSPackedEncoding::Encode() {
    if (this->isEncoded)
        return true;
    usint ringDim                             = GetElementRingDimension();
    usint slots                               = this->GetSlots();
    std::vector<std::complex<double>> inverse = this->GetCKKSPackedValue();
    if (slots < inverse.size()) {
        std::string errMsg = std::string("The number of slots [") + std::to_string(slots) +
                             "] is less than the size of data [" + std::to_string(inverse.size()) + "]";
        OPENFHE_THROW(errMsg);
    }

    // clears all imaginary values as CKKS for complex numbers
    for (size_t i = 0; i < inverse.size(); i++)
        inverse[i].imag(0.0);

    inverse.resize(slots);

    if (this->typeFlag == IsDCRTPoly) {
        DiscreteFourierTransform::FFTSpecialInv(inverse, ringDim * 2);
        double powP = scalingFactor;

        // Compute approxFactor, a value to scale down by, in case the value exceeds a 64-bit integer.
        int32_t MAX_BITS_IN_WORD = LargeScalingFactorConstants::MAX_BITS_IN_WORD;

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
            OPENFHE_THROW("Too small scaling factor");
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
                // IFFT formula:
                // x[n] = (1/N) * \Sum^(N-1)_(k=0) X[k] * exp( j*2*pi*n*k/N )
                // n is i
                // k is idx below
                // N is inverse.size()
                //
                // In the following, we switch to original data domain,
                // and we identify the component that has the maximum
                // contribution to the values in the iFFT domain. We do
                // this to report it to the user, so they can identify
                // large inputs.

                DiscreteFourierTransform::FFTSpecial(inverse, ringDim * 2);

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
                buffer << "- Max imaginary part contribution from input[" << imagMaxIdx << "]: " << imagMax
                       << std::endl;
                buffer << "Scaling factor is " << ceil(log2(powP)) << " bits " << std::endl;
                buffer << "Scaled input is " << scaledInputSize << " bits " << std::endl;
                OPENFHE_THROW(buffer.str());
            }

            int64_t re = std::llround(dre);
            int64_t im = std::llround(dim);

            temp[i]         = (re < 0) ? Max64BitValue() + re : re;
            temp[i + slots] = (im < 0) ? Max64BitValue() + im : im;
        }
        const std::shared_ptr<ILDCRTParams<BigInteger>> params           = this->encodedVectorDCRT.GetParams();
        const std::vector<std::shared_ptr<ILNativeParams>>& nativeParams = params->GetParams();

        for (size_t i = 0; i < nativeParams.size(); i++) {
            NativeVector nativeVec(ringDim, nativeParams[i]->GetModulus());
            FitToNativeVector(temp, Max64BitValue(), &nativeVec);
            NativePoly element = this->GetElement<DCRTPoly>().GetElementAtIndex(i);
            element.SetValues(nativeVec, Format::COEFFICIENT);  // output was in coefficient format
            this->encodedVectorDCRT.SetElementAtIndex(i, element);
        }

        usint numTowers = nativeParams.size();
        std::vector<DCRTPoly::Integer> moduli(numTowers);
        for (usint i = 0; i < numTowers; i++) {
            moduli[i] = nativeParams[i]->GetModulus();
        }

        DCRTPoly::Integer intPowP(static_cast<uint64_t>(std::llround(powP)));
        std::vector<DCRTPoly::Integer> crtPowP(numTowers, intPowP);

        auto currPowP = crtPowP;

        // We want to scale temp by 2^(pd), and the loop starts from j=2
        // because temp is already scaled by 2^p in the re/im loop above,
        // and currPowP already is 2^p.
        for (size_t i = 2; i < noiseScaleDeg; i++) {
            currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
        }

        if (noiseScaleDeg > 1) {
            this->encodedVectorDCRT = this->encodedVectorDCRT.Times(currPowP);
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
                crtApprox = CRTMult(crtApprox, crtSF, moduli);
                logApprox -= logStep;
            }
            encodedVectorDCRT = encodedVectorDCRT.Times(crtApprox);
        }

        this->GetElement<DCRTPoly>().SetFormat(Format::EVALUATION);

        scalingFactor = pow(scalingFactor, noiseScaleDeg);
    }
    else {
        OPENFHE_THROW("Only DCRTPoly is supported for CKKS.");
    }

    this->isEncoded = true;
    return true;
}
#endif

bool CKKSPackedEncoding::Decode(size_t noiseScaleDeg, double scalingFactor, ScalingTechnique scalTech,
                                ExecutionMode executionMode) {
    double p       = encodingParams->GetPlaintextModulus();
    double powP    = 0.0;
    uint32_t Nh    = GetElementRingDimension() / 2;
    uint32_t slots = this->GetSlots();
    uint32_t gap   = Nh / slots;
    value.clear();
    std::vector<std::complex<double>> curValues(slots);

    if (this->typeFlag == IsNativePoly) {
        if (scalTech == FLEXIBLEAUTO || scalTech == FLEXIBLEAUTOEXT)
            powP = pow(scalingFactor, -1);
        else
            powP = pow(2, -p);

        const NativeInteger& q = this->GetElementModulus().ConvertToInt();
        NativeInteger qHalf    = q >> 1;

        for (size_t i = 0, idx = 0; i < slots; ++i, idx += gap) {
            std::complex<double> cur;

            if (GetElement<NativePoly>()[idx] > qHalf)
                cur.real(-((q - GetElement<NativePoly>()[idx])).ConvertToDouble());
            else
                cur.real((GetElement<NativePoly>()[idx]).ConvertToDouble());

            if (GetElement<NativePoly>()[idx + Nh] > qHalf)
                cur.imag(-((q - GetElement<NativePoly>()[idx + Nh])).ConvertToDouble());
            else
                cur.imag((GetElement<NativePoly>()[idx + Nh]).ConvertToDouble());

            curValues[i] = cur;
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

        const BigInteger& q = GetElementModulus();
        BigInteger qHalf    = q >> 1;

        for (size_t i = 0, idx = 0; i < slots; ++i, idx += gap) {
            std::complex<double> cur;

            if (GetElement<Poly>()[idx] > qHalf)
                cur.real(-((q - GetElement<Poly>()[idx])).ConvertToDouble() * scalingFactorPre);
            else
                cur.real((GetElement<Poly>()[idx]).ConvertToDouble() * scalingFactorPre);

            if (GetElement<Poly>()[idx + Nh] > qHalf)
                cur.imag(-((q - GetElement<Poly>()[idx + Nh])).ConvertToDouble() * scalingFactorPre);
            else
                cur.imag((GetElement<Poly>()[idx + Nh]).ConvertToDouble() * scalingFactorPre);

            curValues[i] = cur;
        }
    }

    // the code below adds a Gaussian noise to the decrypted result
    // to prevent key recovery attacks.
    // The standard deviation of the Gaussian noise is sqrt(M+1)*stddev,
    // where stddev is the standard deviation estimated using the imaginary
    // component and M is the extra factor that increases the number of decryption
    // attacks that is needed to average out the added Gaussian noise (after the
    // noise is removed, the attacker still has to find the secret key using the
    // real part only, which requires another attack). By default (M = 1), stddev
    // requires at least 128 decryption queries (in practice the values are
    // typically closer to 10,000 or so). Then M can be used to increase this
    // number further by M^2 (as desired for a given application). By default we
    // we set M to 1.

    // compute m(1/X) corresponding to Conj(z), where z is the decoded vector
    auto conjugate = Conjugate(curValues);

    // Estimate standard deviation from 1/2 (m(X) - m(1/x)),
    // which corresponds to Im(z)
    double stddev = StdDev(curValues, conjugate);

    double logstd = std::log2(stddev);

    if (executionMode == EXEC_NOISE_ESTIMATION) {
        m_logError = logstd;
    }
    else {
        // if stddev < sqrt{N}/8 (minimum approximation error that can be achieved)
        if (stddev < 0.125 * std::sqrt(GetElementRingDimension())) {
            stddev = 0.125 * std::sqrt(GetElementRingDimension());
        }

        // if stddev < sqrt{N}/4 (minimum approximation error that can be achieved)
        // if (stddev < 0.125 * std::sqrt(GetElementRingDimension())) {
        //   if (noiseScaleDeg <= 1) {
        //    OPENFHE_THROW(
        //                   "The decryption failed because the approximation error is
        //                   " "too small. Check the protocol used. ");
        //  } else {  // noiseScaleDeg > 1 and no rescaling operations have been applied yet
        //    stddev = 0.125 * std::sqrt(GetElementRingDimension());
        //  }
        // }

        //   If less than 5 bits of precision is observed
        if (logstd > p - 5.0)
            OPENFHE_THROW(
                "The decryption failed because the approximation error is "
                "too high. Check the parameters. ");

        // real values
        std::vector<std::complex<double>> realValues(slots);

        // CKKS_M_FACTOR is a compile-level parameter
        // set to 1 by default
        stddev = sqrt(CKKS_M_FACTOR + 1) * stddev;

        double scale = 0.5 * powP;

        // TODO temporary removed errors
        std::normal_distribution<> d(0, stddev);
        PRNG& g = PseudoRandomNumberGenerator::GetPRNG();
        // Alternative way to do Gaussian sampling
        // DiscreteGaussianGenerator dgg;

        // TODO we can sample Nh integers instead of 2*Nh
        // We would add sampling only for even indices of i.
        // This change should be done together with the one below.
        for (size_t i = 0; i < slots; ++i) {
            double real = scale * (curValues[i].real() + conjugate[i].real());
            // real += powP * dgg.GenerateIntegerKarney(0.0, stddev);
            real += powP * d(g);
            double imag = scale * (curValues[i].imag() + conjugate[i].imag());
            // imag += powP * dgg.GenerateIntegerKarney(0.0, stddev);
            imag += powP * d(g);
            realValues[i].real(real);
            realValues[i].imag(imag);
        }

        // TODO we can half the dimension for the FFT by decoding in
        // Z[X + 1/X]/(X^n + 1). This would change the complexity from n*logn to
        // roughly (n/2)*log(n/2). This change should be done together with the one
        // above.
        DiscreteFourierTransform::FFTSpecial(realValues, GetElementRingDimension() * 2);

        // clears all imaginary values for security reasons
        for (size_t i = 0; i < realValues.size(); ++i)
            realValues[i].imag(0.0);

        // sets an estimate of the approximation error
        m_logError = std::round(std::log2(stddev * std::sqrt(2 * slots)));

        value = realValues;
    }

    return true;
}

void CKKSPackedEncoding::Destroy() {}

void CKKSPackedEncoding::FitToNativeVector(const std::vector<int64_t>& vec, int64_t bigBound,
                                           NativeVector* nativeVec) const {
    NativeInteger bigValueHf(bigBound >> 1);
    NativeInteger modulus(nativeVec->GetModulus());
    NativeInteger diff = bigBound - modulus;
    uint32_t ringDim   = GetElementRingDimension();
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
void CKKSPackedEncoding::FitToNativeVector(const std::vector<int128_t>& vec, int128_t bigBound,
                                           NativeVector* nativeVec) const {
    NativeInteger bigValueHf((uint128_t)bigBound >> 1);
    NativeInteger modulus(nativeVec->GetModulus());
    NativeInteger diff = NativeInteger((uint128_t)bigBound) - modulus;
    uint32_t ringDim   = GetElementRingDimension();
    uint32_t dslots    = vec.size();
    uint32_t gap       = ringDim / dslots;
    for (usint i = 0; i < vec.size(); i++) {
        NativeInteger n((uint128_t)vec[i]);
        if (n > bigValueHf) {
            (*nativeVec)[gap * i] = n.ModSub(diff, modulus);
        }
        else {
            (*nativeVec)[gap * i] = n.Mod(modulus);
        }
    }
}
#endif

}  // namespace lbcrypto
