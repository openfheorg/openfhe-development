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
Ultilities for AAHE circuits
 */

#include "circuit-utils.h"

namespace lbcrypto {

int count_lines(const std::string& s) {
    return std::accumulate(s.cbegin(), s.cend(), 1, [](int prev, char c) { return c != '\n' ? prev : prev + 1; });
}

LatticeParamsCircuit EstimateCircuitBFV(std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams, size_t dcrtBits,
                                        uint32_t nCustom, const std::string& circuit) {
    const auto cryptoParamsBFVRNS = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoParams);

    EncryptionTechnique encTech = cryptoParamsBFVRNS->GetEncryptionTechnique();

    double sigma           = cryptoParamsBFVRNS->GetDistributionParameter();
    double alpha           = cryptoParamsBFVRNS->GetAssuranceMeasure();
    double p               = static_cast<double>(cryptoParamsBFVRNS->GetPlaintextModulus());
    SecurityLevel stdLevel = cryptoParamsBFVRNS->GetStdLevel();

    // Bound of the Gaussian error polynomial
    double Berr = sigma * std::sqrt(alpha);

    // Bound of the key polynomial
    double Bkey = 0;

    DistributionType distType;

    uint32_t thresholdParties = cryptoParamsBFVRNS->GetThresholdNumOfParties();
    // supports both discrete Gaussian (GAUSSIAN) and ternary uniform distribution
    // (UNIFORM_TERNARY) cases
    if (cryptoParamsBFVRNS->GetSecretKeyDist() == GAUSSIAN) {
        Bkey     = std::sqrt(thresholdParties) * Berr;
        distType = HEStd_error;
    }
    else {
        // Bkey set to thresholdParties * 1 for ternary distribution
        Bkey     = thresholdParties;
        distType = HEStd_ternary;
    }

    // expansion factor delta
    auto delta = [](uint32_t n) -> double {
        return (2. * std::sqrt(n));
    };

    // norm of fresh ciphertext polynomial (for EXTENDED the noise is reduced to modulus switching noise)
    auto Vnorm = [&](uint32_t n) -> double {
        if (encTech == EXTENDED)
            return (1. + delta(n) * Bkey) / 2.;
        else
            return Berr * (1. + 2. * delta(n) * Bkey);
    };

    // GAUSSIAN security constraint
    auto nRLWE = [&](double logq) -> double {
        if (stdLevel == HEStd_NotSet) {
            return 0;
        }
        else {
            return static_cast<double>(
                StdLatticeParm::FindRingDim(distType, stdLevel, static_cast<uint32_t>(std::ceil(logq))));
        }
    };

    // initial values
    uint32_t n = (nCustom != 0) ? nCustom : 512;

    double logq = 0.;

    std::istringstream f(circuit);
    std::string line;

    size_t count = count_lines(circuit);

    std::cout << "count = " << count << std::endl;

    std::vector<Line> circuitLines(count);

    size_t counter = 0;
    std::string temp;

    double vFresh = Vnorm(n);

    while (counter < count) {
        Line circuitLine;
        std::getline(f, temp, '\t');
        circuitLine.id = std::stoi(temp);
        std::getline(f, circuitLine.operation, '\t');
        std::getline(f, temp, '\t');
        circuitLine.low = std::stoi(temp);
        std::getline(f, temp);
        circuitLine.high      = std::stoi(temp);
        circuitLines[counter] = circuitLine;

        if (circuitLine.operation == "input") {
            circuitLines[counter].noise = vFresh;
        }
        else {
            circuitLines[counter].noise =
                circuitLines[circuitLine.low - 1].noise + circuitLines[circuitLine.high - 1].noise + 1;
        }
        counter++;
    }

    double maximumNoise = 0.0;
    counter             = 0;
    while (counter < count) {
        if (circuitLines[counter].noise > maximumNoise) {
            maximumNoise = circuitLines[counter].noise;
        }
        counter++;
    }

    // Correctness constraint
    auto logqBFV = [&](uint32_t n) -> double {
        return std::log2(p * (4 * maximumNoise + p));
    };

    // initial value
    logq = logqBFV(n);

    while (nRLWE(logq) > n) {
        n    = 2 * n;
        logq = logqBFV(n);
    }

    // this code updates n and q to account for the discrete size of CRT moduli
    // = dcrtBits
    int32_t k = static_cast<int32_t>(std::ceil(std::ceil(logq) / dcrtBits));

    double logqCeil = k * dcrtBits;

    while (nRLWE(logqCeil) > n) {
        n        = 2 * n;
        logq     = logqBFV(n);
        k        = static_cast<int32_t>(std::ceil(std::ceil(logq) / dcrtBits));
        logqCeil = k * dcrtBits;
    }

    return {logq, n};
}

}  // namespace lbcrypto
