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
  Simple examples for CKKS without Bootstrapping, modified from simple-real-numbers.cpp provided by OpenFHE.
 */

#define PROFILE

#include "openfhe.h"

using namespace lbcrypto;
void BFVExample(uint32_t multDepth, SecurityLevel secLevel, uint32_t numDigits, uint32_t plaintextModulus,
                uint32_t scalingModSize);
void BGVExample(uint32_t multDepth, SecurityLevel secLevel, uint32_t numDigits, uint32_t plaintextModulus);

int main(int argc, char* argv[]) {
    // SetII
    std::cout << "====================BFV Parameters====================" << std::endl;

    std::cout << "--------------------COLUMN 1--------------------" << std::endl;
    uint32_t multDepth        = 10;
    SecurityLevel secLevel    = HEStd_128_classic;
    uint32_t numDigits        = 6;
    uint32_t plaintextModulus = 65537;
    uint32_t scalingModSize   = 60;
    BFVExample(multDepth, secLevel, numDigits, plaintextModulus, scalingModSize);

    std::cout << "--------------------COLUMN 2--------------------" << std::endl;
    multDepth        = 15;
    secLevel         = HEStd_192_classic;
    numDigits        = 9;
    plaintextModulus = 65537;
    scalingModSize   = 59;
    BFVExample(multDepth, secLevel, numDigits, plaintextModulus, scalingModSize);

    std::cout << "--------------------COLUMN 3--------------------" << std::endl;
    multDepth        = 18;
    secLevel         = HEStd_256_classic;
    numDigits        = 3;
    plaintextModulus = 65537;
    scalingModSize   = 60;
    BFVExample(multDepth, secLevel, numDigits, plaintextModulus, scalingModSize);

    std::cout << "--------------------COLUMN 4--------------------" << std::endl;
    multDepth        = 9;
    secLevel         = HEStd_128_quantum;
    numDigits        = 6;
    plaintextModulus = 65537;
    scalingModSize   = 55;
    BFVExample(multDepth, secLevel, numDigits, plaintextModulus, scalingModSize);

    std::cout << "--------------------COLUMN 5--------------------" << std::endl;
    multDepth        = 14;
    secLevel         = HEStd_192_quantum;
    numDigits        = 9;
    plaintextModulus = 65537;
    scalingModSize   = 55;
    BFVExample(multDepth, secLevel, numDigits, plaintextModulus, scalingModSize);

    std::cout << "--------------------COLUMN 6--------------------" << std::endl;
    multDepth        = 17;
    secLevel         = HEStd_256_quantum;
    numDigits        = 3;
    plaintextModulus = 65537;
    scalingModSize   = 57;
    BFVExample(multDepth, secLevel, numDigits, plaintextModulus, scalingModSize);

    std::cout << "====================BGV Parameters====================" << std::endl;

    std::cout << "--------------------COLUMN 1--------------------" << std::endl;
    multDepth        = 9;
    secLevel         = HEStd_128_classic;
    numDigits        = 11;
    plaintextModulus = 65537;
    BGVExample(multDepth, secLevel, numDigits, plaintextModulus);

    std::cout << "--------------------COLUMN 2--------------------" << std::endl;
    multDepth        = 13;
    secLevel         = HEStd_192_classic;
    numDigits        = 15;
    plaintextModulus = 65537;
    BGVExample(multDepth, secLevel, numDigits, plaintextModulus);

    std::cout << "--------------------COLUMN 3--------------------" << std::endl;
    multDepth        = 16;
    secLevel         = HEStd_256_classic;
    numDigits        = 3;
    plaintextModulus = 65537;
    BGVExample(multDepth, secLevel, numDigits, plaintextModulus);

    std::cout << "--------------------COLUMN 4--------------------" << std::endl;
    multDepth        = 8;
    secLevel         = HEStd_128_quantum;
    numDigits        = 10;
    plaintextModulus = 65537;
    BGVExample(multDepth, secLevel, numDigits, plaintextModulus);

    std::cout << "--------------------COLUMN 5--------------------" << std::endl;
    multDepth        = 12;
    secLevel         = HEStd_192_quantum;
    numDigits        = 14;
    plaintextModulus = 65537;
    BGVExample(multDepth, secLevel, numDigits, plaintextModulus);

    std::cout << "--------------------COLUMN 6--------------------" << std::endl;
    multDepth        = 15;
    secLevel         = HEStd_256_quantum;
    numDigits        = 3;
    plaintextModulus = 65537;
    BGVExample(multDepth, secLevel, numDigits, plaintextModulus);
}
void BFVExample(uint32_t multDepth, SecurityLevel secLevel, uint32_t numDigits, uint32_t plaintextModulus,
                uint32_t scalingModSize) {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetSecurityLevel(secLevel);
    parameters.SetNumLargeDigits(numDigits);
    parameters.SetScalingModSize(scalingModSize);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoContext->GetCryptoParameters());

    std::cout << "Depth L = " << multDepth << std::endl;

    std::cout << "Plaintext modulus " << cryptoParams->GetPlaintextModulus() << std::endl;
    std::cout << "Ring dimension " << cryptoContext->GetRingDimension() << std::endl;
    std::cout << "Log Q " << cryptoContext->GetModulus().GetMSB() << std::endl;

    if (cryptoParams->GetKeySwitchTechnique() == HYBRID) {
        std::cout << "Log P " << cryptoParams->GetParamsP()->GetModulus().GetMSB() << std::endl;
        std::cout << "Log PQ " << cryptoParams->GetParamsQP()->GetModulus().GetMSB() << std::endl;
    }
}

void BGVExample(uint32_t multDepth, SecurityLevel secLevel, uint32_t numDigits, uint32_t plaintextModulus) {
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetSecurityLevel(secLevel);
    parameters.SetNumLargeDigits(numDigits);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoContext->GetCryptoParameters());

    std::cout << "Depth L = " << multDepth << std::endl;

    std::cout << "Plaintext modulus " << cryptoParams->GetPlaintextModulus() << std::endl;
    std::cout << "Ring dimension " << cryptoContext->GetRingDimension() << std::endl;
    std::cout << "Log Q " << cryptoContext->GetModulus().GetMSB() << std::endl;

    if (cryptoParams->GetKeySwitchTechnique() == HYBRID) {
        std::cout << "Log P " << cryptoParams->GetParamsP()->GetModulus().GetMSB() << std::endl;
        std::cout << "Log PQ " << cryptoParams->GetParamsQP()->GetModulus().GetMSB() << std::endl;
    }
}
