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
  Example for scheme switching between CKKS and FHEW and back
 */

#define PROFILE
#include "openfhe.h"
#include "../../binfhe/include/binfhecontext.h"

using namespace lbcrypto;

void SwitchCKKSToFHEW();

int main() {
    SwitchCKKSToFHEW();
    return 0;
}

void SwitchCKKSToFHEW() {
    // Step 1: Setup CryptoContext for CKKS

    // A. Specify main parameters
    /* A1) Multiplicative depth:
  */
    uint32_t multDepth = 1;

    /* A2) Bit-length of scaling factor.
  */
    uint32_t scaleModSize = 50;
    uint32_t ringDim      = 8192;               // 2048;
    SecurityLevel sl      = HEStd_128_classic;  // If this is not HEStd_NotSet, ensure ringDim is compatible

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(FIXEDMANUAL);  // Andreea: currently, we only support scaling for FIXED
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);

    /* A3) Number of plaintext slots used in the ciphertext.
  */
    // uint32_t slots = ringDim/2; // fully-packed
    uint32_t slots     = 16;  // sparsely-packed
    uint32_t batchSize = slots;

    parameters.SetBatchSize(batchSize);

    uint32_t logQ_ccLWE = 29;

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);
    cc->Enable(FHE);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", and number of slots " << slots << std::endl << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    auto FHEWparams = cc->EvalCKKStoFHEWSetup(
        false, logQ_ccLWE, sl,
        slots);  // Andreea: it would help to have a method to extract the cryptocontext from the privateKey
    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;
    cc->EvalCKKStoFHEWKeyGen(keys, privateKeyFHEW);

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1 = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0};
    std::vector<double> x2 = {271.0, 30000.0};

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr);
    Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    auto c2 = cc->Encrypt(keys.publicKey, ptxt2);

    // Step 4: Scheme switching from CKKS to FHEW

    // Set the scaling factor to be able to decrypt
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(c1->GetCryptoParameters());

    // Get the last ciphertext modulus; this assumes the LWE mod switch will be performed on the ciphertext at the last level
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ                                  = elementParams.GetParams();
    // usint sizeQ = paramsQ.size();
    // for (size_t i = 0; i < sizeQ; i++) {
    //     std::cout << paramsQ[i]->GetModulus() << std::endl;
    // }
    auto modulus_CKKS_from = paramsQ[0]->GetModulus();
    // std::cout << "current modulus in CKKS: " << modulus_CKKS_from << ", to Int: " << modulus_CKKS_from.ConvertToInt() << std::endl;

    auto pLWE1       = ccLWE.GetMaxPlaintextSpace().ConvertToInt();  // Small precision
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE.GetBeta().ConvertToInt();
    auto pLWE2       = modulus_LWE / (2 * beta);  // Large precision
    std::cout << "Decryption with small precision is done with plaintext modulus = " << pLWE1 << std::endl;
    std::cout << "Decryption with larger precision is done with plaintext modulus = " << pLWE2 << std::endl;

    double scFactor = cryptoParams->GetScalingFactorReal(c1->GetLevel());
    double scale1   = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE1);
    double scale2   = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE2);

    // Transform the ciphertext from CKKS to FHEW
    auto cTemp = cc->EvalCKKStoFHEW(c1, scale1);

    std::cout << "\n---Decrypting switched ciphertext small precision---\n" << std::endl;

    std::cout << "Input x1: " << ptxt1->GetCKKSPackedValue() << std::endl;
    std::cout << "FHEW decryption: ";
    LWEPlaintext result;
    for (uint32_t i = 0; i < cTemp.size(); ++i) {
        ccLWE.Decrypt(privateKeyFHEW, cTemp[i], &result, pLWE1);  // Small precision
        std::cout << result << " ";
    }
    std::cout << "\n" << std::endl;

    // Transform the ciphertext from CKKS to FHEW
    auto cTemp2 = cc->EvalCKKStoFHEW(c2, scale2, 2);

    std::cout << "\n---Decrypting switched ciphertext large precision---\n" << std::endl;

    std::cout << "Input x2: " << ptxt2->GetCKKSPackedValue() << std::endl;
    std::cout << "FHEW decryption: ";
    for (uint32_t i = 0; i < cTemp2.size(); ++i) {
        ccLWE.Decrypt(privateKeyFHEW, cTemp2[i], &result, pLWE2);  // Large precision
        std::cout << result << " ";
    }
    std::cout << "\n" << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    ccLWE.BTKeyGen(privateKeyFHEW);

    for (uint32_t j = 0; j < cTemp2.size(); j++) {
        // Decompose the large ciphertext into small ciphertexts that fit in q
        auto decomp = ccLWE.EvalDecomp(cTemp2[j]);

        // Decryption
        auto p = ccLWE.GetMaxPlaintextSpace().ConvertToInt();
        LWECiphertext ct;
        std::cout << "Decomposed value: ";
        for (size_t i = 0; i < decomp.size(); i++) {
            ct = decomp[i];
            LWEPlaintext resultDecomp;
            if (i == decomp.size() - 1) {
                p = pLWE2 /
                    pow(pLWE1, std::floor(std::log(pLWE2) /
                                          std::log(pLWE1)));  // The last digit should be up to P / p^floor(log_p(P))
            }
            ccLWE.Decrypt(privateKeyFHEW, ct, &resultDecomp, p);
            std::cout << "(" << resultDecomp << " * " << pLWE1 << "^" << i << ")";
            if (i != decomp.size() - 1) {
                std::cout << " + ";
            }
        }
        std::cout << std::endl;
    }
}
