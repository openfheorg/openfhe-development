//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
  Benchmarks for scheme switching between CKKS and FHEW and back, with intermediate computations
 */

#define PROFILE
#include "openfhe.h"
#include "binfhecontext.h"
#include <chrono>
#include <unistd.h>

using namespace lbcrypto;

void SwitchCKKSToFHEW(uint32_t depth, uint32_t slots, uint32_t numValues);
void SwitchFHEWtoCKKS(uint32_t depth, uint32_t slots, uint32_t numValues);
void ComparisonViaSchemeSwitching(uint32_t depth, uint32_t slots, uint32_t numValues);
void ArgminViaSchemeSwitching(uint32_t depth, uint32_t slots, uint32_t numValues);
void ArgminViaSchemeSwitchingAlt(uint32_t depth, uint32_t slots, uint32_t numValues);
void Argmin(uint32_t depth, uint32_t slots, uint32_t numValues, uint32_t ringDim);
void ArgminAlt(uint32_t depth, uint32_t slots, uint32_t numValues, uint32_t ringDim);
void Comparison(uint32_t depth, uint32_t slots, uint32_t numValues, uint32_t ringDim);

int main() {
    // // all examples set 128-bit security
    // SwitchCKKSToFHEW(24, 1024, 1024);
    // SwitchFHEWtoCKKS(24, 1024, 1024);
    // ComparisonViaSchemeSwitching(24, 1024, 1024);

    // // depth >= 13 + log2(numValues);
    // ArgminViaSchemeSwitching(24, 1024, 1024);
    // ArgminViaSchemeSwitchingAlt(24, 1024, 1024);

    Argmin(39, 256, 256, 1 << 17);
    // ArgminAlt(39, 256, 256, 1 << 17);
    // Comparison(39, 256, 256, 1 << 17);

    return 0;
}

void SwitchCKKSToFHEW(uint32_t depth, uint32_t slots, uint32_t numValues) {
    /*
  Example of switching a packed ciphertext from CKKS to multiple FHEW ciphertexts.
 */
    std::cout << "\n-----SwitchCKKSToFHEW-----\n" << std::endl;

    TimeVar t, tTotal;
    double timeKeyGen(0.0), timeSetup(0.0), timePrecomp(0.0), timeEval(0.0);

    TIC(tTotal);

    // Step 1: Setup CryptoContext for CKKS

    // Specify main parameters
    uint32_t firstModSize = 60;
    uint32_t scaleModSize = 50;
    uint32_t logQ_ccLWE   = 26;
    uint32_t batchSize    = slots;

    CCParams<CryptoContextCKKSRNS> parameters;

    parameters.SetMultiplicativeDepth(depth);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << depth << std::endl
              << std::endl;

    // Generate encryption keys
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE);
    params.SetNumSlotsCKKS(slots);
    TIC(t);
    auto privateKeyFHEW = cc->EvalCKKStoFHEWSetup(params);
    auto ccLWE          = cc->GetBinCCForSchemeSwitch();
    timeSetup           = TOC(t);
    std::cout << "Time to compute the CKKS to FHEW switching setup: " << timeSetup / 1000 << " s" << std::endl;

    TIC(t);
    cc->EvalCKKStoFHEWKeyGen(keys, privateKeyFHEW);
    // Generate bootstrapping key for timing
    ccLWE->BTKeyGen(privateKeyFHEW);
    timeKeyGen = TOC(t);
    std::cout << "Time to compute the CKKS to FHEW switching key generation (+BTKey): " << timeKeyGen / 60000 << " min"
              << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    std::cout << numValues << " slots are being switched." << std::endl << std::endl;

    // Perform the precomputation for switching
    TIC(t);
    // Compute the scaling factor to decrypt correctly in FHEW; the LWE mod switch is performed on the ciphertext at the last level
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ                                  = elementParams.GetParams();
    auto modulus_CKKS_from                        = paramsQ[0]->GetModulus();

    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE->GetBeta().ConvertToInt();
    auto pLWE        = modulus_LWE / (2 * beta);  // Large precision

    double scFactor = cryptoParams->GetScalingFactorReal(0);
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        scFactor = cryptoParams->GetScalingFactorReal(1);
    double scale = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE);

    cc->EvalCKKStoFHEWPrecompute(scale);
    timePrecomp = TOC(t);
    std::cout << "Time to do the precomputations for the CKKS to FHEW switching: " << timePrecomp / 1000 << " s"
              << std::endl;

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0};
    if (x.size() < slots) {
        std::vector<int> zeros(slots - x.size(), 0);
        x.insert(x.end(), zeros.begin(), zeros.end());
    }

    // Encoding as plaintexts
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(x, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto ct = cc->Encrypt(keys.publicKey, ptxt);

    // Step 4: Scheme switching from CKKS to FHEW

    // Transform the ciphertext from CKKS to FHEW
    TIC(t);
    auto cTemp = cc->EvalCKKStoFHEW(ct, numValues);
    timeEval   = TOC(t);
    std::cout << "Time to evaluate the scheme switching from CKKS to FHEW: " << timeEval / 1000 << " s" << std::endl;

    std::vector<int32_t> xInt(slots);
    std::transform(x.begin(), x.end(), xInt.begin(), [&](const double& elem) {
        return static_cast<int32_t>(static_cast<int32_t>(std::round(elem)) % pLWE);
    });
    ptxt->SetLength(slots);
    if (slots < 64) {
        std::cout << "Input: " << ptxt->GetRealPackedValue() << "; which rounds to: " << xInt << std::endl;
        std::cout << "FHEW decryption: ";
        LWEPlaintext result;
        for (uint32_t i = 0; i < cTemp.size(); ++i) {
            ccLWE->Decrypt(privateKeyFHEW, cTemp[i], &result, pLWE);
            std::cout << result << " ";
        }
        std::cout << "\n" << std::endl;
    }
    else {  // Suppress output
        LWEPlaintext result;
        for (uint32_t i = 0; i < cTemp.size(); ++i) {
            ccLWE->Decrypt(privateKeyFHEW, cTemp[i], &result, pLWE);
        }
    }

    double totalTime = TOC(tTotal);
    std::cout << "\nTotal time: " << totalTime / 60000 << " min" << std::endl;
}

void SwitchFHEWtoCKKS(uint32_t depth, uint32_t slots, uint32_t numValues) {
    /*
  Example of switching multiple FHEW ciphertexts to a packed CKKS ciphertext.
 */
    std::cout << "\n-----SwitchFHEWtoCKKS-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back.\n" << std::endl;

    TimeVar t, tTotal;
    double timeKeyGen(0.0), timeSetup(0.0), timeEval(0.0);

    TIC(tTotal);

    // Step 1: Setup CryptoContext for CKKS to be switched into

    // A. Specify main parameters
    ScalingTechnique scTech = FIXEDAUTO;
    if (scTech == FLEXIBLEAUTOEXT)
        depth += 1;
    uint32_t scaleModSize = 50;
    uint32_t logQ_ccLWE   = 26;
    uint32_t batchSize    = slots;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << depth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    auto ccLWE = std::make_shared<BinFHEContext>();
    ccLWE->BinFHEContext::GenerateBinFHEContext(STD128, false, logQ_ccLWE, 0, GINX, false);

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    std::cout << numValues << " slots are being switched." << std::endl << std::endl;

    // Step 3. Precompute the necessary keys and information for switching from FHEW to CKKS
    TIC(t);
    cc->EvalFHEWtoCKKSSetup(ccLWE, slots, logQ_ccLWE);
    timeSetup = TOC(t);
    std::cout << "Time to compute the FHEW to CKKS switching setup: " << timeSetup / 1000 << " s" << std::endl;

    TIC(t);
    // LWE private key
    LWEPrivateKey lwesk;
    lwesk = ccLWE->KeyGen();
    cc->EvalFHEWtoCKKSKeyGen(keys, lwesk, slots);
    // Generate bootstrapping key for timing
    ccLWE->BTKeyGen(lwesk);
    timeKeyGen = TOC(t);
    std::cout << "Time to compute the FHEW to CKKS switching key generation (+ BT key): " << timeKeyGen / 60000
              << " min" << std::endl;

    // Step 4: Encoding and encryption of inputs
    // For correct CKKS decryption, the messages have to be much smaller than the FHEW plaintext modulus!
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE->GetBeta().ConvertToInt();
    auto pLWE        = modulus_LWE / (2 * beta);  // Large precision
    // Inputs
    std::vector<int> x = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    if (x.size() < slots) {
        std::vector<int> zeros(slots - x.size(), 0);
        x.insert(x.end(), zeros.begin(), zeros.end());
    }

    // Encrypt
    std::vector<LWECiphertext> ctxtsLWE(slots);
    for (uint32_t i = 0; i < slots; i++) {
        ctxtsLWE[i] =
            ccLWE->Encrypt(lwesk, x[i], FRESH, pLWE,
                           modulus_LWE);  // encrypted under large plaintext modulus and large ciphertext modulus
    }

    // Step 5. Perform the scheme switching
    std::setprecision(logQ_ccLWE + 10);
    TIC(t);
    auto cTemp = cc->EvalFHEWtoCKKS(ctxtsLWE, numValues, slots, pLWE, 0, pLWE);
    timeEval   = TOC(t);
    std::cout << "Time to evaluate the scheme switching from FHEW to CKKS: " << timeEval / 60000 << " min" << std::endl;

    // Step 6. Decrypt
    Plaintext plaintextDec;
    cc->Decrypt(keys.secretKey, cTemp, &plaintextDec);
    plaintextDec->SetLength(numValues);

    if (numValues <= 64) {  // Otherwise, supress output
        std::cout << "\nInput: " << x << " encrypted under p = " << NativeInteger(pLWE)
                  << " and Q = " << ctxtsLWE[0]->GetModulus() << std::endl;
        std::cout << "Switched CKKS decryption: " << plaintextDec << std::endl;
    }

    double totalTime = TOC(tTotal);
    std::cout << "\nTotal time: " << totalTime / 60000 << " min" << std::endl;
}

void ComparisonViaSchemeSwitching(uint32_t depth, uint32_t slots, uint32_t numValues) {
    /*
  Example of comparing two CKKS ciphertexts via scheme switching.
 */
    std::cout << "\n-----ComparisonViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back.\n" << std::endl;

    TimeVar t, tTotal;
    double timeKeyGen(0.0), timeSetup(0.0), timePrecomp(0.0), timeEval(0.0);

    TIC(tTotal);

    // Step 1: Setup CryptoContext for CKKS
    ScalingTechnique scTech = FIXEDAUTO;
    if (scTech == FLEXIBLEAUTOEXT)
        depth += 1;

    uint32_t scaleModSize = 50;
    uint32_t firstModSize = 60;
    uint32_t logQ_ccLWE   = 26;
    uint32_t batchSize    = slots;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << depth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE);
    params.SetNumSlotsCKKS(slots);
    params.SetNumValues(slots);
    TIC(t);
    auto privateKeyFHEW = cc->EvalSchemeSwitchingSetup(params);
    timeSetup           = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << timeSetup / 1000 << " s" << std::endl;

    auto ccLWE = cc->GetBinCCForSchemeSwitch();

    TIC(t);
    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW);
    timeKeyGen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << timeKeyGen / 60000 << " min" << std::endl
              << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    std::cout << numValues << " slots are being switched." << std::endl;

    TIC(t);
    // Pre-computations
    auto modulus_LWE     = 1 << logQ_ccLWE;
    auto beta            = ccLWE->GetBeta().ConvertToInt();
    auto pLWE            = modulus_LWE / (2 * beta);
    double scaleSignFHEW = 8.0;
    cc->EvalCompareSwitchPrecompute(pLWE, scaleSignFHEW);
    timePrecomp = TOC(t);
    std::cout << "Time to perform precomputations: " << timePrecomp / 1000 << " s" << std::endl;

    // Step 3: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x1 = {0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0};
    std::vector<double> x2(slots, 5.25);
    if (x1.size() < slots) {
        std::vector<int> zeros(slots - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }
    if (x2.size() < slots) {
        std::vector<int> zeros(slots - x2.size(), 0);
        x2.insert(x2.end(), zeros.begin(), zeros.end());
    }

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr);
    Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    auto c2 = cc->Encrypt(keys.publicKey, ptxt2);

    // Compute the difference to compare to zero
    auto cDiff = cc->EvalSub(c1, c2);

    Plaintext pDiff;
    cc->Decrypt(keys.secretKey, cDiff, &pDiff);
    pDiff->SetLength(slots);
    if (slots <= 64) {  // Otherwise, supress output
        std::cout << "Difference of inputs: ";
        for (uint32_t i = 0; i < slots; ++i) {
            std::cout << pDiff->GetRealPackedValue()[i] << " ";
        }
    }

    if (numValues <= 64) {  // Otherwise, supress output
        const double eps = 0.0001;
        std::cout << "\nExpected sign result from CKKS: ";
        for (uint32_t i = 0; i < numValues; ++i) {
            std::cout << int(std::round(pDiff->GetRealPackedValue()[i] / eps) * eps < 0) << " ";
        }
        std::cout << "\n";
    }

    // Step 4: Comparison via CKKS->FHEW->CKKS
    TIC(t);
    auto cResult = cc->EvalCompareSchemeSwitching(c1, c2, numValues, slots);
    timeEval     = TOC(t);
    std::cout << "Time to perform comparison via scheme switching: " << timeEval / 60000 << " min" << std::endl;

    Plaintext plaintextDec3;
    cc->Decrypt(keys.secretKey, cResult, &plaintextDec3);
    plaintextDec3->SetLength(numValues);

    if (numValues <= 64) {  // Otherwise, supress output
        std::cout << "Decrypted switched result: " << plaintextDec3 << std::endl;
    }

    double totalTime = TOC(tTotal);
    std::cout << "\nTotal time: " << totalTime / 60000 << " min" << std::endl;
}

void ArgminViaSchemeSwitching(uint32_t depth, uint32_t slots, uint32_t numValues) {
    /*
  Example of computing the min and argmin of the vector packed in a CKKS ciphertext.
 */
    std::cout << "\n-----ArgminViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back\n" << std::endl;

    TimeVar t, tTotal;
    double timeKeyGen(0.0), timeSetup(0.0), timePrecomp(0.0), timeEvalMin(0.0);  // timeEvalMax(0.0);

    TIC(tTotal);

    // Step 1: Setup CryptoContext for CKKS
    uint32_t scaleModSize = 50;
    uint32_t firstModSize = 60;
    uint32_t logQ_ccLWE   = 26;
    bool oneHot           = true;  // Change to false if the output should not be one-hot encoded

    uint32_t batchSize      = slots;
    ScalingTechnique scTech = FLEXIBLEAUTO;
    if (scTech == FLEXIBLEAUTOEXT)
        depth += 1;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << depth << std::endl << std::endl;

    // Generate encryption keys
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE);
    params.SetNumSlotsCKKS(slots);
    params.SetNumValues(numValues);
    params.SetComputeArgmin(true);
    params.SetOneHotEncoding(oneHot);
    TIC(t);
    auto privateKeyFHEW = cc->EvalSchemeSwitchingSetup(params);
    timeSetup           = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << timeSetup / 1000 << " s" << std::endl;

    auto ccLWE = cc->GetBinCCForSchemeSwitch();

    TIC(t);
    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW);
    timeKeyGen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << timeKeyGen / 60000 << " min" << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    std::cout << numValues << " slots are being switched." << std::endl << std::endl;

    TIC(t);
    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    double scaleSign = 512.0;
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE->GetBeta().ConvertToInt();
    auto pLWE        = modulus_LWE / (2 * beta);  // Large precision
    cc->EvalCompareSwitchPrecompute(pLWE, scaleSign);
    timePrecomp = TOC(t);
    std::cout << "Time to do the precomputations: " << timePrecomp / 1000 << " s" << std::endl;

    // Step 3: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                             9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x.size() < slots) {
        std::vector<int> zeros(slots - x.size(), 0);
        x.insert(x.end(), zeros.begin(), zeros.end());
    }

    std::cout << "Expected minimum value " << *(std::min_element(x.begin(), x.begin() + numValues)) << " at location "
              << std::min_element(x.begin(), x.begin() + numValues) - x.begin() << std::endl;
    std::cout << "Expected maximum value " << *(std::max_element(x.begin(), x.begin() + numValues)) << " at location "
              << std::max_element(x.begin(), x.begin() + numValues) - x.begin() << std::endl;
    std::cout << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    // Step 4: Argmin evaluation
    TIC(t);
    auto result = cc->EvalMinSchemeSwitching(c1, keys.publicKey, numValues, slots);
    timeEvalMin = TOC(t);

    Plaintext ptxtMin;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMin);
    ptxtMin->SetLength(1);
    std::cout << "Minimum value: " << ptxtMin << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMin);

    if (numValues <= 64) {  // Otherwise, supress output
        if (oneHot) {
            ptxtMin->SetLength(numValues);
            std::cout << "Argmin indicator vector: " << ptxtMin << std::endl;
        }
        else {
            ptxtMin->SetLength(1);
            std::cout << "Argmin: " << ptxtMin << std::endl;
        }
    }
    std::cout << "Time to compute min and argmin via scheme switching: " << timeEvalMin / 60000 << " min" << std::endl;

    // TIC(t);
    // result      = cc->EvalMaxSchemeSwitching(c1, keys.publicKey, numValues, slots);
    // timeEvalMax = TOC(t);

    // Plaintext ptxtMax;
    // cc->Decrypt(keys.secretKey, result[0], &ptxtMax);
    // ptxtMax->SetLength(1);
    // std::cout << "Maximum value: " << ptxtMax << std::endl;
    // cc->Decrypt(keys.secretKey, result[1], &ptxtMax);

    // if (numValues <= 64) {  // Otherwise, supress output
    //     if (oneHot) {
    //         ptxtMax->SetLength(numValues);
    //         std::cout << "Argmax indicator vector: " << ptxtMax << std::endl;
    //     }
    //     else {
    //         ptxtMax->SetLength(1);
    //         std::cout << "Argmax: " << ptxtMax << std::endl;
    //     }
    // }
    // std::cout << "Time to compute max and argmax via scheme switching: " << timeEvalMax/ 60000 << " min" << std::endl;

    double totalTime = TOC(tTotal);
    std::cout << "\nTotal time: " << totalTime / 60000 << " min" << std::endl;
}

void ArgminViaSchemeSwitchingAlt(uint32_t depth, uint32_t slots, uint32_t numValues) {
    /*
  Example of computing the min and argmin of the vector packed in a CKKS ciphertext.
 */
    std::cout << "\n-----ArgminViaSchemeSwitchingAlt-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back\n" << std::endl;

    TimeVar t, tTotal;
    double timeKeyGen(0.0), timeSetup(0.0), timePrecomp(0.0), timeEvalMin(0.0);  // timeEvalMax(0.0);

    TIC(tTotal);

    // Step 1: Setup CryptoContext for CKKS
    uint32_t scaleModSize = 50;
    uint32_t firstModSize = 60;
    uint32_t logQ_ccLWE   = 26;
    bool oneHot           = true;  // Change to false if the output should not be one-hot encoded

    uint32_t batchSize      = slots;
    ScalingTechnique scTech = FLEXIBLEAUTO;
    if (scTech == FLEXIBLEAUTOEXT)
        depth += 1;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << depth << std::endl << std::endl;

    // Generate encryption keys
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE);
    params.SetNumSlotsCKKS(slots);
    params.SetNumValues(numValues);
    params.SetComputeArgmin(true);
    params.SetOneHotEncoding(oneHot);
    params.SetUseAltArgmin(true);
    TIC(t);
    auto privateKeyFHEW = cc->EvalSchemeSwitchingSetup(params);
    timeSetup           = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << timeSetup / 1000 << " s" << std::endl;

    auto ccLWE = cc->GetBinCCForSchemeSwitch();

    TIC(t);
    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW);
    timeKeyGen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << timeKeyGen / 60000 << " min" << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    std::cout << numValues << " slots are being switched." << std::endl << std::endl;

    TIC(t);
    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    double scaleSign = 512.0;
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE->GetBeta().ConvertToInt();
    auto pLWE        = modulus_LWE / (2 * beta);  // Large precision
    cc->EvalCompareSwitchPrecompute(pLWE, scaleSign);
    timePrecomp = TOC(t);
    std::cout << "Time to do the precomputations: " << timePrecomp / 1000 << " s" << std::endl;

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                             9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x.size() < slots) {
        std::vector<int> zeros(slots - x.size(), 0);
        x.insert(x.end(), zeros.begin(), zeros.end());
    }

    std::cout << "Expected minimum value " << *(std::min_element(x.begin(), x.begin() + numValues)) << " at location "
              << std::min_element(x.begin(), x.begin() + numValues) - x.begin() << std::endl;
    // std::cout << "Expected maximum value " << *(std::max_element(x.begin(), x.begin() + numValues)) << " at location "
    //   << std::max_element(x.begin(), x.begin() + numValues) - x.begin() << std::endl;
    std::cout << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    // Step 4: Argmin evaluation
    TIC(t);
    auto result = cc->EvalMinSchemeSwitchingAlt(c1, keys.publicKey, numValues, slots);
    timeEvalMin = TOC(t);

    Plaintext ptxtMin;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMin);
    ptxtMin->SetLength(1);
    std::cout << "Minimum value: " << ptxtMin << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMin);

    if (numValues <= 64) {  // Otherwise, supress output
        if (oneHot) {
            ptxtMin->SetLength(numValues);
            std::cout << "Argmin indicator vector: " << ptxtMin << std::endl;
        }
        else {
            ptxtMin->SetLength(1);
            std::cout << "Argmin: " << ptxtMin << std::endl;
        }
    }
    std::cout << "Time to compute min and argmin via scheme switching: " << timeEvalMin / 60000 << " min" << std::endl;

    // TIC(t);
    // result      = cc->EvalMaxSchemeSwitchingAlt(c1, keys.publicKey, numValues, slots);
    // timeEvalMax = TOC(t);

    // Plaintext ptxtMax;
    // cc->Decrypt(keys.secretKey, result[0], &ptxtMax);
    // ptxtMax->SetLength(1);
    // std::cout << "Maximum value: " << ptxtMax << std::endl;
    // cc->Decrypt(keys.secretKey, result[1], &ptxtMax);

    // if (numValues <= 64) {  // Otherwise, supress output
    //     if (oneHot) {
    //         ptxtMax->SetLength(numValues);
    //         std::cout << "Argmax indicator vector: " << ptxtMax << std::endl;
    //     }
    //     else {
    //         ptxtMax->SetLength(1);
    //         std::cout << "Argmax: " << ptxtMax << std::endl;
    //     }
    // }
    // std::cout << "Time to compute max and argmax via scheme switching: " << timeEvalMax/ 60000 << " min" << std::endl;

    double totalTime = TOC(tTotal);
    std::cout << "\nTotal time: " << totalTime / 60000 << " min" << std::endl;
}

void Argmin(uint32_t depth, uint32_t slots, uint32_t numValues, uint32_t ringDim) {
    /*
  Example of computing the min and argmin of the vector packed in a CKKS ciphertext.
 */
    std::cout << "\n-----ArgminViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back\n" << std::endl;

    TimeVar t, tTotal;
    double timeKeyGen(0.0), timeSetup(0.0), timePrecomp(0.0), timeEvalMin(0.0);  // timeEvalMax(0.0);

    TIC(tTotal);

    // Step 1: Setup CryptoContext for CKKS
    uint32_t scaleModSize = 52;
    uint32_t firstModSize = 60;
    uint32_t logQ_ccLWE   = 26;
    bool oneHot           = true;  // Change to false if the output should not be one-hot encoded

    uint32_t batchSize      = slots;
    ScalingTechnique scTech = FLEXIBLEAUTO;
    if (scTech == FLEXIBLEAUTOEXT)
        depth += 1;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetBatchSize(batchSize);
    parameters.SetRingDim(ringDim);
    parameters.SetSecurityLevel(HEStd_NotSet);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << depth << std::endl << std::endl;

    // Generate encryption keys
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE);
    params.SetNumSlotsCKKS(slots);
    params.SetNumValues(numValues);
    params.SetComputeArgmin(true);
    params.SetOneHotEncoding(oneHot);
    TIC(t);
    auto privateKeyFHEW = cc->EvalSchemeSwitchingSetup(params);
    timeSetup           = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << timeSetup / 1000 << " s" << std::endl;

    auto ccLWE = cc->GetBinCCForSchemeSwitch();

    TIC(t);
    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW);
    timeKeyGen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << timeKeyGen / 60000 << " min" << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    std::cout << numValues << " slots are being switched." << std::endl << std::endl;

    TIC(t);
    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    double scaleSign = 512.0;
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE->GetBeta().ConvertToInt();
    auto pLWE        = modulus_LWE / (2 * beta);  // Large precision
    cc->EvalCompareSwitchPrecompute(pLWE, scaleSign);
    timePrecomp = TOC(t);
    std::cout << "Time to do the precomputations: " << timePrecomp / 1000 << " s" << std::endl;

    // Step 3: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                             9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x.size() < slots) {
        std::vector<int> zeros(slots - x.size(), 0);
        x.insert(x.end(), zeros.begin(), zeros.end());
    }

    std::cout << "Expected minimum value " << *(std::min_element(x.begin(), x.begin() + numValues)) << " at location "
              << std::min_element(x.begin(), x.begin() + numValues) - x.begin() << std::endl;
    std::cout << "Expected maximum value " << *(std::max_element(x.begin(), x.begin() + numValues)) << " at location "
              << std::max_element(x.begin(), x.begin() + numValues) - x.begin() << std::endl;
    std::cout << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    // Step 4: Argmin evaluation
    TIC(t);
    auto result = cc->EvalMinSchemeSwitching(c1, keys.publicKey, numValues, slots);
    timeEvalMin = TOC(t);

    Plaintext ptxtMin;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMin);
    ptxtMin->SetLength(1);
    std::cout << "Minimum value: " << ptxtMin << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMin);

    if (numValues <= 64) {  // Otherwise, supress output
        if (oneHot) {
            ptxtMin->SetLength(numValues);
            std::cout << "Argmin indicator vector: " << ptxtMin << std::endl;
        }
        else {
            ptxtMin->SetLength(1);
            std::cout << "Argmin: " << ptxtMin << std::endl;
        }
    }
    std::cout << "Time to compute min and argmin via scheme switching: " << timeEvalMin / 60000 << " min" << std::endl;

    // TIC(t);
    // result      = cc->EvalMaxSchemeSwitching(c1, keys.publicKey, numValues, slots);
    // timeEvalMax = TOC(t);

    // Plaintext ptxtMax;
    // cc->Decrypt(keys.secretKey, result[0], &ptxtMax);
    // ptxtMax->SetLength(1);
    // std::cout << "Maximum value: " << ptxtMax << std::endl;
    // cc->Decrypt(keys.secretKey, result[1], &ptxtMax);

    // if (numValues <= 64) {  // Otherwise, supress output
    //     if (oneHot) {
    //         ptxtMax->SetLength(numValues);
    //         std::cout << "Argmax indicator vector: " << ptxtMax << std::endl;
    //     }
    //     else {
    //         ptxtMax->SetLength(1);
    //         std::cout << "Argmax: " << ptxtMax << std::endl;
    //     }
    // }
    // std::cout << "Time to compute max and argmax via scheme switching: " << timeEvalMax/ 60000 << " min" << std::endl;

    double totalTime = TOC(tTotal);
    std::cout << "\nTotal time: " << totalTime / 60000 << " min" << std::endl;
}

void ArgminAlt(uint32_t depth, uint32_t slots, uint32_t numValues, uint32_t ringDim) {
    /*
  Example of computing the min and argmin of the vector packed in a CKKS ciphertext.
 */
    std::cout << "\n-----ArgminViaSchemeSwitchingAlt-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back\n" << std::endl;

    TimeVar t, tTotal;
    double timeKeyGen(0.0), timeSetup(0.0), timePrecomp(0.0), timeEvalMin(0.0);  // timeEvalMax(0.0);

    TIC(tTotal);

    // Step 1: Setup CryptoContext for CKKS
    uint32_t scaleModSize = 52;
    uint32_t firstModSize = 60;
    uint32_t logQ_ccLWE   = 26;
    bool oneHot           = true;  // Change to false if the output should not be one-hot encoded

    uint32_t batchSize      = slots;
    ScalingTechnique scTech = FLEXIBLEAUTO;
    if (scTech == FLEXIBLEAUTOEXT)
        depth += 1;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetBatchSize(batchSize);
    parameters.SetRingDim(ringDim);
    parameters.SetSecurityLevel(HEStd_NotSet);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << depth << std::endl << std::endl;

    // Generate encryption keys
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE);
    params.SetNumSlotsCKKS(slots);
    params.SetNumValues(numValues);
    params.SetComputeArgmin(true);
    params.SetOneHotEncoding(oneHot);
    params.SetUseAltArgmin(true);
    TIC(t);
    auto privateKeyFHEW = cc->EvalSchemeSwitchingSetup(params);
    timeSetup           = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << timeSetup / 1000 << " s" << std::endl;

    auto ccLWE = cc->GetBinCCForSchemeSwitch();

    TIC(t);
    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW);
    timeKeyGen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << timeKeyGen / 60000 << " min" << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    std::cout << numValues << " slots are being switched." << std::endl << std::endl;

    TIC(t);
    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    double scaleSign = 512.0;
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE->GetBeta().ConvertToInt();
    auto pLWE        = modulus_LWE / (2 * beta);  // Large precision

    uint32_t init_level     = 0;
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        init_level = 1;
    cc->EvalCompareSwitchPrecompute(pLWE, init_level, scaleSign);
    timePrecomp = TOC(t);
    std::cout << "Time to do the precomputations: " << timePrecomp / 1000 << " s" << std::endl;

    // Step 3: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                             9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x.size() < slots) {
        std::vector<int> zeros(slots - x.size(), 0);
        x.insert(x.end(), zeros.begin(), zeros.end());
    }

    std::cout << "Expected minimum value " << *(std::min_element(x.begin(), x.begin() + numValues)) << " at location "
              << std::min_element(x.begin(), x.begin() + numValues) - x.begin() << std::endl;
    std::cout << "Expected maximum value " << *(std::max_element(x.begin(), x.begin() + numValues)) << " at location "
              << std::max_element(x.begin(), x.begin() + numValues) - x.begin() << std::endl;
    std::cout << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    // Step 4: Argmin evaluation
    TIC(t);
    auto result = cc->EvalMinSchemeSwitchingAlt(c1, keys.publicKey, numValues, slots);
    timeEvalMin = TOC(t);

    Plaintext ptxtMin;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMin);
    ptxtMin->SetLength(1);
    std::cout << "Minimum value: " << ptxtMin << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMin);

    if (numValues <= 64) {  // Otherwise, supress output
        if (oneHot) {
            ptxtMin->SetLength(numValues);
            std::cout << "Argmin indicator vector: " << ptxtMin << std::endl;
        }
        else {
            ptxtMin->SetLength(1);
            std::cout << "Argmin: " << ptxtMin << std::endl;
        }
    }
    std::cout << "Time to compute min and argmin via scheme switching: " << timeEvalMin / 60000 << " min" << std::endl;

    // TIC(t);
    // result      = cc->EvalMaxSchemeSwitchingAlt(c1, keys.publicKey, numValues, slots);
    // timeEvalMax = TOC(t);

    // Plaintext ptxtMax;
    // cc->Decrypt(keys.secretKey, result[0], &ptxtMax);
    // ptxtMax->SetLength(1);
    // std::cout << "Maximum value: " << ptxtMax << std::endl;
    // cc->Decrypt(keys.secretKey, result[1], &ptxtMax);

    // if (numValues <= 64) {  // Otherwise, supress output
    //     if (oneHot) {
    //         ptxtMax->SetLength(numValues);
    //         std::cout << "Argmax indicator vector: " << ptxtMax << std::endl;
    //     }
    //     else {
    //         ptxtMax->SetLength(1);
    //         std::cout << "Argmax: " << ptxtMax << std::endl;
    //     }
    // }
    // std::cout << "Time to compute max and argmax via scheme switching: " << timeEvalMax/ 60000 << " min" << std::endl;

    double totalTime = TOC(tTotal);
    std::cout << "\nTotal time: " << totalTime / 60000 << " min" << std::endl;
}

void Comparison(uint32_t depth, uint32_t slots, uint32_t numValues, uint32_t ringDim) {
    /*
  Example of comparing two CKKS ciphertexts via scheme switching.
 */
    std::cout << "\n-----ComparisonViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back.\n" << std::endl;

    TimeVar t, tTotal;
    double timeKeyGen(0.0), timeSetup(0.0), timePrecomp(0.0), timeEval(0.0);

    TIC(tTotal);

    // Step 1: Setup CryptoContext for CKKS
    ScalingTechnique scTech = FIXEDAUTO;
    if (scTech == FLEXIBLEAUTOEXT)
        depth += 1;

    uint32_t scaleModSize = 52;
    uint32_t firstModSize = 60;
    uint32_t logQ_ccLWE   = 26;
    uint32_t batchSize    = slots;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetBatchSize(batchSize);
    parameters.SetRingDim(ringDim);
    parameters.SetSecurityLevel(HEStd_NotSet);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << depth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE);
    params.SetNumSlotsCKKS(slots);
    params.SetNumValues(slots);
    TIC(t);
    auto privateKeyFHEW = cc->EvalSchemeSwitchingSetup(params);
    timeSetup           = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << timeSetup / 1000 << " s" << std::endl;

    auto ccLWE = cc->GetBinCCForSchemeSwitch();

    TIC(t);
    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW);
    timeKeyGen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << timeKeyGen / 60000 << " min" << std::endl
              << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    std::cout << numValues << " slots are being switched." << std::endl;

    TIC(t);
    // Pre-computations
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE->GetBeta().ConvertToInt();
    auto pLWE        = modulus_LWE / (2 * beta);

    double scaleSignFHEW    = 8.0;
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    uint32_t init_level     = 0;
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        init_level = 1;
    cc->EvalCompareSwitchPrecompute(pLWE, init_level, scaleSignFHEW);
    timePrecomp = TOC(t);
    std::cout << "Time to perform precomputations: " << timePrecomp / 1000 << " s" << std::endl;

    // Step 3: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x1 = {0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0};
    std::vector<double> x2(slots, 5.25);
    if (x1.size() < slots) {
        std::vector<int> zeros(slots - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }
    if (x2.size() < slots) {
        std::vector<int> zeros(slots - x2.size(), 0);
        x2.insert(x2.end(), zeros.begin(), zeros.end());
    }

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr);
    Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    auto c2 = cc->Encrypt(keys.publicKey, ptxt2);

    // Compute the difference to compare to zero
    auto cDiff = cc->EvalSub(c1, c2);

    Plaintext pDiff;
    cc->Decrypt(keys.secretKey, cDiff, &pDiff);
    pDiff->SetLength(slots);
    if (slots <= 64) {  // Otherwise, supress output
        std::cout << "Difference of inputs: ";
        for (uint32_t i = 0; i < slots; ++i) {
            std::cout << pDiff->GetRealPackedValue()[i] << " ";
        }
    }

    if (numValues <= 64) {  // Otherwise, supress output
        const double eps = 0.0001;
        std::cout << "\nExpected sign result from CKKS: ";
        for (uint32_t i = 0; i < numValues; ++i) {
            std::cout << int(std::round(pDiff->GetRealPackedValue()[i] / eps) * eps < 0) << " ";
        }
        std::cout << "\n";
    }

    // Step 4: Comparison via CKKS->FHEW->CKKS
    TIC(t);
    auto cResult = cc->EvalCompareSchemeSwitching(c1, c2, numValues, slots);
    timeEval     = TOC(t);
    std::cout << "Time to perform comparison via scheme switching: " << timeEval / 60000 << " min" << std::endl;

    Plaintext plaintextDec3;
    cc->Decrypt(keys.secretKey, cResult, &plaintextDec3);
    plaintextDec3->SetLength(numValues);

    if (numValues <= 64) {  // Otherwise, supress output
        std::cout << "Decrypted switched result: " << plaintextDec3 << std::endl;
    }

    double totalTime = TOC(tTotal);
    std::cout << "\nTotal time: " << totalTime / 60000 << " min" << std::endl;
}
