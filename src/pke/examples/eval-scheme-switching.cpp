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
// #include "math/chebyshev.h" // To compute coefficients
// #define Pi 3.14159265358979323846

using namespace lbcrypto;

void SwitchCKKSToFHEW();
void SwitchFHEWtoCKKS();

double Factorial(int n) {
    return (n == 1 || n == 0) ? 1 : n * Factorial(n - 1);
}

int main() {
    SwitchFHEWtoCKKS();
    // SwitchCKKSToFHEW();

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
    uint32_t logQ_ccLWE   = 27;

    /*Assumption: the CKKS ciphertext modulus when the switching is done (on the last level) has to be
    greater than the FHEW ciphertext modulus.*/

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

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE.GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", ring dimension RGSW/RLWE " << ccLWE.GetParams()->GetLWEParams()->GetN();
    std::cout << ", and modulus q " << ccLWE.GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

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

void SwitchFHEWtoCKKS() {
    TimeVar t, tTotal;

    TIC(tTotal);

    double timeCKKStoFHEWKeyGen(0.0), timeCKKStoFHEWSetup(0.0), timeCKKStoFHEWEval(0.0);

    // Step 1: Setup CryptoContext for CKKS to be switched into

    // A. Specify main parameters
    /* A1) Multiplicative depth: has to allow for scheme switching
    */
    uint32_t multDepth = 1 + 8 + 3 + 1;  // for r = 3 in FHEWtoCKKS, Chebyshev eval depth allowed is 8

    /* A2) Bit-length of scaling factor.
    */
    uint32_t scaleModSize = 50;
    uint32_t ringDim      = 65536;
    SecurityLevel sl      = HEStd_128_classic;  // If this is not HEStd_NotSet, ensure ringDim is compatible
    uint32_t logQ_ccLWE   = 23;

    /*Assumption: the CKKS ciphertext modulus when the switching is done (on the last level) has to be
    greater than the FHEW ciphertext modulus.*/

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(FIXEDMANUAL);  // Andreea: currently, we only support scaling for FIXED
    // parameters.SetSecurityLevel(sl);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(ringDim);

    /* A3) Number of plaintext slots used in the ciphertext.
  */
    // uint32_t slots = ringDim/2; // fully-packed
    uint32_t slots     = 16;  // sparsely-packed
    uint32_t batchSize = slots;
    parameters.SetBatchSize(batchSize);

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

    bool arbFunc = false;  // flag for generating binfhe context for arbitrary functions, leads to larger parameters
                           // LWE cryptocontext
    auto ccLWE = BinFHEContext();
    if (sl == HEStd_128_classic)
        ccLWE.BinFHEContext::GenerateBinFHEContext(STD128, arbFunc, logQ_ccLWE, 0, GINX, false);
    else
        ccLWE.BinFHEContext::GenerateBinFHEContext(TOY, arbFunc, logQ_ccLWE, 0, GINX, false);

    // LWE private key
    LWEPrivateKey lwesk;
    lwesk = ccLWE.KeyGen();

    uint32_t n = ccLWE.GetParams()->GetLWEParams()->Getn();

    std::cout << "FHEW scheme is using lattice parameter " << n;
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", ring dimension RGSW/RLWE " << ccLWE.GetParams()->GetLWEParams()->GetN();
    std::cout << ", and modulus q " << ccLWE.GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    auto pLWE1       = ccLWE.GetMaxPlaintextSpace().ConvertToInt();  // Small precision
    uint32_t pLWE2   = 256;                                          // Medium precision
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE.GetBeta().ConvertToInt();
    auto pLWE3       = modulus_LWE / (2 * beta);  // Large precision

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<int> x1 = {1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0};
    std::vector<int> x2 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    if (x1.size() < slots) {
        std::vector<int> zeros(slots - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
        x2.insert(x2.end(), zeros.begin(), zeros.end());
    }

    // Encrypt
    std::vector<LWECiphertext> ctxtsLWE1(
        slots);  // Andreea: It would be useful to add the p used for LWE encryption to the parameters, so we can automate things like selecting the post-scaling factor in FHEWtoCKKS
    for (uint32_t i = 0; i < slots; i++) {
        ctxtsLWE1[i] =
            ccLWE.Encrypt(lwesk, x1[i]);  // encrypted under small plantext modulus p = 4 and ciphertext modulus
    }
    std::cout << "modulus from LWE ciphertext1 " << ctxtsLWE1[0]->GetModulus().ConvertToInt() << std::endl;

    std::vector<LWECiphertext> ctxtsLWE2(slots);
    for (uint32_t i = 0; i < slots; i++) {
        ctxtsLWE2[i] =
            ccLWE.Encrypt(lwesk, x1[i], FRESH,
                          pLWE1);  // encrypted under larger plaintext modulus p = 16 but small ciphertext modulus
    }
    std::cout << "modulus from LWE ciphertext2 " << ctxtsLWE2[0]->GetModulus().ConvertToInt() << std::endl;

    std::vector<LWECiphertext> ctxtsLWE3(slots);
    for (uint32_t i = 0; i < slots; i++) {
        ctxtsLWE3[i] =
            ccLWE.Encrypt(lwesk, x2[i], FRESH, pLWE2,
                          modulus_LWE);  // encrypted under larger plaintext modulus and large ciphertext modulus
    }
    std::cout << "modulus from LWE ciphertext3 " << ctxtsLWE3[0]->GetModulus().ConvertToInt() << std::endl;

    std::vector<LWECiphertext> ctxtsLWE4(slots);
    for (uint32_t i = 0; i < slots; i++) {
        ctxtsLWE4[i] =
            ccLWE.Encrypt(lwesk, x2[i], FRESH, pLWE3,
                          modulus_LWE);  // encrypted under large plaintext modulus and large ciphertext modulus
    }
    std::cout << "modulus from LWE ciphertext4 " << ctxtsLWE4[0]->GetModulus().ConvertToInt() << std::endl;

    std::cout << "\n---Input x1: " << x1 << "---" << std::endl;
    std::cout << "FHEW decryption under p = " << 4 << ": ";
    LWEPlaintext result;
    for (uint32_t i = 0; i < ctxtsLWE1.size(); ++i) {
        ccLWE.Decrypt(lwesk, ctxtsLWE1[i], &result);  // Small precision, works only for messages that are bits
        std::cout << result << " ";
    }
    std::cout << "\n" << std::endl;

    // Step 4. Precompute the necessary keys and information for switching from FHEW to CKKS
    TIC(t);
    cc->EvalFHEWtoCKKSSetup(ccLWE, slots, logQ_ccLWE);
    timeCKKStoFHEWSetup = TOC(t);
    std::cout << "Time to compute the FHEW to CKKS setup: " << timeCKKStoFHEWSetup << " ms" << std::endl;

    TIC(t);
    cc->EvalFHEWtoCKKSKeyGen(keys, lwesk);
    timeCKKStoFHEWKeyGen = TOC(t);
    std::cout << "Time to generate the FHEW to CKKS keys: " << timeCKKStoFHEWKeyGen << " ms" << std::endl;

    // Step 5. Perform the scheme switching
    // Set the scaling factor to be able to decrypt in CKKS
    double scale = 1.0 / ctxtsLWE1[0]->GetModulus().ConvertToInt();
    TIC(t);
    auto cTemp         = cc->EvalFHEWtoCKKS(ctxtsLWE1, scale, slots);
    timeCKKStoFHEWEval = TOC(t);
    std::cout << "Time to switch from FHEW to CKKS: " << timeCKKStoFHEWEval << " ms" << std::endl;

    // Step 6. Decrypt
    Plaintext plaintextDec;
    cc->Decrypt(keys.secretKey, cTemp, &plaintextDec);
    plaintextDec->SetLength(2 * slots);
    std::cout << "Switched CKKS decryption 1: " << plaintextDec << std::endl;

    std::cout << "\n---Input x1: " << x1 << "---" << std::endl;
    std::cout << "FHEW decryption under p = " << pLWE1 << ": ";
    for (uint32_t i = 0; i < ctxtsLWE2.size(); ++i) {
        ccLWE.Decrypt(lwesk, ctxtsLWE2[i], &result, pLWE1);  // Small precision, works only for messages that are bits
        std::cout << result << " ";
    }
    std::cout << "\n" << std::endl;

    // Step 5. Perform the scheme switching
    // Set the scaling factor to be able to decrypt in CKKS
    scale = 1.0 / ctxtsLWE2[0]->GetModulus().ConvertToInt();
    TIC(t);
    cTemp              = cc->EvalFHEWtoCKKS(ctxtsLWE2, scale, slots, 0, pLWE1);
    timeCKKStoFHEWEval = TOC(t);
    std::cout << "Time to switch from FHEW to CKKS: " << timeCKKStoFHEWEval << " ms" << std::endl;

    // Step 6. Decrypt
    cc->Decrypt(keys.secretKey, cTemp, &plaintextDec);
    plaintextDec->SetLength(2 * slots);
    std::cout << "Switched CKKS decryption 2: " << plaintextDec << std::endl;

    std::cout << "\n---Input x2: " << x2 << "---" << std::endl;
    std::cout << "FHEW decryption under p = " << pLWE2 << ": ";
    for (uint32_t i = 0; i < ctxtsLWE3.size(); ++i) {
        ccLWE.Decrypt(lwesk, ctxtsLWE3[i], &result, pLWE2);
        std::cout << result << " ";
    }
    std::cout << "\n" << std::endl;

    // Step 5. Perform the scheme switching
    // Set the scaling factor to be able to decrypt in CKKS
    scale = 1.0 / ctxtsLWE3[0]->GetModulus().ConvertToInt();
    TIC(t);
    cTemp              = cc->EvalFHEWtoCKKS(ctxtsLWE3, scale, slots, 0, pLWE2);
    timeCKKStoFHEWEval = TOC(t);
    std::cout << "Time to switch from FHEW to CKKS: " << timeCKKStoFHEWEval << " ms" << std::endl;

    // Step 6. Decrypt
    cc->Decrypt(keys.secretKey, cTemp, &plaintextDec);
    plaintextDec->SetLength(2 * slots);
    std::cout << "Switched CKKS decryption 3: " << plaintextDec << std::endl;

    std::cout << "\n---Input x2: " << x2 << "---" << std::endl;
    std::cout << "FHEW decryption under p = " << pLWE3 << ": ";
    for (uint32_t i = 0; i < ctxtsLWE4.size(); ++i) {
        ccLWE.Decrypt(lwesk, ctxtsLWE4[i], &result, pLWE3);
        std::cout << result << " ";
    }
    std::cout << "\n" << std::endl;

    // Step 5. Perform the scheme switching
    // Set the scaling factor to be able to decrypt in CKKS
    scale = 1.0 / ctxtsLWE4[0]->GetModulus().ConvertToInt();
    TIC(t);
    auto cTemp2        = cc->EvalFHEWtoCKKS(ctxtsLWE4, scale, slots, 0, pLWE3);
    timeCKKStoFHEWEval = TOC(t);
    std::cout << "Time to switch from FHEW to CKKS: " << timeCKKStoFHEWEval << " ms" << std::endl;

    // Step 6. Decrypt
    Plaintext plaintextDec2;
    cc->Decrypt(keys.secretKey, cTemp2, &plaintextDec2);
    plaintextDec2->SetLength(2 * slots);
    std::cout << "For a large ratio p/q (e.g., in TOY security), results might not be correct. " << std::endl;
    std::cout << "Switched CKKS decryption 4: " << plaintextDec2 << std::endl;

    std::cout << "\nTotal time: " << TOC(tTotal) << " ms" << std::endl;

    // double a = -128;
    // double b = 128;
    // int degree = 160;
    // auto coefficients = EvalChebyshevCoefficients([](double x) -> double { return (1.0/std::pow(2*Pi,1.0/8.0))*std::cos(2*Pi/8*(x-0.25)); }, a, b, degree);
    // std::cout.precision(16);
    // std::cout << "\n";
    // std::cout << "coefficients of size " << coefficients.size() << ": " << std::endl;
    // for (uint32_t i = 0; i < coefficients.size(); i++) {
    //     std::cout << coefficients[i] << ", ";
    //     if ((i+1) % 4 == 0){
    //         std::cout << "\n";
    //     }
    // }
    // std::cout << std::endl << std::endl;
}
