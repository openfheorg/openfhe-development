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
void FloorViaSchemeSwitching();
void ComparisonViaSchemeSwitching();
void ArbitraryFuncViaSchemeSwitching();
void IteratedSchemeSwitching();
void ArgminViaSchemeSwitching();
void ArgminViaSchemeSwitchingAlt();
void ArgminViaSchemeSwitchingUnit();
void ArgminViaSchemeSwitchingAltUnit();

int main() {
    // SwitchCKKSToFHEW();
    // SwitchFHEWtoCKKS();
    // FloorViaSchemeSwitching();
    // ComparisonViaSchemeSwitching();
    // ArbitraryFuncViaSchemeSwitching();
    // IteratedSchemeSwitching();
    ArgminViaSchemeSwitching();
    ArgminViaSchemeSwitchingAlt();
    ArgminViaSchemeSwitchingUnit();
    ArgminViaSchemeSwitchingAltUnit();

    return 0;
}

void SwitchCKKSToFHEW() {
    std::cout << "\n-----SwitchCKKSToFHEW-----\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS

    // A. Specify main parameters
    /* A1) Multiplicative depth:
    */
    uint32_t multDepth = 3;

    /* A2) Bit-length of scaling factor.
    */
    uint32_t firstModSize = 60;
    uint32_t scaleModSize = 50;
    uint32_t ringDim      = 8192;  // 65536;  // 2048;  //
    SecurityLevel sl =
        HEStd_NotSet;  // HEStd_128_classic;  // If this is not HEStd_NotSet, ensure ringDim is compatible
    uint32_t logQ_ccLWE = 25;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(FIXEDMANUAL);
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
        sl, false, logQ_ccLWE, false,
        slots);  // Andreea: it would help to have a method to extract the cryptocontext from the privateKey
    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;
    cc->EvalCKKStoFHEWKeyGen(keys, privateKeyFHEW);

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE.GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", ring dimension RGSW/RLWE " << ccLWE.GetParams()->GetLWEParams()->GetN();
    std::cout << ", modulus q, " << ccLWE.GetParams()->GetLWEParams()->Getq();
    std::cout << " and bootstrapping modulus " << ccLWE.GetParams()->GetLWEParams()->GetQ() << std::endl << std::endl;

    std::cout << ccLWE.GetParams()->GetLWEParams()->GetQ().Mod(ccLWE.GetParams()->GetLWEParams()->GetN()) << std::endl;
    std::cout << ccLWE.GetParams()->GetLWEParams()->GetQ().Mod(2 * ccLWE.GetParams()->GetLWEParams()->GetN())
              << std::endl
              << std::endl;

    // Set the scaling factor to be able to decrypt
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());

    // Get the last ciphertext modulus; this assumes the LWE mod switch will be performed on the ciphertext at the last level
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ                                  = elementParams.GetParams();
    // usint sizeQ = paramsQ.size();
    // for (size_t i = 0; i < sizeQ; i++) {
    //     std::cout << paramsQ[i]->GetModulus() << std::endl;
    // }
    auto modulus_CKKS_from = paramsQ[0]->GetModulus();

    auto pLWE1       = ccLWE.GetMaxPlaintextSpace().ConvertToInt();  // Small precision
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE.GetBeta().ConvertToInt();
    auto pLWE2       = modulus_LWE / (2 * beta);  // Large precision
    std::cout << "Decryption with small precision is done with plaintext modulus = " << pLWE1 << std::endl;
    std::cout << "Decryption with larger precision is done with plaintext modulus = " << pLWE2 << std::endl;

    double scFactor = cryptoParams->GetScalingFactorReal(0);
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        scFactor = cryptoParams->GetScalingFactorReal(1);
    std::cout << "scFactor = " << scFactor << ", GetScalingFactorReal(1) = " << cryptoParams->GetScalingFactorReal(1)
              << std::endl;
    double scale1 = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE1);
    double scale2 = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE2);

    // // Test no scaling but fixed plaintext modulus = Q/Delta
    // scale1 = 1;
    // scale2 = 1;
    // pLWE1 = 1 << (firstModSize - scaleModSize);
    // pLWE2 = 1 << (firstModSize - scaleModSize);

    cc->EvalCKKStoFHEWPrecompute(scale1);

    // Step 3: Encoding and encryption of inputs

    // Inputs
    // std::vector<std::complex<double>> x1 = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7,
    //                                         0.8, 0.9, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0};
    std::vector<double> x1 = {0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 16.0};
    // std::transform(x1.begin(), x1.end(), x1.begin(),
    //              [&](const double& elem)
    //              {return elem/pLWE1;});
    // if (x1.size() < slots) { // To test correctness of full packing
    //     std::vector<double> ones(slots - x1.size(), 1.0);
    //     x1.insert(x1.end(), ones.begin(), ones.end());
    // }
    std::vector<double> x2 = {0.0, 271.0, 30000.0, static_cast<double>(pLWE2) - 2};
    //   std::transform(x2.begin(), x2.end(), x2.begin(),
    //                  [&](const double& elem)
    //                  {return elem/static_cast<double>(pLWE2);});

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr);
    Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    auto c2 = cc->Encrypt(keys.publicKey, ptxt2);

    // std::cout << "Total number of towers in the ciphertext: " << c1->GetElements()[0].GetNumOfElements() << std::endl;

    // Step 4: Scheme switching from CKKS to FHEW

    // Transform the ciphertext from CKKS to FHEW
    auto cTemp = cc->EvalCKKStoFHEW(c1);

    std::cout << "\n---Decrypting switched ciphertext small precision---\n" << std::endl;

    std::cout << "Input x1: " << ptxt1->GetCKKSPackedValue() << std::endl;
    std::cout << "FHEW decryption: ";
    LWEPlaintext result;
    for (uint32_t i = 0; i < cTemp.size(); ++i) {
        ccLWE.Decrypt(privateKeyFHEW, cTemp[i], &result, pLWE1);  // Small precision
        std::cout << result << " ";
    }
    std::cout << "\n" << std::endl;

    // Scale the matrix differently
    cc->EvalCKKStoFHEWPrecompute(scale2);

    // Transform the ciphertext from CKKS to FHEW
    auto cTemp2 = cc->EvalCKKStoFHEW(c2, 4);

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

    pLWE1 = ccLWE.GetMaxPlaintextSpace().ConvertToInt();
    // pLWE2       = modulus_LWE / (2 * beta);
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
    std::cout << "\n-----SwitchFHEWtoCKKS-----\n" << std::endl;

    TimeVar t, tTotal;

    TIC(tTotal);

    double timeCKKStoFHEWKeyGen(0.0), timeCKKStoFHEWSetup(0.0), timeCKKStoFHEWEval(0.0);

    // Step 1: Setup CryptoContext for CKKS to be switched into

    // A. Specify main parameters
    /* A1) Multiplicative depth: has to allow for scheme switching
    */
    uint32_t multDepth =
        1 + 9 + 3;  // for r = 3 in FHEWtoCKKS, Chebyshev eval depth allowed is 9, 2 more levels for postscaling

    /* A2) Bit-length of scaling factor.
    */
    uint32_t scaleModSize = 50;
    uint32_t ringDim      = 8192;  // 16384;  // 65536;
    SecurityLevel sl =
        HEStd_NotSet;  // HEStd_128_classic;  // If this is not HEStd_NotSet, ensure ringDim is compatible
    uint32_t logQ_ccLWE = 29;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(FIXEDAUTO);
    parameters.SetSecurityLevel(sl);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(ringDim);

    /* A3) Number of plaintext slots used in the ciphertext.
  */
    // uint32_t slots = ringDim/2; // fully-packed
    uint32_t slots = 16;  // sparsely-packed
    // uint32_t batchSize = slots;
    // parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(SCHEMESWITCH);
    cc->Enable(FHE);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", number of slots " << slots << ", and suports a multiplicative depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching

    bool arbFunc = false;  // flag for generating binfhe context for arbitrary functions

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
    LWEPlaintext result;
    std::cout << "FHEW decryption under p = " << 4 << ": ";
    for (uint32_t i = 0; i < ctxtsLWE1.size(); ++i) {
        ccLWE.Decrypt(lwesk, ctxtsLWE1[i], &result, 4);  // Small precision, works only for messages that are bits
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
    double scale = 1.0 / ctxtsLWE1[0]->GetModulus().ConvertToDouble();
    TIC(t);
    auto cTemp         = cc->EvalFHEWtoCKKS(ctxtsLWE1, scale, slots, slots);
    timeCKKStoFHEWEval = TOC(t);
    std::cout << "Time to switch from FHEW to CKKS: " << timeCKKStoFHEWEval << " ms" << std::endl;

    // Step 6. Decrypt
    // cTemp = cc->Compress(cTemp);
    Plaintext plaintextDec;
    cc->Decrypt(keys.secretKey, cTemp, &plaintextDec);
    plaintextDec->SetLength(slots);
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
    scale = 1.0 / ctxtsLWE2[0]->GetModulus().ConvertToDouble();
    TIC(t);
    cTemp              = cc->EvalFHEWtoCKKS(ctxtsLWE2, scale, slots, slots, pLWE1, 0, pLWE1);
    timeCKKStoFHEWEval = TOC(t);
    std::cout << "Time to switch from FHEW to CKKS: " << timeCKKStoFHEWEval << " ms" << std::endl;

    // Step 6. Decrypt
    cc->Decrypt(keys.secretKey, cTemp, &plaintextDec);
    plaintextDec->SetLength(slots);
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
    scale = 1.0 / ctxtsLWE3[0]->GetModulus().ConvertToDouble();
    TIC(t);
    cTemp              = cc->EvalFHEWtoCKKS(ctxtsLWE3, scale, slots, slots, pLWE2, 0, pLWE2);
    timeCKKStoFHEWEval = TOC(t);
    std::cout << "Time to switch from FHEW to CKKS: " << timeCKKStoFHEWEval << " ms" << std::endl;

    // Step 6. Decrypt
    cc->Decrypt(keys.secretKey, cTemp, &plaintextDec);
    plaintextDec->SetLength(slots);
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
    scale = 1.0 / ctxtsLWE4[0]->GetModulus().ConvertToDouble();
    // std::cout << std::fixed << std::endl;
    std::setprecision(logQ_ccLWE + 10);
    std::cout << "scale = " << scale << std::endl;
    TIC(t);
    auto cTemp2        = cc->EvalFHEWtoCKKS(ctxtsLWE4, scale, slots, slots, pLWE3, 0, pLWE3);
    timeCKKStoFHEWEval = TOC(t);
    std::cout << "Time to switch from FHEW to CKKS: " << timeCKKStoFHEWEval << " ms" << std::endl;

    // Step 6. Decrypt
    Plaintext plaintextDec2;
    cc->Decrypt(keys.secretKey, cTemp2, &plaintextDec2);
    plaintextDec2->SetLength(ringDim / 2);
    std::cout << "Switched CKKS decryption 4: " << plaintextDec2 << std::endl;

    std::cout << "\nTotal time: " << TOC(tTotal) << " ms" << std::endl;

    // double a = -128;
    // double b = 128;
    // int degree = 119;
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

void FloorViaSchemeSwitching() {
    std::cout << "\n-----FloorViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back." << std::endl;

    TimeVar t, tTotal;

    TIC(tTotal);

    double timeKeyGen(0.0), timeSetup(0.0), timePrecomp(0.0), timeEval(0.0);

    // Step 1: Setup CryptoContext for CKKS

    // A. Specify main parameters
    /* A1) Multiplicative depth:
    */
    ScalingTechnique scTech = FLEXIBLEAUTOEXT;

    uint32_t multDepth = 9 + 3 + 2;  // 1 for CKKS to FHEW, 14 for FHEW to CKKS
    if (scTech == FLEXIBLEAUTOEXT)
        multDepth += 1;

    /* A2) Bit-length of scaling factor.
    */
    uint32_t scaleModSize = 50;
    uint32_t ringDim      = 8192;     // 32768;    // 65536;
    SecurityLevel sl = HEStd_NotSet;  // HEStd_128_classic; // If this is not HEStd_NotSet, ensure ringDim is compatible
    uint32_t logQ_ccLWE = 23;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(scTech);
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
    std::cout << ", number of slots " << slots << ", and suports a multiplicative depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    TIC(t);
    auto FHEWparams = cc->EvalSchemeSwitchingSetup(
        sl, false, logQ_ccLWE, false,
        slots);  // Andreea: it would help to have a method to extract the cryptocontext from the privateKey
    timeSetup = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << timeSetup << " ms" << std::endl;

    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;

    TIC(t);
    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW);
    timeKeyGen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << timeKeyGen << " ms" << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE.GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE << ", Q = " << (1 << logQ_ccLWE);
    std::cout << ", ring dimension RGSW/RLWE " << ccLWE.GetParams()->GetLWEParams()->GetN();
    std::cout << ", and modulus q " << ccLWE.GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    // Set the scaling factor to be able to decrypt
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());

    // Get the last ciphertext modulus; this assumes the LWE mod switch will be performed on the ciphertext at the last level
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ                                  = elementParams.GetParams();
    auto modulus_CKKS_from                        = paramsQ[0]->GetModulus();
    // std::cout << "current modulus in CKKS: " << modulus_CKKS_from << ", to Int: " << modulus_CKKS_from.ConvertToInt() << std::endl;

    auto pLWE1       = ccLWE.GetMaxPlaintextSpace().ConvertToInt();  // Small precision
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE.GetBeta().ConvertToInt();
    auto pLWE2       = modulus_LWE / (2 * beta);  // Large precision
    std::cout << "Decryption with small precision is done with plaintext modulus = " << pLWE1 << std::endl;
    std::cout << "Decryption with larger precision is done with plaintext modulus = " << pLWE2 << std::endl;

    double scFactor = cryptoParams->GetScalingFactorReal(0);
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        scFactor = cryptoParams->GetScalingFactorReal(1);
    // double scaleCF   = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE1);
    double scaleCF = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE2);

    TIC(t);
    cc->EvalCKKStoFHEWPrecompute(scaleCF);
    timePrecomp = TOC(t);
    std::cout << "Time to do the precomputations: " << timePrecomp << " ms" << std::endl;

    // Step 3: Encoding and encryption of inputs

    uint32_t bits = 1;

    // Inputs
    std::vector<double> x1 = {0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0};

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    // Step 4: Scheme switching from CKKS to FHEW

    // Transform the ciphertext from CKKS to FHEW
    TIC(t);
    auto cTemp = cc->EvalCKKStoFHEW(c1);
    timeEval   = TOC(t);
    std::cout << "Time to compute the switch from CKKS to FHEW: " << timeEval << " ms" << std::endl;

    std::cout << "Input x1: " << ptxt1->GetRealPackedValue() << std::endl;
    LWEPlaintext result;
    std::cout << "\nFHEW decryption pLWE2: ";
    for (uint32_t i = 0; i < cTemp.size(); ++i) {
        ccLWE.Decrypt(privateKeyFHEW, cTemp[i], &result, pLWE2);  // Large precision
        std::cout << result << " ";
    }

    /* Evaluate the floor function
    */
    std::cout << "\n\n---EVALUATE THE FLOOR FUNCTION---\n\n";

    ccLWE.BTKeyGen(privateKeyFHEW);
    cc->EvalMultKeyGen(keys.secretKey);

    std::vector<LWECiphertext> cFloor(cTemp.size());
    for (uint32_t i = 0; i < cTemp.size(); i++) {
        cFloor[i] = ccLWE.EvalFloor(cTemp[i], bits);
    }
    timeEval = TOC(t);
    std::cout << "Time to evaluate the floor: " << timeEval << " ms" << std::endl;

    std::cout << "\n---Decrypting the floored inputs---\n" << std::endl;

    std::cout << "Expected result: ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << (static_cast<int>(ptxt1->GetRealPackedValue()[i]) >> bits) << " ";
    }
    LWEPlaintext pFloor;
    std::cout << "\nFHEW decryption p = " << pLWE2 << "/(1 << bits) = " << pLWE2 / (1 << bits) << ": ";
    for (uint32_t i = 0; i < cFloor.size(); ++i) {
        ccLWE.Decrypt(privateKeyFHEW, cFloor[i], &pFloor, pLWE2 / (1 << bits));  // Larger precision
        std::cout << pFloor << " ";
    }
    std::cout << "\nFHEW decryption p = " << pLWE1 << "/(1 << bits) = " << pLWE1 / (1 << bits) << ": ";
    for (uint32_t i = 0; i < cFloor.size(); ++i) {
        ccLWE.Decrypt(privateKeyFHEW, cFloor[i], &pFloor, pLWE1 / (1 << bits));  // Smaller precision
        std::cout << pFloor << " ";
    }
    std::cout << "\n" << std::endl;

    // Set the scaling factor to be able to decrypt in CKKS
    double scale = 1.0 / modulus_LWE;
    TIC(t);
    auto cTemp2 = cc->EvalFHEWtoCKKS(cFloor, scale, slots, slots, pLWE2 / (1 << bits), 0, pLWE2 / (1 << bits));
    timeEval    = TOC(t);
    std::cout << "Time to switch from FHEW to CKKS: " << timeEval << " ms" << std::endl;

    Plaintext plaintextDec2;
    cc->Decrypt(keys.secretKey, cTemp2, &plaintextDec2);
    plaintextDec2->SetLength(slots);
    std::cout << "Switched floor decryption modulus_LWE mod " << pLWE2 / (1 << bits) << ": " << plaintextDec2
              << std::endl;

    // Set the scaling factor to be able to decrypt in CKKS
    scale = 1.0 / modulus_LWE;
    TIC(t);
    cTemp2   = cc->EvalFHEWtoCKKS(cFloor, scale, slots, slots, pLWE1 / (1 << bits), 0, pLWE1 / (1 << bits));
    timeEval = TOC(t);
    std::cout << "Time to switch from FHEW to CKKS: " << timeEval << " ms" << std::endl;

    cc->Decrypt(keys.secretKey, cTemp2, &plaintextDec2);
    plaintextDec2->SetLength(slots);
    std::cout << "Switched floor decryption modulus_LWE mod " << pLWE1 / (1 << bits) << ": " << plaintextDec2
              << std::endl;

    /* Evaluate the sign function
    */
    std::cout << "\n\n---EVALUATE THE SIGN FUNCTION---\n\n";

    scaleCF = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE1);
    // scaleCF   = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE2);

    TIC(t);
    cc->EvalCKKStoFHEWPrecompute(scaleCF);
    timePrecomp = TOC(t);
    std::cout << "Time to do the precomputations: " << timePrecomp << " ms" << std::endl;

    // Transform the ciphertext from CKKS to FHEW
    TIC(t);
    auto cTemp3 = cc->EvalCKKStoFHEW(c1);
    timeEval    = TOC(t);
    std::cout << "Time to compute the switch from CKKS to FHEW: " << timeEval << " ms" << std::endl;

    std::cout << "Input x1: " << ptxt1->GetRealPackedValue() << std::endl;
    std::cout << "FHEW decryption pLWE1: ";
    LWEPlaintext result2;
    for (uint32_t i = 0; i < cTemp3.size(); ++i) {
        ccLWE.Decrypt(privateKeyFHEW, cTemp3[i], &result2, pLWE1);  // Small precision
        std::cout << result2 << " ";
    }
    std::cout << "\n" << std::endl;

    // Evaluate the sign for decryption in FHEW
    std::vector<LWECiphertext> cSigns(cTemp3.size());
    for (uint32_t i = 0; i < cTemp3.size(); i++) {
        cSigns[i] = ccLWE.EvalSign(cTemp3[i], false);
    }
    timeEval = TOC(t);
    std::cout << "Time to evaluate the sign: " << timeEval << " ms" << std::endl;

    std::cout << "\n---Decrypting signs of inputs---\n" << std::endl;

    std::cout << "Expected result: ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << int(ptxt1->GetRealPackedValue()[i] - pLWE1 / 2 > 0) << " ";
    }
    std::cout << "\nFHEW decryption p = 2: ";
    LWEPlaintext pSigns;
    for (uint32_t i = 0; i < cSigns.size(); ++i) {
        ccLWE.Decrypt(privateKeyFHEW, cSigns[i], &pSigns, 2);  // Small precision
        std::cout << pSigns << " ";
    }
    std::cout << "\n" << std::endl;

    // Evaluate the sign for decryption in CKKS
    for (uint32_t i = 0; i < cTemp3.size(); i++) {
        cSigns[i] = ccLWE.EvalSign(cTemp3[i], true);
    }
    timeEval = TOC(t);
    std::cout << "Time to evaluate the sign: " << timeEval << " ms" << std::endl;

    // Set the scaling factor to be able to decrypt in CKKS
    // scale = 1.0 / modulus_LWE;
    scale = 1.0 / cSigns[0]->GetModulus().ConvertToInt();
    TIC(t);
    auto cTemp4 = cc->EvalFHEWtoCKKS(cSigns, scale, slots, slots, 4, -1.0, 1.0);
    timeEval    = TOC(t);
    std::cout << "Time to switch from FHEW to CKKS: " << timeEval << " ms" << std::endl;

    Plaintext plaintextDec3;
    cc->Decrypt(keys.secretKey, cTemp4, &plaintextDec3);
    plaintextDec3->SetLength(slots);
    std::cout << "Switched sign decryption modulus_LWE mod 4: " << plaintextDec3 << std::endl;
}

void ComparisonViaSchemeSwitching() {
    std::cout << "\n-----ComparisonViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back." << std::endl;

    TimeVar t, tTotal;

    TIC(tTotal);

    double timeKeyGen(0.0), timeSetup(0.0), timePrecomp(0.0), timeEval(0.0);

    // Step 1: Setup CryptoContext for CKKS

    // A. Specify main parameters
    /* A1) Multiplicative depth:
    */
    ScalingTechnique scTech = FIXEDAUTO;
    uint32_t multDepth      = 1 + 9 + 3 + 1 + 1;  // 1 for CKKS to FHEW, 14 for FHEW to CKKS + 1 to test
    if (scTech == FLEXIBLEAUTOEXT)
        multDepth += 1;
    /* A2) Bit-length of scaling factor.
    */
    uint32_t scaleModSize = 50;
    uint32_t firstModSize = 60;
    uint32_t ringDim      = 16384;         // 65536; //
    SecurityLevel sl      = HEStd_NotSet;  // HEStd_128_classic; //
    uint32_t logQ_ccLWE   = 20;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(scTech);
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
    std::cout << ", number of slots " << slots << ", and suports a multiplicative depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    TIC(t);
    auto FHEWparams = cc->EvalSchemeSwitchingSetup(
        sl, false, logQ_ccLWE, false,
        slots);  // Andreea: it would help to have a method to extract the cryptocontext from the privateKey
    timeSetup = TOC(t);

    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;

    TIC(t);
    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW);
    timeKeyGen = TOC(t);

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE.GetParams()->GetLWEParams()->Getn();
    std::cout << ", Q = " << (1 << logQ_ccLWE);
    std::cout << ", ring dimension RGSW/RLWE " << ccLWE.GetParams()->GetLWEParams()->GetN();
    std::cout << ", and modulus q " << ccLWE.GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    std::cout << "Time to compute the scheme switching setup: " << timeSetup << " ms" << std::endl;
    std::cout << "Time to compute the scheme switching key generation: " << timeKeyGen << " ms" << std::endl
              << std::endl;

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1 = {0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0};
    std::vector<double> x2(slots, 5.25);

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr);
    Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    auto c2 = cc->Encrypt(keys.publicKey, ptxt2);

    // Compute the difference to compare to zero
    auto cDiff = cc->EvalSub(c1, c2);

    // Step 4: Sign evaluation

    auto pLWE1       = ccLWE.GetMaxPlaintextSpace().ConvertToInt();  // Small precision
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE.GetBeta().ConvertToInt();
    auto pLWE2       = modulus_LWE / (2 * beta);  // Large precision

    double scaleSignFHEW = 1.0;
    ccLWE.BTKeyGen(privateKeyFHEW);  // For computing sign here

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());

    TIC(t);
    uint32_t init_level = 0;
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        init_level = 1;
    cc->EvalCompareSSPrecompute(pLWE2, init_level, scaleSignFHEW);
    timePrecomp = TOC(t);
    std::cout << "Time to perform precomputations: " << timePrecomp << " ms" << std::endl;

    Plaintext pDiff;
    cc->Decrypt(keys.secretKey, cDiff, &pDiff);
    pDiff->SetLength(slots);
    std::cout << "Difference of inputs: ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << pDiff->GetRealPackedValue()[i] << " ";
    }

    const double eps = 0.0001;
    std::cout << "\nExpected sign result from CKKS: ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << int(std::round(pDiff->GetRealPackedValue()[i] / eps) * eps < 0) << " ";
    }
    std::cout << "\n";

    TIC(t);
    auto LWECiphertexts = cc->EvalCKKStoFHEW(cDiff, slots);
    timeEval            = TOC(t);
    std::cout << "Time to perform comparisons in FHEW: " << timeEval << " ms" << std::endl;

    LWEPlaintext plainLWE;
    std::cout << "\nFHEW decryption with plaintext modulus " << pLWE2 << ": ";
    for (uint32_t i = 0; i < LWECiphertexts.size(); ++i) {
        ccLWE.Decrypt(privateKeyFHEW, LWECiphertexts[i], &plainLWE, pLWE2);
        std::cout << plainLWE << " ";
    }
    std::cout << "\nExpected sign result in FHEW with plaintext modulus " << pLWE2 << " and scale " << scaleSignFHEW
              << ": ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << (static_cast<int>(std::round(pDiff->GetRealPackedValue()[i] * scaleSignFHEW)) % pLWE2 -
                          pLWE2 / 2.0 >=
                      0)
                  << " ";
    }
    std::cout << "\n";

    std::cout << "Obtained sign result in FHEW with plaintext modulus " << pLWE2 << " and scale " << scaleSignFHEW
              << ": ";
    std::vector<LWECiphertext> LWESign(LWECiphertexts.size());
    for (uint32_t i = 0; i < LWECiphertexts.size(); ++i) {
        LWESign[i] = ccLWE.EvalSign(LWECiphertexts[i]);
        ccLWE.Decrypt(privateKeyFHEW, LWESign[i], &plainLWE, 2);
        std::cout << plainLWE << " ";
    }
    std::cout << "\n";

    TIC(t);
    // auto cResult = cc->EvalCompareSchemeSwitching(c1, c2, slots, slots, pLWE2, scaleSignFHEW);
    auto cResult = cc->EvalCompareSchemeSwitching(c1, c2, slots, slots);
    timeEval     = TOC(t);
    std::cout << "Time to perform comparison via scheme switching: " << timeEval << " ms" << std::endl;

    Plaintext plaintextDec3;
    cc->Decrypt(keys.secretKey, cResult, &plaintextDec3);
    plaintextDec3->SetLength(slots);
    std::cout << "Decrypted switched result: " << plaintextDec3 << std::endl;

    scaleSignFHEW = 8.0;
    TIC(t);
    cc->EvalCompareSSPrecompute(pLWE2, init_level, scaleSignFHEW);
    timePrecomp = TOC(t);
    std::cout << "\nTime to perform precomputations: " << timePrecomp << " ms" << std::endl;
    TIC(t);
    LWECiphertexts = cc->EvalCKKStoFHEW(cDiff, slots);
    timeEval       = TOC(t);
    std::cout << "Time to perform comparisons in FHEW: " << timeEval << " ms" << std::endl;

    std::cout << "\nFHEW decryption with plaintext modulus " << pLWE2 << " and scale " << scaleSignFHEW << ": ";
    for (uint32_t i = 0; i < LWECiphertexts.size(); ++i) {
        ccLWE.Decrypt(privateKeyFHEW, LWECiphertexts[i], &plainLWE, pLWE2);
        std::cout << plainLWE << " ";
    }
    std::cout << "\nExpected sign result in FHEW with plaintext modulus " << pLWE2 << " and scale " << scaleSignFHEW
              << ": ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << (static_cast<int>(std::round(pDiff->GetRealPackedValue()[i] * scaleSignFHEW)) % pLWE2 -
                          pLWE2 / 2.0 >=
                      0)
                  << " ";
    }
    std::cout << "\n";
    std::cout << "Obtained sign result in FHEW with plaintext modulus " << pLWE2 << " and scale " << scaleSignFHEW
              << ": ";
    for (uint32_t i = 0; i < LWECiphertexts.size(); ++i) {
        LWESign[i] = ccLWE.EvalSign(LWECiphertexts[i]);
        ccLWE.Decrypt(privateKeyFHEW, LWESign[i], &plainLWE, 2);
        std::cout << plainLWE << " ";
    }
    std::cout << "\n";

    TIC(t);
    cResult = cc->EvalCompareSchemeSwitching(c1, c2, slots, slots, pLWE2, scaleSignFHEW);
    // cResult  = cc->EvalCompareSchemeSwitching(c1, c2, slots, slots);
    timeEval = TOC(t);
    std::cout << "Time to perform comparison via scheme switching: " << timeEval << " ms" << std::endl;

    cc->Decrypt(keys.secretKey, cResult, &plaintextDec3);
    plaintextDec3->SetLength(slots);
    std::cout << "Decrypted switched result: " << plaintextDec3 << std::endl;

    std::cout
        << "\nFor very small LWE plaintext modulus and initial fractional inputs, the sign does not always behave properly close to the boundaries at 0 and p/2."
        << std::endl;
    scaleSignFHEW = 1.0;
    TIC(t);
    cc->EvalCompareSSPrecompute(pLWE1, init_level, scaleSignFHEW);

    // Test no scaling and automated FHEW plaintext modulus
    // cc->EvalCompareSSPrecompute(0, init_level, scaleSignFHEW);
    // pLWE1 = 1 << (firstModSize - scaleModSize);

    // // Test for message already scaled by pLWE
    // cDiff = cc->EvalMult(cDiff, 1.0 / static_cast<double>(pLWE1));
    // cDiff = cc->Rescale(cDiff);
    // cc->EvalCompareSSPrecompute(pLWE1, init_level, scaleSignFHEW, true);

    timePrecomp = TOC(t);
    std::cout << "\nTime to perform precomputations: " << timePrecomp << " ms" << std::endl;
    TIC(t);
    LWECiphertexts = cc->EvalCKKStoFHEW(cDiff, slots);
    timeEval       = TOC(t);
    std::cout << "Time to perform comparisons in FHEW: " << timeEval << " ms" << std::endl;

    std::cout << "\nFHEW decryption with plaintext modulus " << pLWE1 << ": ";
    for (uint32_t i = 0; i < LWECiphertexts.size(); ++i) {
        ccLWE.Decrypt(privateKeyFHEW, LWECiphertexts[i], &plainLWE, pLWE1);
        std::cout << plainLWE << " ";
    }
    std::cout << "\nExpected sign result in FHEW with plaintext modulus " << pLWE1 << " and scale " << scaleSignFHEW
              << ": ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << (static_cast<int>(std::round(pDiff->GetRealPackedValue()[i] * scaleSignFHEW)) % pLWE1 -
                          pLWE1 / 2.0 >=
                      0)
                  << " ";
    }
    std::cout << "\n";
    std::cout << "Obtained sign result in FHEW with plaintext modulus " << pLWE1 << " and scale " << scaleSignFHEW
              << ": ";
    for (uint32_t i = 0; i < LWECiphertexts.size(); ++i) {
        LWESign[i] = ccLWE.EvalSign(LWECiphertexts[i]);
        ccLWE.Decrypt(privateKeyFHEW, LWESign[i], &plainLWE, 2);
        std::cout << plainLWE << " ";
    }
    std::cout << "\n";

    TIC(t);
    cResult = cc->EvalCompareSchemeSwitching(c1, c2, slots, slots, 0, scaleSignFHEW);

    // // Test for messages to be scaled by pLWE
    // cResult  = cc->EvalCompareSchemeSwitching(c1, c2, slots, slots, pLWE1, scaleSignFHEW, true); // only for scaleSignFHEW = 1

    timeEval = TOC(t);
    std::cout << "Time to perform comparison via scheme switching: " << timeEval << " ms" << std::endl;

    cc->Decrypt(keys.secretKey, cResult, &plaintextDec3);
    plaintextDec3->SetLength(slots);
    std::cout << "Decrypted switched result: " << plaintextDec3 << std::endl;
}

void ArbitraryFuncViaSchemeSwitching() {
    std::cout << "\n-----ArbitraryFuncViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back." << std::endl;

    TimeVar t, tTotal;

    TIC(tTotal);

    double timeKeyGen(0.0), timeSetup(0.0), timePrecomp(0.0), timeEval(0.0);

    // Step 1: Setup CryptoContext for CKKS

    // A. Specify main parameters
    /* A1) Multiplicative depth:
    */
    uint32_t multDepth = 9 + 3 + 2;  // 1 for CKKS to FHEW, 14 for FHEW to CKKS

    /* A2) Bit-length of scaling factor.
    */
    uint32_t scaleModSize = 50;
    uint32_t ringDim      = 8192;     // 32768;    // 65536;
    SecurityLevel sl = HEStd_NotSet;  // HEStd_128_classic; // If this is not HEStd_NotSet, ensure ringDim is compatible
    uint32_t logQ_ccLWE = 23;
    bool arbFunc        = true;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);

    /* A3) Number of plaintext slots used in the ciphertext.
  */
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
    TIC(t);
    auto FHEWparams = cc->EvalSchemeSwitchingSetup(
        sl, arbFunc, logQ_ccLWE, false,
        slots);  // Andreea: it would help to have a method to extract the cryptocontext from the privateKey
    timeSetup = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << timeSetup << " ms" << std::endl;

    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;

    TIC(t);
    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW);
    timeKeyGen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << timeKeyGen << " ms" << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE.GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE << ", Q = " << (1 << logQ_ccLWE);
    std::cout << ", ring dimension RGSW/RLWE " << ccLWE.GetParams()->GetLWEParams()->GetN();
    std::cout << ", and modulus q " << ccLWE.GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    // Set the scaling factor to be able to decrypt
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());

    // Get the last ciphertext modulus; this assumes the LWE mod switch will be performed on the ciphertext at the last level
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ                                  = elementParams.GetParams();
    auto modulus_CKKS_from                        = paramsQ[0]->GetModulus();

    auto pLWE1 = ccLWE.GetMaxPlaintextSpace().ConvertToInt();  // Small precision

    double scFactor = cryptoParams->GetScalingFactorReal(0);
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        scFactor = cryptoParams->GetScalingFactorReal(1);
    double scaleCF = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE1);

    TIC(t);
    cc->EvalCKKStoFHEWPrecompute(scaleCF);
    timePrecomp = TOC(t);
    std::cout << "Time to do the precomputations: " << timePrecomp << " ms" << std::endl;

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1 = {0.0, 1.0, 2.0, 0.0, 1.0, 2.0, 0.0, 1.0, 2.0, 0.0, 1.0, 2.0, 1.0, 3.0, 5.0, 7.0};

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    // Step 4: Scheme switching from CKKS to FHEW

    // Transform the ciphertext from CKKS to FHEW
    TIC(t);
    auto cTemp = cc->EvalCKKStoFHEW(c1);
    timeEval   = TOC(t);
    std::cout << "Time to compute the switch from CKKS to FHEW: " << timeEval << " ms" << std::endl;

    std::cout << "Input x1: " << ptxt1->GetRealPackedValue() << std::endl;
    std::cout << "FHEW decryption pLWE1: ";
    LWEPlaintext result;
    for (uint32_t i = 0; i < cTemp.size(); ++i) {
        ccLWE.Decrypt(privateKeyFHEW, cTemp[i], &result, pLWE1);  // Small precision
        std::cout << result << " ";
    }

    // Step 5: Evaluate the arbitrary function

    // Initialize Function f(x) = x^3 % p
    auto fp = [](NativeInteger m, NativeInteger p1) -> NativeInteger {
        if (m < p1)
            return (m * m * m) % p1;
        else
            return ((m - p1 / 2) * (m - p1 / 2) * (m - p1 / 2)) % p1;
    };

    // Generate LUT from function f(x)
    auto lut = ccLWE.GenerateLUTviaFunction(fp, pLWE1);

    ccLWE.BTKeyGen(privateKeyFHEW);
    cc->EvalMultKeyGen(keys.secretKey);

    std::vector<LWECiphertext> cCube(cTemp.size());
    for (uint32_t i = 0; i < cTemp.size(); i++) {
        cCube[i] = ccLWE.EvalFunc(cTemp[i], lut);
    }
    std::cout << "\n";
    timeEval = TOC(t);
    std::cout << "Time to evaluate the cube: " << timeEval << " ms" << std::endl;

    std::cout << "\n---Decrypting the x^3 mod p inputs---\n" << std::endl;

    std::cout << "Expected result: ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << fp(static_cast<int>(x1[i]), pLWE1) << " ";
    }
    LWEPlaintext pCube;
    std::cout << "\nFHEW decryption mod p = " << pLWE1 << ": ";
    for (uint32_t i = 0; i < cCube.size(); ++i) {
        ccLWE.Decrypt(privateKeyFHEW, cCube[i], &pCube, pLWE1);  // Smaller precision
        std::cout << pCube << " ";
    }
    std::cout << "\n" << std::endl;

    // Step 5: Scheme switching from FHEW to CKKS
    double scale = 1.0 / cCube[0]->GetModulus().ConvertToInt();
    TIC(t);
    auto cTemp2 = cc->EvalFHEWtoCKKS(cCube, scale, slots, slots, pLWE1, 0, pLWE1);
    timeEval    = TOC(t);
    std::cout << "Time to switch from FHEW to CKKS: " << timeEval << " ms" << std::endl;

    std::cout << "The switched results are correct only for messages << p!" << std::endl;

    Plaintext plaintextDec2;
    cc->Decrypt(keys.secretKey, cTemp2, &plaintextDec2);
    plaintextDec2->SetLength(slots);
    std::cout << "Switched cube decryption modulus_LWE mod " << pLWE1 << ": " << plaintextDec2 << std::endl;

    // Set the scaling factor to be able to decrypt in CKKS
    scale = 1.0 / cCube[0]->GetModulus().ConvertToInt();
    TIC(t);
    cTemp2   = cc->EvalFHEWtoCKKS(cCube, scale, slots, slots, 4, 0, 2);
    timeEval = TOC(t);
    std::cout << "Time to switch from FHEW to CKKS: " << timeEval << " ms" << std::endl;

    cc->Decrypt(keys.secretKey, cTemp2, &plaintextDec2);
    plaintextDec2->SetLength(slots);

    std::cout << "Arcsin(switched result) * p/2pi gives the correct result if messages are < p/4 " << std::endl;
    for (uint32_t i = 0; i < slots; i++) {
        std::cout << std::asin(plaintextDec2->GetRealPackedValue()[i]) * pLWE1 / (2 * Pi) << " ";
    }
    std::cout << "\n";
}

void IteratedSchemeSwitching() {
    std::cout << "\n-----IteratedSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back." << std::endl;

    TimeVar t, tTotal;

    TIC(tTotal);

    double timeKeyGen(0.0), timeSetup(0.0), timePrecomp(0.0), timeEval(0.0);

    // Step 1: Setup CryptoContext for CKKS

    // A. Specify main parameters
    /* A1) Multiplicative depth:
    */
    ScalingTechnique scTech = FIXEDAUTO;

    uint32_t multDepth = 9 + 3 + 2;  // 1 for CKKS to FHEW, 14 for FHEW to CKKS
    if (scTech == FLEXIBLEAUTOEXT)
        multDepth += 1;
    /* A2) Bit-length of scaling factor.
    */
    uint32_t scaleModSize = 50;
    uint32_t ringDim      = 16384;    // 32768;    // 65536;
    SecurityLevel sl = HEStd_NotSet;  // HEStd_128_classic; // If this is not HEStd_NotSet, ensure ringDim is compatible
    uint32_t logQ_ccLWE = 26;
    bool arbFunc        = false;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(FLEXIBLEAUTOEXT);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);

    /* A3) Number of plaintext slots used in the ciphertext.
  */
    uint32_t numValues = 16;
    // uint32_t slots     = ringDim / 2;  // fully-packed
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
    std::cout << ", number of slots " << slots << ", and suports a multiplicative depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    TIC(t);
    auto FHEWparams = cc->EvalSchemeSwitchingSetup(
        sl, arbFunc, logQ_ccLWE, false,
        slots);  // Andreea: it would help to have a method to extract the cryptocontext from the privateKey
    timeSetup = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << timeSetup << " ms" << std::endl;

    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;

    TIC(t);
    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW, 0, 0, numValues);
    timeKeyGen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << timeKeyGen << " ms" << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE.GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE << ", Q = " << (1 << logQ_ccLWE);
    std::cout << ", ring dimension RGSW/RLWE " << ccLWE.GetParams()->GetLWEParams()->GetN();
    std::cout << ", and modulus q " << ccLWE.GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    // Set the scaling factor to be able to decrypt
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());

    // Get the last ciphertext modulus; this assumes the LWE mod switch will be performed on the ciphertext at the last level
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ                                  = elementParams.GetParams();
    auto modulus_CKKS_from                        = paramsQ[0]->GetModulus();

    // auto pLWE       = ccLWE.GetMaxPlaintextSpace().ConvertToInt();  // Small precision
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE.GetBeta().ConvertToInt();
    auto pLWE        = modulus_LWE / (2 * beta);  // Large precision

    double scFactor = cryptoParams->GetScalingFactorReal(0);
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        scFactor = cryptoParams->GetScalingFactorReal(1);
    double scaleCF = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE);

    TIC(t);
    cc->EvalCKKStoFHEWPrecompute(scaleCF);
    timePrecomp = TOC(t);
    std::cout << "Time to do the precomputations: " << timePrecomp << " ms" << std::endl;

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1 = {0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, -14.0, 500.0};
    if (x1.size() < slots) {
        std::vector<int> zeros(slots - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }
    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
    // Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr, slots);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    // Step 4: Scheme switching from CKKS to FHEW

    // Transform the ciphertext from CKKS to FHEW
    TIC(t);
    auto cTemp = cc->EvalCKKStoFHEW(c1, numValues);
    timeEval   = TOC(t);
    std::cout << "Time to compute the switch from CKKS to FHEW: " << timeEval << " ms" << std::endl;

    std::cout << "Input x1: " << ptxt1->GetRealPackedValue() << std::endl;
    std::cout << "FHEW decryption pLWE: ";
    LWEPlaintext result;
    for (uint32_t i = 0; i < cTemp.size(); ++i) {
        ccLWE.Decrypt(privateKeyFHEW, cTemp[i], &result, pLWE);
        std::cout << result << " ";
    }
    std::cout << "\n";

    // Step 5: Don't do anything to check the case where the decoding matrix is scaled by the same plaintext modulus

    cc->EvalMultKeyGen(keys.secretKey);

    LWEPlaintext pTemp;
    std::cout << "\nFHEW decryption mod p = " << pLWE << ": ";
    for (uint32_t i = 0; i < cTemp.size(); ++i) {
        ccLWE.Decrypt(privateKeyFHEW, cTemp[i], &pTemp, pLWE);
        std::cout << pTemp << " ";
    }
    std::cout << "\n" << std::endl;

    // Step 6: Scheme switching from FHEW to CKKS
    double scale = 1.0 / cTemp[0]->GetModulus().ConvertToInt();
    TIC(t);
    auto cTemp2 = cc->EvalFHEWtoCKKS(cTemp, scale, numValues, slots, pLWE, 0, pLWE);
    timeEval    = TOC(t);
    std::cout << "Time to switch from FHEW to CKKS: " << timeEval << " ms" << std::endl;

    Plaintext plaintextDec2;
    cc->Decrypt(keys.secretKey, cTemp2, &plaintextDec2);
    plaintextDec2->SetLength(slots * 2);
    std::cout << "Switched decryption modulus_LWE mod " << pLWE << ": " << plaintextDec2 << std::endl;

    std::cout << "Ciphertext level and depth at the end of scheme switching: " << cTemp2->GetLevel() << ", "
              << cTemp2->GetNoiseScaleDeg() << std::endl;

    // Step 7: Start the scheme switching again.

    std::cout << "---SECOND SCHEME SWITCHING---" << std::endl;

    // Transform the ciphertext from CKKS to FHEW
    TIC(t);
    cTemp    = cc->EvalCKKStoFHEW(c1, numValues);
    timeEval = TOC(t);
    std::cout << "Time to compute the switch from CKKS to FHEW: " << timeEval << " ms" << std::endl;

    std::cout << "Input x1: " << ptxt1->GetRealPackedValue() << std::endl;
    std::cout << "FHEW decryption pLWE: ";
    for (uint32_t i = 0; i < cTemp.size(); ++i) {
        ccLWE.Decrypt(privateKeyFHEW, cTemp[i], &result, pLWE);
        std::cout << result << " ";
    }

    std::cout << "\n";

    std::cout << "\nFHEW decryption mod p = " << pLWE << ": ";
    for (uint32_t i = 0; i < cTemp.size(); ++i) {
        ccLWE.Decrypt(privateKeyFHEW, cTemp[i], &pTemp, pLWE);
        std::cout << pTemp << " ";
    }
    std::cout << "\n" << std::endl;

    // Step 6: Scheme switching from FHEW to CKKS
    scale = 1.0 / cTemp[0]->GetModulus().ConvertToInt();
    TIC(t);
    cTemp2   = cc->EvalFHEWtoCKKS(cTemp, scale, numValues, slots, pLWE, 0, pLWE);
    timeEval = TOC(t);
    std::cout << "Time to switch from FHEW to CKKS: " << timeEval << " ms" << std::endl;

    cc->Decrypt(keys.secretKey, cTemp2, &plaintextDec2);
    plaintextDec2->SetLength(slots * 2);
    std::cout << "Switched decryption modulus_LWE mod " << pLWE << ": " << plaintextDec2 << std::endl;

    std::cout << "Ciphertext level and depth at the end of scheme switching: " << cTemp2->GetLevel() << ", "
              << cTemp2->GetNoiseScaleDeg() << std::endl;
}

void ArgminViaSchemeSwitching() {
    std::cout << "\n-----ArgminViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back." << std::endl;

    TimeVar t, tTotal;  //, tIter;

    TIC(tTotal);

    double timeKeyGen(0.0), timeSetup(0.0), timePrecomp(0.0), timeEval(0.0);  //, timeArgminIter(0.0);

    // Step 1: Setup CryptoContext for CKKS

    // A. Specify main parameters
    /* A1) Multiplicative depth:
    */
    /* A2) Bit-length of scaling factor.
    */
    uint32_t scaleModSize = 50;
    uint32_t firstModSize = 60;
    uint32_t ringDim      = 16384;         // 32768;         // 8192; //  65536; //
    SecurityLevel sl      = HEStd_NotSet;  // HEStd_128_classic; //
    uint32_t logQ_ccLWE   = 25;
    bool arbFunc          = false;
    bool oneHot           = true;

    /* A3) Number of plaintext slots used in the ciphertext.
  */
    // uint32_t slots = ringDim/2; // fully-packed
    uint32_t slots     = 64;  // sparsely-packed
    uint32_t batchSize = slots;
    // Have slots values encrypted but only want the argmin of the first numValues
    uint32_t numValues      = 64;
    ScalingTechnique scTech = FLEXIBLEAUTOEXT;
    uint32_t multDepth =
        1 + 8 + 3 + 1 +
        static_cast<int>(std::log2(numValues));  // 1 for CKKS to FHEW, 13 for FHEW to CKKS, log2(numValues) for argmin
    if (scTech == FLEXIBLEAUTOEXT)
        multDepth += 1;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
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
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    TIC(t);
    auto FHEWparams = cc->EvalSchemeSwitchingSetup(HEStd_128_classic, arbFunc, logQ_ccLWE, false, slots);
    timeSetup       = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << timeSetup << " ms" << std::endl;

    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;

    TIC(t);
    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW, 0, 0, numValues, oneHot);
    timeKeyGen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << timeKeyGen << " ms" << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE.GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE << ", Q = " << (1 << logQ_ccLWE);
    std::cout << ", ring dimension RGSW/RLWE " << ccLWE.GetParams()->GetLWEParams()->GetN();
    std::cout << ", and modulus q " << ccLWE.GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    // The minimum value at the end will also be scaled by scaleSign.
    double scaleSign = 512.0;

    // auto pLWE       = ccLWE.GetMaxPlaintextSpace().ConvertToInt();  // Small precision
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE.GetBeta().ConvertToInt();
    auto pLWE        = modulus_LWE / (2 * beta);  // Large precision

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    // //Get the last ciphertext modulus; this assumes the LWE mod switch will be performed on the ciphertext at the last level
    // ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    // auto paramsQ                                  = elementParams.GetParams();
    // auto modulus_CKKS_from                        = paramsQ[0]->GetModulus();
    // double scFactor = cryptoParams->GetScalingFactorReal(0);
    // if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
    // scFactor = cryptoParams->GetScalingFactorReal(1);
    // double scaleCF   = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE);

    TIC(t);
    // cc->EvalCKKStoFHEWPrecompute(scaleCF);
    uint32_t init_level = 0;
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        init_level = 1;
    // This formulation is for clarity
    // cc->EvalCompareSSPrecompute(pLWE, init_level, scaleSign);
    // But we can also include the scaleSign in pLWE (here we use the fact both pLWE and scaleSign are powers of two)
    cc->EvalCompareSSPrecompute(pLWE / scaleSign, init_level, 1);
    timePrecomp = TOC(t);
    std::cout << "Time to do the precomputations: " << timePrecomp << " ms" << std::endl;

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1 = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                              9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x1.size() < slots) {
        std::vector<double> zeros(slots - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }
    std::cout << "Minimum value " << *(std::min_element(x1.begin(), x1.begin() + numValues)) << " at location "
              << std::min_element(x1.begin(), x1.begin() + numValues) - x1.begin() << std::endl;
    std::cout << "Maximum value " << *(std::max_element(x1.begin(), x1.begin() + numValues)) << " at location "
              << std::max_element(x1.begin(), x1.begin() + numValues) - x1.begin() << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
    // Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr, slots);
    // Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(Fill(x1,ringDim/2), 1, 0, nullptr, ringDim/2);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    std::cout << "Input: " << x1 << std::endl;

    // Step 4: Argmin evaluation

    /*
   // Local test
    ccLWE.BTKeyGen(privateKeyFHEW);
    cc->EvalMultKeyGen(keys.secretKey);

    std::cout << "\n---Start Argmin evaluation---\n";

    Plaintext pInd;
    if (oneHot) {
        std::vector<std::complex<double>> ind(numValues, 1.0);
        pInd = cc->MakeCKKSPackedPlaintext(ind); // the encoding specified when creating the cryptocontext
    }
    else {
        std::vector<std::complex<double>> ind(numValues);
        std::iota(ind.begin(), ind.end(), 1);
        pInd = cc->MakeCKKSPackedPlaintext(ind); // the encoding specified when creating the cryptocontext
    }
    auto cInd = cc->Encrypt(keys.publicKey, pInd);

    for (uint32_t M = 1; M < numValues; M <<= 1) {
        TIC(tIter);

        std::cout << "M = " << M << std::endl;
        // Step 4.1 Compute CKKS ciphertext encoding difference of the first numValues

        auto cDiff = cc->EvalSub(c1, cc->EvalAtIndex(c1, numValues/(2*M)));

        Plaintext pDiff;
        cc->Decrypt(keys.secretKey, cDiff, &pDiff);
        pDiff->SetLength(slots);
        std::cout << "Difference: " << pDiff->GetRealPackedValue() << std::endl;

        // Step 4.2: Scheme switching from CKKS to FHEW

        // Transform the ciphertext from CKKS to FHEW
        TIC(t);
        auto cTemp = cc->EvalCKKStoFHEW(cDiff, numValues/(2*M));
        timeEval   = TOC(t);
        std::cout << "Time to compute the switch from CKKS to FHEW: " << timeEval << " ms" << std::endl;

        std::cout << "FHEW decryption pLWE: ";
        LWEPlaintext result;
        for (uint32_t i = 0; i < cTemp.size(); ++i) {
            ccLWE.Decrypt(privateKeyFHEW, cTemp[i], &result, pLWE);
            std::cout << result << " ";
        }

        // Step 4.5: Evaluate the sign
        // We always assume for the moment that numValues is a power of 2
        TIC(t);
        std::vector<LWECiphertext> LWESign(numValues/(2*M));
        for (uint32_t j = 0; j < numValues/(2*M); j++) {
            LWESign[j] = ccLWE.EvalSign(cTemp[j], true);
        }
        timeEval    = TOC(t);
        std::cout << "Time to evaluate the signs: " << timeEval << " ms" << std::endl;

        std::cout << "\nFHEW decryption of Signs: ";
        for (uint32_t i = 0; i < LWESign.size(); ++i) {
            ccLWE.Decrypt(privateKeyFHEW, LWESign[i], &result, pLWE);
            std::cout << result << " ";
        }
        std::cout << "\n" << std::endl;

        // Step 4.4: Scheme switching from FHEW to CKKS
        double scale = 1.0 / LWESign[0]->GetModulus().ConvertToInt();
        TIC(t);
        auto cSelect = cc->EvalFHEWtoCKKS(LWESign, scale, numValues/(2*M), slots, 4, -1, 1);
        timeEval    = TOC(t);
        std::cout << "Time to switch from FHEW to CKKS: " << timeEval << " ms" << std::endl;

        Plaintext plaintextDec2;
        cc->Decrypt(keys.secretKey, cSelect, &plaintextDec2);
        plaintextDec2->SetLength(slots);
        std::cout << "Switched decryption modulus_LWE mod " << 2 << ": " << plaintextDec2
                << std::endl;

        std::cout << "Ciphertext level and depth at the end of scheme switching: " << cSelect->GetLevel() << ", " << cSelect->GetNoiseScaleDeg() << std::endl;

        std::vector<std::complex<double>> ones(numValues/(2*M), 1.0);
        Plaintext ptxtOnes = cc->MakeCKKSPackedPlaintext(ones, cSelect->GetNoiseScaleDeg(), cSelect->GetLevel(), nullptr, slots);
        // Plaintext ptxtOnes = cc->MakeCKKSPackedPlaintext(ones, 1, 0, nullptr, slots);
        // std::cout << "ptxtOnes->GetSlots() = " << ptxtOnes->GetSlots() << ": " << ptxtOnes->GetCKKSPackedValue() <<  std::endl;
        // Plaintext ptxtOnes = cc->MakeCKKSPackedPlaintext(ones, 1, 0, nullptr, cc->GetRingDimension()/2);
        cSelect = cc->EvalAdd(cSelect, cc->EvalAtIndex(cc->EvalSub(ptxtOnes, cSelect), -static_cast<int>(numValues/(2*M))));

        auto cExpandSelect = cSelect;
        if (M > 1) {
            for (uint32_t j = numValues/M; j < numValues; j <<= 1)
                cExpandSelect = cc->EvalAdd(cExpandSelect, cc->EvalAtIndex(cExpandSelect, -static_cast<int>(j)));
        }

        cc->Decrypt(keys.secretKey, cExpandSelect, &plaintextDec2);
        plaintextDec2->SetLength(slots);
        std::cout << "Expanded selectors: " << plaintextDec2
                << std::endl;

        // // Encoding as plaintexts
        // Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr, ringDim / 2); // Multiplying plaintexts encoded under different number of slots does not work
        // c1 = cc->Encrypt(keys.publicKey, ptxt2);

        std::cout << "Ciphertext level and depth before multiplication: " << c1->GetLevel() << ", " << c1->GetNoiseScaleDeg() << std::endl;
        std::cout << "Selector level and depth before multiplication: " << cExpandSelect->GetLevel() << ", " << cExpandSelect->GetNoiseScaleDeg() << std::endl;
        std::cout << "cInd level and depth before multiplication: " << cInd->GetLevel() << ", " << cInd->GetNoiseScaleDeg() << std::endl;

        if (cryptoParams->GetScalingTechnique() == FIXEDAUTO) {
            if (cExpandSelect->GetLevel() > c1->GetLevel())
                cc->GetScheme()->LevelReduceInternalInPlace(c1, cExpandSelect->GetLevel() - c1->GetLevel());
            else
                cc->GetScheme()->LevelReduceInternalInPlace(c1, c1->GetLevel() - cExpandSelect->GetLevel());
            if (cExpandSelect->GetLevel() > cInd->GetLevel())
                cc->GetScheme()->LevelReduceInternalInPlace(cInd, cExpandSelect->GetLevel() - cInd->GetLevel());
            else
                cc->GetScheme()->LevelReduceInternalInPlace(cInd, cInd->GetLevel() - cExpandSelect->GetLevel());
        }
        std::cout << "Ciphertext level and depth before multiplication: " << c1->GetLevel() << ", " << c1->GetNoiseScaleDeg() << std::endl;

        // Step 4.5 Update the ciphertext of values and the indicator
        c1 = cc->EvalMult(c1, cExpandSelect);
        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL)
            cc->ModReduceInPlace(c1);

        cc->Decrypt(keys.secretKey, c1, &plaintextDec2);
        plaintextDec2->SetLength(slots);
        std::cout << "c1 multiplied by selector: " << plaintextDec2
                << std::endl;

        c1 = cc->EvalAdd(c1, cc->EvalAtIndex(c1, numValues/(2*M)));

        std::cout << "Ciphertext level and depth before next iteration: " << c1->GetLevel() << ", " << c1->GetNoiseScaleDeg() << std::endl;

        cc->Decrypt(keys.secretKey, c1, &plaintextDec2);
        plaintextDec2->SetLength(slots);
        std::cout << "New ciphertext to compare: " << plaintextDec2
                << std::endl;

        std::cout << "cInd level and depth before multiplication: " << cInd->GetLevel() << ", " << cInd->GetNoiseScaleDeg() << std::endl;

        cInd = cc->EvalMult(cInd, cExpandSelect);
        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL)
            cc->ModReduceInPlace(cInd);
        cc->Decrypt(keys.secretKey, cInd, &plaintextDec2);
        plaintextDec2->SetLength(slots);
        std::cout << "New indicator: " << plaintextDec2
                << std::endl;

        timeArgminIter    = TOC(tIter);
        std::cout << "Time for one argmin iteration: " << timeArgminIter << " ms" << std::endl;
    }

    std::cout << "\n---Finished computing the min and argmin---\n" << std::endl;
    Plaintext ptxtMin;
    cc->Decrypt(keys.secretKey, c1, &ptxtMin);
    ptxtMin->SetLength(1);
    std::cout << "Minimum value: " << ptxtMin << std::endl;
    std::cout << "Level and depth: " << c1->GetLevel() << ", " << c1->GetNoiseScaleDeg() << std::endl;
    if (oneHot) {
        cc->Decrypt(keys.secretKey, cInd, &ptxtMin);
        ptxtMin->SetLength(numValues);
        std::cout << "Indicator vector: " << ptxtMin << std::endl;
    }
    else {
        cc->EvalSumKeyGen(keys.secretKey);
        cInd = cc->EvalSum(cInd, numValues);
        cc->Decrypt(keys.secretKey, cInd, &ptxtMin);
        ptxtMin->SetLength(1);
        std::cout << "Argmin: " << ptxtMin << std::endl;
    }
*/

    TIC(t);
    auto result = cc->EvalMinSchemeSwitching(c1, keys.publicKey, numValues, slots, oneHot);
    timeEval    = TOC(t);
    std::cout << "\nTime to compute min and argmin via scheme switching: " << timeEval << " ms\n" << std::endl;

    Plaintext ptxtMin;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMin);
    ptxtMin->SetLength(1);
    std::cout << "Minimum value: " << ptxtMin << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMin);
    if (oneHot) {
        ptxtMin->SetLength(numValues);
        std::cout << "Indicator vector: " << ptxtMin << std::endl;
    }
    else {
        ptxtMin->SetLength(1);
        std::cout << "Argmin: " << ptxtMin << std::endl;
    }

    TIC(t);
    result   = cc->EvalMaxSchemeSwitching(c1, keys.publicKey, numValues, slots, oneHot);
    timeEval = TOC(t);
    std::cout << "\nTime to compute max and argmax via scheme switching: " << timeEval << " ms\n" << std::endl;

    Plaintext ptxtMax;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMax);
    ptxtMax->SetLength(1);
    std::cout << "Maximum value: " << ptxtMax << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMax);
    if (oneHot) {
        ptxtMax->SetLength(numValues);
        std::cout << "Indicator vector: " << ptxtMax << std::endl;
    }
    else {
        ptxtMax->SetLength(1);
        std::cout << "Argmax: " << ptxtMax << std::endl;
    }

    std::cout << "\nTotal time: " << TOC(tTotal) << " ms" << std::endl;
}

void ArgminViaSchemeSwitchingAlt() {
    std::cout << "-----ArgminViaSchemeSwitchingAlt-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back." << std::endl;

    TimeVar t, tTotal;  // , tIter;

    TIC(tTotal);

    double timeKeyGen(0.0), timeSetup(0.0), timePrecomp(0.0), timeEval(0.0);  //, timeArgminIter(0.0);

    // Step 1: Setup CryptoContext for CKKS

    // A. Specify main parameters
    /* A1) Multiplicative depth:
    */
    /* A2) Bit-length of scaling factor.
    */
    uint32_t scaleModSize = 50;
    uint32_t firstModSize = 60;
    uint32_t ringDim      = 16384;         // 32768;         // 8192;   // 65536; //
    SecurityLevel sl      = HEStd_NotSet;  // HEStd_128_classic; //
    uint32_t logQ_ccLWE   = 25;
    bool arbFunc          = false;
    bool oneHot           = true;
    bool alt =
        true;  // alternative mode of argmin which has fewer rotation keys and does more operations in FHEW than in CKKS

    /* A3) Number of plaintext slots used in the ciphertext.
  */
    // uint32_t slots = ringDim/2; // fully-packed
    uint32_t slots     = 64;  // sparsely-packed
    uint32_t batchSize = slots;
    // Have slots values encrypted but only want the argmin of the first numValues
    uint32_t numValues      = 64;
    ScalingTechnique scTech = FLEXIBLEAUTOEXT;
    uint32_t multDepth =
        1 + 8 + 3 + 1 +
        static_cast<int>(std::log2(numValues));  // 1 for CKKS to FHEW, 13 for FHEW to CKKS, log2(numValues) for argmin
    if (scTech == FLEXIBLEAUTOEXT)
        multDepth += 1;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
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
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    TIC(t);
    auto FHEWparams = cc->EvalSchemeSwitchingSetup(HEStd_128_classic, arbFunc, logQ_ccLWE, false, slots);
    timeSetup       = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << timeSetup << " ms" << std::endl;

    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;

    TIC(t);
    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW, 0, 0, numValues, oneHot, alt);
    timeKeyGen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << timeKeyGen << " ms" << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE.GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE << ", Q = " << (1 << logQ_ccLWE);
    std::cout << ", ring dimension RGSW/RLWE " << ccLWE.GetParams()->GetLWEParams()->GetN();
    std::cout << ", and modulus q " << ccLWE.GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    // The minimum value at the end will also be scaled by scaleSign.
    double scaleSign = 512.0;

    // auto pLWE       = ccLWE.GetMaxPlaintextSpace().ConvertToInt();  // Small precision
    auto modulus_LWE = 1 << logQ_ccLWE;
    auto beta        = ccLWE.GetBeta().ConvertToInt();
    auto pLWE        = modulus_LWE / (2 * beta);  // Large precision

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    // //Get the last ciphertext modulus; this assumes the LWE mod switch will be performed on the ciphertext at the last level
    // ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    // auto paramsQ                                  = elementParams.GetParams();
    // auto modulus_CKKS_from                        = paramsQ[0]->GetModulus();
    // double scFactor = cryptoParams->GetScalingFactorReal(0);
    // double scaleCF   = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE);

    TIC(t);
    // cc->EvalCKKStoFHEWPrecompute(scaleCF);
    uint32_t init_level = 0;
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        init_level = 1;
    // This formulation is for clarity
    // cc->EvalCompareSSPrecompute(pLWE, init_level, scaleSign);
    // But we can also include the scaleSign in pLWE (here we use the fact both pLWE and scaleSign are powers of two)
    cc->EvalCompareSSPrecompute(pLWE / scaleSign, init_level, 1);
    timePrecomp = TOC(t);
    std::cout << "Time to do the precomputations: " << timePrecomp << " ms" << std::endl;

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1 = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                              9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x1.size() < slots) {
        std::vector<double> zeros(slots - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }
    std::cout << "Minimum value " << *(std::min_element(x1.begin(), x1.begin() + numValues)) << " at location "
              << std::min_element(x1.begin(), x1.begin() + numValues) - x1.begin() << std::endl;
    std::cout << "Maximum value " << *(std::max_element(x1.begin(), x1.begin() + numValues)) << " at location "
              << std::max_element(x1.begin(), x1.begin() + numValues) - x1.begin() << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
    // Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr, slots);
    // Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(Fill(x1,ringDim/2), 1, 0, nullptr, ringDim/2);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    std::cout << "Input: " << x1 << std::endl;

    // Step 4: Argmin evaluation

    /*
   // Local test
    ccLWE.BTKeyGen(privateKeyFHEW);
    cc->EvalMultKeyGen(keys.secretKey);

    std::cout << "\n---Start Argmin evaluation---\n";

    Plaintext pInd;
    if (oneHot) {
        std::vector<std::complex<double>> ind(numValues, 1.0);
        pInd = cc->MakeCKKSPackedPlaintext(ind); // the encoding specified when creating the cryptocontext
    }
    else {
        std::vector<std::complex<double>> ind(numValues);
        std::iota(ind.begin(), ind.end(), 1);
        pInd = cc->MakeCKKSPackedPlaintext(ind); // the encoding specified when creating the cryptocontext
    }
    auto cInd = cc->Encrypt(keys.publicKey, pInd);

    for (uint32_t M = 1; M < numValues; M <<= 1) {
        TIC(tIter);

        std::cout << "M = " << M << std::endl;
        // Step 4.1 Compute CKKS ciphertext encoding difference of the first numValues

        auto cDiff = cc->EvalSub(c1, cc->EvalAtIndex(c1, numValues/(2*M)));

        Plaintext pDiff;
        cc->Decrypt(keys.secretKey, cDiff, &pDiff);
        pDiff->SetLength(slots);
        std::cout << "Difference: " << pDiff->GetRealPackedValue() << std::endl;

        // Step 4.2: Scheme switching from CKKS to FHEW

        // Transform the ciphertext from CKKS to FHEW
        TIC(t);
        auto cTemp = cc->EvalCKKStoFHEW(cDiff, numValues/(2*M));
        timeEval   = TOC(t);
        std::cout << "Time to compute the switch from CKKS to FHEW: " << timeEval << " ms" << std::endl;

        std::cout << "FHEW decryption pLWE: ";
        LWEPlaintext result;
        for (uint32_t i = 0; i < cTemp.size(); ++i) {
            ccLWE.Decrypt(privateKeyFHEW, cTemp[i], &result, pLWE);
            std::cout << result << " ";
        }

        // Step 4.5: Evaluate the sign
        // We always assume for the moment that numValues is a power of 2
        TIC(t);
        std::vector<LWECiphertext> LWESign(numValues);

        for (uint32_t j = 0; j < numValues / (2 * M); j++) {
            LWECiphertext tempSign = ccLWE.EvalSign(cTemp[j], true);
            LWECiphertext negTempSign = std::make_shared<LWECiphertextImpl>(*tempSign);
            ccLWE.GetLWEScheme()->EvalAddConstEq(negTempSign, negTempSign->GetModulus() >> 1); // "negated" tempSign
            for(uint32_t i = 0; i < 2*M; i+=2) {
                LWESign[i*numValues/(2*M) + j] = tempSign;
                LWESign[(i+1)*numValues/(2*M) + j] = negTempSign;
            }
        }

        timeEval    = TOC(t);
        std::cout << "Time to evaluate the signs: " << timeEval << " ms" << std::endl;

        std::cout << "\nFHEW decryption of Signs: ";
        for (uint32_t i = 0; i < LWESign.size(); ++i) {
            ccLWE.Decrypt(privateKeyFHEW, LWESign[i], &result, pLWE);
            std::cout << result << " ";
        }
        std::cout << "\n" << std::endl;

        // Step 4.4: Scheme switching from FHEW to CKKS
        double scale = 1.0 / LWESign[0]->GetModulus().ConvertToInt();
        TIC(t);
        auto cExpandSelect = cc->EvalFHEWtoCKKS(LWESign, scale, numValues, slots, 4, -1, 1);
        timeEval    = TOC(t);
        std::cout << "Time to switch from FHEW to CKKS: " << timeEval << " ms" << std::endl;

        Plaintext plaintextDec2;
        cc->Decrypt(keys.secretKey, cExpandSelect, &plaintextDec2);
        plaintextDec2->SetLength(slots);
        std::cout << "Switched decryption modulus_LWE mod " << 2 << ": " << plaintextDec2
                << std::endl;

        std::cout << "Ciphertext level and depth at the end of scheme switching: " << cExpandSelect->GetLevel() << ", " << cExpandSelect->GetNoiseScaleDeg() << std::endl;

        // // Encoding as plaintexts
        // Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr, ringDim / 2); // Multiplying plaintexts encoded under different number of slots does not work
        // c1 = cc->Encrypt(keys.publicKey, ptxt2);

        // Step 4.5 Update the ciphertext of values and the indicator
        c1 = cc->EvalMult(c1, cExpandSelect);
        cc->ModReduceInPlace(c1);

        cc->Decrypt(keys.secretKey, c1, &plaintextDec2);
        plaintextDec2->SetLength(slots);
        std::cout << "c1 multiplied by selector: " << plaintextDec2
                << std::endl;

        c1 = cc->EvalAdd(c1, cc->EvalAtIndex(c1, numValues/(2*M)));

        std::cout << "Ciphertext level and depth before next iteration: " << c1->GetLevel() << ", " << c1->GetNoiseScaleDeg() << std::endl;

        cc->Decrypt(keys.secretKey, c1, &plaintextDec2);
        plaintextDec2->SetLength(slots);
        std::cout << "New ciphertext to compare: " << plaintextDec2
                << std::endl;

        cInd = cc->EvalMult(cInd, cExpandSelect);
        cc->ModReduceInPlace(cInd);
        cc->Decrypt(keys.secretKey, cInd, &plaintextDec2);
        plaintextDec2->SetLength(slots);
        std::cout << "New indicator: " << plaintextDec2
                << std::endl;

        timeArgminIter    = TOC(tIter);
        std::cout << "Time for one argmin iteration: " << timeArgminIter << " ms" << std::endl;
    }

    std::cout << "\n---Finished computing the min and argmin---\n" << std::endl;
    Plaintext ptxtMin;
    cc->Decrypt(keys.secretKey, c1, &ptxtMin);
    ptxtMin->SetLength(1);
    std::cout << "Minimum value: " << ptxtMin << std::endl;
    std::cout << "Level and depth: " << c1->GetLevel() << ", " << c1->GetNoiseScaleDeg() << std::endl;
    if (oneHot) {
        cc->Decrypt(keys.secretKey, cInd, &ptxtMin);
        ptxtMin->SetLength(numValues);
        std::cout << "Indicator vector: " << ptxtMin << std::endl;
    }
    else {
        cc->EvalSumKeyGen(keys.secretKey);
        cInd = cc->EvalSum(cInd, numValues);
        cc->Decrypt(keys.secretKey, cInd, &ptxtMin);
        ptxtMin->SetLength(1);
        std::cout << "Argmin: " << ptxtMin << std::endl;
    }
*/

    TIC(t);
    auto result = cc->EvalMinSchemeSwitchingAlt(c1, keys.publicKey, numValues, slots, oneHot);
    timeEval    = TOC(t);
    std::cout << "\nTime to compute min and argmin via scheme switching: " << timeEval << " ms\n" << std::endl;

    Plaintext ptxtMin;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMin);
    ptxtMin->SetLength(1);
    std::cout << "Minimum value: " << ptxtMin << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMin);
    if (oneHot) {
        ptxtMin->SetLength(numValues);
        std::cout << "Indicator vector: " << ptxtMin << std::endl;
    }
    else {
        ptxtMin->SetLength(1);
        std::cout << "Argmin: " << ptxtMin << std::endl;
    }

    TIC(t);
    result   = cc->EvalMaxSchemeSwitchingAlt(c1, keys.publicKey, numValues, slots, oneHot);
    timeEval = TOC(t);
    std::cout << "\nTime to compute max and argmax via scheme switching: " << timeEval << " ms\n" << std::endl;

    Plaintext ptxtMax;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMax);
    ptxtMax->SetLength(1);
    std::cout << "Maximum value: " << ptxtMax << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMax);
    if (oneHot) {
        ptxtMax->SetLength(numValues);
        std::cout << "Indicator vector: " << ptxtMax << std::endl;
    }
    else {
        ptxtMax->SetLength(1);
        std::cout << "Argmax: " << ptxtMax << std::endl;
    }

    std::cout << "\nTotal time: " << TOC(tTotal) << " ms" << std::endl;
}

void ArgminViaSchemeSwitchingUnit() {
    std::cout << "\n-----ArgminViaSchemeSwitchingUnit-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back." << std::endl;

    TimeVar t, tTotal;

    TIC(tTotal);

    double timeKeyGen(0.0), timeSetup(0.0), timePrecomp(0.0), timeEval(0.0);

    // Step 1: Setup CryptoContext for CKKS

    // A. Specify main parameters
    /* A1) Multiplicative depth:
    */
    /* A2) Bit-length of scaling factor.
    */
    uint32_t scaleModSize = 50;
    uint32_t firstModSize = 60;
    uint32_t ringDim      = 16384;         // 32768;         // 8192; //  65536; //
    SecurityLevel sl      = HEStd_NotSet;  // HEStd_128_classic; //
    uint32_t logQ_ccLWE   = 25;
    bool arbFunc          = false;
    bool oneHot           = true;

    /* A3) Number of plaintext slots used in the ciphertext.
  */
    // uint32_t slots = ringDim/2; // fully-packed
    uint32_t slots     = 64;  // sparsely-packed
    uint32_t batchSize = slots;
    // Have slots values encrypted but only want the argmin of the first numValues
    uint32_t numValues      = 64;
    ScalingTechnique scTech = FLEXIBLEAUTOEXT;
    uint32_t multDepth =
        1 + 8 + 3 + 1 +
        static_cast<int>(std::log2(numValues));  // 1 for CKKS to FHEW, 13 for FHEW to CKKS, log2(numValues) for argmin
    if (scTech == FLEXIBLEAUTOEXT)
        multDepth += 1;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
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
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    TIC(t);
    auto FHEWparams = cc->EvalSchemeSwitchingSetup(HEStd_128_classic, arbFunc, logQ_ccLWE, false, slots);
    timeSetup       = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << timeSetup << " ms" << std::endl;

    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;

    TIC(t);
    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW, 0, 0, numValues, oneHot);
    timeKeyGen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << timeKeyGen << " ms" << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE.GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE << ", Q = " << (1 << logQ_ccLWE);
    std::cout << ", ring dimension RGSW/RLWE " << ccLWE.GetParams()->GetLWEParams()->GetN();
    std::cout << ", and modulus q " << ccLWE.GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());

    TIC(t);
    // cc->EvalCKKStoFHEWPrecompute(scaleCF);
    uint32_t init_level = 0;
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        init_level = 1;
    // Here we assume the message does not need scaling, as they are in the unit circle.
    cc->EvalCompareSSPrecompute(1, init_level, 1);
    timePrecomp = TOC(t);
    std::cout << "Time to do the precomputations: " << timePrecomp << " ms" << std::endl;

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1 = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                              9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x1.size() < slots) {
        std::vector<int> zeros(slots - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }
    std::cout << "Input: " << x1 << std::endl;

    /* Here we to assume each element of x1 is between (-0.5, 0.5]. The user will use heuristics on the size of the plaintext to achieve this.
     * This will mean that even the difference of the messages will be between (-1,1].
     * However, if a good enough approximation of the maximum is not available and the scaled inputs are too small, the precision of the result
     * might not be good enough.
     */
    double p = 1 << (firstModSize - scaleModSize - 1);
    std::transform(x1.begin(), x1.end(), x1.begin(), [&](const double& elem) { return elem / (2 * p); });

    std::cout << "Input scaled: " << x1 << std::endl;
    std::cout << "Minimum value " << *(std::min_element(x1.begin(), x1.begin() + numValues)) << " at location "
              << std::min_element(x1.begin(), x1.begin() + numValues) - x1.begin() << std::endl;
    std::cout << "Maximum value " << *(std::max_element(x1.begin(), x1.begin() + numValues)) << " at location "
              << std::max_element(x1.begin(), x1.begin() + numValues) - x1.begin() << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    // Step 4: Argmin evaluation

    TIC(t);
    auto result = cc->EvalMinSchemeSwitching(c1, keys.publicKey, numValues, slots, oneHot);
    timeEval    = TOC(t);
    std::cout << "\nTime to compute min and argmin via scheme switching: " << timeEval << " ms\n" << std::endl;

    Plaintext ptxtMin;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMin);
    ptxtMin->SetLength(1);
    std::cout << "Minimum value: " << ptxtMin << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMin);
    if (oneHot) {
        ptxtMin->SetLength(numValues);
        std::cout << "Indicator vector: " << ptxtMin << std::endl;
    }
    else {
        ptxtMin->SetLength(1);
        std::cout << "Argmin: " << ptxtMin << std::endl;
    }

    TIC(t);
    result   = cc->EvalMaxSchemeSwitching(c1, keys.publicKey, numValues, slots, oneHot);
    timeEval = TOC(t);
    std::cout << "\nTime to compute max and argmax via scheme switching: " << timeEval << " ms\n" << std::endl;

    Plaintext ptxtMax;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMax);
    ptxtMax->SetLength(1);
    std::cout << "Maximum value: " << ptxtMax << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMax);
    if (oneHot) {
        ptxtMax->SetLength(numValues);
        std::cout << "Indicator vector: " << ptxtMax << std::endl;
    }
    else {
        ptxtMax->SetLength(1);
        std::cout << "Argmax: " << ptxtMax << std::endl;
    }

    std::cout << "\nTotal time: " << TOC(tTotal) << " ms" << std::endl;
}

void ArgminViaSchemeSwitchingAltUnit() {
    std::cout << "\n-----ArgminViaSchemeSwitchingAltUnit-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back." << std::endl;

    TimeVar t, tTotal;

    TIC(tTotal);

    double timeKeyGen(0.0), timeSetup(0.0), timePrecomp(0.0), timeEval(0.0);

    // Step 1: Setup CryptoContext for CKKS

    // A. Specify main parameters
    /* A1) Multiplicative depth:
    */
    /* A2) Bit-length of scaling factor.
    */
    uint32_t scaleModSize = 50;
    uint32_t firstModSize = 60;
    uint32_t ringDim      = 16384;         // 32768;         // 8192; //  65536; //
    SecurityLevel sl      = HEStd_NotSet;  // HEStd_128_classic; //
    uint32_t logQ_ccLWE   = 25;
    bool arbFunc          = false;
    bool oneHot           = true;

    /* A3) Number of plaintext slots used in the ciphertext.
  */
    // uint32_t slots = ringDim/2; // fully-packed
    uint32_t slots     = 64;  // sparsely-packed
    uint32_t batchSize = slots;
    // Have slots values encrypted but only want the argmin of the first numValues
    uint32_t numValues      = 64;
    ScalingTechnique scTech = FLEXIBLEAUTOEXT;
    uint32_t multDepth =
        1 + 8 + 3 + 1 +
        static_cast<int>(std::log2(numValues));  // 1 for CKKS to FHEW, 13 for FHEW to CKKS, log2(numValues) for argmin
    if (scTech == FLEXIBLEAUTOEXT)
        multDepth += 1;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
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
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    TIC(t);
    auto FHEWparams = cc->EvalSchemeSwitchingSetup(HEStd_128_classic, arbFunc, logQ_ccLWE, false, slots);
    timeSetup       = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << timeSetup << " ms" << std::endl;

    auto ccLWE          = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;

    TIC(t);
    cc->EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW, 0, 0, numValues, oneHot);
    timeKeyGen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << timeKeyGen << " ms" << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE.GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE << ", Q = " << (1 << logQ_ccLWE);
    std::cout << ", ring dimension RGSW/RLWE " << ccLWE.GetParams()->GetLWEParams()->GetN();
    std::cout << ", and modulus q " << ccLWE.GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());

    TIC(t);
    // cc->EvalCKKStoFHEWPrecompute(scaleCF);
    uint32_t init_level = 0;
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        init_level = 1;
    // Here we assume the message does not need scaling, as they are in the unit circle.
    cc->EvalCompareSSPrecompute(1, init_level, 1);
    timePrecomp = TOC(t);
    std::cout << "Time to do the precomputations: " << timePrecomp << " ms" << std::endl;

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1 = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                              9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x1.size() < slots) {
        std::vector<int> zeros(slots - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }
    std::cout << "Input: " << x1 << std::endl;

    /* Here we to assume each element of x1 is between (-0.5, 0.5]. The user will use heuristics on the size of the plaintext to achieve this.
     * This will mean that even the difference of the messages will be between (-1,1].
     * However, if a good enough approximation of the maximum is not available and the scaled inputs are too small, the precision of the result
     * might not be good enough.
     */
    double p = 1 << (firstModSize - scaleModSize - 1);
    std::transform(x1.begin(), x1.end(), x1.begin(), [&](const double& elem) { return elem / (2 * p); });

    std::cout << "Input scaled: " << x1 << std::endl;
    std::cout << "Minimum value " << *(std::min_element(x1.begin(), x1.begin() + numValues)) << " at location "
              << std::min_element(x1.begin(), x1.begin() + numValues) - x1.begin() << std::endl;
    std::cout << "Maximum value " << *(std::max_element(x1.begin(), x1.begin() + numValues)) << " at location "
              << std::max_element(x1.begin(), x1.begin() + numValues) - x1.begin() << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    // Step 4: Argmin evaluation

    TIC(t);
    auto result = cc->EvalMinSchemeSwitchingAlt(c1, keys.publicKey, numValues, slots, oneHot);
    timeEval    = TOC(t);
    std::cout << "\nTime to compute min and argmin via scheme switching: " << timeEval << " ms\n" << std::endl;

    Plaintext ptxtMin;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMin);
    ptxtMin->SetLength(1);
    std::cout << "Minimum value: " << ptxtMin << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMin);
    if (oneHot) {
        ptxtMin->SetLength(numValues);
        std::cout << "Indicator vector: " << ptxtMin << std::endl;
    }
    else {
        ptxtMin->SetLength(1);
        std::cout << "Argmin: " << ptxtMin << std::endl;
    }

    TIC(t);
    result   = cc->EvalMaxSchemeSwitchingAlt(c1, keys.publicKey, numValues, slots, oneHot);
    timeEval = TOC(t);
    std::cout << "\nTime to compute max and argmax via scheme switching: " << timeEval << " ms\n" << std::endl;

    Plaintext ptxtMax;
    cc->Decrypt(keys.secretKey, result[0], &ptxtMax);
    ptxtMax->SetLength(1);
    std::cout << "Maximum value: " << ptxtMax << std::endl;
    cc->Decrypt(keys.secretKey, result[1], &ptxtMax);
    if (oneHot) {
        ptxtMax->SetLength(numValues);
        std::cout << "Indicator vector: " << ptxtMax << std::endl;
    }
    else {
        ptxtMax->SetLength(1);
        std::cout << "Argmax: " << ptxtMax << std::endl;
    }

    std::cout << "\nTotal time: " << TOC(tTotal) << " ms" << std::endl;
}
