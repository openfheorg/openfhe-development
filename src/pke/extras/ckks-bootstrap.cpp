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

Example for CKKS bootstrapping

 */

#define PROFILE

#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

void BootstrapExample(SecretKeyDist secretKeyDist, uint32_t n, uint32_t slots, uint32_t levelsRemaining);
// same example with verbose console output removed
void BootstrapExampleClean(SecretKeyDist secretKeyDist, uint32_t n, uint32_t slots, uint32_t levelsRemaining);

int main(int argc, char* argv[]) {
    // MODE - secret key distribution
    // SPARSE - sparse ternary secrets (with h = 64)
    // OPTIMIZED - uniform ternary secrets

    // low-security examples
    // BootstrapExample(SPARSE_TERNARY, 1<<12, 1<<11, 10);
    // BootstrapExample(SPARSE_TERNARY, 1<<12, 1<<10, 10);
    BootstrapExample(UNIFORM_TERNARY, 1 << 12, 1 << 11, 10);
    // BootstrapExample(UNIFORM_TERNARY, 1<<12, 1<<10, 10);

    // BootstrapExample(SPARSE_TERNARY, 1<<17, 1<<16, 10);
    // BootstrapExample(SPARSE_TERNARY, 1<<17, 1<<15, 10);
    // BootstrapExample(UNIFORM_TERNARY, 1<<17, 1<<16, 10);
    // BootstrapExample(UNIFORM_TERNARY, 1<<17, 1<<15, 10);

    return 0;
}

void BootstrapExample(SecretKeyDist secretKeyDist, uint32_t n, uint32_t slots, uint32_t levelsRemaining) {
    TimeVar t;
    double timeKeyGen(0.0);
    double timePrecomp(0.0);
    double timeBootstrap(0.0);

    // giant step for baby-step-giant-step algorithm in linear transforms for encoding and decoding, respectively
    // Choose this a power of 2 preferably, otherwise an exact divisor of the number of elements in the sum
    std::vector<uint32_t> dim1 = {0, 0};

    // budget in levels for FFT for encoding and decoding, respectively
    // Choose a number smaller than ceil(log2(slots))

    std::vector<uint32_t> levelBudget1 = {4, 4};
    std::vector<uint32_t> levelBudget2 = {2, 4};
    std::vector<uint32_t> levelBudget3 = {3, 2};
    std::vector<uint32_t> levelBudget4 = {1, 1};
    std::vector<uint32_t> levelBudget5 = {1, 2};
    std::vector<uint32_t> levelBudget6 = {3, 1};

#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
    ScalingTechnique rescaleTech = FIXEDMANUAL;
    usint dcrtBits               = 78;
    usint firstMod               = 89; /*firstMod*/
#else
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    usint dcrtBits               = 59;
    usint firstMod               = 60; /*firstMod*/
#endif

    // computes how many levels are needed for
    usint depth = levelsRemaining + FHECKKSRNS::GetBootstrapDepth(9, levelBudget1, secretKeyDist);

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetRingDim(n);
    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetNumLargeDigits(3);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetFirstModSize(firstMod);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

#if 0
    CryptoContext<DCRTPoly> cc =
        CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
               depth,
               dcrtBits,
               slots,
               HEStd_NotSet,
               n, /*ringDimension*/
               rescaleTech,
               HYBRID,
               3, /*numLargeDigits*/
               2, /*maxRelinSkDeg*/
    #if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
               89, /*firstMod*/
    #else
               60, /*firstMod*/
    #endif
               0,
               mode);
#endif

    // Turn on features
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    const shared_ptr<CryptoParametersCKKSRNS> cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());

    std::cerr << "SecretKeyDist: " << secretKeyDist << std::endl;

    std::cout << "p = " << cryptoParams->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cryptoParams->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cout << "# slots = " << slots << std::endl;
    std::cout << "log2 q = " << cryptoParams->GetElementParams()->GetModulus().GetMSB() << std::endl;
    std::cout << "log2 q*p = " << cryptoParams->GetParamsQP()->GetModulus().GetMSB() << std::endl;

    std::cout << "dim1 = " << dim1 << std::endl;
    std::cout << "level budget = " << levelBudget1 << std::endl;

    TIC(t);

    vector<uint32_t> slotsvec(6);
    for (size_t i = 0; i < 6; ++i) {
        slotsvec[i] = slots / (1 << i);
    }

    // precomputations for bootstrapping

    cc->EvalBootstrapSetup(levelBudget1, dim1, slotsvec[0]);
    cc->EvalBootstrapSetup(levelBudget2, dim1, slotsvec[1]);
    cc->EvalBootstrapSetup(levelBudget3, dim1, slotsvec[2]);
    cc->EvalBootstrapSetup(levelBudget4, dim1, slotsvec[3]);
    cc->EvalBootstrapSetup(levelBudget5, dim1, slotsvec[4]);
    cc->EvalBootstrapSetup(levelBudget6, dim1, slotsvec[5]);

    // std::cout << "gEnc = " << cc->GetGiantStepEnc() << std::endl;
    // std::cout << "# rot Enc = " << cc->GetNumRotationsEnc() << std::endl;
    // std::cout << "gEncRem = " << cc->GetGiantStepRemEnc() << std::endl;
    // std::cout << "W rot EncRem = " << cc->GetNumRotationsRemEnc() << std::endl;
    // std::cout << "gDec = " << cc->GetGiantStepDec() << std::endl;
    // std::cout << "# rot Dec = " << cc->GetNumRotationsDec() << std::endl;
    // std::cout << "gDecRem = " << cc->GetGiantStepRemDec() << std::endl;
    // std::cout << "W rot DecRem = " << cc->GetNumRotationsRemDec() << std::endl;

    timePrecomp = TOC(t);

    std::cout << "\nLinear transform precomputation time: " << timePrecomp / 1000.0 << " s" << std::endl;

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    // generation of all keys needed for bootstrapping

    for (size_t i = 0; i < 6; ++i) {
        TIC(t);
        cc->EvalBootstrapKeyGen(keyPair.secretKey, slotsvec[i]);
        timeKeyGen = TOC(t);
        std::cout << "\nAutomorphism key generation time: " << timeKeyGen / 1000.0 << " s" << std::endl;
        std::vector<std::complex<double>> a(
            {0.111111, 0.222222, 0.333333, 0.444444, 0.555555, 0.666666, 0.777777, 0.888888});

        size_t encodedLength = a.size();

        std::vector<std::complex<double>> input(Fill(a, slotsvec[i]));
        Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input, 1, depth - 1, nullptr, slotsvec[i]);
        auto ciphertext     = cc->Encrypt(keyPair.publicKey, plaintext);

        std::cerr << "ciphertext number of slots: " << ciphertext->GetSlots() << std::endl;

        std::cerr << "\nNumber of levels before bootstrapping: " << ciphertext->GetElements()[0].GetNumOfElements() - 1
                  << std::endl;

        TIC(t);
        auto ciphertextAfter = cc->EvalBootstrap(ciphertext);
        timeBootstrap        = TOC(t);
        std::cout << "\nBootstrapping time: " << timeBootstrap / 1000.0 << " s" << std::endl;
        std::cerr << "\nNumber of levels consumed: "
                  << depth - ciphertextAfter->GetElements()[0].GetNumOfElements() + ciphertextAfter->GetNoiseScaleDeg()
                  << std::endl;
        std::cerr << "\nNumber of levels remaining: "
                  << ciphertextAfter->GetElements()[0].GetNumOfElements() - ciphertextAfter->GetNoiseScaleDeg()
                  << std::endl;

        Plaintext result;
        std::cerr << "ciphertextAfter level        : " << ciphertextAfter->GetLevel() << std::endl;
        std::cerr << "ciphertextAfter noiseScaleDeg: " << ciphertextAfter->GetNoiseScaleDeg() << std::endl;
        std::cerr << "ciphertextAfter    sf        : " << ciphertextAfter->GetScalingFactor() << std::endl;
        cc->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
        std::cerr << "encodedLength: " << encodedLength << std::endl;

        result->SetLength(encodedLength);
        plaintext->SetLength(encodedLength);

        std::cout << "\nEncrypted text before bootstrapping \n\t" << plaintext << std::endl;

        std::cout << "\nEncrypted text after bootstrapping \n\t" << result << std::endl;

        double error = 0;
        for (size_t i = 0; i < encodedLength; i++) {
            error =
                error + std::fabs((result->GetCKKSPackedValue()[i].real() - plaintext->GetCKKSPackedValue()[i].real()) /
                                  plaintext->GetCKKSPackedValue()[i].real());
        }

        std::cout << "\nAverage error: " << error / static_cast<double>(encodedLength) << std::endl;
        std::cout << "\nAverage error - in bits: " << std::log2(error / static_cast<double>(encodedLength))
                  << std::endl;
    }
}

void BootstrapExampleClean(SecretKeyDist secretKeyDist, uint32_t n, uint32_t slots, uint32_t levelsRemaining) {
    // giant step for baby-step-giant-step algorithm in linear transforms for encoding and decoding, respectively
    // Choose this a power of 2 preferably, otherwise an exact divisor of the number of elements in the sum
    std::vector<uint32_t> dim1 = {0, 0};

    // budget in levels for FFT for encoding and decoding, respectively
    // Choose a number smaller than ceil(log2(slots))
    std::vector<uint32_t> levelBudget = {4, 4};

#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
    ScalingTechnique rescaleTech = FIXEDMANUAL;
    usint dcrtBits               = 78;
    usint firstMod               = 89; /*firstMod*/
#else
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    usint dcrtBits               = 59;
    usint firstMod               = 60; /*firstMod*/
#endif

    // computes how many levels are needed for
    usint depth = levelsRemaining + FHECKKSRNS::GetBootstrapDepth(9, levelBudget, secretKeyDist);

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetRingDim(n);
    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetNumLargeDigits(3);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetFirstModSize(firstMod);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

#if 0
    CryptoContext<DCRTPoly> cc =
        CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
               depth,
               dcrtBits,
               slots,
               HEStd_NotSet,
               n, /*ringDimension*/
               rescaleTech,
               HYBRID,
               3, /*numLargeDigits*/
               2, /*maxRelinSkDeg*/
    #if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
               89, /*firstMod*/
    #else
               60, /*firstMod*/
    #endif
               0,
               mode);
#endif

    // Turn on features
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    // precomputations for bootstrapping
    cc->EvalBootstrapSetup(levelBudget, dim1, slots);

    // keypair is generated
    auto keyPair = cc->KeyGen();

    // generation of evaluation keys
    cc->EvalBootstrapKeyGen(keyPair.secretKey, slots);

    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<std::complex<double>> a(
        {0.111111, 0.222222, 0.333333, 0.444444, 0.555555, 0.666666, 0.777777, 0.888888});

    size_t encodedLength = a.size();

    std::vector<std::complex<double>> input(Fill(a, slots));

    Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(input, 1, depth - 1, nullptr, slots);

    auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

    // bootstrapping operation
    auto ciphertextAfter = cc->EvalBootstrap(ciphertext1);

    Plaintext result;

    cc->Decrypt(keyPair.secretKey, ciphertextAfter, &result);

    result->SetLength(encodedLength);
    plaintext1->SetLength(encodedLength);

    std::cout << "\nEncrypted text before bootstrapping \n\t" << plaintext1 << std::endl;

    std::cout << "\nEncrypted text after bootstrapping \n\t" << result << std::endl;
}
