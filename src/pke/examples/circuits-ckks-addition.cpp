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
  Please see CKKS_NOISE_FLOODING.md for technical details on CKKS noise flooding for the INDCPA^D scenario.

  Example for using CKKS with the experimental NOISE_FLOODING_DECRYPT mode. We do not recommend
  this mode for production yet. This experimental mode gives us equivalent security levels to
  BGV and BFV, but it requires the user to run all encrypted operations twice. The first iteration
  is a preliminary run to measure noise, and the second iteration is the actual run, which
  will input the noise as a parameter. We use the noise to enhance security within decryption.

  Note that a user can choose to run the first computation with NATIVE_SIZE = 64 to estimate noise,
  and the second computation with NATIVE_SIZE = 128, if they wish. This would require a
  different set of binaries: first, with NATIVE_SIZE = 64 and the second one with NATIVE_SIZE = 128.
  It can be considered as an optimization for the case when we need NATIVE_SIZE = 128.

  For NATIVE_SIZE=128, we automatically choose the scaling mod size and first mod size in the second iteration
  based on the input noise estimate. This means that we currently do not support bootstrapping in the
  NOISE_FLOODING_DECRYPT mode, since the scaling mod size and first mod size affect the noise estimate for
  bootstrapping. We plan to add support for bootstrapping in NOISE_FLOODING_DECRYPT mode in a future release.
 */

#include "openfhe.h"

using namespace lbcrypto;

const std::string DATAFOLDER = "demoData";

// Demo function for NOISE_FLOODING_DECRYPT mode in CKKS
void CKKSNoiseFloodingDemo();

/**
 * We recommend putting part of the CryptoContext inside a function because
 * you must make sure all parameters are the same, except EXECUTION_MODE and NOISE_ESTIMATE.
 *
 * @param cryptoParams Crypto parameters that already have their execution mode set (and noise estimate, if in EXEC_EVALUATION mode).
 * @return the cryptoContext.
 */
CryptoContext<DCRTPoly> GetCryptoContext(CCParams<CryptoContextCKKSRNS>& cryptoParams);

int main(int argc, char* argv[]) {
    CKKSNoiseFloodingDemo();
    return 0;
}

void CKKSNoiseFloodingDemo() {
    // ----------------------- Setup first CryptoContext -----------------------------
    // Phase 1 will be for noise estimation.
    // -------------------------------------------------------------------------------
    std::cout << "---------------------------------- PHASE 1: NOISE ESTIMATION ----------------------------------"
              << std::endl;
    CCParams<CryptoContextCKKSRNS> parametersNoiseEstimation;
    // EXEC_NOISE_ESTIMATION indicates that the resulting plaintext will estimate the amount of noise in the computation.
    parametersNoiseEstimation.SetExecutionMode(EXEC_NOISE_ESTIMATION);

    auto cryptoContextNoiseEstimation = GetCryptoContext(parametersNoiseEstimation);

    usint ringDim = cryptoContextNoiseEstimation->GetRingDimension();
    std::cout << "CKKS scheme is using ring dimension " << ringDim << std::endl << std::endl;

    const auto cryptoParamsCKKS =
        std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cryptoContextNoiseEstimation->GetCryptoParameters());

    // std::cout << "circuits" << cryptoParamsCKKS->GetCircuits() << std::endl;

    std::cout << "\nValidating addition circuit" << std::endl;

    std::string fileNameValidate = DATAFOLDER + "/ckks-addition.tsv";
    std::ifstream fileValidate(fileNameValidate);
    std::string circuitAddition((std::istreambuf_iterator<char>(fileValidate)), std::istreambuf_iterator<char>());

    cryptoContextNoiseEstimation->ValidateCircuit(circuitAddition);

    // Key Generation
    auto keyPairNoiseEstimation = cryptoContextNoiseEstimation->KeyGen();

    std::cout << "Before calling EstimateCircuit" << std::endl;

    // We run the encrypted computation the first time.
    auto noiseCiphertexts = cryptoContextNoiseEstimation->EstimateCircuits(keyPairNoiseEstimation.publicKey);

    std::cout << "After calling EstimateCircuit" << std::endl;

    // Decrypt  noise
    double noise = cryptoContextNoiseEstimation->FindMaximumNoise(noiseCiphertexts, keyPairNoiseEstimation.secretKey);
    std::cout << "Noise \n\t" << noise << std::endl;

    // ----------------------- Setup second CryptoContext -----------------------------
    // Phase 2 will be for the actual evaluation.
    // IMPORTANT: We must use a different public/private key pair here to achieve the
    // security guarantees for noise flooding.
    // -------------------------------------------------------------------------------
    std::cout << "---------------------------------- PHASE 2: EVALUATION ----------------------------------"
              << std::endl;
    CCParams<CryptoContextCKKSRNS> parametersEvaluation;
    // EXEC_EVALUATION indicates that we are in phase 2 of computation, and wil5 obtain the actual result.
    parametersEvaluation.SetExecutionMode(EXEC_EVALUATION);
    // Here, we set the noise of our previous computation
    parametersEvaluation.SetNoiseEstimate(noise);

    // We can set our desired precision for 128-bit CKKS only. For NATIVE_SIZE=64, we ignore this parameter.
    parametersEvaluation.SetDesiredPrecision(25);

    // We can set the statistical security and number of adversarial queries, but we can also
    // leave these lines out, as we are setting them to the default values here.
    parametersEvaluation.SetStatisticalSecurity(30);
    parametersEvaluation.SetNumAdversarialQueries(1);

    // The remaining parameters must be the same as the first CryptoContext. Note that we can choose to run the
    // first computation with NATIVEINT = 64 to estimate noise, and the second computation with NATIVEINT = 128,
    // or vice versa, if we wish.
    auto cryptoContextEvaluation = GetCryptoContext(parametersEvaluation);

    std::cerr << *cryptoContextEvaluation->GetCryptoParameters() << std::endl;

    // IMPORTANT: Generate new keys
    auto keyPairEvaluation = cryptoContextEvaluation->KeyGen();

    // First plaintext vector is encoded
    std::vector<double> vectorOfInts1 = {1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    Plaintext plaintext1              = cryptoContextEvaluation->MakeCKKSPackedPlaintext(vectorOfInts1);

    // Ciphertext for the addition circuit
    uint32_t count = 1000;
    std::vector<Ciphertext<DCRTPoly>> vecCtxt(count);
    for (size_t i = 0; i < count; i++) {
        vecCtxt[i] = cryptoContextEvaluation->Encrypt(keyPairEvaluation.publicKey, plaintext1);
    }

    std::cerr << "\nRunning the following circuit: " << fileNameValidate << std::endl;

    // We run the encrypted computation the second time.
    auto ciphertextResult = cryptoContextEvaluation->EvaluateCircuit(circuitAddition, vecCtxt);

    // Decrypt final result
    Plaintext result;
    cryptoContextEvaluation->Decrypt(keyPairEvaluation.secretKey, ciphertextResult, &result);
    size_t vecSize = 8;
    result->SetLength(vecSize);
    std::cout << "Final output \n\t" << result->GetCKKSPackedValue() << std::endl;

    std::vector<std::complex<double>> expectedResult = {1000.0, 0, 1000.0, 1000.0, 1000.0, 1000.0, 1000.0, 1000.0};
    std::cout << "Expected result\n\t " << expectedResult << std::endl;

    fileNameValidate = DATAFOLDER + "/ckks-doubling.tsv";
    fileValidate     = std::ifstream(fileNameValidate);
    std::string circuitDoubling((std::istreambuf_iterator<char>(fileValidate)), std::istreambuf_iterator<char>());

    // Ciphertext for the doubling circuit
    count = 1;
    std::vector<Ciphertext<DCRTPoly>> vecCtxt2(count);
    for (size_t i = 0; i < count; i++) {
        vecCtxt2[i] = cryptoContextEvaluation->Encrypt(keyPairEvaluation.publicKey, plaintext1);
    }

    std::cerr << "\nRunning the following circuit: " << fileNameValidate << std::endl;

    // We run the encrypted computation the second time.
    ciphertextResult = cryptoContextEvaluation->EvaluateCircuit(circuitDoubling, vecCtxt2);

    // Decrypt final result
    cryptoContextEvaluation->Decrypt(keyPairEvaluation.secretKey, ciphertextResult, &result);
    result->SetLength(vecSize);
    std::cout << "Final output \n\t" << result->GetCKKSPackedValue() << std::endl;

    std::cout << "Expected result\n\t " << expectedResult << std::endl;
}

CryptoContext<DCRTPoly> GetCryptoContext(CCParams<CryptoContextCKKSRNS>& parameters) {
    // This demo is to illustrate how to use the security mode NOISE_FLOODING_DECRYPT to achieve enhanced security.
    parameters.SetDecryptionNoiseMode(NOISE_FLOODING_DECRYPT);

    // Specify main parameters
    parameters.SetSecretKeyDist(UNIFORM_TERNARY);

    /* Desired security level based on FHE standards. Note that this is different than NoiseDecryptionMode,
    * which also gives us enhanced security in CKKS when using NOISE_FLOODING_DECRYPT.
    * We must always use the same ring dimension in both iterations, so we set the security level to HEStd_NotSet,
    * and manually set the ring dimension.
    */
    parameters.SetRingDim(1 << 13);

    ScalingTechnique rescaleTech = FIXEDAUTO;
    usint dcrtBits               = 59;
    usint firstMod               = 60;

    std::vector<std::string> circuits;

    std::string fileName = DATAFOLDER + "/ckks-addition.tsv";

    std::cout << "circuit used during parameter/key generation = " << fileName << std::endl;

    std::ifstream file(fileName);
    circuits.push_back(std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>()));

    parameters.SetEvalCircuits(circuits);

    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetFirstModSize(firstMod);

    // In this example, we perform two multiplications and an addition.
    parameters.SetMultiplicativeDepth(0);

    // Generate crypto context.
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    // Enable features that you wish to use.
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(LEVELEDSHE);

    return cryptoContext;
}
