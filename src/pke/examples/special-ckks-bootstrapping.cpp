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

using namespace lbcrypto;

void SimpleBootstrapExample();

int main(int argc, char* argv[]) {
    SimpleBootstrapExample();
}

void SimpleBootstrapExample() {
    CCParams<CryptoContextCKKSRNS> parameters;
    SecretKeyDist secretKeyDist = SPARSE_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(512);

    // maximum values supported for 64-bit arithmetic are
    // dcrtBits = 59 and firstMod = 60
    uint32_t dcrtBits = 44;
    uint32_t firstMod = 45;
    uint32_t numSlots = 8;

    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetFirstModSize(firstMod);
    parameters.SetNumLargeDigits(3);
    parameters.SetBatchSize(numSlots);

    std::vector<uint32_t> levelBudget = {1, 1};

    uint32_t levelsAvailableAfterBootstrap = 2;
    usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    usint ringDim = cryptoContext->GetRingDimension();
    std::cout << "CKKS scheme is using ring dimension " << ringDim << std::endl << std::endl;

    // the default correction factor will be applied if the last argument is 0
    // if you want to disable the scaling down and use instead firstMod - dcrtBits, the last
    // argument can be set to 100; YSP I don't think this will be needed
    cryptoContext->EvalBootstrapSetup(levelBudget, {0, 0}, numSlots, 0);

    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    std::vector<double> x = {0.125, 0.25, 0.375, 0.5, 0.675, 0.75, 0.875, 1.0};
    size_t encodedLength  = x.size();

    // The plaintext will have 2 RNS limbs, level = depth - 1;
    // 1 RNS limb is used to scale down by the correction factor in bootstrapping
    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x, 1, depth - 1);

    ptxt->SetLength(encodedLength);
    std::cout << "Input: " << ptxt << std::endl;

    Ciphertext<DCRTPoly> ctxt = cryptoContext->Encrypt(keyPair.publicKey, ptxt);

    // extract polynomials from the ciphertext
    DCRTPoly element1 = ctxt->GetElements()[0];
    DCRTPoly element2 = ctxt->GetElements()[1];

    std::cerr << "parameters of element1 before converting to Poly: " << *element1.GetParams() << std::endl;

    // switch from EVALUATION representation to COEFFICIENT before converting to Poly
    element1.SetFormat(Format::COEFFICIENT);
    element2.SetFormat(Format::COEFFICIENT);

    // converts from Double-CRT to Multiprecision (Poly)
    Poly element1Poly = element1.CRTInterpolate();
    Poly element2Poly = element2.CRTInterpolate();

    std::cerr << "parameters of element1 after converting to Poly: " << *element1Poly.GetParams() << std::endl;

    // Q' that was used for the Double-CRT polynomial
    BigInteger bigQPrime = element1Poly.GetModulus();

    std::cerr << "Bits in Q': " << bigQPrime.GetMSB() << std::endl;

    // Set Q to 2^89 (firstMod + dcrtBits) - update this if changing firstMod or dcrtBits
    BigInteger bigQ = BigInteger("618970019642690137449562112");

    // std::cerr << "Element1Poly before modswitching: " << element1Poly << std::endl;

    // Do modulus switching from Q' to Q
    element1Poly = element1Poly.MultiplyAndRound(bigQ, bigQPrime);
    element1Poly.SwitchModulus(bigQ, 1, 0, 0);

    element2Poly = element2Poly.MultiplyAndRound(bigQ, bigQPrime);
    element2Poly.SwitchModulus(bigQ, 1, 0, 0);

    // std::cerr << "Element1Poly after modswitching: " << element1Poly << std::endl;

    std::cerr << "parameters of element1 after ModSwitching: " << *element1Poly.GetParams() << std::endl;

    // Set q to 2^40
    BigInteger Bigq          = BigInteger("1099511627776");
    Poly element1PolyReduced = element1Poly;
    // Apply mod q
    element1PolyReduced.SwitchModulus(Bigq, 1, 0, 0);

    std::cerr << "first integer before mod 2^40: " << element1Poly[0] << std::endl;
    std::cerr << "second integer before mod 2^40: " << element1Poly[1] << std::endl;

    std::cerr << "first integer after mod 2^40: " << element1PolyReduced[0] << std::endl;
    std::cerr << "second integer after mod 2^40: " << element1PolyReduced[1] << std::endl;

    // Switching back from Q to Q'
    Poly element1PolyNew = element1Poly.MultiplyAndRound(bigQPrime, bigQ);
    element1PolyNew.SwitchModulus(bigQPrime, 1, 0, 0);

    Poly element2PolyNew = element2Poly.MultiplyAndRound(bigQPrime, bigQ);
    element2PolyNew.SwitchModulus(bigQPrime, 1, 0, 0);

    // Going back to Double-CRT
    DCRTPoly element1New = DCRTPoly(element1PolyNew, element1.GetParams());
    DCRTPoly element2New = DCRTPoly(element2PolyNew, element1.GetParams());

    // Switching to NTT representation
    element1New.SetFormat(Format::EVALUATION);
    element2New.SetFormat(Format::EVALUATION);

    // New ciphertext after modulus switching
    auto ctxtNew = ctxt->Clone();
    ctxtNew->SetElements({element1New, element2New});

    std::cout << "\nInitial number of levels remaining: " << depth - ctxtNew->GetLevel() << std::endl;

    // Perform the bootstrapping operation. The goal is to increase the number of levels remaining
    // for HE computation.
    auto ciphertextAfter1 = cryptoContext->EvalBootstrap(ctxt);

    std::cout << "Number of levels remaining after bootstrapping: "
              << depth - ciphertextAfter1->GetLevel() - (ciphertextAfter1->GetNoiseScaleDeg() - 1) << std::endl
              << std::endl;

    Plaintext result;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter1, &result);
    result->SetLength(encodedLength);
    std::cout << "Output after bootstrapping w/o modulus switching \n\t" << result << std::endl;

    // Perform the bootstrapping operation. The goal is to increase the number of levels remaining
    // for HE computation.
    auto ciphertextAfter2 = cryptoContext->EvalBootstrap(ctxtNew);

    std::cout << "Number of levels remaining after bootstrapping: "
              << depth - ciphertextAfter2->GetLevel() - (ciphertextAfter2->GetNoiseScaleDeg() - 1) << std::endl
              << std::endl;

    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter2, &result);
    result->SetLength(encodedLength);
    std::cout << "Output after bootstrapping w/ modulus switching \n\t" << result << std::endl;
}
