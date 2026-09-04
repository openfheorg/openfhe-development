//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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

Example for generating the application's evaluation keys at a reduced level
(https://github.com/openfheorg/openfhe-development/issues/413) in a CKKS
bootstrapping workload.

In an iterated computation (bootstrap -> compute -> bootstrap -> ...), the
bootstrapping keys must be full-size: the CoeffsToSlots rotations run right
after the modulus raise, at the largest number of RNS limbs. The application's
own rotation keys, however, only ever touch post-bootstrap ciphertexts, which
carry far fewer limbs. Generating those keys at the matching level (or
compressing existing keys with CompressEvalKey) shrinks them substantially at
no cost in performance or precision.

*/

#define PROFILE  // turns on the reporting of timing results

#include "openfhe.h"

// header files needed for (de)serialization to measure key sizes
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include <iostream>
#include <sstream>
#include <vector>

using namespace lbcrypto;

static double SerializedSizeMB(const EvalKey<DCRTPoly>& evalKey) {
    std::stringstream ss;
    Serial::Serialize(evalKey, ss, SerType::BINARY);
    return static_cast<double>(ss.str().size()) / (1024.0 * 1024.0);
}

int main(int argc, char* argv[]) {
    // Step 1: Set up the cryptocontext the same way as in simple-ckks-bootstrapping.cpp
    CCParams<CryptoContextCKKSRNS> parameters;
    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);
    // Use HEStd_NotSet only in non-production environments
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12);

#if NATIVEINT == 128
    ScalingTechnique rescaleTech = FIXEDAUTO;
    uint32_t dcrtBits            = 78;
    uint32_t firstMod            = 89;
#else
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    uint32_t dcrtBits            = 59;
    uint32_t firstMod            = 60;
#endif
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);

    std::vector<uint32_t> levelBudget      = {4, 4};
    uint32_t levelsAvailableAfterBootstrap = 10;
    uint32_t depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    uint32_t ringDim     = cryptoContext->GetRingDimension();
    uint32_t numSlots    = ringDim / 2;
    const uint32_t sizeQ = cryptoContext->GetElementParams()->GetParams().size();
    std::cout << "CKKS scheme ring dimension: " << ringDim << ", RNS limbs in Q: " << sizeQ << "\n\n";

    cryptoContext->EvalBootstrapSetup(levelBudget, {0, 0}, numSlots);

    auto keyPair = cryptoContext->KeyGen();

    // Step 2: Generate the keys that must remain FULL-SIZE.
    // The relinearization key is used inside bootstrapping (EvalMod squarings) at a large
    // number of limbs, and the CoeffsToSlots rotations run right after the modulus raise,
    // so EvalBootstrapKeyGen must generate its keys at level 0.
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    // Step 3: Bootstrap once to observe how many limbs a post-bootstrap ciphertext carries.
    // This is the largest ciphertext the application's own rotation keys will ever touch.
    std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
    size_t encodedLength  = x.size();

    // start from a depleted ciphertext that has used up all of its levels
    Plaintext ptxt            = cryptoContext->MakeCKKSPackedPlaintext(x, 1, depth - 1);
    Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt);

    TimeVar t;
    TIC(t);
    auto ciphertextAfter        = cryptoContext->EvalBootstrap(ciph);
    double timeBootstrap        = TOC(t);
    const uint32_t limbsAfterBT = ciphertextAfter->GetElements()[0].GetNumOfElements();
    std::cout << "EvalBootstrap: " << timeBootstrap << " ms\n";

    // the number of limbs to drop from the application's rotation keys
    const uint32_t appKeyLevels = sizeQ - limbsAfterBT;
    std::cout << "Limbs in a post-bootstrap ciphertext: " << limbsAfterBT << " (out of " << sizeQ << ")\n";
    std::cout << "Application rotation keys are generated with levels = " << appKeyLevels << "\n";

    // Step 4: Choose the application's rotation indices.
    // EvalBootstrapKeyGen has already stored full-size keys for its own rotation indices
    // under the same secret key. Requesting a reduced key for one of those indices is a
    // no-op (the cryptocontext keeps the more capable, full-size key), which is correct but
    // saves nothing for that index. To make the savings visible, this example picks
    // rotation indices that do not overlap the bootstrapping set. We also reserve two
    // extra non-overlapping indices for full-size reference keys used in the comparisons.
    //
    // Clearing the key map and regenerating does not change this picture: the bootstrapping
    // keys must be regenerated full-size, and whichever set is generated first, an index
    // used by bootstrapping ends up with its full-size key (there is one map slot per
    // index, and bootstrapping needs the full key in it). Clearing is the right tool only
    // when a pipeline is done bootstrapping for good: then ClearEvalAutomorphismKeys(keyTag)
    // followed by regenerating only the application's keys at the reduced level also frees
    // the entire (much larger) bootstrapping key set.
    const uint32_t M   = 2 * ringDim;
    const auto& algo   = cryptoContext->GetScheme();
    const auto& keyMap = CryptoContextImpl<DCRTPoly>::GetEvalAutomorphismKeyMap(keyPair.secretKey->GetKeyTag());

    std::vector<int32_t> freshRots;
    for (int32_t r = 1; freshRots.size() < 4 && r < 1000; ++r) {
        if (keyMap.find(algo->FindAutomorphismIndex(r, M)) == keyMap.end())
            freshRots.push_back(r);
    }
    if (freshRots.size() < 4) {
        std::cerr << "Could not find enough rotation indices without existing keys\n";
        return 1;
    }
    const int32_t appRot1 = freshRots[0];
    const int32_t appRot2 = freshRots[1];
    const int32_t refRot1 = freshRots[2];
    const int32_t refRot2 = freshRots[3];
    std::cout << "Application rotation indices (chosen to not overlap the bootstrapping rotations): " << appRot1
              << ", " << appRot2 << "\n\n";

    // Step 5: Generate the application's keys at the reduced level, and two full-size
    // reference keys for the same-shaped comparisons. Key generation scales with the key's
    // size (digits x limbs), so the reduced keys should be proportionally faster to generate.
    TIC(t);
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {appRot1, appRot2}, appKeyLevels);
    double timeKeyGenReduced = TOC(t);
    TIC(t);
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {refRot1, refRot2});
    double timeKeyGenFull = TOC(t);

    const auto& keyApp  = keyMap.at(algo->FindAutomorphismIndex(appRot1, M));
    const auto& keyFull = keyMap.at(algo->FindAutomorphismIndex(refRot1, M));
    std::cout << "Full-size rotation key:   " << keyFull->GetAVector()[0].GetNumOfElements() << " limbs, "
              << SerializedSizeMB(keyFull) << " MB\n";
    std::cout << "Application rotation key: " << keyApp->GetAVector()[0].GetNumOfElements() << " limbs, "
              << SerializedSizeMB(keyApp) << " MB\n";

    // CompressEvalKey produces the same reduction for a key that already exists:
    auto keyCompressed = cryptoContext->CompressEvalKey(keyFull, appKeyLevels);
    std::cout << "The full key compressed:  " << keyCompressed->GetAVector()[0].GetNumOfElements() << " limbs, "
              << SerializedSizeMB(keyCompressed) << " MB\n\n";

    // Step 6: Timings.
    // Applying a key does NOT depend on the key's size - the cost of EvalRotate is
    // determined by the ciphertext's limbs - so the two rotation timings below should be
    // about equal.
    constexpr uint32_t numTrials = 10;
    TIC(t);
    for (uint32_t i = 0; i < numTrials; ++i) {
        auto tmp = cryptoContext->EvalRotate(ciphertextAfter, refRot1);
    }
    double timeRotFull = TOC(t) / numTrials;
    TIC(t);
    for (uint32_t i = 0; i < numTrials; ++i) {
        auto tmp = cryptoContext->EvalRotate(ciphertextAfter, appRot1);
    }
    double timeRotReduced = TOC(t) / numTrials;

    std::cout << "Timings:\n";
    std::cout << "  rotation key generation, 2 full-size keys: " << timeKeyGenFull << " ms\n";
    std::cout << "  rotation key generation, 2 reduced keys:   " << timeKeyGenReduced << " ms\n";
    std::cout << "  EvalRotate with the full-size key:         " << timeRotFull << " ms (avg of " << numTrials
              << ")\n";
    std::cout << "  EvalRotate with the reduced key:           " << timeRotReduced << " ms (avg of " << numTrials
              << ")\n\n";

    // Step 7: Compute on the bootstrapped ciphertext using the reduced keys:
    // a sliding-window sum followed by a squaring.
    auto ciphSum = cryptoContext->EvalAdd(ciphertextAfter, cryptoContext->EvalRotate(ciphertextAfter, appRot1));
    ciphSum      = cryptoContext->EvalAdd(ciphSum, cryptoContext->EvalRotate(ciphertextAfter, appRot2));
    auto ciphOut = cryptoContext->EvalMult(ciphSum, ciphSum);

    Plaintext result;
    cryptoContext->Decrypt(keyPair.secretKey, ciphOut, &result);
    result->SetLength(encodedLength);

    auto xAt = [&x, encodedLength](size_t i) {
        return (i < encodedLength) ? x[i] : 0.0;
    };
    std::cout << "Expected (x[i] + x[i+" << appRot1 << "] + x[i+" << appRot2 << "])^2: ";
    for (size_t i = 0; i < encodedLength; ++i) {
        double s = xAt(i) + xAt(i + appRot1) + xAt(i + appRot2);
        std::cout << s * s << ((i + 1 < encodedLength) ? " " : "\n");
    }
    std::cout << "Computed with reduced keys: " << result;

    // Step 8: The reduced keys refuse ciphertexts with more limbs than they support.
    // A freshly encrypted ciphertext at level 0 carries all limbs, so rotating it with one
    // of the application's reduced keys throws an informative exception.
    auto ptxtFresh = cryptoContext->MakeCKKSPackedPlaintext(x);
    auto ciphFresh = cryptoContext->Encrypt(keyPair.publicKey, ptxtFresh);
    try {
        cryptoContext->EvalRotate(ciphFresh, appRot1);
        std::cout << "\nERROR: rotating a full-size ciphertext with a reduced key should have thrown\n";
    }
    catch (const OpenFHEException& e) {
        std::cout << "\nRotating a fresh (full-size) ciphertext with a reduced key throws, as expected:\n    "
                  << e.what() << "\n";
    }

    cryptoContext->ClearStaticMapsAndVectors();
    return 0;
}
