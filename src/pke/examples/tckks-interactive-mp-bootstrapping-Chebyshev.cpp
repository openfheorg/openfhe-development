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

Demo for Multi-Party Interactive Collective Bootstrapping in Threshold-CKKS (TCKKS).
3 parties want to evaluate a Chebyshev series on their secret input
This protocol is secure against (n-1) collusion among the participating parties, where n is
the number of participating parties.

*/

#define PROFILE

#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

static void checkApproximateEquality(const std::vector<std::complex<double>>& a,
                                     const std::vector<std::complex<double>>& b, int vectorSize, double epsilon) {
    std::vector<std::complex<double>> allTrue(vectorSize);
    std::vector<std::complex<double>> tmp(vectorSize);
    for (int i = 0; i < vectorSize; i++) {
        allTrue[i] = 1;
        tmp[i]     = abs(a[i] - b[i]) <= epsilon;
    }
    if (tmp != allTrue) {
        cerr << __func__ << " - " << __FILE__ << ":" << __LINE__ << " IntMPBoot - Ctxt Chebyshev Failed: " << endl;
        cerr << __func__ << " - " << __FILE__ << ":" << __LINE__ << " - is diff <= eps?: " << tmp << endl;
    }
    else {
        std::cout << "SUCESSFUL Bootstrapping!\n";
    }
}

void TCKKSCollectiveBoot(enum ScalingTechnique scaleTech);

int main(int argc, char* argv[]) {
    std::cout << "Interactive (3P) Bootstrapping Ciphertext [Chebyshev] (TCKKS) started ...\n";

    // Same test with different rescaling techniques in CKKS
    TCKKSCollectiveBoot(ScalingTechnique::FIXEDMANUAL);
    TCKKSCollectiveBoot(ScalingTechnique::FIXEDAUTO);
    TCKKSCollectiveBoot(ScalingTechnique::FLEXIBLEAUTO);
    TCKKSCollectiveBoot(ScalingTechnique::FLEXIBLEAUTOEXT);

    std::cout << "Interactive (3P) Bootstrapping Ciphertext [Chebyshev] (TCKKS) terminated gracefully!\n";

    return 0;
}

// Demonstrate interactive multi-party bootstrapping for 3 parties
// We follow Protocol 5 in https://eprint.iacr.org/2020/304, "Multiparty
// Homomorphic Encryption from Ring-Learning-With-Errors"

void TCKKSCollectiveBoot(enum ScalingTechnique scaleTech) {
    if (scaleTech != ScalingTechnique::FIXEDMANUAL && scaleTech != ScalingTechnique::FIXEDAUTO &&
        scaleTech != ScalingTechnique::FLEXIBLEAUTO && scaleTech != ScalingTechnique::FLEXIBLEAUTOEXT) {
        std::string errMsg = "ERROR: Scaling technique is not supported!";
        OPENFHE_THROW(errMsg);
    }

    CCParams<CryptoContextCKKSRNS> parameters;
    // A. Specify main parameters
    /*  A1) Secret key distribution
	* The secret key distribution for CKKS should either be SPARSE_TERNARY or UNIFORM_TERNARY.
	* The SPARSE_TERNARY distribution was used in the original CKKS paper,
	* but in this example, we use UNIFORM_TERNARY because this is included in the homomorphic
	* encryption standard.
	*/
    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);

    /*  A2) Desired security level based on FHE standards.
	* In this example, we use the "NotSet" option, so the example can run more quickly with
	* a smaller ring dimension. Note that this should be used only in
	* non-production environments, or by experts who understand the security
	* implications of their choices. In production-like environments, we recommend using
	* HEStd_128_classic, HEStd_192_classic, or HEStd_256_classic for 128-bit, 192-bit,
	* or 256-bit security, respectively. If you choose one of these as your security level,
	* you do not need to set the ring dimension.
	*/
    parameters.SetSecurityLevel(HEStd_128_classic);

    /*  A3) Scaling parameters.
	* By default, we set the modulus sizes and rescaling technique to the following values
	* to obtain a good precision and performance tradeoff. We recommend keeping the parameters
	* below unless you are an FHE expert.
	*/
    usint dcrtBits = 50;
    usint firstMod = 60;

    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(scaleTech);
    parameters.SetFirstModSize(firstMod);

    /*  A4) Multiplicative depth.
    * The multiplicative depth detemins the computational capability of the instantiated scheme. It should be set
    * according the following formula:
    * multDepth >= desired_depth + interactive_bootstrapping_depth
    * where,
    *   The desired_depth is the depth of the computation, as chosen by the user.
    *   The interactive_bootstrapping_depth is either 3 or 4, depending on the ciphertext compression mode: COMPACT vs SLACK (see below)
    * Example 1, if you want to perform a computation of depth 24, you can set multDepth to 10, use 6 levels
    * for computation and 4 for interactive bootstrapping. You will need to bootstrap 3 times.
    */
    parameters.SetMultiplicativeDepth(10);
    parameters.SetKeySwitchTechnique(KeySwitchTechnique::HYBRID);

    uint32_t batchSize = 16;
    parameters.SetBatchSize(batchSize);

    /*  Protocol-specific parameters (SLACK or COMPACT)
    * SLACK (default) uses larger masks, which makes it more secure theoretically. However, it is also slightly less efficient.
    * COMPACT uses smaller masks, which makes it more efficient. However, it is relatively less secure theoretically.
    * Both options can be used for practical security.
    * The following table summarizes the differences between SLACK and COMPACT:
    * Parameter	        SLACK	                                        COMPACT
    * Mask size	        Larger	                                        Smaller
    * Security	        More secure	                                    Less secure
    * Efficiency	    Less efficient	                                More efficient
    * Recommended use	For applications where security is paramount	For applications where efficiency is paramount
    */
    auto compressionLevel = COMPRESSION_LEVEL::COMPACT;
    parameters.SetInteractiveBootCompressionLevel(compressionLevel);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(MULTIPARTY);

    usint ringDim = cryptoContext->GetRingDimension();
    // This is the maximum number of slots that can be used for full packing.
    usint maxNumSlots = ringDim / 2;
    std::cout << "TCKKS scheme is using ring dimension " << ringDim << std::endl;
    std::cout << "TCKKS scheme number of slots         " << batchSize << std::endl;
    std::cout << "TCKKS scheme max number of slots     " << maxNumSlots << std::endl;
    std::cout << "TCKKS example with Scaling Technique " << scaleTech << std::endl;

    const usint numParties = 3;

    std::cout << "\n===========================IntMPBoot protocol parameters===========================\n";
    std::cout << "num of parties: " << numParties << "\n";
    std::cout << "===============================================================\n";

    double eps = 0.0001;

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> kp1;  // Party 1
    KeyPair<DCRTPoly> kp2;  // Party 2
    KeyPair<DCRTPoly> kp3;  // Lead party - who finalizes interactive bootstrapping

    KeyPair<DCRTPoly> kpMultiparty;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    // Round 1 (party A)
    kp1 = cryptoContext->KeyGen();

    // Generate evalmult key part for A
    auto evalMultKey = cryptoContext->KeySwitchGen(kp1.secretKey, kp1.secretKey);

    // Generate evalsum key part for A
    cryptoContext->EvalSumKeyGen(kp1.secretKey);
    auto evalSumKeys = std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(
        cryptoContext->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));

    // Round 2 (party B)
    kp2                  = cryptoContext->MultipartyKeyGen(kp1.publicKey);
    auto evalMultKey2    = cryptoContext->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);
    auto evalMultAB      = cryptoContext->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());
    auto evalMultBAB     = cryptoContext->MultiMultEvalKey(kp2.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());
    auto evalSumKeysB    = cryptoContext->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey->GetKeyTag());
    auto evalSumKeysJoin = cryptoContext->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey->GetKeyTag());
    cryptoContext->InsertEvalSumKey(evalSumKeysJoin);
    auto evalMultAAB   = cryptoContext->MultiMultEvalKey(kp1.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());
    auto evalMultFinal = cryptoContext->MultiAddEvalMultKeys(evalMultAAB, evalMultBAB, evalMultAB->GetKeyTag());
    cryptoContext->InsertEvalMultKey({evalMultFinal});

    /////////////////////
    // Round 3 (party C) - Lead Party (who encrypts and finalizes the bootstrapping protocol)
    kp3                 = cryptoContext->MultipartyKeyGen(kp2.publicKey);
    auto evalMultKey3   = cryptoContext->MultiKeySwitchGen(kp3.secretKey, kp3.secretKey, evalMultKey);
    auto evalMultABC    = cryptoContext->MultiAddEvalKeys(evalMultAB, evalMultKey3, kp3.publicKey->GetKeyTag());
    auto evalMultBABC   = cryptoContext->MultiMultEvalKey(kp2.secretKey, evalMultABC, kp3.publicKey->GetKeyTag());
    auto evalMultAABC   = cryptoContext->MultiMultEvalKey(kp1.secretKey, evalMultABC, kp3.publicKey->GetKeyTag());
    auto evalMultCABC   = cryptoContext->MultiMultEvalKey(kp3.secretKey, evalMultABC, kp3.publicKey->GetKeyTag());
    auto evalMultABABC  = cryptoContext->MultiAddEvalMultKeys(evalMultBABC, evalMultAABC, evalMultBABC->GetKeyTag());
    auto evalMultFinal2 = cryptoContext->MultiAddEvalMultKeys(evalMultABABC, evalMultCABC, evalMultCABC->GetKeyTag());
    cryptoContext->InsertEvalMultKey({evalMultFinal2});

    auto evalSumKeysC     = cryptoContext->MultiEvalSumKeyGen(kp3.secretKey, evalSumKeys, kp3.publicKey->GetKeyTag());
    auto evalSumKeysJoin2 = cryptoContext->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysC, kp3.publicKey->GetKeyTag());
    cryptoContext->InsertEvalSumKey(evalSumKeysJoin2);

    if (!kp1.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }
    if (!kp2.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }
    if (!kp3.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }

    // END of Key Generation

    std::vector<std::complex<double>> input({-4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0, 4.0});

    // Chebyshev coefficients
    std::vector<double> coefficients({1.0, 0.558971, 0.0, -0.0943712, 0.0, 0.0215023, 0.0, -0.00505348, 0.0, 0.00119324,
                                      0.0, -0.000281928, 0.0, 0.0000664347, 0.0, -0.0000148709});
    // Input range
    double a = -4;
    double b = 4;

    Plaintext pt1       = cryptoContext->MakeCKKSPackedPlaintext(input);
    usint encodedLength = input.size();

    auto ct1 = cryptoContext->Encrypt(kp3.publicKey, pt1);

    ct1 = cryptoContext->EvalChebyshevSeries(ct1, coefficients, a, b);

    // INTERACTIVE BOOTSTRAPPING STARTS

    ct1 = cryptoContext->IntMPBootAdjustScale(ct1);

    // Leading party (party B) generates a Common Random Poly (crp) at max coefficient modulus (QNumPrime).
    // a is sampled at random uniformly from R_{Q}
    auto crp = cryptoContext->IntMPBootRandomElementGen(kp3.publicKey);
    // Each party generates its own shares: maskedDecryptionShare and reEncryptionShare
    // (h_{0,i}, h_{1,i}) = (masked decryption share, re-encryption share)
    // we use a vector inseat of std::pair for Python API compatibility
    vector<Ciphertext<DCRTPoly>> sharesPair0;  // for Party A
    vector<Ciphertext<DCRTPoly>> sharesPair1;  // for Party B
    vector<Ciphertext<DCRTPoly>> sharesPair2;  // for Party C

    // extract c1 - element-wise
    auto c1 = ct1->Clone();
    c1->GetElements().erase(c1->GetElements().begin());
    // masked decryption on the client: c1 = a*s1
    sharesPair0 = cryptoContext->IntMPBootDecrypt(kp1.secretKey, c1, crp);
    sharesPair1 = cryptoContext->IntMPBootDecrypt(kp2.secretKey, c1, crp);
    sharesPair2 = cryptoContext->IntMPBootDecrypt(kp3.secretKey, c1, crp);

    vector<vector<Ciphertext<DCRTPoly>>> sharesPairVec;
    sharesPairVec.push_back(sharesPair0);
    sharesPairVec.push_back(sharesPair1);
    sharesPairVec.push_back(sharesPair2);

    // Party B finalizes the protocol by aggregating the shares and reEncrypting the results
    auto aggregatedSharesPair = cryptoContext->IntMPBootAdd(sharesPairVec);
    auto ciphertextOutput     = cryptoContext->IntMPBootEncrypt(kp3.publicKey, aggregatedSharesPair, crp, ct1);

    // INTERACTIVE BOOTSTRAPPING ENDS

    // distributed decryption

    auto ciphertextPartial1 = cryptoContext->MultipartyDecryptMain({ciphertextOutput}, kp1.secretKey);
    auto ciphertextPartial2 = cryptoContext->MultipartyDecryptMain({ciphertextOutput}, kp2.secretKey);
    auto ciphertextPartial3 = cryptoContext->MultipartyDecryptLead({ciphertextOutput}, kp3.secretKey);
    vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
    partialCiphertextVec.push_back(ciphertextPartial1[0]);
    partialCiphertextVec.push_back(ciphertextPartial2[0]);
    partialCiphertextVec.push_back(ciphertextPartial3[0]);

    Plaintext plaintextMultiparty;
    cryptoContext->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultiparty);
    plaintextMultiparty->SetLength(encodedLength);

    // Ground truth result
    std::vector<std::complex<double>> result(
        {0.0179885, 0.0474289, 0.119205, 0.268936, 0.5, 0.731064, 0.880795, 0.952571, 0.982011});
    Plaintext plaintextResult = cryptoContext->MakeCKKSPackedPlaintext(result);

    std::cout << "Ground Truth: \n\t" << plaintextResult->GetCKKSPackedValue() << std::endl;
    std::cout << "Computed Res: \n\t" << plaintextMultiparty->GetCKKSPackedValue() << std::endl;

    checkApproximateEquality(plaintextResult->GetCKKSPackedValue(), plaintextMultiparty->GetCKKSPackedValue(),
                             encodedLength, eps);

    std::cout << "\n============================ INTERACTIVE DECRYPTION ENDED ============================\n";

    std::cout << "\nTCKKSCollectiveBoot FHE example with rescaling technique: " << scaleTech << " Completed!"
              << std::endl;
}
