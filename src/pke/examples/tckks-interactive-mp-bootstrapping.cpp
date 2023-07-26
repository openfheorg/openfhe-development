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
 Demo for Multi-Party Interactive Collective Bootstrapping with Threshold-CKKS (TCKKS) for
 a single ciphertext.
 It is a trivial example showing how to encrypt, bootstrap, and decrypt for 3 parties. No
 computation is done here.

 This protocol is secure against (n-1) collusion among the participating parties, where n is
 the number of participating parties.
 */

#define PROFILE

#include "openfhe.h"

using namespace lbcrypto;

/*
 * A utility class defining a party that is involved in the collective bootstrapping protocol
 */
struct Party {
public:
    usint id;  // unique party identifier starting from 0

    std::vector<Ciphertext<DCRTPoly>> sharesPair;  // (h_{0,i}, h_{1,i}) = (masked decryption
                                                   // share, re-encryption share)
                                                   // we use a vector inseat of std::pair for Python API compatibility

    KeyPair<DCRTPoly> kpShard;  // key-pair shard (pk, sk_i)
};

void TCKKSCollectiveBoot(enum ScalingTechnique rescaleTech);

int main(int argc, char* argv[]) {
    std::cout << "Interactive Multi-Party Bootstrapping Ciphertext (TCKKS) started ...\n";

    // Same test with different rescaling techniques in CKKS
    TCKKSCollectiveBoot(ScalingTechnique::FIXEDMANUAL);
    TCKKSCollectiveBoot(ScalingTechnique::FIXEDAUTO);
    TCKKSCollectiveBoot(ScalingTechnique::FLEXIBLEAUTO);
    TCKKSCollectiveBoot(ScalingTechnique::FLEXIBLEAUTOEXT);

    std::cout << "Interactive Multi-Party Bootstrapping Ciphertext (TCKKS) terminated gracefully!\n";

    return 0;
}

// Demonstrate interactive multi-party bootstrapping for 3 parties
// We follow Protocol 5 in https://eprint.iacr.org/2020/304, "Multiparty
// Homomorphic Encryption from Ring-Learning-With-Errors"

void TCKKSCollectiveBoot(enum ScalingTechnique scaleTech) {
    if (scaleTech != ScalingTechnique::FIXEDMANUAL && scaleTech != ScalingTechnique::FIXEDAUTO &&
        scaleTech != ScalingTechnique::FLEXIBLEAUTO && scaleTech != ScalingTechnique::FLEXIBLEAUTOEXT) {
        std::string errMsg = "ERROR: Scaling technique is not supported!";
        OPENFHE_THROW(config_error, errMsg);
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
    uint32_t multiplicativeDepth = 7;
    parameters.SetMultiplicativeDepth(multiplicativeDepth);
    parameters.SetKeySwitchTechnique(KeySwitchTechnique::HYBRID);

    uint32_t batchSize = 4;
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
    auto compressionLevel = COMPRESSION_LEVEL::SLACK;
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

    const usint numParties = 3;  // n: number of parties involved in the interactive protocol

    std::cout << "\n===========================IntMPBoot protocol parameters===========================\n";
    std::cout << "number of parties: " << numParties << "\n";
    std::cout << "===============================================================\n";

    std::vector<Party> parties(numParties);

    // Joint public key
    KeyPair<DCRTPoly> kpMultiparty;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    std::cout << "Running key generation (used for source data)..." << std::endl;

    // Initialization - Assuming numParties (n) of parties
    // P0 is the leading party
    for (usint i = 0; i < numParties; i++) {
        parties[i].id = i;
        std::cout << "Party " << parties[i].id << " started.\n";
        if (0 == i)
            parties[i].kpShard = cryptoContext->KeyGen();
        else
            parties[i].kpShard = cryptoContext->MultipartyKeyGen(parties[0].kpShard.publicKey);
        std::cout << "Party " << i << " key generation completed.\n";
    }
    std::cout << "Joint public key for (s_0 + s_1 + ... + s_n) is generated..." << std::endl;

    // Assert everything is good
    for (usint i = 0; i < numParties; i++) {
        if (!parties[i].kpShard.good()) {
            std::cout << "Key generation failed for party " << i << "!" << std::endl;
            exit(1);
        }
    }

    // Generate the collective public key
    std::vector<PrivateKey<DCRTPoly>> secretKeys;
    for (usint i = 0; i < numParties; i++) {
        secretKeys.push_back(parties[i].kpShard.secretKey);
    }
    kpMultiparty = cryptoContext->MultipartyKeyGen(secretKeys);  // This is the same core key generation operation.

    // Prepare input vector
    std::vector<std::complex<double>> msg1({-0.9, -0.8, 0.2, 0.4});
    Plaintext ptxt1 = cryptoContext->MakeCKKSPackedPlaintext(msg1);

    // Encryption
    Ciphertext<DCRTPoly> inCtxt = cryptoContext->Encrypt(kpMultiparty.publicKey, ptxt1);
    DCRTPoly ptxtpoly           = ptxt1->GetElement<DCRTPoly>();

    std::cout << "Compressing ctxt to the smallest possible number of towers!\n";
    inCtxt = cryptoContext->IntMPBootAdjustScale(inCtxt);

    // INTERACTIVE BOOTSTRAPPING STARTS

    std::cout << "\n============================ INTERACTIVE BOOTSTRAPPING STARTS ============================\n";

    // Leading party (P0) generates a Common Random Poly (a) at max coefficient modulus (QNumPrime).
    // a is sampled at random uniformly from R_{Q}
    Ciphertext<DCRTPoly> a = cryptoContext->IntMPBootRandomElementGen(parties[0].kpShard.publicKey);
    std::cout << "Common Random Poly (a) has been generated with coefficient modulus Q\n";

    // Each party generates its own shares: maskedDecryptionShare and reEncryptionShare
    std::vector<std::vector<Ciphertext<DCRTPoly>>> sharesPairVec;

    // Make a copy of input ciphertext and remove the first element (c0), we only
    // c1 for IntMPBootDecrypt
    auto c1 = inCtxt->Clone();
    c1->GetElements().erase(c1->GetElements().begin());
    for (usint i = 0; i < numParties; i++) {
        std::cout << "Party " << i << " started its part in the Collective Bootstrapping Protocol\n";
        parties[i].sharesPair = cryptoContext->IntMPBootDecrypt(parties[i].kpShard.secretKey, c1, a);
        sharesPairVec.push_back(parties[i].sharesPair);
    }

    // P0 finalizes the protocol by aggregating the shares and reEncrypting the results
    auto aggregatedSharesPair = cryptoContext->IntMPBootAdd(sharesPairVec);
    // Make sure you provide the non-striped ciphertext (inCtxt) in IntMPBootEncrypt
    auto outCtxt = cryptoContext->IntMPBootEncrypt(parties[0].kpShard.publicKey, aggregatedSharesPair, a, inCtxt);

    // INTERACTIVE BOOTSTRAPPING ENDS
    std::cout << "\n============================ INTERACTIVE BOOTSTRAPPING ENDED ============================\n";

    // Distributed decryption

    std::cout << "\n============================ INTERACTIVE DECRYPTION STARTED ============================ \n";

    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec;

    std::cout << "Party 0 started its part in the collective decryption protocol\n";
    partialCiphertextVec.push_back(cryptoContext->MultipartyDecryptLead({outCtxt}, parties[0].kpShard.secretKey)[0]);

    for (usint i = 1; i < numParties; i++) {
        std::cout << "Party " << i << " started its part in the collective decryption protocol\n";
        partialCiphertextVec.push_back(
            cryptoContext->MultipartyDecryptMain({outCtxt}, parties[i].kpShard.secretKey)[0]);
    }

    // Checking the results
    std::cout << "MultipartyDecryptFusion ...\n";
    Plaintext plaintextMultiparty;
    cryptoContext->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultiparty);
    plaintextMultiparty->SetLength(msg1.size());

    std::cout << "Original plaintext \n\t" << ptxt1->GetCKKSPackedValue() << std::endl;
    std::cout << "Result after bootstrapping \n\t" << plaintextMultiparty->GetCKKSPackedValue() << std::endl;

    std::cout << "\n============================ INTERACTIVE DECRYPTION ENDED ============================\n";
}
