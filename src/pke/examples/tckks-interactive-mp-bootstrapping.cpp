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

using namespace std;
using namespace lbcrypto;

/*
 * A utility class defining a party that is involved in the collective bootstrapping protocol
 */
struct Party
{
public:
	usint id; 																// unique party identifier starting from 0

	vector<Ciphertext<DCRTPoly>> sharesPair; 	// (h_{0,i}, h_{1,i}) = (masked decryption
																						// share, re-encryption share)
																						// we use a vector inseat of std::pair for Python API compatibility

	KeyPair<DCRTPoly> kpShard;							// key-pair shard (pk, sk_i)
};

void TCKKSCollectiveBoot(enum ScalingTechnique rescaleTech);

int main(int argc, char* argv[]) {

	std::cout << "Interactive Multi-Party Bootstrapping Ciphertext (TCKKS) started ...\n";

	// TODO:: - check this
//	TCKKSCollectiveBoot(APPROXRESCALE);
//	TCKKSCollectiveBoot(APPROXAUTO);
//	TCKKSCollectiveBoot(EXACTRESCALE);

	TCKKSCollectiveBoot(ScalingTechnique::FLEXIBLEAUTO);

 	std::cout << "Interactive Multi-Party Bootstrapping Ciphertext (TCKKS) terminated gracefully!\n";

	return 0;
}

// Demonstrate interactive multi-party bootstrapping for 3 parties
// We follow Protocol 5 in https://eprint.iacr.org/2020/304, "Multiparty
// Homomorphic Encryption from Ring-Learning-With-Errors"

void TCKKSCollectiveBoot(enum ScalingTechnique scaleTech) {

	// TODO:: how many scaling techniques to support
//	std::string scaleTechStr;
//	if (rescaleTech == ScalingTechnique::APPROXRESCALE)
//		scaleTechStr = "APPROXRESCALE";
//	else if (rescaleTech == ScalingTechnique::EXACTRESCALE)
//		scaleTechStr = "EXACTRESCALE";
//	else if (rescaleTech == ScalingTechnique::APPROXAUTO)
//		scaleTechStr = "APPROXAUTO";
//	else
//	{
//		std::string errMsg =
//		          "ERROR: Scaling technique is not supported!";
//		      PALISADE_THROW(config_error, errMsg);
//	}
	std::string scaleTechStr;
	if (scaleTech == ScalingTechnique::FLEXIBLEAUTO)
		scaleTechStr = "FLEXIBLEAUTO";
//	else if (rescaleTech == ScalingTechnique::EXACTRESCALE)
//		scaleTechStr = "EXACTRESCALE";
//	else if (rescaleTech == ScalingTechnique::APPROXAUTO)
//		scaleTechStr = "APPROXAUTO";
	else
	{
		std::string errMsg =
		          "ERROR: Scaling technique is not supported!";
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
  usint dcrtBits               = 59;
  usint firstMod               = 60;

  parameters.SetScalingModSize(dcrtBits);
  parameters.SetScalingTechnique(scaleTech);
  parameters.SetFirstModSize(firstMod);

  /*  A4) Multiplicative depth.
  * The goal of bootstrapping is to increase the number of available levels we have, or in other words,
  * to dynamically increase the multiplicative depth. However, the bootstrapping procedure itself
  * needs to consume a few levels to run. We compute the number of bootstrapping levels required
  * using GetBootstrapDepth, and add it to levelsUsedBeforeBootstrap to set our initial multiplicative
  * depth. We recommend using the input parameters below to get started.
  */
  parameters.SetMultiplicativeDepth(8-1);
  parameters.SetKeySwitchTechnique(KeySwitchTechnique::HYBRID);

  CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

  cryptoContext->Enable(PKE);
  cryptoContext->Enable(KEYSWITCH);
  cryptoContext->Enable(LEVELEDSHE);
  cryptoContext->Enable(ADVANCEDSHE);
  cryptoContext->Enable(MULTIPARTY);

  usint ringDim = cryptoContext->GetRingDimension();
  // This is the maximum number of slots that can be used for full packing.
  usint numSlots = ringDim / 2;
  std::cout << "TCKKS scheme is using ring dimension " << ringDim << std::endl << std::endl;
  std::cout << "TCKKS scheme number of slots         " << numSlots << std::endl << std::endl;
  std::cout << "TCKKS example with Scaling Technique " << scaleTechStr << std::endl;

  const usint numParties = 3; // n: number of parties involved in the interactive protocol
#if 0
	// Protocol-specific parameters
	auto compressionLevel = COMPRESSION_LEVEL::COMPACT;
	cc->SetMMpIntBootCiphertextCompressionLevel(compressionLevel);
#endif

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
	for (usint i = 0 ; i < numParties ; i++)
	{
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
	for (usint i = 0 ; i < numParties ; i++)
	{
		if( !parties[i].kpShard.good() ) {
				std::cout << "Key generation failed for party " << i << "!" << std::endl;
				exit(1);
			}
	}

	// Generate the collective public key
	vector<PrivateKey<DCRTPoly>> secretKeys;
	for (usint i = 0 ; i < numParties ; i++)
	{
		secretKeys.push_back(parties[i].kpShard.secretKey);
	}
	kpMultiparty = cryptoContext->MultipartyKeyGen(secretKeys);	// This is the same core key generation operation.

	// Prepare input vector
	std::vector<std::complex<double>> msg1({-0.9, -0.8, 0.2, 0.4});
	Plaintext ptxt1 = cryptoContext->MakeCKKSPackedPlaintext(msg1);

	// Encryption
	Ciphertext<DCRTPoly> inCtxt = cryptoContext->Encrypt(kpMultiparty.publicKey, ptxt1);
	DCRTPoly ptxtpoly = ptxt1->GetElement<DCRTPoly>();

	std::cout << "Compressing ctxt to the smallest possible number of towers!\n";
	inCtxt = cryptoContext->IntMPBootAdjustScale(inCtxt);

	// INTERACTIVE BOOTSTRAPPING STARTS

	std::cout << "\n============================ INTERACTIVE BOOTSTRAPPING STARTS ============================\n";

	// Leading party (P0) generates a Common Random Poly (a) at max coefficient modulus (QNumPrime).
	// a is sampled at random uniformly from R_{Q}
	Ciphertext<DCRTPoly> a = cryptoContext->IntMPBootRandomElementGen(parties[0].kpShard.publicKey);
	std::cout << "Common Random Poly (a) has been generated with coefficient modulus Q\n";


	// Each party generates its own shares: maskedDecryptionShare and reEncryptionShare
	vector<vector<Ciphertext<DCRTPoly>>> sharesPairVec;

	// Make a copy of input ciphertext and remove the first element (c0), we only
	// c1 for IntMPBootDecrypt
	auto c1 = inCtxt->Clone();
	c1->GetElements().erase(c1->GetElements().begin());
	for (usint i = 0 ; i < numParties ; i++)
	{
		std::cout << "Party " << i << " started its part in the Collective Bootstrapping Protocol\n";
		parties[i].sharesPair = cryptoContext->IntMPBootDecrypt(parties[i].kpShard.secretKey, c1, a);
		sharesPairVec.push_back(parties[i].sharesPair);
	}

#if 0
	// P0 finalizes the protocol by aggregating the shares and reEncrypting the results
	auto aggregatedSharesPair = cryptoContext->IntMPBootAdd(sharesPairVec);
	// Make sure you provide the non-striped ciphertext (inCtxt) in IntMPBootEncrypt
	auto outCtxt = cryptoContext->IntMPBootEncrypt(parties[0].kpShard.publicKey, aggregatedSharesPair, a, inCtxt);

	// INTERACTIVE BOOTSTRAPPING ENDS
	std::cout << "\n============================ INTERACTIVE BOOTSTRAPPING ENDED ============================\n";

	// Distributed decryption

	std::cout << "\n============================ INTERACTIVE DECRYPTION STARTED ============================ \n";

	vector<Ciphertext<DCRTPoly>> partialCiphertextVec;

	std::cout << "Party 0 started its part in the collective decryption protocol\n";
	partialCiphertextVec.push_back(
			cryptoContext->MultipartyDecryptLead(parties[0].kpShard.secretKey, {outCtxt})[0]
			);

	for (usint i = 1 ; i < numParties ; i++)
	{
		std::cout << "Party " << i << " started its part in the collective decryption protocol\n";
		partialCiphertextVec.push_back( cryptoContext->MultipartyDecryptMain(parties[i].kpShard.secretKey, {outCtxt})[0]
				);
	}

	// Checking the results
	Plaintext plaintextMultiparty;
	cryptoContext->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultiparty);
	plaintextMultiparty->SetLength(msg1.size());

	std::cout << "Original plaintext \n\t" << ptxt1->GetCKKSPackedValue() << std::endl;
	std::cout << "Result after bootstrapping \n\t" << plaintextMultiparty->GetCKKSPackedValue() << std::endl;

#else

	auto outCtxt = inCtxt;

		// INTERACTIVE BOOTSTRAPPING ENDS
		std::cout << "\n============================ INTERACTIVE BOOTSTRAPPING ENDED ============================\n";

		// Distributed decryption

		std::cout << "\n============================ INTERACTIVE DECRYPTION STARTED ============================ \n";

		vector<Ciphertext<DCRTPoly>> partialCiphertextVec;

		std::cout << "Party 0 started its part in the collective decryption protocol\n";
		partialCiphertextVec.push_back(
				cryptoContext->MultipartyDecryptLead({outCtxt}, parties[0].kpShard.secretKey)[0]
				);

		for (usint i = 1 ; i < numParties ; i++)
		{
			std::cout << "Party " << i << " started its part in the collective decryption protocol\n";
			partialCiphertextVec.push_back( cryptoContext->MultipartyDecryptMain({outCtxt}, parties[i].kpShard.secretKey)[0]
					);
		}

		// Checking the results
		Plaintext plaintextMultiparty;
		cryptoContext->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultiparty);
		plaintextMultiparty->SetLength(msg1.size());

		std::cout << "Original plaintext \n\t" << ptxt1->GetCKKSPackedValue() << std::endl;
		std::cout << "Result after bootstrapping \n\t" << plaintextMultiparty->GetCKKSPackedValue() << std::endl;

#endif

	std::cout << "\n============================ INTERACTIVE DECRYPTION ENDED ============================\n";
}
