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

#include "openfhe.h"
#include "../lib/scheme/ckksrns/ckksrns-schemeswitching.cpp"

using namespace std;
using namespace lbcrypto;

void ArgMinExampleTiming(int argc, char** argv){
	uint32_t m = 1<<11;
    uint64_t w = 8;
	uint64_t k = 1;
	uint64_t slots = w*k;
    uint64_t init_size = 30;
    uint64_t dcrtBits = 50;
	auto secLevel = HEStd_NotSet;

    if(argc > 3)
		return;
	else if(argc == 2)
	{	w = atoi(argv[1]);
		slots = w*k;
	}
	else if(argc == 3)
	{
		w = atoi(argv[1]);
                slots = w*k;
		m = 1<<atoi(argv[2]);
		if(atoi(argv[2]) >= 16)
			secLevel = HEStd_128_classic;
	}

    CCParams<CryptoContextCKKSRNS> parameters;
	parameters.SetSecurityLevel(HEStd_NotSet);
	parameters.SetRingDim(m/2);
	parameters.SetMultiplicativeDepth(init_size);
	parameters.SetScalingModSize(dcrtBits);
	// parameters.SetBatchSize(16);
	parameters.SetScalingTechnique(FIXEDMANUAL);
	parameters.SetKeySwitchTechnique(HYBRID);
	parameters.SetFirstModSize(60);
	parameters.SetDigitSize(1);
	CryptoContext<DCRTPoly> ccCKKS = GenCryptoContext(parameters);

	//Turn on features
    ccCKKS->Enable(PKE);
    ccCKKS->Enable(KEYSWITCH);
    ccCKKS->Enable(LEVELEDSHE);
    ccCKKS->Enable(ADVANCEDSHE);
    ccCKKS->Enable(FHE);

    auto thiskp = ccCKKS->KeyGen();

    auto keys = ccCKKS->EvalBridgeSetup(false, 29, secLevel, slots);
    ccCKKS->EvalBridgeKeyGen(keys, thiskp);
	
	// ccCKKS->EvalBridgeSWKeyGen(keys, thiskp, ccCKKS);
    Ciphertext<DCRTPoly> toCompare;
	std::vector<std::complex<double>> inputVec;

	size_t argmin = 0;
	double min = 100;
	double lower_bound = -2.49;
    double upper_bound = 2.49;
    std::uniform_real_distribution<double> unif(lower_bound,upper_bound);
    std::default_random_engine re(std::random_device{}());
	for(size_t i = 0; i < w*k; i++){
		inputVec.push_back(unif(re));
		if(real(inputVec[i]) < min){
			min = real(inputVec[i]);
			argmin = i;
		}
	}
	// cout << inputVec << endl;
	
	Plaintext plaintext1 = ccCKKS->MakeCKKSPackedPlaintext(inputVec);
	toCompare = ccCKKS->Encrypt(thiskp.publicKey, plaintext1);


    auto compareRes = ccCKKS->EvalArgMinOneHot(toCompare, w, k, 10);
	cout << "Doing ArgMin for " << slots << " elements." << endl;

	Plaintext result;

	ccCKKS->Decrypt(thiskp.secretKey, compareRes , &result);
	result->SetLength(w*k);
	auto resVec = result->GetCKKSPackedValue();
	cout << "Expected result: 1 at slot " << argmin << " and the minimum is: " << min << endl;
	for(size_t i = 0; i < resVec.size() ; i++){
		if((real(resVec[i]) - 0) > 0.01){
			cout << "Argmin   result: " << real(resVec[i]) << " at slot " << i << " and the minimum is: " << real(inputVec[i]) << endl;
		}
	}
}

int main(int argc, char** argv) {
	ArgMinExampleTiming(argc, argv);
}