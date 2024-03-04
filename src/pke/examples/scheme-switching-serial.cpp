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
  Real number serialization in a simple context. The goal of this is to show a simple setup for real number
  serialization before progressing into the next logical step - serialization and communication across
  2 separate entities
 */

#include <iomanip>
#include <tuple>
#include <unistd.h>

#include "openfhe.h"
#include "binfhecontext.h"
#include "scheme/ckksrns/schemeswitching-data-serializer.h"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;

/////////////////////////////////////////////////////////////////
// NOTE:
// If running locally, you may want to replace the "hardcoded" DATAFOLDER with
// the DATAFOLDER location below which gets the current working directory
/////////////////////////////////////////////////////////////////
// char buff[1024];
// std::string DATAFOLDER = std::string(getcwd(buff, 1024));

// Save-Load locations for keys
const std::string DATAFOLDER      = "demoData";
std::string ccLocation            = "/cryptocontext.txt";     // cc
std::string pubKeyLocation        = "/key_pub.txt";           // Pub key
std::string multKeyLocation       = "/key_mult.txt";          // relinearization key
std::string rotKeyLocation        = "/key_rot.txt";           // automorphism / rotation key
std::string paramssLocation       = "/paramss.txt";           // cc
std::string binccLocation         = "/bincryptocontext.txt";  // binfhe cc
std::string btRkLocation          = "/bt_rk.txt";             // binfhe bootstrapping refreshing key
std::string btSwkLocation         = "/bt_swk.txt";            // binfhe bootstrapping rotation key
std::string FHEWtoCKKSKeyLocation = "/key_swkFC.txt";         // switching key from FHEW to CKKS

// Save-load locations for RAW ciphertexts
std::string cipherLocation = "/ciphertext.txt";

// Save-load locations for evaluated ciphertext
std::string cipherArgminLocation = "/ciphertextArgmin.txt";

/**
 * Demarcate - Visual separator between the sections of code
 * @param msg - string message that you want displayed between blocks of
 * characters
 */
void demarcate(const std::string& msg) {
    std::cout << std::setw(50) << std::setfill('*') << '\n' << std::endl;
    std::cout << msg << std::endl;
    std::cout << std::setw(50) << std::setfill('*') << '\n' << std::endl;
}

/**
 * serverVerification
 *  - deserialize data from the client.
 *  - Verify that the results are as we expect
 * @param cc cryptocontext that was previously generated
 * @param kp keypair that was previously generated
 * @param vectorSize vector size of the vectors supplied
 * @return
 *  5-tuple of the plaintexts of various operations
 */

Plaintext serverVerification(CryptoContext<DCRTPoly>& cc, KeyPair<DCRTPoly>& kp, int vectorSize) {
    Ciphertext<DCRTPoly> serverCiphertextFromClient_Argmin;

    Serial::DeserializeFromFile(DATAFOLDER + cipherArgminLocation, serverCiphertextFromClient_Argmin, SerType::BINARY);
    std::cout << "Deserialized all data from client on server" << '\n' << std::endl;

    demarcate("Part 5: Correctness verification");

    Plaintext serverPlaintextFromClient_Argmin;
    cc->Decrypt(kp.secretKey, serverCiphertextFromClient_Argmin, &serverPlaintextFromClient_Argmin);

    serverPlaintextFromClient_Argmin->SetLength(vectorSize);

    return serverPlaintextFromClient_Argmin;
}

/**
 * serverSetupAndWrite
 *  - simulates a server at startup where we generate a cryptocontext and keys.
 *  - then, we generate some data (akin to loading raw data on an enclave)
 * before encrypting the data
 * @param ringDim - ring dimension
 * @param batchSize - batch size to use
 * @param multDepth - multiplication depth
 * @param logQ_LWE - number of bits of the ciphertext modulus in FHEW
 * @param oneHot - flag to indicate one hot encoding of the result
 * @return Tuple<cryptoContext, keyPair>
 */
std::tuple<CryptoContext<DCRTPoly>, KeyPair<DCRTPoly>, int> serverSetupAndWrite(uint32_t ringDim, uint32_t batchSize,
                                                                                uint32_t multDepth,
                                                                                uint32_t scaleModSize,
                                                                                uint32_t firstModSize,
                                                                                uint32_t logQ_LWE, bool oneHot) {
    SecurityLevel sl      = HEStd_NotSet;
    BINFHE_PARAMSET slBin = TOY;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);

    CryptoContext<DCRTPoly> serverCC = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    serverCC->Enable(PKE);
    serverCC->Enable(KEYSWITCH);
    serverCC->Enable(LEVELEDSHE);
    serverCC->Enable(ADVANCEDSHE);
    serverCC->Enable(FHE);
    serverCC->Enable(SCHEMESWITCH);

    std::cout << "Cryptocontext generated" << std::endl;

    KeyPair<DCRTPoly> serverKP = serverCC->KeyGen();
    std::cout << "Keypair generated" << std::endl;

    SchSwchParams params;
    params.SetSecurityLevelCKKS(sl);
    params.SetSecurityLevelFHEW(slBin);
    params.SetCtxtModSizeFHEWLargePrec(logQ_LWE);
    params.SetNumSlotsCKKS(batchSize);
    params.SetNumValues(batchSize);
    params.SetComputeArgmin(true);
    params.SetOneHotEncoding(oneHot);
    auto privateKeyFHEW = serverCC->EvalSchemeSwitchingSetup(params);

    serverCC->EvalSchemeSwitchingKeyGen(serverKP, privateKeyFHEW);

    std::vector<std::complex<double>> vec = {1.0, 2.0, 3.0, 4.0};
    std::cout << "\nDisplaying data vector: ";

    for (auto& v : vec) {
        std::cout << v << ',';
    }

    std::cout << '\n' << std::endl;

    Plaintext serverP = serverCC->MakeCKKSPackedPlaintext(vec);

    std::cout << "Plaintext version of vector: " << serverP << std::endl;

    std::cout << "Plaintexts have been generated from complex-double vectors" << std::endl;

    auto serverC = serverCC->Encrypt(serverKP.publicKey, serverP);

    std::cout << "Ciphertext have been generated from Plaintext" << std::endl;

    /*
   * Part 2:
   * We serialize the following:
   *  Cryptocontext
   *  Public key
   *  relinearization (eval mult keys)
   *  rotation keys
   *  binfhe cryptocontext
   *  binfhe bootstrapping keys
   *  Some of the ciphertext
   *
   *  We serialize all of them to files
   */

    demarcate("Scheme Switching Part 2: Data Serialization (server)");

    SchemeSwitchingDataSerializer serializer(serverCC, serverKP.publicKey, serverC);
    serializer.Serialize();

    return std::make_tuple(serverCC, serverKP, vec.size());
}

/**
 * clientProcess
 *  - deserialize data from a file which simulates receiving data from a server
 * after making a request
 *  - we then process the data
 */

void clientProcess(uint32_t modulus_LWE) {
    CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
    CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
    CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

    SchemeSwitchingDataDeserializer deserializer;
    deserializer.Deserialize();

    CryptoContext<DCRTPoly> clientCC{deserializer.getCryptoContext()};
    PublicKey<DCRTPoly> clientPublicKey{deserializer.getPublicKey()};
    std::shared_ptr<lbcrypto::BinFHEContext> clientBinCC{clientCC->GetBinCCForSchemeSwitch()};
    Ciphertext<DCRTPoly> clientC{deserializer.getRAWCiphertext()};

    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    double scaleSign = 512.0;
    auto beta        = clientBinCC->GetBeta().ConvertToInt();
    auto pLWE        = modulus_LWE / (2 * beta);  // Large precision

    clientCC->EvalCompareSwitchPrecompute(pLWE, scaleSign, false);

    std::cout << "Done with precomputations" << '\n' << std::endl;

    // Compute on the ciphertext
    auto clientCiphertextArgmin =
        clientCC->EvalMinSchemeSwitching(clientC, clientPublicKey, clientC->GetSlots(), clientC->GetSlots(), 0, 1);

    std::cout << "Done with argmin computation" << '\n' << std::endl;

    // Now, we want to simulate a client who is encrypting data for the server to
    // decrypt. E.g weights of a machine learning algorithm
    demarcate("Part 3.5: Client Serialization of data that has been operated on");

    Serial::SerializeToFile(DATAFOLDER + cipherArgminLocation, clientCiphertextArgmin[1], SerType::BINARY);

    std::cout << "Serialized ciphertext from client" << '\n' << std::endl;
}

int main() {
    std::cout << "This program requres the subdirectory `" << DATAFOLDER << "' to exist, otherwise you will get "
              << "an error writing serializations." << std::endl;

    // Set main params
    uint32_t ringDim      = 64;
    uint32_t batchSize    = 4;
    uint32_t multDepth    = 13 + static_cast<int>(std::log2(batchSize));
    uint32_t logQ_ccLWE   = 25;
    bool oneHot           = true;
    uint32_t scaleModSize = 50;
    uint32_t firstModSize = 60;

    const int cryptoContextIdx = 0;
    const int keyPairIdx       = 1;
    const int vectorSizeIdx    = 2;

    demarcate(
        "Scheme switching Part 1: Cryptocontext generation, key generation, data encryption "
        "(server)");

    auto tupleCryptoContext_KeyPair =
        serverSetupAndWrite(ringDim, batchSize, multDepth, scaleModSize, firstModSize, logQ_ccLWE, oneHot);

    auto cc         = std::get<cryptoContextIdx>(tupleCryptoContext_KeyPair);
    auto kp         = std::get<keyPairIdx>(tupleCryptoContext_KeyPair);
    auto vectorSize = std::get<vectorSizeIdx>(tupleCryptoContext_KeyPair);

    demarcate("Scheme switching Part 3: Client deserialize all data");

    clientProcess(1 << logQ_ccLWE);

    demarcate("Scheme switching Part 4: Server deserialization of data from client. ");

    auto ArgminRes = serverVerification(cc, kp, vectorSize);

    // vec1: {1,2,3,4}

    std::cout << ArgminRes << std::endl;  // EXPECT: 1.0, 0.0, 0.0, 0.0
}
