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
std::string CKKStoFHEWKeyLocation = "/key_swkCF.txt";         // switching key from CKKS to FHEW
std::string FHEWtoCKKSKeyLocation = "/key_swkFC.txt";         // switching key from FHEW to CKKS

// Save-load locations for RAW ciphertexts
std::string cipherLocation   = "/ciphertext.txt";
std::string cipherKSLocation = "/ciphertextKS.txt";

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
 * serverSetupAndWriteSSObj
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
std::tuple<CryptoContext<DCRTPoly>, KeyPair<DCRTPoly>, int> serverSetupAndWriteSSObj(
    uint32_t ringDim, uint32_t batchSize, uint32_t multDepth, uint32_t scaleModSize, uint32_t firstModSize,
    uint32_t logQ_LWE, bool oneHot) {
    SecurityLevel sl      = HEStd_NotSet;
    BINFHE_PARAMSET slBin = TOY;
    bool arbFunc          = false;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(FIXEDAUTO);

    CryptoContext<DCRTPoly> serverCC = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    serverCC->Enable(PKE);
    serverCC->Enable(KEYSWITCH);
    serverCC->Enable(LEVELEDSHE);
    serverCC->Enable(ADVANCEDSHE);
    serverCC->Enable(SCHEMESWITCH);

    std::cout << "Cryptocontext generated" << std::endl;

    KeyPair<DCRTPoly> serverKP = serverCC->KeyGen();
    std::cout << "Keypair generated" << std::endl;

    auto objSchemeSwitch = std::make_shared<SWITCHCKKSRNS>();

    auto privateKeyFHEW = objSchemeSwitch->EvalSchemeSwitchingSetup(
        *serverCC, sl, slBin, arbFunc, logQ_LWE, false, batchSize, batchSize, true, oneHot, false, 27, 0, 0, 1, 0);
    auto serverBinCC = objSchemeSwitch->GetBinCCForSchemeSwitch();

    auto evalKeys = objSchemeSwitch->EvalSchemeSwitchingKeyGen(serverKP, privateKeyFHEW);

    // Andreea: after Dmitriy's PR is merged, change this
    auto ekv = serverCC->GetAllEvalAutomorphismKeys().find(serverKP.secretKey->GetKeyTag());
    if (ekv == serverCC->GetAllEvalAutomorphismKeys().end()) {
        serverCC->GetAllEvalAutomorphismKeys()[serverKP.secretKey->GetKeyTag()] = evalKeys;
    }
    else {
        auto& currRotMap = serverCC->GetEvalAutomorphismKeyMap(serverKP.secretKey->GetKeyTag());
        auto iterRowKeys = evalKeys->begin();
        while (iterRowKeys != evalKeys->end()) {
            auto idx = iterRowKeys->first;
            // Search current rotation key map and add key
            // only if it doesn't exist
            if (currRotMap.find(idx) == currRotMap.end()) {
                currRotMap.insert(*iterRowKeys);
            }
            iterRowKeys++;
        }
    }

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

    demarcate("Part 2: Data Serialization (server)");

    if (!Serial::SerializeToFile(DATAFOLDER + ccLocation, serverCC, SerType::JSON)) {
        std::cerr << "Error writing serialization of the crypto context to "
                     "cryptocontext.txt"
                  << std::endl;
        std::exit(1);
    }

    std::cout << "Cryptocontext serialized" << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + pubKeyLocation, serverKP.publicKey, SerType::JSON)) {
        std::cerr << "Exception writing public key to pubkey.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Public key serialized" << std::endl;

    std::ofstream multKeyFile(DATAFOLDER + multKeyLocation, std::ios::out | std::ios::binary);
    if (multKeyFile.is_open()) {
        if (!serverCC->SerializeEvalMultKey(multKeyFile, SerType::JSON)) {
            std::cerr << "Error writing eval mult keys" << std::endl;
            std::exit(1);
        }
        std::cout << "EvalMult/ relinearization keys have been serialized" << std::endl;
        multKeyFile.close();
    }
    else {
        std::cerr << "Error serializing EvalMult keys" << std::endl;
        std::exit(1);
    }

    std::ofstream rotationKeyFile(DATAFOLDER + rotKeyLocation, std::ios::out | std::ios::binary);
    if (rotationKeyFile.is_open()) {
        if (!serverCC->SerializeEvalAutomorphismKey(rotationKeyFile, SerType::JSON)) {
            std::cerr << "Error writing rotation keys" << std::endl;
            std::exit(1);
        }
        std::cout << "Rotation keys have been serialized" << std::endl;
    }
    else {
        std::cerr << "Error serializing Rotation keys" << std::endl;
        std::exit(1);
    }

    if (!Serial::SerializeToFile(DATAFOLDER + paramssLocation, objSchemeSwitch, SerType::JSON)) {
        std::cerr << "Error writing serialization of the scheme switching parameters to "
                     "paramss.txt"
                  << std::endl;
        std::exit(1);
    }
    std::cout << "The parameters for scheme switching have been serialized." << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + cipherLocation, serverC, SerType::JSON)) {
        std::cerr << " Error writing ciphertext" << std::endl;
        std::exit(1);
    }

    if (!Serial::SerializeToFile(DATAFOLDER + binccLocation, serverBinCC, SerType::JSON)) {
        std::cerr << "Error serializing the binfhe cryptocontext" << std::endl;
        std::exit(1);
    }
    std::cout << "The binfhe cryptocontext has been serialized." << std::endl;

    // Serializing refreshing and key switching keys (needed for bootstrapping)

    if (!Serial::SerializeToFile(DATAFOLDER + btRkLocation, (*serverBinCC).GetRefreshKey(), SerType::JSON)) {
        std::cerr << "Error serializing the refreshing key" << std::endl;
        std::exit(1);
    }
    std::cout << "The refreshing key has been serialized." << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + btSwkLocation, (*serverBinCC).GetSwitchKey(), SerType::JSON)) {
        std::cerr << "Error serializing the switching key" << std::endl;
        std::exit(1);
    }
    std::cout << "The key switching key has been serialized." << std::endl;

    auto BTKeyMap = (*serverBinCC).GetBTKeyMap();
    for (auto it = BTKeyMap->begin(); it != BTKeyMap->end(); it++) {
        auto index  = it->first;
        auto thekey = it->second;
        if (!Serial::SerializeToFile(DATAFOLDER + "/" + std::to_string(index) + "refreshKey.txt", thekey.BSkey,
                                     SerType::JSON)) {
            std::cerr << "Error serializing the refreshing key" << std::endl;
            std::exit(1);
        }

        if (!Serial::SerializeToFile(DATAFOLDER + "/" + std::to_string(index) + "ksKey.txt", thekey.KSkey,
                                     SerType::JSON)) {
            std::cerr << "Error serializing the switching key" << std::endl;
            std::exit(1);
        }

        std::cout << "The BT map element for baseG = " << index << " has been serialized." << std::endl;
    }

    return std::make_tuple(serverCC, serverKP, vec.size());
}

/**
 * clientProcessSSObj
 *  - deserialize data from a file which simulates receiving data from a server
 * after making a request
 *  - we then process the data
 */
void clientProcessSSObj() {
    CryptoContext<DCRTPoly> clientCC;
    clientCC->ClearEvalMultKeys();
    clientCC->ClearEvalAutomorphismKeys();
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();

    if (!Serial::DeserializeFromFile(DATAFOLDER + ccLocation, clientCC, SerType::JSON)) {
        std::cerr << "I cannot read serialized data from: " << DATAFOLDER << "/cryptocontext.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Client CC deserialized" << std::endl;

    KeyPair<DCRTPoly> clientKP;  // We do NOT have a secret key. The client
    // should not have access to this
    PublicKey<DCRTPoly> clientPublicKey;
    if (!Serial::DeserializeFromFile(DATAFOLDER + pubKeyLocation, clientPublicKey, SerType::JSON)) {
        std::cerr << "I cannot read serialized data from: " << DATAFOLDER << "/cryptocontext.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Client KP deserialized" << std::endl;

    auto objSchemeSwitch = std::make_shared<SWITCHCKKSRNS>();
    if (!Serial::DeserializeFromFile(DATAFOLDER + paramssLocation, objSchemeSwitch, SerType::JSON)) {
        std::cerr << "Cannot read serialized data from: " << DATAFOLDER << "/paramss.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Client scheme switching parameters deserialized" << std::endl;

    std::ifstream multKeyIStream(DATAFOLDER + multKeyLocation, std::ios::in | std::ios::binary);
    if (!multKeyIStream.is_open()) {
        std::cerr << "Cannot read serialization from " << DATAFOLDER + multKeyLocation << std::endl;
        std::exit(1);
    }
    if (!clientCC->DeserializeEvalMultKey(multKeyIStream, SerType::JSON)) {
        std::cerr << "Could not deserialize eval mult key file" << std::endl;
        std::exit(1);
    }

    std::cout << "Deserialized eval mult keys" << std::endl;
    std::ifstream rotKeyIStream(DATAFOLDER + rotKeyLocation, std::ios::in | std::ios::binary);
    if (!rotKeyIStream.is_open()) {
        std::cerr << "Cannot read serialization from " << DATAFOLDER + multKeyLocation << std::endl;
        std::exit(1);
    }
    if (!clientCC->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::JSON)) {
        std::cerr << "Could not deserialize eval rot key file" << std::endl;
        std::exit(1);
    }

    std::shared_ptr<lbcrypto::BinFHEContext> clientBinCC;
    if (Serial::DeserializeFromFile(DATAFOLDER + binccLocation, clientBinCC, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the cryptocontext" << std::endl;
        std::exit(1);
    }
    std::cout << "The cryptocontext has been deserialized." << std::endl;

    // deserializing the refreshing and switching keys (for bootstrapping)

    RingGSWACCKey refreshKey;
    if (Serial::DeserializeFromFile(DATAFOLDER + btRkLocation, refreshKey, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the refresh key" << std::endl;
        std::exit(1);
    }
    std::cout << "The refresh key has been deserialized." << std::endl;

    LWESwitchingKey ksKey;
    if (Serial::DeserializeFromFile(DATAFOLDER + btSwkLocation, ksKey, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the switching key" << std::endl;
        std::exit(1);
    }
    std::cout << "The switching key has been deserialized." << std::endl;

    std::vector<uint32_t> baseGlist = {1 << 18};

    for (size_t i = 0; i < baseGlist.size(); i++) {
        if (Serial::DeserializeFromFile(DATAFOLDER + "/" + std::to_string(baseGlist[i]) + "refreshKey.txt", refreshKey,
                                        SerType::JSON) == false) {
            std::cerr << "Could not deserialize the refresh key" << std::endl;
            std::exit(1);
        }

        LWESwitchingKey ksKey;
        if (Serial::DeserializeFromFile(DATAFOLDER + "/" + std::to_string(baseGlist[i]) + "ksKey.txt", ksKey,
                                        SerType::JSON) == false) {
            std::cerr << "Could not deserialize the switching key" << std::endl;
            std::exit(1);
        }
        std::cout << "The BT map element for baseG = " << baseGlist[i] << " has been deserialized." << std::endl;

        // Loading the keys in the cryptocontext
        (*clientBinCC).BTKeyMapLoadSingleElement(baseGlist[i], {refreshKey, ksKey});
    }

    // Loading the keys in the cryptocontext
    (*clientBinCC).BTKeyLoad({refreshKey, ksKey});

    // Set the internal binfhe cryptocontext
    objSchemeSwitch->SetBinCCForSchemeSwitch(clientBinCC);

    Ciphertext<DCRTPoly> clientC;
    if (!Serial::DeserializeFromFile(DATAFOLDER + cipherLocation, clientC, SerType::JSON)) {
        std::cerr << "Cannot read serialization from " << DATAFOLDER + cipherLocation << std::endl;
        std::exit(1);
    }
    std::cout << "Deserialized ciphertext" << '\n' << std::endl;

    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    double scaleSign = 512.0;
    auto modulus_LWE = objSchemeSwitch->GetModulusLWEToSwitch().ConvertToInt();
    auto beta        = clientBinCC->GetBeta().ConvertToInt();
    auto pLWE        = modulus_LWE / (2 * beta);  // Large precision

    objSchemeSwitch->EvalCompareSwitchPrecompute(*clientCC, pLWE, 0, scaleSign, false);

    std::cout << "Done with precomputations" << '\n' << std::endl;

    // Compute on the ciphertext
    auto clientCiphertextArgmin = objSchemeSwitch->EvalMinSchemeSwitching(
        clientC, clientPublicKey, clientC->GetSlots(), 2 * objSchemeSwitch->GetNumCtxtsToSwitch(), 0, 1);

    std::cout << "Done with argmin computation" << '\n' << std::endl;

    // Now, we want to simulate a client who is encrypting data for the server to
    // decrypt. E.g weights of a machine learning algorithm
    demarcate("Part 3.5: Client Serialization of data that has been operated on");

    Serial::SerializeToFile(DATAFOLDER + cipherArgminLocation, clientCiphertextArgmin[1], SerType::JSON);

    std::cout << "Serialized ciphertext from client" << '\n' << std::endl;
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

    Serial::DeserializeFromFile(DATAFOLDER + cipherArgminLocation, serverCiphertextFromClient_Argmin, SerType::JSON);
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
    bool arbFunc          = false;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(FIXEDAUTO);

    CryptoContext<DCRTPoly> serverCC = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    serverCC->Enable(PKE);
    serverCC->Enable(KEYSWITCH);
    serverCC->Enable(LEVELEDSHE);
    serverCC->Enable(ADVANCEDSHE);
    serverCC->Enable(SCHEMESWITCH);

    std::cout << "Cryptocontext generated" << std::endl;

    KeyPair<DCRTPoly> serverKP = serverCC->KeyGen();
    std::cout << "Keypair generated" << std::endl;

    auto privateKeyFHEW = serverCC->EvalSchemeSwitchingSetup(sl, slBin, arbFunc, logQ_LWE, false, batchSize, batchSize,
                                                             true, oneHot, false, 27, 0, 0, 1, 0);
    auto serverBinCC    = serverCC->GetBinCCForSchemeSwitch();

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

    demarcate("Part 2: Data Serialization (server)");

    if (!Serial::SerializeToFile(DATAFOLDER + ccLocation, serverCC, SerType::JSON)) {
        std::cerr << "Error writing serialization of the crypto context to "
                     "cryptocontext.txt"
                  << std::endl;
        std::exit(1);
    }
    std::cout << "Cryptocontext serialized" << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + pubKeyLocation, serverKP.publicKey, SerType::JSON)) {
        std::cerr << "Exception writing public key to pubkey.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Public key serialized" << std::endl;

    std::ofstream multKeyFile(DATAFOLDER + multKeyLocation, std::ios::out | std::ios::binary);
    if (multKeyFile.is_open()) {
        if (!serverCC->SerializeEvalMultKey(multKeyFile, SerType::JSON)) {
            std::cerr << "Error writing eval mult keys" << std::endl;
            std::exit(1);
        }
        std::cout << "EvalMult/ relinearization keys have been serialized" << std::endl;
        multKeyFile.close();
    }
    else {
        std::cerr << "Error serializing EvalMult keys" << std::endl;
        std::exit(1);
    }

    std::ofstream rotationKeyFile(DATAFOLDER + rotKeyLocation, std::ios::out | std::ios::binary);
    if (rotationKeyFile.is_open()) {
        if (!serverCC->SerializeEvalAutomorphismKey(rotationKeyFile, SerType::JSON)) {
            std::cerr << "Error writing rotation keys" << std::endl;
            std::exit(1);
        }
        std::cout << "Rotation keys have been serialized" << std::endl;
    }
    else {
        std::cerr << "Error serializing Rotation keys" << std::endl;
        std::exit(1);
    }

    if (!Serial::SerializeToFile(DATAFOLDER + cipherLocation, serverC, SerType::JSON)) {
        std::cerr << " Error writing ciphertext" << std::endl;
        std::exit(1);
    }

    if (!Serial::SerializeToFile(DATAFOLDER + binccLocation, serverBinCC, SerType::JSON)) {
        std::cerr << "Error serializing the binfhe cryptocontext" << std::endl;
        std::exit(1);
    }
    std::cout << "The binfhe cryptocontext has been serialized." << std::endl;

    // Serializing refreshing and key switching keys (needed for bootstrapping)

    if (!Serial::SerializeToFile(DATAFOLDER + btRkLocation, (*serverBinCC).GetRefreshKey(), SerType::JSON)) {
        std::cerr << "Error serializing the refreshing key" << std::endl;
        std::exit(1);
    }
    std::cout << "The refreshing key has been serialized." << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + btSwkLocation, (*serverBinCC).GetSwitchKey(), SerType::JSON)) {
        std::cerr << "Error serializing the switching key" << std::endl;
        std::exit(1);
    }
    std::cout << "The key switching key has been serialized." << std::endl;

    auto BTKeyMap = (*serverBinCC).GetBTKeyMap();
    for (auto it = BTKeyMap->begin(); it != BTKeyMap->end(); it++) {
        auto index  = it->first;
        auto thekey = it->second;
        if (!Serial::SerializeToFile(DATAFOLDER + "/" + std::to_string(index) + "refreshKey.txt", thekey.BSkey,
                                     SerType::JSON)) {
            std::cerr << "Error serializing the refreshing key" << std::endl;
            std::exit(1);
        }

        if (!Serial::SerializeToFile(DATAFOLDER + "/" + std::to_string(index) + "ksKey.txt", thekey.KSkey,
                                     SerType::JSON)) {
            std::cerr << "Error serializing the switching key" << std::endl;
            std::exit(1);
        }

        std::cout << "The BT map element for baseG = " << index << " has been serialized." << std::endl;
    }

    return std::make_tuple(serverCC, serverKP, vec.size());
}

/**
 * clientProcess
 *  - deserialize data from a file which simulates receiving data from a server
 * after making a request
 *  - we then process the data
 */
void clientProcess() {
    CryptoContext<DCRTPoly> clientCC;
    clientCC->ClearEvalMultKeys();
    clientCC->ClearEvalSumKeys();
    clientCC->ClearEvalAutomorphismKeys();
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();

    if (!Serial::DeserializeFromFile(DATAFOLDER + ccLocation, clientCC, SerType::JSON)) {
        std::cerr << "I cannot read serialized data from: " << DATAFOLDER + ccLocation << std::endl;
        std::exit(1);
    }
    std::cout << "Client CC deserialized" << std::endl;

    PublicKey<DCRTPoly> clientPublicKey;
    if (!Serial::DeserializeFromFile(DATAFOLDER + pubKeyLocation, clientPublicKey, SerType::JSON)) {
        std::cerr << "I cannot read serialized data from: " << DATAFOLDER + pubKeyLocation << std::endl;
        std::exit(1);
    }
    std::cout << "Client KP deserialized" << std::endl;

    std::ifstream multKeyIStream(DATAFOLDER + multKeyLocation, std::ios::in | std::ios::binary);
    if (!multKeyIStream.is_open()) {
        std::cerr << "Cannot read serialization from " << DATAFOLDER + multKeyLocation << std::endl;
        std::exit(1);
    }
    if (!clientCC->DeserializeEvalMultKey(multKeyIStream, SerType::JSON)) {
        std::cerr << "Could not deserialize eval mult key file" << std::endl;
        std::exit(1);
    }
    std::cout << "Deserialized eval mult keys" << std::endl;

    std::ifstream rotKeyIStream(DATAFOLDER + rotKeyLocation, std::ios::in | std::ios::binary);
    if (!rotKeyIStream.is_open()) {
        std::cerr << "Cannot read serialization from " << DATAFOLDER + multKeyLocation << std::endl;
        std::exit(1);
    }
    if (!clientCC->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::JSON)) {
        std::cerr << "Could not deserialize eval rot key file" << std::endl;
        std::exit(1);
    }
    std::cout << "Deserialized rotation keys" << std::endl;

    std::shared_ptr<lbcrypto::BinFHEContext> clientBinCC;
    if (Serial::DeserializeFromFile(DATAFOLDER + binccLocation, clientBinCC, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the binfhe cryptocontext" << std::endl;
        std::exit(1);
    }
    std::cout << "The cryptocontext has been deserialized." << std::endl;

    // deserializing the refreshing and switching keys (for bootstrapping)

    RingGSWACCKey refreshKey;
    if (Serial::DeserializeFromFile(DATAFOLDER + btRkLocation, refreshKey, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the refresh key" << std::endl;
        std::exit(1);
    }
    std::cout << "The refresh key has been deserialized." << std::endl;

    LWESwitchingKey ksKey;
    if (Serial::DeserializeFromFile(DATAFOLDER + btSwkLocation, ksKey, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the switching key" << std::endl;
        std::exit(1);
    }
    std::cout << "The switching key has been deserialized." << std::endl;

    std::vector<uint32_t> baseGlist = {1 << 18};

    for (size_t i = 0; i < baseGlist.size(); i++) {
        if (Serial::DeserializeFromFile(DATAFOLDER + "/" + std::to_string(baseGlist[i]) + "refreshKey.txt", refreshKey,
                                        SerType::JSON) == false) {
            std::cerr << "Could not deserialize the refresh key" << std::endl;
            std::exit(1);
        }

        LWESwitchingKey ksKey;
        if (Serial::DeserializeFromFile(DATAFOLDER + "/" + std::to_string(baseGlist[i]) + "ksKey.txt", ksKey,
                                        SerType::JSON) == false) {
            std::cerr << "Could not deserialize the switching key" << std::endl;
            std::exit(1);
        }
        std::cout << "The BT map element for baseG = " << baseGlist[i] << " has been deserialized." << std::endl;

        // Loading the keys in the cryptocontext
        (*clientBinCC).BTKeyMapLoadSingleElement(baseGlist[i], {refreshKey, ksKey});
    }

    // Loading the keys in the cryptocontext
    (*clientBinCC).BTKeyLoad({refreshKey, ksKey});

    // Set the internal binfhe cryptocontext
    clientCC->SetBinCCForSchemeSwitch(clientBinCC);

    Ciphertext<DCRTPoly> clientC;
    if (!Serial::DeserializeFromFile(DATAFOLDER + cipherLocation, clientC, SerType::JSON)) {
        std::cerr << "Cannot read serialization from " << DATAFOLDER + cipherLocation << std::endl;
        std::exit(1);
    }
    std::cout << "Deserialized ciphertext" << '\n' << std::endl;

    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    double scaleSign = 512.0;
    auto modulus_LWE = 1 << 25;  // Andreea: get the LWE modulus
    auto beta        = clientBinCC->GetBeta().ConvertToInt();
    auto pLWE        = modulus_LWE / (2 * beta);  // Large precision

    clientCC->EvalCompareSwitchPrecompute(pLWE, 0, scaleSign, false);

    std::cout << "Done with precomputations" << '\n' << std::endl;

    // Compute on the ciphertext
    auto clientCiphertextArgmin =
        clientCC->EvalMinSchemeSwitching(clientC, clientPublicKey, clientC->GetSlots(), clientC->GetSlots(), 0, 1);

    std::cout << "Done with argmin computation" << '\n' << std::endl;

    // Now, we want to simulate a client who is encrypting data for the server to
    // decrypt. E.g weights of a machine learning algorithm
    demarcate("Part 3.5: Client Serialization of data that has been operated on");

    Serial::SerializeToFile(DATAFOLDER + cipherArgminLocation, clientCiphertextArgmin[1], SerType::JSON);

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
        "Part 1: Cryptocontext generation, key generation, data encryption "
        "(server)");

    // // Andreea: the serialization of the scheme switching parameters is done from the scheme-switching object and it is working
    // auto tupleCryptoContext_KeyPair =
    //     serverSetupAndWriteSSObj(ringDim, batchSize, multDepth, scaleModSize, firstModSize, logQ_ccLWE, oneHot);

    // Andreea: the serialization of the scheme switching parameters should be done throught the cryptocontext but currently this is not working
    auto tupleCryptoContext_KeyPair =
        serverSetupAndWrite(ringDim, batchSize, multDepth, scaleModSize, firstModSize, logQ_ccLWE, oneHot);

    auto cc        = std::get<cryptoContextIdx>(tupleCryptoContext_KeyPair);
    auto kp        = std::get<keyPairIdx>(tupleCryptoContext_KeyPair);
    int vectorSize = std::get<vectorSizeIdx>(tupleCryptoContext_KeyPair);

    demarcate("Part 3: Client deserialize all data");

    // // Andreea: the serialization of the scheme switching parameters is done from the scheme-switching object and it is working
    // clientProcessSSObj();

    // Andreea: the serialization of the scheme switching parameters should be done throught the cryptocontext but currently this is not working
    clientProcess();

    demarcate("Part 4: Server deserialization of data from client. ");

    auto ArgminRes = serverVerification(cc, kp, vectorSize);

    // vec1: {1,2,3,4}

    std::cout << ArgminRes << std::endl;  // EXPECT: 1.0, 0.0, 0.0, 0.0
}
