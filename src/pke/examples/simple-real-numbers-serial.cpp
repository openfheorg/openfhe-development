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
const std::string DATAFOLDER = "demoData";
std::string ccLocation       = "/cryptocontext.txt";
std::string pubKeyLocation   = "/key_pub.txt";   // Pub key
std::string multKeyLocation  = "/key_mult.txt";  // relinearization key
std::string rotKeyLocation   = "/key_rot.txt";   // automorphism / rotation key

// Save-load locations for RAW ciphertexts
std::string cipherOneLocation = "/ciphertext1.txt";
std::string cipherTwoLocation = "/ciphertext2.txt";

// Save-load locations for evaluated ciphertexts
std::string cipherMultLocation   = "/ciphertextMult.txt";
std::string cipherAddLocation    = "/ciphertextAdd.txt";
std::string cipherRotLocation    = "/ciphertextRot.txt";
std::string cipherRotNegLocation = "/ciphertextRotNegLocation.txt";
std::string clientVectorLocation = "/ciphertextVectorFromClient.txt";

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
 * serverSetupAndWrite
 *  - simulates a server at startup where we generate a cryptocontext and keys.
 *  - then, we generate some data (akin to loading raw data on an enclave)
 * before encrypting the data
 * @param multDepth - multiplication depth
 * @param scaleModSize - number of bits to use in the scale factor (not the
 * scale factor itself)
 * @param batchSize - batch size to use
 * @return Tuple<cryptoContext, keyPair>
 */
std::tuple<CryptoContext<DCRTPoly>, KeyPair<DCRTPoly>, int> serverSetupAndWrite(int multDepth, int scaleModSize,
                                                                                int batchSize) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> serverCC = GenCryptoContext(parameters);

    serverCC->Enable(PKE);
    serverCC->Enable(KEYSWITCH);
    serverCC->Enable(LEVELEDSHE);

    std::cout << "Cryptocontext generated" << std::endl;

    KeyPair<DCRTPoly> serverKP = serverCC->KeyGen();
    std::cout << "Keypair generated" << std::endl;

    serverCC->EvalMultKeyGen(serverKP.secretKey);
    std::cout << "Eval Mult Keys/ Relinearization keys have been generated" << std::endl;

    serverCC->EvalRotateKeyGen(serverKP.secretKey, {1, 2, -1, -2});
    std::cout << "Rotation keys generated" << std::endl;

    std::vector<std::complex<double>> vec1 = {1.0, 2.0, 3.0, 4.0};
    std::vector<std::complex<double>> vec2 = {12.5, 13.5, 14.5, 15.5};
    std::vector<std::complex<double>> vec3 = {10.5, 11.5, 12.5, 13.5};
    std::cout << "\nDisplaying first data vector: ";

    for (auto& v : vec1) {
        std::cout << v << ',';
    }

    std::cout << '\n' << std::endl;

    Plaintext serverP1 = serverCC->MakeCKKSPackedPlaintext(vec1);
    Plaintext serverP2 = serverCC->MakeCKKSPackedPlaintext(vec2);
    Plaintext serverP3 = serverCC->MakeCKKSPackedPlaintext(vec3);

    std::cout << "Plaintext version of first vector: " << serverP1 << std::endl;

    std::cout << "Plaintexts have been generated from complex-double vectors" << std::endl;

    auto serverC1 = serverCC->Encrypt(serverKP.publicKey, serverP1);
    auto serverC2 = serverCC->Encrypt(serverKP.publicKey, serverP2);
    auto serverC3 = serverCC->Encrypt(serverKP.publicKey, serverP3);

    std::cout << "Ciphertexts have been generated from Plaintexts" << std::endl;

    /*
   * Part 2:
   * We serialize the following:
   *  Cryptocontext
   *  Public key
   *  relinearization (eval mult keys)
   *  rotation keys
   *  Some of the ciphertext
   *
   *  We serialize all of them to files
   */

    demarcate("Part 2: Data Serialization (server)");

    if (!Serial::SerializeToFile(DATAFOLDER + ccLocation, serverCC, SerType::BINARY)) {
        std::cerr << "Error writing serialization of the crypto context to "
                     "cryptocontext.txt"
                  << std::endl;
        std::exit(1);
    }

    std::cout << "Cryptocontext serialized" << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + pubKeyLocation, serverKP.publicKey, SerType::BINARY)) {
        std::cerr << "Exception writing public key to pubkey.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Public key serialized" << std::endl;

    std::ofstream multKeyFile(DATAFOLDER + multKeyLocation, std::ios::out | std::ios::binary);
    if (multKeyFile.is_open()) {
        if (!serverCC->SerializeEvalMultKey(multKeyFile, SerType::BINARY)) {
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
        if (!serverCC->SerializeEvalAutomorphismKey(rotationKeyFile, SerType::BINARY)) {
            std::cerr << "Error writing rotation keys" << std::endl;
            std::exit(1);
        }
        std::cout << "Rotation keys have been serialized" << std::endl;
    }
    else {
        std::cerr << "Error serializing Rotation keys" << std::endl;
        std::exit(1);
    }

    if (!Serial::SerializeToFile(DATAFOLDER + cipherOneLocation, serverC1, SerType::BINARY)) {
        std::cerr << " Error writing ciphertext 1" << std::endl;
    }

    if (!Serial::SerializeToFile(DATAFOLDER + cipherTwoLocation, serverC2, SerType::BINARY)) {
        std::cerr << " Error writing ciphertext 2" << std::endl;
    }

    return std::make_tuple(serverCC, serverKP, vec1.size());
}

/**
 * clientProcess
 *  - deserialize data from a file which simulates receiving data from a server
 * after making a request
 *  - we then process the data by doing operations (multiplication, addition,
 * rotation, etc)
 *  - !! We also create an object and encrypt it in this function before sending
 * it off to the server to be decrypted
 */
void clientProcess() {
    CryptoContext<DCRTPoly> clientCC;
    clientCC->ClearEvalMultKeys();
    clientCC->ClearEvalAutomorphismKeys();
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
    if (!Serial::DeserializeFromFile(DATAFOLDER + ccLocation, clientCC, SerType::BINARY)) {
        std::cerr << "I cannot read serialized data from: " << DATAFOLDER << "/cryptocontext.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Client CC deserialized";

    KeyPair<DCRTPoly> clientKP;  // We do NOT have a secret key. The client
    // should not have access to this
    PublicKey<DCRTPoly> clientPublicKey;
    if (!Serial::DeserializeFromFile(DATAFOLDER + pubKeyLocation, clientPublicKey, SerType::BINARY)) {
        std::cerr << "I cannot read serialized data from: " << DATAFOLDER << "/cryptocontext.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Client KP deserialized" << '\n' << std::endl;

    std::ifstream multKeyIStream(DATAFOLDER + multKeyLocation, std::ios::in | std::ios::binary);
    if (!multKeyIStream.is_open()) {
        std::cerr << "Cannot read serialization from " << DATAFOLDER + multKeyLocation << std::endl;
        std::exit(1);
    }
    if (!clientCC->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY)) {
        std::cerr << "Could not deserialize eval mult key file" << std::endl;
        std::exit(1);
    }

    std::cout << "Deserialized eval mult keys" << '\n' << std::endl;
    std::ifstream rotKeyIStream(DATAFOLDER + rotKeyLocation, std::ios::in | std::ios::binary);
    if (!rotKeyIStream.is_open()) {
        std::cerr << "Cannot read serialization from " << DATAFOLDER + multKeyLocation << std::endl;
        std::exit(1);
    }
    if (!clientCC->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY)) {
        std::cerr << "Could not deserialize eval rot key file" << std::endl;
        std::exit(1);
    }

    Ciphertext<DCRTPoly> clientC1;
    Ciphertext<DCRTPoly> clientC2;
    if (!Serial::DeserializeFromFile(DATAFOLDER + cipherOneLocation, clientC1, SerType::BINARY)) {
        std::cerr << "Cannot read serialization from " << DATAFOLDER + cipherOneLocation << std::endl;
        std::exit(1);
    }
    std::cout << "Deserialized ciphertext1" << '\n' << std::endl;

    if (!Serial::DeserializeFromFile(DATAFOLDER + cipherTwoLocation, clientC2, SerType::BINARY)) {
        std::cerr << "Cannot read serialization from " << DATAFOLDER + cipherTwoLocation << std::endl;
        std::exit(1);
    }

    std::cout << "Deserialized ciphertext1" << '\n' << std::endl;
    auto clientCiphertextMult   = clientCC->EvalMult(clientC1, clientC2);
    auto clientCiphertextAdd    = clientCC->EvalAdd(clientC1, clientC2);
    auto clientCiphertextRot    = clientCC->EvalRotate(clientC1, 1);
    auto clientCiphertextRotNeg = clientCC->EvalRotate(clientC1, -1);

    // Now, we want to simulate a client who is encrypting data for the server to
    // decrypt. E.g weights of a machine learning algorithm
    demarcate("Part 3.5: Client Serialization of data that has been operated on");

    std::vector<std::complex<double>> clientVector1 = {1.0, 2.0, 3.0, 4.0};
    auto clientPlaintext1                           = clientCC->MakeCKKSPackedPlaintext(clientVector1);
    auto clientInitiatedEncryption                  = clientCC->Encrypt(clientPublicKey, clientPlaintext1);
    Serial::SerializeToFile(DATAFOLDER + cipherMultLocation, clientCiphertextMult, SerType::BINARY);
    Serial::SerializeToFile(DATAFOLDER + cipherAddLocation, clientCiphertextAdd, SerType::BINARY);
    Serial::SerializeToFile(DATAFOLDER + cipherRotLocation, clientCiphertextRot, SerType::BINARY);
    Serial::SerializeToFile(DATAFOLDER + cipherRotNegLocation, clientCiphertextRotNeg, SerType::BINARY);
    Serial::SerializeToFile(DATAFOLDER + clientVectorLocation, clientInitiatedEncryption, SerType::BINARY);

    std::cout << "Serialized all ciphertexts from client" << '\n' << std::endl;
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

std::tuple<Plaintext, Plaintext, Plaintext, Plaintext, Plaintext> serverVerification(CryptoContext<DCRTPoly>& cc,
                                                                                     KeyPair<DCRTPoly>& kp,
                                                                                     int vectorSize) {
    Ciphertext<DCRTPoly> serverCiphertextFromClient_Mult;
    Ciphertext<DCRTPoly> serverCiphertextFromClient_Add;
    Ciphertext<DCRTPoly> serverCiphertextFromClient_Rot;
    Ciphertext<DCRTPoly> serverCiphertextFromClient_RogNeg;
    Ciphertext<DCRTPoly> serverCiphertextFromClient_Vec;

    Serial::DeserializeFromFile(DATAFOLDER + cipherMultLocation, serverCiphertextFromClient_Mult, SerType::BINARY);
    Serial::DeserializeFromFile(DATAFOLDER + cipherAddLocation, serverCiphertextFromClient_Add, SerType::BINARY);
    Serial::DeserializeFromFile(DATAFOLDER + cipherRotLocation, serverCiphertextFromClient_Rot, SerType::BINARY);
    Serial::DeserializeFromFile(DATAFOLDER + cipherRotNegLocation, serverCiphertextFromClient_RogNeg, SerType::BINARY);
    Serial::DeserializeFromFile(DATAFOLDER + clientVectorLocation, serverCiphertextFromClient_Vec, SerType::BINARY);
    std::cout << "Deserialized all data from client on server" << '\n' << std::endl;

    demarcate("Part 5: Correctness verification");

    Plaintext serverPlaintextFromClient_Mult;
    Plaintext serverPlaintextFromClient_Add;
    Plaintext serverPlaintextFromClient_Rot;
    Plaintext serverPlaintextFromClient_RotNeg;
    Plaintext serverPlaintextFromClient_Vec;

    cc->Decrypt(kp.secretKey, serverCiphertextFromClient_Mult, &serverPlaintextFromClient_Mult);
    cc->Decrypt(kp.secretKey, serverCiphertextFromClient_Add, &serverPlaintextFromClient_Add);
    cc->Decrypt(kp.secretKey, serverCiphertextFromClient_Rot, &serverPlaintextFromClient_Rot);
    cc->Decrypt(kp.secretKey, serverCiphertextFromClient_RogNeg, &serverPlaintextFromClient_RotNeg);
    cc->Decrypt(kp.secretKey, serverCiphertextFromClient_Vec, &serverPlaintextFromClient_Vec);

    serverPlaintextFromClient_Mult->SetLength(vectorSize);
    serverPlaintextFromClient_Add->SetLength(vectorSize);
    serverPlaintextFromClient_Vec->SetLength(vectorSize);
    serverPlaintextFromClient_Rot->SetLength(vectorSize + 1);
    serverPlaintextFromClient_RotNeg->SetLength(vectorSize + 1);

    return std::make_tuple(serverPlaintextFromClient_Mult, serverPlaintextFromClient_Add, serverPlaintextFromClient_Vec,
                           serverPlaintextFromClient_Rot, serverPlaintextFromClient_RotNeg);
}
int main() {
    std::cout << "This program requres the subdirectory `" << DATAFOLDER << "' to exist, otherwise you will get "
              << "an error writing serializations." << std::endl;

    // Set main params
    const int multDepth    = 5;
    const int scaleModSize = 40;
    const usint batchSize  = 32;

    const int cryptoContextIdx = 0;
    const int keyPairIdx       = 1;
    const int vectorSizeIdx    = 2;

    const int cipherMultResIdx   = 0;
    const int cipherAddResIdx    = 1;
    const int cipherVecResIdx    = 2;
    const int cipherRotResIdx    = 3;
    const int cipherRotNegResIdx = 4;

    demarcate(
        "Part 1: Cryptocontext generation, key generation, data encryption "
        "(server)");

    auto tupleCryptoContext_KeyPair = serverSetupAndWrite(multDepth, scaleModSize, batchSize);
    auto cc                         = std::get<cryptoContextIdx>(tupleCryptoContext_KeyPair);
    auto kp                         = std::get<keyPairIdx>(tupleCryptoContext_KeyPair);
    int vectorSize                  = std::get<vectorSizeIdx>(tupleCryptoContext_KeyPair);

    demarcate("Part 3: Client deserialize all data");
    clientProcess();

    demarcate("Part 4: Server deserialization of data from client. ");

    auto tupleRes  = serverVerification(cc, kp, vectorSize);
    auto multRes   = std::get<cipherMultResIdx>(tupleRes);
    auto addRes    = std::get<cipherAddResIdx>(tupleRes);
    auto vecRes    = std::get<cipherVecResIdx>(tupleRes);
    auto rotRes    = std::get<cipherRotResIdx>(tupleRes);
    auto rotNegRes = std::get<cipherRotNegResIdx>(tupleRes);

    // vec1: {1,2,3,4}
    // vec2: {12.5, 13.5, 14.5, 15.5}

    std::cout << multRes << std::endl;  // EXPECT: 12.5, 27.0, 43.5, 62
    std::cout << addRes << std::endl;   // EXPECT: 13.5, 15.5, 17.5, 19.5
    std::cout << vecRes << std::endl;   // EXPECT:  {1,2,3,4}

    std::cout << "Displaying 5 elements of a 4-element vector to illustrate rotation" << '\n';
    std::cout << rotRes << std::endl;     // EXPECT: {2, 3, 4, noise, noise}
    std::cout << rotNegRes << std::endl;  // EXPECT: {noise, 1, 2, 3, 4}
}
