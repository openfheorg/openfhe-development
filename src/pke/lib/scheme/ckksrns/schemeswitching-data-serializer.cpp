//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
#include "scheme/ckksrns/schemeswitching-data-serializer.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

namespace lbcrypto {

// Macros to be used in this source file only
#define THROW_SERIALIZATION_ERROR   OPENFHE_THROW(std::string("Error serializing to ") + outFile)
#define THROW_DESERIALIZATION_ERROR OPENFHE_THROW(std::string("Error deserializing from ") + outFile)
#define THROW_CAN_NOT_OPEN_FILE     OPENFHE_THROW(std::string("Can not open ") + outFile)
#define SERTYPE                     SerType::BINARY

void SchemeSwitchingDataSerializer::Serialize() {
    // check if all 5 data memebers to be serialized are valid (not NULL)
    if (nullptr == cryptoContext)
        OPENFHE_THROW("cryptoContext is nullptr");
    else if (nullptr == publicKey)
        OPENFHE_THROW("publicKey is nullptr");
    else if (nullptr == binFHECryptoContext)
        OPENFHE_THROW("binFHECryptoContext is nullptr");
    else if (nullptr == FHEWtoCKKSSwitchKey)
        OPENFHE_THROW("FHEWtoCKKSSwitchKey is nullptr");
    else if (nullptr == RAWCiphertext)
        OPENFHE_THROW("RAWCiphertext is nullptr");

    std::string outFile;
    //=============================================================================================================
    outFile = dataDirectory + "/" + cryptoContextFile;
    if (!Serial::SerializeToFile(outFile, cryptoContext, SERTYPE)) {
        THROW_SERIALIZATION_ERROR;
    }
    //=============================================================================================================
    outFile = dataDirectory + "/" + pubKeyFile;
    if (!Serial::SerializeToFile(outFile, publicKey, SERTYPE)) {
        THROW_SERIALIZATION_ERROR;
    }
    //=============================================================================================================
    outFile = dataDirectory + "/" + multKeyFile;
    std::ofstream multKeyFile(outFile, std::ios::out | std::ios::binary);
    if (multKeyFile.is_open()) {
        if (!cryptoContext->SerializeEvalMultKey(multKeyFile, SERTYPE)) {
            THROW_SERIALIZATION_ERROR;
        }
        multKeyFile.close();
    }
    else {
        THROW_CAN_NOT_OPEN_FILE;
    }
    //=============================================================================================================
    outFile = dataDirectory + "/" + rotKeyFile;
    std::ofstream rotationKeyFile(outFile, std::ios::out | std::ios::binary);
    if (rotationKeyFile.is_open()) {
        if (!cryptoContext->SerializeEvalAutomorphismKey(rotationKeyFile, SERTYPE)) {
            THROW_SERIALIZATION_ERROR;
        }
        rotationKeyFile.close();
    }
    else {
        THROW_CAN_NOT_OPEN_FILE;
    }
    //=============================================================================================================
    outFile = dataDirectory + "/" + FHEWtoCKKSSwitchKeyFile;
    if (!Serial::SerializeToFile(outFile, FHEWtoCKKSSwitchKey, SERTYPE)) {
        THROW_SERIALIZATION_ERROR;
    }
    //=============================================================================================================
    outFile = dataDirectory + "/" + ciphertextFile;
    if (!Serial::SerializeToFile(outFile, RAWCiphertext, SERTYPE)) {
        THROW_SERIALIZATION_ERROR;
    }
    //=============================================================================================================
    outFile = dataDirectory + "/" + binFHECryptoContextFile;
    if (!Serial::SerializeToFile(outFile, binFHECryptoContext, SERTYPE)) {
        THROW_SERIALIZATION_ERROR;
    }
    //=============================================================================================================
    outFile = dataDirectory + "/" + binFHEBootRefreshKeyFile;
    if (!Serial::SerializeToFile(outFile, binFHECryptoContext->GetRefreshKey(), SERTYPE)) {
        THROW_SERIALIZATION_ERROR;
    }
    //=============================================================================================================
    outFile = dataDirectory + "/" + binFHEBootRotKeyFile;
    if (!Serial::SerializeToFile(outFile, binFHECryptoContext->GetSwitchKey(), SERTYPE)) {
        THROW_SERIALIZATION_ERROR;
    }
    //=============================================================================================================
    std::vector<uint32_t> indices;
    auto BTKeyMap = binFHECryptoContext->GetBTKeyMap();
    for (auto it = BTKeyMap->begin(); it != BTKeyMap->end(); ++it) {
        uint32_t index      = it->first;
        RingGSWBTKey thekey = it->second;

        outFile = createMapFileName(index, baseRefreshKeyFile);
        if (!Serial::SerializeToFile(outFile, thekey.BSkey, SERTYPE)) {
            THROW_SERIALIZATION_ERROR;
        }

        outFile = createMapFileName(index, baseSwitchingKeyFile);
        if (!Serial::SerializeToFile(outFile, thekey.KSkey, SERTYPE)) {
            THROW_SERIALIZATION_ERROR;
        }

        indices.push_back(index);
    }
    outFile = dataDirectory + "/" + keyIndexFile;
    if (!Serial::SerializeToFile(outFile, indices, SERTYPE)) {
        THROW_SERIALIZATION_ERROR;
    }
    //=============================================================================================================
}

void SchemeSwitchingDataDeserializer::Deserialize() {
    std::string outFile;
    //=============================================================================================================
    outFile = dataDirectory + "/" + cryptoContextFile;
    if (!Serial::DeserializeFromFile(outFile, cryptoContext, SERTYPE)) {
        THROW_DESERIALIZATION_ERROR;
    }
    //=============================================================================================================
    outFile = dataDirectory + "/" + pubKeyFile;
    if (!Serial::DeserializeFromFile(outFile, publicKey, SERTYPE)) {
        THROW_DESERIALIZATION_ERROR;
    }
    //=============================================================================================================
    outFile = dataDirectory + "/" + multKeyFile;
    std::ifstream multKeyFile(outFile, std::ios::in | std::ios::binary);
    if (multKeyFile.is_open()) {
        if (!cryptoContext->DeserializeEvalMultKey(multKeyFile, SERTYPE)) {
            THROW_DESERIALIZATION_ERROR;
        }
        multKeyFile.close();
    }
    else {
        THROW_CAN_NOT_OPEN_FILE;
    }
    //=============================================================================================================
    outFile = dataDirectory + "/" + rotKeyFile;
    std::ifstream rotationKeyFile(outFile, std::ios::in | std::ios::binary);
    if (rotationKeyFile.is_open()) {
        if (!cryptoContext->DeserializeEvalAutomorphismKey(rotationKeyFile, SERTYPE)) {
            THROW_DESERIALIZATION_ERROR;
        }
        rotationKeyFile.close();
    }
    else {
        THROW_CAN_NOT_OPEN_FILE;
    }
    //=============================================================================================================
    outFile = dataDirectory + "/" + FHEWtoCKKSSwitchKeyFile;
    if (!Serial::DeserializeFromFile(outFile, FHEWtoCKKSSwitchKey, SERTYPE)) {
        THROW_DESERIALIZATION_ERROR;
    }
    cryptoContext->SetSwkFC(FHEWtoCKKSSwitchKey);
    //=============================================================================================================
    outFile = dataDirectory + "/" + ciphertextFile;
    if (!Serial::DeserializeFromFile(outFile, RAWCiphertext, SERTYPE)) {
        THROW_DESERIALIZATION_ERROR;
    }
    //=============================================================================================================
    outFile = dataDirectory + "/" + binFHECryptoContextFile;
    if (!Serial::DeserializeFromFile(outFile, binFHECryptoContext, SERTYPE)) {
        THROW_DESERIALIZATION_ERROR;
    }
    //=============================================================================================================
    RingGSWBTKey BTKey;
    outFile = dataDirectory + "/" + binFHEBootRefreshKeyFile;
    if (!Serial::DeserializeFromFile(outFile, BTKey.BSkey, SERTYPE)) {
        THROW_DESERIALIZATION_ERROR;
    }
    //=============================================================================================================
    outFile = dataDirectory + "/" + binFHEBootRotKeyFile;
    if (!Serial::DeserializeFromFile(outFile, BTKey.KSkey, SERTYPE)) {
        THROW_DESERIALIZATION_ERROR;
    }
    binFHECryptoContext->BTKeyLoad(BTKey);
    //=============================================================================================================
    std::vector<uint32_t> indices;
    outFile = dataDirectory + "/" + keyIndexFile;
    if (!Serial::DeserializeFromFile(outFile, indices, SERTYPE)) {
        THROW_SERIALIZATION_ERROR;
    }
    else if (!indices.size()) {
        std::string errMsg(std::string("Error deserializing from ") + outFile + ". No indices found.");
        OPENFHE_THROW(errMsg);
    }
    for (uint32_t index : indices) {
        RingGSWBTKey thekey;
        outFile = createMapFileName(index, baseRefreshKeyFile);
        if (!Serial::DeserializeFromFile(outFile, thekey.BSkey, SERTYPE)) {
            THROW_DESERIALIZATION_ERROR;
        }

        outFile = createMapFileName(index, baseSwitchingKeyFile);
        if (!Serial::DeserializeFromFile(outFile, thekey.KSkey, SERTYPE)) {
            THROW_DESERIALIZATION_ERROR;
        }

        // add single keys to the map
        binFHECryptoContext->BTKeyMapLoadSingleElement(index, thekey);
    }
    cryptoContext->SetBinCCForSchemeSwitch(binFHECryptoContext);
    //=============================================================================================================
}

}  // namespace lbcrypto
