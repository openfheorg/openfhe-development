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
#ifndef __SCHEMESWITCHING_DATA_SERIALIZER_H__
#define __SCHEMESWITCHING_DATA_SERIALIZER_H__

#include "cryptocontext.h"

#include <string>
#include <memory>

namespace lbcrypto {

class DataAndLocation {
protected:
    CryptoContext<DCRTPoly> cryptoContext{nullptr};
    PublicKey<DCRTPoly> publicKey{nullptr};
    std::shared_ptr<lbcrypto::BinFHEContext> binFHECryptoContext{nullptr};
    Ciphertext<DCRTPoly> FHEWtoCKKSSwitchKey{nullptr};
    Ciphertext<DCRTPoly> RAWCiphertext{nullptr};

    // Save-Load locations
    std::string dataDirectory            = "demoData";
    std::string cryptoContextFile        = "cryptocontext.txt";
    std::string pubKeyFile               = "key_pub.txt";
    std::string multKeyFile              = "key_mult.txt";
    std::string rotKeyFile               = "key_rot.txt";
    std::string FHEWtoCKKSSwitchKeyFile  = "key_switch_fhew_ckks.txt";
    std::string ciphertextFile           = "ciphertext.txt";  // RAW ciphertext
    std::string binFHECryptoContextFile  = "binfhe_cryptocontext.txt";
    std::string binFHEBootRefreshKeyFile = "key_binfhe_boot_refresh.txt";
    std::string binFHEBootRotKeyFile     = "key_binfhe_boot_rot.txt";
    std::string baseRefreshKeyFile       = "key_refresh.txt";
    std::string baseSwitchingKeyFile     = "key_switching.txt";
    std::string keyIndexFile             = "key_indices.txt";

    std::string createMapFileName(uint32_t index, const std::string& baseFileName) {
        return std::string(dataDirectory) + "/" + std::to_string(index) + "_" + baseFileName;
    }

    DataAndLocation() = default;
    DataAndLocation(CryptoContext<DCRTPoly> cryptoContext0, PublicKey<DCRTPoly> publicKey0,
                    Ciphertext<DCRTPoly> RAWCiphertext0)
        : cryptoContext(cryptoContext0),
          publicKey(publicKey0),
          binFHECryptoContext(cryptoContext0->GetBinCCForSchemeSwitch()),
          FHEWtoCKKSSwitchKey(cryptoContext0->GetSwkFC()),
          RAWCiphertext(RAWCiphertext0) {}

public:
    void SetDataDirectory(const std::string& dir) {
        if (dir.empty()) {
            OPENFHE_THROW("dir is an empty string");
        }

        // remove slash if it is the last charactes in "dir"
        if (dir.back() == '/')
            dataDirectory = dir.substr(0, dir.size() - 1);
        else
            dataDirectory = dir;
    }
};

class SchemeSwitchingDataSerializer : public DataAndLocation {
public:
    SchemeSwitchingDataSerializer(CryptoContext<DCRTPoly> cryptoContext0, PublicKey<DCRTPoly> publicKey0,
                                  Ciphertext<DCRTPoly> RAWCiphertext0)
        : DataAndLocation(cryptoContext0, publicKey0, RAWCiphertext0) {}

    void Serialize();
};

class SchemeSwitchingDataDeserializer : public DataAndLocation {
public:
    SchemeSwitchingDataDeserializer() = default;

    CryptoContext<DCRTPoly> getCryptoContext() {
        return cryptoContext;
    }
    PublicKey<DCRTPoly> getPublicKey() {
        return publicKey;
    }
    Ciphertext<DCRTPoly> getRAWCiphertext() {
        return RAWCiphertext;
    }

    void Deserialize();
};

}  // namespace lbcrypto

#endif  // __SCHEMESWITCHING_DATA_SERIALIZER_H__
