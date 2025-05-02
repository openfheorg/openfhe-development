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
  serialize cryptocontext; include this in any app that needs to serialize them
 */

#ifndef LBCRYPTO_CRYPTO_CRYPTOCONTEXTSER_H
#define LBCRYPTO_CRYPTO_CRYPTOCONTEXTSER_H

#include "cryptocontext.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

CEREAL_CLASS_VERSION(lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>,
                     lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::SerializedVersion());

// the routines below are only instantiated if the user includes the appropriate
// serialize-*.h file

namespace lbcrypto {
// ================================= JSON serialization/deserialization
namespace Serial {
/**
 * Deserialize for a CryptoContext (that is, a shared pointer to a
 * CryptoContextImpl OpenFHE doesn't want multiple copies of the same crypto
 * context floating around, and it enforces that here
 *
 * @param obj - the target for the deserialization
 * @param stream - where the serialization is coming from
 * @param sertype - JSON serialization type
 */
template <typename T>
void Deserialize(CryptoContext<T>& obj, std::istream& stream, const SerType::SERJSON&) {
    CryptoContext<T> newob;

    cereal::JSONInputArchive archive(stream);
    archive(newob);

    obj = CryptoContextFactory<T>::GetContext(newob->GetCryptoParameters(), newob->GetScheme(), newob->getSchemeId());
}

template <typename T>
bool SerializeToFile(const std::string& filename, const CryptoContext<T>& obj, const SerType::SERJSON& sertype) {
    std::ofstream file(filename, std::ios::out | std::ios::binary);
    if (file.is_open()) {
        Serial::Serialize(obj, file, sertype);
        file.close();
        return true;
    }
    return false;
}

template <typename T>
bool DeserializeFromFile(const std::string& filename, CryptoContext<T>& obj, const SerType::SERJSON& sertype) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (file.is_open()) {
        Serial::Deserialize(obj, file, sertype);
        file.close();
        return true;
    }
    return false;
}
}  // namespace Serial
template void Serial::Deserialize(std::shared_ptr<CryptoContextImpl<DCRTPoly>>& obj, std::istream& stream,
                                  const SerType::SERJSON&);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERJSON>(std::ostream& ser,
                                                                                  const SerType::SERJSON&,
                                                                                  const std::string& keyTag);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERJSON>(std::ostream& ser,
                                                                                  const SerType::SERJSON&,
                                                                                  const CryptoContext<DCRTPoly> cc);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey<SerType::SERJSON>(std::istream& ser,
                                                                                    const SerType::SERJSON&);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey<SerType::SERJSON>(std::ostream& ser,
                                                                                 const SerType::SERJSON&,
                                                                                 const std::string& keyTag);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey<SerType::SERJSON>(std::ostream& ser,
                                                                                 const SerType::SERJSON&,
                                                                                 const CryptoContext<DCRTPoly> cc);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalSumKey<SerType::SERJSON>(std::istream& ser,
                                                                                   const SerType::SERJSON&);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERJSON>(std::ostream& ser,
                                                                                          const SerType::SERJSON&,
                                                                                          const std::string& keyTag);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERJSON>(
    std::ostream& ser, const SerType::SERJSON&, const CryptoContext<DCRTPoly> cc);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalAutomorphismKey<SerType::SERJSON>(std::istream& ser,
                                                                                            const SerType::SERJSON&);

// ================================= BINARY serialization/deserialization
namespace Serial {
/**
 * Deserialize for a CryptoContext (that is, a shared pointer to a
 * CryptoContextImpl OpenFHE doesn't want multiple copies of the same crypto
 * context floating around, and it enforces that here
 *
 * @param obj - the target for the deserialization
 * @param stream - where the serialization is coming from
 * @param sertype - BINARY serialization type
 */
template <typename T>
void Deserialize(CryptoContext<T>& obj, std::istream& stream, const SerType::SERBINARY&) {
    CryptoContext<T> newob;

    cereal::PortableBinaryInputArchive archive(stream);
    archive(newob);

    obj = CryptoContextFactory<T>::GetContext(newob->GetCryptoParameters(), newob->GetScheme(), newob->getSchemeId());
}

template <typename T>
bool SerializeToFile(const std::string& filename, const CryptoContext<T>& obj, const SerType::SERBINARY& sertype) {
    std::ofstream file(filename, std::ios::out | std::ios::binary);
    if (file.is_open()) {
        Serial::Serialize(obj, file, sertype);
        file.close();
        return true;
    }
    return false;
}

template <typename T>
bool DeserializeFromFile(const std::string& filename, CryptoContext<T>& obj, const SerType::SERBINARY& sertype) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (file.is_open()) {
        Serial::Deserialize(obj, file, sertype);
        file.close();
        return true;
    }
    return false;
}

template <typename T>
std::string SerializeToString(const CryptoContext<T>& obj) {
    std::stringstream s;
    Serial::Serialize(obj, s, SerType::JSON);
    return s.str();
}

template <typename T>
void DeserializeFromString(CryptoContext<T>& obj, const std::string& json) {
    std::stringstream s;
    s << json;
    Serial::Deserialize(obj, s, SerType::JSON);
}
}  // namespace Serial

template void Serial::Deserialize(std::shared_ptr<CryptoContextImpl<DCRTPoly>>& obj, std::istream& stream,
                                  const SerType::SERBINARY&);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERBINARY>(std::ostream& ser,
                                                                                    const SerType::SERBINARY&,
                                                                                    const std::string& keyTag);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERBINARY>(std::ostream& ser,
                                                                                    const SerType::SERBINARY&,
                                                                                    const CryptoContext<DCRTPoly> cc);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey<SerType::SERBINARY>(std::istream& ser,
                                                                                      const SerType::SERBINARY&);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey<SerType::SERBINARY>(std::ostream& ser,
                                                                                   const SerType::SERBINARY&,
                                                                                   const std::string& keyTag);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey<SerType::SERBINARY>(std::ostream& ser,
                                                                                   const SerType::SERBINARY&,
                                                                                   const CryptoContext<DCRTPoly> cc);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalSumKey<SerType::SERBINARY>(std::istream& ser,
                                                                                     const SerType::SERBINARY&);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERBINARY>(std::ostream& ser,
                                                                                            const SerType::SERBINARY&,
                                                                                            const std::string& keyTag);
template bool CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERBINARY>(
    std::ostream& ser, const SerType::SERBINARY&, const CryptoContext<DCRTPoly> cc);
template bool CryptoContextImpl<DCRTPoly>::DeserializeEvalAutomorphismKey<SerType::SERBINARY>(
    std::istream& ser, const SerType::SERBINARY&);

}  // namespace lbcrypto

#endif
