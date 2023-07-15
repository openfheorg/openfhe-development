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
  Represents and defines parameters for plaintext encoding
 */

#ifndef LBCRYPTO_ENCODING_ENCODINGPARAMS_H
#define LBCRYPTO_ENCODING_ENCODINGPARAMS_H

#include "utils/serializable.h"
#include "lattice/lat-hal.h"
#include "utils/inttypes.h"

#include <memory>
#include <string>
#include <utility>

namespace lbcrypto {
class EncodingParamsImpl;

typedef std::shared_ptr<EncodingParamsImpl> EncodingParams;

/**
 * @class EncodingParamsImpl
 * @brief All parameters for plaintext encodings into ciphertext space.
 */
class EncodingParamsImpl : public lbcrypto::Serializable {
public:
    /**
   * Main constructor. Supports (1) default constructor, (2) regular encoding
   * with plaintext modulus set, (3) packed encoding with at least first two
   * parameters set. All of the private members not explicitly included as
   * arguments will be initialized to zero.
   *
   * @param plaintextModulus plainext modulus (used by all encodings)
   * @param plaintextGenerator (used by packed encoding for plaintext slot
   * rotation)
   * @param batchSize sets the maximum batch size (as a power of 2) needed for
   * EvalSum
   */
    EncodingParamsImpl(PlaintextModulus plaintextModulus = 0, uint32_t batchSize = 0, uint32_t plaintextGenerator = 0,
                       NativeInteger plaintextRootOfUnity = 0, NativeInteger plaintextBigModulus = 0,
                       NativeInteger plaintextBigRootOfUnity = 0)
        : m_plaintextModulus(plaintextModulus),
          m_plaintextRootOfUnity(std::move(plaintextRootOfUnity)),
          m_plaintextBigModulus(plaintextBigModulus),
          m_plaintextBigRootOfUnity(std::move(plaintextBigRootOfUnity)),
          m_plaintextGenerator(plaintextGenerator),
          m_batchSize(batchSize) {}

    /**
   * Copy constructor.
   *
   * @param &rhs the input set of parameters which is copied.
   */
    EncodingParamsImpl(const EncodingParamsImpl& rhs) {
        m_plaintextModulus        = rhs.m_plaintextModulus;
        m_plaintextRootOfUnity    = rhs.m_plaintextRootOfUnity;
        m_plaintextBigModulus     = rhs.m_plaintextBigModulus;
        m_plaintextBigRootOfUnity = rhs.m_plaintextBigRootOfUnity;
        m_plaintextGenerator      = rhs.m_plaintextGenerator;
        m_batchSize               = rhs.m_batchSize;
    }

    /**
   * Move constructor.
   *
   * @param &rhs the input set of parameters which is copied.
   */
    EncodingParamsImpl(EncodingParamsImpl&& rhs) {
        m_plaintextModulus        = std::move(rhs.m_plaintextModulus);
        m_plaintextRootOfUnity    = std::move(rhs.m_plaintextRootOfUnity);
        m_plaintextBigModulus     = std::move(rhs.m_plaintextBigModulus);
        m_plaintextBigRootOfUnity = std::move(rhs.m_plaintextBigRootOfUnity);
        m_plaintextGenerator      = std::move(rhs.m_plaintextGenerator);
        m_batchSize               = rhs.m_batchSize;
    }

    /**
   * Assignment Operator.
   *
   * @param &rhs the EncodingParamsImpl to be copied.
   * @return the resulting EncodingParamsImpl.
   */
    const EncodingParamsImpl& operator=(const EncodingParamsImpl& rhs) {
        m_plaintextModulus        = rhs.m_plaintextModulus;
        m_plaintextRootOfUnity    = rhs.m_plaintextRootOfUnity;
        m_plaintextBigModulus     = rhs.m_plaintextBigModulus;
        m_plaintextBigRootOfUnity = rhs.m_plaintextBigRootOfUnity;
        m_plaintextGenerator      = rhs.m_plaintextGenerator;
        m_batchSize               = rhs.m_batchSize;
        return *this;
    }

    /**
   * Destructor.
   */
    virtual ~EncodingParamsImpl() {}

    // ACCESSORS

    // Get accessors

    /**
   * @brief Getter for the plaintext modulus.
   * @return The plaintext modulus.
   */
    const PlaintextModulus& GetPlaintextModulus() const {
        return m_plaintextModulus;
    }

    /**
   * @brief Setter for the plaintext modulus.
   */
    void SetPlaintextModulus(PlaintextModulus plaintextModulus) {
        m_plaintextModulus = plaintextModulus;
    }

    /**
   * @brief Getter for the plaintext modulus root of unity.
   * @return The plaintext modulus root of unity.
   */
    const NativeInteger& GetPlaintextRootOfUnity() const {
        return m_plaintextRootOfUnity;
    }

    /**
   * @brief Setter for the plaintext modulus root of unity.
   */
    void SetPlaintextRootOfUnity(const NativeInteger& plaintextRootOfUnity) {
        m_plaintextRootOfUnity = plaintextRootOfUnity;
    }

    /**
   * @brief Getter for the big plaintext modulus.
   * @return The plaintext modulus.
   */
    const NativeInteger& GetPlaintextBigModulus() const {
        return m_plaintextBigModulus;
    }

    /**
   * @brief Setter for the big plaintext modulus.
   */
    void SetPlaintextBigModulus(const NativeInteger& plaintextBigModulus) {
        m_plaintextBigModulus = plaintextBigModulus;
    }

    /**
   * @brief Getter for the big plaintext modulus root of unity.
   * @return The big plaintext modulus root of unity.
   */
    const NativeInteger& GetPlaintextBigRootOfUnity() const {
        return m_plaintextBigRootOfUnity;
    }

    /**
   * @brief Setter for the big plaintext modulus root of unity.
   */
    void SetPlaintextBigRootOfUnity(const NativeInteger& plaintextBigRootOfUnity) {
        m_plaintextBigRootOfUnity = plaintextBigRootOfUnity;
    }

    /**
   * @brief Getter for the plaintext generator.
   * @return The plaintext generator.
   */
    usint GetPlaintextGenerator() const {
        return m_plaintextGenerator;
    }

    /**
   * @brief Setter for the plaintext generator.
   */
    void SetPlaintextGenerator(usint& plaintextGenerator) {
        m_plaintextGenerator = plaintextGenerator;
    }

    /**
   * @brief Getter for the plaintext batch size.
   * @return The plaintext batch size.
   */
    uint32_t GetBatchSize() const {
        return m_batchSize;
    }

    /**
   * @brief Setter for the batch size
   */
    void SetBatchSize(usint batchSize) {
        m_batchSize = batchSize;
    }

    // Operators
    /**
   * @brief output stream operator.
   * @param out the output stream to output.
   * @param item the following object to output.
   * @return the string output.
   */
    friend std::ostream& operator<<(std::ostream& out, const EncodingParamsImpl& item) {
        return item.doprint(out);
    }
    /**
   * @brief Equality operator for the parameters.  Tests that all the parameters
   * are equal.
   * @param other the other parameter set to compare to.
   * @return true if values of all data are equal.
   */
    bool operator==(const EncodingParamsImpl& other) const {
        return m_plaintextModulus == other.m_plaintextModulus &&
               m_plaintextRootOfUnity == other.m_plaintextRootOfUnity &&
               m_plaintextBigModulus == other.m_plaintextBigModulus &&
               m_plaintextBigRootOfUnity == other.m_plaintextBigRootOfUnity &&
               m_plaintextGenerator == other.m_plaintextGenerator && m_batchSize == other.m_batchSize;
    }
    /**
   * @brief Inequality operator for the parameters.  Tests that all the
   * parameters are not equal.
   * @param other the other parameter set to compare to.
   * @return true if values of any data is not equal.
   */
    bool operator!=(const EncodingParamsImpl& other) const {
        return !(*this == other);
    }

private:
    std::ostream& doprint(std::ostream& out) const {
        out << "[p=" << m_plaintextModulus << " rootP =" << m_plaintextRootOfUnity << " bigP =" << m_plaintextBigModulus
            << " rootBigP =" << m_plaintextBigRootOfUnity << " g=" << m_plaintextGenerator << " L=" << m_batchSize
            << "]";
        return out;
    }

    // plaintext modulus that is used by all schemes
    PlaintextModulus m_plaintextModulus;
    // root of unity for plaintext modulus
    NativeInteger m_plaintextRootOfUnity;
    // big plaintext modulus that is used for arbitrary cyclotomics
    NativeInteger m_plaintextBigModulus;
    // root of unity for big plaintext modulus
    NativeInteger m_plaintextBigRootOfUnity;
    // plaintext generator is used for packed encoding (to find the correct
    // automorphism index)
    uint32_t m_plaintextGenerator;
    // maximum batch size used by EvalSumKeyGen for packed encoding
    uint32_t m_batchSize;

public:
    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("m", m_plaintextModulus));
        ar(::cereal::make_nvp("ru", m_plaintextRootOfUnity));
        ar(::cereal::make_nvp("bm", m_plaintextBigModulus));
        ar(::cereal::make_nvp("bru", m_plaintextBigRootOfUnity));
        ar(::cereal::make_nvp("g", m_plaintextGenerator));
        ar(::cereal::make_nvp("bs", m_batchSize));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(::cereal::make_nvp("m", m_plaintextModulus));
        ar(::cereal::make_nvp("ru", m_plaintextRootOfUnity));
        ar(::cereal::make_nvp("bm", m_plaintextBigModulus));
        ar(::cereal::make_nvp("bru", m_plaintextBigRootOfUnity));
        ar(::cereal::make_nvp("g", m_plaintextGenerator));
        ar(::cereal::make_nvp("bs", m_batchSize));
    }

    std::string SerializedObjectName() const {
        return "EncodingParms";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }
};

inline std::ostream& operator<<(std::ostream& out, const std::shared_ptr<EncodingParamsImpl>& o) {
    if (o)
        out << *o;
    return out;
}
inline bool operator==(const std::shared_ptr<EncodingParamsImpl>& o1, const std::shared_ptr<EncodingParamsImpl>& o2) {
    if (o1 && o2)
        return *o1 == *o2;
    if (!o1 && !o2)
        return true;
    return false;
}

}  // namespace lbcrypto

#endif
