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
  Represents and defines plaintext encodings in OpenFHE with packing capabilities
 */

#ifndef LBCRYPTO_UTILS_PACKEDEXTENCODING_H
#define LBCRYPTO_UTILS_PACKEDEXTENCODING_H

#include <functional>
#include <initializer_list>
#include <map>
#include <memory>
#include <numeric>
#include <utility>
#include <vector>

#include "encoding/encodingparams.h"
#include "encoding/plaintext.h"
#include "utils/inttypes.h"

namespace lbcrypto {

// STL pair used as a key for some tables in PackedEncoding
using ModulusM = std::pair<NativeInteger, uint64_t>;

/**
 * @class PackedEncoding
 * @brief Type used for representing IntArray types.
 * Provides conversion functions to encode and decode plaintext data as type
 * vector<int64_t>. This class uses bit packing techniques to enable efficient
 * computing on vectors of integers. It is NOT supported for DCRTPoly
 */

class PackedEncoding : public PlaintextImpl {
    std::vector<int64_t> value;

public:
    // these two constructors are used inside of Decrypt
    template <typename T, typename std::enable_if<std::is_same<T, Poly::Params>::value ||
                                                      std::is_same<T, NativePoly::Params>::value ||
                                                      std::is_same<T, DCRTPoly::Params>::value,
                                                  bool>::type = true>
    PackedEncoding(std::shared_ptr<T> vp, EncodingParams ep) : PlaintextImpl(vp, ep) {}

    template <typename T, typename std::enable_if<std::is_same<T, Poly::Params>::value ||
                                                      std::is_same<T, NativePoly::Params>::value ||
                                                      std::is_same<T, DCRTPoly::Params>::value,
                                                  bool>::type = true>
    PackedEncoding(std::shared_ptr<T> vp, EncodingParams ep, const std::vector<int64_t>& coeffs)
        : PlaintextImpl(vp, ep), value(coeffs) {}

    template <typename T, typename std::enable_if<std::is_same<T, Poly::Params>::value ||
                                                      std::is_same<T, NativePoly::Params>::value ||
                                                      std::is_same<T, DCRTPoly::Params>::value,
                                                  bool>::type = true>
    PackedEncoding(std::shared_ptr<T> vp, EncodingParams ep, std::initializer_list<int64_t> coeffs)
        : PlaintextImpl(vp, ep), value(coeffs) {}

    /**
   * @brief Constructs a container with a copy of each of the elements in rhs,
   * in the same order.
   * @param rhs - The input object to copy.
   */
    explicit PackedEncoding(const std::vector<int64_t>& rhs)
        : PlaintextImpl(std::shared_ptr<Poly::Params>(0), nullptr), value(rhs) {}

    /**
   * @brief Constructs a container with a copy of each of the elements in il, in
   * the same order.
   * @param arr the list to copy.
   */
    PackedEncoding(std::initializer_list<int64_t> arr)
        : PlaintextImpl(std::shared_ptr<Poly::Params>(0), nullptr), value(arr) {}

    /**
   * @brief Default empty constructor with empty uninitialized data elements.
   */
    PackedEncoding() : PlaintextImpl(std::shared_ptr<Poly::Params>(0), nullptr), value() {}

    static usint GetAutomorphismGenerator(usint m) {
        return m_automorphismGenerator[m];
    }

    bool Encode();

    bool Decode();

    const std::vector<int64_t>& GetPackedValue() const {
        return value;
    }

    /**
   * SetIntVectorValue
   * @param val integer vector to initialize the plaintext
   */
    void SetIntVectorValue(const std::vector<int64_t>& val) {
        value = val;
    }

    /**
   * GetEncodingType
   * @return PACKED_ENCODING
   */
    PlaintextEncodings GetEncodingType() const {
        return PACKED_ENCODING;
    }

    /**
   * Get method to return the length of plaintext
   *
   * @return the length of the plaintext in terms of the number of bits.
   */
    size_t GetLength() const {
        return value.size();
    }

    /**
   * @brief Method to set encoding params
   * @param m the encoding cyclotomic order.
   * @params params data structure storing encoding parameters
   */
    static void SetParams(usint m, EncodingParams params);

    /**
   * @brief Method to set encoding params (this method should eventually be
   * replaced by void SetParams(usint m, EncodingParams params);)
   * @param m the encoding cyclotomic order.
   * @params modulus is the plaintext modulus
   */
    static void SetParams(usint m, const PlaintextModulus& modulus)
        __attribute__((deprecated("use SetParams(usint m, EncodingParams p)")));

    /**
   * SetLength of the plaintext to the given size
   * @param siz
   */
    void SetLength(size_t siz) {
        value.resize(siz);
    }

    /**
   * Method to compare two plaintext to test for equivalence.  This method does
   * not test that the plaintext are of the same type.
   *
   * @param other - the other plaintext to compare to.
   * @return whether the two plaintext are equivalent.
   */
    bool CompareTo(const PlaintextImpl& other) const {
        const auto& rv = static_cast<const PackedEncoding&>(other);
        return this->value == rv.value;
    }

    /**
   * @brief Destructor method.
   */
    static void Destroy();

    void PrintValue(std::ostream& out) const {
        // for sanity's sake, trailing zeros get elided into "..."
        out << "(";
        size_t i = value.size();
        while (--i > 0)
            if (value[i] != 0)
                break;

        for (size_t j = 0; j <= i; j++)
            out << ' ' << value[j];

        out << " ... )";
    }

private:
    // initial root of unity for plaintext space
    static std::map<ModulusM, NativeInteger> m_initRoot;
    // modulus and root of unity to be used for Arbitrary CRT
    static std::map<ModulusM, NativeInteger> m_bigModulus;
    static std::map<ModulusM, NativeInteger> m_bigRoot;

    // stores the list of primitive roots used in packing.
    static std::map<usint, usint> m_automorphismGenerator;
    static std::map<usint, std::vector<usint>> m_toCRTPerm;
    static std::map<usint, std::vector<usint>> m_fromCRTPerm;

    static void SetParams_2n(usint m, const NativeInteger& modulusNI);

    static void SetParams_2n(usint m, EncodingParams params);

    /**
   * @brief Packs the slot values into aggregate plaintext space.
   *
   * @param ring is the element containing slot values.
   * @param modulus is the plaintext modulus used for packing.
   */
    template <typename P>
    void Pack(P* ring, const PlaintextModulus& modulus) const;

    // Optimized version of packing designed for DCRTPoly and NativePoly
    void PackNativeVector(const PlaintextModulus& modulus, uint32_t m, NativeVector* values) const;

    /**
   * @brief Unpacks the data from aggregated plaintext to slot values.
   *
   * @param ring is the input polynomial ring in aggregate plaintext.
   * @param modulus is the plaintext modulus used in packing operation.
   */
    template <typename P>
    void Unpack(P* ring, const PlaintextModulus& modulus) const;
};

}  // namespace lbcrypto

#endif
