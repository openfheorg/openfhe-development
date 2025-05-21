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
  Represents and defines packing integers of plaintext objects into polynomial coefficients in OpenFHE
 */

#ifndef SRC_CORE_LIB_ENCODING_COEFPACKEDENCODING_H_
#define SRC_CORE_LIB_ENCODING_COEFPACKEDENCODING_H_

#include "encoding/plaintext.h"

#include <initializer_list>
#include <memory>
#include <string>
#include <vector>

namespace lbcrypto {

class CoefPackedEncoding : public PlaintextImpl {
private:
    std::vector<int64_t> value;

protected:
    /**
    * @brief PrintValue() is called by operator<<
    * @param out stream to print to
    */
    void PrintValue(std::ostream& out) const override {
        out << "(";

        // for sanity's sake: get rid of all trailing zeroes and print "..." instead
        size_t i       = value.size();
        bool allZeroes = true;
        while (i > 0) {
            --i;
            if (value[i] != 0) {
                allZeroes = false;
                break;
            }
        }

        if (allZeroes == false) {
            for (size_t j = 0; j <= i; ++j)
                out << value[j] << ", ";
        }
        out << "... )";
    }

    /**
    * Method to compare two plaintext to test for equivalence
    * Testing that the plaintexts are of the same type done in operator==
    *
    * @param rhs - the other plaintext to compare to.
    * @return whether the two plaintext are equivalent.
    */
    bool CompareTo(const PlaintextImpl& rhs) const override {
        const auto* el = dynamic_cast<const CoefPackedEncoding*>(&rhs);
        return (el != nullptr) && value == el->value;
    }

public:
    template <typename T, typename std::enable_if<std::is_same<T, Poly::Params>::value ||
                                                      std::is_same<T, NativePoly::Params>::value ||
                                                      std::is_same<T, DCRTPoly::Params>::value,
                                                  bool>::type = true>
    CoefPackedEncoding(std::shared_ptr<T> vp, EncodingParams ep, SCHEME schemeId = SCHEME::INVALID_SCHEME)
        : PlaintextImpl(vp, ep, COEF_PACKED_ENCODING, schemeId) {}

    template <typename T, typename std::enable_if<std::is_same<T, Poly::Params>::value ||
                                                      std::is_same<T, NativePoly::Params>::value ||
                                                      std::is_same<T, DCRTPoly::Params>::value,
                                                  bool>::type = true>
    CoefPackedEncoding(std::shared_ptr<T> vp, EncodingParams ep, const std::vector<int64_t>& coeffs,
                       SCHEME schemeId = SCHEME::INVALID_SCHEME)
        : PlaintextImpl(vp, ep, COEF_PACKED_ENCODING, schemeId), value(coeffs) {}

    ~CoefPackedEncoding() override = default;

    /**
   * GetCoeffsValue
   * @return the un-encoded scalar
   */
    const std::vector<int64_t>& GetCoefPackedValue() const override {
        return value;
    }

    /**
   * SetIntVectorValue
   * @param val integer vector to initialize the plaintext
   */
    void SetIntVectorValue(const std::vector<int64_t>& val) override {
        value = val;
    }

    /**
   * Encode the plaintext into the Poly
   * @return true on success
   */
    bool Encode() override;

    /**
   * Decode the Poly into the string
   * @return true on success
   */
    bool Decode() override;

    /**
   * Get length of the plaintext
   *
   * @return number of elements in this plaintext
   */
    size_t GetLength() const override {
        return value.size();
    }

    /**
   * SetLength of the plaintext to the given size
   * @param siz
   */
    void SetLength(size_t siz) override {
        value.resize(siz);
    }
};

} /* namespace lbcrypto */

#endif /* SRC_CORE_LIB_ENCODING_COEFPACKEDENCODING_H_ */
