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

#ifndef LBCRYPTO_UTILS_CKKSPACKEDEXTENCODING_H
#define LBCRYPTO_UTILS_CKKSPACKEDEXTENCODING_H

#include "constants.h"

#include "encoding/encodingparams.h"
#include "encoding/plaintext.h"

#include "math/hal/basicint.h"

#include <algorithm>
#include <functional>
#include <initializer_list>
#include <memory>
#include <numeric>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

/**
 * @class CKKSPackedEncoding
 * @brief Type used for representing IntArray types.
 * Provides conversion functions to encode and decode plaintext data as type
 * vector<uint64_t>. This class uses bit packing techniques to enable efficient
 * computing on vectors of integers. It is NOT supported for DCRTPoly
 */

class CKKSPackedEncoding : public PlaintextImpl {
private:
    std::vector<std::complex<double>> value;
    double m_logError = 0.;

public:
    // these two constructors are used inside of Decrypt
    template <typename T, typename std::enable_if<std::is_same<T, Poly::Params>::value ||
                                                      std::is_same<T, NativePoly::Params>::value ||
                                                      std::is_same<T, DCRTPoly::Params>::value,
                                                  bool>::type = true>
    CKKSPackedEncoding(std::shared_ptr<T> vp, EncodingParams ep, CKKSDataType ckksdt)
        : PlaintextImpl(vp, ep, CKKS_PACKED_ENCODING, CKKSRNS_SCHEME) {
        ckksDataType = ckksdt;
        slots        = GetDefaultSlotSize();
    }

    /*
   * @param noiseScaleDeg degree of the scaling factor of a plaintext
   * @param level level of plaintext to create.
   * @param scFact scaling factor of a plaintext of this level at depth 1.
   *
   */
    template <typename T, typename std::enable_if<std::is_same<T, Poly::Params>::value ||
                                                      std::is_same<T, NativePoly::Params>::value ||
                                                      std::is_same<T, DCRTPoly::Params>::value,
                                                  bool>::type = true>
    CKKSPackedEncoding(std::shared_ptr<T> vp, EncodingParams ep, const std::vector<std::complex<double>>& v,
                       size_t nsdeg, uint32_t lvl, double scFact, uint32_t slts, CKKSDataType ckksdt)
        : PlaintextImpl(vp, ep, CKKS_PACKED_ENCODING, CKKSRNS_SCHEME), value(v) {
        ckksDataType  = ckksdt;
        scalingFactor = scFact;
        level         = lvl;
        noiseScaleDeg = nsdeg;
        slots         = GetDefaultSlotSize(slts, v.size());

        if (ckksDataType == REAL) {
            auto* rvptr = reinterpret_cast<double*>(value.data()) + 1;
            auto* limit = rvptr + 2 * value.size();
            for (; rvptr < limit; rvptr += 2)
                *rvptr = 0;
        }
    }

    /**
   * @brief Constructs a container with a copy of each of the elements in v,
   * in the same order.
   * @param v - The input object to copy.
   */
    explicit CKKSPackedEncoding(const std::vector<std::complex<double>>& v, uint32_t s)
        : PlaintextImpl(std::shared_ptr<Poly::Params>(0), nullptr, CKKS_PACKED_ENCODING, CKKSRNS_SCHEME), value(v) {
        slots = GetDefaultSlotSize(s, v.size());

        // Assumes ckksDataType = REAL
        auto* rvptr = reinterpret_cast<double*>(value.data()) + 1;
        auto* limit = rvptr + 2 * value.size();
        for (; rvptr < limit; rvptr += 2)
            *rvptr = 0;
    }

    /**
   * @brief Default empty constructor with empty uninitialized data elements.
   */
    CKKSPackedEncoding()
        : PlaintextImpl(std::shared_ptr<Poly::Params>(0), nullptr, CKKS_PACKED_ENCODING, CKKSRNS_SCHEME) {
        slots = GetDefaultSlotSize();
    }

    CKKSPackedEncoding(const CKKSPackedEncoding& rhs)
        : PlaintextImpl(rhs), value(rhs.value), m_logError(rhs.m_logError) {}

    CKKSPackedEncoding(CKKSPackedEncoding&& rhs)
        : PlaintextImpl(std::move(rhs)), value(std::move(rhs.value)), m_logError(rhs.m_logError) {}

    bool Encode() override;

    bool Decode() override {
        OPENFHE_THROW("CKKSPackedEncoding::Decode() is not implemented. Use CKKSPackedEncoding::Decode(...) instead.");
    }

    bool Decode(size_t depth, double scalingFactor, ScalingTechnique scalTech, ExecutionMode executionMode) override;

    const std::vector<std::complex<double>>& GetCKKSPackedValue() const override {
        return value;
    }

    std::vector<double> GetRealPackedValue() const override {
        std::vector<double> realValue(value.size());
        auto* rvptr = realValue.data();
        for (auto vit = value.cbegin(); vit != value.cend(); ++vit, ++rvptr)
            *rvptr = vit->real();
        return realValue;
    }

    /**
   * Static utility method to multiply two numbers in CRT representation.
   * CRT representation is stored in a vector of native integers, and each
   * position corresponds to the remainder of the number against one of
   * the moduli in mods.
   *
   * @param a is the first number in CRT representation.
   * @param b is the second number in CRT representation.
   * @return the product of the two numbers in CRT representation.
   */
    static std::vector<DCRTPoly::Integer> CRTMult(const std::vector<DCRTPoly::Integer>& a,
                                                  const std::vector<DCRTPoly::Integer>& b,
                                                  const std::vector<DCRTPoly::Integer>& mods);

    /**
   * Get method to return the length of plaintext
   *
   * @return the length of the plaintext in terms of the number of bits.
   */
    size_t GetLength() const override {
        return value.size();
    }

    /**
   * Get method to return log2 of estimated standard deviation of approximation
   * error
   */
    double GetLogError() const override {
        return m_logError;
    }

    /**
   * Get method to return log2 of estimated precision
   */
    double GetLogPrecision() const override {
        if (ckksDataType == COMPLEX)
            OPENFHE_THROW("GetLogPrecision for complex numbers is not implemented.");
        return encodingParams->GetPlaintextModulus() - m_logError;
    }

    /**
   * SetLength of the plaintext to the given size
   * @param siz
   */
    void SetLength(size_t siz) override {
        value.resize(siz);
    }

    /**
   * @brief Destructor method.
   */
    static void Destroy();

    /**
    * @brief GetFormattedValues() is called by operator<< and requires a precision as an argument
    * @param precision number of decimal digits of precision to print
    * @return string with all values and "estimated precision"
    */
    std::string GetFormattedValues(int64_t precision) const override {
        std::stringstream ss;
        ss << "(";

        // for sanity's sake: get rid of all trailing zeroes and print "..." instead
        size_t i       = value.size();
        bool allZeroes = true;
        while (i > 0) {
            if (value[--i] != std::complex<double>(0, 0)) {
                allZeroes = false;
                break;
            }
        }
        if (!allZeroes) {
            if (ckksDataType == REAL) {
                for (size_t j = 0; j <= i; ++j)
                    ss << std::setprecision(precision) << value[j].real() << ", ";
                ss << "... ); Estimated precision: " << GetLogPrecision() << " bits";
            }
            else {
                for (size_t j = 0; j <= i; ++j)
                    ss << std::setprecision(precision) << " (" << value[j].real() << ", " << value[j].imag() << "), ";
                ss << "... )";
            }
        }
        return ss.str();
    }

protected:
    void PrintValue(std::ostream& out) const override {
        out << GetFormattedValues(8) << std::endl;
    }

    uint32_t GetDefaultSlotSize(uint32_t slots = 0, size_t vlen = 0) {
        if (slots == 0) {
            uint32_t batchSize = GetEncodingParams()->GetBatchSize();
            slots              = (batchSize == 0) ? GetElementRingDimension() >> 1 : batchSize;
        }
        if ((slots & (slots - 1)) != 0)
            OPENFHE_THROW("The number of slots should be a power of two");
        if (slots > GetElementRingDimension() >> 1)
            OPENFHE_THROW("The number of slots cannot be larger than half of ring dimension");
        if (slots < vlen)
            OPENFHE_THROW("The number of slots cannot be smaller than value vector size");
        return slots;
    }

    /**
    * Method to compare two plaintext to test for equivalence.  This method does
    * not test that the plaintext are of the same type.
    *
    * @param rhs - the other plaintext to compare to.
    * @return whether the two plaintext are equivalent.
    */
    bool CompareTo(const PlaintextImpl& rhs) const override {
        const auto* el = dynamic_cast<const CKKSPackedEncoding*>(&rhs);
        return (el != nullptr) && value == el->value;
    }

    /**
   * Set modulus and recalculates the vector values to fit the modulus
   *
   * @param &vec input vector
   * @param &bigValue big bound of the vector values.
   * @param &modulus modulus to be set for vector.
   */
    void FitToNativeVector(const std::vector<int64_t>& vec, int64_t bigBound, NativeVector* nativeVec) const;

#if NATIVEINT == 128
    /**
   * Set modulus and recalculates the vector values to fit the modulus
   *
   * @param &vec input vector
   * @param &bigValue big bound of the vector values.
   * @param &modulus modulus to be set for vector.
   */
    void FitToNativeVector(const std::vector<int128_t>& vec, int128_t bigBound, NativeVector* nativeVec) const;
#endif
};

}  // namespace lbcrypto

#endif
