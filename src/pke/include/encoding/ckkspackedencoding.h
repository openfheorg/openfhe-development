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

#ifndef SRC_PKE_INCLUDE_ENCODING_CKKSPACKEDENCODING_H_
#define SRC_PKE_INCLUDE_ENCODING_CKKSPACKEDENCODING_H_

#include <algorithm>
#include <complex>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <iomanip>
#include <memory>
#include <numeric>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "constants.h"
#include "encoding/encodingparams.h"
#include "encoding/plaintext.h"
#include "math/hal/basicint.h"

namespace lbcrypto {

/**
 * @class CKKSPackedEncoding
 * @brief Type used for representing CKKS packed plaintexts.
 * Provides conversion functions to encode and decode vectors of complex (or real)
 * numbers into the plaintext slots using the CKKS canonical embedding.
 */

class CKKSPackedEncoding : public PlaintextImpl {
  private:
    std::vector<std::complex<double>> value;
    double m_logError = 0.;

  public:
    // these two constructors are used inside of Decrypt
    /**
     * @brief Constructs an empty CKKS plaintext over the given element parameters, with the default number of
     * slots (the batch size, or N/2 if the batch size is 0).
     * @param vp element parameters of the polynomial (Poly, NativePoly or DCRTPoly parameters)
     * @param ep encoding parameters
     * @param ckksdt CKKS data type (REAL discards the imaginary parts)
     */
    template <typename T, typename std::enable_if<std::is_same<T, Poly::Params>::value ||
                                                          std::is_same<T, NativePoly::Params>::value ||
                                                          std::is_same<T, DCRTPoly::Params>::value,
                                                  bool>::type = true>
    CKKSPackedEncoding(std::shared_ptr<T> vp, EncodingParams ep, CKKSDataType ckksdt = REAL)
        : PlaintextImpl(vp, ep, CKKS_PACKED_ENCODING, CKKSRNS_SCHEME) {
        ckksDataType = ckksdt;
        slots = GetDefaultSlotSize();
    }

    /**
     * @brief Constructs a CKKS plaintext holding the given values at a given level and noise scale degree (the
     * values are not encoded yet; call Encode). For REAL data the imaginary parts of the values are zeroed.
     * @param vp element parameters of the polynomial (Poly, NativePoly or DCRTPoly parameters)
     * @param ep encoding parameters
     * @param v the values to be encoded
     * @param nsdeg degree of the scaling factor of a plaintext
     * @param lvl level of plaintext to create.
     * @param scFact scaling factor of a plaintext of this level at depth 1.
     * @param slts number of slots (0 selects the default slot count; must be a power of two not smaller than the
     * size of v)
     * @param ckksdt CKKS data type (REAL discards the imaginary parts)
     */
    template <typename T, typename std::enable_if<std::is_same<T, Poly::Params>::value ||
                                                          std::is_same<T, NativePoly::Params>::value ||
                                                          std::is_same<T, DCRTPoly::Params>::value,
                                                  bool>::type = true>
    CKKSPackedEncoding(std::shared_ptr<T> vp, EncodingParams ep, const std::vector<std::complex<double>>& v,
                       size_t nsdeg, uint32_t lvl, double scFact, uint32_t slts, CKKSDataType ckksdt = REAL)
        : PlaintextImpl(vp, ep, CKKS_PACKED_ENCODING, CKKSRNS_SCHEME), value(v) {
        ckksDataType = ckksdt;
        scalingFactor = scFact;
        level = lvl;
        noiseScaleDeg = nsdeg;
        slots = GetDefaultSlotSize(slts, v.size());

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
     * @param s - The number of slots (0 selects the default slot count for the size of v).
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

    /**
     * @brief Copy constructor.
     * @param rhs the plaintext to copy
     */
    CKKSPackedEncoding(const CKKSPackedEncoding& rhs)
        : PlaintextImpl(rhs), value(rhs.value), m_logError(rhs.m_logError) {}

    /**
     * @brief Move constructor.
     * @param rhs the plaintext to move from
     */
    CKKSPackedEncoding(CKKSPackedEncoding&& rhs) noexcept
        : PlaintextImpl(std::move(rhs)), value(std::move(rhs.value)), m_logError(rhs.m_logError) {}

    /**
     * @brief Encodes the values into the polynomial: applies the inverse canonical embedding (inverse FFT over the
     * slots), scales by the scaling factor raised to the noise scale degree, rounds and reduces modulo the RNS
     * moduli of the level.
     * @return true on success
     */
    bool Encode() override;

    /**
     * @brief Not supported for CKKS: the scaling factor of the ciphertext is needed. Use Decode(depth,
     * scalingFactor, scalTech, executionMode) instead.
     * @return never returns
     */
    bool Decode() override {
        OPENFHE_THROW("CKKSPackedEncoding::Decode() is not implemented. Use CKKSPackedEncoding::Decode(...) instead.");
    }

    /**
     * @brief Decodes the polynomial into the values: divides the coefficients by the scaling factor (2^p for the
     * FIXED* techniques, the level-specific scalingFactor for FLEXIBLE* and COMPOSITESCALING*), estimates the
     * approximation error and adds noise of that size to hide the decryption noise (in EXEC_EVALUATION mode), then
     * applies the canonical embedding (FFT) to obtain the slot values. In EXEC_NOISE_ESTIMATION mode only the
     * error estimate is decoded.
     * @param depth noise scale degree of the decrypted ciphertext
     * @param scalingFactor scaling factor of the decrypted ciphertext
     * @param scalTech scaling technique of the scheme
     * @param executionMode EXEC_NOISE_ESTIMATION or EXEC_EVALUATION
     * @return true on success
     */
    bool Decode(size_t depth, double scalingFactor, ScalingTechnique scalTech, ExecutionMode executionMode) override;

    /**
     * @brief Gets the decoded (or to be encoded) complex values.
     * @return the values, one per slot
     */
    const std::vector<std::complex<double>>& GetCKKSPackedValue() const override {
        return value;
    }

    /**
     * @brief Gets the real parts of the decoded (or to be encoded) values.
     * @return the real parts, one per slot
     */
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
     * @param m is the vector of CRT moduli.
     * @return the product of the two numbers in CRT representation.
     */
    static std::vector<DCRTPoly::Integer> CRTMult(const std::vector<DCRTPoly::Integer>& a,
                                                  const std::vector<DCRTPoly::Integer>& b,
                                                  const std::vector<DCRTPoly::Integer>& m) {
        // TODO: add check that vector lengths match?
        std::vector<DCRTPoly::Integer> r;
        r.reserve(m.size());
        for (uint32_t i = 0; i < a.size(); ++i)
            r.emplace_back(a[i].ModMulFast(b[i], m[i]));
        return r;
    }

#if NATIVEINT == 128
    /**
     * Static utility method to scale a rounded mantissa by a power of two.
     *
     * The 128-bit encodings express a double as mantissa * 2^exponent and rescale the mantissa
     * by 2^pRemaining to reach the plaintext scaling factor. Both ends of the range need care:
     * a strongly negative pRemaining exceeds the width of the intermediate type, and a large
     * positive one overflows it.
     *
     * @param mantissa is the rounded 52-bit mantissa, carrying the sign of the operand.
     * @param pRemaining is the power of two to apply; a negative value shifts right.
     * @return mantissa * 2^pRemaining, truncated toward zero when pRemaining is negative.
     */
    static int128_t ScaleByPowerOfTwo(int64_t mantissa, int32_t pRemaining) {
        // Negating through uint64_t is defined even when std::llround returned the signed
        // minimum, which it may for a non-finite input.
        const uint64_t magnitude = (mantissa < 0) ? uint64_t(0) - uint64_t(mantissa) : uint64_t(mantissa);
        if (magnitude == 0)
            return 0;

        if (pRemaining < 0) {
            // Values below the integer precision truncate toward zero for either sign. Counts at
            // or beyond the word width underflow without evaluating an out-of-range shift.
            const uint64_t truncated = (pRemaining <= -64) ? 0 : (magnitude >> (-pRemaining));
            return (mantissa < 0) ? -static_cast<int128_t>(truncated) : static_cast<int128_t>(truncated);
        }

        // FitToNativeVector reads anything above Max128BitValue() / 2 as a negative value, so
        // that is the largest magnitude this representation carries. Testing before the shift
        // keeps an oversized operand from wrapping into a wrong plaintext.
        constexpr uint128_t maxMagnitude = static_cast<uint128_t>(Max128BitValue()) >> 1;
        if (pRemaining > 126 || magnitude > (maxMagnitude >> pRemaining))
            OPENFHE_THROW("Overflow, try to decrease scaling factor");

        const int128_t scaled = static_cast<int128_t>(static_cast<uint128_t>(magnitude) << pRemaining);
        return (mantissa < 0) ? -scaled : scaled;
    }
#endif

    /**
     * Get method to return the length of plaintext
     *
     * @return the length of the plaintext in terms of the number of elements.
     */
    size_t GetLength() const override {
        return value.size();
    }

    /**
     * Get method to return log2 of estimated standard deviation of approximation
     * error
     * @return log2 of the estimated error
     */
    double GetLogError() const override {
        return m_logError;
    }

    /**
     * Get method to return log2 of estimated precision (only for REAL data)
     * @return log2 of the estimated precision, i.e., the scaling modulus size minus the estimated error
     */
    double GetLogPrecision() const override {
        if (ckksDataType == COMPLEX)
            OPENFHE_THROW("GetLogPrecision for complex numbers is not implemented.");
        return encodingParams->GetPlaintextModulus() - m_logError;
    }

    /**
     * SetLength of the plaintext to the given size
     * @param siz the new number of elements
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
        size_t i = value.size();
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
            } else {
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

    /**
     * @brief Resolves and validates the number of slots: 0 selects the batch size of the encoding parameters (or
     * N/2 if the batch size is 0); the result must be a power of two, at most N/2 and at least vlen.
     * @param slots the requested number of slots (0 = default)
     * @param vlen the number of values to be packed
     * @return the number of slots
     */
    uint32_t GetDefaultSlotSize(uint32_t slots = 0, size_t vlen = 0) {
        if (slots == 0) {
            uint32_t batchSize = GetEncodingParams()->GetBatchSize();
            slots = (batchSize == 0) ? GetElementRingDimension() >> 1 : batchSize;
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
        if (typeid(rhs) != typeid(CKKSPackedEncoding))
            return false;

        const auto& el = static_cast<const CKKSPackedEncoding&>(rhs);
        return value == el.value;
    }

    /**
     * Set modulus and recalculates the vector values to fit the modulus
     *
     * @param vec input vector
     * @param bigBound big bound of the vector values.
     * @param nativeVec output native vector (its modulus is used to fit the values).
     */
    void FitToNativeVector(const std::vector<int64_t>& vec, int64_t bigBound, NativeVector* nativeVec) const;

#if NATIVEINT == 128
    /**
     * Set modulus and recalculates the vector values to fit the modulus
     *
     * @param vec input vector
     * @param bigBound big bound of the vector values.
     * @param nativeVec output native vector (its modulus is used to fit the values).
     */
    void FitToNativeVector(const std::vector<int128_t>& vec, int128_t bigBound, NativeVector* nativeVec) const;
#endif
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_ENCODING_CKKSPACKEDENCODING_H_
