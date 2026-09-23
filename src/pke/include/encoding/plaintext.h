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
  Represents and defines plaintext objects in OpenFHE
 */

#ifndef SRC_PKE_INCLUDE_ENCODING_PLAINTEXT_H_
#define SRC_PKE_INCLUDE_ENCODING_PLAINTEXT_H_

#include <algorithm>
#include <complex>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "constants.h"
#include "encoding/encodingparams.h"
#include "encoding/plaintext-fwd.h"
#include "scheme/scheme-id.h"

namespace lbcrypto {

/**
 * @class PlaintextImpl
 * @brief This class represents plaintext in the OpenFHE library.
 *
 * PlaintextImpl is primarily intended to be
 * used as a container and in conjunction with specific encodings which inherit
 * from this class which depend on the application the plaintext is used with.
 * It provides virtual methods for encoding and decoding of data.
 */
class PlaintextImpl {
  protected:
    /**
   * @brief Type of the polynomial the plaintext is encoded into.
   */
    enum PtxtPolyType { IsPoly, IsDCRTPoly, IsNativePoly };

    bool isEncoded{false};          ///< whether the values have been encoded into the polynomial
    PtxtPolyType typeFlag;          ///< which of the three polynomial members is in use
    EncodingParams encodingParams;  ///< encoding parameters (plaintext modulus, batch size, ...)

    Poly encodedVector;              ///< encoded polynomial (multiprecision)
    NativePoly encodedNativeVector;  ///< encoded polynomial (native integers)
    DCRTPoly encodedVectorDCRT;      ///< encoded polynomial (RNS/CRT representation)

    PlaintextEncodings ptxtEncoding{INVALID_ENCODING};  ///< encoding type
    SCHEME schemeID{SCHEME::INVALID_SCHEME};            ///< scheme the plaintext was created for
    CKKSDataType ckksDataType{REAL};                    ///< CKKS data type (real or complex slots)
    double scalingFactor{1.0};                          ///< CKKS scaling factor
    NativeInteger scalingFactorInt{1};                  ///< BGV scaling factor
    size_t level{0};                                    ///< level (number of dropped RNS limbs) of the plaintext
    size_t noiseScaleDeg{1};                            ///< noise scale degree (power of the scaling factor)
    uint32_t slots{0};                                  ///< number of slots (CKKS)

    /**
    * @brief PrintValue() is called by operator<<
    * @param out stream to print to
    */
    virtual void PrintValue(std::ostream& out) const = 0;

    /**
    * Method to compare two plaintext to test for equivalence.
    * This method is called by operator==
    *
    * @param other - the other plaintext to compare to.
    * @return whether the two plaintext are equivalent.
    */
    virtual bool CompareTo(const PlaintextImpl& other) const = 0;

  public:
    /**
   * Constructs an empty plaintext encoded into a multiprecision polynomial (Poly) in COEFFICIENT format.
   *
   * @param vp element parameters of the polynomial
   * @param ep encoding parameters
   * @param encoding encoding type
   * @param schemeTag scheme the plaintext is created for
   */
    PlaintextImpl(const std::shared_ptr<Poly::Params>& vp, EncodingParams ep, PlaintextEncodings encoding,
                  SCHEME schemeTag = SCHEME::INVALID_SCHEME)
        : typeFlag(IsPoly),
          encodingParams(std::move(ep)),
          encodedVector(vp, Format::COEFFICIENT),
          ptxtEncoding(encoding),
          schemeID(schemeTag) {}

    /**
   * Constructs an empty plaintext encoded into a native polynomial (NativePoly) in COEFFICIENT format.
   *
   * @param vp element parameters of the polynomial
   * @param ep encoding parameters
   * @param encoding encoding type
   * @param schemeTag scheme the plaintext is created for
   */
    PlaintextImpl(const std::shared_ptr<NativePoly::Params>& vp, EncodingParams ep, PlaintextEncodings encoding,
                  SCHEME schemeTag = SCHEME::INVALID_SCHEME)
        : typeFlag(IsNativePoly),
          encodingParams(std::move(ep)),
          encodedNativeVector(vp, Format::COEFFICIENT),
          ptxtEncoding(encoding),
          schemeID(schemeTag) {}

    /**
   * Constructs an empty plaintext encoded into an RNS polynomial (DCRTPoly) in COEFFICIENT format; the
   * multiprecision polynomial is initialized as well because the coefficient-packed encoding uses it.
   *
   * @param vp element parameters of the polynomial
   * @param ep encoding parameters
   * @param encoding encoding type
   * @param schemeTag scheme the plaintext is created for
   */
    // TODO: eliminate use of encodedVector in coefpackedencoding to remove encodedVector init here
    PlaintextImpl(const std::shared_ptr<DCRTPoly::Params>& vp, EncodingParams ep, PlaintextEncodings encoding,
                  SCHEME schemeTag = SCHEME::INVALID_SCHEME)
        : typeFlag(IsDCRTPoly),
          encodingParams(std::move(ep)),
          encodedVector(vp, Format::COEFFICIENT),
          encodedVectorDCRT(vp, Format::COEFFICIENT),
          ptxtEncoding(encoding),
          schemeID(schemeTag) {}

    PlaintextImpl(const PlaintextImpl& rhs) = default;

    PlaintextImpl(PlaintextImpl&& rhs) noexcept = default;

    virtual ~PlaintextImpl() = default;

    /**
   * GetEncodingType
   * @return Encoding type used by this plaintext
   */
    PlaintextEncodings GetEncodingType() const {
        return ptxtEncoding;
    }

    /**
   * Get the scaling factor of the plaintext for CKKS-based plaintexts.
   * @return the scaling factor
   */
    double GetScalingFactor() const {
        return scalingFactor;
    }

    /**
   * Set the scaling factor of the plaintext for CKKS-based plaintexts.
   * @param sf the scaling factor
   */
    void SetScalingFactor(double sf) {
        scalingFactor = sf;
    }

    /**
   * Get the scaling factor of the plaintext for BGV-based plaintexts.
   * @return the integer scaling factor
   */
    NativeInteger GetScalingFactorInt() const {
        return scalingFactorInt;
    }

    /**
   * Set the scaling factor of the plaintext for BGV-based plaintexts.
   * @param sf the integer scaling factor
   */
    void SetScalingFactorInt(NativeInteger sf) {
        scalingFactorInt = sf;
    }

    /**
   * Get the scheme ID the plaintext was created for.
   * @return the scheme ID
   */
    SCHEME GetSchemeID() const {
        return schemeID;
    }

    /**
   * IsEncoded
   * @return true when encoding is done
   */
    bool IsEncoded() const {
        return isEncoded;
    }

    /**
   * GetEncodingParams
   * @return Encoding params used with this plaintext
   */
    EncodingParams GetEncodingParams() const {
        return encodingParams;
    }

    /**
   * GetCKKSDataType
   * @return CKKS data type with this plaintext
   */
    CKKSDataType GetCKKSDataType() const {
        return ckksDataType;
    }

    /**
   * SetCKKSDataType
   * @param cdt CKKS data type to be used with this plaintext
   */
    void SetCKKSDataType(CKKSDataType cdt) {
        ckksDataType = cdt;
    }

    /**
   * Encode the plaintext into a polynomial
   * @return true on success
   */
    virtual bool Encode() = 0;

    /**
   * @brief Decode the polynomial into the plaintext
   * @return true on success
   */
    virtual bool Decode() = 0;

    /**
   * @brief Decode the polynomial into the plaintext for CKKS, i.e., divide by the scaling factor of the
   * ciphertext the plaintext was decrypted from (only implemented by CKKSPackedEncoding).
   * @param depth noise scale degree of the decrypted ciphertext
   * @param scalingFactor scaling factor of the decrypted ciphertext
   * @param scalTech scaling technique of the scheme (selects the fixed or the level-specific scaling factor)
   * @param executionMode EXEC_NOISE_ESTIMATION to decode only the noise estimate, EXEC_EVALUATION otherwise
   * @return true on success
   */
    virtual bool Decode(size_t depth, double scalingFactor, ScalingTechnique scalTech, ExecutionMode executionMode) {
        OPENFHE_THROW("Not implemented");
    }

    /**
   * Calculate and return lower bound that can be encoded with the plaintext
   * modulus the number to encode MUST be greater than this value
   * @return floor(-p/2)
   */
    int64_t LowBound() const {
        uint64_t ptm = GetEncodingParams()->GetPlaintextModulus();
        return -static_cast<int64_t>((ptm >> 1) + (ptm & 0x1));
    }

    /**
   * Calculate and return upper bound that can be encoded with the plaintext
   * modulus the number to encode MUST be less than or equal to this value
   * @return floor(p/2)
   */
    int64_t HighBound() const {
        return GetEncodingParams()->GetPlaintextModulus() >> 1;
    }

    /**
   * SetFormat - allows format to be changed for PlaintextImpl evaluations
   *
   * @param fmt the format (COEFFICIENT or EVALUATION) to switch the encoded element to
   */
    void SetFormat(Format fmt) {
        if (typeFlag == IsPoly)
            encodedVector.SetFormat(fmt);
        else if (typeFlag == IsNativePoly)
            encodedNativeVector.SetFormat(fmt);
        else
            encodedVectorDCRT.SetFormat(fmt);
    }

    /**
   * GetElement
   * @return the Polynomial that the element was encoded into
   */
    template <typename Element>
    Element& GetElement() {
        OPENFHE_THROW("Not implemented");
    }

    /**
   * GetElement
   * @return the Polynomial that the element was encoded into
   */
    template <typename Element>
    const Element& GetElement() const {
        OPENFHE_THROW("Not implemented");
    }

    /**
   * GetElementRingDimension
   * @return ring dimension on the underlying element
   */
    uint32_t GetElementRingDimension() const {
        return typeFlag == IsPoly ? encodedVector.GetRingDimension() :
                                    (typeFlag == IsNativePoly ? encodedNativeVector.GetRingDimension() :
                                                                encodedVectorDCRT.GetRingDimension());
    }

    /**
   * GetElementModulus
   * @return modulus on the underlying element
   */
    BigInteger GetElementModulus() const {
        return typeFlag == IsPoly ? encodedVector.GetModulus() :
                                    (typeFlag == IsNativePoly ? BigInteger(encodedNativeVector.GetModulus()) :
                                                                encodedVectorDCRT.GetModulus());
    }

    /**
   * Get method to return the length of plaintext
   *
   * @return the length of the plaintext in terms of the number of elements.
   */
    virtual size_t GetLength() const = 0;

    /**
   * resize the plaintext; only works for plaintexts that support a resizable
   * vector (coefpacked)
   * @param newSize the new number of elements
   */
    virtual void SetLength(size_t newSize) {
        OPENFHE_THROW("resize not supported");
    }

    /**
   * Method to get the degree of the scaling factor of a plaintext.
   *
   * @return the degree of the scaling factor of the plaintext
   */
    size_t GetNoiseScaleDeg() const {
        return noiseScaleDeg;
    }

    /**
   * Method to set the degree of the scaling factor of a plaintext.
   *
   * @param d the degree of the scaling factor
   */
    void SetNoiseScaleDeg(size_t d) {
        noiseScaleDeg = d;
    }

    /**
   * Method to get the level of a plaintext.
   *
   * @return the level of the plaintext
   */
    size_t GetLevel() const {
        return level;
    }

    /**
   * Method to set the level of a plaintext.
   *
   * @param l the level
   */
    void SetLevel(size_t l) {
        level = l;
    }

    /**
   * Method to get the number of slots of a plaintext.
   *
   * @return the number of slots of the plaintext
   */
    uint32_t GetSlots() const {
        return slots;
    }

    /**
   * Method to set the number of slots of a plaintext.
   *
   * @param l the number of slots
   */
    void SetSlots(uint32_t l) {
        slots = l;
    }

    /**
   * Get log2 of the estimated standard deviation of the approximation error (CKKS only; throws otherwise).
   *
   * @return log2 of the estimated error
   */
    virtual double GetLogError() const {
        OPENFHE_THROW("no estimate of noise available for the current scheme");
    }

    /**
   * Get log2 of the estimated precision of the decoded values (CKKS only; throws otherwise).
   *
   * @return log2 of the estimated precision
   */
    virtual double GetLogPrecision() const {
        OPENFHE_THROW("no estimate of precision available for the current scheme");
    }

    /**
   * Get the decoded string (string encoding only; throws otherwise).
   *
   * @return the string
   */
    virtual const std::string& GetStringValue() const {
        OPENFHE_THROW("not a string");
    }
    /**
   * Get the decoded integer vector (coefficient-packed encoding only; throws otherwise).
   *
   * @return the integer vector
   */
    virtual const std::vector<int64_t>& GetCoefPackedValue() const {
        OPENFHE_THROW("not a packed coefficient vector");
    }
    /**
   * Get the decoded integer vector (packed encoding only; throws otherwise).
   *
   * @return the integer vector
   */
    virtual const std::vector<int64_t>& GetPackedValue() const {
        OPENFHE_THROW("not a packed vector");
    }
    /**
   * Get the decoded complex vector (CKKS packed encoding only; throws otherwise).
   *
   * @return the complex vector
   */
    virtual const std::vector<std::complex<double>>& GetCKKSPackedValue() const {
        OPENFHE_THROW("not a packed vector of complex numbers");
    }
    /**
   * Get the real parts of the decoded complex vector (CKKS packed encoding only; throws otherwise).
   *
   * @return the real vector
   */
    virtual std::vector<double> GetRealPackedValue() const {
        OPENFHE_THROW("not a packed vector of real numbers");
    }
    /**
   * Set the string to encode (string encoding only; throws otherwise).
   */
    virtual void SetStringValue(const std::string&) {
        OPENFHE_THROW("does not support a string");
    }
    /**
   * Set the integer vector to encode (packed and coefficient-packed encodings only; throws otherwise).
   */
    virtual void SetIntVectorValue(const std::vector<int64_t>&) {
        OPENFHE_THROW("does not support an int vector");
    }

    /**
   * operator== for plaintexts.  This method makes sure the plaintexts are of
   * the same type.
   *
   * @param other - the other plaintext to compare to.
   * @return whether the two plaintext are the same.
   */
    bool operator==(const PlaintextImpl& other) const {
        return CompareTo(other);
    }

    /**
   * operator!= for plaintexts.
   *
   * @param other - the other plaintext to compare to.
   * @return whether the two plaintext differ.
   */
    bool operator!=(const PlaintextImpl& other) const {
        return !(*this == other);
    }

    /**
    * @brief operator<< for ostream integration - calls PrintValue()
    * @param out the output stream
    * @param item the plaintext to print
    * @return the output stream
    */
    friend std::ostream& operator<<(std::ostream& out, const PlaintextImpl& item) {
        item.PrintValue(out);
        return out;
    }
    /**
    * @brief operator<< for a shared pointer to a plaintext - prints the plaintext it points to
    * @param out the output stream
    * @param item the plaintext to print (must not be null)
    * @return the output stream
    */
    friend std::ostream& operator<<(std::ostream& out, const Plaintext& item) {
        if (item)
            return out << *item;  // Call the non-pointer version
        OPENFHE_THROW("Cannot de-reference nullptr for printing");
    }

    /**
    * @brief GetFormattedValues() is similar to PrintValue() and requires a precision as an argument
    * @param precision number of decimal digits of precision to print
    * @return string with all values
    */
    virtual std::string GetFormattedValues(int64_t precision) const {
        OPENFHE_THROW("not implemented");
    }
};

/**
 * Compares the plaintexts two shared pointers point to.
 *
 * @param p1 the first plaintext
 * @param p2 the second plaintext
 * @return whether the two plaintexts are the same
 */
inline bool operator==(const Plaintext& p1, const Plaintext& p2) {
    return *p1 == *p2;
}

/**
 * Compares the plaintexts two shared pointers point to.
 *
 * @param p1 the first plaintext
 * @param p2 the second plaintext
 * @return whether the two plaintexts differ
 */
inline bool operator!=(const Plaintext& p1, const Plaintext& p2) {
    return *p1 != *p2;
}

/**
 * GetElement
 * @return the Polynomial that the element was encoded into
 */
template <>
inline const Poly& PlaintextImpl::GetElement<Poly>() const {
    return encodedVector;
}

/**
 * GetElement
 * @return the Polynomial that the element was encoded into
 */
template <>
inline Poly& PlaintextImpl::GetElement<Poly>() {
    return encodedVector;
}

/**
 * GetElement
 * @return the NativePolynomial that the element was encoded into
 */
template <>
inline const NativePoly& PlaintextImpl::GetElement<NativePoly>() const {
    return encodedNativeVector;
}

/**
 * GetElement
 * @return the NativePolynomial that the element was encoded into
 */
template <>
inline NativePoly& PlaintextImpl::GetElement<NativePoly>() {
    return encodedNativeVector;
}

/**
 * GetElement
 * @return the DCRTPolynomial that the element was encoded into
 */
template <>
inline const DCRTPoly& PlaintextImpl::GetElement<DCRTPoly>() const {
    return encodedVectorDCRT;
}

/**
 * GetElement
 * @return the DCRTPolynomial that the element was encoded into
 */
template <>
inline DCRTPoly& PlaintextImpl::GetElement<DCRTPoly>() {
    return encodedVectorDCRT;
}

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_ENCODING_PLAINTEXT_H_
