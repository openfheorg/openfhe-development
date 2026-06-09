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

#ifndef LBCRYPTO_UTILS_PLAINTEXT_H
#define LBCRYPTO_UTILS_PLAINTEXT_H

#include "constants.h"
#include "encoding/encodingparams.h"
#include "encoding/plaintext-fwd.h"
#include "scheme/scheme-id.h"

#include <algorithm>
#include <initializer_list>
#include <memory>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

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
    enum PtxtPolyType { IsPoly, IsDCRTPoly, IsNativePoly };

    bool m_isEncoded{false};
    PtxtPolyType m_typeFlag;
    EncodingParams m_encodingParams;

    Poly m_encodedVector;
    NativePoly m_encodedNativeVector;
    DCRTPoly m_encodedVectorDCRT;

    PlaintextEncodings m_ptxtEncoding{INVALID_ENCODING};
    SCHEME m_schemeID{SCHEME::INVALID_SCHEME};
    CKKSDataType m_ckksDataType{REAL};
    double m_scalingFactor{1.0};
    NativeInteger m_scalingFactorInt{1};
    size_t m_level{0};
    size_t m_noiseScaleDeg{1};
    uint32_t m_slots{0};

    /**
    * @brief PrintValue() is called by operator<<
    * @param out
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
    PlaintextImpl(const std::shared_ptr<Poly::Params>& vp, EncodingParams ep, PlaintextEncodings encoding,
                  SCHEME schemeTag = SCHEME::INVALID_SCHEME)
        : m_typeFlag(IsPoly),
          m_encodingParams(std::move(ep)),
          m_encodedVector(vp, Format::COEFFICIENT),
          m_ptxtEncoding(encoding),
          m_schemeID(schemeTag) {}

    PlaintextImpl(const std::shared_ptr<NativePoly::Params>& vp, EncodingParams ep, PlaintextEncodings encoding,
                  SCHEME schemeTag = SCHEME::INVALID_SCHEME)
        : m_typeFlag(IsNativePoly),
          m_encodingParams(std::move(ep)),
          m_encodedNativeVector(vp, Format::COEFFICIENT),
          m_ptxtEncoding(encoding),
          m_schemeID(schemeTag) {}

    // TODO: eliminate use of m_encodedVector in coefpackedencoding to remove m_encodedVector init here
    PlaintextImpl(const std::shared_ptr<DCRTPoly::Params>& vp, EncodingParams ep, PlaintextEncodings encoding,
                  SCHEME schemeTag = SCHEME::INVALID_SCHEME)
        : m_typeFlag(IsDCRTPoly),
          m_encodingParams(std::move(ep)),
          m_encodedVector(vp, Format::COEFFICIENT),
          m_encodedVectorDCRT(vp, Format::COEFFICIENT),
          m_ptxtEncoding(encoding),
          m_schemeID(schemeTag) {}

    PlaintextImpl(const PlaintextImpl& rhs) = default;

    PlaintextImpl(PlaintextImpl&& rhs) noexcept = default;

    virtual ~PlaintextImpl() = default;

    /**
   * GetEncodingType
   * @return Encoding type used by this plaintext
   */
    PlaintextEncodings GetEncodingType() const {
        return m_ptxtEncoding;
    }

    /**
   * Get the scaling factor of the plaintext for CKKS-based plaintexts.
   */
    double GetScalingFactor() const {
        return m_scalingFactor;
    }

    /**
   * Set the scaling factor of the plaintext for CKKS-based plaintexts.
   */
    void SetScalingFactor(double sf) {
        m_scalingFactor = sf;
    }

    /**
   * Get the scaling factor of the plaintext for BGV-based plaintexts.
   */
    NativeInteger GetScalingFactorInt() const {
        return m_scalingFactorInt;
    }

    /**
   * Set the scaling factor of the plaintext for BGV-based plaintexts.
   */
    void SetScalingFactorInt(NativeInteger sf) {
        m_scalingFactorInt = sf;
    }

    /**
   * Get the encryption technique of the plaintext for BFV-based plaintexts.
   */
    SCHEME GetSchemeID() const {
        return m_schemeID;
    }

    /**
   * IsEncoded
   * @return true when encoding is done
   */
    bool IsEncoded() const {
        return m_isEncoded;
    }

    /**
   * GetEncodingParams
   * @return Encoding params used with this plaintext
   */
    EncodingParams GetEncodingParams() const {
        return m_encodingParams;
    }

    /**
   * GetCKKSDataType
   * @return CKKS data type with this plaintext
   */
    CKKSDataType GetCKKSDataType() const {
        return m_ckksDataType;
    }

    /**
   * SetCKKSDataType
   * @return Set CKKS data type to be used with this plaintext
   */
    void SetCKKSDataType(CKKSDataType cdt) {
        m_ckksDataType = cdt;
    }

    /**
   * Encode the plaintext into a polynomial
   * @return true on success
   */
    virtual bool Encode() = 0;

    /**
   * @brief Decode the polynomial into the plaintext
   * @return
   */
    virtual bool Decode() = 0;
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
   * @param fmt
   */
    void SetFormat(Format fmt) {
        if (m_typeFlag == IsPoly)
            m_encodedVector.SetFormat(fmt);
        else if (m_typeFlag == IsNativePoly)
            m_encodedNativeVector.SetFormat(fmt);
        else
            m_encodedVectorDCRT.SetFormat(fmt);
    }

    /**
   * GetElement
   * @return the Polynomial that the element was encoded into
   */
    template <typename Element>
    Element& GetElement() {
        OPENFHE_THROW("Not implemented");
    }

    template <typename Element>
    const Element& GetElement() const {
        OPENFHE_THROW("Not implemented");
    }

    /**
   * GetElementRingDimension
   * @return ring dimension on the underlying element
   */
    uint32_t GetElementRingDimension() const {
        return m_typeFlag == IsPoly ? m_encodedVector.GetRingDimension() :
                                      (m_typeFlag == IsNativePoly ? m_encodedNativeVector.GetRingDimension() :
                                                                    m_encodedVectorDCRT.GetRingDimension());
    }

    /**
   * GetElementModulus
   * @return modulus on the underlying elemenbt
   */
    BigInteger GetElementModulus() const {
        return m_typeFlag == IsPoly ? m_encodedVector.GetModulus() :
                                      (m_typeFlag == IsNativePoly ? BigInteger(m_encodedNativeVector.GetModulus()) :
                                                                    m_encodedVectorDCRT.GetModulus());
    }

    /**
   * Get method to return the length of plaintext
   *
   * @return the length of the plaintext in terms of the number of bits.
   */
    virtual size_t GetLength() const = 0;

    /**
   * resize the plaintext; only works for plaintexts that support a resizable
   * vector (coefpacked)
   * @param newSize
   */
    virtual void SetLength(size_t newSize) {
        OPENFHE_THROW("resize not supported");
    }

    /*
   * Method to get the degree of the scaling factor of a plaintext.
   *
   * @return the degree of the scaling factor of the plaintext
   */
    size_t GetNoiseScaleDeg() const {
        return m_noiseScaleDeg;
    }

    /*
   * Method to set the degree of the scaling factor of a plaintext.
   */
    void SetNoiseScaleDeg(size_t d) {
        m_noiseScaleDeg = d;
    }

    /*
   * Method to get the m_level of a plaintext.
   *
   * @return the m_level of the plaintext
   */
    size_t GetLevel() const {
        return m_level;
    }

    /*
   * Method to set the m_level of a plaintext.
   */
    void SetLevel(size_t l) {
        m_level = l;
    }

    /*
   * Method to get the m_level of a plaintext.
   *
   * @return the m_level of the plaintext
   */
    uint32_t GetSlots() const {
        return m_slots;
    }

    /*
   * Method to set the m_level of a plaintext.
   */
    void SetSlots(uint32_t l) {
        m_slots = l;
    }

    virtual double GetLogError() const {
        OPENFHE_THROW("no estimate of noise available for the current scheme");
    }

    virtual double GetLogPrecision() const {
        OPENFHE_THROW("no estimate of precision available for the current scheme");
    }

    virtual const std::string& GetStringValue() const {
        OPENFHE_THROW("not a string");
    }
    virtual const std::vector<int64_t>& GetCoefPackedValue() const {
        OPENFHE_THROW("not a packed coefficient vector");
    }
    virtual const std::vector<int64_t>& GetPackedValue() const {
        OPENFHE_THROW("not a packed vector");
    }
    virtual const std::vector<std::complex<double>>& GetCKKSPackedValue() const {
        OPENFHE_THROW("not a packed vector of complex numbers");
    }
    virtual std::vector<double> GetRealPackedValue() const {
        OPENFHE_THROW("not a packed vector of real numbers");
    }
    virtual void SetStringValue(const std::string&) {
        OPENFHE_THROW("does not support a string");
    }
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

    bool operator!=(const PlaintextImpl& other) const {
        return !(*this == other);
    }

    /**
    * @brief operator<< for ostream integration - calls PrintValue()
    * @param out
    * @param item
    * @return
    */
    friend std::ostream& operator<<(std::ostream& out, const PlaintextImpl& item) {
        item.PrintValue(out);
        return out;
    }
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

inline bool operator==(const Plaintext& p1, const Plaintext& p2) {
    return *p1 == *p2;
}

inline bool operator!=(const Plaintext& p1, const Plaintext& p2) {
    return *p1 != *p2;
}

/**
 * GetElement
 * @return the Polynomial that the element was encoded into
 */
template <>
inline const Poly& PlaintextImpl::GetElement<Poly>() const {
    return m_encodedVector;
}

template <>
inline Poly& PlaintextImpl::GetElement<Poly>() {
    return m_encodedVector;
}

/**
 * GetElement
 * @return the NativePolynomial that the element was encoded into
 */
template <>
inline const NativePoly& PlaintextImpl::GetElement<NativePoly>() const {
    return m_encodedNativeVector;
}

template <>
inline NativePoly& PlaintextImpl::GetElement<NativePoly>() {
    return m_encodedNativeVector;
}

/**
 * GetElement
 * @return the DCRTPolynomial that the element was encoded into
 */
template <>
inline const DCRTPoly& PlaintextImpl::GetElement<DCRTPoly>() const {
    return m_encodedVectorDCRT;
}

template <>
inline DCRTPoly& PlaintextImpl::GetElement<DCRTPoly>() {
    return m_encodedVectorDCRT;
}

}  // namespace lbcrypto

#endif
