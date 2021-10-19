// @file plaintext.h Represents and defines plaintext objects in Palisade.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef LBCRYPTO_UTILS_PLAINTEXT_H
#define LBCRYPTO_UTILS_PLAINTEXT_H

#include <initializer_list>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "encoding/encodingparams.h"
#include "lattice/backend.h"
#include "math/backend.h"
#include "utils/inttypes.h"

using std::shared_ptr;

namespace lbcrypto {

enum PlaintextEncodings {
  Unknown = 0,
  CoefPacked,
  Packed,
  String,
  CKKSPacked,
};

inline std::ostream& operator<<(std::ostream& out, const PlaintextEncodings p) {
  switch (p) {
    case Unknown:
      out << "Unknown";
      break;
    case CoefPacked:
      out << "CoefPacked";
      break;
    case Packed:
      out << "Packed";
      break;
    case String:
      out << "String";
      break;
    case CKKSPacked:
      out << "CKKSPacked";
      break;
  }
  return out;
}

class PlaintextImpl;
typedef shared_ptr<PlaintextImpl> Plaintext;
typedef shared_ptr<const PlaintextImpl> ConstPlaintext;

/**
 * @class PlaintextImpl
 * @brief This class represents plaintext in the Palisade library.
 *
 * PlaintextImpl is primarily intended to be
 * used as a container and in conjunction with specific encodings which inherit
 * from this class which depend on the application the plaintext is used with.
 * It provides virtual methods for encoding and decoding of data.
 */

enum PtxtPolyType { IsPoly, IsDCRTPoly, IsNativePoly };

class PlaintextImpl {
 protected:
  bool isEncoded;
  PtxtPolyType typeFlag;
  EncodingParams encodingParams;

  mutable Poly encodedVector;
  mutable NativePoly encodedNativeVector;
  mutable DCRTPoly encodedVectorDCRT;

  static const int intCTOR = 0x01;
  static const int vecintCTOR = 0x02;
  static const int fracCTOR = 0x04;
  static const int vecuintCTOR = 0x08;

  double scalingFactor;
  size_t level;
  size_t depth;

 public:
  PlaintextImpl(shared_ptr<Poly::Params> vp, EncodingParams ep,
                bool isEncoded = false)
      : isEncoded(isEncoded),
        typeFlag(IsPoly),
        encodingParams(ep),
        encodedVector(vp, Format::COEFFICIENT),
        scalingFactor(1),
        level(0),
        depth(1) {}

  PlaintextImpl(shared_ptr<NativePoly::Params> vp, EncodingParams ep,
                bool isEncoded = false)
      : isEncoded(isEncoded),
        typeFlag(IsNativePoly),
        encodingParams(ep),
        encodedNativeVector(vp, Format::COEFFICIENT),
        scalingFactor(1),
        level(0),
        depth(1) {}

  PlaintextImpl(shared_ptr<DCRTPoly::Params> vp, EncodingParams ep,
                bool isEncoded = false)
      : isEncoded(isEncoded),
        typeFlag(IsDCRTPoly),
        encodingParams(ep),
        encodedVector(vp, Format::COEFFICIENT),
        encodedVectorDCRT(vp, Format::COEFFICIENT),
        scalingFactor(1),
        level(0),
        depth(1) {}

  PlaintextImpl(const PlaintextImpl& rhs)
      : isEncoded(rhs.isEncoded),
        typeFlag(rhs.typeFlag),
        encodingParams(rhs.encodingParams),
        encodedVector(rhs.encodedVector),
        encodedVectorDCRT(rhs.encodedVectorDCRT),
        scalingFactor(rhs.scalingFactor),
        level(rhs.level),
        depth(rhs.depth) {}

  PlaintextImpl(const PlaintextImpl&& rhs)
      : isEncoded(rhs.isEncoded),
        typeFlag(rhs.typeFlag),
        encodingParams(std::move(rhs.encodingParams)),
        encodedVector(std::move(rhs.encodedVector)),
        encodedVectorDCRT(std::move(rhs.encodedVectorDCRT)),
        scalingFactor(rhs.scalingFactor),
        level(rhs.level),
        depth(rhs.depth) {}

  virtual ~PlaintextImpl() {}

  /**
   * GetEncodingType
   * @return Encoding type used by this plaintext
   */
  virtual PlaintextEncodings GetEncodingType() const = 0;

  /**
   * Get the scaling factor of the plaintext.
   */
  double GetScalingFactor() const { return scalingFactor; }

  /**
   * Set the scaling factor of the plaintext.
   */
  void SetScalingFactor(double sf) { scalingFactor = sf; }

  /**
   * IsEncoded
   * @return true when encoding is done
   */
  bool IsEncoded() const { return isEncoded; }

  /**
   * GetEncodingParams
   * @return Encoding params used with this plaintext
   */
  const EncodingParams GetEncodingParams() const { return encodingParams; }

  /**
   * Encode the plaintext into a polynomial
   * @return true on success
   */
  virtual bool Encode() = 0;

  /**
   * Decode the polynomial into the plaintext
   * @return
   */
  virtual bool Decode() = 0;

  /**
   * Calculate and return lower bound that can be encoded with the plaintext
   * modulus the number to encode MUST be greater than this value
   * @return floor(-p/2)
   */
  int64_t LowBound() const {
    uint64_t half = GetEncodingParams()->GetPlaintextModulus() >> 1;
    bool odd = (GetEncodingParams()->GetPlaintextModulus() & 0x1) == 1;
    int64_t bound = -1 * half;
    if (odd) bound--;
    return bound;
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
  void SetFormat(Format fmt) const {
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
  Element& GetElement();

  template <typename Element>
  const Element& GetElement() const;

  /**
   * GetElementRingDimension
   * @return ring dimension on the underlying element
   */
  usint GetElementRingDimension() const {
    return typeFlag == IsPoly ? encodedVector.GetRingDimension()
                              : (typeFlag == IsNativePoly
                                     ? encodedNativeVector.GetRingDimension()
                                     : encodedVectorDCRT.GetRingDimension());
  }

  /**
   * GetElementModulus
   * @return modulus on the underlying elemenbt
   */
  const BigInteger GetElementModulus() const {
    return typeFlag == IsPoly
               ? encodedVector.GetModulus()
               : (typeFlag == IsNativePoly
                      ? BigInteger(encodedNativeVector.GetModulus())
                      : encodedVectorDCRT.GetModulus());
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
    PALISADE_THROW(not_implemented_error, "resize not supported");
  }

  /*
   * Method to get the depth of a plaintext.
   *
   * @return the depth of the plaintext
   */
  size_t GetDepth() const { return depth; }

  /*
   * Method to set the depth of a plaintext.
   */
  void SetDepth(size_t d) { depth = d; }

  /*
   * Method to get the level of a plaintext.
   *
   * @return the level of the plaintext
   */
  size_t GetLevel() const { return level; }

  /*
   * Method to set the level of a plaintext.
   */
  void SetLevel(size_t l) { level = l; }

  virtual double GetLogError() const {
    PALISADE_THROW(not_available_error,
                   "no estimate of noise available for the current scheme");
  }

  virtual double GetLogPrecision() const {
    PALISADE_THROW(not_available_error,
                   "no estimate of precision available for the current scheme");
  }

  virtual const std::string& GetStringValue() const {
    PALISADE_THROW(type_error, "not a string");
  }
  virtual const vector<int64_t>& GetCoefPackedValue() const {
    PALISADE_THROW(type_error, "not a packed coefficient vector");
  }
  virtual const vector<int64_t>& GetPackedValue() const {
    PALISADE_THROW(type_error, "not a packed coefficient vector");
  }
  virtual const std::vector<std::complex<double>>& GetCKKSPackedValue() const {
    PALISADE_THROW(type_error, "not a packed vector of complex numbers");
  }
  virtual const std::vector<double> GetRealPackedValue() const {
    PALISADE_THROW(type_error, "not a packed vector of real numbers");
  }
  virtual void SetStringValue(const std::string&) {
    PALISADE_THROW(type_error, "does not support a string");
  }
  virtual void SetIntVectorValue(const vector<int64_t>&) {
    PALISADE_THROW(type_error, "does not support an int vector");
  }

  /**
   * Method to compare two plaintext to test for equivalence.
   * This method is called by operator==
   *
   * @param other - the other plaintext to compare to.
   * @return whether the two plaintext are equivalent.
   */
  virtual bool CompareTo(const PlaintextImpl& other) const = 0;

  /**
   * operator== for plaintexts.  This method makes sure the plaintexts are of
   * the same type.
   *
   * @param other - the other plaintext to compare to.
   * @return whether the two plaintext are the same.
   */
  bool operator==(const PlaintextImpl& other) const { return CompareTo(other); }

  bool operator!=(const PlaintextImpl& other) const {
    return !(*this == other);
  }

  /**
   * operator<< for ostream integration - calls PrintValue
   * @param out
   * @param item
   * @return
   */
  friend std::ostream& operator<<(std::ostream& out, const PlaintextImpl& item);

  /**
   * PrintValue is called by operator<<
   * @param out
   */
  virtual void PrintValue(std::ostream& out) const = 0;
};

inline std::ostream& operator<<(std::ostream& out, const PlaintextImpl& item) {
  item.PrintValue(out);
  return out;
}

inline std::ostream& operator<<(std::ostream& out, const Plaintext item) {
  item->PrintValue(out);
  return out;
}

inline bool operator==(const Plaintext p1, const Plaintext p2) {
  return *p1 == *p2;
}

inline bool operator!=(const Plaintext p1, const Plaintext p2) {
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

template <>
inline DCRTPoly& PlaintextImpl::GetElement<DCRTPoly>() {
  return encodedVectorDCRT;
}

}  // namespace lbcrypto

#endif
