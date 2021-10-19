// @file ckkspackedencoding.h
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, Duality Technologies Inc.
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

#ifndef LBCRYPTO_UTILS_CKKSPACKEDEXTENCODING_H
#define LBCRYPTO_UTILS_CKKSPACKEDEXTENCODING_H

#include <functional>
#include <initializer_list>
#include <memory>
#include <numeric>
#include <utility>
#include <vector>

#include "encoding/encodingparams.h"
#include "encoding/plaintext.h"
#include "utils/inttypes.h"

namespace lbcrypto {

enum RescalingTechnique { APPROXRESCALE, EXACTRESCALE, APPROXAUTO };

// STL pair used as a key for some tables in CKKSPackedEncoding
using ModulusM = std::pair<NativeInteger, uint64_t>;

/**
 * @class CKKSPackedEncoding
 * @brief Type used for representing IntArray types.
 * Provides conversion functions to encode and decode plaintext data as type
 * vector<uint64_t>. This class uses bit packing techniques to enable efficient
 * computing on vectors of integers. It is NOT supported for DCRTPoly
 */

class CKKSPackedEncoding : public PlaintextImpl {
 public:
  // these two constructors are used inside of Decrypt
  CKKSPackedEncoding(shared_ptr<Poly::Params> vp, EncodingParams ep)
      : PlaintextImpl(vp, ep) {
    depth = 1;
    m_logError = 0.0;
  }

  CKKSPackedEncoding(shared_ptr<NativePoly::Params> vp, EncodingParams ep)
      : PlaintextImpl(vp, ep) {
    depth = 1;
    m_logError = 0.0;
  }

  CKKSPackedEncoding(shared_ptr<DCRTPoly::Params> vp, EncodingParams ep)
      : PlaintextImpl(vp, ep) {
    depth = 1;
    m_logError = 0.0;
  }

  CKKSPackedEncoding(shared_ptr<Poly::Params> vp, EncodingParams ep,
                     const std::vector<std::complex<double>> &coeffs,
                     size_t depth, uint32_t level, double scFact)
      : PlaintextImpl(vp, ep), value(coeffs) {
    this->depth = depth;
    this->level = level;
    this->scalingFactor = scFact;
    m_logError = 0.0;
  }

  CKKSPackedEncoding(shared_ptr<NativePoly::Params> vp, EncodingParams ep,
                     const std::vector<std::complex<double>> &coeffs,
                     size_t depth, uint32_t level, double scFact)
      : PlaintextImpl(vp, ep), value(coeffs) {
    this->depth = depth;
    this->level = level;
    this->scalingFactor = scFact;
    m_logError = 0.0;
  }

  /*
   * @param depth depth of plaintext to create.
   * @param level level of plaintext to create.
   * @param scFact scaling factor of a plaintext of this level at depth 1.
   *
   */
  CKKSPackedEncoding(shared_ptr<DCRTPoly::Params> vp, EncodingParams ep,
                     const std::vector<std::complex<double>> &coeffs,
                     size_t depth, uint32_t level, double scFact)
      : PlaintextImpl(vp, ep), value(coeffs) {
    this->depth = depth;
    this->level = level;
    this->scalingFactor = scFact;
    m_logError = 0.0;
  }

  /**
   * @brief Constructs a container with a copy of each of the elements in rhs,
   * in the same order.
   * @param rhs - The input object to copy.
   */
  explicit CKKSPackedEncoding(const std::vector<std::complex<double>> &rhs)
      : PlaintextImpl(shared_ptr<Poly::Params>(0), nullptr), value(rhs) {
    depth = 1;
    m_logError = 0.0;
  }

  /**
   * @brief Default empty constructor with empty uninitialized data elements.
   */
  CKKSPackedEncoding()
      : PlaintextImpl(shared_ptr<Poly::Params>(0), nullptr), value() {
    depth = 1;
    m_logError = 0.0;
  }

  CKKSPackedEncoding(const CKKSPackedEncoding &rhs)
      : PlaintextImpl(rhs), value(rhs.value), m_logError(rhs.m_logError) {}

  CKKSPackedEncoding(const CKKSPackedEncoding &&rhs)
      : PlaintextImpl(rhs),
        value(std::move(rhs.value)),
        m_logError(rhs.m_logError) {}

  bool Encode();

  bool Decode() {
    PALISADE_THROW(
        not_available_error,
        "CKKSPackedEncoding::Decode() is not implemented. "
        "Use CKKSPackedEncoding::Decode(depth,scalingFactor,rstech) instead.");
  }

  bool Decode(size_t depth, double scalingFactor, RescalingTechnique rsTech);

  const std::vector<std::complex<double>> &GetCKKSPackedValue() const {
    return value;
  }

  const std::vector<double> GetRealPackedValue() const {
    std::vector<double> realValue(value.size());
    std::transform(value.begin(), value.end(), realValue.begin(),
                   [](std::complex<double> da) { return da.real(); });

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
  static std::vector<DCRTPoly::Integer> CRTMult(
      const std::vector<DCRTPoly::Integer> &a,
      const std::vector<DCRTPoly::Integer> &b,
      const std::vector<DCRTPoly::Integer> &mods);

  /**
   * GetEncodingType
   * @return this is a Packed encoding
   */
  PlaintextEncodings GetEncodingType() const { return CKKSPacked; }

  /**
   * Get method to return the length of plaintext
   *
   * @return the length of the plaintext in terms of the number of bits.
   */
  size_t GetLength() const { return value.size(); }

  /**
   * Get method to return log2 of estimated standard deviation of approximation
   * error
   */
  double GetLogError() const { return m_logError; }

  /**
   * Get method to return log2 of estimated precision
   */
  double GetLogPrecision() const {
    return encodingParams->GetPlaintextModulus() - m_logError;
  }

  /**
   * SetLength of the plaintext to the given size
   * @param siz
   */
  void SetLength(size_t siz) { value.resize(siz); }

  /**
   * Method to compare two plaintext to test for equivalence.  This method does
   * not test that the plaintext are of the same type.
   *
   * @param other - the other plaintext to compare to.
   * @return whether the two plaintext are equivalent.
   */
  bool CompareTo(const PlaintextImpl &other) const {
    const auto &rv = static_cast<const CKKSPackedEncoding &>(other);
    return this->value == rv.value;
  }

  /**
   * @brief Destructor method.
   */
  static void Destroy();

  void PrintValue(std::ostream &out) const {
    // for sanity's sake, trailing zeros get elided into "..."
    // out.precision(15);
    out << "(";
    size_t i = value.size();
    while (--i > 0)
      if (value[i] != std::complex<double>(0, 0)) break;

    for (size_t j = 0; j <= i; j++) {
      out << value[j].real() << ", ";
    }

    out << " ... ); ";
    out << "Estimated precision: "
        << encodingParams->GetPlaintextModulus() - m_logError << " bits"
        << std::endl;
  }

 private:
  std::vector<std::complex<double>> value;

  double m_logError;

 protected:
  /**
   * Set modulus and recalculates the vector values to fit the modulus
   *
   * @param &vec input vector
   * @param &bigValue big bound of the vector values.
   * @param &modulus modulus to be set for vector.
   */
  void FitToNativeVector(const std::vector<int64_t> &vec, int64_t bigBound,
                         NativeVector *nativeVec) const;

#if NATIVEINT == 128
  /**
   * Set modulus and recalculates the vector values to fit the modulus
   *
   * @param &vec input vector
   * @param &bigValue big bound of the vector values.
   * @param &modulus modulus to be set for vector.
   */
  void FitToNativeVector(const std::vector<__int128> &vec, __int128 bigBound,
                         NativeVector *nativeVec) const;

  constexpr __int128 Max128BitValue() const {
    // 2^127-2^73-1 - max value that could be rounded to int128_t
    return ((unsigned __int128)1 << 127) - ((unsigned __int128)1 << 73) -
           (unsigned __int128)1;
  }

  inline bool is128BitOverflow(double d) const {
    const double EPSILON = 0.000001;

    return EPSILON < (std::abs(d) - Max128BitValue());
  }
#else  // NATIVEINT == 64
  constexpr int64_t Max64BitValue() const {
    // 2^63-2^9-1 - max value that could be rounded to int64_t
    return 9223372036854775295;
  }

  inline bool is64BitOverflow(double d) const {
    const double EPSILON = 0.000001;

    return EPSILON < (std::abs(d) - Max64BitValue());
  }
#endif
};

}  // namespace lbcrypto

#endif
