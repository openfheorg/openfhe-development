// @file ringcore.h - Main ring classes for Boolean circuit FHE.
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

#ifndef BINFHE_RINGCORE_H
#define BINFHE_RINGCORE_H

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "lattice/backend.h"
#include "lwecore.h"
#include "math/backend.h"
#include "math/discretegaussiangenerator.h"
#include "math/nbtheory.h"
#include "math/transfrm.h"
#include "utils/serializable.h"

namespace lbcrypto {

// enum for all supported binary gates
enum BINGATE { OR, AND, NOR, NAND, XOR_FAST, XNOR_FAST, XOR, XNOR };

// Two variants of FHEW are supported based on the bootstrapping technique used:
// AP and GINX Please see "Bootstrapping in FHEW-like Cryptosystems" for details
// on both bootstrapping techniques
enum BINFHEMETHOD { AP, GINX };

/**
 * @brief Class that stores all parameters for the RingGSW scheme used in
 * bootstrapping
 */
class RingGSWCryptoParams : public Serializable {
 public:
  RingGSWCryptoParams()
      : m_baseG(0), m_digitsG(0), m_digitsG2(0), m_baseR(0), m_method(GINX) {}

  /**
   * Main constructor for RingGSWCryptoParams
   *
   * @param lweparams a shared poiter to an instance of LWECryptoParams
   * @param baseG the gadget base used in the bootstrapping
   * @param baseR the base for the refreshing key
   * @param method bootstrapping method (AP or GINX)
   */
  explicit RingGSWCryptoParams(const std::shared_ptr<LWECryptoParams> lweparams,
                               uint32_t baseG, uint32_t baseR,
                               BINFHEMETHOD method)
      : m_LWEParams(lweparams),
        m_baseG(baseG),
        m_baseR(baseR),
        m_method(method) {
    if (!IsPowerOfTwo(baseG)) {
      PALISADE_THROW(config_error, "Gadget base should be a power of two.");
    }

    PreCompute();
  }

  /**
   * Performs precomputations based on the supplied parameters
   */
  void PreCompute() {
    const shared_ptr<LWECryptoParams> lweparams = m_LWEParams;

    NativeInteger Q = lweparams->GetQ();
    NativeInteger q = lweparams->Getq();
    uint32_t N = lweparams->GetN();
    NativeInteger rootOfUnity = RootOfUnity<NativeInteger>(2 * N, Q);

    // Precomputes the table with twiddle factors to support fast NTT
    ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootOfUnity, 2 * N,
                                                           Q);

    // Precomputes a polynomial for MSB extraction
    m_polyParams = std::make_shared<ILNativeParams>(2 * N, Q, rootOfUnity);

    m_digitsG = (uint32_t)std::ceil(log(Q.ConvertToDouble()) /
                                    log(static_cast<double>(m_baseG)));
    m_digitsG2 = m_digitsG * 2;

    // Computes baseR^i (only for AP bootstrapping)
    if (m_method == AP) {
      uint32_t digitCountR =
          (uint32_t)std::ceil(log(static_cast<double>(q.ConvertToInt())) /
                              log(static_cast<double>(m_baseR)));
      // Populate digits
      NativeInteger value = 1;
      for (uint32_t i = 0; i < digitCountR; i++) {
        m_digitsR.push_back(value);
        value *= m_baseR;
      }
    }

    // Computes baseG^i
    NativeInteger vTemp = NativeInteger(1);
    for (uint32_t i = 0; i < m_digitsG; i++) {
      m_Gpower.push_back(vTemp);
      vTemp = vTemp.ModMul(NativeInteger(m_baseG), Q);
    }

    // Sets the gate constants for supported binary operations
    m_gateConst = {
        NativeInteger(5) * (q >> 3),  // OR
        NativeInteger(7) * (q >> 3),  // AND
        NativeInteger(1) * (q >> 3),  // NOR
        NativeInteger(3) * (q >> 3),  // NAND
        NativeInteger(5) * (q >> 3),  // XOR_FAST
        NativeInteger(1) * (q >> 3)   // XNOR_FAST
    };

    // Computes polynomials X^m - 1 that are needed in the accumulator for the
    // GINX bootstrapping
    if (m_method == GINX) {
      // loop for positive values of m
      for (uint32_t i = 0; i < N; i++) {
        NativePoly aPoly = NativePoly(m_polyParams, Format::COEFFICIENT, true);
        aPoly[i].ModAddEq(NativeInteger(1), Q);  // X^m
        aPoly[0].ModSubEq(NativeInteger(1), Q);  // -1
        aPoly.SetFormat(Format::EVALUATION);
        m_monomials.push_back(aPoly);
      }

      // loop for negative values of m
      for (uint32_t i = 0; i < N; i++) {
        NativePoly aPoly = NativePoly(m_polyParams, Format::COEFFICIENT, true);
        aPoly[i].ModSubEq(NativeInteger(1), Q);  // -X^m
        aPoly[0].ModSubEq(NativeInteger(1), Q);  // -1
        aPoly.SetFormat(Format::EVALUATION);
        m_monomials.push_back(aPoly);
      }
    }
#if defined(BINFHE_DEBUG)
    std::cerr << "base_g = " << m_baseG << std::endl;
    std::cerr << "m_digitsG = " << m_digitsG << std::endl;
    std::cerr << "m_digitsG2 = " << m_digitsG2 << std::endl;
    std::cerr << "m_baseR = " << m_baseR << std::endl;
    std::cerr << "m_digitsR = " << m_digitsR << std::endl;
    std::cerr << "m_Gpower = " << m_Gpower << std::endl;
    std::cerr << "n = " << m_LWEParams->Getn() << std::endl;
    std::cerr << "N = " << m_LWEParams->GetN() << std::endl;
    std::cerr << "q = " << m_LWEParams->Getq() << std::endl;
    std::cerr << "Q = " << m_LWEParams->GetQ() << std::endl;
    std::cerr << "baseKS = " << m_LWEParams->GetBaseKS() << std::endl;
    std::cerr << "digitsKS = " << m_LWEParams->GetDigitsKS() << std::endl;
#endif
  }

  const std::shared_ptr<LWECryptoParams> GetLWEParams() const {
    return m_LWEParams;
  }

  uint32_t GetBaseG() const { return m_baseG; }

  uint32_t GetDigitsG() const { return m_digitsG; }

  uint32_t GetDigitsG2() const { return m_digitsG2; }

  uint32_t GetBaseR() const { return m_baseR; }

  const std::vector<NativeInteger>& GetDigitsR() const { return m_digitsR; }

  const shared_ptr<ILNativeParams> GetPolyParams() const {
    return m_polyParams;
  }

  const std::vector<NativeInteger>& GetGPower() const { return m_Gpower; }

  const std::vector<NativeInteger>& GetGateConst() const { return m_gateConst; }

  const NativePoly& GetMonomial(uint32_t i) const { return m_monomials[i]; }

  BINFHEMETHOD GetMethod() const { return m_method; }

  bool operator==(const RingGSWCryptoParams& other) const {
    return *m_LWEParams == *other.m_LWEParams && m_baseR == other.m_baseR &&
           m_baseG == other.m_baseG && m_method == other.m_method;
  }

  bool operator!=(const RingGSWCryptoParams& other) const {
    return !(*this == other);
  }

  template <class Archive>
  void save(Archive& ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("params", m_LWEParams));
    ar(::cereal::make_nvp("bR", m_baseR));
    ar(::cereal::make_nvp("bG", m_baseG));
    ar(::cereal::make_nvp("method", m_method));
  }

  template <class Archive>
  void load(Archive& ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::make_nvp("params", m_LWEParams));
    ar(::cereal::make_nvp("bR", m_baseR));
    ar(::cereal::make_nvp("bG", m_baseG));
    ar(::cereal::make_nvp("method", m_method));

    this->PreCompute();
  }

  std::string SerializedObjectName() const { return "RingGSWCryptoParams"; }
  static uint32_t SerializedVersion() { return 1; }

 private:
  // shared pointer to an instance of LWECryptoParams
  std::shared_ptr<LWECryptoParams> m_LWEParams;

  // gadget base used in bootstrapping
  uint32_t m_baseG;

  // number of digits in decomposing integers mod Q
  uint32_t m_digitsG;

  // twice the number of digits in decomposing integers mod Q
  uint32_t m_digitsG2;

  // base used for the refreshing key (used only for AP bootstrapping)
  uint32_t m_baseR;

  // powers of m_baseR (used only for AP bootstrapping)
  std::vector<NativeInteger> m_digitsR;

  // A vector of powers of baseG
  std::vector<NativeInteger> m_Gpower;

  // Parameters for polynomials in RingGSW/RingLWE
  shared_ptr<ILNativeParams> m_polyParams;

  // Constants used in evaluating binary gates
  std::vector<NativeInteger> m_gateConst;

  // Precomputed polynomials in Format::EVALUATION representation for X^m - 1
  // (used only for GINX bootstrapping)
  std::vector<NativePoly> m_monomials;

  // Bootstrapping method (AP or GINX)
  BINFHEMETHOD m_method;
};

/**
 * @brief Class that stores a RingGSW ciphertext; a two-dimensional vector of
 * ring elements
 */
class RingGSWCiphertext : public Serializable {
 public:
  RingGSWCiphertext() {}

  RingGSWCiphertext(uint32_t rowSize, uint32_t colSize) {
    m_elements.resize(rowSize);
    for (uint32_t i = 0; i < rowSize; i++) m_elements[i].resize(colSize);
  }

  explicit RingGSWCiphertext(
      const std::vector<std::vector<NativePoly>>& elements)
      : m_elements(elements) {}

  explicit RingGSWCiphertext(const RingGSWCiphertext& rhs) {
    this->m_elements = rhs.m_elements;
  }

  explicit RingGSWCiphertext(const RingGSWCiphertext&& rhs) {
    this->m_elements = std::move(rhs.m_elements);
  }

  const RingGSWCiphertext& operator=(const RingGSWCiphertext& rhs) {
    this->m_elements = rhs.m_elements;
    return *this;
  }

  const RingGSWCiphertext& operator=(const RingGSWCiphertext&& rhs) {
    this->m_elements = rhs.m_elements;
    return *this;
  }

  const std::vector<std::vector<NativePoly>>& GetElements() const {
    return m_elements;
  }

  void SetElements(const std::vector<std::vector<NativePoly>>& elements) {
    m_elements = elements;
  }

  /**
   * Switches between COEFFICIENT and Format::EVALUATION polynomial
   * representations using NTT
   */
  void SetFormat(const Format format) {
    for (uint32_t i = 0; i < m_elements.size(); i++)
      // column size is assume to be the same
      for (uint32_t j = 0; j < m_elements[0].size(); j++)
        m_elements[i][j].SetFormat(format);
  }

  std::vector<NativePoly>& operator[](uint32_t i) { return m_elements[i]; }

  const std::vector<NativePoly>& operator[](usint i) const {
    return m_elements[i];
  }

  bool operator==(const RingGSWCiphertext& other) const {
    return m_elements == other.m_elements;
  }

  bool operator!=(const RingGSWCiphertext& other) const {
    return !(*this == other);
  }

  template <class Archive>
  void save(Archive& ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("elements", m_elements));
  }

  template <class Archive>
  void load(Archive& ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::make_nvp("elements", m_elements));
  }

  std::string SerializedObjectName() const { return "RingGSWCiphertext"; }
  static uint32_t SerializedVersion() { return 1; }

 private:
  std::vector<std::vector<NativePoly>> m_elements;
};

/**
 * @brief Class that stores the refreshing key (used in bootstrapping)
 * A three-dimensional vector of RingGSW ciphertexts
 */
class RingGSWBTKey : public Serializable {
 public:
  RingGSWBTKey() {}

  explicit RingGSWBTKey(uint32_t dim1, uint32_t dim2, uint32_t dim3) {
    m_key.resize(dim1);
    for (uint32_t i = 0; i < dim1; i++) {
      m_key[i].resize(dim2);
      for (uint32_t j = 0; j < dim2; j++) m_key[i][j].resize(dim3);
    }
  }

  explicit RingGSWBTKey(
      const std::vector<std::vector<std::vector<RingGSWCiphertext>>>& key)
      : m_key(key) {}

  explicit RingGSWBTKey(const RingGSWBTKey& rhs) { this->m_key = rhs.m_key; }

  explicit RingGSWBTKey(const RingGSWBTKey&& rhs) {
    this->m_key = std::move(rhs.m_key);
  }

  const RingGSWBTKey& operator=(const RingGSWBTKey& rhs) {
    this->m_key = rhs.m_key;
    return *this;
  }

  const RingGSWBTKey& operator=(const RingGSWBTKey&& rhs) {
    this->m_key = std::move(rhs.m_key);
    return *this;
  }

  const std::vector<std::vector<std::vector<RingGSWCiphertext>>>& GetElements()
      const {
    return m_key;
  }

  void SetElements(
      const std::vector<std::vector<std::vector<RingGSWCiphertext>>>& key) {
    m_key = key;
  }

  std::vector<std::vector<RingGSWCiphertext>>& operator[](uint32_t i) {
    return m_key[i];
  }

  const std::vector<std::vector<RingGSWCiphertext>>& operator[](usint i) const {
    return m_key[i];
  }

  bool operator==(const RingGSWBTKey& other) const {
    return m_key == other.m_key;
  }

  bool operator!=(const RingGSWBTKey& other) const { return !(*this == other); }

  template <class Archive>
  void save(Archive& ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("key", m_key));
  }

  template <class Archive>
  void load(Archive& ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::make_nvp("key", m_key));
  }

  std::string SerializedObjectName() const { return "RingGSWBTKey"; }
  static uint32_t SerializedVersion() { return 1; }

 private:
  std::vector<std::vector<std::vector<RingGSWCiphertext>>> m_key;
};

// The struct for storing bootstrapping keys
typedef struct {
  // refreshing key
  std::shared_ptr<RingGSWBTKey> BSkey;
  // switching key
  std::shared_ptr<LWESwitchingKey> KSkey;
} RingGSWEvalKey;

}  // namespace lbcrypto

#endif
