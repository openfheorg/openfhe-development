/** @file hexldcrtpoly.h
 *
 * @brief test file for checking if the interface class is
 * implemented correctly Intel HEXL specific DCRT Polynomial Object
 *
 * @author TPOC: contact@palisade-crypto.org
 *
 * @contributor Jonathan Saylor (jsaylor@dualitytech.com)
 *
 * @copyright Copyright (c) 2021, Duality Technologies
 * (https://dualitytech.com/) All rights reserved. Redistribution and use in
 * source and binary forms, with or without modification, are permitted provided
 * that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#if defined(WITH_INTEL_HEXL)

#ifndef LBCRYPTO_LATTICE_HEXLDCRTPOLY_H
#define LBCRYPTO_LATTICE_HEXLDCRTPOLY_H


// C++ standard libs
#include <vector>

// Third-party libs
#include "hexl/hexl.hpp"

// Local PALISADE libs
#include "math/backend.h"
#include "lattice/dcrtpoly.h"
#include "utils/debug.h"

// PALISADE's main namespace
namespace lbcrypto {

/**
 * @brief A DCRTPoly Implementation optimized for HEXL, Intel's AVX512 IFMA
 * instructions
 *
 * This class overrides the minimum number of methods, what is necassary for use
 * in PALISADE to substitute HexlDCRTPoly for DCRTPolyImpl and methods that have
 * optimized procedures for specific architecture.
 */
template <typename VecType = BigVector>
class HexlDCRTPoly : public DCRTPolyImpl<VecType> {
 public:
  // Shortcut to base class
  using DCRTPolyType = DCRTPolyImpl<VecType>;

  using Integer = typename VecType::Integer;
  using Params = ILDCRTParams<Integer>;

  typedef VecType Vector;

  using DggType = typename DCRTPolyType::DggType;
  using DugType = typename DCRTPolyType::DugType;
  using TugType = typename DCRTPolyType::TugType;
  using BugType = typename DCRTPolyType::BugType;

  // this class contains an array of these:
  using PolyType = typename DCRTPolyType::PolyType;

  // the composed polynomial type
  using PolyLargeType = typename DCRTPolyType::PolyLargeType;

  static const std::string GetElementName() { return "HexlDCRTPoly"; }

  // =============================================================================================
  // All methods in this section are optimized for HEXL

  /** Optimized DropLastElementAndScale for HEXL
   * @see DCRTPolyImpl::DropLastElementAndScale for procedure description
   */
  virtual void DropLastElementAndScale(
      const std::vector<NativeInteger> &QlQlInvModqlDivqlModq,
      const std::vector<NativeInteger> &QlQlInvModqlDivqlModqPrecon,
      const std::vector<NativeInteger> &qlInvModq,
      const std::vector<NativeInteger> &qlInvModqPrecon) override;

  // =============================================================================================
  // All methods below here are required for substitution with DCRTPolyImpl<> but are not optimized

  HexlDCRTPoly() : DCRTPolyType() {}

  HexlDCRTPoly(const shared_ptr<Params> params, Format format = EVALUATION,
               bool initializeElementToZero = false)
      : DCRTPolyType(params, format, initializeElementToZero) {}

  // Need to be able to make a copy,
  HexlDCRTPoly(const DCRTPolyType &dcrtPoly) : DCRTPolyType(dcrtPoly) {}
  HexlDCRTPoly(const std::vector<PolyType> &elements)
      : DCRTPolyType(elements) {}
  HexlDCRTPoly(const DggType &dgg, const shared_ptr<Params> params,
               Format format = EVALUATION)
      : DCRTPolyType(dgg, params, format) {}
  HexlDCRTPoly(DugType &dug, const shared_ptr<Params> params,
               Format format = EVALUATION)
      : DCRTPolyType(dug, params, format) {}
  HexlDCRTPoly(const TugType &tug, const shared_ptr<Params> params,
               Format format = EVALUATION, uint32_t h = 0)
      : DCRTPolyType(tug, params, format, h) {}
  HexlDCRTPoly(const BugType &bug, const shared_ptr<Params> params,
               Format format = EVALUATION)
      : DCRTPolyType(bug, params, format) {}
  HexlDCRTPoly(const PolyLargeType& element, const shared_ptr<Params> params)
      : DCRTPolyType(element, params) {}

  /**
   * @brief Assignment Operator.
   *
   * @param &rhs the copied element.
   * @return the resulting element.
   */
  virtual const HexlDCRTPoly &operator=(const DCRTPolyType &rhs) override {
    DCRTPolyType::operator=(rhs);
    return *this;
  }

  /**
   * @brief Move Assignment Operator.
   *
   * @param &rhs the copied element.
   * @return the resulting element.
   */
  virtual const HexlDCRTPoly &operator=(DCRTPolyType &&rhs) override {
    DCRTPolyType::operator=(rhs);
    return *this;
  }

  // All assignment operators need to be overriden because the return type is
  // different
  const HexlDCRTPoly &operator=(const PolyLargeType &rhs) {
    DCRTPolyType::operator=(rhs);
    return *this;
  }

  const HexlDCRTPoly &operator=(const PolyType &rhs) override {
    DCRTPolyType::operator=(rhs);
    return *this;
  }

  /**
   * @brief Initalizer list
   *
   * @param &rhs the list to initalized the element.
   * @return the resulting element.
   */
  HexlDCRTPoly &operator=(std::initializer_list<uint64_t> rhs) override {
    DCRTPolyType::operator=(rhs);
    return *this;
  }

  /**
   * @brief Assignment Operator. The usint rhs will be set at index zero and all
   * other indices will be set to zero.
   *
   * @param rhs is the usint to assign to index zero.
   * @return the resulting vector.
   */
  HexlDCRTPoly &operator=(uint64_t rhs) override {
    DCRTPolyType::operator=(rhs);
    return *this;
  }

  /**
   * @brief Creates a Poly from a vector of signed integers (used for trapdoor
   * sampling)
   *
   * @param &rhs the vector to set the PolyImpl to.
   * @return the resulting PolyImpl.
   */
  HexlDCRTPoly &operator=(const std::vector<int64_t> &rhs) override {
    DCRTPolyType::operator=(rhs);
    return *this;
  }

  /**
   * @brief Creates a Poly from a vector of signed integers (used for trapdoor
   * sampling)
   *
   * @param &rhs the vector to set the PolyImpl to.
   * @return the resulting PolyImpl.
   */
  HexlDCRTPoly &operator=(const std::vector<int32_t> &rhs) override {
    DCRTPolyType::operator=(rhs);
    return *this;
  }

  /**
   * @brief Initalizer list
   *
   * @param &rhs the list to set the PolyImpl to.
   * @return the resulting PolyImpl.
   */

  HexlDCRTPoly &operator=(std::initializer_list<std::string> rhs) override {
    DCRTPolyType::operator=(rhs);
    return *this;
  }

  /**
   * @brief assignment operator to transform a vector of the Base class into this Derived class
   * 
   * @param dcrtVec 
   * @return std::vector<HexlDCRTPoly> @note this is a copy return intially
   */
  std::vector<HexlDCRTPoly> operator=(std::vector<DCRTPolyType>& dcrtVec) const {
    // Use the base class to do the decompose
    // std::vector<DCRTPolyType> dcrtVec = DCRTPolyType::CRTDecompose(baseBits);
    // std::vector<HexlDCRTPoly> hexlVec(dcrtVec.begin(), dcrtVec.end());
    std::vector<HexlDCRTPoly> hexlVec(dcrtVec.size());

    // use a lambda function to transform the std::vector<DCRTPolyImpl> to std::vector<HexlDCRTPoly>
    std::transform(dcrtVec.begin(), dcrtVec.end(), hexlVec.begin(),
      [](DCRTPolyType& dcrtPoly) -> HexlDCRTPoly {
        return HexlDCRTPoly(dcrtPoly);
      }
    );
    return hexlVec;
  }

};  // HexlDCRTPoly

/// @todo - Not sure if this is needed, was in DCRTPoly.h
// typedef HexlDCRTPoly<BigVector> DCRTPoly;

}  // namespace lbcrypto

#endif  // LBCRYPTO_LATTICE_HEXLDCRTPOLY_H

#endif  // WITH_INTEL_HEXL
