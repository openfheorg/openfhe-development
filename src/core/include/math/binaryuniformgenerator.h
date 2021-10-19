// @file binaryuniformgenerator.cpp This code provides generation of a uniform
// distribution of binary values (modulus 2). Discrete uniform generator relies
// on the built-in C++ generator for 32-bit unsigned integers defined in
// <random>.
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

#ifndef LBCRYPTO_MATH_BINARYUNIFORMGENERATOR_H_
#define LBCRYPTO_MATH_BINARYUNIFORMGENERATOR_H_

#include <random>
#include "math/distributiongenerator.h"

namespace lbcrypto {

template <typename VecType>
class BinaryUniformGeneratorImpl;

typedef BinaryUniformGeneratorImpl<BigVector> BinaryUniformGenerator;

/**
 * @brief A generator of the Binary Uniform Distribution.
 */
template <typename VecType>
class BinaryUniformGeneratorImpl : public DistributionGenerator<VecType> {
 public:
  /**
   * @brief Basic constructor for Binary Uniform Generator.
   */
  BinaryUniformGeneratorImpl() : DistributionGenerator<VecType>() {}
  ~BinaryUniformGeneratorImpl() {}

  /**
   * @brief  Generates a random value within the Binary Uniform Distribution.
   * @return A random value within this Binary Uniform Distribution.
   */
  typename VecType::Integer GenerateInteger() const;

  /**
   * @brief  Generates a vector of random values within the Binary Uniform
   * Distribution.
   * @return A vector of random values within this Binary Uniform Distribution.
   */
  VecType GenerateVector(const usint size,
                         const typename VecType::Integer &modulus) const;

 private:
  static std::bernoulli_distribution m_distribution;
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_MATH_BINARYUNIFORMGENERATOR_H_
