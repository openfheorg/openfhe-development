// @file inttypes.h  This code provides basic integer types for lattice crypto.
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

#ifndef LBCRYPTO_UTILS_INTTYPES_H
#define LBCRYPTO_UTILS_INTTYPES_H

#include <stdint.h>
#include <iostream>
#include <string>

/**
 * @brief Type used for representing unsigned 8-bit integers.
 */
typedef uint8_t uschar;

/**
 * @brief Type used for representing unsigned 16-bit short integers.
 */
typedef uint16_t usshort;

/**
 * @brief Type used for representing unsigned 32-bit integers.
 */
typedef uint32_t usint;

typedef uint64_t PlaintextModulus;

/**
 * @brief Represents whether the polynomial ring is in EVALUATION or COEFFICIENT
 * representation.
 */
enum Format { EVALUATION = 0, COEFFICIENT = 1 };

inline std::ostream &operator<<(std::ostream &s, Format f) {
  switch (f) {
    case EVALUATION:
      s << "EVALUATION";
      break;
    case COEFFICIENT:
      s << "COEFFICIENT";
      break;
    default:
      s << "UKNOWN";
      break;
  }
  return s;
}

/**
 * @brief Lists all features supported by public key encryption schemes
 */
enum PKESchemeFeature {
  ENCRYPTION = 0x01,
  PRE = 0x02,
  SHE = 0x04,
  FHE = 0x08,
  LEVELEDSHE = 0x10,
  MULTIPARTY = 0x20,
  ADVANCEDSHE = 0x40
};

inline std::ostream &operator<<(std::ostream &s, PKESchemeFeature f) {
  switch (f) {
    case ENCRYPTION:
      s << "ENCRYPTION";
      break;
    case PRE:
      s << "PRE";
      break;
    case SHE:
      s << "SHE";
      break;
    case FHE:
      s << "FHE";
      break;
    case LEVELEDSHE:
      s << "LEVELEDSHE";
      break;
    case MULTIPARTY:
      s << "MULTIPARTY";
      break;
    case ADVANCEDSHE:
      s << "ADVANCEDSHE";
      break;
    default:
      s << "UKNOWN";
      break;
  }
  return s;
}

/**
 * @brief Lists all modes for RLWE schemes, such as BGV and BFV
 */
enum MODE { RLWE = 0, OPTIMIZED = 1, SPARSE = 2 };

inline std::ostream &operator<<(std::ostream &s, MODE m) {
  switch (m) {
    case RLWE:
      s << "RLWE";
      break;
    case OPTIMIZED:
      s << "OPTIMIZED";
      break;
    case SPARSE:
      s << "SPARSE";
      break;
    default:
      s << "UKNOWN";
      break;
  }
  return s;
}

#endif
