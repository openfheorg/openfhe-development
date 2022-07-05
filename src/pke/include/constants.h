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

#ifndef _CONSTANTS_H_
#define _CONSTANTS_H_

#include <iosfwd>

/**
 * @brief Lists all features supported by public key encryption schemes
 */
enum PKESchemeFeature {
  PKE = 0x01,
  KEYSWITCH = 0x02,
  PRE = 0x04,
  LEVELEDSHE = 0x08,
  ADVANCEDSHE = 0x10,
  MULTIPARTY = 0x20,
  FHE = 0x40
};

std::ostream& operator<<(std::ostream& s, PKESchemeFeature f);

/**
 * @brief Lists all modes for RLWE schemes, such as BGV and BFV
 */
enum MODE { RLWE = 0, OPTIMIZED = 1, SPARSE = 2 };
std::ostream& operator<<(std::ostream& s, MODE m);

enum RescalingTechnique {
  FIXEDMANUAL,
  FIXEDAUTO,
  FLEXIBLEAUTO,
  FLEXIBLEAUTOEXT,
  NORESCALE,
  INVALID_RS_TECHNIQUE  // TODO (dsuponit): make this the first value
};
std::ostream& operator<<(std::ostream& s, RescalingTechnique t);

enum ProxyReEncryptionMode {
  INDCPA,
  FIXED_NOISE_HRA,
  NOISE_FLOODING_HRA,
  DIVIDE_AND_ROUND_HRA
};
std::ostream& operator<<(std::ostream& s, ProxyReEncryptionMode p);

enum KeySwitchTechnique { INVALID_KS_TECH, BV, HYBRID };
std::ostream& operator<<(std::ostream& s, KeySwitchTechnique t);

enum EncryptionTechnique { STANDARD, POVERQ };
std::ostream& operator<<(std::ostream& s, EncryptionTechnique t);

enum MultiplicationTechnique { BEHZ, HPS, HPSPOVERQ, HPSPOVERQLEVELED };
std::ostream& operator<<(std::ostream& s, MultiplicationTechnique t);

enum LargeScalingFactorConstants {MAX_BITS_IN_WORD = 62, MAX_LOG_STEP = 60};


#endif  // _CONSTANTS_H_
