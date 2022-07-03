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
enum SecretKeyDist { GAUSSIAN = 0, UNIFORM_TERNARY = 1, SPARSE_TERNARY = 2 };
std::ostream& operator<<(std::ostream& s, SecretKeyDist m);

enum RescalingTechnique {
  FIXEDMANUAL,
  FIXEDAUTO,
  FLEXIBLEAUTO,
  FLEXIBLEAUTOEXT,
  NORESCALE,
  INVALID_RS_TECHNIQUE  // TODO (dsuponit): make this the first value
};
std::ostream& operator<<(std::ostream& s, RescalingTechnique t);

enum KeySwitchTechnique { INVALID_KS_TECH, BV, HYBRID };
std::ostream& operator<<(std::ostream& s, KeySwitchTechnique t);

enum EncryptionTechnique { STANDARD, POVERQ };
std::ostream& operator<<(std::ostream& s, EncryptionTechnique t);

enum MultiplicationTechnique { BEHZ, HPS, HPSPOVERQ, HPSPOVERQLEVELED };
std::ostream& operator<<(std::ostream& s, MultiplicationTechnique t);

enum LargeScalingFactorConstants {MAX_BITS_IN_WORD = 62, MAX_LOG_STEP = 60};

enum CKKSBootstrapMethod {
  EvalBTLinearMethod,
  EvalBTFFTMethod
};
std::ostream& operator<<(std::ostream& s, CKKSBootstrapMethod t);

enum CKKS_FFT_PARAMS {
  LEVEL_BUDGET,      // the level budget
  LAYERS_COLL,       // the number of layers to collapse in one level
  LAYERS_REM,        // the number of layers remaining to be collapsed in one level to have exactly the number of levels specified in the level budget
  NUM_ROTATIONS,     // the number of rotations in one level
  BABY_STEP,         // the baby step in the baby-step giant-step strategy
  GIANT_STEP,        // the giant step in the baby-step giant-step strategy
  NUM_ROTATIONS_REM, // the number of rotations in the remaining level
  BABY_STEP_REM,     // the baby step in the baby-step giant-step strategy for the remaining level
  GIANT_STEP_REM,    // the giant step in the baby-step giant-step strategy for the remaining level
  TOTAL_ELEMENTS     // total number of elements in the vector
};
std::ostream& operator<<(std::ostream& s, CKKS_FFT_PARAMS t);

#endif  // _CONSTANTS_H_
