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

// TODO: Review whether we need to include hal.h.
#include "math/hal.h"

/**
 * @brief Lists all features supported by public key encryption schemes
 */
enum PKESchemeFeature {
    PKE         = 0x01,
    KEYSWITCH   = 0x02,
    PRE         = 0x04,
    LEVELEDSHE  = 0x08,
    ADVANCEDSHE = 0x10,
    MULTIPARTY  = 0x20,
    FHE         = 0x40,
};
std::ostream& operator<<(std::ostream& s, PKESchemeFeature f);

/**
 * @brief Lists all modes for RLWE schemes, such as BGV and BFV
 */
enum SecretKeyDist {
    GAUSSIAN        = 0,
    UNIFORM_TERNARY = 1,
    SPARSE_TERNARY  = 2,
};
SecretKeyDist convertToSecretKeyDist(uint32_t num);
std::ostream& operator<<(std::ostream& s, SecretKeyDist m);

enum ScalingTechnique {
    FIXEDMANUAL = 0,
    FIXEDAUTO,
    FLEXIBLEAUTO,
    FLEXIBLEAUTOEXT,
    NORESCALE,
    INVALID_RS_TECHNIQUE,  // TODO (dsuponit): make this the first value
};
ScalingTechnique convertToScalingTechnique(uint32_t num);
std::ostream& operator<<(std::ostream& s, ScalingTechnique t);

enum ProxyReEncryptionMode {
    NOT_SET = 0,
    INDCPA,
    FIXED_NOISE_HRA,
    NOISE_FLOODING_HRA,
    DIVIDE_AND_ROUND_HRA,
};
ProxyReEncryptionMode convertToProxyReEncryptionMode(uint32_t num);
std::ostream& operator<<(std::ostream& s, ProxyReEncryptionMode p);

enum MultipartyMode {
    INVALID_MULTIPARTY_MODE = 0,
    FIXED_NOISE_MULTIPARTY,
    NOISE_FLOODING_MULTIPARTY,
};
MultipartyMode convertToMultipartyMode(uint32_t num);
std::ostream& operator<<(std::ostream& s, MultipartyMode t);

enum ExecutionMode {
    EXEC_EVALUATION = 0,
    EXEC_NOISE_ESTIMATION,
};
ExecutionMode convertToExecutionMode(uint32_t num);
std::ostream& operator<<(std::ostream& s, ExecutionMode t);

enum DecryptionNoiseMode {
    FIXED_NOISE_DECRYPT = 0,
    NOISE_FLOODING_DECRYPT,
};
DecryptionNoiseMode convertToDecryptionNoiseMode(uint32_t num);
std::ostream& operator<<(std::ostream& s, DecryptionNoiseMode t);

enum KeySwitchTechnique {
    INVALID_KS_TECH = 0,
    BV,
    HYBRID,
};
KeySwitchTechnique convertToKeySwitchTechnique(uint32_t num);
std::ostream& operator<<(std::ostream& s, KeySwitchTechnique t);

enum EncryptionTechnique {
    STANDARD = 0,
    EXTENDED,
};
EncryptionTechnique convertToEncryptionTechnique(uint32_t num);
std::ostream& operator<<(std::ostream& s, EncryptionTechnique t);

enum MultiplicationTechnique {
    BEHZ = 0,
    HPS,
    HPSPOVERQ,
    HPSPOVERQLEVELED,
};
MultiplicationTechnique convertToMultiplicationTechnique(uint32_t num);
std::ostream& operator<<(std::ostream& s, MultiplicationTechnique t);

enum PlaintextEncodings {
    INVALID_ENCODING = 0,
    COEF_PACKED_ENCODING,
    PACKED_ENCODING,
    STRING_ENCODING,
    CKKS_PACKED_ENCODING,
};
std::ostream& operator<<(std::ostream& s, PlaintextEncodings p);

enum LargeScalingFactorConstants {
    MAX_BITS_IN_WORD = 61,
    MAX_LOG_STEP     = 60,
};

/**
 * @brief  BASE_NUM_LEVELS_TO_DROP is the most common value for levels/towers to drop (do not make it a default argument
 * as default arguments work differently for virtual functions)
 */
// TODO (dsuponit): remove BASE_NUM_LEVELS_TO_DROP
enum {
    BASE_NUM_LEVELS_TO_DROP = 1,
};

namespace NOISE_FLOODING {
// noise flooding distribution parameter for distributed decryption in threshold FHE
const double MP_SD = 1048576;
// noise flooding distribution parameter for fixed 20 bits noise multihop PRE
const double PRE_SD = 1048576;
// statistical security parameter for noise flooding in PRE
const double STAT_SECURITY = 30;
// number of additional moduli in NOISE_FLOODING_MULTIPARTY mode
const size_t NUM_MODULI_MULTIPARTY = 2;
// modulus size for additional moduli in NOISE_FLOODING_MULTIPARTY mode
#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
const size_t MULTIPARTY_MOD_SIZE = 60;
#else
const size_t MULTIPARTY_MOD_SIZE = MAX_MODULUS_SIZE;
#endif
};  // namespace NOISE_FLOODING

#endif  // _CONSTANTS_H_
