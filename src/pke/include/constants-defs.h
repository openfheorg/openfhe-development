//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2024, NJIT, Duality Technologies Inc. and other contributors
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
#ifndef __CONSTANTS_DEFS_H__
#define __CONSTANTS_DEFS_H__

#include "math/hal/basicint.h"  // for MAX_MODULUS_SIZE

namespace lbcrypto {

/**
 * @brief Lists all features supported by public key encryption schemes
 */
enum PKESchemeFeature {
    PKE          = 0x01,
    KEYSWITCH    = 0x02,
    PRE          = 0x04,
    LEVELEDSHE   = 0x08,
    ADVANCEDSHE  = 0x10,
    MULTIPARTY   = 0x20,
    FHE          = 0x40,
    SCHEMESWITCH = 0x80,
};

enum ScalingTechnique {
    FIXEDMANUAL = 0,
    FIXEDAUTO,
    FLEXIBLEAUTO,
    FLEXIBLEAUTOEXT,
    NORESCALE,
    INVALID_RS_TECHNIQUE,  // TODO (dsuponit): make this the first value
};

enum ProxyReEncryptionMode {
    NOT_SET = 0,
    INDCPA,
    FIXED_NOISE_HRA,
    NOISE_FLOODING_HRA,
};

enum MultipartyMode {
    INVALID_MULTIPARTY_MODE = 0,
    FIXED_NOISE_MULTIPARTY,
    NOISE_FLOODING_MULTIPARTY,
};

enum ExecutionMode {
    EXEC_EVALUATION = 0,
    EXEC_NOISE_ESTIMATION,
};

enum DecryptionNoiseMode {
    FIXED_NOISE_DECRYPT = 0,
    NOISE_FLOODING_DECRYPT,
};

enum KeySwitchTechnique {
    INVALID_KS_TECH = 0,
    BV,
    HYBRID,
};

enum EncryptionTechnique {
    STANDARD = 0,
    EXTENDED,
};

enum MultiplicationTechnique {
    BEHZ = 0,
    HPS,
    HPSPOVERQ,
    HPSPOVERQLEVELED,
};

enum PlaintextEncodings {
    INVALID_ENCODING = 0,
    COEF_PACKED_ENCODING,
    PACKED_ENCODING,
    STRING_ENCODING,
    CKKS_PACKED_ENCODING,
};

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

enum NoiseFlooding {
    // noise flooding distribution parameter for distributed decryption in threshold FHE
    MP_SD = 1048576,
    // noise flooding distribution parameter for fixed 20 bits noise multihop PRE
    PRE_SD = 1048576,
    // number of additional moduli in NOISE_FLOODING_MULTIPARTY mode
    NUM_MODULI_MULTIPARTY = 2,
// modulus size for additional moduli in NOISE_FLOODING_MULTIPARTY mode
#if NATIVEINT == 128
    MULTIPARTY_MOD_SIZE = 60,
#else
    MULTIPARTY_MOD_SIZE = MAX_MODULUS_SIZE,
#endif
};

// Defining the level to which the input ciphertext is brought to before
// interactive multi-party bootstrapping
enum COMPRESSION_LEVEL {  // TODO (dsuponit): change it to camel case
    // we don't support 0 or 1 compression levels
    // do not change values here

    COMPACT = 2,  // more efficient with stronger security assumption
    SLACK   = 3   // less efficient with weaker security assumption
};

}  // namespace lbcrypto

#endif  // __CONSTANTS_DEFS_H__
