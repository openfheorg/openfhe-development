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

#include "constants-fwd.h"

// #include "math/hal/basicint.h"
#include "math/math-hal.h"
#include "lattice/constants-lattice.h"

#include <iosfwd>
#include <string>

namespace lbcrypto {
// PKESchemeFeature helper functions
std::ostream& operator<<(std::ostream& s, PKESchemeFeature f);

// PKESchemeFeature helper functions
ScalingTechnique convertToScalingTechnique(const std::string& str);
ScalingTechnique convertToScalingTechnique(uint32_t num);
std::ostream& operator<<(std::ostream& s, ScalingTechnique t);

// ProxyReEncryptionMode helper functions
ProxyReEncryptionMode convertToProxyReEncryptionMode(const std::string& str);
ProxyReEncryptionMode convertToProxyReEncryptionMode(uint32_t num);
std::ostream& operator<<(std::ostream& s, ProxyReEncryptionMode p);

// MultipartyMode helper functions
MultipartyMode convertToMultipartyMode(const std::string& str);
MultipartyMode convertToMultipartyMode(uint32_t num);
std::ostream& operator<<(std::ostream& s, MultipartyMode t);

// ExecutionMode helper functions
ExecutionMode convertToExecutionMode(const std::string& str);
ExecutionMode convertToExecutionMode(uint32_t num);
std::ostream& operator<<(std::ostream& s, ExecutionMode t);

// DecryptionNoiseMode helper functions
DecryptionNoiseMode convertToDecryptionNoiseMode(const std::string& str);
DecryptionNoiseMode convertToDecryptionNoiseMode(uint32_t num);
std::ostream& operator<<(std::ostream& s, DecryptionNoiseMode t);

// KeySwitchTechnique helper functions
KeySwitchTechnique convertToKeySwitchTechnique(const std::string& str);
KeySwitchTechnique convertToKeySwitchTechnique(uint32_t num);
std::ostream& operator<<(std::ostream& s, KeySwitchTechnique t);

// EncryptionTechnique helper functions
EncryptionTechnique convertToEncryptionTechnique(const std::string& str);
EncryptionTechnique convertToEncryptionTechnique(uint32_t num);
std::ostream& operator<<(std::ostream& s, EncryptionTechnique t);

// MultiplicationTechnique helper functions
MultiplicationTechnique convertToMultiplicationTechnique(const std::string& str);
MultiplicationTechnique convertToMultiplicationTechnique(uint32_t num);
std::ostream& operator<<(std::ostream& s, MultiplicationTechnique t);

// PlaintextEncodings helper functions
std::ostream& operator<<(std::ostream& s, PlaintextEncodings p);

enum NOISE_FLOODING {
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
};  // namespace NOISE_FLOODING

// COMPRESSION_LEVEL helper functions
COMPRESSION_LEVEL convertToCompressionLevel(const std::string& str);
COMPRESSION_LEVEL convertToCompressionLevel(uint32_t num);
std::ostream& operator<<(std::ostream& s, COMPRESSION_LEVEL t);

}  // namespace lbcrypto

#endif  // _CONSTANTS_H_
