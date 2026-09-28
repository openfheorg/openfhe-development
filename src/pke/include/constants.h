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
// This is a collection of helper functions for the enum definitions in constants-defs.h.
// constatns.h was split because of a request to provide a better compatability with
// the Rust wrapper for OpenFHE.
#ifndef SRC_PKE_INCLUDE_CONSTANTS_H_
#define SRC_PKE_INCLUDE_CONSTANTS_H_

#include <cstdint>
#include <iosfwd>
#include <string>

#include "constants-defs.h"  // all enum definitions

namespace lbcrypto {

//======================================================================================================================
/**
 * Prints the name of a PKESchemeFeature enumerator ("UNKNOWN" for a value that is not a defined enumerator).
 *
 * @param s the output stream
 * @param f the enumerator to print
 * @return the output stream
 */
std::ostream& operator<<(std::ostream& s, PKESchemeFeature f);
//======================================================================================================================
/**
 * Converts the name of a ScalingTechnique enumerator (as spelled in constants-defs.h) to its value.
 *
 * @param str the enumerator name
 * @return the corresponding enumerator; throws an exception if the name is unknown
 */
ScalingTechnique convertToScalingTechnique(const std::string& str);
/**
 * Converts an integer to a ScalingTechnique enumerator, checking that it is a defined enumerator value.
 *
 * @param num the integer value of the enumerator
 * @return the corresponding enumerator; throws an exception if the value is not a defined enumerator
 */
ScalingTechnique convertToScalingTechnique(uint32_t num);
/**
 * Prints the name of a ScalingTechnique enumerator ("UNKNOWN" for a value that is not a defined enumerator).
 *
 * @param s the output stream
 * @param t the enumerator to print
 * @return the output stream
 */
std::ostream& operator<<(std::ostream& s, ScalingTechnique t);
//======================================================================================================================
/**
 * Converts the name of a ProxyReEncryptionMode enumerator (as spelled in constants-defs.h) to its value.
 *
 * @param str the enumerator name
 * @return the corresponding enumerator; throws an exception if the name is unknown
 */
ProxyReEncryptionMode convertToProxyReEncryptionMode(const std::string& str);
/**
 * Converts an integer to a ProxyReEncryptionMode enumerator, checking that it is a defined enumerator value.
 *
 * @param num the integer value of the enumerator
 * @return the corresponding enumerator; throws an exception if the value is not a defined enumerator
 */
ProxyReEncryptionMode convertToProxyReEncryptionMode(uint32_t num);
/**
 * Prints the name of a ProxyReEncryptionMode enumerator ("UNKNOWN" for a value that is not a defined enumerator).
 *
 * @param s the output stream
 * @param p the enumerator to print
 * @return the output stream
 */
std::ostream& operator<<(std::ostream& s, ProxyReEncryptionMode p);
//======================================================================================================================
/**
 * Converts the name of a MultipartyMode enumerator (as spelled in constants-defs.h) to its value.
 *
 * @param str the enumerator name
 * @return the corresponding enumerator; throws an exception if the name is unknown
 */
MultipartyMode convertToMultipartyMode(const std::string& str);
/**
 * Converts an integer to a MultipartyMode enumerator, checking that it is a defined enumerator value.
 *
 * @param num the integer value of the enumerator
 * @return the corresponding enumerator; throws an exception if the value is not a defined enumerator
 */
MultipartyMode convertToMultipartyMode(uint32_t num);
/**
 * Prints the name of a MultipartyMode enumerator ("UNKNOWN" for a value that is not a defined enumerator).
 *
 * @param s the output stream
 * @param t the enumerator to print
 * @return the output stream
 */
std::ostream& operator<<(std::ostream& s, MultipartyMode t);
//======================================================================================================================
/**
 * Converts the name of a ExecutionMode enumerator (as spelled in constants-defs.h) to its value.
 *
 * @param str the enumerator name
 * @return the corresponding enumerator; throws an exception if the name is unknown
 */
ExecutionMode convertToExecutionMode(const std::string& str);
/**
 * Converts an integer to a ExecutionMode enumerator, checking that it is a defined enumerator value.
 *
 * @param num the integer value of the enumerator
 * @return the corresponding enumerator; throws an exception if the value is not a defined enumerator
 */
ExecutionMode convertToExecutionMode(uint32_t num);
/**
 * Prints the name of a ExecutionMode enumerator ("UNKNOWN" for a value that is not a defined enumerator).
 *
 * @param s the output stream
 * @param t the enumerator to print
 * @return the output stream
 */
std::ostream& operator<<(std::ostream& s, ExecutionMode t);
//======================================================================================================================
/**
 * Converts the name of a DecryptionNoiseMode enumerator (as spelled in constants-defs.h) to its value.
 *
 * @param str the enumerator name
 * @return the corresponding enumerator; throws an exception if the name is unknown
 */
DecryptionNoiseMode convertToDecryptionNoiseMode(const std::string& str);
/**
 * Converts an integer to a DecryptionNoiseMode enumerator, checking that it is a defined enumerator value.
 *
 * @param num the integer value of the enumerator
 * @return the corresponding enumerator; throws an exception if the value is not a defined enumerator
 */
DecryptionNoiseMode convertToDecryptionNoiseMode(uint32_t num);
/**
 * Prints the name of a DecryptionNoiseMode enumerator ("UNKNOWN" for a value that is not a defined enumerator).
 *
 * @param s the output stream
 * @param t the enumerator to print
 * @return the output stream
 */
std::ostream& operator<<(std::ostream& s, DecryptionNoiseMode t);
//======================================================================================================================
/**
 * Converts the name of a KeySwitchTechnique enumerator (as spelled in constants-defs.h) to its value.
 *
 * @param str the enumerator name
 * @return the corresponding enumerator; throws an exception if the name is unknown
 */
KeySwitchTechnique convertToKeySwitchTechnique(const std::string& str);
/**
 * Converts an integer to a KeySwitchTechnique enumerator, checking that it is a defined enumerator value.
 *
 * @param num the integer value of the enumerator
 * @return the corresponding enumerator; throws an exception if the value is not a defined enumerator
 */
KeySwitchTechnique convertToKeySwitchTechnique(uint32_t num);
/**
 * Prints the name of a KeySwitchTechnique enumerator ("UNKNOWN" for a value that is not a defined enumerator).
 *
 * @param s the output stream
 * @param t the enumerator to print
 * @return the output stream
 */
std::ostream& operator<<(std::ostream& s, KeySwitchTechnique t);
//======================================================================================================================
/**
 * Converts the name of a EncryptionTechnique enumerator (as spelled in constants-defs.h) to its value.
 *
 * @param str the enumerator name
 * @return the corresponding enumerator; throws an exception if the name is unknown
 */
EncryptionTechnique convertToEncryptionTechnique(const std::string& str);
/**
 * Converts an integer to a EncryptionTechnique enumerator, checking that it is a defined enumerator value.
 *
 * @param num the integer value of the enumerator
 * @return the corresponding enumerator; throws an exception if the value is not a defined enumerator
 */
EncryptionTechnique convertToEncryptionTechnique(uint32_t num);
/**
 * Prints the name of a EncryptionTechnique enumerator ("UNKNOWN" for a value that is not a defined enumerator).
 *
 * @param s the output stream
 * @param t the enumerator to print
 * @return the output stream
 */
std::ostream& operator<<(std::ostream& s, EncryptionTechnique t);
//======================================================================================================================
/**
 * Converts the name of a MultiplicationTechnique enumerator (as spelled in constants-defs.h) to its value.
 *
 * @param str the enumerator name
 * @return the corresponding enumerator; throws an exception if the name is unknown
 */
MultiplicationTechnique convertToMultiplicationTechnique(const std::string& str);
/**
 * Converts an integer to a MultiplicationTechnique enumerator, checking that it is a defined enumerator value.
 *
 * @param num the integer value of the enumerator
 * @return the corresponding enumerator; throws an exception if the value is not a defined enumerator
 */
MultiplicationTechnique convertToMultiplicationTechnique(uint32_t num);
/**
 * Prints the name of a MultiplicationTechnique enumerator ("UNKNOWN" for a value that is not a defined enumerator).
 *
 * @param s the output stream
 * @param t the enumerator to print
 * @return the output stream
 */
std::ostream& operator<<(std::ostream& s, MultiplicationTechnique t);
//======================================================================================================================
/**
 * Prints the name of a PlaintextEncodings enumerator ("UNKNOWN" for a value that is not a defined enumerator).
 *
 * @param s the output stream
 * @param p the enumerator to print
 * @return the output stream
 */
std::ostream& operator<<(std::ostream& s, PlaintextEncodings p);
//======================================================================================================================
/**
 * Converts the name of a CompressionLevel enumerator (as spelled in constants-defs.h) to its value.
 *
 * @param str the enumerator name
 * @return the corresponding enumerator; throws an exception if the name is unknown
 */
CompressionLevel convertToCompressionLevel(const std::string& str);
/**
 * Converts an integer to a CompressionLevel enumerator, checking that it is a defined enumerator value.
 *
 * @param num the integer value of the enumerator
 * @return the corresponding enumerator; throws an exception if the value is not a defined enumerator
 */
CompressionLevel convertToCompressionLevel(uint32_t num);
/**
 * Prints the name of a CompressionLevel enumerator ("UNKNOWN" for a value that is not a defined enumerator).
 *
 * @param s the output stream
 * @param t the enumerator to print
 * @return the output stream
 */
std::ostream& operator<<(std::ostream& s, CompressionLevel t);
//======================================================================================================================
/**
 * Converts the name of a CKKSDataType enumerator (as spelled in constants-defs.h) to its value.
 *
 * @param str the enumerator name
 * @return the corresponding enumerator; throws an exception if the name is unknown
 */
CKKSDataType convertToCKKSDataType(const std::string& str);
/**
 * Converts an integer to a CKKSDataType enumerator, checking that it is a defined enumerator value.
 *
 * @param num the integer value of the enumerator
 * @return the corresponding enumerator; throws an exception if the value is not a defined enumerator
 */
CKKSDataType convertToCKKSDataType(uint32_t num);
/**
 * Prints the name of a CKKSDataType enumerator ("UNKNOWN" for a value that is not a defined enumerator).
 *
 * @param s the output stream
 * @param t the enumerator to print
 * @return the output stream
 */
std::ostream& operator<<(std::ostream& s, CKKSDataType t);
//======================================================================================================================

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_CONSTANTS_H_
