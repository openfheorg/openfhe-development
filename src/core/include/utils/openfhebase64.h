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

/*
  OpenFHE native base 64 utlities
 */

#ifndef SRC_CORE_INCLUDE_UTILS_OPENFHEBASE64_H_
#define SRC_CORE_INCLUDE_UTILS_OPENFHEBASE64_H_

#include <utils/exception.h>

#include <cctype>
#include <cstdint>

namespace lbcrypto {

/** the 64-character base64 alphabet "A-Za-z0-9+/", indexed by 6-bit value */
extern const char to_base64_char[];

/**
 * @brief Encodes a 6-bit value as its base64 character.
 * @param c value in [0, 63]
 * @return the base64 character for c
 */
inline unsigned char value_to_base64(int c) {
    return to_base64_char[c];
}

/**
 * @brief Decodes a base64 character to its 6-bit value; '/' and any character outside the alphabet decode to 63.
 * @param b64 base64 character
 * @return value in [0, 63]
 */
inline unsigned char base64_to_value(unsigned char b64) {
    if (isupper(b64))
        return b64 - 'A';
    if (islower(b64))
        return b64 - 'a' + 26;
    if (isdigit(b64))
        return b64 - '0' + 52;
    if (b64 == '+')
        return 62;
    return 63;
}

/**
 * @brief Extracts the 6-bit group of a 64-bit value that ends at bit position index (1-based, counted from the
 * least significant bit): bits [index-6, index) for index > 6, or the lowest index bits for index <= 6.
 * Throws for index == 0.
 * @param m_value value to extract from
 * @param index 1-based position of the most significant bit of the group
 * @return the extracted 6-bit value
 */
inline unsigned char get_6bits_atoffset(uint64_t m_value, uint32_t index) {
    static unsigned char smallmask[] = {0, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f};
    if (index == 0)
        OPENFHE_THROW("Zero index in GetBitAtIndex");
    if (index <= 6)
        return m_value & smallmask[index];
    return (m_value >> (index - 6)) & 0x3f;
}

} /* namespace lbcrypto */

#endif  // SRC_CORE_INCLUDE_UTILS_OPENFHEBASE64_H_
