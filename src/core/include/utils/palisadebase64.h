// @file palisadebase64.h palisade native base 64 utlities.
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

#ifndef SRC_CORE_LIB_UTILS_PALISADEBASE64_H_
#define SRC_CORE_LIB_UTILS_PALISADEBASE64_H_

#include <utils/exception.h>
#include <cctype>
#include <cstdint>

namespace lbcrypto {

extern const char to_base64_char[];

inline unsigned char value_to_base64(int c) { return to_base64_char[c]; }

inline unsigned char base64_to_value(unsigned char b64) {
  if (isupper(b64))
    return b64 - 'A';
  else if (islower(b64))
    return b64 - 'a' + 26;
  else if (isdigit(b64))
    return b64 - '0' + 52;
  else if (b64 == '+')
    return 62;
  else
    return 63;
}

inline unsigned char get_6bits_atoffset(uint64_t m_value, uint32_t index) {
  static unsigned char smallmask[] = {0, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f};

  if (index == 0) {
    PALISADE_THROW(math_error, "Zero index in GetBitAtIndex");
  }
  if (index <= 6) {
    return m_value & smallmask[index];
  }

  return (m_value >> (index - 6)) & 0x3f;
}

} /* namespace lbcrypto */

#endif /* SRC_CORE_LIB_UTILS_PALISADEBASE64_H_ */
