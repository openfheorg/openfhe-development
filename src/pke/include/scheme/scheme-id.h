/**
 * @file scheme-id.h
 *
 * @brief Defines scheme id enums
 *
 * @author TPOC: contact@palisade-crypto.org
 *
 * @contributor Dmitriy Suponitskiy
 *
 * @copyright Copyright (c) 2021, Duality Technologies (https://dualitytech.com/)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _SCHEME_ID_H_
#define _SCHEME_ID_H_

#include <iosfwd>

namespace lbcrypto {

//====================================================================================================================
// TODO: should it be a SCHEME class??? (dsuponit)
enum SCHEME {
  CKKSRNS_SCHEME,
  BFVRNS_SCHEME,
  BGVRNS_SCHEME,
  INVALID_SCHEME
};
//====================================================================================================================
std::ostream& operator<<(std::ostream& os, SCHEME schemeId);
//====================================================================================================================
inline bool isCKKS(SCHEME schemeId) {
    return (schemeId == CKKSRNS_SCHEME);
}
inline bool isBFVRNS(SCHEME schemeId) {
    return (schemeId == BFVRNS_SCHEME);
}
inline bool isBGVRNS(SCHEME schemeId) {
    return (schemeId == BGVRNS_SCHEME);
}

}  // namespace lbcrypto

#endif  // _SCHEME_ID_H_
