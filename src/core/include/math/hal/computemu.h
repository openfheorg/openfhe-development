// @file computemu.h
// @author TPOC: info@DualityTech.com
//
// @copyright Copyright (c) 2021, Duality Technologies Inc.
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

#ifndef __COMPUTEMU_H__
#define __COMPUTEMU_H__

#include "math/hal.h"

/**
 * computeMuUsingDoubleNativeInteger() and computeMuUsingBasicInteger() are helper functions
 * to be called from NativeIntegerT::ComputeMu() ONLY!
 *
 * @param MSB the return value from NativeInteger::GetMSB() (or this->GetMSB() in the code)
 * @param val the return value from NativeInteger::ConvertToInt() (or m_value in the code)
 *
 * @return the result of operations
 */
lbcrypto::BasicInteger computeMuUsingBasicInteger(lbcrypto::BasicInteger val, usint MSB);

lbcrypto::BasicInteger prepModMultUsingBasicInteger(lbcrypto::BasicInteger val,
                                                    lbcrypto::BasicInteger mod,
                                                    lbcrypto::BasicInteger maxBits);

#endif // __COMPUTEMU_H__

