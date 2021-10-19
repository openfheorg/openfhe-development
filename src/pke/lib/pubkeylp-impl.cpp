// @file pubkeylp-impl.cpp - template instantiations and methods for keys
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

#include "cryptocontext.h"
#include "pubkeylp.cpp"
#include "utils/serial.h"

namespace lbcrypto {
extern template class CryptoContextImpl<Poly>;

template class LPPublicKeyImpl<Poly>;
template class LPPrivateKeyImpl<Poly>;
template class LPEvalKeyImpl<Poly>;
template class LPEvalKeyRelinImpl<Poly>;
template class LPCryptoParameters<Poly>;
template class LPCryptoParametersRLWE<Poly>;
template class LPPublicKeyEncryptionScheme<Poly>;

extern template class CryptoContextImpl<NativePoly>;

template class LPPublicKeyImpl<NativePoly>;
template class LPPrivateKeyImpl<NativePoly>;
template class LPEvalKeyImpl<NativePoly>;
template class LPEvalKeyRelinImpl<NativePoly>;
template class LPCryptoParameters<NativePoly>;
template class LPCryptoParametersRLWE<NativePoly>;
template class LPPublicKeyEncryptionScheme<NativePoly>;

extern template class CryptoContextImpl<DCRTPoly>;

template class LPPublicKeyImpl<DCRTPoly>;
template class LPPrivateKeyImpl<DCRTPoly>;
template class LPEvalKeyImpl<DCRTPoly>;
template class LPEvalKeyRelinImpl<DCRTPoly>;
template class LPCryptoParameters<DCRTPoly>;
template class LPCryptoParametersRLWE<DCRTPoly>;
template class LPPublicKeyEncryptionScheme<DCRTPoly>;
}  // namespace lbcrypto
