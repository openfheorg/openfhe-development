// @file pubkeylp-ser.h - serialize keys; include this in any app that needs to
// serialize these objects
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

#ifndef LBCRYPTO_CRYPTO_PUBKEYLPSER_H
#define LBCRYPTO_CRYPTO_PUBKEYLPSER_H

#include "palisade.h"
#include "utils/serial.h"

extern template class lbcrypto::LPCryptoParameters<lbcrypto::Poly>;
extern template class lbcrypto::LPCryptoParameters<lbcrypto::NativePoly>;

extern template class lbcrypto::LPCryptoParametersRLWE<lbcrypto::Poly>;
extern template class lbcrypto::LPCryptoParametersRLWE<lbcrypto::NativePoly>;

extern template class lbcrypto::LPPublicKeyEncryptionScheme<lbcrypto::Poly>;
extern template class lbcrypto::LPPublicKeyEncryptionScheme<
    lbcrypto::NativePoly>;

extern template class lbcrypto::LPEvalKeyImpl<lbcrypto::Poly>;
extern template class lbcrypto::LPEvalKeyImpl<lbcrypto::NativePoly>;

extern template class lbcrypto::LPEvalKeyRelinImpl<lbcrypto::Poly>;
extern template class lbcrypto::LPEvalKeyRelinImpl<lbcrypto::NativePoly>;

extern template class lbcrypto::LPCryptoParameters<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPCryptoParametersRLWE<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPPublicKeyEncryptionScheme<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPEvalKeyImpl<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPEvalKeyRelinImpl<lbcrypto::DCRTPoly>;

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParameters<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParameters<lbcrypto::NativePoly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersRLWE<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersRLWE<lbcrypto::NativePoly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionScheme<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(
    lbcrypto::LPPublicKeyEncryptionScheme<lbcrypto::NativePoly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyImpl<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyImpl<lbcrypto::NativePoly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyRelinImpl<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyRelinImpl<lbcrypto::NativePoly>);

CEREAL_REGISTER_POLYMORPHIC_RELATION(
    lbcrypto::LPEvalKeyImpl<lbcrypto::Poly>,
    lbcrypto::LPEvalKeyRelinImpl<lbcrypto::Poly>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(
    lbcrypto::LPEvalKeyImpl<lbcrypto::NativePoly>,
    lbcrypto::LPEvalKeyRelinImpl<lbcrypto::NativePoly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParameters<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersRLWE<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionScheme<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyImpl<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPEvalKeyRelinImpl<lbcrypto::DCRTPoly>);
CEREAL_REGISTER_POLYMORPHIC_RELATION(
    lbcrypto::LPEvalKeyImpl<lbcrypto::DCRTPoly>,
    lbcrypto::LPEvalKeyRelinImpl<lbcrypto::DCRTPoly>);

#endif
