// @file bfv-ser.h -- serialize BFV; include this in any app that needs to
// serialize this scheme
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

#ifndef LBCRYPTO_CRYPTO_BFVSER_H
#define LBCRYPTO_CRYPTO_BFVSER_H

#include "palisade.h"
#include "utils/serial.h"

extern template class lbcrypto::LPCryptoParametersBFV<lbcrypto::Poly>;
extern template class lbcrypto::LPCryptoParametersBFV<lbcrypto::NativePoly>;

extern template class lbcrypto::LPPublicKeyEncryptionSchemeBFV<lbcrypto::Poly>;
extern template class lbcrypto::LPPublicKeyEncryptionSchemeBFV<
    lbcrypto::NativePoly>;

extern template class lbcrypto::LPAlgorithmBFV<lbcrypto::Poly>;
extern template class lbcrypto::LPAlgorithmBFV<lbcrypto::NativePoly>;

extern template class lbcrypto::LPAlgorithmPREBFV<lbcrypto::Poly>;
extern template class lbcrypto::LPAlgorithmPREBFV<lbcrypto::NativePoly>;

extern template class lbcrypto::LPAlgorithmSHEBFV<lbcrypto::Poly>;
extern template class lbcrypto::LPAlgorithmSHEBFV<lbcrypto::NativePoly>;

extern template class lbcrypto::LPAlgorithmParamsGenBFV<lbcrypto::Poly>;
extern template class lbcrypto::LPAlgorithmParamsGenBFV<lbcrypto::NativePoly>;

extern template class lbcrypto::LPCryptoParametersBFV<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPPublicKeyEncryptionSchemeBFV<
    lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPAlgorithmBFV<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPAlgorithmPREBFV<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPAlgorithmSHEBFV<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPAlgorithmParamsGenBFV<lbcrypto::DCRTPoly>;

CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersBFV<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersBFV<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(lbcrypto::LPCryptoParametersBFV<lbcrypto::DCRTPoly>);

CEREAL_REGISTER_TYPE(lbcrypto::LPPublicKeyEncryptionSchemeBFV<lbcrypto::Poly>);
CEREAL_REGISTER_TYPE(
    lbcrypto::LPPublicKeyEncryptionSchemeBFV<lbcrypto::NativePoly>);
CEREAL_REGISTER_TYPE(
    lbcrypto::LPPublicKeyEncryptionSchemeBFV<lbcrypto::DCRTPoly>);

#endif
