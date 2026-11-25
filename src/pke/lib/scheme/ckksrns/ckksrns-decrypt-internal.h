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
 * Helpers shared by the CKKS decryption code paths. This header is internal to the library and is not installed.
 */

#ifndef SRC_PKE_LIB_SCHEME_CKKSRNS_CKKSRNS_DECRYPT_INTERNAL_H_
#define SRC_PKE_LIB_SCHEME_CKKSRNS_CKKSRNS_DECRYPT_INTERNAL_H_

#include <cstddef>

#include "ciphertext.h"
#include "lattice/lat-hal.h"

namespace lbcrypto {
namespace detail {

/**
 * Rescales a CKKS ciphertext in place. This is the implementation of
 * LeveledSHECKKSRNS::ModReduceInternalInPlace; unlike the SchemeBase wrapper of that method, it does not
 * require LEVELEDSHE to be enabled.
 *
 * @param ciphertext the ciphertext to rescale.
 * @param levels the number of towers to drop.
 */
void ModReduceInternalInPlaceCKKSRNS(Ciphertext<DCRTPoly>& ciphertext, size_t levels);

/**
 * Rescales a CKKS ciphertext with pending rescales (noise scaling degree > 1) to noise scaling degree 1 when
 * its context uses NOISE_FLOODING_DECRYPT. One rescale is done per degree above 1.
 *
 * The flooding noise is calibrated for a ciphertext that is decoded by dividing by a single scaling factor.
 * Decoding at a higher degree divides by a larger factor and suppresses the flooding noise, so decryption
 * rescales first. The rescale is done in both EXEC_NOISE_ESTIMATION and EXEC_EVALUATION, so the noise is
 * estimated for the ciphertext that gets flooded, including the rounding error of the rescale.
 *
 * Any other ciphertext (another scheme, another decryption noise mode, degree 1) is returned unchanged.
 *
 * @param ciphertext the ciphertext to be decrypted.
 * @return the input ciphertext if no rescale is needed, otherwise a rescaled copy.
 * @throws OpenFHEException if too few towers are left for the pending rescales.
 */
ConstCiphertext<DCRTPoly> RescaleForFloodingDecryptCKKSRNS(ConstCiphertext<DCRTPoly> ciphertext);

}  // namespace detail
}  // namespace lbcrypto

#endif  // SRC_PKE_LIB_SCHEME_CKKSRNS_CKKSRNS_DECRYPT_INTERNAL_H_
