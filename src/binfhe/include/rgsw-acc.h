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

#ifndef _RGSW_FHE_H_
#define _RGSW_FHE_H_

#include <map>
#include <vector>
#include <memory>
#include <string>

#include "rgsw-acckey.h"
#include "rgsw-ciphertext.h"
#include "rgsw-cryptoparameters.h"

namespace lbcrypto {

/**
 * @brief Ring GSW accumulator schemes described in
 * https://eprint.iacr.org/2014/816 and https://eprint.iacr.org/2020/08
 */
class RingGSWAccumulator {
public:
    RingGSWAccumulator() {}

    /**
   * Internal RingGSW encryption used in generating the refreshing key
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param skFFT secret key polynomial in the EVALUATION representation
   * @param m plaintext (corresponds to a lookup entry for the LWE scheme secret
   * key)
   * @return a shared pointer to the resulting ciphertext
   */
    virtual RingGSWACCKey KeyGenBlindRotation(const std::shared_ptr<RingGSWCryptoParams> params,
                                              const NativePoly& skNTT, ConstLWEPrivateKey LWEsk) const {
        OPENFHE_THROW(not_implemented_error, "KeyGenACC operation not supported");
    }

    /**
   * Main accumulator function used in bootstrapping - AP variant
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &input input ciphertext
   * @param acc previous value of the accumulator
   */
    virtual void EvalBlindRotation(const std::shared_ptr<RingGSWCryptoParams> params, const RingGSWACCKey ek,
                                   RingGSWCiphertext& acc, const NativeVector& a) const {
        OPENFHE_THROW(not_implemented_error, "BlindRotate operation not supported");
    }

    /**
   * Takes an RLWE ciphertext input and outputs a vector of its digits, i.e., an
   * RLWE' ciphertext
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &input input RLWE ciphertext
   * @param *output input RLWE ciphertext
   */
    void SignedDigitDecompose(const std::shared_ptr<RingGSWCryptoParams> params, const std::vector<NativePoly>& input,
                              std::vector<NativePoly>* output) const;
};

}  // namespace lbcrypto

#endif
