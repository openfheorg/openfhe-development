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

#include "rlwe-ciphertext.h"
#include "rgsw-acckey.h"
#include "rgsw-cryptoparameters.h"

#include <vector>
#include <memory>

namespace lbcrypto {

/**
 * @brief Ring GSW accumulator schemes described in
 * https://eprint.iacr.org/2014/816, https://eprint.iacr.org/2020/086 and https://eprint.iacr.org/2022/198
 */
class RingGSWAccumulator {
public:
    RingGSWAccumulator() = default;

    /**
   * Key generation for internal Ring GSW
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param skNTT secret key polynomial in the EVALUATION representation
   * @param LWEsk the secret key
   * @return a shared pointer to the resulting keys
   */
    virtual RingGSWACCKey KeyGenAcc(const std::shared_ptr<RingGSWCryptoParams>& params, const NativePoly& skNTT,
                                    ConstLWEPrivateKey& LWEsk) const {
        OPENFHE_THROW(not_implemented_error, "KeyGenACC operation not supported");
    }

    /**
   * Main accumulator function used in bootstrapping
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param ek the accumulator key
   * @param acc previous value of the accumulator
   * @param a value to update the accumulator with
   */
    virtual void EvalAcc(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWACCKey& ek,
                         RLWECiphertext& acc, const NativeVector& a) const {
        OPENFHE_THROW(not_implemented_error, "ACC operation not supported");
    }

    /**
   * The signed digit decomposition which takes an RLWE ciphertext input and outputs a vector of its digits, i.e., an
   * RLWE' ciphertext
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param input input RLWE ciphertext
   * @param output output RLWE' ciphertext
   */
    void SignedDigitDecompose(const std::shared_ptr<RingGSWCryptoParams>& params, const std::vector<NativePoly>& input,
                              std::vector<NativePoly>& output) const;

    /**
   * The signed digit decomposition which takes a ring element input and outputs a vector of its digits, i.e.,
   * decompose(a) = (a_0, ..., a_{d-1}) = R^d.
   * Only for automorphism key switching LMKCDEY
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param input input ring element
   * @param output decomposed value
   */
    void SignedDigitDecompose(const std::shared_ptr<RingGSWCryptoParams>& params, const NativePoly& input,
                              std::vector<NativePoly>& output) const;
};
}  // namespace lbcrypto

#endif
