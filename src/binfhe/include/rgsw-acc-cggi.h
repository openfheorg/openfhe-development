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

#ifndef _RGSW_ACC_CGGI_H_
#define _RGSW_ACC_CGGI_H_

#include "rgsw-acc.h"

#include <memory>

namespace lbcrypto {

/**
 * @brief Ring GSW accumulator schemes described in
 * https://eprint.iacr.org/2014/816 and https://eprint.iacr.org/2020/086
 */
class RingGSWAccumulatorCGGI final : public RingGSWAccumulator {
public:
    RingGSWAccumulatorCGGI() = default;

    /**
   * Key generation for internal Ring GSW as described in https://eprint.iacr.org/2018/421.pdf
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param skNTT secret key polynomial in the EVALUATION representation
   * @param LWEsk the secret key
   * @return a shared pointer to the resulting keys
   */
    RingGSWACCKey KeyGenAcc(const std::shared_ptr<RingGSWCryptoParams>& params, const NativePoly& skNTT,
                            ConstLWEPrivateKey& LWEsk) const override;

    /**
   * Main accumulator function used in bootstrapping - GINX variant
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param ek the accumulator key
   * @param acc previous value of the accumulator
   * @param a value to update the accumulator with
   */
    void EvalAcc(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWACCKey& ek, RLWECiphertext& acc,
                 const NativeVector& a) const override;

private:
    /**
   * Key generation for internal Ring GSW as described in https://eprint.iacr.org/2020/086
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param skNTT secret key polynomial in the EVALUATION representation
   * @param m a plaintext
   * @return a shared pointer to the resulting keys
   */
    RingGSWEvalKey KeyGenCGGI(const std::shared_ptr<RingGSWCryptoParams>& params, const NativePoly& skNTT,
                              LWEPlaintext m) const;

    /**
   * CGGI Accumulation as described in https://eprint.iacr.org/2020/086
   * with ternary MUX introduced in paper https://eprint.iacr.org/2022/074.pdf section 5
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param ek1, ek2 evaluation keys for Ring GSW
   * @param a a value to add to the accumulator
   * @param acc previous value of the accumulator
   */
    void AddToAccCGGI(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWEvalKey& ek1,
                      ConstRingGSWEvalKey& ek2, const NativeInteger& a, RLWECiphertext& acc) const;
};

}  // namespace lbcrypto

#endif  // _RGSW_ACC_CGGI_H_
