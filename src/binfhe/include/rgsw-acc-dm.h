//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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

#ifndef SRC_BINFHE_INCLUDE_RGSW_ACC_DM_H_
#define SRC_BINFHE_INCLUDE_RGSW_ACC_DM_H_

#include <cstdint>
#include <memory>

#include "rgsw-acc.h"

namespace lbcrypto {

/**
 * @brief Ring GSW accumulator schemes described in
 * https://eprint.iacr.org/2014/816 and https://eprint.iacr.org/2020/086
 */
class RingGSWAccumulatorDM final : public RingGSWAccumulator {
  public:
    RingGSWAccumulatorDM() = default;

    /**
     * Key generation for internal Ring GSW as described in https://eprint.iacr.org/2020/086
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param skNTT secret key polynomial in the EVALUATION representation
     * @param LWEsk the secret key
     * @return a shared pointer to the resulting keys
     */
    RingGSWACCKey KeyGenAcc(const std::shared_ptr<RingGSWCryptoParams>& params, const NativePoly& skNTT,
                            ConstLWEPrivateKey& LWEsk) const override;

#if NATIVEINT != 32
    /**
     * Key generation for internal Ring GSW as described in https://eprint.iacr.org/2020/086, producing the refreshing
     * key directly in its 32-bit internal form: the RGSW encryptions are sampled on 32-bit words, so the 64-bit key
     * is never materialised. Used when Q fits a 32-bit word (RingGSWACCKey32Impl::Fits)
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param skNTT secret key polynomial in the EVALUATION representation
     * @param LWEsk the secret key
     * @return a shared pointer to the resulting 32-bit keys, laid out as [n][baseR][digitsR] like the 64-bit key
     */
    RingGSWACCKey32 KeyGenAcc32(const std::shared_ptr<RingGSWCryptoParams>& params, const NativePoly& skNTT,
                                ConstLWEPrivateKey& LWEsk) const override;

    /**
     * Main accumulator function used in bootstrapping - AP variant on the 32-bit internal key. The accumulator is
     * narrowed to 32 bits, updated with 32-bit external products, and widened back; the result is bit-identical to
     * EvalAcc on the 64-bit key
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param ek the 32-bit accumulator key
     * @param acc previous value of the accumulator
     * @param a value to update the accumulator with
     */
    void EvalAcc32(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWACCKey32& ek, RLWECiphertext& acc,
                   const NativeVector& a) const override;
#endif

    /**
     * Main accumulator function used in bootstrapping - AP variant
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
     * DM Key generation for internal Ring GSW as described in https://eprint.iacr.org/2014/816
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param skNTT secret key polynomial in the EVALUATION representation
     * @param m a plaintext
     * @param index LWE secret-key coefficient index
     * @return a shared pointer to the resulting keys
     */
    RingGSWEvalKey KeyGenDM(const std::shared_ptr<RingGSWCryptoParams>& params, const NativePoly& skNTT, LWEPlaintext m,
                            uint32_t index) const;

    /**
     * DM Accumulation as described in https://eprint.iacr.org/2020/086
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param ek evaluation key for Ring GSW
     * @param acc previous value of the accumulator
     * @param index LWE secret-key coefficient index
     */
    void AddToAccDM(const std::shared_ptr<RingGSWCryptoParams>& params, ConstRingGSWEvalKey& ek, RLWECiphertext& acc,
                    uint32_t index) const;
};

}  // namespace lbcrypto

#endif  // SRC_BINFHE_INCLUDE_RGSW_ACC_DM_H_
