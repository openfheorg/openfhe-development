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

#ifndef SRC_BINFHE_INCLUDE_RGSW_ACC_H_
#define SRC_BINFHE_INCLUDE_RGSW_ACC_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "rgsw-acckey.h"
#include "rgsw-acckey32.h"
#include "rgsw-cryptoparameters.h"
#include "rlwe-ciphertext.h"

namespace lbcrypto {

/**
 * @brief Ring GSW accumulator schemes described in
 * https://eprint.iacr.org/2014/816, https://eprint.iacr.org/2020/086 and https://eprint.iacr.org/2022/198
 */
class RingGSWAccumulator {
  public:
    RingGSWAccumulator() = default;

#if NATIVEINT != 32
    /**
   * Key generation for internal Ring GSW directly in the 32-bit internal key representation, used when the modulus Q
   * fits a 32-bit word. Takes the same arguments as KeyGenAcc: the RingGSW scheme parameters, the secret key
   * polynomial in the EVALUATION representation, and the LWE secret key. The base implementation returns nullptr,
   * meaning the accumulator does not implement it, so callers fall back to KeyGenAcc
   *
   * @return a shared pointer to the 32-bit refreshing key, or nullptr when not implemented
   */
    virtual RingGSWACCKey32 KeyGenAcc32(const std::shared_ptr<RingGSWCryptoParams>&, const NativePoly&,
                                        ConstLWEPrivateKey&) const {
        return nullptr;
    }

    /**
   * Main accumulator function (blind rotation) on the 32-bit internal key, bit-identical to EvalAcc on the 64-bit
   * key. Takes the same arguments as EvalAcc: the RingGSW scheme parameters, the 32-bit accumulator key, the
   * accumulator to update, and the value to update it with. Implemented by every accumulator that implements
   * KeyGenAcc32; the base implementation throws
   */
    virtual void EvalAcc32(const std::shared_ptr<RingGSWCryptoParams>&, ConstRingGSWACCKey32&, RLWECiphertext&,
                           const NativeVector&) const {
        OPENFHE_THROW("32-bit internal evaluation is not supported by this accumulator");
    }
#endif

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
        OPENFHE_THROW("Operation not supported");
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
        OPENFHE_THROW("Operation not supported");
    }

    /**
   * The signed digit decomposition which takes an RLWE ciphertext input and outputs a vector of its digits, i.e., an
   * RLWE' ciphertext. The current gadget base is used when no coefficient index is provided.
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param input input RLWE ciphertext
   * @param output output RLWE' ciphertext
   */
    void SignedDigitDecompose(const std::shared_ptr<RingGSWCryptoParams>& params, const std::vector<NativePoly>& input,
                              std::vector<NativePoly>& output) const;

    /**
   * The signed digit decomposition which takes an RLWE ciphertext input and outputs a vector of its digits, i.e., an
   * RLWE' ciphertext, using the gadget base associated with the given LWE secret-key coefficient index.
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param input input RLWE ciphertext
   * @param output output RLWE' ciphertext
   * @param index LWE secret-key coefficient index
   */
    void SignedDigitDecompose(const std::shared_ptr<RingGSWCryptoParams>& params, const std::vector<NativePoly>& input,
                              std::vector<NativePoly>& output, uint32_t index) const;

    /**
   * The signed digit decomposition of an RLWE ciphertext into an RLWE' ciphertext with explicit gadget parameters.
   * Both overloads of SignedDigitDecompose for RLWE ciphertexts forward here. The excess-H decomposition produces
   * 2(digitsG - 1) digit polynomials, the first digit being dropped by the approximate gadget decomposition
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param input input RLWE ciphertext
   * @param output output RLWE' ciphertext, sized by the caller to 2(digitsG - 1) polynomials
   * @param bp the gadget parameters (base, digit count, digit width) to decompose with
   */
    void SignedDigitDecomposeImpl(const std::shared_ptr<RingGSWCryptoParams>& params,
                                  const std::vector<NativePoly>& input, std::vector<NativePoly>& output,
                                  const RingGSWCryptoParams::BaseGParams& bp) const;

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

#endif  // SRC_BINFHE_INCLUDE_RGSW_ACC_H_
