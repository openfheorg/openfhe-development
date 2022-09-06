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

#ifndef BINFHE_FHEW_H
#define BINFHE_FHEW_H

#include <map>
#include <vector>
#include <memory>
#include <string>

#include "binfhe-base-params.h"
#include "lwe-pke.h"
#include "rlwe-ciphertext.h"
#include "rgsw-acckey.h"
#include "rgsw-acc.h"
#include "rgsw-acc-dm.h"
#include "rgsw-acc-cggi.h"

namespace lbcrypto {

// The struct for storing bootstrapping keys
typedef struct {
    // refreshing key
    RingGSWACCKey BSkey;
    // switching key
    LWESwitchingKey KSkey;
} RingGSWBTKey;

/**
 * @brief Ring GSW accumulator schemes described in
 * https://eprint.iacr.org/2014/816 and https://eprint.iacr.org/2020/08
 */
class BinFHEScheme {
public:
    BinFHEScheme() {
        LWEscheme = std::make_shared<LWEEncryptionScheme>();
    }

    void SetACCTechnique(BINFHEMETHOD method) {
        if (method == AP) {
            ACCscheme = std::make_shared<RingGSWAccumulatorDM>();
        }
        else if (method == GINX) {
            ACCscheme = std::make_shared<RingGSWAccumulatorCGGI>();
        }
        else
            OPENFHE_THROW(config_error, "method is invalid");
    }

    /**
   * Generates a refreshing key
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param LWEsk a shared pointer to the secret key of the underlying additive
   * LWE scheme
   * @return a shared pointer to the refreshing key
   */
    RingGSWBTKey KeyGen(const std::shared_ptr<BinFHECryptoParams> params, ConstLWEPrivateKey LWEsk) const;

    /**
   * Evaluates a binary gate (calls bootstrapping as a subroutine)
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param gate the gate; can be AND, OR, NAND, NOR, XOR, or XOR
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 first ciphertext
   * @param ct2 second ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalBinGate(const std::shared_ptr<BinFHECryptoParams> params, const BINGATE gate,
                              const RingGSWBTKey& EK, ConstLWECiphertext ct1, ConstLWECiphertext ct2) const;

    /**
   * Evaluates NOT gate
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param ct1 the input ciphertext
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalNOT(const std::shared_ptr<BinFHECryptoParams> params, ConstLWECiphertext ct1) const;

    /**
   * Bootstraps a fresh ciphertext
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext Bootstrap(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                            ConstLWECiphertext ct1) const;

    /**
   * Evaluate an arbitrary function
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param LUT the look-up table of the to-be-evaluated function
   * @param beta the error bound
   * @param bigger_q the ciphertext modulus
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFunc(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                           ConstLWECiphertext ct1, const std::vector<NativeInteger>& LUT, const NativeInteger beta,
                           const NativeInteger bigger_q) const;

    /**
   * Evaluate a round down function
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param beta the error bound
   * @param bigger_q the ciphertext modulus
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFloor(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                            ConstLWECiphertext ct1, const NativeInteger beta, const NativeInteger bigger_q) const;

    /**
   * Evaluate a sign function over large precision
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param beta the error bound
   * @param bigger_q the ciphertext modulus
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalSign(const std::shared_ptr<BinFHECryptoParams> params,
                           const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext ct1,
                           const NativeInteger beta, const NativeInteger bigger_q) const;

    /**
   * Evaluate a degit decomposition process over a large precision LWE ciphertext
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param beta the error bound
   * @param bigger_q the ciphertext modulus
   * @return a shared pointer to the resulting ciphertext
   */
    std::vector<LWECiphertext> EvalDecomp(const std::shared_ptr<BinFHECryptoParams> params,
                                          const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext ct1,
                                          const NativeInteger beta, const NativeInteger bigger_q) const;

private:
    /**
   * Core bootstrapping operation
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param gate the gate; can be AND, OR, NAND, NOR, XOR, or XOR
   * @param &a first part of the input LWE ciphertext
   * @param &b second part of the input LWE ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @return the output RingLWE accumulator
   */
    RLWECiphertext BootstrapCore(const std::shared_ptr<BinFHECryptoParams> params, const BINGATE gate,
                                 const RingGSWACCKey ek, ConstLWECiphertext ct) const;

    // Below is for arbitrary function evaluation purpose

    /**
   * Core bootstrapping operation
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @return a shared pointer to the resulting ciphertext
   */
    template <typename Func>
    RLWECiphertext BootstrapCore(const std::shared_ptr<BinFHECryptoParams> params, const BINGATE gate,
                                 const RingGSWACCKey ek, ConstLWECiphertext ct, const Func f,
                                 const NativeInteger bigger_q) const;

    /**
   * Bootstraps a fresh ciphertext
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param gate the gate; can be AND, OR, NAND, NOR, XOR, or XOR
   * @param &a first part of the input LWE ciphertext
   * @param &b second part of the input LWE ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @return the output RingLWE accumulator
   */
    template <typename Func>
    LWECiphertext Bootstrap(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                            ConstLWECiphertext ct1, const Func f, const NativeInteger bigger_q) const;

protected:
    std::shared_ptr<LWEEncryptionScheme> LWEscheme;
    std::shared_ptr<RingGSWAccumulator> ACCscheme;
};

}  // namespace lbcrypto

#endif
