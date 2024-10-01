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

#include "binfhe-base-params.h"
#include "lwe-pke.h"
#include "rlwe-ciphertext.h"
#include "rgsw-acckey.h"
#include "rgsw-acc.h"
#include "rgsw-acc-dm.h"
#include "rgsw-acc-cggi.h"
#include "rgsw-acc-lmkcdey.h"

#include <map>
#include <memory>
#include <vector>

namespace lbcrypto {

// The struct for storing bootstrapping keys
typedef struct {
    // refreshing key
    RingGSWACCKey BSkey;
    // switching key
    LWESwitchingKey KSkey;
    // public key
    LWEPublicKey Pkey;
} RingGSWBTKey;

/**
 * @brief Ring GSW accumulator schemes described in
 * https://eprint.iacr.org/2014/816, https://eprint.iacr.org/2020/086 and https://eprint.iacr.org/2022/198
 */
class BinFHEScheme {
public:
    BinFHEScheme() = default;

    explicit BinFHEScheme(BINFHE_METHOD method) {
        if (method == AP)
            ACCscheme = std::make_shared<RingGSWAccumulatorDM>();
        else if (method == GINX)
            ACCscheme = std::make_shared<RingGSWAccumulatorCGGI>();
        else if (method == LMKCDEY)
            ACCscheme = std::make_shared<RingGSWAccumulatorLMKCDEY>();
        else
            OPENFHE_THROW("method is invalid");
    }

    /**
   * Generates a refresh key
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param LWEsk a shared pointer to the secret key of the underlying additive
   * @param keygenMode enum to indicate generation of secret key only (SYM_ENCRYPT) or
   * secret key, public key pair (PUB_ENCRYPT)
   * @return a shared pointer to the refresh key
   */
    RingGSWBTKey KeyGen(const std::shared_ptr<BinFHECryptoParams>& params, ConstLWEPrivateKey& LWEsk,
                        KEYGEN_MODE keygenMode) const;

    /**
   * Evaluates a binary gate (calls bootstrapping as a subroutine)
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param gate the gate; can be AND, OR, NAND, NOR, XOR, or XOR
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct1 first ciphertext
   * @param ct2 second ciphertext
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalBinGate(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate, const RingGSWBTKey& EK,
                              ConstLWECiphertext& ct1, ConstLWECiphertext& ct2, bool extended = false) const;

    /**
   * Evaluates a binary gate on a vector of ciphertexts (calls bootstrapping as a subroutine).
   * The evaluation of the gates in this function is specific to 3 input and 4 input
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param gate the gate; can be for 3-input: AND3, OR3, MAJORITY, CMUX, for 4-input: AND4, OR4
   * @param EK a shared pointer to the bootstrapping keys
   * @param ctvector vector of ciphertexts
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalBinGate(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate, const RingGSWBTKey& EK,
                              const std::vector<LWECiphertext>& ctvector, bool extended = false) const;

    /**
   * Evaluates NOT gate
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param ct1 the input ciphertext
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalNOT(const std::shared_ptr<BinFHECryptoParams>& params, ConstLWECiphertext& ct) const;

    /**
   * Bootstraps a fresh ciphertext
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext Bootstrap(const std::shared_ptr<BinFHECryptoParams>& params, const RingGSWBTKey& EK,
                            ConstLWECiphertext& ct, bool extended = false) const;

    /**
   * Evaluate an arbitrary function
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param LUT the look-up table of the to-be-evaluated function
   * @param beta the error bound
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFunc(const std::shared_ptr<BinFHECryptoParams>& params, const RingGSWBTKey& EK,
                           ConstLWECiphertext& ct, const std::vector<NativeInteger>& LUT,
                           const NativeInteger& beta) const;

    /**
   * Evaluate a round down function
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param beta the error bound
   * @param roundbits by how many bits to round down
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFloor(const std::shared_ptr<BinFHECryptoParams>& params, const RingGSWBTKey& EK,
                            ConstLWECiphertext& ct, const NativeInteger& beta, uint32_t roundbits = 0) const;

    /**
   * Evaluate a sign function over large precision
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys map
   * @param ct input ciphertext
   * @param beta the error bound
   * @param schemeSwitch flag that indicates if it should be compatible to scheme switching
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalSign(const std::shared_ptr<BinFHECryptoParams>& params,
                           const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext& ct,
                           const NativeInteger& beta, bool schemeSwitch = false) const;

    /**
   * Evaluate digit decomposition over a large precision LWE ciphertext
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EKs a shared pointer to the bootstrapping keys map
   * @param ct input ciphertext
   * @param beta the error bound
   * @return a shared pointer to the resulting ciphertext
   */
    std::vector<LWECiphertext> EvalDecomp(const std::shared_ptr<BinFHECryptoParams>& params,
                                          const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext& ct,
                                          const NativeInteger& beta) const;

private:
    /**
   * Core bootstrapping operation
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param gate the gate; can be AND, OR, NAND, NOR, XOR, or XOR
   * @param ek a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @return the output RingLWE accumulator
   */
    RLWECiphertext BootstrapGateCore(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate,
                                     ConstRingGSWACCKey& ek, ConstLWECiphertext& ct) const;

    // Arbitrary function evaluation purposes

    /**
   * Core bootstrapping operation
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param ek a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param f function to evaluate in the functional bootstrapping
   * @param fmod modulus over which the function is defined
   * @return a shared pointer to the resulting ciphertext
   */
    template <typename Func>
    RLWECiphertext BootstrapFuncCore(const std::shared_ptr<BinFHECryptoParams>& params, ConstRingGSWACCKey& ek,
                                     ConstLWECiphertext& ct, const Func f, const NativeInteger& fmod) const;

    /**
   * Bootstraps a fresh ciphertext
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param f function to evaluate in the functional bootstrapping
   * @param fmod modulus over which the function is defined
   * @return the output RingLWE accumulator
   */
    template <typename Func>
    LWECiphertext BootstrapFunc(const std::shared_ptr<BinFHECryptoParams>& params, const RingGSWBTKey& EK,
                                ConstLWECiphertext& ct, const Func f, const NativeInteger& fmod) const;

protected:
    std::shared_ptr<LWEEncryptionScheme> LWEscheme{std::make_shared<LWEEncryptionScheme>()};
    std::shared_ptr<RingGSWAccumulator> ACCscheme{nullptr};

    /**
   * Checks type of input function
   *
   * @param lut look up table for the input function
   * @param mod modulus over which the function is defined
   * @return the function type: 0 for negacyclic, 1 for periodic, 2 for arbitrary
   */
    static uint32_t checkInputFunction(const std::vector<NativeInteger>& lut, NativeInteger mod) {
        size_t mid{lut.size() / 2};
        if (lut[0] == (mod - lut[mid])) {
            for (size_t i = 1; i < mid; ++i)
                if (lut[i] != (mod - lut[mid + i]))
                    return 2;
            return 0;
        }
        if (lut[0] == lut[mid]) {
            for (size_t i = 1; i < mid; ++i)
                if (lut[i] != lut[mid + i])
                    return 2;
            return 1;
        }
        return 2;
    }
};

}  // namespace lbcrypto

#endif
