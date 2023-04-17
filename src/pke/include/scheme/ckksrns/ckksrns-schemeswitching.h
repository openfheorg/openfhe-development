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

#ifndef LBCRYPTO_CRYPTO_CKKSRNS_SCHEMESWITCH_H
#define LBCRYPTO_CRYPTO_CKKSRNS_SCHEMESWITCH_H

// Andreea: see what we need
#include "constants.h"
#include "encoding/plaintext-fwd.h"
#include "schemerns/rns-fhe.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include "utils/caller_info.h"
#include "../../binfhe/include/binfhecontext.h"
#include "../../binfhe/include/lwe-pke.h"
#include "../../binfhe/include/lwe-ciphertext.h"

#include <memory>
#include <string>
#include <utility>
#include <map>
#include <vector>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class FHECKKSRNSSS : public FHERNS {
    using ParmType = typename DCRTPoly::Params;

public:
    virtual ~FHECKKSRNSSS() {}

    // //------------------------------------------------------------------------------
    // // Precomputations for SlotsToCoeffs in scheme switching CKKS to FHE
    // //------------------------------------------------------------------------------

    // std::vector<ConstPlaintext> EvalLTPrecomputeSS(const CryptoContextImpl<DCRTPoly>& cc,
    //                                                const std::vector<std::vector<std::complex<double>>>& A,
    //                                                const std::vector<std::vector<std::complex<double>>>& B,
    //                                                uint32_t dim1 = 0, double scale = 1) const;

    // Ciphertext<DCRTPoly> EvalLTWithPrecomputeSS(const CryptoContextImpl<DCRTPoly>& cc,
    //                                             ConstCiphertext<DCRTPoly> ctxt,
    //                                             const std::vector<ConstPlaintext>& A,
    //                                             uint32_t dim1 = 0) const;

    // std::vector<std::vector<ConstPlaintext>> EvalSlotsToCoeffsPrecomputeSS(const CryptoContextImpl<DCRTPoly>& cc,
    //                                                                        const std::vector<std::complex<double>>& A,
    //                                                                        const std::vector<uint32_t>& rotGroup,
    //                                                                        bool flag_i, double scale = 1,
    //                                                                        uint32_t L = 0) const;

    // //------------------------------------------------------------------------------
    // // Evaluation for scheme switching CKKS to FHE: SlotsToCoeffs
    // //------------------------------------------------------------------------------

    // Ciphertext<DCRTPoly> EvalLinearTransformSS(const std::vector<ConstPlaintext>& A,
    //                                            ConstCiphertext<DCRTPoly> ctxt) const;

    // Ciphertext<DCRTPoly> EvalSlotsToCoeffsSS(const CryptoContextImpl<DCRTPoly>& cc, ConstCiphertext<DCRTPoly> ctxt, uint64_t slots) const;

    //------------------------------------------------------------------------------
    // Scheme Switching Wrapper
    //------------------------------------------------------------------------------

    void EvalSchemeSwitchingSetup(const CryptoContextImpl<DCRTPoly>& cc, std::vector<uint32_t> levelBudget,
                                  std::vector<uint32_t> dim1, uint32_t slots, uint32_t correctionFactor) override;

    void EvalSchemeSwitchingKeyGen(const PrivateKey<DCRTPoly> privateKey, uint32_t slots) override;

    void EvalSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext, uint32_t numIterations,
                             uint32_t precision) const override;

    std::pair<BinFHEContext, LWEPrivateKey> EvalCKKStoFHEWSetup(const CryptoContextImpl<DCRTPoly>& cc, bool dynamic,
                                                                uint32_t logQ, SecurityLevel sl,
                                                                uint32_t numSlotsCKKS) override;

    std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> EvalCKKStoFHEWKeyGen(const KeyPair<DCRTPoly>& keyPair,
                                                                             LWEPrivateKey& lwesk) override;

    std::vector<std::shared_ptr<LWECiphertextImpl>> EvalCKKStoFHEW(ConstCiphertext<DCRTPoly> ciphertext, double scale,
                                                                   uint32_t numCtxts) const override;

    //------------------------------------------------------------------------------
    // SERIALIZATION
    //------------------------------------------------------------------------------

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<FHERNS>(this));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<FHERNS>(this));
    }

    std::string SerializedObjectName() const {
        return "FHECKKSRNSSS";
    }

private:
    //     //------------------------------------------------------------------------------
    //     // Complex Plaintext Functions, copied from ckksrns-fhe, figure out how to share them
    //     //------------------------------------------------------------------------------
    //     Plaintext MakeAuxPlaintext(const CryptoContextImpl<DCRTPoly>& cc, const std::shared_ptr<ParmType> params,
    //                                const std::vector<std::complex<double>>& value, size_t noiseScaleDeg, uint32_t level,
    //                                usint slots) const;

    //     Ciphertext<DCRTPoly> EvalMultExt(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const;

    //     void EvalAddExtInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) const;

    //     Ciphertext<DCRTPoly> EvalAddExt(ConstCiphertext<DCRTPoly> ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) const;

    //     /**
    //    * Set modulus and recalculates the vector values to fit the modulus
    //    *
    //    * @param &vec input vector
    //    * @param &bigValue big bound of the vector values.
    //    * @param &modulus modulus to be set for vector.
    //    */
    //     void FitToNativeVector(uint32_t ringDim, const std::vector<int64_t>& vec, int64_t bigBound,
    //                            NativeVector* nativeVec) const;

    // #if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
    //     /**
    //    * Set modulus and recalculates the vector values to fit the modulus
    //    *
    //    * @param &vec input vector
    //    * @param &bigValue big bound of the vector values.
    //    * @param &modulus modulus to be set for vector.
    //    */
    //     void FitToNativeVector(uint32_t ringDim, const std::vector<__int128>& vec, __int128 bigBound,
    //                            NativeVector* nativeVec) const;

    //     constexpr __int128 Max128BitValue() const {
    //         // 2^127-2^73-1 - max value that could be rounded to int128_t
    //         return ((unsigned __int128)1 << 127) - ((unsigned __int128)1 << 73) - (unsigned __int128)1;
    //     }

    //     inline bool is128BitOverflow(double d) const {
    //         const double EPSILON = 0.000001;

    //         return EPSILON < (std::abs(d) - Max128BitValue());
    //     }
    // #else  // NATIVEINT == 64
    //     constexpr int64_t Max64BitValue() const {
    //         // 2^63-2^9-1 - max value that could be rounded to int64_t
    //         return 9223372036854775295;
    //     }

    //     inline bool is64BitOverflow(double d) const {
    //         const double EPSILON = 0.000001;

    //         return EPSILON < (std::abs(d) - Max64BitValue());
    //     }
    // #endif

    // the LWE cryptocontext to generate when scheme switching from CKKS
    BinFHEContext
        m_ccLWE;  // Andreea: can't work with it "the object has type qualifiers that are not compatible with the member function""
    // the associated ciphertext modulus Q for the LWE cryptocontext
    uint64_t m_modulus_LWE;
    // switching key from CKKS to FHEW ("outer", i.e., not for an inner functionality)
    EvalKey<DCRTPoly> m_CKKStoFHEWswk;
    // number of slots encoded in the CKKS ciphertext
    uint32_t m_numSlotsCKKS;
    // Andreea: temporary for debugging, remove later
    PrivateKey<DCRTPoly> m_CKKSsk;
    PrivateKey<DCRTPoly> m_RLWELWEsk;
};

}  // namespace lbcrypto

#endif
