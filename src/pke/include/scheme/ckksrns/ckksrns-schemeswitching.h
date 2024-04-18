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

#include "constants.h"
#include "schemerns/rns-fhe.h"

#include "binfhecontext.h"
#include "lwe-pke.h"
#include "lwe-ciphertext.h"
#include "scheme/scheme-swch-params.h"

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

class SWITCHCKKSRNS : public FHERNS {
    using ParmType = typename DCRTPoly::Params;

public:
    virtual ~SWITCHCKKSRNS() {}

    //------------------------------------------------------------------------------
    // Scheme Switching Wrappers
    //------------------------------------------------------------------------------

    LWEPrivateKey EvalCKKStoFHEWSetup(const SchSwchParams& params) override;

    std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> EvalCKKStoFHEWKeyGen(const KeyPair<DCRTPoly>& keyPair,
                                                                             ConstLWEPrivateKey& lwesk) override;

    void EvalCKKStoFHEWPrecompute(const CryptoContextImpl<DCRTPoly>& cc, double scale) override;

    std::vector<std::shared_ptr<LWECiphertextImpl>> EvalCKKStoFHEW(ConstCiphertext<DCRTPoly> ciphertext,
                                                                   uint32_t numCtxts) override;

    void EvalFHEWtoCKKSSetup(const CryptoContextImpl<DCRTPoly>& ccCKKS, const std::shared_ptr<BinFHEContext>& ccLWE,
                             uint32_t numSlotsCKKS, uint32_t logQ) override;

    std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> EvalFHEWtoCKKSKeyGen(const KeyPair<DCRTPoly>& keyPair,
                                                                             ConstLWEPrivateKey& lwesk,
                                                                             uint32_t numSlots, uint32_t numCtxts,
                                                                             uint32_t dim1, uint32_t L) override;

    Ciphertext<DCRTPoly> EvalFHEWtoCKKS(std::vector<std::shared_ptr<LWECiphertextImpl>>& LWECiphertexts,
                                        uint32_t numCtxts, uint32_t numSlots, uint32_t p, double pmin, double pmax,
                                        uint32_t dim1) const override;

    LWEPrivateKey EvalSchemeSwitchingSetup(const SchSwchParams& params) override;

    std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> EvalSchemeSwitchingKeyGen(const KeyPair<DCRTPoly>& keyPair,
                                                                                  ConstLWEPrivateKey& lwesk) override;

    void EvalCompareSwitchPrecompute(const CryptoContextImpl<DCRTPoly>& ccCKKS, uint32_t pLWE, double scaleSign,
                                     bool unit) override;

    Ciphertext<DCRTPoly> EvalCompareSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext1,
                                                    ConstCiphertext<DCRTPoly> ciphertext2, uint32_t numCtxts,
                                                    uint32_t numSlots, uint32_t pLWE, double scaleSign,
                                                    bool unit) override;

    std::vector<Ciphertext<DCRTPoly>> EvalMinSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext,
                                                             PublicKey<DCRTPoly> publicKey, uint32_t numValues,
                                                             uint32_t numSlots, uint32_t pLWE,
                                                             double scaleSign) override;

    std::vector<Ciphertext<DCRTPoly>> EvalMinSchemeSwitchingAlt(ConstCiphertext<DCRTPoly> ciphertext,
                                                                PublicKey<DCRTPoly> publicKey, uint32_t numValues,
                                                                uint32_t numSlots, uint32_t pLWE,
                                                                double scaleSign) override;

    std::vector<Ciphertext<DCRTPoly>> EvalMaxSchemeSwitching(ConstCiphertext<DCRTPoly> ciphertext,
                                                             PublicKey<DCRTPoly> publicKey, uint32_t numValues,
                                                             uint32_t numSlots, uint32_t pLWE,
                                                             double scaleSign) override;

    std::vector<Ciphertext<DCRTPoly>> EvalMaxSchemeSwitchingAlt(ConstCiphertext<DCRTPoly> ciphertext,
                                                                PublicKey<DCRTPoly> publicKey, uint32_t numValues,
                                                                uint32_t numSlots, uint32_t pLWE,
                                                                double scaleSign) override;

    std::shared_ptr<lbcrypto::BinFHEContext> GetBinCCForSchemeSwitch() override {
        return m_ccLWE;
    }
    void SetBinCCForSchemeSwitch(std::shared_ptr<lbcrypto::BinFHEContext> ccLWE) override {
        m_ccLWE = ccLWE;
    }
    Ciphertext<DCRTPoly> GetSwkFC() override {
        return m_FHEWtoCKKSswk;
    }
    void SetSwkFC(Ciphertext<DCRTPoly> FHEWtoCKKSswk) override {
        m_FHEWtoCKKSswk = FHEWtoCKKSswk;
    }
    uint32_t GetNumCtxtsToSwitch() {
        return m_numCtxts;
    }
    NativeInteger GetModulusLWEToSwitch() {
        return m_modulus_LWE;
    }

    //------------------------------------------------------------------------------
    // SERIALIZATION
    //------------------------------------------------------------------------------

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<FHERNS>(this));
        ar(cereal::make_nvp("QLWE", m_modulus_LWE));
        ar(cereal::make_nvp("QCKKS1", m_modulus_CKKS_initial));
        ar(cereal::make_nvp("QCKKS2", m_modulus_CKKS_from));
        ar(cereal::make_nvp("slots", m_numSlotsCKKS));
        ar(cereal::make_nvp("ctxts", m_numCtxts));
        ar(cereal::make_nvp("bCF", m_dim1CF));
        ar(cereal::make_nvp("bFC", m_dim1FC));
        ar(cereal::make_nvp("lCF", m_LCF));
        ar(cereal::make_nvp("lFC", m_LFC));
        ar(cereal::make_nvp("argmin", m_argmin));
        ar(cereal::make_nvp("oneHot", m_oneHot));
        ar(cereal::make_nvp("alt", m_alt));
        ar(cereal::make_nvp("swkCF", m_CKKStoFHEWswk));
        // ar(cereal::make_nvp("swkFC", m_FHEWtoCKKSswk)); // Avoid a circular issue when deserializing
        ar(cereal::make_nvp("ctKS", m_ctxtKS));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<FHERNS>(this));
        ar(cereal::make_nvp("QLWE", m_modulus_LWE));
        ar(cereal::make_nvp("QCKKS1", m_modulus_CKKS_initial));
        ar(cereal::make_nvp("QCKKS2", m_modulus_CKKS_from));
        ar(cereal::make_nvp("slots", m_numSlotsCKKS));
        ar(cereal::make_nvp("ctxts", m_numCtxts));
        ar(cereal::make_nvp("bCF", m_dim1CF));
        ar(cereal::make_nvp("bFC", m_dim1FC));
        ar(cereal::make_nvp("lCF", m_LCF));
        ar(cereal::make_nvp("lFC", m_LFC));
        ar(cereal::make_nvp("argmin", m_argmin));
        ar(cereal::make_nvp("oneHot", m_oneHot));
        ar(cereal::make_nvp("alt", m_alt));
        ar(cereal::make_nvp("swkCF", m_CKKStoFHEWswk));
        // ar(cereal::make_nvp("swkFC", m_FHEWtoCKKSswk)); // Avoid a circular issue when deserializing
        ar(cereal::make_nvp("ctKS", m_ctxtKS));
    }

    std::string SerializedObjectName() const {
        return "SWITCHCKKSRNS";
    }

private:
    std::vector<ConstPlaintext> EvalLTPrecomputeSwitch(const CryptoContextImpl<DCRTPoly>& cc,
                                                       const std::vector<std::vector<std::complex<double>>>& A,
                                                       uint32_t dim1, uint32_t L, double scale) const;

    std::vector<ConstPlaintext> EvalLTPrecomputeSwitch(const CryptoContextImpl<DCRTPoly>& cc,
                                                       const std::vector<std::vector<std::complex<double>>>& A,
                                                       const std::vector<std::vector<std::complex<double>>>& B,
                                                       uint32_t dim1, uint32_t L, double scale) const;

    Ciphertext<DCRTPoly> EvalLTWithPrecomputeSwitch(const CryptoContextImpl<DCRTPoly>& cc,
                                                    ConstCiphertext<DCRTPoly> ctxt,
                                                    const std::vector<ConstPlaintext>& A, uint32_t dim1) const;

    Ciphertext<DCRTPoly> EvalLTRectWithPrecomputeSwitch(const CryptoContextImpl<DCRTPoly>& cc,
                                                        const std::vector<std::vector<std::complex<double>>>& A,
                                                        ConstCiphertext<DCRTPoly> ct, bool wide, uint32_t dim1,
                                                        uint32_t L) const;

    Ciphertext<DCRTPoly> EvalSlotsToCoeffsSwitch(const CryptoContextImpl<DCRTPoly>& cc,
                                                 ConstCiphertext<DCRTPoly> ciphertext) const;

    Ciphertext<DCRTPoly> EvalPartialHomDecryption(const CryptoContextImpl<DCRTPoly>& cc,
                                                  const std::vector<std::vector<std::complex<double>>>& A,
                                                  ConstCiphertext<DCRTPoly> ct, uint32_t dim1, double scale,
                                                  uint32_t L) const;

    //------------------------------------------------------------------------------
    // Complex Plaintext Functions, copied from ckksrns-fhe. TODO: fix this
    //------------------------------------------------------------------------------

    Plaintext MakeAuxPlaintext(const CryptoContextImpl<DCRTPoly>& cc, const std::shared_ptr<ParmType> params,
                               const std::vector<std::complex<double>>& value, size_t noiseScaleDeg, uint32_t level,
                               usint slots) const;

    Ciphertext<DCRTPoly> EvalMultExt(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const;

    void EvalAddExtInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) const;

    Ciphertext<DCRTPoly> EvalAddExt(ConstCiphertext<DCRTPoly> ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) const;

    EvalKey<DCRTPoly> ConjugateKeyGen(const PrivateKey<DCRTPoly> privateKey) const;

    Ciphertext<DCRTPoly> Conjugate(ConstCiphertext<DCRTPoly> ciphertext,
                                   const std::map<usint, EvalKey<DCRTPoly>>& evalKeys) const;

#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
    /**
   * Set modulus and recalculates the vector values to fit the modulus
   *
   * @param &vec input vector
   * @param &bigValue big bound of the vector values.
   * @param &modulus modulus to be set for vector.
   */
    void FitToNativeVector(uint32_t ringDim, const std::vector<__int128>& vec, __int128 bigBound,
                           NativeVector* nativeVec) const;

#else  // NATIVEINT == 64
    /**
   * Set modulus and recalculates the vector values to fit the modulus
   *
   * @param &vec input vector
   * @param &bigValue big bound of the vector values.
   * @param &modulus modulus to be set for vector.
   */
    void FitToNativeVector(uint32_t ringDim, const std::vector<int64_t>& vec, int64_t bigBound,
                           NativeVector* nativeVec) const;
#endif

    //------------------------------------------------------------------------------
    // Private members
    //------------------------------------------------------------------------------

    // the associated ciphertext modulus Q for the LWE cryptocontext
    NativeInteger m_modulus_LWE;
    // the target ciphertext modulus Q for the CKKS cryptocontext. We assume the switching goes to the same initial cryptocontext
    NativeInteger m_modulus_CKKS_initial;
    // the ciphertext modulus Q' for the CKKS cryptocontext that is secure for the LWE ring dimension
    NativeInteger m_modulus_CKKS_from;
    // number of slots encoded in the CKKS ciphertext
    uint32_t m_numSlotsCKKS;
    // number of ciphertexts to switch, different logic for argmin (i.e., it starts from number of ciphertexts / 2)
    uint32_t m_numCtxts;
    // baby-step dimensions for linear transform for CKKS->FHEW, FHEW->CKKS
    uint32_t m_dim1CF;
    uint32_t m_dim1FC;
    // starting levels for linear transforms
    uint32_t m_LCF;
    uint32_t m_LFC;
    // flags indicating type of argmin computation
    bool m_argmin;
    bool m_oneHot;
    bool m_alt;
    // the LWE cryptocontext to generate when scheme switching from CKKS
    std::shared_ptr<BinFHEContext> m_ccLWE;
    // the CKKS cryptocontext for the intermediate modulus switching in CKKS to FHEW
    CryptoContext<DCRTPoly> m_ccKS;
    // switching key from CKKS to FHEW
    EvalKey<DCRTPoly> m_CKKStoFHEWswk;
    // switching key from FHEW to CKKS
    Ciphertext<DCRTPoly> m_FHEWtoCKKSswk;
    // a ciphertext under the intermediate cryptocontext
    Ciphertext<DCRTPoly> m_ctxtKS;
    // Precomputed matrix for CKKS to FHEW switching
    std::vector<ConstPlaintext> m_U0Pre;

#define Pi 3.14159265358979323846
};

}  // namespace lbcrypto

#endif
