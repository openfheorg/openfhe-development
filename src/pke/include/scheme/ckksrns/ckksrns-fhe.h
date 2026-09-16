//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2025, NJIT, Duality Technologies Inc. and other contributors
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

#ifndef LBCRYPTO_CRYPTO_CKKSRNS_FHE_H
#define LBCRYPTO_CRYPTO_CKKSRNS_FHE_H

#include "constants.h"
#include "encoding/plaintext-fwd.h"
#include "math/hal/basicint.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include "schemerns/rns-fhe.h"
#include "utils/caller_info.h"

#include <complex>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class CKKSBootstrapPrecom {
public:
    CKKSBootstrapPrecom() = default;

    virtual ~CKKSBootstrapPrecom() = default;

    CKKSBootstrapPrecom(const CKKSBootstrapPrecom& rhs) = default;

    CKKSBootstrapPrecom(CKKSBootstrapPrecom&& rhs) noexcept = default;

    // level budget for homomorphic encoding, number of layers to collapse in one level,
    // number of layers remaining to be collapsed in one level to have exactly the number
    // of levels specified in the level budget, the number of rotations in one level,
    // the baby step and giant step in the baby-step giant-step strategy, the number of
    // rotations in the remaining level, the baby step and giant step in the baby-step
    // giant-step strategy for the remaining level
    struct ckks_boot_params m_paramsEnc;

    // level budget for homomorphic decoding, number of layers to collapse in one level,
    // number of layers remaining to be collapsed in one level to have exactly the number
    // of levels specified in the level budget, the number of rotations in one level,
    // the baby step and giant step in the baby-step giant-step strategy, the number of
    // rotations in the remaining level, the baby step and giant step in the baby-step
    // giant-step strategy for the remaining level
    struct ckks_boot_params m_paramsDec;

    // number of slots for which the bootstrapping is performed
    uint32_t m_slots;

    // Linear map U0; used in decoding
    std::vector<ReadOnlyPlaintext> m_U0Pre;

    // Conj(U0^T); used in encoding
    std::vector<ReadOnlyPlaintext> m_U0hatTPre;

    // coefficients corresponding to U0; used in decoding
    std::vector<std::vector<ReadOnlyPlaintext>> m_U0PreFFT;

    // coefficients corresponding to conj(U0^T); used in encoding
    std::vector<std::vector<ReadOnlyPlaintext>> m_U0hatTPreFFT;

    Ciphertext<DCRTPoly> m_precompExp;
    Ciphertext<DCRTPoly> m_precompExpI;

    // flag indicating whether we perform StC before ModRaise
    bool BTSlotsEncoding;

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::make_nvp("dim1_Enc", m_paramsEnc.g));
        ar(cereal::make_nvp("dim1_Dec", m_paramsDec.g));
        ar(cereal::make_nvp("slots", m_slots));
        ar(cereal::make_nvp("lEnc", m_paramsEnc.lvlb));
        ar(cereal::make_nvp("lDec", m_paramsDec.lvlb));
        ar(cereal::make_nvp("BTSlotsEncoding", BTSlotsEncoding));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::make_nvp("dim1_Enc", m_paramsEnc.g));
        ar(cereal::make_nvp("dim1_Dec", m_paramsDec.g));
        ar(cereal::make_nvp("slots", m_slots));
        ar(cereal::make_nvp("lEnc", m_paramsEnc.lvlb));
        ar(cereal::make_nvp("lDec", m_paramsDec.lvlb));
        ar(cereal::make_nvp("BTSlotsEncoding", BTSlotsEncoding));
    }
};

using namespace std::literals::complex_literals;

class FHECKKSRNS : public FHERNS {
private:
    // correction factor, which we scale the message by to improve precision
    uint32_t m_correctionFactor;

    // key tuple is dim1, levelBudgetEnc, levelBudgetDec
    std::map<uint32_t, std::shared_ptr<CKKSBootstrapPrecom>> m_bootPrecomMap;

    using ParmType = typename DCRTPoly::Params;
    using DugType  = typename DCRTPoly::DugType;
    using DggType  = typename DCRTPoly::DggType;
    using TugType  = typename DCRTPoly::TugType;

public:
    virtual ~FHECKKSRNS() = default;

    void ClearBootstrapPrecom() noexcept override {
        m_bootPrecomMap.clear();
    }

    //------------------------------------------------------------------------------
    // Bootstrap Wrapper
    //------------------------------------------------------------------------------

    void EvalBootstrapSetup(const CryptoContextImpl<DCRTPoly>& cc, std::vector<uint32_t> levelBudget,
                            std::vector<uint32_t> dim1, uint32_t slots, uint32_t correctionFactor, bool precompute,
                            bool BTSlotsEncoding) override;

    std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> EvalBootstrapKeyGen(const PrivateKey<DCRTPoly> privateKey,
                                                                               uint32_t slots) override;

    std::vector<uint32_t> EvalBootstrapKeyMapIndices(const CryptoContext<DCRTPoly>& cc, uint32_t slots) override;

    void EvalBootstrapPrecompute(const CryptoContextImpl<DCRTPoly>& cc, uint32_t slots) override;

    Ciphertext<DCRTPoly> EvalBootstrap(ConstCiphertext<DCRTPoly>& ciphertext, uint32_t numIterations,
                                       uint32_t precision) const override;

    Ciphertext<DCRTPoly> EvalBootstrapStCFirst(ConstCiphertext<DCRTPoly>& ciphertext, uint32_t numIterations,
                                               uint32_t precision) const override;

    void EvalFEFuncBootstrapSetup(const CryptoContextImpl<DCRTPoly>& cc, const std::vector<uint32_t>& levelBudget,
                                  const std::vector<uint32_t>& dim1, uint32_t numSlots) override;

    Ciphertext<DCRTPoly> EvalFEFuncBootstrap(ConstCiphertext<DCRTPoly>& ciphertext,
                                             const std::vector<std::complex<double>>& coefficients) const override;

    std::shared_ptr<seriesPowers<DCRTPoly>> EvalFEFuncBootstrapPrecompute(
        ConstCiphertext<DCRTPoly>& ciphertext, const std::vector<std::complex<double>>& coefficients) const override;

    Ciphertext<DCRTPoly> EvalFEFuncBootstrapWithPrecomp(
        const std::shared_ptr<seriesPowers<DCRTPoly>>& powers,
        const std::vector<std::complex<double>>& coefficients) const override;

    void EvalFBTSetup(const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::complex<double>>& coefficients,
                      uint32_t numSlots, const BigInteger& PIn, const BigInteger& POut, const BigInteger& Bigq,
                      const PublicKey<DCRTPoly>& pubKey, const std::vector<uint32_t>& dim1,
                      const std::vector<uint32_t>& levelBudget, uint32_t lvlsAfterBoot = 0,
                      uint32_t depthLeveledComputation = 0, size_t order = 1) override;

    void EvalFBTSetup(const CryptoContextImpl<DCRTPoly>& cc, const std::vector<int64_t>& coefficients,
                      uint32_t numSlots, const BigInteger& PIn, const BigInteger& POut, const BigInteger& Bigq,
                      const PublicKey<DCRTPoly>& pubKey, const std::vector<uint32_t>& dim1,
                      const std::vector<uint32_t>& levelBudget, uint32_t lvlsAfterBoot = 0,
                      uint32_t depthLeveledComputation = 0, size_t order = 1) override;

    Ciphertext<DCRTPoly> EvalFBT(ConstCiphertext<DCRTPoly>& ciphertext,
                                 const std::vector<std::complex<double>>& coefficients, uint32_t digitBitSize,
                                 const BigInteger& initialScaling, uint64_t postScaling, uint32_t levelToReduce = 0,
                                 size_t order = 1) override;
    Ciphertext<DCRTPoly> EvalFBT(ConstCiphertext<DCRTPoly>& ciphertext, const std::vector<int64_t>& coefficients,
                                 uint32_t digitBitSize, const BigInteger& initialScaling, uint64_t postScaling,
                                 uint32_t levelToReduce = 0, size_t order = 1) override;

    Ciphertext<DCRTPoly> EvalFBTNoDecoding(ConstCiphertext<DCRTPoly>& ciphertext,
                                           const std::vector<std::complex<double>>& coefficients, uint32_t digitBitSize,
                                           const BigInteger& initialScaling, size_t order = 1) override;
    Ciphertext<DCRTPoly> EvalFBTNoDecoding(ConstCiphertext<DCRTPoly>& ciphertext,
                                           const std::vector<int64_t>& coefficients, uint32_t digitBitSize,
                                           const BigInteger& initialScaling, size_t order = 1) override;

    Ciphertext<DCRTPoly> EvalHomDecoding(ConstCiphertext<DCRTPoly>& ciphertext, uint64_t postScaling,
                                         uint32_t levelToReduce = 0) override;

    std::shared_ptr<seriesPowers<DCRTPoly>> EvalMVBPrecompute(ConstCiphertext<DCRTPoly>& ciphertext,
                                                              const std::vector<std::complex<double>>& coeffs,
                                                              uint32_t digitBitSize, const BigInteger& initialScaling,
                                                              size_t order = 1) override;
    std::shared_ptr<seriesPowers<DCRTPoly>> EvalMVBPrecompute(ConstCiphertext<DCRTPoly>& ciphertext,
                                                              const std::vector<int64_t>& coeffs, uint32_t digitBitSize,
                                                              const BigInteger& initialScaling,
                                                              size_t order = 1) override;

    Ciphertext<DCRTPoly> EvalMVB(const std::shared_ptr<seriesPowers<DCRTPoly>> ciphertexts,
                                 const std::vector<std::complex<double>>& coeffs, uint32_t digitBitSize,
                                 const uint64_t postScaling, uint32_t levelToReduce = 0, size_t order = 1) override;
    Ciphertext<DCRTPoly> EvalMVB(const std::shared_ptr<seriesPowers<DCRTPoly>> ciphertexts,
                                 const std::vector<int64_t>& coeffs, uint32_t digitBitSize, const uint64_t postScaling,
                                 uint32_t levelToReduce = 0, size_t order = 1) override;

    Ciphertext<DCRTPoly> EvalMVBNoDecoding(const std::shared_ptr<seriesPowers<DCRTPoly>> ciphertexts,
                                           const std::vector<std::complex<double>>& coefficients, uint32_t digitBitSize,
                                           size_t order = 1) override;
    Ciphertext<DCRTPoly> EvalMVBNoDecoding(const std::shared_ptr<seriesPowers<DCRTPoly>> ciphertexts,
                                           const std::vector<int64_t>& coefficients, uint32_t digitBitSize,
                                           size_t order = 1) override;

    Ciphertext<DCRTPoly> EvalHermiteTrigSeries(ConstCiphertext<DCRTPoly>& ciphertext,
                                               const std::vector<std::complex<double>>& coefficientsCheb, double a,
                                               double b, const std::vector<std::complex<double>>& coefficientsHerm,
                                               size_t precomp) override;
    Ciphertext<DCRTPoly> EvalHermiteTrigSeries(ConstCiphertext<DCRTPoly>& ciphertext,
                                               const std::vector<std::complex<double>>& coefficientsCheb, double a,
                                               double b, const std::vector<int64_t>& coefficientsHerm,
                                               size_t precomp) override;

    //------------------------------------------------------------------------------
    // Precomputations for CoeffsToSlots and SlotsToCoeffs
    //------------------------------------------------------------------------------

    std::vector<ReadOnlyPlaintext> EvalLinearTransformPrecompute(
        const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A,
        double scale = 1., uint32_t L = 0) const;

    std::vector<ReadOnlyPlaintext> EvalLinearTransformPrecompute(
        const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A,
        const std::vector<std::vector<std::complex<double>>>& B, uint32_t orientation = 0, double scale = 1,
        uint32_t L = 0) const;

    std::vector<std::vector<ReadOnlyPlaintext>> EvalCoeffsToSlotsPrecompute(const CryptoContextImpl<DCRTPoly>& cc,
                                                                            const std::vector<std::complex<double>>& A,
                                                                            const std::vector<uint32_t>& rotGroup,
                                                                            bool flag_i, double scale = 1,
                                                                            uint32_t L          = 0,
                                                                            bool flagStCComplex = false) const;

    std::vector<std::vector<ReadOnlyPlaintext>> EvalSlotsToCoeffsPrecompute(const CryptoContextImpl<DCRTPoly>& cc,
                                                                            const std::vector<std::complex<double>>& A,
                                                                            const std::vector<uint32_t>& rotGroup,
                                                                            bool flag_i, double scale = 1,
                                                                            uint32_t L          = 0,
                                                                            bool flagStCComplex = false) const;

    //------------------------------------------------------------------------------
    // EVALUATION: CoeffsToSlots and SlotsToCoeffs
    //------------------------------------------------------------------------------
    // The transforms below use a baby-step/giant-step (BSGS) decomposition in
    // which the giant steps are accumulated in Horner form with a single giant-
    // step stride. This requires only one giant-step rotation key per level
    // (instead of one per giant step), minimizing the number of distinct
    // rotation keys that EvalBootstrapKeyGen must generate and store.

    /**
   * Single-level linear transform, used for CoeffsToSlots/SlotsToCoeffs when the
   * level budget is 1. Evaluated with a BSGS decomposition (Horner giant steps).
   * @param A precomputed diagonal plaintexts of the linear transform
   * @param ct input ciphertext
   */
    Ciphertext<DCRTPoly> EvalLinearTransform(const std::vector<ReadOnlyPlaintext>& A,
                                             ConstCiphertext<DCRTPoly>& ct) const;

    /**
   * Homomorphic encoding (CoeffsToSlots) over multiple BSGS levels, evaluated
   * with Horner giant steps to minimize the number of rotation keys.
   * @param A precomputed encoding plaintexts, one inner vector per BSGS level
   * @param ctxt input ciphertext
   */
    Ciphertext<DCRTPoly> EvalCoeffsToSlots(const std::vector<std::vector<ReadOnlyPlaintext>>& A,
                                           ConstCiphertext<DCRTPoly>& ctxt) const;

    /**
   * Homomorphic decoding (SlotsToCoeffs); the inverse of EvalCoeffsToSlots,
   * evaluated with the same Horner giant-step BSGS structure.
   * @param A precomputed decoding plaintexts, one inner vector per BSGS level
   * @param ctxt input ciphertext
   */
    Ciphertext<DCRTPoly> EvalSlotsToCoeffs(const std::vector<std::vector<ReadOnlyPlaintext>>& A,
                                           ConstCiphertext<DCRTPoly>& ctxt) const;

    /**
   * Bootstrapping PartialSum: raised += Rotate(raised, j * slots) for j = 1, 2, 4, ...
   * while j < N / (2 * slots). For HYBRID key switching, element 0 accumulates in the
   * extended (QlP) basis with a single deferred ApproxModDown instead of one per level.
   * @param raised input/output ciphertext at the raised level
   * @param slots number of plaintext slots (sparse packing; slots < N / 2)
   */
    static void EvalPartialSumInPlace(Ciphertext<DCRTPoly>& raised, uint32_t slots);

    /**
   * Rotation fold: ct = sum_{j=0}^{size-1} Rotate(ct, j * stride), evaluated as a doubling
   * (radix-2) loop. For HYBRID key switching, element 0 accumulates in the extended (QlP)
   * basis with a single deferred ApproxModDown; element 1 settles once per level.
   * @param ct input/output ciphertext
   * @param stride slot distance between consecutive summands
   * @param size number of summands (power of two)
   */
    static void EvalPartialSumInPlace(Ciphertext<DCRTPoly>& ct, uint32_t stride, uint32_t size);

    /**
   * Generalized rotation fold: ct = sum_{j=0}^{size-1} Rotate(ct, j * stride), evaluated in
   * radix-bStep levels so each level shares one digit decomposition across its (up to
   * bStep - 1) rotations. For HYBRID key switching, element 0 accumulates in the extended
   * (QlP) basis with a single deferred ApproxModDown. Higher radix trades more rotation keys
   * for fewer digit decompositions. Entry point for callers that carry a runtime radix;
   * @param ct input/output ciphertext
   * @param stride slot distance between consecutive summands
   * @param size number of summands (power of two)
   * @param radix accumulation branching factor (power of two; 2 = plain doubling)
   */
    static void EvalPartialSumInPlace(Ciphertext<DCRTPoly>& ct, uint32_t stride, uint32_t size, uint32_t radix);

    //------------------------------------------------------------------------------
    // SERIALIZATION
    //------------------------------------------------------------------------------

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<FHERNS>(this));
        ar(cereal::make_nvp("paramMap", m_bootPrecomMap));
        ar(cereal::make_nvp("corFactor", m_correctionFactor));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<FHERNS>(this));
        ar(cereal::make_nvp("paramMap", m_bootPrecomMap));
        ar(cereal::make_nvp("corFactor", m_correctionFactor));
    }

    // To be deprecated; left for backwards compatibility
    static uint32_t GetBootstrapDepth(uint32_t approxModDepth, const std::vector<uint32_t>& levelBudget,
                                      SecretKeyDist secretKeyDist);

    static uint32_t GetBootstrapDepth(const std::vector<uint32_t>& levelBudget, SecretKeyDist secretKeyDist);

    // For SPARSE_ENCAPSULATED, firstModSize (the size of the first modulus in bits) selects the approximation tables:
    // a first modulus above 60 bits gives the sparse secret Hamming weight 64 and uses the K = 28 tables of
    // SPARSE_TERNARY, which need one more level than the K = 16 tables of the default Hamming weight 32
    // (see CryptoParametersCKKSRNS::SparseKSHammingWeight).
    template <typename VectorDataType>
    static uint32_t GetFBTDepth(const std::vector<uint32_t>& levelBudget,
                                const std::vector<VectorDataType>& coefficients, const BigInteger& PInput, size_t order,
                                SecretKeyDist skd, uint32_t firstModSize = 60);

    template <typename VectorDataType>
    static uint32_t GetFEFBTDepth(const std::vector<uint32_t>& levelBudget,
                                  const std::vector<VectorDataType>& coefficients, SecretKeyDist skd = SPARSE_TERNARY,
                                  uint32_t firstModSize = 60);

    template <typename VectorDataType>
    static uint32_t AdjustDepthFBT(const std::vector<VectorDataType>& coefficients, const BigInteger& PInput,
                                   size_t order, SecretKeyDist skd = SPARSE_TERNARY, uint32_t firstModSize = 60);

    // same as AdjustDepthFBT, with the approximation tables of SPARSE_ENCAPSULATED selected directly by the Hamming
    // weight of its sparse secret (32 or 64; see CryptoParametersCKKSRNS::GetSparseKSHammingWeight)
    template <typename VectorDataType>
    static uint32_t AdjustDepthFBTInternal(const std::vector<VectorDataType>& coefficients, const BigInteger& PInput,
                                           size_t order, SecretKeyDist skd, uint32_t sparseKSHammingWeight);

    // generates a key going from a denser secret to a sparser one
    static EvalKey<DCRTPoly> KeySwitchGenSparse(const PrivateKey<DCRTPoly>& oldPrivateKey,
                                                const PrivateKey<DCRTPoly>& newPrivateKey);

    // generates a key going from a denser secret to a sparser one
    static Ciphertext<DCRTPoly> KeySwitchSparse(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly>& ek);

    std::string SerializedObjectName() const {
        return "FHECKKSRNS";
    }

    uint32_t GetCKKSBootCorrectionFactor() const override {
        return m_correctionFactor;
    }

    void SetCKKSBootCorrectionFactor(uint32_t cf) override {
        m_correctionFactor = cf;
    }

    static Plaintext MakeAuxPlaintext(const CryptoContextImpl<DCRTPoly>& cc, const std::shared_ptr<ParmType> params,
                                      const std::vector<std::complex<double>>& value, size_t noiseScaleDeg,
                                      uint32_t level, uint32_t slots);

    static Ciphertext<DCRTPoly> EvalMultExt(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext);

    static void EvalAddExtInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2);

    static Ciphertext<DCRTPoly> EvalAddExt(ConstCiphertext<DCRTPoly> ciphertext1,
                                           ConstCiphertext<DCRTPoly> ciphertext2);

    // Loads the loop-invariant automorphism key, index and O(N) permutation map for a constant
    // Horner giant stride, so they are built once instead of re-derived inside the BSGS
    // accumulation loop. Shared by the bootstrapping and scheme-switching linear transforms.
    static EvalKey<DCRTPoly> GetGiantStepRotation(ConstCiphertext<DCRTPoly> ct, int32_t stride, uint32_t& autoIndex,
                                                  std::vector<uint32_t>& map);

    // Inlined giant-step rotation for the Horner accumulation: equivalent to
    // EvalFastRotationExt(KeySwitchDown(outer), stride, precompute(.), addFirst=true), reusing the
    // caller-supplied loop-invariant (autoIndex, map, giantKey) from GetGiantStepRotation.
    static Ciphertext<DCRTPoly> EvalHornerGiantRotate(ConstCiphertext<DCRTPoly> outer, uint32_t autoIndex,
                                                      const std::vector<uint32_t>& map,
                                                      const EvalKey<DCRTPoly>& giantKey);

    static EvalKey<DCRTPoly> ConjugateKeyGen(const PrivateKey<DCRTPoly> privateKey);

    static Ciphertext<DCRTPoly> Conjugate(ConstCiphertext<DCRTPoly> ciphertext,
                                          const std::map<uint32_t, EvalKey<DCRTPoly>>& evalKeys);

private:
    CKKSBootstrapPrecom& GetBootPrecom(uint32_t slots) const {
        auto pair = m_bootPrecomMap.find(slots);
        if (pair != m_bootPrecomMap.end())
            return *(pair->second);
        OPENFHE_THROW("Precomputations for " + std::to_string(slots) + " slots not found.");
    }

    //------------------------------------------------------------------------------
    // Find Rotation Indices
    //------------------------------------------------------------------------------
    std::vector<int32_t> FindBootstrapRotationIndices(uint32_t slots, uint32_t M);

    // ATTN: The following 3 functions are helper methods to be called in FindBootstrapRotationIndices() only.
    // so they DO NOT remove possible duplicates and automorphisms corresponding to 0 and M/4.
    // These methods completely depend on FindBootstrapRotationIndices() to do that.
    std::vector<uint32_t> FindLinearTransformRotationIndices(uint32_t slots, uint32_t M);
    std::vector<uint32_t> FindCoeffsToSlotsRotationIndices(uint32_t slots, uint32_t M);
    std::vector<uint32_t> FindSlotsToCoeffsRotationIndices(uint32_t slots, uint32_t M);

    //------------------------------------------------------------------------------
    // Auxiliary Bootstrap Functions
    //------------------------------------------------------------------------------
    uint32_t GetBootstrapDepthInternal(uint32_t approxModDepth, const std::vector<uint32_t>& levelBudget,
                                       const CryptoContextImpl<DCRTPoly>& cc);
    static uint32_t GetModDepthInternal(SecretKeyDist secretKeyDist);

    void AdjustCiphertext(Ciphertext<DCRTPoly>& ciphertext, double correction, uint32_t lvl,
                          bool modReduce = true) const;
    void AdjustCiphertextFBT(Ciphertext<DCRTPoly>& ciphertext, double correction) const;

    void ExtendCiphertext(std::vector<DCRTPoly>& ciphertext, const CryptoContextImpl<DCRTPoly>& cc,
                          const std::shared_ptr<DCRTPoly::Params> params) const;

    /**
   * Raises the modulus of a depleted ciphertext (bottom level, noise degree 1) to the raised basis, i.e.,
   * extends its bottom RNS limbs (a single prime, or compositeDegree primes for composite scaling) to
   * elementParamsRaisedPtr. For SPARSE_ENCAPSULATED, the ciphertext is switched to the sparse secret before
   * and back to the dense secret after the modulus raise.
   */
    void ModRaiseInPlace(Ciphertext<DCRTPoly>& raised,
                         const std::shared_ptr<DCRTPoly::Params>& elementParamsRaisedPtr) const;

    void ApplyDoubleAngleIterations(Ciphertext<DCRTPoly>& ciphertext, uint32_t numIt) const;

    /**
   * The function-independent part of FE functional bootstrapping: SlotsToCoeffs, modulus raise,
   * CoeffsToSlots and the complex exponential.
   *
   * @param &ciphertext input ciphertext, with slot values in [-1/2, 1/2)
   * @return a ciphertext of exp(2*Pi*i*t), t = mu/2 being the half-period embedding of the message
   */
    Ciphertext<DCRTPoly> EvalFEFuncBootstrapExp(ConstCiphertext<DCRTPoly>& ciphertext) const;

    /**
   * Twice the real part of an evaluated Fourier series, obtained by adding its conjugate to it.
   *
   * @param &ctxtSeries the evaluated series
   * @return the real-valued FE functional bootstrapping output
   */
    static Ciphertext<DCRTPoly> TwiceRealPart(const Ciphertext<DCRTPoly>& ctxtSeries);

    /**
   * Set modulus and recalculates the vector values to fit the modulus
   *
   * @param &vec input vector
   * @param &bigValue big bound of the vector values.
   * @param &modulus modulus to be set for vector.
   */
    static void FitToNativeVector(uint32_t ringDim, const std::vector<int64_t>& vec, int64_t bigBound,
                                  NativeVector* nativeVec);

#if NATIVEINT == 128
    /**
   * Set modulus and recalculates the vector values to fit the modulus
   *
   * @param &vec input vector
   * @param &bigValue big bound of the vector values.
   * @param &modulus modulus to be set for vector.
   */
    static void FitToNativeVector(uint32_t ringDim, const std::vector<int128_t>& vec, int128_t bigBound,
                                  NativeVector* nativeVec);
#endif

    template <typename VectorDataType>
    void EvalFBTSetupInternal(const CryptoContextImpl<DCRTPoly>& cc, const std::vector<VectorDataType>& coefficients,
                              uint32_t numSlots, const BigInteger& PIn, const BigInteger& POut, const BigInteger& Bigq,
                              const PublicKey<DCRTPoly>& pubKey, const std::vector<uint32_t>& dim1,
                              const std::vector<uint32_t>& levelBudget, uint32_t lvlsAfterBoot = 0,
                              uint32_t depthLeveledComputation = 0, size_t order = 1);

    template <typename VectorDataType>
    Ciphertext<DCRTPoly> EvalHermiteTrigSeriesInternal(ConstCiphertext<DCRTPoly>& ciphertext,
                                                       const std::vector<std::complex<double>>& coefficientsCheb,
                                                       double a, double b,
                                                       const std::vector<VectorDataType>& coefficientsHerm,
                                                       size_t precomp);

    template <typename VectorDataType>
    std::shared_ptr<seriesPowers<DCRTPoly>> EvalMVBPrecomputeInternal(ConstCiphertext<DCRTPoly>& ciphertext,
                                                                      const std::vector<VectorDataType>& coefficients,
                                                                      uint32_t digitBitSize,
                                                                      const BigInteger& initialScaling,
                                                                      size_t order = 1);

    template <typename VectorDataType>
    Ciphertext<DCRTPoly> EvalMVBNoDecodingInternal(const std::shared_ptr<seriesPowers<DCRTPoly>>& ciphertext,
                                                   const std::vector<VectorDataType>& coefficients,
                                                   uint32_t digitBitSize, size_t order = 1);

    // upper bounds for the number of overflows in the sparse secret cases; the failure probability depends only on
    // K and on the Hamming weight h of the sparse secret (equation (1) of https://eprint.iacr.org/2022/024)

    // SPARSE_TERNARY (h = 192): failure probability of about 2^{-39} per coefficient, i.e., 2^{-22} for 2^16 slots.
    // Also used for SPARSE_ENCAPSULATED with the denser sparse secret (h = 64: first modulus above 60 bits), where
    // the failure probability is below 2^{-142} for 2^16 slots.
    static constexpr uint32_t K_SPARSE = 28;
    // SPARSE_ENCAPSULATED (h = 32): failure probability below 2^{-137} for 2^16 slots
    static constexpr uint32_t K_SPARSE_ENCAPSULATED = 16;

    // upper bound for the number of overflows in the uniform secret case; used for all scaling techniques,
    // including composite scaling of any degree (the overflow depends only on the secret key distribution and
    // the ring dimension)
    static constexpr uint32_t K_UNIFORM = 512;
    // number of double-angle iterations in CKKS bootstrapping. Must be static because it is used in a static function.
    static constexpr uint32_t R_UNIFORM = 6;
    // number of double-angle iterations in CKKS bootstrapping. Must be static because it is used in a static function.
    // same value is used for both SPARSE and ENCAPSULATED_SPARSE
    static constexpr uint32_t R_SPARSE = 3;
    // number of double-angle iterations in CKKS functional bootstrapping for UNIFORM_TERNARY; matches the
    // interval [-K_UNIFORM, K_UNIFORM] of coeff_exp_512_double_92 and coeff_cos_512_double.
    // Must be static because it is used in a static function.
    static constexpr uint32_t R_UNIFORM_FBT = 6;
    // number of double-angle iterations in CKKS functional bootstrapping for the sparse distributions;
    // matches the intervals of coeff_exp_28_double_* / coeff_exp_16_double_46 and the corresponding cos tables.
    // Must be static because it is used in a static function.
    static constexpr uint32_t R_SPARSE_FBT = 2;
    // number of double-angle iterations in CKKS functional bootstrapping. Must be static because it is used in a static function.
    // for SPARSE_TERNARY secret key distribution (K_SPARSE)
    static const uint32_t R_func_28_double_48 = 3;
    // for SPARSE_ENCAPSULATED secret key distribution
    static const uint32_t R_func_16_double_23 = 4;
    // for UNIFORM_TERNARY secret key distribution
    static const uint32_t R_func_512_double_23 = 9;

    // TODO: regenerate these as hexfloat

    // Chebyshev series coefficients for the SPARSE case with K = K_SPARSE = 28 (degree 44); also used for
    // SPARSE_ENCAPSULATED with the denser sparse secret (Hamming weight 64: first modulus
    // above 60 bits)
    static const inline std::vector<double> g_coefficientsSparse{
        -0.18646470117093214,   0.036680543700430925,    -0.20323558926782626,     0.029327390306199311,
        -0.24346234149506416,   0.011710240188138248,    -0.27023281815251715,     -0.017621188001030602,
        -0.21383614034992021,   -0.048567932060728937,   -0.013982336571484519,    -0.051097367628344978,
        0.24300487324019346,    0.0016547743046161035,   0.23316923792642233,      0.060707936480887646,
        -0.18317928363421143,   0.0076878773048247966,   -0.24293447776635235,     -0.071417413140564698,
        0.37747441314067182,    0.065154496937795681,    -0.24810721693607704,     -0.033588418808958603,
        0.10510660697380972,    0.012045222815124426,    -0.032574751830745423,    -0.0032761730196023873,
        0.0078689491066424744,  0.00070965574480802061,  -0.0015405394287521192,   -0.00012640521062948649,
        0.00025108496615830787, 0.000018944629154033562, -0.000034753284216308228, -2.4309868106111825e-6,
        4.1486274737866247e-6,  2.7079833113674568e-7,   -4.3245388569898879e-7,   -2.6482744214856919e-8,
        3.9770028771436554e-8,  2.2951153557906580e-9,   -3.2556026220554990e-9,   -1.7691071323926939e-10,
        2.5459052150406730e-10};

    // Chebyshev series coefficients for the SPARSE ENCAPSULATED case with K = K_SPARSE_ENCAPSULATED = 16 (degree 32);
    // used for first moduli of at most 60 bits (Hamming weight 32), with or without composite scaling
    static const inline std::vector<double> g_coefficientsSparseEncapsulated{
        0.24554573401685137,    -0.047919064883347899,   0.28388702040840819,      -0.029944538735513584,
        0.35576522619036460,    0.015106561885073030,    0.29532946674499999,      0.071203602333739374,
        -0.10347347339668074,   0.044997590512555294,    -0.42750712431925747,     -0.090342129729094875,
        0.36762876269324946,    0.049318066039335348,    -0.14535986272411980,     -0.015106938483063579,
        0.035951935499240355,   0.0031036582188686437,   -0.0062644606607068463,   -0.00046609430477154916,
        0.00082128798852385086, 0.000053910533892372678, -0.000084551549768927401, -4.9773801787288514e-6,
        7.0466620439083618e-6,  3.7659807574103204e-7,   -4.8648510153626034e-7,   -2.3830267651437146e-8,
        2.8329709716159918e-8,  1.2817720050334158e-9,   -1.4122220430105397e-9,   -5.9306213139085216e-11,
        6.3298928388417848e-11};

    // Chebyshev series coefficients for the OPTIMIZED/uniform case
    static const inline std::vector<double> g_coefficientsUniform{
        0.15421426400235561,    -0.0037671538417132409,  0.16032011744533031,      -0.0034539657223742453,
        0.17711481926851286,    -0.0027619720033372291,  0.19949802549604084,      -0.0015928034845171929,
        0.21756948616367638,    0.00010729951647566607,  0.21600427371240055,      0.0022171399198851363,
        0.17647500259573556,    0.0042856217194480991,   0.086174491919472254,     0.0054640252312780444,
        -0.046667988130649173,  0.0047346914623733714,   -0.17712686172280406,     0.0016205080004247200,
        -0.22703114241338604,   -0.0028145845916205865,  -0.13123089730288540,     -0.0056345646688793190,
        0.078818395388692147,   -0.0037868875028868542,  0.23226434602675575,      0.0021116338645426574,
        0.13985510526186795,    0.0059365649669377071,   -0.13918475289368595,     0.0018580676740836374,
        -0.23254376365752788,   -0.0054103844866927788,  0.056840618403875359,     -0.0035227192748552472,
        0.25667909012207590,    0.0055029673963982112,   -0.073334392714092062,    0.0027810273357488265,
        -0.24912792167850559,   -0.0069524866497120566,  0.21288810409948347,      0.0017810057298691725,
        0.088760951809475269,   0.0055957188940032095,   -0.31937177676259115,     -0.0087539416335935556,
        0.34748800245527145,    0.0075378299617709235,   -0.25116537379803394,     -0.0047285674679876204,
        0.13970502851683486,    0.0023672533925155220,   -0.063649401080083698,    -0.00098993213448982727,
        0.024597838934816905,   0.00035553235917057483,  -0.0082485030307578155,   -0.00011176184313622549,
        0.0024390574829093264,  0.000031180384864488629, -0.00064373524734389861,  -7.8036008952377965e-6,
        0.00015310015145922058, 1.7670804180220134e-6,   -0.000033066844379476900, -3.6460909134279425e-7,
        6.5276969021754105e-6,  6.8957843666189918e-8,   -1.1842811187642386e-6,   -1.2015133285307312e-8,
        1.9839339947648331e-7,  1.9372045971100854e-9,   -3.0815418032523593e-8,   -2.9013806338735810e-10,
        4.4540904298173700e-9,  4.0505136697916078e-11,  -6.0104912807134771e-10,  -5.2873323696828491e-12,
        7.5943206779351725e-11, 6.4679566322060472e-13,  -9.0081200925539902e-12,  -7.4396949275292252e-14,
        1.0057423059167244e-12, 8.1701187638005194e-15,  -1.0611736208855373e-13,  -8.9597492970451533e-16,
        1.1421575296031385e-14};

    // Coefficients for the function std::exp(1i * Pi/2.0 * x) in [-28, 28] of degree 64
    // Need two double-angle iterations to get std::exp(1i * 2Pi * x)
    static const inline std::vector<std::complex<double>> coeff_exp_28_double_64{
        0.16965420038096151724,      std::complex<double>(0, -0.16870362365122679905),
        0.17732563341570652559,      std::complex<double>(0, -0.1525766230255061899),
        0.19813991091980195862,      std::complex<double>(0, -0.11653668445787842769),
        0.22463618146696167977,      std::complex<double>(0, -0.055247612438869925086),
        0.24222204269430454339,      std::complex<double>(0, 0.032868582808249347992),
        0.2287703921693835236,       std::complex<double>(0, 0.13689697922776024241),
        0.16029435207712290875,      std::complex<double>(0, 0.22436545402588617882),
        0.02766140239866483372,      std::complex<double>(0, 0.24197524972429225381),
        -0.13738812802783614996,     std::complex<double>(0, 0.14201639396304748574),
        -0.24717223908160334579,     std::complex<double>(0, -0.060296836210872719268),
        -0.1950767387446053884,      std::complex<double>(0, -0.23771070623058817387),
        0.031920264790175676605,     std::complex<double>(0, -0.20577759355187672105),
        0.24713797547609867293,      std::complex<double>(0, 0.063935986489801286187),
        0.17445420196675215342,      std::complex<double>(0, 0.27019211884413608985),
        -0.15727868519323690949,     std::complex<double>(0, 0.069938677312154154648),
        -0.24950768519855446715,     std::complex<double>(0, -0.27043602073441560887),
        0.13171463314130863062,      std::complex<double>(0, -0.078773986979217012386),
        0.24992317333798480106,      std::complex<double>(0, 0.30762638062603938735),
        -0.23967941768304552442,     std::complex<double>(0, -0.084734164213724621372),
        -0.097114600515942013868,    std::complex<double>(0, -0.25254508172894239964),
        0.35075914986051726668,      std::complex<double>(0, 0.38545551867119718163),
        -0.36787890633417613051,     std::complex<double>(0, -0.3171414381566967748),
        0.25223794632358660259,      std::complex<double>(0, 0.18753750575212231074),
        -0.13151589581952095773,     std::complex<double>(0, -0.087560958842857913883),
        0.05562144498625856842,      std::complex<double>(0, 0.03384376680024801128),
        -0.019788193921288727771,    std::complex<double>(0, -0.011147502877302511997),
        0.0060641459329039143957,    std::complex<double>(0, 0.0031917021630567486126),
        -0.0016280495941498065558,   std::complex<double>(0, -0.00080602799572026548056),
        0.00038783148814341062486,   std::complex<double>(0, 0.00018157669106646224908),
        -0.000082806834460877132114, std::complex<double>(0, -0.000036819304784270099741),
        0.000015977943885509015508,  std::complex<double>(0, 6.7676474801071403371e-6),
        -2.8137340867521752547e-6,   std::complex<double>(0, -1.1114489452735668609e-6),
        5.1712615734270056803e-7};

    // Coefficients for the function std::exp(1i * Pi/2.0 * x) in [-16, 16] of degree 46
    // Need two double-angle iterations to get std::exp(1i * 2Pi * x)
    static const inline std::vector<std::complex<double>> coeff_exp_16_double_46{
        0.22393566906777406473,      std::complex<double>(0, -0.22176384914036407179),
        0.24158307546266121784,      std::complex<double>(0, -0.1833147085131391692),
        0.28534623846463528672,      std::complex<double>(0, -0.092486179824488319267),
        0.32214532018151837923,      std::complex<double>(0, 0.061326880477941559726),
        0.28798365357787248334,      std::complex<double>(0, 0.24466296846427114248),
        0.112756709876058827492,     std::complex<double>(0, 0.33439190718203861982),
        -0.17995397739265354314,     std::complex<double>(0, 0.16254851699551065311),
        -0.34811157721125466184,     std::complex<double>(0, -0.22527723082929950144),
        -0.079206690817227674462,    std::complex<double>(0, -0.3261263217854052566),
        0.3619825467512375429,       std::complex<double>(0, 0.19237548287066772936),
        0.071116210979945962808,     std::complex<double>(0, 0.30556044798491294876),
        -0.43951407397686912164,     std::complex<double>(0, -0.46389876376571955078),
        0.40955141151976834921,      std::complex<double>(0, 0.31828681535789012283),
        -0.22366008829505166164,     std::complex<double>(0, -0.14446909676096391009),
        0.086745018497586218893,     std::complex<double>(0, 0.04881348199387849059),
        -0.025904132260782119283,    std::complex<double>(0, -0.0130280784432671331155),
        0.0062348555293592804908,    std::complex<double>(0, 0.0028488507881147057589),
        -0.00124638777412574748091,  std::complex<double>(0, -0.00052341839132927634389),
        0.00021144315086686549321,   std::complex<double>(0, 0.00008232161624935662744),
        -0.000030941853907267914894, std::complex<double>(0, -0.0000112448146641020618181),
        3.9566691191479419628e-6,    std::complex<double>(0, 1.3496535335845760936e-6),
        -4.4681665467734785701e-7,   std::complex<double>(0, -1.4370869519524496369e-7),
        4.4978579841297345023e-8,    std::complex<double>(0, 1.35960020237312162173e-8),
        -4.3910914593632557649e-9};

    // Coefficients for the function std::exp(1i * Pi/2.0 * x) in [-28, 28] of degree 72
    // Need two double-angle iterations to get std::exp(1i * 2Pi * x)
    static const inline std::vector<std::complex<double>> coeff_exp_28_double_72{
        0.16965420038096151724,     std::complex<double>(0, -0.16870362365122679905),
        0.17732563341570652559,     std::complex<double>(0, -0.1525766230255061899),
        0.19813991091980195862,     std::complex<double>(0, -0.11653668445787842769),
        0.22463618146696167977,     std::complex<double>(0, -0.055247612438869925086),
        0.24222204269430454339,     std::complex<double>(0, 0.032868582808249347992),
        0.2287703921693835236,      std::complex<double>(0, 0.13689697922776024241),
        0.16029435207712290875,     std::complex<double>(0, 0.22436545402588617882),
        0.02766140239866483372,     std::complex<double>(0, 0.24197524972429225381),
        -0.13738812802783614996,    std::complex<double>(0, 0.14201639396304748574),
        -0.24717223908160334579,    std::complex<double>(0, -0.060296836210872719268),
        -0.1950767387446053884,     std::complex<double>(0, -0.23771070623058817387),
        0.031920264790175676605,    std::complex<double>(0, -0.20577759355187672105),
        0.24713797547609867293,     std::complex<double>(0, 0.063935986489801286187),
        0.17445420196675215342,     std::complex<double>(0, 0.27019211884413608985),
        -0.15727868519323690949,    std::complex<double>(0, 0.069938677312154154648),
        -0.24950768519855446715,    std::complex<double>(0, -0.27043602073441560887),
        0.13171463314130863062,     std::complex<double>(0, -0.078773986979217012386),
        0.24992317333798480106,     std::complex<double>(0, 0.30762638062603938735),
        -0.23967941768304552442,    std::complex<double>(0, -0.084734164213724621371),
        -0.097114600515942013865,   std::complex<double>(0, -0.25254508172894239965),
        0.35075914986051726664,     std::complex<double>(0, 0.38545551867119718176),
        -0.36787890633417612999,    std::complex<double>(0, -0.31714143815669677673),
        0.25223794632358659547,     std::complex<double>(0, 0.18753750575212233665),
        -0.13151589581952086469,    std::complex<double>(0, -0.087560958842858243348),
        0.055621444986257417975,    std::complex<double>(0, 0.033843766800251971565),
        -0.019788193921275291299,   std::complex<double>(0, -0.011147502877347431274),
        0.0060641459327559849031,   std::complex<double>(0, 0.0031917021635365177293),
        -0.0016280495926178682665,  std::complex<double>(0, -0.00080602800053477690369),
        0.00038783147325563553017,  std::complex<double>(0, 0.00018157673634916847123),
        -0.00008280669903192180495, std::complex<double>(0, -0.000036819702901995736829),
        0.000015976793962842403359, std::complex<double>(0, 6.7709096799076179181e-6),
        -2.8046484464581095157e-6,  std::complex<double>(0, -1.1362809369336758089e-6),
        4.5055665710274678407e-7,   std::complex<double>(0, 1.7495689078138666335e-7),
        -6.6569514826870561672e-8,  std::complex<double>(0, -2.4831947070297197595e-8),
        9.085788316596281664e-9,    std::complex<double>(0, 3.2617200572729399773e-9),
        -1.1514546120235311216e-9,  std::complex<double>(0, -3.9330321613500482287e-10),
        1.5031673097386347677e-10};

    // Coefficients for the function std::exp(1i * Pi/32.0 * x) in [-512, 512] of degree 92
    // Need six double-angle iterations to get std::exp(1i * 2Pi * x)
    static const inline std::vector<std::complex<double>> coeff_exp_512_double_92{
        0.15875482260721806945,      std::complex<double>(0, -0.1579750920349633735),
        0.16504045180290845041,      std::complex<double>(0, -0.1448415901776870788),
        0.18232964308446051051,      std::complex<double>(0, -0.1158229262086141783),
        0.20537188212129648844,      std::complex<double>(0, -0.066794000891078608641),
        0.22397542409002082748,      std::complex<double>(0, 0.0044995908589821682931),
        0.22236412680405005873,      std::complex<double>(0, 0.092975465726926131697),
        0.18167098817309372606,      std::complex<double>(0, 0.17971697307933749939),
        0.088711743148052377287,     std::complex<double>(0, 0.2291331665924263917),
        -0.048042042187510357275,    std::complex<double>(0, 0.19854865263093980842),
        -0.18234204010692166874,     std::complex<double>(0, 0.067955786056792340492),
        -0.23371566160443221632,     std::complex<double>(0, -0.11802922805489804518),
        -0.13509475246457963366,     std::complex<double>(0, -0.23628471507772426831),
        0.081139059730079847246,     std::complex<double>(0, -0.15880262047449974064),
        0.2391029473829727179,       std::complex<double>(0, 0.088551083420469799546),
        0.14397288454602652212,      std::complex<double>(0, 0.24894905714736187954),
        -0.14328279487122648096,     std::complex<double>(0, 0.077917819169028653578),
        -0.23939059195783441929,     std::complex<double>(0, -0.22688374914924554028),
        0.058514187062838834529,     std::complex<double>(0, -0.14772476119678115983),
        0.26423653922629225534,      std::complex<double>(0, 0.23076620107345806163),
        -0.075493590567964365481,    std::complex<double>(0, 0.11662200902230951848),
        -0.25646304035774407972,     std::complex<double>(0, -0.29155159691080263975),
        0.21915620724282844185,      std::complex<double>(0, 0.074686236854861161515),
        0.091374356646708566199,     std::complex<double>(0, 0.23465572270868111345),
        -0.32877509803452822355,     std::complex<double>(0, -0.36709537049507185554),
        0.357719154870658171,        std::complex<double>(0, 0.31609789034077408956),
        -0.25856048155035421797,     std::complex<double>(0, -0.19829184374622190368),
        0.14381838906411188314,      std::complex<double>(0, 0.0992704541056463567),
        -0.065523441964940601934,    std::complex<double>(0, -0.041512671535409223991),
        0.025322077577455126277,     std::complex<double>(0, 0.014909201885908789415),
        -0.0084913652047327096646,   std::complex<double>(0, -0.0046867179301013621913),
        0.0025108710956997454094,    std::complex<double>(0, 0.0013075452651063058309),
        -0.00066268886123584198631,  std::complex<double>(0, -0.00032724295885685619173),
        0.00015760790704601871819,   std::complex<double>(0, 0.00007410228077101323241),
        -0.000034040437489198023529, std::complex<double>(0, -0.000015289833437359545315),
        6.7198930684778842551e-6,    std::complex<double>(0, 2.8917379438931878043e-6),
        -1.2191501227452748787e-6,   std::complex<double>(0, -5.0385300321183733825e-7),
        2.0423473219299951823e-7,    std::complex<double>(0, 8.1236406020338468791e-8),
        -3.1722722090117057614e-8,   std::complex<double>(0, -1.2166912515654471477e-8),
        4.5852329542527522588e-9,    std::complex<double>(0, 1.6985747923919469126e-9),
        -6.1874610334126146529e-10,  std::complex<double>(0, -2.2171697448745703749e-10),
        7.8179107685642622659e-11,   std::complex<double>(0, 2.7134854206215140081e-11),
        -9.2734773985475872655e-12,  std::complex<double>(0, -3.1215010301961464118e-12),
        1.0351707170122399194e-12,   std::complex<double>(0, 3.3830223748992382941e-13),
        -1.0898184179361594739e-13,  std::complex<double>(0, -3.4615237327403237107e-14),
        1.0842956467662118989e-14,   std::complex<double>(0, 3.3503853028873492513e-15),
        -1.0214195366652095912e-15,  std::complex<double>(0, -3.0730398230793526048e-16),
        9.1259026151799038637e-17};

    // Coefficients for the function std::exp(1i * Pi/4.0 * x) in [-28, 28] of degree 48
    // Need three double-angle iterations to get std::exp(1i * 2Pi * x)
    static const inline std::vector<std::complex<double>> coeff_exp_28_double_48{
        std::complex<double>(-0.23921872631172760859, 0),    std::complex<double>(0, 0.23657700115383345496),
        std::complex<double>(-0.26073438297200735025, 0),    std::complex<double>(0, 0.18915166871496458256),
        std::complex<double>(-0.31234196537783687209, 0),    std::complex<double>(0, 0.075527056772289380415),
        std::complex<double>(-0.34668626372781419231, 0),    std::complex<double>(0, -0.11365065491116921326),
        std::complex<double>(-0.27433400966883908501, 0),    std::complex<double>(0, -0.3132466032403833367),
        std::complex<double>(-0.017938176633367983182, 0),   std::complex<double>(0, -0.32956060027613220953),
        std::complex<double>(0.31175507159809806579, 0),     std::complex<double>(0, 0.010672730092816636385),
        std::complex<double>(0.29913676830824320607, 0),     std::complex<double>(0, 0.3915454927871518942),
        std::complex<double>(-0.23500380845541923858, 0),    std::complex<double>(0, 0.049584187542800486903),
        std::complex<double>(-0.31166476005127552451, 0),    std::complex<double>(0, -0.46061796599707383049),
        std::complex<double>(0.48426832402987213255, 0),     std::complex<double>(0, 0.42022429174214681602),
        std::complex<double>(-0.3183009548267689004, 0),     std::complex<double>(0, -0.21663384982020056357),
        std::complex<double>(0.13484304798350604804, 0),     std::complex<double>(0, 0.077687580508749382036),
        std::complex<double>(-0.041790701371023239452, 0),   std::complex<double>(0, -0.021130199011459616792),
        std::complex<double>(0.010095208213039949877, 0),    std::complex<double>(0, 0.0045770376068954687215),
        std::complex<double>(-0.0019763841502700657884, 0),  std::complex<double>(0, -0.00081527051248687140012),
        std::complex<double>(0.00032212115978693571863, 0),  std::complex<double>(0, 0.00012218639913956890202),
        std::complex<double>(-4.458557750152673685e-05, 0),  std::complex<double>(0, -1.5679036117348630903e-05),
        std::complex<double>(5.3223445183205814063e-06, 0),  std::complex<double>(0, 1.7465569117845625818e-06),
        std::complex<double>(-5.5480241790974107052e-07, 0), std::complex<double>(0, -1.7080468583728841092e-07),
        std::complex<double>(5.1021577626973641342e-08, 0),  std::complex<double>(0, 1.4803000335283182599e-08),
        std::complex<double>(-4.1754496927145128673e-09, 0), std::complex<double>(0, -1.1460429476765435588e-09),
        std::complex<double>(3.0633949336333896473e-10, 0),  std::complex<double>(0, 7.9807924002750502126e-11),
        std::complex<double>(-2.0278895741891271972e-11, 0), std::complex<double>(0, -5.0292161546394711216e-12),
        std::complex<double>(1.2181923617996896608e-12, 0)};

    // Coefficients for the function std::exp(1i * Pi/8.0 * x) in [-16, 16] of degree 23
    // Need four double-angle iterations to get std::exp(1i * 2Pi * x)
    static const inline std::vector<std::complex<double>> coeff_exp_16_double_23{
        std::complex<double>(0.44055381707986857043, 0),     std::complex<double>(0, -0.42476506015273823857),
        std::complex<double>(0.5757607350319376982, 0),      std::complex<double>(0, -0.058224392078514659865),
        std::complex<double>(0.63136093387883518435, 0),     std::complex<double>(0, 0.74564931593694050438),
        std::complex<double>(-0.55537681056570964433, 0),    std::complex<double>(0, -0.31504226022478565294),
        std::complex<double>(0.14659065140093999191, 0),     std::complex<double>(0, 0.058247768279542422309),
        std::complex<double>(-0.020276913022748938725, 0),   std::complex<double>(0, -0.0062956504847548480988),
        std::complex<double>(0.0017667326590585323825, 0),   std::complex<double>(0, 0.00045277117471014590583),
        std::complex<double>(-0.00010684737510145241024, 0), std::complex<double>(0, -2.3376886594863650919e-05),
        std::complex<double>(4.7690365669779870709e-06, 0),  std::complex<double>(0, 9.1161719769832763422e-07),
        std::complex<double>(-1.6396846620747584922e-07, 0), std::complex<double>(0, -2.7852909912067652654e-08),
        std::complex<double>(4.4828133381284258415e-09, 0),  std::complex<double>(0, 6.8557357458132878181e-10),
        std::complex<double>(-9.9853771085012255071e-11, 0), std::complex<double>(0, -1.4132101422613974449e-11)};

    // Coefficients for the function std::exp(1i * Pi/256.0 * x) in [-512, 512] of degree 23
    // Need nine double-angle iterations to get std::exp(1i * 2Pi * x)
    static const inline std::vector<std::complex<double>> coeff_exp_512_double_23{
        std::complex<double>(0.44055381707986857043, 0),     std::complex<double>(0, -0.42476506015273823857),
        std::complex<double>(0.5757607350319376982, 0),      std::complex<double>(0, -0.058224392078514659865),
        std::complex<double>(0.63136093387883518435, 0),     std::complex<double>(0, 0.74564931593694050438),
        std::complex<double>(-0.55537681056570964433, 0),    std::complex<double>(0, -0.31504226022478565294),
        std::complex<double>(0.14659065140093999191, 0),     std::complex<double>(0, 0.058247768279542422309),
        std::complex<double>(-0.020276913022748938725, 0),   std::complex<double>(0, -0.0062956504847548480988),
        std::complex<double>(0.0017667326590585323825, 0),   std::complex<double>(0, 0.00045277117471014590583),
        std::complex<double>(-0.00010684737510145241024, 0), std::complex<double>(0, -2.3376886594863650919e-05),
        std::complex<double>(4.7690365669779870709e-06, 0),  std::complex<double>(0, 9.1161719769832763422e-07),
        std::complex<double>(-1.6396846620747584922e-07, 0), std::complex<double>(0, -2.7852909912067652654e-08),
        std::complex<double>(4.4828133381284258415e-09, 0),  std::complex<double>(0, 6.8557357458132878181e-10),
        std::complex<double>(-9.9853771085012255071e-11, 0), std::complex<double>(0, -1.4132101422613974449e-11)};
    // Coefficients for the function std::cos(Pi/2.0 * x) in [-28, 28] of degree 64
    // Need one double-angle iteration to get std::cos(Pi x)
    static const inline std::vector<double> coeff_cos_28_double{
        0.16965420038096151724,     0, 0.17732563341570652559,    0, 0.19813991091980195862,      0,
        0.22463618146696167977,     0, 0.24222204269430454339,    0, 0.2287703921693835236,       0,
        0.16029435207712290875,     0, 0.02766140239866483372,    0, -0.13738812802783614996,     0,
        -0.24717223908160334579,    0, -0.1950767387446053884,    0, 0.031920264790175676605,     0,
        0.24713797547609867293,     0, 0.17445420196675215342,    0, -0.15727868519323690949,     0,
        -0.24950768519855446715,    0, 0.13171463314130863062,    0, 0.24992317333798480106,      0,
        -0.23967941768304552442,    0, -0.097114600515942013868,  0, 0.35075914986051726668,      0,
        -0.36787890633417613051,    0, 0.25223794632358660259,    0, -0.13151589581952095773,     0,
        0.05562144498625856842,     0, -0.019788193921288727771,  0, 0.0060641459329039143957,    0,
        -0.0016280495941498065558,  0, 0.00038783148814341062486, 0, -0.000082806834460877132114, 0,
        0.000015977943885509015508, 0, -2.8137340867521752547e-6, 0, 5.1712615734270056803e-7};

    // Coefficients for the function std::cos(Pi/2.0 * x) in [-16, 16] of degree 50
    // Need one double-angle iteration to get std::cos(Pi x)
    static const inline std::vector<double> coeff_cos_16_double{
        0.22393566906777406473,    0, 0.24158307546266121784,      0, 0.28534623846463528672,    0,
        0.32214532018151837923,    0, 0.28798365357787248334,      0, 0.11275670987605882749,    0,
        -0.17995397739265354314,   0, -0.34811157721125466184,     0, -0.079206690817227674462,  0,
        0.3619825467512375429,     0, 0.071116210979945962808,     0, -0.43951407397686912164,   0,
        0.40955141151976834921,    0, -0.22366008829505166164,     0, 0.086745018497586218891,   0,
        -0.025904132260782119253,  0, 0.0062348555293592797941,    0, -0.0012463877741257321947, 0,
        0.00021144315086655356181, 0, -0.000030941853901365542544, 0, 3.9566690159249453134e-6,  0,
        -4.4681499226586877671e-7, 0, 4.4954022829997224556e-8,    0, -4.0598440976489881572e-9, 0,
        3.3135648780960312982e-10, 0, -2.6219749998085732829e-11};

    // Coefficients for the function std::cos(Pi/32.0 * x) in [-512, 512] of degree 92
    // Need five double-angle iterations to get std::cos(Pi x)
    static const inline std::vector<double> coeff_cos_512_double{
        0.15875482260721806945,      0, 0.16504045180290845041,     0, 0.18232964308446051051,     0,
        0.20537188212129648844,      0, 0.22397542409002082748,     0, 0.22236412680405005873,     0,
        0.18167098817309372606,      0, 0.088711743148052377287,    0, -0.048042042187510357275,   0,
        -0.18234204010692166874,     0, -0.23371566160443221632,    0, -0.13509475246457963366,    0,
        0.081139059730079847246,     0, 0.2391029473829727179,      0, 0.14397288454602652212,     0,
        -0.14328279487122648096,     0, -0.23939059195783441929,    0, 0.058514187062838834529,    0,
        0.26423653922629225534,      0, -0.075493590567964365481,   0, -0.25646304035774407972,    0,
        0.21915620724282844185,      0, 0.091374356646708566199,    0, -0.32877509803452822355,    0,
        0.357719154870658171,        0, -0.25856048155035421797,    0, 0.14381838906411188314,     0,
        -0.065523441964940601934,    0, 0.025322077577455126277,    0, -0.0084913652047327096646,  0,
        0.0025108710956997454094,    0, -0.00066268886123584198631, 0, 0.00015760790704601871819,  0,
        -0.000034040437489198023529, 0, 6.7198930684778842551e-6,   0, -1.2191501227452748787e-6,  0,
        2.0423473219299951823e-7,    0, -3.1722722090117057614e-8,  0, 4.5852329542527522588e-9,   0,
        -6.1874610334126146529e-10,  0, 7.8179107685642622659e-11,  0, -9.2734773985475872655e-12, 0,
        1.0351707170122399194e-12,   0, -1.0898184179361594739e-13, 0, 1.0842956467662118989e-14,  0,
        -1.0214195366652095912e-15,  0, 9.1259026151799038637e-17};

    // Fourier coefficients for the y = x in [-0.5, 0.5] of degree 25
    static const inline std::vector<std::complex<double>> coeff_identity_1_double_25{
        std::complex<double>(0, 0.000000000000e+00),  std::complex<double>(0, -3.078625958366e-01),
        std::complex<double>(0, 1.392185588975e-01),  std::complex<double>(0, -7.841132880780e-02),
        std::complex<double>(0, 4.632469997106e-02),  std::complex<double>(0, -2.714371637884e-02),
        std::complex<double>(0, 1.534409830487e-02),  std::complex<double>(0, -8.217909893393e-03),
        std::complex<double>(0, 4.107119760690e-03),  std::complex<double>(0, -1.885469837262e-03),
        std::complex<double>(0, 7.796207954152e-04),  std::complex<double>(0, -2.821494030521e-04),
        std::complex<double>(0, 8.502045350971e-05),  std::complex<double>(0, -1.904381272352e-05),
        std::complex<double>(0, 1.955327257209e-06),  std::complex<double>(0, 6.059635912051e-07),
        std::complex<double>(0, -3.233437045926e-07), std::complex<double>(0, 3.188100072853e-08),
        std::complex<double>(0, 2.572697405112e-08),  std::complex<double>(0, -9.811813990468e-09),
        std::complex<double>(0, -1.258193476489e-09), std::complex<double>(0, 1.704301981199e-09),
        std::complex<double>(0, -1.285522356967e-10), std::complex<double>(0, -2.757124392618e-10),
        std::complex<double>(0, 7.211314011213e-11),  std::complex<double>(0, 4.426391086890e-11)};
};

}  // namespace lbcrypto

#endif
