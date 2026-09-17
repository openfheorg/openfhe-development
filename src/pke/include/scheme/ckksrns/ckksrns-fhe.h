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

    // upper bounds for the number of overflows in the uniform ternary secret case; used for all scaling techniques,
    // including composite scaling of any degree (the overflow depends only on the secret key distribution and the
    // ring dimension). Each value is the largest one for which the corresponding approximation below keeps its
    // precision without an additional level of multiplicative depth; the degree of the depth-8 tables is capped at
    // 104 because higher degrees fall into a noisier regime of the Paterson-Stockmeyer evaluation (8 baby-step
    // pieces, or exactly 7 * 15 = 105), which costs about 3 bits of precision. Probabilities of failure for fully
    // packed slots (N/2), with the overflow of a uniform ternary secret (Hamming weight ~2N/3) modeled as a normal
    // distribution of variance (h + 1)/12:
    //   K = 648 (regular bootstrapping):        2^{-71} for N = 2^16, 2^{-28} for N = 2^17
    //   K = 672 (functional bootstrapping):     2^{-77} for N = 2^16, 2^{-31} for N = 2^17
    //   K = 696 (FE functional bootstrapping):  2^{-84} for N = 2^16, 2^{-34} for N = 2^17
    static constexpr uint32_t K_UNIFORM       = 648;
    static constexpr uint32_t K_UNIFORM_FBT   = 672;
    static constexpr uint32_t K_UNIFORM_FEFBT = 696;
    // number of double-angle iterations in CKKS bootstrapping. Must be static because it is used in a static function.
    static constexpr uint32_t R_UNIFORM = 6;
    // number of double-angle iterations in CKKS bootstrapping. Must be static because it is used in a static function.
    // same value is used for both SPARSE and ENCAPSULATED_SPARSE
    static constexpr uint32_t R_SPARSE = 3;
    // number of double-angle iterations in CKKS functional bootstrapping for UNIFORM_TERNARY; matches the
    // interval [-K_UNIFORM_FBT, K_UNIFORM_FBT] of coeff_exp_672_double_104 and coeff_cos_672_double_104.
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
    // for UNIFORM_TERNARY secret key distribution (K_UNIFORM_FEFBT)
    static const uint32_t R_func_696_double_27 = 9;

    // TODO: regenerate these as hexfloat

    // Chebyshev series coefficients for the SPARSE case with K = K_SPARSE = 28 (degree 48); also used for
    // SPARSE_ENCAPSULATED with the denser sparse secret (Hamming weight 64: first modulus
    // above 60 bits)
    static const inline std::vector<double> g_coefficientsSparse{
        -0.18646470117093252861,   0.036680543700430681686,   -0.20323558926782631096,    0.029327390306199328102,
        -0.24346234149506401634,   0.011710240188138305514,   -0.27023281815251748439,    -0.017621188001030563958,
        -0.21383614034992018405,   -0.048567932060728895294,  -0.013982336571484154861,   -0.051097367628345061186,
        0.24300487324019379165,    0.0016547743046159961878,  0.23316923792642238467,     0.060707936480887646213,
        -0.18317928363421173699,   0.0076878773048246725266,  -0.24293447776635196389,    -0.071417413140564683927,
        0.37747441314067164964,    0.065154496937795861045,   -0.24810721693607740157,    -0.033588418808958492301,
        0.10510660697380984352,    0.012045222815124597554,   -0.032574751830745422854,   -0.0032761730196024336711,
        0.0078689491066424796517,  0.00070965574480790578806, -0.0015405394287521703266,  -0.00012640521062950351035,
        0.00025108496615861448107, 1.8944629154051014614e-05, -3.475328421629313028e-05,  -2.4309868105444819976e-06,
        4.1486274733754325284e-06, 2.707983312645711086e-07,  -4.3245388298161974387e-07, -2.648274647458271498e-08,
        3.9769976862509400954e-08, 2.2951601321890868824e-09, -3.254653203623324375e-09,  -1.7769046100728302511e-10,
        2.3878362964407593422e-10, 1.2373864205906022264e-11, -1.5809540399549927648e-11, -7.7742106845205528309e-13,
        1.001495233948273455e-12};

    // Chebyshev series coefficients for the SPARSE ENCAPSULATED case with K = K_SPARSE_ENCAPSULATED = 16 (degree 36);
    // used for first moduli of at most 60 bits (Hamming weight 32), with or without composite scaling
    static const inline std::vector<double> g_coefficientsSparseEncapsulated{
        0.24554573401685125811,    -0.047919064883347899098,  0.2838870204084082971,      -0.029944538735513632349,
        0.35576522619036476947,    0.015106561885073123419,   0.29532946674499999107,     0.071203602333739499097,
        -0.10347347339668094834,   0.044997590512555328546,   -0.4275071243192573589,     -0.09034212972909490269,
        0.36762876269324940015,    0.0493180660393352302,     -0.14535986272411996478,    -0.01510693848306368485,
        0.035951935499240340877,   0.0031036582188687005315,  -0.0062644606607068610907,  -0.00046609430477142572069,
        0.00082128798852389086217, 5.3910533892471557279e-05, -8.4551549768872405238e-05, -4.9773801788208594927e-06,
        7.0466620440941974484e-06, 3.765980756677792052e-07,  -4.86485101424265225e-07,   -2.3830267712305952681e-08,
        2.8329707187359534301e-08, 1.281774628407396656e-09,  -1.4121452243480404948e-09, -5.9391368843495201655e-11,
        6.0992579610647666324e-11, 2.3973045543634602219e-12, -2.306346026629356268e-12,  -8.5029643608477862378e-14,
        7.9314691251993335928e-14};

    // Chebyshev series coefficients for the UNIFORM_TERNARY case with K = K_UNIFORM = 648 (degree 104): interpolation of
    // (2 Pi)^(-1/64) cos(2 Pi K x / 64 - Pi/128) on [-1, 1], followed by R_UNIFORM = 6 scaled double-angle iterations
    // (ApplyDoubleAngleIterations) to get sin(2 Pi K x) / (2 Pi); the approximation error is about 2^-36
    static const inline std::vector<double> g_coefficientsUniform{
        0.19434469187614321534,      0.000028121235020924102279,  0.19430867862208346732,
        0.00032804053246704692819,   0.19304837049242552267,      0.0009239885061941122757,
        0.18713187486250454703,      0.001790513781902917009,     0.1710808161611283042,
        0.0028467803069684297558,    0.13826944065298560445,      0.0039138884205377515022,
        0.083134222110841322102,     0.0046838043398685844379,    0.0051565848584134534659,
        0.0047395193765435668118,    -0.085887877787818373445,    0.0036789622404267100274,
        -0.16598229147968197156,     0.0013731896243041756715,    -0.19939503130900015958,
        -0.0017045122122027995596,   -0.15355473811750672653,     -0.0043116748182450947258,
        -0.0265552968643165264,      -0.0048035383439814405066,   0.12723510977929983817,
        -0.0022504694585396847506,   0.2050503858225569312,       0.0021805212378252080809,
        0.12406879690587807423,      0.0050530609514554468551,    -0.076537335732015209183,
        0.0031628706316878016706,    -0.2102040717970232038,      -0.0023528499510093846267,
        -0.10474346864253283546,     -0.0052629751162979429097,   0.1446361839152810378,
        -0.0010212475903697487815,   0.19564246110042237424,      0.0050183127524795356486,
        -0.067850826119918975175,    0.0028190017533414893933,    -0.22308658761062895557,
        -0.0047564467969067889091,   0.051022309299662099956,     -0.0029451060417833152454,
        0.22828884989526551481,      0.0055117347285916102588,    -0.11758072675055333497,
        0.0009745301618288099474,    -0.18122999806870273465,     -0.006298504301385854314,
        0.24627507693859122916,      0.00396501821133928375,      -0.033002360377489771823,
        0.0025387038817746142413,    -0.21831919675046630088,     -0.007233716354980785084,
        0.3282453555161819341,       0.0079658800471704635092,    -0.29404285358349151936,
        -0.0061038101356206023911,   0.19841553574150252155,      0.0036964558747683769604,
        -0.10928401189842060286,     -0.0018700514063383011434,   0.051172121536912933883,
        0.00081544485078443772862,   -0.020884129076554210245,    -0.00031278250256438376398,
        0.0075558173289240873231,    0.00010706943547419701814,   -0.0024537740300429110688,
        -0.000033066172316610842618, 0.000722172359408322777,     9.2919471033685940617e-6,
        -0.00019410177880310225361,  -2.3924506921144603714e-6,   0.000047944305886204967721,
        5.6766877139124484611e-7,    -0.000010941143964258805288, -1.2473400549852736843e-7,
        2.3172504983237698351e-6,    2.5488321926472057185e-8,    -4.5727131961892729324e-7,
        -4.8613939867917865351e-9,   8.4365334825726498476e-8,    8.6826695107008327309e-10,
        -1.4597300587689942755e-8,   -1.4563807651909241906e-10,  2.3751401758947863432e-9,
        2.300141701919308214e-11,    -3.6432330443102090491e-10,  -3.4285743886268137456e-12,
        5.2800674988089143861e-11,   4.8337223759462070528e-13,   -7.244959258689594979e-12,
        -6.4581668444616276355e-14,  9.42973904271209616e-13,     8.1905428832214402662e-15,
        -1.1678129518123648459e-13,  -9.7570242043553113173e-16,  1.5265533469878859254e-14};

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

    // Coefficients for the function std::exp(1i * Pi/2.0 * x) in [-28, 28] of degree 69
    // Need two double-angle iterations to get std::exp(1i * 2Pi * x)
    static const inline std::vector<std::complex<double>> coeff_exp_28_double_69{
        0.16965420038096151734,     std::complex<double>(0, -0.16870362365122679171),
        0.17732563341570653503,     std::complex<double>(0, -0.15257662302550620281),
        0.19813991091980195924,     std::complex<double>(0, -0.11653668445787843111),
        0.22463618146696168187,     std::complex<double>(0, -0.055247612438869928009),
        0.24222204269430455681,     std::complex<double>(0, 0.032868582808249349747),
        0.22877039216938352406,     std::complex<double>(0, 0.13689697922776022931),
        0.16029435207712292022,     std::complex<double>(0, 0.22436545402588617404),
        0.027661402398664831914,    std::complex<double>(0, 0.24197524972429224066),
        -0.1373881280278361483,     std::complex<double>(0, 0.14201639396304749363),
        -0.247172239081603351,      std::complex<double>(0, -0.060296836210872721551),
        -0.19507673874460537689,    std::complex<double>(0, -0.23771070623058818128),
        0.031920264790175678637,    std::complex<double>(0, -0.20577759355187671964),
        0.24713797547609867022,     std::complex<double>(0, 0.063935986489801283073),
        0.17445420196675215374,     std::complex<double>(0, 0.2701921188441360755),
        -0.15727868519323690011,    std::complex<double>(0, 0.069938677312154154397),
        -0.24950768519855445748,    std::complex<double>(0, -0.27043602073441558309),
        0.13171463314130862909,     std::complex<double>(0, -0.078773986979217017201),
        0.24992317333798480528,     std::complex<double>(0, 0.30762638062603936406),
        -0.23967941768304551475,    std::complex<double>(0, -0.084734164213724622039),
        -0.097114600515942006709,   std::complex<double>(0, -0.25254508172894241103),
        0.35075914986051726085,     std::complex<double>(0, 0.3854555186711972059),
        -0.36787890633417613673,    std::complex<double>(0, -0.31714143815669676441),
        0.25223794632358659262,     std::complex<double>(0, 0.18753750575212232987),
        -0.13151589581952086161,    std::complex<double>(0, -0.087560958842858249707),
        0.055621444986257415066,    std::complex<double>(0, 0.033843766800251973148),
        -0.019788193921275291226,   std::complex<double>(0, -0.011147502877347430922),
        0.006064145932755984382,    std::complex<double>(0, 0.0031917021635365192163),
        -0.0016280495926178602858,  std::complex<double>(0, -0.00080602800053480242858),
        0.00038783147325554135753,  std::complex<double>(0, 0.00018157673634949862587),
        -8.2806699030771099422e-05, std::complex<double>(0, -3.6819702905957927218e-05),
        1.5976793949398898349e-05,  std::complex<double>(0, 6.7709097248534839074e-06),
        -2.8046482984350999447e-06, std::complex<double>(0, -1.136281417032234328e-06),
        4.5055512401421694507e-07,  std::complex<double>(0, 1.7496170925212740869e-07),
        -6.6554613614985004105e-08, std::complex<double>(0, -2.4877274695896239424e-08),
        8.9502114311674543983e-09,  std::complex<double>(0, 3.660317554231398248e-09)};

    // Coefficients for the function std::exp(1i * Pi/32.0 * x) in [-672, 672] of degree 104
    // Need six double-angle iterations to get std::exp(1i * 2Pi * x); the approximation error is about 2^-37
    static const inline std::vector<std::complex<double>> coeff_exp_672_double_104{
        -0.13865640020720140504,     std::complex<double>(0, 0.13813596624226116641),
        -0.14284402341600731954,     std::complex<double>(0, 0.1294752681783404008),
        -0.15461923995242540729,     std::complex<double>(0, 0.11072599858935725765),
        -0.17140265900412296688,     std::complex<double>(0, 0.079549335229813563413),
        -0.18828355223278841015,     std::complex<double>(0, 0.03388646583438599404),
        -0.19752903544671496754,     std::complex<double>(0, -0.025994910157078572118),
        -0.18886057774880706391,     std::complex<double>(0, -0.094699126166024544186),
        -0.15153984585062114253,     std::complex<double>(0, -0.15901463427938507611),
        -0.079231374223438053755,    std::complex<double>(0, -0.197445308125096151),
        0.022523815344751298692,     std::complex<double>(0, -0.18515464566998900174),
        0.12917091340214858433,      std::complex<double>(0, -0.10683773377800005517),
        0.19718592716016723574,      std::complex<double>(0, 0.024672462478262568778),
        0.1799830470995404837,       std::complex<double>(0, 0.15562190987772900789),
        0.062040208002197508074,     std::complex<double>(0, 0.20452174799658166397),
        -0.10536312026697861916,     std::complex<double>(0, 0.11508675380951229742),
        -0.20654067204647062958,     std::complex<double>(0, -0.07275306850887542149),
        -0.13816937207942001221,     std::complex<double>(0, -0.20678941776810897185),
        0.068703278312457181925,     std::complex<double>(0, -0.13597573092971731976),
        0.21297800976577739848,      std::complex<double>(0, 0.096457432664093635148),
        0.10478523707274244496,      std::complex<double>(0, 0.21716778710999025202),
        -0.15197090486181950937,     std::complex<double>(0, 0.032886486424986638922),
        -0.19284631855589696027,     std::complex<double>(0, -0.21265307241697576284),
        0.084358608771748837098,     std::complex<double>(0, -0.10012965499817908671),
        0.2209540048550028878,       std::complex<double>(0, 0.20799080503167236388),
        -0.075394555660674391672,    std::complex<double>(0, 0.098281856774635855026),
        -0.22138695999871551576,     std::complex<double>(0, -0.2372879434147286879),
        0.14547837441247786916,      std::complex<double>(0, -0.0079570243980798104651),
        0.15826298156650308698,      std::complex<double>(0, 0.25112300122813083426),
        -0.26044381525713537002,     std::complex<double>(0, -0.19102015179464764051),
        0.069632885529930186818,     std::complex<double>(0, -0.068585820335076390561),
        0.19230537459813255042,      std::complex<double>(0, 0.28120104766985390587),
        -0.32769971894394244005,     std::complex<double>(0, -0.3347250223158035811),
        0.31157798359331894313,      std::complex<double>(0, 0.26979065003445531408),
        -0.22004173277665193018,     std::complex<double>(0, -0.17046994886498567397),
        0.12620322830953890588,      std::complex<double>(0, 0.08968986030340164974),
        -0.061405598026279630264,    std::complex<double>(0, -0.040616865821882818332),
        0.026017377737559705452,     std::complex<double>(0, 0.016171169925157083977),
        -0.0097696087251537019993,   std::complex<double>(0, -0.0057452553187404773702),
        0.0032930453220255790614,    std::complex<double>(0, 0.0018417803960741896979),
        -0.00100617200514044393,     std::complex<double>(0, -0.00053740157746205312952),
        0.00028085261977364370105,   std::complex<double>(0, 0.00014372730203941707144),
        -0.000072074571983240335437, std::complex<double>(0, -0.000035439174340384266047),
        0.000017096197798761963378,  std::complex<double>(0, 8.0959358636116793622e-6),
        -3.7653637231702013512e-6,   std::complex<double>(0, -1.7207798356271559445e-6),
        7.7306364115820468632e-7,    std::complex<double>(0, 3.4155296127100880813e-7),
        -1.4846511086886219427e-7,   std::complex<double>(0, -6.3514860525519981166e-8),
        2.6752425346657149724e-8,    std::complex<double>(0, 1.1097678044250190165e-8),
        -4.5354374229282876681e-9,   std::complex<double>(0, -1.8266466735865899414e-9),
        7.2520744426710813965e-10,   std::complex<double>(0, 2.8389682949674376298e-10),
        -1.0961315283851321073e-10,  std::complex<double>(0, -4.1751736176627815189e-11),
        1.5693401797664281026e-11,   std::complex<double>(0, 5.8203382574910978539e-12),
        -2.1360361410828636656e-12,  std::complex<double>(0, -7.5933766397977714821e-13),
        3.0921791889667285116e-13};

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

    // Coefficients for the function std::exp(1i * Pi/256.0 * x) in [-696, 696] of degree 27
    // Need nine double-angle iterations to get std::exp(1i * 2Pi * x); the approximation error is about 2^-30
    static const inline std::vector<std::complex<double>> coeff_exp_696_double_27{
        std::complex<double>(0.061360158967239699428, 0),     std::complex<double>(0, 0.54659344251322940602),
        std::complex<double>(-0.066629613152442052538, 0),    std::complex<double>(0, 0.51538959577627480304),
        std::complex<double>(-0.42867894517308958682, 0),     std::complex<double>(0, 0.11387346888727482038),
        std::complex<double>(-0.56200143131878844197, 0),     std::complex<double>(0, -0.6757126790331047618),
        std::complex<double>(0.54556798969587122002, 0),      std::complex<double>(0, 0.34628454590107307674),
        std::complex<double>(-0.18420278697486780942, 0),     std::complex<double>(0, -0.085042852033324798733),
        std::complex<double>(0.034846251050841244725, 0),     std::complex<double>(0, 0.01287190619828963608),
        std::complex<double>(-0.004336693287768814029, 0),    std::complex<double>(0, -0.0013447542933420345281),
        std::complex<double>(0.00038660145494971688697, 0),   std::complex<double>(0, 0.00010366504788206930291),
        std::complex<double>(-0.000026058306391956842504, 0), std::complex<double>(0, -6.1671159813166895155e-6),
        std::complex<double>(1.3793217355337668007e-6, 0),    std::complex<double>(0, 2.9249589397493124655e-7),
        std::complex<double>(-5.8979711163383584045e-8, 0),   std::complex<double>(0, -1.1337966028205898537e-8),
        std::complex<double>(2.082682964567321823e-9, 0),     std::complex<double>(0, 3.6633741022437148116e-10),
        std::complex<double>(-6.1784072322089938085e-11, 0),  std::complex<double>(0, -1.0260866652079843544e-11)};

    // Coefficients for the function std::cos(Pi/2.0 * x) in [-28, 28] of degree 68
    // Need one double-angle iteration to get std::cos(Pi x)
    static const inline std::vector<double> coeff_cos_28_double_68{
        0.16965420038096151734,     0, 0.17732563341570653503,     0, 0.19813991091980195924,     0,
        0.22463618146696168187,     0, 0.24222204269430455681,     0, 0.22877039216938352406,     0,
        0.16029435207712292022,     0, 0.027661402398664835384,    0, -0.1373881280278361483,     0,
        -0.247172239081603351,      0, -0.19507673874460537689,    0, 0.031920264790175678637,    0,
        0.24713797547609867022,     0, 0.17445420196675215374,     0, -0.15727868519323690011,    0,
        -0.24950768519855445748,    0, 0.13171463314130862909,     0, 0.24992317333798480528,     0,
        -0.23967941768304551475,    0, -0.097114600515942020587,   0, 0.35075914986051726085,     0,
        -0.36787890633417613673,    0, 0.25223794632358659262,     0, -0.13151589581952086161,    0,
        0.055621444986257415066,    0, -0.019788193921275291226,   0, 0.0060641459327559904535,   0,
        -0.0016280495926179615503,  0, 0.0003878314732567864553,   0, -8.2806699045358104529e-05, 0,
        1.5976794110764587091e-05,  0, -2.8046499783036893006e-06, 0, 4.5057154372838970687e-07,  0,
        -6.6704930345709428275e-08, 0, 1.0235563061480933036e-08};

    // Coefficients for the function std::cos(Pi/2.0 * x) in [-16, 16] of degree 50
    // Need one double-angle iteration to get std::cos(Pi x)
    static const inline std::vector<double> coeff_cos_16_double_50{
        0.22393566906777406473,    0, 0.24158307546266121784,      0, 0.28534623846463528672,    0,
        0.32214532018151837923,    0, 0.28798365357787248334,      0, 0.11275670987605882749,    0,
        -0.17995397739265354314,   0, -0.34811157721125466184,     0, -0.079206690817227674462,  0,
        0.3619825467512375429,     0, 0.071116210979945962808,     0, -0.43951407397686912164,   0,
        0.40955141151976834921,    0, -0.22366008829505166164,     0, 0.086745018497586218891,   0,
        -0.025904132260782119253,  0, 0.0062348555293592797941,    0, -0.0012463877741257321947, 0,
        0.00021144315086655356181, 0, -0.000030941853901365542544, 0, 3.9566690159249453134e-6,  0,
        -4.4681499226586877671e-7, 0, 4.4954022829997224556e-8,    0, -4.0598440976489881572e-9, 0,
        3.3135648780960312982e-10, 0, -2.6219749998085732829e-11};

    // Coefficients for the function std::cos(Pi/32.0 * x) in [-672, 672] of degree 104
    // Need five double-angle iterations to get std::cos(Pi x); the approximation error is about 2^-34
    static const inline std::vector<double> coeff_cos_672_double_104{
        -0.13865640020720140504,    0, -0.14284402341600731954,    0, -0.15461923995242540729,     0,
        -0.17140265900412296688,    0, -0.18828355223278841015,    0, -0.19752903544671496754,     0,
        -0.18886057774880706391,    0, -0.15153984585062114253,    0, -0.079231374223438053755,    0,
        0.022523815344751298692,    0, 0.12917091340214858433,     0, 0.19718592716016723574,      0,
        0.1799830470995404837,      0, 0.062040208002197508074,    0, -0.10536312026697861916,     0,
        -0.20654067204647062958,    0, -0.13816937207942001221,    0, 0.068703278312457181925,     0,
        0.21297800976577739848,     0, 0.10478523707274244496,     0, -0.15197090486181950937,     0,
        -0.19284631855589696027,    0, 0.084358608771748837098,    0, 0.2209540048550028878,       0,
        -0.075394555660674391672,   0, -0.22138695999871551576,    0, 0.14547837441247786916,      0,
        0.15826298156650308698,     0, -0.26044381525713537002,    0, 0.069632885529930186818,     0,
        0.19230537459813255042,     0, -0.32769971894394244005,    0, 0.31157798359331894313,      0,
        -0.22004173277665193018,    0, 0.12620322830953890588,     0, -0.061405598026279630264,    0,
        0.026017377737559705452,    0, -0.0097696087251537019993,  0, 0.0032930453220255790614,    0,
        -0.00100617200514044393,    0, 0.00028085261977364370105,  0, -0.000072074571983240335437, 0,
        0.000017096197798761963378, 0, -3.7653637231702013512e-6,  0, 7.7306364115820468632e-7,    0,
        -1.4846511086886219427e-7,  0, 2.6752425346657149724e-8,   0, -4.5354374229282876681e-9,   0,
        7.2520744426710813965e-10,  0, -1.0961315283851321073e-10, 0, 1.5693401797664281026e-11,   0,
        -2.1360361410828636656e-12, 0, 3.0921791889667285116e-13};

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
