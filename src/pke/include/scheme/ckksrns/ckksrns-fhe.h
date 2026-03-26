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

    //------------------------------------------------------------------------------
    // Bootstrap Wrapper
    //------------------------------------------------------------------------------

    void EvalBootstrapSetup(const CryptoContextImpl<DCRTPoly>& cc, std::vector<uint32_t> levelBudget,
                            std::vector<uint32_t> dim1, uint32_t slots, uint32_t correctionFactor, bool precompute,
                            bool BTSlotsEncoding) override;

    std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> EvalBootstrapKeyGen(const PrivateKey<DCRTPoly> privateKey,
                                                                               uint32_t slots) override;

    void EvalBootstrapPrecompute(const CryptoContextImpl<DCRTPoly>& cc, uint32_t slots) override;

    Ciphertext<DCRTPoly> EvalBootstrap(ConstCiphertext<DCRTPoly>& ciphertext, uint32_t numIterations,
                                       uint32_t precision) const override;

    Ciphertext<DCRTPoly> EvalBootstrapStCFirst(ConstCiphertext<DCRTPoly>& ciphertext, uint32_t numIterations,
                                               uint32_t precision) const override;

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

    Ciphertext<DCRTPoly> EvalLinearTransform(const std::vector<ReadOnlyPlaintext>& A,
                                             ConstCiphertext<DCRTPoly>& ct) const;

    Ciphertext<DCRTPoly> EvalCoeffsToSlots(const std::vector<std::vector<ReadOnlyPlaintext>>& A,
                                           ConstCiphertext<DCRTPoly>& ctxt) const;

    Ciphertext<DCRTPoly> EvalSlotsToCoeffs(const std::vector<std::vector<ReadOnlyPlaintext>>& A,
                                           ConstCiphertext<DCRTPoly>& ctxt) const;

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

    template <typename VectorDataType>
    static uint32_t GetFBTDepth(const std::vector<uint32_t>& levelBudget,
                                const std::vector<VectorDataType>& coefficients, const BigInteger& PInput, size_t order,
                                SecretKeyDist skd);

    template <typename VectorDataType>
    static uint32_t AdjustDepthFBT(const std::vector<VectorDataType>& coefficients, const BigInteger& PInput,
                                   size_t order, SecretKeyDist skd = SPARSE_TERNARY);

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

    void ApplyDoubleAngleIterations(Ciphertext<DCRTPoly>& ciphertext, uint32_t numIt) const;

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

    // upper bound for the number of overflows in the sparse secret case

    // TODO: unify this
    static constexpr uint32_t K_SPARSE     = 28;
    static constexpr uint32_t K_SPARSE_ALT = 25;
    // corresponds to probability of less than 2^{-128}
    static constexpr uint32_t K_SPARSE_ENCAPSULATED = 16;

    // upper bound for the number of overflows in the uniform secret case
    static constexpr uint32_t K_UNIFORM = 512;
    // upper bound for the number of overflows in the uniform secret case for compositeDegreee > 2
    static constexpr uint32_t K_UNIFORMEXT = 768;
    // number of double-angle iterations in CKKS bootstrapping. Must be static because it is used in a static function.
    static constexpr uint32_t R_UNIFORM = 6;
    // number of double-angle iterations in CKKS bootstrapping. Must be static because it is used in a static function.
    // same value is used for both SPARSE and ENCAPSULATED_SPARSE
    static constexpr uint32_t R_SPARSE = 3;

    // TODO: regenerate these as hexfloat

    // Chebyshev series coefficients for the SPARSE case (degree 44)
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

    // Chebyshev series coefficients for the SPARSE ENCAPSULATED case (degree 32)
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

    // Chebyshev series coefficients for the COMPOSITESCALING case where d > 2
    static const inline std::vector<double> g_coefficientsUniformExt{
        // New Coefficients (K_UNIFORM = 768)
        0.12602195635248634,    -0.0030834928649740388,  0.1293538007310393,      -0.0029150296085609707,
        0.13880323885842225,    -0.0025534902415420128,  0.15259900956315636,     -0.0019572806381606537,
        0.16740348080390202,    -0.0010852123927167594,  0.17795704156012629,     7.3594791671716396e-05,
        0.17708229644467954,    0.0014573280941530976,   0.15661113656175465,     0.0028850600459592078,
        0.10984969661272398,    0.0040295575406054489,   0.035829873357113948,    0.004449523200499763,
        -0.055520186697616318,  0.0037264589074560098,   -0.14007871037019429,    0.001719720247528076,
        -0.18281801001428047,   -0.0011373848818829857,  -0.15209319897288492,    -0.0037123962122311092,
        -0.043785371196750272,  -0.0045107273507656552,  0.09756154430583093,     -0.002604845726688627,
        0.18481556762187912,    0.0012462519210521535,   0.1403768476069214,      0.0043541760219966428,
        -0.024293645826662724,  0.0037846793397644275,   -0.17560536795332429,    -0.0005605968506360667,
        -0.1519811728143392,    -0.0045192348096649545,  0.048231020943727741,    -0.0032001529516056853,
        0.19692074387699257,    0.0024419388214462485,   0.078182928643403107,    0.0047838249172446005,
        -0.16476594792427054,   -0.00036614509861925492, -0.14537982038722122,    -0.0050995116137312257,
        0.13564231010825495,    -0.00050653194386865278, 0.16465075644913021,     0.0052831338103145531,
        -0.1493249604350485,    -0.00016209880585104635, -0.13934114757550983,    -0.0054247353644288178,
        0.20649654831497111,    0.0026431561325639561,   0.032277990808412343,    0.0039463054621702767,
        -0.23636345040634044,   -0.0059041496654351176,  0.17831596275657194,     0.0017594032442182191,
        0.05094162125752931,    0.0040150842221901416,   -0.24841268578463685,    -0.0073080801617375155,
        0.3122522704364516,     0.0073316847629231194,   -0.26606798599442621,    -0.0054892692910619113,
        0.17878607636323862,    0.0033586935001791839,   -0.10066311654486482,    -0.001754132071278842,
        0.049074577561330504,   0.00080234886593034873,  -0.021150143470356698,   -0.0003269871328764949,
        0.0081757002802533667,  0.00012021127618051574,  -0.0028652357611661534,  -4.0244300629116574e-05,
        0.00091801734966694636, 1.2361006806444711e-05,  -0.0002707191913116332,  -3.504631720275642e-06,
        7.3888955616723944e-05, 9.2189772261859728e-07,  -1.8752943907614565e-05, -2.2597387576370175e-07,
        4.4436168671606267e-06, 5.1807959456553769e-08,  -9.8651004908533913e-07, -1.1146078152883018e-08,
        2.0582706963882007e-07, 2.2568126993711184e-09,  -4.0469622058265335e-08, -4.31163542777443e-10,
        7.517057515198321e-09,  7.7904840375183328e-11,  -1.3219720621636946e-09, -1.3342979848924908e-11,
        2.2055962238660182e-10, 2.1724065123826773e-12,  -3.4974624736954921e-11, -3.3609296485004418e-13,
        5.2789108285402917e-12, 4.9471164793087018e-14,  -7.5998777765849013e-13, -4.2492853307002972e-15,
        1.0768090434260388e-13, -2.1478500584069139e-15, -1.3891315735425435e-14};

    // Coefficients for the function std::exp(1i * Pi/2.0 * x) in [-25, 25] of degree 58
    // Need two double-angle iterations to get std::exp(1i * 2Pi * x)
    static const inline std::vector<std::complex<double>> coeff_exp_25_double_58{
        0.18062800362446170148,      std::complex<double>(0, 0.18179610866714050365),
        0.17136920383910273595,      std::complex<double>(0, 0.19925163243335862054),
        0.140925796907040235261,     std::complex<double>(0, 0.22796080003261620565),
        0.082876055856841891882,     std::complex<double>(0, 0.2532858572234829137),
        -0.0074221436141012927592,   std::complex<double>(0, 0.2502618038615061697),
        -0.122133704690862182825,    std::complex<double>(0, 0.18805961883854130208),
        -0.22748947981900530554,     std::complex<double>(0, 0.049028290014482440571),
        -0.25995035380074054116,     std::complex<double>(0, -0.136319989256637197586),
        -0.15580955316508673281,     std::complex<double>(0, -0.26328503536051185873),
        0.072143391454352810524,     std::complex<double>(0, -0.19714884575899848364),
        0.26291684848498283958,      std::complex<double>(0, 0.070656057015580154821),
        0.18734869635645170151,      std::complex<double>(0, 0.28057105360852117596),
        -0.14130673136093645043,     std::complex<double>(0, 0.107850428034749020676),
        -0.27862616125139272005,     std::complex<double>(0, -0.26109773253640144443),
        0.080408993503120812777,     std::complex<double>(0, -0.14643223302221210279),
        0.29668323276411614112,      std::complex<double>(0, 0.30686635603595534211),
        -0.18780259775854393014,     std::complex<double>(0, 0.00079570762613856392926),
        -0.18913992462719792024,     std::complex<double>(0, -0.32672007924592542835),
        0.39325017030968779458,      std::complex<double>(0, 0.39429032240354476156),
        -0.3497483549643555904,      std::complex<double>(0, -0.28258610069142125034),
        0.21153933021645939407,      std::complex<double>(0, 0.14835828410599586121),
        -0.098249509728547702833,    std::complex<double>(0, -0.061801586436542218611),
        0.037094235170279237596,     std::complex<double>(0, 0.021322944460262382422),
        -0.011774353804612492335,    std::complex<double>(0, -0.0062615496337554710171),
        0.0032138570962519864094,    std::complex<double>(0, 0.0015951094513301143899),
        -0.00076681754685412470337,  std::complex<double>(0, -0.00035757527803024873063),
        0.00016195195640370844877,   std::complex<double>(0, 0.000071327121189423030151),
        -0.000030582578262368427032, std::complex<double>(0, -0.0000127704805524093099689),
        5.2199382983514741049e-6,    std::complex<double>(0, 2.0288493823845387861e-6),
        -9.1760095813876081637e-7};

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

    // Coefficients for the function std::exp(1i * Pi/2.0 * x) in [-25, 25] of degree 66
    // Need two double-angle iterations to get std::exp(1i * 2Pi * x)
    static const inline std::vector<std::complex<double>> coeff_exp_25_double_66{
        0.18062800362446170148,      std::complex<double>(0, 0.18179610866714050365),
        0.17136920383910273595,      std::complex<double>(0, 0.19925163243335862054),
        0.140925796907040235261,     std::complex<double>(0, 0.22796080003261620565),
        0.082876055856841891882,     std::complex<double>(0, 0.2532858572234829137),
        -0.0074221436141012927592,   std::complex<double>(0, 0.2502618038615061697),
        -0.122133704690862182825,    std::complex<double>(0, 0.18805961883854130208),
        -0.22748947981900530554,     std::complex<double>(0, 0.049028290014482440571),
        -0.25995035380074054116,     std::complex<double>(0, -0.136319989256637197586),
        -0.15580955316508673281,     std::complex<double>(0, -0.26328503536051185873),
        0.072143391454352810524,     std::complex<double>(0, -0.19714884575899848364),
        0.26291684848498283958,      std::complex<double>(0, 0.070656057015580154821),
        0.18734869635645170151,      std::complex<double>(0, 0.28057105360852117596),
        -0.14130673136093645043,     std::complex<double>(0, 0.107850428034749020676),
        -0.27862616125139272005,     std::complex<double>(0, -0.26109773253640144443),
        0.080408993503120812777,     std::complex<double>(0, -0.14643223302221210279),
        0.29668323276411614112,      std::complex<double>(0, 0.30686635603595534211),
        -0.18780259775854393014,     std::complex<double>(0, 0.00079570762613856393499),
        -0.18913992462719792022,     std::complex<double>(0, -0.32672007924592542844),
        0.39325017030968779421,      std::complex<double>(0, 0.39429032240354476303),
        -0.34974835496435558469,     std::complex<double>(0, -0.28258610069142127212),
        0.21153933021645931215,      std::complex<double>(0, 0.14835828410599616488),
        -0.098249509728546593889,    std::complex<double>(0, -0.061801586436546207273),
        0.037094235170265110974,     std::complex<double>(0, 0.021322944460311634018),
        -0.0117743538044435084438,   std::complex<double>(0, -0.0062615496343258715024),
        0.0032138570943584019707,    std::complex<double>(0, 0.0015951094575104763515),
        -0.00076681752702904489585,  std::complex<double>(0, -0.00035757534050833235054),
        0.00016195176303594945892,   std::complex<double>(0, 0.000071327708688519499983),
        -0.000030580826759715102478, std::complex<double>(0, -0.0000127756020643569477767),
        5.2052571039403208247e-6,    std::complex<double>(0, 2.0700857100449401148e-6),
        -8.0417306853858198433e-7,   std::complex<double>(0, -3.0537377027147436668e-7),
        1.1342790483574502448e-7,    std::complex<double>(0, 4.1236278712476395809e-8),
        -1.4681363476970724015e-8,   std::complex<double>(0, -5.1209415689329717112e-9),
        1.7533962434723710773e-9,    std::complex<double>(0, 5.8131873597716769476e-10),
        -2.1319283919649474434e-10};

    // Coefficients for the function std::cos(Pi/2.0 * x) in [-25, 25] of degree 58
    // Need one double-angle iteration to get std::cos(Pi x)
    static const inline std::vector<double> coeff_cos_25_double{
        0.18062800362446170148,      0, 0.17136920383910273595,     0, 0.14092579690704023526,    0,
        0.082876055856841891882,     0, -0.0074221436141012927592,  0, -0.12213370469086218282,   0,
        -0.22748947981900530554,     0, -0.25995035380074054116,    0, -0.15580955316508673281,   0,
        0.072143391454352810524,     0, 0.26291684848498283958,     0, 0.18734869635645170151,    0,
        -0.14130673136093645043,     0, -0.27862616125139272005,    0, 0.080408993503120812777,   0,
        0.29668323276411614112,      0, -0.18780259775854393014,    0, -0.18913992462719792024,   0,
        0.39325017030968779458,      0, -0.3497483549643555904,     0, 0.21153933021645939407,    0,
        -0.098249509728547702833,    0, 0.037094235170279237596,    0, -0.011774353804612492335,  0,
        0.0032138570962519864094,    0, -0.00076681754685412470337, 0, 0.00016195195640370844877, 0,
        -0.000030582578262368427032, 0, 5.2199382983514741049e-6,   0, -9.1760095813876081637e-7};

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
};

}  // namespace lbcrypto

#endif
